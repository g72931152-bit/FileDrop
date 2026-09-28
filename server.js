'use strict';

const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 10000);
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;
const ONE_HOUR = 60 * 60 * 1000;
const AUTH_TTL = 15 * 60 * 1000;
const ID_LENGTH = 6;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const ROOT = __dirname;
const INDEX_FILE = path.join(ROOT, 'index.html');
const STORAGE = path.join(ROOT, 'storage');
const FILES_DIR = path.join(STORAGE, 'files');
const META_DIR = path.join(STORAGE, 'meta');
const SECRET = process.env.FILEDROP_SECRET || crypto.randomBytes(32).toString('hex');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const metadata = new Map();
const rateBuckets = new Map();

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function createId() {
  let id = '';
  const bytes = crypto.randomBytes(ID_LENGTH);
  for (let i = 0; i < ID_LENGTH; i += 1) {
    id += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return id;
}

async function uniqueId() {
  for (let i = 0; i < 10; i += 1) {
    const id = createId();
    if (!metadata.has(id) && !fs.existsSync(path.join(META_DIR, `${id}.json`))) return id;
  }
  throw new Error('Could not generate a unique share id');
}

function safeFileName(name) {
  const fallback = 'download';
  const cleaned = String(name || '')
    .replace(/[\\/\r\n\0]/g, '_')
    .replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, '_')
    .trim();
  return (cleaned || fallback).slice(0, 180);
}

function contentDisposition(name) {
  const safe = safeFileName(name);
  const asciiFallback = safe.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_') || 'download';
  return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encodeURIComponent(safe)}`;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 32, { N: 1 << 14, r: 8, p: 1 }, (err, derived) => {
      if (err) return reject(err);
      resolve(`${salt}:${derived.toString('hex')}`);
    });
  });
}

async function verifyPassword(password, encoded) {
  const [salt, expectedHex] = String(encoded || '').split(':');
  if (!salt || !expectedHex) return false;
  const actual = await hashPassword(password, salt);
  const expected = `${salt}:${expectedHex}`;
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function readToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, signature] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || !payload.id || !Number.isFinite(payload.exp) || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(header) {
  const result = {};
  for (const piece of String(header || '').split(';')) {
    const idx = piece.indexOf('=');
    if (idx < 0) continue;
    const key = piece.slice(0, idx).trim();
    const value = piece.slice(idx + 1).trim();
    try { result[key] = decodeURIComponent(value); } catch { result[key] = value; }
  }
  return result;
}

function authCookieName(id) {
  return `fd_auth_${id}`;
}

function setAuthCookie(res, id, token) {
  const secure = IS_PRODUCTION ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${authCookieName(id)}=${encodeURIComponent(token)}; Max-Age=${Math.floor(AUTH_TTL / 1000)}; Path=/; HttpOnly; SameSite=Lax${secure}`);
}

function clearAuthCookie(res, id) {
  const secure = IS_PRODUCTION ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${authCookieName(id)}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secure}`);
}

function clientMeta(item) {
  return {
    id: item.id,
    originalName: item.originalName,
    size: item.size,
    mimetype: item.mimetype,
    createdAt: item.createdAt,
    expiresAt: item.expiresAt,
    deleteAfterDownload: item.deleteAfterDownload,
    maxDownloads: item.maxDownloads,
    downloadsUsed: item.downloadsUsed,
    downloadsRemaining: Math.max(0, item.maxDownloads - item.downloadsUsed),
    passwordRequired: Boolean(item.passwordHash),
  };
}

async function writeMeta(item) {
  const tempPath = path.join(META_DIR, `${item.id}.json.tmp`);
  const finalPath = path.join(META_DIR, `${item.id}.json`);
  await fsp.writeFile(tempPath, JSON.stringify(item), 'utf8');
  await fsp.rename(tempPath, finalPath);
}

async function deleteShare(id) {
  const item = metadata.get(id);
  metadata.delete(id);
  await Promise.allSettled([
    fsp.rm(path.join(FILES_DIR, `${id}.bin`), { force: true }),
    fsp.rm(path.join(META_DIR, `${id}.json`), { force: true }),
    fsp.rm(path.join(META_DIR, `${id}.json.tmp`), { force: true }),
  ]);
  return item || null;
}

function tooManyRequests(req, bucket, max, windowMs) {
  const ip = String(req.ip || req.socket.remoteAddress || 'unknown');
  const key = `${bucket}:${ip}`;
  const now = Date.now();
  let entry = rateBuckets.get(key);
  if (!entry || now - entry.started > windowMs) {
    entry = { started: now, count: 0 };
    rateBuckets.set(key, entry);
  }
  entry.count += 1;
  return entry.count > max;
}

const uploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, FILES_DIR),
  filename: (_req, _file, cb) => cb(null, `.upload-${crypto.randomBytes(12).toString('hex')}.tmp`),
});

const upload = multer({
  storage: uploadStorage,
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 8, parts: 12 },
});

app.use(express.json({ limit: '24kb' }));
app.use(express.urlencoded({ extended: false, limit: '24kb' }));

app.get('/healthz', (_req, res) => {
  res.json({ ok: true, service: 'filedrop' });
});

app.post('/api/upload', (req, res, next) => {
  if (tooManyRequests(req, 'upload', 20, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many uploads. Please try again later.' });
  }
  return upload.single('file')(req, res, async (err) => {
    if (err) return next(err);
    try {
      if (!req.file) return res.status(400).json({ error: 'No file selected.' });

      const settings = JSON.parse(req.body.settings || '{}');
      const maxDownloads = Number(settings.maxDownloads || 5);
      if (![1, 2, 3, 4, 5].includes(maxDownloads)) {
        await fsp.rm(req.file.path, { force: true });
        return res.status(400).json({ error: 'Maximum downloads must be between 1 and 5.' });
      }

      const deleteAfterDownload = Boolean(settings.deleteAfterDownload);
      const expiresInHour = settings.expiresInHour !== false;
      const passwordEnabled = Boolean(settings.passwordEnabled);
      const password = String(settings.password || '');
      if (passwordEnabled && password.length < 4) {
        await fsp.rm(req.file.path, { force: true });
        return res.status(400).json({ error: 'Password must contain at least 4 characters.' });
      }

      const id = await uniqueId();
      const finalFile = path.join(FILES_DIR, `${id}.bin`);
      await fsp.rename(req.file.path, finalFile);

      const item = {
        id,
        originalName: safeFileName(req.file.originalname),
        size: req.file.size,
        mimetype: req.file.mimetype || 'application/octet-stream',
        createdAt: Date.now(),
        expiresAt: expiresInHour ? Date.now() + ONE_HOUR : null,
        deleteAfterDownload,
        maxDownloads,
        downloadsUsed: 0,
        passwordHash: passwordEnabled ? await hashPassword(password) : null,
      };

      metadata.set(id, item);
      await writeMeta(item);
      return res.status(201).json({
        ...clientMeta(item),
        shareUrl: `${req.protocol}://${req.get('host')}/${id}`,
      });
    } catch (error) {
      if (req.file?.path) await fsp.rm(req.file.path, { force: true }).catch(() => {});
      return next(error);
    }
  });
});

app.get('/api/share/:id', asyncHandler(async (req, res) => {
  const item = metadata.get(req.params.id);
  if (!item || (item.expiresAt && item.expiresAt <= Date.now())) {
    if (item) await deleteShare(item.id);
    return res.status(404).json({ error: 'This link is no longer available.' });
  }
  if (item.downloadsUsed >= item.maxDownloads) {
    await deleteShare(item.id);
    return res.status(410).json({ error: 'This file has reached its download limit.' });
  }
  return res.json(clientMeta(item));
}));

app.post('/api/unlock/:id', asyncHandler(async (req, res) => {
  if (tooManyRequests(req, 'unlock', 25, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many password attempts. Please try again later.' });
  }
  const item = metadata.get(req.params.id);
  if (!item || (item.expiresAt && item.expiresAt <= Date.now())) {
    if (item) await deleteShare(item.id);
    return res.status(404).json({ error: 'This link is no longer available.' });
  }
  if (!item.passwordHash) return res.status(400).json({ error: 'This file is not password protected.' });

  const password = String(req.body?.password || '');
  const valid = await verifyPassword(password, item.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Incorrect password.' });

  const token = signToken({ id: item.id, exp: Date.now() + AUTH_TTL });
  setAuthCookie(res, item.id, token);
  return res.json({ ok: true });
}));

function authorizedFor(item, req) {
  if (!item.passwordHash) return true;
  const cookies = parseCookies(req.headers.cookie);
  const token = readToken(cookies[authCookieName(item.id)]);
  return Boolean(token && token.id === item.id);
}

app.get('/api/download/:id', asyncHandler(async (req, res) => {
  const item = metadata.get(req.params.id);
  if (!item || (item.expiresAt && item.expiresAt <= Date.now())) {
    if (item) await deleteShare(item.id);
    return res.status(404).json({ error: 'This link is no longer available.' });
  }
  if (!authorizedFor(item, req)) {
    return res.status(401).json({ error: 'Password required.' });
  }
  if (item.downloadsUsed >= item.maxDownloads) {
    await deleteShare(item.id);
    return res.status(410).json({ error: 'This file has reached its download limit.' });
  }

  const filePath = path.join(FILES_DIR, `${item.id}.bin`);
  try {
    await fsp.access(filePath, fs.constants.R_OK);
  } catch {
    await deleteShare(item.id);
    return res.status(404).json({ error: 'The file is no longer stored on this service.' });
  }

  item.downloadsUsed += 1;
  await writeMeta(item);

  let settled = false;
  const rollback = async () => {
    if (settled) return;
    settled = true;
    item.downloadsUsed = Math.max(0, item.downloadsUsed - 1);
    if (metadata.has(item.id)) await writeMeta(item).catch(() => {});
  };

  const stream = fs.createReadStream(filePath);
  stream.on('error', async () => {
    await rollback();
    if (!res.headersSent) res.status(500).json({ error: 'Unable to read the file.' });
    else res.destroy();
  });

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', contentDisposition(item.originalName));
  res.setHeader('Content-Length', String(item.size));
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  res.on('finish', async () => {
    settled = true;
    if (item.deleteAfterDownload || item.downloadsUsed >= item.maxDownloads) {
      await deleteShare(item.id);
    }
  });
  res.on('close', async () => {
    if (!res.writableFinished) await rollback();
  });

  stream.pipe(res);
}));

app.get('/', (_req, res) => {
  return res.sendFile(INDEX_FILE);
});

app.get('/:id', (req, res) => {
  const id = req.params.id;
  if (!/^[A-Za-z0-9]+$/.test(id)) return res.status(404).sendFile(INDEX_FILE);
  return res.sendFile(INDEX_FILE);
});

app.use((_req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File is larger than 2 GB.' });
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  return res.status(500).json({ error: 'Server error.' });
});

async function loadMetadata() {
  await Promise.all([fsp.mkdir(FILES_DIR, { recursive: true }), fsp.mkdir(META_DIR, { recursive: true })]);
  const entries = await fsp.readdir(META_DIR, { withFileTypes: true });
  let loaded = 0;
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
    try {
      const item = JSON.parse(await fsp.readFile(path.join(META_DIR, entry.name), 'utf8'));
      if (!item?.id || !item?.originalName) continue;
      if (item.expiresAt && item.expiresAt <= Date.now()) {
        await deleteShare(item.id);
        continue;
      }
      const filePath = path.join(FILES_DIR, `${item.id}.bin`);
      await fsp.access(filePath, fs.constants.R_OK);
      metadata.set(item.id, item);
      loaded += 1;
    } catch {
      await fsp.rm(path.join(META_DIR, entry.name), { force: true }).catch(() => {});
    }
  }
  console.log(`Loaded ${loaded} active share(s).`);
}

setInterval(() => {
  const now = Date.now();
  const jobs = [];
  for (const item of metadata.values()) {
    if ((item.expiresAt && item.expiresAt <= now) || item.downloadsUsed >= item.maxDownloads) {
      jobs.push(deleteShare(item.id));
    }
  }
  if (jobs.length) Promise.allSettled(jobs).catch(() => {});
}, 60 * 1000).unref();

setInterval(() => {
  const cutoff = Date.now() - 20 * 60 * 1000;
  for (const [key, bucket] of rateBuckets) {
    if (bucket.started < cutoff) rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

loadMetadata()
  .then(() => {
    const server = app.listen(PORT, '0.0.0.0', () => console.log(`FileDrop listening on ${PORT}`));
    server.requestTimeout = 0;
    server.keepAliveTimeout = 120000;
    server.headersTimeout = 130000;
  })
  .catch((error) => {
    console.error('Startup failed:', error);
    process.exit(1);
  });
