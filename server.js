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
const MAX_AVATAR_CHARS = 380 * 1024;
const ONE_MINUTE = 60 * 1000;
const ONE_HOUR = 60 * ONE_MINUTE;
const AUTH_TTL = 15 * ONE_MINUTE;
const PRESENCE_TTL = 10 * ONE_MINUTE;
const ONLINE_WINDOW = 45 * 1000;
const ID_LENGTH = 8;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const VERSION = 'v1 (0.10)';

const ROOT = __dirname;
const INDEX_FILE = path.join(ROOT, 'index.html');
const STYLES_FILE = path.join(ROOT, 'styles.css');
const SCRIPT_FILE = path.join(ROOT, 'app.js');
const ASSETS_DIR = path.join(ROOT, 'assets');
const STORAGE = path.join(ROOT, 'storage');
const FILES_DIR = path.join(STORAGE, 'files');
const META_DIR = path.join(STORAGE, 'meta');

const SECRET = process.env.FILEDROP_SECRET || crypto.randomBytes(32).toString('hex');
const VT_API_KEY = String(process.env.VT_API_KEY || '').trim();
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const metadata = new Map();
const rateBuckets = new Map();
const presence = new Map();
const inboxes = new Map();

const ALLOWED_EXPIRY = new Set([15 * ONE_MINUTE, ONE_HOUR, 6 * ONE_HOUR, 24 * ONE_HOUR, 7 * 24 * ONE_HOUR, null]);
const RISKY_EXTENSIONS = new Set([
  '.ade', '.adp', '.app', '.appx', '.bat', '.cab', '.cmd', '.com', '.cpl', '.dll', '.exe', '.hta',
  '.inf', '.ins', '.iqy', '.iso', '.jar', '.js', '.jse', '.lnk', '.msi', '.msp', '.mst', '.ocx',
  '.ps1', '.reg', '.scr', '.sys', '.vbe', '.vbs', '.wsf', '.wsh'
]);

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function createId() {
  const bytes = crypto.randomBytes(ID_LENGTH);
  let id = '';
  for (let i = 0; i < ID_LENGTH; i += 1) id += ALPHABET[bytes[i] % ALPHABET.length];
  return id;
}

async function uniqueId() {
  for (let i = 0; i < 12; i += 1) {
    const id = createId();
    if (!metadata.has(id) && !fs.existsSync(path.join(META_DIR, `${id}.json`))) return id;
  }
  throw new Error('Could not generate a unique share id.');
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
  if (actual.length !== expected.length) return false;
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
    return payload?.id && Number.isFinite(payload.exp) && payload.exp >= Date.now() ? payload : null;
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

function setCookie(res, name, value, maxAge, httpOnly = true) {
  const secure = IS_PRODUCTION ? '; Secure' : '';
  const http = httpOnly ? '; HttpOnly' : '';
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; Max-Age=${Math.floor(maxAge / 1000)}; Path=/; SameSite=Lax${http}${secure}`);
}

function setAuthCookie(res, id, token) {
  setCookie(res, authCookieName(id), token, AUTH_TTL, true);
}

function setPresenceCookie(res, token) {
  setCookie(res, 'fd_presence', token, 30 * 24 * ONE_HOUR, true);
}

function getPresenceSession(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  let token = cookies.fd_presence;
  if (!token || !/^[A-Za-z0-9_-]{24,80}$/.test(token)) {
    token = crypto.randomBytes(24).toString('base64url');
    setPresenceCookie(res, token);
  }
  return token;
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
    downloadsRemaining: item.maxDownloads === null ? null : Math.max(0, item.maxDownloads - item.downloadsUsed),
    passwordRequired: Boolean(item.passwordHash),
    owner: item.owner || null,
    sha256: item.sha256,
    virusCheck: item.virusCheck,
    riskFlags: item.riskFlags,
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

function isSafeDataUrl(value) {
  return typeof value === 'string' && /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/i.test(value);
}

function normalizeNickname(value) {
  return String(value || '').replace(/[<>\r\n]/g, '').trim().replace(/\s+/g, ' ').slice(0, 32);
}

function isValidUserId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{12,64}$/.test(value);
}

function presenceUser(userId, session) {
  const record = presence.get(userId);
  return record && record.session === session ? record : null;
}

function touchPresence(userId, data, session) {
  const previous = presence.get(userId);
  const record = {
    userId,
    nickname: data.nickname,
    avatar: data.avatar || null,
    visible: data.visible !== false,
    lastSeen: Date.now(),
    session,
    firstSeen: previous?.firstSeen || Date.now(),
  };
  presence.set(userId, record);
  return record;
}

function publicPresence(record) {
  return {
    userId: record.userId,
    nickname: record.nickname,
    avatar: record.avatar || null,
    online: Date.now() - record.lastSeen <= ONLINE_WINDOW,
    lastSeen: record.lastSeen,
  };
}

async function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function lookupVirusTotal(hash) {
  if (!VT_API_KEY) return { status: 'not-configured', provider: 'VirusTotal' };
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': VT_API_KEY, accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    if (response.status === 404) return { status: 'unknown', provider: 'VirusTotal' };
    if (!response.ok) return { status: 'error', provider: 'VirusTotal' };
    const body = await response.json();
    const stats = body?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    return {
      status: malicious > 0 || suspicious > 0 ? 'flagged' : 'known-clean',
      provider: 'VirusTotal',
      malicious,
      suspicious,
      harmless: Number(stats.harmless || 0),
      undetected: Number(stats.undetected || 0),
    };
  } catch {
    return { status: 'error', provider: 'VirusTotal' };
  }
}

function riskFlagsFor(name) {
  const ext = path.extname(String(name || '')).toLowerCase();
  return RISKY_EXTENSIONS.has(ext) ? [`Potentially executable file type: ${ext}`] : [];
}

function makeBaseUrl(req) {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL;
  return `${req.protocol}://${req.get('host')}`;
}

function authorizedFor(item, req) {
  if (!item.passwordHash) return true;
  const cookies = parseCookies(req.headers.cookie);
  const token = readToken(cookies[authCookieName(item.id)]);
  return Boolean(token && token.id === item.id);
}

const uploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, FILES_DIR),
  filename: (_req, _file, cb) => cb(null, `.upload-${crypto.randomBytes(18).toString('hex')}.tmp`),
});

const upload = multer({
  storage: uploadStorage,
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 12, parts: 16 },
});

app.use(express.json({ limit: '450kb' }));
app.use(express.urlencoded({ extended: false, limit: '450kb' }));

app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'filedrop', version: VERSION }));

app.get('/api/config', (_req, res) => {
  res.json({
    version: VERSION,
    maxFileBytes: MAX_FILE_SIZE,
    virusTotalConfigured: Boolean(VT_API_KEY),
  });
});

app.post('/api/upload', (req, res, next) => {
  if (tooManyRequests(req, 'upload', 20, 10 * ONE_MINUTE)) {
    return res.status(429).json({ error: 'Too many uploads. Please try again later.' });
  }
  return upload.single('file')(req, res, async err => {
    if (err) return next(err);
    try {
      if (!req.file) return res.status(400).json({ error: 'No file selected.' });

      let settings;
      try { settings = JSON.parse(req.body.settings || '{}'); } catch { settings = {}; }

      const maxDownloadsRaw = settings.maxDownloads;
      const maxDownloads = maxDownloadsRaw === null || maxDownloadsRaw === 'unlimited' || maxDownloadsRaw === ''
        ? null
        : Number(maxDownloadsRaw);
      if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1 || maxDownloads > 10000)) {
        await fsp.rm(req.file.path, { force: true });
        return res.status(400).json({ error: 'Download limit must be unlimited or an integer from 1 to 10,000.' });
      }

      const deleteAfterDownload = Boolean(settings.deleteAfterDownload);
      const expiresMs = settings.expiresMs === null || settings.expiresMs === '' ? null : Number(settings.expiresMs);
      if (!(ALLOWED_EXPIRY.has(expiresMs))) {
        await fsp.rm(req.file.path, { force: true });
        return res.status(400).json({ error: 'Unsupported expiry selection.' });
      }

      const passwordEnabled = Boolean(settings.passwordEnabled);
      const password = String(settings.password || '');
      if (passwordEnabled && password.length < 4) {
        await fsp.rm(req.file.path, { force: true });
        return res.status(400).json({ error: 'Password must contain at least 4 characters.' });
      }

      const ownerName = normalizeNickname(settings.ownerName);
      const ownerAvatar = String(settings.ownerAvatar || '');
      const owner = ownerName
        ? { name: ownerName, avatar: isSafeDataUrl(ownerAvatar) && ownerAvatar.length <= MAX_AVATAR_CHARS ? ownerAvatar : null }
        : null;

      const id = await uniqueId();
      const finalFile = path.join(FILES_DIR, `${id}.bin`);
      await fsp.rename(req.file.path, finalFile);

      const sha256 = await sha256File(finalFile);
      const virusCheck = await lookupVirusTotal(sha256);
      const riskFlags = riskFlagsFor(req.file.originalname);

      const item = {
        id,
        originalName: safeFileName(req.file.originalname),
        size: req.file.size,
        mimetype: req.file.mimetype || 'application/octet-stream',
        createdAt: Date.now(),
        expiresAt: expiresMs === null ? null : Date.now() + expiresMs,
        deleteAfterDownload,
        maxDownloads,
        downloadsUsed: 0,
        passwordHash: passwordEnabled ? await hashPassword(password) : null,
        owner,
        sha256,
        virusCheck,
        riskFlags,
      };

      metadata.set(id, item);
      await writeMeta(item);

      return res.status(201).json({
        ...clientMeta(item),
        shareUrl: `${makeBaseUrl(req)}/${id}`,
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
  if (item.maxDownloads !== null && item.downloadsUsed >= item.maxDownloads) {
    await deleteShare(item.id);
    return res.status(410).json({ error: 'This file has reached its download limit.' });
  }
  res.setHeader('Cache-Control', 'private, no-store');
  return res.json(clientMeta(item));
}));

app.post('/api/unlock/:id', asyncHandler(async (req, res) => {
  if (tooManyRequests(req, 'unlock', 30, 10 * ONE_MINUTE)) {
    return res.status(429).json({ error: 'Too many password attempts. Please try again later.' });
  }
  const item = metadata.get(req.params.id);
  if (!item || (item.expiresAt && item.expiresAt <= Date.now())) {
    if (item) await deleteShare(item.id);
    return res.status(404).json({ error: 'This link is no longer available.' });
  }
  if (!item.passwordHash) return res.status(400).json({ error: 'This file is not password protected.' });

  const password = String(req.body?.password || '');
  if (!(await verifyPassword(password, item.passwordHash))) return res.status(401).json({ error: 'Incorrect password.' });

  const token = signToken({ id: item.id, exp: Date.now() + AUTH_TTL });
  setAuthCookie(res, item.id, token);
  return res.json({ ok: true });
}));

app.get('/api/download/:id', asyncHandler(async (req, res) => {
  const item = metadata.get(req.params.id);
  if (!item || (item.expiresAt && item.expiresAt <= Date.now())) {
    if (item) await deleteShare(item.id);
    return res.status(404).json({ error: 'This link is no longer available.' });
  }
  if (!authorizedFor(item, req)) return res.status(401).json({ error: 'Password required.' });
  if (item.maxDownloads !== null && item.downloadsUsed >= item.maxDownloads) {
    await deleteShare(item.id);
    return res.status(410).json({ error: 'This file has reached its download limit.' });
  }

  const filePath = path.join(FILES_DIR, `${item.id}.bin`);
  if (!fs.existsSync(filePath)) {
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
    if (item.deleteAfterDownload || (item.maxDownloads !== null && item.downloadsUsed >= item.maxDownloads)) {
      await deleteShare(item.id);
    }
  });
  res.on('close', async () => {
    if (!res.writableFinished) await rollback();
  });

  stream.pipe(res);
}));

app.post('/api/presence/heartbeat', asyncHandler(async (req, res) => {
  if (tooManyRequests(req, 'presence', 120, 10 * ONE_MINUTE)) {
    return res.status(429).json({ error: 'Presence rate limit reached.' });
  }
  const userId = String(req.body?.userId || '');
  if (!isValidUserId(userId)) return res.status(400).json({ error: 'Invalid local user id.' });

  const nickname = normalizeNickname(req.body?.nickname);
  if (nickname.length < 2) return res.status(400).json({ error: 'Nickname must contain at least 2 characters.' });
  const avatar = String(req.body?.avatar || '');
  if (avatar && (!isSafeDataUrl(avatar) || avatar.length > MAX_AVATAR_CHARS)) return res.status(400).json({ error: 'Invalid avatar.' });

  const session = getPresenceSession(req, res);
  touchPresence(userId, { nickname, avatar, visible: req.body?.visible !== false }, session);
  return res.json({ ok: true, online: true, serverTime: Date.now() });
}));

app.get('/api/people', asyncHandler(async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase().slice(0, 32);
  const now = Date.now();
  const results = [];
  for (const [userId, record] of presence) {
    if (now - record.lastSeen > PRESENCE_TTL) {
      presence.delete(userId);
      inboxes.delete(userId);
      continue;
    }
    if (!record.visible) continue;
    if (q && !record.nickname.toLowerCase().includes(q)) continue;
    results.push(publicPresence(record));
  }
  results.sort((a, b) => Number(b.online) - Number(a.online) || a.nickname.localeCompare(b.nickname));
  return res.json({ people: results.slice(0, 50) });
}));

app.post('/api/drop', asyncHandler(async (req, res) => {
  if (tooManyRequests(req, 'drop', 60, 10 * ONE_MINUTE)) {
    return res.status(429).json({ error: 'Too many drops. Please try again later.' });
  }
  const senderId = String(req.body?.senderId || '');
  const recipientId = String(req.body?.recipientId || '');
  const shareId = String(req.body?.shareId || '');
  if (!isValidUserId(senderId) || !isValidUserId(recipientId) || !/^[A-Za-z0-9]+$/.test(shareId)) {
    return res.status(400).json({ error: 'Invalid drop request.' });
  }
  const session = getPresenceSession(req, res);
  const sender = presenceUser(senderId, session);
  if (!sender) return res.status(403).json({ error: 'Your local presence session is not active.' });

  const item = metadata.get(shareId);
  if (!item || (item.expiresAt && item.expiresAt <= Date.now())) {
    if (item) await deleteShare(item.id);
    return res.status(404).json({ error: 'The selected share is no longer available.' });
  }
  const recipient = presence.get(recipientId);
  if (!recipient || Date.now() - recipient.lastSeen > PRESENCE_TTL) {
    return res.status(404).json({ error: 'That user is no longer available.' });
  }

  const message = {
    id: crypto.randomBytes(12).toString('hex'),
    shareId: item.id,
    fileName: item.originalName,
    size: item.size,
    sender: { userId: sender.userId, nickname: sender.nickname, avatar: sender.avatar || null },
    createdAt: Date.now(),
    expiresAt: item.expiresAt,
    passwordRequired: Boolean(item.passwordHash),
    virusCheck: item.virusCheck,
    riskFlags: item.riskFlags,
  };

  const inbox = inboxes.get(recipientId) || [];
  inbox.unshift(message);
  inboxes.set(recipientId, inbox.slice(0, 30));
  return res.status(201).json({ ok: true, queued: true, message });
}));

app.get('/api/inbox', asyncHandler(async (req, res) => {
  const userId = String(req.query.userId || '');
  if (!isValidUserId(userId)) return res.status(400).json({ error: 'Invalid local user id.' });
  const session = getPresenceSession(req, res);
  if (!presenceUser(userId, session)) return res.status(403).json({ error: 'Your local presence session is not active.' });
  const messages = inboxes.get(userId) || [];
  inboxes.delete(userId);
  return res.json({ messages });
}));

app.get('/styles.css', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(STYLES_FILE);
});

app.get('/app.js', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(SCRIPT_FILE);
});

app.use('/assets', express.static(ASSETS_DIR, { maxAge: IS_PRODUCTION ? '7d' : 0 }));

app.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(INDEX_FILE);
});

app.get('/:id', (req, res) => {
  const id = req.params.id;
  if (!/^[A-Za-z0-9]{4,32}$/.test(id)) return res.status(404).send('Not found');
  res.setHeader('Cache-Control', 'no-store');
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
  await Promise.all([
    fsp.mkdir(FILES_DIR, { recursive: true }),
    fsp.mkdir(META_DIR, { recursive: true }),
  ]);

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
      if (typeof item.maxDownloads === 'undefined') item.maxDownloads = 5;
      metadata.set(item.id, item);
      loaded += 1;
    } catch {
      await fsp.rm(path.join(META_DIR, entry.name), { force: true }).catch(() => {});
    }
  }
  console.log(`FileDrop ${VERSION}: loaded ${loaded} active share(s).`);
}

setInterval(() => {
  const now = Date.now();
  const jobs = [];
  for (const item of metadata.values()) {
    if ((item.expiresAt && item.expiresAt <= now) || (item.maxDownloads !== null && item.downloadsUsed >= item.maxDownloads)) {
      jobs.push(deleteShare(item.id));
    }
  }
  if (jobs.length) Promise.allSettled(jobs).catch(() => {});

  for (const [userId, record] of presence) {
    if (now - record.lastSeen > PRESENCE_TTL) {
      presence.delete(userId);
      inboxes.delete(userId);
    }
  }
}, ONE_MINUTE).unref();

setInterval(() => {
  const cutoff = Date.now() - 20 * ONE_MINUTE;
  for (const [key, bucket] of rateBuckets) {
    if (bucket.started < cutoff) rateBuckets.delete(key);
  }
}, 5 * ONE_MINUTE).unref();

loadMetadata()
  .then(() => {
    const server = app.listen(PORT, '0.0.0.0', () => console.log(`FileDrop listening on ${PORT}`));
    server.requestTimeout = 0;
    server.headersTimeout = 130000;
    server.keepAliveTimeout = 120000;
  })
  .catch(error => {
    console.error('Startup failed:', error);
    process.exit(1);
  });
