'use strict';

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 10000);
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;
const MAX_JSON = 512 * 1024;
const MAX_AVATAR_CHARS = 380 * 1024;
const AUTH_TTL = 15 * 60 * 1000;
const PRESENCE_TTL = 10 * 60 * 1000;
const ONLINE_WINDOW = 45 * 1000;
const ONE_MINUTE = 60 * 1000;
const VERSION = 'v1 (0.15)';
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
const presence = new Map();
const inboxes = new Map();
const rateBuckets = new Map();
const shareLocks = new Map();

const EXPIRY_PRESETS = new Set([
  5 * ONE_MINUTE,
  15 * ONE_MINUTE,
  60 * ONE_MINUTE,
  6 * 60 * ONE_MINUTE,
  24 * 60 * ONE_MINUTE,
  3 * 24 * ONE_MINUTE,
  7 * 24 * ONE_MINUTE,
  30 * 24 * ONE_MINUTE,
  null,
]);
const RISKY_EXTENSIONS = new Set([
  '.ade', '.adp', '.app', '.appx', '.bat', '.cab', '.cmd', '.com', '.cpl', '.dll', '.exe', '.hta',
  '.inf', '.ins', '.iqy', '.iso', '.jar', '.js', '.jse', '.lnk', '.msi', '.msp', '.mst', '.ocx',
  '.ps1', '.reg', '.scr', '.sys', '.vbe', '.vbs', '.wsf', '.wsh'
]);
const MIME = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.ico': 'image/x-icon',
};

function now() { return Date.now(); }
function json(res, status, value, headers = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}
function text(res, status, value, headers = {}) {
  const body = Buffer.from(String(value), 'utf8');
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length, ...headers });
  res.end(body);
}
function noContent(res, status = 204, headers = {}) { res.writeHead(status, headers); res.end(); }

function headersForHtml() {
  return {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
  };
}

function createId() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(8);
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
}
async function uniqueId() {
  for (let i = 0; i < 12; i += 1) {
    const id = createId();
    if (!metadata.has(id) && !fs.existsSync(path.join(META_DIR, `${id}.json`))) return id;
  }
  throw new Error('Unable to generate a unique share id.');
}
function safeFileName(value) {
  const cleaned = String(value || 'download')
    .replace(/[\\/\r\n\0]/g, '_')
    .replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, '_')
    .trim();
  return (cleaned || 'download').slice(0, 180);
}
function decodeHeaderValue(value) {
  try { return decodeURIComponent(String(value || '')); } catch { return String(value || ''); }
}
function contentDisposition(name) {
  const safe = safeFileName(name);
  const ascii = safe.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_') || 'download';
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(safe)}`;
}
function normalizeNickname(value) {
  return String(value || '').replace(/[<>\r\n]/g, '').trim().replace(/\s+/g, ' ').slice(0, 32);
}
function isValidUserId(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{12,64}$/.test(value); }
function isSafeDataUrl(value) { return typeof value === 'string' && /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/i.test(value); }
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
  try {
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return payload?.id && Number.isFinite(payload.exp) && payload.exp >= now() ? payload : null;
  } catch { return null; }
}
function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
  }
  return out;
}
function setCookie(res, name, value, maxAgeMs, httpOnly = true) {
  const secure = IS_PRODUCTION ? '; Secure' : '';
  const http = httpOnly ? '; HttpOnly' : '';
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; Max-Age=${Math.floor(maxAgeMs / 1000)}; Path=/; SameSite=Lax${http}${secure}`);
}
function presenceSession(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  let token = cookies.fd_presence;
  if (!token || !/^[A-Za-z0-9_-]{24,80}$/.test(token)) {
    token = crypto.randomBytes(24).toString('base64url');
    setCookie(res, 'fd_presence', token, 30 * 24 * 60 * ONE_MINUTE);
  }
  return token;
}
function rateLimited(req, bucket, max, windowMs) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  const key = `${bucket}:${ip}`;
  const t = now();
  let b = rateBuckets.get(key);
  if (!b || t - b.started >= windowMs) b = { started: t, count: 0 };
  b.count += 1;
  rateBuckets.set(key, b);
  return b.count > max;
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
  if (actual.length !== encoded.length) return false;
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(encoded));
}
function publicBaseUrl(req) { return PUBLIC_BASE_URL || `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`; }
function riskyFlags(name) {
  const ext = path.extname(String(name || '')).toLowerCase();
  return RISKY_EXTENSIONS.has(ext) ? [`Potentially executable file type: ${ext}`] : [];
}
function shareClient(item) {
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
function authorizedFor(item, req) {
  if (!item.passwordHash) return true;
  const cookies = parseCookies(req.headers.cookie);
  const token = readToken(cookies[`fd_auth_${item.id}`]);
  return Boolean(token && token.id === item.id);
}
async function writeMeta(item) {
  const temp = path.join(META_DIR, `${item.id}.json.tmp`);
  const target = path.join(META_DIR, `${item.id}.json`);
  await fsp.writeFile(temp, JSON.stringify(item), 'utf8');
  await fsp.rename(temp, target);
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
async function withShareLock(id, task) {
  const previous = shareLocks.get(id) || Promise.resolve();
  let release;
  const next = new Promise(resolve => { release = resolve; });
  shareLocks.set(id, next);
  await previous;
  try { return await task(); } finally {
    release();
    if (shareLocks.get(id) === next) shareLocks.delete(id);
  }
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
    const s = body?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(s.malicious || 0);
    const suspicious = Number(s.suspicious || 0);
    return {
      status: malicious > 0 || suspicious > 0 ? 'flagged' : 'known-clean',
      provider: 'VirusTotal', malicious, suspicious,
      harmless: Number(s.harmless || 0), undetected: Number(s.undetected || 0),
    };
  } catch { return { status: 'error', provider: 'VirusTotal' }; }
}
async function readBody(req, limit = MAX_JSON) {
  const chunks = [];
  let total = 0;
  return new Promise((resolve, reject) => {
    req.on('data', chunk => {
      total += chunk.length;
      if (total > limit) {
        reject(Object.assign(new Error('Request body is too large.'), { code: 'BODY_TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
    req.on('aborted', () => reject(new Error('Request aborted.')));
  });
}
async function readJson(req) {
  const raw = await readBody(req, MAX_JSON);
  try { return JSON.parse(raw || '{}'); } catch { throw Object.assign(new Error('Invalid JSON.'), { code: 'BAD_JSON' }); }
}
function validateUploadSettings(settings) {
  const maxDownloadsRaw = settings?.maxDownloads;
  const maxDownloads = maxDownloadsRaw === null || maxDownloadsRaw === 'unlimited' || maxDownloadsRaw === ''
    ? null : Number(maxDownloadsRaw);
  if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1 || maxDownloads > 10000)) {
    throw Object.assign(new Error('Download limit must be unlimited or an integer from 1 to 10,000.'), { statusCode: 400 });
  }
  const expiresMs = settings?.expiresMs === null || settings?.expiresMs === '' ? null : Number(settings?.expiresMs);
  const customOk = expiresMs === null || EXPIRY_PRESETS.has(expiresMs) || (Number.isFinite(expiresMs) && expiresMs >= 5 * ONE_MINUTE && expiresMs <= 30 * 24 * 60 * ONE_MINUTE);
  if (!customOk) throw Object.assign(new Error('Unsupported expiry selection.'), { statusCode: 400 });
  const passwordEnabled = Boolean(settings?.passwordEnabled);
  const password = String(settings?.password || '');
  if (passwordEnabled && password.length < 4) throw Object.assign(new Error('Password must contain at least 4 characters.'), { statusCode: 400 });
  const ownerName = normalizeNickname(settings?.ownerName);
  const ownerAvatar = String(settings?.ownerAvatar || '');
  const owner = ownerName ? {
    name: ownerName,
    avatar: isSafeDataUrl(ownerAvatar) && ownerAvatar.length <= MAX_AVATAR_CHARS ? ownerAvatar : null,
  } : null;
  return { maxDownloads, expiresMs, deleteAfterDownload: Boolean(settings?.deleteAfterDownload), passwordEnabled, password, owner };
}
async function parseUploadSettings(req) {
  const encoded = String(req.headers['x-filedrop-settings'] || '');
  if (!encoded) return {};
  let jsonText;
  try { jsonText = Buffer.from(encoded, 'base64url').toString('utf8'); } catch { throw Object.assign(new Error('Invalid upload settings.'), { statusCode: 400 }); }
  try { return JSON.parse(jsonText); } catch { throw Object.assign(new Error('Invalid upload settings.'), { statusCode: 400 }); }
}
async function handleUpload(req, res) {
  if (rateLimited(req, 'upload', 20, 10 * ONE_MINUTE)) return json(res, 429, { error: 'Too many uploads. Please try again later.' });
  const contentLength = Number(req.headers['content-length']);
  if (Number.isFinite(contentLength) && contentLength > MAX_FILE_SIZE) return json(res, 413, { error: 'File is larger than 2 GB.' });

  const rawName = decodeHeaderValue(req.headers['x-file-name']);
  const originalName = safeFileName(rawName);
  const mimetype = String(req.headers['x-file-type'] || 'application/octet-stream').slice(0, 160);
  let settings;
  try { settings = validateUploadSettings(await parseUploadSettings(req)); }
  catch (err) { return json(res, err.statusCode || 400, { error: err.message }); }
  if (!rawName.trim()) return json(res, 400, { error: 'A file name is required.' });

  await fsp.mkdir(FILES_DIR, { recursive: true });
  const tempPath = path.join(FILES_DIR, `.upload-${crypto.randomBytes(18).toString('hex')}.tmp`);
  const out = fs.createWriteStream(tempPath, { flags: 'wx' });
  const hash = crypto.createHash('sha256');
  let size = 0;
  let settled = false;
  const cleanup = async () => { if (!settled) { settled = true; await fsp.rm(tempPath, { force: true }).catch(() => {}); } };

  return new Promise((resolve) => {
    req.on('aborted', async () => { await cleanup(); resolve(); });
    req.on('error', async () => { await cleanup(); if (!res.headersSent) json(res, 400, { error: 'Upload stream failed.' }); resolve(); });
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_FILE_SIZE) {
        req.destroy();
        out.destroy();
        cleanup().then(() => { if (!res.headersSent) json(res, 413, { error: 'File is larger than 2 GB.' }); resolve(); });
        return;
      }
      hash.update(chunk);
      if (!out.write(chunk)) req.pause();
    });
    out.on('drain', () => req.resume());
    req.on('end', async () => {
      if (settled) return;
      out.end();
    });
    out.on('finish', async () => {
      if (settled) return;
      try {
        if (size <= 0) throw Object.assign(new Error('The file is empty.'), { statusCode: 400 });
        const id = await uniqueId();
        const finalPath = path.join(FILES_DIR, `${id}.bin`);
        await fsp.rename(tempPath, finalPath);
        const digest = hash.digest('hex');
        const virusCheck = await lookupVirusTotal(digest);
        const item = {
          id,
          originalName,
          size,
          mimetype,
          createdAt: now(),
          expiresAt: settings.expiresMs === null ? null : now() + settings.expiresMs,
          deleteAfterDownload: settings.deleteAfterDownload,
          maxDownloads: settings.maxDownloads,
          downloadsUsed: 0,
          passwordHash: settings.passwordEnabled ? await hashPassword(settings.password) : null,
          owner: settings.owner,
          sha256: digest,
          virusCheck,
          riskFlags: riskyFlags(originalName),
        };
        metadata.set(id, item);
        await writeMeta(item);
        settled = true;
        const payload = { ...shareClient(item), shareUrl: `${publicBaseUrl(req)}/${id}` };
        json(res, 201, payload);
      } catch (err) {
        await fsp.rm(tempPath, { force: true }).catch(() => {});
        settled = true;
        json(res, err.statusCode || 500, { error: err.statusCode ? err.message : 'Unable to create the share.' });
      }
      resolve();
    });
    out.on('error', async err => {
      await cleanup();
      if (!res.headersSent) json(res, 500, { error: `Upload failed: ${err.message}` });
      resolve();
    });
  });
}

function touchPresence(userId, data, session) {
  const previous = presence.get(userId);
  const record = { userId, nickname: data.nickname, avatar: data.avatar || null, visible: data.visible !== false, lastSeen: now(), session, firstSeen: previous?.firstSeen || now() };
  presence.set(userId, record);
}
function publicPresence(record) {
  return { userId: record.userId, nickname: record.nickname, avatar: record.avatar || null, online: now() - record.lastSeen <= ONLINE_WINDOW, lastSeen: record.lastSeen };
}
function validShareId(id) { return /^[A-Za-z0-9]{4,32}$/.test(id); }

async function handleApi(req, res, url) {
  if (url.pathname === '/api/config' && req.method === 'GET') return json(res, 200, { version: VERSION, maxFileBytes: MAX_FILE_SIZE, virusTotalConfigured: Boolean(VT_API_KEY) });

  const shareMatch = url.pathname.match(/^\/api\/share\/([A-Za-z0-9]{4,32})$/);
  if (shareMatch && req.method === 'GET') {
    const item = metadata.get(shareMatch[1]);
    if (!item || item.pendingDelete || (item.expiresAt && item.expiresAt <= now())) {
      if (item) await deleteShare(item.id);
      return json(res, 404, { error: 'This link is no longer available.' });
    }
    if (item.maxDownloads !== null && item.downloadsUsed >= item.maxDownloads) {
      await deleteShare(item.id);
      return json(res, 410, { error: 'This file has reached its download limit.' });
    }
    return json(res, 200, shareClient(item));
  }

  const unlockMatch = url.pathname.match(/^\/api\/unlock\/([A-Za-z0-9]{4,32})$/);
  if (unlockMatch && req.method === 'POST') {
    if (rateLimited(req, 'unlock', 30, 10 * ONE_MINUTE)) return json(res, 429, { error: 'Too many password attempts. Please try again later.' });
    let body; try { body = await readJson(req); } catch (err) { return json(res, err.code === 'BODY_TOO_LARGE' ? 413 : 400, { error: err.message }); }
    const item = metadata.get(unlockMatch[1]);
    if (!item || (item.expiresAt && item.expiresAt <= now())) { if (item) await deleteShare(item.id); return json(res, 404, { error: 'This link is no longer available.' }); }
    if (!item.passwordHash) return json(res, 400, { error: 'This file is not password protected.' });
    if (!(await verifyPassword(String(body.password || ''), item.passwordHash))) return json(res, 401, { error: 'Incorrect password.' });
    const token = signToken({ id: item.id, exp: now() + AUTH_TTL });
    setCookie(res, `fd_auth_${item.id}`, token, AUTH_TTL, true);
    return json(res, 200, { ok: true });
  }

  const downloadMatch = url.pathname.match(/^\/api\/download\/([A-Za-z0-9]{4,32})$/);
  if (downloadMatch && req.method === 'GET') {
    const id = downloadMatch[1];
    let item;
    try {
      item = await withShareLock(id, async () => {
        const current = metadata.get(id);
        if (!current || current.pendingDelete || (current.expiresAt && current.expiresAt <= now())) { if (current && !current.pendingDelete) await deleteShare(id); throw Object.assign(new Error('This link is no longer available.'), { statusCode: 410 }); }
        if (!authorizedFor(current, req)) throw Object.assign(new Error('Password required.'), { statusCode: 401 });
        if (current.maxDownloads !== null && current.downloadsUsed >= current.maxDownloads) { await deleteShare(id); throw Object.assign(new Error('This file has reached its download limit.'), { statusCode: 410 }); }
        const filePath = path.join(FILES_DIR, `${id}.bin`);
        try { await fsp.access(filePath, fs.constants.R_OK); } catch { await deleteShare(id); throw Object.assign(new Error('The file could not be found on storage.'), { statusCode: 404 }); }
        current.downloadsUsed += 1;
        current.pendingDelete = Boolean(current.deleteAfterDownload || (current.maxDownloads !== null && current.downloadsUsed >= current.maxDownloads));
        await writeMeta(current);
        return current;
      });
    } catch (err) { return json(res, err.statusCode || 500, { error: err.message }); }

    const filePath = path.join(FILES_DIR, `${id}.bin`);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': contentDisposition(item.originalName),
      'Content-Length': String(item.size),
      'Cache-Control': 'private, no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff',
    });
    const stream = fs.createReadStream(filePath);
    let finished = false;
    const rollback = async () => {
      if (finished) return;
      finished = true;
      const current = metadata.get(id);
      if (current) { current.downloadsUsed = Math.max(0, current.downloadsUsed - 1); current.pendingDelete = false; await writeMeta(current).catch(() => {}); }
    };
    stream.on('error', async () => { await rollback(); if (!res.headersSent) json(res, 500, { error: 'Unable to read the file.' }); else res.destroy(); });
    res.on('finish', async () => {
      if (finished) return;
      finished = true;
      if (item.pendingDelete) await deleteShare(id);
    });
    res.on('close', async () => { if (!res.writableFinished) await rollback(); });
    return stream.pipe(res);
  }

  if (url.pathname === '/api/presence/heartbeat' && req.method === 'POST') {
    if (rateLimited(req, 'presence', 120, 10 * ONE_MINUTE)) return json(res, 429, { error: 'Presence rate limit reached.' });
    let body; try { body = await readJson(req); } catch (err) { return json(res, err.code === 'BODY_TOO_LARGE' ? 413 : 400, { error: err.message }); }
    const userId = String(body.userId || '');
    const nickname = normalizeNickname(body.nickname);
    const avatar = String(body.avatar || '');
    if (!isValidUserId(userId)) return json(res, 400, { error: 'Invalid local user id.' });
    if (nickname.length < 2) return json(res, 400, { error: 'Nickname must contain at least 2 characters.' });
    if (avatar && (!isSafeDataUrl(avatar) || avatar.length > MAX_AVATAR_CHARS)) return json(res, 400, { error: 'Invalid avatar.' });
    const session = presenceSession(req, res);
    touchPresence(userId, { nickname, avatar, visible: body.visible !== false }, session);
    return json(res, 200, { ok: true, online: true, serverTime: now() });
  }

  if (url.pathname === '/api/people' && req.method === 'GET') {
    const q = String(url.searchParams.get('q') || '').trim().toLowerCase().slice(0, 32);
    const results = [];
    for (const [userId, record] of presence) {
      if (now() - record.lastSeen > PRESENCE_TTL) { presence.delete(userId); inboxes.delete(userId); continue; }
      if (!record.visible) continue;
      if (q && !record.nickname.toLowerCase().includes(q)) continue;
      results.push(publicPresence(record));
    }
    results.sort((a, b) => Number(b.online) - Number(a.online) || a.nickname.localeCompare(b.nickname));
    return json(res, 200, { people: results.slice(0, 50) });
  }

  if (url.pathname === '/api/drop' && req.method === 'POST') {
    if (rateLimited(req, 'drop', 60, 10 * ONE_MINUTE)) return json(res, 429, { error: 'Too many drops. Please try again later.' });
    let body; try { body = await readJson(req); } catch (err) { return json(res, err.code === 'BODY_TOO_LARGE' ? 413 : 400, { error: err.message }); }
    const senderId = String(body.senderId || '');
    const recipientId = String(body.recipientId || '');
    const shareId = String(body.shareId || '');
    if (!isValidUserId(senderId) || !isValidUserId(recipientId) || !validShareId(shareId)) return json(res, 400, { error: 'Invalid drop request.' });
    const session = presenceSession(req, res);
    const sender = presence.get(senderId);
    if (!sender || sender.session !== session) return json(res, 403, { error: 'Your local presence session is not active.' });
    const item = metadata.get(shareId);
    if (!item || (item.expiresAt && item.expiresAt <= now())) { if (item) await deleteShare(item.id); return json(res, 404, { error: 'The selected share is no longer available.' }); }
    const recipient = presence.get(recipientId);
    if (!recipient || now() - recipient.lastSeen > PRESENCE_TTL) return json(res, 404, { error: 'That user is no longer available.' });
    const message = {
      id: crypto.randomBytes(12).toString('hex'), shareId: item.id, fileName: item.originalName, size: item.size,
      sender: { userId: sender.userId, nickname: sender.nickname, avatar: sender.avatar || null }, createdAt: now(),
      expiresAt: item.expiresAt, passwordRequired: Boolean(item.passwordHash), virusCheck: item.virusCheck, riskFlags: item.riskFlags,
    };
    const inbox = inboxes.get(recipientId) || [];
    inbox.unshift(message); inboxes.set(recipientId, inbox.slice(0, 30));
    return json(res, 201, { ok: true, queued: true, message });
  }

  if (url.pathname === '/api/inbox' && req.method === 'GET') {
    const userId = String(url.searchParams.get('userId') || '');
    if (!isValidUserId(userId)) return json(res, 400, { error: 'Invalid local user id.' });
    const session = presenceSession(req, res);
    const owner = presence.get(userId);
    if (!owner || owner.session !== session) return json(res, 403, { error: 'Your local presence session is not active.' });
    const messages = inboxes.get(userId) || [];
    inboxes.delete(userId);
    return json(res, 200, { messages });
  }

  return json(res, 404, { error: 'API route not found.' });
}

async function serveStatic(req, res, url) {
  let filePath = null;
  if (url.pathname === '/') filePath = INDEX_FILE;
  else if (url.pathname === '/styles.css') filePath = STYLES_FILE;
  else if (url.pathname === '/app.js') filePath = SCRIPT_FILE;
  else if (url.pathname.startsWith('/assets/')) {
    const relative = path.normalize(url.pathname.slice('/assets/'.length));
    if (relative.startsWith('..') || path.isAbsolute(relative)) return text(res, 400, 'Bad path');
    filePath = path.join(ASSETS_DIR, relative);
  } else if (validShareId(url.pathname.slice(1))) filePath = INDEX_FILE;
  else return text(res, 404, 'Not found');

  try {
    const stat = await fsp.stat(filePath);
    if (!stat.isFile()) return text(res, 404, 'Not found');
    const ext = path.extname(filePath).toLowerCase();
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Length': stat.size, 'X-Content-Type-Options': 'nosniff' };
    if (filePath === INDEX_FILE) Object.assign(headers, headersForHtml());
    if (req.method === 'HEAD') { res.writeHead(200, headers); return res.end(); }
    res.writeHead(200, headers);
    fs.createReadStream(filePath).on('error', () => { if (!res.headersSent) text(res, 500, 'Read error'); else res.destroy(); }).pipe(res);
  } catch { return text(res, 404, 'Not found'); }
}

async function router(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (req.method === 'OPTIONS') return noContent(res, 204, { Allow: 'GET,POST,HEAD,OPTIONS' });
  if (url.pathname === '/healthz' && req.method === 'GET') return json(res, 200, { ok: true, service: 'filedrop', version: VERSION });
  if (url.pathname === '/api/upload' && req.method === 'POST') return handleUpload(req, res);
  if (url.pathname.startsWith('/api/')) return handleApi(req, res, url);
  return serveStatic(req, res, url);
}

async function loadMetadata() {
  await Promise.all([fsp.mkdir(FILES_DIR, { recursive: true }), fsp.mkdir(META_DIR, { recursive: true })]);
  for (const entry of await fsp.readdir(META_DIR, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
    try {
      const item = JSON.parse(await fsp.readFile(path.join(META_DIR, entry.name), 'utf8'));
      if (!item?.id || !item?.originalName) continue;
      if (item.pendingDelete || (item.expiresAt && item.expiresAt <= now())) { await deleteShare(item.id); continue; }
      await fsp.access(path.join(FILES_DIR, `${item.id}.bin`), fs.constants.R_OK);
      metadata.set(item.id, item);
    } catch { await fsp.rm(path.join(META_DIR, entry.name), { force: true }).catch(() => {}); }
  }
  console.log(`FileDrop ${VERSION}: loaded ${metadata.size} active share(s).`);
}

setInterval(() => {
  const t = now();
  for (const item of metadata.values()) {
    if ((item.expiresAt && item.expiresAt <= t) || (item.maxDownloads !== null && item.downloadsUsed >= item.maxDownloads)) {
      deleteShare(item.id).catch(() => {});
    }
  }
  for (const [userId, record] of presence) {
    if (t - record.lastSeen > PRESENCE_TTL) { presence.delete(userId); inboxes.delete(userId); }
  }
}, ONE_MINUTE).unref();
setInterval(() => {
  const cutoff = now() - 20 * ONE_MINUTE;
  for (const [key, bucket] of rateBuckets) if (bucket.started < cutoff) rateBuckets.delete(key);
}, 5 * ONE_MINUTE).unref();

loadMetadata().then(() => {
  const server = http.createServer((req, res) => {
    req.setTimeout(0);
    router(req, res).catch(err => {
      console.error(err);
      if (!res.headersSent) json(res, 500, { error: 'Server error.' });
      else res.destroy();
    });
  });
  server.requestTimeout = 0;
  server.headersTimeout = 120000;
  server.keepAliveTimeout = 120000;
  server.listen(PORT, '0.0.0.0', () => console.log(`FileDrop listening on ${PORT}`));
}).catch(error => {
  console.error('Startup failed:', error);
  process.exit(1);
});
