const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
app.use(express.json({ limit: process.env.JSON_LIMIT || '1mb' }));

const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = Number(process.env.PORT || 3000);
const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'data');
const SECRETS_DIR = path.join(ROOT, 'secrets');
const DB_PATH = path.join(DATA_DIR, 'parking.sqlite3');
const DB_KEY_PATH = path.join(SECRETS_DIR, 'db-access.key');
const APP_BASE_URL = String(process.env.APP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_TTL_SECONDS = Math.max(1, Number(process.env.SESSION_TTL_SECONDS || 60 * 60 * 12));
const RATE_LIMIT_WINDOW_MS = Math.max(1000, Number(process.env.RATE_LIMIT_WINDOW_MS || 10 * 60 * 1000));
const AUTH_RATE_LIMIT_MAX = Math.max(1, Number(process.env.AUTH_RATE_LIMIT_MAX || 10));
const ADMIN_RATE_LIMIT_MAX = Math.max(1, Number(process.env.ADMIN_RATE_LIMIT_MAX || 30));
const FLOOR_IMAGE_MAX_BYTES = Math.max(1024, Number(process.env.FLOOR_IMAGE_MAX_BYTES || 5 * 1024 * 1024));
const BOOTSTRAP_TOKEN = String(process.env.BOOTSTRAP_TOKEN || '').trim();

const rateLimitBuckets = new Map();
const oauthStates = new Map();
const oidcCache = new Map();

function logEvent(event, fields = {}) {
  const payload = {
    ts: new Date().toISOString(),
    event,
    ...fields
  };
  console.log(JSON.stringify(payload));
}

function newErrorId(prefix = 'ERR') {
  const ts = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const rnd = crypto.randomBytes(3).toString('hex');
  return `${prefix}-${ts}-${rnd}`;
}

function requestId() {
  return crypto.randomBytes(8).toString('hex');
}

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true, mode: 0o700 });
}

function sha(v) {
  return crypto.createHash('sha256').update(v).digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

function addDays(dateIso, days) {
  const dt = new Date(`${dateIso}T00:00:00Z`);
  dt.setUTCDate(dt.getUTCDate() + days);
  return dt.toISOString().slice(0, 10);
}

function addSecondsToIso(iso, seconds) {
  return new Date(Date.parse(iso) + seconds * 1000).toISOString();
}

function randomSimplePassword(len = 6) {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function normText(v, max = 120) {
  return String(v ?? '').trim().slice(0, max);
}

function validUserId(v) {
  return /^[a-zA-Z0-9._-]{1,64}$/.test(v);
}

function isIsoDate(v) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(v || ''));
}

function isHttpUrl(v) {
  return /^https?:\/\//i.test(String(v || ''));
}

function asPositiveInt(v, label) {
  const out = Number(v);
  if (!Number.isInteger(out) || out <= 0) throw new Error(`${label} must be positive integer`);
  return out;
}

function asNumberOrNull(v, label) {
  if (v === null || v === undefined || v === '') return null;
  const out = Number(v);
  if (!Number.isFinite(out)) throw new Error(`${label} must be a number`);
  return out;
}

function asOptionalEnum(v, label, allowed, fallback = null) {
  if (v === null || v === undefined || v === '') return fallback;
  const out = String(v);
  if (!allowed.includes(out)) throw new Error(`${label} must be one of: ${allowed.join(', ')}`);
  return out;
}

function requireIsoDate(v, label) {
  const out = String(v || '');
  if (!isIsoDate(out)) throw new Error(`${label} must be YYYY-MM-DD`);
  return out;
}

function requirePassword(v, label = 'password') {
  const out = String(v || '');
  if (out.length < 8) throw new Error(`${label} must be at least 8 characters`);
  return out;
}

function requireBoolean(v) {
  return !!v;
}

function requireJsonObject(v, label = 'payload') {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error(`${label} must be object`);
  return v;
}

function detectImageExtension(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return '.png';
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return '.jpg';
  if (buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return '.webp';
  return null;
}

function mimeFromImageExtension(ext) {
  if (ext === '.png') return 'image/png';
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  if (ext === '.webp') return 'image/webp';
  return null;
}

function normalizeFloorImageData(imageData) {
  if (!imageData || typeof imageData !== 'string') return null;
  const match = imageData.match(/^data:(image\/(png|jpeg|jpg|webp));base64,(.+)$/i);
  if (!match) throw new Error('Invalid floor image format');
  const raw = Buffer.from(match[3], 'base64');
  if (!raw.length || raw.length > FLOOR_IMAGE_MAX_BYTES) throw new Error('Floor image size is invalid');
  const detectedExt = detectImageExtension(raw);
  if (!detectedExt) throw new Error('Unsupported floor image content');
  const mime = mimeFromImageExtension(detectedExt);
  return `data:${mime};base64,${raw.toString('base64')}`;
}

function localFloorImageToDataUrl(imagePath) {
  const clean = String(imagePath || '').trim();
  if (!clean) return null;
  if (/^data:image\//i.test(clean)) return clean;
  if (/^https?:\/\//i.test(clean)) return clean;
  const rel = clean.replace(/^[.][\\/]/, '').replace(/^[/\\]+/, '');
  const abs = path.resolve(ROOT, rel);
  if (!abs.startsWith(ROOT) || !fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
  const raw = fs.readFileSync(abs);
  if (!raw.length || raw.length > FLOOR_IMAGE_MAX_BYTES) return null;
  const ext = detectImageExtension(raw);
  const mime = mimeFromImageExtension(ext);
  if (!mime) return null;
  return `data:${mime};base64,${raw.toString('base64')}`;
}

function floorImageValue(row) {
  return row?.image_data || row?.image_path || null;
}

function getMeta(key, fallback = null) {
  const row = db.prepare('SELECT value FROM meta WHERE key = ?').get(key);
  return row ? row.value : fallback;
}

function setMeta(key, value) {
  db.prepare('INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)').run(key, String(value));
}

function isSsoEnabled() {
  return getMeta('sso_enabled', '0') === '1';
}

function getOrCreateDbAccessKey(firstRun) {
  ensureDir(SECRETS_DIR);
  if (fs.existsSync(DB_KEY_PATH)) return fs.readFileSync(DB_KEY_PATH, 'utf8').trim();
  if (!firstRun) throw new Error('DB key missing while DB exists. Refusing to regenerate key.');
  const key = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(DB_KEY_PATH, key, { mode: 0o600 });
  return key;
}

function cryptoKey() {
  if (!fs.existsSync(DB_KEY_PATH)) throw new Error('DB access key file is required');
  const baseKey = fs.readFileSync(DB_KEY_PATH, 'utf8').trim();
  if (!baseKey) throw new Error('DB access key file is empty');
  return crypto.createHash('sha256').update(baseKey).digest();
}

function encryptSecret(plain = '') {
  const text = String(plain || '');
  if (!text) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', cryptoKey(), iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${enc.toString('base64')}`;
}

function decryptSecret(blob = '') {
  const parts = String(blob || '').split('.');
  if (parts.length !== 3) return '';
  try {
    const iv = Buffer.from(parts[0], 'base64');
    const tag = Buffer.from(parts[1], 'base64');
    const enc = Buffer.from(parts[2], 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', cryptoKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

function ssoSettings() {
  return {
    tenantId: getMeta('sso_tenant_id', 'common'),
    clientId: getMeta('sso_client_id', ''),
    clientSecretEncrypted: getMeta('sso_client_secret_enc', ''),
    redirectUri: getMeta('sso_redirect_uri', `${APP_BASE_URL}/api/auth/microsoft/callback`)
  };
}

function isSsoConfigured() {
  const s = ssoSettings();
  return Boolean(s.clientId && s.clientSecretEncrypted && s.redirectUri);
}

function b64urlJsonDecode(part) {
  const b64 = String(part || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
}

function b64urlBytesDecode(part) {
  const b64 = String(part || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function sanitizeUserIdFromEmail(emailOrName = '') {
  const base = String(emailOrName || '')
    .toLowerCase()
    .replace(/@.*/, '')
    .replace(/[^a-z0-9._-]/g, '.')
    .replace(/\.+/g, '.')
    .replace(/^\.|\.$/g, '');
  return (base || 'user').slice(0, 50);
}

function findUniqueUserId(base) {
  let candidate = base;
  let i = 1;
  while (db.prepare('SELECT 1 FROM users WHERE username = ?').get(candidate)) {
    candidate = `${base}.${i++}`.slice(0, 64);
  }
  return candidate;
}

function hasColumn(database, table, column) {
  return database.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
}

function migrate(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      is_builtin_admin INTEGER NOT NULL DEFAULT 0,
      auth_provider TEXT,
      provider_subject TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      revoked_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS floors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      image_path TEXT,
      image_data TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS spaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      floor_id INTEGER NOT NULL,
      space_number TEXT NOT NULL,
      x REAL,
      y REAL,
      w REAL,
      h REAL,
      dir TEXT,
      map_x REAL,
      map_y REAL,
      map_zoom REAL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (floor_id) REFERENCES floors(id) ON DELETE CASCADE,
      UNIQUE (floor_id, space_number)
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      floor_id INTEGER NOT NULL,
      space_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      created_by_user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (floor_id) REFERENCES floors(id) ON DELETE CASCADE,
      FOREIGN KEY (space_id) REFERENCES spaces(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  const extraCols = [
    ['x', 'REAL'],
    ['y', 'REAL'],
    ['w', 'REAL'],
    ['h', 'REAL'],
    ['dir', 'TEXT'],
    ['map_x', 'REAL'],
    ['map_y', 'REAL'],
    ['map_zoom', 'REAL']
  ];
  for (const [name, type] of extraCols) {
    if (!hasColumn(database, 'spaces', name)) database.exec(`ALTER TABLE spaces ADD COLUMN ${name} ${type}`);
  }

  if (!hasColumn(database, 'users', 'full_name')) database.exec('ALTER TABLE users ADD COLUMN full_name TEXT');
  if (!hasColumn(database, 'users', 'auth_provider')) database.exec('ALTER TABLE users ADD COLUMN auth_provider TEXT');
  if (!hasColumn(database, 'users', 'provider_subject')) database.exec('ALTER TABLE users ADD COLUMN provider_subject TEXT');
  if (!hasColumn(database, 'floors', 'image_data')) database.exec('ALTER TABLE floors ADD COLUMN image_data TEXT');
  database.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_provider_subject ON users(auth_provider, provider_subject) WHERE provider_subject IS NOT NULL');
  database.exec("UPDATE users SET full_name = COALESCE(NULLIF(full_name, ''), username)");
  database.exec('CREATE INDEX IF NOT EXISTS ix_sessions_token_hash ON sessions(token_hash)');
  database.exec('CREATE INDEX IF NOT EXISTS ix_sessions_user_id ON sessions(user_id)');

  const legacyFloors = database.prepare('SELECT id, image_path, image_data FROM floors').all();
  for (const floor of legacyFloors) {
    if (floor.image_data || !floor.image_path) continue;
    const asDataUrl = localFloorImageToDataUrl(floor.image_path);
    if (!asDataUrl) continue;
    database.prepare('UPDATE floors SET image_data = ?, image_path = NULL WHERE id = ?').run(asDataUrl, floor.id);
  }
}

function openDbStrict() {
  ensureDir(DATA_DIR);
  const dbExists = fs.existsSync(DB_PATH);
  const key = getOrCreateDbAccessKey(!dbExists);
  const database = new Database(DB_PATH, { fileMustExist: dbExists });
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');
  database.pragma('busy_timeout = 5000');
  migrate(database);

  const row = database.prepare('SELECT value FROM meta WHERE key = ?').get('db_key_hash');
  if (!row) {
    database.prepare('INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)').run('db_key_hash', sha(key));
  } else if (row.value !== sha(key)) {
    throw new Error('Database authorization failed (key mismatch). Not creating/overwriting DB.');
  }

  return database;
}

const db = openDbStrict();

function needsBootstrap() {
  return db.prepare('SELECT COUNT(*) c FROM users').get().c === 0;
}

function cleanupAuthArtifacts() {
  const now = nowIso();
  db.prepare('DELETE FROM sessions WHERE revoked_at IS NOT NULL OR expires_at <= ?').run(now);
  for (const [state, meta] of oauthStates.entries()) {
    if (Date.now() - meta.createdAt > 10 * 60 * 1000) oauthStates.delete(state);
  }
}

function revokeSessionsForUser(userId) {
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(nowIso(), userId);
}

function issueToken(user) {
  cleanupAuthArtifacts();
  const token = crypto.randomBytes(32).toString('base64url');
  const createdAt = nowIso();
  const expiresAt = addSecondsToIso(createdAt, SESSION_TTL_SECONDS);
  db.prepare(`
    INSERT INTO sessions(token_hash, user_id, created_at, expires_at, last_seen_at, revoked_at)
    VALUES (?, ?, ?, ?, ?, NULL)
  `).run(sha(token), user.id, createdAt, expiresAt, createdAt);
  return token;
}

function readSession(token) {
  if (!token) return null;
  cleanupAuthArtifacts();
  const row = db.prepare(`
    SELECT s.id as session_id, s.user_id, s.expires_at, u.username, u.full_name, u.is_admin, u.is_builtin_admin, u.auth_provider
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?
  `).get(sha(token), nowIso());
  if (!row) return null;
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(nowIso(), row.session_id);
  return {
    sessionId: row.session_id,
    userId: row.user_id,
    username: row.username,
    fullName: row.full_name,
    isAdmin: !!row.is_admin,
    isBuiltinAdmin: !!row.is_builtin_admin,
    authProvider: row.auth_provider || null,
    expiresAt: row.expires_at
  };
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '').trim();
  const session = readSession(token);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  req.auth = session;
  req.authToken = token;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.auth.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

function overlaps(startA, endA, startB, endB) {
  return startA <= endB && startB <= endA;
}

function suggestSpotLayout(index) {
  if (index < 13) return { x: 18 + index * 93, y: 160, w: 70, h: 170, dir: 'down' };
  if (index < 20) return { x: 550 + (index - 13) * 88, y: 485, w: 66, h: 165, dir: 'up' };
  const i = index - 20;
  const col = i % 10;
  const row = Math.floor(i / 10);
  return { x: 18 + col * 93, y: 160 + row * 210, w: 70, h: 170, dir: row % 2 === 0 ? 'down' : 'up' };
}

function bookingForDate(spaceId, dateIso) {
  return db.prepare(`
    SELECT b.*, u.full_name as full_name FROM bookings b
    JOIN users u ON u.id = b.user_id
    WHERE b.space_id = ? AND b.start_date <= date(?) AND date(?) <= b.end_date
    ORDER BY b.id DESC LIMIT 1
  `).get(spaceId, `${dateIso}T12:00:00Z`, `${dateIso}T12:00:00Z`);
}

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown')
    .split(',')[0]
    .trim();
}

app.use((req, res, next) => {
  req.requestId = requestId();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://login.microsoftonline.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  next();
});

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logEvent('http_request', {
      requestId: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      ip: clientIp(req)
    });
  });
  next();
});

function consumeRateLimit(key, max, windowMs) {
  const now = Date.now();
  const row = rateLimitBuckets.get(key);
  if (!row || row.resetAt <= now) {
    rateLimitBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: max - 1, resetAt: now + windowMs };
  }
  if (row.count >= max) return { allowed: false, remaining: 0, resetAt: row.resetAt };
  row.count += 1;
  return { allowed: true, remaining: max - row.count, resetAt: row.resetAt };
}

function rateLimit(name, max, windowMs) {
  return (req, res, next) => {
    const result = consumeRateLimit(`${name}:${clientIp(req)}`, max, windowMs);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(result.remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));
    if (!result.allowed) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000))));
      return res.status(429).json({ error: 'Too many requests' });
    }
    next();
  };
}

function isLoopbackRequest(req) {
  const ip = clientIp(req).replace(/^::ffff:/, '');
  return ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
}

function canBootstrap(req) {
  if (!needsBootstrap()) return false;
  if (BOOTSTRAP_TOKEN) {
    const supplied = normText(req.headers['x-bootstrap-token'] || req.body?.bootstrapToken || '', 256);
    if (!supplied) return false;
    return crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(BOOTSTRAP_TOKEN));
  }
  if (NODE_ENV === 'production') return isLoopbackRequest(req);
  return true;
}

function oidcTenantBase(tenantId) {
  return `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}`;
}

async function getOidcConfig(tenantId) {
  const cacheKey = `cfg:${tenantId}`;
  const cached = oidcCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const url = `${oidcTenantBase(tenantId)}/v2.0/.well-known/openid-configuration`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error('Failed to load OIDC configuration');
  const json = await resp.json();
  oidcCache.set(cacheKey, { value: json, expiresAt: Date.now() + 60 * 60 * 1000 });
  return json;
}

async function getOidcJwks(jwksUri) {
  const cacheKey = `jwks:${jwksUri}`;
  const cached = oidcCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const resp = await fetch(jwksUri);
  if (!resp.ok) throw new Error('Failed to load JWKS');
  const json = await resp.json();
  oidcCache.set(cacheKey, { value: json, expiresAt: Date.now() + 60 * 60 * 1000 });
  return json;
}

function expectedIssuers(configIssuer, claims) {
  const issuers = new Set([configIssuer]);
  if (configIssuer.includes('{tenantid}') && claims.tid) issuers.add(configIssuer.replace('{tenantid}', claims.tid));
  return issuers;
}

async function verifyMicrosoftIdToken(idToken, expectedNonce, cfg) {
  const [headerPart, payloadPart, signaturePart] = String(idToken || '').split('.');
  if (!headerPart || !payloadPart || !signaturePart) throw new Error('Malformed id_token');
  const header = b64urlJsonDecode(headerPart);
  const claims = b64urlJsonDecode(payloadPart);
  if (header.alg !== 'RS256') throw new Error('Unsupported id_token algorithm');
  if (!header.kid) throw new Error('Missing key id');

  const oidc = await getOidcConfig(cfg.tenantId);
  const jwks = await getOidcJwks(oidc.jwks_uri);
  const jwk = Array.isArray(jwks.keys) ? jwks.keys.find((k) => k.kid === header.kid) : null;
  if (!jwk) throw new Error('Signing key not found');

  const key = await crypto.webcrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const data = Buffer.from(`${headerPart}.${payloadPart}`);
  const signature = b64urlBytesDecode(signaturePart);
  const valid = await crypto.webcrypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
  if (!valid) throw new Error('Invalid token signature');

  const now = Math.floor(Date.now() / 1000);
  if (!claims.exp || claims.exp <= now) throw new Error('Token expired');
  if (claims.nbf && claims.nbf > now + 60) throw new Error('Token not yet valid');
  if (claims.aud !== cfg.clientId) throw new Error('Token audience mismatch');

  const issuers = expectedIssuers(oidc.issuer, claims);
  if (!issuers.has(claims.iss)) throw new Error('Token issuer mismatch');
  if (expectedNonce && claims.nonce !== expectedNonce) throw new Error('Token nonce mismatch');
  return claims;
}

function validateSsoPayload(payload) {
  const p = requireJsonObject(payload);
  const tenantId = normText(p.tenantId || 'common', 120) || 'common';
  const clientId = normText(p.clientId || '', 256);
  const redirectUri = normText(p.redirectUri || `${APP_BASE_URL}/api/auth/microsoft/callback`, 512);
  const enabled = requireBoolean(p.enabled);
  if (redirectUri && !isHttpUrl(redirectUri)) throw new Error('redirectUri must be http(s) URL');
  return {
    tenantId,
    clientId,
    redirectUri,
    enabled,
    clientSecret: Object.prototype.hasOwnProperty.call(p, 'clientSecret') ? String(p.clientSecret || '').trim() : null
  };
}

function validateUserCreatePayload(payload) {
  const p = requireJsonObject(payload);
  const username = normText(p.username, 64);
  const fullName = normText(p.fullName || p.username, 120);
  const password = requirePassword(p.password, 'password');
  if (!username) throw new Error('username required');
  if (!validUserId(username)) throw new Error('Invalid user id format');
  return { username, fullName: fullName || username, password, isAdmin: !!p.isAdmin };
}

function validateUserPatchPayload(payload, existingUser) {
  const p = requireJsonObject(payload);
  const fullName = normText(p.fullName ?? existingUser.full_name ?? existingUser.username, 120);
  return { fullName: fullName || existingUser.username, isAdmin: !!p.isAdmin };
}

function validateFloorPayload(payload, existingFloor = null) {
  const p = requireJsonObject(payload);
  const name = normText(p.name ?? existingFloor?.name, 120);
  if (!name) throw new Error('name required');
  const imageData = p.imageData ? String(p.imageData) : '';
  const clearImage = !!p.clearImage;
  return { name, imageData, clearImage };
}

function validateSpacePayload(payload, existingSpace = null) {
  const p = requireJsonObject(payload);
  const floorId = asPositiveInt(p.floorId ?? existingSpace?.floor_id, 'floorId');
  const spaceNumber = normText(p.spaceNumber ?? existingSpace?.space_number, 32);
  if (!spaceNumber) throw new Error('spaceNumber required');
  return {
    floorId,
    spaceNumber,
    x: asNumberOrNull(p.x ?? existingSpace?.x, 'x'),
    y: asNumberOrNull(p.y ?? existingSpace?.y, 'y'),
    w: asNumberOrNull(p.w ?? existingSpace?.w, 'w'),
    h: asNumberOrNull(p.h ?? existingSpace?.h, 'h'),
    dir: asOptionalEnum(p.dir ?? existingSpace?.dir, 'dir', ['up', 'down', 'left', 'right'], existingSpace?.dir ?? null),
    mapX: asNumberOrNull(p.mapX ?? existingSpace?.map_x, 'mapX'),
    mapY: asNumberOrNull(p.mapY ?? existingSpace?.map_y, 'mapY'),
    mapZoom: asNumberOrNull(p.mapZoom ?? existingSpace?.map_zoom, 'mapZoom')
  };
}

function validateBookingPayload(payload, authCtx) {
  const p = requireJsonObject(payload);
  const floorId = asPositiveInt(p.floorId, 'floorId');
  const spaceId = asPositiveInt(p.spaceId, 'spaceId');
  const startDate = requireIsoDate(p.startDate, 'startDate');
  const endDate = requireIsoDate(p.endDate, 'endDate');
  if (startDate > endDate) throw new Error('Invalid date range');
  const userId = authCtx.isAdmin ? asPositiveInt(p.userId || authCtx.userId, 'userId') : authCtx.userId;
  return { floorId, spaceId, startDate, endDate, userId };
}

function validateReleasePayload(payload) {
  const p = requireJsonObject(payload);
  const spaceId = asPositiveInt(p.spaceId, 'spaceId');
  const date = requireIsoDate(p.date, 'date');
  const userId = p.userId ? asPositiveInt(p.userId, 'userId') : null;
  const releaseStart = p.releaseStart ? requireIsoDate(p.releaseStart, 'releaseStart') : null;
  const releaseEnd = p.releaseEnd ? requireIsoDate(p.releaseEnd, 'releaseEnd') : null;
  return { spaceId, date, userId, releaseStart, releaseEnd };
}

function validateLoginPayload(payload) {
  const p = requireJsonObject(payload);
  const username = normText(p.username, 64);
  const password = String(p.password || '');
  if (!username || !password) throw new Error('username/password required');
  return { username, password };
}

function validateChangePasswordPayload(payload) {
  const p = requireJsonObject(payload);
  const oldPassword = String(p.oldPassword || '');
  const newPassword = requirePassword(p.newPassword, 'newPassword');
  if (!oldPassword) throw new Error('oldPassword required');
  return { oldPassword, newPassword };
}

function bookingConflictTx(spaceId, startDate, endDate, userId, userScopedOnly) {
  const sameSpace = db.prepare(`
    SELECT 1 FROM bookings
    WHERE space_id = ? AND NOT (end_date < ? OR start_date > ?)
    LIMIT 1
  `).get(spaceId, startDate, endDate);
  if (sameSpace) throw new Error('Space already booked in selected range');
  if (userScopedOnly) {
    const sameUser = db.prepare(`
      SELECT 1 FROM bookings
      WHERE user_id = ? AND NOT (end_date < ? OR start_date > ?)
      LIMIT 1
    `).get(userId, startDate, endDate);
    if (sameUser) throw new Error('You already have booking in this range');
  }
}

const createBookingTx = db.transaction((payload, authCtx) => {
  const floor = db.prepare('SELECT id FROM floors WHERE id = ?').get(payload.floorId);
  if (!floor) throw new Error('Floor not found');
  const space = db.prepare('SELECT id, floor_id FROM spaces WHERE id = ?').get(payload.spaceId);
  if (!space || space.floor_id !== payload.floorId) throw new Error('Space not found for floor');
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(payload.userId);
  if (!user) throw new Error('User not found');
  bookingConflictTx(payload.spaceId, payload.startDate, payload.endDate, payload.userId, !authCtx.isAdmin);
  db.prepare(`
    INSERT INTO bookings(floor_id, space_id, user_id, start_date, end_date, created_by_user_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(payload.floorId, payload.spaceId, payload.userId, payload.startDate, payload.endDate, authCtx.userId);
});

const releaseBookingTx = db.transaction((payload, authCtx) => {
  const b = bookingForDate(payload.spaceId, payload.date);
  if (!b) throw new Error('No booking at selected date');
  if (!authCtx.isAdmin && b.user_id !== authCtx.userId) throw new Error('Cannot release this booking');
  if (authCtx.isAdmin && payload.userId && payload.userId !== b.user_id) throw new Error('Booking belongs to different user');

  const bookingStart = b.start_date;
  const bookingEnd = b.end_date;
  const oneDay = bookingStart === bookingEnd;
  let rs = payload.releaseStart || payload.date;
  let re = payload.releaseEnd || payload.date;

  if (oneDay) {
    rs = bookingStart;
    re = bookingEnd;
  }
  if (rs > re) throw new Error('Invalid release range');
  if (rs < bookingStart) rs = bookingStart;
  if (re > bookingEnd) re = bookingEnd;
  if (!overlaps(rs, re, bookingStart, bookingEnd)) throw new Error('Release range does not overlap booking');

  if (rs <= bookingStart && re >= bookingEnd) {
    db.prepare('DELETE FROM bookings WHERE id = ?').run(b.id);
    return;
  }
  if (rs <= bookingStart && re < bookingEnd) {
    db.prepare('UPDATE bookings SET start_date = ? WHERE id = ?').run(addDays(re, 1), b.id);
    return;
  }
  if (rs > bookingStart && re >= bookingEnd) {
    db.prepare('UPDATE bookings SET end_date = ? WHERE id = ?').run(addDays(rs, -1), b.id);
    return;
  }
  db.prepare('UPDATE bookings SET end_date = ? WHERE id = ?').run(addDays(rs, -1), b.id);
  db.prepare(`
    INSERT INTO bookings(floor_id, space_id, user_id, start_date, end_date, created_by_user_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(b.floor_id, b.space_id, b.user_id, addDays(re, 1), bookingEnd, b.created_by_user_id);
});

app.get('/api/health', (req, res) => {
  cleanupAuthArtifacts();
  res.json({
    ok: true,
    needsBootstrap: needsBootstrap(),
    bootstrapRequiresToken: !!BOOTSTRAP_TOKEN,
    sessionTtlSeconds: SESSION_TTL_SECONDS
  });
});

app.get('/api/auth/sso/status', (req, res) => {
  res.json({ enabled: isSsoEnabled(), configured: isSsoConfigured(), provider: 'microsoft' });
});

app.get('/api/admin/sso', auth, requireAdmin, (req, res) => {
  const s = ssoSettings();
  res.json({
    enabled: isSsoEnabled(),
    configured: isSsoConfigured(),
    tenantId: s.tenantId,
    clientId: s.clientId,
    redirectUri: s.redirectUri,
    hasClientSecret: !!s.clientSecretEncrypted
  });
});

app.post('/api/admin/sso', auth, requireAdmin, (req, res) => {
  try {
    const payload = validateSsoPayload(req.body);
    setMeta('sso_tenant_id', payload.tenantId);
    setMeta('sso_client_id', payload.clientId);
    setMeta('sso_redirect_uri', payload.redirectUri);
    if (payload.clientSecret !== null) setMeta('sso_client_secret_enc', payload.clientSecret ? encryptSecret(payload.clientSecret) : '');
    if (payload.enabled && !isSsoConfigured()) return res.status(400).json({ error: 'Provide tenant/client/secret/redirect before enabling SSO' });
    setMeta('sso_enabled', payload.enabled ? '1' : '0');
    logEvent('sso_config_updated', { requestId: req.requestId, adminUserId: req.auth.userId, enabled: payload.enabled, tenantId: payload.tenantId });
    res.json({ ok: true, enabled: payload.enabled, configured: isSsoConfigured() });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/auth/microsoft/start', rateLimit('sso-start', AUTH_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), (req, res) => {
  if (!isSsoEnabled()) return res.status(400).send('SSO is disabled');
  if (!isSsoConfigured()) return res.status(400).send('SSO not configured');
  const cfg = ssoSettings();
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, { nonce, createdAt: Date.now() });
  getOidcConfig(cfg.tenantId)
    .then((oidc) => {
      const authUrl = new URL(oidc.authorization_endpoint);
      authUrl.searchParams.set('client_id', cfg.clientId);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('redirect_uri', cfg.redirectUri);
      authUrl.searchParams.set('response_mode', 'query');
      authUrl.searchParams.set('scope', 'openid profile email');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('nonce', nonce);
      res.redirect(authUrl.toString());
    })
    .catch((err) => {
      console.error('SSO start error', err);
      res.status(502).send('SSO provider metadata unavailable');
    });
});

app.get('/api/auth/microsoft/callback', rateLimit('sso-callback', AUTH_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), async (req, res) => {
  try {
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const stateRow = oauthStates.get(state);
    oauthStates.delete(state);
    if (!code || !stateRow) return res.redirect('/?sso_error=invalid_state');
    if (Date.now() - stateRow.createdAt > 10 * 60 * 1000) return res.redirect('/?sso_error=state_expired');

    const cfg = ssoSettings();
    const secret = decryptSecret(cfg.clientSecretEncrypted);
    if (!cfg.clientId || !cfg.redirectUri || !secret) return res.redirect('/?sso_error=sso_not_configured');

    const oidc = await getOidcConfig(cfg.tenantId);
    const tokenUrl = oidc.token_endpoint;
    const body = new URLSearchParams();
    body.set('client_id', cfg.clientId);
    body.set('client_secret', secret);
    body.set('code', code);
    body.set('redirect_uri', cfg.redirectUri);
    body.set('grant_type', 'authorization_code');

    const tokenResp = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok || !tokenJson.id_token) return res.redirect('/?sso_error=token_exchange_failed');

    const claims = await verifyMicrosoftIdToken(tokenJson.id_token, stateRow.nonce, cfg);
    const oid = String(claims.oid || claims.sub || '');
    const email = String(claims.preferred_username || claims.email || '');
    const fullName = normText(claims.name || email || 'Microsoft User', 120);
    if (!oid) return res.redirect('/?sso_error=missing_subject');

    let user = db.prepare('SELECT * FROM users WHERE auth_provider = ? AND provider_subject = ?').get('microsoft', oid);
    if (!user) {
      const base = sanitizeUserIdFromEmail(email || fullName);
      const username = findUniqueUserId(base);
      const randomPw = crypto.randomBytes(12).toString('hex');
      const out = db.prepare(`
        INSERT INTO users(username, full_name, password_hash, is_admin, auth_provider, provider_subject)
        VALUES (?, ?, ?, 0, 'microsoft', ?)
      `).run(username, fullName || username, bcrypt.hashSync(randomPw, 10), oid);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(out.lastInsertRowid);
    } else {
      db.prepare('UPDATE users SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(fullName || user.full_name, user.id);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    }

    const token = issueToken(user);
    return res.redirect(`/?token=${encodeURIComponent(token)}&sso=1`);
  } catch (err) {
    logEvent('sso_callback_failed', { error: String(err?.message || err) });
    console.error('SSO callback error', err);
    return res.redirect('/?sso_error=callback_error');
  }
});

app.post('/api/bootstrap', rateLimit('bootstrap', AUTH_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), (req, res) => {
  try {
    requireJsonObject(req.body);
    if (!needsBootstrap()) return res.status(409).json({ error: 'Already bootstrapped' });
    if (!canBootstrap(req)) return res.status(403).json({ error: BOOTSTRAP_TOKEN ? 'Valid bootstrap token required' : 'Bootstrap allowed only from local install context' });
    const adminPassword = requirePassword(req.body.adminPassword, 'adminPassword');
    db.prepare('INSERT INTO users(username, full_name, password_hash, is_admin, is_builtin_admin) VALUES (?, ?, ?, 1, 1)')
      .run('admin', 'Administrator', bcrypt.hashSync(adminPassword, 10));
    logEvent('bootstrap_completed', { requestId: req.requestId, ip: clientIp(req) });
    res.json({ ok: true, username: 'admin' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/login', rateLimit('login', AUTH_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), (req, res) => {
  try {
    const payload = validateLoginPayload(req.body);
    const u = db.prepare('SELECT * FROM users WHERE username = ?').get(payload.username);
    if (!u || !bcrypt.compareSync(payload.password, u.password_hash)) {
      logEvent('login_failed', { requestId: req.requestId, ip: clientIp(req), username: payload.username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = issueToken(u);
    logEvent('login_succeeded', { requestId: req.requestId, ip: clientIp(req), userId: u.id, username: u.username });
    res.json({
      token,
      user: {
        id: u.id,
        username: u.username,
        fullName: u.full_name,
        isAdmin: !!u.is_admin,
        isBuiltinAdmin: !!u.is_builtin_admin,
        authProvider: u.auth_provider || null
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/logout', auth, (req, res) => {
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').run(nowIso(), sha(req.authToken));
  logEvent('logout', { requestId: req.requestId, userId: req.auth.userId, username: req.auth.username });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json(req.auth));

app.get('/api/users', auth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, username, full_name as fullName, is_admin as isAdmin, is_builtin_admin as isBuiltinAdmin, auth_provider as authProvider
    FROM users ORDER BY username
  `).all();
  res.json(rows);
});

app.post('/api/users', auth, requireAdmin, (req, res) => {
  try {
    const payload = validateUserCreatePayload(req.body);
    const out = db.prepare('INSERT INTO users(username, full_name, password_hash, is_admin) VALUES (?, ?, ?, ?)')
      .run(payload.username, payload.fullName, bcrypt.hashSync(payload.password, 10), payload.isAdmin ? 1 : 0);
    res.json({ id: out.lastInsertRowid, username: payload.username, fullName: payload.fullName, isAdmin: payload.isAdmin });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/users/:id', auth, requireAdmin, (req, res) => {
  try {
    const id = asPositiveInt(req.params.id, 'id');
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const payload = validateUserPatchPayload(req.body, user);
    if (user.is_builtin_admin) {
      db.prepare('UPDATE users SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(payload.fullName, id);
      return res.json({ ok: true });
    }
    db.prepare('UPDATE users SET is_admin = ?, full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(payload.isAdmin ? 1 : 0, payload.fullName, id);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/users/:id', auth, requireAdmin, (req, res) => {
  try {
    const id = asPositiveInt(req.params.id, 'id');
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.is_builtin_admin) return res.status(400).json({ error: 'Built-in admin cannot be deleted' });
    const tx = db.transaction(() => {
      db.prepare('DELETE FROM bookings WHERE user_id = ? OR created_by_user_id = ?').run(id, id);
      revokeSessionsForUser(id);
      db.prepare('DELETE FROM users WHERE id = ?').run(id);
    });
    tx();
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/users/:id/reset-password', rateLimit('reset-password', ADMIN_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), auth, requireAdmin, (req, res) => {
  try {
    const id = asPositiveInt(req.params.id, 'id');
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.auth_provider) return res.status(400).json({ error: 'Password reset is not available for SSO users' });
    const newPlain = randomSimplePassword(10);
    db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(bcrypt.hashSync(newPlain, 10), id);
    revokeSessionsForUser(id);
    logEvent('password_reset', { requestId: req.requestId, adminUserId: req.auth.userId, targetUserId: id });
    res.json({ ok: true, temporaryPassword: newPlain });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/me/change-password', auth, (req, res) => {
  try {
    const payload = validateChangePasswordPayload(req.body);
    const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.userId);
    if (!me || me.auth_provider) return res.status(400).json({ error: 'Password change is unavailable for this account' });
    if (!bcrypt.compareSync(payload.oldPassword, me.password_hash)) return res.status(400).json({ error: 'Wrong old password' });
    db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(bcrypt.hashSync(payload.newPassword, 10), me.id);
    revokeSessionsForUser(me.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/floors', (req, res) => {
  const rows = db.prepare('SELECT * FROM floors ORDER BY id').all().map((row) => ({
    ...row,
    image_path: floorImageValue(row)
  }));
  res.json(rows);
});

app.post('/api/floors', auth, requireAdmin, (req, res) => {
  try {
    const payload = validateFloorPayload(req.body);
    const finalImageData = payload.imageData ? normalizeFloorImageData(payload.imageData) : null;
    const out = db.prepare('INSERT INTO floors(name, image_path, image_data) VALUES (?, NULL, ?)').run(payload.name, finalImageData);
    res.json({ id: out.lastInsertRowid, imagePath: finalImageData });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/floors/:id', auth, requireAdmin, (req, res) => {
  try {
    const id = asPositiveInt(req.params.id, 'id');
    const floor = db.prepare('SELECT * FROM floors WHERE id = ?').get(id);
    if (!floor) return res.status(404).json({ error: 'Floor not found' });
    const payload = validateFloorPayload(req.body, floor);
    let imageData = floor.image_data || localFloorImageToDataUrl(floor.image_path) || null;
    if (payload.clearImage) imageData = null;
    if (payload.imageData) imageData = normalizeFloorImageData(payload.imageData);
    db.prepare('UPDATE floors SET name = ?, image_path = NULL, image_data = ? WHERE id = ?').run(payload.name, imageData, id);
    res.json({ ok: true, imagePath: imageData });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/floors/:id', auth, requireAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM floors WHERE id = ?').run(asPositiveInt(req.params.id, 'id'));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/spaces', (req, res) => {
  try {
    const floorId = asPositiveInt(req.query.floorId, 'floorId');
    res.json(db.prepare('SELECT * FROM spaces WHERE floor_id = ? ORDER BY space_number').all(floorId));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/spaces', auth, requireAdmin, (req, res) => {
  try {
    const payload = validateSpacePayload(req.body);
    const count = db.prepare('SELECT COUNT(*) c FROM spaces WHERE floor_id = ?').get(payload.floorId).c;
    const auto = suggestSpotLayout(count);
    const out = db.prepare(`
      INSERT INTO spaces(floor_id, space_number, x, y, w, h, dir, map_x, map_y, map_zoom)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      payload.floorId,
      payload.spaceNumber,
      payload.x ?? auto.x,
      payload.y ?? auto.y,
      payload.w ?? auto.w,
      payload.h ?? auto.h,
      payload.dir ?? auto.dir,
      payload.mapX,
      payload.mapY,
      payload.mapZoom
    );
    res.json({ id: out.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  try {
    const id = asPositiveInt(req.params.id, 'id');
    const space = db.prepare('SELECT * FROM spaces WHERE id = ?').get(id);
    if (!space) return res.status(404).json({ error: 'Space not found' });
    const payload = validateSpacePayload(req.body, space);
    db.prepare(`
      UPDATE spaces SET floor_id = ?, space_number = ?, x = ?, y = ?, w = ?, h = ?, dir = ?, map_x = ?, map_y = ?, map_zoom = ?
      WHERE id = ?
    `).run(
      payload.floorId,
      payload.spaceNumber,
      payload.x,
      payload.y,
      payload.w,
      payload.h,
      payload.dir,
      payload.mapX,
      payload.mapY,
      payload.mapZoom,
      id
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM spaces WHERE id = ?').run(asPositiveInt(req.params.id, 'id'));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/bookings', auth, (req, res) => {
  try {
    const floorId = req.query.floorId ? asPositiveInt(req.query.floorId, 'floorId') : 0;
    const where = [];
    const params = [];
    if (floorId) {
      where.push('b.floor_id = ?');
      params.push(floorId);
    }
    if (!req.auth.isAdmin) {
      where.push('b.user_id = ?');
      params.push(req.auth.userId);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = db.prepare(`
      SELECT b.*, u.full_name as full_name, s.space_number, f.name as floor_name
      FROM bookings b
      JOIN users u ON u.id = b.user_id
      JOIN spaces s ON s.id = b.space_id
      JOIN floors f ON f.id = b.floor_id
      ${whereSql}
      ORDER BY b.start_date
    `).all(...params);
    res.json(rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/availability', (req, res) => {
  try {
    const floorId = asPositiveInt(req.query.floorId, 'floorId');
    const date = requireIsoDate(req.query.date, 'date');
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '').trim();
    const authCtx = readSession(token);
    const spaces = db.prepare('SELECT * FROM spaces WHERE floor_id = ? ORDER BY space_number').all(floorId);
    const out = spaces.map((space) => {
      const booking = bookingForDate(space.id, date);
      if (!booking) {
        return { ...space, isBooked: false, bookingUser: null, bookingId: null, bookingOwnerId: null, bookingStart: null, bookingEnd: null };
      }
      const canSeeBookingDetails = !!authCtx && (authCtx.isAdmin || booking.user_id === authCtx.userId);
      return {
        ...space,
        isBooked: true,
        bookingUser: canSeeBookingDetails ? (booking.full_name || null) : null,
        bookingId: canSeeBookingDetails ? (booking.id || null) : null,
        bookingOwnerId: canSeeBookingDetails ? (booking.user_id || null) : null,
        bookingStart: canSeeBookingDetails ? (booking.start_date || null) : null,
        bookingEnd: canSeeBookingDetails ? (booking.end_date || null) : null
      };
    });
    res.json(out);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/bookings', auth, (req, res) => {
  try {
    const payload = validateBookingPayload(req.body, req.auth);
    createBookingTx(payload, req.auth);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/bookings/release', auth, (req, res) => {
  try {
    const payload = validateReleasePayload(req.body);
    releaseBookingTx(payload, req.auth);
    res.json({ ok: true });
  } catch (err) {
    const msg = String(err?.message || '');
    const status = /No booking/.test(msg) ? 404 : /Cannot release/.test(msg) ? 403 : 400;
    res.status(status).json({ error: msg || 'Invalid request' });
  }
});

app.use((err, req, res, next) => {
  const errorId = newErrorId('API');
  const msg = String(err?.message || '');
  if (/database is locked/i.test(msg)) {
    logEvent('api_error', { requestId: req.requestId, errorId, kind: 'SQLITE_LOCKED', path: req.originalUrl, method: req.method, message: msg });
    console.error(`[${errorId}] SQLITE_LOCKED`, err);
    return res.status(503).json({ error: 'Database is busy. Please retry in a moment.', errorId });
  }
  logEvent('api_error', { requestId: req.requestId, errorId, kind: 'UNHANDLED', path: req.originalUrl, method: req.method, message: msg });
  console.error(`[${errorId}] UNHANDLED`, err);
  return res.status(500).json({ error: 'Unexpected server error. Please contact support and provide error id.', errorId });
});

app.use(express.static(ROOT));
app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'index.html')));

const server = app.listen(PORT, HOST, () => {
  cleanupAuthArtifacts();
  console.log(`Parking app listening on ${APP_BASE_URL}`);
  if (needsBootstrap()) console.log('First run: POST /api/bootstrap {"adminPassword":"...","bootstrapToken":"..."}');
});

function closeServer() {
  return new Promise((resolve, reject) => {
    server.close((err) => {
      try {
        db.close();
      } catch {}
      if (err) return reject(err);
      resolve();
    });
  });
}

module.exports = { app, server, closeServer };
