const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT || 3000);
const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'data');
const SECRETS_DIR = path.join(ROOT, 'secrets');
const DB_PATH = path.join(DATA_DIR, 'parking.sqlite3');
const DB_KEY_PATH = path.join(SECRETS_DIR, 'db-access.key');
const UPLOADS_DIR = path.join(ROOT, 'uploads');
const FLOOR_UPLOADS_DIR = path.join(UPLOADS_DIR, 'floors');

const sessions = new Map();
const oauthStates = new Map();

function newErrorId(prefix = 'ERR') {
  const ts = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const rnd = crypto.randomBytes(3).toString('hex');
  return `${prefix}-${ts}-${rnd}`;
}

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true, mode: 0o700 }); }
function todayISO() { return new Date().toISOString().slice(0, 10); }
function safeExt(filename = '') {
  const ext = path.extname(filename).toLowerCase();
  return ['.png', '.jpg', '.jpeg', '.webp'].includes(ext) ? ext : '.png';
}
function saveFloorImageFromData(imageData, imageName = 'floor.png') {
  if (!imageData || typeof imageData !== 'string') return null;
  const m = imageData.match(/^data:(image\/(png|jpeg|jpg|webp));base64,(.+)$/i);
  if (!m) throw new Error('Invalid floor image format');
  ensureDir(UPLOADS_DIR);
  ensureDir(FLOOR_UPLOADS_DIR);
  const ext = safeExt(imageName);
  const filename = `floor-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`;
  const outPath = path.join(FLOOR_UPLOADS_DIR, filename);
  fs.writeFileSync(outPath, Buffer.from(m[3], 'base64'));
  return `./uploads/floors/${filename}`;
}
function addDays(dateIso, d) {
  const dt = new Date(`${dateIso}T00:00:00Z`);
  dt.setUTCDate(dt.getUTCDate() + d);
  return dt.toISOString().slice(0, 10);
}

function randomSimplePassword(len = 6) {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function sha(v) { return crypto.createHash('sha256').update(v).digest('hex'); }

function normText(v, max=120) {
  const t = String(v ?? '').trim();
  return t.slice(0, max);
}

function validUserId(v) {
  return /^[a-zA-Z0-9._-]{1,64}$/.test(v);
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

function cryptoKey() {
  const baseKey = fs.existsSync(DB_KEY_PATH) ? fs.readFileSync(DB_KEY_PATH, 'utf8').trim() : 'dev-fallback-key';
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
  const redirectFallback = `http://localhost:${PORT}/api/auth/microsoft/callback`;
  return {
    tenantId: getMeta('sso_tenant_id', 'common'),
    clientId: getMeta('sso_client_id', ''),
    clientSecretEncrypted: getMeta('sso_client_secret_enc', ''),
    redirectUri: getMeta('sso_redirect_uri', redirectFallback)
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

function sanitizeUserIdFromEmail(emailOrName = '') {
  const base = String(emailOrName || '').toLowerCase().replace(/@.*/, '').replace(/[^a-z0-9._-]/g, '.').replace(/\.+/g, '.').replace(/^\.|\.$/g, '');
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

function getOrCreateDbAccessKey(firstRun) {
  ensureDir(SECRETS_DIR);
  if (fs.existsSync(DB_KEY_PATH)) return fs.readFileSync(DB_KEY_PATH, 'utf8').trim();
  if (!firstRun) throw new Error('DB key missing while DB exists. Refusing to regenerate key.');
  const key = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(DB_KEY_PATH, key, { mode: 0o600 });
  return key;
}

function hasColumn(db, table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
}

function migrate(db) {
  db.exec(`
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
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS floors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      image_path TEXT,
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
    ['x', 'REAL'], ['y', 'REAL'], ['w', 'REAL'], ['h', 'REAL'], ['dir', 'TEXT'],
    ['map_x', 'REAL'], ['map_y', 'REAL'], ['map_zoom', 'REAL']
  ];
  for (const [name, type] of extraCols) {
    if (!hasColumn(db, 'spaces', name)) db.exec(`ALTER TABLE spaces ADD COLUMN ${name} ${type}`);
  }

  if (!hasColumn(db, 'users', 'full_name')) db.exec('ALTER TABLE users ADD COLUMN full_name TEXT');
  if (!hasColumn(db, 'users', 'auth_provider')) db.exec('ALTER TABLE users ADD COLUMN auth_provider TEXT');
  if (!hasColumn(db, 'users', 'provider_subject')) db.exec('ALTER TABLE users ADD COLUMN provider_subject TEXT');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_provider_subject ON users(auth_provider, provider_subject) WHERE provider_subject IS NOT NULL');
  db.exec("UPDATE users SET full_name = COALESCE(NULLIF(full_name, ''), username)");
}

function openDbStrict() {
  ensureDir(DATA_DIR);
  const dbExists = fs.existsSync(DB_PATH);
  const key = getOrCreateDbAccessKey(!dbExists);
  const db = new Database(DB_PATH, { fileMustExist: dbExists });
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  migrate(db);

  const row = db.prepare('SELECT value FROM meta WHERE key = ?').get('db_key_hash');
  if (!row) {
    db.prepare('INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)').run('db_key_hash', sha(key));
  } else if (row.value !== sha(key)) {
    throw new Error('Database authorization failed (key mismatch). Not creating/overwriting DB.');
  }

  return db;
}

const db = openDbStrict();
function needsBootstrap() { return db.prepare('SELECT COUNT(*) c FROM users').get().c === 0; }

function issueToken(user) {
  const t = crypto.randomBytes(24).toString('base64url');
  sessions.set(t, {
    userId: user.id,
    username: user.username,
    fullName: user.full_name,
    isAdmin: !!user.is_admin,
    isBuiltinAdmin: !!user.is_builtin_admin,
    authProvider: user.auth_provider || null
  });
  return t;
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '').trim();
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  req.auth = sessions.get(token);
  next();
}

function requireAdmin(req, res, next) {
  if (!req.auth.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

function overlaps(startA, endA, startB, endB) {
  return startA <= endB && startB <= endA;
}

function addDaysISO(dateIso, days) {
  const d = new Date(`${dateIso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0,10);
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

app.get('/api/health', (req, res) => res.json({ ok: true, needsBootstrap: needsBootstrap() }));

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
  const p = req.body || {};
  const tenantId = normText(p.tenantId || 'common', 120) || 'common';
  const clientId = normText(p.clientId || '', 256);
  const redirectUri = normText(p.redirectUri || `http://localhost:${PORT}/api/auth/microsoft/callback`, 512);
  const enabled = !!p.enabled;

  if (redirectUri && !/^https?:\/\//i.test(redirectUri)) {
    return res.status(400).json({ error: 'redirectUri must be http(s) URL' });
  }

  setMeta('sso_tenant_id', tenantId);
  setMeta('sso_client_id', clientId);
  setMeta('sso_redirect_uri', redirectUri);

  const hasSecretInPayload = Object.prototype.hasOwnProperty.call(p, 'clientSecret');
  if (hasSecretInPayload) {
    const sec = String(p.clientSecret || '').trim();
    setMeta('sso_client_secret_enc', sec ? encryptSecret(sec) : '');
  }

  if (enabled && !isSsoConfigured()) {
    return res.status(400).json({ error: 'Provide tenant/client/secret/redirect before enabling SSO' });
  }

  setMeta('sso_enabled', enabled ? '1' : '0');
  res.json({ ok: true, enabled, configured: isSsoConfigured() });
});

app.get('/api/auth/microsoft/start', (req, res) => {
  if (!isSsoEnabled()) return res.status(400).send('SSO is disabled');
  if (!isSsoConfigured()) return res.status(400).send('SSO not configured');

  const cfg = ssoSettings();
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, { nonce, createdAt: Date.now() });

  const authUrl = new URL(`https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/authorize`);
  authUrl.searchParams.set('client_id', cfg.clientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', cfg.redirectUri);
  authUrl.searchParams.set('response_mode', 'query');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);

  res.redirect(authUrl.toString());
});

app.get('/api/auth/microsoft/callback', async (req, res) => {
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

    const tokenUrl = `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/token`;
    const body = new URLSearchParams();
    body.set('client_id', cfg.clientId);
    body.set('client_secret', secret);
    body.set('code', code);
    body.set('redirect_uri', cfg.redirectUri);
    body.set('grant_type', 'authorization_code');

    const tokenResp = await fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok || !tokenJson.id_token) return res.redirect('/?sso_error=token_exchange_failed');

    const claims = b64urlJsonDecode(String(tokenJson.id_token).split('.')[1]);
    if (claims.nonce && claims.nonce !== stateRow.nonce) return res.redirect('/?sso_error=nonce_mismatch');

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
  } catch (e) {
    console.error('SSO callback error', e);
    return res.redirect('/?sso_error=callback_error');
  }
});

app.post('/api/bootstrap', (req, res) => {
  if (!needsBootstrap()) return res.status(409).json({ error: 'Already bootstrapped' });
  const { adminPassword } = req.body || {};
  if (!adminPassword || adminPassword.length < 4) return res.status(400).json({ error: 'adminPassword min 4 chars' });
  db.prepare('INSERT INTO users(username,full_name,password_hash,is_admin,is_builtin_admin) VALUES (?,?,?,1,1)')
    .run('admin', 'Administrator', bcrypt.hashSync(adminPassword, 10));
  res.json({ ok: true, username: 'admin' });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const userId = normText(username, 64);
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(userId);
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = issueToken(u);
  res.json({ token, user: { id: u.id, username: u.username, fullName: u.full_name, isAdmin: !!u.is_admin, isBuiltinAdmin: !!u.is_builtin_admin, authProvider: u.auth_provider || null } });
});

app.get('/api/me', auth, (req, res) => res.json(req.auth));

app.get('/api/users', auth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, full_name as fullName, is_admin as isAdmin, is_builtin_admin as isBuiltinAdmin, auth_provider as authProvider FROM users ORDER BY username').all();
  res.json(rows);
});

app.post('/api/users', auth, requireAdmin, (req, res) => {
  const { username, fullName, password, isAdmin = false } = req.body || {};
  const userId = normText(username, 64);
  const safeFullName = normText(fullName || username, 120);
  if (!userId || !password) return res.status(400).json({ error: 'username/password required' });
  if (!validUserId(userId)) return res.status(400).json({ error: 'Invalid user id format' });
  if (password.length < 4) return res.status(400).json({ error: 'password min 4 chars' });
  try {
    const out = db.prepare('INSERT INTO users(username,full_name,password_hash,is_admin) VALUES (?,?,?,?)')
      .run(userId, safeFullName || userId, bcrypt.hashSync(password, 10), isAdmin ? 1 : 0);
    res.json({ id: out.lastInsertRowid, username: userId, fullName: safeFullName || userId, isAdmin: !!isAdmin });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/users/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const nextFullName = normText(req.body?.fullName ?? user.full_name ?? user.username, 120);
  if (user.is_builtin_admin) {
    db.prepare('UPDATE users SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(nextFullName || user.username, id);
    return res.json({ ok: true });
  }
  db.prepare('UPDATE users SET is_admin = ?, full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.body?.isAdmin ? 1 : 0, nextFullName || user.username, id);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_builtin_admin) return res.status(400).json({ error: 'Built-in admin cannot be deleted' });

  const tx = db.transaction(() => {
    // Clean related bookings first to avoid FK issues and keep delete predictable
    db.prepare('DELETE FROM bookings WHERE user_id = ? OR created_by_user_id = ?').run(id, id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  tx();

  // Invalidate active sessions for deleted user
  for (const [token, sess] of sessions.entries()) {
    if (sess.userId === id) sessions.delete(token);
  }

  res.json({ ok: true });
});

app.post('/api/users/:id/reset-password', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.auth_provider) return res.status(400).json({ error: 'Password reset is not available for SSO users' });
  const newPlain = randomSimplePassword(6);
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(bcrypt.hashSync(newPlain, 10), id);

  // Force logout for reset user: invalidate all active sessions
  for (const [token, sess] of sessions.entries()) {
    if (sess.userId === id) sessions.delete(token);
  }

  res.json({ ok: true, temporaryPassword: newPlain });
});

app.post('/api/me/change-password', auth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.userId);
  if (!bcrypt.compareSync(oldPassword || '', me.password_hash)) return res.status(400).json({ error: 'Wrong old password' });
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'newPassword min 4 chars' });
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(bcrypt.hashSync(newPassword, 10), me.id);
  res.json({ ok: true });
});

app.get('/api/floors', (req, res) => res.json(db.prepare('SELECT * FROM floors ORDER BY id').all()));

app.post('/api/floors', auth, requireAdmin, (req, res) => {
  const { name, imagePath = '', imageData = '', imageName = '' } = req.body || {};
  const safeName = normText(name, 120);
  if (!safeName) return res.status(400).json({ error: 'name required' });
  let finalImagePath = imagePath || null;
  if (imageData) finalImagePath = saveFloorImageFromData(imageData, imageName);
  const out = db.prepare('INSERT INTO floors(name,image_path) VALUES (?,?)').run(safeName, finalImagePath);
  res.json({ id: out.lastInsertRowid, imagePath: finalImagePath });
});

app.patch('/api/floors/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const f = db.prepare('SELECT * FROM floors WHERE id = ?').get(id);
  if (!f) return res.status(404).json({ error: 'Floor not found' });
  const name = normText(req.body?.name ?? f.name, 120);
  let imagePath = req.body?.imagePath ?? f.image_path;
  if (req.body?.imageData) imagePath = saveFloorImageFromData(req.body.imageData, req.body.imageName);
  db.prepare('UPDATE floors SET name = ?, image_path = ? WHERE id = ?').run(name, imagePath || null, id);
  res.json({ ok: true, imagePath: imagePath || null });
});

app.delete('/api/floors/:id', auth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM floors WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/spaces', (req, res) => {
  const floorId = Number(req.query.floorId);
  if (!floorId) return res.status(400).json({ error: 'floorId required' });
  res.json(db.prepare('SELECT * FROM spaces WHERE floor_id = ? ORDER BY space_number').all(floorId));
});

app.post('/api/spaces', auth, requireAdmin, (req, res) => {
  const p = req.body || {};
  if (!p.floorId || !p.spaceNumber) return res.status(400).json({ error: 'floorId/spaceNumber required' });
  const safeSpaceNumber = normText(p.spaceNumber, 32);
  try {
    const count = db.prepare('SELECT COUNT(*) c FROM spaces WHERE floor_id = ?').get(p.floorId).c;
    const auto = suggestSpotLayout(count);
    const out = db.prepare(`
      INSERT INTO spaces(floor_id,space_number,x,y,w,h,dir,map_x,map_y,map_zoom)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `).run(
      p.floorId,
      safeSpaceNumber,
      p.x ?? auto.x,
      p.y ?? auto.y,
      p.w ?? auto.w,
      p.h ?? auto.h,
      p.dir ?? auto.dir,
      p.mapX ?? null,
      p.mapY ?? null,
      p.mapZoom ?? null
    );
    res.json({ id: out.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const s = db.prepare('SELECT * FROM spaces WHERE id = ?').get(id);
  if (!s) return res.status(404).json({ error: 'Space not found' });
  const p = req.body || {};
  const safeSpaceNumber = normText(p.spaceNumber ?? s.space_number, 32);
  db.prepare(`
    UPDATE spaces SET floor_id=?, space_number=?, x=?, y=?, w=?, h=?, dir=?, map_x=?, map_y=?, map_zoom=?
    WHERE id=?
  `).run(
    p.floorId ?? s.floor_id, safeSpaceNumber, p.x ?? s.x, p.y ?? s.y,
    p.w ?? s.w, p.h ?? s.h, p.dir ?? s.dir, p.mapX ?? s.map_x, p.mapY ?? s.map_y, p.mapZoom ?? s.map_zoom, id
  );
  res.json({ ok: true });
});

app.delete('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM spaces WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/bookings', auth, (req, res) => {
  const floorId = Number(req.query.floorId || 0);
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
});

app.get('/api/availability', (req, res) => {
  const floorId = Number(req.query.floorId);
  const date = String(req.query.date || '');
  if (!floorId || !date) return res.status(400).json({ error: 'floorId/date required' });

  const token = req.headers.authorization?.replace('Bearer ', '').trim();
  const authCtx = token && sessions.has(token) ? sessions.get(token) : null;

  const spaces = db.prepare('SELECT * FROM spaces WHERE floor_id = ? ORDER BY space_number').all(floorId);
  const out = spaces.map(s => {
    const b = bookingForDate(s.id, date);
    if (!b) {
      return { ...s, isBooked: false, bookingUser: null, bookingId: null, bookingOwnerId: null, bookingStart: null, bookingEnd: null };
    }

    const canSeeBookingDetails = !!authCtx && (authCtx.isAdmin || b.user_id === authCtx.userId);
    return {
      ...s,
      isBooked: true,
      bookingUser: canSeeBookingDetails ? (b.full_name || null) : null,
      bookingId: canSeeBookingDetails ? (b.id || null) : null,
      bookingOwnerId: canSeeBookingDetails ? (b.user_id || null) : null,
      bookingStart: canSeeBookingDetails ? (b.start_date || null) : null,
      bookingEnd: canSeeBookingDetails ? (b.end_date || null) : null
    };
  });

  res.json(out);
});

app.post('/api/bookings', auth, (req, res) => {
  const p = req.body || {};
  if (!p.floorId || !p.spaceId || !p.startDate || !p.endDate) return res.status(400).json({ error: 'floorId/spaceId/startDate/endDate required' });
  const start = p.startDate;
  const end = p.endDate;
  if (new Date(`${start}T00:00:00Z`) > new Date(`${end}T00:00:00Z`)) return res.status(400).json({ error: 'Invalid date range' });

  const targetUserId = req.auth.isAdmin ? Number(p.userId || req.auth.userId) : req.auth.userId;

  const sameSpace = db.prepare('SELECT * FROM bookings WHERE space_id = ?').all(p.spaceId);
  for (const b of sameSpace) if (overlaps(start, end, b.start_date, b.end_date)) return res.status(400).json({ error: 'Space already booked in selected range' });

  if (!req.auth.isAdmin) {
    const userBookings = db.prepare('SELECT * FROM bookings WHERE user_id = ?').all(targetUserId);
    for (const b of userBookings) if (overlaps(start, end, b.start_date, b.end_date)) return res.status(400).json({ error: 'You already have booking in this range' });
  }

  db.prepare(`
    INSERT INTO bookings(floor_id,space_id,user_id,start_date,end_date,created_by_user_id)
    VALUES (?,?,?,?,?,?)
  `).run(p.floorId, p.spaceId, targetUserId, start, end, req.auth.userId);

  res.json({ ok: true });
});

app.post('/api/bookings/release', auth, (req, res) => {
  const { spaceId, date, userId, releaseStart, releaseEnd } = req.body || {};
  if (!spaceId || !date) return res.status(400).json({ error: 'spaceId/date required' });
  const b = bookingForDate(Number(spaceId), date);
  if (!b) return res.status(404).json({ error: 'No booking at selected date' });

  if (!req.auth.isAdmin && b.user_id !== req.auth.userId) return res.status(403).json({ error: 'Cannot release this booking' });
  if (req.auth.isAdmin && userId && Number(userId) !== b.user_id) return res.status(400).json({ error: 'Booking belongs to different user' });

  const bookingStart = b.start_date;
  const bookingEnd = b.end_date;
  const oneDay = bookingStart === bookingEnd;

  let rs = releaseStart || date;
  let re = releaseEnd || date;

  if (oneDay) {
    rs = bookingStart;
    re = bookingEnd;
  }

  if (new Date(`${rs}T00:00:00Z`) > new Date(`${re}T00:00:00Z`)) {
    return res.status(400).json({ error: 'Invalid release range' });
  }

  // Clamp release range to booking period
  if (rs < bookingStart) rs = bookingStart;
  if (re > bookingEnd) re = bookingEnd;

  if (!overlaps(rs, re, bookingStart, bookingEnd)) {
    return res.status(400).json({ error: 'Release range does not overlap booking' });
  }

  // Full remove
  if (rs <= bookingStart && re >= bookingEnd) {
    db.prepare('DELETE FROM bookings WHERE id = ?').run(b.id);
    return res.json({ ok: true });
  }

  // Trim start
  if (rs <= bookingStart && re < bookingEnd) {
    const newStart = addDaysISO(re, 1);
    db.prepare('UPDATE bookings SET start_date = ? WHERE id = ?').run(newStart, b.id);
    return res.json({ ok: true });
  }

  // Trim end
  if (rs > bookingStart && re >= bookingEnd) {
    const newEnd = addDaysISO(rs, -1);
    db.prepare('UPDATE bookings SET end_date = ? WHERE id = ?').run(newEnd, b.id);
    return res.json({ ok: true });
  }

  // Split in middle
  const leftEnd = addDaysISO(rs, -1);
  const rightStart = addDaysISO(re, 1);
  const tx = db.transaction(() => {
    db.prepare('UPDATE bookings SET end_date = ? WHERE id = ?').run(leftEnd, b.id);
    db.prepare(`
      INSERT INTO bookings(floor_id,space_id,user_id,start_date,end_date,created_by_user_id)
      VALUES (?,?,?,?,?,?)
    `).run(b.floor_id, b.space_id, b.user_id, rightStart, bookingEnd, b.created_by_user_id);
  });
  tx();

  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  const errorId = newErrorId('API');
  const msg = String(err?.message || '');

  if (/database is locked/i.test(msg)) {
    console.error(`[${errorId}] SQLITE_LOCKED`, err);
    return res.status(503).json({
      error: 'Database is busy. Please retry in a moment.',
      errorId
    });
  }

  console.error(`[${errorId}] UNHANDLED`, err);
  return res.status(500).json({
    error: 'Unexpected server error. Please contact support and provide error id.',
    errorId
  });
});

app.use(express.static(ROOT));
app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'index.html')));

app.listen(PORT, () => {
  console.log(`Parking app listening on http://localhost:${PORT}`);
  if (needsBootstrap()) console.log('First run: POST /api/bootstrap {"adminPassword":"..."}');
});
