const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'data');
const SECRETS_DIR = path.join(ROOT, 'secrets');
const DB_PATH = path.join(DATA_DIR, 'parking.sqlite3');
const DB_KEY_PATH = path.join(SECRETS_DIR, 'db-access.key');

const tokens = new Map();

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true, mode: 0o700 });
}

function randomSimplePassword(len = 6) {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function getOrCreateDbAccessKey(firstRun) {
  ensureDir(SECRETS_DIR);

  if (fs.existsSync(DB_KEY_PATH)) {
    return fs.readFileSync(DB_KEY_PATH, 'utf8').trim();
  }

  if (!firstRun) {
    throw new Error('Database key is missing while DB exists. Refusing to regenerate key.');
  }

  const generated = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(DB_KEY_PATH, generated, { mode: 0o600 });
  return generated;
}

function hash(v) {
  return crypto.createHash('sha256').update(v).digest('hex');
}

function openDbStrict() {
  ensureDir(DATA_DIR);
  const dbExists = fs.existsSync(DB_PATH);
  const key = getOrCreateDbAccessKey(!dbExists);

  // Important: we do not delete/overwrite DB ever.
  const db = new Database(DB_PATH, { fileMustExist: dbExists });
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  if (!dbExists) {
    runMigrations(db);
    db.prepare('INSERT INTO meta(key, value) VALUES (?, ?)').run('db_key_hash', hash(key));
  } else {
    const row = db.prepare('SELECT value FROM meta WHERE key = ?').get('db_key_hash');
    if (!row || row.value !== hash(key)) {
      throw new Error('Database authorization failed (key mismatch). Refusing to continue.');
    }
  }

  return db;
}

function runMigrations(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
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
}

const db = openDbStrict();

function needBootstrap() {
  const row = db.prepare('SELECT COUNT(*) c FROM users').get();
  return row.c === 0;
}

function issueToken(user) {
  const token = crypto.randomBytes(24).toString('base64url');
  tokens.set(token, { userId: user.id, username: user.username, isAdmin: !!user.is_admin });
  return token;
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '').trim();
  if (!token || !tokens.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  req.auth = tokens.get(token);
  next();
}

function requireAdmin(req, res, next) {
  if (!req.auth?.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

function overlapExists(spaceId, startDate, endDate, ignoreBookingId = null) {
  const rows = db.prepare('SELECT id, start_date, end_date FROM bookings WHERE space_id = ?').all(spaceId);
  const start = new Date(`${startDate}T00:00:00Z`).getTime();
  const end = new Date(`${endDate}T00:00:00Z`).getTime();
  return rows.some(r => {
    if (ignoreBookingId && r.id === ignoreBookingId) return false;
    const rStart = new Date(`${r.start_date}T00:00:00Z`).getTime();
    const rEnd = new Date(`${r.end_date}T00:00:00Z`).getTime();
    return start < rEnd && rStart < end;
  });
}

function userHasOverlap(userId, startDate, endDate) {
  const rows = db.prepare('SELECT start_date, end_date FROM bookings WHERE user_id = ?').all(userId);
  const start = new Date(`${startDate}T00:00:00Z`).getTime();
  const end = new Date(`${endDate}T00:00:00Z`).getTime();
  return rows.some(r => {
    const rStart = new Date(`${r.start_date}T00:00:00Z`).getTime();
    const rEnd = new Date(`${r.end_date}T00:00:00Z`).getTime();
    return start < rEnd && rStart < end;
  });
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, needsBootstrap: needBootstrap() });
});

app.post('/api/bootstrap', (req, res) => {
  if (!needBootstrap()) return res.status(409).json({ error: 'Already bootstrapped' });
  const { adminPassword } = req.body || {};
  if (!adminPassword || adminPassword.length < 8) {
    return res.status(400).json({ error: 'adminPassword must be at least 8 chars' });
  }

  const passwordHash = bcrypt.hashSync(adminPassword, 10);
  db.prepare(`
    INSERT INTO users(username, password_hash, is_admin, is_builtin_admin)
    VALUES('admin', ?, 1, 1)
  `).run(passwordHash);

  return res.json({ ok: true, username: 'admin' });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = issueToken(user);
  res.json({ token, user: { id: user.id, username: user.username, isAdmin: !!user.is_admin } });
});

app.post('/api/users', auth, requireAdmin, (req, res) => {
  const { username, password, isAdmin = false } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const passwordHash = bcrypt.hashSync(password, 10);
  try {
    const out = db.prepare('INSERT INTO users(username, password_hash, is_admin) VALUES (?, ?, ?)').run(username, passwordHash, isAdmin ? 1 : 0);
    res.json({ id: out.lastInsertRowid, username, isAdmin: !!isAdmin });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/users/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { isAdmin } = req.body || {};
  if (user.is_builtin_admin) return res.status(400).json({ error: 'Built-in admin role cannot be changed' });
  db.prepare('UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(isAdmin ? 1 : 0, id);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_builtin_admin) return res.status(400).json({ error: 'Built-in admin cannot be deleted' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/users/:id/reset-password', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const plain = randomSimplePassword(6);
  const hashPw = bcrypt.hashSync(plain, 10);
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hashPw, id);
  res.json({ ok: true, temporaryPassword: plain });
});

app.post('/api/me/change-password', auth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.userId);
  if (!bcrypt.compareSync(oldPassword || '', me.password_hash)) return res.status(400).json({ error: 'Wrong old password' });
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'newPassword too short' });
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), me.id);
  res.json({ ok: true });
});

app.post('/api/floors', auth, requireAdmin, (req, res) => {
  const { name, imagePath = null } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const out = db.prepare('INSERT INTO floors(name, image_path) VALUES (?, ?)').run(name, imagePath);
  res.json({ id: out.lastInsertRowid, name, imagePath });
});

app.patch('/api/floors/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const floor = db.prepare('SELECT * FROM floors WHERE id = ?').get(id);
  if (!floor) return res.status(404).json({ error: 'Floor not found' });
  const name = req.body?.name ?? floor.name;
  const imagePath = req.body?.imagePath ?? floor.image_path;
  db.prepare('UPDATE floors SET name = ?, image_path = ? WHERE id = ?').run(name, imagePath, id);
  res.json({ ok: true });
});

app.delete('/api/floors/:id', auth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM floors WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/spaces', auth, requireAdmin, (req, res) => {
  const { floorId, spaceNumber, mapX = null, mapY = null, mapZoom = null } = req.body || {};
  if (!floorId || !spaceNumber) return res.status(400).json({ error: 'floorId and spaceNumber required' });
  try {
    const out = db.prepare('INSERT INTO spaces(floor_id, space_number, map_x, map_y, map_zoom) VALUES (?, ?, ?, ?, ?)')
      .run(floorId, String(spaceNumber), mapX, mapY, mapZoom);
    res.json({ id: out.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const s = db.prepare('SELECT * FROM spaces WHERE id = ?').get(id);
  if (!s) return res.status(404).json({ error: 'Space not found' });
  const floorId = req.body?.floorId ?? s.floor_id;
  const spaceNumber = req.body?.spaceNumber ?? s.space_number;
  const mapX = req.body?.mapX ?? s.map_x;
  const mapY = req.body?.mapY ?? s.map_y;
  const mapZoom = req.body?.mapZoom ?? s.map_zoom;
  db.prepare('UPDATE spaces SET floor_id = ?, space_number = ?, map_x = ?, map_y = ?, map_zoom = ? WHERE id = ?')
    .run(floorId, String(spaceNumber), mapX, mapY, mapZoom, id);
  res.json({ ok: true });
});

app.delete('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM spaces WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/availability', auth, (req, res) => {
  const { floorId, date } = req.query;
  if (!floorId || !date) return res.status(400).json({ error: 'floorId and date required' });
  const datePoint = `${date}T12:00:00Z`;
  const slots = db.prepare(`
    SELECT s.id, s.space_number,
      EXISTS(
        SELECT 1 FROM bookings b
        WHERE b.space_id = s.id
          AND b.start_date <= date(?)
          AND date(?) < b.end_date
      ) as is_booked
    FROM spaces s
    WHERE s.floor_id = ?
    ORDER BY s.space_number ASC
  `).all(datePoint, datePoint, floorId);
  res.json({ date, floorId: Number(floorId), spaces: slots });
});

app.post('/api/bookings', auth, (req, res) => {
  const { floorId, spaceId, userId, startDate, endDate } = req.body || {};
  if (!floorId || !spaceId || !startDate || !endDate) {
    return res.status(400).json({ error: 'floorId, spaceId, startDate, endDate required' });
  }

  const start = new Date(`${startDate}T00:00:00Z`).getTime();
  const end = new Date(`${endDate}T00:00:00Z`).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) {
    return res.status(400).json({ error: 'Invalid date range' });
  }

  const targetUserId = req.auth.isAdmin ? (userId || req.auth.userId) : req.auth.userId;
  if (!req.auth.isAdmin && userHasOverlap(targetUserId, startDate, endDate)) {
    return res.status(400).json({ error: 'User already has booking in overlapping range' });
  }

  if (overlapExists(spaceId, startDate, endDate)) {
    return res.status(400).json({ error: 'Space already booked in selected range' });
  }

  db.prepare(`
    INSERT INTO bookings(floor_id, space_id, user_id, start_date, end_date, created_by_user_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(floorId, spaceId, targetUserId, startDate, endDate, req.auth.userId);

  res.json({ ok: true });
});

app.post('/api/bookings/release', auth, (req, res) => {
  const { spaceId, date, userId } = req.body || {};
  if (!spaceId || !date) return res.status(400).json({ error: 'spaceId and date required' });

  const booking = db.prepare(`
    SELECT * FROM bookings
    WHERE space_id = ?
      AND start_date <= date(?)
      AND date(?) < end_date
    ORDER BY id DESC LIMIT 1
  `).get(spaceId, `${date}T12:00:00Z`, `${date}T12:00:00Z`);

  if (!booking) return res.status(404).json({ error: 'No active booking at given date' });

  if (!req.auth.isAdmin && booking.user_id !== req.auth.userId) {
    return res.status(403).json({ error: 'Not allowed to release this booking' });
  }

  if (req.auth.isAdmin && userId && booking.user_id !== Number(userId)) {
    return res.status(400).json({ error: 'Booking at date belongs to different user' });
  }

  db.prepare('DELETE FROM bookings WHERE id = ?').run(booking.id);
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Parking API listening on http://localhost:${PORT}`);
  if (needBootstrap()) {
    console.log('First run detected. Call POST /api/bootstrap with { adminPassword }');
  }
});
