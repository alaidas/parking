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

const sessions = new Map();

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true, mode: 0o700 }); }
function todayISO() { return new Date().toISOString().slice(0, 10); }
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
}

function openDbStrict() {
  ensureDir(DATA_DIR);
  const dbExists = fs.existsSync(DB_PATH);
  const key = getOrCreateDbAccessKey(!dbExists);
  const db = new Database(DB_PATH, { fileMustExist: dbExists });
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
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
  sessions.set(t, { userId: user.id, username: user.username, isAdmin: !!user.is_admin });
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
  return startA < endB && startB < endA;
}

function bookingForDate(spaceId, dateIso) {
  return db.prepare(`
    SELECT b.*, u.username FROM bookings b
    JOIN users u ON u.id = b.user_id
    WHERE b.space_id = ? AND b.start_date <= date(?) AND date(?) < b.end_date
    ORDER BY b.id DESC LIMIT 1
  `).get(spaceId, `${dateIso}T12:00:00Z`, `${dateIso}T12:00:00Z`);
}

app.get('/api/health', (req, res) => res.json({ ok: true, needsBootstrap: needsBootstrap() }));

app.post('/api/bootstrap', (req, res) => {
  if (!needsBootstrap()) return res.status(409).json({ error: 'Already bootstrapped' });
  const { adminPassword } = req.body || {};
  if (!adminPassword || adminPassword.length < 8) return res.status(400).json({ error: 'adminPassword min 8 chars' });
  db.prepare('INSERT INTO users(username,password_hash,is_admin,is_builtin_admin) VALUES (?,?,1,1)')
    .run('admin', bcrypt.hashSync(adminPassword, 10));
  res.json({ ok: true, username: 'admin' });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = issueToken(u);
  res.json({ token, user: { id: u.id, username: u.username, isAdmin: !!u.is_admin } });
});

app.get('/api/me', auth, (req, res) => res.json(req.auth));

app.get('/api/users', auth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, is_admin as isAdmin, is_builtin_admin as isBuiltinAdmin FROM users ORDER BY username').all();
  res.json(rows);
});

app.post('/api/users', auth, requireAdmin, (req, res) => {
  const { username, password, isAdmin = false } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });
  try {
    const out = db.prepare('INSERT INTO users(username,password_hash,is_admin) VALUES (?,?,?)')
      .run(username.trim(), bcrypt.hashSync(password, 10), isAdmin ? 1 : 0);
    res.json({ id: out.lastInsertRowid, username: username.trim(), isAdmin: !!isAdmin });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/users/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_builtin_admin) return res.status(400).json({ error: 'Built-in admin role cannot be changed' });
  db.prepare('UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.body?.isAdmin ? 1 : 0, id);
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
  const newPlain = randomSimplePassword(6);
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(bcrypt.hashSync(newPlain, 10), id);
  res.json({ ok: true, temporaryPassword: newPlain });
});

app.post('/api/me/change-password', auth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.userId);
  if (!bcrypt.compareSync(oldPassword || '', me.password_hash)) return res.status(400).json({ error: 'Wrong old password' });
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'newPassword min 8 chars' });
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(bcrypt.hashSync(newPassword, 10), me.id);
  res.json({ ok: true });
});

app.get('/api/floors', auth, (req, res) => res.json(db.prepare('SELECT * FROM floors ORDER BY id').all()));

app.post('/api/floors', auth, requireAdmin, (req, res) => {
  const { name, imagePath = '' } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const out = db.prepare('INSERT INTO floors(name,image_path) VALUES (?,?)').run(name.trim(), imagePath || null);
  res.json({ id: out.lastInsertRowid });
});

app.patch('/api/floors/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const f = db.prepare('SELECT * FROM floors WHERE id = ?').get(id);
  if (!f) return res.status(404).json({ error: 'Floor not found' });
  const name = req.body?.name ?? f.name;
  const imagePath = req.body?.imagePath ?? f.image_path;
  db.prepare('UPDATE floors SET name = ?, image_path = ? WHERE id = ?').run(name, imagePath || null, id);
  res.json({ ok: true });
});

app.delete('/api/floors/:id', auth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM floors WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/spaces', auth, (req, res) => {
  const floorId = Number(req.query.floorId);
  if (!floorId) return res.status(400).json({ error: 'floorId required' });
  res.json(db.prepare('SELECT * FROM spaces WHERE floor_id = ? ORDER BY space_number').all(floorId));
});

app.post('/api/spaces', auth, requireAdmin, (req, res) => {
  const p = req.body || {};
  if (!p.floorId || !p.spaceNumber) return res.status(400).json({ error: 'floorId/spaceNumber required' });
  try {
    const out = db.prepare(`
      INSERT INTO spaces(floor_id,space_number,x,y,w,h,dir,map_x,map_y,map_zoom)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `).run(
      p.floorId, String(p.spaceNumber), p.x ?? 30, p.y ?? 160, p.w ?? 72, p.h ?? 170,
      p.dir ?? 'down', p.mapX ?? null, p.mapY ?? null, p.mapZoom ?? null
    );
    res.json({ id: out.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const s = db.prepare('SELECT * FROM spaces WHERE id = ?').get(id);
  if (!s) return res.status(404).json({ error: 'Space not found' });
  const p = req.body || {};
  db.prepare(`
    UPDATE spaces SET floor_id=?, space_number=?, x=?, y=?, w=?, h=?, dir=?, map_x=?, map_y=?, map_zoom=?
    WHERE id=?
  `).run(
    p.floorId ?? s.floor_id, String(p.spaceNumber ?? s.space_number), p.x ?? s.x, p.y ?? s.y,
    p.w ?? s.w, p.h ?? s.h, p.dir ?? s.dir, p.mapX ?? s.map_x, p.mapY ?? s.map_y, p.mapZoom ?? s.map_zoom, id
  );
  res.json({ ok: true });
});

app.delete('/api/spaces/:id', auth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM spaces WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/bookings', auth, (req, res) => {
  const floorId = Number(req.query.floorId);
  if (!floorId) return res.status(400).json({ error: 'floorId required' });
  const rows = db.prepare(`
    SELECT b.*, u.username, s.space_number
    FROM bookings b
    JOIN users u ON u.id = b.user_id
    JOIN spaces s ON s.id = b.space_id
    WHERE b.floor_id = ?
    ORDER BY b.start_date
  `).all(floorId);
  res.json(rows);
});

app.get('/api/availability', auth, (req, res) => {
  const floorId = Number(req.query.floorId);
  const date = String(req.query.date || '');
  if (!floorId || !date) return res.status(400).json({ error: 'floorId/date required' });
  const spaces = db.prepare('SELECT * FROM spaces WHERE floor_id = ? ORDER BY space_number').all(floorId);
  const out = spaces.map(s => {
    const b = bookingForDate(s.id, date);
    return { ...s, isBooked: !!b, bookingUser: b?.username || null, bookingId: b?.id || null, bookingOwnerId: b?.user_id || null, bookingEnd: b?.end_date || null };
  });
  res.json(out);
});

app.post('/api/bookings', auth, (req, res) => {
  const p = req.body || {};
  if (!p.floorId || !p.spaceId || !p.startDate || !p.endDate) return res.status(400).json({ error: 'floorId/spaceId/startDate/endDate required' });
  const start = p.startDate;
  const end = p.endDate;
  if (new Date(`${start}T00:00:00Z`) >= new Date(`${end}T00:00:00Z`)) return res.status(400).json({ error: 'Invalid date range' });

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
  const { spaceId, date, userId } = req.body || {};
  if (!spaceId || !date) return res.status(400).json({ error: 'spaceId/date required' });
  const b = bookingForDate(Number(spaceId), date);
  if (!b) return res.status(404).json({ error: 'No booking at selected date' });

  if (!req.auth.isAdmin && b.user_id !== req.auth.userId) return res.status(403).json({ error: 'Cannot release this booking' });
  if (req.auth.isAdmin && userId && Number(userId) !== b.user_id) return res.status(400).json({ error: 'Booking belongs to different user' });

  db.prepare('DELETE FROM bookings WHERE id = ?').run(b.id);
  res.json({ ok: true });
});

app.post('/api/seed-demo', auth, requireAdmin, (req, res) => {
  const fCount = db.prepare('SELECT COUNT(*) c FROM floors').get().c;
  if (!fCount) {
    const f1 = db.prepare('INSERT INTO floors(name,image_path) VALUES (?,?)').run('Floor 1', './resources/parking-outside.png').lastInsertRowid;
    const f2 = db.prepare('INSERT INTO floors(name,image_path) VALUES (?,?)').run('Floor 2', './resources/parking-minus-two.png').lastInsertRowid;
    for (let i = 0; i < 13; i++) db.prepare('INSERT INTO spaces(floor_id,space_number,x,y,w,h,dir) VALUES (?,?,?,?,?,?,?)').run(f1, String(i).padStart(3, '0'), 18 + i * 93, 160, 70, 170, 'down');
    for (let i = 0; i < 7; i++) db.prepare('INSERT INTO spaces(floor_id,space_number,x,y,w,h,dir) VALUES (?,?,?,?,?,?,?)').run(f1, String(13 + i).padStart(3, '0'), 550 + i * 88, 485, 66, 165, 'up');
    for (let i = 0; i < 5; i++) db.prepare('INSERT INTO spaces(floor_id,space_number,x,y,w,h,dir) VALUES (?,?,?,?,?,?,?)').run(f2, String(20 + i).padStart(3, '0'), 170 + i * 95, 175, 72, 175, 'down');
    for (let i = 0; i < 5; i++) db.prepare('INSERT INTO spaces(floor_id,space_number,x,y,w,h,dir) VALUES (?,?,?,?,?,?,?)').run(f2, String(25 + i).padStart(3, '0'), 610 + i * 95, 470, 72, 175, 'up');
  }

  const admin = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
  if (admin) {
    const any = db.prepare('SELECT COUNT(*) c FROM bookings').get().c;
    if (!any) {
      const s = db.prepare('SELECT * FROM spaces ORDER BY id LIMIT 1').get();
      if (s) db.prepare('INSERT INTO bookings(floor_id,space_id,user_id,start_date,end_date,created_by_user_id) VALUES (?,?,?,?,?,?)')
        .run(s.floor_id, s.id, admin.id, todayISO(), addDays(todayISO(), 2), admin.id);
    }
  }
  res.json({ ok: true });
});

app.use(express.static(ROOT));
app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'index.html')));

app.listen(PORT, () => {
  console.log(`Parking app listening on http://localhost:${PORT}`);
  if (needsBootstrap()) console.log('First run: POST /api/bootstrap {"adminPassword":"..."}');
});
