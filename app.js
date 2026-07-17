// ============================================================================
// Makkah Health Cluster — Volunteer Management Portal
// Single-file edition. Everything (backend + frontend) lives in this one file.
// Run with:  node app.js
// Requires only Node.js 22.5+ — no npm install, no other files needed.
// ============================================================================
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Auth helpers (password hashing + signed session tokens, node:crypto only)
// ---------------------------------------------------------------------------
const SECRET = process.env.SESSION_SECRET || 'volunteer-mgmt-dev-secret-change-in-production';

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}
function createToken(payload, expiresInSeconds = 60 * 60 * 24 * 7) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds };
  const encoded = base64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  const a = Buffer.from(sig || '', 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(base64urlDecode(encoded));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Database (SQLite via Node's built-in node:sqlite)
// ---------------------------------------------------------------------------
const db = new DatabaseSync(path.join(DATA_DIR, 'vms.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('vp','manager','volunteer')),
  manager_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS kpis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  target_value REAL,
  current_value REAL DEFAULT 0,
  unit TEXT,
  period TEXT,
  status TEXT NOT NULL DEFAULT 'on_track',
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ideas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submitted_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  response TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS complaints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submitted_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  resolution_notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  manager_id INTEGER NOT NULL,
  period TEXT,
  summary TEXT,
  status TEXT NOT NULL DEFAULT 'submitted',
  vp_notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uploaded_by INTEGER NOT NULL,
  filename TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  description TEXT,
  visible_to TEXT NOT NULL DEFAULT 'all',
  size INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS surveys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  google_form_url TEXT,
  google_sheet_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const seedEmail = process.env.VP_EMAIL || 'vp@example.org';
  const seedPassword = process.env.VP_PASSWORD || 'ChangeMe123!';
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run(
    'VP Admin', seedEmail, hashPassword(seedPassword), 'vp'
  );
  console.log('============================================');
  console.log(' First run: created default VP login');
  console.log(' Email:    ' + seedEmail);
  console.log(' Password: ' + seedPassword);
  console.log(' Please log in and change this immediately.');
  console.log('============================================');
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(body);
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    const MAX = 20 * 1024 * 1024;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX) { reject(new Error('Payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
function getAuthUser(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7);
  const payload = verifyToken(token);
  if (!payload) return null;
  const user = db.prepare('SELECT id, name, email, role, manager_id, active FROM users WHERE id = ?').get(payload.id);
  if (!user || !user.active) return null;
  return user;
}
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, email: u.email, role: u.role, manager_id: u.manager_id };
}
function visibleUserIds(user) {
  if (user.role === 'vp') return db.prepare('SELECT id FROM users').all().map((r) => r.id);
  if (user.role === 'manager') {
    const team = db.prepare('SELECT id FROM users WHERE manager_id = ?').all(user.id).map((r) => r.id);
    return [user.id, ...team];
  }
  return [user.id];
}
function isManagerOf(user, targetId) {
  if (user.role === 'vp') return true;
  const row = db.prepare('SELECT manager_id FROM users WHERE id = ?').get(targetId);
  return row && row.manager_id === user.id;
}
function visibleKpiOwnerIds(user) {
  if (user.role === 'vp') return db.prepare('SELECT id FROM users').all().map((r) => r.id);
  if (user.role === 'manager') return [user.id];
  return user.manager_id ? [user.manager_id] : [];
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
const routes = [];
function route(method, pattern, handler) {
  const keys = [];
  const regex = new RegExp('^' + pattern.replace(/:[a-zA-Z]+/g, (m) => { keys.push(m.slice(1)); return '([^/]+)'; }) + '$');
  routes.push({ method, regex, keys, handler });
}

route('POST', '/api/login', async (req, res) => {
  const body = await readJsonBody(req);
  const { email, password } = body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase().trim());
  if (!user || !user.active || !verifyPassword(password || '', user.password)) {
    return send(res, 401, { error: 'Invalid email or password' });
  }
  const token = createToken({ id: user.id });
  send(res, 200, { token, user: publicUser(user) });
});

route('GET', '/api/me', async (req, res, ctx) => { send(res, 200, { user: publicUser(ctx.user) }); });

route('POST', '/api/me/password', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  const full = db.prepare('SELECT * FROM users WHERE id = ?').get(ctx.user.id);
  if (!verifyPassword(body.current_password || '', full.password)) {
    return send(res, 400, { error: 'Current password is incorrect' });
  }
  if (!body.new_password || body.new_password.length < 6) {
    return send(res, 400, { error: 'New password must be at least 6 characters' });
  }
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(body.new_password), ctx.user.id);
  send(res, 200, { ok: true });
});

route('GET', '/api/users', async (req, res, ctx) => {
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT id, name, email, role, manager_id, active, created_at FROM users ORDER BY role, name').all();
  } else if (ctx.user.role === 'manager') {
    rows = db.prepare('SELECT id, name, email, role, manager_id, active, created_at FROM users WHERE manager_id = ? OR id = ? ORDER BY name').all(ctx.user.id, ctx.user.id);
  } else {
    rows = db.prepare('SELECT id, name, email, role, manager_id, active, created_at FROM users WHERE id = ?').all(ctx.user.id);
  }
  send(res, 200, { users: rows });
});

route('POST', '/api/users', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  const { name, email, password, role } = body;
  if (!name || !email || !password || !role) return send(res, 400, { error: 'Missing fields' });
  if (ctx.user.role === 'vp' && role !== 'manager') return send(res, 403, { error: 'VP can only create manager accounts here (managers add their own volunteers)' });
  if (ctx.user.role === 'manager' && role !== 'volunteer') return send(res, 403, { error: 'Managers can only add volunteers' });
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (exists) return send(res, 400, { error: 'A user with that email already exists' });
  const managerId = role === 'volunteer' ? ctx.user.id : null;
  const info = db.prepare('INSERT INTO users (name, email, password, role, manager_id) VALUES (?, ?, ?, ?, ?)')
    .run(name, email.toLowerCase().trim(), hashPassword(password), role, managerId);
  const user = db.prepare('SELECT id, name, email, role, manager_id, active FROM users WHERE id = ?').get(info.lastInsertRowid);
  send(res, 201, { user });
});

route('PUT', '/api/users/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, id) || ctx.user.id === id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (typeof body.name === 'string') { fields.push('name = ?'); values.push(body.name); }
  if (typeof body.active === 'boolean' && ctx.user.role !== 'volunteer') { fields.push('active = ?'); values.push(body.active ? 1 : 0); }
  if (body.password) { fields.push('password = ?'); values.push(hashPassword(body.password)); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  values.push(id);
  db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/users/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  if (!isManagerOf(ctx.user, id) && ctx.user.role !== 'vp') return send(res, 403, { error: 'Not permitted' });
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/kpis', async (req, res, ctx) => {
  const ids = visibleKpiOwnerIds(ctx.user);
  const placeholders = ids.map(() => '?').join(',') || '0';
  const rows = db.prepare(`SELECT k.*, u.name AS owner_name FROM kpis k JOIN users u ON u.id = k.owner_id WHERE k.owner_id IN (${placeholders}) ORDER BY k.created_at DESC`).all(...ids);
  send(res, 200, { kpis: rows });
});

route('POST', '/api/kpis', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const ownerId = ctx.user.role === 'vp' && body.owner_id ? Number(body.owner_id) : ctx.user.id;
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO kpis (owner_id, title, description, target_value, current_value, unit, period, status, created_by) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(ownerId, body.title, body.description || '', body.target_value ?? null, body.current_value ?? 0, body.unit || '', body.period || '', body.status || 'on_track', ctx.user.id);
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/kpis/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const kpi = db.prepare('SELECT * FROM kpis WHERE id = ?').get(id);
  if (!kpi) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || kpi.owner_id === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  for (const f of ['title', 'description', 'target_value', 'current_value', 'unit', 'period', 'status']) {
    if (body[f] !== undefined) { fields.push(`${f} = ?`); values.push(body[f]); }
  }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE kpis SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/kpis/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const kpi = db.prepare('SELECT * FROM kpis WHERE id = ?').get(id);
  if (!kpi) return send(res, 404, { error: 'Not found' });
  if (ctx.user.role !== 'vp' && kpi.owner_id !== ctx.user.id) return send(res, 403, { error: 'Not permitted' });
  db.prepare('DELETE FROM kpis WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/ideas', async (req, res, ctx) => {
  const ids = visibleUserIds(ctx.user);
  const placeholders = ids.map(() => '?').join(',') || '0';
  const rows = db.prepare(`SELECT i.*, u.name AS submitter_name, u.role AS submitter_role FROM ideas i JOIN users u ON u.id = i.submitted_by WHERE i.submitted_by IN (${placeholders}) ORDER BY i.created_at DESC`).all(...ids);
  send(res, 200, { ideas: rows });
});

route('POST', '/api/ideas', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO ideas (submitted_by, title, description) VALUES (?,?,?)').run(ctx.user.id, body.title, body.description || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/ideas/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const idea = db.prepare('SELECT * FROM ideas WHERE id = ?').get(id);
  if (!idea) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, idea.submitted_by) || idea.submitted_by === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (body.status && ctx.user.role !== 'volunteer') { fields.push('status = ?'); values.push(body.status); }
  if (body.response !== undefined && ctx.user.role !== 'volunteer') { fields.push('response = ?'); values.push(body.response); }
  if (body.title && idea.submitted_by === ctx.user.id) { fields.push('title = ?'); values.push(body.title); }
  if (body.description !== undefined && idea.submitted_by === ctx.user.id) { fields.push('description = ?'); values.push(body.description); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE ideas SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('GET', '/api/complaints', async (req, res, ctx) => {
  const ids = visibleUserIds(ctx.user);
  const placeholders = ids.map(() => '?').join(',') || '0';
  const rows = db.prepare(`SELECT c.*, u.name AS submitter_name, u.role AS submitter_role FROM complaints c JOIN users u ON u.id = c.submitted_by WHERE c.submitted_by IN (${placeholders}) ORDER BY c.created_at DESC`).all(...ids);
  send(res, 200, { complaints: rows });
});

route('POST', '/api/complaints', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO complaints (submitted_by, title, description) VALUES (?,?,?)').run(ctx.user.id, body.title, body.description || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/complaints/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const c = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
  if (!c) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, c.submitted_by) || c.submitted_by === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (body.status && ctx.user.role !== 'volunteer') { fields.push('status = ?'); values.push(body.status); }
  if (body.resolution_notes !== undefined && ctx.user.role !== 'volunteer') { fields.push('resolution_notes = ?'); values.push(body.resolution_notes); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE complaints SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('GET', '/api/reports', async (req, res, ctx) => {
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT r.*, u.name AS manager_name FROM reports r JOIN users u ON u.id = r.manager_id ORDER BY r.created_at DESC').all();
  } else if (ctx.user.role === 'manager') {
    rows = db.prepare('SELECT r.*, u.name AS manager_name FROM reports r JOIN users u ON u.id = r.manager_id WHERE r.manager_id = ? ORDER BY r.created_at DESC').all(ctx.user.id);
  } else {
    return send(res, 403, { error: 'Not permitted' });
  }
  send(res, 200, { reports: rows });
});

route('POST', '/api/reports', async (req, res, ctx) => {
  if (ctx.user.role !== 'manager') return send(res, 403, { error: 'Only managers submit reports to the VP' });
  const body = await readJsonBody(req);
  if (!body.summary) return send(res, 400, { error: 'Summary required' });
  const info = db.prepare('INSERT INTO reports (manager_id, period, summary) VALUES (?,?,?)').run(ctx.user.id, body.period || '', body.summary);
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/reports/:id', async (req, res, ctx) => {
  if (ctx.user.role !== 'vp') return send(res, 403, { error: 'Only the VP can update report status' });
  const id = Number(ctx.params.id);
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (body.status) { fields.push('status = ?'); values.push(body.status); }
  if (body.vp_notes !== undefined) { fields.push('vp_notes = ?'); values.push(body.vp_notes); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  values.push(id);
  db.prepare(`UPDATE reports SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('GET', '/api/reports/snapshot', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const scope = visibleUserIds(ctx.user);
  const placeholders = scope.map(() => '?').join(',') || '0';
  const openComplaints = db.prepare(`SELECT COUNT(*) c FROM complaints WHERE status != 'resolved' AND submitted_by IN (${placeholders})`).get(...scope).c;
  const newIdeas = db.prepare(`SELECT COUNT(*) c FROM ideas WHERE status = 'new' AND submitted_by IN (${placeholders})`).get(...scope).c;
  const kpiCount = db.prepare(`SELECT COUNT(*) c FROM kpis WHERE owner_id IN (${placeholders})`).get(...scope).c;
  send(res, 200, { openComplaints, newIdeas, kpiCount });
});

route('GET', '/api/files', async (req, res, ctx) => {
  const rows = db.prepare('SELECT f.id, f.filename, f.description, f.visible_to, f.size, f.created_at, u.name AS uploader_name FROM files f JOIN users u ON u.id = f.uploaded_by ORDER BY f.created_at DESC').all();
  send(res, 200, { files: rows });
});

route('POST', '/api/files', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Only managers/VP can upload files' });
  const body = await readJsonBody(req);
  const { filename, description, data_base64, visible_to } = body;
  if (!filename || !data_base64) return send(res, 400, { error: 'filename and data_base64 required' });
  const safeExt = path.extname(filename).toLowerCase();
  if (!['.csv', '.xlsx', '.xls', '.tsv'].includes(safeExt)) return send(res, 400, { error: 'Only .csv, .tsv, .xls, .xlsx files are allowed' });
  const storedName = crypto.randomBytes(16).toString('hex') + safeExt;
  const buffer = Buffer.from(data_base64, 'base64');
  fs.writeFileSync(path.join(UPLOAD_DIR, storedName), buffer);
  const info = db.prepare('INSERT INTO files (uploaded_by, filename, stored_name, description, visible_to, size) VALUES (?,?,?,?,?,?)')
    .run(ctx.user.id, filename, storedName, description || '', visible_to || 'all', buffer.length);
  send(res, 201, { id: info.lastInsertRowid });
});

route('GET', '/api/files/:id/download', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(id);
  if (!file) return send(res, 404, { error: 'Not found' });
  const filePath = path.join(UPLOAD_DIR, file.stored_name);
  if (!fs.existsSync(filePath)) return send(res, 404, { error: 'File missing on disk' });
  const data = fs.readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${file.filename.replace(/"/g, '')}"` });
  res.end(data);
});

route('DELETE', '/api/files/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const id = Number(ctx.params.id);
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(id);
  if (!file) return send(res, 404, { error: 'Not found' });
  try { fs.unlinkSync(path.join(UPLOAD_DIR, file.stored_name)); } catch {}
  db.prepare('DELETE FROM files WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/surveys', async (req, res, ctx) => {
  const rows = db.prepare('SELECT s.*, u.name AS creator_name FROM surveys s JOIN users u ON u.id = s.created_by ORDER BY s.created_at DESC').all();
  send(res, 200, { surveys: rows });
});

route('POST', '/api/surveys', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO surveys (created_by, title, google_form_url, google_sheet_url) VALUES (?,?,?,?)').run(ctx.user.id, body.title, body.google_form_url || '', body.google_sheet_url || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('DELETE', '/api/surveys/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  db.prepare('DELETE FROM surveys WHERE id = ?').run(Number(ctx.params.id));
  send(res, 200, { ok: true });
});

route('GET', '/api/announcements', async (req, res, ctx) => {
  const rows = db.prepare('SELECT a.*, u.name AS creator_name FROM announcements a JOIN users u ON u.id = a.created_by ORDER BY a.created_at DESC LIMIT 50').all();
  send(res, 200, { announcements: rows });
});

route('POST', '/api/announcements', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO announcements (created_by, title, body) VALUES (?,?,?)').run(ctx.user.id, body.title, body.body || '');
  send(res, 201, { id: info.lastInsertRowid });
});

// ---------------------------------------------------------------------------
// Frontend, embedded as base64 (no separate files needed).
// ---------------------------------------------------------------------------
const INDEX_HTML = Buffer.from('PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04IiAvPgo8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCIgLz4KPHRpdGxlPk1ha2thaCBIZWFsdGggQ2x1c3RlciB8IFZvbHVudGVlciBNYW5hZ2VtZW50IFBvcnRhbDwvdGl0bGU+CjxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iL2Nzcy9zdHlsZS5jc3MiIC8+CjxzY3JpcHQgc3JjPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy94bHN4LzAuMTguNS94bHN4LmZ1bGwubWluLmpzIj48L3NjcmlwdD4KPC9oZWFkPgo8Ym9keT4KCjwhLS0gTE9HSU4gU0NSRUVOIC0tPgo8ZGl2IGlkPSJsb2dpblNjcmVlbiIgY2xhc3M9ImxvZ2luLXdyYXAiPgogIDxkaXYgY2xhc3M9ImxvZ2luLXBhdHRlcm4iPjwvZGl2PgogIDxkaXYgY2xhc3M9ImxvZ2luLWNhcmQiPgogICAgPGRpdiBjbGFzcz0ibG9naW4tbWFyayI+CiAgICAgIDxzdmcgdmlld0JveD0iMCAwIDEwMCAxMDAiIHdpZHRoPSI0NiIgaGVpZ2h0PSI0NiIgYXJpYS1oaWRkZW49InRydWUiPgogICAgICAgIDxwb2x5Z29uIHBvaW50cz0iNTAsNCA2MSwzNSA5NCwzNSA2Nyw1NSA3OCw4OCA1MCw2OCAyMiw4OCAzMyw1NSA2LDM1IDM5LDM1IgogICAgICAgICAgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ2YXIoLS1hY2NlbnQpIiBzdHJva2Utd2lkdGg9IjQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KICAgICAgPC9zdmc+CiAgICA8L2Rpdj4KICAgIDxoMT5NYWtrYWggSGVhbHRoIENsdXN0ZXI8L2gxPgogICAgPHAgY2xhc3M9ImFyLXN1YnRpdGxlIj7Yqtis2YXYuSDZhdmD2Kkg2KfZhNmF2YPYsdmF2Kkg2KfZhNi12K3ZijwvcD4KICAgIDxwIGNsYXNzPSJtdXRlZCI+Vm9sdW50ZWVyIE1hbmFnZW1lbnQgUG9ydGFsICZtZGFzaDsgU2lnbiBpbiB0byBjb250aW51ZTwvcD4KICAgIDxmb3JtIGlkPSJsb2dpbkZvcm0iPgogICAgICA8bGFiZWw+RW1haWw8L2xhYmVsPgogICAgICA8aW5wdXQgdHlwZT0iZW1haWwiIGlkPSJsb2dpbkVtYWlsIiByZXF1aXJlZCBhdXRvY29tcGxldGU9InVzZXJuYW1lIiAvPgogICAgICA8bGFiZWw+UGFzc3dvcmQ8L2xhYmVsPgogICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJsb2dpblBhc3N3b3JkIiByZXF1aXJlZCBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiIC8+CiAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IGJ0bi1ibG9jayI+U2lnbiBJbjwvYnV0dG9uPgogICAgICA8cCBpZD0ibG9naW5FcnJvciIgY2xhc3M9ImVycm9yLXRleHQiPjwvcD4KICAgIDwvZm9ybT4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tIEFQUCBTSEVMTCAtLT4KPGRpdiBpZD0iYXBwIiBjbGFzcz0iYXBwIGhpZGRlbiI+CiAgPGFzaWRlIGNsYXNzPSJzaWRlYmFyIj4KICAgIDxkaXYgY2xhc3M9ImJyYW5kIj4KICAgICAgPHN2ZyB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgd2lkdGg9IjI2IiBoZWlnaHQ9IjI2IiBhcmlhLWhpZGRlbj0idHJ1ZSI+CiAgICAgICAgPHBvbHlnb24gcG9pbnRzPSI1MCw0IDYxLDM1IDk0LDM1IDY3LDU1IDc4LDg4IDUwLDY4IDIyLDg4IDMzLDU1IDYsMzUgMzksMzUiCiAgICAgICAgICBmaWxsPSJub25lIiBzdHJva2U9InZhcigtLWFjY2VudCkiIHN0cm9rZS13aWR0aD0iNSIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPgogICAgICA8L3N2Zz4KICAgICAgPHNwYW4+CiAgICAgICAgPGRpdiBjbGFzcz0iYnJhbmQtZW4iPk1ha2thaCBIZWFsdGggQ2x1c3RlcjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImJyYW5kLWFyIj7Yqtis2YXYuSDZhdmD2Kkg2KfZhNmF2YPYsdmF2Kkg2KfZhNi12K3ZijwvZGl2PgogICAgICA8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxuYXYgaWQ9Im5hdkxpbmtzIj48L25hdj4KICAgIDxkaXYgY2xhc3M9InNpZGViYXItZm9vdGVyIj4KICAgICAgPGRpdiBpZD0idXNlckJhZGdlIiBjbGFzcz0idXNlci1iYWRnZSI+PC9kaXY+CiAgICAgIDxidXR0b24gaWQ9ImNoYW5nZVB3QnRuIiBjbGFzcz0iYnRuIGJ0bi1naG9zdCBidG4tYmxvY2siPkNoYW5nZSBwYXNzd29yZDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGlkPSJsb2dvdXRCdG4iIGNsYXNzPSJidG4gYnRuLWdob3N0IGJ0bi1ibG9jayI+TG9nIG91dDwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9hc2lkZT4KCiAgPG1haW4gY2xhc3M9Im1haW4iPgogICAgPGhlYWRlciBjbGFzcz0idG9wYmFyIj4KICAgICAgPGgyIGlkPSJwYWdlVGl0bGUiPkRhc2hib2FyZDwvaDI+CiAgICAgIDxkaXYgY2xhc3M9InRvcGJhci1zdWIgbXV0ZWQiPlZvbHVudGVlciBNYW5hZ2VtZW50IFBvcnRhbDwvZGl2PgogICAgPC9oZWFkZXI+CiAgICA8ZGl2IGlkPSJ2aWV3IiBjbGFzcz0idmlldyI+PC9kaXY+CiAgPC9tYWluPgo8L2Rpdj4KCjwhLS0gR2VuZXJpYyBtb2RhbCAtLT4KPGRpdiBpZD0ibW9kYWxPdmVybGF5IiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWhlYWRlciI+CiAgICAgIDxoMyBpZD0ibW9kYWxUaXRsZSI+VGl0bGU8L2gzPgogICAgICA8YnV0dG9uIGlkPSJtb2RhbENsb3NlIiBjbGFzcz0iYnRuLWljb24iPiZ0aW1lczs8L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBpZD0ibW9kYWxCb2R5IiBjbGFzcz0ibW9kYWwtYm9keSI+PC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPGRpdiBpZD0idG9hc3QiIGNsYXNzPSJ0b2FzdCBoaWRkZW4iPjwvZGl2PgoKPHNjcmlwdCBzcmM9Ii9qcy9hcHAuanMiPjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K', 'base64').toString('utf8');
const STYLE_CSS = Buffer.from('OnJvb3QgewogIC8qIE1ha2thaCBIZWFsdGggQ2x1c3RlciB0aGVtZTogU2F1ZGkgZmxhZyBncmVlbiArIEthYWJhLWdvbGQgYWNjZW50ICovCiAgLS1wcmltYXJ5OiAjMDA2OTNlOwogIC0tcHJpbWFyeS1kYXJrOiAjMDAzZDI0OwogIC0tYWNjZW50OiAjYzlhMjI3OwogIC0tYmc6ICNmNWY3ZjU7CiAgLS1jYXJkOiAjZmZmZmZmOwogIC0tdGV4dDogIzFjMjYyMjsKICAtLW11dGVkOiAjNjY3MDY5OwogIC0tYm9yZGVyOiAjZTBlNmUxOwogIC0tZGFuZ2VyOiAjYjM0NjJjOwogIC0tc3VjY2VzczogIzAwNjkzZTsKICAtLXdhcm5pbmc6ICNjOWEyMjc7CiAgLS1yYWRpdXM6IDEwcHg7Cn0KCiogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CmJvZHkgewogIG1hcmdpbjogMDsKICBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAiU2Vnb2UgVUkiLCBSb2JvdG8sIEhlbHZldGljYSwgQXJpYWwsIHNhbnMtc2VyaWY7CiAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogIGNvbG9yOiB2YXIoLS10ZXh0KTsKfQouaGlkZGVuIHsgZGlzcGxheTogbm9uZSAhaW1wb3J0YW50OyB9Ci5tdXRlZCB7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IH0KCi8qIExvZ2luICovCi5sb2dpbi13cmFwIHsKICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgbWluLWhlaWdodDogMTAwdmg7CiAgZGlzcGxheTogZmxleDsKICBhbGlnbi1pdGVtczogY2VudGVyOwogIGp1c3RpZnktY29udGVudDogY2VudGVyOwogIGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCgxMzVkZWcsIHZhcigtLXByaW1hcnkpIDAlLCB2YXIoLS1wcmltYXJ5LWRhcmspIDEwMCUpOwogIG92ZXJmbG93OiBoaWRkZW47Cn0KLmxvZ2luLXBhdHRlcm4gewogIHBvc2l0aW9uOiBhYnNvbHV0ZTsgaW5zZXQ6IDA7CiAgb3BhY2l0eTogMC4xMDsKICBiYWNrZ3JvdW5kLWltYWdlOgogICAgcmFkaWFsLWdyYWRpZW50KGNpcmNsZSBhdCAyMCUgMjAlLCB0cmFuc3BhcmVudCAwIDE4cHgsIHJnYmEoMjU1LDI1NSwyNTUsMC41KSAxOXB4LCB0cmFuc3BhcmVudCAyMHB4KSwKICAgIHJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoNDVkZWcsIHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgMCAycHgsIHRyYW5zcGFyZW50IDJweCA0MHB4KSwKICAgIHJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoLTQ1ZGVnLCByZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDAgMnB4LCB0cmFuc3BhcmVudCAycHggNDBweCk7CiAgcG9pbnRlci1ldmVudHM6IG5vbmU7Cn0KLmxvZ2luLWNhcmQgewogIHBvc2l0aW9uOiByZWxhdGl2ZTsKICBiYWNrZ3JvdW5kOiB2YXIoLS1jYXJkKTsKICBwYWRkaW5nOiA0MHB4OwogIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgd2lkdGg6IDM2MHB4OwogIGJveC1zaGFkb3c6IDAgMjBweCA1MHB4IHJnYmEoMCwwLDAsMC4zKTsKICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgYm9yZGVyLXRvcDogNHB4IHNvbGlkIHZhcigtLWFjY2VudCk7Cn0KLmxvZ2luLW1hcmsgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgbWFyZ2luLWJvdHRvbTogMTJweDsgfQoubG9naW4tY2FyZCBoMSB7IGZvbnQtc2l6ZTogMjBweDsgbWFyZ2luOiAwIDAgMnB4OyBjb2xvcjogdmFyKC0tcHJpbWFyeS1kYXJrKTsgfQouYXItc3VidGl0bGUgeyBtYXJnaW46IDAgMCAxMHB4OyBmb250LXNpemU6IDE1cHg7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGRpcmVjdGlvbjogcnRsOyB9Ci5sb2dpbi1jYXJkIHAgeyBtYXJnaW4tdG9wOiAwOyBtYXJnaW4tYm90dG9tOiAyMHB4OyB9Ci5sb2dpbi1jYXJkIGxhYmVsIHsgZGlzcGxheTogYmxvY2s7IGZvbnQtc2l6ZTogMTNweDsgbWFyZ2luOiAxNHB4IDAgNnB4OyBmb250LXdlaWdodDogNjAwOyB0ZXh0LWFsaWduOiBsZWZ0OyB9Ci5sb2dpbi1jYXJkIGlucHV0IHsgd2lkdGg6IDEwMCU7IHBhZGRpbmc6IDEwcHggMTJweDsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogOHB4OyBmb250LXNpemU6IDE0cHg7IH0KLmVycm9yLXRleHQgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgZm9udC1zaXplOiAxM3B4OyBtaW4taGVpZ2h0OiAxOHB4OyBtYXJnaW4tdG9wOiAxMHB4OyB9CgovKiBCdXR0b25zICovCi5idG4gewogIGRpc3BsYXk6IGlubGluZS1mbGV4OwogIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgZ2FwOiA2cHg7CiAgcGFkZGluZzogOXB4IDE2cHg7CiAgYm9yZGVyLXJhZGl1czogOHB4OwogIGJvcmRlcjogMXB4IHNvbGlkIHRyYW5zcGFyZW50OwogIGZvbnQtc2l6ZTogMTRweDsKICBmb250LXdlaWdodDogNjAwOwogIGN1cnNvcjogcG9pbnRlcjsKICBiYWNrZ3JvdW5kOiB2YXIoLS1ib3JkZXIpOwogIGNvbG9yOiB2YXIoLS10ZXh0KTsKfQouYnRuLXByaW1hcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5KTsgY29sb3I6ICNmZmY7IH0KLmJ0bi1wcmltYXJ5OmhvdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeS1kYXJrKTsgfQouYnRuLWRhbmdlciB7IGJhY2tncm91bmQ6IHZhcigtLWRhbmdlcik7IGNvbG9yOiAjZmZmOyB9Ci5idG4tZ2hvc3QgeyBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsgY29sb3I6ICNkN2RlZDk7IGJvcmRlcjogMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4yNSk7IH0KLmJ0bi1naG9zdDpob3ZlciB7IGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7IH0KLmJ0bi1ibG9jayB7IHdpZHRoOiAxMDAlOyBtYXJnaW4tdG9wOiAxOHB4OyB9Ci5idG4tc20geyBwYWRkaW5nOiA1cHggMTBweDsgZm9udC1zaXplOiAxMnB4OyB9Ci5idG4taWNvbiB7IGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OyBib3JkZXI6IG5vbmU7IGZvbnQtc2l6ZTogMjJweDsgY3Vyc29yOiBwb2ludGVyOyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBsaW5lLWhlaWdodDogMTsgfQoKLyogQXBwIHNoZWxsICovCi5hcHAgeyBkaXNwbGF5OiBmbGV4OyBtaW4taGVpZ2h0OiAxMDB2aDsgfQouc2lkZWJhciB7CiAgd2lkdGg6IDIyMHB4OwogIGJhY2tncm91bmQ6IHZhcigtLXByaW1hcnktZGFyayk7CiAgY29sb3I6ICNmZmY7CiAgZGlzcGxheTogZmxleDsKICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogIHBhZGRpbmc6IDIwcHggMDsKICBmbGV4LXNocmluazogMDsKfQouYnJhbmQgewogIGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTBweDsKICBwYWRkaW5nOiAwIDE4cHggMThweDsgbWFyZ2luLWJvdHRvbTogNnB4OwogIGJvcmRlci1ib3R0b206IDFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMTIpOwp9Ci5icmFuZC1lbiB7IGZvbnQtd2VpZ2h0OiA4MDA7IGZvbnQtc2l6ZTogMTRweDsgbGluZS1oZWlnaHQ6IDEuMjU7IH0KLmJyYW5kLWFyIHsgZm9udC1zaXplOiAxMnB4OyBjb2xvcjogI2I5YzljMDsgZGlyZWN0aW9uOiBydGw7IG1hcmdpbi10b3A6IDFweDsgfQouc2lkZWJhciBuYXYgeyBmbGV4OiAxOyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDJweDsgfQouc2lkZWJhciBuYXYgYSB7CiAgY29sb3I6ICNjZmQ4ZDM7CiAgdGV4dC1kZWNvcmF0aW9uOiBub25lOwogIHBhZGRpbmc6IDEwcHggMjBweDsKICBmb250LXNpemU6IDE0cHg7CiAgZm9udC13ZWlnaHQ6IDUwMDsKICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHRyYW5zcGFyZW50OwogIGN1cnNvcjogcG9pbnRlcjsKfQouc2lkZWJhciBuYXYgYTpob3ZlciB7IGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsMC4wNik7IGNvbG9yOiAjZmZmOyB9Ci5zaWRlYmFyIG5hdiBhLmFjdGl2ZSB7IGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsMC4xKTsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiAjZmZmOyB9Ci5zaWRlYmFyLWZvb3RlciB7IHBhZGRpbmc6IDE2cHggMjBweCAwOyBib3JkZXItdG9wOiAxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEyKTsgbWFyZ2luLXRvcDogMTBweDsgfQoudXNlci1iYWRnZSB7IGZvbnQtc2l6ZTogMTNweDsgbWFyZ2luLWJvdHRvbTogMTBweDsgfQoudXNlci1iYWRnZSAucm9sZS1waWxsIHsgZGlzcGxheTogaW5saW5lLWJsb2NrOyBtYXJnaW4tdG9wOiA0cHg7IGZvbnQtc2l6ZTogMTFweDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgbGV0dGVyLXNwYWNpbmc6IDAuNXB4OyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogI2ZmZjsgcGFkZGluZzogMnB4IDhweDsgYm9yZGVyLXJhZGl1czogOTk5cHg7IH0KCi5tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9Ci50b3BiYXIgeyBwYWRkaW5nOiAyMnB4IDMycHg7IGJhY2tncm91bmQ6IHZhcigtLWNhcmQpOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXRvcDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7IH0KLnRvcGJhciBoMiB7IG1hcmdpbjogMDsgZm9udC1zaXplOiAyMHB4OyB9Ci50b3BiYXItc3ViIHsgZm9udC1zaXplOiAxMnB4OyBtYXJnaW4tdG9wOiAycHg7IH0KLnZpZXcgeyBwYWRkaW5nOiAyNHB4IDMycHg7IG1heC13aWR0aDogMTEwMHB4OyB9CgovKiBDYXJkcyAvIGdyaWQgKi8KLmdyaWQgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdChhdXRvLWZpdCwgbWlubWF4KDIwMHB4LCAxZnIpKTsgZ2FwOiAxNnB4OyBtYXJnaW4tYm90dG9tOiAyNHB4OyB9Ci5zdGF0LWNhcmQgeyBiYWNrZ3JvdW5kOiB2YXIoLS1jYXJkKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsgcGFkZGluZzogMThweDsgfQouc3RhdC1jYXJkIC5udW0geyBmb250LXNpemU6IDI4cHg7IGZvbnQtd2VpZ2h0OiA4MDA7IGNvbG9yOiB2YXIoLS1wcmltYXJ5KTsgfQouc3RhdC1jYXJkIC5sYWJlbCB7IGZvbnQtc2l6ZTogMTNweDsgY29sb3I6IHZhcigtLW11dGVkKTsgbWFyZ2luLXRvcDogNHB4OyB9CgouY2FyZCB7IGJhY2tncm91bmQ6IHZhcigtLWNhcmQpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOyBwYWRkaW5nOiAyMHB4OyBtYXJnaW4tYm90dG9tOiAyMHB4OyB9Ci5jYXJkLWhlYWRlciB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgbWFyZ2luLWJvdHRvbTogMTRweDsgfQouY2FyZC1oZWFkZXIgaDMgeyBtYXJnaW46IDA7IGZvbnQtc2l6ZTogMTZweDsgfQoKLyogVGFibGUgKi8KdGFibGUgeyB3aWR0aDogMTAwJTsgYm9yZGVyLWNvbGxhcHNlOiBjb2xsYXBzZTsgZm9udC1zaXplOiAxNHB4OyB9CnRoLCB0ZCB7IHRleHQtYWxpZ246IGxlZnQ7IHBhZGRpbmc6IDEwcHggOHB4OyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgdmVydGljYWwtYWxpZ246IHRvcDsgfQp0aCB7IGZvbnQtc2l6ZTogMTJweDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgbGV0dGVyLXNwYWNpbmc6IDAuNHB4OyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBmb250LXdlaWdodDogNzAwOyB9CnRyOmxhc3QtY2hpbGQgdGQgeyBib3JkZXItYm90dG9tOiBub25lOyB9Ci5lbXB0eS1yb3cgdGQgeyB0ZXh0LWFsaWduOiBjZW50ZXI7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IHBhZGRpbmc6IDI0cHggMDsgfQoKLyogQmFkZ2VzICovCi5iYWRnZSB7IGRpc3BsYXk6IGlubGluZS1ibG9jazsgcGFkZGluZzogM3B4IDlweDsgYm9yZGVyLXJhZGl1czogOTk5cHg7IGZvbnQtc2l6ZTogMTFweDsgZm9udC13ZWlnaHQ6IDcwMDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgbGV0dGVyLXNwYWNpbmc6IDAuM3B4OyB9Ci5iYWRnZS1vcGVuLCAuYmFkZ2UtbmV3IHsgYmFja2dyb3VuZDogI2ZkZWNlYTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KLmJhZGdlLWluX3Byb2dyZXNzLCAuYmFkZ2UtaW5fcmV2aWV3IHsgYmFja2dyb3VuZDogI2ZkZjNlMjsgY29sb3I6IHZhcigtLXdhcm5pbmcpOyB9Ci5iYWRnZS1yZXNvbHZlZCwgLmJhZGdlLWltcGxlbWVudGVkLCAuYmFkZ2UtYXBwcm92ZWQsIC5iYWRnZS1yZXZpZXdlZCB7IGJhY2tncm91bmQ6ICNlNmYzZWM7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQouYmFkZ2UtcmVqZWN0ZWQgeyBiYWNrZ3JvdW5kOiAjZjBmMGYwOyBjb2xvcjogdmFyKC0tbXV0ZWQpOyB9Ci5iYWRnZS1vbl90cmFjayB7IGJhY2tncm91bmQ6ICNlNmYzZWM7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQouYmFkZ2UtYXRfcmlzayB7IGJhY2tncm91bmQ6ICNmZGYzZTI7IGNvbG9yOiB2YXIoLS13YXJuaW5nKTsgfQouYmFkZ2Utb2ZmX3RyYWNrIHsgYmFja2dyb3VuZDogI2ZkZWNlYTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KLmJhZGdlLXN1Ym1pdHRlZCB7IGJhY2tncm91bmQ6ICNlZWYxZjY7IGNvbG9yOiAjM2M1YThhOyB9CgovKiBGb3JtcyAqLwouZm9ybS1yb3cgeyBtYXJnaW4tYm90dG9tOiAxNHB4OyB9Ci5mb3JtLXJvdyBsYWJlbCB7IGRpc3BsYXk6IGJsb2NrOyBmb250LXNpemU6IDEzcHg7IGZvbnQtd2VpZ2h0OiA2MDA7IG1hcmdpbi1ib3R0b206IDZweDsgfQouZm9ybS1yb3cgaW5wdXQsIC5mb3JtLXJvdyBzZWxlY3QsIC5mb3JtLXJvdyB0ZXh0YXJlYSB7CiAgd2lkdGg6IDEwMCU7IHBhZGRpbmc6IDlweCAxMXB4OyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiA4cHg7IGZvbnQtc2l6ZTogMTRweDsgZm9udC1mYW1pbHk6IGluaGVyaXQ7Cn0KLmZvcm0tcm93IHRleHRhcmVhIHsgbWluLWhlaWdodDogODBweDsgcmVzaXplOiB2ZXJ0aWNhbDsgfQouZm9ybS1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBmbGV4LWVuZDsgZ2FwOiAxMHB4OyBtYXJnaW4tdG9wOiAxOHB4OyB9Ci50d28tY29sIHsgZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnIgMWZyOyBnYXA6IDE0cHg7IH0KCi8qIE1vZGFsICovCi5tb2RhbC1vdmVybGF5IHsKICBwb3NpdGlvbjogZml4ZWQ7IGluc2V0OiAwOyBiYWNrZ3JvdW5kOiByZ2JhKDIwLDI1LDIyLDAuNSk7CiAgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsganVzdGlmeS1jb250ZW50OiBjZW50ZXI7IHotaW5kZXg6IDUwOyBwYWRkaW5nOiAyMHB4Owp9Ci5tb2RhbCB7IGJhY2tncm91bmQ6ICNmZmY7IGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7IHdpZHRoOiA0ODBweDsgbWF4LXdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiA5MHZoOyBvdmVyZmxvdy15OiBhdXRvOyB9Ci5tb2RhbC1oZWFkZXIgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47IHBhZGRpbmc6IDE4cHggMjBweDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KLm1vZGFsLWhlYWRlciBoMyB7IG1hcmdpbjogMDsgZm9udC1zaXplOiAxNnB4OyB9Ci5tb2RhbC1ib2R5IHsgcGFkZGluZzogMjBweDsgfQoKLyogVG9hc3QgKi8KLnRvYXN0IHsKICBwb3NpdGlvbjogZml4ZWQ7IGJvdHRvbTogMjRweDsgbGVmdDogNTAlOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeS1kYXJrKTsgY29sb3I6ICNmZmY7IHBhZGRpbmc6IDEycHggMjBweDsgYm9yZGVyLXJhZGl1czogOHB4OyBmb250LXNpemU6IDE0cHg7IHotaW5kZXg6IDEwMDsKICBib3gtc2hhZG93OiAwIDEwcHggMjVweCByZ2JhKDAsMCwwLDAuMjUpOwp9Ci50b2FzdC5lcnJvciB7IGJhY2tncm91bmQ6IHZhcigtLWRhbmdlcik7IH0KCi8qIFByb2dyZXNzIGJhciAqLwoucHJvZ3Jlc3MgeyBiYWNrZ3JvdW5kOiB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgaGVpZ2h0OiA4cHg7IG92ZXJmbG93OiBoaWRkZW47IG1hcmdpbi10b3A6IDhweDsgfQoucHJvZ3Jlc3MtZmlsbCB7IGJhY2tncm91bmQ6IHZhcigtLXByaW1hcnkpOyBoZWlnaHQ6IDEwMCU7IH0KCi5zZWN0aW9uLXRvb2xiYXIgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOiBjZW50ZXI7IG1hcmdpbi1ib3R0b206IDE2cHg7IH0KLnNtYWxsLW5vdGUgeyBmb250LXNpemU6IDEycHg7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IG1hcmdpbi10b3A6IDZweDsgfQoubGluayB7IGNvbG9yOiB2YXIoLS1wcmltYXJ5KTsgdGV4dC1kZWNvcmF0aW9uOiBub25lOyBmb250LXdlaWdodDogNjAwOyB9Ci5saW5rOmhvdmVyIHsgdGV4dC1kZWNvcmF0aW9uOiB1bmRlcmxpbmU7IH0KLnByZXZpZXctdGFibGUtd3JhcCB7IG1heC1oZWlnaHQ6IDMyMHB4OyBvdmVyZmxvdzogYXV0bzsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogOHB4OyBtYXJnaW4tdG9wOiAxMHB4OyB9CgpAbWVkaWEgKG1heC13aWR0aDogODAwcHgpIHsKICAuYXBwIHsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgfQogIC5zaWRlYmFyIHsgd2lkdGg6IDEwMCU7IGZsZXgtZGlyZWN0aW9uOiByb3c7IG92ZXJmbG93LXg6IGF1dG87IHBhZGRpbmc6IDEwcHg7IH0KICAuc2lkZWJhciBuYXYgeyBmbGV4LWRpcmVjdGlvbjogcm93OyB9CiAgLnNpZGViYXItZm9vdGVyIHsgZGlzcGxheTogbm9uZTsgfQogIC50d28tY29sIHsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnI7IH0KfQo=', 'base64').toString('utf8');
const APP_JS = Buffer.from('Ly8gYXBwLmpzIC0gVm9sdW50ZWVyIE1hbmFnZW1lbnQgU3lzdGVtIGZyb250ZW5kICh2YW5pbGxhIEpTLCBubyBidWlsZCBzdGVwKQoKY29uc3Qgc3RhdGUgPSB7CiAgdG9rZW46IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd2bXNfdG9rZW4nKSB8fCBudWxsLAogIHVzZXI6IG51bGwsCiAgcm91dGU6ICdkYXNoYm9hcmQnLAp9OwoKLy8gLS0tLS0tLS0tLSBBUEkgaGVscGVyIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gYXBpKG1ldGhvZCwgcGF0aCwgYm9keSkgewogIGNvbnN0IG9wdHMgPSB7IG1ldGhvZCwgaGVhZGVyczoge30gfTsKICBpZiAoc3RhdGUudG9rZW4pIG9wdHMuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgc3RhdGUudG9rZW47CiAgaWYgKGJvZHkgIT09IHVuZGVmaW5lZCkgewogICAgb3B0cy5oZWFkZXJzWydDb250ZW50LVR5cGUnXSA9ICdhcHBsaWNhdGlvbi9qc29uJzsKICAgIG9wdHMuYm9keSA9IEpTT04uc3RyaW5naWZ5KGJvZHkpOwogIH0KICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCBvcHRzKTsKICBsZXQgZGF0YSA9IG51bGw7CiAgdHJ5IHsgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7IH0gY2F0Y2ggeyBkYXRhID0gbnVsbDsgfQogIGlmICghcmVzLm9rKSB7CiAgICBjb25zdCBtc2cgPSAoZGF0YSAmJiBkYXRhLmVycm9yKSB8fCBgUmVxdWVzdCBmYWlsZWQgKCR7cmVzLnN0YXR1c30pYDsKICAgIHRocm93IG5ldyBFcnJvcihtc2cpOwogIH0KICByZXR1cm4gZGF0YTsKfQoKLy8gLS0tLS0tLS0tLSBUb2FzdCAtLS0tLS0tLS0tCmxldCB0b2FzdFRpbWVyOwpmdW5jdGlvbiBzaG93VG9hc3QobXNnLCBpc0Vycm9yKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndG9hc3QnKTsKICBlbC50ZXh0Q29udGVudCA9IG1zZzsKICBlbC5jbGFzc05hbWUgPSAndG9hc3QnICsgKGlzRXJyb3IgPyAnIGVycm9yJyA6ICcnKTsKICBjbGVhclRpbWVvdXQodG9hc3RUaW1lcik7CiAgdG9hc3RUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4gZWwuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyksIDMyMDApOwp9CgovLyAtLS0tLS0tLS0tIE1vZGFsIC0tLS0tLS0tLS0KZnVuY3Rpb24gb3Blbk1vZGFsKHRpdGxlLCBib2R5SHRtbCkgewogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbFRpdGxlJykudGV4dENvbnRlbnQgPSB0aXRsZTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWxCb2R5JykuaW5uZXJIVE1MID0gYm9keUh0bWw7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsT3ZlcmxheScpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwp9CmZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsT3ZlcmxheScpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbEJvZHknKS5pbm5lckhUTUwgPSAnJzsKfQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWxDbG9zZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VNb2RhbCk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbE92ZXJsYXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIChlKSA9PiB7CiAgaWYgKGUudGFyZ2V0LmlkID09PSAnbW9kYWxPdmVybGF5JykgY2xvc2VNb2RhbCgpOwp9KTsKCi8vIC0tLS0tLS0tLS0gVXRpbHMgLS0tLS0tLS0tLQpmdW5jdGlvbiBlc2MocykgewogIGlmIChzID09PSBudWxsIHx8IHMgPT09IHVuZGVmaW5lZCkgcmV0dXJuICcnOwogIHJldHVybiBTdHJpbmcocykucmVwbGFjZSgvWyY8PiInXS9nLCAoYykgPT4gKHsgJyYnOiAnJmFtcDsnLCAnPCc6ICcmbHQ7JywgJz4nOiAnJmd0OycsICciJzogJyZxdW90OycsICInIjogJyYjMzk7JyB9W2NdKSk7Cn0KZnVuY3Rpb24gZm10RGF0ZShzKSB7CiAgaWYgKCFzKSByZXR1cm4gJyc7CiAgcmV0dXJuIHMucmVwbGFjZSgnVCcsICcgJykuc2xpY2UoMCwgMTYpOwp9CmZ1bmN0aW9uIGJhZGdlKHN0YXR1cykgewogIHJldHVybiBgPHNwYW4gY2xhc3M9ImJhZGdlIGJhZGdlLSR7ZXNjKHN0YXR1cyl9Ij4ke2VzYygoc3RhdHVzIHx8ICcnKS5yZXBsYWNlKC9fL2csICcgJykpfTwvc3Bhbj5gOwp9CgovLyAtLS0tLS0tLS0tIEF1dGggLS0tLS0tLS0tLQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9naW5Gb3JtJykuYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgKGUpID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgY29uc3QgZW1haWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9naW5FbWFpbCcpLnZhbHVlLnRyaW0oKTsKICBjb25zdCBwYXNzd29yZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2dpblBhc3N3b3JkJykudmFsdWU7CiAgY29uc3QgZXJyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9naW5FcnJvcicpOwogIGVyckVsLnRleHRDb250ZW50ID0gJyc7CiAgdHJ5IHsKICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9sb2dpbicsIHsgZW1haWwsIHBhc3N3b3JkIH0pOwogICAgc3RhdGUudG9rZW4gPSBkYXRhLnRva2VuOwogICAgc3RhdGUudXNlciA9IGRhdGEudXNlcjsKICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd2bXNfdG9rZW4nLCBkYXRhLnRva2VuKTsKICAgIGJvb3QoKTsKICB9IGNhdGNoIChlcnIpIHsKICAgIGVyckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgfQp9KTsKCmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2dvdXRCdG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICBzdGF0ZS50b2tlbiA9IG51bGw7CiAgc3RhdGUudXNlciA9IG51bGw7CiAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Ztc190b2tlbicpOwogIGxvY2F0aW9uLnJlbG9hZCgpOwp9KTsKCmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGFuZ2VQd0J0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIG9wZW5Nb2RhbCgnQ2hhbmdlIHBhc3N3b3JkJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5DdXJyZW50IHBhc3N3b3JkPC9sYWJlbD48aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJwd0N1cnJlbnQiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPk5ldyBwYXNzd29yZCAobWluIDYgY2hhcmFjdGVycyk8L2xhYmVsPjxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InB3TmV3IiAvPjwvZGl2PgogICAgPHAgaWQ9InB3RXJyb3IiIGNsYXNzPSJlcnJvci10ZXh0Ij48L3A+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0UGFzc3dvcmRDaGFuZ2UoKSI+U2F2ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0pOwphc3luYyBmdW5jdGlvbiBzdWJtaXRQYXNzd29yZENoYW5nZSgpIHsKICBjb25zdCBlcnJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwd0Vycm9yJyk7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL21lL3Bhc3N3b3JkJywgewogICAgICBjdXJyZW50X3Bhc3N3b3JkOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncHdDdXJyZW50JykudmFsdWUsCiAgICAgIG5ld19wYXNzd29yZDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3B3TmV3JykudmFsdWUsCiAgICB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnUGFzc3dvcmQgdXBkYXRlZCcpOwogIH0gY2F0Y2ggKGVycikgewogICAgZXJyRWwudGV4dENvbnRlbnQgPSBlcnIubWVzc2FnZTsKICB9Cn0KCi8vIC0tLS0tLS0tLS0gTmF2aWdhdGlvbiBjb25maWcgLS0tLS0tLS0tLQpjb25zdCBOQVYgPSB7CiAgdnA6IFsKICAgIFsnZGFzaGJvYXJkJywgJ0Rhc2hib2FyZCddLAogICAgWydrcGlzJywgJ0tQSXMnXSwKICAgIFsnaWRlYXMnLCAnSWRlYXMnXSwKICAgIFsnY29tcGxhaW50cycsICdDb21wbGFpbnRzJ10sCiAgICBbJ3JlcG9ydHMnLCAnTWFuYWdlciBSZXBvcnRzJ10sCiAgICBbJ2ZpbGVzJywgJ0ZpbGVzJ10sCiAgICBbJ3N1cnZleXMnLCAnU3VydmV5cyddLAogICAgWyd0ZWFtJywgJ1Blb3BsZSddLAogICAgWydhbm5vdW5jZW1lbnRzJywgJ0Fubm91bmNlbWVudHMnXSwKICBdLAogIG1hbmFnZXI6IFsKICAgIFsnZGFzaGJvYXJkJywgJ0Rhc2hib2FyZCddLAogICAgWydrcGlzJywgJ015IEtQSXMnXSwKICAgIFsnaWRlYXMnLCAnVGVhbSBJZGVhcyddLAogICAgWydjb21wbGFpbnRzJywgJ1RlYW0gQ29tcGxhaW50cyddLAogICAgWydyZXBvcnRzJywgJ1JlcG9ydHMgdG8gVlAnXSwKICAgIFsnZmlsZXMnLCAnRmlsZXMnXSwKICAgIFsnc3VydmV5cycsICdTdXJ2ZXlzJ10sCiAgICBbJ3RlYW0nLCAnTXkgVm9sdW50ZWVycyddLAogICAgWydhbm5vdW5jZW1lbnRzJywgJ0Fubm91bmNlbWVudHMnXSwKICBdLAogIHZvbHVudGVlcjogWwogICAgWydkYXNoYm9hcmQnLCAnRGFzaGJvYXJkJ10sCiAgICBbJ2twaXMnLCAnVGVhbSBLUElzJ10sCiAgICBbJ2lkZWFzJywgJ015IElkZWFzJ10sCiAgICBbJ2NvbXBsYWludHMnLCAnTXkgQ29tcGxhaW50cyddLAogICAgWydmaWxlcycsICdGaWxlcyddLAogICAgWydzdXJ2ZXlzJywgJ1N1cnZleXMnXSwKICAgIFsnYW5ub3VuY2VtZW50cycsICdBbm5vdW5jZW1lbnRzJ10sCiAgXSwKfTsKCmNvbnN0IFRJVExFUyA9IHsKICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLCBrcGlzOiAnS1BJcycsIGlkZWFzOiAnSWRlYXMnLCBjb21wbGFpbnRzOiAnQ29tcGxhaW50cycsCiAgcmVwb3J0czogJ1JlcG9ydHMnLCBmaWxlczogJ0ZpbGVzJywgc3VydmV5czogJ1N1cnZleXMnLCB0ZWFtOiAnUGVvcGxlJywgYW5ub3VuY2VtZW50czogJ0Fubm91bmNlbWVudHMnLAp9OwoKZnVuY3Rpb24gcmVuZGVyU2lkZWJhcigpIHsKICBjb25zdCBsaW5rcyA9IE5BVltzdGF0ZS51c2VyLnJvbGVdOwogIGNvbnN0IG5hdiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCduYXZMaW5rcycpOwogIG5hdi5pbm5lckhUTUwgPSBsaW5rcwogICAgLm1hcCgoW2tleSwgbGFiZWxdKSA9PiBgPGEgaHJlZj0iIyIgZGF0YS1yb3V0ZT0iJHtrZXl9IiBjbGFzcz0iJHtzdGF0ZS5yb3V0ZSA9PT0ga2V5ID8gJ2FjdGl2ZScgOiAnJ30iPiR7bGFiZWx9PC9hPmApCiAgICAuam9pbignJyk7CiAgbmF2LnF1ZXJ5U2VsZWN0b3JBbGwoJ2EnKS5mb3JFYWNoKChhKSA9PiB7CiAgICBhLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGUpID0+IHsKICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICBuYXZpZ2F0ZShhLmRhdGFzZXQucm91dGUpOwogICAgfSk7CiAgfSk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VzZXJCYWRnZScpLmlubmVySFRNTCA9CiAgICBgPGRpdj48c3Ryb25nPiR7ZXNjKHN0YXRlLnVzZXIubmFtZSl9PC9zdHJvbmc+PC9kaXY+PGRpdiBjbGFzcz0ibXV0ZWQiPiR7ZXNjKHN0YXRlLnVzZXIuZW1haWwpfTwvZGl2PjxzcGFuIGNsYXNzPSJyb2xlLXBpbGwiPiR7ZXNjKHN0YXRlLnVzZXIucm9sZSl9PC9zcGFuPmA7Cn0KCmZ1bmN0aW9uIG5hdmlnYXRlKHJvdXRlKSB7CiAgc3RhdGUucm91dGUgPSByb3V0ZTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncGFnZVRpdGxlJykudGV4dENvbnRlbnQgPSBUSVRMRVNbcm91dGVdIHx8ICcnOwogIHJlbmRlclNpZGViYXIoKTsKICByZW5kZXJWaWV3KCk7Cn0KCmFzeW5jIGZ1bmN0aW9uIHJlbmRlclZpZXcoKSB7CiAgY29uc3QgdmlldyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd2aWV3Jyk7CiAgdmlldy5pbm5lckhUTUwgPSAnPHAgY2xhc3M9Im11dGVkIj5Mb2FkaW5nLi4uPC9wPic7CiAgdHJ5IHsKICAgIHN3aXRjaCAoc3RhdGUucm91dGUpIHsKICAgICAgY2FzZSAnZGFzaGJvYXJkJzogcmV0dXJuIGF3YWl0IHZpZXdEYXNoYm9hcmQodmlldyk7CiAgICAgIGNhc2UgJ2twaXMnOiByZXR1cm4gYXdhaXQgdmlld0twaXModmlldyk7CiAgICAgIGNhc2UgJ2lkZWFzJzogcmV0dXJuIGF3YWl0IHZpZXdJZGVhcyh2aWV3KTsKICAgICAgY2FzZSAnY29tcGxhaW50cyc6IHJldHVybiBhd2FpdCB2aWV3Q29tcGxhaW50cyh2aWV3KTsKICAgICAgY2FzZSAncmVwb3J0cyc6IHJldHVybiBhd2FpdCB2aWV3UmVwb3J0cyh2aWV3KTsKICAgICAgY2FzZSAnZmlsZXMnOiByZXR1cm4gYXdhaXQgdmlld0ZpbGVzKHZpZXcpOwogICAgICBjYXNlICdzdXJ2ZXlzJzogcmV0dXJuIGF3YWl0IHZpZXdTdXJ2ZXlzKHZpZXcpOwogICAgICBjYXNlICd0ZWFtJzogcmV0dXJuIGF3YWl0IHZpZXdUZWFtKHZpZXcpOwogICAgICBjYXNlICdhbm5vdW5jZW1lbnRzJzogcmV0dXJuIGF3YWl0IHZpZXdBbm5vdW5jZW1lbnRzKHZpZXcpOwogICAgICBkZWZhdWx0OiB2aWV3LmlubmVySFRNTCA9ICc8cD5Ob3QgZm91bmQ8L3A+JzsKICAgIH0KICB9IGNhdGNoIChlcnIpIHsKICAgIHZpZXcuaW5uZXJIVE1MID0gYDxwIGNsYXNzPSJlcnJvci10ZXh0Ij4ke2VzYyhlcnIubWVzc2FnZSl9PC9wPmA7CiAgfQp9CgovLyAtLS0tLS0tLS0tIERhc2hib2FyZCAtLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIHZpZXdEYXNoYm9hcmQodmlldykgewogIGNvbnN0IFtrcGlzUmVzLCBpZGVhc1JlcywgY29tcGxhaW50c1JlcywgYW5ub3VuY2VtZW50c1Jlc10gPSBhd2FpdCBQcm9taXNlLmFsbChbCiAgICBhcGkoJ0dFVCcsICcvYXBpL2twaXMnKSwKICAgIGFwaSgnR0VUJywgJy9hcGkvaWRlYXMnKSwKICAgIGFwaSgnR0VUJywgJy9hcGkvY29tcGxhaW50cycpLAogICAgYXBpKCdHRVQnLCAnL2FwaS9hbm5vdW5jZW1lbnRzJyksCiAgXSk7CiAgY29uc3Qgb3BlbkNvbXBsYWludHMgPSBjb21wbGFpbnRzUmVzLmNvbXBsYWludHMuZmlsdGVyKChjKSA9PiBjLnN0YXR1cyAhPT0gJ3Jlc29sdmVkJykubGVuZ3RoOwogIGNvbnN0IG5ld0lkZWFzID0gaWRlYXNSZXMuaWRlYXMuZmlsdGVyKChpKSA9PiBpLnN0YXR1cyA9PT0gJ25ldycpLmxlbmd0aDsKICBjb25zdCBrcGlzID0ga3Bpc1Jlcy5rcGlzOwoKICBsZXQgcmVwb3J0c0NhcmQgPSAnJzsKICBpZiAoc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJykgewogICAgY29uc3QgcmVwb3J0c1JlcyA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvcmVwb3J0cycpOwogICAgY29uc3QgcGVuZGluZyA9IHJlcG9ydHNSZXMucmVwb3J0cy5maWx0ZXIoKHIpID0+IHIuc3RhdHVzID09PSAnc3VibWl0dGVkJykubGVuZ3RoOwogICAgcmVwb3J0c0NhcmQgPSBgPGRpdiBjbGFzcz0ic3RhdC1jYXJkIj48ZGl2IGNsYXNzPSJudW0iPiR7cGVuZGluZ308L2Rpdj48ZGl2IGNsYXNzPSJsYWJlbCI+UmVwb3J0cyBhd2FpdGluZyByZXZpZXc8L2Rpdj48L2Rpdj5gOwogIH0KCiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJncmlkIj4KICAgICAgPGRpdiBjbGFzcz0ic3RhdC1jYXJkIj48ZGl2IGNsYXNzPSJudW0iPiR7a3Bpcy5sZW5ndGh9PC9kaXY+PGRpdiBjbGFzcz0ibGFiZWwiPkFjdGl2ZSBLUElzPC9kaXY+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InN0YXQtY2FyZCI+PGRpdiBjbGFzcz0ibnVtIj4ke25ld0lkZWFzfTwvZGl2PjxkaXYgY2xhc3M9ImxhYmVsIj5OZXcgaWRlYXM8L2Rpdj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ic3RhdC1jYXJkIj48ZGl2IGNsYXNzPSJudW0iPiR7b3BlbkNvbXBsYWludHN9PC9kaXY+PGRpdiBjbGFzcz0ibGFiZWwiPk9wZW4gY29tcGxhaW50czwvZGl2PjwvZGl2PgogICAgICAke3JlcG9ydHNDYXJkfQogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxoMz5MYXRlc3QgYW5ub3VuY2VtZW50czwvaDM+PC9kaXY+CiAgICAgICR7cmVuZGVyQW5ub3VuY2VtZW50TGlzdChhbm5vdW5jZW1lbnRzUmVzLmFubm91bmNlbWVudHMuc2xpY2UoMCwgMykpfQogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxoMz5LUEkgc25hcHNob3Q8L2gzPjwvZGl2PgogICAgICAke3JlbmRlcktwaUxpc3Qoa3Bpcy5zbGljZSgwLCA0KSwgZmFsc2UpfQogICAgPC9kaXY+CiAgYDsKfQoKZnVuY3Rpb24gcmVuZGVyQW5ub3VuY2VtZW50TGlzdChpdGVtcykgewogIGlmICghaXRlbXMubGVuZ3RoKSByZXR1cm4gJzxwIGNsYXNzPSJtdXRlZCI+Tm8gYW5ub3VuY2VtZW50cyB5ZXQuPC9wPic7CiAgcmV0dXJuIGl0ZW1zCiAgICAubWFwKAogICAgICAoYSkgPT4gYDxkaXYgc3R5bGU9Im1hcmdpbi1ib3R0b206MTRweDsiPgogICAgICAgIDxzdHJvbmc+JHtlc2MoYS50aXRsZSl9PC9zdHJvbmc+IDxzcGFuIGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4OyI+YnkgJHtlc2MoYS5jcmVhdG9yX25hbWUpfSAmbWlkZG90OyAke2ZtdERhdGUoYS5jcmVhdGVkX2F0KX08L3NwYW4+CiAgICAgICAgPHAgc3R5bGU9Im1hcmdpbjo0cHggMCAwOyI+JHtlc2MoYS5ib2R5KX08L3A+CiAgICAgIDwvZGl2PmAKICAgICkKICAgIC5qb2luKCcnKTsKfQoKLy8gLS0tLS0tLS0tLSBLUElzIC0tLS0tLS0tLS0KZnVuY3Rpb24gcmVuZGVyS3BpTGlzdChrcGlzKSB7CiAgaWYgKCFrcGlzLmxlbmd0aCkgcmV0dXJuICc8cCBjbGFzcz0ibXV0ZWQiPk5vIEtQSXMgeWV0LjwvcD4nOwogIHJldHVybiBrcGlzCiAgICAubWFwKChrKSA9PiB7CiAgICAgIGNvbnN0IHBjdCA9IGsudGFyZ2V0X3ZhbHVlID8gTWF0aC5taW4oMTAwLCBNYXRoLnJvdW5kKChrLmN1cnJlbnRfdmFsdWUgLyBrLnRhcmdldF92YWx1ZSkgKiAxMDApKSA6IDA7CiAgICAgIGNvbnN0IGNhbkVkaXQgPSBzdGF0ZS51c2VyLnJvbGUgIT09ICd2b2x1bnRlZXInICYmIChzdGF0ZS51c2VyLnJvbGUgPT09ICd2cCcgfHwgay5vd25lcl9pZCA9PT0gc3RhdGUudXNlci5pZCk7CiAgICAgIHJldHVybiBgPGRpdiBzdHlsZT0ibWFyZ2luLWJvdHRvbToxNnB4OyBwYWRkaW5nLWJvdHRvbToxNnB4OyBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyI+CiAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsgYWxpZ24taXRlbXM6ZmxleC1zdGFydDsiPgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPHN0cm9uZz4ke2VzYyhrLnRpdGxlKX08L3N0cm9uZz4gJHtiYWRnZShrLnN0YXR1cyl9CiAgICAgICAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7Ij5Pd25lcjogJHtlc2Moay5vd25lcl9uYW1lKX0gJHtrLnBlcmlvZCA/ICcmbWlkZG90OyAnICsgZXNjKGsucGVyaW9kKSA6ICcnfTwvZGl2PgogICAgICAgICAgICAke2suZGVzY3JpcHRpb24gPyBgPHAgc3R5bGU9Im1hcmdpbjo2cHggMCAwOyI+JHtlc2Moay5kZXNjcmlwdGlvbil9PC9wPmAgOiAnJ30KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodDsgd2hpdGUtc3BhY2U6bm93cmFwOyI+CiAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDsiPiR7ZXNjKGsuY3VycmVudF92YWx1ZSA/PyAwKX0ke2sudGFyZ2V0X3ZhbHVlID8gJyAvICcgKyBlc2Moay50YXJnZXRfdmFsdWUpIDogJyd9ICR7ZXNjKGsudW5pdCB8fCAnJyl9PC9kaXY+CiAgICAgICAgICAgICR7Y2FuRWRpdCA/IGA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIiBzdHlsZT0ibWFyZ2luLXRvcDo2cHg7IiBvbmNsaWNrPSJlZGl0S3BpKCR7ay5pZH0pIj5VcGRhdGU8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tZGFuZ2VyIiBzdHlsZT0ibWFyZ2luLXRvcDo2cHg7IiBvbmNsaWNrPSJkZWxldGVLcGkoJHtrLmlkfSkiPkRlbGV0ZTwvYnV0dG9uPmAgOiAnJ30KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgICR7ay50YXJnZXRfdmFsdWUgPyBgPGRpdiBjbGFzcz0icHJvZ3Jlc3MiPjxkaXYgY2xhc3M9InByb2dyZXNzLWZpbGwiIHN0eWxlPSJ3aWR0aDoke3BjdH0lOyI+PC9kaXY+PC9kaXY+YCA6ICcnfQogICAgICA8L2Rpdj5gOwogICAgfSkKICAgIC5qb2luKCcnKTsKfQoKYXN5bmMgZnVuY3Rpb24gdmlld0twaXModmlldykgewogIGNvbnN0IHsga3BpcyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9rcGlzJyk7CiAgY29uc3QgY2FuQ3JlYXRlID0gc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJzsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+JHtzdGF0ZS51c2VyLnJvbGUgPT09ICd2b2x1bnRlZXInID8gJ1JlYWQtb25seSB2aWV3IG9mIHlvdXIgdGVhbVwncyBLUElzLicgOiAnVHJhY2sgcHJvZ3Jlc3MgYWdhaW5zdCB0YXJnZXRzLid9PC9wPgogICAgICAke2NhbkNyZWF0ZSA/ICc8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9Im5ld0twaSgpIj4rIE5ldyBLUEk8L2J1dHRvbj4nIDogJyd9CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPiR7cmVuZGVyS3BpTGlzdChrcGlzKX08L2Rpdj4KICBgOwp9Cgphc3luYyBmdW5jdGlvbiBuZXdLcGkoKSB7CiAgbGV0IG93bmVyT3B0aW9ucyA9ICcnOwogIGlmIChzdGF0ZS51c2VyLnJvbGUgPT09ICd2cCcpIHsKICAgIGNvbnN0IHsgdXNlcnMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvdXNlcnMnKTsKICAgIGNvbnN0IG1hbmFnZXJzID0gdXNlcnMuZmlsdGVyKCh1KSA9PiB1LnJvbGUgPT09ICdtYW5hZ2VyJyk7CiAgICBvd25lck9wdGlvbnMgPSBgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5Bc3NpZ24gdG8gbWFuYWdlcjwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9ImtwaU93bmVyIj4ke21hbmFnZXJzLm1hcCgobSkgPT4gYDxvcHRpb24gdmFsdWU9IiR7bS5pZH0iPiR7ZXNjKG0ubmFtZSl9PC9vcHRpb24+YCkuam9pbignJyl9PC9zZWxlY3Q+CiAgICA8L2Rpdj5gOwogIH0KICBvcGVuTW9kYWwoJ05ldyBLUEknLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlRpdGxlPC9sYWJlbD48aW5wdXQgaWQ9ImtwaVRpdGxlIiBwbGFjZWhvbGRlcj0iZS5nLiBWb2x1bnRlZXIgcmV0ZW50aW9uIHJhdGUiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkRlc2NyaXB0aW9uPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImtwaURlc2MiPjwvdGV4dGFyZWE+PC9kaXY+CiAgICAke293bmVyT3B0aW9uc30KICAgIDxkaXYgY2xhc3M9InR3by1jb2wiPgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlRhcmdldCB2YWx1ZTwvbGFiZWw+PGlucHV0IGlkPSJrcGlUYXJnZXQiIHR5cGU9Im51bWJlciIgLz48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5DdXJyZW50IHZhbHVlPC9sYWJlbD48aW5wdXQgaWQ9ImtwaUN1cnJlbnQiIHR5cGU9Im51bWJlciIgdmFsdWU9IjAiIC8+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InR3by1jb2wiPgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlVuaXQ8L2xhYmVsPjxpbnB1dCBpZD0ia3BpVW5pdCIgcGxhY2Vob2xkZXI9IiUsIGhvdXJzLCBwZW9wbGUuLi4iIC8+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+UGVyaW9kPC9sYWJlbD48aW5wdXQgaWQ9ImtwaVBlcmlvZCIgcGxhY2Vob2xkZXI9IlEzIDIwMjYiIC8+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRLcGkoKSI+Q3JlYXRlPC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQoKYXN5bmMgZnVuY3Rpb24gc3VibWl0S3BpKCkgewogIGNvbnN0IG93bmVyU2VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2twaU93bmVyJyk7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2twaXMnLCB7CiAgICAgIHRpdGxlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpVGl0bGUnKS52YWx1ZSwKICAgICAgZGVzY3JpcHRpb246IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlEZXNjJykudmFsdWUsCiAgICAgIG93bmVyX2lkOiBvd25lclNlbCA/IE51bWJlcihvd25lclNlbC52YWx1ZSkgOiB1bmRlZmluZWQsCiAgICAgIHRhcmdldF92YWx1ZTogTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlUYXJnZXQnKS52YWx1ZSkgfHwgbnVsbCwKICAgICAgY3VycmVudF92YWx1ZTogTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlDdXJyZW50JykudmFsdWUpIHx8IDAsCiAgICAgIHVuaXQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlVbml0JykudmFsdWUsCiAgICAgIHBlcmlvZDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2twaVBlcmlvZCcpLnZhbHVlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0tQSSBjcmVhdGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKYXN5bmMgZnVuY3Rpb24gZWRpdEtwaShpZCkgewogIGNvbnN0IHsga3BpcyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9rcGlzJyk7CiAgY29uc3QgayA9IGtwaXMuZmluZCgoeCkgPT4geC5pZCA9PT0gaWQpOwogIG9wZW5Nb2RhbCgnVXBkYXRlIEtQSScsIGAKICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+Q3VycmVudCB2YWx1ZTwvbGFiZWw+PGlucHV0IGlkPSJrcGlDdXJyZW50RWRpdCIgdHlwZT0ibnVtYmVyIiB2YWx1ZT0iJHtlc2Moay5jdXJyZW50X3ZhbHVlKX0iIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlN0YXR1czwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9ImtwaVN0YXR1c0VkaXQiPgogICAgICAgICR7Wydvbl90cmFjaycsICdhdF9yaXNrJywgJ29mZl90cmFjayddLm1hcCgocykgPT4gYDxvcHRpb24gdmFsdWU9IiR7c30iICR7ay5zdGF0dXMgPT09IHMgPyAnc2VsZWN0ZWQnIDogJyd9PiR7cy5yZXBsYWNlKCdfJywgJyAnKX08L29wdGlvbj5gKS5qb2luKCcnKX0KICAgICAgPC9zZWxlY3Q+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRLcGlFZGl0KCR7aWR9KSI+U2F2ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KCmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdEtwaUVkaXQoaWQpIHsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQVVQnLCBgL2FwaS9rcGlzLyR7aWR9YCwgewogICAgICBjdXJyZW50X3ZhbHVlOiBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2twaUN1cnJlbnRFZGl0JykudmFsdWUpLAogICAgICBzdGF0dXM6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlTdGF0dXNFZGl0JykudmFsdWUsCiAgICB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnS1BJIHVwZGF0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9Cgphc3luYyBmdW5jdGlvbiBkZWxldGVLcGkoaWQpIHsKICBpZiAoIWNvbmZpcm0oJ0RlbGV0ZSB0aGlzIEtQST8nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL2twaXMvJHtpZH1gKTsKICAgIHNob3dUb2FzdCgnS1BJIGRlbGV0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIElkZWFzIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld0lkZWFzKHZpZXcpIHsKICBjb25zdCB7IGlkZWFzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL2lkZWFzJyk7CiAgY29uc3QgY2FuTWFuYWdlID0gc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJzsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+JHtjYW5NYW5hZ2UgPyAnSWRlYXMgc3VibWl0dGVkIGJ5IHlvdXIgdGVhbS4nIDogJ0lkZWFzIHlvdVwndmUgc3VibWl0dGVkLCBhbmQgbWFuYWdlciByZXNwb25zZXMuJ308L3A+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3SWRlYSgpIj4rIFN1Ym1pdCBpZGVhPC9idXR0b24+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8dGFibGU+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+VGl0bGU8L3RoPjx0aD5TdWJtaXR0ZWQgYnk8L3RoPjx0aD5TdGF0dXM8L3RoPjx0aD5SZXNwb25zZTwvdGg+PHRoPjwvdGg+PC90cj48L3RoZWFkPgogICAgICAgIDx0Ym9keT4KICAgICAgICAgICR7aWRlYXMubGVuZ3RoID8gaWRlYXMubWFwKChpKSA9PiBgCiAgICAgICAgICAgIDx0cj4KICAgICAgICAgICAgICA8dGQ+PHN0cm9uZz4ke2VzYyhpLnRpdGxlKX08L3N0cm9uZz48ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4OyI+JHtlc2MoaS5kZXNjcmlwdGlvbiB8fCAnJyl9PC9kaXY+PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoaS5zdWJtaXR0ZXJfbmFtZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtiYWRnZShpLnN0YXR1cyl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoaS5yZXNwb25zZSB8fCAnJyl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtjYW5NYW5hZ2UgPyBgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSIgb25jbGljaz0icmVzcG9uZElkZWEoJHtpLmlkfSwgJyR7ZXNjKGkuc3RhdHVzKX0nKSI+TWFuYWdlPC9idXR0b24+YCA6ICcnfTwvdGQ+CiAgICAgICAgICAgIDwvdHI+CiAgICAgICAgICBgKS5qb2luKCcnKSA6ICc8dHIgY2xhc3M9ImVtcHR5LXJvdyI+PHRkIGNvbHNwYW49IjUiPk5vIGlkZWFzIHlldC48L3RkPjwvdHI+J30KICAgICAgICA8L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+CiAgYDsKfQoKZnVuY3Rpb24gbmV3SWRlYSgpIHsKICBvcGVuTW9kYWwoJ1N1Ym1pdCBhbiBpZGVhJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UaXRsZTwvbGFiZWw+PGlucHV0IGlkPSJpZGVhVGl0bGUiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkRldGFpbHM8L2xhYmVsPjx0ZXh0YXJlYSBpZD0iaWRlYURlc2MiPjwvdGV4dGFyZWE+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0SWRlYSgpIj5TdWJtaXQ8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdElkZWEoKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2lkZWFzJywgeyB0aXRsZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2lkZWFUaXRsZScpLnZhbHVlLCBkZXNjcmlwdGlvbjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2lkZWFEZXNjJykudmFsdWUgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0lkZWEgc3VibWl0dGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKZnVuY3Rpb24gcmVzcG9uZElkZWEoaWQsIGN1cnJlbnRTdGF0dXMpIHsKICBjb25zdCBzdGF0dXNlcyA9IFsnbmV3JywgJ2luX3JldmlldycsICdhcHByb3ZlZCcsICdpbXBsZW1lbnRlZCcsICdyZWplY3RlZCddOwogIG9wZW5Nb2RhbCgnTWFuYWdlIGlkZWEnLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlN0YXR1czwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9ImlkZWFTdGF0dXMiPiR7c3RhdHVzZXMubWFwKChzKSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHtzfSIgJHtzID09PSBjdXJyZW50U3RhdHVzID8gJ3NlbGVjdGVkJyA6ICcnfT4ke3MucmVwbGFjZSgnXycsICcgJyl9PC9vcHRpb24+YCkuam9pbignJyl9PC9zZWxlY3Q+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+UmVzcG9uc2UgdG8gc3VibWl0dGVyPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImlkZWFSZXNwb25zZSI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRJZGVhUmVzcG9uc2UoJHtpZH0pIj5TYXZlPC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQphc3luYyBmdW5jdGlvbiBzdWJtaXRJZGVhUmVzcG9uc2UoaWQpIHsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQVVQnLCBgL2FwaS9pZGVhcy8ke2lkfWAsIHsgc3RhdHVzOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaWRlYVN0YXR1cycpLnZhbHVlLCByZXNwb25zZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2lkZWFSZXNwb25zZScpLnZhbHVlIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdJZGVhIHVwZGF0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIENvbXBsYWludHMgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3Q29tcGxhaW50cyh2aWV3KSB7CiAgY29uc3QgeyBjb21wbGFpbnRzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL2NvbXBsYWludHMnKTsKICBjb25zdCBjYW5NYW5hZ2UgPSBzdGF0ZS51c2VyLnJvbGUgIT09ICd2b2x1bnRlZXInOwogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10b29sYmFyIj4KICAgICAgPHAgY2xhc3M9Im11dGVkIj4ke2Nhbk1hbmFnZSA/ICdDb21wbGFpbnRzIHJhaXNlZCBieSB5b3VyIHRlYW0uJyA6ICdDb21wbGFpbnRzL3Byb2JsZW1zIHlvdVwndmUgcmFpc2VkLid9PC9wPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9Im5ld0NvbXBsYWludCgpIj4rIFJlcG9ydCBhIHByb2JsZW08L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDx0YWJsZT4KICAgICAgICA8dGhlYWQ+PHRyPjx0aD5UaXRsZTwvdGg+PHRoPlN1Ym1pdHRlZCBieTwvdGg+PHRoPlN0YXR1czwvdGg+PHRoPlJlc29sdXRpb248L3RoPjx0aD48L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHk+CiAgICAgICAgICAke2NvbXBsYWludHMubGVuZ3RoID8gY29tcGxhaW50cy5tYXAoKGMpID0+IGAKICAgICAgICAgICAgPHRyPgogICAgICAgICAgICAgIDx0ZD48c3Ryb25nPiR7ZXNjKGMudGl0bGUpfTwvc3Ryb25nPjxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7Ij4ke2VzYyhjLmRlc2NyaXB0aW9uIHx8ICcnKX08L2Rpdj48L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhjLnN1Ym1pdHRlcl9uYW1lKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2JhZGdlKGMuc3RhdHVzKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhjLnJlc29sdXRpb25fbm90ZXMgfHwgJycpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7Y2FuTWFuYWdlID8gYDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20iIG9uY2xpY2s9InJlc29sdmVDb21wbGFpbnQoJHtjLmlkfSwgJyR7ZXNjKGMuc3RhdHVzKX0nKSI+TWFuYWdlPC9idXR0b24+YCA6ICcnfTwvdGQ+CiAgICAgICAgICAgIDwvdHI+CiAgICAgICAgICBgKS5qb2luKCcnKSA6ICc8dHIgY2xhc3M9ImVtcHR5LXJvdyI+PHRkIGNvbHNwYW49IjUiPk5vdGhpbmcgcmVwb3J0ZWQgeWV0LjwvdGQ+PC90cj4nfQogICAgICAgIDwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj4KICBgOwp9CmZ1bmN0aW9uIG5ld0NvbXBsYWludCgpIHsKICBvcGVuTW9kYWwoJ1JlcG9ydCBhIHByb2JsZW0nLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlRpdGxlPC9sYWJlbD48aW5wdXQgaWQ9ImNUaXRsZSIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RGV0YWlsczwvbGFiZWw+PHRleHRhcmVhIGlkPSJjRGVzYyI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRDb21wbGFpbnQoKSI+U3VibWl0PC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQphc3luYyBmdW5jdGlvbiBzdWJtaXRDb21wbGFpbnQoKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2NvbXBsYWludHMnLCB7IHRpdGxlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY1RpdGxlJykudmFsdWUsIGRlc2NyaXB0aW9uOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY0Rlc2MnKS52YWx1ZSB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnUmVwb3J0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmZ1bmN0aW9uIHJlc29sdmVDb21wbGFpbnQoaWQsIGN1cnJlbnRTdGF0dXMpIHsKICBjb25zdCBzdGF0dXNlcyA9IFsnb3BlbicsICdpbl9wcm9ncmVzcycsICdyZXNvbHZlZCddOwogIG9wZW5Nb2RhbCgnTWFuYWdlIGNvbXBsYWludCcsIGAKICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+U3RhdHVzPC9sYWJlbD4KICAgICAgPHNlbGVjdCBpZD0iY1N0YXR1cyI+JHtzdGF0dXNlcy5tYXAoKHMpID0+IGA8b3B0aW9uIHZhbHVlPSIke3N9IiAke3MgPT09IGN1cnJlbnRTdGF0dXMgPyAnc2VsZWN0ZWQnIDogJyd9PiR7cy5yZXBsYWNlKCdfJywgJyAnKX08L29wdGlvbj5gKS5qb2luKCcnKX08L3NlbGVjdD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5SZXNvbHV0aW9uIG5vdGVzPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImNOb3RlcyI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRDb21wbGFpbnRSZXNvbHZlKCR7aWR9KSI+U2F2ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0Q29tcGxhaW50UmVzb2x2ZShpZCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BVVCcsIGAvYXBpL2NvbXBsYWludHMvJHtpZH1gLCB7IHN0YXR1czogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NTdGF0dXMnKS52YWx1ZSwgcmVzb2x1dGlvbl9ub3RlczogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NOb3RlcycpLnZhbHVlIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdVcGRhdGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBSZXBvcnRzIChtYW5hZ2VyIC0+IFZQKSAtLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIHZpZXdSZXBvcnRzKHZpZXcpIHsKICBjb25zdCB7IHJlcG9ydHMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvcmVwb3J0cycpOwogIGNvbnN0IGlzVnAgPSBzdGF0ZS51c2VyLnJvbGUgPT09ICd2cCc7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPiR7aXNWcCA/ICdSZXBvcnRzIHN1Ym1pdHRlZCBieSB5b3VyIG1hbmFnZXJzLicgOiAnU2VuZCBhIHN1bW1hcnkgb2YgcHJvYmxlbXMsIGlkZWFzIGFuZCBLUEkgcHJvZ3Jlc3MgdG8gdGhlIFZQLid9PC9wPgogICAgICAkeyFpc1ZwID8gJzxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3UmVwb3J0KCkiPisgTmV3IHJlcG9ydDwvYnV0dG9uPicgOiAnJ30KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDx0YWJsZT4KICAgICAgICA8dGhlYWQ+PHRyPjx0aD5NYW5hZ2VyPC90aD48dGg+UGVyaW9kPC90aD48dGg+U3VtbWFyeTwvdGg+PHRoPlN0YXR1czwvdGg+JHtpc1ZwID8gJzx0aD5WUCBub3RlczwvdGg+PHRoPjwvdGg+JyA6ICcnfTwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHk+CiAgICAgICAgICAke3JlcG9ydHMubGVuZ3RoID8gcmVwb3J0cy5tYXAoKHIpID0+IGAKICAgICAgICAgICAgPHRyPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhyLm1hbmFnZXJfbmFtZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2Moci5wZXJpb2QgfHwgJycpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkIHN0eWxlPSJtYXgtd2lkdGg6MjgwcHg7Ij4ke2VzYyhyLnN1bW1hcnkpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7YmFkZ2Uoci5zdGF0dXMpfTwvdGQ+CiAgICAgICAgICAgICAgJHtpc1ZwID8gYDx0ZD4ke2VzYyhyLnZwX25vdGVzIHx8ICcnKX08L3RkPjx0ZD48YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIiBvbmNsaWNrPSJyZXZpZXdSZXBvcnQoJHtyLmlkfSwgJyR7ZXNjKHIuc3RhdHVzKX0nKSI+UmV2aWV3PC9idXR0b24+PC90ZD5gIDogJyd9CiAgICAgICAgICAgIDwvdHI+CiAgICAgICAgICBgKS5qb2luKCcnKSA6IGA8dHIgY2xhc3M9ImVtcHR5LXJvdyI+PHRkIGNvbHNwYW49IiR7aXNWcCA/IDYgOiA0fSI+Tm8gcmVwb3J0cyB5ZXQuPC90ZD48L3RyPmB9CiAgICAgICAgPC90Ym9keT4KICAgICAgPC90YWJsZT4KICAgIDwvZGl2PgogIGA7Cn0KYXN5bmMgZnVuY3Rpb24gbmV3UmVwb3J0KCkgewogIGNvbnN0IHNuYXAgPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3JlcG9ydHMvc25hcHNob3QnKTsKICBvcGVuTW9kYWwoJ05ldyByZXBvcnQgdG8gVlAnLCBgCiAgICA8cCBjbGFzcz0ic21hbGwtbm90ZSI+Q3VycmVudCBzbmFwc2hvdDogJHtzbmFwLm9wZW5Db21wbGFpbnRzfSBvcGVuIGNvbXBsYWludChzKSwgJHtzbmFwLm5ld0lkZWFzfSBuZXcgaWRlYShzKSwgJHtzbmFwLmtwaUNvdW50fSBLUEkocykgdHJhY2tlZC48L3A+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlBlcmlvZDwvbGFiZWw+PGlucHV0IGlkPSJyZXBQZXJpb2QiIHBsYWNlaG9sZGVyPSJRMyAyMDI2LCBvciBKdWx5IDIwMjYiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlN1bW1hcnkgZm9yIHRoZSBWUDwvbGFiZWw+PHRleHRhcmVhIGlkPSJyZXBTdW1tYXJ5IiBwbGFjZWhvbGRlcj0iS2V5IHdpbnMsIHByb2JsZW1zLCBpZGVhcywgYW5kIEtQSSBzdGF0dXMgdGhpcyBwZXJpb2QuLi4iPjwvdGV4dGFyZWE+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0UmVwb3J0KCkiPlNlbmQgdG8gVlA8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdFJlcG9ydCgpIHsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvcmVwb3J0cycsIHsgcGVyaW9kOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVwUGVyaW9kJykudmFsdWUsIHN1bW1hcnk6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZXBTdW1tYXJ5JykudmFsdWUgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1JlcG9ydCBzZW50IHRvIFZQJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQpmdW5jdGlvbiByZXZpZXdSZXBvcnQoaWQsIGN1cnJlbnRTdGF0dXMpIHsKICBvcGVuTW9kYWwoJ1JldmlldyByZXBvcnQnLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlN0YXR1czwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9InJlcFN0YXR1cyI+CiAgICAgICAgJHtbJ3N1Ym1pdHRlZCcsICdyZXZpZXdlZCddLm1hcCgocykgPT4gYDxvcHRpb24gdmFsdWU9IiR7c30iICR7cyA9PT0gY3VycmVudFN0YXR1cyA/ICdzZWxlY3RlZCcgOiAnJ30+JHtzfTwvb3B0aW9uPmApLmpvaW4oJycpfQogICAgICA8L3NlbGVjdD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5Ob3RlcyBiYWNrIHRvIG1hbmFnZXI8L2xhYmVsPjx0ZXh0YXJlYSBpZD0icmVwTm90ZXMiPjwvdGV4dGFyZWE+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0UmVwb3J0UmV2aWV3KCR7aWR9KSI+U2F2ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0UmVwb3J0UmV2aWV3KGlkKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUFVUJywgYC9hcGkvcmVwb3J0cy8ke2lkfWAsIHsgc3RhdHVzOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVwU3RhdHVzJykudmFsdWUsIHZwX25vdGVzOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVwTm90ZXMnKS52YWx1ZSB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnU2F2ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIEZpbGVzIChFeGNlbC9DU1YpIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld0ZpbGVzKHZpZXcpIHsKICBjb25zdCB7IGZpbGVzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL2ZpbGVzJyk7CiAgY29uc3QgY2FuVXBsb2FkID0gc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJzsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+U2hhcmUgc3ByZWFkc2hlZXRzIChyb3N0ZXJzLCBob3VycywgS1BJIHRyYWNrZXJzKSB3aXRoIHlvdXIgdGVhbS48L3A+CiAgICAgICR7Y2FuVXBsb2FkID8gJzxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3RmlsZSgpIj4rIFVwbG9hZCBmaWxlPC9idXR0b24+JyA6ICcnfQogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPHRhYmxlPgogICAgICAgIDx0aGVhZD48dHI+PHRoPkZpbGU8L3RoPjx0aD5EZXNjcmlwdGlvbjwvdGg+PHRoPlVwbG9hZGVkIGJ5PC90aD48dGg+RGF0ZTwvdGg+PHRoPjwvdGg+PC90cj48L3RoZWFkPgogICAgICAgIDx0Ym9keT4KICAgICAgICAgICR7ZmlsZXMubGVuZ3RoID8gZmlsZXMubWFwKChmKSA9PiBgCiAgICAgICAgICAgIDx0cj4KICAgICAgICAgICAgICA8dGQ+PHN0cm9uZz4ke2VzYyhmLmZpbGVuYW1lKX08L3N0cm9uZz48L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhmLmRlc2NyaXB0aW9uIHx8ICcnKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhmLnVwbG9hZGVyX25hbWUpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7Zm10RGF0ZShmLmNyZWF0ZWRfYXQpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSIgb25jbGljaz0icHJldmlld0ZpbGUoJHtmLmlkfSwgJyR7ZXNjKGYuZmlsZW5hbWUpfScpIj5QcmV2aWV3PC9idXR0b24+CiAgICAgICAgICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1zbSIgaHJlZj0iL2FwaS9maWxlcy8ke2YuaWR9L2Rvd25sb2FkP3Q9JHtlbmNvZGVVUklDb21wb25lbnQoc3RhdGUudG9rZW4pfSIgb25jbGljaz0icmV0dXJuIGRvd25sb2FkRmlsZShldmVudCwgJHtmLmlkfSwgJyR7ZXNjKGYuZmlsZW5hbWUpfScpIj5Eb3dubG9hZDwvYT4KICAgICAgICAgICAgICAgICR7Y2FuVXBsb2FkID8gYDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgb25jbGljaz0iZGVsZXRlRmlsZSgke2YuaWR9KSI+RGVsZXRlPC9idXR0b24+YCA6ICcnfQogICAgICAgICAgICAgIDwvdGQ+CiAgICAgICAgICAgIDwvdHI+CiAgICAgICAgICBgKS5qb2luKCcnKSA6ICc8dHIgY2xhc3M9ImVtcHR5LXJvdyI+PHRkIGNvbHNwYW49IjUiPk5vIGZpbGVzIHVwbG9hZGVkIHlldC48L3RkPjwvdHI+J30KICAgICAgICA8L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+CiAgYDsKfQoKZnVuY3Rpb24gbmV3RmlsZSgpIHsKICBvcGVuTW9kYWwoJ1VwbG9hZCBhIHNwcmVhZHNoZWV0JywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5GaWxlICguY3N2LCAudHN2LCAueGxzLCAueGxzeCk8L2xhYmVsPjxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iZmlsZUlucHV0IiBhY2NlcHQ9Ii5jc3YsLnRzdiwueGxzLC54bHN4IiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5EZXNjcmlwdGlvbjwvbGFiZWw+PGlucHV0IGlkPSJmaWxlRGVzYyIgcGxhY2Vob2xkZXI9ImUuZy4gSnVseSB2b2x1bnRlZXIgaG91cnMiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0RmlsZSgpIj5VcGxvYWQ8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmZ1bmN0aW9uIHJlYWRGaWxlQXNCYXNlNjQoZmlsZSkgewogIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7CiAgICBjb25zdCByZWFkZXIgPSBuZXcgRmlsZVJlYWRlcigpOwogICAgcmVhZGVyLm9ubG9hZCA9ICgpID0+IHJlc29sdmUocmVhZGVyLnJlc3VsdC5zcGxpdCgnLCcpWzFdKTsKICAgIHJlYWRlci5vbmVycm9yID0gcmVqZWN0OwogICAgcmVhZGVyLnJlYWRBc0RhdGFVUkwoZmlsZSk7CiAgfSk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0RmlsZSgpIHsKICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmaWxlSW5wdXQnKTsKICBpZiAoIWlucHV0LmZpbGVzLmxlbmd0aCkgcmV0dXJuIHNob3dUb2FzdCgnQ2hvb3NlIGEgZmlsZSBmaXJzdCcsIHRydWUpOwogIGNvbnN0IGZpbGUgPSBpbnB1dC5maWxlc1swXTsKICBpZiAoZmlsZS5zaXplID4gMTIgKiAxMDI0ICogMTAyNCkgcmV0dXJuIHNob3dUb2FzdCgnRmlsZSB0b28gbGFyZ2UgKG1heCB+MTJNQiknLCB0cnVlKTsKICB0cnkgewogICAgY29uc3QgYjY0ID0gYXdhaXQgcmVhZEZpbGVBc0Jhc2U2NChmaWxlKTsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2ZpbGVzJywgeyBmaWxlbmFtZTogZmlsZS5uYW1lLCBkZXNjcmlwdGlvbjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ZpbGVEZXNjJykudmFsdWUsIGRhdGFfYmFzZTY0OiBiNjQgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0ZpbGUgdXBsb2FkZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUZpbGUoaWQpIHsKICBpZiAoIWNvbmZpcm0oJ0RlbGV0ZSB0aGlzIGZpbGU/JykpIHJldHVybjsKICB0cnkgewogICAgYXdhaXQgYXBpKCdERUxFVEUnLCBgL2FwaS9maWxlcy8ke2lkfWApOwogICAgc2hvd1RvYXN0KCdEZWxldGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQphc3luYyBmdW5jdGlvbiBkb3dubG9hZEZpbGUoZSwgaWQsIGZpbGVuYW1lKSB7CiAgZS5wcmV2ZW50RGVmYXVsdCgpOwogIHRyeSB7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChgL2FwaS9maWxlcy8ke2lkfS9kb3dubG9hZGAsIHsgaGVhZGVyczogeyBBdXRob3JpemF0aW9uOiAnQmVhcmVyICcgKyBzdGF0ZS50b2tlbiB9IH0pOwogICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcignRG93bmxvYWQgZmFpbGVkJyk7CiAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICBjb25zdCBhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYScpOwogICAgYS5ocmVmID0gdXJsOyBhLmRvd25sb2FkID0gZmlsZW5hbWU7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOyBhLmNsaWNrKCk7IGEucmVtb3ZlKCk7CiAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KICByZXR1cm4gZmFsc2U7Cn0KYXN5bmMgZnVuY3Rpb24gcHJldmlld0ZpbGUoaWQsIGZpbGVuYW1lKSB7CiAgdHJ5IHsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGAvYXBpL2ZpbGVzLyR7aWR9L2Rvd25sb2FkYCwgeyBoZWFkZXJzOiB7IEF1dGhvcml6YXRpb246ICdCZWFyZXIgJyArIHN0YXRlLnRva2VuIH0gfSk7CiAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCdQcmV2aWV3IGZhaWxlZCcpOwogICAgY29uc3QgYnVmID0gYXdhaXQgcmVzLmFycmF5QnVmZmVyKCk7CiAgICBjb25zdCB3YiA9IFhMU1gucmVhZChidWYsIHsgdHlwZTogJ2FycmF5JyB9KTsKICAgIGNvbnN0IHNoZWV0TmFtZSA9IHdiLlNoZWV0TmFtZXNbMF07CiAgICBjb25zdCByb3dzID0gWExTWC51dGlscy5zaGVldF90b19qc29uKHdiLlNoZWV0c1tzaGVldE5hbWVdLCB7IGhlYWRlcjogMSwgcmF3OiBmYWxzZSB9KTsKICAgIGNvbnN0IGhlYWQgPSByb3dzWzBdIHx8IFtdOwogICAgY29uc3QgYm9keSA9IHJvd3Muc2xpY2UoMSwgMjAxKTsKICAgIGNvbnN0IHRhYmxlSHRtbCA9IGAKICAgICAgPGRpdiBjbGFzcz0icHJldmlldy10YWJsZS13cmFwIj4KICAgICAgICA8dGFibGU+CiAgICAgICAgICA8dGhlYWQ+PHRyPiR7aGVhZC5tYXAoKGgpID0+IGA8dGg+JHtlc2MoaCl9PC90aD5gKS5qb2luKCcnKX08L3RyPjwvdGhlYWQ+CiAgICAgICAgICA8dGJvZHk+JHtib2R5Lm1hcCgocikgPT4gYDx0cj4ke2hlYWQubWFwKChfLCBpKSA9PiBgPHRkPiR7ZXNjKHJbaV0pfTwvdGQ+YCkuam9pbignJyl9PC90cj5gKS5qb2luKCcnKX08L3Rib2R5PgogICAgICAgIDwvdGFibGU+CiAgICAgIDwvZGl2PgogICAgICAke3Jvd3MubGVuZ3RoID4gMjAxID8gYDxwIGNsYXNzPSJzbWFsbC1ub3RlIj5TaG93aW5nIGZpcnN0IDIwMCByb3dzIG9mICR7cm93cy5sZW5ndGggLSAxfS48L3A+YCA6ICcnfQogICAgYDsKICAgIG9wZW5Nb2RhbChmaWxlbmFtZSwgdGFibGVIdG1sKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KCdDb3VsZCBub3QgcHJldmlldyB0aGlzIGZpbGU6ICcgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBTdXJ2ZXlzIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld1N1cnZleXModmlldykgewogIGNvbnN0IHsgc3VydmV5cyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9zdXJ2ZXlzJyk7CiAgY29uc3QgY2FuTWFuYWdlID0gc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJzsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+TGluayBvdXQgdG8gR29vZ2xlIEZvcm1zIGZvciBzdXJ2ZXlzLCBhbmQgR29vZ2xlIFNoZWV0cyBmb3IgcmVzdWx0cy48L3A+CiAgICAgICR7Y2FuTWFuYWdlID8gJzxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3U3VydmV5KCkiPisgQWRkIHN1cnZleSBsaW5rPC9idXR0b24+JyA6ICcnfQogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJncmlkIj4KICAgICAgJHtzdXJ2ZXlzLmxlbmd0aCA/IHN1cnZleXMubWFwKChzKSA9PiBgCiAgICAgICAgPGRpdiBjbGFzcz0ic3RhdC1jYXJkIj4KICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDsiPiR7ZXNjKHMudGl0bGUpfTwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDsgbWFyZ2luLWJvdHRvbTo4cHg7Ij5ieSAke2VzYyhzLmNyZWF0b3JfbmFtZSl9ICZtaWRkb3Q7ICR7Zm10RGF0ZShzLmNyZWF0ZWRfYXQpfTwvZGl2PgogICAgICAgICAgJHtzLmdvb2dsZV9mb3JtX3VybCA/IGA8ZGl2PjxhIGNsYXNzPSJsaW5rIiBocmVmPSIke2VzYyhzLmdvb2dsZV9mb3JtX3VybCl9IiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciI+T3BlbiBmb3JtICZyYXJyOzwvYT48L2Rpdj5gIDogJyd9CiAgICAgICAgICAke3MuZ29vZ2xlX3NoZWV0X3VybCA/IGA8ZGl2PjxhIGNsYXNzPSJsaW5rIiBocmVmPSIke2VzYyhzLmdvb2dsZV9zaGVldF91cmwpfSIgdGFyZ2V0PSJfYmxhbmsiIHJlbD0ibm9vcGVuZXIiPlZpZXcgcmVzdWx0cyBzaGVldCAmcmFycjs8L2E+PC9kaXY+YCA6ICcnfQogICAgICAgICAgJHtjYW5NYW5hZ2UgPyBgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tZGFuZ2VyIiBzdHlsZT0ibWFyZ2luLXRvcDoxMHB4OyIgb25jbGljaz0iZGVsZXRlU3VydmV5KCR7cy5pZH0pIj5SZW1vdmU8L2J1dHRvbj5gIDogJyd9CiAgICAgICAgPC9kaXY+CiAgICAgIGApLmpvaW4oJycpIDogJzxwIGNsYXNzPSJtdXRlZCI+Tm8gc3VydmV5cyBhZGRlZCB5ZXQuPC9wPid9CiAgICA8L2Rpdj4KICBgOwp9CmZ1bmN0aW9uIG5ld1N1cnZleSgpIHsKICBvcGVuTW9kYWwoJ0FkZCBzdXJ2ZXkgbGluaycsIGAKICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+VGl0bGU8L2xhYmVsPjxpbnB1dCBpZD0ic3ZUaXRsZSIgcGxhY2Vob2xkZXI9ImUuZy4gTW9udGhseSB2b2x1bnRlZXIgZmVlZGJhY2siIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkdvb2dsZSBGb3JtIFVSTDwvbGFiZWw+PGlucHV0IGlkPSJzdkZvcm0iIHBsYWNlaG9sZGVyPSJodHRwczovL2Zvcm1zLmdvb2dsZS5jb20vLi4uIiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5Hb29nbGUgU2hlZXQgcmVzdWx0cyBVUkwgKG9wdGlvbmFsKTwvbGFiZWw+PGlucHV0IGlkPSJzdlNoZWV0IiBwbGFjZWhvbGRlcj0iaHR0cHM6Ly9kb2NzLmdvb2dsZS5jb20vc3ByZWFkc2hlZXRzLy4uLiIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRTdXJ2ZXkoKSI+QWRkPC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQphc3luYyBmdW5jdGlvbiBzdWJtaXRTdXJ2ZXkoKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL3N1cnZleXMnLCB7CiAgICAgIHRpdGxlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3ZUaXRsZScpLnZhbHVlLAogICAgICBnb29nbGVfZm9ybV91cmw6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdkZvcm0nKS52YWx1ZSwKICAgICAgZ29vZ2xlX3NoZWV0X3VybDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N2U2hlZXQnKS52YWx1ZSwKICAgIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdTdXJ2ZXkgbGluayBhZGRlZCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KYXN5bmMgZnVuY3Rpb24gZGVsZXRlU3VydmV5KGlkKSB7CiAgaWYgKCFjb25maXJtKCdSZW1vdmUgdGhpcyBzdXJ2ZXkgbGluaz8nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL3N1cnZleXMvJHtpZH1gKTsKICAgIHNob3dUb2FzdCgnUmVtb3ZlZCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KCi8vIC0tLS0tLS0tLS0gVGVhbSAvIFBlb3BsZSAtLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIHZpZXdUZWFtKHZpZXcpIHsKICBjb25zdCB7IHVzZXJzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3VzZXJzJyk7CiAgY29uc3QgaXNWcCA9IHN0YXRlLnVzZXIucm9sZSA9PT0gJ3ZwJzsKICBjb25zdCBhZGRMYWJlbCA9IGlzVnAgPyAnKyBBZGQgbWFuYWdlcicgOiAnKyBBZGQgdm9sdW50ZWVyJzsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+JHtpc1ZwID8gJ0FsbCBtYW5hZ2VycyBhbmQgdm9sdW50ZWVycyBpbiB0aGUgb3JnYW5pemF0aW9uLicgOiAnVm9sdW50ZWVycyBvbiB5b3VyIHRlYW0uJ308L3A+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3VXNlcigpIj4ke2FkZExhYmVsfTwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPHRhYmxlPgogICAgICAgIDx0aGVhZD48dHI+PHRoPk5hbWU8L3RoPjx0aD5FbWFpbDwvdGg+PHRoPlJvbGU8L3RoPjx0aD5TdGF0dXM8L3RoPjx0aD48L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHk+CiAgICAgICAgICAke3VzZXJzLmxlbmd0aCA/IHVzZXJzLm1hcCgodSkgPT4gYAogICAgICAgICAgICA8dHI+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKHUubmFtZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2ModS5lbWFpbCl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2ModS5yb2xlKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke3UuYWN0aXZlID8gJzxzcGFuIGNsYXNzPSJiYWRnZSBiYWRnZS1yZXNvbHZlZCI+YWN0aXZlPC9zcGFuPicgOiAnPHNwYW4gY2xhc3M9ImJhZGdlIGJhZGdlLXJlamVjdGVkIj5pbmFjdGl2ZTwvc3Bhbj4nfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7dS5pZCAhPT0gc3RhdGUudXNlci5pZCA/IGA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1kYW5nZXIiIG9uY2xpY2s9ImRlYWN0aXZhdGVVc2VyKCR7dS5pZH0pIj5EZWFjdGl2YXRlPC9idXR0b24+YCA6ICc8c3BhbiBjbGFzcz0ibXV0ZWQiPnlvdTwvc3Bhbj4nfTwvdGQ+CiAgICAgICAgICAgIDwvdHI+CiAgICAgICAgICBgKS5qb2luKCcnKSA6ICc8dHIgY2xhc3M9ImVtcHR5LXJvdyI+PHRkIGNvbHNwYW49IjUiPk5vIG9uZSBoZXJlIHlldC48L3RkPjwvdHI+J30KICAgICAgICA8L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+CiAgYDsKfQpmdW5jdGlvbiBuZXdVc2VyKCkgewogIGNvbnN0IGlzVnAgPSBzdGF0ZS51c2VyLnJvbGUgPT09ICd2cCc7CiAgb3Blbk1vZGFsKGlzVnAgPyAnQWRkIG1hbmFnZXInIDogJ0FkZCB2b2x1bnRlZXInLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkZ1bGwgbmFtZTwvbGFiZWw+PGlucHV0IGlkPSJ1TmFtZSIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RW1haWw8L2xhYmVsPjxpbnB1dCBpZD0idUVtYWlsIiB0eXBlPSJlbWFpbCIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+VGVtcG9yYXJ5IHBhc3N3b3JkPC9sYWJlbD48aW5wdXQgaWQ9InVQYXNzIiB0eXBlPSJ0ZXh0IiB2YWx1ZT0iV2VsY29tZTEyMyEiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0VXNlcignJHtpc1ZwID8gJ21hbmFnZXInIDogJ3ZvbHVudGVlcid9JykiPkFkZDwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0VXNlcihyb2xlKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL3VzZXJzJywgewogICAgICBuYW1lOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndU5hbWUnKS52YWx1ZSwKICAgICAgZW1haWw6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1RW1haWwnKS52YWx1ZSwKICAgICAgcGFzc3dvcmQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1UGFzcycpLnZhbHVlLAogICAgICByb2xlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0FkZGVkLiBTaGFyZSB0aGUgdGVtcG9yYXJ5IHBhc3N3b3JkIHdpdGggdGhlbSBzZWN1cmVseS4nKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGRlYWN0aXZhdGVVc2VyKGlkKSB7CiAgaWYgKCFjb25maXJtKCdEZWFjdGl2YXRlIHRoaXMgYWNjb3VudD8gVGhleSB3aWxsIG5vIGxvbmdlciBiZSBhYmxlIHRvIGxvZyBpbi4nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL3VzZXJzLyR7aWR9YCk7CiAgICBzaG93VG9hc3QoJ0RlYWN0aXZhdGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBBbm5vdW5jZW1lbnRzIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld0Fubm91bmNlbWVudHModmlldykgewogIGNvbnN0IHsgYW5ub3VuY2VtZW50cyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9hbm5vdW5jZW1lbnRzJyk7CiAgY29uc3QgY2FuUG9zdCA9IHN0YXRlLnVzZXIucm9sZSAhPT0gJ3ZvbHVudGVlcic7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPlVwZGF0ZXMgZnJvbSBtYW5hZ2VycyBhbmQgdGhlIFZQLjwvcD4KICAgICAgJHtjYW5Qb3N0ID8gJzxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3QW5ub3VuY2VtZW50KCkiPisgUG9zdCBhbm5vdW5jZW1lbnQ8L2J1dHRvbj4nIDogJyd9CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPiR7cmVuZGVyQW5ub3VuY2VtZW50TGlzdChhbm5vdW5jZW1lbnRzKX08L2Rpdj4KICBgOwp9CmZ1bmN0aW9uIG5ld0Fubm91bmNlbWVudCgpIHsKICBvcGVuTW9kYWwoJ1Bvc3QgYW5ub3VuY2VtZW50JywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UaXRsZTwvbGFiZWw+PGlucHV0IGlkPSJhblRpdGxlIiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5NZXNzYWdlPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImFuQm9keSI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRBbm5vdW5jZW1lbnQoKSI+UG9zdDwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0QW5ub3VuY2VtZW50KCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9hbm5vdW5jZW1lbnRzJywgeyB0aXRsZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FuVGl0bGUnKS52YWx1ZSwgYm9keTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FuQm9keScpLnZhbHVlIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdQb3N0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIEJvb3QgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiBib290KCkgewogIGlmICghc3RhdGUudG9rZW4pIHJldHVybiBzaG93TG9naW4oKTsKICB0cnkgewogICAgY29uc3QgeyB1c2VyIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL21lJyk7CiAgICBzdGF0ZS51c2VyID0gdXNlcjsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2dpblNjcmVlbicpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FwcCcpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgbmF2aWdhdGUoJ2Rhc2hib2FyZCcpOwogIH0gY2F0Y2ggKGVycikgewogICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Ztc190b2tlbicpOwogICAgc2hvd0xvZ2luKCk7CiAgfQp9CmZ1bmN0aW9uIHNob3dMb2dpbigpIHsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9naW5TY3JlZW4nKS5jbGFzc0xpc3QucmVtb3ZlKCdoaWRkZW4nKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYXBwJykuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyk7Cn0KCmJvb3QoKTsK', 'base64').toString('utf8');

function serveStatic(res, pathname) {
  if (pathname === '/css/style.css') {
    res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
    return res.end(STYLE_CSS);
  }
  if (pathname === '/js/app.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
    return res.end(APP_JS);
  }
  // Everything else (/, /whatever) -> single-page app shell
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(INDEX_HTML);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsed.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (!pathname.startsWith('/api/')) return serveStatic(res, pathname);

  for (const r of routes) {
    if (r.method !== req.method) continue;
    const m = pathname.match(r.regex);
    if (!m) continue;
    const params = {};
    r.keys.forEach((k, i) => (params[k] = m[i + 1]));

    const isPublic = pathname === '/api/login';
    let user = null;
    if (!isPublic) {
      user = getAuthUser(req);
      if (!user) return send(res, 401, { error: 'Unauthorized' });
    }
    try {
      await r.handler(req, res, { user, params });
    } catch (e) {
      console.error(e);
      if (!res.headersSent) send(res, 500, { error: 'Server error', detail: e.message });
    }
    return;
  }
  send(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Makkah Health Cluster Volunteer Management Portal running at http://localhost:${PORT}`);
});
