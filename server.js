'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(ROOT, 'data', 'neat-clean.sqlite');
const SESSION_TTL = 14 * 24 * 60 * 60 * 1000;
const scrypt = promisify(crypto.scrypt);

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    phone TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
    area TEXT NOT NULL DEFAULT '',
    prefs TEXT NOT NULL DEFAULT '[]',
    sms_updates INTEGER NOT NULL DEFAULT 1,
    marketing INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'website',
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    ref TEXT NOT NULL UNIQUE,
    customer_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    customer TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL,
    service TEXT NOT NULL,
    service_name TEXT NOT NULL,
    qty INTEGER NOT NULL,
    unit TEXT NOT NULL,
    method TEXT NOT NULL,
    express INTEGER NOT NULL DEFAULT 0,
    slot_date TEXT NOT NULL,
    slot_idx INTEGER NOT NULL,
    slot TEXT NOT NULL,
    area TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    plan TEXT NOT NULL DEFAULT '',
    base REAL NOT NULL,
    express_fee REAL NOT NULL DEFAULT 0,
    discount REAL NOT NULL DEFAULT 0,
    pickup_fee REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'booked',
    driver TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'website',
    example INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    booked_at INTEGER NOT NULL,
    collected_at INTEGER,
    washing_at INTEGER,
    ready_at INTEGER,
    delivered_at INTEGER
  );
`);

db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());

const SERVICE_CATALOG = {
  'wash-fold': { name: 'Wash & fold', unit: 'kg', price: 185.5, min: 5, max: 40 },
  'wash-iron': { name: 'Wash & iron', unit: 'kg', price: 324.5, min: 4, max: 30 },
  'dry-clean': { name: 'Dry cleaning', unit: 'item', price: 502, min: 1, max: 30 },
  household: { name: 'Bedding & household', unit: 'item', price: 1081, min: 1, max: 20 }
};
const AREA_CATALOG = {
  'naya-bazaar': { name: 'Naya Bazaar', hub: false },
  thamel: { name: 'Thamel', hub: true },
  lazimpat: { name: 'Lazimpat', hub: true },
  basantapur: { name: 'Basantapur', hub: true },
  paknajol: { name: 'Paknajol', hub: false },
  balaju: { name: 'Balaju', hub: true },
  sorhakhutte: { name: 'Sorhakhutte', hub: false },
  swayambhu: { name: 'Swayambhu', hub: false }
};
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml'
};
const PUBLIC_FILES = new Set(['nac.html', 'Tidal Admin.html', 'Tidal Admin.md', '1laundry.jpg']);

function round2(value) {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

function groupedMoney(value) {
  const rounded = round2(value);
  return 'Rs. ' + rounded.toLocaleString('en-IN', {
    minimumFractionDigits: rounded % 1 ? 2 : 0,
    maximumFractionDigits: 2
  });
}

function json(res, status, value, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(JSON.stringify(value));
}

function fail(res, status, message) {
  json(res, status, { error: message });
}

async function readJson(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 64 * 1024) throw Object.assign(new Error('Request is too large.'), { status: 413 });
  }
  if (!body) return {};
  try {
    return JSON.parse(body);
  } catch {
    throw Object.assign(new Error('Request must be valid JSON.'), { status: 400 });
  }
}

function clean(value, max = 500) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function emailValue(value) {
  return clean(value, 254).toLowerCase();
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}

function isLoopback(address) {
  return address === '127.0.0.1' || address === '::1' || String(address).startsWith('::ffff:127.');
}

function isSameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function sessionCookie(token, maxAge = SESSION_TTL / 1000) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `nc_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const item of header.split(';')) {
    const parts = item.trim().split('=');
    if (parts.shift() === name) return decodeURIComponent(parts.join('='));
  }
  return '';
}

function getSessionUser(req) {
  const token = readCookie(req, 'nc_session');
  if (!token) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const row = db.prepare(`
    SELECT u.id, u.name, u.email, u.phone, u.role, u.area, u.prefs,
           u.sms_updates, u.marketing, u.source, u.created_at
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(tokenHash, Date.now());
  return row || null;
}

function attachSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(tokenHash, userId, Date.now() + SESSION_TTL);
  res.setHeader('Set-Cookie', sessionCookie(token));
}

function clearSession(req, res) {
  const token = readCookie(req, 'nc_session');
  if (token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
  }
  res.setHeader('Set-Cookie', sessionCookie('', 0));
}

async function insertUser({ name, email, phone, password, role, area = '', prefs = [], smsUpdates = true, marketing = false }) {
  const id = crypto.randomUUID();
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  const createdAt = Date.now();
  db.prepare(`
    INSERT INTO users (id, name, email, phone, password_salt, password_hash, role,
      area, prefs, sms_updates, marketing, source, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'website', ?)
  `).run(id, name, email, phone, salt.toString('hex'), hash.toString('hex'), role,
    area, JSON.stringify(prefs), smsUpdates ? 1 : 0, marketing ? 1 : 0, createdAt);
  return { id, name, email, phone, role, area, prefs, smsUpdates, marketing, createdAt };
}

async function passwordMatches(user, password) {
  const salt = Buffer.from(user.password_salt, 'hex');
  const actual = Buffer.from(user.password_hash, 'hex');
  const candidate = Buffer.from(await scrypt(password, salt, actual.length));
  return crypto.timingSafeEqual(actual, candidate);
}

function requireAdmin(req, res) {
  const user = getSessionUser(req);
  if (!user || user.role !== 'admin') {
    fail(res, 401, 'Admin sign-in required.');
    return null;
  }
  return user;
}

function adminSetupRequired() {
  return db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").get().count === 0;
}

function dateKeyValid(value) {
  const match = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(value);
  if (!match) return false;
  const [, year, month, day] = match.map(Number);
  const date = new Date(year, month - 1, day);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const max = new Date(today);
  max.setDate(max.getDate() + 60);
  return date.getFullYear() === year && date.getMonth() === month - 1 && date.getDate() === day && date >= today && date <= max;
}

function slotLabel(index) {
  const start = 8 + index * 2;
  const end = start + 2;
  const formatHour = (hour) => hour % 12 || 12;
  const startPeriod = start >= 12 ? 'pm' : 'am';
  const endPeriod = end >= 12 ? 'pm' : 'am';
  return startPeriod === endPeriod
    ? `${formatHour(start)} to ${formatHour(end)} ${endPeriod}`
    : `${formatHour(start)} ${startPeriod} to ${formatHour(end)} ${endPeriod}`;
}

function orderJson(row) {
  return {
    ref: row.ref, customer: row.customer, email: row.email, phone: row.phone,
    service: row.service, serviceName: row.service_name, qty: row.qty, unit: row.unit,
    method: row.method, express: Boolean(row.express), slotDate: row.slot_date,
    slotIdx: row.slot_idx, slot: row.slot, area: row.area, address: row.address,
    notes: row.notes, plan: row.plan, base: row.base, expressFee: row.express_fee,
    discount: row.discount, pickupFee: row.pickup_fee, total: row.total,
    status: row.status, driver: row.driver, source: row.source,
    example: Boolean(row.example), createdAt: row.created_at,
    bookedAt: row.booked_at, collectedAt: row.collected_at,
    washingAt: row.washing_at, readyAt: row.ready_at, deliveredAt: row.delivered_at
  };
}

function customerJson(row) {
  let prefs = [];
  try { prefs = JSON.parse(row.prefs || '[]'); } catch {}
  return {
    _id: row.id, name: row.name, email: row.email, phone: row.phone,
    area: (AREA_CATALOG[row.area] || { name: row.area }).name, prefs, smsUpdates: Boolean(row.sms_updates),
    marketing: Boolean(row.marketing), source: row.source, createdAt: row.created_at
  };
}

function createOrder(input, customerId = null, example = false) {
  const service = SERVICE_CATALOG[input.service];
  const area = AREA_CATALOG[input.area];
  const qty = Number(input.qty);
  const method = input.method;
  const express = Boolean(input.express);
  const date = clean(input.date, 10);
  const time = Number(input.time);
  const name = clean(input.name, 120);
  const phone = clean(input.phone, 40);
  const email = emailValue(input.email);
  const address = clean(input.address, 300);
  const notes = clean(input.notes, 1000);
  const plan = clean(input.plan, 60);

  if (!service) throw Object.assign(new Error('Choose a valid service.'), { status: 400 });
  if (!Number.isInteger(qty) || qty < service.min || qty > service.max) {
    throw Object.assign(new Error('Amount is outside the allowed range.'), { status: 400 });
  }
  if (!area) throw Object.assign(new Error('Choose a Kathmandu service area.'), { status: 400 });
  if (method !== 'pickup' && method !== 'dropoff') throw Object.assign(new Error('Choose pickup or drop-off.'), { status: 400 });
  if (method === 'dropoff' && !area.hub) throw Object.assign(new Error('Choose an area with a drop-off point.'), { status: 400 });
  if (!dateKeyValid(date)) throw Object.assign(new Error('Choose an available future date.'), { status: 400 });
  if (!Number.isInteger(time) || time < 0 || time > 5) throw Object.assign(new Error('Choose a valid time window.'), { status: 400 });
  if (name.length < 2) throw Object.assign(new Error('Enter your full name.'), { status: 400 });
  if ((phone.match(/\d/g) || []).length < 7 || (phone.match(/\d/g) || []).length > 15) {
    throw Object.assign(new Error('Enter a valid phone number.'), { status: 400 });
  }
  if (email && !validEmail(email)) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
  if (method === 'pickup' && address.length < 5) throw Object.assign(new Error('Enter the pickup address.'), { status: 400 });

  const base = round2(service.price * qty);
  const expressFee = express ? 309 : 0;
  const discount = method === 'dropoff' ? round2(base * 0.1) : 0;
  const subtotal = round2(base + expressFee - discount);
  const pickupFee = method === 'pickup' && subtotal < 1930 ? 231.5 : 0;
  const total = round2(subtotal + pickupFee);
  const ref = 'NC-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const createdAt = Date.now();
  const id = crypto.randomUUID();
  const slot = slotLabel(time);

  db.prepare(`
    INSERT INTO orders (id, ref, customer_id, customer, email, phone, service, service_name,
      qty, unit, method, express, slot_date, slot_idx, slot, area, address, notes, plan,
      base, express_fee, discount, pickup_fee, total, status, source, example, created_at, booked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'booked', ?, ?, ?, ?)
  `).run(id, ref, customerId, name, email, phone, input.service, service.name,
    qty, service.unit, method, express ? 1 : 0, date, time, slot, area.name,
    method === 'pickup' ? address : '', notes, plan, base, expressFee, discount, pickupFee,
    total, example ? 'admin sample' : 'website', example ? 1 : 0, createdAt, createdAt);
  return { ref, total, serviceName: service.name, qty, unit: service.unit, method, area: area.name, slot, date };
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  const pathname = decodeURIComponent(url.pathname);
  const method = req.method || 'GET';

  if (pathname.startsWith('/api/') && method !== 'GET' && method !== 'HEAD' && !isSameOrigin(req)) {
    return fail(res, 403, 'Cross-origin request denied.');
  }

  if (method === 'GET' && pathname === '/api/health') return json(res, 200, { ok: true });
  if (method === 'GET' && pathname === '/api/session') {
    const user = getSessionUser(req);
    return json(res, 200, {
      user: user ? { id: user.id, name: user.name, email: user.email, phone: user.phone, area: user.area, role: user.role } : null,
      adminSetupRequired: adminSetupRequired()
    });
  }

  if (method === 'POST' && pathname === '/api/admin/setup') {
    if (!isLoopback(req.socket.remoteAddress)) return fail(res, 403, 'First admin setup is only available on this computer.');
    if (!adminSetupRequired()) return fail(res, 409, 'An admin account already exists. Sign in instead.');
    const body = await readJson(req);
    const name = clean(body.name, 120);
    const email = emailValue(body.email);
    const password = String(body.password || '');
    if (name.length < 2 || !validEmail(email) || password.length < 12) {
      return fail(res, 400, 'Enter a name, valid email, and password of at least 12 characters.');
    }
    const user = await insertUser({ name, email, phone: '', password, role: 'admin' });
    attachSession(res, user.id);
    return json(res, 201, { user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  }

  if (method === 'POST' && pathname === '/api/admin/login') {
    const body = await readJson(req);
    const email = emailValue(body.email);
    const password = String(body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email);
    if (!user || user.role !== 'admin' || !(await passwordMatches(user, password))) {
      return fail(res, 401, 'Email or password is incorrect.');
    }
    attachSession(res, user.id);
    return json(res, 200, { user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  }

  if (method === 'POST' && pathname === '/api/signup') {
    const body = await readJson(req);
    const name = clean(body.name, 120);
    const email = emailValue(body.email);
    const phone = clean(body.phone, 40);
    const password = String(body.password || '');
    const area = clean(body.area, 60);
    const prefs = Array.isArray(body.prefs) ? body.prefs.map((x) => clean(x, 60)).slice(0, 12) : [];
    const smsUpdates = Boolean(body.smsUpdates);
    const marketing = Boolean(body.marketing);
    if (name.length < 2 || !validEmail(email) || password.length < 8 ||
      (phone.match(/\d/g) || []).length < 7 || !AREA_CATALOG[area]) {
      return fail(res, 400, 'Check your name, email, phone, password, and Kathmandu neighbourhood.');
    }
    try {
      const user = await insertUser({ name, email, phone, password, role: 'customer', area, prefs, smsUpdates, marketing });
      attachSession(res, user.id);
      return json(res, 201, { user: { id: user.id, name, email, role: 'customer' } });
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) return fail(res, 409, 'An account with that email already exists.');
      throw error;
    }
  }

  if (method === 'POST' && pathname === '/api/logout') {
    clearSession(req, res);
    return json(res, 200, { ok: true });
  }

  if (method === 'POST' && pathname === '/api/bookings') {
    const sessionUser = getSessionUser(req);
    const body = await readJson(req);
    if (sessionUser) {
      body.name = body.name || sessionUser.name;
      body.phone = body.phone || sessionUser.phone;
      body.email = body.email || sessionUser.email;
      body.area = body.area || sessionUser.area;
    }
    const booking = createOrder(body, sessionUser && sessionUser.role === 'customer' ? sessionUser.id : null);
    return json(res, 201, booking);
  }

  if (method === 'GET' && pathname === '/api/admin/data') {
    if (!requireAdmin(req, res)) return;
    const orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 1000').all().map(orderJson);
    const customers = db.prepare('SELECT * FROM users WHERE role = \'customer\' ORDER BY created_at DESC LIMIT 1000').all().map(customerJson);
    return json(res, 200, { orders, customers });
  }

  if (method === 'PATCH' && pathname.startsWith('/api/admin/orders/')) {
    if (!requireAdmin(req, res)) return;
    const ref = decodeURIComponent(pathname.slice('/api/admin/orders/'.length));
    const body = await readJson(req);
    const transitions = { booked: 'collected', collected: 'washing', washing: 'ready', ready: 'delivered' };
    const row = db.prepare('SELECT status FROM orders WHERE ref = ?').get(ref);
    if (!row) return fail(res, 404, 'Booking not found.');
    if (transitions[row.status] !== body.status) return fail(res, 400, 'Invalid booking status transition.');
    db.prepare(`UPDATE orders SET status = ?, ${body.status}_at = ? WHERE ref = ?`).run(body.status, Date.now(), ref);
    return json(res, 200, { ok: true, ref, status: body.status });
  }

  if (method === 'POST' && pathname === '/api/admin/orders/simulate') {
    if (!requireAdmin(req, res)) return;
    const names = ['Mira Shrestha', 'Aarav Karki', 'Noor Ali', 'Ben Gurung', 'Aiko Tamang', 'Lena Rai'];
    const services = ['wash-fold', 'wash-iron', 'dry-clean', 'household'];
    const areaIds = Object.keys(AREA_CATALOG);
    const service = services[Math.floor(Math.random() * services.length)];
    const spec = SERVICE_CATALOG[service];
    const qty = spec.min + Math.floor(Math.random() * Math.min(4, spec.max - spec.min + 1));
    const date = new Date(); date.setDate(date.getDate() + 1);
    const area = areaIds[Math.floor(Math.random() * areaIds.length)];
    const result = createOrder({
      service, qty, method: 'pickup', express: false, area,
      date: `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`,
      time: 2, name: names[Math.floor(Math.random() * names.length)],
      phone: '98' + String(Math.floor(10000000 + Math.random() * 89999999)),
      email: '', address: 'Sample address, ' + AREA_CATALOG[area].name,
      notes: '', plan: ''
    }, null, true);
    return json(res, 201, result);
  }

  if (method === 'DELETE' && pathname === '/api/admin/sample') {
    if (!requireAdmin(req, res)) return;
    const result = db.prepare('DELETE FROM orders WHERE example = 1').run();
    return json(res, 200, { deleted: result.changes });
  }

  if (method === 'GET' || method === 'HEAD') {
    const requested = pathname === '/' ? '/nac.html' : pathname;
    const name = requested.slice(1);
    if (!PUBLIC_FILES.has(name)) return fail(res, 404, 'Not found.');
    const filePath = path.join(ROOT, name);
    if (!fs.existsSync(filePath)) return fail(res, 404, 'Not found.');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'Cache-Control': 'no-cache'
    });
    if (method === 'HEAD') return res.end();
    return fs.createReadStream(filePath).pipe(res);
  }

  return fail(res, 404, 'Not found.');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error(error);
    if (res.headersSent) return res.destroy();
    fail(res, error.status || 500, error.status ? error.message : 'Unexpected server error.');
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Neat & Clean Laundry running at http://${HOST}:${PORT}`);
  console.log(`Homepage: http://${HOST}:${PORT}/nac.html`);
  console.log(`Admin: http://${HOST}:${PORT}/Tidal%20Admin.html`);
  if (adminSetupRequired()) console.log('Open the Admin page on this computer to create the first admin account.');
});

function close() {
  db.close();
  server.close(() => process.exit(0));
}
process.on('SIGINT', close);
process.on('SIGTERM', close);
