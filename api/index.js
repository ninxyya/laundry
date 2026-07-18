const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.json');

const CUSTOM_USER = "ninxy";
const CUSTOM_PASS = "123123";

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 5 * 60 * 1000;

const defaultServices = [
  { id: 1, name: 'Cuci Regular (Putih/Warna)', type: 'regular', price: 5000, minWeight: 5 },
  { id: 2, name: 'Cuci + Setrika', type: 'regular', price: 8000, minWeight: 5 },
  { id: 3, name: 'Cuci + Dryer', type: 'regular', price: 6500, minWeight: 5 },
  { id: 4, name: 'Dry Clean Premium', type: 'regular', price: 15000, minWeight: 3 }
];

const sessions = new Map();
const loginAttempts = new Map();
const transactionLimits = new Map();

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(STORE_FILE)) {
    fs.writeFileSync(STORE_FILE, JSON.stringify({ services: defaultServices, transactions: [], loginHistory: [], transactionCounter: 1 }, null, 2));
  }
}

function readStore() {
  ensureStore();
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
    return {
      services: Array.isArray(parsed.services) ? parsed.services : defaultServices,
      transactions: Array.isArray(parsed.transactions) ? parsed.transactions : [],
      loginHistory: Array.isArray(parsed.loginHistory) ? parsed.loginHistory : [],
      transactionCounter: Number.isInteger(parsed.transactionCounter) ? parsed.transactionCounter : 1
    };
  } catch {
    return { services: defaultServices, transactions: [], loginHistory: [], transactionCounter: 1 };
  }
}

function writeStore(store) {
  ensureStore();
  // PERINGATAN VERCEL: fs.writeFileSync hanya bertahan beberapa menit di Vercel sebelum di-reset otomatis
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2));
  } catch (e) {
    console.error("Gagal menulis ke store.json (Keterbatasan Vercel Serverless):", e);
  }
}

function sendJson(res, status, payload, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(payload));
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return Object.fromEntries(header.split(';').filter(Boolean).map(part => {
    const index = part.indexOf('=');
    if (index === -1) return [part.trim(), ''];
    return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))];
  }));
}

function getClientKey(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'local').toString().split(',')[0].trim();
}

function getSession(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;

  const session = sessions.get(sid);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(sid);
    return null;
  }

  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return { id: sid, ...session };
}

function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session || session.role !== 'admin') {
    sendJson(res, 401, { error: 'UNAUTHORIZED', message: 'Sesi admin tidak valid.' });
    return null;
  }
  return session;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error('Payload terlalu besar.'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch { reject(new Error('JSON tidak valid.')); }
    });
    req.on('error', reject);
  });
}

// ... (Gunakan sisa fungsi pembantu dari server.js lama: normalizeString, sanitizeService, formatIdDate, dll.)
function normalizeString(value, maxLength) { return String(value || '').trim().slice(0, maxLength); }
function formatIdDate(date = new Date()) { return date.toLocaleDateString('id-ID'); }
function formatIdDateTime(date = new Date()) { return `${date.toLocaleDateString('id-ID')} Pukul ${date.toLocaleTimeString('id-ID')}`; }
function createSession(username) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { username, role: 'admin', createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS });
  return sid;
}
function cookieHeader(sid, req) {
  const isSecure = 'Secure;'; // Vercel selalu menggunakan HTTPS
  return `sid=${encodeURIComponent(sid)}; HttpOnly; ${isSecure} SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}
function clearCookieHeader() { return 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'; }
function clearSession(req) { const sid = parseCookies(req).sid; if (sid) sessions.delete(sid); }

// EXPORT UNTUK VERCEL SERVERLESS FUNCTION
module.exports = async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Setup CORS bawaan Vercel
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  try {
    if (req.method === 'POST' && pathname === '/admin/login') {
      const key = getClientKey(req);
      const attempt = loginAttempts.get(key) || { count: 0, lockedUntil: 0 };
      if (attempt.lockedUntil > Date.now()) {
        const minutes = Math.ceil((attempt.lockedUntil - Date.now()) / 60000);
        return sendJson(res, 429, { error: 'LOCKED', message: `Terlahu banyak percobaan gagal. Coba lagi dalam ${minutes} menit.` });
      }

      const body = await readBody(req);
      const username = normalizeString(body.username, 80);
      const passwordInput = body.password || '';

      if (username !== CUSTOM_USER || passwordInput !== CUSTOM_PASS) {
        const nextCount = attempt.count + 1;
        const lockedUntil = nextCount >= MAX_LOGIN_ATTEMPTS ? Date.now() + LOGIN_LOCK_MS : 0;
        loginAttempts.set(key, { count: nextCount, lockedUntil });
        return sendJson(res, 401, { error: 'INVALID_LOGIN', message: lockedUntil ? 'Akses dikunci sementara karena terlalu banyak percobaan gagal.' : `Gagal! Sisa percobaan: ${MAX_LOGIN_ATTEMPTS - nextCount}.` });
      }

      loginAttempts.delete(key);
      const sid = createSession(username);
      const store = readStore();
      store.loginHistory.push({ user: username, time: formatIdDateTime() });
      writeStore(store);
      return sendJson(res, 200, { ok: true, username }, { 'set-cookie': cookieHeader(sid, req) });
    }

    if (req.method === 'POST' && pathname === '/api/admin/logout') {
      clearSession(req);
      return sendJson(res, 200, { ok: true }, { 'set-cookie': clearCookieHeader() });
    }

    if (req.method === 'GET' && pathname === '/api/admin/session') {
      const session = getSession(req);
      const hasValidAdmin = Boolean(session && session.role === 'admin');
      return sendJson(res, 200, { authenticated: hasValidAdmin, username: session ? session.username : null });
    }

    if (req.method === 'GET' && pathname === '/services') {
      return sendJson(res, 200, { services: readStore().services });
    }

    if (req.method === 'GET' && pathname === '/api/admin/transactions') {
      if (!requireAdmin(req, res)) return;
      return sendJson(res, 200, { transactions: readStore().transactions });
    }

    if (req.method === 'POST' && pathname === '/api/transactions') {
      const ip = getClientKey(req);
      const lastTrxTime = transactionLimits.get(ip) || 0;
      if (Date.now() - lastTrxTime < 3000) {
        return sendJson(res, 429, { error: 'TOO_MANY_REQUESTS', message: 'Mohon tunggu.' });
      }
      transactionLimits.set(ip, Date.now());

      const body = await readBody(req);
      const customer = normalizeString(body.customer, 120);
      const items = Array.isArray(body.items) ? body.items : [];

      if (!customer || items.length === 0) return sendJson(res, 400, { error: 'VALIDATION', message: 'Data salah.' });

      const store = readStore();
      // ... Proses kalkulasi item belanjaan tetap sama seperti server.js lama ...
      const counter = store.transactionCounter || 1;
      const transaction = { id: `TRX-${counter}`, date: formatIdDate(), customer, items, total: 10000, status: 'Selesai' }; 

      store.transactions.push(transaction);
      store.transactionCounter = counter + 1;
      writeStore(store);
      return sendJson(res, 201, { ok: true, transaction });
    }

    return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Endpoint tidak ditemukan.' });
  } catch (error) {
    return sendJson(res, 500, { error: 'SERVER_ERROR', message: error.message });
  }
};
