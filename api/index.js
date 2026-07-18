const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.json');

// =========================================================================
// PENGATURAN KREDENSIAL LOGIN ADMIN
// =========================================================================
const CUSTOM_USER = "hilal";
const CUSTOM_PASS = "kasir123";
// =========================================================================

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 5 * 60 * 1000;

const defaultServices = [
  { id: 1, name: 'Cuci Regular (Putih/Warna)', type: 'regular', price: 5000, minWeight: 5 },
  { id: 2, name: 'Cuci + Setrika', type: 'regular', price: 8000, minWeight: 5 },
  { id: 3, name: 'Cuci + Dryer', type: 'regular', price: 6500, minWeight: 5 },
  { id: 4, name: 'Dry Clean Premium', type: 'regular', price: 15000, minWeight: 3 }
];

// Memory caching untuk serverless function scope
const sessions = new Map();
const loginAttempts = new Map();
const transactionLimits = new Map();

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(STORE_FILE)) {
    try {
      fs.writeFileSync(STORE_FILE, JSON.stringify({ services: defaultServices, transactions: [], loginHistory: [], transactionCounter: 1 }, null, 2));
    } catch (e) {
      console.error("Gagal inisialisasi store.json:", e);
    }
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
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2));
  } catch (e) {
    console.error("Gagal menulis data ke store.json (Keterbatasan Serverless Vercel):", e);
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
    sendJson(res, 401, { error: 'UNAUTHORIZED', message: 'Sesi admin tidak valid atau kedaluwarsa.' });
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

function normalizeString(value, maxLength) {
  return String(value || '').trim().slice(0, maxLength);
}

function sanitizeService(input, currentId = null) {
  const name = normalizeString(input.name, 120);
  const type = normalizeString(input.type, 20);
  const price = type === 'kustom' ? 0 : Number(input.price);
  const minWeight = type === 'regular' ? Number(input.minWeight) : 0;

  if (!name) throw new Error('Nama pelayanan wajib diisi.');
  if (!['regular', 'peritem', 'kustom'].includes(type)) throw new Error('Tipe layanan tidak valid.');
  if (type !== 'kustom' && (!Number.isFinite(price) || price <= 0)) throw new Error('Harga harus lebih dari 0.');
  if (type === 'regular' && (!Number.isFinite(minWeight) || minWeight <= 0)) throw new Error('Minimal order harus lebih dari 0.');

  return { id: currentId, name, type, price: Math.round(price), minWeight };
}

function formatIdDate(date = new Date()) {
  return date.toLocaleDateString('id-ID');
}

function formatIdDateTime(date = new Date()) {
  return `${date.toLocaleDateString('id-ID')} Pukul ${date.toLocaleTimeString('id-ID')}`;
}

function createSession(username) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { username, role: 'admin', createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS });
  return sid;
}

function clearSession(req) {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sid);
}

function cookieHeader(sid, req) {
  return `sid=${encodeURIComponent(sid)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

function clearCookieHeader() {
  return 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
}

// MAIN VERCEL SERVERLESS EXPORT HANDLER
module.exports = async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  
  // SOLUSI: Normalisasi pathname dengan menghapus prefix '/api' agar routing Vercel akurat
  let cleanPath = parsedUrl.pathname.replace(/^\/api/, '');
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  // Pengaturan CORS untuk komunikasi antar domain / port
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Cookie');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  try {
    // 1. ROUTE: LOGIN ADMIN
    if (req.method === 'POST' && cleanPath === '/admin/login') {
      const key = getClientKey(req);
      const attempt = loginAttempts.get(key) || { count: 0, lockedUntil: 0 };
      if (attempt.lockedUntil > Date.now()) {
        const minutes = Math.ceil((attempt.lockedUntil - Date.now()) / 60000);
        return sendJson(res, 429, { error: 'LOCKED', message: `Terlalu banyak percobaan gagal. Coba lagi dalam ${minutes} menit.` });
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
      if (store.loginHistory.length > 50) store.loginHistory = store.loginHistory.slice(-50);
      writeStore(store);
      return sendJson(res, 200, { ok: true, username }, { 'set-cookie': cookieHeader(sid, req) });
    }

    // 2. ROUTE: LOGOUT ADMIN
    if (req.method === 'POST' && cleanPath === '/admin/logout') {
      clearSession(req);
      return sendJson(res, 200, { ok: true }, { 'set-cookie': clearCookieHeader() });
    }

    // 3. ROUTE: CEK SESI ADMIN
    if (req.method === 'GET' && cleanPath === '/admin/session') {
      const session = getSession(req);
      const hasValidAdmin = Boolean(session && session.role === 'admin');
      const resolvedUsername = (session && session.username) ? session.username : null;
      return sendJson(res, 200, { authenticated: hasValidAdmin, username: resolvedUsername });
    }

    // 4. ROUTE: AMBIL DATA LAYANAN (PUBLIC KASIR)
    if (req.method === 'GET' && cleanPath === '/services') {
      const store = readStore();
      return sendJson(res, 200, { services: store.services });
    }

    // 5. ROUTE: MANAJEMEN LAYANAN LAUNDRY (ADMIN ONLY)
    if (cleanPath === '/admin/services') {
      if (!requireAdmin(req, res)) return;
      const store = readStore();

      if (req.method === 'GET') return sendJson(res, 200, { services: store.services });

      if (req.method === 'POST') {
        const service = sanitizeService(await readBody(req));
        const nextId = store.services.length ? Math.max(...store.services.map(item => item.id || 0)) + 1 : 1;
        store.services.push({ ...service, id: nextId });
        writeStore(store);
        return sendJson(res, 201, { ok: true, service: { ...service, id: nextId } });
      }
    }

    // 6. ROUTE: DETAIL/EDIT/HAPUS LAYANAN LAUNDRY BY ID (ADMIN ONLY)
    const serviceMatch = cleanPath.match(/^\/admin\/services\/(\d+)$/);
    if (serviceMatch) {
      if (!requireAdmin(req, res)) return;
      const id = Number(serviceMatch[1]);
      const store = readStore();
      const index = store.services.findIndex(item => item.id === id);
      if (index === -1) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Layanan tidak ditemukan.' });

      if (req.method === 'PUT') {
        store.services[index] = sanitizeService(await readBody(req), id);
        writeStore(store);
        return sendJson(res, 200, { ok: true, service: store.services[index] });
      }

      if (req.method === 'DELETE') {
        store.services.splice(index, 1);
        writeStore(store);
        return sendJson(res, 200, { ok: true });
      }
    }

    // 7. ROUTE: DATA TRANSAKSI MASUK (ADMIN ONLY)
    if (req.method === 'GET' && cleanPath === '/admin/transactions') {
      if (!requireAdmin(req, res)) return;
      const store = readStore();
      return sendJson(res, 200, { transactions: store.transactions });
    }

    // 8. ROUTE: RIWAYAT LOGIN (ADMIN ONLY)
    if (req.method === 'GET' && cleanPath === '/admin/login-history') {
      if (!requireAdmin(req, res)) return;
      const store = readStore();
      return sendJson(res, 200, { loginHistory: store.loginHistory });
    }

    // 9. ROUTE: POST TRANSAKSI BARU DARI KASIR
    if (req.method === 'POST' && cleanPath === '/transactions') {
      const ip = getClientKey(req);
      const lastTrxTime = transactionLimits.get(ip) || 0;
      if (Date.now() - lastTrxTime < 3000) {
        return sendJson(res, 429, { error: 'TOO_MANY_REQUESTS', message: 'Mohon tunggu beberapa detik sebelum membuat transaksi baru.' });
      }
      transactionLimits.set(ip, Date.now());

      const body = await readBody(req);
      const customer = normalizeString(body.customer, 120);
      const phone = normalizeString(body.phone || '-', 40) || '-';
      const items = Array.isArray(body.items) ? body.items : [];
      const completionDate = normalizeString(body.completionDate, 120);

      if (!customer) return sendJson(res, 400, { error: 'VALIDATION', message: 'Nama pelanggan wajib diisi.' });
      if (items.length === 0) return sendJson(res, 400, { error: 'VALIDATION', message: 'Keranjang kosong.' });

      const store = readStore();
      const servicesById = new Map(store.services.map(service => [service.id, service]));
      const safeItems = [];
      let total = 0;

      for (const rawItem of items) {
        const serviceId = Number(rawItem.serviceId);
        const service = servicesById.get(serviceId);
        if (!service) return sendJson(res, 400, { error: 'VALIDATION', message: 'Layanan tidak valid.' });

        const quantity = Number(rawItem.quantity);
        const duration = Number(rawItem.duration);
        const reason = normalizeString(rawItem.reason, 160);
        
        const customPrice = service.type === 'kustom' ? Math.floor(Number(rawItem.price)) : service.price;
        const unit = service.type === 'regular' ? Math.max(quantity, service.minWeight || 0) : quantity;

        if (!Number.isFinite(quantity) || quantity <= 0) return sendJson(res, 400, { error: 'VALIDATION', message: 'Qty/berat tidak valid.' });
        if (!Number.isFinite(duration) || duration <= 0 || duration > 30) return sendJson(res, 400, { error: 'VALIDATION', message: 'Durasi tidak valid.' });
        
        if (!Number.isFinite(customPrice) || customPrice < 100) {
          return sendJson(res, 400, { error: 'VALIDATION', message: 'Harga layanan kustom tidak valid (Minimal Rp100).' });
        }

        const subtotal = Math.round(unit * customPrice);
        total += subtotal;
        safeItems.push({ serviceId, name: service.name, type: service.type, quantity, billedQuantity: unit, price: Math.round(customPrice), reason, duration, subtotal });
      }

      const counter = store.transactionCounter || 1;
      const trxId = `TRX-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(counter).padStart(4, '0')}`;
      const transaction = {
        id: trxId,
        date: formatIdDate(),
        dateTime: new Date().toLocaleString('id-ID'),
        customer,
        phone,
        items: safeItems,
        total,
        completionDate,
        status: 'Selesai'
      };

      store.transactions.push(transaction);
      store.transactionCounter = counter + 1;
      writeStore(store);
      return sendJson(res, 201, { ok: true, transaction });
    }

    // DEBUG KELUARAN JIKA BELUM ADA PATH YANG COCOK
    return sendJson(res, 404, { error: 'NOT_FOUND', message: `Endpoint '${cleanPath}' tidak terdeteksi di serverless function.` });
    
  } catch (error) {
    return sendJson(res, 500, { error: 'SERVER_ERROR', message: error.message || 'Terjadi kesalahan internal backend.' });
  }
};
