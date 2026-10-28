#!/usr/bin/env node
/**
 * SATU-SATUNYA JALUR untuk membuat/mengganti password admin.
 *
 * api/index.js (yang live di internet) HANYA membaca KV untuk verifikasi
 * login — tidak pernah menulis credential, tidak ada endpoint HTTP yang
 * bisa dipakai buat reset password dari luar.
 *
 * Jalanin ini LOKAL di komputer kamu (bukan di Vercel):
 *   1. vercel env pull .env.local        (sekali, setelah KV di-connect ke project)
 *   2. node scripts/set-admin-password.js <username>
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Load .env.local manually (no dotenv dependency needed).
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (match && !process.env[match[1]]) {
      process.env[match[1]] = match[2].replace(/^"(.*)"$/, '$1');
    }
  }
}

if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
  console.error('KV_REST_API_URL / KV_REST_API_TOKEN tidak ketemu.');
  console.error('Jalankan dulu: vercel env pull .env.local');
  console.error('(pastikan KV storage sudah di-connect ke project di dashboard Vercel)');
  process.exit(1);
}

const { kv } = require('@vercel/kv');
const PBKDF2_ITERATIONS = 210000;

function deriveHash(password, salt) {
  return crypto.pbkdf2Sync(String(password), salt, PBKDF2_ITERATIONS, 32, 'sha256').toString('hex');
}

function createLineReader() {
  const lines = [];
  let pendingResolve = null;
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (line) => {
    if (pendingResolve) { const r = pendingResolve; pendingResolve = null; r(line); }
    else lines.push(line);
  });
  return {
    ask: (promptText) => {
      process.stdout.write(promptText + '\n');
      if (lines.length > 0) return Promise.resolve(lines.shift());
      return new Promise((resolve) => { pendingResolve = resolve; });
    },
    close: () => rl.close()
  };
}

async function main() {
  const username = (process.argv[2] || '').trim();
  if (!username) {
    console.error('Pemakaian: node scripts/set-admin-password.js <username>');
    process.exit(1);
  }

  const reader = createLineReader();
  const password = await reader.ask(`Password baru untuk "${username}": `);
  const confirm = await reader.ask('Ulangi password: ');
  reader.close();

  if (password.length < 8) { console.error('Password minimal 8 karakter.'); process.exit(1); }
  if (password !== confirm) { console.error('Password tidak sama. Dibatalkan.'); process.exit(1); }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = deriveHash(password, salt);

  await kv.set(`admin:credentials:${username}`, { username, salt, hash, updatedAt: new Date().toISOString() });

  console.log(`Password untuk "${username}" tersimpan di Vercel KV.`);
  console.log('Langsung aktif, tidak perlu redeploy.');
}

main().catch((error) => {
  console.error('ERROR:', error.message || error);
  process.exit(1);
});
