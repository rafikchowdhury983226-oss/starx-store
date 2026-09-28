'use strict';
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'starx.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  emoji TEXT NOT NULL DEFAULT '🎬',
  price REAL NOT NULL,
  duration TEXT NOT NULL,
  features TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_id INTEGER NOT NULL REFERENCES plans(id),
  txn_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  credentials TEXT,
  admin_note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const check = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch { return false; }
}
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function getSetting(key, fallback = '') {
  const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return r ? r.value : fallback;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value));
}

// Seed admin + default plans + settings on first run
const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const adminPass = process.env.ADMIN_PASSWORD || 'StarX@Admin2026';
  db.prepare('INSERT INTO users (name, email, pass_hash, role, status) VALUES (?,?,?,?,?)')
    .run('Admin', 'admin@starx.store', hashPassword(adminPass), 'admin', 'active');
  console.log('--- ADMIN ACCOUNT SEEDED ---');
  console.log('Email: admin@starx.store');
  console.log('Password: ' + adminPass);
  console.log('(Set ADMIN_PASSWORD env var to choose your own. CHANGE THIS PASSWORD AFTER FIRST LOGIN!)');
  const seed = db.prepare('INSERT INTO plans (name, emoji, price, duration, features) VALUES (?,?,?,?,?)');
  seed.run('Netflix Premium', '🎬', 199, '1 Month', JSON.stringify(['4K + HDR','4 Screens','All Movies & Series','Official Warranty']));
  seed.run('Prime Video', '📺', 99, '1 Month', JSON.stringify(['HD + 4K','2 Screens','All Content','Fast Replacement']));
  seed.run('Disney+ Hotstar', '🏏', 149, '3 Months', JSON.stringify(['4K Quality','2 Screens','IPL + Movies','Full Support']));
  seed.run('Spotify Premium', '🎧', 59, '1 Month', JSON.stringify(['Individual Plan','Offline Download','No Ads','Ad-free Music']));
  setSetting('upi_id', 'starx@upi');
  setSetting('whatsapp', '');
}

module.exports = { db, hashPassword, verifyPassword, sha256, getSetting, setSetting };
