'use strict';
const crypto = require('node:crypto');
const { db, sha256 } = require('./db');

const SESSION_DAYS = 7;
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','yopmail.com','tempmail.com','10minutemail.com','guerrillamail.com',
  'sharklasers.com','trashmail.com','getnada.com','dispostable.com','fakeinbox.com',
  'throwawaymail.com','maildrop.cc','temp-mail.org','tempr.email','1secmail.com','mohmal.com'
]);

function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + SESSION_DAYS * 86400000;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)').run(sha256(token), userId, expires);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  res.setHeader('Set-Cookie', `starx_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}`);
}
function destroySession(req, res) {
  const cookies = parseCookies(req);
  const token = cookies.starx_session;
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  res.setHeader('Set-Cookie', 'starx_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}
function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie;
  if (!h) return out;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function getSessionUser(req) {
  const token = parseCookies(req).starx_session;
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.status, s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?`).get(sha256(token));
  if (!row || row.expires_at < Date.now()) return null;
  if (row.status !== 'active') return { blocked: true, name: row.name, status: row.status };
  return { id: row.id, name: row.name, email: row.email, role: row.role, status: row.status };
}

// Simple in-memory rate limiter per IP+action
const hits = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  return arr.length <= max;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) && !DISPOSABLE_DOMAINS.has(email.split('@')[1].toLowerCase());
}
function strongPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}

module.exports = { createSession, destroySession, getSessionUser, rateLimit, validEmail, strongPassword };
