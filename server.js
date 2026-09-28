'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { db, hashPassword, verifyPassword, getSetting, setSetting } = require('./db');
const { createSession, destroySession, getSessionUser, rateLimit, validEmail, strongPassword } = require('./auth');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const MIME = { '.html':'text/html; charset=utf-8', '.css':'text/css', '.js':'text/javascript', '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml', '.ico':'image/x-icon', '.json':'application/json' };

function json(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 100000) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}
const DENY = new Set(['server.js','package.json','db.js','auth.js','README.md','render.yaml','.gitignore']);
function serveStatic(res, file) {
  if (DENY.has(file)) { res.writeHead(404); return res.end('Not found'); }
  const full = path.join(PUBLIC_DIR, file);
  if (!full.startsWith(PUBLIC_DIR) || !fs.existsSync(full) || !fs.statSync(full).isFile()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(full).pipe(res);
}
const clean = s => String(s == null ? '' : s).trim().slice(0, 300);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();
  try {
    // ---------- AUTH API ----------
    if (p === '/api/signup' && req.method === 'POST') {
      if (!rateLimit('signup:' + ip, 5, 10 * 60000)) return json(res, 429, { error: 'Bahut zyada requests. Thodi der baad try karein.' });
      const b = await readBody(req);
      const name = clean(b.name), email = clean(b.email).toLowerCase(), pass = String(b.password || '');
      if (name.length < 2) return json(res, 400, { error: 'Naam kam se kam 2 letters ka hona chahiye.' });
      if (!validEmail(email)) return json(res, 400, { error: 'Valid email daalein (temporary/fake email allowed nahi hai).' });
      if (!strongPassword(pass)) return json(res, 400, { error: 'Password mein 8+ characters, ek letter aur ek number hone chahiye.' });
      if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return json(res, 409, { error: 'Yeh email pehle se registered hai.' });
      // Only the first ever account is admin; everyone else is a normal user pending approval
      const isFirst = db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0;
      db.prepare('INSERT INTO users (name, email, pass_hash, role, status) VALUES (?,?,?,?,?)')
        .run(name, email, hashPassword(pass), isFirst ? 'admin' : 'user', isFirst ? 'active' : 'pending');
      return json(res, 201, { ok: true, message: isFirst ? 'Admin account ban gaya!' : 'Account ban gaya! Admin approval ke baad login hoga. Status: PENDING' });
    }

    if (p === '/api/login' && req.method === 'POST') {
      if (!rateLimit('login:' + ip, 8, 10 * 60000)) return json(res, 429, { error: 'Bahut zyada login attempts. 10 minute baad try karein.' });
      const b = await readBody(req);
      const email = clean(b.email).toLowerCase(), pass = String(b.password || '');
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (!user || !verifyPassword(pass, user.pass_hash)) return json(res, 401, { error: 'Email ya password galat hai.' });
      if (user.status === 'pending') return json(res, 403, { error: 'Aapka account abhi admin approval ka wait kar raha hai.' });
      if (user.status === 'blocked') return json(res, 403, { error: 'Aapka account block kiya gaya hai. Support se contact karein.' });
      createSession(res, user.id);
      return json(res, 200, { ok: true, role: user.role, name: user.name });
    }

    if (p === '/api/logout' && req.method === 'POST') { destroySession(req, res); return json(res, 200, { ok: true }); }

    if (p === '/api/me' && req.method === 'GET') {
      const u = getSessionUser(req);
      if (!u) return json(res, 200, { user: null });
      return json(res, 200, { user: u });
    }

    // ---------- PUBLIC PLANS ----------
    if (p === '/api/plans' && req.method === 'GET') {
      const plans = db.prepare('SELECT id, name, emoji, price, duration, features FROM plans WHERE active = 1 ORDER BY price').all()
        .map(pl => ({ ...pl, features: JSON.parse(pl.features) }));
      return json(res, 200, { plans, upi_id: getSetting('upi_id'), whatsapp: getSetting('whatsapp') });
    }

    // ---------- USER ORDERS ----------
    if (p === '/api/orders' && req.method === 'POST') {
      const u = getSessionUser(req);
      if (!u || u.blocked) return json(res, 401, { error: 'Pehle login karein.' });
      const b = await readBody(req);
      const plan = db.prepare('SELECT * FROM plans WHERE id = ? AND active = 1').get(Number(b.plan_id));
      if (!plan) return json(res, 400, { error: 'Plan valid nahi hai.' });
      const txn = clean(b.txn_id);
      if (txn.length < 4) return json(res, 400, { error: 'Payment ka UTR/Transaction ID daalein (min 4 characters).' });
      if (db.prepare('SELECT id FROM orders WHERE user_id = ? AND plan_id = ? AND status IN (?,?)').get(u.id, plan.id, 'pending', 'paid'))
        return json(res, 409, { error: 'Is plan ke liye order pehle se pending/paid hai.' });
      const r = db.prepare('INSERT INTO orders (user_id, plan_id, txn_id) VALUES (?,?,?)').run(u.id, plan.id, txn);
      return json(res, 201, { ok: true, order_id: r.lastInsertRowid, message: 'Order placed! Admin payment verify karega, phir credentials milenge.' });
    }
    if (p === '/api/my-orders' && req.method === 'GET') {
      const u = getSessionUser(req);
      if (!u || u.blocked) return json(res, 401, { error: 'Login required.' });
      const orders = db.prepare(`SELECT o.id, o.txn_id, o.status, o.credentials, o.admin_note, o.created_at,
        pl.name AS plan_name, pl.price, pl.duration FROM orders o JOIN plans pl ON pl.id = o.plan_id
        WHERE o.user_id = ? ORDER BY o.id DESC`).all(u.id);
      return json(res, 200, { orders, upi_id: getSetting('upi_id'), whatsapp: getSetting('whatsapp') });
    }

    // ---------- ADMIN API ----------
    if (p.startsWith('/api/admin/')) {
      const u = getSessionUser(req);
      if (!u || u.blocked) return json(res, 401, { error: 'Login required.' });
      if (u.role !== 'admin') return json(res, 403, { error: 'Sirf admin access kar sakta hai.' });

      if (p === '/api/admin/stats' && req.method === 'GET') {
        const s = db.prepare(`SELECT
          (SELECT COUNT(*) FROM users WHERE role='user') AS total_users,
          (SELECT COUNT(*) FROM users WHERE status='pending') AS pending_users,
          (SELECT COUNT(*) FROM orders) AS total_orders,
          (SELECT COUNT(*) FROM orders WHERE status='pending') AS pending_orders,
          (SELECT COALESCE(SUM(price),0) FROM orders o JOIN plans pl ON pl.id=o.plan_id WHERE o.status='paid') AS revenue`).get();
        return json(res, 200, { stats: s });
      }
      if (p === '/api/admin/orders' && req.method === 'GET') {
        const rows = db.prepare(`SELECT o.id, o.txn_id, o.status, o.credentials, o.admin_note, o.created_at,
          u.name AS user_name, u.email AS user_email, pl.name AS plan_name, pl.price, pl.duration
          FROM orders o JOIN users u ON u.id=o.user_id JOIN plans pl ON pl.id=o.plan_id ORDER BY o.id DESC`).all();
        return json(res, 200, { orders: rows });
      }
      if (p === '/api/admin/order' && req.method === 'POST') {
        const b = await readBody(req);
        const id = Number(b.id), status = clean(b.status);
        if (!['pending','paid','delivered','rejected'].includes(status)) return json(res, 400, { error: 'Invalid status.' });
        db.prepare('UPDATE orders SET status = ?, credentials = ?, admin_note = ? WHERE id = ?')
          .run(status, clean(b.credentials), clean(b.admin_note), id);
        return json(res, 200, { ok: true });
      }
      if (p === '/api/admin/users' && req.method === 'GET') {
        const rows = db.prepare(`SELECT u.id, u.name, u.email, u.role, u.status, u.created_at,
          (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id) AS order_count FROM users u ORDER BY u.id DESC`).all();
        return json(res, 200, { users: rows });
      }
      if (p === '/api/admin/user-status' && req.method === 'POST') {
        const b = await readBody(req);
        const id = Number(b.id), status = clean(b.status);
        if (!['pending','active','blocked'].includes(status)) return json(res, 400, { error: 'Invalid status.' });
        const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
        if (!target) return json(res, 404, { error: 'User not found.' });
        if (target.role === 'admin') return json(res, 400, { error: 'Admin account change nahi kar sakte.' });
        db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, id);
        if (status !== 'active') db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id); // force logout
        return json(res, 200, { ok: true });
      }
      if (p === '/api/admin/plans' && req.method === 'GET') {
        const plans = db.prepare('SELECT * FROM plans ORDER BY id').all().map(pl => ({ ...pl, features: JSON.parse(pl.features) }));
        return json(res, 200, { plans });
      }
      if (p === '/api/admin/plan' && req.method === 'POST') {
        const b = await readBody(req);
        const id = Number(b.id || 0);
        const name = clean(b.name), emoji = clean(b.emoji) || '🎬', price = Number(b.price), duration = clean(b.duration);
        const features = Array.isArray(b.features) ? b.features.map(clean).filter(Boolean).slice(0, 10) : [];
        if (name.length < 2 || !(price >= 0) || duration.length < 2) return json(res, 400, { error: 'Plan details valid nahi hain.' });
        if (id) db.prepare('UPDATE plans SET name=?, emoji=?, price=?, duration=?, features=?, active=? WHERE id=?')
          .run(name, emoji, price, duration, JSON.stringify(features), b.active === false ? 0 : 1, id);
        else db.prepare('INSERT INTO plans (name, emoji, price, duration, features) VALUES (?,?,?,?,?)')
          .run(name, emoji, price, duration, JSON.stringify(features));
        return json(res, 200, { ok: true });
      }
      if (p === '/api/admin/plan-delete' && req.method === 'POST') {
        const b = await readBody(req);
        db.prepare('UPDATE plans SET active = 0 WHERE id = ?').run(Number(b.id));
        return json(res, 200, { ok: true });
      }
      if (p === '/api/admin/settings' && req.method === 'GET') {
        return json(res, 200, { settings: { upi_id: getSetting('upi_id'), whatsapp: getSetting('whatsapp') } });
      }
      if (p === '/api/admin/settings' && req.method === 'POST') {
        const b = await readBody(req);
        setSetting('upi_id', clean(b.upi_id)); setSetting('whatsapp', clean(b.whatsapp));
        return json(res, 200, { ok: true });
      }
      return json(res, 404, { error: 'Not found' });
    }

    // ---------- STATIC PAGES ----------
    if (req.method === 'GET') {
      const routes = { '/': 'index.html', '/index.html': 'index.html', '/login': 'login.html', '/signup': 'signup.html', '/account': 'account.html', '/admin': 'admin.html' };
      let f = p.replace(/^\/+/, '');
      if (f.startsWith('css/')) f = f.slice(4);
      if (f.startsWith('js/')) f = f.slice(3);
      return serveStatic(res, routes[p] || f);
    }
    res.writeHead(404); res.end('Not found');
  } catch (e) {
    json(res, 400, { error: 'Kuch galat ho gaya. Dobara try karein.' });
  }
});
server.listen(PORT, () => console.log(`StarX Store running → http://localhost:${PORT}`));
