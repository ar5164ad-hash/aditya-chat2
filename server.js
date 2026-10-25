// Aditya Chat v2 - zero-dependency Node server (Node 16+)
// Features: serial-number accounts, end-to-end encrypted chats & groups (server only stores ciphertext),
// 24h statuses, directory of all registered users.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data.json');
const PUBLIC = __dirname; // files sit next to server.js
const ALLOWED = ['index.html', 'manifest.json', 'sw.js', 'background.png'];
const DAY = 24 * 60 * 60 * 1000;
const ONLINE_MS = 60 * 1000;

let db = { users: {}, messages: [], statuses: [], groups: [], gmessages: [] };
if (fs.existsSync(DB_FILE)) {
  try { Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) {}
}
// Drop legacy (unencrypted / keyless) data from older versions
for (const s of Object.keys(db.users)) if (!db.users[s].pub) delete db.users[s];
db.messages = db.messages.filter((m) => m.ct && db.users[m.from] && db.users[m.to]);
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db));

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp'
};

const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
};
const body = (req, limit = 1e5) => new Promise((resolve) => {
  let d = '', done = false;
  req.on('data', (c) => {
    d += c;
    if (d.length > limit && !done) { done = true; resolve({}); req.destroy(); }
  });
  req.on('end', () => { if (done) return; try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
});
const auth = (req) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return null;
  const u = Object.values(db.users).find((x) => x.token === token);
  if (u) u.lastSeen = Date.now();
  return u;
};
const online = (u) => Date.now() - (u.lastSeen || 0) < ONLINE_MS;
const pub = (u) => ({ serial: u.serial, name: u.name, online: online(u) });
const full = (u) => ({ ...pub(u), pub: u.pub });
const validSerial = (s) => /^\d{1,5}$/.test(s);
const validPub = (p) => p && p.kty === 'EC' && p.crv === 'P-256' &&
  typeof p.x === 'string' && typeof p.y === 'string' && p.x.length < 100 && p.y.length < 100
  ? { kty: 'EC', crv: 'P-256', x: p.x, y: p.y } : null;
const B64 = /^[A-Za-z0-9+/=]+$/;
const validBlob = (iv, ct, maxCt = 12000) =>
  typeof iv === 'string' && typeof ct === 'string' && iv.length > 0 && iv.length <= 40 &&
  ct.length > 0 && ct.length <= maxCt && B64.test(iv) && B64.test(ct);
const newId = () => crypto.randomBytes(6).toString('hex');

function pruneStatuses() {
  const now = Date.now(), before = db.statuses.length;
  db.statuses = db.statuses.filter((s) => now - s.time < DAY && db.users[s.serial]);
  if (db.statuses.length !== before) save();
}
const visibleG = (g, me) => (m) => m.gid === g.id && m.time >= ((g.joined || {})[me] || 0);

async function api(req, res, url) {
  const p = url.pathname, M = req.method;

  if (p === '/api/check' && M === 'GET') {
    const s = url.searchParams.get('serial') || '';
    if (!validSerial(s)) return send(res, 400, { error: 'Serial must be 1-5 digits' });
    return send(res, 200, { available: !db.users[s] });
  }

  if (p === '/api/register' && M === 'POST') {
    const { serial, name, pub: pk } = await body(req);
    if (!validSerial(String(serial))) return send(res, 400, { error: 'Serial must be 1-5 digits' });
    if (!name || !String(name).trim()) return send(res, 400, { error: 'Name required' });
    const key = validPub(pk);
    if (!key) return send(res, 400, { error: 'Missing encryption key' });
    if (db.users[serial]) return send(res, 409, { error: 'This serial number is already reserved' });
    const token = crypto.randomBytes(24).toString('hex');
    db.users[serial] = { serial: String(serial), name: String(name).trim().slice(0, 30), token, pub: key, lastSeen: Date.now(), created: Date.now() };
    save();
    return send(res, 200, { user: pub(db.users[serial]), token });
  }

  const me = auth(req);
  if (p === '/api/me' && M === 'GET') {
    return me ? send(res, 200, { user: pub(me) }) : send(res, 401, { error: 'Not logged in' });
  }
  if (!me) return send(res, 401, { error: 'Not logged in' });

  // ---- directory ----
  if (p === '/api/users' && M === 'GET') {
    const users = Object.values(db.users).filter((u) => u.serial !== me.serial)
      .sort((a, b) => (online(b) - online(a)) || (b.created || 0) - (a.created || 0)).map(pub);
    return send(res, 200, { users, total: Object.keys(db.users).length });
  }
  if (p === '/api/search' && M === 'GET') {
    const q = (url.searchParams.get('q') || '').replace(/\D/g, '');
    if (!q) return send(res, 200, { results: [] });
    const results = Object.values(db.users)
      .filter((u) => u.serial.startsWith(q) && u.serial !== me.serial).slice(0, 20).map(pub);
    return send(res, 200, { results });
  }
  if (p.startsWith('/api/user/') && M === 'GET') {
    const u = db.users[p.split('/').pop()];
    return u ? send(res, 200, { user: full(u) }) : send(res, 404, { error: 'No such user' });
  }

  // ---- 1:1 encrypted messages (server stores ciphertext only) ----
  if (p === '/api/messages' && M === 'GET') {
    const other = url.searchParams.get('with');
    const msgs = db.messages.filter((m) =>
      (m.from === me.serial && m.to === other) || (m.from === other && m.to === me.serial));
    return send(res, 200, { messages: msgs });
  }
  if (p === '/api/messages' && M === 'POST') {
    const { to, iv, ct } = await body(req);
    if (!db.users[to]) return send(res, 404, { error: 'No such user' });
    if (!validBlob(iv, ct)) return send(res, 400, { error: 'Invalid message' });
    const m = { from: me.serial, to, iv, ct, time: Date.now() };
    db.messages.push(m); save();
    return send(res, 200, { message: m });
  }
  if (p === '/api/chats' && M === 'GET') {
    const seen = new Map();
    for (const m of db.messages) {
      if (m.from !== me.serial && m.to !== me.serial) continue;
      seen.set(m.from === me.serial ? m.to : m.from, m);
    }
    const chats = [...seen.entries()].filter(([s]) => db.users[s])
      .map(([s, last]) => ({ user: full(db.users[s]), last }))
      .sort((a, b) => b.last.time - a.last.time);
    return send(res, 200, { chats });
  }

  // ---- status (24h) ----
  if (p === '/api/status' && M === 'GET') {
    pruneStatuses();
    const by = new Map();
    for (const s of db.statuses) {
      if (!by.has(s.serial)) by.set(s.serial, []);
      by.get(s.serial).push({ id: s.id, text: s.text, bg: s.bg, image: s.image, time: s.time });
    }
    const statuses = [...by.entries()].map(([serial, items]) => ({ user: pub(db.users[serial]), items }))
      .sort((a, b) => Math.max(...b.items.map((i) => i.time)) - Math.max(...a.items.map((i) => i.time)));
    return send(res, 200, { statuses });
  }
  if (p === '/api/status' && M === 'POST') {
    const { text, bg, image } = await body(req, 600000);
    const t = String(text || '').trim().slice(0, 300);
    let img = null;
    if (image) {
      const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(image));
      if (!m || image.length > 450000) return send(res, 400, { error: 'Invalid or too large image' });
      img = image;
    }
    if (!t && !img) return send(res, 400, { error: 'Write something or add a photo' });
    if (db.statuses.filter((s) => s.serial === me.serial).length >= 20) return send(res, 400, { error: 'Max 20 active statuses' });
    const st = { id: newId(), serial: me.serial, text: t, bg: /^#[0-9a-f]{6}$/i.test(bg || '') ? bg : '#075e54', image: img, time: Date.now() };
    db.statuses.push(st); save();
    return send(res, 200, { ok: true, id: st.id });
  }
  if (p === '/api/status/delete' && M === 'POST') {
    const { id } = await body(req);
    const before = db.statuses.length;
    db.statuses = db.statuses.filter((s) => !(s.id === id && s.serial === me.serial));
    if (db.statuses.length !== before) save();
    return send(res, 200, { ok: true });
  }

  // ---- groups ----
  if (p === '/api/groups' && M === 'POST') {
    const { name, members, keys } = await body(req, 300000);
    const nm = String(name || '').trim().slice(0, 40);
    if (!nm) return send(res, 400, { error: 'Group name required' });
    if (!Array.isArray(members)) return send(res, 400, { error: 'Pick members' });
    const list = [...new Set([me.serial, ...members.map(String)])].filter((s) => db.users[s]);
    if (list.length < 2) return send(res, 400, { error: 'Pick at least one member' });
    if (list.length > 256) return send(res, 400, { error: 'Max 256 members' });
    for (const s of list) {
      const k = keys && keys[s];
      if (!k || k.by !== me.serial || !validBlob(k.iv, k.ct, 400)) return send(res, 400, { error: 'Missing group key for ' + s });
    }
    const now = Date.now(), joined = {}, kk = {};
    for (const s of list) { joined[s] = now; kk[s] = { by: keys[s].by, iv: keys[s].iv, ct: keys[s].ct }; }
    const g = { id: newId(), name: nm, owner: me.serial, members: list, keys: kk, joined, created: now };
    db.groups.push(g); save();
    return send(res, 200, { id: g.id });
  }
  if (p === '/api/groups' && M === 'GET') {
    const groups = db.groups.filter((g) => g.members.includes(me.serial)).map((g) => {
      const msgs = db.gmessages.filter(visibleG(g, me.serial));
      const last = msgs.length ? msgs[msgs.length - 1] : null;
      return { id: g.id, name: g.name, count: g.members.length, myKey: g.keys[me.serial], created: g.created,
        last: last ? { from: last.from, iv: last.iv, ct: last.ct, time: last.time } : null };
    }).sort((a, b) => ((b.last && b.last.time) || b.created) - ((a.last && a.last.time) || a.created));
    return send(res, 200, { groups });
  }
  const gm = p.match(/^\/api\/groups\/([0-9a-f]{12})(?:\/(messages|add|leave))?$/);
  if (gm) {
    const g = db.groups.find((x) => x.id === gm[1]);
    if (!g || !g.members.includes(me.serial)) return send(res, 404, { error: 'No such group' });
    const sub = gm[2];

    if (!sub && M === 'GET') {
      return send(res, 200, { id: g.id, name: g.name, owner: g.owner, myKey: g.keys[me.serial],
        members: g.members.filter((s) => db.users[s]).map((s) => pub(db.users[s])) });
    }
    if (sub === 'messages' && M === 'GET') {
      const messages = db.gmessages.filter(visibleG(g, me.serial)).map((m) => ({
        from: m.from, name: db.users[m.from] ? db.users[m.from].name : '?', iv: m.iv, ct: m.ct, time: m.time }));
      return send(res, 200, { messages });
    }
    if (sub === 'messages' && M === 'POST') {
      const { iv, ct } = await body(req);
      if (!validBlob(iv, ct)) return send(res, 400, { error: 'Invalid message' });
      db.gmessages.push({ gid: g.id, from: me.serial, iv, ct, time: Date.now() }); save();
      return send(res, 200, { ok: true });
    }
    if (sub === 'add' && M === 'POST') {
      const { serial, key } = await body(req);
      if (!db.users[serial]) return send(res, 404, { error: 'No such user' });
      if (g.members.includes(serial)) return send(res, 400, { error: 'Already in group' });
      if (g.members.length >= 256) return send(res, 400, { error: 'Group is full' });
      if (!key || key.by !== me.serial || !validBlob(key.iv, key.ct, 400)) return send(res, 400, { error: 'Missing group key' });
      g.members.push(String(serial));
      g.keys[serial] = { by: key.by, iv: key.iv, ct: key.ct };
      g.joined = g.joined || {}; g.joined[serial] = Date.now();
      save();
      return send(res, 200, { ok: true });
    }
    if (sub === 'leave' && M === 'POST') {
      g.members = g.members.filter((s) => s !== me.serial);
      delete g.keys[me.serial];
      if (!g.members.length) {
        db.groups = db.groups.filter((x) => x.id !== g.id);
        db.gmessages = db.gmessages.filter((m) => m.gid !== g.id);
      } else if (g.owner === me.serial) g.owner = g.members[0];
      save();
      return send(res, 200, { ok: true });
    }
  }

  send(res, 404, { error: 'Not found' });
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    try { return await api(req, res, url); } catch (e) { console.error(e); return send(res, 500, { error: 'Server error' }); }
  }
  const file = path.join(PUBLIC, url.pathname === '/' ? 'index.html' : url.pathname);
  if (path.dirname(file) !== PUBLIC || !ALLOWED.includes(path.basename(file))) { res.writeHead(404); return res.end('Not found'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(file);
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' || ext === '.js' ? 'no-cache' : 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(data);
  });
}).listen(PORT, () => console.log('Aditya Chat running on http://localhost:' + PORT));
