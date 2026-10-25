// Aditya Chat - zero-dependency Node server (Node 16+)
// Run: node server.js   then open http://localhost:3000
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data.json');
const PUBLIC = __dirname; // files sit next to server.js
const ALLOWED = ['index.html', 'manifest.json', 'sw.js', 'background.png'];

let db = { users: {}, messages: [] }; // users: serial -> {serial,name,token}
if (fs.existsSync(DB_FILE)) {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
}
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db));

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp'
};

const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};
const body = (req) => new Promise((resolve) => {
  let d = '';
  req.on('data', (c) => { d += c; if (d.length > 1e5) req.destroy(); });
  req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
});
const auth = (req) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  return Object.values(db.users).find((u) => u.token === token);
};
const pub = (u) => ({ serial: u.serial, name: u.name });
const validSerial = (s) => /^\d{1,5}$/.test(s);

async function api(req, res, url) {
  const p = url.pathname;

  if (p === '/api/check' && req.method === 'GET') {
    const s = url.searchParams.get('serial') || '';
    if (!validSerial(s)) return send(res, 400, { error: 'Serial must be 1-5 digits' });
    return send(res, 200, { available: !db.users[s] });
  }

  if (p === '/api/register' && req.method === 'POST') {
    const { serial, name } = await body(req);
    if (!validSerial(String(serial))) return send(res, 400, { error: 'Serial must be 1-5 digits' });
    if (!name || !String(name).trim()) return send(res, 400, { error: 'Name required' });
    if (db.users[serial]) return send(res, 409, { error: 'This serial number is already reserved' });
    const token = crypto.randomBytes(24).toString('hex');
    db.users[serial] = { serial: String(serial), name: String(name).trim().slice(0, 30), token };
    save();
    return send(res, 200, { user: pub(db.users[serial]), token });
  }

  if (p === '/api/me' && req.method === 'GET') {
    const me = auth(req);
    return me ? send(res, 200, { user: pub(me) }) : send(res, 401, { error: 'Not logged in' });
  }

  const me = auth(req);
  if (!me) return send(res, 401, { error: 'Not logged in' });

  if (p === '/api/search' && req.method === 'GET') {
    const q = (url.searchParams.get('q') || '').replace(/\D/g, '');
    if (!q) return send(res, 200, { results: [] });
    const results = Object.values(db.users)
      .filter((u) => u.serial.startsWith(q) && u.serial !== me.serial)
      .slice(0, 20).map(pub);
    return send(res, 200, { results });
  }

  if (p.startsWith('/api/user/') && req.method === 'GET') {
    const u = db.users[p.split('/').pop()];
    return u ? send(res, 200, { user: pub(u) }) : send(res, 404, { error: 'No such user' });
  }

  if (p === '/api/messages' && req.method === 'GET') {
    const other = url.searchParams.get('with');
    const msgs = db.messages.filter((m) =>
      (m.from === me.serial && m.to === other) || (m.from === other && m.to === me.serial));
    return send(res, 200, { messages: msgs });
  }

  if (p === '/api/messages' && req.method === 'POST') {
    const { to, text } = await body(req);
    if (!db.users[to]) return send(res, 404, { error: 'No such user' });
    if (!text || !String(text).trim()) return send(res, 400, { error: 'Empty message' });
    const m = { from: me.serial, to, text: String(text).slice(0, 1000), time: Date.now() };
    db.messages.push(m); save();
    return send(res, 200, { message: m });
  }

  if (p === '/api/chats' && req.method === 'GET') {
    const seen = new Map();
    for (const m of db.messages) {
      if (m.from !== me.serial && m.to !== me.serial) continue;
      const other = m.from === me.serial ? m.to : m.from;
      seen.set(other, m);
    }
    const chats = [...seen.entries()]
      .map(([s, last]) => ({ user: pub(db.users[s]), last }))
      .sort((a, b) => b.last.time - a.last.time);
    return send(res, 200, { chats });
  }

  send(res, 404, { error: 'Not found' });
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) return api(req, res, url);
  let file = path.join(PUBLIC, url.pathname === '/' ? 'index.html' : url.pathname);
  if (path.dirname(file) !== PUBLIC || !ALLOWED.includes(path.basename(file))) { res.writeHead(404); return res.end('Not found'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, () => console.log('Aditya Chat running on http://localhost:' + PORT));
