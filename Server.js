const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PASS = process.env.OWNER_PASSWORD || 'admin123';   // Replit Secrets me OWNER_PASSWORD set karo
const TOKEN = crypto.createHash('sha256').update('gym:' + PASS).digest('hex');
const FILE = path.join(__dirname, 'data.json');
let db = {}; try { db = JSON.parse(fs.readFileSync(FILE)); } catch (e) {}
const save = () => fs.writeFileSync(FILE, JSON.stringify(db));
const keyOf = s => [...s].map(c => c.charCodeAt(0).toString(36)).join('-');
const send = (res, c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };

http.createServer((req, res) => {
  const u = req.url.split('?')[0];
  if (!u.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
  }
  let body = ''; req.on('data', c => body += c);
  req.on('end', () => {
    let b = {}; try { b = body ? JSON.parse(body) : {}; } catch (e) {}
    const owner = req.headers['x-token'] === TOKEN, m = req.method;
    if (u === '/api/login' && m === 'POST')
      return b.password === PASS ? send(res, 200, { token: TOKEN }) : send(res, 401, { error: 'Wrong password' });
    const [, , kind, col, id] = u.split('/');
    if (kind === 'col' && m === 'GET') {
      if (!owner) return send(res, 401, { error: 'Owner only' });
      return send(res, 200, { docs: Object.entries(db[col] || {}).map(([id, data]) => ({ id, data })) });
    }
    if (kind === 'doc' && col && id) {
      if (m === 'GET') {
        if (!owner && !['settings', 'roster'].includes(col)) return send(res, 401, { error: 'Owner only' });
        return send(res, 200, { data: (db[col] || {})[id] ?? null });
      }
      if (m === 'PUT' && !owner && col === 'attendance') {
        if (!b.fn || !(db.roster || {})[keyOf(b.fn)]) return send(res, 403, { error: 'Not a member' });
      } else if (!owner) return send(res, 401, { error: 'Owner only' });
      db[col] = db[col] || {};
      if (m === 'PUT') db[col][id] = b;
      else if (m === 'PATCH') db[col][id] = { ...db[col][id], ...b };
      else if (m === 'DELETE') delete db[col][id];
      else return send(res, 405, { error: 'Method not allowed' });
      save(); return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'Not found' });
  });
}).listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Gym app running'));
