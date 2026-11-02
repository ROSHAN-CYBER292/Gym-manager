const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

// ---- Password: Render > Environment me OWNER_PASSWORD zaroor set karo ----
let PASS = process.env.OWNER_PASSWORD;
if (!PASS) { PASS = crypto.randomBytes(8).toString('hex'); console.log('WARNING: OWNER_PASSWORD set nahi hai. Temporary password:', PASS); }
const TOKEN = crypto.createHash('sha256').update('gym:' + PASS).digest('hex');

const FILE = path.join(__dirname, 'data.json');
let db = {}; try { db = JSON.parse(fs.readFileSync(FILE)); } catch (e) {}
const save = () => fs.writeFileSync(FILE, JSON.stringify(db));

const keyOf = s => [...s].map(c => c.charCodeAt(0).toString(36)).join('-');
function pinFor(seed, d) { let h = 0; const s = seed + d; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0; return String(h % 10000).padStart(4, '0'); }
const istDate = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
const istTime = () => new Date().toLocaleTimeString('en-GB', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' });

const fails = new Map(), posts = new Map();
const recent = (map, k, ms) => { const n = Date.now(), a = (map.get(k) || []).filter(t => n - t < ms); map.set(k, a); return a; };
const ipOf = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const sameToken = t => { const a = Buffer.from(String(t || '')), b = Buffer.from(TOKEN); return a.length === b.length && crypto.timingSafeEqual(a, b); };

const send = (res, c, o) => { res.writeHead(c, { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(o)); };

http.createServer((req, res) => {
  const u = req.url.split('?')[0];
  if (!u.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
  }
  let body = '', big = false;
  req.on('data', c => { body += c; if (body.length > 100000) { big = true; req.destroy(); } });
  req.on('end', () => {
    if (big) return;
    let b = {}; try { b = body ? JSON.parse(body) : {}; } catch (e) {}
    const owner = sameToken(req.headers['x-token']), m = req.method, ip = ipOf(req);

    if (u === '/api/login' && m === 'POST') {
      if (recent(fails, ip, 15 * 60000).length >= 5) return send(res, 429, { error: 'Too many wrong attempts. 15 minute baad try karo.' });
      if (b.password === PASS) return send(res, 200, { token: TOKEN });
      recent(fails, ip, 15 * 60000).push(Date.now());
      return send(res, 401, { error: 'Wrong password' });
    }

    const [, , kind, col, id] = u.split('/');
    if (kind === 'col' && m === 'GET') {
      if (!owner) return send(res, 401, { error: 'Owner only' });
      return send(res, 200, { docs: Object.entries(db[col] || {}).map(([id, data]) => ({ id, data })) });
    }
    if (kind === 'doc' && col && id) {
      if (m === 'GET') {
        if (!owner && !['settings', 'roster'].includes(col)) return send(res, 401, { error: 'Owner only' });
        let d = (db[col] || {})[id] ?? null;
        if (!owner && col === 'settings' && d) { d = { ...d }; delete d.seed; }   // daily code ka seed public nahi
        return send(res, 200, { data: d });
      }
      if (!owner) {
        // Sirf member attendance allowed, aur wo bhi server par jaanch ke baad
        if (m !== 'PUT' || col !== 'attendance') return send(res, 401, { error: 'Owner only' });
        const hits = recent(posts, ip, 60000);
        if (hits.length >= 15) return send(res, 429, { error: 'Bahut zyada requests. Thodi der baad try karo.' });
        hits.push(Date.now());
        const fn = String(b.fn || '').trim().toLowerCase();
        const seed = ((db.settings || {}).gym || {}).seed;
        if (!fn || !(db.roster || {})[keyOf(fn)]) return send(res, 403, { error: 'Name not found. Only registered members can mark attendance.' });
        if (!seed || String(b.pin) !== pinFor(seed, istDate())) return send(res, 403, { error: 'Wrong code. Today\u2019s code is displayed inside the gym.' });
        if (id !== istDate() + '_' + keyOf(fn)) return send(res, 400, { error: 'Bad request' });
        db.attendance = db.attendance || {};
        db.attendance[id] = { date: istDate(), fn, name: String(b.name || fn).slice(0, 40), time: istTime() };
        save(); return send(res, 200, { ok: true });
      }
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
