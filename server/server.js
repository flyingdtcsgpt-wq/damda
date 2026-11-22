// 담다 동기화 서버 — 의존성 없음 (Node 18+). 실행: node server/server.js
// 서버는 암호화된 덩어리만 보관합니다. 암호·복구 키·글 내용은 서버로 오지 않습니다.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 8787;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const APP = path.join(__dirname, '..', 'app');
const MAX_BODY = 200 * 1024 * 1024;
// 이 서버에 만들 수 있는 보관함 수. 기본 1개 = 처음 연결한 내 보관함 전용. (가족과 함께 쓰려면 MAX_VAULTS=3 처럼 늘린다)
const MAX_VAULTS = +(process.env.MAX_VAULTS || 1);
const RATE = +(process.env.RATE_PER_MIN || 1200); // IP당 분당 요청 수
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // 프록시 뒤에 있을 때 X-Forwarded-For 사용
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; media-src blob:; connect-src http: https:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// 접속 제한: 분당 요청 수, 그리고 인증 실패가 10분에 20번 쌓이면 그 IP를 10분간 막는다.
const hits = new Map(), fails = new Map();
const ipOf = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
function bump(map, ip, windowMs) {
  const now = Date.now(); let e = map.get(ip);
  if (!e || now > e.reset) { e = { n: 0, reset: now + windowMs }; map.set(ip, e); }
  return ++e.n;
}
const blocked = ip => { const e = fails.get(ip); return !!e && Date.now() <= e.reset && e.n >= 20; };
setInterval(() => { const now = Date.now(); for (const m of [hits, fails]) for (const [k, e] of m) if (now > e.reset) m.delete(k); }, 60e3).unref();
const vaultCount = () => { try { return fs.readdirSync(DATA).filter(d => fs.existsSync(path.join(DATA, d, 'meta.json'))).length; } catch { return 0; } };
const ID = /^[A-Za-z0-9_-]{8,64}$/;
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json' };

const vaults = new Map();
const vdir = id => path.join(DATA, id);
function load(id) {
  if (vaults.has(id)) return vaults.get(id);
  try { const m = JSON.parse(fs.readFileSync(path.join(vdir(id), 'meta.json'), 'utf8')); vaults.set(id, m); return m; } catch { return null; }
}
function save(id, m) {
  fs.mkdirSync(path.join(vdir(id), 'r'), { recursive: true });
  const f = path.join(vdir(id), 'meta.json');
  fs.writeFileSync(f + '.tmp', JSON.stringify(m)); fs.renameSync(f + '.tmp', f);
  vaults.set(id, m);
}
const sha = s => crypto.createHash('sha256').update(s).digest();
const authed = (m, req) => {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  return !!t && crypto.timingSafeEqual(sha(t), Buffer.from(m.tokenHash, 'hex'));
};
function body(req) {
  return new Promise((res, rej) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { rej(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => res(Buffer.concat(chunks))); req.on('error', rej);
  });
}
function send(res, code, data, type = 'application/json') {
  const b = Buffer.isBuffer(data) ? data : Buffer.from(typeof data === 'string' ? data : JSON.stringify(data));
  res.writeHead(code, { 'Content-Type': type, 'Content-Length': b.length, 'Cache-Control': 'no-store' }); res.end(b);
}
// 최신 것이 이김(LWW). 받아들이면 순번(seq)을 올려 다른 기기가 가져갈 수 있게 한다.
function accept(m, id, kind, updatedAt, deleted) {
  const cur = m.recs[id];
  if (cur && cur.u >= updatedAt) return false;
  m.recs[id] = { k: kind, u: updatedAt, d: deleted ? 1 : 0, s: ++m.seq };
  return true;
}

async function api(req, res, url) {
  const [, , vid, op, rid] = url.pathname.split('/'), ip = ipOf(req);
  if (blocked(ip)) return send(res, 429, { error: 'too many failed attempts' });
  const deny = () => { bump(fails, ip, 600e3); return send(res, 401, { error: 'unauthorized' }); };
  if (!ID.test(vid || '')) return send(res, 400, { error: 'bad vault id' });
  let m = load(vid);

  if (op === 'keys' && req.method === 'GET') return m ? send(res, 200, m.keys) : send(res, 404, { error: 'not found' });
  if (op === 'keys' && req.method === 'PUT') {
    const keys = JSON.parse(await body(req));
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!m) {
      if (token.length < 32) return deny();
      if (vaultCount() >= MAX_VAULTS) return send(res, 403, { error: 'this server does not accept new vaults' });
      m = { tokenHash: sha(token).toString('hex'), seq: 0, recs: {}, keys };
    } else { if (!authed(m, req)) return deny(); if ((keys.updatedAt || 0) > (m.keys.updatedAt || 0)) m.keys = keys; }
    save(vid, m); return send(res, 200, { ok: true });
  }
  if (!m) return send(res, 404, { error: 'not found' });
  if (!authed(m, req)) return deny();
  const file = id => path.join(vdir(vid), 'r', id);

  if (op === 'changes' && req.method === 'GET') {
    const since = +url.searchParams.get('since') || 0, LIMIT = 300;
    const list = Object.entries(m.recs).filter(([, r]) => r.s > since).sort((a, b) => a[1].s - b[1].s);
    const page = list.slice(0, LIMIT);
    const records = page.map(([id, r]) => ({ id, kind: r.k, updatedAt: r.u, deleted: !!r.d,
      data: r.k === 'item' && !r.d ? fs.readFileSync(file(id), 'utf8') : undefined }));
    return send(res, 200, { records, seq: page.length ? page[page.length - 1][1].s : since, more: list.length > LIMIT });
  }
  if (op === 'push' && req.method === 'POST') {
    const { records = [] } = JSON.parse(await body(req));
    for (const r of records) {
      if (!ID.test(r.id) || !['item', 'blob'].includes(r.kind) || typeof r.updatedAt !== 'number') continue;
      if (r.kind === 'blob' && !r.deleted) continue; // 파일 본문은 /blob 으로
      if (!accept(m, r.id, r.kind, r.updatedAt, r.deleted)) continue;
      if (r.deleted) fs.rmSync(file(r.id), { force: true }); else fs.writeFileSync(file(r.id), String(r.data));
    }
    save(vid, m); return send(res, 200, { ok: true, seq: m.seq });
  }
  if (op === 'blob' && ID.test(rid || '')) {
    if (req.method === 'PUT') {
      const buf = await body(req);
      if (accept(m, rid, 'blob', +url.searchParams.get('u') || Date.now(), false)) { fs.writeFileSync(file(rid), buf); save(vid, m); }
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET') {
      const r = m.recs[rid];
      if (!r || r.d || !fs.existsSync(file(rid))) return send(res, 404, { error: 'not found' });
      return send(res, 200, fs.readFileSync(file(rid)), 'application/octet-stream');
    }
  }
  send(res, 404, { error: 'not found' });
}

function serveStatic(req, res, url) {
  let p = path.normalize(decodeURIComponent(url.pathname)).replace(/^([/\\]|\.\.)+/, '');
  let f = path.join(APP, p || 'index.html');
  if (!f.startsWith(APP) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(APP, 'index.html');
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache', 'Content-Security-Policy': CSP });
  fs.createReadStream(f).pipe(res);
}

http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, OPTIONS');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (bump(hits, ipOf(req), 60e3) > RATE) return send(res, 429, { error: 'slow down' });
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/v/')) await api(req, res, url);
    else if (req.method === 'GET') serveStatic(req, res, url);
    else send(res, 405, { error: 'method' });
  } catch (e) { if (!res.headersSent) send(res, 500, { error: String(e.message || e) }); }
}).listen(PORT, () => console.log(`담다: http://localhost:${PORT}  (데이터: ${DATA})`));
