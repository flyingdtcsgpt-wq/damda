(() => {
// 담다 — 개인용 암호화 노트 (PWA)
// 구조: [유틸] [암호화] [저장소(IndexedDB)] [보관함·잠금] [데이터] [동기화] [화면] [동작]

// ───────── 유틸
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = new TextEncoder(), dec = new TextDecoder();
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
function unb64(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
const uid = () => b64(rnd(12)).replace(/\+/g, '-').replace(/\//g, '_');
const pad = n => String(n).padStart(2, '0');
const ymd = (d = new Date()) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const fmt = t => new Date(t).toLocaleDateString('ko-KR', { year: 'numeric', month: 'short', day: 'numeric' });
const mmss = s => `${Math.floor(s / 60)}:${pad(Math.floor(s % 60))}`;
const safeUrl = u => /^https?:\/\//i.test(u || '') ? u : '';
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.className = 'show'; clearTimeout(toast.t); toast.t = setTimeout(() => t.className = '', 3200); }
const VERSION = '0.2.0', REPO = 'flyingdtcsgpt-wq/damda';
const NATIVE = !!window.Capacitor?.isNativePlatform?.(), DESKTOP = location.protocol === 'app:'; // 안드로이드 앱 / PC 앱
async function download(name, blob) {
  if (NATIVE) { // 안드로이드 앱 안에서는 파일을 임시로 쓴 뒤 공유 창(드라이브·내 파일 등)으로 넘긴다
    try {
      const { uri } = await Capacitor.nativePromise('Filesystem', 'writeFile', { path: name, data: b64(new Uint8Array(await blob.arrayBuffer())), directory: 'CACHE' });
      await Capacitor.nativePromise('Share', 'share', { title: name, files: [uri] });
    } catch (e) { if (!/cancel/i.test(e?.message || '')) toast('파일을 내보내지 못했어요: ' + (e?.message || e)); }
    return;
  }
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
function pickFiles(accept, multiple = true) {
  return new Promise(res => { const i = document.createElement('input'); i.type = 'file'; i.accept = accept; i.multiple = multiple; i.onchange = () => res([...i.files]); i.click(); });
}

// ───────── 암호화 (WebCrypto: AES-256-GCM + PBKDF2)
const PW_ITER = 600000, REC_ITER = 100000;
async function kdf(secret, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, bytes) {
  const iv = rnd(12), ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
}
async function unseal(key, data) { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12))); }
async function wrapWith(secret, iter, raw) { const salt = rnd(16); return { salt: b64(salt), wrap: b64(await seal(await kdf(secret, salt, iter), raw)), iter }; }
// 암호는 Argon2id(메모리 64MB)로 변환한다. 예전 방식(PBKDF2)으로 잠긴 보관함도 열 수 있고, 열 때 새 방식으로 바꿔 둔다.
async function derive(secret, w) {
  if (w.kdf !== 'argon2id') return kdf(secret, unb64(w.salt), w.iter);
  const bits = await hashwasm.argon2id({ password: secret.normalize('NFC'), salt: unb64(w.salt), parallelism: w.p, iterations: w.t, memorySize: w.m, hashLength: 32, outputType: 'binary' });
  return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function wrapPw(secret, raw) {
  if (!window.hashwasm) return wrapWith(secret, PW_ITER, raw);
  const w = { kdf: 'argon2id', m: 65536, t: 3, p: 1, salt: b64(rnd(16)) };
  w.wrap = b64(await seal(await derive(secret, w), raw)); return w;
}
async function unwrapWith(secret, w) { return unseal(await derive(secret, w), unb64(w.wrap)); }
const REC_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const genRec = () => [...rnd(25)].map(b => REC_ABC[b & 31]).join('').replace(/(.{5})(?=.)/g, '$1-');
const normRec = s => String(s).toUpperCase().replace(/[^A-Z0-9]/g, '');
// 암호 또는 복구 키로 마스터 키 풀기. 틀리면 null.
async function tryUnwrap(v, secret) {
  if (!secret) return null;
  tryUnwrap.viaPw = false;
  if (v.pw) { try { const r = await unwrapWith(secret, v.pw); tryUnwrap.viaPw = true; return r; } catch { } }
  try { return await unwrapWith(normRec(secret), v.rec); } catch { }
  return null;
}

// ───────── 저장소
let _db;
function db() {
  return _db ||= new Promise((res, rej) => {
    const r = indexedDB.open('damda', 1);
    r.onupgradeneeded = () => { const d = r.result; d.createObjectStore('meta'); for (const s of ['items', 'blobs']) d.createObjectStore(s, { keyPath: 'id' }).createIndex('dirty', 'dirty'); };
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function tx(store, mode, fn) {
  const d = await db();
  return new Promise((res, rej) => { const t = d.transaction(store, mode), rq = fn(t.objectStore(store)); t.oncomplete = () => res(rq?.result); t.onerror = t.onabort = () => rej(t.error); });
}
const idb = {
  get: (s, k) => tx(s, 'readonly', o => o.get(k)),
  put: (s, v, k) => tx(s, 'readwrite', o => k === undefined ? o.put(v) : o.put(v, k)),
  del: (s, k) => tx(s, 'readwrite', o => o.delete(k)),
  all: s => tx(s, 'readonly', o => o.getAll()),
  keys: s => tx(s, 'readonly', o => o.getAllKeys()),
  dirtyKeys: s => tx(s, 'readonly', o => o.index('dirty').getAllKeys()),
  // 읽고 고쳐 쓰기를 한 번에 (그 사이에 다른 저장이 끼어들지 못하게)
  update: (s, k, fn) => tx(s, 'readwrite', o => { const g = o.get(k); g.onsuccess = () => { const v = fn(g.result); if (v) o.put(v); }; }),
};

// ───────── 상태
const KINDS = {
  diary: ['일기', '📔'], write: ['글쓰기', '✍️'], material: ['글쓰기 자료', '📚'], plan: ['계획서', '🗂️'],
  todo: ['할 일', '✅'], image: ['이미지 보드', '🖼️'], audio: ['녹음', '🎙️'], link: ['링크', '🔗'],
};
const TEXT_KINDS = ['diary', 'write', 'material', 'plan'];
const TEMPLATES = {
  diary: '오늘 있었던 일\n\n\n기억하고 싶은 것\n\n\n내일의 나에게\n',
  plan: '목표\n\n\n왜 하는가\n\n\n단계\n1. \n2. \n3. \n\n일정\n\n\n필요한 것\n',
  write: '한 줄 요약\n\n\n개요\n- 처음: \n- 중간: \n- 끝: \n\n본문\n',
};
const HOURS = [[0, '앱을 닫으면 바로 잠금'], [1, '1시간'], [8, '8시간'], [24, '1일'], [72, '3일'], [168, '7일'], [720, '30일']];
const S = { key: null, raw: null, token: null, expires: 0, vault: null, cfg: { hours: 24 }, entries: new Map(), view: 'home', cur: null, draft: null, q: '', tag: null, drawer: false, focus: false, sync: '' };
const saveCfg = () => idb.put('meta', S.cfg, 'cfg');
const saveVault = v => { S.vault = v; return idb.put('meta', v, 'vault'); };
const cur = () => S.entries.get(S.cur) || (S.draft?.id === S.cur ? S.draft : null);

// ───────── 보관함 · 잠금
async function openWithRaw(raw) {
  S.raw = raw;
  S.key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...enc.encode('damda-auth'), ...raw])));
  S.token = [...h].map(b => b.toString(16).padStart(2, '0')).join('');
  await saveSession(); await enter();
}
// 암호가 없으면 기기에 키를 그대로 두고, 있으면 정해둔 시간만큼만 (꺼낼 수 없는 형태로) 기억한다.
async function saveSession() {
  if (!S.vault.pw) { if (S.raw) await idb.put('meta', b64(S.raw), 'devicekey'); await idb.del('meta', 'session'); S.expires = 0; return; }
  await idb.del('meta', 'devicekey');
  const h = S.cfg.hours;
  if (h > 0) { S.expires = Date.now() + h * 3600e3; await idb.put('meta', { key: S.key, token: S.token, expires: S.expires }, 'session'); }
  else { S.expires = 0; await idb.del('meta', 'session'); }
}
async function enter() {
  navigator.storage?.persist?.();
  S.entries.clear();
  const recs = (await idb.all('items')).filter(r => r.data);
  const list = await Promise.all(recs.map(r => unseal(S.key, r.data).then(b => JSON.parse(dec.decode(b))).catch(() => null)));
  for (const e of list) if (e) S.entries.set(e.id, e);
  await takeShared(); render(); sync();
  const due = [...S.entries.values()].filter(e => e.kind === 'todo' && !e.done && !e.trashed && e.date && e.date <= ymd()).length;
  if (due) toast(`오늘까지 할 일이 ${due}개 있어요`);
  if (!S.creating) maybeGuide();
}
async function lock() {
  if (R) return toast('녹음을 먼저 정지해 주세요');
  await flush(); await snapshot();
  S.key = S.raw = S.token = null; S.entries.clear(); S.cur = S.draft = null;
  for (const p of urls.values()) p.then(u => u && URL.revokeObjectURL(u)); urls.clear();
  await idb.del('meta', 'session');
  $('#modal').innerHTML = ''; renderLock();
}
async function createVault(pw, hint) {
  const raw = rnd(32), recKey = genRec();
  await saveVault({ v: 1, vaultId: uid() + uid(), pw: pw ? await wrapPw(pw, raw) : null, rec: await wrapWith(normRec(recKey), REC_ITER, raw), hint: hint || '', updatedAt: Date.now() });
  S.creating = true; await openWithRaw(raw); S.creating = false; showRecovery(recKey);
}
async function needRaw() {
  if (S.raw) return S.raw;
  const r = await ask({ title: '본인 확인', desc: '계속하려면 현재 암호 또는 복구 키를 입력하세요.', fields: [{ name: 's', label: '암호 / 복구 키', type: 'password' }] });
  if (!r) return null;
  const raw = await tryUnwrap(S.vault, r.s);
  if (!raw) { toast('암호가 맞지 않아요'); return null; }
  return S.raw = raw;
}
async function askNewPw(title) {
  const r = await ask({ title, desc: '8자 이상을 권해요. 암호는 어디에도 전송되지 않습니다.', fields: [{ name: 'a', label: '새 암호', type: 'password' }, { name: 'b', label: '한 번 더', type: 'password' }, { name: 'hint', label: '힌트 (선택 · 잠금 화면에 보임)', value: S.vault?.hint }] });
  if (!r) return null;
  if (!r.a) { toast('암호를 입력해 주세요'); return null; }
  if (r.a !== r.b) { toast('두 암호가 서로 달라요'); return null; }
  return r;
}
async function setPassword(raw, pw, hint) {
  await saveVault({ ...S.vault, pw: pw ? await wrapPw(pw, raw) : null, hint: pw ? hint || '' : '', updatedAt: Date.now() });
  await saveSession(); queueSync();
}

// ───────── 데이터
async function putEntry(e) {
  e.updated = Date.now(); S.entries.set(e.id, e); if (S.draft?.id === e.id) S.draft = null;
  const data = await seal(S.key, enc.encode(JSON.stringify(e))), updatedAt = e.updated;
  await idb.update('items', e.id, c => ({ id: e.id, updatedAt, base: c?.base, deleted: false, dirty: 1, data })); // base(서버와 맞춘 버전)는 유지
  queueSync();
}
const tomb = (store, id) => idb.update(store, id, c => ({ id, updatedAt: Date.now(), base: c?.base, deleted: true, dirty: 1, data: null }));
const vis = e => e.kind !== '_ver'; // '_ver' = 글의 예전 버전(기록). 목록에는 보이지 않는다.
const blobIds = e => (e.atts || []).flatMap(a => a.thumb ? [a.id, a.thumb] : [a.id]);
// 다른 글(충돌 사본 등)이 같은 첨부를 쓰고 있으면 지우지 않는다.
async function dropBlobs(ids) {
  const used = new Set(); for (const x of S.entries.values()) for (const id of blobIds(x)) used.add(id);
  for (const id of ids) if (!used.has(id)) { await tomb('blobs', id); urls.delete(id); }
}
async function purgeEntry(e) {
  S.entries.delete(e.id); await dropBlobs(blobIds(e));
  if (vis(e)) for (const v of versions(e.id)) { S.entries.delete(v.id); await tomb('items', v.id); }
  await tomb('items', e.id); queueSync();
}
// 기록: 글을 열어 고치면, 고치기 전 내용을 한 벌 남긴다 (글마다 최근 20개).
const versions = id => [...S.entries.values()].filter(v => v.kind === '_ver' && v.of === id).sort((a, b) => b.t - a.t);
const origOf = e => ({ id: e.id, title: e.title, body: e.body, t: e.updated, at: Date.now() });
async function snapshot(keep) {
  const o = S.orig, e = o && S.entries.get(o.id); S.orig = keep && e ? origOf(e) : null;
  if (!e || !o.body || (o.body === e.body && o.title === e.title)) return;
  await putEntry({ id: uid(), kind: '_ver', of: e.id, t: o.t, title: o.title, body: o.body });
  for (const v of versions(e.id).slice(20)) await purgeEntry(v);
}
// 목록용 작은 이미지. 원본이 이미 작으면 만들지 않는다.
async function makeThumb(file) {
  try {
    const bmp = await createImageBitmap(file), sc = Math.min(1, 640 / Math.max(bmp.width, bmp.height));
    if (sc === 1 && file.size < 300e3) return null;
    const c = document.createElement('canvas'); c.width = Math.round(bmp.width * sc); c.height = Math.round(bmp.height * sc);
    const g = c.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, c.width, c.height); g.drawImage(bmp, 0, 0, c.width, c.height);
    const b = await new Promise(r => c.toBlob(r, 'image/jpeg', 0.82)); return b ? await putBlob(b) : null;
  } catch { return null; }
}
async function putBlob(blob) {
  const id = uid();
  await idb.put('blobs', { id, updatedAt: Date.now(), deleted: false, dirty: 1, data: await seal(S.key, new Uint8Array(await blob.arrayBuffer())) });
  return id;
}
const urls = new Map();
function blobUrl(id, mime) {
  if (!urls.has(id)) urls.set(id, (async () => {
    let r = await idb.get('blobs', id);
    if (!r?.data && !r?.deleted && S.cfg.sync?.url && navigator.onLine) { // 아직 못 받은 첨부는 볼 때 받아 온다
      const br = await api('GET', '/blob/' + id).catch(() => null);
      if (br) { r = { id, updatedAt: 1, deleted: false, data: new Uint8Array(await br.arrayBuffer()) }; await idb.put('blobs', r); }
    }
    if (!r?.data) { urls.delete(id); return ''; }
    return URL.createObjectURL(new Blob([await unseal(S.key, r.data)], { type: mime }));
  })().catch(() => ''));
  return urls.get(id);
}
const newEntry = (kind, extra = {}) => ({ id: uid(), kind, title: '', body: '', tags: [], fav: false, atts: [], created: Date.now(), updated: Date.now(), date: kind === 'diary' ? ymd() : '', ...extra });
const isEmpty = e => !e.title && !e.body && !e.url && !(e.atts || []).length;

let saveT, pending;
function saveSoon(e) { pending = e; clearTimeout(saveT); saveT = setTimeout(flush, 500); const s = $('#saved'); if (s) s.textContent = '저장 중…'; }
async function flush() {
  clearTimeout(saveT); if (!pending || !S.key) return; const e = pending; pending = null; await putEntry(e);
  const s = $('#saved'); if (s) s.textContent = '저장됨';
  if (S.orig?.id === e.id && Date.now() - S.orig.at > 15 * 60e3) await snapshot(true); // 오래 쓰는 중에는 15분마다 기록
}

async function addImages(files, target, url) {
  files = files.filter(f => f.type.startsWith('image/')); if (!files.length) return;
  for (const f of files) {
    const att = { id: await putBlob(f), type: 'image', mime: f.type, name: f.name || '' }, th = await makeThumb(f);
    if (th) att.thumb = th;
    if (target) target.atts = [...(target.atts || []), att];
    else await putEntry(newEntry('image', { title: (f.name || '').replace(/\.[^.]+$/, ''), atts: [att], url: url || '' }));
  }
  if (target) await putEntry(target);
  toast(`이미지 ${files.length}장 저장`); render();
}
// 주소로 이미지 저장. PC 앱은 사이트 제한 없이 가져오고, 이미지가 아니면(원하면) 링크로 담는다.
async function saveImageUrl(url, target, orLink) {
  try {
    let blob;
    if (window.damdaNative) { const r = await damdaNative.fetchImage(url); blob = new Blob([r.data], { type: r.mime }); }
    else blob = await (await fetch(url)).blob();
    if (!blob.type.startsWith('image/')) throw 0;
    const name = decodeURIComponent(url.split('/').pop().split(/[?#]/)[0]).slice(0, 60);
    await addImages([new File([blob], name, { type: blob.type })], target, url);
  } catch {
    if (!orLink || target) return toast('이 사이트는 직접 저장을 막아두었어요. 이미지를 복사해서 붙여넣어 보세요.');
    await putEntry(newEntry('link', { url })); toast('링크로 저장했어요'); render();
  }
}

// 녹음
let R = null;
async function startRec(done) {
  if (R) return;
  let stream; try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch { return toast('마이크 권한이 필요해요'); }
  const mime = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/webm'].find(m => MediaRecorder.isTypeSupported(m));
  const mr = new MediaRecorder(stream, mime ? { mimeType: mime } : {}), chunks = [], t0 = Date.now();
  const bar = document.createElement('div'); bar.id = 'recbar';
  bar.innerHTML = `<span class="dot"></span> 녹음 중 <b>0:00</b> <button data-act="stopRec">■ 정지 · 저장</button>`; document.body.append(bar);
  mr.ondataavailable = e => e.data.size && chunks.push(e.data);
  mr.onstop = async () => {
    stream.getTracks().forEach(t => t.stop()); clearInterval(R.iv); bar.remove(); R = null;
    const type = (mr.mimeType || 'audio/webm').split(';')[0];
    await done({ id: await putBlob(new Blob(chunks, { type })), type: 'audio', mime: type, dur: Math.round((Date.now() - t0) / 1000) });
  };
  R = { mr, iv: setInterval(() => $('b', bar).textContent = mmss((Date.now() - t0) / 1000), 500) };
  mr.start(1000);
}

// 다른 앱의 '공유'로 들어온 링크·글 받기
const shared = (() => { const p = new URLSearchParams(location.search); const o = { title: p.get('title'), text: p.get('text'), url: p.get('url') }; return o.title || o.text || o.url ? o : null; })();
async function takeShared() {
  if (!shared || shared.done) return; shared.done = true; history.replaceState(null, '', location.pathname);
  const url = safeUrl(shared.url) || (shared.text || '').match(/https?:\/\/\S+/)?.[0];
  await putEntry(newEntry(url ? 'link' : 'material', { title: shared.title || '', body: url ? (shared.text || '').replace(url, '').trim() : shared.text || '', url: url || '' }));
  S.view = url ? 'link' : 'material'; toast('공유받은 내용을 저장했어요');
}

// ───────── 동기화 (서버에는 암호화된 덩어리만 올라간다)
let syncT;
const queueSync = () => { clearTimeout(syncT); syncT = setTimeout(sync, 1500); };
function setSync(s) { S.sync = s; const el = $('#syncstate'); if (el) el.textContent = s; }
async function api(method, p, body, raw) {
  const r = await fetch(S.cfg.sync.url + '/v/' + S.vault.vaultId + p, { method, headers: { Authorization: 'Bearer ' + S.token, ...(body && !raw ? { 'Content-Type': 'application/json' } : {}) }, body: raw ? body : body ? JSON.stringify(body) : undefined });
  if (r.status === 404) return null;
  if (r.status === 401) throw new Error('인증 실패');
  if (r.status === 403) throw new Error('이 서버는 다른 보관함 전용이에요');
  if (r.status === 429) throw new Error('요청이 많아 잠시 쉬는 중');
  if (!r.ok) throw new Error('서버 오류 ' + r.status);
  return r;
}
// base = 서버와 마지막으로 맞춘 버전. 내가 올린 것이 되돌아온 것인지, 다른 기기가 고친 것인지 가린다.
const clean = (store, id, updatedAt) => idb.update(store, id, c => { if (!c) return; c.base = updatedAt; if (c.updatedAt === updatedAt) delete c.dirty; return c; });
const sameText = (a, b) => ['kind', 'title', 'body', 'url', 'date', 'done'].every(k => (a[k] || '') === (b[k] || '')) && blobIds(a).join() === blobIds(b).join();
async function sync() {
  const sc = S.cfg.sync; if (!sc?.url || !S.key || S.syncing) return;
  if (!navigator.onLine) return setSync('오프라인 · 연결되면 동기화');
  S.syncing = true; setSync('동기화 중…'); let changed = false, curChanged = false, conflicts = 0;
  try {
    const kb = await (await api('GET', '/keys'))?.json();
    if (kb && kb.updatedAt > S.vault.updatedAt) { await saveVault(kb); if (kb.pw) await idb.del('meta', 'devicekey'); }
    else if (!kb || kb.updatedAt < S.vault.updatedAt) await api('PUT', '/keys', S.vault);
    for (; ;) { // 받기
      const r = await (await api('GET', '/changes?since=' + (sc.seq || 0))).json();
      if (r.head < (sc.seq || 0)) { await markAllDirty(); sc.seq = 0; continue; } // 서버가 비워졌다 → 전부 다시 올린다
      for (const rec of r.records) {
        if (rec.kind === 'item' && rec.id === S.cur) await flush();
        const store = rec.kind === 'blob' ? 'blobs' : 'items', loc = await idb.get(store, rec.id);
        if (loc && (loc.updatedAt === rec.updatedAt || loc.base === rec.updatedAt)) continue; // 이미 가진 것
        let data = null;
        if (rec.kind === 'item' && loc?.dirty && !loc.deleted) { // 두 기기에서 같은 글을 고쳤다
          const keep = () => idb.update('items', rec.id, c => c && { ...c, base: rec.updatedAt, updatedAt: Math.max(c.updatedAt, rec.updatedAt + 1) });
          if (rec.deleted) { await keep(); continue; } // 저쪽에서 지웠어도 여기서 고친 글은 살린다
          data = unb64(rec.data);
          const mine = S.entries.get(rec.id), theirs = await unseal(S.key, data).then(b => JSON.parse(dec.decode(b))).catch(() => null);
          if (mine && theirs && !sameText(mine, theirs)) { // 진 쪽을 사본으로 남겨 아무것도 잃지 않게 한다
            const lose = rec.updatedAt > loc.updatedAt ? mine : theirs;
            await putEntry({ ...lose, id: uid(), title: (lose.title || '제목 없음') + ' (충돌 사본)', fav: false }); conflicts++;
          }
          if (loc.updatedAt > rec.updatedAt) { await keep(); continue; }
        } else if (loc && loc.updatedAt >= rec.updatedAt) continue;
        if (!rec.deleted && !data) {
          if (rec.kind === 'item') data = unb64(rec.data);
          else { const br = await api('GET', '/blob/' + rec.id); if (!br) continue; data = new Uint8Array(await br.arrayBuffer()); }
        }
        await idb.put(store, { id: rec.id, updatedAt: rec.updatedAt, base: rec.updatedAt, deleted: !!rec.deleted, data });
        if (rec.kind === 'blob') { urls.delete(rec.id); changed = true; continue; }
        if (data) { try { S.entries.set(rec.id, JSON.parse(dec.decode(await unseal(S.key, data)))); } catch { } } else S.entries.delete(rec.id);
        changed = true; if (rec.id === S.cur) curChanged = true;
      }
      sc.seq = r.seq; await saveCfg(); if (!r.more) break;
    }
    const ids = await idb.dirtyKeys('items'); // 보내기
    for (let i = 0; i < ids.length; i += 50) {
      const part = []; for (const id of ids.slice(i, i + 50)) part.push(await idb.get('items', id));
      await api('POST', '/push', { records: part.map(r => ({ id: r.id, kind: 'item', updatedAt: r.updatedAt, deleted: r.deleted, data: r.data ? b64(r.data) : null })) });
      for (const r of part) await clean('items', r.id, r.updatedAt);
    }
    for (const id of await idb.dirtyKeys('blobs')) {
      const r = await idb.get('blobs', id);
      if (r.deleted) await api('POST', '/push', { records: [{ id, kind: 'blob', updatedAt: r.updatedAt, deleted: true }] });
      else await api('PUT', `/blob/${id}?u=${r.updatedAt}`, r.data, true);
      await clean('blobs', id, r.updatedAt);
    }
    const d = new Date(); setSync(`동기화됨 · ${pad(d.getHours())}:${pad(d.getMinutes())}`);
  } catch (e) { setSync('동기화 실패 · ' + (e.message === 'Failed to fetch' ? '서버에 연결할 수 없음' : e.message)); }
  S.syncing = false;
  if (!S.key) return;
  if (conflicts) toast(`두 기기에서 같은 글을 고쳐서 '충돌 사본' ${conflicts}개를 남겼어요`);
  if (curChanged) { clearTimeout(saveT); pending = null; S.orig = null; render(); if (!conflicts) toast('다른 기기에서 고친 내용을 불러왔어요'); }
  else if (changed && !S.cur && !['settings', 'help'].includes(S.view)) refreshList();
}
async function markAllDirty() {
  for (const s of ['items', 'blobs']) await tx(s, 'readwrite', o => { o.openCursor().onsuccess = ev => { const c = ev.target.result; if (c) { c.update({ ...c.value, dirty: 1 }); c.continue(); } }; });
}

// ───────── 화면: 공통
function ask({ title, desc, fields = [], ok = '확인', cancel = '취소' }) {
  return new Promise(res => {
    const m = $('#modal');
    m.innerHTML = `<div class="mback"><form class="mbox"><h3>${esc(title)}</h3>${desc ? `<p>${desc}</p>` : ''}${fields.map(f => `<label>${esc(f.label)}<input name="${f.name}" type="${f.type || 'text'}" placeholder="${esc(f.placeholder || '')}" value="${esc(f.value || '')}" autocomplete="off"></label>`).join('')}<div class="mbtn">${cancel ? `<button type="button" class="ghost" data-x>${cancel}</button>` : ''}<button class="primary">${ok}</button></div></form></div>`;
    const f = $('form', m), done = v => { m.innerHTML = ''; res(v); };
    f.onsubmit = e => { e.preventDefault(); done(Object.fromEntries(new FormData(f))); };
    $('[data-x]', m)?.addEventListener('click', () => done(null));
    ($('input', m) || $('.primary', m)).focus();
  });
}
function showRecovery(key) {
  const m = $('#modal');
  m.innerHTML = `<div class="mback"><div class="mbox"><h3>복구 키를 보관하세요</h3>
  <p>암호를 잊었을 때 <b>이 키가 유일한 복구 방법</b>입니다. 내용이 내 기기에서 암호화되기 때문에, 서버도 개발자도 대신 풀어줄 수 없어요. 종이에 적거나 파일로 저장해 안전한 곳에 두세요.</p>
  <div class="reckey">${key}</div>
  <div class="mbtn"><button class="ghost" id="rc">복사</button><button class="ghost" id="rd">파일로 저장</button><button class="primary" id="ro">보관했어요</button></div></div></div>`;
  $('#rc').onclick = () => navigator.clipboard.writeText(key).then(() => toast('복사했어요'));
  $('#rd').onclick = () => download('담다-복구키.txt', new Blob([`담다 복구 키\n\n${key}\n\n암호를 잊었을 때 잠금 화면의 "암호를 잊었어요"에 입력하세요.\n`], { type: 'text/plain' }));
  $('#ro').onclick = () => { m.innerHTML = ''; maybeGuide(); };
}
const authShell = inner => `<div class="auth"><div class="authbox"><div class="logo">담다</div>${inner}</div></div>`;

function renderSetup(mode = 'new') {
  const app = $('#app');
  if (mode === 'new') {
    app.innerHTML = authShell(`<p class="muted">일기 · 글 · 자료 · 계획 · 할 일 · 이미지 · 녹음을<br>내 기기에서 암호화해 담아둡니다.</p>
    <form id="f"><label>암호 <input name="a" type="password" placeholder="비워두면 암호 없이 시작" autocomplete="new-password"></label>
    <label>암호 확인 <input name="b" type="password" autocomplete="new-password"></label>
    <label>힌트 (선택) <input name="hint"></label>
    <button class="primary">시작하기</button></form>
    <p><a href="#" id="link">다른 기기에서 쓰던 보관함 연결</a> · <a href="#" id="restore">백업 파일로 복원</a></p>`);
    $('#f').onsubmit = async ev => {
      ev.preventDefault(); const v = Object.fromEntries(new FormData(ev.target));
      if (v.a !== v.b) return toast('두 암호가 서로 달라요');
      ev.target.querySelector('button').disabled = true; await createVault(v.a, v.hint);
    };
    $('#link').onclick = ev => { ev.preventDefault(); renderSetup('link'); };
    $('#restore').onclick = async ev => {
      ev.preventDefault(); const [f] = await pickFiles('.damda,application/json', false); if (!f) return;
      try { const b = JSON.parse(await f.text()); await importRecords(b); await saveVault(b.vault); toast('복원했어요. 암호로 잠금을 푸세요.'); renderLock(); } catch { toast('백업 파일을 읽지 못했어요'); }
    };
  } else {
    app.innerHTML = authShell(`<p class="muted">기존 기기의 <b>설정 → 동기화</b>에 있는 동기화 코드를 붙여넣으세요.</p>
    <form id="f"><label>동기화 코드 <input name="code" placeholder="https://서버주소#보관함ID" required></label>
    <label>암호 또는 복구 키 <input name="s" type="password" required></label>
    <button class="primary">연결하기</button></form><p><a href="#" id="back">← 새로 시작</a></p>`);
    $('#back').onclick = ev => { ev.preventDefault(); renderSetup(); };
    $('#f').onsubmit = async ev => {
      ev.preventDefault(); const v = Object.fromEntries(new FormData(ev.target));
      try {
        const [url, vid] = v.code.trim().split('#'), base = url.replace(/\/+$/, '');
        const r = await fetch(base + '/v/' + vid + '/keys').catch(() => null);
        if (!r?.ok) throw new Error('보관함을 찾지 못했어요. 코드를 확인해 주세요.');
        const vault = await r.json(), raw = await tryUnwrap(vault, v.s);
        if (!raw) throw new Error('암호(또는 복구 키)가 맞지 않아요');
        S.cfg.sync = { url: base, seq: 0 }; await saveCfg(); await saveVault(vault); await openWithRaw(raw);
      } catch (e) { toast(e.message); }
    };
  }
}
// 틀린 시도가 쌓이면 대기 시간을 늘린다 (5회부터 30초, 두 배씩, 최대 1시간)
async function waitLeft() { const f = await idb.get('meta', 'fails'); return f?.until > Date.now() ? Math.ceil((f.until - Date.now()) / 1000) : 0; }
async function noteFail(ok) {
  if (ok) return idb.del('meta', 'fails');
  const f = await idb.get('meta', 'fails') || { n: 0 }; f.n++;
  f.until = f.n >= 5 ? Date.now() + Math.min(30e3 * 2 ** (f.n - 5), 3600e3) : 0;
  await idb.put('meta', f, 'fails');
}
const waitMsg = s => `여러 번 틀려서 잠시 막았어요. ${s >= 60 ? Math.ceil(s / 60) + '분' : s + '초'} 뒤에 다시 시도하세요.`;

// 지문·얼굴 잠금 해제: 기기의 인증 장치(패스키)가 내주는 비밀값으로 마스터 키를 한 벌 더 잠가 이 기기에만 둔다.
const bioOK = () => !!window.PublicKeyCredential && location.protocol.startsWith('http');
async function bioKey(bio) {
  const cred = await navigator.credentials.get({ publicKey: { challenge: rnd(32), allowCredentials: [{ type: 'public-key', id: unb64(bio.credId) }], userVerification: 'required', extensions: { prf: { eval: { first: unb64(bio.salt) } } } } });
  const out = cred.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error('이 기기·브라우저는 지문·얼굴 잠금 해제를 지원하지 않아요');
  return crypto.subtle.importKey('raw', out, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function bioEnable(raw) {
  const salt = rnd(32);
  const cred = await navigator.credentials.create({ publicKey: { challenge: rnd(32), rp: { name: '담다' }, user: { id: rnd(16), name: '담다', displayName: '담다' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' }, extensions: { prf: { eval: { first: salt } } } } });
  if (!cred.getClientExtensionResults().prf?.enabled) throw new Error('이 기기·브라우저는 지문·얼굴 잠금 해제를 지원하지 않아요');
  const bio = { credId: b64(new Uint8Array(cred.rawId)), salt: b64(salt) };
  bio.wrap = b64(await seal(await bioKey(bio), raw));
  await idb.put('meta', bio, 'bio'); S.bio = bio;
}

function renderLock() {
  const v = S.vault, hasPw = !!v.pw;
  $('#app').innerHTML = authShell(`<p class="muted">🔒 잠겨 있어요</p>
  <form id="f"><label>${hasPw ? '암호' : '복구 키'} <input name="s" type="password" autofocus autocomplete="current-password"></label>
  <button class="primary">잠금 풀기</button>${S.bio && bioOK() ? `<button type="button" id="bio">지문·얼굴로 풀기</button>` : ''}</form>
  <p>${v.hint ? `<a href="#" id="hint">힌트 보기</a> · ` : ''}${hasPw ? `<a href="#" id="forgot">암호를 잊었어요</a>` : ''}</p>`);
  $('#f').onsubmit = async ev => {
    ev.preventDefault(); const w = await waitLeft(); if (w) return toast(waitMsg(w));
    const btn = ev.target.querySelector('button'); btn.disabled = true; btn.textContent = '확인 중…';
    const secret = ev.target.s.value, raw = await tryUnwrap(v, secret); await noteFail(!!raw);
    if (raw) {
      if (tryUnwrap.viaPw && v.pw.kdf !== 'argon2id' && window.hashwasm) await saveVault({ ...v, pw: await wrapPw(secret, raw), updatedAt: Date.now() });
      return openWithRaw(raw);
    }
    btn.disabled = false; btn.textContent = '잠금 풀기'; const w2 = await waitLeft(); toast(w2 ? waitMsg(w2) : '암호가 맞지 않아요'); ev.target.s.select();
  };
  $('#bio')?.addEventListener('click', async () => {
    let raw = null; try { raw = await unseal(await bioKey(S.bio), unb64(S.bio.wrap)); } catch { }
    if (!raw) return toast('지문·얼굴 인증에 실패했어요. 암호로 풀어 주세요.');
    await noteFail(true); openWithRaw(raw);
  });
  $('#hint')?.addEventListener('click', ev => { ev.preventDefault(); toast('힌트: ' + v.hint); });
  $('#forgot')?.addEventListener('click', async ev => {
    ev.preventDefault();
    const r = await ask({ title: '복구 키로 암호 재설정', desc: '처음 만들 때 받은 복구 키(25자)를 입력하세요. 글은 그대로 유지됩니다.', fields: [{ name: 'k', label: '복구 키', placeholder: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX' }, { name: 'a', label: '새 암호', type: 'password' }, { name: 'b', label: '한 번 더', type: 'password' }] });
    if (!r) return;
    if (!r.a || r.a !== r.b) return toast('새 암호를 똑같이 두 번 입력해 주세요');
    const w = await waitLeft(); if (w) return toast(waitMsg(w));
    let raw = null; try { raw = await unwrapWith(normRec(r.k), v.rec); } catch { }
    await noteFail(!!raw);
    if (!raw) return toast('복구 키가 맞지 않아요');
    S.raw = raw; await saveVault({ ...v, pw: await wrapPw(r.a, raw), hint: '', updatedAt: Date.now() });
    await openWithRaw(raw); toast('암호를 새로 설정했어요');
  });
}

// ───────── 화면: 본문
function items() {
  const v = S.view, q = S.q.trim().toLowerCase();
  let a = [...S.entries.values()].filter(e => vis(e) && (v === 'trash' ? e.trashed : !e.trashed));
  if (KINDS[v]) a = a.filter(e => e.kind === v);
  if (v === 'fav') a = a.filter(e => e.fav);
  if (q) a = a.filter(e => [e.title, e.locked ? '' : e.body, e.url, (e.tags || []).join(' ')].join(' ').toLowerCase().includes(q));
  if (S.tag) a = a.filter(e => (e.tags || []).includes(S.tag));
  if (v === 'diary') a.sort((x, y) => (y.date || '').localeCompare(x.date || '') || y.created - x.created);
  else if (v === 'todo') a.sort((x, y) => (!!x.done - !!y.done) || (x.date || '9').localeCompare(y.date || '9') || y.created - x.created);
  else if (v === 'image' || v === 'audio' || v === 'link') a.sort((x, y) => y.created - x.created);
  else a.sort((x, y) => y.updated - x.updated);
  return a;
}
// 목록에서는 작은 이미지(thumb)를, 글 안에서는 원본(full)을 쓴다.
const img = (a, cls = '', full) => `<img class="${cls}" data-att="${full || !a.thumb ? a.id : a.thumb}" data-mime="${esc(full || !a.thumb ? a.mime : 'image/jpeg')}" alt="" loading="lazy">`;
const tagsHTML = e => (e.tags || []).map(t => `<span class="tag" data-act="tag" data-tag="${esc(t)}">#${esc(t)}</span>`).join('');
const audioBtn = a => `<button class="play" data-act="play" data-att="${a.id}" data-mime="${esc(a.mime)}">▶ 재생 ${a.dur ? mmss(a.dur) : ''}</button>`;
function card(e) {
  const im = !e.locked && (e.atts || []).find(a => a.type === 'image'), au = (e.atts || []).filter(a => a.type === 'audio').length;
  const lines = e.locked ? [] : (e.body || '').split('\n').filter(Boolean), title = e.title || lines[0] || e.url || (e.locked ? '잠긴 글' : '제목 없음');
  return `<article class="card" data-act="open" data-id="${e.id}">${im ? img(im, 'thumb') : ''}<div class="cbody">
  <div class="ctitle">${KINDS[e.kind][1]} ${esc(title)}${e.fav ? ' <span class="star">★</span>' : ''}</div>
  <div class="csnip">${e.locked ? '🔒 잠긴 글' : esc((e.title ? lines : lines.slice(1)).join(' ').slice(0, 160))}</div>
  <div class="cmeta">${e.kind === 'diary' && e.date ? esc(e.date) + ' ' + (e.mood || '') + (e.weather || '') : fmt(e.updated)}${au ? ` · 🎙${au}` : ''} ${tagsHTML(e)}</div>
  ${S.view === 'trash' ? `<div class="cmeta"><button data-act="restore" data-id="${e.id}">복원</button> <button data-act="purge" data-id="${e.id}">영구 삭제</button></div>` : ''}</div></article>`;
}
// 일기 달력: 쓴 날에는 기분(없으면 점)이 찍힌다. 날짜를 누르면 그날 일기를 열거나 새로 쓴다.
function calHTML() {
  const [y, m] = (S.cal ||= ymd().slice(0, 7)).split('-').map(Number), first = new Date(y, m - 1, 1).getDay(), days = new Date(y, m, 0).getDate(), by = {};
  for (const e of S.entries.values()) if (e.kind === 'diary' && !e.trashed && e.date?.startsWith(S.cal)) (by[e.date] ||= []).push(e);
  let cells = '<i></i>'.repeat(first);
  for (let d = 1; d <= days; d++) { const k = `${S.cal}-${pad(d)}`, es = by[k]; cells += `<button class="day ${es ? 'has' : ''} ${k === ymd() ? 'today' : ''}" data-act="calDay" data-date="${k}"><span>${d}</span><em>${es ? es.find(e => e.mood)?.mood || '●' : ''}</em></button>`; }
  return `<div class="cal"><div class="calhead"><button class="icon" data-act="calMove" data-d="-1" title="이전 달">‹</button><b>${y}년 ${m}월</b><button class="icon" data-act="calMove" data-d="1" title="다음 달">›</button></div>
  <div class="calgrid">${[...'일월화수목금토'].map(d => `<small>${d}</small>`).join('')}${cells}</div></div>`;
}
// 본문의 [[제목]] 으로 이어진 글과, 이 글을 가리키는 글
function linksHTML(e) {
  if (!(e.body || '').includes('[[') && !e.title) return '';
  const all = [...S.entries.values()].filter(x => vis(x) && !x.trashed && x.id !== e.id);
  const names = [...new Set([...(e.body || '').matchAll(/\[\[([^\]\n]+)\]\]/g)].map(m => m[1].trim()).filter(Boolean))];
  const out = names.map(n => { const t = all.find(x => x.title === n); return t ? `<span class="tag" data-act="open" data-id="${t.id}">→ ${esc(n)}</span>` : `<span class="tag new" data-act="newLinked" data-title="${esc(n)}">＋ ${esc(n)} 만들기</span>`; });
  const back = e.title ? all.filter(x => !x.locked && (x.body || '').includes(`[[${e.title}]]`)).map(x => `<span class="tag" data-act="open" data-id="${x.id}">← ${esc(x.title || '제목 없음')}</span>`) : [];
  return out.length || back.length ? `<div class="filter">연결된 글 ${out.join(' ')} ${back.join(' ')}</div>` : '';
}
function listHTML() {
  const v = S.view, a = items();
  const filter = S.tag ? `<div class="filter">태그 <span class="tag on" data-act="cleartag">#${esc(S.tag)} ✕</span></div>` : '';
  const empty = `<p class="empty">${S.q || S.tag ? '찾는 내용이 없어요.' : '아직 비어 있어요.'}</p>`;
  if (v === 'settings') return settingsHTML();
  if (v === 'help') return helpHTML();
  const cal = v === 'diary' && !S.q && !S.tag ? calHTML() : '';
  if (v === 'home' && !S.q && !S.tag) {
    const md = ymd().slice(5), past = a.filter(e => e.kind === 'diary' && e.date && e.date.slice(5) === md && e.date < ymd());
    const favs = a.filter(e => e.fav).slice(0, 6);
    return `${past.length ? `<h2>오늘의 과거 일기</h2><div class="cards">${past.map(card).join('')}</div>` : ''}
    ${favs.length ? `<h2>즐겨찾기</h2><div class="cards">${favs.map(card).join('')}</div>` : ''}
    <h2>최근</h2>${a.length ? `<div class="cards">${a.slice(0, 30).map(card).join('')}</div>` : `<p class="empty">위 버튼으로 첫 글을 남겨 보세요. 이미지는 어디서든 붙여넣기(Ctrl+V)나 끌어다 놓기로 저장됩니다.</p>`}`;
  }
  if (!a.length) return cal + filter + empty;
  if (v === 'todo') return filter + a.map(e => `<div class="rowitem ${e.done ? 'done' : ''}"><input type="checkbox" data-act="toggle" data-id="${e.id}" ${e.done ? 'checked' : ''}>
    <span class="grow" data-act="open" data-id="${e.id}">${esc(e.title || '(제목 없음)')}${e.fav ? ' <span class="star">★</span>' : ''}</span>
    ${e.repeat ? '<small>🔁</small>' : ''}${e.date ? `<small class="${!e.done && e.date < ymd() ? 'late' : ''}">${esc(e.date)}</small>` : ''}<button class="icon" data-act="trash" data-id="${e.id}">✕</button></div>`).join('');
  if (v === 'image') return filter + `<div class="masonry">${a.map(e => { const im = !e.locked && (e.atts || []).find(x => x.type === 'image'); return `<figure class="pin" data-act="open" data-id="${e.id}">${im ? img(im) : ''}${e.title || e.fav || e.locked ? `<figcaption>${e.locked ? '🔒 ' : ''}${e.fav ? '<span class="star">★</span> ' : ''}${esc(e.title)}</figcaption>` : ''}</figure>`; }).join('')}</div>`;
  if (v === 'audio') return filter + a.map(e => `<div class="rowitem"><div class="grow"><div data-act="open" data-id="${e.id}"><b>${esc(e.title || '녹음')}</b>${e.fav ? ' <span class="star">★</span>' : ''}</div><div class="cmeta">${fmt(e.created)} ${tagsHTML(e)}</div>${(e.atts || []).filter(x => x.type === 'audio').map(audioBtn).join('')}</div></div>`).join('');
  if (v === 'link') return filter + a.map(e => `<div class="rowitem"><div class="grow" data-act="open" data-id="${e.id}"><b>${esc(e.title || e.url)}</b>${e.fav ? ' <span class="star">★</span>' : ''}<div class="cmeta">${esc(e.url)} ${tagsHTML(e)}</div></div>${safeUrl(e.url) ? `<a class="btn" href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">열기 ↗</a>` : ''}</div>`).join('');
  return cal + filter + `<div class="cards">${a.map(card).join('')}</div>`;
}
function quickHTML() {
  const v = S.view, nb = k => `<button data-act="new" data-kind="${k}">${KINDS[k][1]} ${KINDS[k][0]}</button>`;
  if (v === 'home') return `<div class="quick">${['diary', 'write', 'material', 'plan'].map(nb).join('')}<button data-act="addImg">🖼️ 이미지</button><button data-act="rec">🎙️ 녹음</button></div>`;
  if (TEXT_KINDS.includes(v)) return `<div class="quick"><button class="primary" data-act="new" data-kind="${v}">＋ 새 ${KINDS[v][0]}</button></div>`;
  if (v === 'todo') return `<form class="quick" id="addTodo"><input name="t" class="grow" placeholder="할 일을 적고 Enter" required><input name="d" type="date"><button class="primary">추가</button></form>`;
  if (v === 'link') return `<form class="quick" id="addLink"><input name="u" class="grow" placeholder="https:// 주소 붙여넣기" required><input name="t" placeholder="이름 (선택)"><button class="primary">저장</button></form>`;
  if (v === 'image') return `<div class="quick"><button class="primary" data-act="addImg">＋ 이미지 추가</button><button data-act="imgUrl">주소로 저장</button><button data-act="draw">✏️ 그리기</button><span class="muted">복사한 이미지를 붙여넣거나 끌어다 놓아도 저장돼요</span></div>`;
  if (v === 'audio') return `<div class="quick"><button class="primary" data-act="rec">● 녹음 시작</button></div>`;
  if (v === 'trash') return `<div class="quick"><button data-act="emptyTrash">휴지통 비우기</button></div>`;
  return '';
}
const VIEW_TITLE = { home: '전체', fav: '즐겨찾기', trash: '휴지통', settings: '설정', help: '가이드' };
function viewHTML() {
  const v = S.view;
  return `<header class="top"><button class="icon menu" data-act="drawer">☰</button><h1>${VIEW_TITLE[v] || KINDS[v][0]}</h1><span class="sp"></span>${v === 'settings' || v === 'help' ? '' : `<input id="q" type="search" placeholder="검색" value="${esc(S.q)}">`}</header>
  <div class="page">${quickHTML()}<div id="list">${listHTML()}</div></div>`;
}
const sel = (f, cur, opts) => `<select data-f="${f}">${opts.map(([v, n]) => `<option value="${v}" ${v === (cur || '') ? 'selected' : ''}>${n}</option>`).join('')}</select>`;
const MOODS = ['', '😀', '🙂', '😐', '😢', '😡', '😴', '🤒'], WEATHER = ['', '☀️', '⛅', '☁️', '🌧️', '❄️', '🌬️'];
function editorHTML(e) {
  const k = e.kind, imgs = (e.atts || []).filter(a => a.type === 'image'), auds = (e.atts || []).filter(a => a.type === 'audio');
  return `<div class="editor"><header class="top"><button class="icon" data-act="back" title="뒤로">←</button>
  <select data-f="kind">${Object.entries(KINDS).map(([v, [n, i]]) => `<option value="${v}" ${v === k ? 'selected' : ''}>${i} ${n}</option>`).join('')}</select>
  <span class="sp"></span><span id="saved" class="muted"></span>
  <button class="icon ${e.fav ? 'on' : ''}" data-act="fav" title="즐겨찾기">${e.fav ? '★' : '☆'}</button>
  <button class="icon ${e.locked ? 'on' : ''}" data-act="noteLock" title="이 글만 한 번 더 잠그기">${e.locked ? '🔐' : '🔓'}</button>
  <button class="icon" data-act="focus" title="집중 모드 (Esc로 해제)">⛶</button>
  <button class="icon" data-act="trash" data-id="${e.id}" title="휴지통으로">🗑</button></header>
  <div class="page">
  <input class="title" data-f="title" placeholder="제목" value="${esc(e.title)}">
  <div class="quick meta">${['diary', 'todo', 'plan'].includes(k) ? `<label>${k === 'diary' ? '날짜' : '기한'} <input type="date" data-f="date" value="${esc(e.date || '')}"></label>` : ''}
  ${k === 'diary' ? `<label>기분 ${sel('mood', e.mood, MOODS.map(m => [m, m || '—']))}</label><label>날씨 ${sel('weather', e.weather, WEATHER.map(m => [m, m || '—']))}</label>` : ''}
  ${k === 'todo' ? `<label>반복 ${sel('repeat', e.repeat, [['', '없음'], ['day', '매일'], ['week', '매주'], ['month', '매월']])}</label>` : ''}
  ${['link', 'image'].includes(k) ? `<input type="url" class="grow" data-f="url" placeholder="출처 주소 https://…" value="${esc(e.url || '')}">${safeUrl(e.url) ? `<a class="btn" href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">열기 ↗</a>` : ''}` : ''}</div>
  ${imgs.length ? `<div class="atts">${imgs.map(a => `<div class="att">${img(a, '', 1)}<button class="icon del" data-act="delAtt" data-att="${a.id}" title="삭제">✕</button></div>`).join('')}</div>` : ''}
  ${auds.map(a => `<div class="rowitem">${audioBtn(a)}<span class="sp"></span><button class="icon" data-act="delAtt" data-att="${a.id}" title="삭제">✕</button></div>`).join('')}
  <textarea data-f="body" placeholder="${k === 'todo' ? '메모' : '여기에 쓰기 시작하세요…  [[다른 글 제목]] 으로 글끼리 이을 수 있어요'}">${esc(e.body)}</textarea>
  <div id="links">${linksHTML(e)}</div>
  <input data-f="tags" placeholder="태그 (쉼표로 구분)" value="${esc((e.tags || []).join(', '))}">
  <footer class="tools"><button data-act="addImg">🖼 이미지</button><button data-act="rec">🎙 녹음</button><button data-act="draw">✏️ 그림</button>${TEMPLATES[k] ? `<button data-act="template">📋 템플릿</button>` : ''}
  <button data-act="history">🕘 기록</button><button data-act="exportTxt">⬇ 내보내기</button>${NATIVE ? '' : `<button data-act="print">🖨 인쇄</button>`}
  <span class="sp"></span><label class="muted">목표 <input type="number" min="0" step="100" data-f="goal" value="${e.goal || ''}" placeholder="0">자</label><span id="count" class="muted"></span></footer>
  </div></div>`;
}
// ───────── 가이드
const GUIDE = [
  ['담다에 오신 것을 환영해요', '일기, 글, 자료, 계획, 할 일, 이미지, 녹음, 링크를 한곳에 담는 나만의 공간입니다.<br><br>담은 내용은 <b>이 기기 안에서 암호화</b>되어 저장돼요. 동기화 서버를 쓰더라도 서버는 내용을 읽을 수 없습니다.'],
  ['무엇이든 빠르게 담기', '· 왼쪽 메뉴에서 종류를 고르고 <b>＋ 새 글</b><br>· 이미지: 복사해서 <b>붙여넣기</b>, 끌어다 놓기, 또는 🖼 버튼<br>· 녹음: 🎙 버튼 한 번으로 시작, 쓰던 글에 바로 붙일 수도 있어요<br>· 손그림: ✏️ 버튼<br>· 주소를 붙여넣으면 링크로 저장돼요<br>· <b>★</b>를 누르면 즐겨찾기에 모입니다'],
  ['글쓰기를 돕는 것들', '· 쓰는 대로 <b>자동 저장</b>됩니다<br>· ⛶ 집중 모드, 글자 수 목표, 📋 템플릿<br>· 🕘 <b>기록</b>: 고치기 전 내용이 남아 있어 되돌릴 수 있어요<br>· 본문에 <b>[[다른 글 제목]]</b> 을 쓰면 글끼리 이어집니다<br>· 일기는 달력으로 보고, 기분과 날씨를 남길 수 있어요<br>· 할 일은 매일·매주·매월 반복할 수 있어요'],
  ['잠금과 복구', '· <b>설정 → 잠금</b>에서 암호를 걸거나 없앨 수 있어요<br>· 한 번 풀면 몇 시간~며칠 동안 다시 묻지 않게 정할 수 있어요<br>· 🔓 버튼으로 <b>특정 글만 한 번 더</b> 잠글 수 있어요<br>· 암호를 잊으면 <b>복구 키</b>로 새 암호를 정합니다. 복구 키까지 잃으면 아무도 복구할 수 없으니 꼭 보관하세요'],
  ['여러 기기와 백업', '· <b>설정 → 동기화</b>에 서버 주소를 넣으면 PC와 휴대폰에서 같은 내용을 봅니다<br>· 두 기기에서 같은 글을 고치면 한쪽은 <b>충돌 사본</b>으로 남아요<br>· <b>설정 → 백업</b>에서 백업 파일을 가끔 내려받아 두세요<br><br>이 안내는 왼쪽 메뉴의 <b>📖 가이드</b>에서 언제든 다시 볼 수 있어요.'],
];
function showGuide(i = 0) {
  const [t, body] = GUIDE[i], last = i === GUIDE.length - 1, m = $('#modal');
  m.innerHTML = `<div class="mback"><div class="mbox guide"><div class="muted small">${i + 1} / ${GUIDE.length}</div><h3>${t}</h3><p>${body}</p>
  <div class="mbtn">${last ? '' : `<button class="ghost" id="gskip">건너뛰기</button>`}<span class="sp"></span>${i ? `<button class="ghost" id="gprev">이전</button>` : ''}<button class="primary" id="gnext">${last ? '시작하기' : '다음'}</button></div></div></div>`;
  const done = () => { m.innerHTML = ''; idb.put('meta', 1, 'guided'); };
  $('#gskip')?.addEventListener('click', done); $('#gprev')?.addEventListener('click', () => showGuide(i - 1));
  $('#gnext').onclick = () => last ? done() : showGuide(i + 1);
}
async function maybeGuide() { if (S.key && !$('#modal').innerHTML && !await idb.get('meta', 'guided')) showGuide(); }
function helpHTML() {
  return `<section class="set help"><div class="quick"><button class="primary" data-act="guide">처음 안내 다시 보기</button></div>
  ${GUIDE.map(([t, b]) => `<h2>${t}</h2><p>${b}</p>`).join('')}
  <h2>단축키 (PC)</h2><p>· Ctrl/⌘+S 바로 저장 · Ctrl/⌘+V 이미지·주소 붙여넣기 · Esc 집중 모드 끄기</p>
  <h2>자주 묻는 것</h2>
  <p><b>글은 어디에 저장되나요?</b><br>이 기기 안(앱 데이터)에 암호화되어 저장됩니다. 동기화를 켜면 암호화된 사본이 내 서버에도 올라갑니다.</p>
  <p><b>암호를 잊었어요.</b><br>잠금 화면의 "암호를 잊었어요"에 복구 키를 넣으면 새 암호를 정할 수 있어요. 이메일로는 복구할 수 없습니다.</p>
  <p><b>글별 잠금(🔐)은 얼마나 안전한가요?</b><br>앱이 풀려 있는 동안 남이 그 글을 열어 보지 못하게 막는 용도입니다. 앱 전체 암호가 실제 보호막이에요.</p>
  <p><b>지운 글을 되살리려면?</b><br>휴지통에서 복원하세요. 휴지통을 비우기 전까지 남아 있습니다.</p>
  <p><b>휴대폰을 바꾸면?</b><br>동기화를 쓰고 있다면 새 폰 첫 화면에서 "보관함 연결"을, 아니면 백업 파일로 "복원"을 누르세요.</p></section>`;
}
function settingsHTML() {
  const v = S.vault, sc = S.cfg.sync;
  return `<section class="set"><h2>잠금</h2>
  <p>${v.pw ? '암호가 설정되어 있어요.' : '지금은 <b>암호 없이</b> 쓰는 중이에요. 내용은 기기 안에서 암호화되어 있지만, 이 기기를 여는 사람은 볼 수 있어요.'}</p>
  <div class="quick"><button data-act="setpw">${v.pw ? '암호 바꾸기' : '암호 설정'}</button>${v.pw ? `<button data-act="rmpw">암호 없애기</button><button data-act="lock">지금 잠그기</button>` : ''}</div>
  ${v.pw ? `<label>한 번 풀면 유지되는 시간 <select id="hours">${HOURS.map(([h, n]) => `<option value="${h}" ${h === S.cfg.hours ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
  ${bioOK() ? `<div class="quick"><button data-act="${S.bio ? 'bioOff' : 'bioOn'}">${S.bio ? '지문·얼굴 잠금 해제 끄기' : '지문·얼굴로 잠금 해제 켜기'}</button><span class="muted">이 기기에만 적용돼요. 암호는 그대로 쓸 수 있어요.</span></div>` : `<p class="muted small">${DESKTOP || NATIVE ? '지문·얼굴 잠금 해제는 설치형 앱에서 아직 지원하지 않아요.' : '지문·얼굴 잠금 해제는 https 주소나 localhost로 열었을 때만 쓸 수 있어요.'}</p>`}` : ''}
  <h2>암호를 잊었을 때</h2>
  <p>복구 키(25자)를 잠금 화면의 "암호를 잊었어요"에 입력하면 새 암호를 정할 수 있어요. 내용이 내 기기에서 암호화되기 때문에 이메일 인증으로는 복구할 수 없고, 복구 키가 유일한 방법입니다.</p>
  <div class="quick"><button data-act="newrec">복구 키 새로 발급</button></div>
  <h2>동기화</h2>
  ${sc?.url ? `<p>서버: <b>${esc(sc.url)}</b> · <span>${esc(S.sync)}</span></p>
  <label>동기화 코드 — 다른 기기의 첫 화면 "보관함 연결"에 붙여넣기<input readonly id="code" value="${esc(sc.url + '#' + v.vaultId)}"></label>
  <div class="quick"><button data-act="copyCode">코드 복사</button><button data-act="syncNow">지금 동기화</button><button data-act="syncOff">연결 끊기</button></div>`
      : `<p>동기화 서버 주소를 넣으면 여러 기기에서 같은 내용을 볼 수 있어요. 서버에는 암호화된 데이터만 올라갑니다.</p>
  <form class="quick" id="syncForm"><input name="u" class="grow" placeholder="https://내-서버-주소" value="${location.protocol.startsWith('http') ? esc(location.origin) : ''}" required><button class="primary">연결</button></form>`}
  <h2>백업</h2><p>암호화된 그대로 파일 하나로 내보냅니다. 복원하려면 암호나 복구 키가 필요해요.</p>
  <div class="quick"><button data-act="export">백업 파일 내보내기</button><button data-act="import">백업 파일 가져오기</button></div>
  <p class="muted small" id="usage"></p>
  ${DESKTOP || NATIVE ? '' : `<h2>설치</h2><p>Windows · Mac: Chrome/Edge 주소창 오른쪽의 설치 아이콘. iPhone/iPad: Safari 공유 → "홈 화면에 추가". Android: Chrome 메뉴 → "앱 설치". 설치 후에는 인터넷 없이도 열립니다.</p>
  ${S.installEvt ? `<div class="quick"><button class="primary" data-act="install">이 기기에 설치</button></div>` : ''}`}
  <h2>버전</h2><p>담다 ${VERSION} · <span id="upd"></span></p>
  <div class="quick"><button data-act="checkUpdate">새 버전 확인</button><a class="btn" href="https://github.com/${REPO}/releases/latest" target="_blank" rel="noopener noreferrer">내려받기 페이지 ↗</a></div></section>`;
}
function render() {
  if (!S.key) return;
  const e = S.cur && cur(); if (S.cur && !e) S.cur = null;
  const count = k => { let n = 0; for (const x of S.entries.values()) if (!x.trashed && (k === 'fav' ? x.fav : x.kind === k) && vis(x) && !(k === 'todo' && x.done)) n++; return n || ''; };
  const nav = (v, label, n = '') => `<button class="nav ${S.view === v && !S.cur ? 'on' : ''}" data-act="nav" data-view="${v}">${label}<small>${n}</small></button>`;
  $('#app').innerHTML = `<div class="shell ${S.focus && e ? 'focus' : ''} ${S.drawer ? 'drawer' : ''}">
  <aside class="side"><div class="logo">담다</div>${nav('home', '🏠 전체')}${nav('fav', '⭐ 즐겨찾기', count('fav'))}<hr>
  ${Object.entries(KINDS).map(([k, [n, i]]) => nav(k, `${i} ${n}`, count(k))).join('')}<hr>${nav('trash', '🗑 휴지통')}${nav('settings', '⚙️ 설정')}${nav('help', '📖 가이드')}
  <div class="sp"></div><div class="muted small" id="syncstate">${esc(S.sync)}</div>${S.vault.pw ? `<button class="nav" data-act="lock">🔒 잠그기</button>` : ''}</aside>
  <div class="scrim" data-act="drawer"></div><main>${e ? editorHTML(e) : viewHTML()}</main></div>`;
  bind(); hydrate();
}
function refreshList() { const l = $('#list'); if (l && !S.cur) { l.innerHTML = listHTML(); bindSettings(); hydrate(); } }
const io = new IntersectionObserver(es => { for (const x of es) if (x.isIntersecting) { io.unobserve(x.target); blobUrl(x.target.dataset.att, x.target.dataset.mime).then(u => { if (u) x.target.src = u; }); } }, { rootMargin: '400px' });
const hydrate = () => document.querySelectorAll('img[data-att]:not([src])').forEach(i => io.observe(i));
const grow = t => { t.style.height = 'auto'; t.style.height = t.scrollHeight + 2 + 'px'; };
function updCount(e) {
  const c = $('#count'); if (!c) return; const n = (e.body || '').length, ns = (e.body || '').replace(/\s/g, '').length;
  c.textContent = e.goal ? `${n.toLocaleString()} / ${(+e.goal).toLocaleString()}자 (${Math.min(100, Math.round(n / e.goal * 100))}%)` : `${n.toLocaleString()}자 · 공백 제외 ${ns.toLocaleString()}자`;
}
function bind() {
  const q = $('#q'); if (q) q.oninput = () => { S.q = q.value; refreshList(); };
  const e = S.cur && cur();
  if (e) {
    const root = $('.editor'), ta = $('textarea', root); grow(ta); updCount(e);
    root.addEventListener('input', ev => {
      const t = ev.target, f = t.dataset.f; if (!f) return;
      if (f === 'tags') e.tags = [...new Set(t.value.split(',').map(s => s.trim().replace(/^#/, '')).filter(Boolean))];
      else if (f === 'goal') e.goal = +t.value || 0; else e[f] = t.value;
      if (f === 'body') grow(t);
      if (f === 'body' || f === 'title') { const l = $('#links'); if (l && (l.innerHTML || e.body.includes('[['))) l.innerHTML = linksHTML(e); }
      updCount(e); saveSoon(e);
    });
    root.addEventListener('change', async ev => { if (['kind', 'url'].includes(ev.target.dataset.f)) { await flush(); render(); } });
    if (isEmpty(e) && !('ontouchstart' in window)) $(e.kind === 'diary' ? 'textarea' : '.title', root).focus();
  }
  $('#addTodo')?.addEventListener('submit', async ev => { ev.preventDefault(); const f = ev.target; await putEntry(newEntry('todo', { title: f.t.value.trim(), date: f.d.value })); f.t.value = ''; refreshList(); f.t.focus(); });
  $('#addLink')?.addEventListener('submit', async ev => {
    ev.preventDefault(); const f = ev.target; let u = f.u.value.trim(); if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    await putEntry(newEntry('link', { url: u, title: f.t.value.trim() })); f.reset(); refreshList();
  });
  bindSettings();
}
function bindSettings() {
  const u = $('#usage'); if (u) navigator.storage?.estimate?.().then(x => { if (x?.usage != null) u.textContent = `이 기기에서 쓰는 저장 공간: ${(x.usage / 1048576).toFixed(1)}MB`; }).catch(() => { });
  const h = $('#hours'); if (h) h.onchange = async () => { S.cfg.hours = +h.value; await saveCfg(); await saveSession(); toast('저장했어요'); };
  $('#syncForm')?.addEventListener('submit', async ev => {
    ev.preventDefault(); S.cfg.sync = { url: ev.target.u.value.trim().replace(/\/+$/, ''), seq: 0 };
    await saveCfg(); await markAllDirty(); await sync(); refreshList();
  });
}

// ───────── 동작
// 편집기를 떠날 때: 저장하고, 기록을 남기고, 빈 글은 치운다.
async function leave() {
  await flush(); await snapshot();
  const e = cur(); if (e && S.entries.has(e.id) && isEmpty(e)) await purgeEntry(e);
  S.cur = S.draft = null; S.focus = false;
}
async function goBack() { await leave(); render(); }
function showEditor(id) { S.cur = id; if (!history.state?.ed) history.pushState({ ed: 1 }, ''); render(); window.scrollTo(0, 0); } // 뒤로 가기(안드로이드 포함)로 닫히게
async function openEntry(id) {
  const e = S.entries.get(id); if (!e) return;
  if (e.locked && S.vault.pw) {
    const r = await ask({ title: '잠긴 글', desc: '이 글을 열려면 암호를 입력하세요.', fields: [{ name: 's', label: '암호', type: 'password' }] });
    if (!r) return; if (!await tryUnwrap(S.vault, r.s)) return toast('암호가 맞지 않아요');
  }
  await leave(); S.orig = origOf(e); showEditor(id);
}
function nextDate(d, rep) {
  const t = new Date((d || ymd()) + 'T12:00');
  do { if (rep === 'day') t.setDate(t.getDate() + 1); else if (rep === 'week') t.setDate(t.getDate() + 7); else t.setMonth(t.getMonth() + 1); } while (ymd(t) <= ymd());
  return ymd(t);
}
function sheet(html, cls = '') {
  const m = $('#modal'); m.innerHTML = `<div class="mback"><div class="mbox wide ${cls}">${html}</div></div>`;
  m.querySelectorAll('[data-x]').forEach(b => b.onclick = () => m.innerHTML = ''); return m;
}
const byId = id => S.entries.get(id);
const actions = {
  nav: async el => { await leave(); Object.assign(S, { view: el.dataset.view, cur: null, draft: null, q: '', tag: null, drawer: false, focus: false }); render(); },
  drawer: () => { S.drawer = !S.drawer; $('.shell').classList.toggle('drawer', S.drawer); },
  new: async el => { await leave(); S.draft = newEntry(el.dataset.kind); showEditor(S.draft.id); },
  newLinked: async el => { await leave(); S.draft = newEntry('material', { title: el.dataset.title }); showEditor(S.draft.id); },
  open: el => openEntry(el.dataset.id),
  back: () => history.state?.ed ? history.back() : goBack(),
  noteLock: async () => {
    const e = cur(); if (!e) return; if (!S.vault.pw) return toast('먼저 설정 → 잠금에서 암호를 설정하세요');
    e.locked = !e.locked; await flush(); await putEntry(e); const b = $('.editor [data-act=noteLock]'); if (b) { b.textContent = e.locked ? '🔐' : '🔓'; b.classList.toggle('on', e.locked); }
    toast(e.locked ? '이 글은 열 때마다 암호를 묻습니다' : '글 잠금을 풀었어요');
  },
  calMove: el => { const [y, m] = S.cal.split('-').map(Number); S.cal = ymd(new Date(y, m - 1 + +el.dataset.d, 1)).slice(0, 7); refreshList(); },
  calDay: async el => {
    const d = el.dataset.date, es = [...S.entries.values()].filter(e => e.kind === 'diary' && !e.trashed && e.date === d).sort((a, b) => b.updated - a.updated);
    if (es.length) return openEntry(es[0].id);
    S.draft = newEntry('diary', { date: d }); showEditor(S.draft.id);
  },
  history: async () => {
    const e = cur(); if (!e) return; await flush(); const vs = versions(e.id);
    sheet(`<h3>기록</h3><p>글을 열어 고칠 때마다 고치기 전 내용이 남습니다 (최근 20개).</p>${vs.length ? vs.map(v => `<div class="rowitem"><div class="grow"><b>${new Date(v.t).toLocaleString('ko-KR')}</b><div class="cmeta">${esc((v.body || '').slice(0, 70))} · ${(v.body || '').length.toLocaleString()}자</div></div><button data-act="verView" data-id="${v.id}">보기</button></div>`).join('') : '<p class="empty">아직 기록이 없어요.</p>'}<div class="mbtn"><button class="ghost" data-x>닫기</button></div>`);
  },
  verView: el => { const v = byId(el.dataset.id); sheet(`<h3>${new Date(v.t).toLocaleString('ko-KR')}</h3><pre class="ver">${esc(v.title)}\n\n${esc(v.body)}</pre><div class="mbtn"><button class="ghost" data-act="history">목록</button><button class="primary" data-act="verRestore" data-id="${v.id}">이 내용으로 되돌리기</button></div>`); },
  verRestore: async el => {
    const v = byId(el.dataset.id), e = cur(); if (!v || !e) return; await flush();
    await putEntry({ id: uid(), kind: '_ver', of: e.id, t: Date.now(), title: e.title, body: e.body }); // 지금 내용도 기록에 남긴다
    e.title = v.title; e.body = v.body; await putEntry(e); S.orig = origOf(e); $('#modal').innerHTML = ''; render(); toast('되돌렸어요');
  },
  exportTxt: async () => { const e = cur(); if (!e) return; await flush(); download(`${(e.title || '담다').replace(/[\\/:*?"<>|]/g, '_')}.txt`, new Blob([`${e.title}\n${e.date || fmt(e.updated)}\n\n${e.body}\n${(e.tags || []).map(t => '#' + t).join(' ')}\n`], { type: 'text/plain' })); },
  print: () => window.print(),
  guide: () => showGuide(),
  checkUpdate: async () => {
    const u = $('#upd'); u.textContent = '확인 중…';
    try { const tag = (await (await fetch(`https://api.github.com/repos/${REPO}/releases/latest`)).json()).tag_name; const num = v => v.replace(/^v/, '').split('.').map(Number), [r, l] = [num(tag || '0'), num(VERSION)], newer = r.some((x, i) => x > (l[i] || 0) && r.slice(0, i).every((y, j) => y === (l[j] || 0)));
      u.textContent = !tag ? '확인하지 못했어요' : newer ? `새 버전 ${tag} 이 있어요 — 내려받기 페이지에서 받으세요` : '최신 버전이에요'; }
    catch { u.textContent = '확인하지 못했어요 (인터넷 연결 필요)'; }
  },
  draw: async () => {
    const t = S.cur && cur(); if (t) await flush();
    const m = sheet(`<div class="drawbar">${[0, 1, 2, 3].map(i => `<button class="pen c${i}" data-pen="${i}" title="펜"></button>`).join('')}<button data-pen="erase">지우개</button><button data-w="3">가늘게</button><button data-w="8">굵게</button><button id="dundo" title="되돌리기">↶</button><span class="sp"></span><button class="ghost" data-x>취소</button><button class="primary" id="dsave">저장</button></div><canvas id="pad"></canvas>`, 'draw');
    const COLORS = ['#222222', '#c0392b', '#2a6fdb', '#2e8b57'], cv = $('#pad'), dpr = window.devicePixelRatio || 1, box = cv.getBoundingClientRect();
    cv.width = Math.round(box.width * dpr); cv.height = Math.round(box.height * dpr);
    const g = cv.getContext('2d'); g.scale(dpr, dpr); g.fillStyle = '#fff'; g.fillRect(0, 0, box.width, box.height); g.lineCap = g.lineJoin = 'round';
    let pen = 0, w = 3, down = false; const undo = [];
    const pos = ev => { const b = cv.getBoundingClientRect(); return [ev.clientX - b.left, ev.clientY - b.top]; };
    cv.onpointerdown = ev => {
      cv.setPointerCapture(ev.pointerId); undo.push(g.getImageData(0, 0, cv.width, cv.height)); if (undo.length > 15) undo.shift();
      down = true; g.strokeStyle = pen === 'erase' ? '#fff' : COLORS[pen]; g.lineWidth = pen === 'erase' ? 24 : w; g.beginPath(); g.moveTo(...pos(ev)); g.lineTo(...pos(ev)); g.stroke();
    };
    cv.onpointermove = ev => { if (down) { g.lineTo(...pos(ev)); g.stroke(); } };
    cv.onpointerup = cv.onpointercancel = () => down = false;
    m.querySelectorAll('[data-pen]').forEach(b => b.onclick = () => pen = b.dataset.pen === 'erase' ? 'erase' : +b.dataset.pen);
    m.querySelectorAll('[data-w]').forEach(b => b.onclick = () => w = +b.dataset.w);
    $('#dundo').onclick = () => { const d = undo.pop(); if (d) g.putImageData(d, 0, 0); };
    $('#dsave').onclick = () => cv.toBlob(async b => { m.innerHTML = ''; await addImages([new File([b], `그림 ${ymd()}.png`, { type: 'image/png' })], t || null); }, 'image/png');
  },
  fav: async () => { const e = cur(); if (!e) return; e.fav = !e.fav; await flush(); await putEntry(e); const b = $('.editor [data-act=fav]'); if (b) { b.textContent = e.fav ? '★' : '☆'; b.classList.toggle('on', e.fav); } },
  focus: () => { S.focus = !S.focus; $('.shell').classList.toggle('focus', S.focus); },
  trash: async el => { await flush(); await snapshot(); const e = byId(el.dataset.id); if (e) { e.trashed = true; await putEntry(e); toast('휴지통으로 옮겼어요'); } S.cur = S.draft = null; render(); },
  restore: async el => { const e = byId(el.dataset.id); delete e.trashed; await putEntry(e); render(); },
  purge: async el => { if (confirm('영구 삭제할까요? 되돌릴 수 없어요.')) { await purgeEntry(byId(el.dataset.id)); render(); } },
  emptyTrash: async () => { const a = [...S.entries.values()].filter(e => e.trashed && vis(e)); if (a.length && confirm(`${a.length}개를 영구 삭제할까요? 되돌릴 수 없어요.`)) { for (const e of a) await purgeEntry(e); render(); } },
  toggle: async el => {
    const e = byId(el.dataset.id); e.done = el.checked;
    if (e.done && e.repeat) { // 반복 할 일: 끝내면 다음 차례를 만들어 둔다
      await putEntry(newEntry('todo', { title: e.title, body: e.body, tags: e.tags, repeat: e.repeat, date: nextDate(e.date, e.repeat) }));
      e.repeat = ''; toast('다음 차례를 추가했어요');
    }
    await putEntry(e); refreshList();
  },
  tag: async el => { await leave(); S.tag = el.dataset.tag; render(); },
  cleartag: () => { S.tag = null; refreshList(); },
  addImg: async () => { const t = S.cur && cur(); if (t) await flush(); addImages(await pickFiles('image/*'), t || null); },
  imgUrl: async () => { const r = await ask({ title: '이미지 주소로 저장', fields: [{ name: 'u', label: '이미지 주소', placeholder: 'https://…' }] }); if (r && safeUrl(r.u)) await saveImageUrl(r.u.trim(), null); },
  rec: async () => {
    const t = S.cur && cur(); if (t) await flush();
    startRec(async att => {
      if (!S.key) return;
      if (t) { t.atts = [...(t.atts || []), att]; await putEntry(t); }
      else { const d = new Date(); await putEntry(newEntry('audio', { title: `녹음 ${ymd(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`, atts: [att] })); if (!S.cur) S.view = 'audio'; }
      toast('녹음을 저장했어요'); if (!S.cur || S.cur === t?.id) render();
    });
  },
  stopRec: () => R?.mr.stop(),
  play: async el => { const u = await blobUrl(el.dataset.att, el.dataset.mime); if (!u) return toast('아직 이 기기로 받아오지 못했어요'); const a = document.createElement('audio'); a.controls = true; a.src = u; el.replaceWith(a); a.play().catch(() => { }); },
  delAtt: async el => { const e = cur(); if (!e || !confirm('첨부를 삭제할까요?')) return; await flush(); const a = e.atts.find(a => a.id === el.dataset.att); e.atts = e.atts.filter(x => x !== a); await dropBlobs(a?.thumb ? [a.id, a.thumb] : [el.dataset.att]); await putEntry(e); render(); },
  template: () => { const e = cur(), ta = $('textarea'); if (e.body.trim() && !confirm('본문 끝에 템플릿을 덧붙일까요?')) return; e.body = (e.body.trim() ? e.body.trimEnd() + '\n\n' : '') + TEMPLATES[e.kind]; ta.value = e.body; grow(ta); updCount(e); saveSoon(e); },
  lock,
  setpw: async () => { const raw = await needRaw(); if (!raw) return; const r = await askNewPw(S.vault.pw ? '암호 바꾸기' : '암호 설정'); if (!r) return; await setPassword(raw, r.a, r.hint); toast('암호를 설정했어요'); render(); },
  rmpw: async () => { const raw = await needRaw(); if (!raw) return; if (!confirm('암호를 없앨까요? 이 기기를 여는 사람은 누구나 내용을 볼 수 있게 됩니다.')) return; await setPassword(raw, null); toast('암호 없이 사용합니다'); render(); },
  newrec: async () => { const raw = await needRaw(); if (!raw) return; if (!confirm('새 복구 키를 만들면 이전 복구 키는 쓸 수 없게 됩니다. 계속할까요?')) return; const k = genRec(); await saveVault({ ...S.vault, rec: await wrapWith(normRec(k), REC_ITER, raw), updatedAt: Date.now() }); queueSync(); showRecovery(k); },
  bioOn: async () => { const raw = await needRaw(); if (!raw) return; try { await bioEnable(raw); toast('지문·얼굴 잠금 해제를 켰어요'); } catch (e) { toast(e.name === 'NotAllowedError' ? '취소했어요' : e.message); } refreshList(); },
  bioOff: async () => { await idb.del('meta', 'bio'); S.bio = null; toast('껐어요'); refreshList(); },
  copyCode: () => navigator.clipboard.writeText($('#code').value).then(() => toast('복사했어요')),
  syncNow: async () => { await sync(); toast(S.sync); refreshList(); },
  syncOff: async () => { if (!confirm('이 기기의 동기화 연결을 끊을까요? 기기 안의 내용은 그대로 남습니다.')) return; delete S.cfg.sync; await saveCfg(); setSync(''); refreshList(); },
  export: async () => {
    const out = { app: 'damda', v: 1, exported: Date.now(), vault: S.vault, items: [], blobs: [] };
    for (const s of ['items', 'blobs']) for (const id of await idb.keys(s)) { const r = await idb.get(s, id); out[s].push({ id, updatedAt: r.updatedAt, deleted: r.deleted, data: r.data ? b64(r.data) : null }); }
    download(`담다-백업-${ymd()}.damda`, new Blob([JSON.stringify(out)], { type: 'application/json' }));
  },
  import: async () => {
    const [f] = await pickFiles('.damda,application/json', false); if (!f) return;
    try { const b = JSON.parse(await f.text()); if (b.vault?.vaultId !== S.vault.vaultId) return toast('다른 보관함의 백업이에요. 새 기기 첫 화면의 "백업 파일로 복원"을 사용하세요.'); const n = await importRecords(b); await enter(); toast(`${n}개 항목을 가져왔어요`); }
    catch { toast('백업 파일을 읽지 못했어요'); }
  },
  install: async () => { await S.installEvt.prompt(); S.installEvt = null; refreshList(); },
};
async function importRecords(b) {
  if (b.app !== 'damda' || !b.vault?.rec) throw new Error('bad'); let n = 0;
  for (const s of ['items', 'blobs']) for (const r of b[s] || []) {
    const loc = await idb.get(s, r.id); if (loc && loc.updatedAt >= r.updatedAt) continue;
    await idb.put(s, { id: r.id, updatedAt: r.updatedAt, deleted: !!r.deleted, dirty: 1, data: r.data ? unb64(r.data) : null }); n++;
  }
  return n;
}

document.addEventListener('click', ev => {
  const el = ev.target.closest('[data-act]'); if (!el) return;
  const fn = actions[el.dataset.act]; if (fn) Promise.resolve(fn(el, ev)).catch(e => { console.error(e); toast('문제가 생겼어요: ' + (e.message || e)); });
});
document.addEventListener('keydown', ev => {
  if (ev.key === 'Escape' && S.focus) actions.focus();
  if ((ev.ctrlKey || ev.metaKey) && ev.key === 's') { ev.preventDefault(); flush(); }
});
const inField = ev => !!ev.target.closest?.('input, textarea, select');
document.addEventListener('paste', ev => {
  if (!S.key || $('#modal').innerHTML) return; const fs = [...(ev.clipboardData?.files || [])];
  if (fs.some(f => f.type.startsWith('image/'))) { ev.preventDefault(); return addImages(fs, S.cur ? cur() : null); }
  const url = safeUrl((ev.clipboardData?.getData('text') || '').trim()); // 입력칸 밖에서 주소를 붙여넣으면 이미지나 링크로 담는다
  if (url && !/\s/.test(url) && !inField(ev) && !S.cur) { ev.preventDefault(); saveImageUrl(url, null, true); }
});
document.addEventListener('dragover', ev => { const t = ev.dataTransfer?.types || []; if (S.key && (t.includes('Files') || (t.includes('text/uri-list') && !inField(ev)))) ev.preventDefault(); });
document.addEventListener('drop', ev => {
  const dt = ev.dataTransfer; if (!S.key || !dt) return; const target = S.cur ? cur() : null;
  if (dt.files.length) { ev.preventDefault(); return addImages([...dt.files], target); }
  if (inField(ev)) return; // 브라우저에서 끌어온 이미지·링크
  const url = safeUrl(((dt.getData('text/html').match(/<img[^>]+src="([^"]+)"/i) || [])[1] || '').replace(/&amp;/g, '&')) || safeUrl(dt.getData('text/uri-list').split('\n')[0].trim());
  if (url) { ev.preventDefault(); saveImageUrl(url, target, true); }
});
window.addEventListener('popstate', () => { if (S.key && S.cur) goBack(); });
window.addEventListener('online', sync);
window.addEventListener('beforeinstallprompt', ev => { ev.preventDefault(); S.installEvt = ev; });
window.addEventListener('pagehide', flush);
let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { hiddenAt = Date.now(); flush(); return; }
  if (S.key && S.vault?.pw && !R && S.cfg.hours === 0 && hiddenAt && Date.now() - hiddenAt > 5 * 60e3) lock(); else sync();
});
setInterval(() => { if (S.key && S.vault?.pw && S.expires && Date.now() > S.expires && !R) lock(); }, 20000);
setInterval(sync, 5 * 60e3);

// ───────── 시작
(async () => {
  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(() => { });
  S.cfg = await idb.get('meta', 'cfg') || { hours: 24 };
  S.vault = await idb.get('meta', 'vault');
  S.bio = await idb.get('meta', 'bio');
  if (!S.vault) return renderSetup();
  const dk = await idb.get('meta', 'devicekey');
  if (dk && !S.vault.pw) return openWithRaw(unb64(dk));
  const ses = await idb.get('meta', 'session');
  if (ses && ses.expires > Date.now()) { S.key = ses.key; S.token = ses.token; S.expires = ses.expires; return enter(); }
  renderLock();
})();
})();
