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
function download(name, blob) { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000); }
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
  for (const r of await idb.all('items')) if (r.data) { try { const e = JSON.parse(dec.decode(await unseal(S.key, r.data))); S.entries.set(e.id, e); } catch { } }
  await takeShared(); render(); sync();
}
async function lock() {
  if (R) return toast('녹음을 먼저 정지해 주세요');
  await flush();
  S.key = S.raw = S.token = null; S.entries.clear(); S.cur = S.draft = null;
  for (const p of urls.values()) p.then(u => u && URL.revokeObjectURL(u)); urls.clear();
  await idb.del('meta', 'session');
  $('#modal').innerHTML = ''; renderLock();
}
async function createVault(pw, hint) {
  const raw = rnd(32), recKey = genRec();
  await saveVault({ v: 1, vaultId: uid() + uid(), pw: pw ? await wrapPw(pw, raw) : null, rec: await wrapWith(normRec(recKey), REC_ITER, raw), hint: hint || '', updatedAt: Date.now() });
  await openWithRaw(raw); showRecovery(recKey);
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
  await idb.put('items', { id: e.id, updatedAt: e.updated, deleted: false, dirty: 1, data: await seal(S.key, enc.encode(JSON.stringify(e))) });
  queueSync();
}
const tomb = (store, id) => idb.put(store, { id, updatedAt: Date.now(), deleted: true, dirty: 1, data: null });
async function purgeEntry(e) {
  for (const a of e.atts || []) await tomb('blobs', a.id);
  S.entries.delete(e.id); await tomb('items', e.id); queueSync();
}
async function putBlob(blob) {
  const id = uid();
  await idb.put('blobs', { id, updatedAt: Date.now(), deleted: false, dirty: 1, data: await seal(S.key, new Uint8Array(await blob.arrayBuffer())) });
  return id;
}
const urls = new Map();
function blobUrl(id, mime) {
  if (!urls.has(id)) urls.set(id, (async () => { const r = await idb.get('blobs', id); return r?.data ? URL.createObjectURL(new Blob([await unseal(S.key, r.data)], { type: mime })) : ''; })().catch(() => ''));
  return urls.get(id);
}
const newEntry = (kind, extra = {}) => ({ id: uid(), kind, title: '', body: '', tags: [], fav: false, atts: [], created: Date.now(), updated: Date.now(), date: kind === 'diary' ? ymd() : '', ...extra });
const isEmpty = e => !e.title && !e.body && !e.url && !(e.atts || []).length;

let saveT, pending;
function saveSoon(e) { pending = e; clearTimeout(saveT); saveT = setTimeout(flush, 500); const s = $('#saved'); if (s) s.textContent = '저장 중…'; }
async function flush() { clearTimeout(saveT); if (!pending || !S.key) return; const e = pending; pending = null; await putEntry(e); const s = $('#saved'); if (s) s.textContent = '저장됨'; }

async function addImages(files, target) {
  files = files.filter(f => f.type.startsWith('image/')); if (!files.length) return;
  for (const f of files) {
    const att = { id: await putBlob(f), type: 'image', mime: f.type, name: f.name || '' };
    if (target) target.atts = [...(target.atts || []), att];
    else await putEntry(newEntry('image', { title: (f.name || '').replace(/\.[^.]+$/, ''), atts: [att] }));
  }
  if (target) await putEntry(target);
  toast(`이미지 ${files.length}장 저장`); render();
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
async function clean(store, id, updatedAt) { const c = await idb.get(store, id); if (c && c.updatedAt === updatedAt) { delete c.dirty; await idb.put(store, c); } }
async function sync() {
  const sc = S.cfg.sync; if (!sc?.url || !S.key || S.syncing) return;
  if (!navigator.onLine) return setSync('오프라인 · 연결되면 동기화');
  S.syncing = true; setSync('동기화 중…'); let changed = false;
  try {
    const kb = await (await api('GET', '/keys'))?.json();
    if (kb && kb.updatedAt > S.vault.updatedAt) { await saveVault(kb); if (kb.pw) await idb.del('meta', 'devicekey'); }
    else if (!kb || kb.updatedAt < S.vault.updatedAt) await api('PUT', '/keys', S.vault);
    for (; ;) { // 받기
      const r = await (await api('GET', '/changes?since=' + (sc.seq || 0))).json();
      for (const rec of r.records) {
        const store = rec.kind === 'blob' ? 'blobs' : 'items', loc = await idb.get(store, rec.id);
        if (loc && loc.updatedAt >= rec.updatedAt) continue;
        let data = null;
        if (!rec.deleted) {
          if (rec.kind === 'item') data = unb64(rec.data);
          else { const br = await api('GET', '/blob/' + rec.id); if (!br) continue; data = new Uint8Array(await br.arrayBuffer()); }
        }
        await idb.put(store, { id: rec.id, updatedAt: rec.updatedAt, deleted: !!rec.deleted, data });
        if (rec.kind === 'blob') { urls.delete(rec.id); changed = true; continue; }
        if (data) { try { S.entries.set(rec.id, JSON.parse(dec.decode(await unseal(S.key, data)))); } catch { } } else S.entries.delete(rec.id);
        changed = true;
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
  if (changed && S.key) { if (S.cur || S.view === 'settings') return; refreshList(); }
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
  $('#ro').onclick = () => m.innerHTML = '';
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
  let a = [...S.entries.values()].filter(e => v === 'trash' ? e.trashed : !e.trashed);
  if (KINDS[v]) a = a.filter(e => e.kind === v);
  if (v === 'fav') a = a.filter(e => e.fav);
  if (q) a = a.filter(e => [e.title, e.body, e.url, (e.tags || []).join(' ')].join(' ').toLowerCase().includes(q));
  if (S.tag) a = a.filter(e => (e.tags || []).includes(S.tag));
  if (v === 'diary') a.sort((x, y) => (y.date || '').localeCompare(x.date || '') || y.created - x.created);
  else if (v === 'todo') a.sort((x, y) => (!!x.done - !!y.done) || (x.date || '9').localeCompare(y.date || '9') || y.created - x.created);
  else if (v === 'image' || v === 'audio' || v === 'link') a.sort((x, y) => y.created - x.created);
  else a.sort((x, y) => y.updated - x.updated);
  return a;
}
const img = (a, cls = '') => `<img class="${cls}" data-att="${a.id}" data-mime="${esc(a.mime)}" alt="" loading="lazy">`;
const tagsHTML = e => (e.tags || []).map(t => `<span class="tag" data-act="tag" data-tag="${esc(t)}">#${esc(t)}</span>`).join('');
const audioBtn = a => `<button class="play" data-act="play" data-att="${a.id}" data-mime="${esc(a.mime)}">▶ 재생 ${a.dur ? mmss(a.dur) : ''}</button>`;
function card(e) {
  const im = (e.atts || []).find(a => a.type === 'image'), au = (e.atts || []).filter(a => a.type === 'audio').length;
  const lines = (e.body || '').split('\n').filter(Boolean), title = e.title || lines[0] || e.url || '제목 없음';
  return `<article class="card" data-act="open" data-id="${e.id}">${im ? img(im, 'thumb') : ''}<div class="cbody">
  <div class="ctitle">${KINDS[e.kind][1]} ${esc(title)}${e.fav ? ' <span class="star">★</span>' : ''}</div>
  <div class="csnip">${esc((e.title ? lines : lines.slice(1)).join(' ').slice(0, 160))}</div>
  <div class="cmeta">${e.kind === 'diary' && e.date ? esc(e.date) : fmt(e.updated)}${au ? ` · 🎙${au}` : ''} ${tagsHTML(e)}</div>
  ${S.view === 'trash' ? `<div class="cmeta"><button data-act="restore" data-id="${e.id}">복원</button> <button data-act="purge" data-id="${e.id}">영구 삭제</button></div>` : ''}</div></article>`;
}
function listHTML() {
  const v = S.view, a = items();
  const filter = S.tag ? `<div class="filter">태그 <span class="tag on" data-act="cleartag">#${esc(S.tag)} ✕</span></div>` : '';
  const empty = `<p class="empty">${S.q || S.tag ? '찾는 내용이 없어요.' : '아직 비어 있어요.'}</p>`;
  if (v === 'settings') return settingsHTML();
  if (v === 'home' && !S.q && !S.tag) {
    const md = ymd().slice(5), past = a.filter(e => e.kind === 'diary' && e.date && e.date.slice(5) === md && e.date < ymd());
    const favs = a.filter(e => e.fav).slice(0, 6);
    return `${past.length ? `<h2>오늘의 과거 일기</h2><div class="cards">${past.map(card).join('')}</div>` : ''}
    ${favs.length ? `<h2>즐겨찾기</h2><div class="cards">${favs.map(card).join('')}</div>` : ''}
    <h2>최근</h2>${a.length ? `<div class="cards">${a.slice(0, 30).map(card).join('')}</div>` : `<p class="empty">위 버튼으로 첫 글을 남겨 보세요. 이미지는 어디서든 붙여넣기(Ctrl+V)나 끌어다 놓기로 저장됩니다.</p>`}`;
  }
  if (!a.length) return filter + empty;
  if (v === 'todo') return filter + a.map(e => `<div class="rowitem ${e.done ? 'done' : ''}"><input type="checkbox" data-act="toggle" data-id="${e.id}" ${e.done ? 'checked' : ''}>
    <span class="grow" data-act="open" data-id="${e.id}">${esc(e.title || '(제목 없음)')}${e.fav ? ' <span class="star">★</span>' : ''}</span>
    ${e.date ? `<small class="${!e.done && e.date < ymd() ? 'late' : ''}">${esc(e.date)}</small>` : ''}<button class="icon" data-act="trash" data-id="${e.id}">✕</button></div>`).join('');
  if (v === 'image') return filter + `<div class="masonry">${a.map(e => { const im = (e.atts || []).find(x => x.type === 'image'); return `<figure class="pin" data-act="open" data-id="${e.id}">${im ? img(im) : ''}${e.title || e.fav ? `<figcaption>${e.fav ? '<span class="star">★</span> ' : ''}${esc(e.title)}</figcaption>` : ''}</figure>`; }).join('')}</div>`;
  if (v === 'audio') return filter + a.map(e => `<div class="rowitem"><div class="grow"><div data-act="open" data-id="${e.id}"><b>${esc(e.title || '녹음')}</b>${e.fav ? ' <span class="star">★</span>' : ''}</div><div class="cmeta">${fmt(e.created)} ${tagsHTML(e)}</div>${(e.atts || []).filter(x => x.type === 'audio').map(audioBtn).join('')}</div></div>`).join('');
  if (v === 'link') return filter + a.map(e => `<div class="rowitem"><div class="grow" data-act="open" data-id="${e.id}"><b>${esc(e.title || e.url)}</b>${e.fav ? ' <span class="star">★</span>' : ''}<div class="cmeta">${esc(e.url)} ${tagsHTML(e)}</div></div>${safeUrl(e.url) ? `<a class="btn" href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">열기 ↗</a>` : ''}</div>`).join('');
  return filter + `<div class="cards">${a.map(card).join('')}</div>`;
}
function quickHTML() {
  const v = S.view, nb = k => `<button data-act="new" data-kind="${k}">${KINDS[k][1]} ${KINDS[k][0]}</button>`;
  if (v === 'home') return `<div class="quick">${['diary', 'write', 'material', 'plan'].map(nb).join('')}<button data-act="addImg">🖼️ 이미지</button><button data-act="rec">🎙️ 녹음</button></div>`;
  if (TEXT_KINDS.includes(v)) return `<div class="quick"><button class="primary" data-act="new" data-kind="${v}">＋ 새 ${KINDS[v][0]}</button></div>`;
  if (v === 'todo') return `<form class="quick" id="addTodo"><input name="t" class="grow" placeholder="할 일을 적고 Enter" required><input name="d" type="date"><button class="primary">추가</button></form>`;
  if (v === 'link') return `<form class="quick" id="addLink"><input name="u" class="grow" placeholder="https:// 주소 붙여넣기" required><input name="t" placeholder="이름 (선택)"><button class="primary">저장</button></form>`;
  if (v === 'image') return `<div class="quick"><button class="primary" data-act="addImg">＋ 이미지 추가</button><button data-act="imgUrl">주소로 저장</button><span class="muted">복사한 이미지를 붙여넣거나 끌어다 놓아도 저장돼요</span></div>`;
  if (v === 'audio') return `<div class="quick"><button class="primary" data-act="rec">● 녹음 시작</button></div>`;
  if (v === 'trash') return `<div class="quick"><button data-act="emptyTrash">휴지통 비우기</button></div>`;
  return '';
}
const VIEW_TITLE = { home: '전체', fav: '즐겨찾기', trash: '휴지통', settings: '설정' };
function viewHTML() {
  const v = S.view;
  return `<header class="top"><button class="icon menu" data-act="drawer">☰</button><h1>${VIEW_TITLE[v] || KINDS[v][0]}</h1><span class="sp"></span>${v === 'settings' ? '' : `<input id="q" type="search" placeholder="검색" value="${esc(S.q)}">`}</header>
  <div class="page">${quickHTML()}<div id="list">${listHTML()}</div></div>`;
}
function editorHTML(e) {
  const k = e.kind, imgs = (e.atts || []).filter(a => a.type === 'image'), auds = (e.atts || []).filter(a => a.type === 'audio');
  return `<div class="editor"><header class="top"><button class="icon" data-act="back" title="뒤로">←</button>
  <select data-f="kind">${Object.entries(KINDS).map(([v, [n, i]]) => `<option value="${v}" ${v === k ? 'selected' : ''}>${i} ${n}</option>`).join('')}</select>
  <span class="sp"></span><span id="saved" class="muted"></span>
  <button class="icon ${e.fav ? 'on' : ''}" data-act="fav" title="즐겨찾기">${e.fav ? '★' : '☆'}</button>
  <button class="icon" data-act="focus" title="집중 모드 (Esc로 해제)">⛶</button>
  <button class="icon" data-act="trash" data-id="${e.id}" title="휴지통으로">🗑</button></header>
  <div class="page">
  <input class="title" data-f="title" placeholder="제목" value="${esc(e.title)}">
  <div class="quick meta">${['diary', 'todo', 'plan'].includes(k) ? `<label>${k === 'diary' ? '날짜' : '기한'} <input type="date" data-f="date" value="${esc(e.date || '')}"></label>` : ''}
  ${['link', 'image'].includes(k) ? `<input type="url" class="grow" data-f="url" placeholder="출처 주소 https://…" value="${esc(e.url || '')}">${safeUrl(e.url) ? `<a class="btn" href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">열기 ↗</a>` : ''}` : ''}</div>
  ${imgs.length ? `<div class="atts">${imgs.map(a => `<div class="att">${img(a)}<button class="icon del" data-act="delAtt" data-att="${a.id}" title="삭제">✕</button></div>`).join('')}</div>` : ''}
  ${auds.map(a => `<div class="rowitem">${audioBtn(a)}<span class="sp"></span><button class="icon" data-act="delAtt" data-att="${a.id}" title="삭제">✕</button></div>`).join('')}
  <textarea data-f="body" placeholder="${k === 'todo' ? '메모' : '여기에 쓰기 시작하세요…'}">${esc(e.body)}</textarea>
  <input data-f="tags" placeholder="태그 (쉼표로 구분)" value="${esc((e.tags || []).join(', '))}">
  <footer class="tools"><button data-act="addImg">🖼 이미지</button><button data-act="rec">🎙 녹음</button>${TEMPLATES[k] ? `<button data-act="template">📋 템플릿</button>` : ''}
  <span class="sp"></span><label class="muted">목표 <input type="number" min="0" step="100" data-f="goal" value="${e.goal || ''}" placeholder="0">자</label><span id="count" class="muted"></span></footer>
  </div></div>`;
}
function settingsHTML() {
  const v = S.vault, sc = S.cfg.sync;
  return `<section class="set"><h2>잠금</h2>
  <p>${v.pw ? '암호가 설정되어 있어요.' : '지금은 <b>암호 없이</b> 쓰는 중이에요. 내용은 기기 안에서 암호화되어 있지만, 이 기기를 여는 사람은 볼 수 있어요.'}</p>
  <div class="quick"><button data-act="setpw">${v.pw ? '암호 바꾸기' : '암호 설정'}</button>${v.pw ? `<button data-act="rmpw">암호 없애기</button><button data-act="lock">지금 잠그기</button>` : ''}</div>
  ${v.pw ? `<label>한 번 풀면 유지되는 시간 <select id="hours">${HOURS.map(([h, n]) => `<option value="${h}" ${h === S.cfg.hours ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
  ${bioOK() ? `<div class="quick"><button data-act="${S.bio ? 'bioOff' : 'bioOn'}">${S.bio ? '지문·얼굴 잠금 해제 끄기' : '지문·얼굴로 잠금 해제 켜기'}</button><span class="muted">이 기기에만 적용돼요. 암호는 그대로 쓸 수 있어요.</span></div>` : `<p class="muted small">지문·얼굴 잠금 해제는 https 주소나 localhost로 열었을 때만 쓸 수 있어요.</p>`}` : ''}
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
  <h2>설치</h2><p>Windows · Mac: Chrome/Edge 주소창 오른쪽의 설치 아이콘. iPhone/iPad: Safari 공유 → "홈 화면에 추가". Android: Chrome 메뉴 → "앱 설치". 설치 후에는 인터넷 없이도 열립니다.</p>
  ${S.installEvt ? `<div class="quick"><button class="primary" data-act="install">이 기기에 설치</button></div>` : ''}</section>`;
}
function render() {
  if (!S.key) return;
  const e = S.cur && cur(); if (S.cur && !e) S.cur = null;
  const count = k => { let n = 0; for (const x of S.entries.values()) if (!x.trashed && (k === 'fav' ? x.fav : x.kind === k) && !(k === 'todo' && x.done)) n++; return n || ''; };
  const nav = (v, label, n = '') => `<button class="nav ${S.view === v && !S.cur ? 'on' : ''}" data-act="nav" data-view="${v}">${label}<small>${n}</small></button>`;
  $('#app').innerHTML = `<div class="shell ${S.focus && e ? 'focus' : ''} ${S.drawer ? 'drawer' : ''}">
  <aside class="side"><div class="logo">담다</div>${nav('home', '🏠 전체')}${nav('fav', '⭐ 즐겨찾기', count('fav'))}<hr>
  ${Object.entries(KINDS).map(([k, [n, i]]) => nav(k, `${i} ${n}`, count(k))).join('')}<hr>${nav('trash', '🗑 휴지통')}${nav('settings', '⚙️ 설정')}
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
  const h = $('#hours'); if (h) h.onchange = async () => { S.cfg.hours = +h.value; await saveCfg(); await saveSession(); toast('저장했어요'); };
  $('#syncForm')?.addEventListener('submit', async ev => {
    ev.preventDefault(); S.cfg.sync = { url: ev.target.u.value.trim().replace(/\/+$/, ''), seq: 0 };
    await saveCfg(); await markAllDirty(); await sync(); refreshList();
  });
}

// ───────── 동작
async function goBack() { await flush(); const e = cur(); if (e && S.entries.has(e.id) && isEmpty(e)) await purgeEntry(e); S.cur = S.draft = null; S.focus = false; render(); }
const byId = id => S.entries.get(id);
const actions = {
  nav: async el => { await flush(); Object.assign(S, { view: el.dataset.view, cur: null, draft: null, q: '', tag: null, drawer: false, focus: false }); render(); },
  drawer: () => { S.drawer = !S.drawer; $('.shell').classList.toggle('drawer', S.drawer); },
  new: el => { S.draft = newEntry(el.dataset.kind); S.cur = S.draft.id; render(); },
  open: el => { S.cur = el.dataset.id; render(); window.scrollTo(0, 0); },
  back: goBack,
  fav: async () => { const e = cur(); if (!e) return; e.fav = !e.fav; await flush(); await putEntry(e); const b = $('[data-act=fav]'); b.textContent = e.fav ? '★' : '☆'; b.classList.toggle('on', e.fav); },
  focus: () => { S.focus = !S.focus; $('.shell').classList.toggle('focus', S.focus); },
  trash: async el => { await flush(); const e = byId(el.dataset.id); if (e) { e.trashed = true; await putEntry(e); toast('휴지통으로 옮겼어요'); } S.cur = S.draft = null; render(); },
  restore: async el => { const e = byId(el.dataset.id); delete e.trashed; await putEntry(e); render(); },
  purge: async el => { if (confirm('영구 삭제할까요? 되돌릴 수 없어요.')) { await purgeEntry(byId(el.dataset.id)); render(); } },
  emptyTrash: async () => { const a = [...S.entries.values()].filter(e => e.trashed); if (a.length && confirm(`${a.length}개를 영구 삭제할까요? 되돌릴 수 없어요.`)) { for (const e of a) await purgeEntry(e); render(); } },
  toggle: async el => { const e = byId(el.dataset.id); e.done = el.checked; await putEntry(e); refreshList(); },
  tag: el => { S.tag = el.dataset.tag; S.cur = null; render(); },
  cleartag: () => { S.tag = null; refreshList(); },
  addImg: async () => { const t = S.cur && cur(); if (t) await flush(); addImages(await pickFiles('image/*'), t || null); },
  imgUrl: async () => {
    const r = await ask({ title: '이미지 주소로 저장', fields: [{ name: 'u', label: '이미지 주소', placeholder: 'https://…' }] }); if (!r || !safeUrl(r.u)) return;
    try { const b = await (await fetch(r.u)).blob(); if (!b.type.startsWith('image/')) throw 0; await putEntry(newEntry('image', { url: r.u, atts: [{ id: await putBlob(b), type: 'image', mime: b.type }] })); render(); }
    catch { toast('이 사이트는 직접 저장을 막아두었어요. 이미지를 복사해서 붙여넣어 보세요.'); }
  },
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
  delAtt: async el => { const e = cur(); if (!e || !confirm('첨부를 삭제할까요?')) return; await flush(); e.atts = e.atts.filter(a => a.id !== el.dataset.att); await tomb('blobs', el.dataset.att); await putEntry(e); render(); },
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
document.addEventListener('paste', ev => { if (!S.key) return; const fs = [...(ev.clipboardData?.files || [])]; if (fs.some(f => f.type.startsWith('image/'))) { ev.preventDefault(); addImages(fs, S.cur ? cur() : null); } });
document.addEventListener('dragover', ev => { if (S.key && ev.dataTransfer?.types.includes('Files')) ev.preventDefault(); });
document.addEventListener('drop', ev => { if (!S.key || !ev.dataTransfer?.files.length) return; ev.preventDefault(); addImages([...ev.dataTransfer.files], S.cur ? cur() : null); });
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
