// Cho CTF Workspace - UI logic.
const api = window.cho;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// ======================================================================
// state
// ======================================================================
const S = {
  status: null, settings: {}, catalog: [], list: [],
  dir: null, ch: null,                 // open challenge folder + its challenge.json data
  tree: [], collapsed: new Set(), sel: null, vtab: 'preview', hexOffset: 0,
  images: [], busy: false, chatId: null,
  agent: { running: false, paused: false, waiting: false, steps: 0 },
  term: { cwd: '', hist: [], idx: 0 },
  runningIds: new Set(),
  findingIdx: 0,
};

let seq = 0;
const uid = (p) => `${p}-${Date.now()}-${seq++}`;
const dataHandlers = {};
const tokenHandlers = {};
api.onData(({ id, chunk }) => dataHandlers[id]?.(chunk));
api.onToken(({ id, token }) => tokenHandlers[id]?.(token));

const trunc = (s, n) => (s.length > n ? `${s.slice(0, n)}\n…[truncated ${s.length - n} chars]` : s);
const shq = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
const psq = (s) => `'${String(s).replace(/'/g, "''")}'`;
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
};
const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

function toast(msg, ms = 2600) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove('show'), ms);
}

// ======================================================================
// Cho avatar
// ======================================================================
function choSvg() { return $('#cho-tpl').content.firstElementChild.cloneNode(true); }
$$('[data-cho]').forEach((c) => c.append(choSvg()));

function mood(m, ms) {
  $('#cho-main').dataset.mood = m;
  $('#cho-status').textContent = { idle: 'ready', thinking: 'thinking…', talking: 'talking…', happy: 'found something!', error: 'hmm, something went wrong' }[m] || m;
  clearTimeout(mood.t);
  if (ms) mood.t = setTimeout(() => mood(S.busy ? 'thinking' : 'idle'), ms);
}
function say(text, ms = 9000) {
  const b = $('#cho-bubble');
  b.textContent = text;
  b.classList.add('show');
  clearTimeout(say.t);
  if (ms) say.t = setTimeout(() => b.classList.remove('show'), ms);
}
$('#cho-bubble').addEventListener('click', () => $('#cho-bubble').classList.remove('show'));

function aiReady() { return S.status?.ollama.ok && currentModel(); }
function currentModel() {
  const models = S.status?.ollama.models || [];
  return models.includes(S.settings.model) ? S.settings.model : models[0] || null;
}
function greeting() {
  if (!S.ch) return "Hi, I'm Cho!  Create a challenge (or just drop the files on me) and tell me what the question is.";
  if (!S.ch.description && !Object.keys(S.ch.analyses).length) {
    return "Hi, I'm Cho! What's the challenge? Paste the question above, drop the files / zip / pcap / link, then ask me anything.";
  }
  if (!aiReady()) return "My AI brain (Ollama) isn't running yet, but I can still analyse files. Set it up from Overview → Environment setup.";
  return `What should we try next on "${S.ch.name}"?`;
}
$('#cho-main').addEventListener('click', () => {
  mood('talking', 1200);
  say(greeting());
  $('#chat-input').focus();
});

// ======================================================================
// environment status
// ======================================================================
function shellMode() {
  const pref = S.settings.shell || 'auto';
  if (pref === 'container') return S.status?.container?.ok && S.status.container.imageReady ? 'container' : 'powershell';
  if (pref === 'wsl') return 'wsl';
  if (pref === 'powershell') return 'powershell';
  return S.status?.wsl.ok ? 'wsl' : 'powershell';
}

async function refreshStatus() {
  $('#env-pill').textContent = '● checking…';
  $('#env-pill').className = 'pill';
  S.status = await api.status();
  S.settings = S.status.settings;
  const { wsl, ollama, python } = S.status;
  const pill = $('#env-pill');
  if (wsl.ok && aiReady()) { pill.className = 'pill ok'; pill.textContent = '● Sandbox ready'; }
  else if (aiReady()) { pill.className = 'pill warn'; pill.textContent = '● Kali tools missing'; }
  else if (wsl.ok) { pill.className = 'pill warn'; pill.textContent = '● AI offline'; }
  else { pill.className = 'pill warn'; pill.textContent = '● Setup needed'; }
  pill.title = `Kali/WSL: ${wsl.ok ? `${wsl.distro} (${wsl.tools.length} tools)` : 'not installed'}\nOllama: ${ollama.ok ? `${ollama.models.length} model(s)` : 'offline'}\nPython: ${python.ok ? python.version : 'not found'}\nClick for setup.`;

  $('#sb-tools').innerHTML = wsl.ok
    ? `<span class="on">▣</span> Local tools: ${esc(wsl.distro)} · ${wsl.tools.length} tools`
    : `▣ Local tools: PowerShell${python.ok ? ' + Python' : ''} <span class="dim">(Kali not installed)</span>`;
  $('#sb-ws').innerHTML = '<span class="on">●</span> Isolated workspace';
  $('#sb-ws').title = S.status.workspace;
  $('#sb-model').textContent = aiReady() ? `model: ${currentModel()}` : 'model: AI offline';
  updateShellLabel();
  renderOverview();
  renderSettings();
  if (S.catalog.length) renderToolbox();
}
$('#btn-refresh').addEventListener('click', refreshStatus);
$('#env-pill').addEventListener('click', () => showView('overview'));

// ======================================================================
// views
// ======================================================================
function showView(name) {
  $$('.sidenav button').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  if (name === 'files') renderFilesView();
  if (name === 'toolbox') renderToolbox();
  if (name === 'overview') renderOverview();
  if (name === 'challenges' && !S.ch) showChallengeList();
}
$$('.sidenav button').forEach((b) => b.addEventListener('click', () => {
  if (b.dataset.view === 'challenges' && S.ch && $('#view-challenges').classList.contains('active')) showChallengeList();
  else showView(b.dataset.view);
}));

// ======================================================================
// challenges: list, open, create, save
// ======================================================================
async function loadList() {
  S.list = await api.listChallenges();
  const sel = $('#ch-select');
  sel.innerHTML = '';
  const add = (v, t) => { const o = el('option', null, t); o.value = v; sel.append(o); };
  if (!S.ch) add('', '— No challenge open —');
  for (const c of S.list) add(c.dir, `${c.solved ? '✓ ' : ''}${c.name}`);
  add('__new', '＋ New challenge…');
  add('__all', '☰ All challenges');
  sel.value = S.dir || '';
}
$('#ch-select').addEventListener('change', async (e) => {
  const v = e.target.value;
  if (v === '__new') await newChallenge();
  else if (v === '__all') { showView('challenges'); showChallengeList(); }
  else if (v) await openChallenge(v);
  e.target.value = S.dir || '';
});

function showChallengeList() {
  $('#ch-list').classList.remove('hidden');
  $('#workbench').classList.add('hidden');
  const cards = $('#ch-cards');
  cards.innerHTML = '';
  if (!S.list.length) {
    const e = el('div', 'empty');
    const c = el('div', 'cho-big');
    c.dataset.mood = 'idle';
    c.append(choSvg());
    e.append(c, el('div', null, 'No challenges yet. Click "New challenge", or drop challenge files anywhere in this window.'));
    cards.style.display = 'block';
    cards.append(e);
    return;
  }
  cards.style.display = '';
  for (const c of S.list) {
    const card = el('div', `ch-card${c.solved ? ' solved' : ''}`);
    card.innerHTML = `<div class="nm"></div><div class="chips"><span class="chip c-purple"></span><span class="chip c-amber"></span><span class="chip c-green"></span></div><div class="dim small" style="margin-top:8px"></div>`;
    $('.nm', card).textContent = `${c.solved ? '✓ ' : ''}${c.name}`;
    const chips = $$('.chip', card);
    chips[0].textContent = c.category === 'auto' ? 'auto' : c.category;
    chips[1].textContent = c.difficulty;
    chips[2].textContent = `${c.points || 0} pts`;
    $('.dim', card).textContent = `${c.files} file(s) · ${c.flags || 0} flag candidate(s) · ${new Date(c.created).toLocaleString()}`;
    card.onclick = () => openChallenge(c.dir);
    cards.append(card);
  }
}
$('#crumb-all').addEventListener('click', (e) => { e.preventDefault(); showChallengeList(); });
$('#btn-new-ch').addEventListener('click', () => newChallenge());

async function newChallenge(name) {
  const r = await api.createChallenge(name || 'New challenge');
  await loadList();
  await openChallenge(r.dir);
  if (!name) { $('#ch-title').focus(); $('#ch-title').select(); }
  say("New challenge! Name it, paste the question, and drop the files in. Then click me or just ask.");
}

async function openChallenge(dir) {
  const data = await api.loadChallenge(dir);
  if (!data) { toast('Could not open that challenge'); return; }
  await saveNow();
  stopAgent();
  S.dir = dir;
  S.ch = Object.assign({ flags: [], analyses: {}, messages: [], plan: [], findings: [], progress: {}, mode: 'guided' }, data);
  S.sel = null;
  S.term.cwd = '';
  S.findingIdx = 0;
  store.set('cho.lastDir', dir);
  $('#ch-title').value = S.ch.name;
  $('#ch-category').value = S.ch.category || 'auto';
  $('#ch-difficulty').value = S.ch.difficulty || 'medium';
  $('#ch-points').value = S.ch.points || 0;
  $('#ch-flagfmt').value = S.ch.flagFormat || '';
  $('#ch-targets').value = S.ch.targets || '';
  $('#ch-desc').value = S.ch.description || '';
  $('#flag-input').value = S.ch.solvedFlag || S.ch.flags[0] || '';
  $('#term-log').textContent = '';
  $('#out-log').textContent = '';
  $('#py-out').textContent = '';
  $('#py-editor').value = (await api.readText(dir, 'solve.py')) || PY_TEMPLATE;
  $('#notes').value = await api.readText(dir, 'notes.md');
  setMode(S.ch.mode || 'guided', true);
  updateCrumb();
  updateSolved();
  updateFlagList();
  renderChat();
  renderPlan();
  renderFinding();
  updateCtxChips();
  updateShellLabel();
  await refreshTree();
  const first = Object.keys(S.ch.analyses)[0];
  if (first) selectFile(first); else renderViewer();
  $('#ch-list').classList.add('hidden');
  $('#workbench').classList.remove('hidden');
  showView('challenges');
  await loadList();
}

let saveTimer;
function saveNow() {
  clearTimeout(saveTimer);
  if (!S.dir) return Promise.resolve();
  const data = { ...S.ch, messages: S.ch.messages.slice(-200).map(({ images, ...m }) => m) };
  return api.saveChallenge(S.dir, data);
}
function scheduleSave() {
  if (!S.dir) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNow, 500);
}

function bindField(id, key, transform = (v) => v, after) {
  $(id).addEventListener('input', (e) => {
    if (!S.ch) return;
    S.ch[key] = transform(e.target.value);
    scheduleSave();
    after?.();
  });
}
bindField('#ch-title', 'name', (v) => v, () => { clearTimeout(bindField.t); bindField.t = setTimeout(loadList, 800); });
bindField('#ch-category', 'category', (v) => v, () => { updateCrumb(); renderPlan(); });
bindField('#ch-difficulty', 'difficulty');
bindField('#ch-points', 'points', (v) => Number(v) || 0);
bindField('#ch-flagfmt', 'flagFormat');
bindField('#ch-targets', 'targets');
bindField('#ch-desc', 'description', (v) => v, updateCtxChips);
$('#ch-category').addEventListener('change', (e) => e.target.dispatchEvent(new Event('input')));
$('#ch-difficulty').addEventListener('change', (e) => e.target.dispatchEvent(new Event('input')));

function updateCrumb() {
  const c = S.ch?.category;
  $('#crumb-cat').textContent = !c || c === 'auto' ? 'Auto-detect' : c[0].toUpperCase() + c.slice(1);
}
function updateSolved() { $('#solved-badge').classList.toggle('hidden', !S.ch?.solved); }

async function ensureChallenge(nameHint) {
  if (S.dir) return;
  await newChallenge(nameHint || 'New challenge');
}

// ======================================================================
// importing files (drag & drop anywhere, import button, paperclip)
// ======================================================================
let dragDepth = 0;
window.addEventListener('dragenter', (e) => { if (e.dataTransfer?.types.includes('Files')) { dragDepth++; $('#drop-overlay').classList.remove('hidden'); } });
window.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) $('#drop-overlay').classList.add('hidden'); });
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  $('#drop-overlay').classList.add('hidden');
  const paths = [...(e.dataTransfer?.files || [])].map((f) => api.pathForFile(f)).filter(Boolean);
  if (paths.length) addPaths(paths);
});
$('#btn-import').addEventListener('click', async () => addPaths(await api.pickFiles()));
$('#btn-attach').addEventListener('click', async () => addPaths(await api.pickFiles()));

function slim(a) {
  const { preview, text, ...rest } = a;
  if (text) rest.textHints = { hashes: text.hashes, hints: text.hints, decodes: text.decodes.slice(0, 3).map((d) => ({ method: d.method, output: d.output.slice(0, 300) })) };
  rest.interesting = (a.interesting || []).slice(0, 25);
  return rest;
}

async function addPaths(paths) {
  if (!paths?.length) return;
  await ensureChallenge(paths[0].split(/[\\/]/).pop().replace(/\.[^.]+$/, ''));
  mood('thinking');
  say(`Looking at ${paths.length} item${paths.length > 1 ? 's' : ''}…`, 0);
  const r = await api.addFiles(S.dir, paths, S.ch.flagFormat);
  const ok = [];
  for (const a of r.added) {
    if (a.error) { toast(`${a.name}: ${a.error}`, 5000); continue; }
    S.ch.analyses[a.rel] = slim(a);
    ok.push(a);
    findingsFromAnalysis(a);
    for (const f of a.flags || []) addFlag(f, a.rel, true);
  }
  for (const n of r.notes) {
    if (n.error) { note(`[zip] ${n.zip}: ${n.error}`); continue; }
    note(`[zip] Extracted ${n.count} file(s) from **${n.zip}** into \`${n.extractedTo}/\`${n.skipped.length ? ` (skipped ${n.skipped.length}: ${n.skipped.slice(0, 3).map((s) => `${s.name} — ${s.reason}`).join('; ')})` : ''}`);
    if (n.encrypted) addFinding(`${n.zip} has password-protected entries: try zip2john + john / fcrackzip`, n.zip, 'preview');
    if (n.comment) addFinding(`${n.zip} has a zip comment: "${n.comment.slice(0, 120)}"`, n.zip, 'strings');
  }
  S.ch.progress.identified = true;
  await refreshTree();
  renderPlan();
  updateCtxChips();
  scheduleSave();
  if (ok.length) {
    const pick = ok.find((a) => /image/i.test(a.type)) || ok[0];
    selectFile(pick.rel);
    const extra = ok.some((a) => a.embedded?.length) ? ' I can see hidden data in there too ' : '';
    say(`Got it! ${ok.length} file(s). ${pick.rel} looks like ${pick.type} (${pick.category}).${extra} Ask me to dig in!`);
    note(`[+] Added ${ok.length} file(s): ${ok.slice(0, 6).map((a) => `${a.rel} (${a.type})`).join(', ')}${ok.length > 6 ? '…' : ''}`);
    mood(ok.some((a) => a.flags?.length) ? 'happy' : 'idle', 2500);
  } else {
    mood('error', 2500);
  }
}

// ======================================================================
// file tree
// ======================================================================
async function refreshTree() {
  if (!S.dir) return;
  S.tree = await api.tree(S.dir);
  renderTree();
}
let treeRefreshTimer;
function refreshTreeSoon() { clearTimeout(treeRefreshTimer); treeRefreshTimer = setTimeout(refreshTree, 400); }
$('#show-hidden').addEventListener('change', renderTree);

function fileIcon(n) {
  if (n.dir) return S.collapsed.has(n.rel) ? '+' : '-';
  const x = n.name.toLowerCase();
  if (/\.(png|jpe?g|gif|bmp|webp|tiff?)$/.test(x)) return 'i';
  if (/\.(zip|rar|7z|gz|tgz|tar|xz|bz2)$/.test(x)) return 'z';
  if (/\.(pcapng?|cap)$/.test(x)) return '%';
  if (/\.(wav|mp3|flac|ogg)$/.test(x)) return '~';
  if (/\.pdf$/.test(x)) return 'p';
  if (/\.(txt|md|csv|log|json|xml|html?|py|c|js|php)$/.test(x)) return '=';
  if (/\.(raw|mem|vmem|dmp|img|dd|e01)$/.test(x)) return 'd';
  return '#';
}

function renderTree() {
  const box = $('#tree');
  box.innerHTML = '';
  const showHidden = $('#show-hidden').checked;
  const walk = (nodes, depth) => {
    for (const n of nodes) {
      const hidden = n.name.startsWith('.');
      if (hidden && !showHidden) continue;
      const row = el('div', `tnode${S.sel === n.rel ? ' sel' : ''}${hidden ? ' hiddenfile' : ''}`);
      row.style.paddingLeft = `${8 + depth * 16}px`;
      row.title = n.dir ? n.rel : `${n.rel} (${fmtSize(n.size)})`;
      row.append(el('span', 'car', n.dir ? (S.collapsed.has(n.rel) ? '▸' : '▾') : ''), el('span', 'fi', fileIcon(n)), el('span', 'nm', n.name));
      row.onclick = () => {
        if (n.dir) { S.collapsed.has(n.rel) ? S.collapsed.delete(n.rel) : S.collapsed.add(n.rel); renderTree(); }
        else selectFile(n.rel);
      };
      box.append(row);
      if (n.dir && !S.collapsed.has(n.rel)) walk(n.children, depth + 1);
    }
  };
  walk(S.tree, 0);
  if (!box.children.length) box.append(el('div', 'dim small', '  No files yet. Import or drop some.'));
}

function flatFiles(nodes = S.tree, acc = []) {
  for (const n of nodes) { if (n.dir) flatFiles(n.children, acc); else acc.push(n); }
  return acc;
}

// ======================================================================
// viewer: preview / hex / metadata / strings
// ======================================================================
$$('.vtabs button').forEach((b) => b.addEventListener('click', () => { S.vtab = b.dataset.vtab; renderViewer(); }));

async function selectFile(rel, tab) {
  S.sel = rel;
  S.hexOffset = 0;
  if (tab) S.vtab = tab;
  renderTree();
  if (!S.ch.analyses[rel]) {
    try {
      const a = await api.analyzeFile(S.dir, rel, S.ch.flagFormat);
      S.ch.analyses[rel] = slim(a);
      findingsFromAnalysis(a);
      for (const f of a.flags || []) addFlag(f, rel, true);
      updateCtxChips();
      scheduleSave();
    } catch { /* file vanished */ }
  }
  renderViewer();
}

let viewerToken = 0;
async function renderViewer() {
  $$('.vtabs button').forEach((b) => b.classList.toggle('active', b.dataset.vtab === S.vtab));
  const body = $('#viewer-body');
  const token = ++viewerToken;
  $('#vfile').textContent = S.sel || '';
  if (!S.ch || !S.sel) {
    body.innerHTML = '<div class="placeholder">Select a file on the left, or drop challenge files (zip, image, pcap, binary…) anywhere.</div>';
    return;
  }
  const a = S.ch.analyses[S.sel] || {};
  body.innerHTML = '<div class="placeholder">Loading…</div>';
  try {
    if (S.vtab === 'preview') {
      const r = await api.readFile(S.dir, S.sel, 'preview');
      if (token !== viewerToken) return;
      body.innerHTML = '';
      body.append(previewView(r, a));
    } else if (S.vtab === 'hex') {
      const r = await api.readFile(S.dir, S.sel, 'hex', S.hexOffset);
      if (token !== viewerToken) return;
      body.innerHTML = '';
      body.append(hexView(r));
    } else if (S.vtab === 'meta') {
      S.ch.progress.meta = true;
      renderPlan();
      const r = await api.readFile(S.dir, S.sel, 'meta');
      if (token !== viewerToken) return;
      body.innerHTML = '';
      body.append(metaView(r.meta, a));
    } else {
      const r = await api.readFile(S.dir, S.sel, 'strings');
      if (token !== viewerToken) return;
      body.innerHTML = '';
      body.append(stringsView(r.strings));
    }
  } catch (err) {
    body.innerHTML = '';
    body.append(el('div', 'placeholder', `Can't read this file: ${err.message}`));
  }
}

function kvTable(rows) {
  const t = el('table', 'kv');
  for (const [k, v] of rows) {
    const tr = el('tr');
    tr.append(el('td', null, k), el('td', null, v));
    t.append(tr);
  }
  return t;
}
function sideBox(title, children) {
  const b = el('div', 'side-box');
  b.append(el('h4', null, title), ...children);
  return b;
}

function previewView(r, a) {
  const wrap = el('div', 'pv');
  const main = el('div', 'pv-main');
  if (r.kind === 'image') { const img = el('img'); img.src = r.src; main.append(img); }
  else if (r.kind === 'text') { const pre = el('pre', null, r.text + (r.truncated ? '\n…(truncated, open Strings or the terminal for more)' : '')); main.append(pre); }
  else main.append(el('div', 'placeholder', 'Binary file: look at the Hex and Strings tabs, or ask Cho.'));
  const side = el('div');
  side.append(sideBox('File', [kvTable([
    ['File', S.sel.split('/').pop()], ['Size', a.sizeText || fmtSize(r.size)], ['Type', a.type || '?'],
    ['Category', a.category || '?'], ['Entropy', a.entropy != null ? `${a.entropy} / 8` : '?'],
    ['MD5', a.md5 || ''], ['SHA-256', a.sha256 ? `${a.sha256.slice(0, 24)}…` : ''],
  ])]));
  const warns = [];
  for (const f of a.flags || []) warns.push(el('div', 'flag-line', `[FLAG] ${f}`));
  for (const e of a.embedded || []) warns.push(el('div', 'warn-line', `⚠ ${e.type} @ 0x${e.offset.toString(16)}`));
  for (const w of a.meta?.warnings || []) warns.push(el('div', 'warn-line', `⚠ ${w}`));
  if (a.entropy > 7.5 && !/zip|compress|archive|7-zip|gzip|png|jpeg/i.test(a.type || '')) warns.push(el('div', 'warn-line', '⚠ Very high entropy: encrypted or compressed data'));
  if (warns.length) side.append(sideBox('Findings', warns));
  if ((a.suggestions || []).length) {
    const rows = [];
    if (shellMode() === 'powershell') rows.push(el('div', 'warn-line', 'These need Kali (WSL). Install it from Overview.'));
    for (const cmd of a.suggestions) {
      const row = el('div', 'sugg');
      const c = el('code', null, cmd);
      c.title = cmd;
      const b = el('button', null, '▶');
      b.title = 'Run it (output goes to Cho)';
      b.disabled = shellMode() === 'powershell';
      b.onclick = () => runCommand(cmd, { origin: 'user' });
      row.append(c, b);
      rows.push(row);
    }
    side.append(sideBox('Suggested commands', rows));
  }
  wrap.append(main, side);
  return wrap;
}

function hexView(r) {
  const bytes = Uint8Array.from(atob(r.bytes), (c) => c.charCodeAt(0));
  const wrap = el('div');
  const nav = el('div', 'row');
  const prev = el('button', null, '◀ Prev');
  const next = el('button', null, 'Next ▶');
  const jump = el('input');
  jump.placeholder = 'go to offset (0x…)';
  jump.style.width = '170px';
  prev.disabled = r.offset === 0;
  next.disabled = r.offset + bytes.length >= r.size;
  prev.onclick = () => { S.hexOffset = Math.max(0, r.offset - 4096); renderViewer(); };
  next.onclick = () => { S.hexOffset = r.offset + 4096; renderViewer(); };
  jump.onkeydown = (e) => {
    if (e.key !== 'Enter') return;
    const v = parseInt(jump.value, jump.value.startsWith('0x') ? 16 : 10);
    if (!Number.isNaN(v)) { S.hexOffset = Math.max(0, Math.min(r.size - 1, v - (v % 16))); renderViewer(); }
  };
  nav.append(prev, next, jump, el('span', 'dim small', `0x${r.offset.toString(16)}–0x${(r.offset + bytes.length).toString(16)} of ${fmtSize(r.size)}`));
  const pre = el('pre', 'hexdump');
  let html = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = [...row].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    html += `<span class="o">${(r.offset + i).toString(16).padStart(8, '0')}</span>  ${hex}  <span class="a">${esc(ascii)}</span>\n`;
  }
  pre.innerHTML = html;
  wrap.append(nav, pre);
  return wrap;
}

function metaView(m, a) {
  const wrap = el('div', 'pv');
  const left = el('div');
  if (m) {
    left.append(sideBox(`${m.format} metadata`, [m.fields.length ? kvTable(m.fields) : el('div', 'warn-line', 'No metadata fields found')]));
    if (m.warnings.length) left.append(sideBox('Anomalies', m.warnings.map((w) => el('div', 'warn-line', `⚠ ${w}`))));
  } else {
    left.append(el('div', 'placeholder', 'No built-in metadata parser for this type. Use exiftool (Kali) for the full picture.'));
  }
  const right = el('div');
  if (m?.chunks.length) right.append(sideBox('Structure', [el('pre', 'strings-list', m.chunks.join('\n'))]));
  const b = el('button', 'wide', '▶ Run exiftool (full metadata)');
  b.disabled = shellMode() === 'powershell';
  b.title = b.disabled ? 'Needs Kali (WSL)' : '';
  b.onclick = () => runCommand(`exiftool ${shq(S.sel)}`, { origin: 'user' });
  right.append(b);
  if (a.interesting?.length) right.append(sideBox('Interesting strings', [el('pre', 'strings-list', a.interesting.join('\n'))]));
  wrap.append(left, right);
  return wrap;
}

function stringsView(strings) {
  const wrap = el('div');
  const bar = el('div', 'row');
  const filter = el('input');
  filter.placeholder = 'filter (regex)…';
  filter.style.flex = '1';
  const minLen = el('select');
  for (const n of [4, 6, 8, 12]) { const o = el('option', null, `min ${n}`); o.value = n; minLen.append(o); }
  minLen.value = 6;
  const count = el('span', 'dim small');
  bar.append(filter, minLen, count);
  const pre = el('pre', 'strings-list');
  const flagRe = /[A-Za-z0-9_]{2,24}\{[^\s{}]{3,160}\}/;
  const draw = () => {
    let re = null;
    try { re = filter.value ? new RegExp(filter.value, 'i') : null; } catch { re = null; }
    const list = strings.filter((s) => s.length >= Number(minLen.value) && (!re || re.test(s)));
    count.textContent = `${list.length} strings`;
    pre.innerHTML = list.slice(0, 3000).map((s) => (flagRe.test(s) ? `<mark>${esc(s)}</mark>` : esc(s))).join('\n');
  };
  filter.oninput = draw;
  minLen.onchange = draw;
  draw();
  wrap.append(bar, pre);
  return wrap;
}

$('#act-meta').addEventListener('click', () => { if (!S.sel) return; S.vtab = 'meta'; renderViewer(); });
$('#act-strings').addEventListener('click', () => { if (!S.sel) return; S.vtab = 'strings'; renderViewer(); });
$('#act-analyze').addEventListener('click', () => {
  if (!S.ch) return;
  const what = S.sel ? `the file \`${S.sel}\`` : 'the challenge files';
  sendMessage(`Analyze ${what} and work through the challenge.`);
});

// ======================================================================
// dock: terminal / python / output + command runner
// ======================================================================
$$('.dtabs button[data-dtab]').forEach((b) => b.addEventListener('click', () => showDock(b.dataset.dtab)));
function showDock(name) {
  $$('.dtabs button[data-dtab]').forEach((x) => x.classList.toggle('active', x.dataset.dtab === name));
  $$('.dpane').forEach((p) => p.classList.toggle('active', p.id === `dock-${name}`));
}
$('#dock-clear').addEventListener('click', () => {
  const active = $('.dpane.active');
  $$('pre', active).forEach((p) => { p.textContent = ''; });
});
$('#dock-kill').addEventListener('click', () => { for (const id of S.runningIds) api.kill(id); });
$('#sb-activity').addEventListener('click', () => { showView('challenges'); if (S.ch) showDock('output'); });

function updateShellLabel() {
  const sh = shellMode();
  $('#shell-label').textContent = sh === 'container' ? `container · ${S.status.container.engine} · network off unless target authorised`
    : sh === 'wsl' ? `bash · ${S.status?.wsl.distro || 'WSL'}` : 'PowerShell (no container engine or Kali)';
  // Kali-style two-line prompt for bash shells.
  const here = `${S.ch ? S.ch.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'challenge' : '~'}${S.term.cwd ? `/${S.term.cwd}` : ''}`;
  $('#term-prompt').textContent = sh === 'container' ? `┌──(ctf㉿sandbox)-[/work${S.term.cwd ? `/${S.term.cwd}` : ''}]\n└─$`
    : sh === 'wsl' ? `┌──(cho㉿kali)-[~/${here}]\n└─$`
      : `PS ${S.term.cwd ? `.\\${S.term.cwd.replace(/\//g, '\\')}` : '.'}>`;
  document.documentElement.style.setProperty('--prompt-ch', String($('#term-prompt').textContent.split('\n').pop().length + 1));
  document.documentElement.style.setProperty('--win-title', JSON.stringify(sh === 'powershell' ? 'Windows PowerShell' : `cho@${sh === 'container' ? 'sandbox' : 'kali'}: ~/${here}`));
}

function append(pre, text, cls) {
  const s = el('span', cls, text);
  pre.append(s);
  if (pre.childNodes.length > 4000) pre.firstChild.remove();
  pre.scrollTop = pre.scrollHeight;
}

// Low-level: run a command in the challenge folder, streaming to `sink`.
async function runProc(cmd, { origin = 'user', sink, cwd = '' } = {}) {
  await ensureChallenge();
  const sh = shellMode();
  const full = cwd ? (sh !== 'powershell' ? `cd ${shq(cwd)} && ${cmd}` : `Set-Location -LiteralPath ${psq(cwd)}; ${cmd}`) : cmd;
  const id = uid('p');
  S.runningIds.add(id);
  $('#dock-kill').classList.remove('hidden');
  dataHandlers[id] = sink;
  const r = await api.run({ id, cmd: full, dir: S.dir, shell: sh, origin });
  delete dataHandlers[id];
  S.runningIds.delete(id);
  if (!S.runningIds.size) $('#dock-kill').classList.add('hidden');
  scanForFlags(r.output, 'command output');
  if (/\b(exiftool)\b/.test(cmd)) S.ch.progress.meta = true;
  if (/\b(binwalk|foremost|zsteg|steghide|stegseek|scalpel|bulk_extractor)\b/.test(cmd)) S.ch.progress.embedded = true;
  renderPlan();
  refreshTreeSoon();
  return r;
}

// High-level: run a command for Cho (tool card in chat + Output pane + message history).
async function runCommand(cmd, { origin = 'user' } = {}) {
  if (!S.ch) { toast('Open a challenge first'); return null; }
  const card = el('div', 'toolrun');
  card.innerHTML = '<div class="bar"><span class="c"></span><span class="s">running…</span></div><pre></pre>';
  $('.c', card).textContent = `$ ${cmd}`;
  $('.bar', card).onclick = () => card.classList.toggle('collapsed');
  const pre = $('pre', card);
  $('#chat').append(card);
  scrollChat();
  const out = $('#out-log');
  append(out, `\n[${origin === 'agent' ? 'cho-agent' : 'you'}] $ ${cmd}\n`, 'cmd');
  mood('thinking');
  const r = await runProc(cmd, {
    origin,
    sink: (chunk) => { pre.textContent += chunk; pre.scrollTop = pre.scrollHeight; append(out, chunk); scrollChat(); },
  });
  $('.s', card).textContent = `exit ${r.code}`;
  if (!r.output.trim()) pre.textContent = '(no output)';
  if (r.output.length > 600) card.classList.add('collapsed');
  pushMsg({ role: 'user', kind: 'tool', cmd, code: r.code, content: `[${origin === 'agent' ? 'Agent ran' : 'I ran'}] $ ${cmd}\n(exit ${r.code})\n\`\`\`\n${trunc(r.output || '(no output)', 6000)}\n\`\`\`` });
  if (!S.busy) mood('idle');
  return r;
}

// ----- terminal -----
$('#term-input').addEventListener('keydown', async (e) => {
  const input = e.target;
  const T = S.term;
  if (e.key === 'ArrowUp' && T.hist.length) { T.idx = Math.max(0, T.idx - 1); input.value = T.hist[T.idx]; e.preventDefault(); return; }
  if (e.key === 'ArrowDown' && T.hist.length) { T.idx = Math.min(T.hist.length, T.idx + 1); input.value = T.hist[T.idx] || ''; e.preventDefault(); return; }
  if (e.key !== 'Enter') return;
  const cmd = input.value.trim();
  input.value = '';
  const log = $('#term-log');
  if (!cmd) return;
  T.hist.push(cmd);
  T.idx = T.hist.length;
  append(log, `${$('#term-prompt').textContent} ${cmd}\n`, 'cmd');
  if (cmd === 'clear' || cmd === 'cls') { log.textContent = ''; return; }
  // ---- console built-ins: the same prompt runs shell commands and talks to Cho ----
  if (cmd === 'help') {
    append(log, [
      'CONSOLE COMMANDS',
      '  <any shell command>     run it in the challenge folder (nmap, gobuster, curl ... for a box)',
      '  fetch <url>             download an authorised page/file into the challenge and scan it',
      '  target <host[:port]>    add an authorised target (HTB box IP, challenge URL host)',
      '  ? <question>            ask Cho (same as: cho <question>)',
      '  mode hint|guided|agent  switch how Cho works',
      '  solve                   agent mode: Cho works the challenge, you approve network steps',
      '  flag <value>            record a flag and mark the challenge solved',
      '  new <name>              start a new challenge',
      '  clear                   clear the screen',
      '', ''].join('\n'), 'info');
    return;
  }
  const ask = /^(?:\?|cho[:,]?(?=\s))\s*(.+)$/is.exec(cmd);
  const modeCmd = /^mode\s+(hint|guided|agent)$/i.exec(cmd);
  const flagCmd = /^flag\s+(\S.*)$/i.exec(cmd);
  const newCmd = /^new\s+(.+)$/i.exec(cmd);
  const fetchCmd = /^fetch\s+(\S+)$/i.exec(cmd);
  const targetCmd = /^target\s+(\S.*)$/i.exec(cmd);
  if (targetCmd) {
    if (!S.ch) { append(log, 'Open a challenge first.\n', 'err'); return; }
    const t = $('#ch-targets');
    t.value = `${t.value ? `${t.value.trim()} ` : ''}${targetCmd[1].trim()}`;
    t.dispatchEvent(new Event('input'));
    await saveNow();
    append(log, `[*] authorised targets: ${t.value}\n`, 'info');
    return;
  }
  if (newCmd) { await newChallenge(newCmd[1].trim()); append(log, `[+] challenge created: ${S.ch.name}\n`, 'info'); return; }
  if (fetchCmd) {
    await ensureChallenge();
    append(log, `[*] fetching ${fetchCmd[1]} ...\n`, 'info');
    const r = await api.fetchUrl(S.dir, fetchCmd[1]);
    if (!r.ok) { append(log, `[x] fetch failed: ${r.error}\n`, 'err'); return; }
    if (r.authorised) append(log, `[*] authorised target added: ${r.authorised}\n`, 'info');
    S.ch.analyses[r.rel] = r.analysis;
    findingsFromAnalysis(r.analysis);
    for (const f of r.analysis.flags || []) addFlag(f, r.rel, true);
    await refreshTree();
    selectFile(r.rel);
    updateCtxChips();
    scheduleSave();
    append(log, `[+] saved ${r.rel}  (${r.status} ${r.contentType.split(';')[0]}, ${(r.size / 1024).toFixed(1)} KB)\n`, 'info');
    if (r.analysis.flags?.length) append(log, `[FLAG] ${r.analysis.flags.join(' ')}\n`, 'info');
    return;
  }
  if (modeCmd) { setMode(modeCmd[1].toLowerCase()); append(log, `[*] cho mode: ${modeCmd[1].toLowerCase()}\n`, 'info'); return; }
  if (flagCmd) { $('#flag-input').value = flagCmd[1].trim(); $('#flag-submit').click(); append(log, `[FLAG] recorded: ${flagCmd[1].trim()}\n`, 'info'); return; }
  if (ask || cmd === 'solve') {
    if (S.busy) { append(log, 'cho is busy; wait or press Stop.\n', 'err'); return; }
    if (cmd === 'solve') setMode('agent', true);
    const before = S.ch ? S.ch.messages.length : 0;
    append(log, 'cho> thinking...\n', 'info');
    await sendMessage(cmd === 'solve' ? 'Analyze the challenge files and find the flag.' : ask[1]);
    const reply = (S.ch?.messages || []).slice(before).filter((m) => m.role === 'assistant' || m.role === 'note').pop();
    const text = (reply?.content || '(no reply)').replace(/```plan[\s\S]*?```\s*/i, '').replace(/\*\*|```\w*|`/g, '').trim();
    append(log, `cho> ${text}\n\n`, 'info');
    return;
  }
  const cd =/^(cd|Set-Location)\s*(.*)$/i.exec(cmd);
  if (cd) {
    const target = cd[2].trim().replace(/^['"]|['"]$/g, '');
    const parts = target && target !== '~' && !target.startsWith('/') ? `${T.cwd}/${target}`.split(/[\\/]+/) : [];
    const stack = [];
    for (const p of parts) { if (!p || p === '.') continue; if (p === '..') { if (!stack.length) { append(log, 'cho: staying inside the challenge folder\n', 'err'); return; } stack.pop(); } else stack.push(p); }
    T.cwd = stack.join('/');
    updateShellLabel();
    return;
  }
  if (!S.ch) { append(log, 'Open or create a challenge first.\n', 'err'); return; }
  input.disabled = true;
  const r = await runProc(cmd, { sink: (c) => append(log, c), cwd: T.cwd });
  if (r.code !== 0) append(log, `[exit ${r.code}]\n`, 'err');
  input.disabled = false;
  input.focus();
  pushMsg({ role: 'user', kind: 'term', content: `[I ran this in my terminal] $ ${cmd}\n(exit ${r.code})\n\`\`\`\n${trunc(r.output || '(no output)', 4000)}\n\`\`\`` }, false);
});

// ----- python -----
const PY_TEMPLATE = `# solve.py: runs inside the challenge folder
from pathlib import Path

for f in sorted(Path(".").rglob("*")):
    if f.is_file() and f.name not in ("challenge.json", "solve.py"):
        data = f.read_bytes()
        print(f"{f}  {len(data)} bytes  head={data[:16].hex()}")
`;
$('#py-editor').addEventListener('keydown', (e) => {
  if (e.key === 'Tab') { e.preventDefault(); document.execCommand('insertText', false, '    '); }
  if (e.key === 'Enter' && e.ctrlKey) { e.preventDefault(); $('#py-run').click(); }
});
$('#py-run').addEventListener('click', async () => {
  if (!S.ch) { toast('Open a challenge first'); return; }
  const code = $('#py-editor').value;
  await api.writeFile(S.dir, 'solve.py', code);
  const out = $('#py-out');
  out.textContent = '';
  const sh = shellMode();
  if (sh === 'powershell' && !S.status?.python.ok) { append(out, 'No Python found. Install Python or Kali.\n', 'err'); return; }
  const r = await runProc(sh !== 'powershell' ? 'python3 solve.py' : 'python solve.py', { sink: (c) => append(out, c) });
  append(out, `\n[exit ${r.code}]\n`, r.code ? 'err' : 'info');
  pushMsg({ role: 'user', kind: 'term', content: `[I ran solve.py]\n\`\`\`python\n${trunc(code, 3000)}\n\`\`\`\nOutput (exit ${r.code}):\n\`\`\`\n${trunc(r.output || '(no output)', 4000)}\n\`\`\`` }, false);
});
$('#py-cho').addEventListener('click', () => sendMessage('Write a complete Python solve.py for this challenge in a ```python block. It runs in the challenge folder.'));

// ======================================================================
// flags & submission
// ======================================================================
function flagRegex() {
  const pre = (S.ch?.flagFormat || '').replace(/\{.*$/, '').trim();
  return pre
    ? new RegExp(`${pre.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\{[\\x21-\\x7a\\x7c\\x7e]{1,200}\\}`, 'gi')
    : /\b(?:flag|ctf|htb|thm|[A-Za-z0-9_]{1,12}ctf)\{[\x21-\x7a\x7c\x7e]{3,160}\}/gi;
}
function scanForFlags(text, source) {
  if (!S.ch || !text) return;
  for (const m of text.matchAll(flagRegex())) {
    if (/^(if|for|while|function|return|else|switch|catch|try|class|struct|do|def)\{/i.test(m[0])) continue;
    addFlag(m[0], source);
  }
}
function addFlag(flag, source, quiet) {
  if (!S.ch || S.ch.flags.includes(flag)) return;
  S.ch.flags.push(flag);
  S.ch.progress.flag = true;
  updateFlagList();
  addFinding(`Candidate flag${source ? ` in ${source}` : ''}: ${flag}`, S.ch.analyses[source] ? source : null, 'strings');
  if (!$('#flag-input').value) $('#flag-input').value = flag;
  if (!quiet) { say(`[FLAG] Possible flag${source ? ` (${source})` : ''}: ${flag}`, 12000); mood('happy', 3000); }
  renderPlan();
  scheduleSave();
}
function updateFlagList() {
  const dl = $('#flag-cands');
  dl.innerHTML = '';
  for (const f of S.ch?.flags || []) { const o = el('option'); o.value = f; dl.append(o); }
}
$('#flag-submit').addEventListener('click', () => {
  if (!S.ch) return;
  const f = $('#flag-input').value.trim();
  if (!f) { toast('Type or pick a flag first'); return; }
  const pre = (S.ch.flagFormat || '').replace(/\{.*$/, '').trim();
  if (pre && !f.toLowerCase().startsWith(`${pre.toLowerCase()}{`) && !confirm(`This doesn't match the flag format ${S.ch.flagFormat}. Save it anyway?`)) return;
  S.ch.solved = true;
  S.ch.solvedFlag = f;
  if (!S.ch.flags.includes(f)) S.ch.flags.push(f);
  S.ch.progress.flag = true;
  updateSolved();
  renderPlan();
  saveNow().then(loadList);
  navigator.clipboard.writeText(f);
  mood('happy', 5000);
  say(` We did it! "${f}" is saved and copied. Paste it on the competition site to score the points!`, 12000);
  note(`[ok] Challenge marked solved with **${f}** (copied to clipboard — submit it on the CTF platform).`);
});

// ======================================================================
// findings & task progress
// ======================================================================
function findingsFromAnalysis(a) {
  for (const d of a.decoded || []) addFinding(`Decoded ${d.source} in ${a.rel} (${d.method}) → ${d.flags.join(' ')}`, a.rel, 'meta');
  for (const e of (a.embedded || []).slice(0, 3)) addFinding(`${a.rel}: hidden/embedded ${e.type} at 0x${e.offset.toString(16)}`, a.rel, 'hex');
  for (const [k, v] of a.meta?.fields || []) {
    if (/comment|tEXt|zTXt|iTXt|XMP|EXIF text|Keywords|Subject|Author/i.test(k) && String(v).trim()) {
      addFinding(`Metadata in ${a.rel} contains an unusual ${k.toLowerCase()}: "${String(v).slice(0, 80)}"`, a.rel, 'meta');
    }
  }
  for (const w of a.meta?.warnings || []) addFinding(`${a.rel}: ${w}`, a.rel, 'meta');
  if (a.entropy > 7.6 && !/zip|compress|archive|7-zip|gzip|png|jpeg|mp3|ogg|flac/i.test(a.type)) addFinding(`${a.rel} has very high entropy (${a.entropy}): likely encrypted`, a.rel, 'hex');
}
function addFinding(text, rel, tab) {
  if (!S.ch) return;
  if (S.ch.findings.some((f) => f.text === text)) return;
  S.ch.findings.push({ text, rel, tab, t: Date.now() });
  // Keep showing a flag-related finding first; otherwise show the newest.
  const cur = S.ch.findings[S.findingIdx];
  if (!cur || !/flag/i.test(cur.text) || /flag/i.test(text)) S.findingIdx = S.ch.findings.length - 1;
  renderFinding();
  scheduleSave();
}
function renderFinding() {
  const card = $('#finding-card');
  const list = S.ch?.findings || [];
  if (!list.length) { card.classList.add('hidden'); return; }
  card.classList.remove('hidden');
  const i = Math.min(S.findingIdx, list.length - 1);
  const f = list[i];
  card.innerHTML = '<span class="fi-ic">[*]</span><div class="fi-tx grow"><div><b>Finding:</b> <span class="t"></span></div><div class="row small" style="margin-top:4px"></div></div>';
  $('.t', card).textContent = f.text;
  const row = $('.row', card);
  if (f.rel) {
    const a = el('a', null, 'View evidence ↗');
    a.href = '#';
    a.onclick = (e) => { e.preventDefault(); showView('challenges'); selectFile(f.rel, f.tab); };
    row.append(a);
  }
  if (list.length > 1) {
    const nav = el('span', 'dim', ` ${i + 1}/${list.length} `);
    const prev = el('a', null, '‹ prev');
    const next = el('a', null, 'next ›');
    prev.href = '#'; next.href = '#';
    prev.onclick = (e) => { e.preventDefault(); S.findingIdx = (i - 1 + list.length) % list.length; renderFinding(); };
    next.onclick = (e) => { e.preventDefault(); S.findingIdx = (i + 1) % list.length; renderFinding(); };
    row.append(el('span', 'grow'), prev, nav, next);
  }
}

const DEFAULT_PLANS = {
  crypto: ['Identify the cipher / encoding', 'Find the key or weakness', 'Decrypt the message', 'Validate candidate flag'],
  web: ['Recon the target', 'Find the vulnerability', 'Exploit it', 'Validate candidate flag'],
  reversing: ['Identify binary & protections', 'Find the flag check', 'Recover the input', 'Validate candidate flag'],
  pwn: ['Identify binary & protections', 'Find the vulnerability', 'Build the exploit', 'Validate candidate flag'],
  network: ['Protocol overview', 'Find interesting streams', 'Extract transferred data', 'Validate candidate flag'],
  osint: ['Collect clues from the prompt', 'Search sources', 'Verify the answer', 'Validate candidate flag'],
};
function currentPlan() {
  if (S.ch?.plan?.length) return S.ch.plan;
  const p = S.ch?.progress || {};
  const names = DEFAULT_PLANS[S.ch?.category] || ['Identify file types', 'Inspect metadata', 'Check embedded content', 'Validate candidate flag'];
  const done = [!!(p.identified || Object.keys(S.ch?.analyses || {}).length), !!p.meta, !!p.embedded, !!S.ch?.solved];
  let doingSet = false;
  return names.map((t, i) => {
    if (done[i]) return { t, s: 'done' };
    if (!doingSet) { doingSet = true; return { t, s: 'doing' }; }
    return { t, s: 'todo' };
  });
}
function renderPlan() {
  const card = $('#plan-card');
  if (!S.ch) { card.classList.add('hidden'); return; }
  const plan = currentPlan();
  card.classList.remove('hidden');
  const list = $('#plan-list');
  list.innerHTML = '';
  for (const p of plan) {
    const row = el('div', `plan-item ${p.s}`);
    row.append(el('span', 'pi', p.s === 'done' ? '✓' : ''), el('span', 't', p.t), el('span', 's', p.s === 'done' ? 'Complete' : p.s === 'doing' ? 'In progress' : 'Pending'));
    list.append(row);
  }
  const done = plan.filter((p) => p.s === 'done').length;
  $('#plan-count').textContent = `${done} of ${plan.length} complete`;
}
$('#plan-card .row').addEventListener('click', () => {
  $('#plan-card').classList.toggle('collapsed');
  store.set('cho.planCollapsed', $('#plan-card').classList.contains('collapsed') ? '1' : '');
});
if (store.get('cho.planCollapsed')) $('#plan-card').classList.add('collapsed');

function parsePlan(text) {
  const m = /```plan[^\n]*\n([\s\S]*?)```/i.exec(text);
  if (!m) return null;
  const items = [];
  for (const line of m[1].split('\n')) {
    const x = /^\s*[-*]?\s*\[(x|~|\s?)\]\s*(.+)$/i.exec(line);
    if (x) items.push({ t: x[2].trim(), s: x[1].toLowerCase() === 'x' ? 'done' : x[1] === '~' ? 'doing' : 'todo' });
  }
  return items.length ? items : null;
}

// ======================================================================
// chat
// ======================================================================
const chat = $('#chat');
const scrollChat = () => { chat.scrollTop = chat.scrollHeight; };

function pushMsg(m, render = false) {
  if (!S.ch) return;
  S.ch.messages.push(m);
  if (render) renderMsg(m);
  scheduleSave();
}
function note(text) { pushMsg({ role: 'note', content: text }, true); }

function msgShell(role) {
  const row = el('div', `msg ${role}`);
  const av = el('div', 'av');
  if (role === 'assistant') av.append(choSvg()); else if (role === 'user') av.textContent = '>';
  const bd = el('div', 'bd');
  if (role !== 'note') row.append(av);
  row.append(bd);
  chat.append(row);
  return bd;
}

function renderMsg(m) {
  if (m.role === 'note') { const bd = msgShell('note'); bd.append(md.render(m.content)); }
  else if (m.kind === 'tool') {
    const card = el('div', 'toolrun collapsed');
    card.innerHTML = '<div class="bar"><span class="c"></span><span class="s"></span></div><pre></pre>';
    $('.c', card).textContent = `$ ${m.cmd || ''}`;
    $('.s', card).textContent = `exit ${m.code ?? '?'}`;
    $('pre', card).textContent = (/```\n([\s\S]*)\n```$/.exec(m.content) || [])[1] || m.content;
    $('.bar', card).onclick = () => card.classList.toggle('collapsed');
    chat.append(card);
  } else if (m.kind === 'term') {
    return; // terminal commands stay in the terminal pane; Cho still sees them
  } else if (m.role === 'user') {
    const bd = msgShell('user');
    bd.textContent = m.content;
    for (const img of m.images || []) { const i = el('img'); i.src = `data:image/png;base64,${img}`; bd.append(i); }
  } else {
    renderAssistant(msgShell('assistant'), m.content, false);
  }
  scrollChat();
}

function renderChat() {
  chat.innerHTML = '';
  if (!S.ch) return;
  if (!S.ch.messages.length) {
    const bd = msgShell('assistant');
    bd.append(md.render(`Hi! I'm **Cho**, your CTF teammate.\n\nTell me the challenge and drop in the files (zip, image, pcap, binary…) or a link. I'll suggest the next step and the command to run — you approve each one. Ask me anything in the box below, or type \`? your question\` in the terminal.`));
  }
  for (const m of S.ch.messages) renderMsg(m);
}

// Render an assistant reply; returns runnable code blocks [{cmd, el}].
function renderAssistant(bd, text, live) {
  const shown = text.replace(/```plan[^\n]*\n[\s\S]*?```\s*/i, '');
  bd.innerHTML = '';
  bd.append(md.render(shown, {
    onRun: (cmd) => userRun(cmd),
    onEditor: (code) => { $('#py-editor').value = code; showView('challenges'); showDock('python'); toast('Loaded into the Python tab: press Run'); },
  }));
  if (live) return [];
  return $$('.code', bd).filter((c) => c.runButton).map((c) => ({ cmd: $('pre', c).textContent, el: c }));
}

function buildContext() {
  const files = Object.values(S.ch.analyses).map((a) => a.summary).filter(Boolean);
  return {
    mode: S.ch.mode,
    name: S.ch.name,
    category: S.ch.category,
    flagFormat: S.ch.flagFormat,
    description: S.ch.ctxPrompt === false ? '' : S.ch.description,
    files: S.ch.ctxFiles === false ? null : files,
    plan: S.ch.plan,
    tools: S.status?.wsl.ok ? S.status.wsl.tools : [],
    shell: shellMode(),
    targets: S.ch.targets || '',
  };
}

function historyForModel() {
  const msgs = S.ch.messages.filter((m) => m.role !== 'note').slice(-40);
  let lastImg = -1;
  msgs.forEach((m, i) => { if (m.images?.length) lastImg = i; });
  return msgs.map((m, i) => (i === lastImg ? { role: m.role, content: m.content, images: m.images } : { role: m.role, content: m.content }));
}

function setBusy(b) {
  S.busy = b;
  $('#btn-send').disabled = b;
  $('#agent-ctl').classList.toggle('hidden', !b && !S.agent.running);
  $('#agent-pause').classList.toggle('hidden', !S.agent.running);
}

// Offline fallback so Cho still helps without Ollama.
function offlineReply() {
  const L = ["My AI brain (Ollama) isn't running yet, so here's what my built-in analysis found:\n"];
  const as = Object.values(S.ch.analyses);
  if (!as.length) L.push('- No files yet. Drop the challenge files in and I\'ll scan them.');
  for (const a of as.slice(0, 8)) {
    L.push(`- **${a.rel}**: ${a.type}, ${a.sizeText}, entropy ${a.entropy}${a.embedded?.length ? `, ⚠ ${a.embedded.length} embedded item(s)` : ''}${a.flags?.length ? `, [FLAG] ${a.flags.join(' ')}` : ''}`);
  }
  for (const f of (S.ch.findings || []).slice(-5)) L.push(`FINDING: ${f.text}`);
  if (as[0]?.suggestions?.length) L.push(`\nNext things to try on ${as[0].rel}:`, ...as[0].suggestions.slice(0, 5).map((s) => `- \`${s}\``));
  L.push('\nTo talk with me properly, go to **Overview → Environment setup** and install Ollama + a model.');
  return L.join('\n');
}

async function askCho() {
  if (!S.ch) return;
  if (!aiReady()) {
    const text = offlineReply();
    pushMsg({ role: 'note', content: text }, true);
    say("I'm in offline mode: I posted what my scanners found. Set up Ollama on the Overview page to wake my brain up!");
    stopAgent();
    return;
  }
  setBusy(true);
  mood('thinking');
  const id = uid('chat');
  S.chatId = id;
  const bd = msgShell('assistant');
  bd.textContent = '…';
  scrollChat();
  let text = '';
  tokenHandlers[id] = (t) => {
    if (!text) mood('talking');
    text += t;
    renderAssistant(bd, text, true);
    scrollChat();
  };
  const res = await api.chat({ id, model: currentModel(), context: buildContext(), messages: historyForModel() });
  delete tokenHandlers[id];
  const final = res.ok ? res.text : text;
  let blocks = [];
  if (final) {
    S.ch.messages.push({ role: 'assistant', content: final });
    blocks = renderAssistant(bd, final, false);
    const plan = parsePlan(final);
    if (plan) { S.ch.plan = plan; renderPlan(); }
    for (const m of final.matchAll(/^FINDING:\s*(.+)$/gm)) addFinding(m[1].trim(), S.sel, 'preview');
    for (const m of final.matchAll(/^FLAG:\s*(\S+)/gm)) addFlag(m[1].replace(/[`*]/g, ''), 'Cho');
    scanForFlags(final.replace(/```[\s\S]*?```/g, ''), 'Cho');
    scheduleSave();
  } else if (!res.ok) {
    bd.textContent = '';
  }
  if (!res.ok && res.error !== 'stopped') {
    bd.append(el('div', 'err', `⚠ ${res.error}`));
    bd.lastChild.style.color = 'var(--red)';
    mood('error', 2500);
    stopAgent();
  } else if (!S.ch.flags.length || S.ch.mode !== 'agent') {
    mood('idle');
  }
  setBusy(false);
  scrollChat();
  if (res.ok) await agentStep(final, blocks);
}

// ----- user-approved runs from Run buttons -----
async function userRun(cmd) {
  await runCommand(cmd, { origin: 'user' });
  if (S.agent.running) { S.agent.waiting = false; S.agent.steps++; continueAgent(); }
  else if (S.ch.mode === 'guided' && aiReady() && !S.busy) askCho();
}

// ----- agent loop -----
async function agentStep(reply, blocks) {
  if (S.ch.mode !== 'agent' || !S.agent.running) return;
  if (/^FLAG:/m.test(reply)) { stopAgent(); say(' I think I found the flag! Check it and hit Submit flag.', 12000); mood('happy', 4000); return; }
  if (!blocks.length) { stopAgent(); return; }
  const max = Number(S.settings.agentMaxSteps) || 8;
  if (S.agent.steps >= max) { stopAgent(); note(`[paused] Agent reached ${max} steps. Send a message (or press Agent again) to keep going.`); return; }
  const { cmd, el: block } = blocks[0];
  await saveNow();
  const c = await api.classify(cmd, S.dir);
  if (c.scope && !c.scope.ok) {
    note(`[x] Out of scope: \`${cmd.slice(0, 120)}\` — ${c.scope.reason}. Add the host under **Authorised targets** only if the competition lists it as in scope.`);
    pushMsg({ role: 'user', content: `[Scope] That command was refused: ${c.scope.reason}. Only the authorised targets for this challenge may be contacted. Continue with local analysis or ask me to authorise the host.` });
    stopAgent();
    mood('idle');
    return;
  }
  if (c.level === 'blocked') {
    note(`[x] Blocked \`${cmd.slice(0, 120)}\` (${c.reason}).`);
    pushMsg({ role: 'user', content: `[Safety] That command was blocked because it ${c.reason}. Use a safer approach that stays in the challenge folder.` });
    S.agent.steps++;
    continueAgent();
    return;
  }
  if (c.level === 'approve' || !S.settings.agentAutoRun) {
    S.agent.waiting = true;
    block.classList.add('needs-approval');
    $('.bar span', block).textContent = `⚠ needs your approval: ${c.reason}`;
    say('This step needs your OK. Click ▶ Run on the highlighted command if it looks right.');
    mood('idle');
    return;
  }
  block.runButton.disabled = true;
  block.runButton.textContent = '# auto';
  S.agent.steps++;
  await runCommand(cmd, { origin: 'agent' });
  continueAgent();
}
function continueAgent() {
  if (!S.agent.running || S.busy) return;
  if (S.agent.paused) { $('#cho-status').textContent = 'paused'; return; }
  askCho();
}
function startAgent() {
  S.agent = { running: true, paused: false, waiting: false, steps: 0 };
  $('#agent-pause').textContent = '❚❚ Pause';
  setBusy(S.busy);
}
function stopAgent() {
  S.agent.running = false;
  S.agent.paused = false;
  S.agent.waiting = false;
  if (S.chatId) api.stopChat(S.chatId);
  setBusy(S.busy);
}
$('#agent-pause').addEventListener('click', () => {
  S.agent.paused = !S.agent.paused;
  $('#agent-pause').textContent = S.agent.paused ? '▶ Resume' : '❚❚ Pause';
  if (!S.agent.paused && !S.agent.waiting) continueAgent();
});
$('#agent-stop').addEventListener('click', () => {
  stopAgent();
  if (S.chatId) api.stopChat(S.chatId);
  for (const id of S.runningIds) api.kill(id);
  mood('idle');
  setBusy(false);
});

// ----- modes & context chips -----
function setMode(m, silent) {
  if (S.ch) S.ch.mode = m;
  $$('.modes button').forEach((b) => b.classList.toggle('active', b.dataset.mode === m));
  $('#chat-input').placeholder = { hint: 'Ask for a hint…', guided: 'Ask a question or attach files…', agent: 'Tell Cho to solve it, e.g. "find the flag"…' }[m];
  if (!silent) {
    scheduleSave();
    say({ hint: "Hint mode: I'll only give you small nudges.", guided: "Guided mode: I suggest one step at a time and you approve each command.", agent: "Agent mode: I'll run local analysis myself and ask before touching the network. Pause or Stop me anytime!" }[m], 6000);
  }
}
$$('.modes button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));

function updateCtxChips() {
  const n = Object.keys(S.ch?.analyses || {}).length;
  $('#ctx-files-n').textContent = `${n} file${n === 1 ? '' : 's'}`;
  $('#ctx-prompt').classList.toggle('on', S.ch?.ctxPrompt !== false);
  $('#ctx-files').classList.toggle('on', S.ch?.ctxFiles !== false);
}
$('#ctx-prompt').addEventListener('click', () => { if (!S.ch) return; S.ch.ctxPrompt = S.ch.ctxPrompt === false; updateCtxChips(); scheduleSave(); });
$('#ctx-files').addEventListener('click', () => { if (!S.ch) return; S.ch.ctxFiles = S.ch.ctxFiles === false; updateCtxChips(); scheduleSave(); });

// ----- composer -----
async function sendMessage(text) {
  await ensureChallenge();
  const images = S.images.splice(0);
  renderAttachments();
  const content = text || 'Here is a screenshot of my screen. What do you see and what should I do?';
  pushMsg({ role: 'user', content, ...(images.length ? { images } : {}) }, true);
  if (S.ch.mode === 'agent') startAgent();
  await askCho();
}
async function send() {
  const input = $('#chat-input');
  const text = input.value.trim();
  if (S.busy || (!text && !S.images.length)) return;
  input.value = '';
  await sendMessage(text);
}
$('#btn-send').addEventListener('click', send);
$('#chat-input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
$('#chat-input').addEventListener('paste', (e) => {
  for (const item of e.clipboardData?.items || []) {
    if (!item.type.startsWith('image/')) continue;
    e.preventDefault();
    const reader = new FileReader();
    reader.onload = () => { S.images.push(String(reader.result).split(',')[1]); renderAttachments(); };
    reader.readAsDataURL(item.getAsFile());
  }
});
$('#btn-screen').addEventListener('click', async () => {
  try {
    S.images.push(await api.captureScreen());
    renderAttachments();
    say('Got a snapshot of your screen! Tell me what to look at and press Send. (Reading images needs a vision model like qwen2.5vl.)');
  } catch (err) { toast(`Couldn't capture the screen: ${err.message}`); }
});
function renderAttachments() {
  const box = $('#attachments');
  box.innerHTML = '';
  S.images.forEach((img, i) => {
    const d = el('div', 'att');
    const im = el('img');
    im.src = `data:image/png;base64,${img}`;
    const x = el('button', null, '×');
    x.onclick = () => { S.images.splice(i, 1); renderAttachments(); };
    d.append(im, x);
    box.append(d);
  });
}

// ======================================================================
// toolbox
// ======================================================================
let tbCat = 'All';
function renderToolbox() {
  const installed = new Set(S.status?.wsl.tools || []);
  const q = $('#tb-search').value.toLowerCase();
  const cats = ['All', ...new Set(S.catalog.map((t) => t.cat))];
  const chips = $('#tb-cats');
  chips.innerHTML = '';
  for (const c of cats) {
    const b = el('button', c === tbCat ? 'active' : '', c);
    b.onclick = () => { tbCat = c; renderToolbox(); };
    chips.append(b);
  }
  const bins = new Set(S.catalog.filter((t) => t.bin && !t.external).map((t) => t.bin));
  const ext = S.catalog.filter((t) => t.external).length;
  $('#tb-count').textContent = S.status?.wsl.ok ? `${[...bins].filter((b) => installed.has(b)).length}/${bins.size} tools installed · ${ext} external` : `${bins.size} tools (Kali not installed)`;
  $('#tb-install').textContent = S.status?.wsl.ok ? '⤓ Install / update forensic toolkit' : '⤓ Install Kali Linux (WSL)';
  const list = $('#tb-list');
  list.innerHTML = '';
  const fileArg = S.sel ? shq(S.sel) : 'FILE';
  for (const cat of cats.slice(1)) {
    if (tbCat !== 'All' && tbCat !== cat) continue;
    const tools = S.catalog.filter((t) => t.cat === cat && (!q || `${t.name} ${t.desc} ${t.bin}`.toLowerCase().includes(q)));
    if (!tools.length) continue;
    list.append(el('div', 'tb-cat', cat));
    const grid = el('div', 'tb-grid');
    for (const t of tools) {
      const card = el('div', 'tool');
      const top = el('div', 'top');
      const runnable = !!t.cmd && !!t.bin;
      const state = t.external ? 'ext' : installed.has(t.bin) ? 'ok' : 'no';
      const label = t.external ? '↗ external' : installed.has(t.bin) ? '✓ installed' : 'not installed';
      top.append(el('span', 'nm', t.name), el('span', `st ${state === 'ok' ? 'ok' : 'no'}`, label));
      card.append(top, el('div', 'dim small', t.desc));
      if (runnable) {
        const cmd = t.cmd.replaceAll('{f}', fileArg);
        const code = el('code', null, cmd);
        code.title = cmd;
        card.append(code);
        const use = el('button', null, '▸ Use in terminal');
        use.onclick = () => {
          if (!S.ch) { toast('Open a challenge first'); return; }
          showView('challenges');
          showDock('terminal');
          $('#term-input').value = cmd;
          $('#term-input').focus();
        };
        card.append(use);
      } else if (t.url) {
        const a = el('a', 'tool-link', t.note || 'Open ↗');
        a.href = t.url;
        a.target = '_blank';
        card.append(a);
      } else if (t.note) {
        card.append(el('div', 'dim small', t.note));
      }
      if (t.install && !t.external && !installed.has(t.bin)) {
        const inst = el('code', 'tool-install', t.install);
        inst.title = `Install: ${t.install}`;
        card.append(inst);
      }
      grid.append(card);
    }
    list.append(grid);
  }
}
$('#tb-search').addEventListener('input', renderToolbox);
$('#tb-install').addEventListener('click', () => {
  if (S.status?.wsl.ok) {
    if (confirm('This opens a Kali terminal that installs the full forensic toolkit (several GB). It will ask for your Kali password. Continue?')) api.openSetup('tools');
  } else if (confirm('This opens an Administrator PowerShell running:\n\n  wsl --install -d kali-linux\n\nWindows will ask for permission and you may need to reboot. Continue?')) {
    api.openSetup('kali');
  }
});

// ======================================================================
// overview
// ======================================================================
function renderOverview() {
  if (!S.status) return;
  const { wsl, ollama, python } = S.status;
  const box = $('#setup-list');
  box.innerHTML = '';
  const bins = new Set(S.catalog.map((t) => t.bin));
  const have = (wsl.tools || []).filter((t) => bins.has(t)).length;
  const items = [
    { ok: wsl.ok, t: 'Kali Linux (WSL)', d: wsl.ok ? wsl.distro : 'Linux engine for the security tools', btn: 'Install', act: () => { if (confirm('Opens an Administrator PowerShell running "wsl --install -d kali-linux". You may need to reboot, then open Kali once from the Start menu to create a user. Continue?')) api.openSetup('kali'); } },
    { ok: wsl.ok && have >= 25, t: 'Forensic toolkit', d: wsl.ok ? `${have} of ${bins.size} tools installed` : 'Needs Kali first', btn: wsl.ok ? 'Install' : null, act: () => { if (confirm('Opens a Kali terminal that installs the forensic toolkit (asks for your Kali password). Continue?')) api.openSetup('tools'); } },
    { ok: ollama.ok, t: 'Ollama (AI engine)', d: ollama.ok ? 'running' : 'Runs Cho\'s brain locally on your GPU', btn: 'Install', act: () => { if (confirm('Opens PowerShell running "winget install Ollama.Ollama". Accept the prompts there, then press ⟳. Continue?')) api.openSetup('ollama'); } },
    { ok: ollama.models?.length > 0, t: 'AI model', d: ollama.models?.length ? ollama.models.join(', ') : 'qwen2.5:7b recommended (~4.7 GB)', btn: ollama.ok ? 'Download' : null, act: () => { showView('settings'); $('#pull-btn').click(); } },
    { ok: python.ok, t: 'Python (Windows)', d: python.ok ? python.version : 'Used by the Python tab when Kali is missing', btn: null },
  ];
  for (const it of items) {
    const row = el('div', 'setup-item');
    row.append(el('span', `ic ${it.ok ? 'ok' : 'no'}`, it.ok ? '✓' : ''));
    const tx = el('div', 'tx');
    tx.append(el('div', null, it.t), el('div', null, it.d));
    row.append(tx);
    if (!it.ok && it.btn) { const b = el('button', null, it.btn); b.onclick = it.act; row.append(b); }
    box.append(row);
  }
  const stats = $('#stats');
  stats.innerHTML = '';
  const st = (n, l) => { const d = el('div', 'stat'); d.append(el('b', null, String(n)), el('span', 'dim small', l)); stats.append(d); };
  st(S.list.length, 'challenges');
  st(S.list.filter((c) => c.solved).length, 'solved');
  st(S.list.reduce((s, c) => s + (c.points && c.solved ? c.points : 0), 0), 'points');
  const recent = $('#recent');
  recent.innerHTML = '';
  for (const c of S.list.slice(0, 6)) {
    const r = el('div', 'recent-item');
    r.append(el('span', null, `${c.solved ? '✓ ' : ''}${c.name}`), el('span', 'dim small', c.category));
    r.onclick = () => openChallenge(c.dir);
    recent.append(r);
  }
  if (!S.list.length) recent.append(el('div', 'dim small', 'None yet.'));
}

// ======================================================================
// files view
// ======================================================================
function renderFilesView() {
  const box = $('#files-table');
  box.innerHTML = '';
  if (!S.ch) { box.append(el('div', 'placeholder', 'Open a challenge to see its files.')); return; }
  const t = el('table', 'files-tbl');
  t.innerHTML = '<tr><th>File</th><th>Size</th><th>Type</th><th>Category</th><th>Entropy</th><th>MD5</th></tr>';
  for (const f of flatFiles()) {
    const a = S.ch.analyses[f.rel] || {};
    const tr = el('tr');
    for (const v of [f.rel, fmtSize(f.size), a.type || '—', a.category || '—', a.entropy ?? '—', a.md5 || '—']) tr.append(el('td', null, String(v)));
    tr.onclick = () => { showView('challenges'); selectFile(f.rel); };
    t.append(tr);
  }
  box.append(t);
}
$('#files-open').addEventListener('click', () => S.dir && api.openFolder(S.dir));

// ======================================================================
// notes
// ======================================================================
let notesTimer;
$('#notes').addEventListener('input', () => {
  if (!S.dir) { $('#notes-state').textContent = '(open a challenge to save)'; return; }
  $('#notes-state').textContent = 'saving…';
  clearTimeout(notesTimer);
  notesTimer = setTimeout(async () => { await api.writeFile(S.dir, 'notes.md', $('#notes').value); $('#notes-state').textContent = 'saved'; }, 600);
});
function appendNotes(text) {
  const n = $('#notes');
  n.value = `${n.value.trimEnd()}\n\n${text}\n`;
  n.dispatchEvent(new Event('input'));
}
$('#notes-cho').addEventListener('click', () => {
  const last = [...(S.ch?.messages || [])].reverse().find((m) => m.role === 'assistant');
  if (last) appendNotes(last.content.replace(/```plan[\s\S]*?```\s*/i, ''));
});
$('#notes-flags').addEventListener('click', () => S.ch && appendNotes(`Flags:\n${S.ch.flags.map((f) => `- ${f}`).join('\n') || '- none yet'}`));

// ======================================================================
// settings
// ======================================================================
function renderSettings() {
  const s = S.settings;
  const sel = $('#set-model');
  sel.innerHTML = '';
  for (const m of S.status?.ollama.models || []) { const o = el('option', null, m); o.value = m; sel.append(o); }
  if (!sel.options.length) sel.append(el('option', null, '(no models yet)'));
  sel.value = currentModel() || '';
  $('#set-url').value = s.ollamaUrl || '';
  $('#set-shell').value = s.shell || 'auto';
  $('#set-steps').value = s.agentMaxSteps || 8;
  $('#set-autorun').checked = s.agentAutoRun !== false;
  $('#set-ws').textContent = S.status?.workspace || '';
}
async function saveSetting(patch) { S.settings = await api.setSettings(patch); updateShellLabel(); }
$('#set-model').addEventListener('change', (e) => { saveSetting({ model: e.target.value }); $('#sb-model').textContent = `model: ${e.target.value}`; });
$('#set-url').addEventListener('change', (e) => saveSetting({ ollamaUrl: e.target.value }).then(refreshStatus));
$('#set-shell').addEventListener('change', (e) => saveSetting({ shell: e.target.value }));
$('#set-steps').addEventListener('change', (e) => saveSetting({ agentMaxSteps: Number(e.target.value) || 8 }));
$('#set-autorun').addEventListener('change', (e) => saveSetting({ agentAutoRun: e.target.checked }));
$('#set-ws-open').addEventListener('click', () => S.status && api.openFolder(S.status.workspace));
$('#pull-btn').addEventListener('click', async () => {
  if (!S.status?.ollama.ok) { toast('Install and start Ollama first (Overview → Environment setup)'); return; }
  const name = $('#pull-name').value.trim();
  if (!name) return;
  const log = $('#pull-log');
  log.textContent = '';
  const id = uid('pull');
  dataHandlers[id] = (c) => { log.textContent = c + log.textContent.split('\n').slice(0, 5).join('\n'); };
  $('#pull-btn').disabled = true;
  const r = await api.pullModel(id, name);
  delete dataHandlers[id];
  $('#pull-btn').disabled = false;
  log.textContent = r.ok ? `✓ ${name} is ready\n${log.textContent}` : `✗ ${r.error}\n${log.textContent}`;
  if (r.ok) { await saveSetting({ model: name }); await refreshStatus(); say(`My brain is upgraded with ${name}! Let's hack. model:`); }
});

// ======================================================================
// search
// ======================================================================
$('#search').addEventListener('input', (e) => {
  const q = e.target.value.trim().toLowerCase();
  const box = $('#search-results');
  box.innerHTML = '';
  if (!q) { box.classList.add('hidden'); return; }
  const res = [];
  for (const c of S.list) if (c.name.toLowerCase().includes(q)) res.push({ k: 'challenge', t: c.name, go: () => openChallenge(c.dir) });
  for (const f of flatFiles()) if (f.rel.toLowerCase().includes(q)) res.push({ k: 'file', t: f.rel, go: () => { showView('challenges'); selectFile(f.rel); } });
  for (const t of S.catalog) if (`${t.name} ${t.desc}`.toLowerCase().includes(q)) res.push({ k: 'tool', t: `${t.name}: ${t.desc}`, go: () => { $('#tb-search').value = t.name; showView('toolbox'); } });
  for (const r of res.slice(0, 14)) {
    const row = el('div', 'res');
    row.append(el('span', 'k', r.k), el('span', null, r.t));
    row.onmousedown = (ev) => { ev.preventDefault(); r.go(); box.classList.add('hidden'); e.target.value = ''; };
    box.append(row);
  }
  if (!res.length) box.append(el('div', 'res dim', 'No matches'));
  box.classList.remove('hidden');
});
$('#search').addEventListener('blur', () => setTimeout(() => $('#search-results').classList.add('hidden'), 150));
$('#search').addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.target.value = ''; e.target.blur(); } });

// ======================================================================
// boot
// ======================================================================
// ---- top-bar gear + tool belt ----
$('#btn-settings').addEventListener('click', () => showView('settings'));

function beltRun(cmd) {
  if (!S.sel) { toast('Select a file first'); return; }
  if (shellMode() === 'powershell') { toast('This tool needs Kali/WSL — install it from Settings'); return; }
  runCommand(cmd.replaceAll('{f}', shq(S.sel)), { origin: 'user' });
}
document.querySelectorAll('[data-belt]').forEach((b) => b.addEventListener('click', () => {
  const act = b.dataset.belt;
  if (act === 'run') { showDock('terminal'); $('#term-input').focus(); return; }
  if (act === 'hex') { if (!S.sel) { toast('Select a file first'); return; } S.vtab = 'hex'; renderViewer(); return; }
  if (act === 'decode') { if (!S.sel) { toast('Select a file first'); return; } S.vtab = 'strings'; renderViewer(); return; }
  if (act === 'file') beltRun('file {f}');
  if (act === 'strings') beltRun('strings -n 6 {f} | head -100');
  if (act === 'exif') beltRun('exiftool {f}');
}));

(async function boot() {
  S.catalog = await api.catalog();
  const nt = document.getElementById('nav-tools-count');
  if (nt) nt.textContent = `(${new Set(S.catalog.filter((t) => t.bin && !t.external).map((t) => t.bin)).size})`;
  await loadList();
  await refreshStatus();
  const last = store.get('cho.lastDir');
  if (last && S.list.some((c) => c.dir === last)) await openChallenge(last);
  else { showView('challenges'); showChallengeList(); }
  setTimeout(() => say(greeting(), 9000), 500);
})();
