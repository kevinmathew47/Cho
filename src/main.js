// Cho CTF Workspace - Electron main process.
const { app, BrowserWindow, ipcMain, shell, dialog, desktopCapturer, screen } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const analyzers = require('./analyzers');
const meta = require('./meta');
const zip = require('./zip');
const ollama = require('./ollama');
const safety = require('./safety');
const scope = require('./scope');
const sandbox = require('./sandbox');
const { CATALOG, BINARIES } = require('./tools-catalog');
const { buildSystemPrompt } = require('./prompt');

let win;
const running = new Map();
const chats = new Map();
let lastStatus = { wsl: { ok: false }, ollama: { ok: false }, python: { ok: false } };

const WORKSPACE = () => path.join(app.getPath('documents'), 'Cho-CTF-Workspace');
const SETTINGS_FILE = () => path.join(app.getPath('userData'), 'settings.json');
const DEFAULT_SETTINGS = { model: '', ollamaUrl: 'http://127.0.0.1:11434', shell: 'auto', agentMaxSteps: 8, agentAutoRun: true };
const IMAGE_EXT = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp' };

// ---------------- helpers ----------------
function loadSettings() {
  try { return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_FILE(), 'utf8')) }; } catch { return { ...DEFAULT_SETTINGS }; }
}
function saveSettings(s) {
  fs.mkdirSync(path.dirname(SETTINGS_FILE()), { recursive: true });
  fs.writeFileSync(SETTINGS_FILE(), JSON.stringify(s, null, 2));
  ollama.setBase(s.ollamaUrl);
}

// Every file path coming from the UI must live inside the workspace.
function inWorkspace(p) {
  const root = path.resolve(WORKSPACE()).toLowerCase();
  const full = path.resolve(p).toLowerCase();
  return full === root || full.startsWith(root + path.sep);
}
function resolveIn(dir, rel) {
  const full = path.resolve(dir, rel || '.');
  if (!inWorkspace(dir) || !inWorkspace(full) || !full.toLowerCase().startsWith(path.resolve(dir).toLowerCase())) {
    throw new Error('Path is outside the challenge folder');
  }
  return full;
}
const relOf = (dir, full) => path.relative(dir, full).split(path.sep).join('/');

function decode(buf) {
  let zeros = 0;
  const n = Math.min(buf.length, 64);
  for (let i = 1; i < n; i += 2) if (buf[i] === 0) zeros++;
  return n > 4 && zeros > n / 4 ? buf.toString('utf16le') : buf.toString('utf8');
}

function execCapture(exe, args, timeoutMs = 15000) {
  return new Promise((resolve) => {
    let out = '';
    let p;
    try { p = spawn(exe, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (err) { resolve({ code: -1, out: String(err) }); return; }
    const t = setTimeout(() => { try { p.kill(); } catch { /* ignore */ } }, timeoutMs);
    p.stdout.on('data', (d) => { out += decode(d); });
    p.stderr.on('data', (d) => { out += decode(d); });
    p.on('error', (err) => { clearTimeout(t); resolve({ code: -1, out: String(err) }); });
    p.on('close', (code) => { clearTimeout(t); resolve({ code, out }); });
  });
}

function toWslPath(p) {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(p);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}` : p;
}

async function wslStatus() {
  const script = '. /etc/os-release 2>/dev/null; echo "DISTRO:$PRETTY_NAME"; printf "TOOLS:"; '
    + `for t in ${BINARIES.join(' ')}; do command -v "$t" >/dev/null 2>&1 && printf "%s " "$t"; done; echo`;
  const r = await execCapture('wsl.exe', ['-e', 'bash', '-lc', script], 20000);
  const distro = /DISTRO:(.*)/.exec(r.out);
  if (r.code !== 0 || !distro) return { ok: false, error: r.out.replace(/\0/g, '').trim().slice(0, 300) || 'WSL not available' };
  const tools = (/TOOLS:(.*)/.exec(r.out)?.[1] || '').trim().split(/\s+/).filter(Boolean);
  return { ok: true, distro: distro[1].trim() || 'Linux', tools };
}

async function pythonStatus() {
  const r = await execCapture('python', ['--version'], 8000);
  return /Python \d/.test(r.out) ? { ok: true, version: r.out.trim() } : { ok: false };
}

// ---------------- window ----------------
function createWindow() {
  win = new BrowserWindow({
    width: 1600, height: 980, minWidth: 1200, minHeight: 720,
    backgroundColor: '#0b0f17', title: 'Cho CTF Workspace',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
}

app.whenReady().then(() => {
  fs.mkdirSync(WORKSPACE(), { recursive: true });
  ollama.setBase(loadSettings().ollamaUrl);
  createWindow();
});
app.on('window-all-closed', () => {
  for (const p of running.values()) { try { p.kill(); } catch { /* ignore */ } }
  app.quit();
});

// ---------------- status & settings ----------------
ipcMain.handle('sys:status', async () => {
  const [wsl, llm, python, container] = await Promise.all([wslStatus(), ollama.status(), pythonStatus(), sandbox.status()]);
  lastStatus = { wsl, ollama: llm, python, container };
  return { ...lastStatus, workspace: WORKSPACE(), settings: loadSettings() };
});
ipcMain.handle('settings:get', () => loadSettings());
ipcMain.handle('settings:set', (_e, patch) => { const s = { ...loadSettings(), ...patch }; saveSettings(s); return s; });
ipcMain.handle('catalog:get', () => CATALOG);
ipcMain.handle('cmd:classify', (_e, { cmd, dir }) => {
  const c = safety.classify(cmd);
  if (c.level === 'approve' && dir && inWorkspace(dir)) c.scope = scope.check(cmd, readChallenge(dir)?.targets || '');
  return c;
});

// ---------------- challenges ----------------
const CH_FILE = 'challenge.json';
function readChallenge(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, CH_FILE), 'utf8')); } catch { return null; }
}

ipcMain.handle('challenge:list', () => {
  const root = WORKSPACE();
  const out = [];
  for (const d of fs.readdirSync(root, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    const dir = path.join(root, d.name);
    const c = readChallenge(dir);
    if (!c) continue;
    out.push({ dir, name: c.name, category: c.category, difficulty: c.difficulty, points: c.points, solved: c.solved, created: c.created, files: Object.keys(c.analyses || {}).length, flags: (c.flags || []).length });
  }
  return out.sort((a, b) => (b.created || '').localeCompare(a.created || ''));
});

ipcMain.handle('challenge:create', (_e, name) => {
  const slug = String(name || 'challenge').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'challenge';
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
  const dir = path.join(WORKSPACE(), `${stamp}_${slug}`);
  fs.mkdirSync(dir, { recursive: true });
  const data = {
    v: 1, name: name || 'Untitled challenge', category: 'auto', difficulty: 'medium', points: 0, flagFormat: '', description: '',
    created: new Date().toISOString(), solved: false, solvedFlag: '', flags: [], analyses: {}, messages: [], plan: [], findings: [], mode: 'guided',
  };
  fs.writeFileSync(path.join(dir, CH_FILE), JSON.stringify(data, null, 2));
  return { dir, data };
});

ipcMain.handle('challenge:load', (_e, dir) => {
  if (!inWorkspace(dir)) throw new Error('Not a workspace folder');
  return readChallenge(dir);
});

ipcMain.handle('challenge:save', (_e, { dir, data }) => {
  if (!inWorkspace(dir)) throw new Error('Not a workspace folder');
  fs.writeFileSync(path.join(dir, CH_FILE), JSON.stringify(data, null, 1));
  return true;
});

ipcMain.handle('challenge:open-folder', (_e, dir) => inWorkspace(dir) && shell.openPath(dir));

// ---------------- files ----------------
ipcMain.handle('files:pick', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'] });
  return r.canceled ? [] : r.filePaths;
});

function analyzeIn(dir, full, flagPrefix) {
  const a = analyzers.analyzeFile(full, flagPrefix);
  a.rel = relOf(dir, full);
  try {
    const { buf } = readHeadSync(full, 32 * 1024 * 1024);
    const m = meta.parse(buf);
    if (m) a.meta = m;
  } catch { /* ignore */ }
  // Auto-decode suspicious metadata values and strings (base64/hex/rot…) and look for flags inside.
  a.decoded = [];
  const cands = [...(a.meta?.fields || []).map(([k, v]) => [`metadata "${k}"`, String(v)]), ...(a.interesting || []).map((s) => ['string', s])];
  for (const [source, value] of cands.slice(0, 40)) {
    const v = value.trim();
    if (v.length < 8 || v.length > 4000) continue;
    const hit = analyzers.decodeAll(v, flagPrefix).find((d) => d.flags.length);
    if (!hit) continue;
    a.decoded.push({ source, method: hit.method, value: v.slice(0, 80), flags: hit.flags });
    for (const f of hit.flags) if (!a.flags.includes(f)) a.flags.push(f);
  }
  if (a.decoded.length) a.summary += `\n  Auto-decoded: ${a.decoded.map((d) => `${d.source} via ${d.method} → ${d.flags.join(' ')}`).join(' || ')}`;
  if (a.meta?.fields.length) a.summary += `\n  Metadata: ${a.meta.fields.map(([k, v]) => `${k}=${String(v).slice(0, 100)}`).join('; ')}`;
  if (a.meta?.warnings.length) a.summary += `\n  Metadata anomalies: ${a.meta.warnings.join('; ')}`;
  delete a.path;
  return a;
}

function readHeadSync(p, max) {
  const size = fs.statSync(p).size;
  const n = Math.min(size, max);
  const buf = Buffer.alloc(n);
  const fd = fs.openSync(p, 'r');
  try { fs.readSync(fd, buf, 0, n, 0); } finally { fs.closeSync(fd); }
  return { buf, size };
}

function walk(dir, base, depth = 0, acc = []) {
  if (depth > 6 || acc.length > 3000) return acc;
  for (const d of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, d.name);
    if (d.isDirectory()) walk(full, base, depth + 1, acc);
    else acc.push(full);
  }
  return acc;
}

ipcMain.handle('files:add', async (_e, { dir, paths, flagPrefix }) => {
  if (!inWorkspace(dir)) throw new Error('Not a workspace folder');
  const added = [];
  const notes = [];
  for (const src of paths) {
    try {
      const st = fs.statSync(src);
      let targets = [];
      if (st.isDirectory()) {
        const destDir = path.join(dir, path.basename(src));
        fs.cpSync(src, destDir, { recursive: true });
        targets = walk(destDir, dir);
      } else {
        const dest = path.join(dir, path.basename(src));
        if (path.resolve(src).toLowerCase() !== path.resolve(dest).toLowerCase()) fs.copyFileSync(src, dest);
        targets = [dest];
      }
      for (const t of targets) {
        added.push(analyzeIn(dir, t, flagPrefix));
        // Auto-extract zips (and zip-based files named .zip) so their contents show in the tree.
        if (/\.zip$/i.test(t)) {
          try {
            // If everything sits under one top folder (e.g. evidence/), extract next to the zip
            // so we get evidence/skyline.png instead of evidence/evidence/skyline.png.
            const { entries } = zip.list(t);
            const tops = new Set(entries.map((x) => x.name.split('/')[0]));
            const top = [...tops][0];
            const singleRoot = tops.size === 1 && entries.some((x) => x.name.includes('/'));
            let outDir = singleRoot ? path.dirname(t) : t.replace(/\.zip$/i, '');
            if ((singleRoot && fs.existsSync(path.join(outDir, top))) || (!singleRoot && fs.existsSync(outDir))) {
              outDir = `${t.replace(/\.zip$/i, '')}_extracted`;
            }
            const r = zip.extract(t, outDir);
            for (const w of r.written) added.push(analyzeIn(dir, w, flagPrefix));
            const shown = singleRoot ? path.join(outDir, top) : outDir;
            notes.push({ zip: relOf(dir, t), extractedTo: relOf(dir, shown), count: r.written.length, skipped: r.skipped, comment: r.comment, encrypted: r.encrypted });
          } catch (err) {
            notes.push({ zip: relOf(dir, t), error: err.message });
          }
        }
      }
    } catch (err) {
      added.push({ name: path.basename(src), rel: path.basename(src), error: err.message });
    }
  }
  return { added, notes };
});

ipcMain.handle('files:analyze', (_e, { dir, rel, flagPrefix }) => analyzeIn(dir, resolveIn(dir, rel), flagPrefix));

ipcMain.handle('files:tree', (_e, dir) => {
  if (!inWorkspace(dir)) return [];
  const build = (d, depth) => {
    if (depth > 6) return [];
    return fs.readdirSync(d, { withFileTypes: true })
      .filter((x) => !(depth === 0 && x.name === CH_FILE))
      .sort((a, b) => (b.isDirectory() - a.isDirectory()) || a.name.localeCompare(b.name))
      .slice(0, 500)
      .map((x) => {
        const full = path.join(d, x.name);
        if (x.isDirectory()) return { name: x.name, rel: relOf(dir, full), dir: true, children: build(full, depth + 1) };
        let size = 0;
        try { size = fs.statSync(full).size; } catch { /* ignore */ }
        return { name: x.name, rel: relOf(dir, full), dir: false, size };
      });
  };
  return build(dir, 0);
});

ipcMain.handle('files:read', (_e, { dir, rel, mode, offset = 0 }) => {
  const full = resolveIn(dir, rel);
  const size = fs.statSync(full).size;
  if (mode === 'hex') {
    const n = Math.max(0, Math.min(4096, size - offset));
    const buf = Buffer.alloc(n);
    const fd = fs.openSync(full, 'r');
    try { fs.readSync(fd, buf, 0, n, offset); } finally { fs.closeSync(fd); }
    return { size, offset, bytes: buf.toString('base64') };
  }
  if (mode === 'strings') {
    const { buf } = readHeadSync(full, 32 * 1024 * 1024);
    return { size, strings: analyzers.extractStrings(buf, 4, 6000) };
  }
  if (mode === 'meta') {
    const { buf } = readHeadSync(full, 32 * 1024 * 1024);
    return { size, meta: meta.parse(buf) };
  }
  // preview
  const ext = path.extname(full).toLowerCase();
  if (IMAGE_EXT[ext] && size < 20 * 1024 * 1024) {
    return { size, kind: 'image', src: `data:${IMAGE_EXT[ext]};base64,${fs.readFileSync(full).toString('base64')}` };
  }
  const { buf } = readHeadSync(full, 200 * 1024);
  const sample = buf.subarray(0, 8192).toString('latin1');
  let ok = 0;
  for (let i = 0; i < sample.length; i++) { const c = sample.charCodeAt(i); if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++; }
  if (!sample.length || ok / sample.length > 0.9) return { size, kind: 'text', text: buf.toString('utf8'), truncated: size > buf.length };
  return { size, kind: 'binary' };
});

ipcMain.handle('files:write', (_e, { dir, rel, content }) => {
  const full = resolveIn(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, 'utf8');
  return true;
});

ipcMain.handle('files:read-text', (_e, { dir, rel }) => {
  try { return fs.readFileSync(resolveIn(dir, rel), 'utf8'); } catch { return ''; }
});

ipcMain.handle('text:analyze', (_e, { text, flagPrefix }) => analyzers.analyzeText(String(text || ''), flagPrefix));

// ---------------- screenshot (only when the user clicks) ----------------
ipcMain.handle('screen:capture', async () => {
  win.hide();
  await new Promise((r) => setTimeout(r, 400));
  try {
    const d = screen.getDisplayNearestPoint(screen.getCursorScreenPoint());
    const sources = await desktopCapturer.getSources({
      types: ['screen'],
      thumbnailSize: { width: Math.round(d.size.width * d.scaleFactor), height: Math.round(d.size.height * d.scaleFactor) },
    });
    const src = sources.find((s) => String(s.display_id) === String(d.id)) || sources[0];
    if (!src) throw new Error('No screen available to capture');
    let img = src.thumbnail;
    if (img.getSize().width > 1600) img = img.resize({ width: 1600 });
    return img.toPNG().toString('base64');
  } finally {
    win.show();
  }
});

// ---------------- command runner ----------------
// shell: 'wsl' | 'powershell'. origin 'agent' commands are re-checked here so the UI can't be bypassed.
ipcMain.handle('proc:run', (e, { id, cmd, dir, shell: sh, origin }) => new Promise((resolve) => {
  if (!inWorkspace(dir)) { resolve({ code: -1, output: 'Refused: not a workspace folder' }); return; }
  if (origin === 'agent' && safety.classify(cmd).level !== 'auto') {
    resolve({ code: -1, output: 'Refused: Agent mode may only auto-run local analysis commands.' });
    return;
  }
  // Network commands (from anyone) must name only hosts authorised for this challenge.
  const usesNetwork = safety.classify(cmd).level === 'approve';
  if (usesNetwork) {
    const s = scope.check(cmd, readChallenge(dir)?.targets || '');
    if (!s.ok) {
      resolve({ code: -1, output: `Refused: ${s.reason}\nAdd the host to "Authorised targets" for this challenge only if the competition says it is in scope.\n` });
      return;
    }
  }
  const MAX = 300000;
  let out = '';
  let p;
  try {
    p = sh === 'container'
      ? spawn(lastStatus.container?.engine || 'docker', sandbox.buildArgs({ dir, cmd, network: usesNetwork }), { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
      : sh === 'powershell'
      ? spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', `[Console]::OutputEncoding=[Text.Encoding]::UTF8; ${cmd}`], { cwd: dir, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
      : spawn('wsl.exe', ['--cd', dir, '-e', 'bash', '-lc', cmd], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) { resolve({ code: -1, output: String(err) }); return; }
  running.set(id, p);
  const send = (chunk) => { if (!e.sender.isDestroyed()) e.sender.send('proc:data', { id, chunk }); };
  const timer = setTimeout(() => { send('\n[cho] timed out after 5 minutes, process killed\n'); try { p.kill(); } catch { /* ignore */ } }, 5 * 60 * 1000);
  const onData = (d) => { const s = decode(d); if (out.length < MAX) out += s; send(s); };
  p.stdout.on('data', onData);
  p.stderr.on('data', onData);
  p.on('error', (err) => { clearTimeout(timer); running.delete(id); resolve({ code: -1, output: out + String(err) }); });
  p.on('close', (code) => { clearTimeout(timer); running.delete(id); resolve({ code, output: out }); });
}));

ipcMain.on('proc:kill', (_e, id) => {
  const p = running.get(id);
  if (!p) return;
  // Kill the whole process tree (wsl.exe / powershell children).
  spawn('taskkill', ['/pid', String(p.pid), '/T', '/F'], { windowsHide: true });
});

// ---------------- Cho's brain ----------------
ipcMain.handle('cho:chat', async (e, { id, model, context, messages }) => {
  const ac = new AbortController();
  chats.set(id, ac);
  try {
    const text = await ollama.chat({
      model,
      messages: [{ role: 'system', content: buildSystemPrompt(context) }, ...messages],
      signal: ac.signal,
      onToken: (token) => { if (!e.sender.isDestroyed()) e.sender.send('cho:token', { id, token }); },
    });
    return { ok: true, text };
  } catch (err) {
    return { ok: false, error: ac.signal.aborted ? 'stopped' : err.message };
  } finally {
    chats.delete(id);
  }
});
ipcMain.on('cho:stop', (_e, id) => chats.get(id)?.abort());

ipcMain.handle('ollama:pull', async (e, { id, model }) => {
  const ac = new AbortController();
  chats.set(id, ac);
  try {
    await ollama.pull(model, (p) => { if (!e.sender.isDestroyed()) e.sender.send('proc:data', { id, chunk: p }); }, ac.signal);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  } finally {
    chats.delete(id);
  }
});

// ---------------- fetch an authorised remote challenge into the workspace ----------------
function safeNameFromUrl(u) {
  try {
    const url = new URL(u);
    let base = path.basename(url.pathname) || url.hostname;
    base = base.split('?')[0].replace(/[^\w.\-]/g, '_').slice(0, 60) || 'page';
    if (!/\.[a-z0-9]{1,8}$/i.test(base)) base += '.html';
    return base;
  } catch { return 'download.bin'; }
}

// Downloads one authorised URL into the challenge folder, then analyses it.
// An explicit fetch authorises that host for this challenge (recorded in challenge.json).
ipcMain.handle('net:fetch', async (_e, { dir, url }) => {
  if (!inWorkspace(dir)) return { ok: false, error: 'Not a workspace folder' };
  let parsed;
  try { parsed = new URL(url); } catch { return { ok: false, error: 'That is not a valid URL' }; }
  if (!/^https?:$/.test(parsed.protocol)) return { ok: false, error: 'Only http:// and https:// URLs can be fetched' };

  // Record the host as an authorised target for this challenge (explicit user action).
  const ch = readChallenge(dir) || {};
  const host = parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  const targets = scope.parseTargets(ch.targets || '');
  const known = targets.some((t) => (t.host.startsWith('*.') ? parsed.hostname.endsWith(t.host.slice(1)) : t.host === parsed.hostname));
  let authorisedNote = '';
  if (!known) {
    ch.targets = `${ch.targets ? `${ch.targets} ` : ''}${host}`;
    fs.writeFileSync(path.join(dir, CH_FILE), JSON.stringify(ch, null, 1));
    authorisedNote = host;
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'User-Agent': 'cho-ctf-workspace' } });
    const type = res.headers.get('content-type') || '';
    const reader = res.body.getReader();
    const MAX = 50 * 1024 * 1024;
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX) { ctrl.abort(); return { ok: false, error: 'File is larger than 50 MB; download it manually instead' }; }
      chunks.push(value);
    }
    const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    let name = safeNameFromUrl(url);
    if (/text\/html/i.test(type) && !/\.html?$/i.test(name)) name += '.html';
    let dest = path.join(dir, name);
    if (fs.existsSync(dest)) dest = path.join(dir, `${Date.now().toString().slice(-6)}_${name}`);
    fs.writeFileSync(dest, buf);
    const a = analyzeIn(dir, dest, ch.flagFormat);
    return { ok: true, rel: a.rel, status: res.status, contentType: type, size: buf.length, analysis: slimForIpc(a), authorised: authorisedNote };
  } catch (err) {
    return { ok: false, error: ctrl.signal.aborted ? 'timed out after 30s' : err.message };
  } finally {
    clearTimeout(timer);
  }
});

// trims a big analysis object for the renderer (mirrors the renderer's own slim())
function slimForIpc(a) {
  const { preview, ...rest } = a;
  return rest;
}

// ---------------- one-click setup helpers (open visible windows so the user sees every prompt) ----------------
ipcMain.handle('setup:open', (_e, what) => {
  const script = toWslPath(path.join(__dirname, '..', 'scripts', 'setup-wsl.sh').replace('app.asar', 'app.asar.unpacked'));
  const commands = {
    ollama: ['cmd.exe', ['/c', 'start', 'powershell', '-NoExit', '-Command', 'winget install --id Ollama.Ollama -e; Write-Host \"`nDone. Return to Cho and press Refresh.\"']],
    kali: ['powershell.exe', ['-NoProfile', '-Command', "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','wsl --install -d kali-linux; Write-Host Reboot if asked, then open Kali from the Start menu once to create your user.'"]],
    tools: ['cmd.exe', ['/c', 'start', 'wsl.exe', '-e', 'bash', script]],
  };
  const c = commands[what];
  if (!c) return false;
  spawn(c[0], c[1], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
  return true;
});
