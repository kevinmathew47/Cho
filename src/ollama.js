// Minimal client for a local Ollama server (https://ollama.com). Everything stays on this PC.
let BASE = 'http://127.0.0.1:11434';
function setBase(url) { if (url) BASE = String(url).replace(/\/+$/, ''); }

async function status() {
  try {
    const r = await fetch(`${BASE}/api/tags`, { signal: AbortSignal.timeout(10000) });
    const j = await r.json();
    return { ok: true, models: (j.models || []).map((m) => m.name) };
  } catch {
    return { ok: false, models: [] };
  }
}

async function* ndjson(body) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) yield JSON.parse(line);
    }
  }
}

async function chat({ model, messages, signal, onToken }) {
  const r = await fetch(`${BASE}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, messages, stream: true, keep_alive: '60m', options: { temperature: 0.3, num_ctx: 8192 } }),
    signal,
  });
  if (!r.ok) throw new Error(`Ollama error ${r.status}: ${(await r.text()).slice(0, 300)}`);
  let full = '';
  for await (const j of ndjson(r.body)) {
    if (j.error) throw new Error(j.error);
    const t = j.message?.content || '';
    if (t) { full += t; onToken(t); }
  }
  return full;
}

async function pull(model, onProgress, signal) {
  const r = await fetch(`${BASE}/api/pull`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model, stream: true }), signal });
  if (!r.ok) throw new Error(`Ollama error ${r.status}`);
  let last = '';
  for await (const j of ndjson(r.body)) {
    if (j.error) throw new Error(j.error);
    const pct = j.total ? ` ${Math.floor((100 * (j.completed || 0)) / j.total)}%` : '';
    const line = `${j.status}${pct}`;
    if (line !== last) { onProgress(`${line}\n`); last = line; }
  }
}

module.exports = { status, chat, pull, setBase };
