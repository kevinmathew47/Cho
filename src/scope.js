// Authorised-target scope: network commands may only name hosts the user listed for this challenge.
// This is a gate on the command text, not a firewall. Container mode adds the real network isolation.
const FILE_EXT = /\.(png|jpe?g|gif|bmp|webp|txt|md|py|js|c|h|cpp|php|html?|json|xml|csv|log|zip|rar|7z|gz|tar|xz|bz2|pcap|pcapng|cap|pdf|wav|mp3|flac|ogg|bin|elf|exe|dll|so|img|raw|mem|dmp|hash|yar|sh|ps1|db|sqlite|out|key|pem|crt|enc|dat)$/i;

// "10.10.10.5, chall.ctf.example:31337 *.practice.local" -> [{host, port}]
function parseTargets(text) {
  const out = [];
  for (const raw of String(text || '').split(/[\s,;]+/)) {
    let t = raw.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/.*$/, '');
    if (!t) continue;
    let port = null;
    const m = /^(.*):(\d{1,5})$/.exec(t);
    if (m && !m[1].includes(':')) { t = m[1]; port = Number(m[2]); }
    if (!/^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(t)) continue;
    out.push({ host: t, port });
  }
  return out;
}

// Best-effort list of destinations a command line names: [{host, port}]
function extractHosts(cmd) {
  const found = new Map();
  const add = (host, port) => {
    const h = String(host).toLowerCase().replace(/\.$/, '');
    if (!h) return;
    const key = `${h}:${port || ''}`;
    if (!found.has(key)) found.set(key, { host: h, port: port ? Number(port) : null });
  };
  let rest = String(cmd || '');
  rest = rest.replace(/\b[a-z][a-z0-9+.-]*:\/\/(?:[^\s/@'"]*@)?(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::(\d{1,5}))?[^\s'"]*/gi, (_m, h, p) => { add(h.replace(/[[\]]/g, ''), p); return ' '; });
  rest = rest.replace(/\b((?:\d{1,3}\.){3}\d{1,3})(?:[:\s]+(\d{1,5})\b)?/g, (_m, h, p) => { add(h, p); return ' '; });
  for (const m of rest.matchAll(/(?:^|[\s'"=@])((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[:\s]+(\d{1,5})\b)?/gi)) {
    if (FILE_EXT.test(m[1])) continue;
    add(m[1], m[2]);
  }
  if (/\blocalhost\b/i.test(rest)) add('localhost', (/\blocalhost[:\s]+(\d{1,5})\b/i.exec(rest) || [])[1]);
  return [...found.values()];
}

function allowed(dest, targets) {
  return targets.some((t) => {
    const hostOk = t.host.startsWith('*.') ? dest.host.endsWith(t.host.slice(1)) : dest.host === t.host;
    return hostOk && (t.port == null || dest.port == null || t.port === dest.port);
  });
}

// -> { ok, hosts, unauthorised: [..], reason }
function check(cmd, targetsText) {
  const targets = Array.isArray(targetsText) ? targetsText : parseTargets(targetsText);
  const hosts = extractHosts(cmd);
  if (!hosts.length) {
    return { ok: false, hosts, unauthorised: ['(destination not recognised)'], reason: 'This command uses the network but no destination could be read from it.' };
  }
  const bad = hosts.filter((h) => !allowed(h, targets)).map((h) => (h.port ? `${h.host}:${h.port}` : h.host));
  if (bad.length) {
    return { ok: false, hosts, unauthorised: bad, reason: `Not in this challenge's authorised targets: ${bad.join(', ')}` };
  }
  return { ok: true, hosts, unauthorised: [], reason: '' };
}

module.exports = { parseTargets, extractHosts, check };
