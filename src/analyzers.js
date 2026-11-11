// Built-in first-pass analysis. Pure JavaScript, so it works even before WSL is set up.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const READ_LIMIT = 64 * 1024 * 1024;

// [hex signature, label, category]
const MAGIC = [
  ['89504E470D0A1A0A', 'PNG image', 'stego'],
  ['FFD8FF', 'JPEG image', 'stego'],
  ['47494638', 'GIF image', 'stego'],
  ['424D', 'BMP image', 'stego'],
  ['504B0304', 'ZIP archive (or docx/xlsx/apk/jar)', 'forensics'],
  ['526172211A07', 'RAR archive', 'forensics'],
  ['377ABCAF271C', '7-Zip archive', 'forensics'],
  ['1F8B', 'GZIP compressed', 'forensics'],
  ['425A68', 'BZIP2 compressed', 'forensics'],
  ['FD377A585A00', 'XZ compressed', 'forensics'],
  ['25504446', 'PDF document', 'forensics'],
  ['7F454C46', 'ELF executable (Linux)', 'reversing/pwn'],
  ['4D5A', 'PE executable (Windows)', 'reversing'],
  ['CAFEBABE', 'Java class file', 'reversing'],
  ['D4C3B2A1', 'PCAP network capture', 'network'],
  ['A1B2C3D4', 'PCAP network capture', 'network'],
  ['0A0D0D0A', 'PCAPNG network capture', 'network'],
  ['52494646', 'RIFF container (WAV/AVI/WEBP)', 'stego'],
  ['494433', 'MP3 audio', 'stego'],
  ['664C6143', 'FLAC audio', 'stego'],
  ['4F676753', 'OGG audio', 'stego'],
  ['53514C69746520666F726D6174', 'SQLite database', 'forensics'],
  ['D0CF11E0A1B11AE1', 'MS Office legacy (OLE) document', 'forensics'],
  ['7B5C727466', 'RTF document', 'forensics'],
  ['2D2D2D2D2D424547494E', 'PEM key or certificate', 'crypto'],
];

// Signatures worth finding *inside* a file (hidden/appended data).
const EMBEDDED = {
  PNG: '89504e470d0a1a0a', JPEG: 'ffd8ffe', ZIP: '504b0304', PDF: '255044462d',
  '7z': '377abcaf271c', GZIP: '1f8b0800', ELF: '7f454c4602', RAR: '526172211a07',
};

// Flag body: printable ASCII without spaces or braces.
const FLAG_RE = /([A-Za-z0-9_]{2,24})\{([\x21-\x7a\x7c\x7e]{3,160})\}/g;
const KNOWN_PREFIX = /(flag|ctf|htb|thm|key)$/i;
const CODE_NOISE = /^(if|for|while|function|return|else|switch|catch|try|class|struct|var|let|const|do|def|elif)$/i;

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// strict = binary data: only accept the user's flag prefix or well-known prefixes (flag{, CTF{, picoCTF{…).
function findFlags(text, flagPrefix, strict = false) {
  const found = new Set();
  const pre = (flagPrefix || '').replace(/\{.*$/, '').trim();
  if (pre) {
    const re = new RegExp(`${escapeRe(pre)}\\{[\\x21-\\x7a\\x7c\\x7e]{1,200}\\}`, 'gi');
    for (const m of text.matchAll(re)) found.add(m[0]);
  }
  for (const [full, prefix, inner] of text.matchAll(FLAG_RE)) {
    if (CODE_NOISE.test(prefix)) continue;
    if (KNOWN_PREFIX.test(prefix)) { found.add(full); continue; }
    if (strict || pre) continue;
    // Unknown prefix in text: only accept flag-shaped bodies like th1s_is_1t.
    const wordRatio = (inner.match(/[A-Za-z0-9_]/g) || []).length / inner.length;
    if (prefix.length >= 3 && inner.length >= 5 && wordRatio >= 0.8 && /[_\d]/.test(inner)) found.add(full);
  }
  return [...found].slice(0, 30);
}

function readHead(p, max = READ_LIMIT) {
  const st = fs.statSync(p);
  const n = Math.min(st.size, max);
  const buf = Buffer.alloc(n);
  const fd = fs.openSync(p, 'r');
  try { fs.readSync(fd, buf, 0, n, 0); } finally { fs.closeSync(fd); }
  return { buf, size: st.size, truncated: st.size > max };
}

function printableRatio(s) {
  if (!s.length) return 0;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13) ok++;
  }
  return ok / s.length;
}

function englishScore(s) {
  if (!s.length) return 0;
  let sc = 0;
  const common = 'etaoin shrdlu';
  for (const ch of s.toLowerCase()) {
    if (common.includes(ch)) sc += 1;
    else if (ch >= 'a' && ch <= 'z') sc += 0.5;
    else if (/[0-9{}_]/.test(ch)) sc += 0.3;
  }
  return sc / s.length;
}

function entropy(buf) {
  if (!buf.length) return 0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  let e = 0;
  for (const c of counts) if (c) { const p = c / buf.length; e -= p * Math.log2(p); }
  return e;
}

function extractStrings(buf, min = 5, limit = 5000) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    const printable = (c >= 0x20 && c < 0x7f) || c === 9;
    if (printable) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= min) {
      out.push(buf.toString('latin1', start, i));
      if (out.length >= limit) break;
    }
    start = -1;
  }
  return out;
}

function detectType(buf, name) {
  const hex = buf.subarray(0, 16).toString('hex').toUpperCase();
  for (const [sig, label, cat] of MAGIC) if (hex.startsWith(sig)) return { label, category: cat };
  if (buf.length > 12 && buf.subarray(4, 8).toString('latin1') === 'ftyp') return { label: 'MP4/MOV video', category: 'stego' };
  const ext = path.extname(name).toLowerCase();
  if (['.raw', '.mem', '.vmem', '.dmp', '.lime', '.img'].includes(ext) && buf.length > 16 * 1024 * 1024) {
    return { label: 'Possible memory/disk image', category: 'forensics' };
  }
  if (printableRatio(buf.subarray(0, 8192).toString('latin1')) > 0.95) {
    if (['.py', '.c', '.cpp', '.js', '.php', '.java', '.go', '.rs', '.sh'].includes(ext)) return { label: `Source code (${ext})`, category: 'reversing/crypto' };
    if (['.html', '.htm'].includes(ext)) return { label: 'HTML page', category: 'web' };
    return { label: 'Text', category: 'crypto/misc' };
  }
  return { label: 'Unknown binary data', category: 'misc' };
}

function findEmbedded(buf) {
  const hits = [];
  for (const [label, sig] of Object.entries(EMBEDDED)) {
    const needle = Buffer.from(sig.length % 2 ? sig.slice(0, -1) : sig, 'hex');
    // A file's own format repeats its signature internally (e.g. every zip entry starts with PK\3\4).
    if (buf.length >= needle.length && buf.subarray(0, needle.length).equals(needle)) continue;
    let from = 1;
    let count = 0;
    while (count < 5) {
      const idx = buf.indexOf(needle, from);
      if (idx < 0) break;
      hits.push({ type: label, offset: idx });
      from = idx + 1;
      count++;
    }
  }
  // Data hidden after the end marker of PNG/JPEG.
  const iend = buf.lastIndexOf(Buffer.from('IEND'));
  if (buf.subarray(0, 4).toString('hex') === '89504e47' && iend > 0 && iend + 8 < buf.length) {
    hits.push({ type: `${buf.length - (iend + 8)} bytes after PNG IEND`, offset: iend + 8 });
  }
  const eoi = buf.lastIndexOf(Buffer.from('ffd9', 'hex'));
  if (buf.subarray(0, 3).toString('hex') === 'ffd8ff' && eoi > 0 && eoi + 2 < buf.length - 16) {
    hits.push({ type: `${buf.length - (eoi + 2)} bytes after JPEG end marker`, offset: eoi + 2 });
  }
  return hits.sort((a, b) => a.offset - b.offset).slice(0, 20);
}

function interestingStrings(strs) {
  const out = [];
  const seen = new Set();
  const add = (s) => { if (!seen.has(s) && out.length < 40) { seen.add(s); out.push(s.slice(0, 200)); } };
  for (const s of strs) {
    if (/https?:\/\/|ftp:\/\/|[\w.-]+@[\w-]+\.\w+/i.test(s)) add(s);
    else if (/pass(word)?|secret|key|flag|token|admin|user(name)?|hidden|ctf/i.test(s)) add(s);
    else if (/^[A-Za-z0-9+/]{24,}={0,2}$/.test(s.trim())) add(s);
    else if (/ZmxhZ3|Q1RGe|ZmxhZ/.test(s)) add(s); // base64 of "flag{" / "CTF{"
  }
  return out;
}

function shq(name) { return `'${String(name).replace(/'/g, "'\\''")}'`; }

function suggestions(type, name, embedded) {
  const f = shq(name);
  const base = [`file ${f}`, `exiftool ${f}`, `strings -n 6 ${f} | head -50`, `binwalk ${f}`];
  const label = type.label;
  let extra = [];
  if (label.startsWith('PNG') || label.startsWith('BMP')) extra = [`zsteg -a ${f} | head -40`, `pngcheck -v ${f}`];
  else if (label.startsWith('JPEG')) extra = [`steghide info ${f} -p ''`, `stegseek ${f} /usr/share/wordlists/rockyou.txt`];
  else if (label.startsWith('GIF')) extra = [`convert ${f} frame_%03d.png && ls`];
  else if (label.startsWith('ZIP')) extra = [`unzip -l ${f}`, `zip2john ${f} > zip.hash && john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt`];
  else if (label.startsWith('RAR') || label.startsWith('7-Zip')) extra = [`7z l ${f}`];
  else if (label.startsWith('PDF')) extra = [`pdftotext ${f} - | head -60`, `pdfinfo ${f}`];
  else if (label.startsWith('ELF')) extra = [`checksec --file=${f}`, `objdump -d -M intel ${f} | grep -A30 '<main>:'`];
  else if (label.startsWith('PE')) extra = [`objdump -x ${f} | head -60`];
  else if (label.startsWith('PCAP')) extra = [`tshark -r ${f} -q -z io,phs`, `tshark -r ${f} -Y http.request -T fields -e http.host -e http.request.uri | head -40`, `mkdir -p http_objects && tshark -r ${f} --export-objects http,http_objects && ls http_objects`];
  else if (label.startsWith('RIFF') || label.includes('audio')) extra = [`sox ${f} -n spectrogram -o spectrogram.png && echo saved spectrogram.png`];
  else if (label.startsWith('SQLite')) extra = [`sqlite3 ${f} .tables`];
  else if (label.includes('memory')) extra = [`vol -f ${f} windows.info`, `vol -f ${f} windows.pslist`];
  if (embedded.length) extra.unshift(`binwalk -e ${f} && ls -R _${name}.extracted | head -50`);
  return [...base, ...extra];
}

// ---------- text decoding ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MORSE = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
  '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
  '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '..--.-': '_',
  '-.--.': '(', '-.--.-': ')', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!',
};

const shift = (s, k) => s.replace(/[a-z]/gi, (c) => {
  const b = c <= 'Z' ? 65 : 97;
  return String.fromCharCode(((c.charCodeAt(0) - b + k + 26) % 26) + b);
});

// Encodings: return a Buffer (or null). These are chained.
const ENCODINGS = {
  Base64: (s) => {
    const t = s.replace(/\s+/g, '');
    if (t.length < 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(t) || t.length % 4 === 1) return null;
    return Buffer.from(t, 'base64');
  },
  Base64url: (s) => {
    const t = s.trim();
    if (t.length < 4 || !/^[A-Za-z0-9_-]+={0,2}$/.test(t) || !/[_-]/.test(t)) return null;
    return Buffer.from(t, 'base64url');
  },
  Base32: (s) => {
    const t = s.replace(/\s+/g, '').toUpperCase().replace(/=+$/, '');
    if (t.length < 8 || !/^[A-Z2-7]+$/.test(t)) return null;
    let bits = '';
    for (const c of t) bits += B32.indexOf(c).toString(2).padStart(5, '0');
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(bytes);
  },
  Base58: (s) => {
    const t = s.trim();
    if (t.length < 6 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(t) || /^[0-9]+$/.test(t)) return null;
    let n = 0n;
    for (const c of t) n = n * 58n + BigInt(B58.indexOf(c));
    let hex = n.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    return Buffer.from(hex, 'hex');
  },
  Hex: (s) => {
    const t = s.replace(/0x|\\x|[\s:,]/gi, '');
    if (t.length < 4 || t.length % 2 || !/^[0-9a-f]+$/i.test(t)) return null;
    return Buffer.from(t, 'hex');
  },
  Binary: (s) => {
    const t = s.replace(/[\s,]/g, '');
    if (t.length < 8 || t.length % 8 || !/^[01]+$/.test(t)) return null;
    const bytes = [];
    for (let i = 0; i < t.length; i += 8) bytes.push(parseInt(t.slice(i, i + 8), 2));
    return Buffer.from(bytes);
  },
  Decimal: (s) => {
    const t = s.trim();
    if (!/^\d{1,3}([\s,]+\d{1,3}){2,}$/.test(t)) return null;
    const nums = t.split(/[\s,]+/).map(Number);
    return nums.every((n) => n <= 255) ? Buffer.from(nums) : null;
  },
  Octal: (s) => {
    const t = s.trim();
    if (!/^\\?[0-7]{2,3}([\s,\\]+[0-7]{2,3}){2,}$/.test(t)) return null;
    return Buffer.from(t.split(/[\s,\\]+/).filter(Boolean).map((x) => parseInt(x, 8)));
  },
  URL: (s) => {
    if (!/%[0-9a-f]{2}/i.test(s)) return null;
    try { return Buffer.from(decodeURIComponent(s), 'utf8'); } catch { return null; }
  },
  Morse: (s) => {
    const t = s.trim();
    if (!/^[.\-/\s|]+$/.test(t) || !/[.-]/.test(t)) return null;
    const out = t.split(/\s*[/|]\s*|\s{2,}/).map((w) => w.split(/\s+/).map((c) => MORSE[c] || '?').join('')).join(' ');
    return Buffer.from(out);
  },
};

// Transforms: string -> string. Applied as final steps.
const TRANSFORMS = {
  ROT13: (s) => shift(s, 13),
  ROT47: (s) => s.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94))),
  Atbash: (s) => s.replace(/[a-z]/gi, (c) => {
    const b = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(25 - (c.charCodeAt(0) - b) + b);
  }),
  Reverse: (s) => [...s].reverse().join(''),
};

function xorBrute(buf) {
  if (buf.length < 4 || buf.length > 4096) return [];
  const res = [];
  for (let k = 1; k < 256; k++) {
    const s = Buffer.from(buf.map((b) => b ^ k)).toString('latin1');
    if (printableRatio(s) > 0.97) res.push({ key: k, s, score: englishScore(s) });
  }
  return res.sort((a, b) => b.score - a.score).slice(0, 2);
}

function decodeAll(input, flagPrefix) {
  const results = [];
  const seen = new Set([input]);
  const push = (method, output) => {
    if (seen.has(output) || !output.trim()) return;
    seen.add(output);
    const flags = findFlags(output, flagPrefix);
    results.push({ method, output: output.slice(0, 3000), flags, score: (flags.length ? 10 : 0) + englishScore(output) + printableRatio(output) });
  };

  const explore = (str, chain, depth) => {
    for (const [name, fn] of Object.entries(ENCODINGS)) {
      let buf;
      try { buf = fn(str); } catch { buf = null; }
      if (!buf || !buf.length) continue;
      const out = buf.toString('utf8');
      const steps = [...chain, name];
      if (printableRatio(out) > 0.9) {
        if (seen.has(out)) continue;
        push(steps.join(' → '), out);
        if (depth < 4) explore(out.trim(), steps, depth + 1);
      } else {
        for (const x of xorBrute(buf)) push(`${steps.join(' → ')} → XOR 0x${x.key.toString(16).padStart(2, '0')}`, x.s);
      }
    }
  };
  explore(input.trim(), [], 1);

  for (const [name, fn] of Object.entries(TRANSFORMS)) push(name, fn(input));

  // Caesar brute force: keep shifts that reveal a flag, else the most English-looking one.
  const caesar = [];
  for (let k = 1; k < 26; k++) {
    if (k === 13) continue;
    const s = shift(input, k);
    caesar.push({ k, s, flags: findFlags(s, flagPrefix).length, score: englishScore(s) });
  }
  const withFlag = caesar.filter((c) => c.flags);
  const picks = withFlag.length ? withFlag : caesar.sort((a, b) => b.score - a.score).slice(0, 1);
  for (const c of picks) push(`Caesar shift ${c.k}${withFlag.length ? '' : ' (best guess)'}`, c.s);

  return results.sort((a, b) => b.score - a.score).slice(0, 15);
}

function identifyHash(s) {
  const t = s.trim();
  const out = [];
  if (/^\$2[abxy]?\$\d\d\$/.test(t)) out.push('bcrypt (hashcat -m 3200)');
  if (/^\$1\$/.test(t)) out.push('md5crypt (hashcat -m 500)');
  if (/^\$5\$/.test(t)) out.push('sha256crypt (hashcat -m 7400)');
  if (/^\$6\$/.test(t)) out.push('sha512crypt (hashcat -m 1800)');
  if (/^\$y\$/.test(t)) out.push('yescrypt (john --format=crypt)');
  if (/^\$argon2/.test(t)) out.push('Argon2');
  if (/^[a-f0-9]+$/i.test(t)) {
    const map = {
      8: ['CRC32 / Adler32'], 16: ['MySQL323', 'half MD5'], 32: ['MD5 (hashcat -m 0)', 'NTLM (hashcat -m 1000)', 'MD4 (hashcat -m 900)'],
      40: ['SHA-1 (hashcat -m 100)', 'RIPEMD-160 (hashcat -m 6000)'], 56: ['SHA-224 (hashcat -m 1300)'],
      64: ['SHA-256 (hashcat -m 1400)', 'SHA3-256 (hashcat -m 17400)', 'Keccak-256'], 96: ['SHA-384 (hashcat -m 10800)'],
      128: ['SHA-512 (hashcat -m 1700)', 'SHA3-512 (hashcat -m 17600)', 'Whirlpool'],
    };
    if (map[t.length]) out.push(...map[t.length]);
  }
  if (/^[a-f0-9]{32}:[a-f0-9]{32}$/i.test(t)) out.push('LM:NTLM pair (pwdump format)');
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(t)) out.push('JWT token: decode header/payload, check alg "none" and weak HS256 secrets (hashcat -m 16500)');
  return out;
}

function textHints(s) {
  const h = [];
  if (/\bn\s*[=:]\s*\d{20,}/i.test(s) && /\be\s*[=:]\s*\d+/i.test(s)) {
    h.push('Looks like RSA (n, e, c). Try factordb.com for n, small-e / Wiener / common-modulus attacks, or RsaCtfTool.');
  }
  if (/-----BEGIN (RSA |)?(PUBLIC|PRIVATE) KEY-----/.test(s)) h.push('Contains a PEM key: inspect it with `openssl rsa -in key.pem -text -noout` (or -pubin for public keys).');
  if (/^[+\-<>[\].,\s]{20,}$/.test(s.trim())) h.push('Only + - < > [ ] . , characters: this is Brainfuck.');
  if (/(Ook[.!?]\s*){6,}/.test(s)) h.push('Ook! language (Brainfuck variant).');
  if (/^[[\]()!+\s]{40,}$/.test(s.trim())) h.push('JSFuck (JavaScript written with []()!+). Run it in a JS console to decode.');
  if (/^[ \t\r\n]{30,}$/.test(s)) h.push('Only whitespace: probably the Whitespace language, or hidden bits in spaces and tabs.');
  if (/[​-‍﻿]/.test(s)) h.push('Zero-width characters present: possible zero-width steganography.');
  const letters = s.replace(/[^a-z]/gi, '');
  if (letters.length > 60 && letters === letters.toUpperCase() && englishScore(s) < 0.6) {
    h.push('Long uppercase text that is not English: try Vigenère (dcode.fr has a key finder) or a substitution solver (quipqiup.com).');
  }
  return h;
}

// Pull encoded-looking tokens out of mixed text (HTML, source, logs) and decode each for a flag.
function decodeEmbeddedTokens(text, flagPrefix) {
  const out = [];
  const seen = new Set();
  const tokens = text.match(/[A-Za-z0-9+/=_-]{16,}/g) || [];
  for (const tok of tokens.slice(0, 400)) {
    if (seen.has(tok)) continue;
    seen.add(tok);
    const hit = decodeAll(tok, flagPrefix).find((d) => d.flags.length);
    if (hit) out.push({ method: hit.method, token: tok.slice(0, 60), output: hit.output.slice(0, 200), flags: hit.flags });
    if (out.length >= 10) break;
  }
  return out;
}

function analyzeText(text, flagPrefix) {
  const s = text.length > 200000 ? text.slice(0, 200000) : text;
  const embeddedDecodes = decodeEmbeddedTokens(s, flagPrefix);
  const decodes = (s.trim().length && s.length < 20000 ? decodeAll(s, flagPrefix) : []);
  for (const e of embeddedDecodes) if (!decodes.some((d) => d.output === e.output)) decodes.unshift({ method: `token ${e.method}`, output: e.output, flags: e.flags, score: 10 });
  const flags = findFlags(s, flagPrefix);
  for (const e of embeddedDecodes) for (const f of e.flags) if (!flags.includes(f)) flags.push(f);
  return { hashes: identifyHash(s), hints: textHints(s), flags, decodes };
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function analyzeFile(filePath, flagPrefix) {
  const name = path.basename(filePath);
  const { buf, size, truncated } = readHead(filePath);
  const type = detectType(buf, name);
  const ent = entropy(buf.subarray(0, 4 * 1024 * 1024));
  const embedded = findEmbedded(buf);
  const strs = extractStrings(buf);
  const latin = buf.toString('latin1');
  const isText = type.label === 'Text' || type.label.startsWith('Source') || type.label.startsWith('HTML');
  const flags = findFlags(latin, flagPrefix, !isText);
  const text = isText && size < 1024 * 1024 ? analyzeText(buf.toString('utf8'), flagPrefix) : null;
  if (text) for (const d of text.decodes) for (const fl of d.flags) if (!flags.includes(fl)) flags.push(fl);

  const result = {
    name,
    path: filePath,
    size,
    sizeText: fmtSize(size),
    truncated,
    type: type.label,
    category: type.category,
    entropy: Number(ent.toFixed(3)),
    md5: crypto.createHash('md5').update(buf).digest('hex'),
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    embedded,
    flags,
    interesting: interestingStrings(strs),
    preview: isText ? buf.subarray(0, 1500).toString('utf8') : null,
    text,
    suggestions: suggestions(type, name, embedded),
  };
  result.summary = summarize(result);
  return result;
}

function summarize(a) {
  const L = [`- ${a.name}: ${a.type}, ${a.sizeText}, entropy ${a.entropy}/8${a.entropy > 7.5 ? ' (very high: compressed or encrypted)' : ''}`];
  if (a.flags.length) L.push(`  Possible flags found: ${a.flags.join(' | ')}`);
  if (a.embedded.length) L.push(`  Embedded/hidden data: ${a.embedded.map((e) => `${e.type}@0x${e.offset.toString(16)}`).join(', ')}`);
  if (a.interesting.length) L.push(`  Interesting strings: ${a.interesting.slice(0, 12).join(' || ')}`);
  if (a.preview) L.push(`  Content preview:\n${a.preview.slice(0, 1200)}`);
  if (a.text?.hashes.length) L.push(`  Hash candidates: ${a.text.hashes.join(', ')}`);
  if (a.text?.hints.length) L.push(`  Hints: ${a.text.hints.join(' ')}`);
  if (a.text?.decodes.length) L.push(`  Best decodes: ${a.text.decodes.slice(0, 3).map((d) => `[${d.method}] ${d.output.slice(0, 120)}`).join(' || ')}`);
  return L.join('\n');
}

module.exports = { analyzeFile, analyzeText, decodeAll, identifyHash, findFlags, entropy, extractStrings };
