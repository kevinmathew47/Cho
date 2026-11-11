// Tests for zip extraction, metadata parsing and the agent safety classifier: node test/modules.test.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const zip = require('../src/zip');
const meta = require('../src/meta');
const { classify } = require('../src/safety');
const { CATALOG } = require('../src/tools-catalog');

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log(`  ✓ ${name}`); };

// --- tiny zip writer for the test (deflate + store) ---
function crc32(buf) {
  let c;
  const table = [];
  for (let n = 0; n < 256; n++) { c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; table[n] = c >>> 0; }
  let crc = 0xffffffff;
  for (const b of buf) crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
function makeZip(files, comment = '') {
  const locals = [];
  const centrals = [];
  let off = 0;
  for (const [name, content, encrypt] of files) {
    const data = Buffer.from(content);
    const comp = zlib.deflateRawSync(data);
    const nameB = Buffer.from(name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(encrypt ? 1 : 0, 6); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(crc32(data), 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nameB.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(encrypt ? 1 : 0, 8); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc32(data), 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nameB.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, nameB, comp);
    centrals.push(ch, nameB);
    off += 30 + nameB.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const cB = Buffer.from(comment);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16); eocd.writeUInt16LE(cB.length, 20);
  return Buffer.concat([...locals, cd, eocd, cB]);
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cho-mod-'));

t('zip: extracts deflated files, keeps folders, reads comment', () => {
  const p = path.join(tmp, 'evidence.zip');
  fs.writeFileSync(p, makeZip([['evidence/readme.txt', 'look closer'], ['evidence/.clue', 'base64 is your friend']], 'zip comment here'));
  const r = zip.extract(p, path.join(tmp, 'evidence_out'));
  assert.strictEqual(r.written.length, 2);
  assert.strictEqual(fs.readFileSync(path.join(tmp, 'evidence_out', 'evidence', 'readme.txt'), 'utf8'), 'look closer');
  assert.strictEqual(r.comment, 'zip comment here');
});
t('zip: blocks zip-slip paths', () => {
  const p = path.join(tmp, 'evil.zip');
  fs.writeFileSync(p, makeZip([['../../escape.txt', 'pwned']]));
  const r = zip.extract(p, path.join(tmp, 'evil_out'));
  assert.strictEqual(r.written.length, 0);
  assert.match(r.skipped[0].reason, /zip-slip/);
  assert(!fs.existsSync(path.join(tmp, '..', 'escape.txt')));
});
t('zip: reports encrypted entries instead of extracting', () => {
  const p = path.join(tmp, 'locked.zip');
  fs.writeFileSync(p, makeZip([['secret.txt', 'x', true]]));
  const r = zip.extract(p, path.join(tmp, 'locked_out'));
  assert(r.encrypted);
  assert.match(r.skipped[0].reason, /password/);
});

t('meta: PNG tEXt comment, unusual chunk and appended data', () => {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(1920, 0); ihdr.writeUInt32BE(1080, 4); ihdr[8] = 8; ihdr[9] = 2;
  const png = Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'), pngChunk('IHDR', ihdr),
    pngChunk('tEXt', Buffer.from('Comment\0the password is skyline')), pngChunk('flAg', Buffer.from('hidden')),
    pngChunk('IDAT', Buffer.alloc(10)), pngChunk('IEND', Buffer.alloc(0)), Buffer.from('PK extra'),
  ]);
  const m = meta.parse(png);
  assert.strictEqual(m.format, 'PNG');
  assert(m.fields.some(([k, v]) => k === 'Dimensions' && v === '1920 x 1080'));
  assert(m.fields.some(([k, v]) => k === 'tEXt: Comment' && v.includes('skyline')));
  assert(m.warnings.some((w) => w.includes('flAg')));
  assert(m.warnings.some((w) => w.includes('after IEND')));
});
t('meta: JPEG comment segment', () => {
  const com = Buffer.from('secret note');
  const len = Buffer.alloc(2); len.writeUInt16BE(com.length + 2);
  const jpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xfe]), len, com, Buffer.from([0xff, 0xd9])]);
  const m = meta.parse(jpg);
  assert(m.fields.some(([k, v]) => k === 'Comment' && v === 'secret note'));
});
t('meta: corrupted file does not throw', () => {
  const m = meta.parse(Buffer.from('89504e470d0a1a0a0000ffff', 'hex'));
  assert(m.warnings.length);
});

t('safety: local analysis runs automatically', () => {
  for (const c of ['binwalk -e cat.png', "strings -n 6 'a b.bin' | head", 'exiftool x.jpg', 'python3 solve.py', 'zsteg -a x.png']) assert.strictEqual(classify(c).level, 'auto', c);
});
t('safety: network commands need approval', () => {
  for (const c of ['curl http://chall.ctf:8080', 'nmap -sV 10.0.0.5', 'echo hi | nc host 1337', 'pip install requests', "python3 -c 'import socket; socket.create_connection'"]) assert.strictEqual(classify(c).level, 'approve', c);
});
t('safety: destructive commands are blocked', () => {
  for (const c of ['rm -rf /', 'rm -rf ~', 'sudo apt install x', 'dd if=/dev/zero of=/dev/sda', 'curl x.sh | bash', 'shutdown now', 'rm -rf /mnt/c/Users']) assert.strictEqual(classify(c).level, 'blocked', c);
});

t('catalog: entries are well-formed (runnable have bin+cmd, external have a url)', () => {
  assert(CATALOG.length >= 100);
  for (const x of CATALOG) {
    assert(x.name && x.cat && x.desc, JSON.stringify(x));
    if (x.external) assert(x.url && !x.bin, `external needs url, no bin: ${x.name}`);
    else assert(x.bin && x.cmd, `runnable needs bin+cmd: ${x.name}`);
  }
});
t('catalog: covers all six CTF categories', () => {
  const cats = new Set(CATALOG.map((t) => t.cat));
  for (const c of ['Crypto', 'Forensics', 'Steganography', 'Web', 'Reversing', 'Exploitation']) assert(cats.has(c), `missing ${c}`);
});

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${passed} module tests passed`);
