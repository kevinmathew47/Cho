// Minimal ZIP reader/extractor (store + deflate). No dependencies.
// Encrypted entries are reported, not extracted (crack them with zip2john/john).
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function readCentralDirectory(buf) {
  const min = Math.max(0, buf.length - 65557);
  let eocd = -1;
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a valid zip (no end-of-central-directory record)');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const commentLen = buf.readUInt16LE(eocd + 20);
  const comment = buf.toString('latin1', eocd + 22, eocd + 22 + commentLen);
  if (off === 0xffffffff) throw new Error('ZIP64 archives are not supported here; use 7z in the terminal');
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const size = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const cmtLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    // Windows tools (PowerShell Compress-Archive) sometimes write backslash separators.
    const name = buf.toString((flags & 0x800) ? 'utf8' : 'latin1', off + 46, off + 46 + nameLen).replace(/\\/g, '/');
    const fileComment = buf.toString('latin1', off + 46 + nameLen + extraLen, off + 46 + nameLen + extraLen + cmtLen);
    entries.push({ name, method, compSize, size, localOff, encrypted: !!(flags & 1), dir: name.endsWith('/'), comment: fileComment });
    off += 46 + nameLen + extraLen + cmtLen;
  }
  return { entries, comment };
}

function list(file) {
  return readCentralDirectory(fs.readFileSync(file));
}

function extract(file, outDir) {
  const buf = fs.readFileSync(file);
  const { entries, comment } = readCentralDirectory(buf);
  const root = path.resolve(outDir);
  const written = [];
  const skipped = [];
  let total = 0;
  for (const e of entries.slice(0, 5000)) {
    const clean = path.normalize(e.name).replace(/^([/\\])+/, '');
    const dest = path.resolve(root, clean);
    if (!dest.startsWith(root + path.sep) && dest !== root) { skipped.push({ name: e.name, reason: 'unsafe path (zip-slip)' }); continue; }
    if (e.dir) { fs.mkdirSync(dest, { recursive: true }); continue; }
    if (e.encrypted) { skipped.push({ name: e.name, reason: 'password protected' }); continue; }
    const nameLen = buf.readUInt16LE(e.localOff + 26);
    const extraLen = buf.readUInt16LE(e.localOff + 28);
    const start = e.localOff + 30 + nameLen + extraLen;
    const data = buf.subarray(start, start + e.compSize);
    let out;
    if (e.method === 0) out = data;
    else if (e.method === 8) out = zlib.inflateRawSync(data);
    else { skipped.push({ name: e.name, reason: `compression method ${e.method} not supported (use 7z)` }); continue; }
    total += out.length;
    if (total > 1024 * 1024 * 1024) { skipped.push({ name: e.name, reason: 'over 1 GB extracted, stopped (zip bomb?)' }); break; }
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, out);
    written.push(dest);
  }
  return { written, skipped, comment, encrypted: entries.some((e) => e.encrypted), entries };
}

module.exports = { list, extract };
