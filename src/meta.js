// Lightweight metadata parsing in pure JS (PNG chunks, JPEG comments/EXIF, GIF comments, PDF info).
// exiftool in WSL gives the full picture; this gives an instant first look.
const zlib = require('zlib');

function png(buf) {
  const out = { format: 'PNG', fields: [], chunks: [], warnings: [] };
  let off = 8;
  let sawIEND = false;
  while (off + 12 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString('latin1', off + 4, off + 8);
    if (!/^[A-Za-z]{4}$/.test(type) || off + 12 + len > buf.length) { out.warnings.push(`Corrupt chunk at 0x${off.toString(16)}`); break; }
    const data = buf.subarray(off + 8, off + 8 + len);
    out.chunks.push(`${type} (${len} bytes)`);
    if (type === 'IHDR') {
      out.fields.push(['Dimensions', `${data.readUInt32BE(0)} x ${data.readUInt32BE(4)}`]);
      out.fields.push(['Bit depth / colour type', `${data[8]} / ${data[9]}`]);
    } else if (type === 'tEXt') {
      const i = data.indexOf(0);
      out.fields.push([`tEXt: ${data.toString('latin1', 0, i)}`, data.toString('latin1', i + 1)]);
    } else if (type === 'zTXt') {
      const i = data.indexOf(0);
      let v = '(compressed)';
      try { v = zlib.inflateSync(data.subarray(i + 2)).toString('latin1'); } catch { /* ignore */ }
      out.fields.push([`zTXt: ${data.toString('latin1', 0, i)}`, v]);
    } else if (type === 'iTXt') {
      const i = data.indexOf(0);
      const parts = data.subarray(i + 3).toString('utf8').split('\0');
      out.fields.push([`iTXt: ${data.toString('latin1', 0, i)}`, parts.slice(2).join(' ')]);
    } else if (type === 'eXIf') {
      out.fields.push(['EXIF', exifStrings(data).join(' | ')]);
    } else if (!['IDAT', 'PLTE', 'IEND', 'pHYs', 'sRGB', 'gAMA', 'cHRM', 'bKGD', 'tIME', 'iCCP', 'sBIT', 'tRNS'].includes(type)) {
      out.warnings.push(`Unusual chunk "${type}" — custom chunks often hide data`);
    }
    off += 12 + len;
    if (type === 'IEND') { sawIEND = true; break; }
  }
  if (sawIEND && off < buf.length) out.warnings.push(`${buf.length - off} extra bytes after IEND (appended data)`);
  if (!sawIEND) out.warnings.push('No IEND chunk — file may be truncated or have a broken header');
  return out;
}

function exifStrings(buf) {
  const s = [];
  let cur = '';
  for (const b of buf) {
    if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
    else { if (cur.length >= 4) s.push(cur); cur = ''; }
  }
  if (cur.length >= 4) s.push(cur);
  return s.filter((x) => !/^(Exif|MM|II)$/.test(x)).slice(0, 30);
}

function jpeg(buf) {
  const out = { format: 'JPEG', fields: [], chunks: [], warnings: [] };
  let off = 2;
  while (off + 4 <= buf.length && buf[off] === 0xff) {
    const marker = buf[off + 1];
    if (marker === 0xd9 || marker === 0xda) { out.chunks.push(marker === 0xda ? 'SOS (image data)' : 'EOI'); break; }
    const len = buf.readUInt16BE(off + 2);
    const data = buf.subarray(off + 4, off + 2 + len);
    const name = `APP${marker - 0xe0}`;
    if (marker === 0xfe) {
      out.fields.push(['Comment', data.toString('latin1')]);
    } else if (marker === 0xe1 && data.toString('latin1', 0, 4) === 'Exif') {
      out.fields.push(['EXIF text', exifStrings(data).join(' | ')]);
    } else if (marker === 0xe1 && data.toString('latin1', 0, 4) === 'http') {
      out.fields.push(['XMP', data.toString('utf8').replace(/\s+/g, ' ').slice(0, 1500)]);
    } else if (marker >= 0xc0 && marker <= 0xc3) {
      out.fields.push(['Dimensions', `${data.readUInt16BE(3)} x ${data.readUInt16BE(1)}`]);
    }
    out.chunks.push(marker >= 0xe0 && marker <= 0xef ? `${name} (${len})` : `0xFF${marker.toString(16).toUpperCase()} (${len})`);
    off += 2 + len;
  }
  const eoi = buf.lastIndexOf(Buffer.from([0xff, 0xd9]));
  if (eoi > 0 && eoi + 2 < buf.length) out.warnings.push(`${buf.length - eoi - 2} bytes after the JPEG end marker (appended data)`);
  return out;
}

function gif(buf) {
  const out = { format: 'GIF', fields: [['Dimensions', `${buf.readUInt16LE(6)} x ${buf.readUInt16LE(8)}`]], chunks: [], warnings: [] };
  let frames = 0;
  for (let i = 0; i < buf.length - 1; i++) {
    if (buf[i] === 0x21 && buf[i + 1] === 0xfe) {
      let j = i + 2;
      let c = '';
      while (j < buf.length && buf[j]) { c += buf.toString('latin1', j + 1, j + 1 + buf[j]); j += buf[j] + 1; }
      out.fields.push(['Comment', c]);
    }
    if (buf[i] === 0x21 && buf[i + 1] === 0xf9) frames++;
  }
  out.fields.push(['Frames (approx.)', String(frames || 1)]);
  if (frames > 1) out.warnings.push('Animated GIF: check individual frames, data often hides in one frame');
  return out;
}

function pdf(buf) {
  const s = buf.toString('latin1');
  const out = { format: 'PDF', fields: [], chunks: [], warnings: [] };
  for (const k of ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate']) {
    const m = new RegExp(`/${k}\\s*\\(([^)]{0,300})\\)`).exec(s);
    if (m) out.fields.push([k, m[1]]);
  }
  const objs = (s.match(/\d+ \d+ obj/g) || []).length;
  out.fields.push(['Objects', String(objs)]);
  if (/\/JavaScript|\/JS\b/.test(s)) out.warnings.push('Contains JavaScript');
  if (/\/EmbeddedFile/.test(s)) out.warnings.push('Has embedded files');
  if (/\/Encrypt/.test(s)) out.warnings.push('PDF is encrypted (try pdfcrack)');
  if ((s.match(/%%EOF/g) || []).length > 1) out.warnings.push('Multiple %%EOF markers: incremental updates, earlier versions may hold data');
  return out;
}

function parse(buf) {
  const h = buf.subarray(0, 8).toString('hex');
  try {
    if (h.startsWith('89504e47')) return png(buf);
    if (h.startsWith('ffd8ff')) return jpeg(buf);
    if (h.startsWith('47494638')) return gif(buf);
    if (h.startsWith('25504446')) return pdf(buf);
  } catch (err) {
    return { format: 'unknown', fields: [], chunks: [], warnings: [`Metadata parse error: ${err.message} (file may be corrupted on purpose)`] };
  }
  return null;
}

module.exports = { parse };
