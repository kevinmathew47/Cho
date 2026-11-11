// Quick self-test for the built-in analyzers: node test/analyzers.test.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const a = require('../src/analyzers');

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log(`  ✓ ${name}`); };
const has = (decodes, flag) => decodes.some((d) => d.output.includes(flag));

const FLAG = 'flag{ch0_w4s_h3r3}';
t('base64', () => assert(has(a.decodeAll(Buffer.from(FLAG).toString('base64')), FLAG)));
t('hex', () => assert(has(a.decodeAll(Buffer.from(FLAG).toString('hex')), FLAG)));
t('base64 of hex (chained)', () => assert(has(a.decodeAll(Buffer.from(Buffer.from(FLAG).toString('hex')).toString('base64')), FLAG)));
t('binary', () => assert(has(a.decodeAll([...Buffer.from(FLAG)].map((b) => b.toString(2).padStart(8, '0')).join(' ')), FLAG)));
t('rot13', () => assert(has(a.decodeAll('synt{pu0_j4f_u3e3}'), FLAG)));
t('caesar shift', () => assert(has(a.decodeAll('iodj{fk0_z4v_k3u3}'), FLAG)));
t('single-byte xor in hex', () => assert(has(a.decodeAll(Buffer.from([...Buffer.from(FLAG)].map((b) => b ^ 0x42)).toString('hex')), FLAG)));
t('morse', () => assert(a.decodeAll('... --- ...').some((d) => d.output === 'SOS')));
t('hash id md5', () => assert(a.identifyHash('5f4dcc3b5aa765d61d8327deb882cf99').some((h) => h.startsWith('MD5'))));
t('hash id bcrypt', () => assert(a.identifyHash('$2b$12$abcdefghijklmnopqrstuuJ8yZp1sKq3W1')[0].startsWith('bcrypt')));
t('custom flag prefix', () => assert.deepStrictEqual(a.findFlags('xx picoCTF{abc_123} yy', 'picoCTF{...}'), ['picoCTF{abc_123}']));

t('file: PNG with appended zip containing a flag', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cho-'));
  const png = Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.alloc(40), Buffer.from('IEND'), Buffer.alloc(4),
    Buffer.from('504b0304', 'hex'), Buffer.from(`junk ${FLAG} junk`),
  ]);
  const p = path.join(dir, 'cat.png');
  fs.writeFileSync(p, png);
  const r = a.analyzeFile(p);
  assert.strictEqual(r.type, 'PNG image');
  assert(r.embedded.some((e) => e.type === 'ZIP'));
  assert(r.embedded.some((e) => e.type.includes('after PNG IEND')));
  assert(r.flags.includes(FLAG));
  assert(r.suggestions.some((s) => s.startsWith('binwalk -e')));
  fs.rmSync(dir, { recursive: true });
});

t('file: text with base64 flag', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cho-'));
  const p = path.join(dir, 'msg.txt');
  fs.writeFileSync(p, Buffer.from(FLAG).toString('base64'));
  const r = a.analyzeFile(p);
  assert(r.flags.includes(FLAG));
  fs.rmSync(dir, { recursive: true });
});

t('no false flags from binary garbage', () => {
  const junk = Buffer.from('c3a951527bdef08229ad53d7ec78521ccb7ee91d8e2908b0b347df4d13b17d6b7a536a7b543b6c7d', 'hex').toString('latin1');
  assert.deepStrictEqual(a.findFlags(junk, '', true), []);
  assert.deepStrictEqual(a.findFlags('kzSj{T;l} QR{xx}', ''), []);
  assert.deepStrictEqual(a.findFlags('if{x=1;} function{return}', ''), []);
});
t('real flags still found', () => {
  assert.deepStrictEqual(a.findFlags('junk picoCTF{r3al_fl4g} junk', '', true), ['picoCTF{r3al_fl4g}']);
  assert.deepStrictEqual(a.findFlags('answer: DUCTF{th1s_is_1t}', ''), ['DUCTF{th1s_is_1t}']);
  assert.deepStrictEqual(a.findFlags('answer: SECRET{y0u_g0t_it}', ''), ['SECRET{y0u_g0t_it}']);
});
t('a zip does not report its own entries as embedded zips', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cho-'));
  const p = path.join(dir, 'x.zip');
  fs.writeFileSync(p, Buffer.concat([Buffer.from('504b0304', 'hex'), Buffer.alloc(50), Buffer.from('504b0304', 'hex'), Buffer.alloc(50)]));
  assert.strictEqual(a.analyzeFile(p).embedded.length, 0);
  fs.rmSync(dir, { recursive: true });
});

t('decodes a flag from base64 embedded inside HTML/text', () => {
  const b64 = Buffer.from('flag{r3m0t3_w3b}').toString('base64');
  const r = a.analyzeText(`<html><p>${b64}</p><a href="x">y</a></html>`, 'flag{...}');
  assert(r.flags.includes('flag{r3m0t3_w3b}'), JSON.stringify(r.flags));
});

console.log(`\n${passed} tests passed`);
