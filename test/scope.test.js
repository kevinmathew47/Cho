// Tests for the authorised-target gate and the container argument builder: node test/scope.test.js
const assert = require('assert');
const scope = require('../src/scope');
const sandbox = require('../src/sandbox');

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log(`  ✓ ${name}`); };

t('parseTargets: hosts, ports, urls, wildcards', () => {
  assert.deepStrictEqual(scope.parseTargets('10.10.10.5, chall.ctf.example:31337 http://web.practice.local/x *.lab.test'), [
    { host: '10.10.10.5', port: null }, { host: 'chall.ctf.example', port: 31337 },
    { host: 'web.practice.local', port: null }, { host: '*.lab.test', port: null },
  ]);
  assert.deepStrictEqual(scope.parseTargets('  '), []);
});
t('extractHosts: urls, ip + port, host + port, ignores file names', () => {
  assert.deepStrictEqual(scope.extractHosts('curl -sS http://web.practice.local:8080/a?b=1'), [{ host: 'web.practice.local', port: 8080 }]);
  assert.deepStrictEqual(scope.extractHosts('echo hi | nc -w 3 10.10.10.5 1337'), [{ host: '10.10.10.5', port: 1337 }]);
  assert.deepStrictEqual(scope.extractHosts('nc chall.ctf.example 31337 < payload.bin'), [{ host: 'chall.ctf.example', port: 31337 }]);
  assert.deepStrictEqual(scope.extractHosts('strings evidence/skyline.png > out.txt'), []);
});
t('check: in-scope host passes', () => {
  assert(scope.check('curl http://web.practice.local/', 'web.practice.local').ok);
  assert(scope.check('nc 10.10.10.5 1337', '10.10.10.5:1337').ok);
  assert(scope.check('curl https://a.lab.test/x', '*.lab.test').ok);
});
t('check: anything else is refused', () => {
  assert(!scope.check('curl http://example.org/', 'web.practice.local').ok);
  assert(!scope.check('nc 10.10.10.5 22', '10.10.10.5:1337').ok);
  assert(!scope.check('curl http://web.practice.local/ && curl http://other.example/', 'web.practice.local').ok);
  assert(!scope.check('curl http://web.practice.local/', '').ok);
  assert(!scope.check('curl http://evil-web.practice.local.example/', 'web.practice.local').ok);
});
t('check: network command with no readable destination is refused', () => {
  const r = scope.check('pip install requests', 'web.practice.local');
  assert(!r.ok);
  assert.match(r.reason, /no destination/);
});
t('sandbox: network is off by default, folder is the only mount', () => {
  const a = sandbox.buildArgs({ dir: 'C:\\ws\\ch1', cmd: 'file x' });
  assert.strictEqual(a[a.indexOf('--network') + 1], 'none');
  assert.strictEqual(a.filter((x) => x === '-v').length, 1);
  assert.strictEqual(a[a.indexOf('-v') + 1], 'C:\\ws\\ch1:/work');
  assert(a.includes('no-new-privileges') && a.includes('ALL'));
  assert.deepStrictEqual(a.slice(-3), ['bash', '-lc', 'file x']);
  assert.strictEqual(sandbox.buildArgs({ dir: 'd', cmd: 'c', network: true })[4], 'bridge');
});

console.log(`\n${passed} scope tests passed`);
