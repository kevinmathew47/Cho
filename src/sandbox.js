// Container sandbox: runs commands in a throwaway Docker/Podman container with only the challenge folder mounted.
// Network is off unless the command passed the authorised-target check (see scope.js).
const { spawn } = require('child_process');

const IMAGE = 'cho-ctf-tools:latest';

function probe(exe, args) {
  return new Promise((resolve) => {
    let out = '';
    let p;
    try { p = spawn(exe, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); } catch { resolve({ code: -1, out: '' }); return; }
    const t = setTimeout(() => { try { p.kill(); } catch { /* ignore */ } }, 8000);
    p.stdout.on('data', (d) => { out += d; });
    p.on('error', () => { clearTimeout(t); resolve({ code: -1, out: '' }); });
    p.on('close', (code) => { clearTimeout(t); resolve({ code, out }); });
  });
}

// -> { ok, engine, version, image, imageReady }
async function status() {
  for (const engine of ['docker', 'podman']) {
    const v = await probe(engine, ['version', '--format', '{{.Server.Version}}']);
    if (v.code !== 0 || !v.out.trim()) continue;
    const img = await probe(engine, ['image', 'inspect', IMAGE, '--format', '{{.Id}}']);
    return { ok: true, engine, version: v.out.trim(), image: IMAGE, imageReady: img.code === 0 };
  }
  return { ok: false, engine: null, image: IMAGE, imageReady: false };
}

// Arguments for one isolated run. `network` is true only for an approved, in-scope command.
function buildArgs({ dir, cmd, network = false, image = IMAGE }) {
  return [
    'run', '--rm', '-i',
    '--network', network ? 'bridge' : 'none',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '256',
    '--memory', '2g',
    '--cpus', '2',
    '--tmpfs', '/tmp:rw,size=256m',
    '-v', `${dir}:/work`,
    '-w', '/work',
    image,
    'bash', '-lc', cmd,
  ];
}

module.exports = { status, buildArgs, IMAGE };
