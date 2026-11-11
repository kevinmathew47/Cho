// Classifies commands Cho wants to run in Agent mode.
//   blocked  -> never run automatically (destructive / escapes the challenge folder)
//   approve  -> touches the network or installs things: the user must click Run
//   auto     -> local analysis inside the challenge folder: Agent mode may run it
const BLOCKED = [
  /\brm\s+-[a-z]*r[a-z]*f?\s+(\/|~|\*|\.\.|\/mnt)/i,
  /\brm\s+.*\s(\/|~)(\s|$)/,
  /\bmkfs\b/, /\bdd\b.*\bof=\/dev\//, /\bshutdown\b|\breboot\b|\bpoweroff\b|\bhalt\b/,
  /:\(\)\s*\{.*\};\s*:/, /\bchmod\s+-R\s+\S+\s+\//, />\s*\/dev\/sd/, /\bsudo\b/, /\bsu\s+-/,
  /\|\s*(ba|z)?sh\b/, /\bcurl\b.*\|\s*python/, /\bcrontab\b/, /\bpasswd\b/, /\buserdel\b|\buseradd\b/,
  /\/mnt\/[a-z]\/(windows|users|program)/i, /\bformat\s+[a-z]:/i, /\bRemove-Item\b.*-Recurse/i, /\breg\s+delete\b/i,
  /\bkill(all)?\s+-9\s+(-1|1)\b/,
];
const NETWORK = [
  /\b(curl|wget|nc|ncat|netcat|telnet|ssh|scp|ftp|nmap|masscan|sqlmap|gobuster|ffuf|dirb|nikto|hydra|whatweb|wfuzz|ping|dig|nslookup|host|openssl\s+s_client)\b/,
  /\bgit\s+clone\b/, /\bpip3?\s+install\b/, /\bapt(-get)?\b/, /\bgem\s+install\b/, /\bnpm\s+i(nstall)?\b/,
  /\brequests\.|socket\.|remote\(|urllib/, /https?:\/\//,
];

function classify(cmd) {
  const c = String(cmd || '');
  if (BLOCKED.some((r) => r.test(c))) return { level: 'blocked', reason: 'looks destructive or reaches outside the challenge folder' };
  if (NETWORK.some((r) => r.test(c))) return { level: 'approve', reason: 'contacts the network or installs software' };
  return { level: 'auto', reason: 'local analysis inside the challenge folder' };
}

module.exports = { classify };
