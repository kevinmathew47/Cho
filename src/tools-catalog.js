// Catalogue of CTF tools shown in the Toolbox, covering the solving stack from awesome-ctf
// (github.com/apsdehal/awesome-ctf). Each entry:
//   cat, name, desc          — grouping, label, one-line purpose
//   bin                      — binary checked inside Kali/WSL (presence = "installed")
//   cmd                      — example command; {f} is the selected file (already quoted). Omit for non-runnable.
//   install                  — how to install it if missing (shown when not present)
//   external, url, note      — for GUI/online/commercial tools that don't run from here
const CATALOG = [
  // ============================================================ CRYPTO
  { cat: 'Crypto', name: 'Decoder (built-in)', bin: 'python3', desc: 'Base64/32/58, hex, binary, URL, morse, ROT/Caesar/Atbash, XOR — in the app Decoder and auto-analysis', cmd: 'python3 -c "import base64,sys;print(base64.b64decode(sys.argv[1]))" STRING' },
  { cat: 'Crypto', name: 'CyberChef', bin: null, external: true, url: 'https://gchq.github.io/CyberChef/', desc: 'The "cyber swiss-army knife" for encoding/encryption recipes', note: 'Open CyberChef ↗ (web)' },
  { cat: 'Crypto', name: 'RsaCtfTool', bin: 'RsaCtfTool', desc: 'Automated RSA attacks (weak/known keys, Wiener, common modulus)', cmd: 'RsaCtfTool --publickey {f} --private', install: 'pipx install git+https://github.com/RsaCtfTool/RsaCtfTool' },
  { cat: 'Crypto', name: 'rsatool', bin: 'rsatool', desc: 'Compute RSA parameters (d from p,q)', cmd: 'rsatool -p P -q Q', install: 'pipx install rsatool || git clone https://github.com/ius/rsatool' },
  { cat: 'Crypto', name: 'xortool', bin: 'xortool', desc: 'Find XOR key length and key', cmd: 'xortool {f}', install: 'pipx install xortool' },
  { cat: 'Crypto', name: 'FeatherDuster', bin: 'featherduster', desc: 'Automated analysis & decryption of classical crypto', cmd: 'featherduster {f}', install: 'git clone https://github.com/nccgroup/featherduster && pip install ./featherduster' },
  { cat: 'Crypto', name: 'hash_extender', bin: 'hash_extender', desc: 'Hash length-extension attacks (MD5/SHA)', cmd: 'hash_extender --help', install: 'git clone https://github.com/iagox86/hash_extender && make -C hash_extender' },
  { cat: 'Crypto', name: 'padding-oracle-attacker', bin: 'poattack', desc: 'CBC padding-oracle attacks', cmd: 'poattack --help', install: 'npm i -g padding-oracle-attacker' },
  { cat: 'Crypto', name: 'PkCrack', bin: 'pkcrack', desc: 'Break legacy ZipCrypto with known plaintext', cmd: 'pkcrack -C enc.zip -c file -P plain.zip -p file -d out.zip', install: 'git clone https://github.com/keyunluo/pkcrack && cmake pkcrack' },
  { cat: 'Crypto', name: 'QuipQiup', bin: null, external: true, url: 'https://quipqiup.com/', desc: 'Automated substitution-cipher / cryptogram solver', note: 'Open quipqiup ↗ (web)' },
  { cat: 'Crypto', name: 'dcode.fr', bin: null, external: true, url: 'https://www.dcode.fr/en', desc: 'Huge classical-cipher identifier and solver collection', note: 'Open dCode ↗ (web)' },
  { cat: 'Crypto', name: 'SageMath', bin: 'sage', desc: 'Mathematics system for ECC/lattice/number-theory crypto', cmd: 'sage script.sage', install: 'sudo apt install sagemath' },
  { cat: 'Crypto', name: 'z3', bin: 'python3', desc: 'SMT solver for constraint-based crypto/reversing (Python)', cmd: 'python3 -c "import z3; print(z3.get_version_string())"', install: 'pip install z3-solver' },
  { cat: 'Crypto', name: 'openssl', bin: 'openssl', desc: 'Keys, certificates, ciphers, digests', cmd: 'openssl rsa -pubin -in {f} -text -noout' },
  { cat: 'Crypto', name: 'factordb (helper)', bin: 'python3', desc: 'Look up factorisations of RSA modulus n', cmd: 'python3 -c "import urllib.request,sys;print(urllib.request.urlopen(\'http://factordb.com/api?query=\'+sys.argv[1]).read())" N' },

  // ============================================================ PASSWORDS / BRUTEFORCE
  { cat: 'Passwords', name: 'John the Ripper', bin: 'john', desc: 'Crack hashes with a wordlist or rules', cmd: 'john --wordlist=/usr/share/wordlists/rockyou.txt {f}' },
  { cat: 'Passwords', name: 'hashcat', bin: 'hashcat', desc: 'GPU-accelerated hash cracking', cmd: 'hashcat -m 0 {f} /usr/share/wordlists/rockyou.txt' },
  { cat: 'Passwords', name: 'hashid', bin: 'hashid', desc: 'Identify the type of a hash', cmd: 'hashid -m "$(head -1 {f})"' },
  { cat: 'Passwords', name: 'hash-identifier', bin: 'hash-identifier', desc: 'Interactive hash-type identifier', cmd: 'echo HASH | hash-identifier', install: 'sudo apt install hash-identifier' },
  { cat: 'Passwords', name: 'Hydra', bin: 'hydra', desc: 'Network login brute-forcer (ssh, ftp, http...)', cmd: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt HOST ssh', install: 'sudo apt install hydra' },
  { cat: 'Passwords', name: 'Patator', bin: 'patator', desc: 'Flexible multi-protocol brute-forcer', cmd: 'patator ssh_login host=HOST user=root password=FILE0 0=/usr/share/wordlists/rockyou.txt', install: 'sudo apt install patator' },
  { cat: 'Passwords', name: 'Ophcrack', bin: 'ophcrack', desc: 'Windows password cracking via rainbow tables', cmd: 'ophcrack', install: 'sudo apt install ophcrack' },
  { cat: 'Passwords', name: 'zip2john', bin: 'zip2john', desc: 'Extract a crackable hash from a protected zip', cmd: 'zip2john {f} > zip.hash && john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt' },
  { cat: 'Passwords', name: 'fcrackzip', bin: 'fcrackzip', desc: 'Brute-force zip passwords', cmd: 'fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt {f}' },
  { cat: 'Passwords', name: 'pdfcrack', bin: 'pdfcrack', desc: 'Recover PDF passwords', cmd: 'pdfcrack -f {f} -w /usr/share/wordlists/rockyou.txt' },
  { cat: 'Passwords', name: '*2john suite', bin: 'john', desc: 'rar2john, ssh2john, keepass2john, office2john, etc.', cmd: 'ssh2john id_rsa > ssh.hash && john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt' },

  // ============================================================ EXPLOITATION / PWN
  { cat: 'Exploitation', name: 'pwntools', bin: 'pwn', desc: 'Exploit-development framework (Python)', cmd: 'pwn checksec {f}', install: 'pip install pwntools' },
  { cat: 'Exploitation', name: 'checksec', bin: 'checksec', desc: 'Show binary mitigations (NX, PIE, canary, RELRO)', cmd: 'checksec --file={f}' },
  { cat: 'Exploitation', name: 'ROPgadget', bin: 'ROPgadget', desc: 'Find ROP gadgets in a binary', cmd: 'ROPgadget --binary {f} | head -60', install: 'pip install ROPgadget' },
  { cat: 'Exploitation', name: 'ropper', bin: 'ropper', desc: 'Find gadgets and build ROP chains', cmd: 'ropper --file {f} --search "pop rdi"', install: 'pip install ropper' },
  { cat: 'Exploitation', name: 'one_gadget', bin: 'one_gadget', desc: 'Find one-shot execve gadgets in libc', cmd: 'one_gadget /lib/x86_64-linux-gnu/libc.so.6', install: 'gem install one_gadget' },
  { cat: 'Exploitation', name: 'libc-database', bin: 'python3', desc: 'Identify libc version from leaked symbol offsets', cmd: './find printf OFFSET', install: 'git clone https://github.com/niklasb/libc-database' },
  { cat: 'Exploitation', name: 'Metasploit', bin: 'msfconsole', desc: 'Exploitation framework & payload generator', cmd: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf -o payload', install: 'sudo apt install metasploit-framework' },
  { cat: 'Exploitation', name: 'angr', bin: 'python3', desc: 'Binary analysis & symbolic execution (solves many crackmes)', cmd: 'python3 -c "import angr; print(angr.__version__)"', install: 'pip install angr' },
  { cat: 'Exploitation', name: 'pwninit', bin: 'pwninit', desc: 'Auto-set-up pwn challenges (patch libc/loader)', cmd: 'pwninit', install: 'cargo install pwninit' },
  { cat: 'Exploitation', name: 'gef / pwndbg / peda', bin: 'gdb', desc: 'Exploitation-focused GDB enhancements', cmd: 'gdb -q {f}', install: 'bash -c "$(curl -fsSL https://gef.blah.cat/sh)"' },

  // ============================================================ FORENSICS
  { cat: 'Forensics', name: 'file', bin: 'file', desc: 'Identify a file type by magic bytes', cmd: 'file {f}' },
  { cat: 'Forensics', name: 'binwalk', bin: 'binwalk', desc: 'Find and extract embedded files', cmd: 'binwalk -e {f}' },
  { cat: 'Forensics', name: 'foremost', bin: 'foremost', desc: 'Carve files by header/footer signatures', cmd: 'foremost -i {f} -o foremost_out && ls -R foremost_out' },
  { cat: 'Forensics', name: 'scalpel', bin: 'scalpel', desc: 'Fast file carver', cmd: 'scalpel {f} -o scalpel_out' },
  { cat: 'Forensics', name: 'bulk_extractor', bin: 'bulk_extractor', desc: 'Pull emails, URLs, keys out of any data blob', cmd: 'bulk_extractor -o bulk_out {f} && ls bulk_out' },
  { cat: 'Forensics', name: 'ExifTool', bin: 'exiftool', desc: 'Read/write metadata of almost any file', cmd: 'exiftool {f}' },
  { cat: 'Forensics', name: 'strings', bin: 'strings', desc: 'Printable strings in a file', cmd: 'strings -n 6 {f} | head -100' },
  { cat: 'Forensics', name: 'xxd', bin: 'xxd', desc: 'Hex dump', cmd: 'xxd {f} | head -40' },
  { cat: 'Forensics', name: 'The Sleuth Kit', bin: 'fls', desc: 'Disk-image forensics: mmls, fls, icat, fsstat', cmd: 'mmls {f}; fls -r -p {f} | head -60' },
  { cat: 'Forensics', name: 'PhotoRec / TestDisk', bin: 'photorec', desc: 'Recover deleted files and partitions', cmd: 'photorec /log /d recovered {f}' },
  { cat: 'Forensics', name: 'extundelete', bin: 'extundelete', desc: 'Recover deleted files from ext3/4', cmd: 'extundelete {f} --restore-all', install: 'sudo apt install extundelete' },
  { cat: 'Forensics', name: 'ewf-tools', bin: 'ewfinfo', desc: 'Inspect/mount E01 evidence images', cmd: 'ewfinfo {f}' },
  { cat: 'Forensics', name: 'Volatility 3', bin: 'vol', desc: 'Memory-image forensics (processes, files, hashes)', cmd: 'vol -f {f} windows.info', install: 'pipx install volatility3' },
  { cat: 'Forensics', name: 'creddump', bin: 'pwdump', desc: 'Extract credentials from Windows registry hives', cmd: 'pwdump system sam', install: 'pipx install creddump3' },
  { cat: 'Forensics', name: 'RegRipper', bin: 'regripper', desc: 'Parse Windows registry hives', cmd: 'regripper -r {f} -a | head -80' },
  { cat: 'Forensics', name: 'bkhive / samdump2', bin: 'samdump2', desc: 'Dump Windows password hashes from SAM', cmd: 'samdump2 SYSTEM SAM', install: 'sudo apt install samdump2' },
  { cat: 'Forensics', name: 'pngcheck', bin: 'pngcheck', desc: 'Validate PNG structure/CRCs (spot tampering)', cmd: 'pngcheck -vtp7 {f}' },
  { cat: 'Forensics', name: 'pdf-parser', bin: 'pdf-parser', desc: 'Inspect PDF objects and streams', cmd: 'pdf-parser --stats {f}' },
  { cat: 'Forensics', name: 'pdftotext / pdfinfo', bin: 'pdftotext', desc: 'Extract text and info from PDFs', cmd: 'pdftotext {f} - | head -80' },
  { cat: 'Forensics', name: 'oletools', bin: 'olevba', desc: 'Analyse Office macros / OLE structures', cmd: 'olevba {f}' },
  { cat: 'Forensics', name: 'YARA', bin: 'yara', desc: 'Pattern-match files against rules', cmd: 'yara rules.yar {f}' },
  { cat: 'Forensics', name: 'Audacity', bin: 'audacity', desc: 'Audio editor — inspect waveforms/spectrograms (GUI, WSLg)', cmd: 'audacity {f} &', install: 'sudo apt install audacity' },
  { cat: 'Forensics', name: 'hashdeep', bin: 'hashdeep', desc: 'Hash files recursively for integrity', cmd: 'hashdeep -r .' },

  // ============================================================ NETWORKING / PCAP
  { cat: 'Networking', name: 'Wireshark (GUI)', bin: 'wireshark', desc: 'Full packet analyser (WSLg)', cmd: 'wireshark {f} &' },
  { cat: 'Networking', name: 'tshark', bin: 'tshark', desc: 'Wireshark on the command line', cmd: 'tshark -r {f} -q -z io,phs' },
  { cat: 'Networking', name: 'tshark: export objects', bin: 'tshark', desc: 'Save files transferred over HTTP in a capture', cmd: 'mkdir -p http_objects && tshark -r {f} --export-objects http,http_objects && ls -la http_objects' },
  { cat: 'Networking', name: 'NetworkMiner', bin: 'networkminer', desc: 'Carve files/credentials from pcaps (GUI)', cmd: 'networkminer {f} &', install: 'sudo apt install networkminer' },
  { cat: 'Networking', name: 'Zeek', bin: 'zeek', desc: 'Network-traffic analysis framework', cmd: 'zeek -r {f} && ls *.log', install: 'sudo apt install zeek' },
  { cat: 'Networking', name: 'tcpflow', bin: 'tcpflow', desc: 'Reassemble TCP streams into files', cmd: 'tcpflow -r {f} -o flows && ls flows | head' },
  { cat: 'Networking', name: 'ngrep', bin: 'ngrep', desc: 'grep inside packet payloads', cmd: 'ngrep -I {f} -q -i "flag|pass"' },
  { cat: 'Networking', name: 'Nmap', bin: 'nmap', desc: 'Port/service scanner for a CTF host', cmd: 'nmap -sV -T4 HOST' },
  { cat: 'Networking', name: 'masscan', bin: 'masscan', desc: 'Very fast internet-scale port scanner', cmd: 'masscan HOST -p1-65535 --rate 1000', install: 'sudo apt install masscan' },
  { cat: 'Networking', name: 'netcat', bin: 'nc', desc: 'Talk to a CTF service / move data', cmd: 'echo hello | nc -w 3 HOST PORT' },
  { cat: 'Networking', name: 'socat', bin: 'socat', desc: 'Flexible relays and sockets', cmd: 'socat - TCP:HOST:PORT', install: 'sudo apt install socat' },

  // ============================================================ REVERSING
  { cat: 'Reversing', name: 'Ghidra', bin: 'ghidra', desc: 'NSA decompiler/disassembler suite (GUI, WSLg)', cmd: 'ghidra &', install: 'sudo apt install ghidra' },
  { cat: 'Reversing', name: 'radare2', bin: 'r2', desc: 'Reverse-engineering framework', cmd: "r2 -q -c 'aaa; afl; pdf @ main' {f} | head -120" },
  { cat: 'Reversing', name: 'rizin / cutter', bin: 'rizin', desc: 'radare2 fork with the Cutter GUI', cmd: 'rizin -q -c "aaa; afl" {f}', install: 'sudo apt install rizin cutter' },
  { cat: 'Reversing', name: 'objdump', bin: 'objdump', desc: 'Disassemble (binutils)', cmd: "objdump -d -M intel {f} | grep -A40 '<main>:'" },
  { cat: 'Reversing', name: 'GDB', bin: 'gdb', desc: 'The GNU debugger', cmd: "gdb -batch -ex 'info functions' {f} | head -60" },
  { cat: 'Reversing', name: 'ltrace / strace', bin: 'ltrace', desc: 'Trace library/system calls (leaks comparisons)', cmd: 'chmod +x {f} && echo test | ltrace ./{f} 2>&1 | head -40' },
  { cat: 'Reversing', name: 'Frida', bin: 'frida', desc: 'Dynamic instrumentation / hooking', cmd: 'frida-trace -f {f} -i "strcmp"', install: 'pip install frida-tools' },
  { cat: 'Reversing', name: 'apktool', bin: 'apktool', desc: 'Decode/rebuild Android APK resources & smali', cmd: 'apktool d {f} -o apk_out', install: 'sudo apt install apktool' },
  { cat: 'Reversing', name: 'jadx', bin: 'jadx', desc: 'Decompile Android APK/DEX to Java', cmd: 'jadx {f} -d jadx_out', install: 'sudo apt install jadx' },
  { cat: 'Reversing', name: 'dex2jar', bin: 'd2j-dex2jar', desc: 'Convert Android DEX to a JAR', cmd: 'd2j-dex2jar {f}', install: 'sudo apt install dex2jar' },
  { cat: 'Reversing', name: 'androguard', bin: 'androguard', desc: 'Python toolkit for Android analysis', cmd: 'androguard analyze {f}', install: 'pip install androguard' },
  { cat: 'Reversing', name: 'uncompyle6 / decompyle3', bin: 'uncompyle6', desc: 'Decompile Python .pyc back to source', cmd: 'uncompyle6 {f}', install: 'pip install decompyle3 uncompyle6' },
  { cat: 'Reversing', name: 'upx', bin: 'upx', desc: 'Pack/unpack UPX-compressed binaries', cmd: 'upx -d {f}', install: 'sudo apt install upx-ucl' },
  { cat: 'Reversing', name: 'Java decompilers', bin: 'procyon', desc: 'Decompile .class/.jar (Procyon/CFR)', cmd: 'procyon {f}', install: 'sudo apt install procyon-decompiler' },
  { cat: 'Reversing', name: 'nasm / objdump', bin: 'nasm', desc: 'Assemble/inspect x86 shellcode', cmd: 'nasm -f elf64 sc.asm && objdump -d sc.o', install: 'sudo apt install nasm' },
  { cat: 'Reversing', name: 'IDA Free', bin: null, external: true, url: 'https://hex-rays.com/ida-free/', desc: 'Industry-standard disassembler (free edition)', note: 'Download IDA Free ↗' },
  { cat: 'Reversing', name: 'Binary Ninja', bin: null, external: true, url: 'https://binary.ninja/', desc: 'Commercial reversing platform (cloud demo available)', note: 'Open Binary Ninja ↗' },

  // ============================================================ STEGANOGRAPHY
  { cat: 'Steganography', name: 'zsteg', bin: 'zsteg', desc: 'LSB stego in PNG/BMP', cmd: 'zsteg -a {f} | head -40', install: 'sudo gem install zsteg' },
  { cat: 'Steganography', name: 'steghide', bin: 'steghide', desc: 'Hide/extract data in JPEG/BMP/WAV', cmd: "steghide extract -sf {f} -p '' -f" },
  { cat: 'Steganography', name: 'stegseek', bin: 'stegseek', desc: 'Crack steghide passphrases fast', cmd: 'stegseek {f} /usr/share/wordlists/rockyou.txt' },
  { cat: 'Steganography', name: 'stegcracker', bin: 'stegcracker', desc: 'Brute-force steghide passphrases', cmd: 'stegcracker {f} /usr/share/wordlists/rockyou.txt', install: 'pipx install stegcracker' },
  { cat: 'Steganography', name: 'outguess', bin: 'outguess', desc: 'Outguess JPEG steganography', cmd: 'outguess -r {f} out.txt && cat out.txt' },
  { cat: 'Steganography', name: 'Stegsolve', bin: 'stegsolve', desc: 'Bit-plane / channel browser for images (Java GUI)', cmd: 'stegsolve', install: 'wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve && chmod +x stegsolve' },
  { cat: 'Steganography', name: 'zsteg / exiv2', bin: 'exiv2', desc: 'Inspect and edit image metadata', cmd: 'exiv2 -pa {f}', install: 'sudo apt install exiv2' },
  { cat: 'Steganography', name: 'ImageMagick', bin: 'convert', desc: 'Transform images, split GIF frames', cmd: 'convert {f} -coalesce frame_%03d.png' },
  { cat: 'Steganography', name: 'sox / spectrogram', bin: 'sox', desc: 'Audio → spectrogram (flags hide in audio)', cmd: 'sox {f} -n spectrogram -o spectrogram.png' },
  { cat: 'Steganography', name: 'ffmpeg', bin: 'ffmpeg', desc: 'Split video/GIF into frames; extract audio', cmd: 'mkdir -p frames && ffmpeg -i {f} frames/%04d.png' },
  { cat: 'Steganography', name: 'stegsnow', bin: 'stegsnow', desc: 'Whitespace steganography in text', cmd: 'stegsnow -C {f}', install: 'sudo apt install stegsnow' },
  { cat: 'Steganography', name: 'pngtools / pngcheck', bin: 'pngcheck', desc: 'Inspect PNG chunks for hidden data', cmd: 'pngcheck -vtp7 {f}' },
  { cat: 'Steganography', name: 'AperiSolve', bin: null, external: true, url: 'https://www.aperisolve.com/', desc: 'Runs zsteg/steghide/binwalk/exif on an image in one page', note: 'Open AperiSolve ↗ (web)' },
  { cat: 'Steganography', name: 'StegOnline', bin: null, external: true, url: 'https://stegonline.georgeom.net/', desc: 'Browser bit-plane explorer (Stegsolve in the web)', note: 'Open StegOnline ↗ (web)' },

  // ============================================================ WEB
  { cat: 'Web', name: 'curl', bin: 'curl', desc: 'Fetch a page with headers; send requests', cmd: 'curl -sS -i URL | head -60' },
  { cat: 'Web', name: 'gobuster', bin: 'gobuster', desc: 'Brute-force directories/vhosts/DNS', cmd: 'gobuster dir -u URL -w /usr/share/wordlists/dirb/common.txt -q' },
  { cat: 'Web', name: 'ffuf', bin: 'ffuf', desc: 'Fast web fuzzer (paths, params, auth)', cmd: 'ffuf -u URL/FUZZ -w /usr/share/wordlists/dirb/common.txt' },
  { cat: 'Web', name: 'feroxbuster', bin: 'feroxbuster', desc: 'Recursive content discovery', cmd: 'feroxbuster -u URL', install: 'sudo apt install feroxbuster' },
  { cat: 'Web', name: 'wfuzz', bin: 'wfuzz', desc: 'Web brute-forcer/fuzzer', cmd: 'wfuzz -w /usr/share/wordlists/dirb/common.txt URL/FUZZ', install: 'sudo apt install wfuzz' },
  { cat: 'Web', name: 'sqlmap', bin: 'sqlmap', desc: 'Automated SQL-injection detection & exploitation', cmd: "sqlmap -u 'URL?id=1' --batch --dbs" },
  { cat: 'Web', name: 'commix', bin: 'commix', desc: 'Automated command-injection exploitation', cmd: 'commix -u "URL?q=1" --batch', install: 'sudo apt install commix' },
  { cat: 'Web', name: 'nikto', bin: 'nikto', desc: 'Web-server vulnerability scanner', cmd: 'nikto -h URL', install: 'sudo apt install nikto' },
  { cat: 'Web', name: 'whatweb', bin: 'whatweb', desc: 'Fingerprint web technologies', cmd: 'whatweb URL' },
  { cat: 'Web', name: 'wpscan', bin: 'wpscan', desc: 'WordPress vulnerability scanner', cmd: 'wpscan --url URL', install: 'sudo apt install wpscan' },
  { cat: 'Web', name: 'Burp Suite', bin: 'burpsuite', desc: 'Intercepting web proxy (Community edition, GUI)', cmd: 'burpsuite &', install: 'sudo apt install burpsuite' },
  { cat: 'Web', name: 'OWASP ZAP', bin: 'zaproxy', desc: 'Open-source intercepting proxy/scanner (GUI)', cmd: 'zaproxy &', install: 'sudo apt install zaproxy' },

  // ============================================================ MISC
  { cat: 'Misc', name: '7-Zip', bin: '7z', desc: 'Extract almost any archive format', cmd: '7z x {f} -oextracted' },
  { cat: 'Misc', name: 'sqlite3', bin: 'sqlite3', desc: 'Browse SQLite DBs (browser history, app data)', cmd: 'sqlite3 {f} .tables' },
  { cat: 'Misc', name: 'python3', bin: 'python3', desc: 'Scripting with pwntools/pycryptodome/sympy/z3', cmd: 'python3 solve.py' },
  { cat: 'Misc', name: 'xdotool / wmctrl', bin: 'xdotool', desc: 'Automate GUI apps under WSLg', cmd: 'xdotool key ctrl+c', install: 'sudo apt install xdotool' },
  { cat: 'Misc', name: 'qrencode / zbarimg', bin: 'zbarimg', desc: 'Decode/encode QR and barcodes', cmd: 'zbarimg {f}', install: 'sudo apt install zbar-tools qrencode' },
];

const BINARIES = [...new Set(CATALOG.filter((t) => t.bin && !t.external).map((t) => t.bin))];

module.exports = { CATALOG, BINARIES };
