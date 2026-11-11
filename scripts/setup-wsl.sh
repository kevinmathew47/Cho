#!/usr/bin/env bash
# Installs the full CTF solving stack inside WSL (Kali recommended; Ubuntu/Debian also work).
# Covers crypto, passwords, exploitation, forensics, networking, reversing, stego and web.
# Run inside your WSL terminal:   bash /mnt/d/CTF/cho-ctf/scripts/setup-wsl.sh
set -u
say() { printf '\n\033[1;32m[cho]\033[0m %s\n' "$*"; }

say "Updating package lists (enter your Kali password if asked)..."
sudo apt-get update -y

IS_KALI=0
grep -qi kali /etc/os-release && IS_KALI=1

if [ "$IS_KALI" = 1 ]; then
  say "Kali detected: installing the official tool sets (several GB, 20-40 min)."
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    kali-tools-forensics kali-tools-crypto-stego kali-tools-reverse-engineering \
    kali-tools-passwords kali-tools-web kali-tools-sniffing-spoofing \
    || say "A metapackage failed; continuing with individual tools."
fi

PKGS=(
  # basics
  file binutils xxd bsdextrautils curl wget git unzip p7zip-full netcat-openbsd socat python3 python3-pip python3-venv pipx
  build-essential ruby ruby-dev nasm imagemagick ffmpeg sox jq cargo golang-go
  # forensics
  sleuthkit autopsy testdisk ewf-tools dc3dd scalpel foremost bulk-extractor hashdeep yara extundelete
  samdump2 chntpw regripper binwalk libimage-exiftool-perl poppler-utils pdf-parser python3-oletools sqlite3 audacity
  # networking
  tshark wireshark tcpflow ngrep tcpdump zeek masscan nmap
  # stego
  steghide stegseek outguess pngcheck exiv2 stegsnow
  # crypto / passwords
  john john-data hashcat hashid hash-identifier fcrackzip pdfcrack ophcrack hydra patator openssl sagemath
  # exploitation / reversing
  gdb radare2 rizin cutter checksec ltrace strace upx-ucl metasploit-framework
  apktool dex2jar jadx procyon-decompiler
  # web
  gobuster ffuf feroxbuster wfuzz sqlmap commix nikto whatweb wpscan zaproxy burpsuite
  # misc
  xdotool wmctrl zbar-tools qrencode
  # wordlists
  wordlists seclists
)

TO_INSTALL=()
for p in "${PKGS[@]}"; do
  if apt-cache show "$p" >/dev/null 2>&1; then TO_INSTALL+=("$p"); else echo "  - not in repos, skipping: $p"; fi
done
say "Installing ${#TO_INSTALL[@]} apt packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${TO_INSTALL[@]}"

say "Installing Ruby gems (zsteg, one_gadget)..."
sudo gem install zsteg one_gadget 2>/dev/null || echo "  gem install failed (optional)"

say "Installing Python tooling (pwntools, pycryptodome, angr, ROPgadget, volatility3, ...)."
pipx ensurepath 2>/dev/null || true
for t in volatility3 xortool stegcracker ropper creddump3 androguard uncompyle6 rsatool; do
  pipx install "$t" 2>/dev/null || true
done
python3 -m pip install --user --break-system-packages \
  pwntools pycryptodome gmpy2 sympy z3-solver angr ropgadget frida-tools requests 2>/dev/null \
  || python3 -m pip install --user pwntools pycryptodome gmpy2 sympy z3-solver angr ropgadget frida-tools requests \
  || echo "  pip install failed (optional)"

command -v RsaCtfTool >/dev/null 2>&1 || pipx install git+https://github.com/RsaCtfTool/RsaCtfTool 2>/dev/null || true

if [ ! -f stegsolve ] && command -v wget >/dev/null; then
  say "Fetching Stegsolve.jar..."
  wget -q http://www.caesum.com/handbook/Stegsolve.jar -O /usr/local/bin/stegsolve 2>/dev/null && chmod +x /usr/local/bin/stegsolve || true
fi

# rockyou wordlist
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  say "Unpacking rockyou.txt..."
  sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
fi

say "Done. Tool check:"
for t in file strings xxd binwalk foremost scalpel bulk_extractor exiftool mmls fls photorec extundelete samdump2 yara \
         tshark tcpflow ngrep zeek masscan nmap zsteg steghide stegseek outguess exiv2 stegsnow pngcheck sox ffmpeg convert \
         john hashcat hashid hydra patator ophcrack fcrackzip pdfcrack openssl sage xortool RsaCtfTool \
         pwn ROPgadget ropper one_gadget msfconsole checksec gdb r2 rizin ltrace upx apktool jadx d2j-dex2jar frida \
         gobuster ffuf feroxbuster wfuzz sqlmap commix nikto whatweb wpscan zaproxy burpsuite zbarimg python3 7z sqlite3; do
  if command -v "$t" >/dev/null 2>&1; then printf "  \033[32m+\033[0m %s\n" "$t"; else printf "  \033[31m-\033[0m %s\n" "$t"; fi
done
say "Go back to Cho and press the refresh button (top right). You can close this window."
read -r -p "Press Enter to close..." _ || true
