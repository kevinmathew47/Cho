# Analysis image for Cho CTF Workspace's container mode.
# Build:  docker build -t cho-ctf-tools:latest docker/
# Each command runs in a fresh container: no network by default, challenge folder mounted at /work.
FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      file binutils xxd bsdextrautils unzip p7zip-full \
      libimage-exiftool-perl binwalk foremost pngcheck poppler-utils sqlite3 \
      tshark steghide sox ffmpeg imagemagick \
      python3 python3-pip python3-pycryptodome python3-gmpy2 python3-sympy \
      gdb ltrace strace curl netcat-openbsd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 ctf
USER ctf
WORKDIR /work
