#!/bin/bash
# Full firmware reverse engineering toolset installer
# Tested on Ubuntu 22.04/24.04

set -e
echo "[*] Installing firmware RE toolset for EAP723 analysis"

# Core system tools
apt-get update -qq
apt-get install -y -qq \
    binwalk \
    squashfs-tools \
    p7zip-full \
    python3-pip \
    python3-magic \
    lzma lzop \
    mtd-utils \
    u-boot-tools \
    radare2 \
    qemu-system-arm \
    qemu-user-static \
    liblzma-dev \
    libssl-dev \
    cmake \
    git \
    build-essential \
    openssl \
    nmap \
    wireshark-common \
    tshark

# Python RE libraries
pip3 install --quiet \
    pycryptodome \
    ubi_reader \
    yara-python \
    capstone \
    pyelftools

# Build OpenWRT firmware-utils (tplink-safeloader + many vendor tools)
echo "[*] Building OpenWRT firmware-utils..."
cd /tmp
if [ ! -d firmware-utils ]; then
    git clone --depth=1 https://github.com/openwrt/firmware-utils.git
fi
cd /tmp/firmware-utils
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF 2>/dev/null
make -j"$(nproc)" 2>/dev/null
cp /tmp/firmware-utils/build/tplink-safeloader /usr/local/bin/
echo "[+] tplink-safeloader installed to /usr/local/bin/"

# Install Ghidra (NSA decompiler - best free decompiler for MIPS/ARM)
echo "[*] Checking for Ghidra..."
if ! command -v ghidra &>/dev/null; then
    echo "[!] Ghidra not found. Install manually:"
    echo "    wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.x/ghidra_11.x.zip"
    echo "    unzip ghidra_11.x.zip -d /opt/"
    echo "    ln -s /opt/ghidra_*/ghidraRun /usr/local/bin/ghidra"
fi

# Install sasquatch (squashfs with additional compression support)
echo "[*] Building sasquatch (extended squashfs)..."
cd /tmp
if [ ! -d sasquatch ]; then
    git clone --depth=1 https://github.com/devttys0/sasquatch.git 2>/dev/null || true
fi
if [ -d sasquatch ]; then
    cd sasquatch && ./build.sh 2>/dev/null && cp sasquatch /usr/local/bin/ && echo "[+] sasquatch installed"
fi

# Install jefferson (JFFS2 extraction)
pip3 install --quiet jefferson 2>/dev/null && echo "[+] jefferson installed" || true

# Install firmwalker
if [ ! -f /usr/local/bin/firmwalker ]; then
    cd /tmp
    git clone --depth=1 https://github.com/craigz28/firmwalker.git 2>/dev/null || true
    if [ -d firmwalker ]; then
        cp /tmp/firmwalker/firmwalker.sh /usr/local/bin/firmwalker
        chmod +x /usr/local/bin/firmwalker
        echo "[+] firmwalker installed"
    fi
fi

echo ""
echo "[+] Installation complete. Available tools:"
echo "    binwalk          - firmware scanning and extraction"
echo "    tplink-safeloader - TP-Link specific firmware format (older EAP)"
echo "    radare2 / r2     - disassembly and binary analysis"
echo "    sasquatch        - SquashFS extraction (extended compression)"
echo "    jefferson        - JFFS2 filesystem extraction"
echo "    firmwalker       - filesystem interesting-file scanner"
echo "    openssl          - AES decryption once key known"
echo "    python3 + pycryptodome - crypto scripting"
echo "    qemu-user-static - run extracted ARM/MIPS binaries"
echo ""
echo "    Ghidra (manual install required) - best free decompiler"
