# Firmware RE Toolset

## Gold Standard Toolset for Embedded Linux Firmware RE

### Tier 1 — Essential (install first)

| Tool | Purpose | Install |
|------|---------|---------|
| **Binwalk** | Firmware scanning, entropy, signature detection, extraction | `apt install binwalk` |
| **Ghidra** | NSA decompiler — best free option, supports MIPS/ARM/AArch64 | Manual from ghidra-sre.org |
| **Radare2** | CLI disassembler/RE framework, scriptable | `apt install radare2` |
| **squashfs-tools** | Extract SquashFS root filesystems | `apt install squashfs-tools` |
| **pycryptodome** | AES/RSA/crypto in Python | `pip3 install pycryptodome` |
| **openssl** | AES decryption from CLI | `apt install openssl` |

### Tier 2 — Highly Recommended

| Tool | Purpose | Install |
|------|---------|---------|
| **Sasquatch** | SquashFS with extra compression (LZMA variants) | Build from devttys0/sasquatch |
| **Jefferson** | JFFS2 filesystem extraction | `pip3 install jefferson` |
| **ubi_reader** | UBI/UBIFS flash filesystem | `pip3 install ubi_reader` |
| **Firmwalker** | Grep extracted FS for keys/passwords/certs | craigz28/firmwalker |
| **tplink-safeloader** | Parse older TP-Link EAP firmware | Build from openwrt/firmware-utils |
| **QEMU user-static** | Run individual ARM/MIPS binaries | `apt install qemu-user-static` |
| **strings + grep** | Fast string hunting | Built-in |

### Tier 3 — Advanced

| Tool | Purpose | Install |
|------|---------|---------|
| **Firmadyne** | Automated full firmware emulation | firmadyne/firmadyne |
| **IDA Pro + HexRays** | Commercial gold standard decompiler | Commercial |
| **GDB + gdbserver** | Dynamic analysis / live debugging | `apt install gdb` |
| **YARA** | Pattern matching rules | `pip3 install yara-python` |
| **Capstone** | Disassembly engine (Python) | `pip3 install capstone` |
| **pyelftools** | Parse ELF binaries in Python | `pip3 install pyelftools` |
| **Wireshark/tshark** | Capture device's update traffic | `apt install wireshark` |
| **mitmproxy** | HTTPS interception | `pip3 install mitmproxy` |

### Hardware Tools (for key extraction)

| Tool | Purpose |
|------|---------|
| **USB-UART adapter** (CH340/CP2102) | UART console access to U-Boot |
| **OpenOCD** | JTAG/SWD debugging and flash dump |
| **Raspberry Pi / Bus Pirate** | JTAG adapter |
| **Logic analyzer** | Protocol analysis on PCB test points |
| **Soldering iron + test clips** | Physical access to UART/JTAG pins |

---

## Workflow for Encrypted TP-Link EAP Firmware

```
1. STATIC ANALYSIS
   binwalk -E firmware.bin          # entropy scan (high = encrypted/compressed)
   binwalk firmware.bin             # signature scan
   python3 01_initial_analysis.py   # our custom header parser

2. KEY RECOVERY (pick one)
   a. UART → U-Boot shell → memory dump
   b. JTAG → full flash dump
   c. GPL source code analysis
   d. Omada Controller jar analysis

3. DECRYPTION
   python3 03_decrypt_attempt.py    # add key to CANDIDATE_KEYS
   openssl enc -d -aes-256-cbc ...  # or direct openssl

4. POST-DECRYPT EXTRACTION
   binwalk -e -M decrypted.bin      # extract all layers
   python3 04_post_decrypt_extract.py

5. FILESYSTEM ANALYSIS
   firmwalker extracted/            # find interesting files
   strings bin/busybox | grep -i key
   
6. BINARY DISASSEMBLY
   ghidra                           # load ELF binaries
   r2 -A binary                     # radare2 CLI analysis
```
