# EAP723 Firmware Reverse Engineering Notes

## Firmware File
- **File**: `EAP723_V2.20_1.2.2_Build_20260522.zip`
- **Inner binary**: `EAP723v2_1.2.2_[20260522-rel25172]_up_signed.bin`
- **Size**: 29,863,640 bytes (28.5 MB)
- **MD5**: 6d05037a340b18eda1a44bc2c0c1cc0b
- **Device**: TP-Link EAP723 (Omada WiFi 6E Access Point, AXE5400)
- **Firmware version**: V2.20, Build 1.2.2, Release 25172, Date 20260522

---

## Binary Structure (Discovered)

```
Offset       Size    Content
─────────────────────────────────────────────────────────────
0x00000000   4       Payload size field = 0x01C7ADD0 (29,863,376 bytes)
0x00000004   256     RSA-2048 signature (verifies payload integrity)
0x00000104   4       Extra header field = 0x9D2F3821 (purpose TBD)
0x00000108   29,863,376  AES-encrypted firmware payload
─────────────────────────────────────────────────────────────
Total: 0x01C7AED8 = 29,863,640 bytes
```

**Key observation**: `file_size - header_size = 29,863,640 - 264 = 29,863,376 = first_4_bytes_BE`

---

## Encryption Analysis

| Property          | Finding                                          |
|-------------------|--------------------------------------------------|
| Entropy           | ~8.0 bits/byte (uniformly distributed)           |
| ECB mode          | **No** (zero repeated 16-byte blocks in 1.87M)  |
| XOR cipher        | **No** (byte distribution std_dev = 16.3 ≈ 16.0 random) |
| Cipher mode       | **AES-CBC or AES-CTR** (highest probability)     |
| Key size          | AES-128, AES-192, or AES-256 (unknown)          |
| IV location       | Unknown - possibly first 16 bytes of payload, zero, or from bootloader NVRAM |

Binwalk found only 1 hit: MySQL ISAM v5 false-positive at 0xE9ADEF. No real filesystem magic anywhere.

---

## Tools Analysis Results

| Tool              | Result                                        |
|-------------------|-----------------------------------------------|
| `binwalk`         | 1 false-positive, no real signatures found    |
| `tplink-safeloader -i` | "cannot find fwuphdr" — newer format  |
| `file`            | "data" (opaque binary)                        |
| OpenWRT safeloader| Supports up to EAP615, not EAP723             |

---

## Decryption: What We Need

### Option 1: UART Console (Recommended)
1. Open EAP723 — locate UART header pins (usually 4-pin near CPU)
2. Connect 3.3V UART-to-USB adapter at 115200 8N1
3. Boot to U-Boot prompt (interrupt boot: `tpl` or space bar)
4. Dump bootloader: `md.b 0x00000000 0x10000` (modify for your flash map)
5. Search dumped bytes for 16/32-byte AES key patterns

### Option 2: JTAG
1. Identify JTAG pins on PCB (TCK/TMS/TDI/TDO/TRST)
2. Use OpenOCD + Raspberry Pi or dedicated JTAG adapter
3. Dump full flash including bootloader partition

### Option 3: GPL Source Code (Legal)
- TP-Link MUST provide GPL source code: https://www.tp-link.com/en/support/gpl-code/
- Search for "EAP723" in the GPL release
- The build scripts and bootloader source may contain the key
- Contact: opensource@tp-link.com

### Option 4: Omada Controller Analysis  
1. Install Omada Controller (Linux/Windows/Docker)
2. Search jar files: `jar xf EAPController.jar && grep -r "key\|aes\|secret" .`
3. The controller validates and processes firmware updates — may have the key

### Option 5: Known-Plaintext Attack
- If an older unencrypted EAP723 firmware exists, use it as known plaintext
- Firmware updates often patch specific byte ranges — useful for differential analysis

---

## Hardware Info (EAP723)

| Component     | Spec                                        |
|---------------|---------------------------------------------|
| WiFi          | 6E (2.4/5/6 GHz), AXE5400                 |
| CPU           | Qualcomm IPQ5332 (Arm Cortex-A53 quad-core) |
| RAM           | 512 MB DDR4                                 |
| Flash         | 128 MB NAND                                 |
| OS            | OpenWRT-based Linux                         |
| Boot          | U-Boot (Qualcomm Secure Boot, signed MBN)   |

**Confirmed by `show modules` on live device:** `qca_ol`, `umac`, `ipq_cnss2`, `qca_nss_*` — all Qualcomm IPQ5332 kernel modules.

**Flash map (from fw_data partition table, EAP723 v1.0.4 rootfs):**
```
APPSBL at 0x00880000: common/openwrt-ipq5332-u-boot.mbn
file-system at 0x01000000: squashfs rootfs
mtdblock19: running squashfs root (decrypted V2.20 in live device)
```

**Note:** Earlier notes incorrectly identified the SoC as MediaTek MT7986A — confirmed IPQ5332 (Qualcomm) via live kernel module inspection.

---

## Radare2 Quick Reference (once decrypted)

```bash
# Load and analyze firmware
r2 -a arm -b 64 decrypted_kernel.bin

# List functions
afl

# Disassemble function
pdf @ sym.main

# Search for strings
iz

# Search for AES S-box (find crypto routines)
/x 637c777b   # AES S-box first 4 bytes
```

## Ghidra (Recommended for decompilation)
1. New Project → Import file → select kernel/rootfs binary
2. Auto-analyze: Language = MIPS:BE:32 (older EAP) or ARM:LE:64 (IPQ5332/EAP723)
3. Search → Memory → `\x1f\x8b` to find compression boundaries

---

## References
- OpenWRT TP-Link safeloader: https://github.com/openwrt/firmware-utils/blob/master/src/tplink-safeloader.c
- OpenWRT EAP hardware tables: https://openwrt.org/toh/tp-link/eap_series
- TP-Link GPL source: https://www.tp-link.com/en/support/gpl-code/
- binwalk: https://github.com/ReFirmLabs/binwalk
- Ghidra: https://ghidra-sre.org/
