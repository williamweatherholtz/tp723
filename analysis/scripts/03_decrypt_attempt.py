#!/usr/bin/env python3
"""
EAP723 Firmware AES Decryption Attempt
Tests candidate keys and IVs. Edit CANDIDATE_KEYS to add new keys as they are discovered.

Key sources to investigate:
  - UART console: Boot into recovery mode, dump /dev/mtd0 (bootloader)
  - JTAG: Full flash dump including bootloader partition
  - Omada Controller: Search for keys in /opt/tplink/EAPController/lib/*.jar
  - GPL source: TP-Link GPL release may include build scripts with embedded keys
  - update_util binary: Reverse the Windows/macOS Omada app update utility
  - Previous firmware: Known-plaintext attack if older unencrypted version exists
"""
import sys
import struct
import os
from Crypto.Cipher import AES

# --- Add discovered keys here ---
CANDIDATE_KEYS = [
    # (name, key_hex, notes)
    # ("omada_v1", "e8a26c0a6f1c11eabc550242ac130003", "UUID found in some Omada binaries"),
    # ("eap723_key", "<64_hex_chars_for_AES256>", "Found in bootloader at offset 0x..."),
]

MAGIC_CHECKS = {
    b'\x27\x05\x19\x56': "U-Boot legacy image",
    b'\x7fELF':           "ELF binary",
    b'hsqs':              "SquashFS (little-endian)",
    b'sqsh':              "SquashFS (big-endian)",
    b'\x1f\x8b':          "GZIP",
    b'\xfd7zX':           "XZ/LZMA2",
    b'BZh':               "BZIP2",
    b'\x85\x19':          "JFFS2 (little-endian)",
    b'CSYS':              "TP-Link CSYS container",
}

def try_decrypt(payload, key_hex, iv_hex, label):
    try:
        key = bytes.fromhex(key_hex)
        iv  = bytes.fromhex(iv_hex)
        if len(key) not in (16, 24, 32):
            print(f"  SKIP {label}: invalid key length {len(key)}")
            return None
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        dec = cipher.decrypt(payload[:4096])

        for magic, name in MAGIC_CHECKS.items():
            if dec[:len(magic)] == magic:
                print(f"  *** HIT: {label}: {name} at start!")
                return dec

        # Check for valid plaintext deeper
        readable = sum(1 for b in dec[:256] if 32 <= b < 127)
        if readable > 200:  # >78% printable = likely text
            print(f"  POSSIBLE {label}: {readable}/256 printable chars")
            print(f"    {dec[:64]}")
        return None
    except Exception as e:
        print(f"  ERROR {label}: {e}")
        return None

def run(fw_path, out_dir="."):
    with open(fw_path, 'rb') as f:
        data = f.read()

    size = len(data)
    payload_size = struct.unpack('>I', data[0:4])[0]
    header_size  = size - payload_size
    payload = data[header_size:]

    # IVs to test
    ivs = {
        "zero_iv":    "00" * 16,
        "payload_iv": payload[:16].hex(),
        "sig_end_iv": data[248:264].hex(),
        "size_field": data[0:4].hex() + "00" * 12,
    }

    print(f"Payload: {len(payload):,} bytes, testing {len(CANDIDATE_KEYS)} key(s) x {len(ivs)} IVs")
    print()

    if not CANDIDATE_KEYS:
        print("No candidate keys defined. Add keys to CANDIDATE_KEYS list.")
        print("See header comments for key recovery strategies.")
        return

    for name, key_hex, notes in CANDIDATE_KEYS:
        print(f"Key: {name} ({notes})")
        for iv_name, iv_hex in ivs.items():
            result = try_decrypt(payload, key_hex, iv_hex, f"{name}+{iv_name}")
            if result:
                out_path = os.path.join(out_dir, f"decrypted_{name}_{iv_name}.bin")
                with open(out_path, 'wb') as f:
                    f.write(result)
                print(f"  Saved decrypted output: {out_path}")
                print(f"  Run: binwalk {out_path}")

if __name__ == "__main__":
    fw  = sys.argv[1] if len(sys.argv) > 1 else "firmware/raw/EAP723v2_1.2.2_[20260522-rel25172]_up_signed.bin"
    out = sys.argv[2] if len(sys.argv) > 2 else "analysis/decrypted"
    os.makedirs(out, exist_ok=True)
    run(fw, out)
