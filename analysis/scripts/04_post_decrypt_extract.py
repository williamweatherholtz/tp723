#!/usr/bin/env python3
"""
EAP723 Post-Decryption Extraction
Run this AFTER successful decryption to extract the inner firmware layers.

Usage:
    python3 04_post_decrypt_extract.py <decrypted.bin> [output_dir]

After extraction, use radare2/Ghidra to analyze individual ELF binaries.
"""
import sys
import os
import subprocess
import struct

def extract_firmware(dec_path, out_dir="analysis/filesystem"):
    os.makedirs(out_dir, exist_ok=True)

    with open(dec_path, 'rb') as f:
        data = f.read()

    print(f"Analyzing decrypted firmware: {dec_path}")
    print(f"Size: {len(data):,} bytes")

    # Run binwalk for signature scan
    print("\n=== Binwalk signature scan ===")
    r = subprocess.run(['binwalk', dec_path], capture_output=True, text=True)
    print(r.stdout)

    # Run binwalk extraction
    print("=== Binwalk extraction ===")
    ext_dir = os.path.join(out_dir, "_binwalk_extract")
    r = subprocess.run(['binwalk', '-e', '-M', '-C', ext_dir, dec_path],
                       capture_output=True, text=True)
    print(r.stdout)
    if r.returncode == 0:
        print(f"Extracted to: {ext_dir}")

    # Walk extracted filesystem for interesting files
    print("\n=== Interesting files in extracted filesystem ===")
    interesting = ['passwd', 'shadow', 'config', 'nvram', 'mtd', 'hostapd',
                   'wpa_supplicant', 'dropbear', 'ssh', 'telnetd', 'httpd',
                   'private_key', '.pem', '.key', 'aes', 'secret', 'token']
    for root, dirs, files in os.walk(ext_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, ext_dir)
            for keyword in interesting:
                if keyword.lower() in fname.lower():
                    print(f"  [INTERESTING] {rel}")
                    break

    print(f"\nNext steps:")
    print(f"  radare2 -A <binary>        # analyze ELF binary")
    print(f"  ghidra                     # GUI decompiler (add binary as project)")
    print(f"  strings <binary> | grep -i key  # look for embedded keys")
    print(f"  firmwalker <extracted_dir> # automated interesting file scanner")

if __name__ == "__main__":
    dec = sys.argv[1] if len(sys.argv) > 1 else "analysis/decrypted/firmware_decrypted.bin"
    out = sys.argv[2] if len(sys.argv) > 2 else "analysis/filesystem"
    extract_firmware(dec, out)
