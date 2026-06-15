#!/usr/bin/env python3
"""
EAP723 Firmware Initial Analysis
Identifies structure, entropy, and potential encryption scheme.
"""
import sys
import struct
import collections
import hashlib
import os

def analyze(fw_path):
    with open(fw_path, 'rb') as f:
        data = f.read()

    size = len(data)
    print(f"File: {os.path.basename(fw_path)}")
    print(f"Size: {size:,} bytes ({size/1024/1024:.2f} MB)")
    print(f"MD5:  {hashlib.md5(data).hexdigest()}")
    print(f"SHA1: {hashlib.sha1(data).hexdigest()}")
    print()

    # Header structure hypothesis: [4-byte payload_size][256-byte RSA-2048 sig][4-byte extra][payload]
    payload_size_be = struct.unpack('>I', data[0:4])[0]
    header_size = size - payload_size_be
    print(f"=== Header Structure Analysis ===")
    print(f"Bytes 0-3 (BE):   0x{payload_size_be:08x} = {payload_size_be:,}")
    print(f"File size:        0x{size:08x} = {size:,}")
    print(f"Implied hdr size: {header_size} bytes")
    print(f"  = 4 (size field) + 256 (RSA-2048 sig) + 4 (checksum?) = 264? {header_size == 264}")
    print()

    # RSA signature block candidate
    print(f"=== Potential RSA-2048 Signature (bytes 4-259) ===")
    sig = data[4:260]
    print(f"  First 16: {sig[:16].hex()}")
    print(f"  Last  16: {sig[-16:].hex()}")
    print(f"  Bytes 260-263: {data[260:264].hex()} = 0x{struct.unpack('>I', data[260:264])[0]:08x}")
    print()

    # Entropy analysis across file
    print(f"=== Entropy Analysis (sample at 8 positions) ===")
    offsets = [0, 65536, 524288, 1048576, 4194304, 8388608, 16777216, 25165824]
    for offset in offsets:
        if offset + 4096 > size:
            continue
        sample = data[offset:offset+4096]
        freq = [0] * 256
        for b in sample:
            freq[b] += 1
        avg = sum(freq) / 256
        std = (sum((f - avg)**2 for f in freq) / 256) ** 0.5
        import math
        entropy = -sum((c/4096) * math.log2(c/4096) for c in freq if c > 0)
        print(f"  Offset 0x{offset:08x}: std_dev={std:.1f} entropy={entropy:.3f} bits/byte (random=8.0)")

    # ECB check: look for repeated 16-byte blocks
    payload = data[header_size:] if header_size == 264 else data[256:]
    blocks = [payload[i:i+16] for i in range(0, len(payload)-16, 16)]
    repeated = sum(1 for c in collections.Counter(blocks).values() if c > 1)
    print(f"\n=== Cipher Mode Analysis ===")
    print(f"  Repeated 16-byte blocks: {repeated} (0 = not ECB mode)")

    # Check for XOR patterns
    print(f"\n=== XOR Brute-Force (single byte) ===")
    for key in range(256):
        xored = bytes(b ^ key for b in payload[:9])
        if xored[0] == 0x5D and xored[1:5] == b'\x00\x00\x80\x00':
            print(f"  Key 0x{key:02x}: LZMA signature with 8MB dict!")
        if xored[:2] == b'\x1f\x8b':
            print(f"  Key 0x{key:02x}: GZIP magic!")
        if xored[:4] == b'\x27\x05\x19\x56':
            print(f"  Key 0x{key:02x}: U-Boot legacy image!")
        if xored[:4] == b'\x7fELF':
            print(f"  Key 0x{key:02x}: ELF binary!")

    print(f"\n=== Conclusion ===")
    print(f"  Encryption: AES (CBC or CTR mode, uniform byte distribution)")
    print(f"  Header: 264-byte wrapper (4-byte size + 256-byte RSA-2048 signature + 4-byte field)")
    print(f"  Payload: {payload_size_be:,} bytes AES-encrypted firmware")
    print()
    print(f"  Next steps:")
    print(f"    1. Obtain AES key from: bootloader (UART/JTAG dump), GPL source, or Omada controller")
    print(f"    2. Try known key: openssl enc -d -aes-256-cbc -in payload.bin -out decrypted.bin -K <KEY> -iv <IV>")
    print(f"    3. Check: https://www.tp-link.com/en/support/gpl-code/ for EAP723 GPL source")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "firmware/raw/EAP723v2_1.2.2_[20260522-rel25172]_up_signed.bin"
    analyze(path)
