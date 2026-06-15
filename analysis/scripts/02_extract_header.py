#!/usr/bin/env python3
"""
EAP723 Firmware Header Extraction
Extracts the RSA signature block and encrypted payload from the firmware update file.
"""
import sys
import struct
import os

def extract(fw_path, out_dir="."):
    with open(fw_path, 'rb') as f:
        data = f.read()

    size = len(data)
    payload_size = struct.unpack('>I', data[0:4])[0]
    header_size = size - payload_size

    print(f"Total size:   {size:,} bytes")
    print(f"Header size:  {header_size} bytes")
    print(f"Payload size: {payload_size:,} bytes")

    os.makedirs(out_dir, exist_ok=True)

    # Write size field
    with open(os.path.join(out_dir, "field_size.bin"), 'wb') as f:
        f.write(data[0:4])
    print(f"Written: field_size.bin (4 bytes)")

    # Write RSA signature
    with open(os.path.join(out_dir, "rsa_signature.bin"), 'wb') as f:
        f.write(data[4:260])
    print(f"Written: rsa_signature.bin (256 bytes - potential RSA-2048 signature)")

    # Write extra header field
    with open(os.path.join(out_dir, "header_extra.bin"), 'wb') as f:
        f.write(data[260:header_size])
    print(f"Written: header_extra.bin ({header_size-260} bytes)")

    # Write encrypted payload
    payload = data[header_size:]
    with open(os.path.join(out_dir, "payload_encrypted.bin"), 'wb') as f:
        f.write(payload)
    print(f"Written: payload_encrypted.bin ({len(payload):,} bytes - AES encrypted)")

    print(f"\nTo decrypt (once key is known):")
    print(f"  openssl enc -d -aes-256-cbc -in payload_encrypted.bin -out payload_decrypted.bin -K <HEX_KEY> -iv <HEX_IV> -nopad")
    print(f"  openssl enc -d -aes-128-cbc -in payload_encrypted.bin -out payload_decrypted.bin -K <HEX_KEY> -iv <HEX_IV> -nopad")

if __name__ == "__main__":
    fw = sys.argv[1] if len(sys.argv) > 1 else "firmware/raw/EAP723v2_1.2.2_[20260522-rel25172]_up_signed.bin"
    out = sys.argv[2] if len(sys.argv) > 2 else "analysis/extracted_parts"
    extract(fw, out)
