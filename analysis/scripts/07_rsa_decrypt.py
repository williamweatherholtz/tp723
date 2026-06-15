#!/usr/bin/env python3
"""
EAP723 RSA-based AES Key Recovery

Uses RSA public keys extracted from older EAP723 firmware's product-info file
(CAPI PUBLICKEYBLOB format) to perform raw RSA public-key operation on the
256-byte signature block in the encrypted firmware header.

TP-Link scheme (watchfulip/robbins research):
  encrypted_firmware = [4-byte size][256-byte RSA block][4-byte extra][AES payload]
  AES_key (+IV) = PKCS1_unpad(RSA_pub_op(sig_block, e, n))
"""
import base64
import struct
import sys
import zipfile
import io
from Crypto.Cipher import AES

FIRMWARE_ZIP = "firmware/raw/EAP723_V2.20_1.2.2_Build_20260522.zip"

# RSA public keys from product-info.EAP723_2_0 (old 1.0.4 firmware rootfs)
# These are Microsoft CAPI PUBLICKEYBLOB format (base64 encoded)
CAPI_KEYS = {
    "key": "BgIAAAAkAABSU0ExAAQAAAEAAQDZtUNzD6KsxO4Tfx/Sp8S7w8TwPWwoppXy77wSPNs5WoV+Wr4kh09nu70vHVmSPji5KFUG+hmRjapsJsIJj+M0Zmd4EycKY8r0Ea3D4XO/uvloX4VHVPsDZkm8Krian5iNy6BgApVlebx0zQxto0GkgvPBq1nhoZxJNapLghGO7w==",
    "rsaKey": "BgIAAACkAABSU0ExAAQAAAEAAQDzyeWCpUptcSIr3Wuk6j3wEyGLbCalB127Ge315dfiwAV8UfeMi9m34xauO62IMNPSSm5biNChqO+eDyLG2dSndRA+BYnh6xFYu9t6PkxiJRvaumwejQwork0ohtXuqBC8k4yd1HlXcsI/rzvgZ0eDon5mdUzQ6Ac0iLA3RXDAng==",
}

def parse_capi_pubkey(b64_str):
    """Parse Microsoft CAPI PUBLICKEYBLOB → (n, e, bitlen)."""
    blob = base64.b64decode(b64_str)
    btype    = blob[0]    # 06 = PUBLICKEYBLOB
    bver     = blob[1]    # 02 = CUR_BLOB_VERSION
    # blob[2:4] = reserved
    aiKeyAlg = struct.unpack_from('<I', blob, 4)[0]
    magic    = blob[8:12]  # b"RSA1"
    bitlen   = struct.unpack_from('<I', blob, 12)[0]
    pubexp   = struct.unpack_from('<I', blob, 16)[0]
    mod_le   = blob[20 : 20 + bitlen // 8]
    n        = int.from_bytes(mod_le, 'little')  # CAPI: little-endian modulus
    print(f"  bType=0x{btype:02x} bVer=0x{bver:02x} aiKeyAlg=0x{aiKeyAlg:08x}")
    print(f"  magic={magic} bitlen={bitlen} pubexp={pubexp} (0x{pubexp:x})")
    print(f"  modulus ({bitlen}-bit): {n.to_bytes(bitlen//8,'big').hex()[:64]}...")
    return n, pubexp, bitlen

def rsa_raw(sig_bytes, e, n):
    """Raw RSA public key operation: m = sig^e mod n."""
    sig_int = int.from_bytes(sig_bytes, 'big')
    m_int   = pow(sig_int, e, n)
    return m_int.to_bytes(len(sig_bytes), 'big')

def pkcs1_unpad_v15(m_bytes):
    """
    PKCS#1 v1.5 unpadding.
    Format: 00 01 [FF ... FF] 00 [message]   (signature / type 1)
         or 00 02 [random]   00 [message]   (encryption / type 2)
    Returns the inner message bytes, or None if not valid PKCS1.
    """
    if m_bytes[0] != 0x00:
        return None, "first byte not 0x00"
    pad_type = m_bytes[1]
    if pad_type not in (0x01, 0x02):
        return None, f"unknown pad type 0x{pad_type:02x}"
    try:
        sep = m_bytes.index(0x00, 2)
    except ValueError:
        return None, "no 0x00 separator found"
    msg = m_bytes[sep+1:]
    return msg, f"PKCS1 type {pad_type} ok, message {len(msg)} bytes"

MAGIC = {
    b'\x27\x05\x19\x56': "U-Boot legacy image",
    b'\x7fELF':           "ELF binary",
    b'hsqs':              "SquashFS LE",
    b'sqsh':              "SquashFS BE",
    b'\x1f\x8b':          "GZIP",
    b'\xfd7zX':           "XZ/LZMA2",
    b'BZh':               "BZIP2",
    b'\x5d\x00\x00':      "LZMA",
    b'CSYS':              "TP-Link CSYS",
    b'TPOS':              "TP-Link TPOS",
    b'\x00\x00\x00\x01':  "TP-Link v1 header",
    b'HDRV':              "TP-Link HDR",
    b'\x84\x13':          "JFFS2 BE",
    b'\x19\x85':          "JFFS2 LE",
    b'UBI#':              "UBI volume",
}

def check_magic(data):
    for magic, name in MAGIC.items():
        if data[:len(magic)] == magic:
            return name
    return None

def try_aes(payload, key_bytes, iv_bytes, label):
    """Try AES-CBC decryption and check result."""
    for keylen in (16, 24, 32):
        k = key_bytes[:keylen]
        if len(k) < keylen:
            continue
        try:
            cipher = AES.new(k, AES.MODE_CBC, iv=iv_bytes[:16])
            dec = cipher.decrypt(payload[:512])
            hit = check_magic(dec)
            if hit:
                print(f"  *** HIT: {label} AES-{keylen*8} → {hit} ***")
                print(f"      key={k.hex()} iv={iv_bytes[:16].hex()}")
                print(f"      first 32 bytes: {dec[:32].hex()}")
                return k, iv_bytes[:16], dec
        except Exception as ex:
            pass
    return None, None, None

# ---------------------------------------------------------------------------
# Load firmware
# ---------------------------------------------------------------------------
print("=" * 60)
print("EAP723 RSA Key Recovery + AES Decryption")
print("=" * 60)

with open(FIRMWARE_ZIP, 'rb') as f:
    z = zipfile.ZipFile(io.BytesIO(f.read()))
    bins = [n for n in z.namelist() if n.endswith('.bin')]
    print(f"Zip contains: {z.namelist()}")
    raw = z.read(bins[0])

size_be   = struct.unpack('>I', raw[0:4])[0]
sig_block = raw[4:260]       # 256-byte RSA signature block
extra     = raw[260:264]
payload   = raw[264:]        # AES-encrypted firmware payload

print(f"Firmware: {len(raw):,} bytes, payload={size_be:,} bytes")
print(f"Sig block first 16: {sig_block[:16].hex()}")
print(f"Extra field: {extra.hex()}")
print()

# ---------------------------------------------------------------------------
# Process each RSA key
# ---------------------------------------------------------------------------
hits = []

for key_name, b64 in CAPI_KEYS.items():
    print(f"\n--- RSA key: '{key_name}' ---")
    n, e, bitlen = parse_capi_pubkey(b64)
    key_size = bitlen // 8  # 128 bytes for 1024-bit

    # RSA operation on signature block
    # The sig_block is 256 bytes; we may need only key_size bytes
    # Try both first key_size bytes and last key_size bytes
    sig_candidates = {
        "sig_first":  sig_block[:key_size],
        "sig_last":   sig_block[-key_size:],
        "sig_block":  sig_block if key_size == 256 else None,
    }

    for sig_label, sig_bytes in sig_candidates.items():
        if sig_bytes is None:
            continue
        print(f"\n  Trying RSA op on {sig_label} ({len(sig_bytes)} bytes)...")
        try:
            m = rsa_raw(sig_bytes, e, n)
            print(f"  RSA result: {m.hex()}")

            msg, status = pkcs1_unpad_v15(m)
            print(f"  PKCS1 unpad: {status}")

            if msg is not None:
                print(f"  Inner message ({len(msg)} bytes): {msg.hex()}")
                # Extract AES key and IV from the inner message
                # Common layouts:
                #   [16-byte key] (AES-128, zero IV)
                #   [32-byte key] (AES-256, zero IV)
                #   [16-byte key][16-byte IV]
                #   [32-byte key][16-byte IV]
                for klen in (16, 24, 32):
                    if len(msg) >= klen:
                        k = msg[:klen]
                        iv_zero = b'\x00' * 16
                        # Also try: IV from message if long enough
                        iv_from_msg = msg[klen:klen+16] if len(msg) >= klen+16 else iv_zero
                        for iv_label, iv in [("zero_iv", iv_zero),
                                              ("msg_iv", iv_from_msg),
                                              ("sig_first16", sig_block[:16]),
                                              ("extra+zeros", extra + b'\x00'*12)]:
                            lbl = f"{key_name}/{sig_label}/AES{klen*8}/{iv_label}"
                            k_out, iv_out, dec = try_aes(payload, k, iv, lbl)
                            if k_out:
                                hits.append((lbl, k_out, iv_out, dec))
            else:
                # Even without valid PKCS1, try raw RSA output bytes as key
                print(f"  No PKCS1 padding — trying raw RSA output as key...")
                for iv_label, iv in [("zero_iv", b'\x00'*16),
                                      ("sig_first16", sig_block[:16]),
                                      ("payload_first16", payload[:16])]:
                    lbl = f"{key_name}/{sig_label}/raw/{iv_label}"
                    k_out, iv_out, dec = try_aes(payload, m, iv, lbl)
                    if k_out:
                        hits.append((lbl, k_out, iv_out, dec))
                    # Also try last 16/32 bytes of RSA result
                    k_out, iv_out, dec = try_aes(payload, m[-32:], iv, lbl+"_tail")
                    if k_out:
                        hits.append((lbl+"_tail", k_out, iv_out, dec))

        except Exception as ex:
            print(f"  RSA op failed: {ex}")

# ---------------------------------------------------------------------------
# Also try: RSA on full 256-byte block with both keys (for 256-bit RSA — unlikely
# but covers edge case where key is concatenated or double-applied)
# ---------------------------------------------------------------------------
print("\n--- Extra: trying payload_first16 as IV with RSA results ---")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
if hits:
    print(f"SUCCESS: {len(hits)} decryption hit(s)!")
    for label, key, iv, dec in hits:
        print(f"\n  Label: {label}")
        print(f"  Key:   {key.hex()}")
        print(f"  IV:    {iv.hex()}")
        print(f"  Magic: {check_magic(dec)}")
        print(f"  Head:  {dec[:32].hex()}")

    # Write decrypted output for first hit
    label, key, iv, dec_head = hits[0]
    print(f"\nDecrypting full payload ({len(payload):,} bytes)...")
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(payload)
    outpath = "firmware/decrypted.bin"
    with open(outpath, 'wb') as f:
        f.write(decrypted)
    print(f"Written: {outpath} ({len(decrypted):,} bytes)")
else:
    print("No decryption hits with RSA-derived keys.")
    print("The RSA keys from EAP723 1.0.4 may not match this firmware version.")
    print("Next: try UART/JTAG to dump bootloader and extract key directly.")
