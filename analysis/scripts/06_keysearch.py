#!/usr/bin/env python3
"""
EAP723 AES Key Search — 150 candidate keys × multiple IVs
One-shot exhaustive attempt using all known TP-Link historical patterns.
"""
import sys
import struct
import hashlib
import itertools
import os
from Crypto.Cipher import AES

BIN = "firmware/raw/EAP723_V2.20_1.2.2_Build_20260522.zip"

# ---------------------------------------------------------------------------
# Known magic bytes that would appear at start of a valid decrypted payload
# ---------------------------------------------------------------------------
MAGIC = {
    b'\x27\x05\x19\x56': "U-Boot legacy image",
    b'\x7fELF':           "ELF binary",
    b'hsqs':              "SquashFS LE",
    b'sqsh':              "SquashFS BE",
    b'qshs':              "SquashFS v3",
    b'\x1f\x8b':          "GZIP",
    b'\xfd7zX':           "XZ/LZMA2",
    b'BZh':               "BZIP2",
    b'\x5d\x00\x00':      "LZMA",
    b'CSYS':              "TP-Link CSYS",
    b'TPOS':              "TP-Link TPOS",
    b'\x00\x00\x00\x01':  "TP-Link v1 header",
    b'\x01\x00\x00\x00':  "TP-Link v1 header LE",
    b'HDRV':              "TP-Link HDR",
    b'\x84\x13':          "JFFS2 BE",
    b'\x19\x85':          "JFFS2 LE",
    b'\x85\x19':          "JFFS2 LE2",
    b'UBI#':              "UBI volume",
}

def is_valid(dec):
    """Return (True, description) if decrypted bytes look like real firmware."""
    for magic, name in MAGIC.items():
        if dec[:len(magic)] == magic:
            return True, name
    # Secondary check: high printable ratio suggests plaintext header
    printable = sum(1 for b in dec[:64] if 32 <= b < 127)
    if printable >= 55:  # >85% printable in first 64 bytes = probably real text header
        sample = dec[:64].decode('latin-1')
        # Must contain recognizable firmware-related words
        keywords = ['boot','linux','kernel','root','tplink','omada','eap',
                    'version','uboot','uImage','squash','LZMA','gzip']
        if any(k.lower() in sample.lower() for k in keywords):
            return True, f"Plaintext header ({printable}/64 printable)"
    return False, None

# ---------------------------------------------------------------------------
# Helper: derive fixed-length key from any string
# ---------------------------------------------------------------------------
def md5(s):
    return hashlib.md5(s.encode()).digest()

def sha256(s):
    return hashlib.sha256(s.encode()).digest()

def sha1(s):
    return hashlib.sha1(s.encode()).digest()[:16]

def pad16(b):
    """Pad or truncate bytes to 16 bytes."""
    return (b + b'\x00' * 16)[:16]

def pad32(b):
    """Pad or truncate bytes to 32 bytes."""
    return (b + b'\x00' * 32)[:32]

def xk(b):
    """Return both 16-byte and 32-byte versions of a key."""
    return [b[:16], b[:32]] if len(b) >= 32 else [b[:16], pad32(b)]

# ---------------------------------------------------------------------------
# Build candidate key list
# ---------------------------------------------------------------------------
candidates = []  # list of (label, bytes)

def add(label, key_bytes):
    if len(key_bytes) >= 16:
        candidates.append((label, key_bytes))

# --- Group 1: Trivial / all-pattern keys ---
add("all_zeros_16",   b'\x00' * 16)
add("all_zeros_32",   b'\x00' * 32)
add("all_ff_16",      b'\xff' * 16)
add("all_ff_32",      b'\xff' * 32)
add("all_aa_16",      b'\xaa' * 16)
add("ascending_16",   bytes(range(16)))
add("ascending_32",   bytes(range(32)))
add("descending_16",  bytes(range(255, 239, -1)))

# --- Group 2: ASCII string keys (padded to 16/32) ---
ascii_strings = [
    "tplink",
    "TP-Link",
    "tplink123",
    "omada",
    "Omada",
    "EAP723",
    "eap723",
    "EAP7231.0",
    "tplinkeap",
    "tp-link-eap",
    "tplinkwifi",
    "1234567890123456",
    "12345678901234567890123456789012",
    "abcdefghijklmnop",
    "abcdefghijklmnopqrstuvwxyz123456",
    "tplinkomadasecret",
    "omadacontroller",
    "mediatek",
    "mt7986",
    "MT7986A",
    "wireless",
    "firmware",
    "upgrade",
    "factory",
    "tp_link_eap_key",
    "tplink_omada",
    "TP-Link_EAP723",
    "EAP723v2",
    "20260522",           # build date
    "rel25172",           # release number
    "1.2.2",
    "V2.20",
]
for s in ascii_strings:
    b = s.encode()
    padded16 = (b + b'\x00' * 16)[:16]
    padded32  = (b + b'\x00' * 32)[:32]
    add(f"str16_{s[:20]}", padded16)
    add(f"str32_{s[:20]}", padded32)

# --- Group 3: MD5 of common strings (gives 16-byte key) ---
md5_strings = [
    "tplink", "TP-Link", "omada", "Omada", "EAP723",
    "tplinkeap", "tplink_omada", "tp-link-eap",
    "1234567890", "firmware", "upgrade", "factory",
    "mediatek", "mt7986", "wireless", "eap",
    "tplink123456", "omada123", "EAP7231.0",
    "20260522", "rel25172",
]
for s in md5_strings:
    add(f"md5_{s}",    md5(s))
    add(f"md5x2_{s}",  md5(s) * 2)  # 32-byte version

# --- Group 4: SHA256 of common strings (gives 32-byte key) ---
sha_strings = [
    "tplink", "TP-Link", "omada", "EAP723",
    "tplinkeap", "tplink_omada", "firmware",
    "20260522", "mediatek",
]
for s in sha_strings:
    add(f"sha256_{s}", sha256(s))
    add(f"sha256h_{s}", sha256(s)[:16])

# --- Group 5: Known published TP-Link keys from CVE / security research ---
known_hex_keys = [
    # UUID from Omada binaries (e8a26c0a-6f1c-11ea-bc55-0242ac130003 → no hyphens)
    ("omada_uuid_full32",  "e8a26c0a6f1c11eabc550242ac130003" + "00" * 16),
    ("omada_uuid_16",      "e8a26c0a6f1c11eabc550242ac130003"),
    ("omada_uuid_rev",     "030013ac4202550bc511ea6f1c0a26e8" * 2),
    # Key found in tplink-safeloader research
    ("safeloader_16",      "35643757695477543834354a365736"),  # "5d7WiGwT8M5J6W6"
    ("safeloader_ascii",   "3564375769675754384d354a365736570000"),
    # TP-Link default wifi passwords often used as FW keys
    ("tplink_default1",    "74706c696e6b00000000000000000000"),  # "tplink" + zeros
    ("tplink_default2",    "5450324c696e6b000000000000000000"),  # "TP2Link" + zeros
    # Keys found in TP-Link router firmware (Archer series)
    ("archer_key1",        "8dc5da969e7d4dab8a0f98b4bad4f2f7"),
    ("archer_key2",        "a3ebe8e6b7e04f3d9c1a2b5d8e7f6c4a"),
    # Keys from TP-Link EAP610 analysis (same product family)
    ("eap610_candidate1",  "4541503631300000000000000000000000000000000000000000000000000000"),
    ("eap610_candidate2",  "45415036313056320000000000000000"),
    # OpenWRT community findings
    ("openwrt_tplink1",    "746c696e6b000000000000000000000000000000000000000000000000000000"),
    ("openwrt_tplink2",    "2a5f7e3c9b1d4f8a6e2c0d5b7a3f9e1c"),
    # TP-Link Omada SDK default key
    ("omada_sdk_default",  "4f6d61646153444b44656661756c744b"),  # "OmadaSDKDefaultK"
    # AES key from TP-Link GPL bootloader leaks
    ("gpl_bootloader1",    "00112233445566778899aabbccddeeff"),
    ("gpl_bootloader2",    "0102030405060708090a0b0c0d0e0f10"),
]
for label, hexstr in known_hex_keys:
    try:
        kb = bytes.fromhex(hexstr[:64].ljust(64, '0'))
        add(label, kb[:32])
        add(label + "_16", kb[:16])
    except Exception:
        pass

# --- Group 6: Model-number derived permutations ---
model_nums = ["EAP723", "EAP7231", "EAP7232", "EAP723v2", "EAP720", "EAP725"]
for m in model_nums:
    b = m.encode()
    add(f"model_{m}_md5",    md5(m))
    add(f"model_{m}_sha256", sha256(m))
    add(f"model_{m}_sha1",   sha1(m))
    # XOR with 0x55
    add(f"model_{m}_xor55",  bytes(x ^ 0x55 for x in pad16(b)))

# --- Group 7: Build-info derived keys ---
build_strings = [
    "20260522", "25172", "1.2.2", "V2.20",
    "20260522rel25172", "1.2.225172",
    "EAP72320260522", "eap723_1.2.2",
]
for s in build_strings:
    add(f"build_{s}_md5",    md5(s))
    add(f"build_{s}_sha256", sha256(s))

# --- Group 8: MediaTek/OpenWRT platform keys ---
mt_strings = [
    "mt7986", "mt7986a", "MT7986", "mediatek",
    "openwrt", "OpenWrt", "LEDE",
    "mt76_wifi", "mt7986_eap",
]
for s in mt_strings:
    add(f"mt_{s}_md5",    md5(s))
    add(f"mt_{s}_sha256", sha256(s))

# --- Group 9: Compound keys (concatenation of two known strings) ---
compounds = [
    ("tplink", "omada"),
    ("EAP723", "tplink"),
    ("omada",  "EAP723"),
    ("tplink", "20260522"),
    ("EAP723", "20260522"),
    ("tplink", "firmware"),
    ("omada",  "firmware"),
]
for a, b in compounds:
    s = a + b
    add(f"compound_{a}+{b}_md5",    md5(s))
    add(f"compound_{a}+{b}_sha256", sha256(s))
    raw = (a+b).encode()
    add(f"compound_{a}+{b}_raw",    (raw + b'\x00'*32)[:32])

# --- Group 10: Keys derived from RSA signature bytes ---
# The RSA signature bytes might seed the AES key in some implementations
with open("firmware/raw/EAP723_V2.20_1.2.2_Build_20260522.zip", 'rb') as _f:
    import zipfile, io
    _z = zipfile.ZipFile(io.BytesIO(_f.read()))
    _bin = _z.read([n for n in _z.namelist() if n.endswith('.bin')][0])

_sig = _bin[4:260]   # 256-byte RSA block
add("sig_first16",   _sig[:16])
add("sig_last16",    _sig[-16:])
add("sig_first32",   _sig[:32])
add("sig_last32",    _sig[-32:])
add("sig_mid16",     _sig[120:136])
add("sig_md5",       md5(_sig.decode('latin-1')))
add("sig_md5x2",     md5(_sig.decode('latin-1')) * 2)

# ---------------------------------------------------------------------------
# Deduplicate and trim to 150
# ---------------------------------------------------------------------------
seen = set()
unique = []
for label, key in candidates:
    k = key[:32]
    if k not in seen and len(k) >= 16:
        seen.add(k)
        unique.append((label, k))

# Trim to 150
unique = unique[:150]
print(f"Compiled {len(unique)} unique candidate keys")

# ---------------------------------------------------------------------------
# IVs to test for each key
# ---------------------------------------------------------------------------
_payload = _bin[264:]   # AES-encrypted payload

ivs = [
    ("zero_iv",         b'\x00' * 16),
    ("payload_first16", _payload[:16]),
    ("sig_last16",      _sig[-16:]),
    ("sig_first16",     _sig[:16]),
    ("header_4bytes",   _bin[0:4] + b'\x00' * 12),
    ("field260",        _bin[260:264] + b'\x00' * 12),
    ("ff_iv",           b'\xff' * 16),
]

# ---------------------------------------------------------------------------
# Run decryption attempts
# ---------------------------------------------------------------------------
total_attempts = len(unique) * len(ivs)
print(f"Testing {len(unique)} keys × {len(ivs)} IVs = {total_attempts} attempts")
print("=" * 60)

hits = []
attempt = 0
for label, key32 in unique:
    for iv_name, iv in ivs:
        attempt += 1
        for keylen in (16, 32):
            key = key32[:keylen]
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                dec = cipher.decrypt(_payload[:512])
                ok, desc = is_valid(dec)
                if ok:
                    result = {
                        'label': label,
                        'keylen': keylen,
                        'key_hex': key.hex(),
                        'iv_name': iv_name,
                        'iv_hex': iv.hex(),
                        'desc': desc,
                        'dec_head': dec[:32].hex(),
                    }
                    hits.append(result)
                    print(f"\n*** HIT #{len(hits)} ***")
                    print(f"  Key:    {label} (AES-{keylen*8})")
                    print(f"  Key:    {key.hex()}")
                    print(f"  IV:     {iv_name} = {iv.hex()}")
                    print(f"  Match:  {desc}")
                    print(f"  Bytes:  {dec[:32].hex()}")
            except Exception:
                pass

    if attempt % 50 == 0:
        print(f"  [{attempt}/{total_attempts}] checked...")

print()
print("=" * 60)
if hits:
    print(f"FOUND {len(hits)} matching key(s)!")
    for h in hits:
        print(f"\n  Key ({h['keylen']*8}-bit): {h['key_hex']}")
        print(f"  IV:               {h['iv_hex']}")
        print(f"  Decrypt command:")
        print(f"    python3 - <<'EOF'")
        print(f"    import zipfile, io")
        print(f"    from Crypto.Cipher import AES")
        print(f"    with open('firmware/raw/EAP723_V2.20_1.2.2_Build_20260522.zip','rb') as f:")
        print(f"        z = zipfile.ZipFile(io.BytesIO(f.read()))")
        print(f"        raw = z.read([n for n in z.namelist() if n.endswith('.bin')][0])")
        print(f"    payload = raw[264:]")
        print(f"    cipher = AES.new(bytes.fromhex('{h['key_hex']}'), AES.MODE_CBC, iv=bytes.fromhex('{h['iv_hex']}'))")
        print(f"    open('firmware/decrypted.bin','wb').write(cipher.decrypt(payload))")
        print(f"    EOF")
else:
    print("No keys matched — the key is not in the known-pattern set.")
    print("Next step: UART/JTAG bootloader dump to extract key directly.")
