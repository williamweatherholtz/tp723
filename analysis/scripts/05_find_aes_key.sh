#!/bin/bash
# EAP723 AES Key Recovery - Search extracted filesystems for key material
# Run after extracting a bootloader dump or similar image

SEARCH_DIR="${1:-.}"
echo "Searching for AES key material in: $SEARCH_DIR"
echo ""

echo "=== AES key-sized entropy strings (16/24/32 bytes) ==="
# Look for 32-byte hex strings (AES-256 key)
grep -roa '[0-9a-fA-F]\{64\}' "$SEARCH_DIR" 2>/dev/null | head -20

echo ""
echo "=== Base64-encoded keys ==="
grep -roa '[A-Za-z0-9+/]\{44\}=' "$SEARCH_DIR" 2>/dev/null | head -20

echo ""
echo "=== Interesting binary strings ==="
strings -n 8 "$SEARCH_DIR" 2>/dev/null | grep -iE 'aes|key|secret|encrypt|decrypt|cipher|omada|tplink' | head -30

echo ""
echo "=== Potential raw key bytes at known offsets ==="
# Bootloader typically stores key at fixed offsets - check if this is a bootloader dump
if [ -f "$SEARCH_DIR" ]; then
    echo "Bytes at offset 0x1000 (4096): $(dd if="$SEARCH_DIR" bs=1 skip=4096 count=32 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    echo "Bytes at offset 0x2000 (8192): $(dd if="$SEARCH_DIR" bs=1 skip=8192 count=32 2>/dev/null | od -An -tx1 | tr -d ' \n')"
fi
