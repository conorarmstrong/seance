#!/usr/bin/env python3
"""Decrypt a VeraCrypt volume header on the host and print the AES-256-XTS master keys.

    PYTHONPATH=<dir holding cryptography> python3 scripts/oracle/vc_header_keys.py VOLUME PASSWORD [ITERATIONS]

Written from the public header description (a 64-byte salt, then a 448-byte header encrypted with
AES-256-XTS, data unit 0, under a PBKDF2-HMAC-SHA512 key; the decrypted header begins `VERA`, stores a CRC-32
of its 256-byte master key area at offset 8, and keeps that area at offset 192) and checked by the magic and
that CRC, so a wrong password or a wrong reading fails loudly. No VeraCrypt source was read. The first 64 bytes
of the master key area are the primary and secondary 32-byte keys of a single AES-256-XTS volume. Prints JSON
with the keys' SHA-256 digests (the keys themselves are written only with --keys).
"""
import hashlib
import json
import sys
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    volume, password = args[0], args[1].encode()
    iterations = int(args[2]) if len(args) > 2 else 500000
    raw = open(volume, "rb").read(512)
    salt, body = raw[:64], raw[64:]
    key = hashlib.pbkdf2_hmac("sha512", password, salt, iterations, 64)
    decryptor = Cipher(algorithms.AES(key), modes.XTS((0).to_bytes(16, "little"))).decryptor()
    header = decryptor.update(body) + decryptor.finalize()
    assert header[:4] == b"VERA", "wrong password, iteration count or header layout: no VERA magic"
    want = int.from_bytes(header[8:12], "big")
    area = header[192:192 + 256]
    assert zlib.crc32(area) & 0xFFFFFFFF == want, "the master key area does not match its stored CRC-32"
    primary, secondary = area[:32], area[32:64]
    out = {
        "volume": volume.rsplit("/", 1)[-1],
        "header_version": int.from_bytes(header[4:6], "big"),
        "iterations": iterations,
        "primary_sha256": hashlib.sha256(primary).hexdigest(),
        "secondary_sha256": hashlib.sha256(secondary).hexdigest(),
    }
    if "--keys" in sys.argv:
        out["primary_hex"], out["secondary_hex"] = primary.hex(), secondary.hex()
    print(json.dumps(out, indent=1))


main()
