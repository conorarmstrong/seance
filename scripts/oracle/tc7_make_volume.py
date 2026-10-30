#!/usr/bin/env python3
"""Write a TrueCrypt 7.x container file with a chosen cipher or cascade, password and fresh random keys.

    PYTHONPATH=<dir holding cryptography, pyserpent, twofish> python3 scripts/oracle/tc7_make_volume.py \
        OUT.tc CIPHER PASSWORD [SIZE_MIB [HEADER_VERSION [vera]]]   # CIPHER as TrueCrypt names it: AES, Serpent-AES, AES-Twofish-Serpent ...

HEADER_VERSION is 5 (TrueCrypt 7.x, the default) or 4 (6.x: minimum program version 0x0600, no sector-size field).
A last argument `vera` writes a VeraCrypt header instead (magic `VERA`, PBKDF2-HMAC-SHA-512 of 500,000 iterations, minimum
program version 0x0100) for the VeraCrypt releases whose `VeraCrypt Format.exe` has no command line; read it back with
`vc_header_keys_all.py FILE PASSWORD` and let the real driver mount it.

`TrueCrypt Format.exe` 7.1a has no command line for creating a volume, and driving its wizard needs a mouse, so the
header is written here from the volume format specification (TrueCrypt documentation, "Volume Format Specification"):
64 bytes of salt, then 448 bytes encrypted in XTS (data unit 0) under a PBKDF2-HMAC-SHA-512 key of 1,000 iterations
(TrueCrypt's value for SHA-512): the magic `TRUE`, header version 5, minimum program version 0x0700, the CRC-32 of the
256-byte key area, times, hidden volume size 0, volume size, the offset of the data area (131,072), its length, flags 0,
sector size 512, and at 192 the master keys. A cascade applies the ciphers in the reverse of the order its name gives and
each has its own 32 + 32 key bytes. The data area is random bytes (the volume holds no file system: the real driver is
asked to mount it, which needs the header only). The file ends with the 128 KiB of backup headers the format reserves,
random here. `vc_header_keys_all.py --magic=TRUE --hash=sha512 FILE PASSWORD 1000` reads the header back, which is the
check that this writer and the reader agree; the real TrueCrypt driver mounting the file is the check that they agree
with TrueCrypt.

Prints a JSON line with the keys, so a memory capture of the mounted volume has an answer key.
"""
import hashlib
import json
import os
import sys
import time
import zlib

import vc_header_keys_all as vc


def xts_encrypt(enc, enc_tweak, data):
    tweak = int.from_bytes(enc_tweak((0).to_bytes(16, "little")), "little")
    out = bytearray()
    for i in range(0, len(data), 16):
        t = tweak.to_bytes(16, "little")
        x = bytes(a ^ b for a, b in zip(data[i:i + 16], t))
        y = enc(x)
        out += bytes(a ^ b for a, b in zip(y, t))
        carry = tweak >> 127
        tweak = ((tweak << 1) & ((1 << 128) - 1)) ^ (0x87 if carry else 0)
    return bytes(out)


def block_encryptor(name, key):
    # `_enc_for` builds an encryptor for the three ciphers TrueCrypt has.
    return vc._enc_for(name, key)


def main():
    out, cipher, password = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    size_mib = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    hdr_version = int(sys.argv[5]) if len(sys.argv) > 5 else 5
    vera = len(sys.argv) > 6 and sys.argv[6] == "vera"
    names = cipher.split("-")
    n = len(names)
    volume_size = size_mib * 1024 * 1024
    data_size = volume_size - 2 * 131072
    master = os.urandom(64 * n)          # n primary keys of 32, then n secondary (tweak) keys of 32
    plain = bytearray(448)
    plain[0:4] = b"VERA" if vera else b"TRUE"
    plain[4:6] = hdr_version.to_bytes(2, "big")
    plain[6:8] = (0x0100 if vera else 0x0700 if hdr_version >= 5 else 0x0600).to_bytes(2, "big")
    now = int((time.time() + 11644473600) * 10_000_000)
    plain[12:20] = now.to_bytes(8, "big")
    plain[20:28] = now.to_bytes(8, "big")
    plain[28:36] = (0).to_bytes(8, "big")
    plain[36:44] = data_size.to_bytes(8, "big")
    plain[44:52] = (131072).to_bytes(8, "big")
    plain[52:60] = data_size.to_bytes(8, "big")
    plain[60:64] = (0).to_bytes(4, "big")
    plain[64:68] = (512 if hdr_version >= 5 else 0).to_bytes(4, "big")
    plain[192:192 + 64 * n] = master
    plain[8:12] = (zlib.crc32(bytes(plain[192:448])) & 0xFFFFFFFF).to_bytes(4, "big")
    plain[188:192] = (zlib.crc32(bytes(plain[0:188])) & 0xFFFFFFFF).to_bytes(4, "big")
    salt = os.urandom(64)
    km = hashlib.pbkdf2_hmac("sha512", password, salt, 500000 if vera else 1000, 64 * 3)
    # decryption order is the name order; its key chunks are taken from the key area reversed (chunk i belongs to
    # the cipher at name position n-1-i), as the reader finds on a cascade.
    chunks = [(km[32 * i:32 * i + 32], km[32 * n + 32 * i:32 * n + 32 * i + 32]) for i in range(n)][::-1]
    data = bytes(plain)
    for name, (k1, k2) in reversed(list(zip(names, chunks))):
        data = xts_encrypt(block_encryptor(name, k1), block_encryptor(name, k2), data)
    header = salt + data
    with open(out, "wb") as f:
        f.write(header + os.urandom(131072 - 512))
        f.write(os.urandom(data_size))
        f.write(os.urandom(131072))
    area = bytes(plain[192:448])
    keys = [{"cipher": names[n - 1 - i], "primary_hex": area[32 * i:32 * i + 32].hex(),
             "secondary_hex": area[32 * n + 32 * i:32 * n + 32 * i + 32].hex()} for i in range(n)]
    # the key area is read back with the same chunk rule vc_header_keys_all.py uses: chunk i is cipher names[n-1-i]
    for k in keys:
        k["primary_sha256"] = hashlib.sha256(bytes.fromhex(k["primary_hex"])).hexdigest()
        k["secondary_sha256"] = hashlib.sha256(bytes.fromhex(k["secondary_hex"])).hexdigest()
    print(json.dumps({"volume": os.path.basename(out), "cipher": cipher, "decryption_order": names, "keys": keys}))


if __name__ == "__main__":
    main()
