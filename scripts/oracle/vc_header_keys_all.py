#!/usr/bin/env python3
"""Decrypt a VeraCrypt volume header of ANY single cipher or cascade on the host and print its master keys.

    PYTHONPATH=<dir holding cryptography, pyserpent, twofish> python3 scripts/oracle/vc_header_keys_all.py VOLUME PASSWORD

AES, Serpent, Twofish, Camellia and Kuznyechik are the five ciphers; a header is 64 bytes of salt and 448 bytes encrypted with XTS
(data unit 0) under a PBKDF2-HMAC-SHA512 key (500,000 iterations). A cascade applies its ciphers one after another, each
with its own 32 key bytes and 32 tweak-key bytes; the key area holds every cipher's primary key, then every cipher's secondary key; the order of the ciphers and which key bytes belong to which
is not assumed: every ordering is tried, and the one that makes the header decrypt to the `VERA` magic with a matching CRC-32
of the key area is the answer. A wrong password, or a layout none of the orderings fits, fails loudly. No VeraCrypt source was read. `--magic=TRUE --hash=sha512` and a 1,000 iteration count read a TrueCrypt 7.x header.

Serpent is `pyserpent`, Twofish is the `twofish` package (Niels Ferguson's C library); AES and Camellia are `cryptography`; Kuznyechik (GOST R 34.12-2015) is `gostcrypto`. Their outputs are
checked against published known-answer vectors before they are used (Twofish-256: key 0, plaintext 0 -> 57ff739d...216f).
"""
import hashlib
import itertools
import json
import sys
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import gostcrypto
import pyserpent
import twofish


def _aes_dec(key):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return lambda block: d.update(block)


def _twofish_dec(key):
    t = twofish.Twofish(key)
    return t.decrypt


def _serpent_dec(key):
    s = pyserpent.Serpent(key)
    return s.decrypt


def _camellia_dec(key):
    d = Cipher(algorithms.Camellia(key), modes.ECB()).decryptor()
    return lambda block: d.update(block)


def _kuznyechik(key):
    g = gostcrypto.gostcipher
    return g.new("kuznechik", key, g.MODE_ECB, pad_mode=g.PAD_MODE_1)


def _kuznyechik_dec(key):
    c = _kuznyechik(key)
    return lambda block: bytes(c.decrypt(block))


CIPHERS = {
    "AES": _aes_dec,
    "Twofish": _twofish_dec,
    "Serpent": _serpent_dec,
    "Camellia": _camellia_dec,
    "Kuznyechik": _kuznyechik_dec,
}


def _xts_decrypt(dec, enc_tweak, data):
    """IEEE 1619 XTS, data unit 0, 16-byte blocks. `enc_tweak` encrypts the tweak under the second key."""
    tweak = int.from_bytes(enc_tweak((0).to_bytes(16, "little")), "little")
    out = bytearray()
    for i in range(0, len(data), 16):
        t = tweak.to_bytes(16, "little")
        x = bytes(a ^ b for a, b in zip(data[i:i + 16], t))
        y = dec(x)
        out += bytes(a ^ b for a, b in zip(y, t))
        carry = tweak >> 127
        tweak = ((tweak << 1) & ((1 << 128) - 1)) ^ (0x87 if carry else 0)
    return bytes(out)


def _enc_for(name, key):
    if name == "AES":
        e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return lambda b: e.update(b)
    if name == "Twofish":
        return twofish.Twofish(key).encrypt
    if name == "Camellia":
        e = Cipher(algorithms.Camellia(key), modes.ECB()).encryptor()
        return lambda b: e.update(b)
    if name == "Kuznyechik":
        c = _kuznyechik(key)
        return lambda b: bytes(c.encrypt(b))[:16]
    return pyserpent.Serpent(key).encrypt


def _self_test():
    assert twofish.Twofish(b"\0" * 32).encrypt(b"\0" * 16).hex() == "57ff739d4dc92c1bd7fc01700cc8216f"
    # RFC 7801 appendix A (Kuznyechik) and RFC 3713 appendix A (Camellia-256).
    k = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    assert _enc_for("Kuznyechik", k)(bytes.fromhex("1122334455667700ffeeddccbbaa9988")).hex() == "7f679d90bebc24305a468d42b9d4edcd"
    assert _kuznyechik_dec(k)(bytes.fromhex("7f679d90bebc24305a468d42b9d4edcd")).hex() == "1122334455667700ffeeddccbbaa9988"
    ck = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677" "8899aabbccddeeff")
    assert _enc_for("Camellia", ck)(bytes.fromhex("0123456789abcdeffedcba9876543210")).hex() == "9acc237dff16d76c20ef7c919e3a7509"


def decrypt_header(raw, password, iterations=500000, hash_name="sha512", magic=b"VERA"):
    salt, body = raw[:64], raw[64:512]
    names = [(c,) for c in CIPHERS]
    names += list(itertools.permutations(CIPHERS, 2))
    names += list(itertools.permutations(CIPHERS, 3))
    key_material = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, 64 * 3)
    for order in names:
        # each cipher in the cascade takes 32 bytes of cipher key and 32 of tweak key; try the key blocks in the
        # order given and in reverse (the header's decryption order is the reverse of the encryption order)
        for reverse_keys in (False, True):
            data = body
            ciphers = list(order)
            n = len(ciphers)
            # The key material is every cipher's primary key, then every cipher's secondary (tweak) key.
            chunks = [(key_material[32 * i:32 * i + 32], key_material[32 * n + 32 * i:32 * n + 32 * i + 32]) for i in range(n)]
            if reverse_keys:
                chunks = chunks[::-1]
            for name, (k1, k2) in zip(ciphers, chunks):
                data = _xts_decrypt(CIPHERS[name](k1), _enc_for(name, k2), data)
            if data[:4] == magic and zlib.crc32(data[192:448]) & 0xFFFFFFFF == int.from_bytes(data[8:12], "big"):
                return order, reverse_keys, data
    raise SystemExit("no ordering of the five ciphers opens this header: wrong password or an unknown layout")


def main():
    _self_test()
    options = dict(a[2:].split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    volume, password = args[0], args[1].encode()
    iterations = int(args[2]) if len(args) > 2 else 500000
    raw = open(volume, "rb").read(512)
    # VeraCrypt: SHA-512, 500,000 iterations, magic VERA. TrueCrypt 7.x: pass --magic=TRUE and the hash and
    # iteration count of the volume (SHA-512 with 1,000 iterations, say).
    order, reverse_keys, header = decrypt_header(
        raw, password, iterations, options.get("hash", "sha512"), options.get("magic", "VERA").encode()
    )
    area = header[192:448]
    n = len(order)
    keys = []
    for i in range(n):
        # The cipher that takes area chunk i: decryption-order position i, or n-1-i when the chunks were reversed.
        keys.append({"area_chunk": i, "cipher": order[n - 1 - i if reverse_keys else i],
                     "primary_sha256": hashlib.sha256(area[32 * i:32 * i + 32]).hexdigest(),
                     "secondary_sha256": hashlib.sha256(area[32 * n + 32 * i:32 * n + 32 * i + 32]).hexdigest()})
    out = {"volume": volume.rsplit("/", 1)[-1], "header_version": int.from_bytes(header[4:6], "big"),
           "decryption_order": list(order), "keys_reversed": reverse_keys, "keys": keys}
    if "--keys" in sys.argv:
        for i, k in enumerate(keys):
            k["primary_hex"] = area[32 * i:32 * i + 32].hex()
            k["secondary_hex"] = area[32 * n + 32 * i:32 * n + 32 * i + 32].hex()
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
