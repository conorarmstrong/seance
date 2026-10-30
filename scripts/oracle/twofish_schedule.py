#!/usr/bin/env python3
"""A from-the-specification Twofish-256 key schedule in Python, used to design and grade the Rust one.

    PYTHONPATH=<dir holding twofish> python3 scripts/oracle/twofish_schedule.py [--fixture OUT.json]

Written from the Twofish paper (Schneier, Kelsey, Whiting, Wagner, Hall, Ferguson): the q0/q1 permutations from their
four 4-bit tables, the MDS and RS matrices, the h function, and the round-subkey schedule K[0..39]. It is checked here against
the K array of Niels Ferguson's reference C library (the `twofish` package) on random keys, and `--fixture` writes those
(key, K[40], S[4], mk_tab[1024]) tuples for the Rust tests. It also contains the schedule INVERSION that the memory scan relies on: from K[40]
alone, the 256-bit key is recovered (the subkeys are linear in the h outputs, and h is a keyed byte permutation per byte lane).
"""
import json
import random
import sys

import twofish

T = {
    0: ([0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
        [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
        [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
        [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA]),
    1: ([0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
        [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
        [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
        [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA]),
}


def _ror4(x, n):
    return ((x >> n) | (x << (4 - n))) & 0xF


def _q(which, x):
    t0, t1, t2, t3 = T[which]
    a0, b0 = x >> 4, x & 15
    a1 = a0 ^ b0
    b1 = (a0 ^ _ror4(b0, 1) ^ ((8 * a0) & 15)) & 15
    a2, b2 = t0[a1], t1[b1]
    a3 = a2 ^ b2
    b3 = (a2 ^ _ror4(b2, 1) ^ ((8 * a2) & 15)) & 15
    a4, b4 = t2[a3], t3[b3]
    return (b4 << 4) | a4


Q = [[_q(0, x) for x in range(256)], [_q(1, x) for x in range(256)]]
Q0, Q1 = Q


def gf(a, b, poly):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


MDS = [[0x01, 0xEF, 0x5B, 0x5B], [0x5B, 0xEF, 0xEF, 0x01], [0xEF, 0x5B, 0x01, 0xEF], [0xEF, 0x01, 0xEF, 0x5B]]
RS = [[0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E], [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
      [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19], [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]]

# Per byte lane, the sequence of q-permutations applied outermost-last: x -> Qa[x]^L3 -> Qb[.]^L2 -> Qc[.]^L1 -> Qd[.]^L0 -> Qe.
LANES = [(Q1, Q1, Q0, Q0, Q1), (Q0, Q1, Q1, Q0, Q0), (Q0, Q0, Q0, Q1, Q1), (Q1, Q0, Q1, Q1, Q0)]


def lane(j, x, lbytes):
    """Byte lane j of h for k = 4, `lbytes` = (L0, L1, L2, L3) bytes of that lane."""
    a, b, c, d, e = LANES[j]
    return e[d[c[b[a[x] ^ lbytes[3]] ^ lbytes[2]] ^ lbytes[1]] ^ lbytes[0]]


def h(x, L):
    xb = [(x >> (8 * j)) & 0xFF for j in range(4)]
    y = [lane(j, xb[j], [(L[i] >> (8 * j)) & 0xFF for i in range(4)]) for j in range(4)]
    z = [0] * 4
    for r in range(4):
        v = 0
        for c in range(4):
            v ^= gf(MDS[r][c], y[c], 0x169)
        z[r] = v
    return z[0] | z[1] << 8 | z[2] << 16 | z[3] << 24


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def schedule(key):
    M = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    Me, Mo = [M[0], M[2], M[4], M[6]], [M[1], M[3], M[5], M[7]]
    K = []
    for i in range(20):
        A = h(2 * i * 0x01010101, Me)
        B = rol(h((2 * i + 1) * 0x01010101, Mo), 8)
        K += [(A + B) & 0xFFFFFFFF, rol((A + 2 * B) & 0xFFFFFFFF, 9)]
    S = []
    for i in range(4):
        v = 0
        for r in range(4):
            acc = 0
            for c in range(8):
                acc ^= gf(RS[r][c], key[8 * i + c], 0x14D)
            v |= acc << (8 * r)
        S.append(v)
    return K, S


def col(j, y):
    out = 0
    for r in range(4):
        out |= gf(MDS[r][j], y, 0x169) << (8 * r)
    return out


def mk_tab(key):
    """VeraCrypt's key-dependent S-box tables: table j, entry x = MDS column j times the lane-j value of x keyed by S,
    S taken in reverse (S3 first). Read off a real mounted volume's memory and found equal to this for tables 0 to 2 and
    for the part of table 3 that lies in the same physical page (the rest was in another page)."""
    _, S = schedule(key)
    L = S[::-1]
    return [col(j, lane(j, x, [(L[i] >> (8 * j)) & 0xFF for i in range(4)])) for j in range(4) for x in range(256)]


def main():
    random.seed(2026)
    keys = [bytes(32), bytes(range(32))] + [bytes(random.randrange(256) for _ in range(32)) for _ in range(10)]
    out = []
    for n, key in enumerate(keys):
        K, S = schedule(key)
        ref = list(twofish.Twofish(key).key.K)
        assert K == ref, "my K differs from Ferguson's for key " + key.hex()
        out.append({"key": key.hex(), "K": [format(w, "08x") for w in K], "S": [format(w, "08x") for w in S],
                    "mk_tab": [format(w, "08x") for w in mk_tab(key)] if n < 3 else None})
    print("key schedule matches the reference library on", len(keys), "keys")
    if "--tc-fixture" in sys.argv:
        # TrueCrypt 7.1a's structure (read off a mounted volume: `VALIDATION.md` MEM-VC-5): l_key[40], then s_key[4]
        # (S in reverse), then mk_tab with the four tables interleaved, entry x of table j at word 4x + j; 4,272 bytes.
        path = sys.argv[sys.argv.index("--tc-fixture") + 1]
        rows = []
        for key in keys[:4]:
            K, S = schedule(key)
            mk = mk_tab(key)
            words = K + S[::-1] + [mk[j * 256 + x] for x in range(256) for j in range(4)]
            rows.append({"key": key.hex(), "structure": b"".join(w.to_bytes(4, "little") for w in words).hex()})
        json.dump(rows, open(path, "w"), indent=1)
    if "--fixture" in sys.argv:
        path = sys.argv[sys.argv.index("--fixture") + 1]
        json.dump({"source": "Twofish-256 K[40] from Niels Ferguson's C library (python `twofish` 0.3.0); S[4] from the RS matrix",
                   "vectors": out}, open(path, "w"), indent=1)


if __name__ == "__main__":
    main()
