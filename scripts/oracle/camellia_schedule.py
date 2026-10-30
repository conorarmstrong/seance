"""Camellia-256 key schedule (RFC 3713), pure Python, for the key-recovery recogniser of `seance_bulk::camellia`.

    python3 scripts/oracle/camellia_schedule.py            self-test: RFC 3713 appendix A ciphertext for the 256-bit key
    python3 scripts/oracle/camellia_schedule.py --fixture  write seance_bulk/tests/fixtures/camellia_schedules.json

The S-box is the one printed in RFC 3713; the self-test runs the whole cipher built on this schedule against the RFC's
published ciphertext, so a wrong table, rotation or subkey order fails it. KL, KR, KA and the six `ke` subkeys of a key are
what the recogniser needs: VeraCrypt's in-memory table keeps the `ke` subkeys (and nothing else of the schedule) in the RFC's
form, as 32-bit words, and the other subkeys with the whitening keys absorbed (the Linux/NTT optimisation).
"""
S1=[112,130,44,236,179,39,192,229,228,133,87,53,234,12,174,65,35,239,107,147,69,25,165,33,237,14,79,78,29,101,146,189,134,184,175,143,124,235,31,206,62,48,220,95,94,197,11,26,166,225,57,202,213,71,93,61,217,1,90,214,81,86,108,77,139,13,154,102,251,204,176,45,116,18,43,32,240,177,132,153,223,76,203,194,52,126,118,5,109,183,169,49,209,23,4,215,20,88,58,97,222,27,17,28,50,15,156,22,83,24,242,34,254,68,207,178,195,181,122,145,36,8,232,168,96,252,105,80,170,208,160,125,161,137,98,151,84,91,30,149,224,255,100,210,16,196,0,72,163,247,117,219,138,3,230,218,9,63,221,148,135,92,131,2,205,74,144,51,115,103,246,243,157,127,191,226,82,155,216,38,200,55,198,59,129,150,111,75,19,190,99,46,233,121,167,140,159,110,188,142,41,245,249,182,47,253,180,89,120,152,6,106,231,70,113,186,212,37,171,66,136,162,141,250,114,7,185,85,248,238,172,10,54,73,42,104,60,56,241,164,64,40,211,123,187,201,67,193,21,227,173,244,119,199,128,158]
assert len(S1)==256 and len(set(S1))==256
def rol8(x,n): return ((x<<n)|(x>>(8-n)))&0xff
S2=[rol8(v,1) for v in S1]
S3=[rol8(v,7) for v in S1]
S4=[S1[rol8(x,1)] for x in range(256)]
M64=(1<<64)-1
M128=(1<<128)-1
def F(x,k):
    x^=k
    t=[(x>>(56-8*i))&0xff for i in range(8)]
    t1=S1[t[0]];t2=S2[t[1]];t3=S3[t[2]];t4=S4[t[3]];t5=S2[t[4]];t6=S3[t[5]];t7=S4[t[6]];t8=S1[t[7]]
    y1=t1^t3^t4^t6^t7^t8
    y2=t1^t2^t4^t5^t7^t8
    y3=t1^t2^t3^t5^t6^t8
    y4=t2^t3^t4^t5^t6^t7
    y5=t1^t2^t6^t7^t8
    y6=t2^t3^t5^t7^t8
    y7=t3^t4^t5^t6^t8
    y8=t1^t4^t5^t6^t7
    r=0
    for y in (y1,y2,y3,y4,y5,y6,y7,y8): r=(r<<8)|y
    return r
SIG=[0xA09E667F3BCC908B,0xB67AE8584CAA73B2,0xC6EF372FE94F82BE,0x54FF53A5F1D36F1C,0x10E527FADE682D1D,0xB05688C2B3E6C1FD]
def rotl128(x,n): return ((x<<n)|(x>>(128-n)))&M128
def schedule256(key):
    KL=int.from_bytes(key[:16],'big'); KR=int.from_bytes(key[16:],'big')
    D1=((KL^KR)>>64)&M64; D2=(KL^KR)&M64
    D2^=F(D1,SIG[0]); D1^=F(D2,SIG[1])
    D1^=(KL>>64)&M64; D2^=KL&M64
    D2^=F(D1,SIG[2]); D1^=F(D2,SIG[3])
    KA=(D1<<64)|D2
    D1=((KA^KR)>>64)&M64; D2=(KA^KR)&M64
    D2^=F(D1,SIG[4]); D1^=F(D2,SIG[5])
    KB=(D1<<64)|D2
    hi=lambda v:(v>>64)&M64
    lo=lambda v:v&M64
    kw=[hi(KL),lo(KL),hi(rotl128(KB,111)),lo(rotl128(KB,111))]
    pairs=lambda v:[hi(v),lo(v)]
    k=(pairs(KB)+pairs(rotl128(KR,15))+pairs(rotl128(KA,15))+pairs(rotl128(KB,30))+pairs(rotl128(KL,45))+pairs(rotl128(KA,45))
       +pairs(rotl128(KR,60))+pairs(rotl128(KB,60))+pairs(rotl128(KL,77))+pairs(rotl128(KR,94))+pairs(rotl128(KA,94))+pairs(rotl128(KL,111)))
    ke=pairs(rotl128(KR,30))+pairs(rotl128(KL,60))+pairs(rotl128(KA,77))
    return kw,k,ke


def encrypt(key, blk):
    kw, k, ke = schedule256(key)

    def fl(x, kk):
        x1, x2 = x >> 32, x & 0xFFFFFFFF
        k1, k2 = kk >> 32, kk & 0xFFFFFFFF
        t = x1 & k1
        x2 ^= ((t << 1) | (t >> 31)) & 0xFFFFFFFF
        x1 ^= x2 | k2
        return (x1 << 32) | x2

    def flinv(y, kk):
        y1, y2 = y >> 32, y & 0xFFFFFFFF
        k1, k2 = kk >> 32, kk & 0xFFFFFFFF
        y1 ^= y2 | k2
        t = y1 & k1
        y2 ^= ((t << 1) | (t >> 31)) & 0xFFFFFFFF
        return (y1 << 32) | y2

    d1, d2 = int.from_bytes(blk[:8], "big"), int.from_bytes(blk[8:], "big")
    d1 ^= kw[0]
    d2 ^= kw[1]
    for r in range(24):
        if r % 2 == 0:
            d2 ^= F(d1, k[r])
        else:
            d1 ^= F(d2, k[r])
        if r in (5, 11, 17):
            i = (r + 1) // 6 - 1
            d1 = fl(d1, ke[2 * i])
            d2 = flinv(d2, ke[2 * i + 1])
    d2 ^= kw[2]
    d1 ^= kw[3]
    return d2.to_bytes(8, "big") + d1.to_bytes(8, "big")


def ka_and_ke(key):
    """(KL, KR, KA, KB, the six ke subkeys as 64-bit integers)."""
    kl, kr = int.from_bytes(key[:16], "big"), int.from_bytes(key[16:], "big")
    d1, d2 = ((kl ^ kr) >> 64) & M64, (kl ^ kr) & M64
    d2 ^= F(d1, SIG[0]); d1 ^= F(d2, SIG[1])
    d1 ^= kl >> 64; d2 ^= kl & M64
    d2 ^= F(d1, SIG[2]); d1 ^= F(d2, SIG[3])
    ka = (d1 << 64) | d2
    kw, k, ke = schedule256(key)
    return kl, kr, ka, ke


RFC_KEY = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677" "8899aabbccddeeff")


def self_test():
    assert encrypt(RFC_KEY, bytes.fromhex("0123456789abcdeffedcba9876543210")).hex() == "9acc237dff16d76c20ef7c919e3a7509"


def main():
    import json
    import os
    import random
    import sys
    self_test()
    if "--fixture" not in sys.argv:
        print("ok")
        return
    rng = random.Random(11)
    keys = [RFC_KEY] + [bytes(rng.randrange(256) for _ in range(32)) for _ in range(11)]
    out = []
    for key in keys:
        kl, kr, ka, ke = ka_and_ke(key)
        out.append({"key": key.hex(), "ka": "%032x" % ka, "ke": ["%016x" % v for v in ke]})
    path = os.path.join(os.path.dirname(__file__), "..", "..", "seance_bulk", "tests", "fixtures", "camellia_schedules.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", os.path.normpath(path))


if __name__ == "__main__":
    main()
