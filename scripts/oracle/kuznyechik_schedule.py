"""Kuznyechik (GOST R 34.12-2015) round keys, written from RFC 7801 (section 4.3 and appendix A) in pure Python.

    python3 scripts/oracle/kuznyechik_schedule.py            self-test against the RFC 7801 round keys K1..K10
    python3 scripts/oracle/kuznyechik_schedule.py --fixture  write seance_bulk/tests/fixtures/kuznyechik_schedules.json

The reference the Rust key-schedule recogniser (`seance_bulk::kuznyechik`) is graded against, on top of the RFC vector
itself. The cipher built on these round keys is checked against `gostcrypto` by `vc_header_keys_all.py`, which only
decrypts a header if both are right.
"""
PI=[252,238,221,17,207,110,49,22,251,196,250,218,35,197,4,77,233,119,240,219,147,46,153,186,23,54,241,187,20,205,95,193,249,24,101,90,226,92,239,33,129,28,60,66,139,1,142,79,5,132,2,174,227,106,143,160,6,11,237,152,127,212,211,31,235,52,44,81,234,200,72,171,242,42,104,162,253,58,206,204,181,112,14,86,8,12,118,18,191,114,19,71,156,183,93,135,21,161,150,41,16,123,154,199,243,145,120,111,157,158,178,177,50,117,25,61,255,53,138,126,109,84,198,128,195,189,13,87,223,245,36,169,62,168,67,201,215,121,214,246,124,34,185,3,224,15,236,222,122,148,176,188,220,232,40,80,78,51,10,74,167,151,96,115,30,0,98,68,26,184,56,130,100,159,38,65,173,69,70,146,39,94,85,47,140,163,165,125,105,213,149,59,7,88,179,64,134,172,29,247,48,55,107,228,136,217,231,137,225,27,131,73,76,63,248,254,141,83,170,144,202,216,133,97,32,113,103,164,45,43,9,91,203,155,37,208,190,229,108,82,89,166,116,210,230,244,180,192,209,102,175,194,57,75,99,182]
LC=[148,32,133,16,194,192,1,251,1,192,194,16,133,32,148,1]
def gmul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a<<=1
        if a&0x100: a^=0x1c3
        b>>=1
    return r
def R(b):
    x=0
    for i in range(16): x^=gmul(b[i],LC[i])
    return [x]+b[:15]
def L(b):
    for _ in range(16): b=R(b)
    return b
def LSX(k,a):
    x=[p^q for p,q in zip(k,a)]
    return L([PI[v] for v in x])
def schedule(key):
    k=list(key)
    a1,a0=k[:16],k[16:]
    rks=[a1,a0]
    C=[L([0]*15+[i]) for i in range(1,33)]
    for i in range(4):
        for j in range(8):
            c=C[8*i+j]
            a1,a0=[p^q for p,q in zip(LSX(c,a1),a0)],a1
        rks+=[a1,a0]
    return [bytes(r) for r in rks]

RFC_KEY = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
RFC_ROUND_KEYS = [
    "8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef", "db31485315694343228d6aef8cc78c44",
    "3d4553d8e9cfec6815ebadc40a9ffd04", "57646468c44a5e28d3e59246f429f1ac", "bd079435165c6432b532e82834da581b",
    "51e640757e8745de705727265a0098b1", "5a7925017b9fdd3ed72a91a22286f984", "bb44e25378c73123a5f32f73cdb6e517",
    "72e9dd7416bcf45b755dbaa88e4a4043",
]


def self_test():
    assert [r.hex() for r in schedule(RFC_KEY)] == RFC_ROUND_KEYS


def main():
    import json
    import os
    import sys
    self_test()
    if "--fixture" not in sys.argv:
        print("ok")
        return
    rng = __import__("random").Random(7)
    keys = [RFC_KEY] + [bytes(rng.randrange(256) for _ in range(32)) for _ in range(11)]
    out = [{"key": k.hex(), "round_keys": b"".join(schedule(k)).hex()} for k in keys]
    path = os.path.join(os.path.dirname(__file__), "..", "..", "seance_bulk", "tests", "fixtures", "kuznyechik_schedules.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", os.path.normpath(path))


if __name__ == "__main__":
    main()
