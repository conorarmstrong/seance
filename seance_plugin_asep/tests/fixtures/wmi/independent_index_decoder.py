#!/usr/bin/env python3
"""Independent reading of a CIM repository's INDEX.BTR (HUNT-195, WMI-4).

Written from the format reference (Metz, libyal dtformats "WMI repository file
format") and from the bytes of the repositories listed in VALIDATION.md WMI-4,
not from the Rust decoder and not from dissect.cim (AGPL-3.0, used only as an
external grader of this script's output, never read or copied).

  independent_index_decoder.py <repository directory> [--json]

The directory holds INDEX.BTR, MAPPING1-3.MAP and OBJECTS.DATA. The script
  1. chooses the well-formed MAPPINGn.MAP with the highest sequence number,
  2. walks the index B-tree from its root page (the INDEX.BTR section's first
     mapping entry carries the root logical page in its fourth u32),
     collecting every key that is a data reference
     `<key>.<logical data page>.<record id>.<record size>`,
  3. walks OBJECTS.DATA in logical order, reading each unclaimed page's
     descriptor table (16 bytes: id, offset, size, crc) and letting a record
     that runs past its page claim the following logical pages,
  4. prints the descriptor-listed records the index does not name.
"""
import json
import struct
import sys

P = 8192


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def sections(b):
    """Both sections of a MAPPINGn.MAP: (sequence, physical, logical map, root_aux)."""
    out = []
    at = 0
    for _ in range(2):
        assert u32(b, at) == 0xABCD, "mapping signature"
        seq, phys, n = u32(b, at + 4), u32(b, at + 16), u32(b, at + 20)
        e = at + 24
        logical = [u32(b, e + 24 * k) for k in range(n)]
        aux = u32(b, e + 12) if n else 0  # fourth u32 of entry 0
        fo = e + 24 * n
        nfree = u32(b, fo)
        end = fo + 4 + 4 * nfree
        assert u32(b, end) == 0xDCBA, "mapping footer"
        out.append((seq, phys, logical, aux))
        at = end + 4
    return out


def choose(d):
    best = None
    for name in ("MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"):
        try:
            s = sections(open(f"{d}/{name}", "rb").read())
        except (AssertionError, struct.error):
            continue
        if best is None or s[0][0] > best[0][0][0]:
            best = (s, name)
    return best


def index_page(idx, phys):
    p = idx[phys * P:(phys + 1) * P]
    assert u32(p, 0) == 0xACCC, "index page signature"
    own, n = u32(p, 4), u32(p, 16)
    o = 20 + 4 * n
    children = [u32(p, o + 4 * k) for k in range(n + 1)]
    o += 4 * (n + 1)
    keys = [u16(p, o + 2 * k) for k in range(n)]
    o += 2 * n
    dts = u16(p, o)
    table = [u16(p, o + 2 + 2 * k) for k in range(dts)]
    o += 2 + 2 * dts
    ns = u16(p, o)
    offs = [u16(p, o + 2 + 2 * k) for k in range(ns + 1)]
    base = o + 2 + 2 * (ns + 1)

    def string(i):
        s = base + offs[i]
        return p[s:p.index(b"\0", s)].decode("utf-8", "replace")

    out = []
    for off in keys:
        cnt = table[off]
        out.append("/".join(string(table[off + 1 + j]) for j in range(cnt)))
    return own, children, out


def walk_index(d, sec):
    idx = open(f"{d}/INDEX.BTR", "rb").read()
    seq, phys, logical, aux = sec
    assert len(idx) // P == phys, "INDEX.BTR size vs mapping"
    refs, seen, stack = set(), set(), [aux]
    keys_total = 0
    while stack:
        lp = stack.pop()
        if lp in seen:
            continue
        seen.add(lp)
        own, children, keys = index_page(idx, logical[lp])
        assert own == lp, f"page {lp} names itself {own}"
        keys_total += len(keys)
        for k in keys:
            if "." in k:
                a, b_, c = k.rsplit(".", 3)[1:]
                refs.add((int(a), int(b_), int(c)))
        for c in children:
            if c not in (0, 0xFFFFFFFF):
                stack.append(c)
    return refs, len(seen), keys_total


def descriptors(d, sec):
    obj = open(f"{d}/OBJECTS.DATA", "rb").read()
    seq, phys, logical, aux = sec
    claimed, out = set(), set()
    for lp, pp in enumerate(logical):
        if pp == 0xFFFFFFFF or lp in claimed:
            continue
        for i in range(P // 16):
            id_, off, size, crc = struct.unpack_from("<4I", obj, pp * P + 16 * i)
            if id_ == 0 or size == 0 or off >= P:
                break
            out.add((lp, id_, size))
            for k in range(1, (off + size - 1) // P + 1):
                claimed.add(lp + k)
    return out


def main():
    d = sys.argv[1]
    (obj_sec, idx_sec), name = choose(d)
    refs, pages, keys_total = walk_index(d, idx_sec)
    desc = descriptors(d, obj_sec)
    unindexed = sorted(desc - refs)
    res = {
        "mapping": name,
        "sequence": obj_sec[0],
        "index_root_logical_page": idx_sec[3],
        "index_pages_visited": pages,
        "index_keys": keys_total,
        "index_data_references": len(refs),
        "descriptors_listed": len(desc),
        "index_references_without_descriptor": len(refs - desc),
        "listed_not_indexed": [list(t) for t in unindexed],
        "indexed": sorted(list(t) for t in refs & desc),
    }
    if "--json" in sys.argv:
        print(json.dumps(res))
    else:
        for k, v in res.items():
            if k not in ("indexed", "listed_not_indexed"):
                print(k, v)
        print("listed_not_indexed", len(unindexed), unindexed[:5])


main()
