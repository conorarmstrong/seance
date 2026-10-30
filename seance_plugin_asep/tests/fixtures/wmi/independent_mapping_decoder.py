#!/usr/bin/env python3
"""Independent reading of a CIM repository's page mapping (HUNT-195).

Written from the format references (Metz, libyal dtformats "WMI repository file
format"; FireEye's flare-wmi) and not from the Rust decoder, to grade it.

  independent_mapping_decoder.py <mapping file> <OBJECTS.DATA> [xp]

Prints the mapping header and counts, then walks OBJECTS.DATA in logical page
order: each page not already claimed as a continuation has its descriptor
table read; a record running past its page claims as many following logical
pages as its size needs. Every record, whole or reassembled, is parsed as a
class definition. On XP each reassembled record's stored CRC-32 is checked, and
the same records are read again with the physically next page in place of the
next logical one for comparison.
"""
import re
import struct
import sys
import zlib

P = 8192


def u(b, o):
    return struct.unpack_from("<I", b, o)[0]


def mapping(path, xp):
    b = open(path, "rb").read()
    if xp:
        seq, phys, n, hdr, es = u(b, 4), u(b, 8), u(b, 12), 16, 4
    else:
        seq, phys, n, hdr, es = u(b, 4), u(b, 16), u(b, 20), 24, 24
    logical = [u(b, hdr + es * k) for k in range(n)]
    fo = hdr + es * n
    free = [u(b, fo + 4 + 4 * k) for k in range(u(b, fo))]
    footer = u(b, fo + 4 + 4 * len(free))
    return seq, phys, logical, free, footer


def table(obj, p):
    out = []
    for i in range(P // 16):
        id_, off, size, crc = struct.unpack_from("<4I", obj, p * P + 16 * i)
        if id_ == 0 or size == 0 or off >= P:
            break
        out.append((id_, off, size, crc))
    end = (len(out) + 1) * 16
    return [d for d in out if d[1] >= end]


NAME = re.compile(r"^[A-Za-z0-9_]+$")


def heap_string(heap, at):
    if at >= len(heap):
        return None
    if heap[at] == 0:
        e = heap.find(b"\0", at + 1)
        return heap[at + 1 : (len(heap) if e < 0 else e)].decode("latin1")
    if heap[at] == 1:
        units = []
        for i in range(at + 1, len(heap) - 1, 2):
            c = struct.unpack_from("<H", heap, i)[0]
            if c == 0:
                break
            units.append(chr(c))
        return "".join(units)
    return None


def class_definition(r):
    """(name, superclass, property names) or None."""
    try:
        s = u(r, 0)
        if s > 256:
            return None
        sup = r[4 : 4 + 2 * s].decode("utf-16le")
        if not re.match(r"^[A-Za-z0-9_]*$", sup):
            return None
        be = 4 + 2 * s + 8
        bs = u(r, be)
        blk = r[be : be + bs]
        if bs < 40 or len(blk) < bs:
            return None
        cn, dv, q = u(blk, 5), u(blk, 9), 13
        q += u(blk, q)
        q += u(blk, q)
        cnt = u(blk, q)
        q += 4
        if cnt > 1024:
            return None
        hl = u(blk, q + 8 * cnt + dv)
        if not hl & 0x80000000:
            return None
        heap = blk[q + 8 * cnt + dv + 4 : q + 8 * cnt + dv + 4 + (hl & 0x7FFFFFFF)]
        name = heap_string(heap, cn)
        if not name or not NAME.match(name):
            return None
        props = []
        for k in range(cnt):
            pn = heap_string(heap, u(blk, q + 8 * k))
            if not pn or not NAME.match(pn):
                return None
            props.append(pn)
        return name, sup, props
    except (struct.error, UnicodeDecodeError):
        return None


def main():
    xp = len(sys.argv) > 3 and sys.argv[3] == "xp"
    seq, phys, logical, free, footer = mapping(sys.argv[1], xp)
    obj = open(sys.argv[2], "rb").read()
    npages = len(obj) // P
    print(f"sequence {seq} physical {phys} logical {len(logical)} free {len(free)} footer {footer:#x}")
    mapped = set(p for p in logical if p != 0xFFFFFFFF)
    print("mapped + free == all physical pages:", sorted(mapped | set(free)) == list(range(phys)))
    cont = {}
    descriptors = spanning = reassembled = classdefs = classdefs_span = 0
    naive_classdefs = crc_ok = naive_crc_ok = crc_stored = 0
    for l, p in enumerate(logical):
        if p == 0xFFFFFFFF or l in cont:
            continue
        for id_, off, size, crc in table(obj, p):
            descriptors += 1
            if off + size <= P:
                classdefs += class_definition(obj[p * P + off : p * P + off + size]) is not None
                continue
            spanning += 1
            k = (off + size - 1) // P
            if l + k >= len(logical):
                continue
            nxt = [logical[l + j] for j in range(1, k + 1)]
            for j in range(1, k + 1):
                cont[l + j] = True
            reassembled += 1
            whole = obj[p * P + off : (p + 1) * P] + b"".join(obj[q * P : (q + 1) * P] for q in nxt)
            naive = obj[p * P + off : (p + 1 + k) * P]
            whole, naive = whole[:size], naive[:size]
            if class_definition(whole):
                classdefs += 1
                classdefs_span += 1
            naive_classdefs += class_definition(naive) is not None
            if crc:
                crc_stored += 1
                crc_ok += zlib.crc32(whole) == crc
                naive_crc_ok += zlib.crc32(naive) == crc
    unmapped = [p for p in range(npages) if p not in mapped]
    in_unmapped = 0
    for p in unmapped:
        for id_, off, size, crc in table(obj, p):
            in_unmapped += 1
            if off + size <= P:
                classdefs += class_definition(obj[p * P + off : p * P + off + size]) is not None
    print(f"pages {npages} continuation {len(cont)} unmapped {len(unmapped)}")
    print(f"descriptor records {descriptors + in_unmapped} (in unmapped pages {in_unmapped})")
    print(f"spanning {spanning} reassembled {reassembled}")
    print(f"class definitions {classdefs} (reassembled {classdefs_span}; physically-next reading {naive_classdefs})")
    print(f"stored CRC-32s on spanning records {crc_stored}: match {crc_ok}, physically-next {naive_crc_ok}")


if __name__ == "__main__":
    main()
