#!/usr/bin/env python3
"""HUNT-278 SYNTHETIC exFAT volume: a deleted directory whose entry sets are
still on disk.

Usage: make_hunt278_exfat.py BASE.img OUT.img

BASE.img is an empty volume from `mkfs.exfat -c 512` (the generator script makes
it). This writer, in stdlib python3 only (no exFAT populator is available here):

  1. adds live directory /DIR, NoFatChain, two contiguous 512 B clusters, holding
     six file entry sets f1..f6 (set f6 straddles the cluster boundary), and
     writes the result to OUT.live.img so `fsck.exfat -n` can vouch that this
     live layout is a valid volume;
  2. deletes /DIR the way a driver does: InUse cleared on its three entries
     (0x85->0x05, 0xC0->0x40, 0xC1->0x41), its bitmap bits cleared. Inside it,
     f2's set is also marked deleted (its checksum is left as the in-use set's,
     as drivers leave it), and f3's SetChecksum is corrupted.

The answer key is this script: f1, f2, f4, f5, f6 carry a SetChecksum that
verifies (f2 against the in-use form of its bytes); f3 does not.
"""
import struct
import sys


def checksum(entries):
    data = b"".join(entries)
    s = 0
    for i, b in enumerate(data):
        if i in (2, 3):
            continue
        s = (((s << 15) | (s >> 1)) + b) & 0xFFFF
    return s


def name_hash(name):
    h = 0
    for ch in name.upper().encode("utf-16-le"):
        h = (((h << 15) | (h >> 1)) + ch) & 0xFFFF
    return h


def ts(y, mo, d, h, mi, s):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s // 2)


def entry_set(name, attrs=0x20, first_cluster=0, length=0, flags=0x01):
    chars = name.encode("utf-16-le")
    names = [chars[i:i + 30].ljust(30, b"\0") for i in range(0, len(chars), 30)]
    t = ts(2026, 10, 20, 12, 0, 0)
    primary = bytearray(32)
    primary[0] = 0x85
    primary[1] = 1 + len(names)
    struct.pack_into("<H", primary, 4, attrs)
    struct.pack_into("<III", primary, 8, t, t, t)
    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = flags
    stream[3] = len(name)
    struct.pack_into("<H", stream, 4, name_hash(name))
    struct.pack_into("<Q", stream, 8, length)
    struct.pack_into("<I", stream, 20, first_cluster)
    struct.pack_into("<Q", stream, 24, length)
    parts = [primary, stream]
    for n in names:
        e = bytearray(32)
        e[0] = 0xC1
        e[2:32] = n
        parts.append(e)
    struct.pack_into("<H", parts[0], 2, checksum([bytes(p) for p in parts]))
    return parts


def main():
    base, out = sys.argv[1], sys.argv[2]
    img = bytearray(open(base, "rb").read())
    bps = 1 << img[108]
    cluster_size = bps << img[109]
    heap = struct.unpack_from("<I", img, 88)[0] * bps
    root = struct.unpack_from("<I", img, 96)[0]
    count = struct.unpack_from("<I", img, 92)[0]

    def coff(c):
        return heap + (c - 2) * cluster_size

    # Root directory: find the bitmap and the first free slot.
    root_off = coff(root)
    bitmap = None
    free_slot = None
    for i in range(cluster_size // 32):
        e = img[root_off + i * 32: root_off + i * 32 + 32]
        if e[0] == 0x81 and bitmap is None:
            bitmap = (struct.unpack_from("<I", e, 20)[0], struct.unpack_from("<Q", e, 24)[0])
        if e[0] == 0x00:
            free_slot = i
            break
    assert bitmap and free_slot is not None
    bm_off = coff(bitmap[0])

    def bit(c):
        return img[bm_off + (c - 2) // 8] >> ((c - 2) % 8) & 1

    def setbit(c, v):
        if v:
            img[bm_off + (c - 2) // 8] |= 1 << ((c - 2) % 8)
        else:
            img[bm_off + (c - 2) // 8] &= ~(1 << ((c - 2) % 8)) & 0xFF

    free = [c for c in range(2, count + 2) if not bit(c)]
    dir_clusters = (free[0], free[0] + 1)
    assert dir_clusters[1] == dir_clusters[0] + 1 and not bit(dir_clusters[1])
    for c in dir_clusters:
        setbit(c, 1)
        img[coff(c): coff(c) + cluster_size] = bytes(cluster_size)

    # The six sets, three entries each (names fit one name entry), laid end to end.
    names = [f"f{i}.txt" for i in range(1, 7)]
    sets = [entry_set(n) for n in names]
    flat = [bytes(e) for s in sets for e in s]
    dir_bytes = b"".join(flat)
    assert len(dir_bytes) == 18 * 32
    img[coff(dir_clusters[0]): coff(dir_clusters[0]) + cluster_size] = dir_bytes[:cluster_size]
    img[coff(dir_clusters[1]): coff(dir_clusters[1]) + len(dir_bytes) - cluster_size] = dir_bytes[cluster_size:]

    dir_set = entry_set("DIR", attrs=0x10, first_cluster=dir_clusters[0],
                        length=2 * cluster_size, flags=0x03)
    for k, e in enumerate(dir_set):
        o = root_off + (free_slot + k) * 32
        assert img[o] == 0x00
        img[o: o + 32] = e
    open(out + ".live.img", "wb").write(img)

    # Delete /DIR: InUse cleared on its set, bitmap bits cleared.
    for k in range(len(dir_set)):
        img[root_off + (free_slot + k) * 32] &= 0x7F
    for c in dir_clusters:
        setbit(c, 0)
    # f2's set loses InUse too, checksum untouched (as a driver leaves it).
    base2 = coff(dir_clusters[0]) + 3 * 32
    for k in range(3):
        img[base2 + k * 32] &= 0x7F
    # f3's SetChecksum is corrupted.
    base3 = coff(dir_clusters[0]) + 6 * 32
    img[base3 + 2] ^= 0xFF
    open(out, "wb").write(img)


main()
