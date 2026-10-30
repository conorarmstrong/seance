#!/usr/bin/env python3
"""HUNT-278 SYNTHETIC: plant an end-of-directory marker inside directory S of a
FAT16 image built by make_hunt278_fixtures.sh, and a garbage slot behind it.

Layout of S (one 512 B cluster, found through the root entry): slot 0 '.',
slot 1 '..', slots 2..8 ONE..SEVEN. The marker replaces the first byte of slot 5
(FOUR); slot 8 (SEVEN) becomes bytes no directory writes. Everything else is
what mtools wrote.
"""
import struct, sys

img = bytearray(open(sys.argv[1], "rb").read())
rsvd, = struct.unpack_from("<H", img, 14)
nfats = img[16]
root_entries, = struct.unpack_from("<H", img, 17)
fat_sectors, = struct.unpack_from("<H", img, 22)
root_start = (rsvd + nfats * fat_sectors) * 512
data_start = root_start + root_entries * 32  # 1 sector per cluster


def find(dir_off, name):
    for i in range(root_entries):
        e = img[dir_off + i * 32: dir_off + i * 32 + 32]
        if e[:11] == name.ljust(11).encode():
            return struct.unpack_from("<H", e, 26)[0]
    raise SystemExit(f"{name} not found")


cl = find(root_start, "S")
base = data_start + (cl - 2) * 512
assert img[base:base + 3] == b".  ", "S does not begin with '.'"
img[base + 5 * 32] = 0x00  # marker over FOUR
img[base + 8 * 32: base + 9 * 32] = bytes([0xFF, 0xFE] * 16)  # garbage slot
open(sys.argv[1], "wb").write(img)
