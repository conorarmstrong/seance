#!/usr/bin/env python3
"""Generate minimal magic-valid seed inputs for the fuzz targets.

Unseeded filesystem/container targets stall at the parser's magic/length gate
(~19 edges) and never exercise real code. These synthetic seeds carry the right
signature so the fuzzer mutates from a structure that reaches the parser. They
are intentionally minimal; richer coverage comes from real-image samples
(gitignored) added locally. CI runs this before fuzzing to seed each corpus.

Usage: python3 fuzz/gen_seeds.py   (writes to fuzz/corpus/<target>/seed)
"""
import os
import struct

ROOT = os.path.join(os.path.dirname(__file__), "corpus")


def write(target, data):
    d = os.path.join(ROOT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "seed_synthetic"), "wb") as f:
        f.write(data)


def fat_boot():
    b = bytearray(1024)
    b[0:3] = b"\xeb\x3c\x90"          # jump
    b[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", b, 11, 512)   # bytes/sector
    b[13] = 1                             # sectors/cluster
    struct.pack_into("<H", b, 14, 1)     # reserved
    b[16] = 2                             # num FATs
    struct.pack_into("<H", b, 17, 512)   # root entries
    struct.pack_into("<H", b, 19, 2048)  # total sectors
    struct.pack_into("<H", b, 22, 9)     # sectors/FAT
    b[54:62] = b"FAT16   "
    b[510], b[511] = 0x55, 0xAA
    return bytes(b)


def ext_sb():
    b = bytearray(2048)
    struct.pack_into("<I", b, 1024 + 0, 64)      # inodes_count
    struct.pack_into("<I", b, 1024 + 4, 256)     # blocks_count
    struct.pack_into("<I", b, 1024 + 20, 1)      # first_data_block
    struct.pack_into("<I", b, 1024 + 24, 0)      # log_block_size (1 KiB)
    struct.pack_into("<I", b, 1024 + 32, 128)    # blocks_per_group
    struct.pack_into("<I", b, 1024 + 40, 32)     # inodes_per_group
    struct.pack_into("<H", b, 1024 + 56, 0xEF53) # magic
    struct.pack_into("<H", b, 1024 + 88, 32)     # desc_size
    return bytes(b)


def mbr():
    b = bytearray(512)
    # one FAT16 primary partition, LBA 1, 100 sectors
    base = 446
    b[base + 4] = 0x06
    struct.pack_into("<I", b, base + 8, 1)
    struct.pack_into("<I", b, base + 12, 100)
    b[510], b[511] = 0x55, 0xAA
    return bytes(b)


def mft():
    b = bytearray(1024)
    b[0:4] = b"FILE"
    struct.pack_into("<H", b, 4, 0x30)   # update seq offset
    struct.pack_into("<H", b, 6, 3)      # update seq count
    struct.pack_into("<H", b, 20, 0x38)  # first attribute offset
    struct.pack_into("<H", b, 22, 0x01)  # flags in-use
    struct.pack_into("<I", b, 0x38, 0xFFFFFFFF)  # end marker
    return bytes(b)


def with_magic(magic, size, off=0):
    b = bytearray(size)
    b[off:off + len(magic)] = magic
    return bytes(b)


def recycle_bin_i():
    # $I record, version 2: version, original size, deletion FILETIME,
    # path length, then the UTF-16 path.
    path = "C:\\Users\\x\\Desktop\\a.txt".encode("utf-16-le") + b"\x00\x00"
    b = bytearray(28)
    struct.pack_into("<Q", b, 0, 2)
    struct.pack_into("<Q", b, 8, 1234)
    struct.pack_into("<Q", b, 16, 0x01D9E5B0C0000000)
    struct.pack_into("<I", b, 24, len(path) // 2)
    return bytes(b) + path


SEEDS = {
    "fat_parser": fat_boot(),
    "ext4_parser": ext_sb(),
    "partition_parser": mbr(),
    "mft_parser": mft(),
    "apfs_parser": with_magic(b"NXSB", 4096, 32),
    "btrfs_parser": with_magic(b"_BHRfS_M", 0x11000, 0x10040),
    "xfs_parser": with_magic(b"XFSB", 4096, 0),
    "hfsplus": with_magic(b"H+", 2048, 1024),
    "iso9660": with_magic(b"\x01CD001\x01\x00", 0x8100, 0x8000),
    "qcow2": with_magic(b"QFI\xfb", 512, 0),
    "vhdx": with_magic(b"vhdxfile", 0x10000, 0),
    "vmdk": with_magic(b"KDMV", 512, 0),
    "vhd": with_magic(b"conectix", 512, 0),
    "zip_container": with_magic(b"PK\x03\x04", 256, 0),
    "registry_parser": with_magic(b"regf", 4096, 0),
    "evtx_parser": with_magic(b"ElfFile\x00", 4096, 0),
    "lnk_parser": with_magic(b"\x4c\x00\x00\x00\x01\x14\x02\x00", 512, 0),
    # AutomaticDestinations-ms is an OLE2 compound file.
    "jumplists_parser": with_magic(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 4096, 0),
    # ShellBags live in a registry hive.
    "shellbags_parser": with_magic(b"regf", 8192, 0),
    # The target prepends the CMMM signature itself; seed the header body.
    "thumbcache_parser": with_magic(b"\x14\x00\x00\x00", 1024, 0),
    "recyclebin_parser": recycle_bin_i(),
    # The targets prepend the regf / ESE magic themselves; seed a header body
    # of the size each reader expects before it looks at anything else.
    "amcache_parser": with_magic(b"\x00" * 4, 8192, 0),
    "shimcache_parser": with_magic(b"\x00" * 4, 8192, 0),
    "srum_parser": with_magic(b"\x00" * 4, 16384, 0),
    "webcache_parser": with_magic(b"\x00" * 4, 16384, 0),
    "winsearch_edb": with_magic(b"\x00" * 4, 16384, 0),
    # HIBR with the 4096-byte page size at 0x18, so a run reaches the
    # restore-set walk rather than stopping at the page-size check.
    "hibernation": with_magic(b"HIBR", 0x2000, 0)[:0x18]
    + (4096).to_bytes(4, "little")
    + with_magic(b"HIBR", 0x2000, 0)[0x1C:],
}


def ost4k_real_pages():
    """ost4k_parser: not synthetic. The Data Leakage OST cut at 0x98000 —
    every page and block either B-tree references lies below that, at its
    original offset (a block's signature folds in its offset, so nothing can
    be moved) — with the first 32 bytes naming the two roots (the target reads
    its roots from there; the header path re-forges magic and CRCs over the
    rest). None if the fixture is absent."""
    src = os.path.join(os.path.dirname(__file__), "..", "seance_plugin_email",
                       "tests", "fixtures", "ost_v36",
                       "iaman.informant_initialised_prefix.ost")
    if not os.path.exists(src):
        return None
    with open(src, "rb") as f:
        d = f.read()
    roots = struct.pack("<QQQQ", 0x36EB, 0x90000, 0x36F0, 0x91000)
    return roots + d[32:0x98000]


def main():
    for target, data in SEEDS.items():
        write(target, data)
    print(f"wrote {len(SEEDS)} synthetic seeds under {ROOT}")
    real = ost4k_real_pages()
    if real is not None:
        d = os.path.join(ROOT, "ost4k_parser")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "seed_real_pages"), "wb") as f:
            f.write(real)
        print("wrote the ost4k_parser seed cut from the Data Leakage OST")


if __name__ == "__main__":
    main()
