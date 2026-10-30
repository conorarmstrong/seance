#!/usr/bin/env python3
"""Synthesise the ext4 volumes whose shapes the parser used to refuse (EXT4-001)
and write down the answer from independent tools.

    python3 scripts/synth/build_ext4_refused_fixtures.py --out seance_plugin_ext4/tests/fixtures

SYNTHETIC. Every image is written by `mke2fs -d` (e2fsprogs), the real tool, from
a staging directory; none is real-world evidence and none may be used to grade a
claim about real-world evidence. The answer key comes from `debugfs` and
`dumpe2fs`, never from Seance:

    ext4_inline    inline_data volume: files held in i_block, in i_block plus the
                   system.data xattr, and inline directories (one with a
                   system.data continuation). Key: `debugfs cat` bytes, `debugfs
                   ls` names, `e2fsck -fn` clean.
    ext4_bigalloc  bigalloc volume (1 KiB blocks, 4 KiB clusters, four groups).
                   Key: dumpe2fs per-group `Free blocks:` ranges, `debugfs cat`.
    ext4_uninit_*  lazily initialised volumes with BLOCK_UNINIT groups, in the
                   flex_bg, no-flex_bg, meta_bg and 4 KiB-block layouts. Key: dumpe2fs per-group
                   `Free blocks:` ranges (libext2fs computes the bitmap the kernel
                   would for an uninitialised group).

Writes <out>/<name>/<name>.img.gz and <out>/<name>/expected.json. Needs mke2fs,
debugfs, dumpe2fs and e2fsck.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile


def run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True)
    if check and r.returncode != 0:
        raise SystemExit(f"{cmd} failed: {r.stderr.decode(errors='replace')}")
    return r


def fill(seed, n):
    """Deterministic, non-repeating-looking bytes."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def make_image(path, size, args, src=None):
    with open(path, "wb") as f:
        f.truncate(size)
    cmd = ["mke2fs", "-q", "-t", "ext4", "-E", "lazy_itable_init=1", *args]
    if src:
        cmd += ["-d", src]
    run(cmd + [path])


def debugfs_w(img, request):
    return run(["debugfs", "-w", "-R", request, img]).stdout


def debugfs(img, request):
    return run(["debugfs", "-R", request, img]).stdout


def stat_size(img, path):
    m = re.search(r"Size: (\d+)", debugfs(img, f"stat {path}").decode())
    return int(m.group(1))


def cat(img, path):
    """`debugfs cat`, cut to the size debugfs's own `stat` reports: debugfs 1.47
    pads an inline file shorter than 60 bytes out to the whole of i_block."""
    return debugfs(img, f"cat {path}")[: stat_size(img, path)]


def ls_names(img, path):
    names = []
    for line in debugfs(img, f"ls -p {path}").decode().splitlines():
        parts = line.split("/")
        if len(parts) > 5 and parts[5] not in ("", ".", ".."):
            names.append(parts[5])
    return sorted(names)


def group_table(img):
    """Per-group free ranges and flags exactly as dumpe2fs prints them."""
    text = run(["dumpe2fs", img]).stdout.decode()
    groups = []
    for m in re.finditer(
        r"^Group (\d+): \(Blocks (\d+)-(\d+)\)[^\n]*?(?:\[([^\]]*)\])?\n(.*?)(?=^Group |\Z)",
        text,
        re.M | re.S,
    ):
        body = m.group(5)
        free = []
        fm = re.search(r"Free blocks: ([^\n]*)", body)
        if fm and fm.group(1).strip():
            for rng in fm.group(1).split(", "):
                lo, _, hi = rng.partition("-")
                free.append([int(lo), int(hi or lo)])
        groups.append(
            {
                "group": int(m.group(1)),
                "first": int(m.group(2)),
                "last": int(m.group(3)),
                "flags": (m.group(4) or "").split(", ") if m.group(4) else [],
                "free": free,
            }
        )
    return groups


def e2fsck_clean(img):
    return run(["e2fsck", "-fn", img], check=False).returncode == 0


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write_fixture(out, name, img, expected):
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    with open(img, "rb") as f:
        raw = f.read()
    expected["image"] = f"{name}.img"
    expected["image_sha256"] = sha(raw)
    expected["synthetic"] = True
    expected["grades"] = "the parser against debugfs/dumpe2fs on a volume mke2fs wrote; never a real-world claim"
    with gzip.GzipFile(os.path.join(d, f"{name}.img.gz"), "wb", 9, mtime=0) as g:
        g.write(raw)
    with open(os.path.join(d, "expected.json"), "w") as f:
        json.dump(expected, f, indent=2, sort_keys=True)
        f.write("\n")


def stage(root, files, dirs=()):
    for d in dirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)


def build_inline(out, tmp):
    src = os.path.join(tmp, "inline_src")
    files = {
        "tiny.txt": b"inline file, 26 bytes long",
        "h100.txt": fill("h100", 100),  # 60 in i_block + 40 in system.data
        "exact60.bin": fill("e60", 60),  # all of i_block
        "split61.bin": fill("s61", 61),  # one byte in system.data
        "mid.txt": fill("mid", 136),  # too big for the inode: extents
        "sub/x.txt": b"x",
        "sub/y.txt": b"yy",
        # five short names: the listing overflows i_block into system.data
        **{f"many/{c}": c.encode() for c in "abcde"},
    }
    stage(src, files, dirs=["d1", "sub", "many"])
    img = os.path.join(tmp, "ext4_inline.img")
    make_image(img, 8 << 20, ["-O", "inline_data,^has_journal", "-I", "256", "-b", "1024"], src)
    # libext2fs expands an inline directory into a block rather than spill it
    # into system.data, so the continuation (which the kernel does write) is
    # planted with debugfs: a new inode, unlinked from the root (debugfs leaves
    # its link count at 1), named by a dirent in /sub's system.data, with i_size
    # raised to 60 + the continuation's length. e2fsck then has to agree.
    zz = b"continued in system.data"
    zz_path = os.path.join(tmp, "zz.txt")
    with open(zz_path, "wb") as f:
        f.write(zz)
    debugfs_w(img, f"write {zz_path} zz.txt")
    zz_ino = int(re.search(r"Inode: (\d+)", debugfs(img, "stat /zz.txt").decode()).group(1))
    debugfs_w(img, "unlink /zz.txt")
    cont = struct.pack("<IHBB", zz_ino, 16, 6, 1) + b"zz.txt\0\0"
    cont_path = os.path.join(tmp, "cont.bin")
    with open(cont_path, "wb") as f:
        f.write(cont)
    debugfs_w(img, f"ea_set -f {cont_path} /sub system.data")
    debugfs_w(img, f"sif /sub size {60 + len(cont)}")
    exp = {"files": {}, "dirs": {}, "e2fsck_clean": e2fsck_clean(img)}
    got = cat(img, "/sub/zz.txt")
    assert got == zz
    exp["files"]["sub/zz.txt"] = {"size": len(zz), "sha256": sha(got), "inline": True, "hex": got.hex()}
    for rel, data in files.items():
        got = cat(img, "/" + rel)
        assert got == data, (rel, got[:80], data[:80])
        stat = debugfs(img, f"stat /{rel}").decode()
        exp["files"][rel] = {
            "size": len(data),
            "sha256": sha(got),
            "hex": got.hex(),
            "inline": bool(int(re.search(r"Flags: (0x[0-9a-f]+)", stat).group(1), 16) & 0x10000000),
        }
    for d in ["d1", "sub", "many"]:
        stat = debugfs(img, f"stat /{d}").decode()
        flags = int(re.search(r"Flags: (0x[0-9a-f]+)", stat).group(1), 16)
        exp["dirs"][d] = {"names": ls_names(img, f"/{d}"), "inline": bool(flags & 0x10000000)}
    write_fixture(out, "ext4_inline", img, exp)


def build_bigalloc(out, tmp):
    src = os.path.join(tmp, "bigalloc_src")
    files = {
        "one.bin": fill("one", 1),
        "five.bin": fill("five", 5000),
        "big.bin": fill("big", 70000),
        "dir/inner.txt": fill("inner", 3000),
    }
    stage(src, files, dirs=["dir"])
    img = os.path.join(tmp, "ext4_bigalloc.img")
    make_image(
        img,
        128 << 20,
        ["-O", "bigalloc,^resize_inode,^has_journal", "-b", "1024", "-C", "4096"],
        src,
    )
    exp = {
        "block_size": 1024,
        "cluster_size": 4096,
        "groups": group_table(img),
        "e2fsck_clean": e2fsck_clean(img),
        "files": {},
    }
    for rel, data in files.items():
        got = cat(img, "/" + rel)
        assert got == data, (rel, got[:80], data[:80])
        exp["files"][rel] = {"size": len(data), "sha256": sha(got)}
    write_fixture(out, "ext4_bigalloc", img, exp)


def build_uninit(out, tmp):
    variants = {
        "ext4_uninit_flex": ["-O", "^has_journal,resize_inode"],
        "ext4_uninit_noflex": ["-O", "^has_journal,^flex_bg,resize_inode"],
        "ext4_uninit_meta": ["-O", "^has_journal,meta_bg,^resize_inode"],
        # 4 KiB blocks, gdt_csum rather than metadata_csum. mke2fs never leaves
        # a backup-superblock group BLOCK_UNINIT, so groups 3 and 5 (each with a
        # backup superblock, a descriptor block and 127 reserved descriptor
        # blocks) are flagged BLOCK_UNINIT through `debugfs set_bg` and their
        # on-disk block bitmaps zeroed, as a stale bitmap would be. e2fsck -fn
        # stays clean. This mutation is part of the SYNTHETIC construction.
        "ext4_uninit_4k": ["-O", "^has_journal,resize_inode,^metadata_csum,uninit_bg"],
    }
    for name, feat in variants.items():
        src = os.path.join(tmp, name + "_src")
        files = {"a.txt": fill(name, 3000)}
        stage(src, files)
        img = os.path.join(tmp, name + ".img")
        if name == "ext4_uninit_4k":
            block, size, geom = 4096, 256 << 20, ["-b", "4096", "-g", "8192"]
        else:
            block, size, geom = 1024, 64 << 20, ["-b", "1024", "-g", "8192"]
        make_image(img, size, feat + geom, src)
        if name == "ext4_uninit_4k":
            for g in (3, 5):
                debugfs_w(img, f"set_bg {g} flags 7")
                debugfs_w(img, f"set_bg {g} checksum calc")
                m = re.search(
                    rf"^Group {g}:.*?Block bitmap at (\d+)",
                    run(["dumpe2fs", img]).stdout.decode(),
                    re.M | re.S,
                )
                with open(img, "r+b") as f:
                    f.seek(int(m.group(1)) * block)
                    f.write(bytes(block))
        groups = group_table(img)
        exp = {
            "block_size": block,
            "groups": groups,
            "uninit_groups": [g["group"] for g in groups if "BLOCK_UNINIT" in g["flags"]],
            "e2fsck_clean": e2fsck_clean(img),
            "files": {"a.txt": {"size": 3000, "sha256": sha(cat(img, "/a.txt"))}},
        }
        write_fixture(out, name, img, exp)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", choices=["inline", "bigalloc", "uninit"])
    a = ap.parse_args()
    for tool in ("mke2fs", "debugfs", "dumpe2fs", "e2fsck"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} not found")
    with tempfile.TemporaryDirectory() as tmp:
        if a.only in (None, "inline"):
            build_inline(a.out, tmp)
        if a.only in (None, "bigalloc"):
            build_bigalloc(a.out, tmp)
        if a.only in (None, "uninit"):
            build_uninit(a.out, tmp)


if __name__ == "__main__":
    main()
