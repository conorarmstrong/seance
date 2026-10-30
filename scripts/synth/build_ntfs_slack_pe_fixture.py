#!/usr/bin/env python3
"""Synthesise a real NTFS volume inside an MBR partition, with a PE image
planted in a live file's cluster slack, and write the answer down (HUNT-124).

    python3 scripts/synth/build_ntfs_slack_pe_fixture.py --out /tmp/ntfs_slack_pe

mkntfs writes the volume (512-byte sectors, 4096-byte clusters), ntfscp adds
files, sfdisk puts the volume in an MBR partition starting at LBA 2048. The
planted bytes go at a disk offset derived from the cluster ntfscluster (an
independent reader) reports for each file. The plan is this script's own,
checked against ntfscluster, never against Seance.

    host.bin     1000 B, 1 cluster, PE32 planted in slack at +1024 -> one region
    zero.bin     1000 B, 1 cluster, tail all zero                  -> no region
    exact.bin    4096 B, 1 cluster, no tail                        -> nothing

SYNTHETIC: the volume is real mkntfs output, the planted payload is not
real-world evidence. Needs ntfs-3g tools (mkntfs, ntfscp, ntfscluster), sfdisk.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile

SECTOR, CLUSTER, START_LBA, PE_AT = 512, 4096, 2048, 1024


def tiny_pe32():
    pe = bytearray(0x400)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    c = 0x44
    struct.pack_into("<HH", pe, c, 0x014C, 1)
    struct.pack_into("<H", pe, c + 16, 0xE0)
    struct.pack_into("<H", pe, c + 18, 0x0102)
    o = c + 20
    struct.pack_into("<H", pe, o, 0x010B)
    for off, v in [(16, 0x1000), (20, 0x1000), (24, 0x1000), (28, 0x400000),
                   (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200),
                   (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000)]:
        struct.pack_into("<I", pe, o + off, v)
    struct.pack_into("<H", pe, o + 40, 4)
    struct.pack_into("<H", pe, o + 48, 4)
    struct.pack_into("<H", pe, o + 68, 2)
    struct.pack_into("<I", pe, o + 92, 16)
    s = o + 0xE0
    pe[s:s + 5] = b".text"
    for off, v in [(8, 0x100), (12, 0x1000), (16, 0x200), (20, 0x200), (36, 0x60000020)]:
        struct.pack_into("<I", pe, s + off, v)
    pe[0x200] = 0xC3
    return bytes(pe)


def run(*a):
    return subprocess.run(a, check=True, capture_output=True, text=True).stdout


def lcn_of(part, name):
    out = run("ntfscluster", "-f", "-F", "/" + name, part)
    # The data run table prints "VCN LCN Length" then one "0 <lcn> <len>" row.
    m = re.search(r"^\s+0\s+(\d+)\s+\d+\s*$", out, re.M)
    if not m:
        raise SystemExit(f"ntfscluster did not report a cluster for {name}:\n{out}")
    return int(m.group(1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    out = ap.parse_args().out
    os.makedirs(out, exist_ok=True)
    tmp = tempfile.mkdtemp()
    part = os.path.join(tmp, "part.img")
    disk = os.path.join(out, "ntfs_slack_pe.img")
    run("truncate", "-s", "6M", part)
    run("mkntfs", "-F", "-q", "-s", str(SECTOR), "-c", str(CLUSTER), part)
    files = {"host.bin": (1000, b"H"), "zero.bin": (1000, b"Z"), "exact.bin": (4096, b"E")}
    for n, (size, ch) in files.items():
        p = os.path.join(tmp, n)
        with open(p, "wb") as f:
            f.write(ch * size)
        run("ntfscp", "-f", part, p, n)
    lcns = {n: lcn_of(part, n) for n in files}
    run("truncate", "-s", "8M", disk)
    run("sh", "-c", f"echo 'start={START_LBA}, type=7' | sfdisk -q {disk}")
    run("dd", f"if={part}", f"of={disk}", f"seek={START_LBA}", "bs=512",
        "conv=notrunc", "status=none")
    pe = tiny_pe32()
    start = START_LBA * SECTOR
    host_off = start + lcns["host.bin"] * CLUSTER + PE_AT
    with open(disk, "r+b") as f:
        f.seek(host_off)
        f.write(pe)
    with open(disk, "rb") as f:
        raw = f.read()
    exp = {
        "image": "ntfs_slack_pe.img",
        "synthetic": True,
        "image_sha256": hashlib.sha256(raw).hexdigest(),
        "partition_start_bytes": start,
        "cluster_size": CLUSTER,
        "lcn": lcns,
        "pe_disk_offset": host_off,
        "pe_host": "host.bin",
        "pe_len": len(pe),
        "regions_expected": ["host.bin"],
        "no_region_expected": ["zero.bin", "exact.bin"],
    }
    with open(os.path.join(out, "expected.json"), "w") as f:
        json.dump(exp, f, indent=2)
    with gzip.GzipFile(disk + ".gz", "wb", mtime=0) as g:
        g.write(raw)
    print(json.dumps(exp, indent=2))


if __name__ == "__main__":
    main()
