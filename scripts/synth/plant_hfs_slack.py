#!/usr/bin/env python3
"""Plant bytes in the slack of a real HFS+ partition and let The Sleuth Kit confirm them.

    python3 scripts/synth/plant_hfs_slack.py KEY.json IMAGE SECTOR_OFFSET WORKDIR

SYNTHETIC. The real partition's file tails are all zero, so there is nothing for a
slack reader to find on it. This copies the partition to WORKDIR, writes a
deterministic non-zero pattern into the tail of every fifth file in KEY.json's
`zero_files` (offsets and lengths come from `icat -s`, not from Seance), then runs
`icat -s` on the copy and checks that the bytes TSK prints as each file's slack are
exactly the planted ones. The pattern for file `cnid` is

    byte i = 1 + ((cnid * 131 + i) % 250)

which the Rust test `seance_plugin_hfsplus/tests/real_slack_test.rs` reproduces to
plant the same bytes in memory. Nothing here is real-world evidence.
"""
import json
import subprocess
import sys


def pattern(cnid, length):
    return bytes(1 + ((cnid * 131 + i) % 250) for i in range(length))


def main():
    key_path, image, sector, work = sys.argv[1:5]
    key = json.load(open(key_path))
    start = int(sector) * 512
    part = work + "/hfs-planted.img"
    with open(image, "rb") as src, open(part, "wb") as dst:
        src.seek(start)
        remaining = key.get("partition_bytes") or 976563 * 512
        while remaining:
            chunk = src.read(min(remaining, 1 << 24))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
    chosen = sorted(key["zero_files"].items())[::5]
    with open(part, "r+b") as f:
        for path, t in chosen:
            f.seek(t["offset"])
            f.write(pattern(t["cnid"], t["length"]))
    bad = 0
    for path, t in chosen:
        out = subprocess.run(["icat", "-s", part, str(t["cnid"])], capture_output=True, check=True).stdout
        if out[-t["length"]:] != pattern(t["cnid"], t["length"]):
            bad += 1
            print("MISMATCH", path)
    print(f"planted {len(chosen)} tails, TSK agrees on {len(chosen) - bad}")
    sys.exit(1 if bad else 0)


main()
