#!/usr/bin/env python3
"""Synthesise a small real ext4 image whose files have known tails, with known
bytes planted in two of them, and write the answer down.

    python3 scripts/synth/build_ext4_slack_fixture.py --out /tmp/ext4_slack

`mke2fs -d` writes a real ext4 volume (1 KiB blocks, no journal) from a staging
directory; no root, no loop device. mke2fs leaves every file's tail zero, so
the script then writes recognisable bytes into the tails of two files at the
physical offsets pytsk3 (an independent reader) reports for their last blocks.
The ground truth is therefore this script's own plan, checked against pytsk3,
never against Séance:

    tail_a.txt     1500 B  2 blocks  548-byte tail, PLANTED   -> one slack region
    big.bin        5000 B  5 blocks  120-byte tail, PLANTED   -> one slack region
    tail_zero.txt   700 B  1 block   324-byte tail, all zero  -> counted, no region
    exact.bin      2048 B  2 blocks  no tail                  -> nothing
    empty.dat         0 B                                      -> nothing
    tail_a_link.txt   a hard link to tail_a.txt: one inode, offered once

Writes <out>/ext4_slack.img and <out>/expected.json. Needs mke2fs and pytsk3.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

BLOCK = 1024
FILES = {
    "tail_a.txt": (1500, b"A"),
    "big.bin": (5000, b"B"),
    "tail_zero.txt": (700, b"Z"),
    "exact.bin": (2048, b"E"),
    "empty.dat": (0, b""),
}
# A second name for the same inode: its tail is one tail, not two.
LINKS = {"tail_a_link.txt": "tail_a.txt"}
PLANTED = {
    "tail_a.txt": b"leftover of a deleted file: alpha-7f3a9c ",
    "big.bin": b"SLACK-MARK-BIG-5d21 ",
}


def fill(pattern, n):
    return (pattern * (n // len(pattern) + 1))[:n]


def last_block_offset(fs, path):
    f = fs.open(path)
    runs = [(r.addr, r.len) for a in f for r in a]
    addr, length = runs[-1]
    return (addr + length - 1) * BLOCK


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not shutil.which("mke2fs"):
        sys.exit("mke2fs (e2fsprogs) is required")
    import pytsk3
    os.makedirs(a.out, exist_ok=True)
    image = os.path.join(a.out, "ext4_slack.img")
    with tempfile.TemporaryDirectory() as stage:
        for name, (size, pat) in FILES.items():
            with open(os.path.join(stage, name), "wb") as f:
                f.write(fill(pat, size) if size else b"")
        for link, target in LINKS.items():
            os.link(os.path.join(stage, target), os.path.join(stage, link))
        if os.path.exists(image):
            os.remove(image)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", str(BLOCK), "-O",
                        "^has_journal", "-L", "SLACKFIX", "-d", stage, image,
                        "2048"], check=True)
    fs = pytsk3.FS_Info(pytsk3.Img_Info(image))
    plan = {}
    with open(image, "r+b") as img:
        for name, (size, _) in FILES.items():
            if size == 0 or size % BLOCK == 0:
                plan[name] = {"size": size, "tail": None}
                continue
            tail_len = BLOCK - size % BLOCK
            tail_at = last_block_offset(fs, "/" + name) + size % BLOCK
            img.seek(tail_at)
            assert img.read(tail_len) == bytes(tail_len), "mke2fs left a non-zero tail"
            entry = {"size": size, "tail": {"offset": tail_at, "length": tail_len}}
            if name in PLANTED:
                data = fill(PLANTED[name], tail_len)
                img.seek(tail_at)
                img.write(data)
                entry["tail"]["planted"] = data.decode()
            plan[name] = entry
    data = open(image, "rb").read()
    # Independent check: the planted bytes sit exactly where pytsk3 says each
    # file's content ends, and the file content itself is untouched.
    fs = pytsk3.FS_Info(pytsk3.Img_Info(image))
    for name, e in plan.items():
        f = fs.open("/" + name)
        assert f.info.meta.size == e["size"]
        content = f.read_random(0, e["size"]) if e["size"] else b""
        assert content == (fill(FILES[name][1], e["size"]) if e["size"] else b"")
        if e["tail"] and "planted" in e["tail"]:
            t = e["tail"]
            assert data[t["offset"]:t["offset"] + t["length"]] == t["planted"].encode()
    out = {
        "image": "ext4_slack.img",
        "block_size": BLOCK,
        "image_sha256": hashlib.sha256(data).hexdigest(),
        "regions_expected": [n for n in plan if plan[n]["tail"] and "planted" in plan[n]["tail"]],
        "zero_tails_expected": [n for n in plan if plan[n]["tail"] and "planted" not in plan[n]["tail"]],
        "hard_links": LINKS,
        "files": plan,
    }
    with open(os.path.join(a.out, "expected.json"), "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
