#!/usr/bin/env python3
"""Write the file-slack answer key for one HFS+ partition from The Sleuth Kit.

    python3 scripts/cftt/hfs_slack_key.py IMAGE SECTOR_OFFSET > key.json

For every regular file with a catalog node ID of 16 or more, `fls` names it,
`istat` gives its size and data-fork blocks, and `icat -s` prints its slack, the
bytes from the logical end to the end of the last allocation block. The key
records, for each file whose slack is not all zero, the slack's offset in the
partition, its length and its SHA-256, and for each file whose tail is all zero
the same offset and length without a digest. Nothing here is produced by Seance.
"""
import hashlib
import json
import re
import subprocess
import sys


def run(cmd, binary=False):
    out = subprocess.run(cmd, check=True, capture_output=True).stdout
    return out if binary else out.decode("utf-8", "replace")


def blocks_of(istat_text):
    """The data fork's allocation blocks in file order."""
    m = re.search(r"Data Fork Blocks:\n(.*?)\n\n", istat_text + "\n\n", re.S)
    out = []
    if not m:
        return out
    for token in m.group(1).split():
        if "-" in token:
            lo, hi = token.split("-")
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(token))
    return out


def main():
    image, offset = sys.argv[1], sys.argv[2]
    fsstat = run(["fsstat", "-o", offset, image])
    block_size = int(re.search(r"Allocation Block Size:\s*(\d+)", fsstat).group(1))
    key = {"image_basename": image.rsplit("/", 1)[-1], "sector_offset": int(offset),
           "block_size": block_size, "files": {}, "zero_files": {}, "zero_tail": 0, "no_tail": 0}
    for line in run(["fls", "-r", "-p", "-F", "-o", offset, image]).splitlines():
        m = re.match(r"r/r (\d+):\t(.*)", line)
        if not m:
            continue
        inode, path = int(m.group(1)), m.group(2)
        if inode < 16:
            continue
        ist = run(["istat", "-o", offset, image, str(inode)])
        size = int(re.search(r"Type: DATA .*?size: (\d+)", ist).group(1))
        if size == 0 or size % block_size == 0:
            key["no_tail"] += 1
            continue
        blocks = blocks_of(ist)
        last = blocks[(size - 1) // block_size]
        slack = run(["icat", "-s", "-o", offset, image, str(inode)], binary=True)
        want = block_size - size % block_size
        # icat -s prints the file's content followed by its slack on some
        # builds; the slack is the final `want` bytes.
        slack = slack[-want:]
        assert len(slack) == want, (path, len(slack), want)
        if not any(slack):
            key["zero_tail"] += 1
            key["zero_files"]["/" + path] = {
                "cnid": inode,
                "size": size,
                "offset": last * block_size + size % block_size,
                "length": want,
            }
            continue
        key["files"]["/" + path] = {
            "cnid": inode,
            "size": size,
            "offset": last * block_size + size % block_size,
            "length": want,
            "sha256": hashlib.sha256(slack).hexdigest(),
        }
    json.dump(key, sys.stdout, indent=1, sort_keys=True)
    print()


main()
