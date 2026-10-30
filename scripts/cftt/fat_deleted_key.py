#!/usr/bin/env python3
"""Write the deleted-file answer key for one FAT volume from The Sleuth Kit.

    python3 scripts/cftt/fat_deleted_key.py IMAGE SECTOR_OFFSET > key.json

`fls -r -d` lists every deleted file entry TSK finds, including entries in free clusters it reaches
by scanning (the `$OrphanFiles` pseudo-directory); `istat` gives each one's size and first sector.
The key records, for each, its path as TSK names it, its size and its first sector in the volume. Nothing
in it comes from Seance.
"""
import json
import re
import subprocess
import sys


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True).stdout.decode("utf-8", "replace")


def main():
    image, offset = sys.argv[1], sys.argv[2]
    key = {"image_basename": image.rsplit("/", 1)[-1], "sector_offset": int(offset), "files": {}, "directories": {}}
    for line in run(["fls", "-r", "-d", "-p", "-o", offset, image]).splitlines():
        m = re.match(r"([-rdv/]+)\s+\*\s+(\d+)(?:\([^)]*\))?:\t(.*)", line)
        if not m:
            continue
        kind, inode, path = m.group(1), int(m.group(2)), m.group(3)
        ist = run(["istat", "-o", offset, image, str(inode)])
        size = re.search(r"^Size: (\d+)", ist, re.M)
        sectors = re.search(r"Sectors:\n(\d+)", ist)
        record = {"inode": inode, "size": int(size.group(1)) if size else None,
                  "first_sector": int(sectors.group(1)) if sectors else None}
        (key["directories"] if kind.endswith("d") and kind.startswith(("-/d", "d/d")) else key["files"])["/" + path] = record
    json.dump(key, sys.stdout, indent=1, sort_keys=True)
    print()


main()
