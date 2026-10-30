#!/usr/bin/env python3
"""Resolve each CFTT answer-key row's byte offset to the file that holds it.

    scripts/cftt/resolve-key-files.py <image.dd> <win_string_doc.txt> <key-files.json>

Uses The Sleuth Kit (mmls, fsstat, ifind, ffind) as an independent reference
tool -- NOT Séance -- so the grader can tell "the tool did not recover the
file" apart from "the key names a file the image does not hold" (VAL-002:
twelve of the key's file names are aliases no partition holds, e.g.
LIVE-LOUDBIRD-fat-ascii.txt, whose offset is in LIVE-thunderbird-fat-ascii.txt).

Rows skipped, each for a stated reason: a bare `UNKNOWN` file field (the META
rows, whose hit may be in a directory entry or MFT record rather than a file's
content), `unalloc` rows, and rows with no numeric offset.

For an offset inside the NTFS $MFT (a resident file's data), `ifind` answers
`$MFT`; the MFT record holding the offset is read instead (the `FILE` record's
own number at 0x2C) and that record's name is used.

A fragmented row resolves only when every fragment lands in the same file.
Each offset is converted to the file system's own data unit before `ifind -d`:
Sleuth Kit addresses FAT and exFAT by sector, NTFS by cluster, and Ext2/3/4 and
HFS+/HFSX by block (sizes from `fsstat`). Any other file system, or a partition
fsstat does not recognise (the unix image's fourth partition), is recorded as
"could not look" -- never as "no file there".

Anything unresolved is written as `image_file: null` with the reason -- never
guessed. Exit 3 when Sleuth Kit is not installed; exit 4 when no named row
resolved at all, so the runner reports the key as not checked.
"""
import json
import os
import shutil
import struct
import subprocess
import sys


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def partitions(image):
    rc, out = run("mmls", image)
    if rc != 0:
        return []
    parts = []
    for line in out.splitlines():
        f = line.split()
        # "004:  000  0000000034  0000976561  0000976528  ..." -- numbered slots only
        if len(f) >= 5 and f[0].endswith(":") and f[1].isdigit():
            parts.append((int(f[2]), int(f[3])))
    return parts


_fs_cache = {}


def fs_info(image, start):
    """(file system type, geometry) for the file system at sector `start`.

    Geometry holds the sizes `fsstat` reports: `sector`, `cluster` (FAT,
    exFAT, NTFS), `block` (Ext2/3/4 "Block Size", HFS+/HFSX "Allocation Block
    Size"). A size fsstat did not print is absent, never assumed.
    """
    if start not in _fs_cache:
        rc, out = run("fsstat", "-o", str(start), image)
        fstype, geo = None, {}
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                key, _, val = line.partition(":")
                val = val.strip()
                if key == "File System Type" and fstype is None:
                    fstype = val
                elif key in ("Sector Size", "Cluster Size", "Block Size", "Allocation Block Size") \
                        and val.isdigit():
                    name = {"Sector Size": "sector", "Cluster Size": "cluster",
                            "Block Size": "block", "Allocation Block Size": "block"}[key]
                    geo.setdefault(name, int(val))
        _fs_cache[start] = (fstype, geo)
    return _fs_cache[start]


def data_unit(fstype, rel_sector, geo):
    """The address `ifind -d` takes for 512-byte sector `rel_sector` of a file system.

    Returns (unit, None), or (None, reason) where this resolver does not know
    how Sleuth Kit addresses the file system -- which is "could not look",
    never "nothing there". Sleuth Kit addresses FAT and exFAT data by sector,
    NTFS by cluster, and Ext2/3/4 and HFS+/HFSX by the file system's block.
    """
    by = None
    if fstype in ("FAT12", "FAT16", "FAT32", "exFAT"):
        by = geo.get("sector", 512)
    elif fstype == "NTFS":
        by = geo.get("cluster")
    elif fstype in ("Ext2", "Ext3", "Ext4", "HFS+", "HFSX"):
        by = geo.get("block")
    else:
        return None, (f"could not look: this resolver does not know how Sleuth Kit addresses "
                      f"{fstype} data units")
    if not by:
        return None, f"could not look: fsstat reported no data-unit size for {fstype}"
    return rel_sector * 512 // by, None


def resolve_offset(image, parts, off):
    sector = off // 512
    part = next(((s, e) for s, e in parts if s <= sector <= e), None)
    if part is None:
        return None, "the offset is in no partition"
    start = part[0]
    fstype, geo = fs_info(image, start)
    if fstype is None:
        return None, f"could not look: no file system Sleuth Kit recognises at sector {start}"
    unit, why = data_unit(fstype, sector - start, geo)
    if unit is None:
        return None, why
    rc, inode = run("ifind", "-o", str(start), "-d", str(unit), image)
    if rc != 0 or not inode or "not found" in inode.lower():
        # Said as what ifind reported, not as "no file there": on Ext4 and
        # HFS+ a deleted file's metadata no longer points at its blocks, so
        # ifind cannot place it even where its bytes remain.
        return None, (f"ifind names no file owning {fstype} data unit {unit} (a deleted file "
                      f"whose metadata no longer points at its blocks cannot be placed this way)")
    how = f"ifind -o {start} -d {unit} -> {inode}"
    if fstype == "NTFS" and inode.split("-")[0] == "0":
        part_byte = start * 512
        rec = part_byte + (off - part_byte) // 1024 * 1024
        with open(image, "rb") as fh:
            fh.seek(rec)
            raw = fh.read(1024)
        if raw[:4] != b"FILE":
            return None, f"{how}; the 1024-byte record at {rec} is not a FILE record"
        inode = str(struct.unpack_from("<I", raw, 0x2C)[0])
        how += f"; resident data in MFT record {inode}"
    rc, path = run("ffind", "-o", str(start), image, inode)
    if rc != 0 or not path or "not found" in path.lower() or "invalid" in path.lower():
        return None, f"{how}; ffind names no file for inode {inode}"
    path = path.splitlines()[0]
    deleted = path.startswith("* ")
    path = path[2:] if deleted else path
    return {"path": path, "deleted": deleted, "how": how}, None


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    image, key, out = sys.argv[1:]
    missing = [t for t in ("mmls", "fsstat", "ifind", "ffind") if shutil.which(t) is None]
    if missing:
        print(f"Sleuth Kit is not installed (missing {', '.join(missing)}): the key's file names "
              "cannot be checked against the image, and the grader will withhold file-recovery "
              "attribution.", file=sys.stderr)
        return 3
    parts = partitions(image)
    rows = []
    with open(key, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            rid, _, rest = line.partition(":")
            f = rest.rsplit(":", 5)
            if len(f) < 6:
                continue
            term, byte_raw, _sector, file_field, locus, _enc = f
            if file_field.strip().upper() == "UNKNOWN" or locus.strip() == "unalloc":
                continue
            try:
                offsets = [int(x) for x in byte_raw.split(",")]
            except ValueError:
                continue
            found, why = [], None
            for off in offsets:
                r, why = resolve_offset(image, parts, off)
                if r is None:
                    break
                found.append(r)
            row = {"id": rid.strip(), "term": term, "offsets": offsets,
                   "key_file": file_field.strip(), "image_file": None}
            if why is not None:
                row["unresolved"] = why
            elif len({r["path"] for r in found}) != 1:
                row["unresolved"] = "the fragments land in different files: " + ", ".join(
                    r["path"] for r in found)
            else:
                row.update(image_file=os.path.basename(found[0]["path"]), path=found[0]["path"],
                           deleted=found[0]["deleted"], how=[r["how"] for r in found])
            rows.append(row)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=1)
    resolved = [r for r in rows if r["image_file"]]
    differ = [r for r in resolved if r["image_file"].lower() != os.path.basename(r["key_file"]).lower()]
    blind = [r for r in rows if r.get("unresolved", "").startswith("could not look")]
    print(f"{len(resolved)} of {len(rows)} named rows resolved to a file on the image; "
          f"{len(differ)} name a different file than the key does; "
          f"{len(blind)} could not be looked at (unsupported or unrecognised file system)",
          file=sys.stderr)
    # A resolution that resolved nothing is not a resolution: say so with a
    # non-zero exit, so the runner prints that the key was NOT checked rather
    # than grading as though it had been.
    if rows and not resolved:
        print("no named row resolved to a file: the key's file names were not checked "
              "against this image", file=sys.stderr)
        return 4
    return 0

if __name__ == "__main__":
    sys.exit(main())
