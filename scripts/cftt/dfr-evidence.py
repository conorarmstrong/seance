#!/usr/bin/env python3
"""Evidence for DFR non-conformances, from The Sleuth Kit (ROADMAP §5.2).

    scripts/cftt/dfr-evidence.py <report.json> <dd-dir> <classes-out.json> [<results.json>]

`cftt-grade --dfr` classes every failure "real defect" until someone shows
otherwise. This script is the "shows otherwise" for ONE pattern, and only
where an independent reference tool (The Sleuth Kit, not Séance) bears it out:

  DFR-CR-02 "listed, but no content was produced" on an ext image, where the
  deleted file's residual metadata identifies no content -- its directory
  entry holds inode 0 (`fls` prints `* 0:`), or its inode records size 0 and
  no blocks (`istat`). Nothing in residual metadata says where the content
  was, so no object can be built from it: the grader's expectation, not the
  tool, is what failed. Such rows are classed `grader_artifact` with the
  Sleuth Kit output quoted as the reason. Where `fls` does not list the name
  at all (a name recovered from an orphaned directory block) and the run's
  results.json gives the inode the tool read, `istat` is asked about that
  inode on every partition, and the row is evidenced only when every
  partition's inode of that number records size 0 and no blocks.

  DFR-CR-01 "not listed" or "listed only as not deleted" (and the DFR-CR-02
  that follows from it) on an ext, FAT, NTFS or exFAT image, where The Sleuth
  Kit's `fls -r -d` finds no deleted entry of that name on any partition
  either. NIST's layout says residual metadata describes the file; two
  independent tools find none. That is classed `corpus_divergence`, with the
  reason saying exactly that -- it is not proof the layout is wrong, and the
  report says two tools agree, not that the file was never there. HFS+
  (`osx`) is excluded: Sleuth Kit does not list deleted HFS+ entries, so its
  silence there is not evidence.

Every other failure is left alone. A failure this script could not look at
(Sleuth Kit missing, image absent, name not found by `fls`) keeps the default
class; it is never excused for want of evidence.
"""
import json
import os
import re
import subprocess
import sys


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace").stdout


def partitions(dd):
    """Start sectors of the image's data partitions, from `mmls`."""
    out = []
    for line in run("mmls", dd).splitlines():
        m = re.match(r"\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)", line)
        if m and "Unallocated" not in m.group(4) and "Table" not in m.group(4) \
                and "Extended" not in m.group(4):
            out.append(int(m.group(1)))
    return out


def evidence(dd, name):
    """(True, reason) when the name's residual metadata identifies no content."""
    for off in partitions(dd):
        for line in run("fls", "-r", "-d", "-p", "-o", str(off), dd).splitlines():
            m = re.match(r"\S+\s+\*\s+(\d+)(?:-\S+)?(?:\(realloc\))?:\s+(.*)$", line)
            if not m or os.path.basename(m.group(2)) != name:
                continue
            inode = int(m.group(1))
            if inode == 0:
                return True, (f"The Sleuth Kit: `fls -d -o {off}` lists `{m.group(2)}` with inode 0 "
                              "-- the directory entry no longer names an inode")
            ist = run("istat", "-o", str(off), dd, str(inode))
            size = re.search(r"^size:\s+(\d+)", ist, re.M)
            blocks = re.search(r"^Direct Blocks:\s*\n(\s*\d)", ist, re.M)
            if size and int(size.group(1)) == 0 and not blocks:
                return True, (f"The Sleuth Kit: `istat -o {off}` on inode {inode} (`{m.group(2)}`) "
                              "records size 0 and no blocks")
            return False, None
    return False, None


def deleted_names(dd):
    """Every deleted name `fls -r -d` lists on any partition (or the whole
    image when it has no partition table), and whether any partition was read."""
    names, looked = set(), False
    offs = partitions(dd) or [None]
    for off in offs:
        args = ["fls", "-r", "-d", "-p"] + (["-o", str(off)] if off is not None else []) + [dd]
        out = run(*args)
        if out.strip():
            looked = True
        for line in out.splitlines():
            m = re.match(r"\S+\s+\*\s+\S+?:\s+(.*)$", line)
            if m:
                names.add(os.path.basename(m.group(1)))
    return names, looked


def inode_evidence(dd, name, inode):
    """(True, reason) when inode `inode` records size 0 and no blocks on every
    partition -- so whichever partition the name came from, its residual
    metadata locates no content."""
    offs = partitions(dd)
    if not offs:
        return False, None
    for off in offs:
        ist = run("istat", "-o", str(off), dd, str(inode))
        size = re.search(r"^size:\s+(\d+)", ist, re.M)
        blocks = re.search(r"^Direct Blocks:\s*\n(\s*\d)", ist, re.M)
        if not size or int(size.group(1)) != 0 or blocks:
            return False, None
    return True, (f"The tool read `{name}` from inode {inode}, and The Sleuth Kit's `istat` records "
                  f"that inode as size 0 with no blocks on every partition "
                  f"({', '.join(map(str, offs))})")


def main():
    report, dd_dir, out = sys.argv[1:4]
    inodes = {}
    if len(sys.argv) > 4:
        for img in json.load(open(sys.argv[4])):
            for e in img.get("entries") or []:
                if e.get("deleted") and e.get("inode") is not None:
                    inodes.setdefault((os.path.basename(img["image"]), e["name"]), e["inode"])
    rows = json.load(open(report))["rows"]
    rules = []
    fls_cache = {}
    for r in rows:
        if r["status"] == "FAIL" and r["assertion"] in ("DFR-CR-01", "DFR-CR-02") and r["file"] \
                and (r["actual"] == "not listed" or r["actual"].startswith("listed only as not deleted")
                     or r["actual"].startswith("the file is not listed")):
            fs, rest = r["image"].split("-", 1)
            if fs not in ("ext", "fat", "ntfs", "xfat"):
                continue
            nn, _, variant = rest.partition("-")
            dd = os.path.join(dd_dir, f"dfr-{nn}{'-' + variant if variant else ''}-{fs}.dd")
            if not os.path.exists(dd):
                continue
            if dd not in fls_cache:
                fls_cache[dd] = deleted_names(dd)
            names, looked = fls_cache[dd]
            if looked and r["file"] not in names:
                rules.append({"image": r["image"], "assertion": r["assertion"], "file": r["file"],
                              "class": "corpus_divergence",
                              "reason": "NIST's layout says residual metadata describes this file, and "
                                        "neither this tool nor The Sleuth Kit (`fls -r -d`, every "
                                        "partition, 2026-09-27) finds a deleted entry of that name"})
            continue
        if r["status"] != "FAIL" or r["assertion"] != "DFR-CR-02" or not r["file"]:
            continue
        if not r["image"].startswith("ext-") or not r["actual"].startswith("listed, but no content"):
            continue
        fs, rest = r["image"].split("-", 1)
        nn, _, variant = rest.partition("-")
        dd = os.path.join(dd_dir, f"dfr-{nn}{'-' + variant if variant else ''}-{fs}.dd")
        if not os.path.exists(dd):
            continue
        ok, why = evidence(dd, r["file"])
        if not ok and (os.path.basename(dd), r["file"]) in inodes:
            ok, why = inode_evidence(dd, r["file"], inodes[(os.path.basename(dd), r["file"])])
        if ok:
            rules.append({"image": r["image"], "assertion": "DFR-CR-02", "file": r["file"],
                          "class": "grader_artifact",
                          "reason": why + "; nothing in residual metadata locates the content"})
    json.dump(rules, open(out, "w"), ensure_ascii=False, indent=1)
    print(f"{len(rules)} failure(s) evidenced", file=sys.stderr)


if __name__ == "__main__":
    main()
