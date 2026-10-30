#!/usr/bin/env python3
"""Measure structural code duplication between crates (ROADMAP §5.11).

A window of W consecutive non-comment lines, with string literals, numbers and
identifiers normalised away (Rust keywords kept), is a clone when it appears in
two or more crates. Test files and vendored code are skipped. This finds
copy-paste with renamed identifiers; it does not find reimplementation of the
same idea in different shapes, so a low count is a floor on duplication, not a
certificate of its absence.

    python3 scripts/clone-scan.py            # summary
    python3 scripts/clone-scan.py A B        # line ranges cloned between crates A and B
"""
import collections
import glob
import os
import re
import sys

W = 15
KEYWORDS = set(
    "fn let mut if else match return Ok Err Some None for in while loop use pub struct "
    "enum impl self Self as ref const static mod crate super where true false move async "
    "await unsafe break continue".split()
)


def normalise(line):
    line = line.strip()
    if line.startswith("//"):
        return ""
    line = re.sub(r'"(?:[^"\\]|\\.)*"', "S", line)
    line = re.sub(r"\b\d[\d_.xXa-fA-F]*\b", "N", line)
    line = re.sub(
        r"[A-Za-z_][A-Za-z_0-9]*", lambda m: m.group(0) if m.group(0) in KEYWORDS else "I", line
    )
    return re.sub(r"\s+", " ", line)


def production_files():
    return [
        f
        for f in glob.glob("seance_*/src/**/*.rs", recursive=True)
        if "test" not in os.path.basename(f) and "/tests/" not in f
    ]


def windows():
    seen = collections.defaultdict(list)
    for path in production_files():
        crate = path.split("/")[0]
        kept = [(i + 1, normalise(l)) for i, l in enumerate(open(path, errors="ignore"))]
        kept = [(i, l) for i, l in kept if l]
        for k in range(len(kept) - W):
            block = [l for _, l in kept[k : k + W]]
            if len(set(block)) < 8:  # boilerplate: braces, repeated one-liners
                continue
            seen[hash("\n".join(block))].append((crate, path, kept[k][0]))
    return seen


def summary():
    multi = [locs for locs in windows().values() if len({c for c, _, _ in locs}) >= 2]
    pairs = collections.Counter(tuple(sorted({c for c, _, _ in l})[:3]) for l in multi)
    print(f"{len(multi)} cloned {W}-line windows across crates")
    for crates, n in pairs.most_common(15):
        print(f"{n:5d}  {' + '.join(crates)}")


def between(a, b):
    by_crate = collections.defaultdict(list)
    for locs in windows().values():
        crates = {c for c, _, _ in locs}
        if a in crates and b in crates:
            for c, p, i in locs:
                if c in (a, b):
                    by_crate[p].append(i)
    for path, starts in sorted(by_crate.items()):
        starts.sort()
        runs = []
        for s in starts:
            if runs and s <= runs[-1][1] + 1:
                runs[-1][1] = s
            else:
                runs.append([s, s])
        print(path, ", ".join(f"{s}-{e + W}" for s, e in runs))


if __name__ == "__main__":
    between(sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else summary()
