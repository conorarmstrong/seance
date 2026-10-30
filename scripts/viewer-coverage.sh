#!/usr/bin/env bash
# Report which record types the backend emits that have no tailored viewer.
#
# A record type an examiner needs, reaching a generic key/value table, is a
# usability defect even when nothing false is shown: a USN reason bitmask or an
# NTFS LSN cannot be grouped, sorted or read as raw JSON. The Analysis index
# already badges such a type "generic view", so the operator can see it — this
# makes the same gap visible to the developer, and countable over time.
#
# Status/disclosure records (*ParseStatus, *Incomplete, *Summary, ...) are
# excluded: they are markers attached to their parent record's disclosure, not
# evidence anyone browses as a table.
#
#   scripts/viewer-coverage.sh            # summary + the gap
#   scripts/viewer-coverage.sh --count    # just the gap size (for a trend)
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "${1:-}" <<'PY'
import re, subprocess, sys

emitted = set()
out = subprocess.run(
    ["grep", "-rhoE", r'"type"\s*:\s*"[A-Za-z0-9_]+"', "--include=*.rs",
     "seance_api", "seance_core", "seance_memory"]
    + [d for d in __import__("glob").glob("seance_plugin_*")],
    capture_output=True, text=True).stdout
for line in out.splitlines():
    m = re.search(r'"type"\s*:\s*"([A-Za-z0-9_]+)"', line)
    if m:
        emitted.add(m.group(1))

src = open("frontend/src/pages/analysis/viewers.tsx").read()
body = src[src.index("export const VIEWERS"):]
viewers = {m.group(1) for m in re.finditer(r'^  ([A-Za-z_][A-Za-z0-9_]*):\s*\{', body, re.M)}

def is_status(t: str) -> bool:
    return any(k in t for k in
               ("ParseStatus", "Status", "Incomplete", "Summary",
                "Warning", "Coverage", "Error", "Truncated", "Skipped",
                "Failure", "NotScanned", "PartialScan"))

# Serde enum variants and test-only strings that are not record types.
NOISE = {"not", "other", "simple", "string", "test", "raw", "compound",
         "SomethingElse", "Doc", "crypt", "plist"}

# Types whose evidence is presented by a PURPOSE-BUILT PAGE rather than by a
# row viewer in the Analysis index. These are not gaps: sending an examiner to
# a generic table for a process tree would be worse, not better. Listed
# explicitly so the exclusion is arguable rather than silent.
DEDICATED_PAGE = {
    # /memory/* — image profile, process tree, network, handles, system,
    # credentials, findings, cross-view.
    "MemoryImage", "MemoryProfile", "MemoryProcess", "MemoryProcessList",
    "MemoryProcessHandles", "MemoryProcessModules", "MemoryProcessVads",
    "MemoryNetwork", "MemoryCredential", "MemoryCrossView",
    "MemoryRecoveredFile", "MemoryGpu",
    # /files/:sourceId grid and the evidence tree.
    "FileEntry", "IndexAllocation",
    # /duplicates and /gallery (near-duplicate grouping, thumbnails).
    "PerceptualHash",
    # /geo
    "browser_location",
}

rest = {t for t in emitted - viewers if not is_status(t) and t not in NOISE}
paged = sorted(rest & DEDICATED_PAGE)
gap = sorted(rest - DEDICATED_PAGE)

if sys.argv[1] == "--count":
    print(len(gap)); sys.exit(0)

print(f"emitted record types      : {len(emitted)}")
print(f"tailored viewers          : {len(viewers)}")
print(f"served by dedicated pages : {len(paged)}")
print(f"UNTAILORED (generic view) : {len(gap)}\n")
for t in gap:
    print(" ", t)
PY
