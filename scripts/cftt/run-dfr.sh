#!/usr/bin/env bash
# Run NIST CFTT's Deleted File Recovery methodology against Séance.
#
# ROADMAP §5.2. This ingests NIST's DFR test images one at a time, exports
# what the tool reports for each (every file entry: name, path, size, whether
# it is deleted, whether content was produced, and the image-absolute sectors
# that content came from), and grades the lot with `cftt-grade --dfr` against
# the truth parsed from NIST's own layout document.
#
#   scripts/cftt/run-dfr.sh --corpus ~/forensic_corpora/nist_dfr --out /tmp/cftt-dfr \
#       [--images dfr-01-ext.dd,dfr-01-fat.dd]  [--classes rules.json]
#
# Options:
#   --corpus DIR    holds setup-july-10-2012.pdf and dd/*.dd (decompressed)
#   --out DIR       where to put the workspace, the results and the report
#   --images LIST   comma-separated image file names (default: every dd/*.dd)
#   --classes FILE  non-conformance classifications for cftt-grade --classes
#   --port N        API port (default: 8232)
#   --timeout SECS  give up on one image's ingest after this long (default: 3600)
#   CFTT_GRADE=path a built cftt-grade to use instead of `cargo run --release`
#   KEEP_WS=1       keep each image's workspace (deleted by default: 90 of them do not fit)
#
# WHAT THIS RUN CAN AND CANNOT SAY:
#
#  1. Running a published methodology is NOT third-party validation. NIST has
#     not tested this tool.
#  2. The truth is NIST's layout document, and NIST elides rows from it
#     (`<N> omitted`, `. . . + N more`): 8,979 of the 10,085 deleted files it
#     declares are in elided rows. Those are counted and graded not assessed.
#  3. Sectors come from each file entry's `data_runs` (volume-relative bytes)
#     plus its file system's `offset_bytes`. Where either is missing the
#     entry's sectors are reported as unknown, and CR-03/CR-04 are not
#     assessed for it -- never passed.
#  4. An ingest the script did not see settle is recorded
#     `ingest_complete: false`, and every assertion on that image is then
#     graded not assessed: an idle queue between stages is not a committed
#     case.
set -euo pipefail

CORPUS=""; OUT=""; IMAGES=""; CLASSES=""; PORT=8232; TIMEOUT=3600
while [ $# -gt 0 ]; do
    case "$1" in
        --corpus)  CORPUS="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --images)  IMAGES="$2"; shift 2 ;;
        --classes) CLASSES="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[ -n "$CORPUS" ] && [ -n "$OUT" ] || { sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

LAYOUT_PDF="$CORPUS/setup-july-10-2012.pdf"
[ -s "$LAYOUT_PDF" ] || { echo "missing: $LAYOUT_PDF" >&2; exit 3; }
command -v pdftotext >/dev/null || { echo "pdftotext (poppler-utils) is required" >&2; exit 3; }
if [ -z "$IMAGES" ]; then
    IMAGES=$(cd "$CORPUS/dd" && ls ./*.dd | sed 's#^\./##' | paste -sd, -)
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${SEANCE_BIN:-$ROOT/target/release/seance}"
[ -x "$BIN" ] || { echo "build it first: cargo build --release -p seance_cli" >&2; exit 3; }

rm -rf "$OUT"; mkdir -p "$OUT/per-image"
pdftotext -layout "$LAYOUT_PDF" "$OUT/layout.txt"
sha256sum "$BIN" > "$OUT/binary.sha256"

# Auth off, the evidence directory on the allow-list, the spill on a real
# filesystem: the same three settings run-string-search.sh records.
export SEANCE_AUTH_ENABLED=false
export SEANCE_EVIDENCE_ROOTS="$(cd "$CORPUS/dd" && pwd)"

API="http://127.0.0.1:$PORT/api/v1"
PID=""
cleanup() { [ -n "$PID" ] && { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }; PID=""; }
trap cleanup EXIT

# ONE SERVER AND ONE WORKSPACE PER IMAGE. The first sweep shared one server
# across images: an image that had not settled kept writing while the next
# case was created, the case insert failed with "database is locked", and the
# run died. Each image now starts clean, so nothing one image does can reach
# the next image's result.
start_server() {
    WS="$OUT/ws/$1"; LOG="$OUT/logs/$1.server.log"
    mkdir -p "$WS/tmp" "$OUT/logs"
    TMPDIR="$WS/tmp" "$BIN" --headless --workspace "$WS" --port "$PORT" -l 2 >"$LOG" 2>&1 &
    PID=$!
    for _ in $(seq 1 120); do
        curl -sf "$API/status" >/dev/null 2>&1 && return 0
        kill -0 "$PID" 2>/dev/null || { echo "server exited during startup; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }
        sleep 1
    done
    echo "server never answered on $PORT; see $LOG" >&2; exit 1
}

active_tasks() {
    curl -sf "$API/status" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("active_tasks",-1))' 2>/dev/null || echo -1
}
case_artifacts() {
    python3 - "$WS/seance.sqlite" "$1" <<'PY' 2>/dev/null || echo -1
import sqlite3, sys, uuid
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(db.execute("SELECT COUNT(*) FROM artifacts WHERE case_id = ?", (uuid.UUID(sys.argv[2]).bytes,)).fetchone()[0])
PY
}

IFS=',' read -r -a LIST <<< "$IMAGES"
for IMG in "${LIST[@]}"; do
    IMAGE="$CORPUS/dd/$IMG"
    [ -s "$IMAGE" ] || { echo "missing: $IMAGE" >&2; exit 3; }
    start_server "$IMG"
    CASE=$(curl -sf -X POST "$API/cases" -H 'content-type: application/json' \
        -d "{\"name\":\"CFTT DFR $IMG\",\"examiner_name\":\"scripts/cftt/run-dfr.sh\"}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    echo "$IMG: case $CASE"
    curl -sf -X POST "$API/cases/$CASE/ingest" -H 'content-type: application/json' \
        -d "{\"path\":\"$IMAGE\",\"profile\":\"deep\"}" >/dev/null || {
        echo "ingest of $IMG was refused; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }

    STARTED=$(date +%s); COMPLETE=true
    # Wait for the work to begin before believing it has ended.
    for _ in $(seq 1 60); do
        a=$(active_tasks); n=$(case_artifacts "$CASE")
        { [ "$a" != "0" ] || [ "${n:-0}" -gt 1 ]; } && break
        sleep 1
    done
    # Idle is not finished: four idle reads in a row, AND the case's artifact
    # count unchanged across five reads, before the case is read.
    idle=0; stable=0; last=-2
    while :; do
        a=$(active_tasks); n=$(case_artifacts "$CASE")
        if [ "$a" = "0" ]; then idle=$((idle+1)); else idle=0; fi
        if [ "$n" = "$last" ]; then stable=$((stable+1)); else stable=0; fi
        last="$n"
        { [ "$idle" -ge 4 ] && [ "$stable" -ge 5 ]; } && break
        if [ $(( $(date +%s) - STARTED )) -gt "$TIMEOUT" ]; then
            echo "  INGEST DID NOT SETTLE within ${TIMEOUT}s; graded not assessed" >&2
            COMPLETE=false; break
        fi
        if ! kill -0 "$PID" 2>/dev/null; then
            # Recorded, not fatal: the image is graded not assessed and the
            # sweep goes on, so one image cannot silence the other 89.
            echo "  SERVER DIED MID-INGEST; graded not assessed; see $LOG" >&2
            COMPLETE=false; break
        fi
        sleep 2
    done
    echo "  settled after $(( $(date +%s) - STARTED ))s with $last artifact(s)"

    python3 - "$WS/seance.sqlite" "$CASE" "$IMG" "$COMPLETE" "$OUT/per-image/$IMG.json" <<'PY'
import json, sqlite3, sys, uuid
db_path, case, img, complete, out = sys.argv[1:6]
db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
rows = db.execute(
    "SELECT id, parent_id, artifact_type, metadata_json FROM artifacts WHERE case_id = ?",
    (uuid.UUID(case).bytes,),
).fetchall()
by_id = {r[0]: r for r in rows}

def fs_offset(row):
    """The byte offset of the file system an entry belongs to, by walking its
    parents to the FileSystem artifact. None when the walk does not reach one."""
    seen = 0
    while row is not None and seen < 10000:
        if row[2] == "FileSystem":
            return json.loads(row[3]).get("offset_bytes")
        row = by_id.get(row[1])
        seen += 1
    return None

entries = []
for r in rows:
    if r[2] != "FileEntry":
        continue
    md = json.loads(r[3])
    if md.get("is_directory"):
        continue
    off = fs_offset(r)
    runs = md.get("data_runs")
    sectors = None
    if off is not None and isinstance(runs, list) and runs:
        acc = []
        for run in runs:
            if not isinstance(run, list) or len(run) < 2 or run[0] is None or not run[1]:
                acc = None
                break
            start = off + int(run[0])
            acc.append([start // 512, (start + int(run[1]) - 1) // 512])
        sectors = acc
    has_content = bool(md.get("size")) and (bool(runs) or bool(md.get("resident_data_b64")))
    entries.append({
        "name": md.get("name") or "",
        "path": md.get("path") or "",
        "size": md.get("size"),
        "deleted": bool(md.get("deleted")),
        "has_content": has_content,
        "sectors": sectors,
        # The inode (ext) or MFT record the tool read this entry from, when it
        # says: scripts/cftt/dfr-evidence.py checks it with istat. Not graded.
        "inode": md.get("inode", md.get("record_number")),
    })
json.dump({"image": img, "ingest_complete": complete == "true", "entries": entries},
          open(out, "w"), ensure_ascii=False)
print(f"  {len(entries)} file entries, {sum(e['deleted'] for e in entries)} deleted", file=sys.stderr)
PY
    cleanup
    # The per-image JSON and the server log are the record; KEEP_WS=1 keeps
    # the workspace too, for looking at a result's records afterwards.
    [ "${KEEP_WS:-0}" = "1" ] || rm -rf "$WS"
done

python3 - "$OUT/per-image" "$OUT/results.json" <<'PY'
import json, os, sys
d = sys.argv[1]
json.dump([json.load(open(os.path.join(d, f))) for f in sorted(os.listdir(d))],
          open(sys.argv[2], "w"), ensure_ascii=False)
PY

echo
echo "grading"
CLASS_ARGS=()
[ -n "$CLASSES" ] && CLASS_ARGS=(--classes "$CLASSES")
if [ -n "${CFTT_GRADE:-}" ]; then
    "$CFTT_GRADE" --dfr --layout "$OUT/layout.txt" --results "$OUT/results.json" \
        --out "$OUT/report" "${CLASS_ARGS[@]}"
else
    cargo run -q --release -p seance_validate --bin cftt-grade -- --dfr --layout "$OUT/layout.txt" \
        --results "$OUT/results.json" --out "$OUT/report" "${CLASS_ARGS[@]}"
fi
