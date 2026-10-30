#!/usr/bin/env bash
# Run NIST CFTT's Forensic String Search methodology against Séance.
#
# ROADMAP §5.2. This ingests one of the data set's images, issues one search per
# distinct target term, and writes the results where `cftt-grade` can grade them
# against the published answer key.
#
#   scripts/cftt/run-string-search.sh \
#       --corpus ~/forensic_corpora/cftt_string_search \
#       --out    /tmp/cftt-ss
#
# Options:
#   --corpus DIR   the fetched data set (scripts/cftt/fetch.sh string-search)
#   --out DIR      where to put the workspace, the results and the report
#   --image win|unix   which of the two images (default: win)
#   --port N       API port (default: 8231)
#   --workers N    cap ingest concurrency (SEANCE_WORKERS)
#   --timeout SECS give up on the ingest after this long (default: 14400)
#
# WHAT THIS RUN CAN AND CANNOT SAY. Three things, up front, because a number
# from this script is quotable and must not be quoted for more than it is:
#
#  1. Running a published methodology is NOT third-party validation. NIST has
#     not tested this tool. `documentation/VALIDATION.md` carries the
#     determination. No document may claim more.
#  2. The expectations are verified against the publisher and THE QUESTIONS ARE
#     NOT: the answer key gives the expected hit identifiers and never the
#     query. Every search term here comes from the data set's
#     `string-search-test-cases.html`, which fails all three of the publisher's
#     hash algorithms.
#  3. Of the key's 921 expectations, 134 are not applicable to this tool
#     (unallocated space) and 77 cannot be compared (they state a position and
#     name no file: `UNKNOWN`). One more, row 7010, is contradicted by the
#     image's own bytes and is graded not assessed as a fault in the key. Of
#     the 709 that remain, 60 are expected to fail for `SEARCH-002`: the
#     realistic ceiling is 649. That is measured and recorded BEFORE the run
#     (seance_validate's `the_frag_unknown_rows_return_with_key_files`), so a
#     result cannot be read against a denominator chosen after it.
#  4. The key's file names are checked against the image with The Sleuth Kit
#     (`scripts/cftt/resolve-key-files.py`: mmls, fsstat, ifind, ffind) --
#     an independent reference tool, not Séance. On the Windows image
#     fourteen rows name a file that is not at their offset (twelve
#     LOUDBIRD/WADI aliases and two FRAG-UNKNOWN); those are graded against
#     the file Sleuth Kit places there, each says so, and the count is
#     printed beside the headline (VAL-002, owner decision 2026-09-26). Each
#     offset is put in its file system's own data unit (FAT/exFAT sector,
#     NTFS cluster, Ext4/HFS+ block). On the unix image 356 of 926 named rows
#     resolve (six LOUDBIRD/WADI aliases); the 342 DELETED rows on Ext4/HFS+
#     cannot be placed by `ifind`, and the 228 on the partition `fsstat` does
#     not recognise are recorded "could not look" -- all fall back to the
#     key's names with no recovery attribution. Without Sleuth Kit installed,
#     or when no row resolves, this step says the key was NOT checked.
set -euo pipefail

CORPUS=""; OUT=""; WHICH="win"; PORT=8231; WORKERS=""; TIMEOUT=14400
while [ $# -gt 0 ]; do
    case "$1" in
        --corpus)  CORPUS="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --image)   WHICH="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --workers) WORKERS="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[ -n "$CORPUS" ] && [ -n "$OUT" ] || { sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

SET="$CORPUS/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019"
case "$WHICH" in
    win)  IMAGE="$SET/copy-to-test-computer/ss-win-07-25-18.dd"; KEY="$SET/win_string_doc.txt" ;;
    unix) IMAGE="$SET/copy-to-test-computer/ss-unix-07-25-18.dd"; KEY="$SET/unix_string_doc.txt" ;;
    *) echo "--image must be win or unix" >&2; exit 2 ;;
esac
for f in "$IMAGE" "$KEY"; do
    [ -s "$f" ] || { echo "missing: $f -- run scripts/cftt/fetch.sh string-search first" >&2; exit 3; }
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/target/release/seance"
[ -x "$BIN" ] || { echo "build it first: cargo build --release -p seance_cli" >&2; exit 3; }

WS="$OUT/ws"; LOG="$OUT/server.log"
rm -rf "$OUT"; mkdir -p "$WS" "$WS/tmp"

# The same three settings `scripts/findings-sweep.sh` records, for the same
# reasons: auth off (a run has no examiner to log in), the evidence directory on
# the allow-list, and the spill on a real filesystem rather than the system
# tmpfs -- a previous sweep was invalidated when the index writer was killed
# mid-ingest by a full 16 GB tmpfs.
export SEANCE_AUTH_ENABLED=false
export SEANCE_EVIDENCE_ROOTS="$(cd "$(dirname "$IMAGE")" && pwd)"
export TMPDIR="$WS/tmp"
[ -n "$WORKERS" ] && export SEANCE_WORKERS="$WORKERS"

"$BIN" --headless --workspace "$WS" --port "$PORT" -l 2 >"$LOG" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap cleanup EXIT

API="http://127.0.0.1:$PORT/api/v1"
ready=0
for _ in $(seq 1 120); do
    curl -sf "$API/status" >/dev/null 2>&1 && { ready=1; break; }
    kill -0 "$PID" 2>/dev/null || { echo "server exited during startup; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }
    sleep 1
done
[ "$ready" -eq 1 ] || { echo "server never answered on $PORT; see $LOG" >&2; exit 1; }

CASE=$(curl -sf -X POST "$API/cases" -H 'content-type: application/json' \
    -d "{\"name\":\"CFTT string search ($WHICH)\",\"examiner_name\":\"scripts/cftt/run-string-search.sh\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "case $CASE"

echo "ingesting $IMAGE ($(stat -c %s "$IMAGE") bytes)"
curl -sf -X POST "$API/cases/$CASE/ingest" -H 'content-type: application/json' \
    -d "{\"path\":\"$IMAGE\",\"profile\":\"deep\"}" >/dev/null || {
    echo "ingest was refused; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }

STARTED=$(date +%s)
# Wait for the work to BEGIN before believing it has ended: the POST returns as
# soon as the source is accepted, so early zeroes are an empty queue and not a
# finished ingest.
for _ in $(seq 1 60); do
    a=$(curl -sf "$API/status" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("active_tasks",0))' 2>/dev/null || echo 0)
    n=$(sqlite3 "$WS/seance.sqlite" 'SELECT COUNT(*) FROM artifacts;' 2>/dev/null || echo 0)
    { [ "$a" != "0" ] || [ "${n:-0}" -gt 1 ]; } && break
    sleep 1
done
# Idle is not finished: the queue empties between stages, so four consecutive
# idle reads a second apart is what distinguishes them.
idle=0
while :; do
    active=$(curl -sf "$API/status" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("active_tasks",-1))' 2>/dev/null || echo -1)
    if [ "$active" = "0" ]; then idle=$((idle+1)); else idle=0; fi
    [ "$idle" -ge 4 ] && break
    if [ $(( $(date +%s) - STARTED )) -gt "$TIMEOUT" ]; then
        echo "INGEST DID NOT FINISH within ${TIMEOUT}s. Every search below runs over a PARTIAL" >&2
        echo "case, so a term not found may simply not have been indexed yet. The report says so." >&2
        echo "partial" > "$OUT/ingest-incomplete"
        break
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "server died mid-ingest; see $LOG" >&2
        if command -v journalctl >/dev/null 2>&1 &&
           journalctl -k --since "-1 hour" 2>/dev/null | grep -q "Killed process $PID"; then
            echo "  the kernel OOM-killed it -- BUGS.md HUNT-125. Retry with --workers lower." >&2
        fi
        tail -40 "$LOG" >&2
        exit 1
    fi
    sleep 2
done
ELAPSED=$(( $(date +%s) - STARTED ))
echo "the task queue settled after ${ELAPSED}s"

# AN IDLE TASK QUEUE IS NOT A COMMITTED INDEX. The search index commits
# asynchronously, so the queue can be empty while documents are still becoming
# visible to a reader -- and a search run then is a floor, not a measurement.
#
# Measured on the first run of this script: the task queue went idle after 10s,
# every search reported 8,134 documents examined, and the case held 11,390
# artifacts when the run finished. The 448 hits it graded were therefore a
# floor and the report could not say so.
#
# So the index's own visible size is polled directly -- `examined_documents` on
# any search response is how many documents the reader walked -- and the run
# waits for it to stop growing before asking a single question.
echo "waiting for the index to stop growing"
STABLE=0; LAST=-1
for _ in $(seq 1 600); do
    SEEN=$(curl -sf "$API/cases/$CASE/search?q=seance_index_probe_term&limit=1" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("examined_documents",-1))' 2>/dev/null || echo -1)
    ARTS=$(sqlite3 "$WS/seance.sqlite" 'SELECT COUNT(*) FROM artifacts;' 2>/dev/null || echo -1)
    if [ "$SEEN" = "$LAST" ]; then STABLE=$((STABLE+1)); else STABLE=0; fi
    LAST="$SEEN"
    [ "$STABLE" -ge 5 ] && break
    sleep 2
done
echo "the index reader sees $LAST document(s); the case holds $ARTS artifact(s)"
if [ "$STABLE" -lt 5 ]; then
    echo "THE INDEX WAS STILL GROWING when the wait gave up. Every count below is a FLOOR." >&2
    echo "partial-index" > "$OUT/ingest-incomplete"
fi

# One search per DISTINCT term. The term is field 2 of the key and is taken
# RAW: 35 rows carry a leading or trailing space that is part of what the
# publisher asks to be searched for, and trimming finds different hits.
python3 - "$KEY" "$OUT/terms.json" <<'PY'
import json, sys
terms = []
seen = set()
with open(sys.argv[1], encoding='utf-8') as fh:
    for line in fh:
        line = line.rstrip('\n')
        if not line:
            continue
        # The id from the left and the last five fields from the right, so a
        # term containing a colon survives -- the same rule the Rust parser uses.
        head, _, rest = line.partition(':')
        parts = rest.rsplit(':', 5)
        if len(parts) < 6:
            continue
        term = parts[0]
        if term and term not in seen:
            seen.add(term)
            terms.append(term)
json.dump(terms, open(sys.argv[2], 'w'), ensure_ascii=False)
print(f"{len(terms)} distinct terms", file=sys.stderr)
PY

python3 - "$OUT/terms.json" "$API/cases/$CASE" "$OUT/results.json" <<'PY'
import json, subprocess, sys, urllib.parse
terms = json.load(open(sys.argv[1]))
base, out = sys.argv[2], sys.argv[3]
results = {}
for i, term in enumerate(terms, 1):
    q = urllib.parse.quote(term, safe='')
    url = f"{base}/search?q={q}&limit=1000&offset=0"
    try:
        raw = subprocess.run(['curl', '-sf', url], capture_output=True, timeout=180).stdout
        body = json.loads(raw)
    except Exception as e:
        # A failed search is NOT an empty result: recorded as incomplete so the
        # grader reports it unassessed rather than as a miss.
        results[term] = {"artifact_names": [], "offsets": [],
                         "search_incomplete": f"the search request failed: {e}"}
        continue
    incomplete = None
    if body.get("index_incomplete"):
        incomplete = "the index reported index_incomplete for this query"
    elif body.get("truncated"):
        incomplete = "the result set was truncated at the API's page cap"
    results[term] = {
        "artifact_names": [r.get("name") or "" for r in body.get("results", [])],
        "offsets": [],
        "search_incomplete": incomplete,
    }
    if i % 10 == 0:
        print(f"  {i}/{len(terms)}", file=sys.stderr)
json.dump(results, open(out, 'w'), ensure_ascii=False, indent=1)
print(f"wrote {out}", file=sys.stderr)
PY

# The files the tool recovered, so a miss can be attributed to the right half
# of it: a term missing from a file that was never recovered is a
# FILE-RECOVERY finding, not a search one, and reporting both as "not found"
# sends an examiner to the wrong place. The inventory is compared against the
# file Sleuth Kit places at each row's offset (below), NOT the key's name: the
# first real run (2026-09-15) compared names and blamed recovery for fifteen
# rows whose files are all on the image (VAL-002).
sqlite3 "$WS/seance.sqlite" \
    "SELECT name FROM artifacts WHERE artifact_type='FileEntry' AND name IS NOT NULL;" \
    | python3 -c 'import json,sys; json.dump([l.rstrip("\n") for l in sys.stdin if l.strip()], sys.stdout, ensure_ascii=False)' \
    > "$OUT/inventory.json"
echo "the case holds $(python3 -c "import json;print(len(json.load(open('$OUT/inventory.json'))))") recovered file(s)"

# The file at each row's offset, from The Sleuth Kit. Exit 3 is "not
# installed" and exit 4 "no row resolved"; either is reported and leaves the
# grader withholding attribution.
KEYFILES=()
if python3 "$ROOT/scripts/cftt/resolve-key-files.py" "$IMAGE" "$KEY" "$OUT/key-files.json"; then
    KEYFILES=(--key-files "$OUT/key-files.json")
else
    echo "the key's file names were NOT checked against the image; no miss will be attributed" >&2
    echo "to file recovery, and rows whose named file is an alias stay graded on that name." >&2
fi

# The published case table (Expected Results by ID), so each graded row says
# which FT-SS case it is evidence for and the report carries a per-case table.
CASES=()
CASES_DOC="$SET/Expected Results by ID v1.1 9-27-19.docx"
if [ -f "$CASES_DOC" ]; then
    CASES=(--cases "$CASES_DOC" --cases-set "$WHICH")
else
    echo "the case table ($CASES_DOC) is not present; rows will not name their FT-SS case" >&2
fi

echo
echo "grading"
INCOMPLETE=""
[ -f "$OUT/ingest-incomplete" ] && INCOMPLETE="--ingest-incomplete"
cargo run -q --release -p seance_validate --bin cftt-grade -- \
    --key "$KEY" --results "$OUT/results.json" --inventory "$OUT/inventory.json" \
    --image "$IMAGE" "${KEYFILES[@]}" "${CASES[@]}" \
    --out "$OUT/report" $INCOMPLETE
