#!/usr/bin/env bash
#
# Measure the findings layer against one image, and report what it raised.
#
# The nine detections of ROADMAP §2.2 shipped with unit tests and no
# measurement. HUNT-122 is what that cost: one classifier fired 788 times on
# the first real disk it saw, because the fixtures fed it a value shape no
# enumerator produces. A detection layer is a claim about a false-positive
# rate, and a claim nobody measured is not evidence of anything.
#
# So this is the harness VALIDATION.md points at. One image in, one JSON
# summary out: how many leads, from which detection, at which confidence, over
# how large a population — and, separately, what the cross-view pass could not
# ask. It is deliberately a script and not a set of remembered commands,
# because the last run lost a measurement to a second server that silently
# failed to bind while the first held the port, and the run was only caught
# because two images produced byte-identical counts.
#
# Usage:
#   scripts/findings-sweep.sh --image PATH --label NAME [options]
#
#   --image PATH     the evidence to ingest (required)
#   --label NAME     a name for the run, used for the workspace and the output
#   --port N         API port (default: a free one above 8300)
#   --scratch DIR    where the workspace goes (default: $TMPDIR or /tmp)
#   --profile NAME   ingestion profile (default: deep)
#   --out FILE       where the JSON summary goes (default: <scratch>/<label>.json)
#   --workers N      cap ingest concurrency (SEANCE_WORKERS; default: one per core)
#   --memory         declare the source a raw memory capture
#   --keep           leave the workspace behind for inspection
#   --timeout SECS   give up on the ingest after this long (default: 7200)
#
# It cleans up after itself: the server is killed BY RECORDED PID, never by a
# pattern (`pkill -f "port 8123"` matches the shell that issued it, and did),
# and the workspace is removed unless --keep, because a workspace is about the
# size of the image and these images run to 33 GB.
set -uo pipefail

IMAGE=""; LABEL=""; PORT=""; SCRATCH="${TMPDIR:-/tmp}"; PROFILE="deep"
OUT=""; KEEP=0; MEMORY=0; TIMEOUT=7200; WORKERS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --image)   IMAGE="$2"; shift 2 ;;
        --label)   LABEL="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --scratch) SCRATCH="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --workers) WORKERS="$2"; shift 2 ;;
        --memory)  MEMORY=1; shift ;;
        --keep)    KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 2; }
[ -n "$LABEL" ] || { echo "--label is required" >&2; exit 2; }
[ -e "$IMAGE" ] || { echo "no such evidence: $IMAGE" >&2; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SEANCE_BIN:-$ROOT/target/release/seance}"
[ -x "$BIN" ] || { echo "build it first: cargo build --release" >&2; exit 2; }

WS="$SCRATCH/findings-sweep-$LABEL"
LOG="$WS/server.log"
[ -n "$OUT" ] || OUT="$SCRATCH/$LABEL.json"

# A free port, so two lanes of a fan-out never land on the same one. The
# failure this avoids is silent: the second server does not bind, the first
# answers, and the run measures the wrong workspace.
if [ -z "$PORT" ]; then
    for p in $(seq 8300 8399); do
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then PORT="$p"; break; fi
    done
    [ -n "$PORT" ] || { echo "no free port in 8300-8399" >&2; exit 1; }
fi

PID=""
cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
        kill -9 "$PID" 2>/dev/null
    fi
    if [ "$KEEP" -eq 0 ] && [ -n "$WS" ] && [ -d "$WS" ]; then rm -rf "$WS"; fi
}
trap cleanup EXIT INT TERM

rm -rf "$WS"; mkdir -p "$WS"

# The three settings the last run lost twenty minutes to, stated rather than
# rediscovered: auth off (a sweep has no examiner to log in), the evidence
# directory on the allow-list (the policy refuses a path outside it), and a log
# level that does not write a gigabyte.
export SEANCE_AUTH_ENABLED=false
export SEANCE_EVIDENCE_ROOTS="$(cd "$(dirname "$IMAGE")" && pwd)"

# The task queue and the search-index writer spill through the system temp
# directory, and on this host that is a 16 GB tmpfs — RAM, not disk. A 33 GB
# image fills it, the index writer is killed mid-ingest, and the run is
# invalid: the last one lost 3,662 writes that way and the measurement with
# them. So the spill goes beside the workspace, on the same real filesystem
# whose free space the caller can see.
mkdir -p "$WS/tmp"
export TMPDIR="$WS/tmp"

# Ingest concurrency. One worker per core is the default, and on a 33 GB image
# that reached 24.8 GB resident and was OOM-killed on a 30 GB host -- the
# task queue had spilled 124,241 of its 133,385 tasks, so the queue was not
# what held the memory. A sweep must be able to trade wall-clock for headroom,
# and a run that dies is not a measurement.
if [ -n "$WORKERS" ]; then export SEANCE_WORKERS="$WORKERS"; fi

"$BIN" --headless --workspace "$WS" --port "$PORT" -l 2 >"$LOG" 2>&1 &
PID=$!

API="http://127.0.0.1:$PORT/api/v1"
ready=0
for _ in $(seq 1 120); do
    if curl -sf "$API/status" >/dev/null 2>&1; then ready=1; break; fi
    kill -0 "$PID" 2>/dev/null || { echo "server exited during startup; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }
    sleep 1
done
[ "$ready" -eq 1 ] || { echo "server never answered on $PORT; see $LOG" >&2; exit 1; }

CASE=$(curl -sf -X POST "$API/cases" -H 'content-type: application/json' \
    -d "{\"name\":\"findings-sweep $LABEL\",\"examiner_name\":\"scripts/findings-sweep.sh\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') || {
    echo "could not create a case; see $LOG" >&2; exit 1; }

# Prove the server answering is THIS one, by looking for the case just created
# in the workspace THIS one was given. `/status` carries no pid to compare, and
# a check that silently finds nothing to compare is the failure it was written
# to prevent: a stale server holding the port answers every request, the new
# one never binds, and the run measures the wrong workspace. That happened, and
# was caught only because two images produced byte-identical counts.
if ! sqlite3 "$WS/seance.sqlite" \
    "SELECT 1 FROM cases WHERE lower(hex(id)) IS NOT NULL LIMIT 1;" 2>/dev/null | grep -q 1; then
    echo "the case created on port $PORT is not in $WS -- another server holds that port" >&2
    exit 1
fi

DECL=""
[ "$MEMORY" -eq 1 ] && DECL=',"memory_image":true'
INGEST=$(curl -sf -X POST "$API/cases/$CASE/ingest" -H 'content-type: application/json' \
    -d "{\"path\":\"$IMAGE\",\"profile\":\"$PROFILE\"$DECL}") || {
    echo "ingest was refused; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }

STARTED=$(date +%s)
# Wait for the work to BEGIN before believing it has ended. The ingest POST
# returns as soon as the source is accepted, so the first few reads of
# `active_tasks` can all be 0 because nothing has been enqueued yet -- and four
# zeroes in a row would then be read as a finished ingest over an empty case.
# Either a task appears or an artifact does; on an image small enough to finish
# inside the window, the artifact count is what proves it ran.
for _ in $(seq 1 60); do
    a=$(curl -sf "$API/status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("active_tasks",0))' 2>/dev/null || echo 0)
    n=$(sqlite3 "$WS/seance.sqlite" 'SELECT COUNT(*) FROM artifacts;' 2>/dev/null || echo 0)
    if [ "$a" != "0" ] || [ "${n:-0}" -gt 1 ]; then break; fi
    sleep 1
done

# Idle is not the same as finished: the queue empties between stages. Four
# consecutive idle reads, a second apart, is what distinguishes the two.
idle=0
while :; do
    active=$(curl -sf "$API/status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("active_tasks",-1))' 2>/dev/null || echo -1)
    if [ "$active" = "0" ]; then idle=$((idle+1)); else idle=0; fi
    [ "$idle" -ge 4 ] && break
    now=$(date +%s)
    if [ $((now - STARTED)) -gt "$TIMEOUT" ]; then
        echo "ingest did not finish within ${TIMEOUT}s; reporting what it reached" >&2
        break
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "server died mid-ingest; see $LOG" >&2
        # "Died" is three different failures, and an examiner re-running this
        # needs to know which. An OOM kill means retry with fewer --workers;
        # anything else means read the log.
        if command -v journalctl >/dev/null 2>&1 &&
           journalctl -k --since "-1 hour" 2>/dev/null | grep -q "Killed process $PID (seance)"; then
            echo "  the kernel OOM-killed it. Retry with --workers set lower." >&2
        fi
        tail -40 "$LOG" >&2
        exit 1
    fi
    sleep 1
done
ELAPSED=$(( $(date +%s) - STARTED ))

curl -sf "$API/cases/$CASE/findings" >"$WS/findings.json" || echo "{}" >"$WS/findings.json"
curl -sf "$API/cases/$CASE/stats"    >"$WS/stats.json"    || echo "{}" >"$WS/stats.json"

# The API caps its list at 1,000 rows, and a sweep asking "how many did this
# raise" must not be answered by the ceiling. The persisted findings are
# counted in the database, uncapped; the two cross-view detections are not
# persisted at all, and their count comes from the API, which is the only place
# that has it.
DB="$WS/seance.sqlite"
sqlite3 -json "$DB" "
    SELECT json_extract(metadata_json,'\$.finding_kind') AS kind,
           json_extract(metadata_json,'\$.confidence')   AS confidence,
           COUNT(*) AS n
      FROM artifacts
     WHERE json_extract(metadata_json,'\$.type') = 'Finding'
     GROUP BY kind, confidence
     ORDER BY n DESC;" >"$WS/by_kind.json" 2>/dev/null || echo '[]' >"$WS/by_kind.json"
# `FileEntry` is the artifact_type COLUMN; `Finding` is a record kind inside
# metadata_json. Asking metadata for the file entries answered 0 over an image
# holding 26 of them, which is the shape of every false-absence in this
# codebase: the question was well-formed and aimed at the wrong place.
sqlite3 -json "$DB" "
    SELECT (SELECT COUNT(*) FROM artifacts) AS artifacts,
           (SELECT COUNT(*) FROM artifacts WHERE artifact_type = 'FileEntry') AS file_entries,
           (SELECT COUNT(*) FROM artifacts
             WHERE json_extract(metadata_json,'\$.type') = 'Finding') AS findings_persisted;" >"$WS/population.json" 2>/dev/null || echo '[]' >"$WS/population.json"
# The top leads by confidence, so a dominating classifier can be recognised
# without re-running the ingest.
sqlite3 -json "$DB" "
    SELECT json_extract(metadata_json,'\$.finding_kind')          AS kind,
           json_extract(metadata_json,'\$.confidence')            AS confidence,
           json_extract(metadata_json,'\$.name')                  AS title,
           json_extract(metadata_json,'\$.observation')           AS observation,
           json_extract(metadata_json,'\$.subject_artifact_id')   AS subject,
           json_extract(metadata_json,'\$.source_module')         AS module
      FROM artifacts
     WHERE json_extract(metadata_json,'\$.type') = 'Finding'
       AND json_extract(metadata_json,'\$.confidence') IN ('strong','notable')
     LIMIT 120;" >"$WS/top.json" 2>/dev/null || echo '[]' >"$WS/top.json"
sqlite3 -json "$DB" "
    SELECT json_extract(metadata_json,'\$.incomplete_reason') AS reason, COUNT(*) AS n
      FROM artifacts
     WHERE json_extract(metadata_json,'\$.incomplete_reason') IS NOT NULL
     GROUP BY reason ORDER BY n DESC LIMIT 20;" >"$WS/incomplete.json" 2>/dev/null || echo '[]' >"$WS/incomplete.json"

IMAGE="$IMAGE" LABEL="$LABEL" PROFILE="$PROFILE" ELAPSED="$ELAPSED" \
WS="$WS" OUT="$OUT" python3 - <<'PY'
import json, os, sys

WS = os.environ["WS"]

def j(name, default):
    """Read one of the harness's intermediate files.

    Through files, not the environment: a case with a thousand leads made the
    argument list too long, and the run that produced the figures died at the
    step that was meant to write them down."""
    try:
        with open(os.path.join(WS, name + ".json")) as fh:
            return json.load(fh)
    except Exception:
        return default

findings = j("findings", {})
pop = (j("population", []) or [{}])[0]
by_kind = j("by_kind", [])

kinds, conf = {}, {}
for row in by_kind:
    k = row.get("kind") or "(unnamed)"
    kinds[k] = kinds.get(k, 0) + row["n"]
    c = row.get("confidence") or "(ungraded)"
    conf[c] = conf.get(c, 0) + row["n"]

# The two cross-view detections are computed over the whole case at request
# time and are NEVER written to the database, so the SQL above cannot see them.
# Counting only what it sees reported `execution_of_absent_binary` as silent on
# an image where it raised the seventeen leads that answered the case — a false
# absence produced by the measuring instrument, which is the one place this
# project cannot tolerate one. They are counted from the API's own rows and
# kept distinguishable from the persisted ones, because a reader citing a lead
# needs to know whether it is in the case database or was recomputed.
cross = {}
for row in findings.get("findings") or []:
    if row.get("persisted"):
        continue
    k = row.get("finding_kind") or "(unnamed)"
    cross[k] = cross.get(k, 0) + 1
    c = row.get("confidence") or "(ungraded)"
    conf[c] = conf.get(c, 0) + 1
for k, n in cross.items():
    kinds[k] = kinds.get(k, 0) + n

# A detection that raised nothing is a result, not an absence of one, so every
# detection this build carries is named with its count — zero included.
for d in findings.get("detections") or []:
    kinds.setdefault(d["kind"], 0)

# The API lists at most 1,000 rows, so a sweep whose cross-view pass raised
# more than the listing holds must not report the listing as the count.
sweep_total = (findings.get("cross_view") or {}).get("findings", 0)
cross_listed = sum(cross.values())
cross_undercount = sweep_total - cross_listed if sweep_total > cross_listed else 0

summary = {
    "label": os.environ["LABEL"],
    "image": os.environ["IMAGE"],
    "profile": os.environ["PROFILE"],
    "ingest_seconds": int(os.environ["ELAPSED"]),
    "population": pop,
    "leads_persisted": pop.get("findings_persisted", 0),
    "leads_cross_view": (findings.get("cross_view") or {}).get("findings", 0),
    "by_detection": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
    "by_detection_cross_view": cross,
    # Non-zero means the listing truncated before every cross-view lead was
    # seen, so the per-detection split above is a floor and not the count.
    "cross_view_not_listed": cross_undercount,
    "by_confidence": conf,
    "by_detection_and_confidence": by_kind,
    # What the run could NOT assess. A false-positive rate measured over a
    # population that was itself capped is a rate over the part that was read.
    "cross_view": findings.get("cross_view"),
    "absence_note": findings.get("absence_note"),
    "incomplete_reasons": j("incomplete", []),
    "stats": j("stats", {}),
    "notable_and_strong": j("top", []),
}
with open(os.environ["OUT"], "w") as fh:
    json.dump(summary, fh, indent=2)

n = summary["leads_persisted"] + summary["leads_cross_view"]
print(f'{summary["label"]}: {n} leads over {pop.get("file_entries", "?")} file entries '
      f'({pop.get("artifacts", "?")} artifacts, {summary["ingest_seconds"]}s)')
for k, v in list(summary["by_detection"].items()):
    if v:
        where = " (recomputed, not persisted)" if k in cross else ""
        print(f'  {v:>6}  {k}{where}')
zero = [k for k, v in summary["by_detection"].items() if not v]
if zero:
    print(f'  silent: {", ".join(sorted(zero))}')
if cross_undercount:
    print(f'  NOT LISTED: {cross_undercount} further cross-view lead(s) past the listing cap')
print(f'  -> {os.environ["OUT"]}')
PY
rc=$?
exit $rc
