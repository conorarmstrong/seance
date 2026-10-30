#!/usr/bin/env bash
# Run NIST CFTT's Mobile Device Data population against Séance (HTC Desire S).
#
# ROADMAP §5.2 / VALIDATION.md "CFTT-MDT-1". Ingests the JTAG image, exports
# every Contact record, takes the image's SHA-256 and stat before and after the
# whole run, and grades with `cftt-grade --mdt` against the expectation file
# scripts/cftt/mdt-extract-key.sh wrote.
#
#   scripts/cftt/run-mobile.sh --corpus ~/forensic_corpora/cftt_mobile --out /tmp/cftt-mdt \
#       [--profile triage|deep]
#
# Options:
#   --corpus DIR    holds HTC_Desire_S_JTAG.bin
#   --out DIR       workspace, results and report
#   --profile P     ingestion profile (default: triage)
#   --key FILE      expectations (default: the committed fixture)
#   --port N        API port (default: 8233)
#   --timeout SECS  give up on the ingest after this long (default: 3600)
#   SEANCE_BIN      the release binary (default: target/release/seance). It must
#                   be built from the commit being recorded.
#   CFTT_GRADE      a built cftt-grade, else `cargo run --release`
#   KEEP_WS=1       keep the workspace
#
# WHAT THIS RUN CAN AND CANNOT SAY:
#  1. Not third-party validation. NIST has not tested this tool.
#  2. NIST's population PDF is a template. Expectations are the handset's own
#     stored values (TSK icat + sqlite3), compared with the PDF row by row.
#  3. Only MDT-CA-02, CA-11, CA-12 and CA-13 are graded (owner decision
#     2026-10-03). Everything else is stated not assessed or not applicable.
#  4. An ingest the script did not see settle is recorded `ingest_complete:
#     false` and nothing is then graded from it.
set -euo pipefail

CORPUS=""; OUT=""; PROFILE="triage"; PORT=8233; TIMEOUT=3600; KEY=""
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
while [ $# -gt 0 ]; do
    case "$1" in
        --corpus)  CORPUS="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --key)     KEY="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[ -n "$CORPUS" ] && [ -n "$OUT" ] || { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
KEY="${KEY:-$ROOT/seance_validate/tests/fixtures/cftt_mdt/htc_desire_s_contacts.json}"
IMAGE="$CORPUS/HTC_Desire_S_JTAG.bin"
[ -s "$IMAGE" ] || { echo "missing: $IMAGE" >&2; exit 3; }
BIN="${SEANCE_BIN:-$ROOT/target/release/seance}"
[ -x "$BIN" ] || { echo "build it first: cargo build --release -p seance_cli" >&2; exit 3; }

rm -rf "$OUT"; mkdir -p "$OUT"
sha256sum "$BIN" > "$OUT/binary.sha256"
git -C "$ROOT" rev-parse HEAD > "$OUT/commit.txt"

SHA_BEFORE=$(sha256sum "$IMAGE" | cut -d' ' -f1)
STAT_BEFORE=$(stat -c '%s %Y' "$IMAGE")

export SEANCE_AUTH_ENABLED=false
export SEANCE_EVIDENCE_ROOTS="$(cd "$CORPUS" && pwd)"
export SEANCE_WORKERS=2

API="http://127.0.0.1:$PORT/api/v1"
PID=""; PEAK_KB=0
note_rss() {
    [ -n "$PID" ] && [ -r "/proc/$PID/status" ] || return 0
    local v; v=$(awk '/^VmHWM:/{print $2}' "/proc/$PID/status" 2>/dev/null || true)
    [ -n "$v" ] && [ "$v" -gt "$PEAK_KB" ] && PEAK_KB=$v
    return 0
}
cleanup() { [ -n "$PID" ] && { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }; PID=""; }
trap cleanup EXIT

WS="$OUT/ws"; LOG="$OUT/server.log"
mkdir -p "$WS/tmp"
TMPDIR="$WS/tmp" "$BIN" --headless --workspace "$WS" --port "$PORT" -l 2 >"$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 120); do
    curl -sf "$API/status" >/dev/null 2>&1 && break
    kill -0 "$PID" 2>/dev/null || { echo "server exited during startup; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }
    sleep 1
done

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

CASE=$(curl -sf -X POST "$API/cases" -H 'content-type: application/json' \
    -d '{"name":"CFTT MDT HTC Desire S","examiner_name":"scripts/cftt/run-mobile.sh"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "case $CASE, profile $PROFILE"
STARTED=$(date +%s)
curl -sf -X POST "$API/cases/$CASE/ingest" -H 'content-type: application/json' \
    -d "{\"path\":\"$IMAGE\",\"profile\":\"$PROFILE\"}" >/dev/null || {
    echo "ingest was refused; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }

COMPLETE=true
for _ in $(seq 1 60); do
    a=$(active_tasks); n=$(case_artifacts "$CASE")
    { [ "$a" != "0" ] || [ "${n:-0}" -gt 1 ]; } && break
    sleep 1
done
idle=0; stable=0; last=-2
while :; do
    a=$(active_tasks); n=$(case_artifacts "$CASE"); note_rss
    if [ "$a" = "0" ]; then idle=$((idle+1)); else idle=0; fi
    if [ "$n" = "$last" ]; then stable=$((stable+1)); else stable=0; fi
    last="$n"
    { [ "$idle" -ge 4 ] && [ "$stable" -ge 5 ]; } && break
    if [ $(( $(date +%s) - STARTED )) -gt "$TIMEOUT" ]; then
        echo "INGEST DID NOT SETTLE within ${TIMEOUT}s; nothing will be graded" >&2
        COMPLETE=false; break
    fi
    kill -0 "$PID" 2>/dev/null || { echo "SERVER DIED MID-INGEST; see $LOG" >&2; COMPLETE=false; break; }
    sleep 2
done
WALL=$(( $(date +%s) - STARTED ))
echo "settled after ${WALL}s with $last artifact(s); peak RSS ${PEAK_KB} kB"
printf '{"profile":"%s","wall_seconds":%s,"peak_rss_kb":%s,"artifacts":%s,"ingest_complete":%s}\n' \
    "$PROFILE" "$WALL" "$PEAK_KB" "$last" "$COMPLETE" > "$OUT/run-stats.json"

python3 -I - "$WS/seance.sqlite" "$CASE" "$COMPLETE" "$OUT/results.json" <<'PY'
import json, sqlite3, sys, uuid
db_path, case, complete, out = sys.argv[1:5]
db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
contacts = []
for (md,) in db.execute(
        "SELECT metadata_json FROM artifacts WHERE case_id = ?", (uuid.UUID(case).bytes,)):
    m = json.loads(md)
    if m.get("type") == "Contact" and m.get("subtype") == "contact":
        contacts.append({
            "rowid": m.get("rowid"),
            "display_name": m.get("display_name") or "",
            "phone_numbers": m.get("phone_numbers") or [],
            "emails": m.get("emails") or [],
            "deleted": m.get("deleted"),
        })
contacts.sort(key=lambda c: (c["rowid"] is None, c["rowid"]))
json.dump({"image": "HTC_Desire_S_JTAG.bin", "ingest_complete": complete == "true",
           "contacts": contacts}, open(out, "w"), ensure_ascii=False, indent=1)
print(f"{len(contacts)} Contact records exported", file=sys.stderr)
PY
cleanup

SHA_AFTER=$(sha256sum "$IMAGE" | cut -d' ' -f1)
STAT_AFTER=$(stat -c '%s %Y' "$IMAGE")
[ "${KEEP_WS:-0}" = "1" ] || rm -rf "$WS"

echo "grading"
ARGS=(--mdt --key "$KEY" --results "$OUT/results.json"
      --image-sha-before "$SHA_BEFORE" --image-sha-after "$SHA_AFTER"
      --image-stat-before "$STAT_BEFORE" --image-stat-after "$STAT_AFTER"
      --out "$OUT/report")
if [ -n "${CFTT_GRADE:-}" ]; then
    "$CFTT_GRADE" "${ARGS[@]}"
else
    cargo run -q --release -p seance_validate --bin cftt-grade -- "${ARGS[@]}"
fi
