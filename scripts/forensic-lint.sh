#!/usr/bin/env bash
#
# forensic-lint.sh — detect the recurring defect CLASSES that produce silent
# evidence fabrication, rather than fixing their instances one at a time.
#
# Why this exists: repeated whole-repo audits kept surfacing the *same* few
# mistakes replicated across dozens of parsers. Fixing instances is whack-a-mole;
# this gate makes the pattern fail CI so it cannot come back.
#
# The classes:
#
#   1. ZERO-PAD PARSE — a pre-zeroed buffer filled by a bare `read_at` whose
#      returned length is ignored. A short read leaves the tail zeroed and it is
#      then parsed as real on-disk data. Use `seance_core::io::read_exact_or_fail`
#      (fail closed) or `read_full` (honest short count).
#
#   2. SWALLOWED ERROR — `unwrap_or_default()` / `unwrap_or(vec![])` on a fallible
#      lookup, which turns "the query failed" into "there were no results". In a
#      forensic tool that is a false negative, not a default.
#
#   3. UNESCAPED LIKE — `format!("%{}%", ...)` bound into a LIKE without an
#      ESCAPE clause, so `_` and `%` in evidence-derived names silently over-match.
#
#   5. RAGGED STRING — a run of whitespace inside a user-facing string literal,
#      which is what a continuation whose trailing backslash was lost leaves
#      behind. The generated method-statement register shipped twenty lines of
#      it. A paragraph of prose has no meaningful run of whitespace.
#
# Usage:
#   scripts/forensic-lint.sh          # report violations, exit 1 if any
#   scripts/forensic-lint.sh --list   # list the allowlist and exit
#
# Suppressing a genuine false positive: put `forensic-lint: allow <class>` in a
# comment on the same line or the line above, with a short justification.

set -uo pipefail
# `set -e` is deliberately off here so every gate runs, which means a failed
# `cd` would not stop the script: it would run the whole suite against
# whatever directory it happened to be in and report the result as this
# repository's. Exit explicitly instead.
cd "$(dirname "$0")/.." || exit 1

if [ "${1:-}" = "--list" ]; then
  grep -rn "forensic-lint: allow" --include="*.rs" . 2>/dev/null | grep -v "^./target" || echo "(no allowlisted lines)"
  exit 0
fi

VIOLATIONS=0

report() {
  local class="$1" hits="$2" guidance="$3"
  local n
  n=$(printf '%s' "$hits" | grep -c . || true)
  if [ "$n" -gt 0 ]; then
    echo "======================================================================"
    echo "[$class] $n violation(s)"
    echo "$guidance"
    echo "----------------------------------------------------------------------"
    printf '%s\n' "$hits"
    echo
    VIOLATIONS=$((VIOLATIONS + n))
  fi
}

# Lines that opt out explicitly.
strip_allowed() {
  grep -v "forensic-lint: allow" || true
}

# --- Class 2: swallowed fallible lookups -------------------------------------
# `.await.unwrap_or_default()` on a DB/IO call hides the failure as "no rows".
SWALLOWED=$(grep -rn --include="*.rs" -E "\.await\s*$" -A 1 seance_api seance_db seance_core 2>/dev/null \
  | grep -E "unwrap_or_default\(\)|unwrap_or\(vec!\[\]\)|unwrap_or\(Vec::new\(\)\)" \
  | strip_allowed || true)
report "SWALLOWED-ERROR" "$SWALLOWED" \
  "A failed lookup must not read as an empty result. Propagate the error (map_err + ?) so
   a transient failure cannot masquerade as 'no hits'."

# --- Class 3: unescaped LIKE patterns ----------------------------------------
LIKE=$(grep -rn --include="*.rs" -E 'format!\("%\{\}%"' seance_db seance_api 2>/dev/null \
  | strip_allowed || true)
LIKE_UNESCAPED=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  # Heuristic: the file must mention an ESCAPE clause somewhere if it builds LIKE
  # patterns. Files with no ESCAPE at all are certainly unescaped.
  if ! grep -q "ESCAPE" "$file" 2>/dev/null; then
    LIKE_UNESCAPED+="$line"$'\n'
  fi
done <<< "$LIKE"
report "UNESCAPED-LIKE" "${LIKE_UNESCAPED%$'\n'}" \
  "Bind LIKE patterns with an ESCAPE clause and escape % and _ in the needle, or an
   evidence-derived name containing '_' (report_final.docx) silently over-matches."

# --- Class 4: reorderable recursive walks over the artifact tree --------------
# A recursive CTE whose step reads `FROM artifacts a JOIN <queue> ON a.parent_id`
# lets SQLite choose the join order, and it chooses wrong: `artifacts` becomes
# the outer loop, so every step searches the whole case and scans the queue for
# each row. That is quadratic, and on a real case it does not finish — the
# counts-by-source walk ran past ten minutes on 163,000 artifacts, the endpoint
# timed out at 300s, and the gallery waited on "Loading images..." for ever
# (UI-024). The queue must be written first and joined with CROSS JOIN, which is
# SQLite's documented way to pin the order. Writing it first WITHOUT `CROSS`
# does not work: the planner reorders it anyway.
REORDERABLE_WALK=$(grep -rn --include="*.rs" -E "FROM artifacts a JOIN [a-z_]+ [a-z]+ ON a\.parent_id" \
  seance_db seance_api seance_core 2>/dev/null | strip_allowed || true)
report "REORDERABLE-TREE-WALK" "$REORDERABLE_WALK" \
  "Write the queue first and join with CROSS JOIN:
     FROM <queue> q CROSS JOIN artifacts a ON a.parent_id = q.id
   See the CROSS JOIN section on seance_db::subtree_cte, and the plan test
   artifact_tree_walks_seek_the_parent_index which fails if the order is lost."

# --- Class 5: a run of whitespace inside a user-facing string ----------------
# A long message is written in Rust as a string continued with a trailing
# backslash, which strips the newline AND the next line's indentation. Write it
# without the backslash — or let a tool that rewrites the file eat it — and the
# indentation ends up INSIDE the string. `documentation/METHOD_STATEMENTS.md`
# shipped twenty lines reading "carrying the              service", in a
# document this project describes as the paragraph an examiner reads aloud.
#
# A paragraph of prose has no meaningful run of whitespace in it, so the
# pattern is the defect. Matched conservatively: three or more spaces between
# two word characters, on a line that holds a quote and is not a comment.
# SQL is excluded outright: a multi-line query literal's internal whitespace is
# insignificant to SQLite and it is not prose, so collapsing it would be churn
# with no reader on the other end. Anything else intentional — ASCII art, a
# column pad, real file content in a fixture — belongs behind
# `forensic-lint: allow RAGGED-STRING`.
RAGGED_RAW=$(grep -rn --include='*.rs' -E '[a-zA-Z0-9,.;:!?)]   +[a-zA-Z0-9(]' \
  --exclude-dir=target --exclude-dir=vendor . 2>/dev/null \
  | grep '"' \
  | grep -vE ':[0-9]+: *(//|#)' \
  | grep -vE '(SELECT|FROM |WHERE|JOIN|GROUP BY|ORDER BY|COALESCE|json_extract|CAST\()' \
  || true)
# The opt-out is honoured on the matched line OR the line above it, because a
# continuation inside a string literal cannot carry a trailing comment.
RAGGED=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  above=$((lineno > 1 ? lineno - 1 : 1))
  if sed -n "${above},${lineno}p" "$file" 2>/dev/null | grep -q 'forensic-lint: allow'; then
    continue
  fi
  RAGGED+="$line"$'\n'
done <<< "$RAGGED_RAW"
RAGGED="${RAGGED%$'\n'}"
report "RAGGED-STRING" "$RAGGED" \
  "A run of whitespace inside a string reaches the screen and the report. It is almost
   always a continuation whose backslash was lost: write the message as a concat! of
   quoted chunks, which cannot suffer this, or join it onto one line."

# ---------------------------------------------------------------------------
# A validation report outside the repository root is a report nobody reads.
#
# `documentation/VALIDATION.md` points at `validation-report.{json,md}` at the
# root, and that pair is what a reader checks a claim against. `seance-validate`
# writes `--out` relative to the WORKING DIRECTORY, so running it from anywhere
# else silently produces a second, divergent report — which happened: one was
# committed into `frontend/` while the documented pair stayed at the previous
# release's commit and date. Two reports, and the documented one stale.
STRAY_REPORTS=$(find . -name 'validation-report.*' \
  -not -path './validation-report.*' \
  -not -path './target/*' -not -path './node_modules/*' -not -path './.git/*' \
  2>/dev/null || true)
report "STRAY-VALIDATION-REPORT" "$STRAY_REPORTS" \
  "seance-validate writes --out relative to the working directory. The report the
   documentation cites lives at the repository root; run it from there, and delete
   the stray copy rather than leaving two reports that can disagree."

echo "======================================================================"
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "FORENSIC LINT: clean — no known fabrication-class patterns detected."
  exit 0
else
  echo "FORENSIC LINT FAILED: $VIOLATIONS violation(s)."
  echo "Each is a class that has previously produced silent wrong evidence."
  echo "Fix, or annotate with 'forensic-lint: allow <class>' plus a justification."
  exit 1
fi
