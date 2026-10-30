#!/usr/bin/env bash
#
# ci-gate.sh — run the EXACT checks the GitHub Actions CI runs, locally.
#
# Why this exists: the project's hosted-runner Actions minutes can be exhausted
# (a billing state, not a code problem), which leaves push/PR CI stuck `queued`.
# This script reproduces every CI gate on your own machine so a build can be
# certified green before it is submitted, regardless of the hosted-CI state.
# It mirrors `.github/workflows/test.yml` and `audit.yml` — every job in both,
# which is the point. Two of those jobs — `cargo deny check` and
# `scripts/check-unsafe.sh` — were missing here, and both were failing on main.
# This script does not report a gate it skipped, it simply omits it, so its
# banner could read ALL CHECKS PASSED over two red CI jobs it had never run.
#
# What neither this script nor any workflow does: set the corpus variables
# (`SEANCE_HIVE_CORPUS`, `SEANCE_EVTX_CORPUS`, `SEANCE_APP_SCHEMA_CORPUS`, ...)
# that gate the known-answer tests against evidence the repository does not
# carry. Those tests skip here exactly as they skip in CI, and a green run
# says nothing about them. `documentation/TESTING.md` owns the list;
# `SEANCE_REQUIRE_CORPUS=1` turns the skips it reaches into failures.
#
# Usage:
#   scripts/ci-gate.sh            # full gate: fmt, clippy, tests, doc-tests,
#                                 #   audit, deny, unsafe guard, forensic lint,
#                                 #   version agreement, feature edges
#   scripts/ci-gate.sh --quick    # fast gate: everything except the test suites
#   scripts/ci-gate.sh --release  # also do a release link-build of seance_cli
#   scripts/ci-gate.sh --tag v1.0.0-rc  # also check the tag names the manifests' version
#   scripts/ci-gate.sh --extra    # also the plaso schema-drift and golden-image jobs
#                                 #   (network, and the image-building toolchain)
#
# Exit code is 0 only if every selected gate passed. Each gate runs even if an
# earlier one failed, so you see the full picture in one run.

set -uo pipefail
# `set -e` is deliberately off here so every gate runs, which means a failed
# `cd` would not stop the script: it would run the whole suite against
# whatever directory it happened to be in and report the result as this
# repository's. Exit explicitly instead.
cd "$(dirname "$0")/.." || exit 1

QUICK=false
RELEASE=false
EXTRA=false
TAG=""
while [ $# -gt 0 ]; do
  arg="$1"; shift
  case "$arg" in
    --extra) EXTRA=true ;;
    --tag) TAG="${1:-}"; [ -n "$TAG" ] || { echo "--tag needs a value" >&2; exit 2; }; shift ;;
    --quick) QUICK=true ;;
    --release) RELEASE=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

FAILED=()
SKIPPED=()
run() {
  local name="$1"; shift
  echo "======================================================================"
  echo ">>> $name"
  echo ">>>   $*"
  echo "======================================================================"
  if "$@"; then
    echo "[PASS] $name"
  else
    echo "[FAIL] $name"
    FAILED+=("$name")
  fi
  echo
}

# 1. Formatting (test.yml: fmt job).
run "rustfmt" cargo fmt --all -- --check

# 2. Clippy with warnings-as-errors. `--all-targets` is a superset of CI's
#    `--all-features` clippy: it also lints test/bench/example code.
run "clippy -D warnings" cargo clippy --workspace --all-targets --all-features -- -D warnings

if [ "$QUICK" = false ]; then
  # 3. Full test suite (test.yml: test job). test_data-gated tests self-skip
  #    when the corpus is absent, exactly as on CI.
  run "test suite" cargo test --workspace --all-features
  # 4. Doc tests (test.yml).
  run "doc tests" cargo test --workspace --doc
fi

# 5. Dependency audit (audit.yml). Install on demand if missing.
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo ">>> installing cargo-audit (one-time)"
  cargo install cargo-audit --locked || FAILED+=("cargo-audit install")
fi
run "cargo audit" cargo audit

# 5a. Licence, ban and source policy (test.yml: cargo-deny job). `cargo audit`
#     and `cargo deny check advisories` read the same lock file but not the same
#     ignore list — audit.toml and deny.toml are maintained by hand — and they
#     do not agree about scope either: cargo-deny reports informational
#     advisories for workspace-direct dependencies only, where cargo-audit
#     reports them transitively. Running one is not running the other. Skipped
#     with a warning rather than installed on demand: unlike cargo-audit, this
#     is a large build and forcing it on someone running --quick would be rude.
if command -v cargo-deny >/dev/null 2>&1; then
  run "cargo deny check" cargo deny check
else
  # A skipped gate is NOT a passed gate, and this script exists precisely
  # because saying otherwise is how four gates stayed red on main for weeks.
  # It goes in its own bucket rather than FAILED so the banner can tell "this
  # gate ran and found something" apart from "this gate never ran" — different
  # facts, different next actions — but either way the exit code is non-zero
  # and the build is not certified.
  echo ">>> SKIPPED: cargo deny check — cargo-deny is not installed"
  echo ">>>   install with: cargo install cargo-deny --locked"
  echo
  SKIPPED+=("cargo deny check")
fi

# 5b. The no-unsafe guarantee (audit.yml: unsafe-guard job). Every crate must
#     carry #![forbid(unsafe_code)] or sit on the documented FFI allow-list.
#     Cheap, and it is the gate a newly-added crate silently fails.
run "unsafe-code guard" scripts/check-unsafe.sh

# 5c. Forensic defect-class lint. Catches the patterns that silently fabricate
#     evidence (zero-pad parses, swallowed lookups, unescaped LIKE) as a CLASS,
#     so they cannot be reintroduced one file at a time.
run "forensic lint" scripts/forensic-lint.sh

# 5d. Version agreement (release.yml: check-version job). seance_cli, seance_api
#     and frontend/package.json each put a version in front of a court, and all
#     three must be the one number in [workspace.package]. Cheap, and it is the
#     gate a hand-edited manifest silently fails.
run "version agreement" scripts/check-version.sh $TAG

# 5e. Feature edges (test.yml: fmt job). A native-C feature that is off must
#     leave its C crate out of the release binary's graph; a plain edge from
#     seance_api pulled libesedb into every e01-only build for two releases
#     and no x86_64 Windows asset was ever built (REL-003). `cargo tree` only.
run "feature edges" scripts/check-feature-edges.sh

# 5g. Frontend (test.yml: frontend job) and the bundle the release attaches
#     (release.yml: build-web-ui). Skipped, not passed, without node.
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  run "frontend install" npm --prefix frontend ci
  run "frontend typecheck" npm --prefix frontend run typecheck
  run "frontend lint" npm --prefix frontend run lint
  if [ "$QUICK" = false ]; then
    run "frontend tests" npm --prefix frontend test
    run "frontend build" npm --prefix frontend run build
  fi
else
  echo ">>> SKIPPED: frontend gates: node/npm is not installed"
  SKIPPED+=("frontend gates")
fi

# 5h. Jobs that need the network or an image-building toolchain (test.yml:
#     app-schema-corpus and golden-images). Opt in with --extra.
if [ "$EXTRA" = true ] && [ "$QUICK" = false ]; then
  if [ ! -d reference/plaso/test_data ]; then
    # Pinned: upstream plaso moved test_data/ after this commit.
    run "fetch plaso test data" bash -c "git init -q reference/plaso && git -C reference/plaso fetch -q --depth 1 https://github.com/log2timeline/plaso e3401d1558f322a69ea35ae5c2b308fcbb0f7870 && git -C reference/plaso checkout -q FETCH_HEAD"
  fi
  export SEANCE_PLASO_TEST_DATA="$PWD/reference/plaso/test_data" SEANCE_SKYPE_SAMPLES="$PWD/reference/plaso/test_data"
  run "plaso: browser history" cargo test -p seance_plugin_browser_history --test corpus
  run "plaso: skype" cargo test -p seance_plugin_skype --lib the_real_skype_store
  run "plaso: android sms" cargo test -p seance_plugin_android_sms --lib real_telephony_stores
  run "plaso: imessage" cargo test -p seance_plugin_imessage --lib real_message_stores
  run "plaso: twitter" cargo test -p seance_plugin_twitter --lib real_
  run "plaso: call history" cargo test -p seance_plugin_call_history --lib real_call_logs
  if [ ! -d golden_images ]; then
    run "build golden image" ./scripts/build_golden_images.sh golden_images
  fi
  run "golden-image regression" env SEANCE_GOLDEN_IMAGES="$PWD/golden_images" SEANCE_REQUIRE_CORPUS=1 \
    cargo test -p seance_tests --features e01 golden_multipart_tests
fi

# 6. Optional release link-build (proves the E01/libewf native link on this
#    host; the release matrix does this per target).
if [ "$RELEASE" = true ]; then
  run "release build (seance_cli)" cargo build --release -p seance_cli
fi

echo "======================================================================"
if [ ${#FAILED[@]} -ne 0 ]; then
  echo "CI GATE FAILED (${#FAILED[@]}): ${FAILED[*]}"
  [ ${#SKIPPED[@]} -ne 0 ] && echo "  ...and NOT RUN (${#SKIPPED[@]}): ${SKIPPED[*]}"
  echo "Do not submit until these are green."
  exit 1
elif [ ${#SKIPPED[@]} -ne 0 ]; then
  # Everything that ran, passed — and that is not the same as passing. The
  # whole point of this script is that a gate nobody ran cannot be reported as
  # a gate that passed.
  echo "CI GATE INCOMPLETE (${#SKIPPED[@]} not run): ${SKIPPED[*]}"
  echo "Everything that ran passed, but this build is NOT certified: the gates"
  echo "above were never executed, and CI will still run them."
  exit 1
else
  echo "CI GATE: ALL CHECKS PASSED — safe to submit."
  exit 0
fi
