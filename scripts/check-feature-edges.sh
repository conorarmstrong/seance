#!/usr/bin/env bash
#
# check-feature-edges.sh — assert that an opt-out feature really opts out.
#
# The release matrix builds x86_64 Windows with `--no-default-features
# --features e01`, because `libesedb-sys` does not compile under MSYS2 gcc.
# That only works if nothing in the graph pulls libesedb in unconditionally —
# and for two releases something did (`seance_plugin_webcache`, a plain edge
# from seance_api), so the job failed on every tag and no x86_64 Windows binary
# was ever built (REL-003). The feature gate at the call sites was right; the
# dependency edge was not, and nothing checked the edge.
#
# This checks the edge. For each native-C feature, the dependency graph of the
# release binary built WITHOUT that feature must not contain the C crate.
#
# Usage: scripts/check-feature-edges.sh
# Needs only cargo.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {
  local feature="$1" crate="$2" features_kept="$3"
  local tree
  tree=$(cargo tree -p seance_cli --no-default-features --features "$features_kept" -e normal 2>/dev/null)
  if grep -q "^[^a-zA-Z]*${crate} " <<<"$tree" || grep -q "── ${crate} " <<<"$tree"; then
    echo "FAIL: with feature '${feature}' off (features: ${features_kept}), '${crate}' is still in seance_cli's dependency graph:"
    grep "${crate} " <<<"$tree" | head -5
    fail=1
  else
    echo "ok: feature '${feature}' off -> no '${crate}' in the graph"
  fi
}

check esedb libesedb-sys "e01,heic,video-thumbs"
check e01 seance_container_e01 "esedb,heic,video-thumbs"
check heic libheif-rs "e01,esedb,video-thumbs"
check video-thumbs openh264 "e01,esedb,heic"

exit $fail
