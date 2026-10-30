#!/usr/bin/env bash
# Guard the "no unsafe" guarantee.
#
# Every workspace crate must EITHER declare `#![forbid(unsafe_code)]` at its
# crate root (a compile-time guarantee that the crate contains no unsafe), OR be
# on the short allow-list of crates that genuinely need FFI unsafe. This stops a
# new crate from silently shipping unsafe without review, and stops the
# attribute from being quietly dropped.
#
# The forbid attribute is enforced by every `cargo build`/`test` already; this
# script only checks that the attribute (or an explicit exception) is present.
set -euo pipefail
cd "$(dirname "$0")/.."

# Crates permitted to contain unsafe, each for a documented FFI reason.
#   seance_container_e01 -> libewf C bindings (E01 forensic images)
#   seance_cli           -> libc::kill(pid, 0) liveness probe for the workspace lock
ALLOW="seance_container_e01 seance_cli"

fail=0
for cargo in */Cargo.toml; do
  crate="$(dirname "$cargo")"
  case " $ALLOW " in *" $crate "*) continue ;; esac

  root=""
  [ -f "$crate/src/lib.rs" ] && root="$crate/src/lib.rs"
  [ -z "$root" ] && [ -f "$crate/src/main.rs" ] && root="$crate/src/main.rs"
  [ -z "$root" ] && continue  # no crate root (e.g. a build-only helper)

  if ! grep -q '#!\[forbid(unsafe_code)\]' "$root"; then
    echo "MISSING #![forbid(unsafe_code)]: $root"
    echo "  Add it, or add $crate to ALLOW in scripts/check-unsafe.sh with a reason."
    fail=1
  fi
done

# The allow-listed crates should still be the ONLY ones with unsafe in source.
for crate in $ALLOW; do
  if [ -d "$crate/src" ] && ! grep -rqE '\bunsafe\b' "$crate/src"; then
    echo "NOTE: $crate is allow-listed for unsafe but no longer uses any."
    echo "  Consider removing it from ALLOW and adding #![forbid(unsafe_code)]."
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "unsafe-code guard failed." >&2
  exit 1
fi
echo "unsafe-code guard passed: all crates forbid unsafe except the FFI allow-list."
