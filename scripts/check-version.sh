#!/usr/bin/env bash
#
# check-version.sh — assert that every version a user can see agrees.
#
# Three places state the product version and each reaches a court-facing
# surface: seance_cli (the `seance` binary's `--version` and its reports),
# seance_api (`tool_version` in signed reports and the /api/v1/version
# endpoint) and frontend/package.json (the Web UI bundle). All three are meant
# to come from `[workspace.package].version` in the root Cargo.toml; this
# script proves they do, and, when handed a release tag, that the tag names
# the same number. A tag that disagrees with the manifests fails here before
# any release asset is built.
#
# Usage:
#   scripts/check-version.sh            # manifests agree with each other
#   scripts/check-version.sh v1.0.0     # ...and with the tag (leading v optional)
#
# Prints the agreed version on stdout on success. Needs only cargo, jq and node
# (all three are present on every build host that can build the product).

set -euo pipefail
cd "$(dirname "$0")/.."

tag="${1:-}"

meta=$(cargo metadata --format-version 1 --no-deps)
cli=$(jq -r '.packages[] | select(.name=="seance_cli") | .version' <<<"$meta")
api=$(jq -r '.packages[] | select(.name=="seance_api") | .version' <<<"$meta")
# The `;` before `}` is required by POSIX and by BSD sed; GNU sed tolerates its
# absence, so this read the workspace version on Linux and failed outright on
# macOS with "bad flag in substitute command".
workspace=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' Cargo.toml)
web=$(node -e 'process.stdout.write(require("./frontend/package.json").version)')
weblock=$(node -e 'process.stdout.write(require("./frontend/package-lock.json").version)')

fail=0
say() { printf '  %-32s %s\n' "$1" "$2"; }
echo "version sources:"
say "Cargo.toml [workspace.package]" "${workspace:-<missing>}"
say "seance_cli"                     "${cli:-<missing>}"
say "seance_api"                     "${api:-<missing>}"
say "frontend/package.json"          "${web:-<missing>}"
say "frontend/package-lock.json"     "${weblock:-<missing>}"

for v in "$workspace" "$cli" "$api" "$web" "$weblock"; do
  if [ -z "$v" ] || [ "$v" != "$workspace" ]; then fail=1; fi
done
if [ "$fail" -ne 0 ]; then
  echo "FAIL: the version sources above do not agree." >&2
  echo "      Set [workspace.package].version in Cargo.toml (crates inherit it)" >&2
  echo "      and frontend/package.json + package-lock.json to the same value." >&2
  exit 1
fi

if [ -n "$tag" ]; then
  tagver="${tag#refs/tags/}"
  tagver="${tagver#v}"
  say "tag" "$tag"
  if [ "$tagver" != "$workspace" ]; then
    echo "FAIL: tag '$tag' names $tagver but the manifests say $workspace." >&2
    echo "      Bump [workspace.package].version and the frontend package files," >&2
    echo "      or tag the commit that carries that version." >&2
    exit 1
  fi
fi

echo "OK: $workspace"
