#!/usr/bin/env bash
# Fetch a NIST CFTT test data set into the corpus, and record its provenance.
#
# ROADMAP §5.2. This script is COMMITTED on purpose. A deleted-file-recovery
# sweep was run on 2026-09-11 and is unreproducible, because its grader was
# never in the repository and its images were deleted after grading. A recorded
# run whose method is gone is an anecdote.
#
# It does not run anything. It fetches, verifies where the publisher published a
# hash to verify against, and writes what it found -- including, explicitly,
# where there was nothing to verify against. `seance_validate::manifest` turns
# that into the paragraph a validation document needs.
#
#   scripts/cftt/fetch.sh string-search  ~/forensic_corpora
#   scripts/cftt/fetch.sh dfr            ~/forensic_corpora --one-at-a-time
#   scripts/cftt/fetch.sh mobile         ~/forensic_corpora
#
# DISK. The deleted-file-recovery set is 90 images of exactly 1,073,742,336
# bytes each -- 90 GiB decompressed, which will not fit here and must not be
# attempted (`BUGS.md` HUNT-125 is this project already OOM-killed by ingest
# memory that scaled with the evidence). With --one-at-a-time the script
# decompresses one image, prints its path, and waits for the caller to delete it
# before fetching the next; the sweep runner drives that loop.
set -euo pipefail

SET="${1:-}"
ROOT="${2:-}"
shift 2 || true
ONE_AT_A_TIME=0
for arg in "$@"; do
  case "$arg" in
    --one-at-a-time) ONE_AT_A_TIME=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ -z "$SET" || -z "$ROOT" ]]; then
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi

for tool in curl sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 3; }
done

# --- the three data sets, and what each publisher does and does not publish --
#
# Each `provenance` value is the answer to "is there a publisher hash to check
# against", and it is recorded as a value rather than left implicit. A manifest
# that omitted the field where no hash exists would read as verified.
case "$SET" in
  string-search)
    DIR="$ROOT/cftt_string_search"
    PAGE='https://cfreds-archive.nist.gov/StringSearching/'
    ARCHIVE='https://cfreds-archive.nist.gov/StringSearching/string-search-federated-testing-data-set-version-1-1-revised-september-27-2019.zip'
    # The only one of the three that ships a hash list. Its name, not its
    # path: the archive extracts into a versioned top-level directory, and a
    # fixed path reported "no hash list" for the one set that has one.
    HASH_LIST='hash-sha256.txt'
    ;;
  dfr)
    DIR="$ROOT/cftt_dfr"
    PAGE='https://cfreds-archive.nist.gov/dfr-test-images.html'
    ARCHIVE=''          # 90 separate .dd.bz2 files, listed from the index page
    HASH_LIST=''        # the publisher publishes NONE
    ;;
  mobile)
    DIR="$ROOT/cftt_mobile"
    PAGE='https://cfreds-archive.nist.gov/mobile/index.html'
    ARCHIVE='https://s3.amazonaws.com/cftt.cfreds.nist.gov/cfreds/mobile/JTAG/HTC+Desire+S/HTC_Desire_S_JTAG.bin'
    HASH_LIST=''        # the publisher publishes NONE
    ;;
  *)
    echo "unknown data set: $SET (expected string-search, dfr or mobile)" >&2
    exit 2
    ;;
esac

mkdir -p "$DIR"
cd "$DIR"

echo "== $SET -> $DIR"
echo "   publisher page: $PAGE"
if [[ -n "$HASH_LIST" ]]; then
  echo "   publisher hash list: $HASH_LIST"
else
  # Said out loud, every run. This is the fact the manifest exists to carry.
  echo "   publisher hash list: NONE PUBLISHED — our digests will be a record of"
  echo "                        what we fetched, not a check against the publisher."
fi

fetch() {
  local url="$1" out="$2"
  if [[ -s "$out" ]]; then
    echo "   have $out"
    return
  fi
  echo "   fetching $out"
  # `--fail` so an HTML error page never lands as evidence, and `-C -` so an
  # interrupted multi-gigabyte fetch resumes rather than restarting.
  curl --fail --location --retry 3 --retry-delay 5 -C - -o "$out.part" "$url"
  mv "$out.part" "$out"
}

case "$SET" in
  string-search)
    fetch "$ARCHIVE" 'string-search-1.1.zip'
    command -v unzip >/dev/null || { echo "missing: unzip" >&2; exit 3; }
    unzip -o -q 'string-search-1.1.zip'
    ;;
  dfr)
    # The index page IS the list. Parsed rather than hard-coded, so a set that
    # gains or loses an image is not silently graded as the old set.
    fetch "$PAGE" 'dfr-index.html'
    mapfile -t IMAGES < <(
      grep -oE 'dfr-images/dfr-[A-Za-z0-9._-]+\.dd\.bz2' 'dfr-index.html' | sort -u
    )
    echo "   the index lists ${#IMAGES[@]} images"
    fetch 'https://cfreds-archive.nist.gov/dfr-images/setup-july-10-2012.pdf' \
          'setup-july-10-2012.pdf'
    for rel in "${IMAGES[@]}"; do
      base="$(basename "$rel")"
      fetch "https://cfreds-archive.nist.gov/$rel" "$base"
      if [[ "$ONE_AT_A_TIME" == 1 ]]; then
        bunzip2 -k -f "$base"
        echo "   READY ${base%.bz2}"
        echo "   waiting: delete ${base%.bz2} to continue"
        while [[ -e "${base%.bz2}" ]]; do sleep 2; done
      fi
    done
    ;;
  mobile)
    fetch "$ARCHIVE" 'HTC_Desire_S_JTAG.bin'
    fetch 'https://s3.amazonaws.com/cftt.cfreds.nist.gov/cfreds/mobile/JTAG/HTC+Desire+S/Mobile+Device+Data+Population_HTC_Desire_S.pdf' \
          'Mobile_Device_Data_Population_HTC_Desire_S.pdf'
    ;;
esac

# --- what is here, and what can be said about it -----------------------------
echo "   hashing"
: > 'our-sha256.txt'
# At ANY depth: this archive puts its two images three levels down, under a
# versioned directory and then `copy-to-test-computer/`. And `__MACOSX` and
# `._*` are macOS resource forks the publisher's zip carries; hashing them as
# though they were evidence would put files in the manifest that are not part
# of the data set.
while IFS= read -r -d '' f; do
  sha256sum "$f" >> 'our-sha256.txt'
done < <(
  find . -type f \
    ! -path './__MACOSX/*' ! -name '._*' ! -name '.DS_Store' \
    ! -name 'our-sha256.txt' ! -name '*.part' -print0
)

echo
echo "== done. Provenance:"
LIST_PATH=''
if [[ -n "$HASH_LIST" ]]; then
  # Found, not assumed: the archive's top-level directory carries a version in
  # its name, so the list is not at a path this script can hard-code.
  LIST_PATH="$(find . -type f -name "$HASH_LIST" ! -path './__MACOSX/*' | head -1)"
fi
if [[ -n "$LIST_PATH" && -s "$LIST_PATH" ]]; then
  echo "   comparing against the publisher's $LIST_PATH"
  # Base names, because the hash list's paths and the archive's do not agree
  # for every file in the real set -- measured: the list names
  # "Expected Results by ID - 07-25 Data Set.pdf" and the archive holds
  # "Expected Results by ID v1.1 9-27-19.pdf". Those are reported as NOT
  # FETCHED, which is what they are: the publisher's hash is for a file this
  # archive does not contain under that name, so nothing here is verified by it.
  fails=0
  absent=0
  verified=0
  while read -r want path; do
    base="$(basename "${path#\*}")"
    got="$(awk -v b="$base" '{ n=$2; sub(/.*\//, "", n); if (n == b) print $1 }' 'our-sha256.txt' | head -1)"
    if [[ -z "$got" ]]; then
      echo "   no such file: $base (the publisher hashes it; this archive has no file of that name)"
      absent=$((absent + 1))
    elif [[ "${got,,}" == "${want,,}" ]]; then
      echo "   verified:     $base"
      verified=$((verified + 1))
    else
      echo "   MISMATCH:     $base (publisher $want, ours $got)"
      fails=$((fails + 1))
    fi
  done < <(
    # Both shapes the publisher ships, in one directory: `<hex>  <path>` in its
    # SHA-1 and SHA-256 lists, and `ALGO (<path>) = <hex>` in its MD5 list. A
    # reader that knew only the first read ZERO entries from hash-md5.txt.
    {
      grep -E '^[0-9a-fA-F]{64}[[:space:]]' "$LIST_PATH" || true
      sed -nE 's/^[A-Za-z0-9]+ \((.*)\) = ([0-9a-fA-F]{32,128})$/\2  \1/p' "$LIST_PATH" || true
    }
  )
  echo
  echo "   $verified verified, $fails mismatched, $absent hashed by the publisher and not present"
  if (( fails > 0 )); then
    echo
    echo "   $fails file(s) do not match the publisher. These are NOT the bytes the"
    echo "   published assertions were written for; do not run against them."
    exit 4
  fi
  if (( verified == 0 )); then
    echo
    echo "   NOTHING was verified against the publisher, though a hash list exists."
    echo "   Treat this set as unverified and find out why before running it."
    exit 5
  fi
else
  echo "   the publisher publishes no hash list for this data set."
  echo "   our-sha256.txt is a FIRST-ACQUISITION record: it says what we fetched,"
  echo "   not that it is what the publisher shipped. A second party re-running"
  echo "   this work compares against these digests, not against the publisher."
fi
