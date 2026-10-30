#!/usr/bin/env bash
#
# Build the reproducible "golden image" regression corpus.
#
# These images are NOT third-party evidence with published answers (that is what
# the CFReDS / Ali Hadi corpora are — see documentation/TESTING.md). They are
# synthesised here from a *declared* layout so that the ground truth is this
# script itself: readable, auditable, and reproducible on any machine without
# root. The matching test (seance_tests/src/golden_multipart_tests.rs) asserts
# that Séance recovers exactly what this script wrote — Séance is checked against
# mkntfs / mke2fs / mtools + a fixed layout, never against its own prior output.
#
# What it produces (in the output directory, default ./golden_images):
#
#   golden_multipart.E01  — a GPT disk imaged into EnCase E01, carrying four
#                           partitions so one image exercises the whole
#                           E01 -> partition -> filesystem -> file chain for
#                           every filesystem Séance walks natively on a disk:
#                             p1  NTFS   (walked via the $MFT parser)
#                             p2  ext4   (walked via the ext4 parser)
#                             p3  FAT16  (walked via the FAT parser)
#                             p4  APFS   (container/volume via the APFS parser)
#
# APFS is a partial case: mkapfs (from apfsprogs) builds a real container and
# volume on Linux, but there is no rootless way to write *files* into APFS (no
# writable FUSE, and the kernel module needs root). So p4's ground truth is
# structural — fixed container/volume UUIDs and block size — while file content
# stays the NTFS/ext4/FAT job. A file-bearing APFS image still needs a real Mac
# capture; see documentation/TESTING.md.
#
# Everything runs rootless: NTFS/ext4/FAT filesystems are written directly into
# image files (no loop mounts), populated with debugfs / ntfscp / mcopy, dd'd
# into their partition slots, and wrapped with ewfacquire.
#
# The file layout below is the ground truth the test asserts. Keep the two in
# sync: the constants in golden_multipart_tests.rs mirror these names, contents
# and the 256-byte 0x00..0xFF data.bin.
#
# Requires: sgdisk, mkntfs+ntfscp (ntfs-3g), mke2fs+debugfs (e2fsprogs),
#           mkfs.vfat+mtools, ewfacquire+ewfverify (libewf-tools), dd, truncate.

set -euo pipefail

OUT_DIR="${1:-./golden_images}"
IMAGE_NAME="golden_multipart"

# apfsprogs commit that mkapfs is built from when it is not already installed.
# Pinned for reproducibility; bump deliberately.
APFSPROGS_REPO="https://github.com/linux-apfs/apfsprogs.git"
APFSPROGS_COMMIT="3721463ba7f539e532907bc1d10ed5b9a97d0449"

# --- preflight: fail early and clearly if a tool is missing ------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
for t in sgdisk mkntfs ntfscp mke2fs debugfs mkfs.vfat mcopy dd truncate ewfacquire ewfverify; do
    need "$t"
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# mkapfs is not packaged anywhere, so build it from apfsprogs (pinned) when it is
# not already on PATH. This is the one filesystem here with no distro mkfs; it
# needs git + a C toolchain, checked only if we actually have to build.
MKAPFS="$(command -v mkapfs || true)"
if [ -z "$MKAPFS" ]; then
    for t in git gcc make; do need "$t"; done
    echo "==> mkapfs not found; building apfsprogs @ ${APFSPROGS_COMMIT:0:12}"
    git clone -q "$APFSPROGS_REPO" apfsprogs
    (cd apfsprogs && git checkout -q "$APFSPROGS_COMMIT" && make -C mkapfs >/dev/null 2>&1)
    MKAPFS="$WORK/apfsprogs/mkapfs/mkapfs"
fi

SECT=512
# 1 MiB-aligned layout. Sizes chosen small (cache-friendly) but above each
# filesystem's minimum: FAT16 / NTFS / APFS each need a few MiB; 16-32 MiB is safe.
P1_START=2048;                 P1_MIB=32   # NTFS
P2_START=$((P1_START + P1_MIB*1024*1024/SECT)); P2_MIB=16   # ext4
P3_START=$((P2_START + P2_MIB*1024*1024/SECT)); P3_MIB=16   # FAT16
P4_START=$((P3_START + P3_MIB*1024*1024/SECT)); P4_MIB=32   # APFS
P4_SECT=$((P4_MIB*1024*1024/SECT))
# Total = end of last partition + room for the backup GPT (33 sectors) + slack.
TOTAL_SECT=$((P4_START + P4_SECT + 2048))
TOTAL_BYTES=$((TOTAL_SECT * SECT))

echo "==> building ${IMAGE_NAME}.E01  (${TOTAL_BYTES} bytes raw, GPT: NTFS+ext4+FAT16+APFS)"

# --- the ground-truth payload, identical in every partition ------------------
# A filesystem-tagged text file (proves we read the right partition) and a
# 256-byte binary file of 0x00..0xFF (proves exact content round-trips).
python3 - <<'PY'
import sys
with open("data.bin", "wb") as f:
    f.write(bytes(range(256)))
PY
# Exact bytes matter: the test asserts this content verbatim. printf gives real
# newlines (57 bytes total), so the Rust constant can mirror it unambiguously.
printf 'golden regression corpus\nbuilt by build_golden_images.sh\n' > readme.txt

# --- partition 1: NTFS -------------------------------------------------------
truncate -s "${P1_MIB}M" p1.img
mkntfs -F -Q -L NTFSVOL p1.img >/dev/null 2>&1
printf 'SEANCE GOLDEN NTFS\n' > hello.ntfs.txt
ntfscp p1.img hello.ntfs.txt /hello.txt
ntfscp p1.img data.bin /data.bin
ntfscp p1.img readme.txt /readme.txt

# --- partition 2: ext4 -------------------------------------------------------
truncate -s "${P2_MIB}M" p2.img
# Fixed UUID keeps the ext4 superblock stable across rebuilds (content, not raw
# bytes, is what the test asserts, but a stable UUID makes diffs legible).
mke2fs -F -q -t ext4 -L LINUXVOL -U 11111111-2222-3333-4444-555555555555 p2.img >/dev/null 2>&1
printf 'SEANCE GOLDEN EXT4\n' > hello.ext4.txt
debugfs -w -R "write hello.ext4.txt hello.txt" p2.img >/dev/null 2>&1
debugfs -w -R "write data.bin data.bin" p2.img >/dev/null 2>&1
debugfs -w -R "write readme.txt readme.txt" p2.img >/dev/null 2>&1

# --- partition 3: FAT16 ------------------------------------------------------
truncate -s "${P3_MIB}M" p3.img
mkfs.vfat -F 16 -n FATVOL p3.img >/dev/null 2>&1
printf 'SEANCE GOLDEN FAT\n' > hello.fat.txt
mcopy -i p3.img hello.fat.txt ::/hello.txt
mcopy -i p3.img data.bin ::/data.bin
mcopy -i p3.img readme.txt ::/readme.txt

# --- partition 4: APFS -------------------------------------------------------
# mkapfs makes an empty container + volume; there is no rootless way to write
# files into APFS on Linux (no writable FUSE, and the kernel module needs root).
# So this partition's ground truth is structural: fixed container/volume UUIDs
# and block size, which the test asserts. Files stay the NTFS/ext4/FAT job.
truncate -s "${P4_MIB}M" p4.img
"$MKAPFS" -L GOLDENAPFS \
    -U 00000000-1111-2222-3333-444444444444 \
    -u 55555555-6666-7777-8888-999999999999 \
    p4.img >/dev/null 2>&1

# --- assemble the GPT disk and drop each filesystem into its slot ------------
truncate -s "$TOTAL_BYTES" disk.raw
sgdisk -a 2048 \
    -n "1:${P1_START}:+${P1_MIB}M" -t 1:0700 -c 1:NTFSVOL \
    -n "2:${P2_START}:+${P2_MIB}M" -t 2:8300 -c 2:LINUXVOL \
    -n "3:${P3_START}:+${P3_MIB}M" -t 3:0700 -c 3:FATVOL \
    -n "4:${P4_START}:+${P4_MIB}M" -t 4:af0a -c 4:APFSVOL \
    disk.raw >/dev/null
dd if=p1.img of=disk.raw bs=$SECT seek=$P1_START conv=notrunc status=none
dd if=p2.img of=disk.raw bs=$SECT seek=$P2_START conv=notrunc status=none
dd if=p3.img of=disk.raw bs=$SECT seek=$P3_START conv=notrunc status=none
dd if=p4.img of=disk.raw bs=$SECT seek=$P4_START conv=notrunc status=none

# --- wrap the raw disk into E01 ----------------------------------------------
rm -f "${OUT_DIR}/${IMAGE_NAME}.E01"
ewfacquire -u -t "${OUT_DIR}/${IMAGE_NAME}" -f encase6 -c deflate:best -S 1GiB \
    -C GOLD-001 -D "Seance synthetic multi-partition golden image" \
    -e SeanceCI -E 001 \
    -N "GPT NTFS+ext4+FAT16+APFS; reproducible from scripts/build_golden_images.sh" \
    -m fixed -M logical disk.raw >/dev/null

ewfverify "${OUT_DIR}/${IMAGE_NAME}.E01" >/dev/null 2>&1 \
    && echo "==> ewfverify: OK"

ls -la "${OUT_DIR}/${IMAGE_NAME}.E01"
echo "==> done. Point SEANCE_GOLDEN_IMAGES at ${OUT_DIR} to run the regression test."
