#!/bin/bash
#
# Regenerate the real-filesystem validation fixtures used by the forensic
# parser validations. These images are intentionally NOT committed (test_data/
# is gitignored) because they are large and reproducible. This script rebuilds
# them from scratch so the validations are repeatable in CI or on a fresh
# checkout.
#
# Requirements:
#   - Docker (privileged) for btrfs/xfs/ntfs images (Linux mkfs in a container)
#   - macOS `hdiutil` + `diskutil` for the APFS image (skipped elsewhere)
#   - curl for the AFF4 reference images
#
# Ground-truth md5s are printed as each fixture is built; the Rust validations
# compare against them. Usage: scripts/build_validation_fixtures.sh [outdir]
#
set -euo pipefail

OUT="${1:-test_data/fixtures}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
echo "Writing fixtures to $OUT"

have() { command -v "$1" >/dev/null 2>&1; }

# --- btrfs (single, RAID1, RAID0, compressed, subvolumes, large dir) --------
build_btrfs() {
  have docker || { echo "skip btrfs: docker not found"; return; }
  echo "== btrfs =="
  docker run --rm --privileged -v "$OUT:/out" alpine sh -c '
    set -e
    apk add --no-cache btrfs-progs >/dev/null 2>&1

    # Single device with a subvolume + snapshot (snapshot preserves pre-change state)
    dd if=/dev/zero of=/out/btrfs_snap.img bs=1M count=300 status=none
    mkfs.btrfs -q /out/btrfs_snap.img
    mkdir -p /mnt/b; mount -t btrfs -o loop /out/btrfs_snap.img /mnt/b
    echo "top-level file" > /mnt/b/toplevel.txt
    btrfs subvolume create /mnt/b/subvol1 >/dev/null
    echo "inside subvolume" > /mnt/b/subvol1/insub.txt
    btrfs subvolume snapshot /mnt/b/subvol1 /mnt/b/snap1 >/dev/null
    echo "post-snapshot" > /mnt/b/subvol1/after_snap.txt
    umount /mnt/b

    # Large multi-node directory (5000 files)
    dd if=/dev/zero of=/out/btrfs_bigdir.img bs=1M count=400 status=none
    mkfs.btrfs -q /out/btrfs_bigdir.img
    mount -t btrfs -o loop /out/btrfs_bigdir.img /mnt/b
    mkdir /mnt/b/bigdir
    i=0; while [ $i -lt 5000 ]; do echo "file $i" > /mnt/b/bigdir/file_$(printf %05d $i).txt; i=$((i+1)); done
    umount /mnt/b

    # RAID1 (mirror) and RAID0 (stripe) two-device sets
    for prof in raid1 raid0; do
      dd if=/dev/zero of=/out/btrfs_${prof}_d1.img bs=1M count=300 status=none
      dd if=/dev/zero of=/out/btrfs_${prof}_d2.img bs=1M count=300 status=none
      L1=$(losetup -f); losetup $L1 /out/btrfs_${prof}_d1.img
      L2=$(losetup -f); losetup $L2 /out/btrfs_${prof}_d2.img
      mkfs.btrfs -q -d $prof -m raid1 $L1 $L2
      mount $L1 /mnt/b
      head -c 2000000 /dev/urandom > /mnt/b/known.bin
      echo "btrfs $prof known.bin md5: $(md5sum /mnt/b/known.bin | cut -d" " -f1)"
      umount /mnt/b; losetup -d $L1; losetup -d $L2
    done
  '
}

# --- XFS v5 (real inode timestamps) -----------------------------------------
# The util-linux blkid test set already ships a real mkfs.xfs v5 image at
# reference/util-linux/tests/ts/blkid/images-fs/xfs-v5.img.xz -- decompress it:
build_xfs() {
  echo "== xfs (from vendored util-linux test set) =="
  local src="reference/util-linux/tests/ts/blkid/images-fs/xfs-v5.img.xz"
  if [ -f "$src" ]; then
    xz -dkc "$src" > "$OUT/xfs_v5.img" && echo "xfs_v5.img ready"
  else
    echo "skip xfs: $src not found"
  fi
}

# --- NTFS with LZNT1-compressed files ---------------------------------------
build_ntfs_compressed() {
  have docker || { echo "skip ntfs: docker not found"; return; }
  echo "== ntfs (compressed) =="
  docker run --rm --privileged -v "$OUT:/out" alpine sh -c '
    set -e
    apk add --no-cache ntfs-3g ntfs-3g-progs util-linux attr >/dev/null 2>&1
    dd if=/dev/zero of=/out/ntfs_comp.img bs=1M count=64 status=none
    mkntfs -Q -F /out/ntfs_comp.img >/dev/null 2>&1
    mkdir -p /mnt/n
    L=$(losetup -f); losetup $L /out/ntfs_comp.img
    ntfs-3g -o compression $L /mnt/n
    mkdir /mnt/n/c; setfattr -n system.ntfs_attrib_be -v 0x00000800 /mnt/n/c 2>/dev/null || true
    yes ABCDEFGH | head -c 262144 > /mnt/n/c/text.log
    echo "ntfs text.log md5: $(md5sum /mnt/n/c/text.log | cut -d" " -f1)"
    umount /mnt/n; losetup -d $L
  '
}

# --- APFS with advanced checkpoints (macOS only) ----------------------------
build_apfs() {
  have hdiutil && have diskutil || { echo "skip apfs: hdiutil/diskutil not found (macOS only)"; return; }
  echo "== apfs =="
  local raw="$OUT/apfs.raw"
  rm -f "$raw"; dd if=/dev/zero of="$raw" bs=1m count=80 status=none
  local dev
  dev=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$raw" | head -1 | awk '{print $1}')
  diskutil partitionDisk "$dev" GPT APFS CKTEST 100% >/dev/null
  sleep 1
  echo "apfs marker content" > /Volumes/CKTEST/marker.txt || true
  echo "apfs marker.txt md5: $(md5 -q /Volumes/CKTEST/marker.txt 2>/dev/null || echo n/a)"
  diskutil unmount /Volumes/CKTEST >/dev/null 2>&1 || true
  hdiutil detach "$dev" >/dev/null 2>&1 || true
  echo "apfs.raw ready (APFS container at partition, ~byte 20480)"
}

# --- HFS+ volume (macOS only) -----------------------------------------------
build_hfsplus() {
  have hdiutil && have newfs_hfs || { echo "skip hfs+: hdiutil/newfs_hfs not found (macOS only)"; return; }
  echo "== hfs+ =="
  local raw="$OUT/hfsplus.raw"
  rm -f "$raw"; dd if=/dev/zero of="$raw" bs=1m count=40 status=none
  local dev
  dev=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$raw" | head -1 | awk '{print $1}')
  newfs_hfs -v HFSTEST "$dev" >/dev/null 2>&1
  diskutil mount "$dev" >/dev/null 2>&1
  local mp; mp=$(mount | grep -i "$dev" | awk '{print $3}' | head -1)
  if [ -n "$mp" ]; then
    echo "hello from hfs plus content" > "$mp/hello.txt"
    head -c 300000 /dev/urandom > "$mp/data.bin"
    mkdir -p "$mp/sub"; echo "nested unique-marker-HFS" > "$mp/sub/nested.txt"
    echo "hfs+ hello.txt md5: $(md5 -q "$mp/hello.txt")"
    diskutil unmount "$mp" >/dev/null 2>&1
  fi
  hdiutil detach "$dev" >/dev/null 2>&1
  echo "hfsplus.raw ready (HFS+ volume, header at byte 1024)"
}

# --- AFF4 reference images (Evimetry / c-aff4 standard set) ------------------
build_aff4() {
  have curl || { echo "skip aff4: curl not found"; return; }
  echo "== aff4 (reference images) =="
  local base="https://raw.githubusercontent.com/aff4/ReferenceImages/master/AFF4Std"
  for f in Base-Linear.aff4 Base-Allocated.aff4 Base-Linear-ReadError.aff4 \
           Striped/Base-Linear_1.aff4 Striped/Base-Linear_2.aff4; do
    curl -sL "$base/$f" -o "$OUT/$(basename "$f")" && echo "got $(basename "$f")"
  done
}

build_btrfs
build_xfs
build_ntfs_compressed
build_apfs
build_hfsplus
build_aff4

echo "Done. Fixtures in $OUT"
echo "Note: VSS (vss_2003, vss_1_vol) and DFTT (#6/#7/#11) images come from the"
echo "dfir_ntfs and Digital Forensics Tool Testing projects; place them under"
echo "test_data/ as documented in the memory / validation notes."
