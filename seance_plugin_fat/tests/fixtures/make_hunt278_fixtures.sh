#!/bin/bash
# HUNT-278 SYNTHETIC FAT16 volumes, built with mkfs.fat and mtools. They grade
# the parser on a known layout; they say nothing about real-world evidence.
# Usage: make_hunt278_fixtures.sh OUTDIR   (writes *.raw.gz; mtools stamps the
# current time, so a rebuild differs byte for byte but not in layout.)
set -euo pipefail
out=${1:?outdir}
mkdir -p "$out"
here=$(cd "$(dirname "$0")" && pwd)
export MTOOLS_SKIP_CHECK=1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

new() { # name
  dd if=/dev/zero of="$work/$1.img" bs=1M count=4 status=none
  mkfs.fat -F 16 -s 1 -n HUNT278 "$work/$1.img" >/dev/null
}
empties() { # img dir from to : empty files with long names
  for i in $(seq "$3" "$4"); do
    : > "$work/e"
    mcopy -i "$1" "$work/e" "::/$2/Recovered Long Name $(printf %02d "$i").txt"
  done
}
text() { # file bytes : text that is not a directory entry
  python3 -c "import sys;sys.stdout.write(('the quick brown fox jumps over the lazy dog. ' * 40)[:int(sys.argv[1])])" "$2" > "$1"
}

# A: 40 empty long-named files in D (several 512 B clusters), then D deleted.
new a
mmd -i "$work/a.img" ::/KEEP
mmd -i "$work/a.img" ::/D
empties "$work/a.img" D 1 40
mdeltree -i "$work/a.img" ::/D

# A2: D fills its first cluster, a text file is written then deleted into the
# clusters that follow (so the next cluster is free but holds file bytes), D then
# grows non-contiguously, then D is deleted.
new a2
mmd -i "$work/a2.img" ::/D
empties "$work/a2.img" D 1 4
text "$work/t.txt" 1200
mcopy -i "$work/a2.img" "$work/t.txt" ::/filler.txt
empties "$work/a2.img" D 5 12
mdel -i "$work/a2.img" ::/filler.txt
mdeltree -i "$work/a2.img" ::/D

# B: a decoy directory E is made and deleted first, so the file written after D
# is deleted takes E's root slot and clusters 2 and 3, and D's own root entry
# survives with its first cluster (3) now belonging to that file.
new b
mmd -i "$work/b.img" ::/E
mmd -i "$work/b.img" ::/D
empties "$work/b.img" D 1 6
mdeltree -i "$work/b.img" ::/E
mdeltree -i "$work/b.img" ::/D
text "$work/t.txt" 900
mcopy -i "$work/b.img" "$work/t.txt" ::/reused.txt

# C: live directory S with a 0x00 planted mid-directory, entries left behind it.
new c
mmd -i "$work/c.img" ::/S
for n in ONE TWO THREE FOUR FIVE SIX SEVEN; do
  : > "$work/e"
  mcopy -i "$work/c.img" "$work/e" "::/S/$n.TXT"
done
mmd -i "$work/c.img" ::/Z
: > "$work/e"
mcopy -i "$work/c.img" "$work/e" ::/Z/ZERO.TXT
python3 "$here/plant_hunt278_slack.py" "$work/c.img"

# D: exFAT. mkfs.exfat base volume (8 MiB, 512 B clusters), then the stdlib
# writer adds /DIR with six entry sets and deletes it. fsck.exfat -n is run on
# the live layout the writer produced before it deletes anything: that is the
# check that the structure being deleted is a valid exFAT directory.
truncate -s 8M "$work/exbase.img"
mkfs.exfat -c 512 -L HUNT278 "$work/exbase.img" >/dev/null
python3 "$here/make_hunt278_exfat.py" "$work/exbase.img" "$work/d.img"
fsck.exfat -n "$work/d.img.live.img"

# E: the shape Linux's vfat leaves (VALIDATION.md LINUX-FAT-1): long-named files whose name slots straddle
# a 512 B directory cluster, the directory growing around 50 KB of file data, then deleted whole. Names are 57
# characters (5 name slots and the short entry), so a name starts in one cluster and ends in the next.
new e
mmd -i "$work/e.img" ::/DirD
longname() { printf 'Quarterly-report-DirD-%03d-with-a-long-descriptive-name.txt' "$1"; }
for i in $(seq 1 40); do echo "DirD $i" > "$work/e.txt"; mcopy -i "$work/e.img" "$work/e.txt" "::/DirD/$(longname "$i")"; done
head -c 51200 /dev/zero | tr '\0' 'x' > "$work/filler.bin"
mcopy -i "$work/e.img" "$work/filler.bin" ::/filler.bin
for i in $(seq 41 100); do echo "DirD $i" > "$work/e.txt"; mcopy -i "$work/e.img" "$work/e.txt" "::/DirD/$(longname "$i")"; done
mdeltree -i "$work/e.img" ::/DirD

for f in a a2 b c d e; do
  gzip -9n -c "$work/$f.img" > "$out/hunt278_$([ $f = d ] && echo exfat || echo fat16_$f).raw.gz"
done
sha256sum "$out"/hunt278_fat16_*.raw.gz
