set -eu
sudo umount /mnt/x 2>/dev/null || true
sudo mkfs.xfs -f -q /dev/vdb
sudo mkdir -p /mnt/x && sudo mount /dev/vdb /mnt/x && sudo chown ubuntu /mnt/x
cd /mnt/x
# shortform directory: a few small entries
mkdir short
for n in alpha bravo charlie delta; do printf "short %s content\n" $n > short/$n.txt; done
# block-form directory: ~40 entries fits one 4K block
mkdir block
for i in $(seq 1 40); do printf "block file %02d body\n" $i > block/file_$i.dat; done
# multi-block (leaf) directory: 400 entries with long names
mkdir leaf
for i in $(seq 1 400); do printf "leaf %03d\n" $i > leaf/a_fairly_long_file_name_to_fill_blocks_$i.log; done
# multi-extent file content
head -c 200000 /dev/urandom > block/big.bin
printf "top level survivor\n" > survivor.txt
printf "top level doomed\n" > doomed.txt
sync
# ground truth before deletion
find /mnt/x -xdev -printf '%i\t%y\t%s\t%P\n' | sort -k4 > /tmp/manifest_before.tsv
( cd /mnt/x && find . -type f -print0 | xargs -0 sha256sum ) | sort -k2 > /tmp/sha_before.txt
# deletions
rm short/bravo.txt short/delta.txt
rm block/file_7.dat block/file_8.dat block/file_23.dat block/big.bin
for i in 5 6 7 100 250 399; do rm leaf/a_fairly_long_file_name_to_fill_blocks_$i.log; done
rm doomed.txt
sync
find /mnt/x -xdev -printf '%i\t%y\t%s\t%P\n' | sort -k4 > /tmp/manifest_after.tsv
cd / && sudo umount /mnt/x
sudo xfs_info /dev/vdb
