//! HUNT-252: every inode of a real v5 (CRC-enabled) XFS volume passes the XFS
//! carving signature's header check.
//!
//! The volume is `seance_plugin_xfs/tests/fixtures/xfs_v5_deleted.img.gz`
//! (made by mkfs.xfs on a Linux 6.8 guest, see its `build.sh`): 512-byte
//! version 3 inodes, 576 of them allocated in its inode chunks (regular files,
//! directories and free slots). This is real evidence for the mechanism on one
//! mkfs.xfs default layout; it does not cover 1024/2048-byte inodes, which the
//! 512-byte carving block cannot CRC-verify.

use flate2::read::GzDecoder;
use seance_carving::signature::DataCheckResult;
use seance_carving::{formats, FileRecovery, SignatureRegistry};
use std::io::Read;

#[test]
fn every_inode_of_a_real_v5_volume_passes_the_xfs_header_check() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../seance_plugin_xfs/tests/fixtures/xfs_v5_deleted.img.gz"
    );
    let mut img = Vec::new();
    GzDecoder::new(std::fs::File::open(path).expect("fixture present"))
        .read_to_end(&mut img)
        .expect("gunzip");

    let mut registry = SignatureRegistry::new();
    formats::register_all(&mut registry);

    let (mut inodes, mut accepted) = (0usize, 0usize);
    for block in img.as_chunks::<512>().0 {
        if !(block.starts_with(b"IN") && block[4] == 3) {
            continue;
        }
        inodes += 1;
        let xfs = registry
            .find_matches(block)
            .into_iter()
            .find(|(sig, off)| sig.name() == "XFS" && *off == 0);
        let Some((sig, _)) = xfs else { continue };
        let Some(init) = sig.header_check(block, 0) else {
            continue;
        };
        let mut rec = FileRecovery::from_init(&init, 0);
        if sig.data_check(block, &mut rec) != DataCheckResult::Error {
            accepted += 1;
        }
    }
    assert_eq!(inodes, 576, "v3 inode blocks in the volume");
    assert_eq!(accepted, inodes, "v3 inodes the XFS signature accepts");
}
