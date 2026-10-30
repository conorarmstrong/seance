//! A real XFS v5 volume with files deleted by the Linux kernel, graded against
//! the ground truth recorded when it was made (HUNT-175).
//!
//! # The fixture
//!
//! `fixtures/xfs_v5_deleted.img.gz` is a 300 MiB volume made by `mkfs.xfs`
//! (xfsprogs defaults: v5, crc, finobt, sparse inodes, reflink, bigtime,
//! 4 AGs, 4 KiB blocks, 512-byte inodes) and populated inside an Ubuntu 24.04
//! guest (Linux 6.8.0-136) by `fixtures/xfs_v5_deleted.build.sh`: a shortform
//! directory, a single-block directory, a 400-entry multi-block directory and
//! a 200,000-byte file, then 13 files removed with `rm` and the volume
//! unmounted cleanly. `find -printf '%i\t%y\t%s\t%P'` was run before and after
//! the deletions; those listings are the `manifest_before`/`manifest_after`
//! files here. The internal log (64 MiB at AG 2 block 7) was zeroed before
//! compression — the parser never reads it, and the log still held copies of
//! the deleted names that no on-disk structure the parser reads does.
//!
//! What the kernel left, observed with `xfs_db` on the image: each freed
//! inode keeps its core (magic, uid, gid, atime, mtime, ctime, crtime,
//! generation) with `di_mode`, `di_size` and the extent count zeroed and the
//! data fork cleared, so a deleted file's name and times survive and its
//! content does not. A name removed from a block or leaf-form directory
//! survives inside the free region that replaced it; a name removed from a
//! shortform (inline) directory does not — the inline list is compacted.

use flate2::read::GzDecoder;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_xfs::XfsParser;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::Arc;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn image() -> Vec<u8> {
    let gz = std::fs::read(format!("{FIXTURES}/xfs_v5_deleted.img.gz")).expect("fixture");
    let mut out = Vec::new();
    GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("decompress");
    out
}

/// `path -> (inode, type)` from a `find -printf '%i\t%y\t%s\t%P'` listing.
fn manifest(which: &str) -> BTreeMap<String, (u64, String)> {
    std::fs::read_to_string(format!("{FIXTURES}/xfs_v5_deleted.manifest_{which}.tsv"))
        .expect("manifest")
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (!f[3].is_empty()).then(|| (format!("/{}", f[3]), (f[0].parse().unwrap(), f[1].into())))
        })
        .collect()
}

fn run(img: Vec<u8>) -> Vec<Artifact> {
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(src),
        json!({ "subtype": "xfs", "filesystem_type": "XFS" }),
    );
    XfsParser.process(&fs).expect("process")
}

fn is_deleted(a: &Artifact) -> bool {
    a.metadata.get("deleted") == Some(&json!(true))
}

fn deleted_paths(before: &BTreeMap<String, (u64, String)>) -> BTreeMap<String, u64> {
    let after = manifest("after");
    before
        .iter()
        .filter(|(p, _)| !after.contains_key(*p))
        .map(|(p, (ino, _))| (p.clone(), *ino))
        .collect()
}

#[test]
fn the_live_inventory_is_exactly_the_volume_after_the_deletions() {
    let out = run(image());
    let live: BTreeSet<String> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry && !is_deleted(a))
        .filter_map(|a| a.metadata["path"].as_str().map(str::to_string))
        .filter(|p| p != "/")
        .collect();
    let expected: BTreeSet<String> = manifest("after").into_keys().collect();
    assert_eq!(live, expected);
}

/// The ten names removed from block- and leaf-form directories survive in the
/// free regions that replaced them, and each is recovered with the inode
/// number the manifest recorded for it before the deletion.
#[test]
fn names_removed_from_block_and_leaf_directories_are_recovered() {
    let out = run(image());
    let gone = deleted_paths(&manifest("before"));
    assert_eq!(gone.len(), 13);

    let recovered: BTreeMap<String, &Artifact> = out
        .iter()
        .filter(|a| is_deleted(a))
        .filter(|a| a.metadata["deleted_recovery_source"] == "xfs_directory_free_space")
        .map(|a| (a.metadata["path"].as_str().unwrap().to_string(), a))
        .collect();

    let expected: BTreeSet<&String> = gone
        .keys()
        .filter(|p| p.starts_with("/block/") || p.starts_with("/leaf/"))
        .collect();
    assert_eq!(expected.len(), 10);
    assert_eq!(
        recovered.keys().collect::<BTreeSet<_>>(),
        expected,
        "every name removed from a block/leaf directory, and nothing else"
    );
    for (path, a) in &recovered {
        assert_eq!(a.metadata["inode"], gone[path], "{path}");
        assert_eq!(a.artifact_type, ArtifactType::FileEntry);
        assert!(a.data.is_none(), "{path}: no content is claimed");
        assert_eq!(a.metadata["content_incomplete"], true, "{path}");
        // The freed inode it names is still an unallocated inode, so its
        // surviving times are read and the record says the inode is free.
        assert_eq!(a.metadata["inode_state"], "free", "{path}");
        assert!(a.metadata["changed"].as_str().is_some(), "{path}");
    }
}

/// Every inode freed by the deletions is found by walking the inode B+tree,
/// including the three whose names went with a compacted shortform directory.
#[test]
fn every_freed_inode_is_recovered_once_named_where_a_name_survives() {
    let out = run(image());
    let gone = deleted_paths(&manifest("before"));
    let gone_inodes: BTreeSet<u64> = gone.values().copied().collect();

    let freed: Vec<&Artifact> = out
        .iter()
        .filter(|a| is_deleted(a))
        .filter(|a| a.metadata["deleted_recovery_source"] == "xfs_freed_inode")
        .collect();
    let freed_inodes: BTreeSet<u64> = freed
        .iter()
        .map(|a| a.metadata["inode"].as_u64().unwrap())
        .collect();
    let named: BTreeSet<u64> = out
        .iter()
        .filter(|a| a.metadata["deleted_recovery_source"] == "xfs_directory_free_space")
        .map(|a| a.metadata["inode"].as_u64().unwrap())
        .collect();

    // A freed inode whose name was recovered is reported once, on the name.
    assert_eq!(
        freed_inodes.union(&named).copied().collect::<BTreeSet<_>>(),
        gone_inodes
    );
    assert!(freed_inodes.is_disjoint(&named));
    assert_eq!(freed.len(), 3, "the three shortform deletions");
    for a in freed {
        assert!(a.metadata["name"].is_null(), "no name is invented");
        assert!(a.metadata["path"].is_null());
        assert_eq!(a.metadata["name_recovered"], false);
        assert!(a.metadata["modified"].as_str().is_some());
    }
}

/// XFS inode 128 is this volume's root; with its magic destroyed the walk
/// cannot start, and the file system record must say so rather than read as
/// a volume that holds no files.
#[test]
fn an_unreadable_root_inode_is_flagged_on_the_file_system_record() {
    let mut img = image();
    // Root inode 128: AG 0, 8 inodes per 4 KiB block, so block 16, slot 0.
    assert_eq!(&img[65536..65538], b"IN");
    img[65536..65538].copy_from_slice(b"\0\0");

    let out = run(img);
    let fs = &out[0];
    assert_eq!(fs.artifact_type, ArtifactType::FileSystem);
    assert_eq!(fs.metadata["inventory_incomplete"], true, "{}", fs.metadata);
    assert_eq!(
        fs.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(fs.metadata["inventory_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("root inode"));
}

/// The `block` directory is this volume's one single-block (`XDB3`)
/// directory: file system block 19,215. Its tail records 43 leaf entries, so
/// the leaf array starts at byte 3,744 of the block, and the last free region
/// (1,056 + 2,688) ends exactly there.
const BLOCK_DIR_AT: usize = 19_215 * 4096;

/// HUNT-234. The entry scan of a single-block directory stopped only on a
/// zero inode or name length, never at the leaf array the block's tail
/// bounds. On a sound block it halts there by luck — the first leaf's ninth
/// byte is the zero high byte of the `..` hash — but a free region whose
/// length runs past the leaf array (here by one leaf entry, a single damaged
/// field) walked into the leaf bytes and read hash/address pairs as a
/// directory entry. The scan now ends where the tail says the entries end.
#[test]
fn a_single_block_directory_is_scanned_only_up_to_its_leaf_array() {
    let mut img = image();
    let b = &mut img[BLOCK_DIR_AT..BLOCK_DIR_AT + 4096];
    assert_eq!(&b[0..4], b"XDB3");
    assert_eq!(u32::from_be_bytes(b[4088..4092].try_into().unwrap()), 43);
    // The last free region: tag 0xFFFF, length 2,688, ending at the leaf array.
    assert_eq!(&b[1056..1060], &[0xFF, 0xFF, 0x0A, 0x80]);
    b[1058..1060].copy_from_slice(&(2688u16 + 8).to_be_bytes());

    let out = run(img);
    let dir = out
        .iter()
        .find(|a| a.metadata["path"] == "/block" && a.artifact_type == ArtifactType::FileEntry)
        .expect("the block directory");
    assert!(
        dir.metadata.get("directory_parse_incomplete").is_none(),
        "leaf bytes were read as an entry: {}",
        dir.metadata
    );
    let live: BTreeSet<String> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry && !is_deleted(a))
        .filter_map(|a| a.metadata["path"].as_str().map(str::to_string))
        .filter(|p| p != "/")
        .collect();
    let expected: BTreeSet<String> = manifest("after").into_keys().collect();
    assert_eq!(live, expected, "no entry made of leaf bytes");
}
