//! Reads a real SquashFS image built by `mksquashfs -comp gzip` and checks the
//! reader recovers the tree, file content, and a symlink target.
//!
//! The fixture `tests/fixtures/tree.sqfs` is committed, so this runs everywhere
//! (no `mksquashfs` needed at test time). Its tree:
//!   readme.txt      -> "hello squashfs\n"
//!   docs/note.txt   -> "nested content in a subdirectory\n"
//!   link.txt        -> symlink to readme.txt

use seance_core::data_source::DataSource;
use seance_plugin_squashfs::squashfs::{Compression, SquashReader};
use std::sync::Arc;

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tree.sqfs"
    ))
    .expect("read fixture")
}

/// Read a [`SquashEntry`]'s lazy content source to the end, the way every real
/// caller (hasher, search, content viewer) does — content is no longer
/// materialised eagerly during the walk, so tests read it explicitly.
fn read_all(ds: &Arc<dyn DataSource>) -> Vec<u8> {
    let mut out = vec![0u8; ds.size() as usize];
    let mut got = 0usize;
    while got < out.len() {
        match ds.read_at(got as u64, &mut out[got..]).expect("read_at") {
            0 => break,
            n => got += n,
        }
    }
    out.truncate(got);
    out
}

#[test]
fn reads_the_superblock() {
    let img = fixture();
    let r = SquashReader::open(Arc::from(img)).expect("open squashfs");
    assert_eq!(r.superblock().compression, Compression::Gzip);
    assert_eq!(r.superblock().block_size, 0x20000);
    assert!(r.superblock().inode_count >= 3);
}

#[test]
fn enumerates_the_tree_with_content_and_symlink() {
    let img = fixture();
    let r = SquashReader::open(Arc::from(img)).expect("open squashfs");
    let entries = r.entries(1024 * 1024).expect("walk tree");

    // The directory is present.
    assert!(
        entries.iter().any(|e| e.path == "docs" && e.is_dir),
        "docs/ directory must be listed; got {:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );

    // A top-level file with its exact content.
    let readme = entries
        .iter()
        .find(|e| e.path == "readme.txt")
        .expect("readme.txt present");
    assert!(!readme.is_dir);
    assert_eq!(
        read_all(readme.content.as_ref().expect("readme.txt has content")),
        b"hello squashfs\n"
    );

    // A nested file, reached by walking into the subdirectory.
    let note = entries
        .iter()
        .find(|e| e.path == "docs/note.txt")
        .expect("docs/note.txt present");
    assert_eq!(
        read_all(note.content.as_ref().expect("docs/note.txt has content")),
        b"nested content in a subdirectory\n"
    );

    // The symlink and its target.
    let link = entries
        .iter()
        .find(|e| e.path == "link.txt")
        .expect("link.txt present");
    assert!(link.is_symlink);
    assert_eq!(link.symlink_target.as_deref(), Some("readme.txt"));
}

#[test]
fn walks_an_extended_directory_with_an_index() {
    // `bigdir.sqfs` holds a directory of 2000 files, which mksquashfs stores as
    // an *extended* directory inode (type 8) with a directory index — a code
    // path the small fixture never reaches, and where the block_offset field
    // sits at a different offset than in a basic directory.
    let img = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bigdir.sqfs"
    ))
    .expect("read bigdir fixture");
    let r = SquashReader::open(Arc::from(img)).expect("open bigdir");
    let entries = r.entries(64 * 1024).expect("walk big tree");

    let files: Vec<_> = entries
        .iter()
        .filter(|e| e.path.starts_with("many/") && !e.is_dir)
        .collect();
    assert_eq!(
        files.len(),
        2000,
        "every file in the extended directory must list"
    );

    // A specific file's content proves the extended-dir entries resolve to the
    // right inodes, not just that the count is right.
    let marker = entries
        .iter()
        .find(|e| e.path == "many/file_1500.txt")
        .expect("file_1500.txt present");
    assert_eq!(
        read_all(marker.content.as_ref().expect("file_1500.txt has content")),
        b"marker payload for the extended-dir test\n"
    );
}

#[test]
fn extracts_content_from_an_extended_file_inode() {
    // A hard-linked file (nlink > 1) is stored as an *extended* regular inode
    // (type 9), whose `fragment` and `offset` fields sit at different offsets
    // than a basic file. Both names must resolve to the same content.
    let img = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/hardlink.sqfs"
    ))
    .expect("read hardlink fixture");
    let r = SquashReader::open(Arc::from(img)).expect("open hardlink");
    let entries = r.entries(64 * 1024).expect("walk");
    let expected = &b"extended-file content reached through a hard link\n"[..];
    for name in ["original.txt", "hardlink.txt"] {
        let e = entries
            .iter()
            .find(|e| e.path == name)
            .unwrap_or_else(|| panic!("{name} present"));
        assert_eq!(
            read_all(
                e.content
                    .as_ref()
                    .unwrap_or_else(|| panic!("{name} has content"))
            ),
            expected,
            "{name} content via the extended-file inode"
        );
    }
}

#[test]
fn extracts_a_file_with_full_data_blocks_and_a_fragment_tail() {
    // `big.bin` is 300,000 bytes with block_size 128 KiB → two full data blocks
    // plus a ~37 KiB fragment tail. Reconstructing it correctly requires the
    // data-block loop AND the fragment path (block_offset into the fragment
    // block) to both be right. Content is deterministic: byte i == i % 251.
    let img = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fragmented.sqfs"
    ))
    .expect("read fragmented fixture");
    let r = SquashReader::open(Arc::from(img)).expect("open fragmented");
    let entries = r.entries(4 * 1024 * 1024).expect("walk");

    let big = entries
        .iter()
        .find(|e| e.path == "big.bin")
        .expect("big.bin");
    let content = read_all(big.content.as_ref().expect("big.bin content"));
    assert_eq!(content.len(), 300_000, "full size reassembled");
    let expected: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        content, expected,
        "data blocks + fragment tail must be byte-exact"
    );

    // A small file stored entirely in a fragment (no full data blocks).
    let tiny = entries
        .iter()
        .find(|e| e.path == "tiny.txt")
        .expect("tiny.txt");
    assert_eq!(
        read_all(tiny.content.as_ref().expect("tiny.txt has content")),
        b"small file packed entirely into a fragment\n"
    );
}

#[test]
fn an_unsupported_codec_is_named_not_silently_empty() {
    use seance_plugin_squashfs::squashfs::SquashError;
    // Real zstd- and xz-compressed images. This build inflates only gzip; the
    // examiner must learn the image needs a codec, not that it held no files.
    for (name, codec) in [("zstd.sqfs", "zstd"), ("xz.sqfs", "xz")] {
        let img = std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_else(|e| panic!("read {name}: {e}"));
        match SquashReader::open(Arc::from(img)) {
            Err(SquashError::UnsupportedCompression(c)) => {
                assert_eq!(c, codec, "the error names the actual codec");
            }
            Err(other) => panic!("{name}: expected UnsupportedCompression({codec}), got {other}"),
            Ok(_) => panic!("{name}: expected UnsupportedCompression({codec}), but it opened"),
        }
    }
}

#[test]
fn a_large_file_gets_metadata_but_no_content_over_the_cap() {
    let img = fixture();
    let r = SquashReader::open(Arc::from(img)).expect("open squashfs");
    // A 0-byte cap means no file content is extracted, but the tree still lists.
    let entries = r.entries(0).expect("walk tree");
    let readme = entries.iter().find(|e| e.path == "readme.txt").unwrap();
    assert!(readme.content.is_none());
    assert_eq!(readme.size, "hello squashfs\n".len() as u64);
}
