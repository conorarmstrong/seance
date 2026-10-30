//! Unit tests for the F2FS parser.
//!
//! Each test builds a minimal, hand-laid F2FS image in memory (a superblock, a
//! single NAT block, a handful of inode blocks and dentry blocks) over an
//! in-memory `DataSource`, then drives the real parser and asserts on the
//! emitted `FileEntry` artifacts. No real image is required.

use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use std::sync::Arc;
use uuid::Uuid;

const BLOCK: usize = 4096;

// --- In-memory data source ---

use seance_core::data_source::ByteSliceDataSource;

// --- Little-endian image builder ---

struct Builder {
    data: Vec<u8>,
}

impl Builder {
    fn new(blocks: usize) -> Self {
        Self {
            data: vec![0u8; blocks * BLOCK],
        }
    }
    fn put(&mut self, off: usize, bytes: &[u8]) {
        self.data[off..off + bytes.len()].copy_from_slice(bytes);
    }
    fn put_u16(&mut self, off: usize, v: u16) {
        self.put(off, &v.to_le_bytes());
    }
    fn put_u32(&mut self, off: usize, v: u32) {
        self.put(off, &v.to_le_bytes());
    }
    fn put_u64(&mut self, off: usize, v: u64) {
        self.put(off, &v.to_le_bytes());
    }
}

// Superblock field offsets are relative to F2FS_SUPER_OFFSET (byte 1024).
const SB: usize = F2FS_SUPER_OFFSET as usize;

/// Write a standard 4 KiB-block superblock: NAT at block 4, root inode = 3.
fn write_superblock(b: &mut Builder) {
    b.put_u32(SB, F2FS_MAGIC); // magic @0
    b.put_u32(SB + 16, 12); // log_blocksize -> 4096
    b.put_u32(SB + 20, 9); // log_blocks_per_seg -> 512 blocks/seg
    b.put_u32(SB + 84, 4); // nat_blkaddr = block 4
    b.put_u32(SB + 96, 3); // root_ino = 3
    b.put_u32(SB + 100, 1); // node_ino
    b.put_u32(SB + 104, 2); // meta_ino
    b.put_u32(SB + 2180, 0); // feature = 0 (no extra_attr)
}

/// Write a NAT entry mapping node id `nid` -> physical `block_addr`.
/// With bitmap assumed 0 and nid < 455, the entry lives at
/// `nat_blkaddr*BLOCK + nid*9`.
fn write_nat(b: &mut Builder, nat_blkaddr: usize, nid: u32, block_addr: u32) {
    let off = nat_blkaddr * BLOCK + (nid as usize) * (NAT_ENTRY_SIZE as usize);
    b.put(off, &[1]); // version
    b.put_u32(off + 1, nid); // ino
    b.put_u32(off + 5, block_addr); // block_addr
}

/// Write a directory inode with a single data block at `data_block`.
fn write_dir_inode(b: &mut Builder, block_addr: usize, size: u64, data_block: u32) {
    let base = block_addr * BLOCK;
    b.put_u16(base, 0x41ED); // mode: S_IFDIR | 0755
    b.put(base + 3, &[0]); // i_inline = 0
    b.put_u64(base + 16, size); // i_size
    b.put_u64(base + 48, 1_600_000_000); // i_mtime
    b.put_u32(base + 360, data_block); // i_addr[0]
}

/// Write a regular file inode whose data lives inline in the inode.
fn write_inline_file_inode(b: &mut Builder, block_addr: usize, content: &[u8]) {
    let base = block_addr * BLOCK;
    b.put_u16(base, 0x81A4); // mode: S_IFREG | 0644
    b.put(base + 3, &[F2FS_INLINE_DATA]); // i_inline = INLINE_DATA
    b.put_u64(base + 16, content.len() as u64); // i_size
    b.put_u64(base + 48, 1_600_000_000);
    // inline data begins one reserved __le32 slot past i_addr[0] -> byte 364.
    b.put(base + 364, content);
}

/// Write a regular file inode with two contiguous data blocks.
fn write_block_file_inode(b: &mut Builder, block_addr: usize, size: u64, data0: u32, data1: u32) {
    let base = block_addr * BLOCK;
    b.put_u16(base, 0x81A4); // mode: S_IFREG | 0644
    b.put(base + 3, &[0]);
    b.put_u64(base + 16, size);
    b.put_u64(base + 48, 1_600_000_000);
    b.put_u32(base + 360, data0); // i_addr[0]
    b.put_u32(base + 364, data1); // i_addr[1]
}

/// Write one dir entry (slot `bit`) into a dentry block whose block starts at
/// byte `block_base`. Also sets the corresponding bitmap bits.
fn write_dentry(
    b: &mut Builder,
    block_base: usize,
    bit: usize,
    ino: u32,
    name: &[u8],
    file_type: u8,
) {
    let de = block_base + DENTRY_BLOCK_DENTRY_OFF + bit * SIZE_OF_DIR_ENTRY;
    b.put_u32(de + 4, ino);
    b.put_u16(de + 8, name.len() as u16);
    b.put(de + 10, &[file_type]);
    let name_off = block_base + DENTRY_BLOCK_FILENAME_OFF + bit * F2FS_SLOT_LEN;
    b.put(name_off, name);
    // Set one bitmap bit per occupied slot (little-endian bit order).
    let slots = name.len().div_ceil(F2FS_SLOT_LEN).max(1);
    for s in 0..slots {
        let idx = bit + s;
        b.data[block_base + idx / 8] |= 1 << (idx % 8);
    }
}

/// Build the full synthetic image described by the module tests and return a
/// `FileSystem` artifact over it.
fn build_image() -> (Artifact, Arc<ByteSliceDataSource>) {
    // Layout (block numbers): NAT=4, root inode=100, subdir inode=101,
    // hello.txt inode=102, nested.bin inode=103, root dentry=200,
    // subdir dentry=201, nested.bin data=300,301.
    let mut b = Builder::new(320);
    write_superblock(&mut b);

    write_nat(&mut b, 4, 3, 100); // root
    write_nat(&mut b, 4, 4, 101); // subdir
    write_nat(&mut b, 4, 5, 102); // hello.txt
    write_nat(&mut b, 4, 6, 103); // nested.bin

    write_dir_inode(&mut b, 100, BLOCK as u64, 200); // root -> dentry block 200
    write_dir_inode(&mut b, 101, BLOCK as u64, 201); // subdir -> dentry block 201
    write_inline_file_inode(&mut b, 102, b"hello world!"); // 12 bytes inline
    write_block_file_inode(&mut b, 103, 5000, 300, 301); // 5000 bytes, blocks 300,301

    // Root dentry block: ".", "..", "subdir" (dir), "hello.txt" (file).
    let root_dent = 200 * BLOCK;
    write_dentry(&mut b, root_dent, 0, 3, b".", 2);
    write_dentry(&mut b, root_dent, 1, 3, b"..", 2);
    write_dentry(&mut b, root_dent, 2, 4, b"subdir", 2);
    write_dentry(&mut b, root_dent, 3, 5, b"hello.txt", 1);

    // Subdir dentry block: ".", "..", "nested.bin" (file).
    let sub_dent = 201 * BLOCK;
    write_dentry(&mut b, sub_dent, 0, 4, b".", 2);
    write_dentry(&mut b, sub_dent, 1, 3, b"..", 2);
    write_dentry(&mut b, sub_dent, 2, 6, b"nested.bin", 1);

    // nested.bin data: first block all 'A', second block all 'B'.
    b.put(300 * BLOCK, &[b'A'; BLOCK]);
    b.put(301 * BLOCK, &[b'B'; BLOCK]);

    let source = Arc::new(ByteSliceDataSource::new(b.data));
    let metadata = json!({
        "subtype": "f2fs",
        "filesystem_type": "F2FS",
        "offset_bytes": 0,
        "size_bytes": source.size(),
    });
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source.clone() as Arc<dyn DataSource>),
        metadata,
    );
    (artifact, source)
}

fn find<'a>(entries: &'a [Artifact], name: &str) -> &'a Artifact {
    entries
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("no FileEntry named {:?}", name))
}

#[test]
fn parses_tree_files_and_dirs() {
    let (artifact, _src) = build_image();
    let out = F2fsParser::new().process(&artifact).expect("process ok");

    // root + subdir + hello.txt + nested.bin
    assert_eq!(out.len(), 4, "expected 4 entries, got {}", out.len());
    for a in &out {
        assert_eq!(a.artifact_type, ArtifactType::FileEntry);
        assert_eq!(a.parent_id, Some(artifact.id));
    }

    // Directory
    let subdir = find(&out, "subdir");
    assert_eq!(subdir.metadata["is_directory"], json!(true));
    assert_eq!(subdir.metadata["path"], json!("/subdir"));

    // Inline-data file: content re-served from resident_data_b64 and the source.
    let hello = find(&out, "hello.txt");
    assert_eq!(hello.metadata["is_directory"], json!(false));
    assert_eq!(hello.metadata["size"], json!(12));
    assert_eq!(hello.metadata["path"], json!("/hello.txt"));
    let b64 = hello.metadata["resident_data_b64"].as_str().unwrap();
    let decoded = BASE64.decode(b64).unwrap();
    assert_eq!(decoded, b"hello world!");
    // The attached data source serves the same bytes.
    let ds = hello.data.as_ref().unwrap();
    let mut buf = vec![0u8; 12];
    let n = ds.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello world!");

    // Block-mapped file nested inside subdir: data_runs resolve + coalesce to a
    // single run clamped to the exact file size.
    let nested = find(&out, "nested.bin");
    assert_eq!(nested.metadata["is_directory"], json!(false));
    assert_eq!(nested.metadata["size"], json!(5000));
    assert_eq!(nested.metadata["path"], json!("/subdir/nested.bin"));
    assert_eq!(nested.metadata["parent_path"], json!("/subdir"));
    // block 300 * 4096 = 1228800, contiguous with block 301, clamped to 5000.
    assert_eq!(
        nested.metadata["data_runs"],
        json!([[1_228_800u64, 5000u64]])
    );
    assert_eq!(nested.metadata["data_runs_complete"], json!(true));
    // Content: 4096 'A' from block 300, then 904 'B' from block 301.
    let ds = nested.data.as_ref().unwrap();
    assert_eq!(ds.size(), 5000);
    let mut buf = vec![0u8; 5000];
    let n = ds.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 5000);
    assert!(buf[..4096].iter().all(|&x| x == b'A'));
    assert!(buf[4096..5000].iter().all(|&x| x == b'B'));
}

#[test]
fn ignores_non_f2fs_filesystem() {
    let (mut artifact, _src) = build_image();
    // Re-tag the same (valid F2FS) volume as ext4: the gate must skip it.
    artifact.metadata = json!({
        "subtype": "ext4",
        "filesystem_type": "ext4",
    });
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    assert!(out.is_empty(), "non-f2fs artifact must yield nothing");
}

#[test]
fn garbage_input_returns_ok_no_panic() {
    // Claims to be f2fs but the bytes are junk: parser must return Ok(empty).
    let source = Arc::new(ByteSliceDataSource::new(vec![0x5A; 512]));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source as Arc<dyn DataSource>),
        json!({ "subtype": "f2fs", "filesystem_type": "F2FS" }),
    );
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    // HUNT-173: not an empty list -- that reads as "a volume with no files".
    assert!(!out
        .iter()
        .any(|a| a.artifact_type == ArtifactType::FileEntry));
    let status = walk_summary(&out);
    assert_eq!(status["walked"], false);
    assert_eq!(status["inventory_incomplete"], true);
}

#[test]
fn truncated_after_superblock_reports_an_unwalked_volume() {
    // Valid superblock but the image ends before the NAT / inodes: the root
    // lookup fails. The parser must not panic, and must not return an empty
    // list either — an empty list reads as "this volume held no files", which
    // is a claim we cannot make about a tree we never walked (B7-010).
    let mut b = Builder::new(2); // 8 KiB: superblock only
    write_superblock(&mut b);
    let source = Arc::new(ByteSliceDataSource::new(b.data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source as Arc<dyn DataSource>),
        json!({ "subtype": "f2fs" }),
    );
    let out = F2fsParser::new().process(&artifact).expect("process ok");

    assert!(
        !out.iter()
            .any(|a| a.artifact_type == ArtifactType::FileEntry),
        "no file may be invented from an unreadable tree"
    );
    let summary = walk_summary(&out);
    assert_eq!(summary["files_emitted"], 0);
    assert_eq!(summary["unresolved_inodes"], 1, "the root inode itself");
    assert_eq!(summary["inventory_incomplete"], true);
    assert_eq!(
        summary["inventory_incomplete_reason"],
        "unresolved_structure"
    );
}

/// The single `f2fs_walk_status` record, or a panic naming what was returned.
fn walk_summary(out: &[Artifact]) -> &serde_json::Value {
    out.iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("f2fs_walk_status"))
        .map(|a| &a.metadata)
        .unwrap_or_else(|| {
            panic!(
                "an incomplete f2fs walk must publish a walk summary; got {} artifact(s)",
                out.len()
            )
        })
}

#[test]
fn empty_data_source_errors_gracefully() {
    // subtype says f2fs but there is no data source at all.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        None,
        json!({ "subtype": "f2fs" }),
    );
    // Missing data source is an InvalidInputFormat error, not a panic.
    assert!(F2fsParser::new().process(&artifact).is_err());
}

#[test]
fn superblock_short_read_fails_closed() {
    // Valid magic + log_blocksize are present at the head, but the source is
    // truncated well before the later fields (feature @2180). The parser must
    // fail closed rather than read the zero-filled tail as real geometry.
    let mut data = vec![0u8; 2000];
    data[SB..SB + 4].copy_from_slice(&F2FS_MAGIC.to_le_bytes());
    data[SB + 16..SB + 20].copy_from_slice(&12u32.to_le_bytes());
    let src = ByteSliceDataSource::new(data);
    assert!(
        Superblock::parse(&src).is_err(),
        "a truncated superblock window must fail closed"
    );
}

#[test]
fn superblock_full_read_parses() {
    // Control: a full-size superblock window parses successfully via the
    // short-read fill loop.
    let mut b = Builder::new(2); // 8 KiB: covers 1024 + 4096 comfortably
    write_superblock(&mut b);
    let src = ByteSliceDataSource::new(b.data);
    let sb = Superblock::parse(&src).expect("full superblock parses");
    assert_eq!(sb.nat_blkaddr, 4);
    assert_eq!(sb.root_ino, 3);
}

#[test]
fn inode_flags_detect_fscrypt_and_compression() {
    // An fscrypt-encrypted, compressed regular-file inode must expose both
    // markers so the emitted FileEntry can flag ciphertext/compressed content
    // (BUG-165).
    let mut raw = vec![0u8; BLOCK];
    raw[0..2].copy_from_slice(&0x8000u16.to_le_bytes()); // i_mode = S_IFREG
    raw[2] = FADVISE_ENCRYPT_BIT; // i_advise: fscrypt
    raw[80..84].copy_from_slice(&F2FS_COMPR_FL.to_le_bytes()); // i_flags: compressed

    let inode = Inode::parse(raw, 0);
    assert!(inode.is_file());
    assert!(
        inode.is_encrypted(),
        "FADVISE_ENCRYPT_BIT must flag fscrypt"
    );
    assert!(inode.is_compressed(), "F2FS_COMPR_FL must flag compression");

    // A plain regular file carries neither flag.
    let mut plain = vec![0u8; BLOCK];
    plain[0..2].copy_from_slice(&0x8000u16.to_le_bytes());
    let plain = Inode::parse(plain, 0);
    assert!(!plain.is_encrypted());
    assert!(!plain.is_compressed());
}

#[test]
fn partial_inode_block_is_not_parsed() {
    // BUG-244: the image ends 8 bytes into the root inode block. i_mode still
    // reads as a directory, but i_size and every block pointer would come from
    // the pre-zeroed buffer tail — a fabricated empty directory presented as a
    // real one. A partial inode block must be rejected outright.
    let (_full, src) = build_image();
    let mut data = src.resident_bytes().expect("in-memory image").to_vec();
    data.truncate(100 * BLOCK + 8);

    let source = Arc::new(ByteSliceDataSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source as Arc<dyn DataSource>),
        json!({ "subtype": "f2fs", "filesystem_type": "F2FS" }),
    );

    let out = F2fsParser::new().process(&artifact).expect("process ok");
    let files = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    assert_eq!(
        files, 0,
        "a partially read inode block must not become a FileEntry"
    );
    // Rejecting it is only half the contract: the rejection has to be visible,
    // or the volume reads as an empty directory tree rather than an unread one.
    let summary = walk_summary(&out);
    assert_eq!(summary["unresolved_inodes"], 1);
    assert_eq!(summary["inventory_incomplete"], true);
    assert_eq!(
        summary["inventory_incomplete_reason"],
        "unresolved_structure"
    );
}

// ============================================================================
// B2-066: an unresolvable node subtree must not shift the blocks after it
// ============================================================================

/// B2-066: a subtree the walk cannot resolve (NAT miss, node block off the end
/// of the image, short read, budget exhausted) used to return without reserving
/// its slice of the file's logical block space. Every later `i_nid` subtree then
/// slid leftward, so the file's surviving bytes were reported at offsets they
/// never occupied — and the result still hashed cleanly. The subtree's span must
/// be held open as holes and the file marked incomplete.
#[test]
fn an_unresolvable_node_subtree_holds_its_place_instead_of_shifting_later_blocks() {
    // Blocks: 0..3 misc, 4 = NAT, 20 = direct node for nid 11.
    let mut b = Builder::new(32);
    write_superblock(&mut b);
    // nid 10 resolves to a node block far past the end of the image.
    write_nat(&mut b, 4, 10, 10_000);
    // nid 11 is a real direct node whose first data pointer is block 0x1234.
    write_nat(&mut b, 4, 11, 20);
    b.put_u32(20 * BLOCK, 0x1234);

    let sb = Superblock {
        block_size: BLOCK as u64,
        blocks_per_seg: 512,
        nat_blkaddr: 4,
        root_ino: 3,
        feature: 0,
    };

    let mut raw = vec![0u8; BLOCK];
    raw[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
    raw[INODE_I_NID_OFF..INODE_I_NID_OFF + 4].copy_from_slice(&10u32.to_le_bytes());
    raw[INODE_I_NID_OFF + 4..INODE_I_NID_OFF + 8].copy_from_slice(&11u32.to_le_bytes());
    let inode = Inode::parse(raw, 0);

    let source = ByteSliceDataSource::new(b.data);
    let capped = (inode.addrs_per_inode + 2 * ADDRS_PER_BLOCK) as u64;
    let mut complete = true;
    let addrs = collect_addrs(&source, &sb, &inode, capped, &mut complete);

    assert!(
        !complete,
        "an unresolvable subtree makes the run list incomplete"
    );
    let second_subtree = inode.addrs_per_inode + ADDRS_PER_BLOCK;
    assert!(
        addrs.len() > second_subtree,
        "both subtrees must occupy logical space, got {} addresses",
        addrs.len()
    );
    assert!(
        addrs[inode.addrs_per_inode..second_subtree]
            .iter()
            .all(|&a| a == NULL_ADDR),
        "the unresolved subtree's span must be reserved as holes"
    );
    assert_eq!(
        addrs[second_subtree], 0x1234,
        "the next subtree must keep its own logical offset, not slide into the gap"
    );
}

/// The same walk with both subtrees resolvable stays complete and puts each
/// pointer where it belongs — the success path of the check above.
#[test]
fn resolvable_node_subtrees_report_complete_and_keep_their_offsets() {
    let mut b = Builder::new(32);
    write_superblock(&mut b);
    write_nat(&mut b, 4, 10, 19);
    write_nat(&mut b, 4, 11, 20);
    b.put_u32(19 * BLOCK, 0x1111);
    b.put_u32(20 * BLOCK, 0x1234);

    let sb = Superblock {
        block_size: BLOCK as u64,
        blocks_per_seg: 512,
        nat_blkaddr: 4,
        root_ino: 3,
        feature: 0,
    };

    let mut raw = vec![0u8; BLOCK];
    raw[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
    raw[INODE_I_NID_OFF..INODE_I_NID_OFF + 4].copy_from_slice(&10u32.to_le_bytes());
    raw[INODE_I_NID_OFF + 4..INODE_I_NID_OFF + 8].copy_from_slice(&11u32.to_le_bytes());
    let inode = Inode::parse(raw, 0);

    let source = ByteSliceDataSource::new(b.data);
    let capped = (inode.addrs_per_inode + 2 * ADDRS_PER_BLOCK) as u64;
    let mut complete = true;
    let addrs = collect_addrs(&source, &sb, &inode, capped, &mut complete);

    assert!(complete, "both subtrees resolved");
    assert_eq!(addrs[inode.addrs_per_inode], 0x1111);
    assert_eq!(addrs[inode.addrs_per_inode + ADDRS_PER_BLOCK], 0x1234);
}

/// B2-155: a directory whose dentry block cannot be read loses those names.
/// The `complete` flag `collect_addrs` already produced was computed and then
/// discarded, so the short listing was published as the directory's full
/// contents — and an examiner reads "not in this directory" as fact.
#[test]
fn a_directory_whose_dentry_block_is_unreadable_says_so() {
    let (artifact, _src) = build_image();
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    let root = out
        .iter()
        .find(|a| a.metadata.get("path").and_then(|v| v.as_str()) == Some("/"))
        .expect("root directory entry");
    assert!(
        root.metadata.get("directory_parse_incomplete").is_none(),
        "a fully read directory must not be flagged, or the flag means nothing"
    );

    // Same image, but subdir's dentry block address points past the end of the
    // volume: its entries are unreadable, not absent.
    let mut b = Builder::new(320);
    write_superblock(&mut b);
    write_nat(&mut b, 4, 3, 100);
    write_nat(&mut b, 4, 4, 101);
    write_nat(&mut b, 4, 5, 102);
    write_dir_inode(&mut b, 100, BLOCK as u64, 200);
    // Block 5000 is outside the 320-block image.
    write_dir_inode(&mut b, 101, BLOCK as u64, 5000);
    write_inline_file_inode(&mut b, 102, b"hello world!");

    let root_dent = 200 * BLOCK;
    write_dentry(&mut b, root_dent, 0, 3, b".", 2);
    write_dentry(&mut b, root_dent, 1, 3, b"..", 2);
    write_dentry(&mut b, root_dent, 2, 4, b"subdir", 2);
    write_dentry(&mut b, root_dent, 3, 5, b"hello.txt", 1);

    let source = Arc::new(ByteSliceDataSource::new(b.data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source as Arc<dyn DataSource>),
        json!({
            "subtype": "f2fs",
            "filesystem_type": "F2FS",
            "offset_bytes": 0,
            "size_bytes": 320u64 * BLOCK as u64,
        }),
    );

    let out = F2fsParser::new().process(&artifact).expect("process ok");
    let subdir = find(&out, "subdir");
    assert_eq!(
        subdir.metadata["directory_parse_incomplete"],
        json!(true),
        "an unreadable dentry block must not yield a silently empty directory"
    );
    assert_eq!(
        subdir.metadata["directory_parse_incomplete_reason"],
        json!("short_read")
    );
}

/// A directory entry naming an inode we cannot resolve used to be a bare
/// `return`: the file vanished and the `/data` inventory was published as the
/// complete tree, so "no such file" read as fact (B7-010).
#[test]
fn children_whose_inodes_cannot_be_resolved_are_counted_on_a_summary() {
    let mut b = Builder::new(320);
    write_superblock(&mut b);

    write_nat(&mut b, 4, 3, 100); // root
    write_nat(&mut b, 4, 5, 102); // hello.txt
                                  // nid 4 ("subdir") deliberately has NO NAT entry: unresolvable.

    write_dir_inode(&mut b, 100, BLOCK as u64, 200);
    write_inline_file_inode(&mut b, 102, b"hello world!");

    let root_dent = 200 * BLOCK;
    write_dentry(&mut b, root_dent, 0, 3, b".", 2);
    write_dentry(&mut b, root_dent, 1, 3, b"..", 2);
    write_dentry(&mut b, root_dent, 2, 4, b"subdir", 2); // no NAT entry
    write_dentry(&mut b, root_dent, 3, 5, b"hello.txt", 1);

    let source = Arc::new(ByteSliceDataSource::new(b.data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source as Arc<dyn DataSource>),
        json!({ "subtype": "f2fs", "filesystem_type": "F2FS" }),
    );

    let produced = F2fsParser::new().process(&artifact).unwrap();
    let summary = produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("f2fs_walk_status"))
        .expect("an inventory short of the volume must say so");

    assert_eq!(summary.metadata["unresolved_inodes"], 1);
    assert_eq!(summary.metadata["inventory_incomplete"], true);
    assert_eq!(
        summary.metadata["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(summary.metadata["content_incomplete"], true);
}

/// HUNT-173: a superblock the detector matched but this parser will not read
/// (here the log_blocksize of a 16 KiB-block volume) was a `warn!` and an
/// empty list, which the orchestrator files as "ran with no output". It is a
/// refusal on the volume, with the reason.
#[test]
fn a_superblock_that_will_not_parse_is_refused_on_the_volume_not_silently_empty() {
    let (artifact, src) = build_image();
    let mut data = src.resident_bytes().expect("in-memory image").to_vec();
    data[SB + 16..SB + 20].copy_from_slice(&14u32.to_le_bytes());
    let artifact = Artifact::new(
        artifact.case_id,
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
        artifact.metadata.clone(),
    );
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    assert_eq!(out.len(), 1, "one refusal record, no files");
    let status = walk_summary(&out);
    assert_eq!(out[0].parent_id, Some(artifact.id));
    assert_eq!(status["walked"], false);
    assert_eq!(status["files_emitted"], 0);
    assert_eq!(status["inventory_incomplete"], true);
    assert_eq!(
        status["inventory_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(
        status["superblock_error"]
            .as_str()
            .unwrap()
            .contains("log_blocksize 14"),
        "{status}"
    );

    // A superblock cut short says `short_read`.
    let (artifact, src) = build_image();
    let short = src.resident_bytes().expect("in-memory image")[..2048].to_vec();
    let artifact = Artifact::new(
        artifact.case_id,
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(short)) as Arc<dyn DataSource>),
        artifact.metadata.clone(),
    );
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    assert_eq!(
        walk_summary(&out)["inventory_incomplete_reason"],
        "short_read"
    );
}

/// HUNT-173: a file over the 2^21-block (8 GiB) run cap is capped, and says
/// `cap_reached` -- not `unresolved_structure`, which would send the examiner
/// looking for corruption that is not there.
#[test]
fn a_file_past_the_block_cap_says_cap_reached() {
    let (artifact, src) = build_image();
    let mut data = src.resident_bytes().expect("in-memory image").to_vec();
    // Re-size nested.bin (inode block 103, two direct blocks) to 9 GiB: the
    // rest of its node tree is sparse (zero nids), as a real sparse file's is.
    let size: u64 = 9 << 30;
    data[103 * BLOCK + 16..103 * BLOCK + 24].copy_from_slice(&size.to_le_bytes());
    let artifact = Artifact::new(
        artifact.case_id,
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
        artifact.metadata.clone(),
    );
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    let nested = find(&out, "nested.bin");
    assert_eq!(nested.metadata["data_runs_complete"], json!(false));
    assert_eq!(nested.metadata["content_incomplete"], json!(true));
    assert_eq!(
        nested.metadata["content_incomplete_reason"],
        json!("cap_reached"),
        "{}",
        nested.metadata
    );
}

/// HUNT-173: a directory reached twice through a cyclic graph was emitted
/// twice, under two paths, before the cycle guard stopped the descent. It is
/// emitted once, and the second path it was reached by is recorded on it.
#[test]
fn a_directory_reached_twice_is_emitted_once() {
    let (artifact, src) = build_image();
    let mut b = Builder {
        data: src.resident_bytes().expect("in-memory image").to_vec(),
    };
    // subdir's dentry block gains "loop" -> the root directory (nid 3).
    write_dentry(&mut b, 201 * BLOCK, 5, 3, b"loop", 2);
    let artifact = Artifact::new(
        artifact.case_id,
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(b.data)) as Arc<dyn DataSource>),
        artifact.metadata.clone(),
    );
    let out = F2fsParser::new().process(&artifact).expect("process ok");
    let roots: Vec<_> = out
        .iter()
        .filter(|a| a.metadata.get("inode").and_then(|v| v.as_u64()) == Some(3))
        .collect();
    assert_eq!(
        roots.len(),
        1,
        "root emitted under {:?}",
        roots
            .iter()
            .map(|a| &a.metadata["path"])
            .collect::<Vec<_>>()
    );
    assert_eq!(roots[0].metadata["path"], "/");
    assert_eq!(
        roots[0].metadata["also_reached_at"],
        json!(["/subdir/loop"])
    );
}

/// A real volume: `mkfs.f2fs -q -f -l SEANCE` (f2fs-tools 1.16.0) on a 64 MiB
/// file, populated without mounting by `sload.f2fs -f src img` from a tree of
/// `inline.txt` ("hi\n"), `big.bin` (5,000 random bytes) and
/// `dir/sub/a.txt` ("real f2fs\n"); `fsck.f2fs` passes it.
fn sload_image() -> Vec<u8> {
    use std::io::Read;
    let gz = include_bytes!("../tests/fixtures/sload_f2fs.img.gz");
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn f2fs_artifact(data: Vec<u8>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
        json!({ "subtype": "f2fs", "filesystem_type": "F2FS" }),
    )
}

#[test]
fn a_real_sload_f2fs_volume_walks_complete() {
    let out = F2fsParser::new()
        .process(&f2fs_artifact(sload_image()))
        .unwrap();
    let read = |name: &str| {
        let ds = find(&out, name).data.clone().expect("content");
        let mut buf = vec![0u8; ds.size() as usize];
        let n = ds.read_at(0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    };
    assert_eq!(read("inline.txt"), b"hi\n");
    assert_eq!(read("a.txt"), b"real f2fs\n");
    assert_eq!(read("big.bin").len(), 5000);
    assert_eq!(find(&out, "a.txt").metadata["path"], "/dir/sub/a.txt");
    assert!(
        !out.iter()
            .any(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("f2fs_walk_status")),
        "a clean volume carries no walk status"
    );
}

/// HUNT-173 on the real superblock: a log_blocksize this parser does not read
/// is refused on the volume, not answered with an empty list.
#[test]
fn a_real_superblock_with_an_unread_block_size_is_refused() {
    let mut data = sload_image();
    data[SB + 16..SB + 20].copy_from_slice(&14u32.to_le_bytes());
    let out = F2fsParser::new().process(&f2fs_artifact(data)).unwrap();
    let status = walk_summary(&out);
    assert_eq!(status["walked"], false);
    assert_eq!(
        status["inventory_incomplete_reason"],
        "unresolved_structure"
    );
}
