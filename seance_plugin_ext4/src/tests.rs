use super::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use seance_core::test_support::DribbleSource;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// --- Mock Data Source ---

#[derive(Clone, Debug)]
struct MockDataSource {
    data: Arc<Mutex<Vec<u8>>>,
}

impl MockDataSource {
    fn new(size: usize) -> Self {
        Self {
            data: Arc::new(Mutex::new(vec![0u8; size])),
        }
    }

    fn write_at(&self, offset: u64, data: &[u8]) {
        let mut guard = self.data.lock().unwrap();
        if offset as usize + data.len() > guard.len() {
            guard.resize(offset as usize + data.len(), 0);
        }
        guard[offset as usize..offset as usize + data.len()].copy_from_slice(data);
    }

    // Helper to write u16
    #[allow(dead_code)]
    fn write_u16(&self, offset: u64, val: u16) {
        let mut buf = vec![];
        buf.write_u16::<LittleEndian>(val).unwrap();
        self.write_at(offset, &buf);
    }

    // Helper to write u32
    #[allow(dead_code)]
    fn write_u32(&self, offset: u64, val: u32) {
        let mut buf = vec![];
        buf.write_u32::<LittleEndian>(val).unwrap();
        self.write_at(offset, &buf);
    }
}

impl DataSource for MockDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self.data.lock().unwrap();
        if offset >= guard.len() as u64 {
            return Ok(0);
        }
        let available = guard.len() as u64 - offset;
        let to_read = std::cmp::min(available, buf.len() as u64) as usize;
        buf[..to_read].copy_from_slice(&guard[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.lock().unwrap().len() as u64
    }
}

// --- Helper Functions to Construct Ext4 Structures ---

fn create_valid_superblock() -> Vec<u8> {
    let mut buf = vec![0u8; 1024]; // Standard SB size is 1024 (though usually padded in block)
    let mut cursor = Cursor::new(&mut buf);

    cursor.write_u32::<LittleEndian>(100).unwrap(); // inodes_count
    cursor.write_u32::<LittleEndian>(1000).unwrap(); // blocks_count_lo
    cursor.write_u32::<LittleEndian>(0).unwrap(); // r_blocks_count_lo
    cursor.write_u32::<LittleEndian>(0).unwrap(); // free_blocks_count_lo
    cursor.write_u32::<LittleEndian>(0).unwrap(); // free_inodes_count
    cursor.write_u32::<LittleEndian>(0).unwrap(); // first_data_block
    cursor.write_u32::<LittleEndian>(2).unwrap(); // log_block_size (2 -> 4096 block size)
    cursor.write_u32::<LittleEndian>(0).unwrap(); // log_cluster_size
    cursor.write_u32::<LittleEndian>(32768).unwrap(); // blocks_per_group
    cursor.write_u32::<LittleEndian>(0).unwrap(); // clusters_per_group
    cursor.write_u32::<LittleEndian>(8192).unwrap(); // inodes_per_group
    cursor.write_u32::<LittleEndian>(0).unwrap(); // mtime
    cursor.write_u32::<LittleEndian>(0).unwrap(); // wtime
    cursor.write_u16::<LittleEndian>(0).unwrap(); // mnt_count
    cursor.write_u16::<LittleEndian>(0).unwrap(); // max_mnt_count
    cursor.write_u16::<LittleEndian>(0xEF53).unwrap(); // magic

    // s_rev_level at 76: a revision-1 (dynamic) superblock, so the inode_size
    // field below exists and is believed.
    cursor.seek(SeekFrom::Start(76)).unwrap();
    cursor.write_u32::<LittleEndian>(1).unwrap();

    // Jump to inode_size at 88
    cursor.seek(SeekFrom::Start(88)).unwrap();
    cursor.write_u16::<LittleEndian>(256).unwrap(); // inode_size

    // Jump to features at 96
    cursor.seek(SeekFrom::Start(96)).unwrap();
    cursor.write_u32::<LittleEndian>(0x2C0).unwrap(); // incompat_features (EXTENTS | 64BIT | FLEX_BG)
    cursor.write_u32::<LittleEndian>(0x1).unwrap(); // ro_compat_features (SPARSE_SUPER)

    // Jump to desc_size at 254 (for 64bit)
    cursor.seek(SeekFrom::Start(254)).unwrap();
    cursor.write_u16::<LittleEndian>(64).unwrap(); // desc_size

    buf
}

fn create_inode(mode: u16, size: u64, flags: u32, blocks: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 256]; // inode size
    let mut cursor = Cursor::new(&mut buf);

    cursor.write_u16::<LittleEndian>(mode).unwrap();
    cursor.write_u16::<LittleEndian>(1000).unwrap(); // uid
    cursor.write_u32::<LittleEndian>(size as u32).unwrap(); // size_lo
    cursor.write_u32::<LittleEndian>(0).unwrap(); // atime
    cursor.write_u32::<LittleEndian>(0).unwrap(); // ctime
    cursor.write_u32::<LittleEndian>(0).unwrap(); // mtime
    cursor.write_u32::<LittleEndian>(0).unwrap(); // dtime
    cursor.write_u16::<LittleEndian>(1000).unwrap(); // gid
    cursor.write_u16::<LittleEndian>(1).unwrap(); // links_count
    cursor
        .write_u32::<LittleEndian>((size / 512) as u32)
        .unwrap(); // blocks_lo (sectors)
    cursor.write_u32::<LittleEndian>(flags).unwrap(); // flags
    cursor.write_u32::<LittleEndian>(0).unwrap(); // osd1

    // Block array (60 bytes)
    cursor.write_all(blocks).unwrap();
    // Pad rest of block array if needed
    let remaining_block = 60 - blocks.len();
    if remaining_block > 0 {
        cursor.write_all(&vec![0u8; remaining_block]).unwrap();
    }

    cursor.write_u32::<LittleEndian>(0).unwrap(); // generation
    cursor.write_u32::<LittleEndian>(0).unwrap(); // file_acl_lo
    cursor
        .write_u32::<LittleEndian>((size >> 32) as u32)
        .unwrap(); // size_hi

    buf
}

fn create_extent_header(entries: u16, depth: u16) -> Vec<u8> {
    let mut buf = vec![];
    buf.write_u16::<LittleEndian>(0xF30A).unwrap(); // magic
    buf.write_u16::<LittleEndian>(entries).unwrap(); // entries_count
    buf.write_u16::<LittleEndian>(4).unwrap(); // max_entries
    buf.write_u16::<LittleEndian>(depth).unwrap(); // depth
    buf.write_u32::<LittleEndian>(0).unwrap(); // generation
    buf
}

fn create_extent_leaf(block: u32, len: u16, start_block: u64) -> Vec<u8> {
    let mut buf = vec![];
    buf.write_u32::<LittleEndian>(block).unwrap(); // ee_block (logical)
    buf.write_u16::<LittleEndian>(len).unwrap(); // ee_len
    buf.write_u16::<LittleEndian>((start_block >> 32) as u16)
        .unwrap(); // ee_start_hi
    buf.write_u32::<LittleEndian>(start_block as u32).unwrap(); // ee_start_lo
    buf
}

fn create_extent_idx(block: u32, leaf_block: u64) -> Vec<u8> {
    let mut buf = vec![];
    buf.write_u32::<LittleEndian>(block).unwrap(); // ei_block
    buf.write_u32::<LittleEndian>(leaf_block as u32).unwrap(); // ei_leaf_lo
    buf.write_u16::<LittleEndian>((leaf_block >> 32) as u16)
        .unwrap(); // ei_leaf_hi
    buf.write_u16::<LittleEndian>(0).unwrap(); // ei_unused
    buf
}

fn create_dir_entry(inode: u32, name: &str) -> Vec<u8> {
    create_dir_entry_typed(inode, name, 1) // file_type 1 = regular file
}

/// Same as [`create_dir_entry`], but with an explicit `ext4_dir_entry_2`
/// `file_type` byte — needed for `.`/`..` (type 2, directory) and for the
/// reuse/type-mismatch tests, which depend on what this byte says versus what
/// the inode's own mode bits say.
fn create_dir_entry_typed(inode: u32, name: &str, file_type: u8) -> Vec<u8> {
    let mut buf = vec![];
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u8;

    // rec_len must be 4-byte aligned
    let mut rec_len = 8 + name_len as u16;
    if !rec_len.is_multiple_of(4) {
        rec_len += 4 - (rec_len % 4);
    }

    buf.write_u32::<LittleEndian>(inode).unwrap();
    buf.write_u16::<LittleEndian>(rec_len).unwrap();
    buf.write_u8(name_len).unwrap();
    buf.write_u8(file_type).unwrap();
    buf.write_all(name_bytes).unwrap();
    // padding
    while buf.len() < rec_len as usize {
        buf.write_u8(0).unwrap();
    }

    buf
}

// --- Tests ---

#[test]
fn test_superblock_parsing() {
    let source = MockDataSource::new(4096 * 10);
    // Write superblock at 1024
    source.write_at(1024, &create_valid_superblock());

    let sb = Superblock::parse(&source).expect("Failed to parse superblock");

    // Magic not in struct but checked in parse
    assert_eq!(sb.block_size, 4096);
    assert_eq!(sb.inode_size, 256);
    assert_eq!(sb.desc_size, 64);
    assert_eq!(sb.blocks_count, 1000);
}

#[test]
fn test_inode_parsing_direct_blocks() {
    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Create GDT
    // GDT is at block 0 + 1 (since block size is 4096 and SB is in block 0)
    // Actually for block_size=4096, block 0 contains SB at offset 1024.
    // If block_size > 1024, SB is in block 0. GDT starts at next block?
    // Logic in lib.rs:
    // first_data_block is 0.
    // if block_size=1024, table_start_block=2.
    // if block_size>1024, table_start_block=1.

    // Let's setup a simplified GDT for group 0
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    // inode table at block 10
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap(); // inode_table_lo

    // Write GDT at block 1 (offset 4096)
    source.write_at(4096, &gdt_entry);

    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].get_inode_table_block(), 10);

    // Create Inode 1 (Root) at Table Block 10
    // Inode 1 is index 0 in table
    let offset = 10 * 4096;

    // Direct blocks: 0x4000 (dir), size 4096, flags 0 (no extents)
    // Points to block 20
    let mut block_ptr = vec![0u8; 60];
    block_ptr[0] = 20; // Block 20

    let inode_data = create_inode(0x4000 | 0o755, 4096, 0, &block_ptr);
    source.write_at(offset, &inode_data);

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    assert_eq!(inode.mode & 0xF000, 0x4000);
    assert!(!inode.uses_extents());
    assert_eq!(inode.size(), 4096);

    // Verify FileSource reading via direct blocks
    // Write content at block 20
    source.write_at(20 * 4096, b"Hello World");

    let fs = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);
    let mut buf = vec![0u8; 11];
    let n = fs.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 11);
    assert_eq!(&buf, b"Hello World");
}

#[test]
fn test_inode_parsing_extents_depth_0() {
    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap(); // inode_table_lo
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create Inode 1 with Extents
    // Extent Tree: Header + 1 Leaf
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    // Leaf: Logical Block 0, Len 1, Physical Block 30
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 30));

    let offset = 10 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, 4096, 0x80000, &blocks); // 0x80000 = EXTENTS_FL
    source.write_at(offset, &inode_data);

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    assert!(inode.uses_extents());

    // Write content at physical block 30
    source.write_at(30 * 4096, b"Extent Content");

    let fs = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);
    let mut buf = vec![0u8; 14];
    let n = fs.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 14);
    assert_eq!(&buf, b"Extent Content");
}

#[test]
fn test_inode_parsing_deep_extents() {
    let source = MockDataSource::new(4096 * 200);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create Inode with Deep Extents (Depth 1)
    // Root Node (in inode): Header + 1 Index
    let mut root_blocks = vec![];
    root_blocks.extend_from_slice(&create_extent_header(1, 1));
    // Index: Logical Block 0 covers everything, points to leaf block 50
    root_blocks.extend_from_slice(&create_extent_idx(0, 50));

    let offset = 10 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, 4096 * 2, 0x80000, &root_blocks);
    source.write_at(offset, &inode_data);

    // Create Leaf Node at Block 50
    // Header + 2 Extents
    let mut leaf_node = vec![0u8; 4096];
    let mut leaf_cursor = Cursor::new(&mut leaf_node);
    leaf_cursor.write_all(&create_extent_header(2, 0)).unwrap();
    // Extent 1: Logical 0, Len 1, Phys 60
    leaf_cursor
        .write_all(&create_extent_leaf(0, 1, 60))
        .unwrap();
    // Extent 2: Logical 1, Len 1, Phys 61
    leaf_cursor
        .write_all(&create_extent_leaf(1, 1, 61))
        .unwrap();

    source.write_at(50 * 4096, &leaf_node);

    // Write Content at Phys 60 and 61
    source.write_at(60 * 4096, b"Block 1 Data");
    source.write_at(61 * 4096, b"Block 2 Data");

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    assert!(inode.uses_extents());

    let fs = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);

    // Read Block 1
    let mut buf1 = vec![0u8; 12];
    let n1 = fs.read_at(0, &mut buf1).unwrap();
    assert_eq!(n1, 12);
    assert_eq!(&buf1, b"Block 1 Data");

    // Read Block 2 (Offset 4096)
    let mut buf2 = vec![0u8; 12];
    let n2 = fs.read_at(4096, &mut buf2).unwrap();
    assert_eq!(n2, 12);
    assert_eq!(&buf2, b"Block 2 Data");
}

#[test]
fn test_directory_parsing_linear() {
    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create Dir Inode pointing to block 20
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));

    let offset = 10 * 4096;
    let inode_data = create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks);
    source.write_at(offset, &inode_data);

    // Create Directory Entries in Block 20
    let mut dir_block = vec![0u8; 4096];
    let mut cursor = Cursor::new(&mut dir_block);

    // Entry 1: .
    cursor.write_all(&create_dir_entry(1, ".")).unwrap();
    // Entry 2: ..
    cursor.write_all(&create_dir_entry(1, "..")).unwrap();
    // Entry 3: file.txt
    cursor.write_all(&create_dir_entry(2, "file.txt")).unwrap();

    // Set rec_len of last entry to cover rest of block
    let pos = cursor.position();
    let _remaining = 4096 - (pos - create_dir_entry(2, "file.txt").len() as u64); // rough calc
                                                                                  // Actually we need to fix up the last entry's rec_len
                                                                                  // But parse_directory_entries handles multiple entries fine

    source.write_at(20 * 4096, &dir_block);

    // We need to invoke parse_directory_entries
    // Since it's private, we can't call it directly from integration test if this was external
    // But since this is a unit test module inside the crate, we can test it via a context

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    // Create fake Inode 2 for the file.txt so recursion works
    // Inode 2 (index 1 in table)
    let offset_inode2 = 10 * 4096 + 256;
    let inode2_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    source.write_at(offset_inode2, &inode2_data);

    // Manually call parse_directory_entries
    // Or call parse_inode on the dir
    parse_inode(&mut ctx, 1, "/").unwrap();

    assert_eq!(produced.len(), 2); // Root dir + file.txt

    let file_art = produced
        .iter()
        .find(|a| a.metadata["name"] == "file.txt")
        .unwrap();
    assert_eq!(file_art.metadata["inode"], 2);
}

/// HUNT-066. The kernel deletes a directory entry by widening the previous
/// entry's `rec_len` over it; the name and inode number stay in the block.
/// The walk followed `rec_len` and so never saw one, and the NIST DFR set's
/// simplest scenario — "recover one non-fragmented file" — found 0 of 3
/// deleted files on ext while `LINUX_DESIGN.md` claimed deleted-inode
/// recovery. Every entry's slack is walked for the entries the kernel hid.
#[test]
fn a_directory_entry_hidden_in_its_neighbours_slack_is_recovered_as_deleted() {
    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Root directory inode 1 -> block 20.
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));
    source.write_at(
        10 * 4096,
        &create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks),
    );
    // Inode 2: live file. Inode 3: the deleted one — dtime set, no links.
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 100, 0, &[0u8; 60]),
    );
    let mut gone = create_inode(0x8000 | 0o644, 4296, 0, &[0u8; 60]);
    gone[0x14..0x18].copy_from_slice(&1_328_282_700u32.to_le_bytes()); // dtime
    gone[0x1A..0x1C].copy_from_slice(&0u16.to_le_bytes()); // links_count
    source.write_at(10 * 4096 + 512, &gone);

    // Block 20: ".", "..", "live.txt", then "Bunda.txt" deleted the way the
    // kernel does it — live.txt's rec_len widened to swallow it, its bytes
    // left in place.
    let mut dir_block = vec![0u8; 4096];
    let dot = create_dir_entry(1, ".");
    let dotdot = create_dir_entry(1, "..");
    let mut live = create_dir_entry(2, "live.txt");
    let gone_entry = create_dir_entry(3, "Bunda.txt");
    let widened = (live.len() + gone_entry.len()) as u16;
    live[4..6].copy_from_slice(&widened.to_le_bytes());
    let mut pos = 0;
    for e in [&dot[..], &dotdot[..], &live[..], &gone_entry[..]] {
        dir_block[pos..pos + e.len()].copy_from_slice(e);
        pos += e.len();
    }
    // The last live entry spans the rest of the block, as on disk.
    let tail = 4096 - (pos - gone_entry.len());
    let live_pos = dot.len() + dotdot.len();
    // live.txt's rec_len covers the hidden entry AND the rest of the block.
    dir_block[live_pos + 4..live_pos + 6].copy_from_slice(&(tail as u16).to_le_bytes());
    source.write_at(20 * 4096, &dir_block);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    let live_art = produced
        .iter()
        .find(|a| a.metadata["name"] == "live.txt")
        .expect("live file");
    assert!(live_art.metadata.get("deleted").is_none());

    let gone_art = produced
        .iter()
        .find(|a| a.metadata["name"] == "Bunda.txt")
        .expect("the entry hidden in live.txt's slack is the deleted file");
    assert_eq!(gone_art.metadata["deleted"], true);
    assert_eq!(gone_art.metadata["inode"], 3);
    assert_eq!(gone_art.metadata["path"], "/Bunda.txt");
    assert_eq!(
        gone_art.metadata["deleted_recovery_source"],
        "directory_slack"
    );
    assert_eq!(gone_art.metadata["size"], 4296);
}

/// The ext2 variant of the same deletion: `ext2_delete_entry` zeroes the
/// hidden entry's inode number as well as merging its length, so the name
/// survives with nothing behind it. On `dfr-01-ext`'s ext2 partition that is
/// `Bellatrix.txt`. A name the directory still holds is the directory's own
/// record that the file existed; what is not reachable through it is said.
#[test]
fn an_ext2_hidden_entry_with_its_inode_zeroed_is_recovered_as_a_name_only_deletion() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));
    source.write_at(
        10 * 4096,
        &create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks),
    );
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 100, 0, &[0u8; 60]),
    );

    let mut dir_block = vec![0u8; 4096];
    let dot = create_dir_entry(1, ".");
    let dotdot = create_dir_entry(1, "..");
    let live = create_dir_entry(2, "Algol.txt");
    let gone_entry = create_dir_entry(0, "Bellatrix.txt"); // inode zeroed
    let mut pos = 0;
    for e in [&dot[..], &dotdot[..], &live[..], &gone_entry[..]] {
        dir_block[pos..pos + e.len()].copy_from_slice(e);
        pos += e.len();
    }
    let live_pos = dot.len() + dotdot.len();
    let tail = 4096 - live_pos;
    dir_block[live_pos + 4..live_pos + 6].copy_from_slice(&(tail as u16).to_le_bytes());
    source.write_at(20 * 4096, &dir_block);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    let gone = produced
        .iter()
        .find(|a| a.metadata["name"] == "Bellatrix.txt")
        .expect("a name with its inode zeroed is still a deletion the directory records");
    assert_eq!(gone.metadata["deleted"], true);
    assert!(gone.metadata["inode"].is_null());
    assert_eq!(gone.metadata["path"], "/Bellatrix.txt");
    assert_eq!(gone.metadata["metadata_unavailable"], true);
    assert_eq!(gone.metadata["content_incomplete"], true);
    assert!(
        gone.metadata.get("size").is_none(),
        "no size may be invented"
    );
    assert!(gone.data.is_none(), "there is no content to serve");
}

/// Build the standard 1000-block/4096-byte-block volume used by the
/// allocation-map tests, with blocks 0-7 marked in-use and block 8 onward
/// free, and the inode table at block 10. Shared by the orphaned-directory-
/// block tests below, which write their content into the free range.
fn setup_fs_with_bitmap(source: &MockDataSource) -> (Superblock, Vec<BlockGroupDescriptor>) {
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    {
        let mut cursor = Cursor::new(&mut gdt_entry);
        cursor.write_u32::<LittleEndian>(5).unwrap(); // block_bitmap_lo
        cursor.write_u32::<LittleEndian>(6).unwrap(); // inode_bitmap_lo
        cursor.write_u32::<LittleEndian>(10).unwrap(); // inode_table_lo
    }
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(source, &sb).unwrap();
    // Blocks 0-7 in use; block 8 onward free (bytes past this default to
    // zero, i.e. free, same as test_allocation_map_from_block_bitmap).
    source.write_at(5 * 4096, &[0xFFu8]);
    (sb, groups)
}

/// Write a `256`-byte inode at inode number `inode_num` into the table set up
/// by `setup_fs_with_bitmap` (table at block 10, inode_size 256), and set its
/// `dtime`/`links_count` fields the way `create_inode` leaves at zero.
fn write_inode_at(
    source: &MockDataSource,
    inode_num: u32,
    mode: u16,
    size: u64,
    dtime: u32,
    links_count: u16,
) {
    let mut data = create_inode(mode, size, 0, &[0u8; 60]);
    data[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    data[0x1A..0x1C].copy_from_slice(&links_count.to_le_bytes());
    let offset = 10 * 4096 + (inode_num as u64 - 1) * 256;
    source.write_at(offset, &data);
}

/// A block this crate's own free-space bitmap says is unallocated, at 8*4096,
/// holding a full `.`/`..` + two-file dirent chain: `photo.jpg` at inode 5 and
/// `notes.txt` at inode 6. Neither inode 1 (root) nor inode 4 (the directory's
/// own, named by `.`) needs to exist — the scan never resolves them, exactly
/// as a live directory listing never resolves `.`/`..` into separate entries.
fn write_orphaned_directory_block(source: &MockDataSource) {
    let dot = create_dir_entry_typed(4, ".", EXT4_FT_DIR);
    let dotdot = create_dir_entry_typed(1, "..", EXT4_FT_DIR);
    let file1 = create_dir_entry_typed(5, "photo.jpg", EXT4_FT_REG_FILE);
    let mut file2 = create_dir_entry_typed(6, "notes.txt", EXT4_FT_REG_FILE);
    // The block's last entry always carries a rec_len stretched to the end of
    // the block, exactly as `parse_directory_entries` expects of a live one.
    // file1, not being last, keeps the minimal 4-aligned rec_len
    // create_dir_entry_typed already wrote.
    let used_before_last = dot.len() + dotdot.len() + file1.len();
    let tail = 4096 - used_before_last;
    file2[4..6].copy_from_slice(&(tail as u16).to_le_bytes());

    let mut block = vec![0u8; 4096];
    let mut pos = 0;
    for e in [&dot[..], &dotdot[..], &file1[..], &file2[..]] {
        block[pos..pos + e.len()].copy_from_slice(e);
        pos += e.len();
    }
    source.write_at(8 * 4096, &block);
}

fn scan_context<'a>(
    sb: &'a Superblock,
    groups: &'a Vec<BlockGroupDescriptor>,
    source: &MockDataSource,
    produced: &'a mut Vec<Artifact>,
) -> ParsingContext<'a> {
    ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: sb,
        groups,
        produced_artifacts: produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    }
}

/// ROADMAP §5.6 / NIST DFR `dfr-11`: a directory is deleted (the kernel
/// clears its inode's block pointers), but its own dirent block was never
/// overwritten and this crate's free-space bitmap still calls it unallocated.
/// The scan must recognise the orphaned block by its content and reconstruct
/// the file list — names and inodes — even though nothing live points at the
/// block any more.
#[test]
fn an_orphaned_directory_block_reconstructs_its_deleted_file_list() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs_with_bitmap(&source);
    write_orphaned_directory_block(&source);

    // Both files were deleted along with their directory: mode still names a
    // regular file, but dtime is set and links_count is 0, exactly the
    // deletion marker `parse_inode_from` itself treats as "this inode still
    // holds (or plausibly still holds) the file it names".
    write_inode_at(&source, 5, 0x8000 | 0o644, 12345, 1_700_000_000, 0);
    write_inode_at(&source, 6, 0x8000 | 0o644, 42, 1_700_000_001, 0);

    let mut produced = Vec::new();
    let mut ctx = scan_context(&sb, &groups, &source, &mut produced);
    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("bitmap reads");
    scan_orphaned_directory_blocks(&mut ctx, &bitmaps);

    let photo = produced
        .iter()
        .find(|a| a.metadata["name"] == "photo.jpg")
        .expect("photo.jpg recovered from the orphaned block");
    assert_eq!(photo.metadata["inode"], 5);
    assert_eq!(photo.metadata["deleted"], true);
    assert_eq!(
        photo.metadata["deleted_recovery_source"],
        "orphaned_directory_block"
    );
    assert_eq!(photo.metadata["orphaned_directory_block"], 8);
    assert_eq!(photo.metadata["inode_status"], "resolved");
    assert_eq!(photo.metadata["is_directory"], false);
    assert_eq!(photo.metadata["size"], 12345);
    assert!(photo.metadata["path"].is_null());
    assert!(photo.metadata.get("inode_reused").is_none());

    let notes = produced
        .iter()
        .find(|a| a.metadata["name"] == "notes.txt")
        .expect("notes.txt recovered from the orphaned block");
    assert_eq!(notes.metadata["inode"], 6);
    assert_eq!(notes.metadata["inode_status"], "resolved");
    assert_eq!(notes.metadata["size"], 42);

    let summary = produced
        .iter()
        .find(|a| {
            a.artifact_type == ArtifactType::ParsedRecord
                && a.metadata["type"] == "orphaned_directory_scan"
        })
        .expect("the scan reports its own reach even when it recovers everything cleanly");
    assert_eq!(summary.metadata["orphaned_directory_blocks_found"], 1);
    assert_eq!(summary.metadata["orphaned_directory_entries_recovered"], 2);
    assert!(summary
        .metadata
        .get("orphaned_directory_entries_cap")
        .is_none());
}

/// The other half of §5.6's forensic requirement: an inode a recovered dirent
/// names has since been reallocated to a live, unrelated file. The recovered
/// entry must say so and must NOT present that file's content under the old
/// name — the entire forensic value of the feature is this distinction.
#[test]
fn a_reused_inode_is_reported_unresolved_not_attached_to_the_new_files_content() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs_with_bitmap(&source);
    write_orphaned_directory_block(&source);

    // photo.jpg (inode 5): still looks like the same deleted file.
    write_inode_at(&source, 5, 0x8000 | 0o644, 12345, 1_700_000_000, 0);
    // notes.txt (inode 6): reallocated since — a live regular file (mode
    // valid, dtime == 0, links_count > 0) with completely different content.
    // Same file_type as the dirent claims (regular file), which is exactly
    // why the dtime/links_count check matters: type alone cannot catch this.
    write_inode_at(&source, 6, 0x8000 | 0o600, 999_999, 0, 1);

    let mut produced = Vec::new();
    let mut ctx = scan_context(&sb, &groups, &source, &mut produced);
    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("bitmap reads");
    scan_orphaned_directory_blocks(&mut ctx, &bitmaps);

    let notes = produced
        .iter()
        .find(|a| a.metadata["name"] == "notes.txt")
        .expect("notes.txt is still reported -- as an unresolved name");
    assert_eq!(notes.metadata["inode_status"], "reused");
    assert_eq!(notes.metadata["inode_reused"], true);
    assert_eq!(notes.metadata["content_incomplete"], true);
    assert!(
        notes.metadata.get("size").is_none(),
        "the live file's size must never be reported under the deleted name"
    );
    assert!(
        notes.data.is_none(),
        "the live file's content must never be attached to the deleted name"
    );

    // The other entry, whose inode was NOT reused, still resolves normally.
    let photo = produced
        .iter()
        .find(|a| a.metadata["name"] == "photo.jpg")
        .expect("photo.jpg recovered from the orphaned block");
    assert_eq!(photo.metadata["inode_status"], "resolved");
    assert_eq!(photo.metadata["size"], 12345);
}

#[test]
fn test_htree_directory_fallback() {
    // This tests that if htree flag is set but htree parsing fails (e.g. invalid structure),
    // it falls back to linear scan which should still find the entries.

    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create Dir Inode with HTREE flag (0x1000)
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));

    let offset = 10 * 4096;
    let inode_data = create_inode(0x4000 | 0o755, 4096, 0x80000 | 0x1000, &blocks);
    source.write_at(offset, &inode_data);

    // Block 20: Just put linear directory entries (no dx_root)
    // This simulates a corrupted or non-compliant htree structure
    let mut dir_block = vec![0u8; 4096];
    let mut cursor = Cursor::new(&mut dir_block);
    cursor.write_all(&create_dir_entry(1, ".")).unwrap();
    cursor.write_all(&create_dir_entry(1, "..")).unwrap();
    cursor
        .write_all(&create_dir_entry(2, "fallback.txt"))
        .unwrap();
    source.write_at(20 * 4096, &dir_block);

    // Create fake Inode 2
    let offset_inode2 = 10 * 4096 + 256;
    let inode2_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    source.write_at(offset_inode2, &inode2_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    parse_inode(&mut ctx, 1, "/").unwrap();

    assert_eq!(produced.len(), 2);
    let file_art = produced
        .iter()
        .find(|a| a.metadata["name"] == "fallback.txt")
        .unwrap();
    assert_eq!(file_art.metadata["inode"], 2);
}

#[test]
fn test_htree_double_failure_flags_incomplete() {
    // htree flag is set, the htree parse fails, AND the linear reparse cannot
    // read the directory data (its extent points beyond the image). The loss
    // must be flagged on the directory artifact, not silently swallowed.
    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT: inode table at block 10.
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Dir inode with HTREE (0x1000) + extents (0x80000) whose single extent
    // points to physical block 100000, far past the 100-block image, so every
    // read of the directory data returns 0 bytes.
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 100_000));
    let offset = 10 * 4096;
    let inode_data = create_inode(0x4000 | 0o755, 4096, 0x80000 | 0x1000, &blocks);
    source.write_at(offset, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    parse_inode(&mut ctx, 1, "/").unwrap();

    // The directory artifact is produced but carries the incomplete marker.
    let dir_art = produced
        .iter()
        .find(|a| a.metadata.get("directory_parse_incomplete").is_some())
        .expect("directory artifact must carry the parse-failure marker");
    assert_eq!(dir_art.metadata["directory_parse_incomplete"], true);
}

/// Build a valid ext4 `dx_root` block.
///
/// Layout (fs/ext4/namei.c): `.` and `..` are FIXED 12-byte fake dirents, so
/// `dx_root_info` always starts at 24 and `entries[]` at 24 + info_length.
/// `..`'s rec_len spans the rest of the block on purpose, which is exactly why a
/// parser must not use it to step over the entry (BUG-177).
///
/// `entries` are (hash, block) pairs; entries[0]'s hash word is overlaid by
/// `dx_countlimit { limit, count }`. `trailing` slots are written past `count`:
/// a parser that honours `count` must never walk them (BUG-178).
fn create_dx_root(
    block_size: usize,
    indirect_levels: u8,
    entries: &[(u32, u32)],
    trailing: &[(u32, u32)],
) -> Vec<u8> {
    let mut block = vec![0u8; block_size];

    // "." fake dirent
    LittleEndian::write_u32(&mut block[0..4], 1);
    LittleEndian::write_u16(&mut block[4..6], 12);
    block[6] = 1; // name_len
    block[7] = 2; // file_type = directory
    block[8] = b'.';

    // ".." fake dirent: 12 bytes on disk, rec_len covers the rest of the block
    LittleEndian::write_u32(&mut block[12..16], 1);
    LittleEndian::write_u16(&mut block[16..18], (block_size - 12) as u16);
    block[18] = 2; // name_len
    block[19] = 2; // file_type = directory
    block[20] = b'.';
    block[21] = b'.';

    // dx_root_info at 24: reserved_zero(4) hash_version info_length
    // indirect_levels unused_flags
    block[28] = 1; // DX_HASH_HALF_MD4
    block[29] = 8; // info_length
    block[30] = indirect_levels;

    write_dx_entries(&mut block, 32, entries, trailing);
    block
}

/// Build an interior htree node (`dx_node`): an 8-byte fake dirent, then entries.
fn create_dx_node(block_size: usize, entries: &[(u32, u32)]) -> Vec<u8> {
    let mut block = vec![0u8; block_size];
    LittleEndian::write_u16(&mut block[4..6], block_size as u16); // rec_len
    write_dx_entries(&mut block, 8, entries, &[]);
    block
}

fn write_dx_entries(
    block: &mut [u8],
    entries_offset: usize,
    entries: &[(u32, u32)],
    trailing: &[(u32, u32)],
) {
    let limit = ((block.len() - entries_offset) / 8) as u16;
    LittleEndian::write_u16(&mut block[entries_offset..entries_offset + 2], limit);
    LittleEndian::write_u16(
        &mut block[entries_offset + 2..entries_offset + 4],
        entries.len() as u16,
    );
    for (i, (hash, blk)) in entries.iter().enumerate() {
        let base = entries_offset + i * 8;
        if i > 0 {
            // entries[0]'s hash word is the limit/count overlay
            LittleEndian::write_u32(&mut block[base..base + 4], *hash);
        }
        LittleEndian::write_u32(&mut block[base + 4..base + 8], *blk);
    }
    for (i, (hash, blk)) in trailing.iter().enumerate() {
        let base = entries_offset + (entries.len() + i) * 8;
        LittleEndian::write_u32(&mut block[base..base + 4], *hash);
        LittleEndian::write_u32(&mut block[base + 4..base + 8], *blk);
    }
}

/// A directory block holding one dirent whose `rec_len` spans the block, as a real leaf does.
fn leaf_dir_block(block_size: usize, inode: u32, name: &str) -> Vec<u8> {
    let mut block = vec![0u8; block_size];
    let mut entry = create_dir_entry(inode, name);
    // A real leaf's last entry spans the rest of the block.
    entry[4..6].copy_from_slice(&(block_size as u16).to_le_bytes());
    block[..entry.len()].copy_from_slice(&entry);
    block
}

/// Superblock + GDT (inode table at block 10) shared by the htree fixtures.
fn htree_fixture(size_blocks: usize) -> (MockDataSource, Superblock, Vec<BlockGroupDescriptor>) {
    let source = MockDataSource::new(4096 * size_blocks);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();

    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    (source, sb, groups)
}

/// BUG-177/BUG-178: a well-formed single-level htree must be walked from the
/// correctly aligned dx_root, and only the `dx_countlimit.count` entries may be
/// followed. Before the fix the ".." skip landed 2 bytes early, every dx_root
/// field was shifted, and entries were scanned until a zero hash/block pair.
#[test]
fn test_htree_root_alignment_and_entry_count() {
    let (source, sb, groups) = htree_fixture(100);

    // Directory inode: htree + extents, 3 blocks mapped logical 0..2 -> phys 20..22
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 3, 20));
    let inode_data = create_inode(0x4000 | 0o755, 3 * 4096, 0x80000 | 0x1000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    // dx_root: two leaves (logical blocks 1 and 2) plus a trailing slot past
    // `count` pointing at a block outside the directory. Honouring `count`
    // means that slot is never read.
    let root = create_dx_root(4096, 0, &[(0, 1), (0x1234_5678, 2)], &[(0xDEAD_BEEF, 99)]);
    source.write_at(20 * 4096, &root);
    source.write_at(21 * 4096, &leaf_dir_block(4096, 2, "alpha.txt"));
    source.write_at(22 * 4096, &leaf_dir_block(4096, 3, "beta.txt"));

    // Child inodes 2 and 3
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]),
    );
    source.write_at(
        10 * 4096 + 512,
        &create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]),
    );

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    let names: Vec<String> = produced
        .iter()
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        names.iter().any(|n| n == "alpha.txt"),
        "htree leaf 1 not walked: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "beta.txt"),
        "htree leaf 2 not walked: {names:?}"
    );
    assert_eq!(produced.len(), 3, "root dir + 2 files expected: {names:?}");
    assert!(
        produced[0]
            .metadata
            .get("directory_parse_incomplete")
            .is_none(),
        "a fully walked htree must not be flagged incomplete"
    );
}

/// BUG-178: with `indirect_levels = 1` the root entries address interior nodes,
/// not leaf directory blocks. Treating them as leaves loses every child.
#[test]
fn test_htree_multi_level_descends_index_nodes() {
    let (source, sb, groups) = htree_fixture(100);

    // 4 blocks: 0 = dx_root, 1 = dx_node, 2 = leaf, mapped to phys 20..23
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 4, 20));
    let inode_data = create_inode(0x4000 | 0o755, 4 * 4096, 0x80000 | 0x1000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    source.write_at(20 * 4096, &create_dx_root(4096, 1, &[(0, 1)], &[]));
    source.write_at(21 * 4096, &create_dx_node(4096, &[(0, 2)]));
    source.write_at(22 * 4096, &leaf_dir_block(4096, 2, "deep.txt"));
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]),
    );

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    assert!(
        produced.iter().any(|a| a.metadata["name"] == "deep.txt"),
        "two-level htree must descend the index node"
    );
    assert!(produced[0]
        .metadata
        .get("directory_parse_incomplete")
        .is_none());
}

/// BUG-179: a directory whose dirent data exceeds the 1 MiB scan cap loses its
/// later entries; the truncation must be visible on the directory artifact.
#[test]
fn test_linear_directory_over_cap_flags_incomplete() {
    let (source, sb, groups) = htree_fixture(400);

    // 300 blocks (~1.17 MiB) of directory data: past EXT4_MAX_DIR_BYTES.
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 300, 20));
    let dir_size = 300u64 * 4096;
    assert!(dir_size > EXT4_MAX_DIR_BYTES);
    let inode_data = create_inode(0x4000 | 0o755, dir_size, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    let mut dir_block = vec![0u8; 4096];
    let mut cursor = Cursor::new(&mut dir_block);
    cursor.write_all(&create_dir_entry(1, ".")).unwrap();
    cursor.write_all(&create_dir_entry(1, "..")).unwrap();
    cursor.write_all(&create_dir_entry(2, "big.txt")).unwrap();
    source.write_at(20 * 4096, &dir_block);
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]),
    );

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    // The entries we could read are still emitted...
    assert!(produced.iter().any(|a| a.metadata["name"] == "big.txt"));
    // ...but the directory is marked as only partially enumerated.
    assert_eq!(
        produced[0].metadata["directory_parse_incomplete"], true,
        "a directory larger than the scan cap must be flagged incomplete"
    );
}

/// BUG-180: an inode with EXT4_ENCRYPT_FL (0x800) serves fscrypt ciphertext
/// through its extents. The artifact must say so; a plain inode must not.
#[test]
fn test_encrypted_inode_marks_ciphertext() {
    let (source, sb, groups) = htree_fixture(100);

    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 30));
    // Inode 1: fscrypt-encrypted regular file.
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 100, 0x80000 | 0x800, &blocks),
    );
    // Inode 2: same, without the encrypt flag.
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 100, 0x80000, &blocks),
    );
    source.write_at(30 * 4096, b"opaque-bytes");

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/secret.bin").unwrap();
    parse_inode(&mut ctx, 2, "/plain.bin").unwrap();

    let secret = produced
        .iter()
        .find(|a| a.metadata["name"] == "secret.bin")
        .expect("encrypted inode artifact");
    assert_eq!(secret.metadata["encrypted"], true);
    assert_eq!(secret.metadata["content_ciphertext"], "ext4_fscrypt");
    // `content_ciphertext` is display only. The flag the API, export and
    // integrity-verify paths read is `content_incomplete`: without it the
    // ciphertext is hashed and exported as if it were the file's plaintext
    // and an examiner comparing it to a known-file hash set sees only a
    // non-match, with nothing to say why (B2-135).
    assert_eq!(secret.metadata["content_incomplete"], true);
    assert_eq!(secret.metadata["content_incomplete_reason"], "encrypted");

    let plain = produced
        .iter()
        .find(|a| a.metadata["name"] == "plain.bin")
        .expect("plain inode artifact");
    assert!(
        plain.metadata.get("encrypted").is_none(),
        "an unencrypted inode must not be flagged"
    );
    assert!(
        plain.metadata.get("content_incomplete").is_none(),
        "an unencrypted inode's content is complete"
    );
}

#[test]
fn test_extent_tree_depth_2() {
    // Test multi-level extent tree (depth=2: root -> index blocks -> leaf extents)
    let source = MockDataSource::new(4096 * 200);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create extent tree with depth=2
    // Root extent header points to index blocks
    let mut extent_tree = vec![];
    extent_tree.extend_from_slice(&create_extent_header(2, 2)); // depth=2, 2 entries

    // Two index entries pointing to leaf blocks
    // Index entry 1: points to block 50 (which contains leaf extents)
    let mut index_entry_1 = vec![0u8; 12];
    let mut cursor = Cursor::new(&mut index_entry_1);
    cursor.write_u32::<LittleEndian>(0).unwrap(); // first_logical_block
    cursor.write_u32::<LittleEndian>(50).unwrap(); // physical_block (lower 32 bits)
    cursor.write_u16::<LittleEndian>(0).unwrap(); // physical_block (upper 16 bits)
    extent_tree.extend_from_slice(&index_entry_1);

    // Index entry 2: points to block 51
    let mut index_entry_2 = vec![0u8; 12];
    let mut cursor = Cursor::new(&mut index_entry_2);
    cursor.write_u32::<LittleEndian>(100).unwrap(); // first_logical_block
    cursor.write_u32::<LittleEndian>(51).unwrap(); // physical_block
    cursor.write_u16::<LittleEndian>(0).unwrap();
    extent_tree.extend_from_slice(&index_entry_2);

    // Pad to 60 bytes
    extent_tree.resize(60, 0);

    // Create inode with this extent tree
    let offset = 10 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, 8192, 0x80000, &extent_tree);
    source.write_at(offset, &inode_data);

    // Create leaf extent blocks at blocks 50 and 51
    // Block 50: Contains extent leaves pointing to actual data blocks
    let mut leaf_block_1 = vec![0u8; 4096];
    let mut cursor = Cursor::new(&mut leaf_block_1);
    cursor.write_all(&create_extent_header(0, 1)).unwrap(); // depth=0 (leaf), 1 entry
    cursor.write_all(&create_extent_leaf(0, 2, 100)).unwrap(); // logical 0-1, physical 100-101 (2 blocks)
    source.write_at(50 * 4096, &leaf_block_1);

    // Block 51: More leaf extents
    let mut leaf_block_2 = vec![0u8; 4096];
    let mut cursor = Cursor::new(&mut leaf_block_2);
    cursor.write_all(&create_extent_header(0, 1)).unwrap();
    cursor.write_all(&create_extent_leaf(100, 2, 150)).unwrap(); // logical 100-101, physical 150-151
    source.write_at(51 * 4096, &leaf_block_2);

    // Write actual data to blocks 100, 101, 150, 151
    source.write_at(100 * 4096, b"First block data");
    source.write_at(101 * 4096, b"Second block data");
    source.write_at(150 * 4096, b"Third block data");
    source.write_at(151 * 4096, b"Fourth block data");

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    parse_inode(&mut ctx, 1, "/test_file").unwrap();

    // Verify file was parsed
    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0].metadata["name"], "test_file");
    assert_eq!(produced[0].metadata["size"], 8192);
}

#[test]
fn test_extent_tree_sparse_extents() {
    // Test extent tree with sparse/uninitialized extents (holes in file)
    let source = MockDataSource::new(4096 * 100);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create extent tree with gaps (sparse file)
    let mut extent_tree = vec![];
    extent_tree.extend_from_slice(&create_extent_header(1, 2)); // depth=1, 2 extents

    // Extent 1: logical blocks 0-9 -> physical blocks 20-29
    extent_tree.extend_from_slice(&create_extent_leaf(0, 10, 20));

    // Extent 2: logical blocks 100-109 -> physical blocks 30-39
    // This creates a sparse region (logical blocks 10-99 are holes)
    extent_tree.extend_from_slice(&create_extent_leaf(100, 10, 30));

    extent_tree.resize(60, 0);

    let offset = 10 * 4096;
    // File size represents full range including sparse regions
    let file_size = 110 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, file_size, 0x80000, &extent_tree);
    source.write_at(offset, &inode_data);

    // Write some data to allocated blocks
    source.write_at(20 * 4096, b"Data in first extent");
    source.write_at(30 * 4096, b"Data in second extent after hole");

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    parse_inode(&mut ctx, 1, "/sparse_file").unwrap();

    // Verify sparse file was parsed
    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0].metadata["name"], "sparse_file");
    assert_eq!(produced[0].metadata["size"], file_size);
}

#[test]
fn test_extent_tree_error_handling_invalid_magic() {
    // Test that invalid extent header magic is handled gracefully
    let source = MockDataSource::new(4096 * 50);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create extent tree with INVALID magic number
    let mut extent_tree = vec![0u8; 60];
    let mut cursor = Cursor::new(&mut extent_tree);
    cursor.write_u16::<LittleEndian>(0xBADF).unwrap(); // Invalid magic (should be 0xF30A)
    cursor.write_u16::<LittleEndian>(1).unwrap(); // entries
    cursor.write_u16::<LittleEndian>(1).unwrap(); // max
    cursor.write_u16::<LittleEndian>(0).unwrap(); // depth

    let offset = 10 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, 4096, 0x80000, &extent_tree);
    source.write_at(offset, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    // Should handle gracefully (either error or ignore bad extents)
    let result = parse_inode(&mut ctx, 1, "/invalid_extent");
    // Parser may either reject invalid magic (Err) or ignore it (Ok with 0 or 1 artifacts)
    // The key is it shouldn't panic
    match result {
        Ok(_) => {
            // Parser gracefully ignored invalid extent magic
            // This is acceptable behavior
        }
        Err(_) => {
            // Parser rejected invalid magic
            // This is also acceptable
        }
    }
}

#[test]
fn test_extent_tree_error_handling_depth_mismatch() {
    // Test that mismatched extent tree depth is handled
    let source = MockDataSource::new(4096 * 50);
    let sb_data = create_valid_superblock();
    source.write_at(1024, &sb_data);
    let sb = Superblock::parse(&source).unwrap();

    // Setup GDT
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Create extent tree claiming depth=2 but providing leaf extents
    let mut extent_tree = vec![];
    extent_tree.extend_from_slice(&create_extent_header(2, 1)); // Claim depth=2
                                                                // But add a leaf extent (which is depth=0 format)
    extent_tree.extend_from_slice(&create_extent_leaf(0, 1, 20));
    extent_tree.resize(60, 0);

    let offset = 10 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, 4096, 0x80000, &extent_tree);
    source.write_at(offset, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    // Should handle gracefully (either error or degrade gracefully)
    let result = parse_inode(&mut ctx, 1, "/depth_mismatch");
    // We allow either success (if parser is forgiving) or error (if strict)
    // The key is it shouldn't panic
    match result {
        Ok(_) => {
            // Parser was forgiving and handled it
        }
        Err(_) => {
            // Parser rejected invalid structure
        }
    }
}

// --- Timestamp decoding (crtime, extra epoch/nanosecond bits) ---

#[test]
fn test_decode_extra_time_epoch_and_nanos() {
    // extra layout: bits 1-0 = epoch extension, bits 31-2 = nanoseconds
    let (secs, nanos) = decode_extra_time(0x1234, (500 << 2) | 1);
    assert_eq!(
        secs,
        0x1234 + (1i64 << 32),
        "epoch bit must add 2^32 seconds"
    );
    assert_eq!(nanos, 500);

    // No extra bits: plain 32-bit seconds
    let (secs, nanos) = decode_extra_time(1_700_000_000, 0);
    assert_eq!(secs, 1_700_000_000);
    assert_eq!(nanos, 0);
}

#[test]
fn test_inode_crtime_and_extra_parsing() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();

    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // 256-byte inode with extended fields
    let mut inode_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    {
        let mut c = Cursor::new(&mut inode_data);
        c.seek(SeekFrom::Start(128)).unwrap();
        c.write_u16::<LittleEndian>(32).unwrap(); // i_extra_isize
        c.seek(SeekFrom::Start(144)).unwrap();
        c.write_u32::<LittleEndian>(1_600_000_000).unwrap(); // i_crtime
        c.write_u32::<LittleEndian>(123 << 2).unwrap(); // i_crtime_extra: 123ns
    }
    source.write_at(10 * 4096, &inode_data);

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    assert_eq!(inode.crtime_ts(), Some((1_600_000_000i64, 123u32)));
}

#[test]
fn test_metadata_changed_vs_created() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();

    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Inode 1: ctime set, no crtime (extra_isize = 0)
    let mut inode_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    {
        let mut c = Cursor::new(&mut inode_data);
        c.seek(SeekFrom::Start(8)).unwrap();
        c.write_u32::<LittleEndian>(1_111_111_111).unwrap(); // atime
        c.write_u32::<LittleEndian>(1_222_222_222).unwrap(); // ctime
        c.write_u32::<LittleEndian>(1_333_333_333).unwrap(); // mtime
    }
    source.write_at(10 * 4096, &inode_data);

    // Inode 2: same but with crtime present
    let mut inode2_data = inode_data.clone();
    {
        let mut c = Cursor::new(&mut inode2_data);
        c.seek(SeekFrom::Start(128)).unwrap();
        c.write_u16::<LittleEndian>(32).unwrap(); // i_extra_isize
        c.seek(SeekFrom::Start(144)).unwrap();
        c.write_u32::<LittleEndian>(1_000_000_000).unwrap(); // i_crtime
    }
    source.write_at(10 * 4096 + 256, &inode2_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };

    parse_inode(&mut ctx, 1, "/no_crtime.txt").unwrap();
    parse_inode(&mut ctx, 2, "/with_crtime.txt").unwrap();
    assert_eq!(produced.len(), 2);

    // Without crtime: ctime must be labeled "changed", not "created"
    let a = &produced[0].metadata;
    assert!(
        a.get("created").is_none(),
        "ctime must not be mislabeled as created"
    );
    assert!(
        a["changed"].as_str().unwrap().starts_with("2008-09-24"),
        "changed should be ctime, got {:?}",
        a["changed"]
    );
    assert!(a["modified"].as_str().unwrap().starts_with("2012-04-02"));
    assert!(a["accessed"].as_str().unwrap().starts_with("2005-03-18"));

    // With crtime: "created" comes from i_crtime
    let b = &produced[1].metadata;
    assert!(
        b["created"].as_str().unwrap().starts_with("2001-09-09"),
        "created should be crtime, got {:?}",
        b["created"]
    );
    assert!(b["changed"].as_str().unwrap().starts_with("2008-09-24"));
}

// --- Data runs metadata contract ---

fn setup_fs(source: &MockDataSource) -> (Superblock, Vec<BlockGroupDescriptor>) {
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap(); // inode table at block 10
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(source, &sb).unwrap();
    (sb, groups)
}

#[test]
fn test_data_runs_from_extents() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    // File with a single extent: logical 0, len 2, physical 30
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 2, 30));

    let inode_data = create_inode(0x8000 | 0o644, 8192, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/extent.bin").unwrap();

    assert_eq!(produced.len(), 1);
    let meta = &produced[0].metadata;
    assert_eq!(
        meta["data_runs"],
        serde_json::json!([[30u64 * 4096, 2u64 * 4096]])
    );
    assert_eq!(meta["data_runs_complete"], true);
}

#[test]
fn test_data_runs_sparse_and_coalesced_extents() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    // Three extents: logical 0-1 phys 20, logical 2 phys 22 (contiguous with
    // previous physically), then a hole, then logical 10 phys 40
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(3, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 2, 20));
    blocks.extend_from_slice(&create_extent_leaf(2, 1, 22));
    blocks.extend_from_slice(&create_extent_leaf(10, 1, 40));

    let file_size = 11 * 4096;
    let inode_data = create_inode(0x8000 | 0o644, file_size, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/sparse.bin").unwrap();

    assert_eq!(produced.len(), 1);
    let meta = &produced[0].metadata;
    // 3 physical blocks coalesced, sparse hole of 7 blocks, final block
    assert_eq!(
        meta["data_runs"],
        serde_json::json!([
            [20u64 * 4096, 3u64 * 4096],
            [serde_json::Value::Null, 7u64 * 4096],
            [40u64 * 4096, 4096u64],
        ])
    );
    assert_eq!(meta["data_runs_complete"], true);
}

#[test]
fn test_data_runs_block_mapped() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    // Legacy block-mapped file: direct blocks 20, 21 (contiguous)
    let mut block_ptrs = vec![0u8; 60];
    block_ptrs[0..4].copy_from_slice(&20u32.to_le_bytes());
    block_ptrs[4..8].copy_from_slice(&21u32.to_le_bytes());

    let inode_data = create_inode(0x8000 | 0o644, 8192, 0, &block_ptrs);
    source.write_at(10 * 4096, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/mapped.bin").unwrap();

    assert_eq!(produced.len(), 1);
    let meta = &produced[0].metadata;
    assert_eq!(
        meta["data_runs"],
        serde_json::json!([[20u64 * 4096, 2u64 * 4096]])
    );
    assert_eq!(meta["data_runs_complete"], true);
}

#[test]
fn test_directories_have_no_data_runs() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));
    let inode_data = create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/dir").unwrap();

    assert!(!produced.is_empty());
    assert!(produced[0].metadata.get("data_runs").is_none());
}

// --- Unwritten (preallocated) extents and sparse holes ---

/// BUG-207: `ee_len > 32768` marks an unwritten (fallocate'd) extent. The
/// kernel serves zeros for it; the residual bytes sitting at its physical
/// blocks are NOT file content and must never be read or persisted as runs.
#[test]
fn test_unwritten_extent_reads_as_zeros() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(2, 0));
    // Written extent: logical block 0 -> physical 30
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 30));
    // Unwritten extent: logical block 1 -> physical 31, ee_len = 1 | 32768
    blocks.extend_from_slice(&create_extent_leaf(1, 1 + 32768, 31));
    let inode_data = create_inode(0x8000 | 0o644, 2 * 4096, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    source.write_at(30 * 4096, b"real file data");
    // Residual data left behind in the preallocated (never written) blocks.
    source.write_at(31 * 4096, b"RESIDUAL SECRET");

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    let fs = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);

    // The written extent still serves its real bytes.
    let mut first = vec![0u8; 14];
    assert_eq!(fs.read_at(0, &mut first).unwrap(), 14);
    assert_eq!(&first, b"real file data");

    // The unwritten extent must read as zeros, not as the residual bytes.
    let mut second = vec![0u8; 4096];
    assert_eq!(fs.read_at(4096, &mut second).unwrap(), 4096);
    assert!(
        second.iter().all(|&b| b == 0),
        "unwritten extent must read as zeros, got residual disk bytes"
    );

    // The persisted runs must mark the unwritten range sparse so a later
    // re-serve from the DB cannot resurrect the residual bytes either.
    let collected = fs.collect_runs().unwrap();
    assert_eq!(
        collected.runs,
        vec![(Some(30u64 * 4096), 4096u64), (None, 4096u64)]
    );
    assert!(collected.complete);
    assert!(collected.unwritten);
}

/// The honesty flag rides along on the artifact metadata.
#[test]
fn test_unwritten_extent_flagged_in_metadata() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 2 + 32768, 40));
    let inode_data = create_inode(0x8000 | 0o644, 2 * 4096, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/prealloc.bin").unwrap();

    assert_eq!(produced.len(), 1);
    let meta = &produced[0].metadata;
    assert_eq!(meta["has_unwritten_extents"], true);
    // Two preallocated blocks -> one sparse run covering the whole file.
    assert_eq!(
        meta["data_runs"],
        serde_json::json!([[serde_json::Value::Null, 2u64 * 4096]])
    );
}

/// BUG-211: a hole between extents must read as zeros. Previously the read
/// stopped at the hole and returned a short (or zero-length) read, which
/// callers take for EOF -- ingest hashed a truncated prefix.
#[test]
fn test_sparse_hole_between_extents_is_zero_filled() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(2, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 30));
    // logical block 1 is a hole; logical block 2 -> physical 32
    blocks.extend_from_slice(&create_extent_leaf(2, 1, 32));
    let inode_data = create_inode(0x8000 | 0o644, 3 * 4096, 0x80000, &blocks);
    source.write_at(10 * 4096, &inode_data);

    source.write_at(30 * 4096, b"head");
    source.write_at(32 * 4096, b"tail");

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    let fs = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);

    // A read that starts inside the hole must make progress, not return 0.
    let mut hole = vec![0xAAu8; 4096];
    let n = fs.read_at(4096, &mut hole).unwrap();
    assert_eq!(n, 4096, "a hole must be zero-filled, not reported as EOF");
    assert!(hole.iter().all(|&b| b == 0));

    // A whole-file read spans head, hole and tail in one go.
    let mut all = vec![0xAAu8; 3 * 4096];
    assert_eq!(fs.read_at(0, &mut all).unwrap(), 3 * 4096);
    assert_eq!(&all[0..4], b"head");
    assert!(all[4096..8192].iter().all(|&b| b == 0));
    assert_eq!(&all[8192..8196], b"tail");
}

/// The same hole handling has to hold through an extent *tree* (depth > 0),
/// where a hole sits at the tail of one leaf's coverage.
#[test]
fn test_sparse_hole_in_extent_tree_is_zero_filled() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs(&source);

    // Root (in inode): depth 1, one index entry covering logical block 0+.
    let mut root_blocks = vec![];
    root_blocks.extend_from_slice(&create_extent_header(1, 1));
    root_blocks.extend_from_slice(&create_extent_idx(0, 50));
    let inode_data = create_inode(0x8000 | 0o644, 3 * 4096, 0x80000, &root_blocks);
    source.write_at(10 * 4096, &inode_data);

    // Leaf at block 50: logical 0 -> physical 60, then a hole to EOF.
    let mut leaf = vec![0u8; 4096];
    let mut leaf_cursor = Cursor::new(&mut leaf);
    leaf_cursor.write_all(&create_extent_header(1, 0)).unwrap();
    leaf_cursor
        .write_all(&create_extent_leaf(0, 1, 60))
        .unwrap();
    source.write_at(50 * 4096, &leaf);
    source.write_at(60 * 4096, b"only block");

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    let fs = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);

    let mut all = vec![0xAAu8; 3 * 4096];
    assert_eq!(fs.read_at(0, &mut all).unwrap(), 3 * 4096);
    assert_eq!(&all[0..10], b"only block");
    assert!(all[4096..].iter().all(|&b| b == 0));
}

// --- Allocation map ---

#[test]
fn test_allocation_map_from_block_bitmap() {
    // The image holds all 1000 blocks the superblock declares: the map covers
    // what fits in the image, so a shorter image would (rightly) shrink it.
    let source = MockDataSource::new(4096 * 1000);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();

    // GDT: block bitmap at block 5, inode table at block 10
    let mut gdt_entry = vec![0u8; 64];
    {
        let mut cursor = Cursor::new(&mut gdt_entry);
        cursor.write_u32::<LittleEndian>(5).unwrap(); // block_bitmap_lo
        cursor.write_u32::<LittleEndian>(6).unwrap(); // inode_bitmap_lo
        cursor.write_u32::<LittleEndian>(10).unwrap(); // inode_table_lo
    }
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Bitmap: first 8 blocks allocated (superblock says 1000 blocks total)
    source.write_at(5 * 4096, &[0xFFu8]);

    let case_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let source_arc: Arc<dyn DataSource> = Arc::new(MockDataSource::new(4096 * 1000));
    let (artifact, free_regions) =
        build_allocation_map_artifact(case_id, parent_id, &source, &source_arc, &sb, &groups)
            .expect("allocation map should be emitted");

    // The free blocks as regions the carver reads (§5.4): 1,000 blocks, the
    // first eight in use, so one run of 992 from block 8.
    assert_eq!(
        free_regions
            .iter()
            .map(|r| (
                r.metadata["first_cluster"].as_u64().unwrap(),
                r.metadata["clusters"].as_u64().unwrap(),
                r.metadata["offset_bytes"].as_u64().unwrap(),
            ))
            .collect::<Vec<_>>(),
        vec![(8, 992, 8 * 4096)],
        "ext4 numbers blocks from the volume's start, so a block's offset is its own number \
         times the block size"
    );
    assert_eq!(artifact.metadata["free_regions_emitted"], 1);
    assert_eq!(artifact.metadata["free_bytes_emitted"], 992u64 * 4096);
    for region in &free_regions {
        assert_eq!(region.metadata["filesystem"], "ext4");
        assert_eq!(region.parent_id, Some(parent_id));
    }

    assert_eq!(artifact.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(artifact.parent_id, Some(parent_id));
    let meta = &artifact.metadata;
    assert_eq!(meta["type"], "allocation_map");
    assert_eq!(meta["allocation_total_clusters"], 1000);
    assert_eq!(meta["allocation_cluster_size"], 4096);
    assert_eq!(meta["allocation_clusters_per_bucket"], 1);

    use base64::Engine as _;
    let buckets = base64::engine::general_purpose::STANDARD
        .decode(meta["allocation_bitmap_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(buckets.len(), 1000);
    assert!(buckets[..8].iter().all(|&b| b == 255));
    assert!(buckets[8..].iter().all(|&b| b == 0));
}

#[test]
fn test_allocation_map_omitted_without_bitmap() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source); // GDT has block_bitmap = 0

    let source_arc: Arc<dyn DataSource> = Arc::new(MockDataSource::new(0));
    let artifact = build_allocation_map_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &source,
        &source_arc,
        &sb,
        &groups,
    );
    assert!(
        artifact.is_none(),
        "missing bitmap must omit the allocation map, and with it every free-space region: a \
         volume whose bitmaps could not be read has no free space anyone established"
    );
}

// --- Real image integration ---

#[test]
fn test_real_ext4_image_contract() {
    let path = std::path::Path::new("../test_data/ext4.raw");
    if !path.exists() {
        eprintln!("skipping: ../test_data/ext4.raw not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture ext4.raw missing");
    let source: Arc<dyn DataSource> = Arc::new(MockDataSource {
        data: Arc::new(Mutex::new(data)),
    });

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"filesystem_type": "ext4"}),
    );

    let parser = Ext4Parser::new();
    let results = parser.process(&artifact).unwrap();

    let entries: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();
    assert!(!entries.is_empty(), "expected file entries from ext4.raw");

    // Path contract on every FileEntry
    for entry in &entries {
        assert!(entry.metadata["path"].as_str().unwrap().starts_with('/'));
        assert!(entry.metadata.get("parent_path").is_some());
    }

    // At least one regular file with content persists data runs
    let with_runs: Vec<_> = entries
        .iter()
        .filter(|e| e.metadata.get("data_runs").is_some())
        .collect();
    assert!(!with_runs.is_empty(), "expected data_runs on regular files");
    for entry in &with_runs {
        assert!(entry.metadata["data_runs"].is_array());
        assert!(entry.metadata["data_runs_complete"].is_boolean());
    }

    // Allocation map emitted as a ParsedRecord child of the input artifact
    let map = results
        .iter()
        .find(|a| {
            a.artifact_type == ArtifactType::ParsedRecord && a.metadata["type"] == "allocation_map"
        })
        .expect("allocation_map should be emitted for a real image");
    assert_eq!(map.parent_id, Some(artifact.id));
    assert_eq!(map.metadata["allocation_cluster_size"], 1024);
    assert_eq!(map.metadata["allocation_total_clusters"], 4096);
    assert!(map.metadata["allocation_bitmap_b64"].is_string());
    assert_eq!(map.metadata["allocation_clusters_per_bucket"], 1);
}

#[test]
fn test_ext4_progress_reporter_receives_file_events() {
    use seance_core::orchestrator::{OrchestratorEvent, ProgressReporter};

    let path = std::path::Path::new("../test_data/ext4.raw");
    if !path.exists() {
        eprintln!("skipping: ../test_data/ext4.raw not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture ext4.raw missing");
    let source: Arc<dyn DataSource> = Arc::new(MockDataSource {
        data: Arc::new(Mutex::new(data)),
    });

    let (tx, mut rx) = tokio::sync::broadcast::channel(4096);
    let reporter = ProgressReporter::new(tx, "plugin.fs.ext4");
    let parser = Ext4Parser::new().with_progress(reporter);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"filesystem_type": "ext4"}),
    );
    let artifact_id = artifact.id;
    parser.process(&artifact).unwrap();

    let mut saw_files = false;
    while let Ok(event) = rx.try_recv() {
        if let OrchestratorEvent::ModuleProgress {
            module_id,
            artifact_id: reported_id,
            units_total,
            unit,
            ..
        } = event
        {
            assert_eq!(module_id, "plugin.fs.ext4");
            assert_eq!(reported_id, artifact_id);
            assert_eq!(unit, "files");
            assert!(
                units_total.unwrap() > 0,
                "denominator must be a real inode count"
            );
            saw_files = true;
        }
    }
    assert!(
        saw_files,
        "expected at least one ModuleProgress event with unit=files"
    );
}

#[test]
fn test_ext4_cancellation_returns_early() {
    use seance_core::orchestrator::CancellationHandle;

    let path = std::path::Path::new("../test_data/ext4.raw");
    if !path.exists() {
        eprintln!("skipping: ../test_data/ext4.raw not present (gitignored corpus, absent in CI)");
        return;
    }
    let data = std::fs::read(path).expect("fixture ext4.raw missing");
    let source: Arc<dyn DataSource> = Arc::new(MockDataSource {
        data: Arc::new(Mutex::new(data)),
    });

    let handle = CancellationHandle::new();
    handle.cancel_all();
    let parser = Ext4Parser::new().with_cancellation(handle);

    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(source),
        serde_json::json!({"filesystem_type": "ext4"}),
    );
    let results = parser.process(&artifact).unwrap();

    // A full walk of this image yields several FileEntry artifacts; a
    // pre-cancelled run must bail at the root inode before producing any.
    let entries = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .count();
    assert!(
        entries < 5,
        "cancelled parse should stop early, got {} entries",
        entries
    );
}

#[test]
fn test_ext4_log_block_size_out_of_range_is_rejected() {
    // Reproduces the fuzz crash: log_block_size = 99 makes `1024 << log_block_size`
    // overflow the shift (panic in debug, a wrapped bogus block size in release).
    // Superblock::parse must reject any value outside ext4's 0..=6 range.
    let source = MockDataSource::new(2048);
    // Valid magic 0xEF53 at superblock offset 56 -> file offset 1080.
    source.write_u16(1080, 0xEF53);
    // log_block_size (u32) at superblock offset 24 -> file offset 1048.
    source.write_u32(1048, 99);

    let err = Superblock::parse(&source).expect_err("out-of-range log_block_size must error");
    assert!(
        err.to_string().contains("log_block_size"),
        "unexpected error: {err}"
    );
}

// ============================================================================
// GAP 1 -- Extended attributes (xattrs)
// ============================================================================

/// Build a block-based xattr block: 32-byte ext4_xattr_header followed by
/// entries (from offset 32 upward) and values (packed from the block end
/// downward). `entries` = (e_name_index, name, value). Value offsets are
/// measured from the start of the block (block-xattr semantics).
fn build_xattr_block(block_size: usize, entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
    let mut block = vec![0u8; block_size];
    LittleEndian::write_u32(&mut block[0..4], 0xEA02_0000); // h_magic
    block[4..8].copy_from_slice(&1u32.to_le_bytes()); // h_refcount
    block[8..12].copy_from_slice(&1u32.to_le_bytes()); // h_blocks

    let mut entry_pos = 32usize;
    let mut value_top = block_size;
    for (idx, name, value) in entries {
        let name_bytes = name.as_bytes();
        let nlen = name_bytes.len();
        let value_pos = (value_top - value.len()) & !3;
        block[value_pos..value_pos + value.len()].copy_from_slice(value);
        value_top = value_pos;

        block[entry_pos] = nlen as u8; // e_name_len
        block[entry_pos + 1] = *idx; // e_name_index
        LittleEndian::write_u16(&mut block[entry_pos + 2..entry_pos + 4], value_pos as u16);
        // e_value_inum (4) = 0
        LittleEndian::write_u32(
            &mut block[entry_pos + 8..entry_pos + 12],
            value.len() as u32,
        );
        // e_hash (4) = 0
        block[entry_pos + 16..entry_pos + 16 + nlen].copy_from_slice(name_bytes);

        entry_pos += (16 + nlen).div_ceil(4) * 4;
    }
    block
}

/// Write in-inode xattrs into an inode buffer. The ibody header magic sits at
/// `128 + extra_isize`; entries begin right after it (IFIRST) and value offsets
/// are measured from IFIRST.
fn write_inode_xattrs(inode: &mut [u8], extra_isize: u16, entries: &[(u8, &str, &[u8])]) {
    let inode_size = inode.len();
    LittleEndian::write_u16(&mut inode[128..130], extra_isize);
    let hdr = 128 + extra_isize as usize;
    LittleEndian::write_u32(&mut inode[hdr..hdr + 4], 0xEA02_0000);
    let ifirst = hdr + 4;

    let mut entry_pos = ifirst;
    let mut value_top = inode_size;
    for (idx, name, value) in entries {
        let name_bytes = name.as_bytes();
        let nlen = name_bytes.len();
        let value_pos = (value_top - value.len()) & !3;
        inode[value_pos..value_pos + value.len()].copy_from_slice(value);
        value_top = value_pos;

        inode[entry_pos] = nlen as u8;
        inode[entry_pos + 1] = *idx;
        LittleEndian::write_u16(
            &mut inode[entry_pos + 2..entry_pos + 4],
            (value_pos - ifirst) as u16,
        );
        LittleEndian::write_u32(
            &mut inode[entry_pos + 8..entry_pos + 12],
            value.len() as u32,
        );
        inode[entry_pos + 16..entry_pos + 16 + nlen].copy_from_slice(name_bytes);

        entry_pos += (16 + nlen).div_ceil(4) * 4;
    }
}

fn ctx_for<'a>(
    source: &MockDataSource,
    sb: &'a Superblock,
    groups: &'a Vec<BlockGroupDescriptor>,
    produced: &'a mut Vec<Artifact>,
) -> ParsingContext<'a> {
    ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: sb,
        groups,
        produced_artifacts: produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    }
}

#[test]
fn test_xattr_prefix_table() {
    assert_eq!(xattr_prefix(1), Some("user."));
    assert_eq!(xattr_prefix(2), Some("system.posix_acl_access"));
    assert_eq!(xattr_prefix(3), Some("system.posix_acl_default"));
    assert_eq!(xattr_prefix(4), Some("trusted."));
    assert_eq!(xattr_prefix(6), Some("security."));
    assert_eq!(xattr_prefix(7), Some("system."));
    assert_eq!(xattr_prefix(8), Some("system.richacl"));
    assert_eq!(xattr_prefix(99), None);
}

#[test]
fn test_xattr_block_parsing() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    // Regular file inode with i_file_acl pointing to block 40.
    let mut inode_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    inode_data[104..108].copy_from_slice(&40u32.to_le_bytes()); // i_file_acl_lo
    source.write_at(10 * 4096, &inode_data);

    let block = build_xattr_block(
        4096,
        &[(1, "comment", b"hello"), (6, "selinux", b"system_u")],
    );
    source.write_at(40 * 4096, &block);

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/file.txt").unwrap();

    assert_eq!(produced.len(), 1);
    let x = &produced[0].metadata["xattrs"];
    assert_eq!(x["user.comment"], "hello");
    assert_eq!(x["security.selinux"], "system_u");
}

#[test]
fn test_xattr_in_inode_parsing() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut inode_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    write_inode_xattrs(&mut inode_data, 32, &[(1, "foo", b"bar")]);
    source.write_at(10 * 4096, &inode_data);

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/inline.txt").unwrap();

    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0].metadata["xattrs"]["user.foo"], "bar");
}

#[test]
fn test_xattr_binary_value_base64() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut inode_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    inode_data[104..108].copy_from_slice(&40u32.to_le_bytes());
    source.write_at(10 * 4096, &inode_data);

    // index 2 => "system.posix_acl_access" with empty name; binary value.
    let value = [0u8, 1, 2, 255];
    let block = build_xattr_block(4096, &[(2, "", &value)]);
    source.write_at(40 * 4096, &block);

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/acl.bin").unwrap();

    let v = produced[0].metadata["xattrs"]["system.posix_acl_access"]
        .as_str()
        .unwrap();
    assert!(v.starts_with("base64:"), "binary value must be base64: {v}");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&v["base64:".len()..])
        .unwrap();
    assert_eq!(decoded, value.to_vec());
}

#[test]
fn test_xattr_out_of_bounds_no_panic() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let mut inode_data = create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]);
    inode_data[104..108].copy_from_slice(&40u32.to_le_bytes());
    source.write_at(10 * 4096, &inode_data);

    // Valid magic, one entry whose value offset/size point far outside the block.
    let mut block = vec![0u8; 4096];
    LittleEndian::write_u32(&mut block[0..4], 0xEA02_0000);
    block[32] = 3; // e_name_len
    block[33] = 1; // e_name_index (user.)
    LittleEndian::write_u16(&mut block[34..36], 65000); // e_value_offs (OOB)
    LittleEndian::write_u32(&mut block[40..44], 999_999); // e_value_size (OOB)
    block[48..51].copy_from_slice(b"key");
    source.write_at(40 * 4096, &block);

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    // Must not panic; the artifact is still produced.
    parse_inode(&mut ctx, 1, "/oob.bin").unwrap();
    assert_eq!(produced.len(), 1);
    // The out-of-bounds value is skipped (empty), never read past the block.
    let x = produced[0]
        .metadata
        .get("xattrs")
        .expect("xattrs must be present: the entry itself is well-formed");
    assert_eq!(x["user.key"], "");
}

// ============================================================================
// GAP 2 -- JBD2 journal parsing
// ============================================================================

fn jbd2_header(buf: &mut [u8], blocktype: u32, sequence: u32) {
    BigEndian::write_u32(&mut buf[0..4], 0xC03B_3998); // h_magic
    BigEndian::write_u32(&mut buf[4..8], blocktype); // h_blocktype
    BigEndian::write_u32(&mut buf[8..12], sequence); // h_sequence
}

fn build_journal_superblock(
    block_size: usize,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
    feature_incompat: u32,
) -> Vec<u8> {
    let mut b = vec![0u8; block_size];
    jbd2_header(&mut b, 4, 0); // JBD2_SUPERBLOCK_V2
    BigEndian::write_u32(&mut b[12..16], block_size as u32); // s_blocksize
    BigEndian::write_u32(&mut b[16..20], maxlen); // s_maxlen
    BigEndian::write_u32(&mut b[20..24], first); // s_first
    BigEndian::write_u32(&mut b[24..28], sequence); // s_sequence
    BigEndian::write_u32(&mut b[28..32], start); // s_start
    BigEndian::write_u32(&mut b[40..44], feature_incompat); // s_feature_incompat
    b
}

/// Non-64bit, non-csum-v3 descriptor block (8-byte tags). The first tag carries
/// a 16-byte UUID (SAME_UUID unset); the last tag sets LAST_TAG.
fn build_descriptor_block(block_size: usize, sequence: u32, targets: &[u32]) -> Vec<u8> {
    let mut b = vec![0u8; block_size];
    jbd2_header(&mut b, 1, sequence);
    let mut pos = 12;
    for (i, &t) in targets.iter().enumerate() {
        BigEndian::write_u32(&mut b[pos..pos + 4], t); // t_blocknr
        let mut flags: u16 = 0;
        if i > 0 {
            flags |= 2; // JBD2_FLAG_SAME_UUID
        }
        if i == targets.len() - 1 {
            flags |= 8; // JBD2_FLAG_LAST_TAG
        }
        BigEndian::write_u16(&mut b[pos + 6..pos + 8], flags);
        pos += 8;
        if flags & 2 == 0 {
            pos += 16; // 16-byte UUID follows the first tag
        }
    }
    b
}

fn build_commit_block(block_size: usize, sequence: u32) -> Vec<u8> {
    let mut b = vec![0u8; block_size];
    jbd2_header(&mut b, 2, sequence);
    b
}

fn build_revoke_block(block_size: usize, sequence: u32, revoked: &[u32]) -> Vec<u8> {
    let mut b = vec![0u8; block_size];
    jbd2_header(&mut b, 5, sequence);
    BigEndian::write_u32(&mut b[12..16], (16 + revoked.len() * 4) as u32); // r_count
    let mut pos = 16;
    for &r in revoked {
        BigEndian::write_u32(&mut b[pos..pos + 4], r);
        pos += 4;
    }
    b
}

/// Superblock with HAS_JOURNAL compat + s_journal_inum = 8, group 0 inode table
/// at block 10.
fn setup_fs_journal(source: &MockDataSource) -> (Superblock, Vec<BlockGroupDescriptor>) {
    source.write_at(1024, &create_valid_superblock());
    source.write_u32(1024 + 92, 0x4); // s_feature_compat: HAS_JOURNAL
    source.write_u32(1024 + 224, 8); // s_journal_inum
    let sb = Superblock::parse(source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(source, &sb).unwrap();
    (sb, groups)
}

/// Install inode 8 (journal) as a single-extent file mapping logical blocks
/// 0..N to physical `phys_start..`, and write the journal blocks there.
fn install_journal(source: &MockDataSource, phys_start: u64, journal_blocks: &[Vec<u8>]) {
    let n = journal_blocks.len() as u16;
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, n, phys_start));
    let inode_data = create_inode(0x8000 | 0o600, (n as u64) * 4096, 0x80000, &blocks);
    // inode 8 -> index 7 in group 0 inode table (block 10).
    source.write_at(10 * 4096 + 7 * 256, &inode_data);
    for (i, blk) in journal_blocks.iter().enumerate() {
        source.write_at((phys_start + i as u64) * 4096, blk);
    }
}

fn journal_source(source: &MockDataSource) -> Arc<dyn DataSource> {
    Arc::new(source.clone()) as Arc<dyn DataSource>
}

#[test]
fn test_journal_superblock_parse_fields() {
    let b = build_journal_superblock(4096, 1024, 1, 5, 3, 0x2);
    let jsb = JournalSuperblock::parse(&b).unwrap();
    assert_eq!(jsb.blocksize, 4096);
    assert_eq!(jsb.maxlen, 1024);
    assert_eq!(jsb.first, 1);
    assert_eq!(jsb.sequence, 5);
    assert_eq!(jsb.start, 3);
    assert!(jsb.is_64bit());
    assert_eq!(jsb.tag_bytes(), 12);

    let mut bad = b.clone();
    bad[0] = 0; // corrupt magic
    assert!(JournalSuperblock::parse(&bad).is_none());
}

#[test]
fn test_journal_descriptor_tags_64bit() {
    // 64bit feature => 12-byte tags with a high 32-bit block half.
    let mut block = vec![0u8; 4096];
    jbd2_header(&mut block, 1, 7);
    BigEndian::write_u32(&mut block[12..16], 0x1000); // t_blocknr (low)
    BigEndian::write_u16(&mut block[18..20], 2 | 8); // t_flags: SAME_UUID | LAST_TAG
    BigEndian::write_u32(&mut block[20..24], 0x2); // t_blocknr_high

    let (targets, last_tag_seen) = parse_descriptor_tags(&block, 12, false, true);
    assert_eq!(targets, vec![(0x2u64 << 32) | 0x1000]);
    assert!(last_tag_seen, "the tag carries JBD2_FLAG_LAST_TAG");
}

#[test]
fn test_journal_single_transaction() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs_journal(&source);

    // [0]=sb [1]=descriptor(seq2,[100,101]) [2]=data [3]=data [4]=commit(seq2)
    let journal_blocks = vec![
        build_journal_superblock(4096, 5, 1, 2, 1, 0),
        build_descriptor_block(4096, 2, &[100, 101]),
        vec![0xAAu8; 4096],
        vec![0xBBu8; 4096],
        build_commit_block(4096, 2),
    ];
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("journal artifact");
    assert_eq!(art.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(art.metadata["type"], "ext4_journal");
    assert_eq!(art.metadata["journal_inode"], 8);
    assert_eq!(art.metadata["transaction_count"], 1);

    let txns = art.metadata["transactions"].as_array().unwrap();
    assert_eq!(txns.len(), 1);
    assert_eq!(txns[0]["sequence"], 2);
    assert_eq!(txns[0]["blocks"], serde_json::json!([100, 101]));
    assert!(
        art.metadata.get("journal_walk_incomplete").is_none(),
        "a log that ends on a sequence mismatch was walked to its end"
    );
}

#[test]
fn test_journal_revoke_block() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs_journal(&source);

    // [0]=sb [1]=descriptor(seq2,[100]) [2]=data [3]=revoke(seq2,[200,201]) [4]=commit
    let journal_blocks = vec![
        build_journal_superblock(4096, 5, 1, 2, 1, 0),
        build_descriptor_block(4096, 2, &[100]),
        vec![0xAAu8; 4096],
        build_revoke_block(4096, 2, &[200, 201]),
        build_commit_block(4096, 2),
    ];
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("journal artifact");
    let txns = art.metadata["transactions"].as_array().unwrap();
    assert_eq!(txns.len(), 1);
    assert_eq!(txns[0]["blocks"], serde_json::json!([100]));
    assert_eq!(txns[0]["revoked"], serde_json::json!([200, 201]));
}

#[test]
fn test_journal_clean_no_transactions() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs_journal(&source);

    // s_start = 0 => clean journal, nothing to replay.
    let journal_blocks = vec![
        build_journal_superblock(4096, 5, 1, 2, 0, 0),
        vec![0u8; 4096],
        vec![0u8; 4096],
        vec![0u8; 4096],
        vec![0u8; 4096],
    ];
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("journal artifact");
    assert_eq!(art.metadata["clean"], true);
    assert_eq!(art.metadata["transaction_count"], 0);
}

#[test]
fn test_journal_corrupt_reports_unreadable_not_clean() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs_journal(&source);

    // Journal inode present but block 0 lacks the JBD2 magic.
    let journal_blocks = vec![vec![0u8; 4096], vec![0u8; 4096]];
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect(
        "the volume declares a journal, so an unreadable one must still be \
         reported: emitting nothing is indistinguishable from a clean journal",
    );

    // Zero transactions, but explicitly because the journal could not be read.
    assert_eq!(art.metadata["transaction_count"], 0);
    assert!(
        art.metadata["journal_unreadable"].is_string(),
        "the reason the journal could not be walked must be stated"
    );
    assert_eq!(art.metadata["journal_walk_incomplete"], true);
    assert_eq!(art.metadata["content_incomplete"], true);
    assert_eq!(
        art.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    // A clean journal reports `clean: true`; an unreadable one must never.
    assert!(
        art.metadata.get("clean").is_none(),
        "an unreadable journal must not claim to be clean"
    );
}

#[test]
fn test_journal_no_panic_on_garbage() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs_journal(&source);

    // Valid superblock + descriptor but no commit; remaining blocks are garbage.
    let mut journal_blocks = vec![
        build_journal_superblock(4096, 8, 1, 2, 1, 0),
        build_descriptor_block(4096, 2, &[100]),
    ];
    for _ in 0..6 {
        journal_blocks.push(vec![0xFFu8; 4096]);
    }
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("journal artifact");
    // No commit block => no finalized transaction, and no panic.
    assert_eq!(art.metadata["transaction_count"], 0);
}

// ============================================================================
// Fail-closed structural reads (BUG-243, BUG-272)
// ============================================================================

/// BUG-243: the superblock buffer is pre-zeroed, so a truncated image could
/// still pass the 0xEF53 magic check while desc_size and the 64-bit high fields
/// came back as fabricated zeros. It must error instead.
#[test]
fn test_truncated_superblock_read_fails_closed() {
    // Only 176 of the superblock's 1024 bytes are present: enough for the magic,
    // not enough for desc_size (offset 254).
    let source = MockDataSource::new(1200);
    source.write_at(1024, &create_valid_superblock()[..176]);

    let err = Superblock::parse(&source).expect_err("a truncated superblock must not parse");
    assert!(
        err.to_string().contains("short read"),
        "unexpected error: {err}"
    );
}

/// BUG-243: the group-descriptor buffer is reused across the loop, so a short
/// read leaves the PREVIOUS descriptor in place and silently duplicates it.
#[test]
fn test_truncated_group_descriptor_read_fails_closed() {
    // The image stops 30 bytes into the 64-byte descriptor at block 1.
    let source = MockDataSource::new(4096 + 34);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();

    let err = BlockGroupDescriptor::parse_table(&source, &sb)
        .expect_err("a truncated group descriptor table must not parse");
    assert!(
        err.to_string().contains("short read"),
        "unexpected error: {err}"
    );
}

/// BUG-272: an extent-tree index/leaf block read short still passes the 0xF30A
/// magic check, and the entries that were cut off then map as "no covering
/// extent" — i.e. real content served as a zero-filled hole. Both the serving
/// path and the data-run collector must fail closed.
#[test]
fn test_truncated_extent_tree_block_fails_closed() {
    const BS: usize = 4096;
    let mut image = vec![0u8; 51 * BS];

    // Leaf node at block 50: header claiming 2 extents, then both records.
    let leaf_at = 50 * BS;
    image[leaf_at..leaf_at + 12].copy_from_slice(&create_extent_header(2, 0));
    image[leaf_at + 12..leaf_at + 24].copy_from_slice(&create_extent_leaf(0, 1, 60));
    image[leaf_at + 24..leaf_at + 36].copy_from_slice(&create_extent_leaf(1, 1, 61));

    // The image is truncated inside the leaf node: the second extent is gone.
    image.truncate(leaf_at + 20);
    let inner: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::ByteSliceDataSource::new(image));

    // Inode root node: one index entry pointing at leaf block 50.
    let mut inode_blocks = [0u8; 60];
    inode_blocks[..12].copy_from_slice(&create_extent_header(1, 1));
    inode_blocks[12..24].copy_from_slice(&create_extent_idx(0, 50));

    let fs = Ext4FileSource {
        inner,
        block_size: BS as u32,
        inode_blocks,
        size: (2 * BS) as u64,
        uses_extents: true,
    };

    let mut buf = vec![0u8; BS];
    let err = fs
        .read_at(0, &mut buf)
        .expect_err("a partially read extent node must not be parsed");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

    let err = fs
        .collect_runs()
        .expect_err("data runs must not be collected from a partial extent node");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

// ============================================================================
// B2-002 / B2-038 / B2-098: short reads and caps must not be papered over
// ============================================================================

/// Two direct block pointers, block 0 -> physical 20, block 1 -> physical 21.
fn direct_two_block_inode_blocks() -> [u8; 60] {
    let mut inode_blocks = [0u8; 60];
    LittleEndian::write_u32(&mut inode_blocks[0..4], 20);
    LittleEndian::write_u32(&mut inode_blocks[4..8], 21);
    inode_blocks
}

/// B2-002: the legacy (direct/indirect) read path advanced its cursors by the
/// number of bytes it *asked* for, so a short `read_at` left a gap and pushed
/// every later block sideways in the returned buffer. The file then hashed as
/// complete while its bytes were misaligned, which is worse than truncation
/// because nothing downstream can see it.
#[test]
fn block_mapped_reads_keep_later_blocks_aligned_when_read_at_returns_short() {
    const BS: usize = 4096;
    let mut image = vec![0u8; 22 * BS];
    image[20 * BS..21 * BS].fill(0xA1);
    image[21 * BS..22 * BS].fill(0xB2);

    // A backing image that holds every byte but never returns more than 100 from
    // one `read_at`, exactly as a windowed / E01-backed / network source may.
    let dribble = Arc::new(DribbleSource::new(image, 100));
    let inner: Arc<dyn DataSource> = dribble.clone();

    let fs = Ext4FileSource {
        inner,
        block_size: BS as u32,
        inode_blocks: direct_two_block_inode_blocks(),
        size: (2 * BS) as u64,
        uses_extents: false,
    };

    let mut buf = vec![0u8; 2 * BS];
    let n = fs.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 2 * BS, "the whole file is present in the image");
    assert!(
        buf[..BS].iter().all(|&b| b == 0xA1),
        "the first block must be delivered whole, not 100 bytes then a gap"
    );
    assert!(
        buf[BS..].iter().all(|&b| b == 0xB2),
        "the second block must start exactly at the block boundary"
    );
    dribble.assert_dribbled();
}

/// B2-002, failure path: when the image genuinely cannot deliver the bytes, the
/// reader reports the honest short length instead of padding the shortfall with
/// zeros that would hash as real content.
#[test]
fn block_mapped_reads_report_a_short_length_on_a_truncated_image() {
    const BS: usize = 4096;
    let mut image = vec![0u8; 22 * BS];
    image[20 * BS..21 * BS].fill(0xA1);
    image[21 * BS..22 * BS].fill(0xB2);
    // The image ends 1000 bytes into physical block 20; block 21 is gone.
    image.truncate(20 * BS + 1000);

    let dribble = Arc::new(DribbleSource::new(image, 512));
    let inner: Arc<dyn DataSource> = dribble.clone();

    let fs = Ext4FileSource {
        inner,
        block_size: BS as u32,
        inode_blocks: direct_two_block_inode_blocks(),
        size: (2 * BS) as u64,
        uses_extents: false,
    };

    let mut buf = vec![0xEEu8; 2 * BS];
    let n = fs.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 1000, "only the bytes the image holds may be reported");
    assert!(buf[..1000].iter().all(|&b| b == 0xA1));
    assert!(
        buf[1000..].iter().all(|&b| b == 0xEE),
        "the unread tail must not be zero-filled into fabricated content"
    );
    dribble.assert_dribbled();
}

/// B2-038: a descriptor block whose tag list has no JBD2_FLAG_LAST_TAG gives no
/// trustworthy count of the journaled data blocks that follow it, so the ring
/// cursor cannot be advanced. Guessing would land on a data block and silently
/// drop or mis-attribute every later transaction.
#[test]
fn journal_walk_stops_when_a_descriptor_block_has_no_final_tag() {
    let mut desc = build_descriptor_block(4096, 2, &[100]);
    // Clear the tag flags: SAME_UUID and LAST_TAG both go away.
    BigEndian::write_u16(&mut desc[18..20], 0);

    let mut bytes = Vec::new();
    for blk in [
        build_journal_superblock(4096, 5, 1, 2, 1, 0),
        desc,
        vec![0xAAu8; 4096],
        build_commit_block(4096, 2),
        vec![0u8; 4096],
    ] {
        bytes.extend_from_slice(&blk);
    }
    let src = seance_core::data_source::ByteSliceDataSource::new(bytes.clone());
    let jsb = JournalSuperblock::parse(&bytes[..4096]).unwrap();

    let walk = walk_journal(&src, &jsb);
    assert!(
        walk.transactions.is_empty(),
        "no transaction may be finalized past an untrustworthy descriptor"
    );
    assert_eq!(walk.incomplete, Some(IncompleteReason::UnresolvedStructure));
}

/// B2-038: a journal block that reads short is not a journal block. Parsing the
/// zero-padded remainder invents a tag count and desynchronises the ring.
#[test]
fn journal_walk_flags_a_short_read_instead_of_parsing_a_partial_block() {
    let mut bytes = Vec::new();
    for blk in [
        build_journal_superblock(4096, 5, 1, 2, 1, 0),
        build_descriptor_block(4096, 2, &[100]),
    ] {
        bytes.extend_from_slice(&blk);
    }
    // The journal is truncated 100 bytes into the descriptor block.
    bytes.truncate(4096 + 100);

    let src = seance_core::data_source::ByteSliceDataSource::new(bytes.clone());
    let jsb = JournalSuperblock::parse(&bytes[..4096]).unwrap();

    let walk = walk_journal(&src, &jsb);
    assert!(walk.transactions.is_empty());
    assert_eq!(walk.incomplete, Some(IncompleteReason::ShortRead));
}

/// B2-098: the transaction cap truncates the log, and the summary must say so.
/// A capped list presented as `transaction_count` reads as a complete account of
/// the filesystem's recent history.
#[test]
fn journal_artifact_flags_a_walk_that_stopped_at_the_ring_bound() {
    let source = MockDataSource::new(4096 * 200);
    let (sb, groups) = setup_fs_journal(&source);

    // Every block of the ring is a revoke block for the open transaction, so the
    // sequence never advances and no commit ever ends the chain: the walk stops
    // only because the ring bound stops it.
    let mut journal_blocks = vec![build_journal_superblock(4096, 4, 1, 2, 1, 0)];
    for _ in 0..3 {
        journal_blocks.push(build_revoke_block(4096, 2, &[200]));
    }
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("journal artifact");
    assert_eq!(art.metadata["journal_walk_incomplete"], true);
    assert_eq!(
        art.metadata["journal_walk_incomplete_reason"],
        IncompleteReason::CapReached.as_str()
    );
}

// ============================================================================
// B7-011 / B7-012: journal honesty
// ============================================================================

/// The COMPAT bit says this volume has a journal. When the journal inode or its
/// superblock cannot be read, returning `None` published nothing at all — and a
/// clean empty journal publishes `clean: true`, so "broken journal" and
/// "nothing to note" were indistinguishable (B7-012).
#[test]
fn a_declared_but_unreadable_journal_is_reported_not_omitted() {
    let source = MockDataSource::new(64 * 4096);
    let (sb, groups) = setup_fs_journal(&source);
    // Inode 8 is never installed, and no JBD2 superblock is written.

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("a declared journal that cannot be read must still be reported");

    assert_eq!(art.metadata["type"], "ext4_journal");
    assert!(art.metadata["journal_unreadable"].is_string());
    assert_eq!(art.metadata["content_incomplete"], true);
    assert_eq!(
        art.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(art.metadata["inventory_incomplete"], true);
    assert!(
        art.metadata.get("clean").is_none(),
        "a journal we could not read must never be called clean"
    );
}

/// A journal walk that stopped early carried only `journal_walk_incomplete*`,
/// which nothing outside this crate reads. The incompleteness census, the court
/// report and the artifact UI all key off the standard pair (B7-011).
#[test]
fn a_truncated_journal_walk_carries_the_standard_incompleteness_pair() {
    let source = MockDataSource::new(256 * 4096);
    let (sb, groups) = setup_fs_journal(&source);

    // s_start = 1 (dirty). The descriptor block's only tag has its LAST_TAG
    // flag cleared, so the journaled-block count — and with it the position of
    // every later record — is unrecoverable.
    let mut descriptor = build_descriptor_block(4096, 2, &[100]);
    BigEndian::write_u16(&mut descriptor[18..20], 0); // clear LAST_TAG
    let journal_blocks = vec![
        build_journal_superblock(4096, 5, 1, 2, 1, 0),
        descriptor,
        vec![0xAAu8; 4096],
        vec![0xAAu8; 4096],
        vec![0xAAu8; 4096],
    ];
    install_journal(&source, 60, &journal_blocks);

    let art = build_journal_artifacts(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &journal_source(&source),
        &sb,
        &groups,
    )
    .expect("journal artifact");

    if art.metadata.get("journal_walk_incomplete").is_some() {
        assert_eq!(
            art.metadata["content_incomplete"], true,
            "an incomplete journal walk must set the standard flag too"
        );
        assert_eq!(
            art.metadata["content_incomplete_reason"],
            art.metadata["journal_walk_incomplete_reason"],
            "the standard reason must match the ext4-specific one"
        );
    } else {
        panic!("an uncommitted transaction must leave the walk flagged incomplete");
    }
}

/// **A recovered deleted file must not present its content as certainly its own.**
///
/// The extents name where the file's blocks *were*. ext4 frees them on unlink,
/// so any of them may since have been reallocated — and the content served
/// would then be another file's, under this file's name, with this file's size
/// and timestamps beside it. An examiner hashing it against a known-file set
/// would read the non-match as the file itself differing.
///
/// The FAT reader has qualified its own deleted recoveries since B2-160; this
/// asserts ext4 makes the same claim, no stronger.
#[test]
fn a_deleted_inode_says_its_blocks_may_have_been_reallocated() {
    let (source, sb, groups) = htree_fixture(100);

    // A regular file inode with a deletion time set: mode is intact, so the
    // file type is known, and `dtime != 0` is what marks it deleted.
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 30));
    let mut inode_data = create_inode(0x8000 | 0o644, 4096, 0x80000, &blocks);
    // dtime sits at offset 20 in the inode.
    inode_data[20..24].copy_from_slice(&1_600_000_000u32.to_le_bytes());
    source.write_at(10 * 4096 + 256, &inode_data);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 2, "/gone.txt").unwrap();

    let entry = produced
        .iter()
        .find(|a| a.metadata.get("deleted") == Some(&serde_json::json!(true)))
        .expect("the deleted inode must produce an entry — recovering it is the point");

    assert_eq!(
        entry.metadata["deleted_content_caveat"],
        serde_json::json!("blocks_may_be_reallocated"),
        "a recovered deleted file must say its blocks may no longer hold its data"
    );
    assert_eq!(
        entry.metadata["content_incomplete"],
        serde_json::json!(true),
        "content_incomplete is what the export and integrity-verify paths read; without \
         it the digest of whatever now occupies those blocks is recorded as this file's"
    );
    // And the recovery itself must survive: qualifying a finding must never
    // withdraw it.
    assert!(
        entry.data.is_some(),
        "the caveat must qualify the content, not remove it — an examiner still needs \
         the bytes to judge them"
    );
}

/// HUNT-080. The two recovery paths in `parse_directory_entries` — live
/// entries (`inode != 0`) and names hidden in a predecessor's widened slack —
/// both miss a deleted entry that the kernel left as an `inode == 0` record
/// **in the live chain**, with its own `rec_len` intact rather than merged
/// into a neighbour. The main walk steps over it (the `inode != 0` block is
/// skipped) and its slack is empty (`real_len == rec_len`), so it is dropped.
///
/// On `dfr-09-ext`'s ext4 partition ("recover a large number of files, no
/// overwrite") that lost exactly one deleted file, `xB0247-5.txt`, whose
/// directory entry `debugfs` recovers in this very form; its neighbours
/// survived only because they also had a slack copy. A recoverable deleted
/// file the reference tool sees and the product does not is a silent gap in
/// the one thing this scenario tests.
#[test]
fn an_inode_zero_entry_standing_in_the_live_chain_is_recovered_as_deleted() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    // Root inode 1 -> block 20; inode 2 is the one live file.
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));
    source.write_at(
        10 * 4096,
        &create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks),
    );
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 100, 0, &[0u8; 60]),
    );

    // Block 20: ".", "..", "live.txt", then TWO deleted entries that stand in
    // the chain with inode 0 and their own rec_len — the shape `xB0247-5.txt`
    // has on disk. Neither is inside another entry's slack. The last entry's
    // rec_len is widened to the end of the block, as the kernel leaves it.
    let mut dir_block = vec![0u8; 4096];
    let dot = create_dir_entry(1, ".");
    let dotdot = create_dir_entry(1, "..");
    let live = create_dir_entry(2, "live.txt");
    let gone_a = create_dir_entry(0, "xB0246-5.txt"); // inode 0, own rec_len
    let mut gone_b = create_dir_entry(0, "xB0247-5.txt"); // inode 0, own rec_len

    let mut pos = 0usize;
    for e in [&dot[..], &dotdot[..], &live[..], &gone_a[..]] {
        dir_block[pos..pos + e.len()].copy_from_slice(e);
        pos += e.len();
    }
    // The final chain entry spans the rest of the block.
    let tail = 4096 - pos;
    gone_b[4..6].copy_from_slice(&(tail as u16).to_le_bytes());
    dir_block[pos..pos + gone_b.len()].copy_from_slice(&gone_b);
    source.write_at(20 * 4096, &dir_block);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    // The live file is present and not flagged deleted.
    assert!(produced
        .iter()
        .any(|a| a.metadata["name"] == "live.txt" && a.metadata.get("deleted").is_none()));

    // BOTH inode-0 chain entries are recovered as name-only deletions — the
    // one that also had a slack copy AND the one (xB0247-5.txt) that did not.
    for name in ["xB0246-5.txt", "xB0247-5.txt"] {
        let gone = produced
            .iter()
            .find(|a| a.metadata["name"] == name)
            .unwrap_or_else(|| panic!("{name} left as an inode-0 chain entry was not recovered"));
        assert_eq!(gone.metadata["deleted"], true, "{name}");
        assert!(gone.metadata["inode"].is_null(), "{name}");
        assert_eq!(gone.metadata["path"], format!("/{name}"));
        assert_eq!(gone.metadata["metadata_unavailable"], true, "{name}");
        assert_eq!(
            gone.metadata["deleted_recovery_source"], "directory_slack",
            "{name}"
        );
    }
}

/// HUNT-080 (the real cause). A churned directory block hides its deleted
/// entries not in one clean chain but nested: one hidden entry's `rec_len` is
/// widened to swallow a later-deleted entry, so that inner name sits off the
/// `rec_len` chain the slack walk followed and was lost. On `dfr-09-ext`'s
/// htree `/box` that was `xB0247-5.txt`, a name `debugfs` recovers. The
/// second, 4-byte-aligned carve pass reaches it.
#[test]
fn a_deleted_name_nested_inside_another_slack_entry_is_carved_out() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt_entry = vec![0u8; 64];
    let mut cursor = Cursor::new(&mut gdt_entry);
    cursor.seek(SeekFrom::Start(8)).unwrap();
    cursor.write_u32::<LittleEndian>(10).unwrap();
    source.write_at(4096, &gdt_entry);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 20));
    source.write_at(
        10 * 4096,
        &create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks),
    );
    source.write_at(
        10 * 4096 + 256,
        &create_inode(0x8000 | 0o644, 100, 0, &[0u8; 60]),
    );

    // Block 20: ".", "..", "live.txt", then a deleted entry "OUTER.txt" whose
    // rec_len is widened to the end of the block — and, sitting INSIDE that
    // widened span (off the rec_len chain), two further deleted names
    // "inner-a.txt" and "inner-b.txt". Pass 1 follows live.txt -> OUTER.txt ->
    // end; pass 2's carve is what reaches the inner names.
    let mut dir_block = vec![0u8; 4096];
    let dot = create_dir_entry(1, ".");
    let dotdot = create_dir_entry(1, "..");
    let mut live = create_dir_entry(2, "live.txt");
    let outer = create_dir_entry(0, "OUTER.txt"); // inode 0, name-only
    let inner_a = create_dir_entry(0, "inner-a.txt");
    let inner_b = create_dir_entry(0, "inner-b.txt");

    // live.txt's rec_len swallows OUTER + the rest of the block.
    let mut pos = 0usize;
    for e in [&dot[..], &dotdot[..]] {
        dir_block[pos..pos + e.len()].copy_from_slice(e);
        pos += e.len();
    }
    let live_pos = pos;
    dir_block[pos..pos + live.len()].copy_from_slice(&live);
    pos += live.len();
    let outer_pos = pos;
    dir_block[pos..pos + outer.len()].copy_from_slice(&outer);
    // Nest the inner names inside OUTER's widened span, at 4-aligned offsets
    // that are NOT where OUTER's own rec_len chain points.
    let inner_a_pos = outer_pos + outer.len();
    dir_block[inner_a_pos..inner_a_pos + inner_a.len()].copy_from_slice(&inner_a);
    let inner_b_pos = inner_a_pos + inner_a.len();
    dir_block[inner_b_pos..inner_b_pos + inner_b.len()].copy_from_slice(&inner_b);

    // OUTER's rec_len spans from OUTER to the end of the block, hiding the
    // inner names in its slack; live.txt's rec_len spans OUTER too.
    let outer_rec = 4096 - outer_pos;
    dir_block[outer_pos + 4..outer_pos + 6].copy_from_slice(&(outer_rec as u16).to_le_bytes());
    let live_rec = outer_pos + outer_rec - live_pos;
    let _ = live_rec;
    // live.txt keeps its own short rec_len so pass 1 lands on OUTER next.
    let _ = &mut live;
    source.write_at(20 * 4096, &dir_block);

    let mut produced = vec![];
    let mut ctx = ParsingContext {
        artifact_id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        data_source: Arc::new(source.clone()),
        superblock: &sb,
        groups: &groups,
        produced_artifacts: &mut produced,
        max_recursion_depth: 5,
        depth: 0,
        visited_dirs: std::collections::HashSet::new(),
        listing_gaps: ListingGaps::default(),
        progress: &None,
        cancellation: &None,
        total_inodes: 0,
    };
    parse_inode(&mut ctx, 1, "/").unwrap();

    let names: std::collections::HashSet<String> = produced
        .iter()
        .filter_map(|a| a.metadata["name"].as_str().map(String::from))
        .collect();
    assert!(names.contains("live.txt"), "{names:?}");
    // The nested names the rec_len chain steps over are carved out, name-only.
    for n in ["OUTER.txt", "inner-a.txt", "inner-b.txt"] {
        let art = produced
            .iter()
            .find(|a| a.metadata["name"] == n)
            .unwrap_or_else(|| panic!("nested deleted name {n} was not recovered: {names:?}"));
        assert_eq!(art.metadata["deleted"], true, "{n}");
        assert!(art.metadata["inode"].is_null(), "{n}");
    }
    // No name is emitted twice.
    let mut counts = std::collections::HashMap::new();
    for a in &produced {
        if let Some(n) = a.metadata["name"].as_str() {
            *counts.entry(n.to_string()).or_insert(0) += 1;
        }
    }
    for n in ["inner-a.txt", "inner-b.txt", "OUTER.txt"] {
        assert_eq!(counts.get(n), Some(&1), "{n} emitted more than once");
    }
}

// ============================================================================
// Review fixes: walk honesty, hostile structures, journal and group layout
// ============================================================================

/// `entries` laid back to back with their minimal `rec_len`, then the `hidden`
/// entries written into the last live entry's slack, the way the kernel leaves
/// a deleted name: the last live entry's `rec_len` is widened to the end of the
/// block and the hidden bytes stay where they were.
fn dir_block_with_hidden(entries: &[(u32, &str, u8)], hidden: &[(u32, &str, u8)]) -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    let mut pos = 0;
    let mut last_live = 0;
    for (i, &(inode, name, file_type)) in entries.iter().chain(hidden.iter()).enumerate() {
        let e = create_dir_entry_typed(inode, name, file_type);
        block[pos..pos + e.len()].copy_from_slice(&e);
        if i < entries.len() {
            last_live = pos;
        }
        pos += e.len();
    }
    let tail = (4096 - last_live) as u16;
    block[last_live + 4..last_live + 6].copy_from_slice(&tail.to_le_bytes());
    block
}

/// A well-formed directory block: the last entry spans the rest of the block.
fn dir_block_of(entries: &[(u32, &str, u8)]) -> Vec<u8> {
    dir_block_with_hidden(entries, &[])
}

/// Inode `inode_num` (inode table at block 10, 256-byte inodes) as a one-block
/// extent-mapped directory whose dirents live in `block`.
fn write_dir_inode(source: &MockDataSource, inode_num: u32, block: u64) {
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, block));
    source.write_at(
        10 * 4096 + (inode_num as u64 - 1) * 256,
        &create_inode(0x4000 | 0o755, 4096, 0x80000, &blocks),
    );
}

/// Inode `inode_num` as an empty regular file.
fn write_empty_file_inode(source: &MockDataSource, inode_num: u32) {
    source.write_at(
        10 * 4096 + (inode_num as u64 - 1) * 256,
        &create_inode(0x8000 | 0o644, 0, 0, &[0u8; 60]),
    );
}

fn fs_artifact(source: &MockDataSource) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(source.clone()) as Arc<dyn DataSource>),
        serde_json::json!({"filesystem_type": "ext4"}),
    )
}

fn by_path<'a>(produced: &'a [Artifact], path: &str) -> Option<&'a Artifact> {
    produced.iter().find(|a| a.metadata["path"] == path)
}

/// A crafted index tree whose every entry points at the same child block is
/// exponential work from a handful of real blocks. A valid tree never shares a
/// child block, so the walk refuses it instead of enumerating it.
#[test]
fn a_crafted_extent_tree_that_shares_child_blocks_is_refused_not_walked() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);

    let index_block = |depth: u16, child: u64| {
        let mut b = create_extent_header(340, depth);
        for _ in 0..340 {
            b.extend_from_slice(&create_extent_idx(0, child));
        }
        b.resize(4096, 0);
        b
    };
    source.write_at(20 * 4096, &index_block(2, 21));
    source.write_at(21 * 4096, &index_block(1, 22));
    let mut leaf = create_extent_header(1, 0);
    leaf.extend_from_slice(&create_extent_leaf(0, 1, 50));
    source.write_at(22 * 4096, &leaf);

    let mut root = create_extent_header(4, 3);
    for _ in 0..4 {
        root.extend_from_slice(&create_extent_idx(0, 20));
    }
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 4096 * 4, 0x80000, &root),
    );

    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    let file = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);
    let err = file
        .collect_runs()
        .expect_err("a tree that revisits a block is malformed and must not be enumerated");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

/// The walk's own leaf cap: a tree of distinct blocks is still bounded.
#[test]
fn an_extent_tree_with_more_leaves_than_the_cap_is_refused() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    // One leaf block, reached once, holding 340 extents is fine; the cap is
    // exercised through the helper directly so the test stays small.
    let mut leaf = create_extent_header(340, 0);
    for i in 0..340u32 {
        leaf.extend_from_slice(&create_extent_leaf(i, 1, 50));
    }
    leaf.resize(4096, 0);
    source.write_at(20 * 4096, &leaf);
    let mut root = create_extent_header(1, 1);
    root.extend_from_slice(&create_extent_idx(0, 20));
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 340 * 4096, 0x80000, &root),
    );
    let inode = Inode::parse(&source, &sb, &groups, 1).unwrap();
    let file = Ext4FileSource::new(Arc::new(source.clone()), 4096, &inode);
    let mut out = Vec::new();
    let mut visited = std::collections::HashSet::new();
    file.collect_extents(
        &inode.block,
        MAX_EXTENT_TREE_DEPTH,
        &mut out,
        &mut visited,
        100,
    )
    .expect_err("340 leaves exceed a cap of 100");
}

/// An unreadable root must say so: a volume with zero files and no marker is
/// indistinguishable from an empty one.
#[test]
fn a_root_inode_past_the_end_of_the_image_is_reported_not_shown_as_an_empty_volume() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    let mut gdt = vec![0u8; 64];
    LittleEndian::write_u32(&mut gdt[8..12], 90_000); // inode table far past the image
    source.write_at(4096, &gdt);

    let results = Ext4Parser::new().process(&fs_artifact(&source)).unwrap();
    assert!(!results
        .iter()
        .any(|a| a.artifact_type == ArtifactType::FileEntry));
    let notice = results
        .iter()
        .find(|a| a.metadata.get("root_inode_readable") == Some(&serde_json::json!(false)))
        .expect("an unreadable root inode must leave a marker, not an empty listing");
    assert_eq!(notice.metadata["content_incomplete"], true);
    assert_eq!(
        notice.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(notice.metadata["root_inode_error"].is_string());
}

#[test]
fn an_unallocated_root_inode_is_reported_not_shown_as_an_empty_volume() {
    let source = MockDataSource::new(4096 * 100);
    let _ = setup_fs(&source); // inode table at block 10, never written: mode == 0

    let results = Ext4Parser::new().process(&fs_artifact(&source)).unwrap();
    assert!(!results
        .iter()
        .any(|a| a.artifact_type == ArtifactType::FileEntry));
    let notice = results
        .iter()
        .find(|a| a.metadata.get("root_inode_readable") == Some(&serde_json::json!(false)))
        .expect("a root inode with mode 0 must leave a marker");
    assert_eq!(notice.metadata["content_incomplete"], true);
}

/// A live dirent names an inode that cannot be resolved (out of range, or mode
/// 0): the name is the directory's own record and must survive, and the
/// directory must not read as complete.
#[test]
fn a_live_dirent_whose_inode_cannot_be_resolved_is_named_and_the_directory_flagged() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_empty_file_inode(&source, 2);
    // Inode 3 is never written (mode 0); inode 9999 is past the last group.
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (1, ".", EXT4_FT_DIR),
            (1, "..", EXT4_FT_DIR),
            (9999, "ghost.txt", EXT4_FT_REG_FILE),
            (3, "blank.txt", EXT4_FT_REG_FILE),
            (2, "ok.txt", EXT4_FT_REG_FILE),
        ]),
    );

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();

    let root = by_path(&produced, "/").expect("root");
    assert_eq!(root.metadata["directory_parse_incomplete"], true);
    assert_eq!(
        root.metadata["directory_parse_incomplete_reason"],
        "unresolved_structure"
    );
    for (name, inode) in [("ghost.txt", 9999), ("blank.txt", 3)] {
        let e = by_path(&produced, &format!("/{name}"))
            .unwrap_or_else(|| panic!("{name} must be named even though its inode is unusable"));
        assert_eq!(e.metadata["inode"], inode);
        assert_eq!(e.metadata["metadata_unavailable"], true);
        assert_eq!(e.metadata["content_incomplete"], true);
        assert_eq!(
            e.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(e.metadata.get("deleted").is_none(), "the dirent is live");
        assert!(e.metadata.get("size").is_none(), "no size may be invented");
    }
    let ok = by_path(&produced, "/ok.txt").expect("ok.txt");
    assert!(ok.metadata.get("metadata_unavailable").is_none());
}

/// Directories deeper than the recursion cap are not walked; the directory at
/// the cap must say its listing stops there.
#[test]
fn a_directory_tree_deeper_than_the_cap_flags_the_directory_at_the_limit() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    for i in 1..=6u32 {
        write_dir_inode(&source, i, 20 + i as u64);
        source.write_at(
            (20 + i as u64) * 4096,
            &dir_block_of(&[
                (i, ".", EXT4_FT_DIR),
                (i, "..", EXT4_FT_DIR),
                (i + 1, "d", EXT4_FT_DIR),
            ]),
        );
    }
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    ctx.max_recursion_depth = 3;
    parse_inode(&mut ctx, 1, "/").unwrap();

    assert!(by_path(&produced, "/d/d/d/d").is_none(), "beyond the cap");
    let at_limit = by_path(&produced, "/d/d/d").expect("the directory at the limit");
    assert_eq!(at_limit.metadata["directory_parse_incomplete"], true);
    assert_eq!(
        at_limit.metadata["directory_parse_incomplete_reason"],
        "cap_reached"
    );
    let above = by_path(&produced, "/d/d").expect("its parent");
    assert!(above.metadata.get("directory_parse_incomplete").is_none());
}

const INLINE_DATA_FEATURE: u32 = 0x8000;
const INLINE_FL: u32 = 0x1000_0000;

/// Superblock for the inline tests: the volume declares the INLINE_DATA feature.
fn inline_fs(source: &MockDataSource) -> (Superblock, Vec<BlockGroupDescriptor>) {
    let (mut sb, groups) = setup_fs(source);
    sb.incompat_features |= INLINE_DATA_FEATURE;
    (sb, groups)
}

/// Dirents for an inline directory region: `entries` packed, the last record's
/// `rec_len` reaching `total` (the kernel's rule for both regions).
fn inline_dirents(entries: &[(u32, &str, u8)], total: usize) -> Vec<u8> {
    let mut out = vec![0u8; total];
    let mut pos = 0usize;
    for (i, (ino, name, ft)) in entries.iter().enumerate() {
        let real = (8 + name.len()).div_ceil(4) * 4;
        let rec = if i + 1 == entries.len() {
            total - pos
        } else {
            real
        };
        out[pos..pos + 4].copy_from_slice(&ino.to_le_bytes());
        out[pos + 4..pos + 6].copy_from_slice(&(rec as u16).to_le_bytes());
        out[pos + 6] = name.len() as u8;
        out[pos + 7] = *ft;
        out[pos + 8..pos + 8 + name.len()].copy_from_slice(name.as_bytes());
        pos += rec;
    }
    out
}

fn bytes_of_source(a: &Artifact) -> Vec<u8> {
    let d = a.data.as_ref().expect("content is served");
    let mut b = vec![0u8; d.size() as usize];
    let n = d.read_at(0, &mut b).unwrap();
    b.truncate(n);
    b
}

/// SYNTHETIC: a file whose whole content sits in `i_block` is served from it.
#[test]
fn inline_data_in_i_block_is_served() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = inline_fs(&source);
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 20, INLINE_FL, b"hello inline data!!!"),
    );
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/small.txt").unwrap();
    let file = by_path(&produced, "/small.txt").unwrap();
    assert_eq!(file.metadata["inline_data"], true);
    assert_eq!(file.metadata["inline_data_bytes_in_inode"], 20);
    assert_eq!(file.metadata["inline_data_bytes_in_xattr"], 0);
    assert!(file.metadata.get("content_incomplete").is_none());
    assert!(
        file.metadata.get("data_runs").is_none(),
        "no block run exists"
    );
    assert_eq!(bytes_of_source(file), b"hello inline data!!!");
}

/// SYNTHETIC: 60 bytes in `i_block` and the rest in the `system.data` xattr.
#[test]
fn inline_data_continues_in_the_system_data_xattr() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = inline_fs(&source);
    let first: Vec<u8> = (0u8..60).collect();
    let rest: Vec<u8> = (100u8..140).collect();
    let mut inode = create_inode(0x8000 | 0o644, 100, INLINE_FL, &first);
    write_inode_xattrs(&mut inode, 32, &[(7, "data", &rest)]);
    source.write_at(10 * 4096, &inode);
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/h100.txt").unwrap();
    let file = by_path(&produced, "/h100.txt").unwrap();
    assert_eq!(file.metadata["inline_data_bytes_in_inode"], 60);
    assert_eq!(file.metadata["inline_data_bytes_in_xattr"], 40);
    assert!(file.metadata.get("content_incomplete").is_none());
    let mut want = first.clone();
    want.extend_from_slice(&rest);
    assert_eq!(bytes_of_source(file), want);
}

/// SYNTHETIC: the inode claims more bytes than i_block and system.data hold;
/// what exists is served and the shortfall is named, never padded.
#[test]
fn inline_data_shorter_than_the_size_is_served_and_marked_incomplete() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = inline_fs(&source);
    let first: Vec<u8> = (0u8..60).collect();
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 100, INLINE_FL, &first),
    );
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/short.txt").unwrap();
    let file = by_path(&produced, "/short.txt").unwrap();
    assert_eq!(file.metadata["content_incomplete"], true);
    assert!(file.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("40"));
    assert_eq!(bytes_of_source(file), first, "not padded");
}

/// SYNTHETIC: an inline directory has a 4-byte parent word, then dirents in
/// `i_block[4..60]`, then more dirents in `system.data`. No `.` or `..`.
#[test]
fn an_inline_directory_is_listed_from_i_block_and_system_data() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = inline_fs(&source);
    let mut iblock = vec![0u8; 60];
    iblock[0..4].copy_from_slice(&2u32.to_le_bytes());
    iblock[4..].copy_from_slice(&inline_dirents(
        &[
            (3, "a.txt", EXT4_FT_REG_FILE),
            (4, "b.txt", EXT4_FT_REG_FILE),
        ],
        56,
    ));
    let cont = inline_dirents(&[(5, "c.txt", EXT4_FT_REG_FILE)], 20);
    let mut dir = create_inode(0x4000 | 0o755, 80, INLINE_FL, &iblock);
    write_inode_xattrs(&mut dir, 32, &[(7, "data", &cont)]);
    source.write_at(10 * 4096 + 256, &dir); // inode 2
    for ino in 3..=5u64 {
        source.write_at(
            10 * 4096 + (ino - 1) * 256,
            &create_inode(0x8000 | 0o644, 3, INLINE_FL, b"abc"),
        );
    }
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 2, "/d").unwrap();
    let d = by_path(&produced, "/d").unwrap();
    assert_eq!(d.metadata["inline_data"], true);
    assert_eq!(d.metadata["inline_dir_parent_inode"], 2);
    assert!(d.metadata.get("directory_parse_incomplete").is_none());
    for n in ["/d/a.txt", "/d/b.txt", "/d/c.txt"] {
        assert!(by_path(&produced, n).is_some(), "{n} listed");
    }
    assert_eq!(produced.len(), 4, "no . or .. entries");
}

/// The INLINE_DATA flag on a volume without the feature is meaningless: the
/// inode is refused, not decoded either way.
#[test]
fn the_inline_flag_without_the_feature_is_still_refused() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    assert_eq!(sb.incompat_features & INLINE_DATA_FEATURE, 0);
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 20, INLINE_FL, b"hello inline data!!!"),
    );
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/x").unwrap();
    let file = by_path(&produced, "/x").unwrap();
    assert_eq!(file.metadata["content_incomplete"], true);
    assert!(file.data.is_none());
}

/// A name recovered from /a's slack whose inode is now a live directory linked
/// at /z must not be descended: the live directory's children belong at /z.
#[test]
fn a_slack_name_whose_inode_is_now_a_live_directory_is_not_descended() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_dir_inode(&source, 3, 21);
    write_dir_inode(&source, 4, 22);
    write_empty_file_inode(&source, 5);
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (1, ".", EXT4_FT_DIR),
            (1, "..", EXT4_FT_DIR),
            (3, "a", EXT4_FT_DIR),
            (4, "z", EXT4_FT_DIR),
        ]),
    );
    source.write_at(
        21 * 4096,
        &dir_block_with_hidden(
            &[
                (3, ".", EXT4_FT_DIR),
                (1, "..", EXT4_FT_DIR),
                (5, "alive.txt", EXT4_FT_REG_FILE),
            ],
            &[(4, "old.txt", EXT4_FT_REG_FILE)],
        ),
    );
    source.write_at(
        22 * 4096,
        &dir_block_of(&[
            (4, ".", EXT4_FT_DIR),
            (1, "..", EXT4_FT_DIR),
            (5, "child.txt", EXT4_FT_REG_FILE),
        ]),
    );

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();

    assert_eq!(
        produced
            .iter()
            .filter(|a| a.metadata["path"] == "/z/child.txt")
            .count(),
        1,
        "the live directory's children are emitted once, at their real path"
    );
    assert!(
        !produced.iter().any(|a| a.metadata["path"]
            .as_str()
            .is_some_and(|p| p.starts_with("/a/old.txt/"))),
        "nothing may appear under the stale slack name"
    );
    let stale = by_path(&produced, "/a/old.txt").expect("the stale name itself is recorded");
    assert_eq!(stale.metadata["deleted"], true);
    assert_eq!(stale.metadata["inode_reused"], true);
}

/// A slack name whose nonzero inode now yields no record (mode 0), and a slack
/// name of a deleted directory, must still be recorded by name.
#[test]
fn slack_names_whose_inode_yields_no_record_are_still_named() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_empty_file_inode(&source, 2);
    source.write_at(
        20 * 4096,
        &dir_block_with_hidden(
            &[
                (1, ".", EXT4_FT_DIR),
                (1, "..", EXT4_FT_DIR),
                (2, "live.txt", EXT4_FT_REG_FILE),
            ],
            &[
                (7, "ghost.txt", EXT4_FT_REG_FILE),
                (8, "gonedir", EXT4_FT_DIR),
            ],
        ),
    );

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();

    for (name, inode, is_dir) in [("ghost.txt", 7, false), ("gonedir", 8, true)] {
        let all: Vec<_> = produced
            .iter()
            .filter(|a| a.metadata["name"] == name)
            .collect();
        assert_eq!(all.len(), 1, "{name} must be recorded exactly once");
        let e = all[0];
        assert_eq!(e.metadata["deleted"], true);
        assert_eq!(e.metadata["inode"], inode);
        assert_eq!(e.metadata["is_directory"], is_dir);
        assert_eq!(e.metadata["metadata_unavailable"], true);
        assert!(
            !e.metadata["content_incomplete_detail"]
                .as_str()
                .unwrap()
                .contains("zeroed on deletion"),
            "the inode number was not zeroed; the record must not say it was"
        );
    }
}

/// A slack-recovered, inode-reused entry for inode X is pushed before the live
/// entry for X; it must not consume X's one chance to offer file slack.
#[test]
fn a_stale_slack_name_does_not_consume_the_live_files_slack() {
    let source = MockDataSource::new(4096 * 100);
    let _ = setup_fs(&source);
    write_dir_inode(&source, 2, 20); // root is inode 2
    write_dir_inode(&source, 3, 21);
    write_empty_file_inode(&source, 5);
    // Inode 4: a live 100-byte file in block 30 whose tail holds bytes.
    let mut blocks = vec![];
    blocks.extend_from_slice(&create_extent_header(1, 0));
    blocks.extend_from_slice(&create_extent_leaf(0, 1, 30));
    source.write_at(
        10 * 4096 + 3 * 256,
        &create_inode(0x8000 | 0o644, 100, 0x80000, &blocks),
    );
    source.write_at(30 * 4096 + 200, b"residue in the file slack");
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (2, ".", EXT4_FT_DIR),
            (2, "..", EXT4_FT_DIR),
            (3, "a", EXT4_FT_DIR),
            (4, "f", EXT4_FT_REG_FILE),
        ]),
    );
    source.write_at(
        21 * 4096,
        &dir_block_with_hidden(
            &[
                (3, ".", EXT4_FT_DIR),
                (2, "..", EXT4_FT_DIR),
                (5, "keep.txt", EXT4_FT_REG_FILE),
            ],
            &[(4, "old.txt", EXT4_FT_REG_FILE)],
        ),
    );

    let results = Ext4Parser::new().process(&fs_artifact(&source)).unwrap();
    assert!(
        by_path(&results, "/a/old.txt").is_some(),
        "the stale name is walked first"
    );
    let slack: Vec<_> = results
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect();
    assert_eq!(slack.len(), 1, "the live file's tail slack must be offered");
    assert_eq!(slack[0].metadata["parent_path"], "/f");
}

/// blocks_per_group is attacker-controlled: the bound must come from the image.
#[test]
fn a_hostile_blocks_per_group_cannot_inflate_the_block_bound() {
    let source = MockDataSource::new(4096 * 100);
    source.write_at(1024, &create_valid_superblock());
    source.write_u32(1024 + 4, 0xFFFF_FFFF); // s_blocks_count_lo
    source.write_u32(1024 + 32, 0xFFFF_FFFF); // s_blocks_per_group
    let sb = Superblock::parse(&source).unwrap();
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    assert!(
        total_blocks_bound(&sb, &groups, source.size()) <= 100,
        "100 blocks fit in the image; the bound may not be 4 billion"
    );
}

/// A journal whose own block size disagrees with the filesystem's would be
/// read at the wrong offsets, and an absurd one would be allocated.
#[test]
fn a_journal_block_size_that_disagrees_with_the_filesystem_is_reported_unreadable() {
    for declared in [0xFFFF_FFF0u32, 2048] {
        let source = MockDataSource::new(256 * 4096);
        let (sb, groups) = setup_fs_journal(&source);
        let mut jsb = build_journal_superblock(4096, 5, 1, 2, 1, 0);
        BigEndian::write_u32(&mut jsb[12..16], declared); // s_blocksize
        install_journal(&source, 60, &[jsb, vec![0u8; 4096]]);

        let art = build_journal_artifacts(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &journal_source(&source),
            &sb,
            &groups,
        )
        .expect("a declared journal is always reported");
        assert!(
            art.metadata["journal_unreadable"].is_string(),
            "block size {declared:#x} must be refused"
        );
        assert_eq!(art.metadata["content_incomplete"], true);
    }
}

/// With META_BG, groups below s_first_meta_bg's meta-group live in the classic
/// contiguous GDT after the superblock, not at meta-group positions.
#[test]
fn groups_below_first_meta_bg_are_read_from_the_classic_gdt() {
    let source = MockDataSource::new(330 * 1024);
    let mut sb_bytes = create_valid_superblock();
    LittleEndian::write_u32(&mut sb_bytes[4..8], 320); // blocks_count_lo
    LittleEndian::write_u32(&mut sb_bytes[20..24], 1); // first_data_block (1 KiB blocks)
    LittleEndian::write_u32(&mut sb_bytes[24..28], 0); // log_block_size 0 -> 1024
    LittleEndian::write_u32(&mut sb_bytes[32..36], 16); // blocks_per_group
    LittleEndian::write_u32(&mut sb_bytes[96..100], 0x2C0 | 0x10); // + META_BG
    LittleEndian::write_u32(&mut sb_bytes[0x104..0x108], 2); // s_first_meta_bg
    source.write_at(1024, &sb_bytes);
    let sb = Superblock::parse(&source).unwrap();
    // 20 groups of 64-byte descriptors, contiguous from block 2.
    for i in 0..20u64 {
        let mut d = vec![0u8; 64];
        LittleEndian::write_u32(&mut d[8..12], 1000 + i as u32); // inode table
        source.write_at(2 * 1024 + i * 64, &d);
    }
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    assert_eq!(groups.len(), 20);
    // Group 17 is in meta-group 1, which is still below first_meta_bg = 2.
    assert_eq!(groups[17].get_inode_table_block(), 1017);
    assert_eq!(groups[3].get_inode_table_block(), 1003);
}

/// A BLOCK_UNINIT group's on-disk bitmap is not valid: its blocks are neither
/// known free nor known allocated.
#[test]
fn a_block_uninit_group_is_unassessed_not_free() {
    let source = MockDataSource::new(4096 * 1000);
    let mut sb_bytes = create_valid_superblock();
    LittleEndian::write_u32(&mut sb_bytes[100..104], 0x1 | 0x10); // SPARSE_SUPER | GDT_CSUM
    source.write_at(1024, &sb_bytes);
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt = vec![0u8; 64];
    LittleEndian::write_u32(&mut gdt[0..4], 5); // block bitmap
    LittleEndian::write_u32(&mut gdt[8..12], 10); // inode table
    LittleEndian::write_u16(&mut gdt[18..20], 0x2); // EXT4_BG_BLOCK_UNINIT
    source.write_at(4096, &gdt);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    // The stale bitmap block is all zeros: every bit says "free".

    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("uninit groups still read");
    assert!(matches!(bitmaps.state(8), BlockState::Unassessed));
    assert!(bitmaps.is_allocated(8), "never reported as free in the map");

    let source_arc: Arc<dyn DataSource> = Arc::new(source.clone());
    let (map, free) = build_allocation_map_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &source,
        &source_arc,
        &sb,
        &groups,
    )
    .expect("map");
    assert!(
        free.is_empty(),
        "an uninitialised group is not carved as free space"
    );
    assert_eq!(map.metadata["allocation_map_incomplete"], true);
    assert_eq!(map.metadata["free_space_complete"], false);
}

/// Bigalloc bitmaps index clusters, not blocks: refuse rather than index them
/// as blocks and report allocated data as free.
#[test]
fn a_bigalloc_volume_omits_the_bitmap_views_and_says_so() {
    let source = MockDataSource::new(4096 * 100);
    let mut sb_bytes = create_valid_superblock();
    LittleEndian::write_u32(&mut sb_bytes[100..104], 0x1 | 0x200); // + BIGALLOC
    source.write_at(1024, &sb_bytes);
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt = vec![0u8; 64];
    LittleEndian::write_u32(&mut gdt[0..4], 5);
    LittleEndian::write_u32(&mut gdt[8..12], 10);
    source.write_at(4096, &gdt);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();

    assert!(GroupBitmaps::read(&source, &sb, &groups).is_none());

    let results = Ext4Parser::new().process(&fs_artifact(&source)).unwrap();
    assert!(!results
        .iter()
        .any(|a| a.metadata["type"] == "allocation_map"));
    let notice = results
        .iter()
        .find(|a| a.metadata.get("allocation_map_unavailable") == Some(&serde_json::json!(true)))
        .expect("an omitted allocation map must be said, not silent");
    assert_eq!(notice.metadata["content_incomplete"], true);
    assert!(notice.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("bigalloc"));
}

/// A `DataSource` that counts `read_at` calls.
#[derive(Debug)]
struct CountingSource {
    inner: MockDataSource,
    reads: std::sync::atomic::AtomicUsize,
}

impl DataSource for CountingSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.read_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// The orphaned-directory scan reads runs of free blocks, not one block per
/// `read_at`, and recovers exactly what the per-block scan did.
#[test]
fn the_orphaned_directory_scan_reads_free_runs_in_chunks() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs_with_bitmap(&source);
    write_orphaned_directory_block(&source);
    write_inode_at(&source, 5, 0x8000 | 0o644, 12345, 1_700_000_000, 0);
    write_inode_at(&source, 6, 0x8000 | 0o644, 42, 1_700_000_001, 0);

    let counting = Arc::new(CountingSource {
        inner: source.clone(),
        reads: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut produced = Vec::new();
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    ctx.data_source = counting.clone();
    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("bitmap reads");
    scan_orphaned_directory_blocks(&mut ctx, &bitmaps);

    let mut names: Vec<_> = produced
        .iter()
        .filter_map(|a| a.metadata["name"].as_str().map(str::to_string))
        .collect();
    names.sort();
    assert_eq!(names, vec!["notes.txt", "photo.jpg"]);
    let reads = counting.reads.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        reads < 20,
        "92 free blocks must not cost 92 reads; got {reads}"
    );
}

/// A group bitmap the image cannot deliver in full leaves its unread blocks
/// unassessed: neither free (never carved) nor claimed allocated.
#[derive(Debug)]
struct ShortAt {
    inner: MockDataSource,
    /// Reads stop at this byte offset inside the bitmap block.
    limit: u64,
    block: u64,
}

impl DataSource for ShortAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.block * 4096;
        if offset >= start && offset < start + 4096 {
            if offset >= self.limit {
                return Ok(0);
            }
            let room = (self.limit - offset) as usize;
            let n = buf.len().min(room);
            return self.inner.read_at(offset, &mut buf[..n]);
        }
        self.inner.read_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

#[test]
fn a_short_group_bitmap_leaves_unread_blocks_unassessed_and_uncarved() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs_with_bitmap(&source); // bitmap at block 5, blocks 0-7 in use
    let short = ShortAt {
        inner: source.clone(),
        limit: 5 * 4096 + 4, // only 32 bitmap bits arrive: blocks 0..32
        block: 5,
    };
    let source_arc: Arc<dyn DataSource> = Arc::new(source.clone());
    let (map, free) = build_allocation_map_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &short,
        &source_arc,
        &sb,
        &groups,
    )
    .expect("a short bitmap still yields a flagged map");

    assert_eq!(map.metadata["allocation_map_incomplete"], true);
    assert_eq!(map.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(map.metadata["free_space_complete"], false);
    // 100 blocks in the image, 32 assessed: 68 are unassessed.
    assert_eq!(map.metadata["free_space_blocks_short_group_bitmaps"], 68);
    for region in &free {
        let off = region.metadata["offset_bytes"].as_u64().unwrap();
        let len = region.metadata["size_bytes"].as_u64().unwrap();
        assert!(
            off + len <= 32 * 4096,
            "free region {off}+{len} reaches an unassessed block"
        );
    }
    assert!(
        !free.is_empty(),
        "the 24 assessed free blocks are still carvable"
    );
}

/// A live directory entry that stops early (rec_len 0, or a name running past
/// the data) must not read as a complete listing.
#[test]
fn a_directory_block_with_a_zero_rec_len_mid_block_is_flagged_incomplete() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_empty_file_inode(&source, 2);
    // "a.txt" keeps its minimal rec_len, so the next 4 bytes are rec_len == 0;
    // "lost.txt" sits further on and is never reached.
    let mut block = vec![0u8; 4096];
    let mut pos = 0;
    for e in [
        create_dir_entry_typed(1, ".", 2),
        create_dir_entry_typed(1, "..", 2),
        create_dir_entry(2, "a.txt"),
    ] {
        block[pos..pos + e.len()].copy_from_slice(&e);
        pos += e.len();
    }
    let lost = create_dir_entry(2, "lost.txt");
    block[2048..2048 + lost.len()].copy_from_slice(&lost);
    source.write_at(20 * 4096, &block);

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();
    assert!(by_path(&produced, "/lost.txt").is_none());
    assert_eq!(
        by_path(&produced, "/").unwrap().metadata["directory_parse_incomplete"],
        true
    );
}

#[test]
fn a_directory_entry_whose_name_overruns_the_data_is_flagged_incomplete() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    let mut block = vec![0u8; 4096];
    let dot = create_dir_entry_typed(1, ".", 2);
    let mut dotdot = create_dir_entry_typed(1, "..", 2);
    // ".." reaches exactly to the last 16 bytes of the block.
    let dotdot_len = (4080 - dot.len()) as u16;
    dotdot[4..6].copy_from_slice(&dotdot_len.to_le_bytes());
    block[..dot.len()].copy_from_slice(&dot);
    block[dot.len()..dot.len() + dotdot.len()].copy_from_slice(&dotdot);
    // An entry at 4080 claiming a 200-byte name.
    LittleEndian::write_u32(&mut block[4080..4084], 2);
    LittleEndian::write_u16(&mut block[4084..4086], 16);
    block[4086] = 200;
    block[4087] = 1;
    source.write_at(20 * 4096, &block);

    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();
    assert_eq!(
        by_path(&produced, "/").unwrap().metadata["directory_parse_incomplete"],
        true
    );
}

/// A live dirent name containing '/' would split into a fake path whose
/// components disagree with the recorded name.
#[test]
fn a_live_dirent_name_containing_a_slash_is_escaped_and_flagged() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_empty_file_inode(&source, 2);
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (1, ".", EXT4_FT_DIR),
            (1, "..", EXT4_FT_DIR),
            (2, "x/../../etc", EXT4_FT_REG_FILE),
        ]),
    );
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();

    assert!(
        !produced.iter().any(|a| a.metadata["parent_path"]
            .as_str()
            .is_some_and(|p| p.starts_with("/x"))),
        "no record may carry a path built from the hostile name"
    );
    let e = produced
        .iter()
        .find(|a| a.metadata.get("name_invalid") == Some(&serde_json::json!(true)))
        .expect("the entry is recorded, not hidden");
    assert_eq!(e.metadata["parent_path"], "/");
    assert_eq!(e.metadata["path"], "/x%2F..%2F..%2Fetc");
    assert_eq!(
        by_path(&produced, "/").unwrap().metadata["directory_parse_incomplete"],
        true
    );
}

/// An extent tree that cannot be read must not leave a file looking like it
/// has complete content.
#[test]
fn a_live_file_whose_extent_tree_is_unreadable_is_flagged_incomplete() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    // EXTENTS flag set, but i_block holds no 0xF30A header.
    source.write_at(
        10 * 4096,
        &create_inode(0x8000 | 0o644, 4096, 0x80000, &[0u8; 60]),
    );
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/broken.bin").unwrap();

    let e = by_path(&produced, "/broken.bin").unwrap();
    assert!(e.metadata.get("data_runs").is_none());
    assert_eq!(e.metadata["content_incomplete"], true);
    assert_eq!(
        e.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(e.metadata["content_incomplete_detail"].is_string());
}

/// CSUM_V2 widens every descriptor tag by two bytes.
#[test]
fn csum_v2_journal_tags_are_two_bytes_wider() {
    let v2 = JournalSuperblock::parse(&build_journal_superblock(4096, 1024, 1, 5, 3, 0x8)).unwrap();
    assert_eq!(v2.tag_bytes(), 10);
    let v2_64 = JournalSuperblock::parse(&build_journal_superblock(4096, 1024, 1, 5, 3, 0x8 | 0x2))
        .unwrap();
    assert_eq!(v2_64.tag_bytes(), 14);
    let v3 =
        JournalSuperblock::parse(&build_journal_superblock(4096, 1024, 1, 5, 3, 0x10)).unwrap();
    assert_eq!(v3.tag_bytes(), 16);

    // A V2 descriptor: tag 1 (UUID follows), then tag 2 (SAME_UUID | LAST_TAG),
    // each tag 10 bytes.
    let mut block = vec![0u8; 4096];
    jbd2_header(&mut block, 1, 7);
    BigEndian::write_u32(&mut block[12..16], 100);
    BigEndian::write_u16(&mut block[18..20], 0); // flags: UUID follows
    let second = 12 + 10 + 16;
    BigEndian::write_u32(&mut block[second..second + 4], 200);
    BigEndian::write_u16(&mut block[second + 6..second + 8], 2 | 8);
    let (targets, last) = parse_descriptor_tags(&block, v2.tag_bytes(), false, false);
    assert_eq!(targets, vec![100, 200]);
    assert!(last);
}

/// Revision-0 superblocks have no inode_size field: inodes are 128 bytes.
#[test]
fn a_revision_zero_superblock_has_128_byte_inodes() {
    let source = MockDataSource::new(8192);
    let mut sb_bytes = create_valid_superblock();
    LittleEndian::write_u32(&mut sb_bytes[76..80], 0); // s_rev_level
    LittleEndian::write_u16(&mut sb_bytes[88..90], 0); // field does not exist
    source.write_at(1024, &sb_bytes);
    assert_eq!(Superblock::parse(&source).unwrap().inode_size, 128);
}

#[test]
fn an_implausible_inode_size_is_rejected_with_an_error() {
    for bad in [0u16, 64, 100, 8192] {
        let source = MockDataSource::new(8192);
        let mut sb_bytes = create_valid_superblock();
        LittleEndian::write_u16(&mut sb_bytes[88..90], bad);
        source.write_at(1024, &sb_bytes);
        let err = Superblock::parse(&source).expect_err("inode_size must be validated");
        assert!(err.to_string().contains("inode_size"), "{err}");
    }
}

/// A pre-cancelled run produces no file entries at all (exact, in memory) and
/// is not mistaken for an unreadable root.
#[test]
fn a_pre_cancelled_run_produces_no_entries() {
    use seance_core::orchestrator::CancellationHandle;
    let source = MockDataSource::new(4096 * 100);
    let _ = setup_fs(&source);
    write_dir_inode(&source, 2, 20);
    write_empty_file_inode(&source, 3);
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (2, ".", EXT4_FT_DIR),
            (2, "..", EXT4_FT_DIR),
            (3, "f", EXT4_FT_REG_FILE),
        ]),
    );
    let handle = CancellationHandle::new();
    handle.cancel_all();
    let results = Ext4Parser::new()
        .with_cancellation(handle)
        .process(&fs_artifact(&source))
        .unwrap();
    assert_eq!(
        results
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .count(),
        0
    );
    assert!(!results
        .iter()
        .any(|a| a.metadata.get("root_inode_readable").is_some()));
}

/// Progress denominators are the superblock's inode count; the final event
/// carries exactly the entries walked.
#[test]
fn progress_events_report_the_inode_denominator_and_the_walked_count() {
    use seance_core::orchestrator::{OrchestratorEvent, ProgressReporter};
    let source = MockDataSource::new(4096 * 100);
    let _ = setup_fs(&source);
    write_dir_inode(&source, 2, 20);
    write_empty_file_inode(&source, 3);
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (2, ".", EXT4_FT_DIR),
            (2, "..", EXT4_FT_DIR),
            (3, "f", EXT4_FT_REG_FILE),
        ]),
    );
    let (tx, mut rx) = tokio::sync::broadcast::channel(64);
    let parser = Ext4Parser::new().with_progress(ProgressReporter::new(tx, "plugin.fs.ext4"));
    let artifact = fs_artifact(&source);
    parser.process(&artifact).unwrap();

    let mut last = None;
    while let Ok(event) = rx.try_recv() {
        if let OrchestratorEvent::ModuleProgress {
            artifact_id,
            units_done,
            units_total,
            unit,
            ..
        } = event
        {
            assert_eq!(artifact_id, artifact.id);
            assert_eq!(unit, "files");
            assert_eq!(units_total, Some(100), "the superblock's inodes_count");
            last = Some(units_done);
        }
    }
    assert_eq!(last, Some(2), "root directory + one file");
}

// ============================================================================
// EXT4-001: live directory entries are validated, and a walk that stopped early
// or reached a directory twice says so
// ============================================================================

/// Root directory 1 (block 20) holding `.`, `..` and "a.txt" (inode 5, a
/// regular file); `patch` may corrupt the block before it is written. Returns
/// the records the walk produced.
fn walk_root_with(patch: impl FnOnce(&mut Vec<u8>), a_txt_type: u8) -> Vec<Artifact> {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_empty_file_inode(&source, 5);
    let mut block = dir_block_of(&[
        (1, ".", EXT4_FT_DIR),
        (1, "..", EXT4_FT_DIR),
        (5, "a.txt", a_txt_type),
    ]);
    patch(&mut block);
    source.write_at(20 * 4096, &block);
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/d").unwrap();
    produced
}

/// A live entry whose `rec_len` is not a multiple of four cannot be stepped
/// over: the kernel rejects it, and the next "entry" would be read from the
/// middle of a field.
#[test]
fn a_misaligned_live_rec_len_stops_the_block_and_flags_the_directory() {
    let produced = walk_root_with(
        |b| b[24 + 4..24 + 6].copy_from_slice(&13u16.to_le_bytes()),
        1,
    );
    let d = by_path(&produced, "/d").unwrap();
    assert_eq!(d.metadata["directory_parse_incomplete"], true);
    assert!(
        by_path(&produced, "/d/a.txt").is_none(),
        "a record whose rec_len is not a multiple of four is not an entry"
    );
}

/// A `rec_len` that runs past its block is rejected, not followed: the entry is
/// not walked and the directory is flagged.
#[test]
fn a_live_rec_len_running_past_the_block_is_refused_and_flags_the_directory() {
    let produced = walk_root_with(
        |b| b[24 + 4..24 + 6].copy_from_slice(&5000u16.to_le_bytes()),
        1,
    );
    let d = by_path(&produced, "/d").unwrap();
    assert_eq!(d.metadata["directory_parse_incomplete"], true);
    assert!(by_path(&produced, "/d/a.txt").is_none());
}

/// A `rec_len` too short to hold the entry's own name is rejected.
#[test]
fn a_live_rec_len_shorter_than_its_own_name_is_refused() {
    let produced = walk_root_with(
        |b| b[24 + 4..24 + 6].copy_from_slice(&8u16.to_le_bytes()),
        1,
    );
    let d = by_path(&produced, "/d").unwrap();
    assert_eq!(d.metadata["directory_parse_incomplete"], true);
    assert!(by_path(&produced, "/d/a.txt").is_none());
}

/// A well-formed block is unchanged by the validation.
#[test]
fn a_well_formed_directory_block_is_still_listed_whole() {
    let produced = walk_root_with(|_| {}, 1);
    let d = by_path(&produced, "/d").unwrap();
    assert!(d.metadata.get("directory_parse_incomplete").is_none());
    assert!(by_path(&produced, "/d/a.txt").is_some());
    assert!(by_path(&produced, "/d/a.txt")
        .unwrap()
        .metadata
        .get("dirent_file_type_mismatch")
        .is_none());
}

/// The dirent's `file_type` byte says directory; the inode's mode says regular
/// file. The entry is kept, both values are published.
#[test]
fn a_dirent_file_type_that_disagrees_with_the_inode_mode_is_marked() {
    let produced = walk_root_with(|_| {}, EXT4_FT_DIR);
    let a = by_path(&produced, "/d/a.txt").expect("the entry is not suppressed");
    assert_eq!(a.metadata["dirent_file_type_mismatch"], true);
    assert_eq!(a.metadata["dirent_file_type"], EXT4_FT_DIR);
    assert_eq!(a.metadata["inode_file_type"], EXT4_FT_REG_FILE);
}

/// A directory with two names (a hard link, or a corrupt cycle) is emitted at
/// both and listed once; the second record says it was reached twice.
#[test]
fn a_directory_reached_a_second_time_is_marked_not_silently_repeated() {
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_dir_inode(&source, 3, 21);
    write_empty_file_inode(&source, 5);
    source.write_at(
        20 * 4096,
        &dir_block_of(&[
            (1, ".", EXT4_FT_DIR),
            (1, "..", EXT4_FT_DIR),
            (3, "x", EXT4_FT_DIR),
            (3, "y", EXT4_FT_DIR),
        ]),
    );
    source.write_at(
        21 * 4096,
        &dir_block_of(&[
            (3, ".", EXT4_FT_DIR),
            (1, "..", EXT4_FT_DIR),
            (5, "f.txt", EXT4_FT_REG_FILE),
        ]),
    );
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    parse_inode(&mut ctx, 1, "/").unwrap();
    let x = by_path(&produced, "/x").unwrap();
    let y = by_path(&produced, "/y").unwrap();
    assert!(x.metadata.get("duplicate_directory_visit").is_none());
    assert_eq!(y.metadata["duplicate_directory_visit"], true);
    assert!(by_path(&produced, "/x/f.txt").is_some());
    assert!(by_path(&produced, "/y/f.txt").is_none(), "not re-descended");
}

/// A walk cancelled before it started returns no inventory; it must not read as
/// an empty volume.
#[test]
fn a_cancelled_walk_leaves_a_status_record() {
    use seance_core::orchestrator::CancellationHandle;
    let source = MockDataSource::new(4096 * 100);
    let _ = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    let handle = CancellationHandle::new();
    handle.cancel_all();
    let results = Ext4Parser::new()
        .with_cancellation(handle)
        .process(&fs_artifact(&source))
        .unwrap();
    let rec = results
        .iter()
        .find(|a| a.metadata["type"] == "ext4_walk_status")
        .expect("a cancelled walk leaves a marker");
    assert_eq!(rec.metadata["inventory_incomplete"], true);
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert!(rec.metadata["inventory_incomplete_reason"].is_string());
}

/// A child skipped because cancellation fired mid-listing is counted against
/// the directory that held its name.
#[test]
fn a_child_skipped_by_cancellation_flags_its_directory() {
    use seance_core::orchestrator::CancellationHandle;
    let source = MockDataSource::new(4096 * 100);
    let (sb, groups) = setup_fs(&source);
    write_dir_inode(&source, 1, 20);
    write_empty_file_inode(&source, 5);
    let handle = Some(CancellationHandle::new());
    let mut produced = vec![];
    let mut ctx = ctx_for(&source, &sb, &groups, &mut produced);
    ctx.cancellation = &handle;
    handle.as_ref().unwrap().cancel_case(ctx.case_id);
    walk_live_child(&mut ctx, 5, EXT4_FT_REG_FILE, b"a.txt", "/d");
    assert_eq!(ctx.listing_gaps.cancelled, 1);
}

// ============================================================================
// EXT4-001: a BLOCK_UNINIT group's bitmap is derived, not left unassessed
// ============================================================================

/// SYNTHETIC mock volume: 4 groups of 256 blocks, flex_bg-style tables.
/// Groups 2 and 3 are BLOCK_UNINIT; group 3 carries a backup superblock, one
/// descriptor block and three reserved descriptor blocks. Group 3's own
/// bitmaps and inode table sit in group 2, as flex_bg places them. `g3_table`
/// is where group 3's inode table starts.
fn uninit_volume(g3_table: u32) -> (MockDataSource, Superblock, Vec<BlockGroupDescriptor>) {
    let source = MockDataSource::new(4096 * 1000);
    let mut sb_bytes = create_valid_superblock();
    LittleEndian::write_u32(&mut sb_bytes[32..36], 256); // blocks_per_group
    LittleEndian::write_u32(&mut sb_bytes[40..44], 64); // inodes_per_group: 4 table blocks
    LittleEndian::write_u32(&mut sb_bytes[100..104], 0x1 | 0x10); // SPARSE_SUPER | GDT_CSUM
    LittleEndian::write_u16(&mut sb_bytes[0xCE..0xD0], 3); // reserved GDT blocks
    source.write_at(1024, &sb_bytes);
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt = vec![0u8; 4 * 64];
    let mut set = |g: usize, bb: u32, ib: u32, it: u32, flags: u16| {
        let d = &mut gdt[g * 64..(g + 1) * 64];
        LittleEndian::write_u32(&mut d[0..4], bb);
        LittleEndian::write_u32(&mut d[4..8], ib);
        LittleEndian::write_u32(&mut d[8..12], it);
        LittleEndian::write_u16(&mut d[18..20], flags);
    };
    set(0, 5, 6, 10, 0);
    set(1, 100, 101, 102, 0);
    set(2, 512, 513, 514, 0x2);
    set(3, 518, 519, g3_table, 0x2);
    source.write_at(4096, &gdt);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    (source, sb, groups)
}

#[test]
fn a_block_uninit_group_gets_the_bitmap_the_kernel_would_compute() {
    let (source, sb, groups) = uninit_volume(520);
    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("read");
    assert_eq!(bitmaps.synthesized_groups(), 2);
    assert_eq!(bitmaps.uninit_groups(), 0);
    // Group 2: its own bitmaps and table (512..=517) plus group 3's, which
    // flex_bg put here (518..=523). Group 3: backup superblock 768, one
    // descriptor block 769, three reserved descriptor blocks 770..=772.
    let in_use: Vec<u64> = (512..=523).chain(768..=772).collect();
    for block in 512..1000u64 {
        let want = if in_use.contains(&block) {
            BlockState::InUse
        } else {
            BlockState::Free
        };
        assert_eq!(
            std::mem::discriminant(&bitmaps.state(block)),
            std::mem::discriminant(&want),
            "block {block}"
        );
    }
}

#[test]
fn the_allocation_map_says_a_bitmap_was_derived_not_read() {
    let (source, sb, groups) = uninit_volume(520);
    let source_arc: Arc<dyn DataSource> = Arc::new(source.clone());
    let (map, free) = build_allocation_map_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &source,
        &source_arc,
        &sb,
        &groups,
    )
    .expect("map");
    assert_eq!(
        map.metadata["allocation_block_uninit_groups_synthesized"],
        2
    );
    assert!(map.metadata["allocation_block_uninit_basis"]
        .as_str()
        .unwrap()
        .contains("not read from disk"));
    assert!(map.metadata.get("allocation_block_uninit_groups").is_none());
    assert!(
        free.iter()
            .any(|r| r.metadata["first_cluster"].as_u64().unwrap() <= 600
                && r.metadata["first_cluster"].as_u64().unwrap()
                    + r.metadata["clusters"].as_u64().unwrap()
                    > 700),
        "the derived free run in group 2 is offered to the carver"
    );
}

/// A table that falls off the end of the volume cannot be marked: the layout is
/// not derivable, so no group is called free on a guess.
#[test]
fn a_block_uninit_group_whose_layout_cannot_be_derived_stays_unassessed() {
    let (source, sb, groups) = uninit_volume(998);
    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("read");
    assert_eq!(bitmaps.synthesized_groups(), 0);
    assert_eq!(bitmaps.uninit_groups(), 2);
    assert!(matches!(bitmaps.state(600), BlockState::Unassessed));
    assert!(bitmaps.is_allocated(600), "never reported as free");
}

// ============================================================================
// EXT4-001: bigalloc bitmaps are indexed by cluster
// ============================================================================

/// SYNTHETIC mock bigalloc volume: 4 KiB blocks, 16 KiB clusters (four blocks
/// to a bit), one group of 32768 blocks and 8192 clusters. The bitmap at block
/// 5 marks clusters 0 and 2 in use.
fn bigalloc_volume(
    log_cluster_size: u32,
) -> (MockDataSource, Superblock, Vec<BlockGroupDescriptor>) {
    let source = MockDataSource::new(4096 * 1000);
    let mut sb_bytes = create_valid_superblock();
    LittleEndian::write_u32(&mut sb_bytes[0x1C..0x20], log_cluster_size);
    LittleEndian::write_u32(&mut sb_bytes[0x24..0x28], 8192); // clusters per group
    LittleEndian::write_u32(&mut sb_bytes[100..104], 0x1 | 0x200); // SPARSE_SUPER | BIGALLOC
    source.write_at(1024, &sb_bytes);
    let sb = Superblock::parse(&source).unwrap();
    let mut gdt = vec![0u8; 64];
    LittleEndian::write_u32(&mut gdt[0..4], 5);
    LittleEndian::write_u32(&mut gdt[4..8], 6);
    LittleEndian::write_u32(&mut gdt[8..12], 10);
    source.write_at(4096, &gdt);
    source.write_at(5 * 4096, &[0b0000_0101u8]);
    let groups = BlockGroupDescriptor::parse_table(&source, &sb).unwrap();
    (source, sb, groups)
}

/// One bit covers four blocks: a block is in use when its cluster's bit is.
#[test]
fn a_bigalloc_bitmap_is_read_one_bit_per_cluster() {
    let (source, sb, groups) = bigalloc_volume(4);
    let bitmaps = GroupBitmaps::read(&source, &sb, &groups).expect("bigalloc is read");
    for block in 0..16u64 {
        let in_use = matches!(block / 4, 0 | 2);
        assert_eq!(
            matches!(bitmaps.state(block), BlockState::InUse),
            in_use,
            "block {block}"
        );
        assert_eq!(bitmaps.is_allocated(block), in_use, "block {block}");
    }
    assert!(matches!(bitmaps.state(16), BlockState::Free));
}

/// Free regions on a bigalloc volume start and end on cluster boundaries.
#[test]
fn bigalloc_free_regions_are_whole_clusters() {
    let (source, sb, groups) = bigalloc_volume(4);
    let source_arc: Arc<dyn DataSource> = Arc::new(source.clone());
    let (map, free) = build_allocation_map_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &source,
        &source_arc,
        &sb,
        &groups,
    )
    .expect("map");
    assert!(map.metadata.get("allocation_map_unavailable").is_none());
    let runs: Vec<(u64, u64)> = free
        .iter()
        .map(|r| {
            (
                r.metadata["first_cluster"].as_u64().unwrap(),
                r.metadata["clusters"].as_u64().unwrap(),
            )
        })
        .collect();
    assert!(runs.contains(&(4, 4)), "cluster 1 is free: {runs:?}");
    assert!(runs.iter().all(|(first, n)| first % 4 == 0 && n % 4 == 0));
}

/// Cluster fields that disagree with the block fields leave the bitmaps
/// unindexed, and the volume says so.
#[test]
fn a_bigalloc_volume_with_inconsistent_cluster_fields_is_still_refused() {
    let (source, sb, groups) = bigalloc_volume(2); // cluster no larger than a block
    assert!(GroupBitmaps::read(&source, &sb, &groups).is_none());
}
