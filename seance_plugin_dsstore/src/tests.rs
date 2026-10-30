use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;
use uuid::Uuid;

// --- synthetic .DS_Store builder --------------------------------------------

/// Encode one record: `u32 name_len` (UTF-16 units), UTF-16BE name, 4-byte
/// structureId, 4-byte dataType, then the raw value bytes.
fn encode_record(name: &str, sid: &[u8; 4], dtype: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    let units: Vec<u16> = name.encode_utf16().collect();
    r.extend_from_slice(&(units.len() as u32).to_be_bytes());
    for u in units {
        r.extend_from_slice(&u.to_be_bytes());
    }
    r.extend_from_slice(sid);
    r.extend_from_slice(dtype);
    r.extend_from_slice(value);
    r
}

/// Append a buddy block so that its file offset is `(multiple of 32) + 4`, then
/// return the packed buddy address (offset | size-exponent).
fn align_push(buf: &mut Vec<u8>, block: &[u8]) -> u32 {
    while (buf.len() as isize - 4).rem_euclid(32) != 0 {
        buf.push(0);
    }
    let file_off = buf.len();
    let offset_val = (file_off - 4) as u32; // multiple of 32 => low 5 bits clear
    let mut exp = 5u32;
    while (1usize << exp) < block.len().max(1) {
        exp += 1;
    }
    let addr = offset_val | exp;
    buf.extend_from_slice(block);
    while buf.len() < file_off + (1usize << exp) {
        buf.push(0);
    }
    addr
}

/// Build a minimal but structurally valid `.DS_Store` with a single leaf node
/// holding three records: `note.txt`/Iloc(long), `note.txt`/bwsp(blob),
/// `photo.png`/vSrn(long).
fn build_synthetic() -> Vec<u8> {
    let mut leaf = Vec::new();
    leaf.extend_from_slice(&0u32.to_be_bytes()); // mode = leaf
    leaf.extend_from_slice(&3u32.to_be_bytes()); // record count
    leaf.extend(encode_record(
        "note.txt",
        b"Iloc",
        b"long",
        &42u32.to_be_bytes(),
    ));
    let mut blob = 4u32.to_be_bytes().to_vec();
    blob.extend_from_slice(b"AAAA");
    leaf.extend(encode_record("note.txt", b"bwsp", b"blob", &blob));
    leaf.extend(encode_record(
        "photo.png",
        b"vSrn",
        b"long",
        &7u32.to_be_bytes(),
    ));

    // Header (32 bytes); buddy offsets filled in after the bookkeeping block.
    let mut buf = vec![0u8; 32];
    buf[0..4].copy_from_slice(&1u32.to_be_bytes());
    buf[4..8].copy_from_slice(b"Bud1");

    let leaf_addr = align_push(&mut buf, &leaf);

    // Master (DSDB) block: root_id -> block index 2 (the leaf).
    let mut master = Vec::new();
    master.extend_from_slice(&2u32.to_be_bytes()); // root_block_id
    master.extend_from_slice(&0u32.to_be_bytes()); // levels
    master.extend_from_slice(&3u32.to_be_bytes()); // record_count
    master.extend_from_slice(&1u32.to_be_bytes()); // block_count
    let master_addr = align_push(&mut buf, &master);

    // Bookkeeping block: block_count, unused, 256 address slots, dir table.
    let mut bk = Vec::new();
    bk.extend_from_slice(&3u32.to_be_bytes()); // block_count (indices 0,1,2)
    bk.extend_from_slice(&0u32.to_be_bytes()); // unused
    let mut addrs = vec![0u32; 256];
    addrs[1] = master_addr; // dir "DSDB" -> block 1
    addrs[2] = leaf_addr; // master.root_id == 2
    for a in &addrs {
        bk.extend_from_slice(&a.to_be_bytes());
    }
    bk.extend_from_slice(&1u32.to_be_bytes()); // dir_count
    bk.push(4);
    bk.extend_from_slice(b"DSDB");
    bk.extend_from_slice(&1u32.to_be_bytes()); // block number 1

    while (buf.len() as isize - 4).rem_euclid(32) != 0 {
        buf.push(0);
    }
    let bk_file_off = buf.len();
    buf.extend_from_slice(&bk);

    let off_bk = (bk_file_off - 4) as u32;
    buf[8..12].copy_from_slice(&off_bk.to_be_bytes());
    buf[12..16].copy_from_slice(&(bk.len() as u32).to_be_bytes());
    buf[16..20].copy_from_slice(&off_bk.to_be_bytes());
    buf
}

fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    DSStoreParser.process(&art).unwrap()
}

// --- tests -------------------------------------------------------------------

#[test]
fn module_id_stable() {
    assert_eq!(DSStoreParser.id(), "plugin.macos.ds_store");
}

#[test]
fn parses_synthetic_btree() {
    let arts = run(".DS_Store", build_synthetic());
    // Two distinct filenames, one record each.
    assert_eq!(arts.len(), 2, "expected 2 DSStoreEntry records");

    let by_name = |n: &str| {
        arts.iter()
            .find(|a| a.metadata["filename"] == n)
            .unwrap_or_else(|| panic!("missing filename {n}"))
    };

    let note = by_name("note.txt");
    assert_eq!(note.metadata["type"], "DSStoreEntry");
    assert_eq!(note.metadata["subtype"], "ds_store");
    assert_eq!(note.metadata["name"], "note.txt");
    let structs: Vec<&str> = note.metadata["structures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(structs, vec!["Iloc", "bwsp"]);

    let photo = by_name("photo.png");
    assert_eq!(photo.metadata["structures"], json!(["vSrn"]));
    // Child artifacts must be parented to the source.
    assert!(note.parent_id.is_some());
}

#[test]
fn self_selects_by_magic_without_name() {
    // Named like an unrelated file, but the Bud1 magic still selects it.
    let arts = run("random_carved_blob.bin", build_synthetic());
    assert_eq!(arts.len(), 2);
}

#[test]
fn non_ds_store_yields_nothing() {
    assert!(run("notes.txt", b"this is not a ds_store file".to_vec()).is_empty());
    // Right name, but no Bud1 magic -> nothing.
    assert!(run(".DS_Store", b"\x00\x00\x00\x01XXXXjunk".to_vec()).is_empty());
    // No data source at all.
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": ".DS_Store" }),
    );
    assert!(DSStoreParser.process(&art).unwrap().is_empty());
}

#[test]
fn does_not_panic_on_truncation() {
    // Every truncation prefix of a valid file must be handled gracefully.
    let full = build_synthetic();
    for len in 0..=full.len() {
        let _ = run(".DS_Store", full[..len].to_vec());
    }
    // Valid magic followed by garbage of assorted lengths.
    for len in 8..512 {
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&1u32.to_be_bytes());
        b[4..8].copy_from_slice(b"Bud1");
        for (i, byte) in b.iter_mut().enumerate().skip(8) {
            *byte = (i * 37 % 251) as u8;
        }
        let _ = run(".DS_Store", b);
    }
}

#[test]
fn linear_scan_recovers_when_btree_broken() {
    // Corrupt the buddy header so the B-tree walk fails, forcing the fallback
    // scan to recover the embedded records directly.
    let mut buf = build_synthetic();
    buf[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    buf[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let arts = run(".DS_Store", buf);
    let names: Vec<&str> = arts
        .iter()
        .map(|a| a.metadata["filename"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"note.txt"),
        "scan missed note.txt: {names:?}"
    );
    assert!(
        names.contains(&"photo.png"),
        "scan missed photo.png: {names:?}"
    );
}

/// Real-sample test, gated on `SEANCE_DSSTORE_SAMPLE=/path/to/.DS_Store`.
#[test]
fn real_sample() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_DSSTORE_SAMPLE") else {
        return;
    };
    let path = path.display().to_string();
    let Ok(bytes) = std::fs::read(&path) else {
        panic!("SEANCE_DSSTORE_SAMPLE set but unreadable: {path}");
    };
    let arts = run(".DS_Store", bytes);
    assert!(
        !arts.is_empty(),
        "expected >=1 DSStoreEntry from real sample {path}"
    );
    for a in &arts {
        assert_eq!(a.metadata["type"], "DSStoreEntry");
        let filename = a.metadata["filename"].as_str().unwrap_or("");
        assert!(!filename.is_empty(), "empty filename in a DSStoreEntry");
        let structs = a.metadata["structures"].as_array().unwrap();
        assert!(
            !structs.is_empty(),
            "DSStoreEntry for {filename} has no structures"
        );
    }
}

// --- Partial-parse honesty (B2-086) ------------------------------------------

/// A fully read, fully walked `.DS_Store` must not claim to be a prefix.
#[test]
fn a_complete_ds_store_emits_no_incomplete_marker() {
    let arts = run(".DS_Store", build_synthetic());
    assert!(
        !arts
            .iter()
            .any(|a| a.metadata["type"] == "DSStoreParseStatus"),
        "a complete parse must not claim to be incomplete"
    );
}

/// A `.DS_Store` served short of its declared size yields a prefix of the folder
/// inventory; without the marker that prefix reads as the whole folder listing.
#[test]
fn a_short_read_ds_store_emits_an_incomplete_marker() {
    use seance_core::test_support::TruncatedSource;

    let bytes = build_synthetic();
    let declared = bytes.len() as u64 + 4096;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": ".DS_Store" }),
    );
    let arts = DSStoreParser.process(&art).unwrap();
    let marker = arts
        .iter()
        .find(|a| a.metadata["type"] == "DSStoreParseStatus")
        .expect("short read must leave an incomplete marker");
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(marker.metadata["input_truncated"], json!(true));
    assert_eq!(marker.metadata["record_cap_reached"], json!(false));
    assert_eq!(marker.metadata["declared_size"], json!(declared));
}
