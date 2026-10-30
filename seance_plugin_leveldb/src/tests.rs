use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

fn varint32(mut n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

fn put_entry(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut e = vec![1u8];
    e.extend(varint32(key.len() as u32));
    e.extend_from_slice(key);
    e.extend(varint32(value.len() as u32));
    e.extend_from_slice(value);
    e
}

fn delete_entry(key: &[u8]) -> Vec<u8> {
    let mut e = vec![0u8];
    e.extend(varint32(key.len() as u32));
    e.extend_from_slice(key);
    e
}

fn write_batch(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut wb = Vec::new();
    wb.extend_from_slice(&1u64.to_le_bytes()); // sequence
    wb.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // count
    for e in entries {
        wb.extend_from_slice(e);
    }
    wb
}

/// Wrap a payload in a physical log record (crc ignored by the parser).
fn log_record(rtype: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    r.push(rtype);
    r.extend_from_slice(payload);
    r
}

fn utf16_value(s: &str) -> Vec<u8> {
    let mut v = vec![0u8]; // UTF-16LE marker
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn latin1_value(s: &str) -> Vec<u8> {
    let mut v = vec![1u8]; // Latin-1/UTF-8 marker
    v.extend_from_slice(s.as_bytes());
    v
}

fn run(name: &str, path: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name, "path": path }),
    );
    LevelDbStorageParser.process(&art).unwrap()
}

const LOG_PATH: &str =
    "/Users/x/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb/000003.log";

#[test]
fn extracts_local_storage_items() {
    let origin = "https://example.com";
    let entries = vec![
        put_entry(
            format!("_{origin}\0theme").as_bytes(),
            &latin1_value("dark"),
        ),
        put_entry(
            format!("_{origin}\0widget").as_bytes(),
            &utf16_value("panel-A"),
        ),
        // META and VERSION keys must be ignored.
        put_entry(format!("META:{origin}").as_bytes(), &[0, 0, 0]),
        put_entry(b"VERSION", &[1]),
        delete_entry(format!("_{origin}\0stale").as_bytes()),
    ];
    let log = log_record(1, &write_batch(&entries));
    let out = run("000003.log", LOG_PATH, log);

    // Two puts + one delete under the data-key schema; META/VERSION skipped.
    assert_eq!(
        out.len(),
        3,
        "got {:?}",
        out.iter().map(|a| &a.metadata).collect::<Vec<_>>()
    );

    let theme = out
        .iter()
        .find(|a| a.metadata.get("storage_key").and_then(|v| v.as_str()) == Some("theme"))
        .unwrap();
    assert_eq!(theme.metadata["origin"], origin);
    assert_eq!(theme.metadata["value"], "dark");
    assert_eq!(theme.metadata["deleted"], false);
    assert_eq!(theme.metadata["type"], "LocalStorageItem");

    let widget = out
        .iter()
        .find(|a| a.metadata.get("storage_key").and_then(|v| v.as_str()) == Some("widget"))
        .unwrap();
    assert_eq!(widget.metadata["value"], "panel-A"); // UTF-16 decoded

    let stale = out
        .iter()
        .find(|a| a.metadata.get("storage_key").and_then(|v| v.as_str()) == Some("stale"))
        .unwrap();
    assert_eq!(stale.metadata["deleted"], true);
    assert!(stale.metadata.get("value").is_none());
}

#[test]
fn reassembles_records_split_across_first_and_last() {
    let origin = "https://split.test";
    let wb = write_batch(&[put_entry(
        format!("_{origin}\0k").as_bytes(),
        &latin1_value("v"),
    )]);
    let mid = wb.len() / 2;
    let mut log = log_record(2, &wb[..mid]); // FIRST
    log.extend(log_record(4, &wb[mid..])); // LAST
    let out = run("000005.log", LOG_PATH, log);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["origin"], origin);
    assert_eq!(out[0].metadata["value"], "v");
}

#[test]
fn ignores_non_storage_log_paths() {
    let log = log_record(
        1,
        &write_batch(&[put_entry(b"_https://x.com\0a", &latin1_value("b"))]),
    );
    // Right shape, but the path isn't a storage/leveldb location.
    assert!(run("app.log", "/var/log/app.log", log.clone()).is_empty());
    // Not a .log at all.
    assert!(run("data.bin", LOG_PATH, log).is_empty());
}

#[test]
fn garbage_log_yields_no_storage_items_without_panic() {
    // Garbage recovers no storage items, and now says why: a `.log` under a
    // Local Storage path whose framing is unreadable is a finding, not an empty
    // profile (B2-162). An actually-empty file stays completely unmarked.
    let garbage = run("000001.log", LOG_PATH, vec![0xff; 100]);
    assert!(garbage
        .iter()
        .all(|a| a.metadata["type"] != "LocalStorageItem"));
    assert_eq!(
        garbage
            .iter()
            .filter(|a| a.metadata["type"] == "LevelDbParseStatus")
            .count(),
        1
    );

    assert!(run("000001.log", LOG_PATH, Vec::new()).is_empty());
}

#[test]
fn module_metadata() {
    let p = LevelDbStorageParser;
    assert_eq!(p.id(), "plugin.browsers.leveldb_storage");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

// ── SSTable (.ldb) fixtures & tests ──────────────────────────────────────────

fn varint64(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

/// A LevelDB InternalKey: user key + 8-byte `(seq<<8)|type` trailer (LE).
fn internal_key(user: &[u8], ty: u8) -> Vec<u8> {
    let mut k = user.to_vec();
    let trailer: u64 = (1u64 << 8) | ty as u64;
    k.extend_from_slice(&trailer.to_le_bytes());
    k
}

/// A block with all-full keys (shared=0) and a single restart point.
fn build_block(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    for (k, v) in entries {
        b.extend(varint32(0));
        b.extend(varint32(k.len() as u32));
        b.extend(varint32(v.len() as u32));
        b.extend_from_slice(k);
        b.extend_from_slice(v);
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // restart[0] = 0
    b.extend_from_slice(&1u32.to_le_bytes()); // num_restarts = 1
    b
}

/// (block+trailer bytes, content size for the BlockHandle).
fn block_with_trailer(block: &[u8], snappy: bool) -> (Vec<u8>, usize) {
    let content = if snappy {
        snap::raw::Encoder::new().compress_vec(block).unwrap()
    } else {
        block.to_vec()
    };
    let size = content.len();
    let mut out = content;
    out.push(if snappy { 1 } else { 0 });
    out.extend_from_slice(&0u32.to_le_bytes()); // crc (ignored)
    (out, size)
}

fn build_sstable(entries: &[(Vec<u8>, Vec<u8>)], snappy: bool) -> Vec<u8> {
    let refs: Vec<(&[u8], &[u8])> = entries
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let (data_full, data_size) = block_with_trailer(&build_block(&refs), snappy);

    let mut file = Vec::new();
    let data_off = file.len();
    file.extend_from_slice(&data_full);

    // Index: one entry pointing at the data block.
    let mut handle = varint64(data_off as u64);
    handle.extend(varint64(data_size as u64));
    let last_key = entries.last().map(|(k, _)| k.clone()).unwrap_or_default();
    let (index_full, index_size) = block_with_trailer(&build_block(&[(&last_key, &handle)]), false);
    let index_off = file.len();
    file.extend_from_slice(&index_full);

    // Metaindex: empty.
    let (meta_full, meta_size) = block_with_trailer(&build_block(&[]), false);
    let meta_off = file.len();
    file.extend_from_slice(&meta_full);

    // Footer: metaindex handle, index handle, pad to 40, magic.
    let mut footer = Vec::new();
    footer.extend(varint64(meta_off as u64));
    footer.extend(varint64(meta_size as u64));
    footer.extend(varint64(index_off as u64));
    footer.extend(varint64(index_size as u64));
    footer.resize(40, 0);
    footer.extend_from_slice(&0xdb47_7524_8b80_fb57u64.to_le_bytes());
    file.extend_from_slice(&footer);
    file
}

const LDB_PATH: &str =
    "/Users/x/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb/000010.ldb";

#[test]
fn extracts_from_sstable_uncompressed_and_snappy() {
    let origin = "https://sstable.test";
    let entries = vec![
        (
            internal_key(format!("_{origin}\0a").as_bytes(), 1),
            latin1_value("va"),
        ),
        (
            internal_key(format!("_{origin}\0b").as_bytes(), 1),
            utf16_value("vb"),
        ),
        (
            internal_key(format!("_{origin}\0gone").as_bytes(), 0),
            Vec::new(),
        ),
    ];
    for snappy in [false, true] {
        let sst = build_sstable(&entries, snappy);
        let out = run("000010.ldb", LDB_PATH, sst);
        assert_eq!(out.len(), 3, "snappy={snappy}");
        let a = out
            .iter()
            .find(|x| x.metadata["storage_key"] == "a")
            .unwrap();
        assert_eq!(a.metadata["value"], "va", "snappy={snappy}");
        let b = out
            .iter()
            .find(|x| x.metadata["storage_key"] == "b")
            .unwrap();
        assert_eq!(b.metadata["value"], "vb", "snappy={snappy} (UTF-16)");
        let gone = out
            .iter()
            .find(|x| x.metadata["storage_key"] == "gone")
            .unwrap();
        assert_eq!(gone.metadata["deleted"], true, "snappy={snappy}");
    }
}

#[test]
fn parse_block_reconstructs_prefix_compressed_keys() {
    // "apple" then shared=5 + "sauce" => "applesauce".
    let mut b = Vec::new();
    b.extend(varint32(0));
    b.extend(varint32(5));
    b.extend(varint32(1));
    b.extend_from_slice(b"apple1");
    b.extend(varint32(5));
    b.extend(varint32(5));
    b.extend(varint32(1));
    b.extend_from_slice(b"sauce2");
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());

    let (kvs, intact) = super::parse_block(&b);
    assert!(intact, "a well-formed block must report itself complete");
    assert_eq!(kvs.len(), 2);
    assert_eq!(kvs[0].0, b"apple");
    assert_eq!(kvs[0].1, b"1");
    assert_eq!(kvs[1].0, b"applesauce");
    assert_eq!(kvs[1].1, b"2");
}

// --- B2-162: a capped or damaged prefix is not the whole database -----------
//
// `read_capped(.., MAX_LOG_BYTES)` keeps the first 256 MiB and the log/SSTable
// walks stop at the first byte they cannot believe. Both produced a tidy list
// of `localStorage` keys with nothing to say the rest of the file was never
// read, so "this origin stored nothing" and "we stopped before reaching it"
// rendered identically. Against the unfixed crate every test below fails: no
// `content_incomplete` and no `LevelDbParseStatus` existed anywhere in it.

use seance_core::test_support::TruncatedSource;

fn run_ds(name: &str, path: &str, ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name, "path": path }),
    );
    LevelDbStorageParser.process(&art).unwrap()
}

/// A log holding two ordinary put entries.
fn sample_log() -> Vec<u8> {
    let origin = "https://cap.test";
    log_record(
        1,
        &write_batch(&[
            put_entry(format!("_{origin}\0one").as_bytes(), &latin1_value("1")),
            put_entry(format!("_{origin}\0two").as_bytes(), &latin1_value("2")),
        ]),
    )
}

fn status_records(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "LevelDbParseStatus")
        .collect()
}

fn storage_items(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "LocalStorageItem")
        .collect()
}

#[test]
fn a_whole_log_carries_no_incompleteness() {
    // The counterweight: if a complete parse were marked, the marks on the
    // truncated ones would mean nothing.
    let out = run("000003.log", LOG_PATH, sample_log());
    assert_eq!(storage_items(&out).len(), 2);
    assert!(status_records(&out).is_empty());
    for a in &out {
        assert!(a.metadata.get("content_incomplete").is_none());
    }
}

#[test]
fn a_source_that_under_delivers_marks_every_item_and_says_so() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(sample_log()));
    let out = run_ds("000003.log", LOG_PATH, ds);

    let items = storage_items(&out);
    assert_eq!(items.len(), 2, "the readable prefix must still parse");
    for i in &items {
        assert_eq!(i.metadata["content_incomplete"], true);
        assert_eq!(i.metadata["content_incomplete_reason"], "short_read");
    }

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "short_read"
    );
    assert_eq!(status[0].metadata["items_emitted"], 2);
    assert_eq!(status[0].metadata["subtype"], "local_storage_incomplete");
    assert!(status[0].metadata["detail"].is_string());
}

/// The sentence has to reach the examiner, not just the JSON.
///
/// `frontend/src/lib/incompleteness.ts` is the one place the incompleteness
/// pair is read, and it takes the parser's sentence from
/// `content_incomplete_detail`. This crate wrote it to a bare `detail` that
/// nothing on that path displays, so a truncated Local Storage database showed
/// the examiner the token "short_read" and never how many of its bytes were
/// missing — on the status record OR on the storage items themselves, which
/// carried no sentence at all. Both assertions fail against the unfixed crate.
#[test]
fn the_sentence_lands_on_the_key_the_examiner_facing_reader_shows() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(sample_log()));
    let out = run_ds("000003.log", LOG_PATH, ds);

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    let detail = status[0].metadata["detail"].as_str().unwrap();
    assert_eq!(status[0].metadata["content_incomplete_detail"], detail);

    for i in storage_items(&out) {
        assert_eq!(
            i.metadata["content_incomplete_detail"], detail,
            "the stamp on a record has to say what the marker says"
        );
    }
}

#[test]
fn a_file_over_the_byte_cap_reports_cap_reached() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(sample_log(), MAX_LOG_BYTES + 1));
    let out = run_ds("000003.log", LOG_PATH, ds);

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "cap_reached"
    );
    assert_eq!(status[0].metadata["declared_size"], MAX_LOG_BYTES + 1);
    assert_eq!(status[0].metadata["max_log_bytes"], MAX_LOG_BYTES);
    for i in storage_items(&out) {
        assert_eq!(i.metadata["content_incomplete_reason"], "cap_reached");
    }
}

#[test]
fn log_framing_that_stops_making_sense_is_reported() {
    let mut data = sample_log();
    // A header claiming more payload than the file holds: everything after it
    // is unreachable, and used to be dropped with a bare `break`.
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&4096u16.to_le_bytes());
    data.push(1);
    data.extend_from_slice(&[0u8; 8]);

    let out = run("000003.log", LOG_PATH, data);
    assert_eq!(storage_items(&out).len(), 2, "records before the damage");
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

#[test]
fn an_unterminated_logical_record_is_not_an_empty_database() {
    // A FIRST fragment with no LAST: nothing decodes at all. Without the status
    // record this is byte-for-byte the same output as a log with no entries.
    let origin = "https://split.test";
    let wb = write_batch(&[put_entry(
        format!("_{origin}\0k").as_bytes(),
        &latin1_value("v"),
    )]);
    let out = run("000003.log", LOG_PATH, log_record(2, &wb));

    assert!(storage_items(&out).is_empty());
    let status = status_records(&out);
    assert_eq!(
        status.len(),
        1,
        "an unreadable log must not render as an empty one"
    );
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(status[0].metadata["items_emitted"], 0);
}

#[test]
fn a_write_batch_shorter_than_its_declared_count_is_reported() {
    let origin = "https://batch.test";
    let mut wb = Vec::new();
    wb.extend_from_slice(&1u64.to_le_bytes()); // sequence
    wb.extend_from_slice(&3u32.to_le_bytes()); // claims three operations
    wb.extend(put_entry(
        format!("_{origin}\0only").as_bytes(),
        &latin1_value("v"),
    )); // but carries one

    let out = run("000003.log", LOG_PATH, log_record(1, &wb));
    assert_eq!(storage_items(&out).len(), 1);
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

#[test]
fn an_sstable_without_a_valid_footer_is_reported_not_treated_as_empty() {
    // Every early exit in `sstable_key_values` returned the same empty vector
    // an empty table returns. A `.ldb` we cannot read must say so.
    let junk = vec![0x41u8; 256];
    let out = run("000010.ldb", LDB_PATH, junk);

    assert!(storage_items(&out).is_empty());
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(status[0].metadata["items_emitted"], 0);
    assert_eq!(status[0].metadata["file_name"], "000010.ldb");
}

#[test]
fn a_block_cut_mid_entry_reports_itself_incomplete() {
    // Entries are prefix-compressed against their predecessor, so a bad varint
    // makes every later entry undecodable too — the prefix decoded so far is
    // not the block's contents.
    let mut b = Vec::new();
    b.extend(varint32(0));
    b.extend(varint32(5));
    b.extend(varint32(1));
    b.extend_from_slice(b"apple1");
    // A second entry claiming a key longer than the block holds.
    b.extend(varint32(0));
    b.extend(varint32(99));
    b.extend(varint32(1));
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());

    let (kvs, intact) = super::parse_block(&b);
    assert_eq!(kvs.len(), 1, "the decodable prefix is still returned");
    assert!(
        !intact,
        "a block cut mid-entry must not report itself whole"
    );
}

/// An over-wide varint was **truncated**, not refused. `read_varint32` looped
/// `while shift < 32` and accepted a fifth byte at `shift = 28`, where
/// `(b & 0x7f) << 28` silently drops that byte's top three bits: a length
/// field of 0x1_0000_0000 read back as 0, which is a different record from
/// the one on disk. A value that does not fit is not a value this reader knows.
#[test]
fn an_over_wide_varint32_is_refused_and_not_truncated() {
    // 0xFF 0xFF 0xFF 0xFF 0x1F encodes 2^33 - 1: the fifth byte carries five
    // significant bits where only four fit.
    let over = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x1F];
    assert_eq!(read_varint32(&over, 0), None, "must refuse, not truncate");

    // The widest value that does fit still reads, so the guard is not simply
    // refusing every five-byte form.
    let widest = varint32(u32::MAX);
    assert_eq!(widest.len(), 5);
    assert_eq!(read_varint32(&widest, 0), Some((u32::MAX as usize, 5)));
    assert_eq!(read_varint32(&varint32(0), 0), Some((0, 1)));
}

/// The same shape one byte wider: `read_varint64`'s tenth byte at `shift = 63`
/// keeps one bit and drops six.
#[test]
fn an_over_wide_varint64_is_refused_and_not_truncated() {
    let over = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03];
    assert_eq!(read_varint64(&over, 0), None, "must refuse, not truncate");

    let widest = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    assert_eq!(read_varint64(&widest, 0), Some((u64::MAX, 10)));
}
