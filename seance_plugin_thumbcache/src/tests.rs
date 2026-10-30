use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// Run the parser over an in-memory buffer presented as a named `FileEntry`.
fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    ThumbcacheParser.process(&art).unwrap()
}

/// Build a synthetic thumbcache: a 24-byte `CMMM` file header followed by one
/// `CMMM` entry per `(entry_hash, identifier_utf16, data)` tuple. Each entry
/// uses a 28-byte header, so `cache_entry_size = 28 + id + padding(0) + data`.
fn build_file(entries: &[(u64, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    // File header (24 bytes).
    buf.extend_from_slice(b"CMMM");
    buf.extend_from_slice(&0x14u32.to_le_bytes()); // version
    buf.extend_from_slice(&1u32.to_le_bytes()); // cache_type
    buf.extend_from_slice(&24u32.to_le_bytes()); // first_cache_entry
    buf.extend_from_slice(&0u32.to_le_bytes()); // first_available_entry
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // number_of_cache_entries

    for (hash, ident, data) in entries {
        let id_size = ident.len() as u32;
        let pad_size = 0u32;
        let data_size = data.len() as u32;
        let cache_entry_size = 28 + id_size + pad_size + data_size;
        buf.extend_from_slice(b"CMMM");
        buf.extend_from_slice(&cache_entry_size.to_le_bytes());
        buf.extend_from_slice(&hash.to_le_bytes());
        buf.extend_from_slice(&id_size.to_le_bytes());
        buf.extend_from_slice(&pad_size.to_le_bytes());
        buf.extend_from_slice(&data_size.to_le_bytes());
        buf.extend_from_slice(ident);
        buf.extend_from_slice(data);
    }
    buf
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// A minimal but structurally valid JPEG (SOI + APP0 + EOI).
fn tiny_jpeg() -> Vec<u8> {
    vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0xFF, 0xD9,
    ]
}

#[test]
fn parses_single_jpeg_entry() {
    let data = tiny_jpeg();
    let buf = build_file(&[(0x0123_4567_89ab_cdef, utf16le("thumb"), data.clone())]);

    let arts = run("thumbcache_1600.db", buf);
    assert_eq!(arts.len(), 1);

    let a = &arts[0];
    assert_eq!(a.artifact_type, ArtifactType::ParsedRecord);
    assert!(a.parent_id.is_some());

    let m = &a.metadata;
    assert_eq!(m["type"], "ThumbcacheEntry");
    assert_eq!(m["subtype"], "thumbcache");
    assert_eq!(m["entry_hash"], "0123456789abcdef");
    assert_eq!(m["image_format"], "jpeg");
    assert_eq!(m["data_size"].as_u64(), Some(data.len() as u64));
    assert_eq!(m["identifier"], "thumb");
    assert_eq!(m["name"], "thumbcache 0123456789abcdef");
}

#[test]
fn parses_multiple_formats_in_order() {
    let jpeg = tiny_jpeg();
    let png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
    let bmp = vec![0x42, 0x4D, 0x10, 0x00, 0x00, 0x00];
    let junk = vec![0x00, 0x11, 0x22, 0x33];

    let buf = build_file(&[
        (0x1, utf16le("a"), jpeg),
        (0x2, Vec::new(), png), // empty identifier
        (0xdead_beef, utf16le("b"), bmp),
        (0xff, utf16le("c"), junk),
    ]);

    let arts = run("thumbcache_256.db", buf);
    assert_eq!(arts.len(), 4);
    assert_eq!(arts[0].metadata["image_format"], "jpeg");
    assert_eq!(arts[1].metadata["image_format"], "png");
    // Empty identifier is omitted from the record.
    assert!(arts[1].metadata.get("identifier").is_none());
    assert_eq!(arts[2].metadata["image_format"], "bmp");
    assert_eq!(arts[2].metadata["entry_hash"], "00000000deadbeef");
    assert_eq!(arts[3].metadata["image_format"], "unknown");
}

#[test]
fn ignores_non_thumbcache() {
    // Right size but wrong magic (all zeros).
    assert!(run("thumbcache_1600.db", vec![0u8; 100]).is_empty());
    // Different magic entirely.
    assert!(run(
        "random.bin",
        b"NOTC and some trailing bytes here...".to_vec()
    )
    .is_empty());
    // Empty file.
    assert!(run("empty.db", Vec::new()).is_empty());
}

#[test]
fn truncated_entry_does_not_panic() {
    let full = build_file(&[(0xabc, utf16le("x"), tiny_jpeg())]);
    // Every prefix must parse without panicking and never over-produce. A
    // prefix may additionally carry one parse-status record saying the cache
    // did not end cleanly, so count entry records only.
    for cut in 0..=full.len() {
        let arts = run("thumbcache_1600.db", full[..cut].to_vec());
        let entries = arts
            .iter()
            .filter(|a| a.metadata["type"] == "ThumbcacheEntry")
            .count();
        assert!(entries <= 1, "cut {cut} produced {entries} entries");
    }
    // The complete buffer still yields exactly one entry.
    assert_eq!(run("thumbcache_1600.db", full).len(), 1);
}

/// Read the incompleteness reason off the status record, if one was emitted.
fn stop_reason(arts: &[Artifact]) -> Option<String> {
    let status = arts
        .iter()
        .find(|a| a.metadata["type"] == "ThumbcacheParseStatus")?;
    assert_eq!(
        status.metadata["content_incomplete"], true,
        "the status record must carry the standard incompleteness flag"
    );
    assert_eq!(
        status.metadata["inventory_incomplete"], true,
        "a short entry listing must also be flagged as an incomplete inventory"
    );
    Some(
        status.metadata["content_incomplete_reason"]
            .as_str()
            .expect("reason must be a string")
            .to_string(),
    )
}

#[test]
fn a_corrupt_entry_signature_mid_cache_is_reported_not_swallowed() {
    // Two good entries, then eight bytes of non-CMMM data standing where the
    // third entry's header belongs, then a third entry the walk cannot reach.
    let head = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    let tail = build_file(&[(0x3333, utf16le("c"), tiny_jpeg())]);
    let mut buf = head;
    let stop_offset = buf.len() as u64;
    buf.extend_from_slice(b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    // Entry bytes only (skip the 24-byte file header of the second build).
    buf.extend_from_slice(&tail[24..]);

    let arts = run("thumbcache_1600.db", buf);
    assert_eq!(
        arts.iter()
            .filter(|a| a.metadata["type"] == "ThumbcacheEntry")
            .count(),
        2,
        "the two intact entries are still recovered"
    );
    assert_eq!(
        stop_reason(&arts).as_deref(),
        Some("entry_signature_mismatch"),
        "a mid-cache signature break must be stated, not read as end-of-cache"
    );
    let status = arts
        .iter()
        .find(|a| a.metadata["type"] == "ThumbcacheParseStatus")
        .unwrap();
    assert_eq!(status.metadata["stopped_at_offset"], stop_offset);
}

#[test]
fn an_entry_declaring_an_impossible_size_is_reported_not_swallowed() {
    let mut buf = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    // Corrupt the SECOND entry's cache_entry_size to a value smaller than the
    // entry header, which makes the stride to any following entry unknowable.
    let first_len = 28 + utf16le("a").len() + tiny_jpeg().len();
    let second = 24 + first_len;
    buf[second + 4..second + 8].copy_from_slice(&4u32.to_le_bytes());

    let arts = run("thumbcache_1600.db", buf);
    assert_eq!(
        arts.iter()
            .filter(|a| a.metadata["type"] == "ThumbcacheEntry")
            .count(),
        1
    );
    assert_eq!(
        stop_reason(&arts).as_deref(),
        Some("invalid_entry_size"),
        "an unusable entry size must be reported: the rest of the cache is unreachable"
    );
}

#[test]
fn an_entry_whose_size_fields_contradict_each_other_is_counted_as_skipped() {
    let mut buf = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    // Inflate the FIRST entry's data_size (offset 24 within the entry) so the
    // variable regions no longer fit inside the entry. The stride is still
    // known, so the walk carries on to the second entry.
    buf[24 + 24..24 + 28].copy_from_slice(&0xFFFFu32.to_le_bytes());

    let arts = run("thumbcache_1600.db", buf);
    assert_eq!(
        arts.iter()
            .filter(|a| a.metadata["type"] == "ThumbcacheEntry")
            .count(),
        1,
        "the walk continues past an unusable entry"
    );
    let status = arts
        .iter()
        .find(|a| a.metadata["type"] == "ThumbcacheParseStatus")
        .expect("a dropped entry must be declared, not silently omitted");
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "inconsistent_entry_fields"
    );
    assert_eq!(status.metadata["entries_skipped"], 1);
}

#[test]
fn trailing_zero_fill_is_free_space_not_an_incomplete_parse() {
    // A thumbcache grown in place ends in zero fill. That is normal free
    // space, and claiming incompleteness for it would cry wolf on every cache.
    let mut buf = build_file(&[(0x1111, utf16le("a"), tiny_jpeg())]);
    buf.extend_from_slice(&[0u8; 512]);

    let arts = run("thumbcache_1600.db", buf);
    assert_eq!(arts.len(), 1);
    assert!(
        arts.iter().all(|a| a.metadata["type"] == "ThumbcacheEntry"),
        "zero fill after the last entry must not be reported as a short walk"
    );
}

#[test]
fn module_metadata_stable() {
    assert_eq!(ThumbcacheParser.id(), "plugin.windows.thumbcache");
    assert_eq!(
        ThumbcacheParser.subscribes_to(),
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            ArtifactType::ParsedRecord
        ]
    );
}

/// Real Thumbcache samples, gated on SEANCE_THUMBCACHE_SAMPLES=/dir/with/*.db.
#[test]
fn real_samples() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_THUMBCACHE_SAMPLES") else {
        return;
    };
    let read_dir = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("SEANCE_THUMBCACHE_SAMPLES is set to {dir:?} but cannot be listed: {e}")
    });
    for entry in read_dir.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if !name.starts_with("thumbcache_") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            // Must not panic; entries (if any) all carry the expected type. A
            // cache that did not parse to its end also carries one status
            // record saying so.
            let arts = run(&name, bytes);
            for a in &arts {
                let kind = a.metadata["type"].as_str().unwrap_or_default();
                assert!(
                    kind == "ThumbcacheEntry" || kind == "ThumbcacheParseStatus",
                    "unexpected record type {kind}"
                );
            }
        }
    }
}

#[test]
fn a_cache_that_ends_mid_entry_says_so_instead_of_looking_complete() {
    let full = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    // Cut the second entry in half: its thumbnail is unreachable.
    let cut = full.len() - 6;
    let arts = run("thumbcache_1600.db", full[..cut].to_vec());

    let status = arts
        .iter()
        .find(|a| a.metadata["type"] == "ThumbcacheParseStatus")
        .expect("a torn cache must emit a parse-status record");
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "truncated_final_entry"
    );
    assert_eq!(
        arts.iter()
            .filter(|a| a.metadata["type"] == "ThumbcacheEntry")
            .count(),
        1,
        "the intact first entry is still recovered"
    );
}

#[test]
fn a_cache_parsed_to_its_end_carries_no_incomplete_marker() {
    let full = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    let arts = run("thumbcache_1600.db", full);
    assert_eq!(arts.len(), 2);
    assert!(
        arts.iter().all(|a| a.metadata["type"] == "ThumbcacheEntry"),
        "a complete parse must not claim to be incomplete"
    );
}

use seance_core::test_support::TruncatedSource;

fn run_short(bytes: Vec<u8>, declared: u64) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "thumbcache_256.db" }),
    );
    ThumbcacheParser.process(&art).unwrap()
}

/// HUNT-197, red before the fix: a source that stopped answering at an entry
/// boundary was stamped `file_read_capped` — "this build chose not to read the
/// rest" — when the rest could not be read. A 30 KiB file is nowhere near the
/// 1 GiB cap.
#[test]
fn a_source_that_answers_short_is_a_short_read_not_a_cap() {
    let full = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    let arts = run_short(full.clone(), full.len() as u64 + 30 * 1024);
    assert_eq!(stop_reason(&arts).as_deref(), Some("short_read"));
}

/// HUNT-197: when the short read tears an entry, the torn entry is a
/// consequence of the read, not a fact about the file; the reason is still
/// the short read.
#[test]
fn a_short_read_that_tears_an_entry_is_still_a_short_read() {
    let full = build_file(&[
        (0x1111, utf16le("a"), tiny_jpeg()),
        (0x2222, utf16le("b"), tiny_jpeg()),
    ]);
    let arts = run_short(full[..full.len() - 6].to_vec(), full.len() as u64);
    assert_eq!(stop_reason(&arts).as_deref(), Some("short_read"));
    assert_eq!(
        arts.iter()
            .filter(|a| a.metadata["type"] == "ThumbcacheEntry")
            .count(),
        1
    );
}

/// HUNT-197: the cap reason is kept for exactly the case it names — the file
/// is over the cap and every byte up to the cap arrived.
#[test]
fn load_shortfall_names_the_cap_only_when_the_cap_cut_the_read() {
    assert_eq!(load_shortfall(100, 100), None);
    assert_eq!(load_shortfall(100, 60), Some("short_read"));
    assert_eq!(
        load_shortfall(MAX_FILE_BYTES + 1, MAX_FILE_BYTES),
        Some("file_read_capped")
    );
    assert_eq!(
        load_shortfall(MAX_FILE_BYTES + 1, MAX_FILE_BYTES - 1),
        Some("short_read")
    );
}

/// HUNT-277. SYNTHETIC: the cache is built in-test by `build_file`; no real
/// evidence is graded. A `ParsedRecord` shaped like the engine's prior-version
/// record for a shadow copy of a thumbcache file.
fn prior_version(bytes: Vec<u8>) -> Artifact {
    let file_name = "thumbcache_1600.db";
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds),
        json!({
            "type": "VssPriorVersion",
            "name": format!("{file_name} [shadow copy 2015-03-23T00:00:00Z]"),
            "file_name": file_name,
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 1,
        }),
    )
}

#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let buf = build_file(&[(0x0123_4567_89ab_cdef, utf16le("thumb"), tiny_jpeg())]);

    let out = ThumbcacheParser
        .process(&prior_version(buf.clone()))
        .unwrap();
    assert_eq!(out.len(), 1, "the prior version yields its entry");
    let m = &out[0].metadata;
    assert_eq!(m["type"], "ThumbcacheEntry");
    assert_eq!(m["is_snapshot_version"], true);
    assert_eq!(m["vss_snapshot_id"], "snap-1");
    assert!(
        m.get("shadow_copy_sidecars_not_searched").is_some(),
        "{m:#?}"
    );

    // A ParsedRecord that is not a prior version is not this parser's.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf.clone()));
    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(ds),
        json!({ "type": "SomethingElse", "name": "thumbcache_1600.db" }),
    );
    assert!(ThumbcacheParser.process(&plain).unwrap().is_empty());

    // The same bytes as a live FileEntry are not stamped.
    let live = run("thumbcache_1600.db", buf);
    assert_eq!(live.len(), 1);
    assert!(live[0].metadata.get("is_snapshot_version").is_none());
    assert!(live[0]
        .metadata
        .get("shadow_copy_sidecars_not_searched")
        .is_none());
}
