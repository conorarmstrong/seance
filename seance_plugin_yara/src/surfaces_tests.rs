//! The surfaces beyond a plain file: alternate data streams, registry values
//! and unallocated space — and the entropy each scanned region carries.
//!
//! The shapes here are the ones the producing parsers publish (`is_ads` and
//! `stream_name` from the $MFT parser, `all_values` on the registry hive
//! record, `offset_bytes`/`size_bytes`/`offset_basis` on a free region), built
//! by hand so each test isolates one claim. The real-evidence tests over those
//! parsers' own output are in `surfaces_real_tests.rs`.

use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource, WindowSource};
use std::sync::Arc;
use tempfile::TempDir;

const RULES: &str = r#"
rule marker : test {
    strings:
        $a = "X5O!P%@AP-MARKER"
    condition:
        $a
}
rule wide_marker : test {
    strings:
        $w = "WIDE-MARKER" wide
    condition:
        $w
}
rule always {
    condition:
        true
}
"#;

fn scanner() -> (TempDir, YaraScanner) {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("r.yar"), RULES).expect("write rules");
    let scanner = YaraScanner::from_rule_path(dir.path()).expect("rules must load");
    (dir, scanner)
}

fn bytes_source(bytes: &[u8]) -> Arc<dyn DataSource> {
    Arc::new(ByteSliceDataSource::new(bytes.to_vec()))
}

fn records_of<'a>(out: &'a [Artifact], kind: &str) -> Vec<&'a Artifact> {
    out.iter().filter(|a| a.metadata["type"] == kind).collect()
}

fn matches_for<'a>(out: &'a [Artifact], rule: &str) -> Vec<&'a Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "YaraMatch" && a.metadata["rule"] == rule)
        .collect()
}

fn ads_entry(bytes: &[u8], extra: serde_json::Value) -> Artifact {
    let mut meta = json!({
        "name": "invoice.pdf:Zone.Identifier",
        "stream_name": "Zone.Identifier",
        "size": bytes.len(),
        "is_ads": true,
        "parent_file": "invoice.pdf",
        "record_number": 17630,
        "path": "/Users/x/Downloads/invoice.pdf:Zone.Identifier",
    });
    if let (Some(map), Some(more)) = (meta.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            map.insert(k.clone(), v.clone());
        }
    }
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(bytes)),
        meta,
    )
}

fn unallocated_region(volume: &[u8], offset: u64, size: u64) -> Artifact {
    let window: Arc<dyn DataSource> =
        Arc::new(WindowSource::new(bytes_source(volume), offset, size));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(window),
        json!({
            "offset_bytes": offset,
            "size_bytes": size,
            "filesystem": "NTFS",
            "offset_basis": "the NTFS volume this region was found in, not the evidence",
            "first_cluster": offset / 4096,
            "clusters": size / 4096,
            "cluster_size": 4096,
            "source": "allocation_bitmap",
        }),
    )
}

fn hive_record(values: Vec<serde_json::Value>, extra: serde_json::Value) -> Artifact {
    let mut meta = json!({
        "type": "RegistryHive",
        "hive_type": "NTUSER.DAT",
        "total_values": values.len(),
        "all_values": values,
        "key_inventory_complete": true,
    });
    if let (Some(map), Some(more)) = (meta.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            map.insert(k.clone(), v.clone());
        }
    }
    Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, meta)
}

fn value(key: &str, name: &str, ty: &str, rendering: &str, raw: usize) -> serde_json::Value {
    json!({
        "key_path": key,
        "value_name": name,
        "value_type": ty,
        "value_data": rendering,
        "raw_data_size": raw,
    })
}

/// The hex rendering the registry parser gives a binary value of 64 bytes or
/// fewer: two lowercase digits per byte, space-separated.
fn hex_rendering(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

// --- Every match names its surface ---------------------------------------------

/// A plain file's match says so, and the field is the same one every other
/// surface uses — a reader filtering on it sees every surface or none.
#[test]
fn a_plain_file_match_is_stamped_with_the_file_surface() {
    let (_dir, scanner) = scanner();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(b"X5O!P%@AP-MARKER")),
        json!({ "name": "sample.bin" }),
    );
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].metadata["surface"], "file");
}

/// An alternate data stream is a `FileEntry` with `is_ads: true`. A match in
/// it is a match in the stream, not in the file the stream hangs off, and the
/// record names the stream and its base file so the two cannot be conflated.
#[test]
fn an_ads_match_is_stamped_ads_and_names_the_stream_and_its_base_file() {
    let (_dir, scanner) = scanner();
    let art = ads_entry(b"[ZoneTransfer]\r\nX5O!P%@AP-MARKER", json!({}));
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "ads");
    assert_eq!(meta["stream_name"], "Zone.Identifier");
    assert_eq!(meta["base_file"], "invoice.pdf");
    assert_eq!(
        meta["path"],
        "/Users/x/Downloads/invoice.pdf:Zone.Identifier"
    );
    assert!(
        meta.get("entry_deleted").is_none(),
        "the source entry carried no deleted flag, so the match must not invent one"
    );
}

/// A stream whose base record is not in use is a recovered stream. The flag
/// the $MFT parser put on the entry travels onto the hit, so a match in a
/// deleted stream is never read as a match in a live one.
#[test]
fn a_match_in_a_deleted_ads_carries_the_entry_deleted_flag() {
    let (_dir, scanner) = scanner();
    let art = ads_entry(
        b"X5O!P%@AP-MARKER",
        json!({ "deleted": true, "deleted_recovery_source": "mft" }),
    );
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].metadata["entry_deleted"], json!(true));
    assert_eq!(m[0].metadata["surface"], "ads");
}

/// A hit in free space is not a hit in any file. The surface says so, and the
/// hit carries where in the parent's coordinate space it was found — with the
/// basis those offsets are relative to, because a volume-relative figure
/// presented as evidence-absolute is the wrong place on the disk.
#[test]
fn an_unallocated_match_is_stamped_unallocated_and_carries_its_offset_and_basis() {
    let (_dir, scanner) = scanner();
    let mut volume = vec![0u8; 16384];
    volume[8192 + 100..8192 + 116].copy_from_slice(b"X5O!P%@AP-MARKER");
    let region = unallocated_region(&volume, 8192, 8192);
    let out = scanner.process(&region).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "unallocated");
    assert_eq!(meta["offset_bytes"], json!(8192u64));
    assert_eq!(meta["size_bytes"], json!(8192u64));
    assert_eq!(
        meta["offset_basis"],
        "the NTFS volume this region was found in, not the evidence"
    );
    assert_eq!(meta["filesystem"], "NTFS");
    assert_eq!(meta["region_source"], "allocation_bitmap");
    let hits = meta["pattern_matches"].as_array().expect("pattern matches");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["pattern"], "$a");
    assert_eq!(hits[0]["offset_in_region"], json!(100u64));
    assert_eq!(hits[0]["length"], json!(16u64));
    assert_eq!(
        hits[0]["offset_in_parent"],
        json!(8192u64 + 100),
        "region offset plus offset in region, in the parent's coordinate space"
    );
    assert_eq!(meta["pattern_match_count"], json!(1));
    assert_eq!(meta["matched_without_pattern"], json!(false));
}

/// A region the partition parser emitted carries no `offset_basis` and no
/// `filesystem`; the hit must not invent either.
#[test]
fn a_partition_gap_match_carries_only_what_the_region_states() {
    let (_dir, scanner) = scanner();
    let gap = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(bytes_source(b"X5O!P%@AP-MARKER")),
        json!({
            "partition_scheme": "MBR",
            "gap_index": 0,
            "offset_bytes": 512,
            "size_bytes": 16,
            "sector_size": 512,
        }),
    );
    let out = scanner.process(&gap).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1);
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "unallocated");
    assert_eq!(meta["region_source"], "partition_gap");
    assert!(meta.get("offset_basis").is_none(), "{meta}");
    assert!(meta.get("filesystem").is_none(), "{meta}");
    assert_eq!(
        meta["pattern_matches"][0]["offset_in_parent"],
        json!(512u64)
    );
}

/// A rule true without any of its strings being found (`condition: true`, a
/// filesize test) has no offset to carry, and the record says so rather than
/// carrying an empty list that reads like "matched at nowhere".
#[test]
fn a_rule_that_fires_without_a_pattern_says_so() {
    let (_dir, scanner) = scanner();
    let art = ads_entry(b"nothing of note", json!({}));
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "always");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].metadata["matched_without_pattern"], json!(true));
    assert_eq!(m[0].metadata["pattern_match_count"], json!(0));
}

// --- Entropy -----------------------------------------------------------------------

#[test]
fn entropy_is_zero_over_one_byte_value_and_eight_over_all_of_them() {
    assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
    let all: Vec<u8> = (0..=255u8).collect();
    assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    let two: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
    assert!((shannon_entropy(&two) - 1.0).abs() < 1e-9);
    assert_eq!(shannon_entropy(&[]), 0.0, "no bytes, no information");
}

/// Every hit on the new surfaces carries the entropy of the region it was
/// found in, beside the byte count it was computed over — an entropy figure
/// without its population is a number with no meaning.
#[test]
fn a_match_carries_the_entropy_of_the_scanned_region_and_its_byte_count() {
    let (_dir, scanner) = scanner();
    let mut bytes = vec![0u8; 1000];
    bytes[..16].copy_from_slice(b"X5O!P%@AP-MARKER");
    let art = ads_entry(&bytes, json!({}));
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1);
    let meta = &m[0].metadata;
    let e = meta["entropy_bits_per_byte"].as_f64().expect("entropy");
    let expected = shannon_entropy(&bytes);
    assert!((e - expected).abs() < 1e-3, "{e} vs {expected}");
    assert_eq!(meta["entropy_bytes"], json!(1000u64));
    assert_eq!(meta["bytes_scanned"], json!(1000u64));
}

/// A stream or region scanned end to end that matched nothing still says it
/// was scanned, and carries its entropy: a high-entropy free region is a
/// lead in itself, and "no match" is only meaningful next to "was looked at".
#[test]
fn a_scanned_ads_or_region_with_no_match_yields_a_region_record_with_entropy() {
    let (_dir, scanner) = scanner();
    let bytes: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 256) as u8).collect();
    let out = scanner.process(&ads_entry(&bytes, json!({}))).unwrap();
    // `always` fires on everything; the region record is separate from it.
    let region = records_of(&out, "YaraRegionScanned");
    assert_eq!(region.len(), 1, "{out:?}");
    let meta = &region[0].metadata;
    assert_eq!(meta["surface"], "ads");
    assert_eq!(meta["stream_name"], "Zone.Identifier");
    assert_eq!(meta["bytes_scanned"], json!(4096u64));
    assert_eq!(meta["declared_size"], json!(4096u64));
    assert_eq!(meta["scan_complete"], json!(true));
    assert_eq!(meta["entropy_bytes"], json!(4096u64));
    assert!(
        (meta["entropy_bits_per_byte"].as_f64().unwrap() - shannon_entropy(&bytes)).abs() < 1e-3
    );
    assert_eq!(meta["matches"], json!(1), "the `always` rule fired once");

    let mut volume = vec![0u8; 8192];
    for (i, b) in volume.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let out = scanner
        .process(&unallocated_region(&volume, 4096, 4096))
        .unwrap();
    let region = records_of(&out, "YaraRegionScanned");
    assert_eq!(region.len(), 1, "{out:?}");
    let meta = &region[0].metadata;
    assert_eq!(meta["surface"], "unallocated");
    assert_eq!(meta["offset_bytes"], json!(4096u64));
    assert_eq!(meta["entropy_bytes"], json!(4096u64));
    assert_eq!(meta["region_source"], "allocation_bitmap");
}

/// A plain file keeps its existing contract: a full scan that matched nothing
/// produces nothing. The region record is a property of the surfaces this
/// item adds, not a change to the one it did not.
#[test]
fn a_plain_file_still_yields_nothing_when_fully_scanned_and_unmatched() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("r.yar"),
        "rule m { strings: $a = \"MARK\" condition: $a }",
    )
    .unwrap();
    let scanner = YaraScanner::from_rule_path(dir.path()).unwrap();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(b"quiet")),
        json!({ "name": "quiet.txt" }),
    );
    assert!(scanner.process(&art).unwrap().is_empty());
}

/// When only a prefix of a region could be read, the region record's entropy
/// is over the prefix and says so, and the partial-scan record is still there.
#[test]
fn a_short_read_region_states_entropy_over_the_bytes_it_had() {
    let (_dir, scanner) = scanner();
    let full = vec![0xA5u8; 4096];
    let window: Arc<dyn DataSource> = Arc::new(WindowSource::new(bytes_source(&full), 0, 8192));
    let region = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(window),
        json!({ "offset_bytes": 0, "size_bytes": 8192, "partition_scheme": "GPT" }),
    );
    let out = scanner.process(&region).unwrap();
    assert_eq!(records_of(&out, "YaraPartialScan").len(), 1, "{out:?}");
    let region = records_of(&out, "YaraRegionScanned");
    assert_eq!(region.len(), 1);
    assert_eq!(region[0].metadata["scan_complete"], json!(false));
    assert_eq!(region[0].metadata["bytes_scanned"], json!(4096u64));
    assert_eq!(region[0].metadata["declared_size"], json!(8192u64));
    assert_eq!(region[0].metadata["entropy_bytes"], json!(4096u64));
    assert_eq!(region[0].metadata["content_incomplete"], json!(true));
}

// --- Registry values ----------------------------------------------------------------

/// The registry parser publishes the bytes of a binary value over 64 bytes as
/// base64. Those are the value's exact bytes, and a hit in them is stamped
/// with the key and value it was found in.
#[test]
fn a_hit_in_a_base64_published_binary_value_is_exact_and_names_the_value() {
    use base64::Engine as _;
    let (_dir, scanner) = scanner();
    let mut payload = vec![0x11u8; 100];
    payload[40..56].copy_from_slice(b"X5O!P%@AP-MARKER");
    let mut v = value(
        "ROOT\\Software\\Vendor",
        "Blob",
        "RegBinary",
        "100 bytes (binary data)",
        100,
    );
    v["value_data_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(&payload));
    let out = scanner.process(&hive_record(vec![v], json!({}))).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "registry_value");
    assert_eq!(meta["hive_type"], "NTUSER.DAT");
    assert_eq!(meta["key_path"], "ROOT\\Software\\Vendor");
    assert_eq!(meta["value_name"], "Blob");
    assert_eq!(meta["value_type"], "RegBinary");
    assert_eq!(meta["value_bytes_basis"], "exact");
    assert_eq!(meta["raw_data_size"], json!(100));
    assert_eq!(meta["bytes_scanned"], json!(100u64));
    assert_eq!(meta["pattern_matches"][0]["offset_in_region"], json!(40u64));
    assert_eq!(meta["entropy_bytes"], json!(100u64));
    assert!(
        (meta["entropy_bits_per_byte"].as_f64().unwrap() - shannon_entropy(&payload)).abs() < 1e-3
    );
}

/// A record from a build before `HUNT-159` publishes a binary value of 64
/// bytes or fewer as a hex rendering alone. That rendering is lossless, so the
/// bytes are rebuilt from it — and labelled as rebuilt (`HUNT-207`).
#[test]
fn a_hit_in_a_hex_rendered_binary_value_is_rebuilt_from_the_rendering() {
    let (_dir, scanner) = scanner();
    let payload = b"\x00\x01X5O!P%@AP-MARKER\xff".to_vec();
    let v = value(
        "ROOT\\Software\\Vendor",
        "Small",
        "RegBinary",
        &hex_rendering(&payload),
        payload.len(),
    );
    let out = scanner.process(&hive_record(vec![v], json!({}))).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    assert_eq!(m[0].metadata["value_bytes_basis"], "rebuilt_from_rendering");
    assert_eq!(m[0].metadata["bytes_scanned"], json!(payload.len() as u64));
    assert_eq!(
        m[0].metadata["pattern_matches"][0]["offset_in_region"],
        json!(2u64)
    );
}

/// A string value is published as its decoded text, not its bytes. Scanning
/// it means re-encoding that text as UTF-16LE, which reproduces the stored
/// bytes only for a well-formed string with one terminator — so the hit says
/// its bytes are re-encoded, and carries the stored size beside the scanned
/// one for the reader to compare.
#[test]
fn a_hit_in_a_string_value_is_labelled_reencoded_and_shows_both_sizes() {
    let (_dir, scanner) = scanner();
    let text = "powershell -e WIDE-MARKER";
    let stored = utf16le(text).len() + 2;
    let v = value(
        "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Updater",
        "RegSZ",
        text,
        stored,
    );
    let out = scanner.process(&hive_record(vec![v], json!({}))).unwrap();
    let m = matches_for(&out, "wide_marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["value_bytes_basis"], "reencoded_utf16le");
    assert_eq!(meta["raw_data_size"], json!(stored));
    assert_eq!(meta["bytes_scanned"], json!(utf16le(text).len() as u64));
    assert!(
        meta["value_bytes_basis_means"]
            .as_str()
            .unwrap()
            .contains("re-encod"),
        "{meta}"
    );
    // The narrow rule cannot fire on UTF-16 text, and must not be made to.
    assert!(matches_for(&out, "marker").is_empty());
}

/// `HUNT-207`: a `REG_DWORD_BIG_ENDIAN` with no stored bytes on its record is
/// not rebuilt as though it were little-endian. The type name `RegDWord` is a
/// prefix of `RegDWordBigEndian`; a substring match rebuilt the bytes
/// byte-swapped and labelled them `exact`. Which byte order the rendering was
/// decoded in depends on the build that wrote the record (`HUNT-158`), so the
/// value is not scanned and is counted by that reason.
#[test]
fn a_big_endian_dword_without_stored_bytes_is_not_rebuilt_byte_swapped() {
    use base64::Engine as _;
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("r.yar"),
        "rule swapped { strings: $a = { 78 56 34 12 } condition: $a }\n\
         rule stored { strings: $a = { 12 34 56 78 } condition: $a }",
    )
    .unwrap();
    let scanner = YaraScanner::from_rule_path(dir.path()).unwrap();
    // Stored bytes 12 34 56 78, rendered as the big-endian number they are.
    let bare = value(
        "ROOT\\K",
        "Bare",
        "RegDWordBigEndian",
        "0x12345678 (305419896)",
        4,
    );
    let mut with_bytes = value(
        "ROOT\\K",
        "WithBytes",
        "RegDWordBigEndian",
        "0x12345678 (305419896)",
        4,
    );
    with_bytes["value_data_b64"] =
        json!(base64::engine::general_purpose::STANDARD.encode([0x12, 0x34, 0x56, 0x78]));
    let out = scanner
        .process(&hive_record(vec![bare, with_bytes], json!({})))
        .unwrap();
    assert!(
        matches_for(&out, "swapped").is_empty(),
        "no value's bytes were 78 56 34 12: {out:?}"
    );
    let stored = matches_for(&out, "stored");
    assert_eq!(stored.len(), 1, "{out:?}");
    assert_eq!(stored[0].metadata["value_name"], "WithBytes");
    assert_eq!(stored[0].metadata["value_bytes_basis"], "exact");
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["values_not_scanned"], json!(1), "{c}");
    assert_eq!(
        c["not_scanned_reasons"]["big_endian_dword_rendering_order_unknown"],
        json!(1),
        "{c}"
    );
}

/// `HUNT-207`: bytes rebuilt from a rendering are labelled as rebuilt, and
/// only the stored bytes (`value_data_b64`) are `exact`. A DWORD's `0x…`
/// rendering is lossless at its own width, but the bytes scanned are the
/// scanner's reconstruction, not bytes the parser published.
#[test]
fn bytes_rebuilt_from_a_rendering_are_labelled_rebuilt_not_exact() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("r.yar"),
        "rule dw { strings: $a = { 78 56 34 12 } condition: $a }",
    )
    .unwrap();
    let scanner = YaraScanner::from_rule_path(dir.path()).unwrap();
    let v = value("ROOT\\K", "D", "RegDWord", "0x12345678 (305419896)", 4);
    let out = scanner.process(&hive_record(vec![v], json!({}))).unwrap();
    let m = matches_for(&out, "dw");
    assert_eq!(m.len(), 1, "{out:?}");
    assert_eq!(m[0].metadata["value_bytes_basis"], "rebuilt_from_rendering");
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["values_scanned_exact"], json!(0), "{c}");
    assert_eq!(c["values_scanned_rebuilt"], json!(1), "{c}");
}

/// `HUNT-217`: a `REG_MULTI_SZ` held back by the registry's per-hive byte cap
/// carries no stored bytes, but since `HUNT-208` it carries its elements as the
/// array `value_data_list`. Its `" | "`-joined rendering is lossy (the second
/// element below holds that separator); the array is not. The elements are
/// re-encoded as the list the registry stores — each UTF-16LE string with its
/// terminator, then the list terminator — scanned, and labelled as re-encoded
/// from the element list rather than refused.
#[test]
fn a_capped_multi_string_is_scanned_from_its_element_list_and_labelled() {
    let (_dir, scanner) = scanner();
    let elements = ["autocheck autochk *", "C:\\Temp\\x.exe WIDE-MARKER | b"];
    let mut stored: Vec<u8> = Vec::new();
    for e in elements {
        stored.extend(utf16le(e));
        stored.extend([0, 0]);
    }
    stored.extend([0, 0]);
    let mut capped = value(
        "ROOT\\ControlSet001\\Control\\Session Manager",
        "BootExecute",
        "RegMultiSZ",
        &elements.join(" | "),
        stored.len(),
    );
    capped["value_data_b64_omitted"] =
        json!("the hive's per-hive cap on published value bytes was reached");
    capped["value_data_list"] = json!(elements);
    // A record from a build before HUNT-208 carries no list and is still refused.
    let old = value("ROOT\\A", "m", "RegMultiSZ", "a | b", 10);
    let out = scanner
        .process(&hive_record(vec![capped, old], json!({})))
        .unwrap();
    let m = matches_for(&out, "wide_marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["value_bytes_basis"], "reencoded_utf16le_elements");
    assert_eq!(meta["bytes_scanned"], json!(stored.len() as u64));
    assert_eq!(meta["raw_data_size"], json!(stored.len()));
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["values_scanned"], json!(1), "{c}");
    assert_eq!(c["values_scanned_reencoded"], json!(1), "{c}");
    assert_eq!(
        c["not_scanned_reasons"]["multi_sz_rendering_is_lossy"],
        json!(1)
    );
}

/// A DWORD or QWORD rendered as `0x… (n)` reproduces its four or eight bytes
/// exactly, but only when the stored size is that; a longer value was cut to
/// the rendering and cannot be rebuilt from it.
#[test]
fn a_dword_reproduces_its_bytes_only_at_its_own_size() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("r.yar"),
        "rule dw { strings: $a = { 78 56 34 12 } condition: $a }",
    )
    .unwrap();
    let scanner = YaraScanner::from_rule_path(dir.path()).unwrap();
    let good = value("ROOT\\K", "Good", "RegDWord", "0x12345678 (305419896)", 4);
    let odd = value("ROOT\\K", "Odd", "RegDWord", "0x12345678 (305419896)", 6);
    let out = scanner
        .process(&hive_record(vec![good, odd], json!({})))
        .unwrap();
    let m = matches_for(&out, "dw");
    assert_eq!(m.len(), 1, "{out:?}");
    assert_eq!(m[0].metadata["value_name"], "Good");
    assert_eq!(m[0].metadata["value_bytes_basis"], "rebuilt_from_rendering");
    let cov = records_of(&out, "YaraRegistryCoverage");
    assert_eq!(cov.len(), 1);
    assert_eq!(cov[0].metadata["values_not_scanned"], json!(1));
    assert_eq!(
        cov[0].metadata["not_scanned_reasons"]["rendering_does_not_reproduce_bytes"],
        json!(1)
    );
}

/// What was and was not scanned, per hive, with the reason for each value that
/// was not. A hive of five thousand values that yielded no match is only
/// "clean" if every value was looked at, and this record is where that is read.
#[test]
fn the_coverage_record_counts_every_value_and_names_why_each_unscanned_one_was_not() {
    let (_dir, scanner) = scanner();
    let values = vec![
        value("ROOT\\A", "s", "RegSZ", "plain text", 22),
        value("ROOT\\A", "e", "RegExpandSZ", "%SystemRoot%\\x", 30),
        value("ROOT\\A", "empty", "RegSZ", "(empty string)", 0),
        value("ROOT\\A", "onebyte", "RegSZ", "(empty string)", 1),
        value("ROOT\\A", "m", "RegMultiSZ", "a | b | c", 16),
        value("ROOT\\A", "bin", "RegBinary", "de ad be ef", 4),
        value("ROOT\\A", "nothing", "RegBinary", "", 0),
        value("ROOT\\A", "d", "RegDWord", "0x00000001 (1)", 4),
        value("ROOT\\A", "q", "RegQWord", "0x0000000000000002 (2)", 8),
        value("ROOT\\A", "baddw", "RegDWord", "(invalid DWORD)", 2),
        value(
            "ROOT\\A",
            "unreadable",
            "RegBinary",
            "(error reading value: cell out of bounds)",
            0,
        ),
        value("ROOT\\A", "none", "RegNone", "00 01", 2),
        value("ROOT\\A", "unknown", "Unknown(99)", "aa bb cc", 3),
    ];
    let total = values.len();
    let out = scanner.process(&hive_record(values, json!({}))).unwrap();
    let cov = records_of(&out, "YaraRegistryCoverage");
    assert_eq!(cov.len(), 1, "{out:?}");
    let c = &cov[0].metadata;
    assert_eq!(c["surface"], "registry_value");
    assert_eq!(c["hive_type"], "NTUSER.DAT");
    assert_eq!(c["values_total"], json!(total));
    // Scanned: s, e (re-encoded); empty, bin, nothing, d, q, none, unknown
    // (rebuilt from their renderings — none of these records carries bytes).
    assert_eq!(c["values_scanned"], json!(9), "{c}");
    assert_eq!(c["values_scanned_exact"], json!(0));
    assert_eq!(c["values_scanned_rebuilt"], json!(7));
    assert_eq!(c["values_scanned_reencoded"], json!(2));
    // Not scanned: onebyte, m, baddw, unreadable.
    assert_eq!(c["values_not_scanned"], json!(4));
    let reasons = &c["not_scanned_reasons"];
    assert_eq!(reasons["multi_sz_rendering_is_lossy"], json!(1));
    assert_eq!(reasons["parser_could_not_read_value"], json!(1));
    assert_eq!(reasons["rendering_does_not_reproduce_bytes"], json!(2));
    assert_eq!(c["content_incomplete"], json!(true));
    assert_eq!(
        c["content_incomplete_reason"],
        IncompleteReason::UnresolvedStructure.as_str()
    );
    assert_eq!(
        c["bytes_scanned"],
        // s and e re-encoded without their terminators (20 + 28), then the
        // rebuilt ones: empty 0, bin 4, nothing 0, d 4, q 8, none 2, unknown 3.
        json!(20 + 28 + 4 + 4 + 8 + 2 + 3)
    );
    assert_eq!(c["values_engine_error"], json!(0));
    assert_eq!(c["rules_in_set"], json!(3));
    // `always` fired on every scanned value, including the empty ones.
    assert_eq!(c["matches"], json!(9));
    assert_eq!(matches_for(&out, "always").len(), 9);
    for m in matches_for(&out, "always") {
        assert_eq!(m.metadata["surface"], "registry_value");
        assert_eq!(m.metadata["hive_type"], "NTUSER.DAT");
    }
}

/// A hive whose every value was reproduced and scanned is complete, and the
/// coverage record does not carry an incompleteness it does not have.
#[test]
fn a_fully_scanned_hive_has_a_complete_coverage_record() {
    let (_dir, scanner) = scanner();
    let values = vec![
        value("ROOT\\A", "bin", "RegBinary", "de ad", 2),
        value("ROOT\\A", "d", "RegDWord", "0x00000001 (1)", 4),
    ];
    let out = scanner.process(&hive_record(values, json!({}))).unwrap();
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["values_not_scanned"], json!(0));
    assert!(c.get("content_incomplete").is_none(), "{c}");
    assert_eq!(c["hive_key_inventory_complete"], json!(true));
}

/// The hive record's own incompleteness — a capped walk, a short file — is
/// carried onto every record this scan emits for it, so a match set over
/// half a hive is never read as the whole hive's.
#[test]
fn a_hive_that_is_itself_incomplete_stamps_that_on_every_record() {
    let (_dir, scanner) = scanner();
    let values = vec![value("ROOT\\A", "bin", "RegBinary", "de ad", 2)];
    let out = scanner
        .process(&hive_record(
            values,
            json!({
                "key_inventory_complete": false,
                "content_incomplete": true,
                "content_incomplete_reason": "cap_reached",
            }),
        ))
        .unwrap();
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["hive_key_inventory_complete"], json!(false));
    assert_eq!(c["hive_content_incomplete"], json!(true));
    assert_eq!(c["hive_content_incomplete_reason"], "cap_reached");
    let m = matches_for(&out, "always");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].metadata["hive_content_incomplete"], json!(true));
    assert_eq!(m[0].metadata["hive_key_inventory_complete"], json!(false));
}

/// A hive record with no value inventory was not scanned, and says so.
#[test]
fn a_hive_record_without_a_value_inventory_is_reported_as_not_scanned() {
    let (_dir, scanner) = scanner();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({ "type": "RegistryHive", "hive_type": "SAM" }),
    );
    let out = scanner.process(&art).unwrap();
    let rec = records_of(&out, "YaraNotScanned");
    assert_eq!(rec.len(), 1, "{out:?}");
    assert_eq!(rec[0].metadata["surface"], "registry_value");
    assert_eq!(
        rec[0].metadata["content_incomplete_reason"],
        IncompleteReason::UnresolvedStructure.as_str()
    );
    assert!(matches_for(&out, "always").is_empty());
}

/// The byte budget over one hive's values is a ceiling, and a ceiling is
/// reported with the count it stopped at — not by the values past it going
/// quietly unscanned.
#[test]
fn the_registry_byte_budget_is_reported_with_the_values_it_left_unscanned() {
    let (_dir, scanner) = scanner();
    let values: Vec<serde_json::Value> = (0..10)
        .map(|i| {
            value(
                "ROOT\\A",
                &format!("v{i}"),
                "RegBinary",
                "de ad be ef 00 01 02 03",
                8,
            )
        })
        .collect();
    let hive = hive_record(values, json!({}));
    let all_values = hive.metadata["all_values"].as_array().unwrap();
    // 8 bytes each; a budget of 20 admits two whole values and not a third.
    let out = scanner.scan_hive_values(&hive, all_values, 20);
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["values_scanned"], json!(2), "{c}");
    assert_eq!(c["values_not_scanned"], json!(8));
    assert_eq!(c["not_scanned_reasons"]["byte_budget_reached"], json!(8));
    assert_eq!(c["byte_budget"], json!(20u64));
    assert_eq!(c["byte_budget_reached"], json!(true));
    assert_eq!(c["bytes_scanned"], json!(16u64));
    assert_eq!(c["content_incomplete"], json!(true));
    assert_eq!(
        c["content_incomplete_reason"],
        IncompleteReason::CapReached.as_str()
    );
    assert_eq!(matches_for(&out, "always").len(), 2);
}

/// The values a `process` call admits are budgeted at the same ceiling a
/// single file gets, and the record states it.
#[test]
fn process_budgets_a_hive_at_the_scan_cap() {
    let (_dir, scanner) = scanner();
    let values = vec![value("ROOT\\A", "bin", "RegBinary", "de ad", 2)];
    let out = scanner.process(&hive_record(values, json!({}))).unwrap();
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["byte_budget"], json!(MAX_SCAN_BYTES));
    assert_eq!(c["byte_budget_reached"], json!(false));
}

// --- Module identity ---------------------------------------------------------------

/// The API lists a module against the artifact types it subscribes to, so an
/// opt-in module is only offered on the types named here. The surfaces this
/// item adds are reached through their own types.
#[test]
fn the_module_subscribes_to_the_types_the_new_surfaces_arrive_as() {
    let (_dir, scanner) = scanner();
    let types = scanner.subscribes_to();
    assert!(types.contains(&ArtifactType::FileEntry));
    assert!(types.contains(&ArtifactType::FileContent));
    assert!(types.contains(&ArtifactType::UnallocatedSpace));
    assert!(
        types.contains(&ArtifactType::ParsedRecord),
        "a registry hive record is a ParsedRecord"
    );
}

/// The surface vocabulary is closed and spelled once.
#[test]
fn the_surface_vocabulary_is_closed() {
    let names: Vec<&str> = Surface::ALL.iter().map(Surface::as_str).collect();
    assert_eq!(
        names,
        vec![
            "file",
            "ads",
            "registry_value",
            "unallocated",
            "carved",
            "deleted_file",
            "volume",
            "slack"
        ]
    );
}

// --- The surfaces a plain `file` stamp used to swallow ----------------------------

/// Only the `file` surface may say the file system serves the bytes. Every
/// other statement is about bytes no live file-system listing vouches for,
/// and each is its own sentence rather than a copy of another's.
#[test]
fn only_the_file_surface_claims_the_file_system_serves_the_bytes() {
    let mut seen = std::collections::HashSet::new();
    for surface in Surface::ALL {
        let statement = surface.statement();
        assert!(!statement.is_empty(), "{surface:?}");
        assert!(
            seen.insert(statement),
            "{surface:?} repeats another surface's sentence"
        );
        let claims_served = statement.contains("file system serves");
        assert_eq!(
            claims_served,
            surface == Surface::File,
            "{surface:?}: {statement}"
        );
    }
}

fn carved_entry(bytes: &[u8], extra: serde_json::Value) -> Artifact {
    let mut meta = json!({
        "name": "carved_00002000.jpg",
        "size": bytes.len(),
        "carved": true,
        "carving_signature": "jpeg",
        "carving_offset": 8192,
        "carving_size": bytes.len(),
    });
    if let (Some(map), Some(more)) = (meta.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            map.insert(k.clone(), v.clone());
        }
    }
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(bytes)),
        meta,
    )
}

fn deleted_entry(bytes: &[u8], extra: serde_json::Value) -> Artifact {
    let mut meta = json!({
        "name": "gone.docx",
        "path": "/Users/x/Documents/gone.docx",
        "size": bytes.len(),
        "deleted": true,
        "deleted_recovery_source": "mft",
        "deleted_content_caveat": "clusters_may_be_reallocated",
        "content_incomplete": true,
        "content_incomplete_reason": "unresolved_structure",
    });
    if let (Some(map), Some(more)) = (meta.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            map.insert(k.clone(), v.clone());
        }
    }
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(bytes)),
        meta,
    )
}

fn volume_artifact(ty: ArtifactType, bytes: &[u8], meta: serde_json::Value) -> Artifact {
    Artifact::new(Uuid::new_v4(), ty, Some(bytes_source(bytes)), meta)
}

/// A carved object was cut out of a scanned region by signature. No file
/// system served it, its bounds are the carver's inference, and a hit in it
/// must say so instead of being stamped as a hit in a live file.
#[test]
fn a_carved_entry_is_stamped_carved_and_names_its_signature_and_offset() {
    let (_dir, scanner) = scanner();
    let mut bytes = vec![0u8; 256];
    bytes[40..56].copy_from_slice(b"X5O!P%@AP-MARKER");
    let art = carved_entry(&bytes, json!({ "carving_validated": true }));
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "carved");
    assert_eq!(meta["carving_signature"], "jpeg");
    assert_eq!(meta["carving_offset"], json!(8192u64));
    assert_eq!(meta["carving_validated"], json!(true));
    assert!(
        !meta["surface_means"]
            .as_str()
            .unwrap()
            .contains("file system serves"),
        "{}",
        meta["surface_means"]
    );
    let hits = meta["pattern_matches"].as_array().expect("pattern matches");
    assert_eq!(hits[0]["offset_in_region"], json!(40u64));
    assert_eq!(
        hits[0]["offset_in_parent"],
        json!(8192u64 + 40),
        "carving offset plus offset in the carved object, in the scanned input's space"
    );
    assert!(
        meta.get("entry_deleted").is_none(),
        "the carver wrote no deleted flag, so none is invented"
    );
}

/// A carved object cut from slack reports its offset within the slack window,
/// which is not its parent's coordinate space; the hit carries the carver's
/// fields and does not add the two.
#[test]
fn a_slack_carved_entry_carries_its_source_and_is_not_placed_in_its_parent() {
    let (_dir, scanner) = scanner();
    let art = carved_entry(
        b"X5O!P%@AP-MARKER",
        json!({
            "carving_source": "slack",
            "carving_offset_absolute": 1_048_576,
            "parent_file": "report.pdf",
        }),
    );
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "carved");
    assert_eq!(meta["carving_source"], "slack");
    assert_eq!(meta["carving_offset_absolute"], json!(1_048_576u64));
    assert_eq!(meta["base_file"], "report.pdf");
    assert!(
        meta["pattern_matches"][0].get("offset_in_parent").is_none(),
        "{meta}"
    );
}

/// A file the file system no longer lists is a recovered file: its record
/// still points at clusters that may since have been given to something else.
/// The surface says so, with the producer's recovery source and caveat.
#[test]
fn a_deleted_entry_is_stamped_deleted_file_with_its_recovery_source_and_caveat() {
    let (_dir, scanner) = scanner();
    let art = deleted_entry(b"X5O!P%@AP-MARKER", json!({}));
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "deleted_file");
    assert_eq!(meta["entry_deleted"], json!(true));
    assert_eq!(meta["deleted_recovery_source"], "mft");
    assert_eq!(
        meta["deleted_content_caveat"],
        "clusters_may_be_reallocated"
    );
    assert_eq!(meta["path"], "/Users/x/Documents/gone.docx");
    assert!(
        !meta["surface_means"]
            .as_str()
            .unwrap()
            .contains("file system serves"),
        "{}",
        meta["surface_means"]
    );
}

/// A `deleted: false` the producer wrote is a live file; the flag is carried
/// and the surface stays `file`. A stream off a deleted record stays `ads`,
/// because the stream is the finding and `entry_deleted` already says the
/// record is not in use.
#[test]
fn a_live_entry_stays_file_and_a_deleted_stream_stays_ads() {
    let (_dir, scanner) = scanner();
    let live = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(b"X5O!P%@AP-MARKER")),
        json!({ "name": "here.txt", "deleted": false }),
    );
    let out = scanner.process(&live).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m[0].metadata["surface"], "file");
    assert_eq!(m[0].metadata["entry_deleted"], json!(false));

    let stream = ads_entry(b"X5O!P%@AP-MARKER", json!({ "deleted": true }));
    let out = scanner.process(&stream).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m[0].metadata["surface"], "ads");
    assert_eq!(m[0].metadata["entry_deleted"], json!(true));
}

/// A partition, file system or evidence image handed to the module whole is
/// scanned end to end. A hit in it is at a byte offset in that image and is
/// attributed to no file — it may lie in a live file, a deleted one, slack or
/// free space — and the record says exactly that rather than "file".
#[test]
fn a_partition_scanned_whole_is_stamped_volume_and_places_hits_in_its_parent() {
    let (_dir, scanner) = scanner();
    let mut bytes = vec![0u8; 4096];
    bytes[1000..1016].copy_from_slice(b"X5O!P%@AP-MARKER");
    let art = volume_artifact(
        ArtifactType::Partition,
        &bytes,
        json!({
            "name": "Partition 1",
            "partition_type": "NTFS",
            "offset_bytes": 1_048_576,
            "size_bytes": 4096,
        }),
    );
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "volume");
    assert_eq!(meta["volume_type"], "Partition");
    assert_eq!(meta["offset_bytes"], json!(1_048_576u64));
    assert_eq!(meta["size_bytes"], json!(4096u64));
    let sentence = meta["surface_means"].as_str().unwrap();
    assert!(!sentence.contains("file system serves"), "{sentence}");
    assert!(
        sentence.contains("not attributed to any file"),
        "{sentence}"
    );
    let hits = meta["pattern_matches"].as_array().expect("pattern matches");
    assert_eq!(hits[0]["offset_in_region"], json!(1000u64));
    assert_eq!(hits[0]["offset_in_parent"], json!(1_048_576u64 + 1000));
}

/// A file system's `offset_bytes` is copied from its partition — the
/// grandparent's coordinate space, not the parent's — and an evidence image
/// has no parent at all. Both are `volume`; neither hit is placed "in parent".
#[test]
fn a_file_system_or_evidence_image_scanned_whole_is_volume_without_a_parent_offset() {
    let (_dir, scanner) = scanner();
    let fs = volume_artifact(
        ArtifactType::FileSystem,
        b"X5O!P%@AP-MARKER",
        json!({ "name": "NTFS", "offset_bytes": 1_048_576, "size_bytes": 16 }),
    );
    let out = scanner.process(&fs).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    assert_eq!(m[0].metadata["surface"], "volume");
    assert_eq!(m[0].metadata["volume_type"], "FileSystem");
    assert_eq!(m[0].metadata["offset_bytes"], json!(1_048_576u64));
    assert!(m[0].metadata["pattern_matches"][0]
        .get("offset_in_parent")
        .is_none());

    for ty in [ArtifactType::RawEvidence, ArtifactType::Container] {
        let art = volume_artifact(
            ty.clone(),
            b"X5O!P%@AP-MARKER",
            json!({ "name": "disk.dd" }),
        );
        let out = scanner.process(&art).unwrap();
        let m = matches_for(&out, "marker");
        assert_eq!(m.len(), 1, "{ty:?}: {out:?}");
        assert_eq!(m[0].metadata["surface"], "volume", "{ty:?}");
        assert_eq!(m[0].metadata["volume_type"], ty.to_string());
        assert!(m[0].metadata.get("offset_bytes").is_none(), "{ty:?}");
        assert!(m[0].metadata["pattern_matches"][0]
            .get("offset_in_parent")
            .is_none());
    }
}

/// A `carved: true` on a whole-volume type is still a carved object: the
/// provenance flag outranks the artifact type.
#[test]
fn the_carved_flag_outranks_the_artifact_type() {
    let (_dir, scanner) = scanner();
    let art = volume_artifact(
        ArtifactType::FileContent,
        b"X5O!P%@AP-MARKER",
        json!({ "carved": true, "carving_signature": "zip", "carving_offset": 0 }),
    );
    let out = scanner.process(&art).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m[0].metadata["surface"], "carved");
}

/// On every surface but a live file the region is itself the finding, so a
/// full scan that matched nothing still says the bytes were looked at, with
/// their entropy.
#[test]
fn carved_deleted_and_volume_scans_yield_a_region_record_when_unmatched() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("r.yar"),
        "rule m { strings: $a = \"MARK\" condition: $a }",
    )
    .unwrap();
    let scanner = YaraScanner::from_rule_path(dir.path()).unwrap();
    let bytes: Vec<u8> = (0..2048u32).map(|i| (i * 13 % 256) as u8).collect();
    let cases = vec![
        ("carved", carved_entry(&bytes, json!({}))),
        ("deleted_file", deleted_entry(&bytes, json!({}))),
        (
            "volume",
            volume_artifact(
                ArtifactType::RawEvidence,
                &bytes,
                json!({ "name": "disk.dd" }),
            ),
        ),
    ];
    for (surface, art) in cases {
        let out = scanner.process(&art).unwrap();
        let region = records_of(&out, "YaraRegionScanned");
        assert_eq!(region.len(), 1, "{surface}: {out:?}");
        let meta = &region[0].metadata;
        assert_eq!(meta["surface"], surface);
        assert_eq!(meta["bytes_scanned"], json!(2048u64));
        assert_eq!(meta["scan_complete"], json!(true));
        assert_eq!(meta["matches"], json!(0));
        assert_eq!(meta["entropy_bytes"], json!(2048u64));
        assert!(
            (meta["entropy_bits_per_byte"].as_f64().unwrap() - shannon_entropy(&bytes)).abs()
                < 1e-3
        );
    }
}

/// An artifact of a type this module has no surface for — a parsed record
/// that is not a registry hive, a timeline event — is not scanned under a
/// surface it cannot vouch for. It is refused with a record that names the
/// type and carries no `surface`, because stamping one would be the claim
/// the field exists to prevent.
#[test]
fn an_artifact_with_no_surface_is_refused_not_stamped_file() {
    let (_dir, scanner) = scanner();
    for ty in [ArtifactType::ParsedRecord, ArtifactType::TimelineEvent] {
        let art = volume_artifact(
            ty.clone(),
            b"X5O!P%@AP-MARKER",
            json!({ "type": "Something", "name": "x" }),
        );
        let out = scanner.process(&art).unwrap();
        assert!(matches_for(&out, "marker").is_empty(), "{ty:?}: {out:?}");
        let refused = records_of(&out, "YaraNotScanned");
        assert_eq!(refused.len(), 1, "{ty:?}: {out:?}");
        let meta = &refused[0].metadata;
        assert!(meta.get("surface").is_none(), "{ty:?}: {meta}");
        assert!(meta.get("surface_means").is_none(), "{ty:?}: {meta}");
        assert_eq!(meta["content_incomplete"], json!(true));
        assert_eq!(meta["refused_artifact_type"], ty.to_string());
        let detail = meta["content_incomplete_detail"].as_str().unwrap();
        assert!(detail.contains(&ty.to_string()), "{detail}");
    }
}

/// A `SystemArtifact` is a file the ingest path serves — a hive, an $MFT, an
/// event log picked out of a file system or ingested on its own — and, like
/// `FileContent`, is a live file unless its producer marked it otherwise.
#[test]
fn a_system_artifact_and_file_content_are_live_files() {
    let (_dir, scanner) = scanner();
    for ty in [ArtifactType::SystemArtifact, ArtifactType::FileContent] {
        let art = volume_artifact(ty.clone(), b"X5O!P%@AP-MARKER", json!({ "name": "SYSTEM" }));
        let out = scanner.process(&art).unwrap();
        let m = matches_for(&out, "marker");
        assert_eq!(m.len(), 1, "{ty:?}: {out:?}");
        assert_eq!(m[0].metadata["surface"], "file", "{ty:?}");
    }
}

// --- Composed with the §2.1 decode-and-rescan substrate ---------------------------

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// A rule written for a payload fires on the payload, not on its base64 —
/// and a hit on decoded bytes says it is on decoded bytes, where the span
/// was, and that the offsets it carries are into the decoded buffer.
#[test]
fn a_base64_encoded_payload_in_an_ads_is_found_on_its_decoded_bytes_and_labelled() {
    let (_dir, scanner) = scanner();
    let payload = b"prefix-bytes X5O!P%@AP-MARKER trailing-bytes".to_vec();
    let mut stream = b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec();
    let span_offset = stream.len();
    stream.extend_from_slice(b64(&payload).as_bytes());
    stream.extend_from_slice(b"\r\n");
    let out = scanner.process(&ads_entry(&stream, json!({}))).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "ads");
    assert_eq!(meta["stream_name"], "Zone.Identifier");
    assert_eq!(meta["bytes_are_decoded"], json!(true));
    assert_eq!(meta["decoded_via"], "base64");
    assert_eq!(meta["decoded_span_offset_in_region"], json!(span_offset));
    assert_eq!(meta["decoded_bytes"], json!(payload.len()));
    assert_eq!(meta["decoded_truncated"], json!(false));
    assert_eq!(meta["bytes_scanned"], json!(payload.len()));
    let hit = &meta["pattern_matches"][0];
    assert_eq!(hit["offset_in_decoded"], json!(13u64));
    assert!(hit.get("offset_in_region").is_none(), "{hit}");
    assert!(hit.get("offset_in_parent").is_none(), "{hit}");
    assert!(
        (meta["entropy_bits_per_byte"].as_f64().unwrap() - shannon_entropy(&payload)).abs() < 1e-3,
        "entropy is over the decoded bytes the rule was run on"
    );
    let region = records_of(&out, "YaraRegionScanned");
    assert_eq!(region.len(), 1);
    assert_eq!(region[0].metadata["decoded_spans_found"], json!(1));
    assert_eq!(region[0].metadata["decoded_spans_scanned"], json!(1));
    assert_eq!(
        region[0].metadata["decoded_bytes_scanned"],
        json!(payload.len())
    );
    assert_eq!(region[0].metadata["decoded_cap_reached"], json!(false));
    // The region's count covers the stream and its decoded spans: `always`
    // on the stream, `always` and `marker` on the decoded payload.
    assert_eq!(region[0].metadata["matches"], json!(3));
    assert_eq!(region[0].metadata["decoded_matches"], json!(2));
}

/// A gzip member in free space is inflated and scanned; the hit is placed
/// at the member's offset in the region and in the parent, and says the
/// pattern offset is into the inflated bytes.
#[test]
fn a_gzip_member_in_free_space_is_found_on_its_inflated_bytes() {
    let (_dir, scanner) = scanner();
    let payload = b"some text and then X5O!P%@AP-MARKER and more text after it".to_vec();
    let member = gzip(&payload);
    let mut volume = vec![0u8; 16384];
    let at = 8192 + 700;
    volume[at..at + member.len()].copy_from_slice(&member);
    let out = scanner
        .process(&unallocated_region(&volume, 8192, 8192))
        .unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "unallocated");
    assert_eq!(meta["decoded_via"], "gzip");
    assert_eq!(meta["decoded_span_offset_in_region"], json!(700u64));
    assert_eq!(meta["decoded_span_offset_in_parent"], json!(8192u64 + 700));
    assert_eq!(
        meta["pattern_matches"][0]["offset_in_decoded"],
        json!(19u64)
    );
    assert!(meta["decoded_means"].as_str().unwrap().contains("decoded"));
}

/// A base64 payload in a string value sits in the hive as UTF-16 text, whose
/// interleaved zero bytes break every span. The value's published text is
/// what the encoding lives in, so that is what the decoders are run over —
/// and the hit says so.
#[test]
fn a_base64_payload_in_a_string_value_is_decoded_from_the_published_text() {
    let (_dir, scanner) = scanner();
    let payload = b"IEX (New-Object Net.WebClient) X5O!P%@AP-MARKER".to_vec();
    let text = format!("powershell -EncodedCommand {}", b64(&payload));
    let stored = utf16le(&text).len() + 2;
    let v = value("ROOT\\Software\\Run", "Updater", "RegSZ", &text, stored);
    let out = scanner.process(&hive_record(vec![v], json!({}))).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "registry_value");
    assert_eq!(meta["value_name"], "Updater");
    assert_eq!(meta["bytes_are_decoded"], json!(true));
    assert_eq!(meta["decoded_via"], "base64");
    assert_eq!(meta["decoded_from"], "value_text");
    assert_eq!(
        meta["decoded_span_offset_in_text"],
        json!("powershell -EncodedCommand ".len())
    );
    let c = &records_of(&out, "YaraRegistryCoverage")[0].metadata;
    assert_eq!(c["decoded_spans_found"], json!(1));
    assert_eq!(c["decoded_spans_scanned"], json!(1));
    assert_eq!(
        c["matches"],
        json!(3),
        "`always` on the value; `always` and `marker` on its decoded span"
    );
    assert_eq!(c["decoded_matches"], json!(2));
}

/// A binary value's spans are found in its bytes, and the hit says so.
#[test]
fn a_base64_payload_in_a_binary_value_is_decoded_from_its_bytes() {
    use base64::Engine as _;
    let (_dir, scanner) = scanner();
    let payload = b"a binary blob holding X5O!P%@AP-MARKER inside".to_vec();
    let mut raw = b"\x01\x02\x03\x04 ".to_vec();
    raw.extend_from_slice(b64(&payload).as_bytes());
    raw.extend_from_slice(b" \x05\x06");
    let mut v = value(
        "ROOT\\Software\\Vendor",
        "Blob",
        "RegBinary",
        &format!("{} bytes (binary data)", raw.len()),
        raw.len(),
    );
    v["value_data_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(&raw));
    let out = scanner.process(&hive_record(vec![v], json!({}))).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    assert_eq!(m[0].metadata["decoded_from"], "value_bytes");
    assert_eq!(m[0].metadata["decoded_span_offset_in_region"], json!(5u64));
}

/// The decode ceilings are reported with the numbers they stopped at.
#[test]
fn the_decoded_span_ceiling_is_reported_on_the_region_record() {
    let (_dir, scanner) = scanner();
    let mut stream = Vec::new();
    let spans = MAX_DECODED_SPANS_PER_REGION + 40;
    for i in 0..spans {
        stream.extend_from_slice(b64(format!("span-number-{i:06}-payload").as_bytes()).as_bytes());
        stream.push(b' ');
    }
    let out = scanner.process(&ads_entry(&stream, json!({}))).unwrap();
    let region = records_of(&out, "YaraRegionScanned");
    assert_eq!(region.len(), 1);
    let r = &region[0].metadata;
    assert_eq!(r["decoded_spans_found"], json!(spans));
    assert_eq!(
        r["decoded_spans_scanned"],
        json!(MAX_DECODED_SPANS_PER_REGION)
    );
    assert_eq!(r["decoded_cap_reached"], json!(true));
    assert_eq!(r["decoded_span_cap"], json!(MAX_DECODED_SPANS_PER_REGION));
    assert_eq!(r["decoded_byte_cap"], json!(MAX_DECODED_BYTES_PER_REGION));
    assert_eq!(r["content_incomplete"], json!(true));
    assert!(
        r["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("40 decoded span"),
        "{r}"
    );
    // `always` fires once on the stream and once per decoded span scanned.
    assert_eq!(
        matches_for(&out, "always").len(),
        1 + MAX_DECODED_SPANS_PER_REGION
    );
}

/// A plain file has no region record; when its decode step hit a ceiling, a
/// coverage record says so, and when it did not, nothing extra is emitted.
#[test]
fn a_plain_file_reports_a_decode_ceiling_and_is_otherwise_silent() {
    let (_dir, scanner) = scanner();
    let mut file = Vec::new();
    for i in 0..(MAX_DECODED_SPANS_PER_REGION + 1) {
        file.extend_from_slice(b64(format!("span-number-{i:06}-payload").as_bytes()).as_bytes());
        file.push(b'\n');
    }
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(&file)),
        json!({ "name": "spans.txt" }),
    );
    let out = scanner.process(&art).unwrap();
    let cov = records_of(&out, "YaraDecodeCoverage");
    assert_eq!(cov.len(), 1, "{out:?}");
    assert_eq!(cov[0].metadata["surface"], "file");
    assert_eq!(cov[0].metadata["decoded_cap_reached"], json!(true));
    assert_eq!(cov[0].metadata["content_incomplete"], json!(true));

    let quiet = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(bytes_source(b"just text, nothing encoded")),
        json!({ "name": "quiet.txt" }),
    );
    let out = scanner.process(&quiet).unwrap();
    assert!(records_of(&out, "YaraDecodeCoverage").is_empty());
    assert!(records_of(&out, "YaraRegionScanned").is_empty());
}

/// Decoding is one level deep: a base64 span inside a decoded span is not
/// decoded again, and the record states the depth.
#[test]
fn decoding_is_one_level_deep_and_says_so() {
    let (_dir, scanner) = scanner();
    let inner = b64(b"X5O!P%@AP-MARKER padded to be long enough");
    let outer = b64(format!("wrapper {inner} wrapper").as_bytes());
    let out = scanner
        .process(&ads_entry(outer.as_bytes(), json!({})))
        .unwrap();
    assert!(matches_for(&out, "marker").is_empty(), "{out:?}");
    let region = records_of(&out, "YaraRegionScanned");
    assert_eq!(region[0].metadata["decoded_depth"], json!(1));
}

// --- File slack (ROADMAP §2.3) -----------------------------------------------------

/// A slack region exactly as the producer publishes it: built by
/// `seance_core::slack::SlackCollector`, the code the NTFS, FAT and exFAT
/// parsers call, rather than a shape written from a reading of it (the
/// fixture failure `HUNT-122` recorded). `volume` is the file system's bytes;
/// the window is `len` bytes at `offset` in it.
fn slack_region(volume: &[u8], offset: u64, len: u64) -> (Artifact, Artifact) {
    use seance_core::slack::{SlackCollector, SlackLabels, SlackOwner, SlackWindow};
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(bytes_source(volume)),
        json!({ "name": "ntfs" }),
    );
    let source = fs.data.clone().unwrap();
    let owner_id = Uuid::new_v4();
    let mut collector = SlackCollector::new(
        SlackLabels {
            filesystem: "NTFS",
            offset_basis: "the NTFS volume this region was found in, not the evidence",
        },
        4096,
    );
    collector.offer(
        &fs,
        &source,
        SlackOwner {
            artifact_id: owner_id,
            name: "report.docx",
            path: Some("/Users/x/report.docx"),
            logical_size: 4096 - len,
        },
        SlackWindow { offset, len },
    );
    let (out, _) = collector.finish(&fs);
    let region = out
        .into_iter()
        .find(|a| a.artifact_type == ArtifactType::SlackSpace)
        .expect("the producer emits a region for a non-zero tail");
    (fs, region)
}

/// A hit in a file's slack is stamped `slack`, names the live file whose last
/// cluster it lies in, carries the region's volume offset and its basis, and
/// is placed in the file system's coordinate space — the parent the producer
/// hangs the region on.
#[test]
fn a_slack_region_is_scanned_as_surface_slack_and_names_its_parent_file() {
    let (_dir, scanner) = scanner();
    let mut volume = vec![0u8; 16384];
    // The window is the last 1000 bytes of the cluster at 8192.
    let start = 8192 + 3096;
    volume[start..start + 1000].fill(0x41);
    volume[start + 200..start + 216].copy_from_slice(b"X5O!P%@AP-MARKER");
    let (fs, region) = slack_region(&volume, start as u64, 1000);
    assert_eq!(region.parent_id, Some(fs.id));
    let out = scanner.process(&region).unwrap();
    let m = matches_for(&out, "marker");
    assert_eq!(m.len(), 1, "{out:?}");
    let meta = &m[0].metadata;
    assert_eq!(meta["surface"], "slack");
    assert_eq!(meta["base_file"], "report.docx");
    assert_eq!(meta["path"], "/Users/x/report.docx");
    assert_eq!(meta["offset_bytes"], json!(start as u64));
    assert_eq!(meta["size_bytes"], json!(1000u64));
    assert_eq!(meta["filesystem"], "NTFS");
    assert_eq!(
        meta["offset_basis"],
        "the NTFS volume this region was found in, not the evidence"
    );
    assert_eq!(meta["region_source"], "file_slack");
    assert_eq!(meta["logical_size"], json!(4096u64 - 1000));
    assert_eq!(meta["cluster_size"], json!(4096u64));
    assert!(meta["owner_artifact_id"].is_string(), "{meta}");
    let hits = meta["pattern_matches"].as_array().expect("pattern matches");
    assert_eq!(hits[0]["offset_in_region"], json!(200u64));
    assert_eq!(
        hits[0]["offset_in_parent"],
        json!(start as u64 + 200),
        "region offset plus offset in region, in the file system's coordinate space"
    );

    // Fully scanned and unmatched, the region still says it was read.
    let mut quiet = vec![0u8; 16384];
    quiet[start..start + 1000].fill(0x41);
    let (_fs, region) = slack_region(&quiet, start as u64, 1000);
    let out = scanner.process(&region).unwrap();
    assert!(matches_for(&out, "marker").is_empty());
    let rec = records_of(&out, "YaraRegionScanned");
    assert_eq!(rec.len(), 1, "{out:?}");
    assert_eq!(rec[0].metadata["surface"], "slack");
    assert_eq!(rec[0].metadata["bytes_scanned"], json!(1000u64));
    assert_eq!(rec[0].metadata["scan_complete"], json!(true));
    assert!(records_of(&out, "YaraNotScanned").is_empty(), "{out:?}");
}

/// Slack is the eighth surface, and what its statement says is what slack
/// is: bytes past the live file's logical end, not its content, possibly an
/// earlier file's — and a string split across that end is not matched whole.
#[test]
fn surface_all_has_eight_and_statement_names_slack() {
    assert_eq!(Surface::ALL.len(), 8);
    let slack = Surface::ALL
        .iter()
        .find(|s| s.as_str() == "slack")
        .expect("a slack surface");
    let statement = slack.statement();
    assert!(statement.contains("logical end"), "{statement}");
    assert!(statement.contains("not the file's content"), "{statement}");
    assert!(statement.contains("earlier file"), "{statement}");
    assert!(statement.contains("split"), "{statement}");
}

/// The API offers an opt-in module only against the types it subscribes to,
/// so without `SlackSpace` here no slack region would ever be scanned.
#[test]
fn the_module_subscribes_to_slack_regions() {
    let (_dir, scanner) = scanner();
    assert!(scanner.subscribes_to().contains(&ArtifactType::SlackSpace));
}
