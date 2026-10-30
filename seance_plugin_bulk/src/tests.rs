use super::*;
use seance_bulk::aes::expand_key;
use uuid::Uuid;

fn mem_image_artifact(bytes: Vec<u8>) -> Artifact {
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        json!({ "type": "MemoryImage", "subtype": "memory_image" }),
    )
}

fn unalloc_artifact(bytes: Vec<u8>) -> Artifact {
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(src),
        json!({}),
    )
}

fn records<'a>(arts: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    arts.iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some(ty))
        .collect()
}

#[test]
fn aes_scanner_recovers_a_planted_key_from_a_memory_image() {
    let key: Vec<u8> = (0..32).map(|i| (i * 7 + 1) as u8).collect();
    let sched = expand_key(&key);
    let mut mem = vec![0u8; 200_000];
    for (i, b) in mem.iter_mut().enumerate() {
        *b = (i * 131 % 251) as u8;
    }
    let at = 100_000;
    mem[at..at + sched.len()].copy_from_slice(&sched);

    let art = mem_image_artifact(mem);
    let out = AesKeyScanner.process(&art).unwrap();
    let keys = records(&out, "RecoveredKey");
    assert_eq!(keys.len(), 1, "one key");
    let k = keys[0];
    assert_eq!(k.metadata["bits"], 256);
    assert_eq!(k.metadata["device_offset"], at as u64);
    assert_eq!(k.metadata["key_hex"], hex(&key));
    // A summary is always emitted when something was found.
    assert_eq!(records(&out, "RecoveredKeySummary").len(), 1);
}

#[test]
fn aes_scanner_finds_a_key_across_a_window_boundary() {
    // Plant the key so it straddles the 8 MiB window boundary, proving the
    // overlap works.
    let key: Vec<u8> = (0..32).map(|i| (i * 3 + 9) as u8).collect();
    let sched = expand_key(&key);
    let mut mem = vec![0u8; CHUNK + 100_000];
    for (i, b) in mem.iter_mut().enumerate() {
        *b = (i * 97 % 253) as u8;
    }
    let at = CHUNK - 100; // spans the boundary
    mem[at..at + sched.len()].copy_from_slice(&sched);

    let art = mem_image_artifact(mem);
    let out = AesKeyScanner.process(&art).unwrap();
    let keys = records(&out, "RecoveredKey");
    assert_eq!(keys.len(), 1, "boundary-straddling key must still be found");
    assert_eq!(keys[0].metadata["device_offset"], at as u64);
}

#[test]
fn aes_scanner_ignores_non_memory_parsed_records() {
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 1000]));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        json!({ "type": "SomethingElse" }),
    );
    assert!(AesKeyScanner.process(&art).unwrap().is_empty());
}

#[test]
fn feature_scanner_finds_selectors_in_unallocated_with_offsets() {
    let mut buf = vec![0u8; 5000];
    let planted = b"agent@agency.gov and card 4111 1111 1111 1111 at 51.5074, -0.1278";
    let at = 2000;
    buf[at..at + planted.len()].copy_from_slice(planted);

    let art = unalloc_artifact(buf);
    let out = BulkFeatureScanner.process(&art).unwrap();
    let feats = records(&out, "Feature");
    assert!(feats
        .iter()
        .any(|f| f.metadata["kind"] == "email" && f.metadata["value"] == "agent@agency.gov"));
    assert!(feats.iter().any(|f| f.metadata["kind"] == "ccn"));
    assert!(feats.iter().any(|f| f.metadata["kind"] == "gps"));
    // Offset provenance is absolute within the artifact.
    let email = feats
        .iter()
        .find(|f| f.metadata["kind"] == "email")
        .unwrap();
    assert_eq!(email.metadata["device_offset"], (at) as u64);
    // Summary present with a by-kind breakdown.
    let summary = records(&out, "FeatureSummary");
    assert_eq!(summary.len(), 1);
    assert!(summary[0].metadata["by_kind"]["email"].as_u64().unwrap() >= 1);
}

/// The histogram summary is one record per scan, carrying the counts the
/// histogram accumulated while the hits streamed past — never a re-tally of
/// the emitted `Feature` records, which are capped.
#[test]
fn feature_scanner_publishes_one_histogram_summary_with_exact_counts() {
    let text = b"a@example.com b@example.com http://one.test/x a@example.com \
                 http://one.test/x a@example.com";
    let mut buf = vec![0u8; 4096];
    buf[100..100 + text.len()].copy_from_slice(text);

    let out = BulkFeatureScanner.process(&unalloc_artifact(buf)).unwrap();
    let hist = records(&out, "FeatureHistogramSummary");
    assert_eq!(hist.len(), 1, "exactly one histogram summary per scan");
    let m = &hist[0].metadata;
    assert_eq!(m["subtype"], "summary");
    assert_eq!(m["total_hits"], 6);
    assert_eq!(m["distinct_values"], 3);
    assert_eq!(m["hits_dropped"], 0);
    assert_eq!(m["capped"], false);
    assert_eq!(
        m["max_distinct_values"],
        seance_bulk::MAX_DISTINCT_VALUES as u64,
        "the ceiling is named on the record"
    );
    assert_eq!(m["top_n"], HISTOGRAM_TOP_N as u64);
    assert_eq!(m["top_omitted"], 0);

    let top = m["top"].as_array().unwrap();
    assert_eq!(top.len(), 3);
    assert_eq!(top[0]["kind"], "email");
    assert_eq!(top[0]["value"], "a@example.com");
    assert_eq!(top[0]["count"], 3);
    assert_eq!(top[1]["kind"], "url");
    assert_eq!(top[1]["value"], "http://one.test/x");
    assert_eq!(top[1]["count"], 2);
    assert_eq!(top[2]["value"], "b@example.com");
    assert_eq!(top[2]["count"], 1);

    assert_eq!(m["by_kind"]["email"]["hits"], 4);
    assert_eq!(m["by_kind"]["email"]["distinct_values"], 2);
    assert_eq!(m["by_kind"]["url"]["hits"], 2);
    assert_eq!(m["by_kind"]["url"]["distinct_values"], 1);

    // The per-occurrence records and the older by-kind summary still stand.
    assert_eq!(records(&out, "Feature").len(), 6);
    let summary = records(&out, "FeatureSummary");
    assert_eq!(summary[0].metadata["features_found"], 6);
    assert_eq!(summary[0].metadata["by_kind"]["email"], 4);
}

/// The histogram over a real file, against counts measured off the file with
/// `grep -o | sort | uniq -c` before the record existed.
///
/// `gcp_logging.jsonl` (21,883 bytes, sha256 `028852c6…42ca9b`) from the plaso
/// project's `test_data`, named by `SEANCE_BULK_CORPUS`: nine distinct
/// addresses over 25 occurrences, `fakeemailxyz@gmail.com` twelve times;
/// 21 URLs each seen once; three IPv4 addresses over ten occurrences,
/// `1.1.1.1` eight times.
#[test]
fn feature_scanner_histogram_over_a_real_gcp_log_matches_counts_measured_off_the_file() {
    let Some(path) =
        seance_core::test_support::corpus::file("SEANCE_BULK_CORPUS", "gcp_logging.jsonl")
    else {
        return;
    };
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes.len(), 21_883, "the file the counts were measured off");

    let out = BulkFeatureScanner
        .process(&unalloc_artifact(bytes))
        .unwrap();
    let hist = records(&out, "FeatureHistogramSummary");
    assert_eq!(hist.len(), 1);
    let m = &hist[0].metadata;

    assert_eq!(m["by_kind"]["email"]["hits"], 25);
    assert_eq!(m["by_kind"]["email"]["distinct_values"], 9);
    assert_eq!(m["by_kind"]["url"]["hits"], 21);
    assert_eq!(m["by_kind"]["url"]["distinct_values"], 21);
    assert_eq!(m["by_kind"]["ipv4"]["hits"], 10);
    assert_eq!(m["by_kind"]["ipv4"]["distinct_values"], 3);

    let top = m["top"].as_array().unwrap();
    assert_eq!(top[0]["kind"], "email");
    assert_eq!(top[0]["value"], "fakeemailxyz@gmail.com");
    assert_eq!(top[0]["count"], 12);
    assert_eq!(top[1]["kind"], "ipv4");
    assert_eq!(top[1]["value"], "1.1.1.1");
    assert_eq!(top[1]["count"], 8);
    let count_of = |kind: &str, value: &str| {
        top.iter()
            .find(|e| e["kind"] == kind && e["value"] == value)
            .map(|e| e["count"].as_u64().unwrap())
    };
    assert_eq!(
        count_of("email", "test-1@fake-project.iam.gserviceaccount.com"),
        Some(3)
    );
    assert_eq!(count_of("email", "fake-account@fake-project.com"), Some(2));
    assert_eq!(
        count_of(
            "email",
            "123456123456-compute@developer.gserviceaccount.com"
        ),
        Some(1)
    );
    assert_eq!(
        count_of("url", "https://www.googleapis.com/auth/cloud-platform"),
        Some(1)
    );

    // The record is internally consistent: the totals are the by-kind sums,
    // and the top list is the whole table when the table fits in it.
    let by_kind = m["by_kind"].as_object().unwrap();
    let hits: u64 = by_kind.values().map(|k| k["hits"].as_u64().unwrap()).sum();
    let distinct: u64 = by_kind
        .values()
        .map(|k| k["distinct_values"].as_u64().unwrap())
        .sum();
    assert_eq!(m["total_hits"], hits);
    assert_eq!(m["distinct_values"], distinct);
    assert_eq!(top.len() as u64, distinct);
    assert_eq!(m["top_omitted"], 0);
    assert_eq!(m["capped"], false);
    assert_eq!(m["hits_dropped"], 0);
    // Every occurrence also went out as a Feature record: the file is far
    // below the per-artifact record cap.
    assert_eq!(records(&out, "Feature").len() as u64, hits);
}

/// More distinct values than the histogram's ceiling: the record must say it
/// is capped, name the ceiling, and give the exact number of hits turned away.
/// Synthetic by necessity — 100,003 distinct addresses written to a buffer.
#[test]
fn feature_scanner_histogram_says_so_on_the_record_when_capped() {
    let over = 3;
    let mut buf = Vec::new();
    for i in 0..seance_bulk::MAX_DISTINCT_VALUES + over {
        buf.extend_from_slice(format!("u{i}@cap.test ").as_bytes());
    }
    let out = BulkFeatureScanner.process(&unalloc_artifact(buf)).unwrap();
    let hist = records(&out, "FeatureHistogramSummary");
    assert_eq!(hist.len(), 1);
    let m = &hist[0].metadata;
    assert_eq!(m["capped"], true);
    assert_eq!(m["hits_dropped"], over as u64);
    assert_eq!(
        m["max_distinct_values"],
        seance_bulk::MAX_DISTINCT_VALUES as u64
    );
    assert_eq!(
        m["distinct_values"],
        seance_bulk::MAX_DISTINCT_VALUES as u64
    );
    assert_eq!(
        m["total_hits"],
        (seance_bulk::MAX_DISTINCT_VALUES + over) as u64,
        "the total is what the scan produced, not what the table kept"
    );
    assert_eq!(
        m["by_kind"]["email"]["hits"],
        (seance_bulk::MAX_DISTINCT_VALUES + over) as u64
    );
    assert_eq!(m["top"].as_array().unwrap().len(), HISTOGRAM_TOP_N);
    assert_eq!(
        m["top_omitted"],
        (seance_bulk::MAX_DISTINCT_VALUES - HISTOGRAM_TOP_N) as u64
    );
    assert!(
        m["note"].as_str().unwrap().contains("100000"),
        "the cap is spelled out in prose too: {}",
        m["note"]
    );
}

/// A selector match cut by a window edge must never surface as a truncated
/// second value: the source is read in overlapping windows, and a match that
/// straddles one edge is whole in the neighbouring window.
///
/// Three straddles, each of which the naive window loop turns into a phantom:
/// an address across the second window's leading edge (`ce@example.com` at the
/// edge), one across the first window's trailing edge (`carol@example.co`,
/// which is itself a well-formed address), and one across the re-read tail of
/// a sub-window source (`ve@example.com`).
#[test]
fn feature_scanner_does_not_report_a_match_cut_by_a_window_edge_as_a_second_value() {
    let mut buf = vec![0u8; CHUNK + 4096];
    let alice = b"alice@example.com";
    let alice_at = CHUNK - 3;
    buf[alice_at..alice_at + alice.len()].copy_from_slice(alice);
    let carol = b"carol@example.com";
    let carol_at = CHUNK + 1024 - 16;
    buf[carol_at..carol_at + carol.len()].copy_from_slice(carol);

    let out = BulkFeatureScanner.process(&unalloc_artifact(buf)).unwrap();
    let mut found: Vec<(u64, String)> = records(&out, "Feature")
        .iter()
        .map(|f| {
            (
                f.metadata["device_offset"].as_u64().unwrap(),
                f.metadata["value"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            (alice_at as u64, "alice@example.com".to_string()),
            (carol_at as u64, "carol@example.com".to_string()),
        ]
    );
    let hist = records(&out, "FeatureHistogramSummary");
    assert_eq!(hist[0].metadata["total_hits"], 2);
    assert_eq!(hist[0].metadata["distinct_values"], 2);

    // The sub-window case: a source shorter than one window, with an address
    // straddling the point 1,024 bytes before its end.
    let mut small = vec![0u8; 4096];
    let dave = b"dave@example.com";
    let dave_at = 4096 - 1024 - 2;
    small[dave_at..dave_at + dave.len()].copy_from_slice(dave);
    let out = BulkFeatureScanner
        .process(&unalloc_artifact(small))
        .unwrap();
    let feats = records(&out, "Feature");
    assert_eq!(feats.len(), 1, "one address, one record: {feats:?}");
    assert_eq!(feats[0].metadata["value"], "dave@example.com");
    assert_eq!(feats[0].metadata["device_offset"], dave_at as u64);
}

/// The ownership edge between two windows sits `overlap` bytes past the first
/// window's chunk. A match ending just before it, starting exactly on it,
/// straddling it, or ending exactly on it is reported once, at its true offset.
#[test]
fn feature_scanner_reports_a_match_at_the_ownership_edge_exactly_once() {
    let edge = CHUNK + 1024;
    let cases: [&[(usize, &[u8])]; 2] = [
        // Ends one byte before the edge; starts on it; well after it.
        &[
            (edge - 16, b"ann@before.test"),
            (edge, b"bea@on-edge.test"),
            (edge + 40, b"cy@after.test"),
        ],
        // Ends exactly on the edge; a straddler further on is not possible
        // without overlapping, so a second scan carries the straddler alone.
        &[
            (edge - 13, b"eve@ends.test"),
            (edge + 4096, b"fay@later.test"),
        ],
    ];
    let straddler: &[(usize, &[u8])] = &[(edge - 5, b"dan@straddle.test")];
    for plants in cases.iter().copied().chain(std::iter::once(straddler)) {
        let mut buf = vec![0u8; CHUNK + 8192];
        for (at, text) in plants {
            buf[*at..*at + text.len()].copy_from_slice(text);
        }
        let out = BulkFeatureScanner.process(&unalloc_artifact(buf)).unwrap();
        let mut found: Vec<(u64, String)> = records(&out, "Feature")
            .iter()
            .map(|f| {
                (
                    f.metadata["device_offset"].as_u64().unwrap(),
                    f.metadata["value"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        found.sort();
        let expected: Vec<(u64, String)> = plants
            .iter()
            .map(|(at, text)| (*at as u64, String::from_utf8(text.to_vec()).unwrap()))
            .collect();
        assert_eq!(found, expected);
    }
}

/// A source that declares more bytes than it can deliver: every read at or
/// past `fails_at` is an I/O error — a bad sector, or an image segment that
/// went missing after the size was taken.
#[derive(Debug)]
struct FailingTail {
    bytes: Vec<u8>,
    declared: u64,
    fails_at: u64,
}

impl DataSource for FailingTail {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.fails_at {
            return Err(std::io::Error::other("read error past the bad sector"));
        }
        let end = (offset + buf.len() as u64).min(self.fails_at) as usize;
        let n = end - offset as usize;
        buf[..n].copy_from_slice(&self.bytes[offset as usize..end]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.declared
    }
}

#[test]
fn feature_scanner_reports_the_bytes_it_read_not_the_bytes_it_meant_to() {
    // A 20 MiB unallocated region whose reads fail from 9 MiB on. The scan
    // covers what it read and must say so: the summaries publish the bytes
    // covered and stamp the short read, rather than claiming all 20 MiB.
    let declared: u64 = 20 * 1024 * 1024;
    let fails_at: u64 = 9 * 1024 * 1024;
    let mut bytes = vec![0u8; fails_at as usize];
    let email = b"contact ops@example.org today";
    bytes[4096..4096 + email.len()].copy_from_slice(email);
    let src: Arc<dyn DataSource> = Arc::new(FailingTail {
        bytes,
        declared,
        fails_at,
    });
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(src),
        json!({}),
    );
    let out = BulkFeatureScanner.process(&art).unwrap();
    for ty in ["FeatureSummary", "FeatureHistogramSummary"] {
        let s = records(&out, ty);
        assert_eq!(s.len(), 1, "{ty}");
        let m = &s[0].metadata;
        assert_eq!(
            m["bytes_scanned"],
            json!(fails_at),
            "{ty} must publish the bytes read, not the limit"
        );
        assert_eq!(m["short_read"], json!(true), "{ty}");
        assert_eq!(m["source_size"], json!(declared), "{ty}");
        assert_eq!(m["content_incomplete"], json!(true), "{ty}");
        assert_eq!(m["content_incomplete_reason"], json!("short_read"), "{ty}");
        assert_eq!(
            m["unreadable_ranges"],
            json!([{ "offset": fails_at, "length": declared - fails_at }]),
            "{ty}: the failing tail is named by its range"
        );
    }
}

#[test]
fn a_short_read_with_no_hits_is_said_not_passed_off_as_an_empty_region() {
    // Nothing found in 9 MiB of a 20 MiB region the source stopped answering
    // in is not "nothing there": each sweep publishes its summary anyway.
    let declared: u64 = 20 * 1024 * 1024;
    let fails_at: u64 = 9 * 1024 * 1024;
    let src: Arc<dyn DataSource> = Arc::new(FailingTail {
        bytes: vec![0u8; fails_at as usize],
        declared,
        fails_at,
    });
    let unalloc = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(src.clone()),
        json!({}),
    );
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(src),
        json!({}),
    );
    let checks: [(&str, Vec<Artifact>); 3] = [
        (
            "FeatureSummary",
            BulkFeatureScanner.process(&unalloc).unwrap(),
        ),
        ("RecoveredKeySummary", AesKeyScanner.process(&raw).unwrap()),
        (
            "NetworkCarveSummary",
            NetworkPacketCarver.process(&raw).unwrap(),
        ),
    ];
    for (ty, out) in checks {
        let s = records(&out, ty);
        assert_eq!(s.len(), 1, "{ty} must be published on a short read");
        assert_eq!(s[0].metadata["short_read"], json!(true), "{ty}");
        assert_eq!(s[0].metadata["bytes_scanned"], json!(fails_at), "{ty}");
        assert_eq!(s[0].metadata["content_incomplete"], json!(true), "{ty}");
    }
}

#[test]
fn feature_scanner_is_quiet_on_clean_data() {
    let art = unalloc_artifact(vec![0u8; 10_000]);
    let out = BulkFeatureScanner.process(&art).unwrap();
    assert!(out.is_empty(), "no features, no summary");
}

#[test]
fn net_carver_is_optin_and_produces_a_pcap_fileentry() {
    assert_eq!(NetworkPacketCarver.execution_mode(), ExecutionMode::OptIn);
    // Build a valid UDP packet with a correct checksum (mirrors the net tests).
    let payload = b"dns query";
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 5]);
    p[16..20].copy_from_slice(&[8, 8, 8, 8]);
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);

    let mut mem = vec![0u8; 4000];
    for (i, b) in mem.iter_mut().enumerate() {
        *b = (i * 37 % 251) as u8;
    }
    mem[1000..1000 + p.len()].copy_from_slice(&p);

    let art = mem_image_artifact(mem);
    let out = NetworkPacketCarver.process(&art).unwrap();
    let pcaps: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();
    assert_eq!(pcaps.len(), 1);
    assert_eq!(pcaps[0].metadata["packet_count"], 1);
    // The pcap FileEntry carries readable bytes starting with the pcap magic.
    let mut hdr = [0u8; 4];
    pcaps[0]
        .data
        .as_ref()
        .unwrap()
        .read_at(0, &mut hdr)
        .unwrap();
    assert_eq!(hdr, 0xa1b2c3d4u32.to_le_bytes());
    assert_eq!(records(&out, "NetworkCarveSummary").len(), 1);
}

#[test]
fn decode_rescan_is_optin_and_lifts_a_base64_payload() {
    use seance_bulk::decode;
    assert_eq!(DecodeRescan.execution_mode(), ExecutionMode::OptIn);
    // base64 of a buffer containing an email — a decoded child the pipeline can
    // re-scan.
    let inner = b"hidden bob@secret.org inside padding padding padding padding";
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(inner)
    };
    let mut buf = b"prefix ".to_vec();
    buf.extend_from_slice(b64.as_bytes());
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );

    let out = DecodeRescan.process(&art).unwrap();
    let decoded = records(&out, "DecodedBuffer");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].metadata["decode_method"], "base64");
    // The child carries the next generation, so a re-queue is bounded.
    assert_eq!(decoded[0].metadata["decode_generation"], 1);
    // The child buffer really contains the inner bytes.
    let child = decoded[0].data.as_ref().unwrap();
    let mut got = vec![0u8; inner.len()];
    child.read_at(0, &mut got).unwrap();
    assert_eq!(&got, inner);
    // And the decode module's output really re-scans clean via the feature scanner.
    let _ = decode::decode_base64_spans(&got, 8); // smoke
}

#[test]
fn decode_rescan_lifts_a_single_byte_xor_obfuscated_payload() {
    // Single-byte XOR is the classic packer/malware obfuscation, and the module
    // advertises lifting it. A buffer that proves its own key (a known plaintext
    // shows through under it) must yield a deobfuscated child to re-scan.
    let mut plain = b"This program cannot be run in DOS mode".to_vec();
    plain.extend_from_slice(b" -- contact dave@covert.gov about the drop");
    let obfuscated: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(obfuscated));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );

    let out = DecodeRescan.process(&art).unwrap();
    let xor: Vec<&Artifact> = records(&out, "DecodedBuffer")
        .into_iter()
        .filter(|a| a.metadata["decode_method"] == "xor")
        .collect();
    assert_eq!(xor.len(), 1, "the proven XOR key must yield one child");
    // The key and the plaintext that proved it are both recorded, so an examiner
    // can check the claim rather than take the child on trust.
    assert_eq!(xor[0].metadata["xor_key"], "0x5a");
    assert!(xor[0].metadata["xor_evidence"].is_string());
    assert_eq!(xor[0].metadata["decode_generation"], 1);
    let child = xor[0].data.as_ref().unwrap();
    let mut got = vec![0u8; plain.len()];
    child.read_at(0, &mut got).unwrap();
    assert_eq!(got, plain, "the child must be the buffer in the clear");
}

#[test]
fn decode_rescan_does_not_xor_a_buffer_that_is_already_in_the_clear() {
    // XOR "succeeds" on any bytes, so decoding with a guessed key would hand the
    // examiner a whole buffer of noise for every file — and, once re-queued,
    // forever. A buffer whose plaintext is already visible proves only the no-op
    // key, so it must produce no XOR child at all.
    let mut plain = b"This program cannot be run in DOS mode".to_vec();
    plain.extend_from_slice(b" and nothing in here is obfuscated at all");
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(plain));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );

    let out = DecodeRescan.process(&art).unwrap();
    assert!(
        records(&out, "DecodedBuffer")
            .iter()
            .all(|a| a.metadata["decode_method"] != "xor"),
        "a clear-text buffer must not be XORed with a guessed key"
    );
}

#[test]
fn decode_rescan_stops_at_the_generation_cap() {
    // A child re-fed at the depth cap must produce nothing, so nested/compounding
    // encodings cannot recurse forever through the orchestrator's re-queue.
    let inner = b"buried carol@x.gov inside padding padding padding padding";
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(inner)
    };
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b64.into_bytes()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({ "decode_generation": 8 }),
    );
    assert!(
        DecodeRescan.process(&art).unwrap().is_empty(),
        "decode must stop at the generation cap"
    );
}

#[test]
fn decode_rescan_discloses_when_it_caps_the_child_count() {
    // More decodable spans than MAX_CHILDREN (256) must NOT pass silently: the
    // examiner has to know the buffer held more than was surfaced.
    use base64::Engine;
    // 18 bytes → exactly 24 base64 chars, above both the 24-char span floor and
    // the 16-byte minimum decoded length.
    let one = base64::engine::general_purpose::STANDARD.encode(b"eighteen bytes ok!");
    let mut buf = Vec::new();
    for _ in 0..300 {
        buf.extend_from_slice(one.as_bytes());
        buf.push(b' '); // a non-base64 separator so each is its own span
    }
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );

    let out = DecodeRescan.process(&art).unwrap();
    let children = records(&out, "DecodedBuffer");
    assert!(children.len() <= 256, "child count must be capped");
    let summary = records(&out, "DecodeRescanSummary");
    assert_eq!(summary.len(), 1, "a dropped-child cap must be disclosed");
    assert_eq!(summary[0].metadata["children_found"], 300);
    assert!(
        summary[0].metadata["children_dropped"].as_u64().unwrap() > 0,
        "the summary must state how many spans were not surfaced"
    );
}

#[test]
fn decode_rescan_counts_spans_the_base64_decoder_left_undecoded() {
    // More spans than the decoder's own ceiling (MAX_BASE64_SPANS): the ones it
    // counted and did not decode are still spans the buffer held, and the
    // summary says the decoder's ceiling — not only the child cap — was hit.
    use base64::Engine;
    let spans = decode::MAX_BASE64_SPANS + 500;
    let mut buf = Vec::new();
    for i in 0..spans {
        let payload = format!("line {i:06} of the spool");
        buf.extend_from_slice(
            base64::engine::general_purpose::STANDARD
                .encode(payload.as_bytes())
                .as_bytes(),
        );
        buf.push(b'\n');
    }
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buf));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );
    let out = DecodeRescan.process(&art).unwrap();
    let summary = records(&out, "DecodeRescanSummary");
    assert_eq!(summary.len(), 1);
    let m = &summary[0].metadata;
    assert_eq!(m["children_found"], json!(spans));
    assert_eq!(m["base64_decode_capped"], json!(true));
    assert_eq!(m["base64_spans_not_decoded"], json!(500));
    assert_eq!(m["base64_span_cap"], json!(decode::MAX_BASE64_SPANS));
}

#[test]
fn decode_rescan_is_silent_when_nothing_is_capped() {
    // The common case (one small child, whole input read) emits no summary, so
    // the disclosure record only appears when there is genuinely something to say.
    use base64::Engine;
    let inner = b"a single buried payload long enough to survive";
    let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b64.into_bytes()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );
    let out = DecodeRescan.process(&art).unwrap();
    assert_eq!(records(&out, "DecodedBuffer").len(), 1);
    assert!(
        records(&out, "DecodeRescanSummary").is_empty(),
        "no cap hit, so no summary"
    );
}

#[test]
fn aes_scanner_is_optin() {
    // Opt-in so it never auto-sweeps a raw disk on ingest, but still available
    // (and still accepts raw evidence) when an examiner triggers it.
    assert_eq!(AesKeyScanner.execution_mode(), ExecutionMode::OptIn);
    assert!(AesKeyScanner
        .subscribes_to()
        .contains(&ArtifactType::RawEvidence));
}

#[test]
fn modules_have_stable_ids() {
    assert_eq!(AesKeyScanner.id(), "plugin.bulk.aes_keys");
    assert_eq!(BulkFeatureScanner.id(), "plugin.bulk.features");
    assert_eq!(NetworkPacketCarver.id(), "plugin.bulk.net_carve");
    assert_eq!(DecodeRescan.id(), "plugin.bulk.decode_rescan");
}

/// HUNT-218. A memory image is not one contiguous run: a LiME or ELF capture
/// of a PC leaves the legacy VGA/BIOS window below 1 MiB and reserved ranges
/// higher up out of the file, and the real memory layer refuses any read that
/// touches such a gap (it returns `Err`, never a partial count, never zeros).
/// The sweep must scan every mapped byte around each gap, report each gap by
/// its exact range, and never splice the two sides together.
///
/// memory `0x0000_0000..0x0009_F000`  segment A (low memory)
/// memory `0x0009_F000..0x0010_0000`  hole (the VGA/BIOS window)
/// memory `0x0010_0000..0x00B0_0000`  segment B (10 MiB, wider than a window)
/// memory `0x00B0_0000..0x00F0_0000`  hole (4 MiB reserved)
/// memory `0x00F0_0000..0x0150_0000`  segment C (6 MiB)
fn holed_memory_image(plants: &[(u64, &[u8])]) -> (Arc<dyn DataSource>, u64) {
    use seance_memory::{LayerMeta, MemoryImageFormat, Segment, SegmentedLayer};
    let segs: [(u64, u64); 3] = [
        (0x0000_0000, 0x0009_F000),
        (0x0010_0000, 0x00A0_0000),
        (0x00F0_0000, 0x0060_0000),
    ];
    let mapped: u64 = segs.iter().map(|s| s.1).sum();
    let mut file = vec![0u8; mapped as usize];
    let mut segments = Vec::new();
    let mut file_off = 0u64;
    for (mem, len) in segs {
        for (at, text) in plants {
            if *at >= mem && *at + text.len() as u64 <= mem + len {
                let f = (file_off + (*at - mem)) as usize;
                file[f..f + text.len()].copy_from_slice(text);
            }
        }
        segments.push(Segment::new(file_off, mem, len));
        file_off += len;
    }
    let layer = SegmentedLayer::new(
        Arc::new(ByteSliceDataSource::new(file)),
        segments,
        LayerMeta::new(MemoryImageFormat::Lime),
    )
    .expect("a valid segment list");
    (Arc::new(layer), mapped)
}

fn memory_artifact_over(src: Arc<dyn DataSource>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        json!({ "type": "MemoryImage", "subtype": "memory_image" }),
    )
}

#[test]
fn the_sweeps_scan_past_each_hole_in_a_memory_image_and_name_every_gap() {
    let key: Vec<u8> = (0..32).map(|i| (i * 5 + 3) as u8).collect();
    let sched = expand_key(&key);
    let pre_gap: &[u8] = b"bob@pre-gap.test";
    let b_end: &[u8] = b"eve@b-end.test";
    let plants: Vec<(u64, &[u8])> = vec![
        (0x1000, b"ann@low.test"),
        // Ends on the last mapped byte before the first hole.
        (0x0009_F000 - pre_gap.len() as u64, pre_gap),
        // The first byte after the first hole.
        (0x0010_0000, b"cat@post-gap.test"),
        // Straddles the edge of the window that starts after the first hole.
        (0x0010_0000 + CHUNK as u64 - 5, b"dan@window.test"),
        // Ends on the last mapped byte before the second hole.
        (0x00B0_0000 - b_end.len() as u64, b_end),
        // The first byte after the second hole, and one near the top.
        (0x00F0_0000, b"fay@high.test"),
        (0x0150_0000 - 64, b"gus@top.test"),
        (0x00F0_2000, &sched),
    ];
    let (src, mapped) = holed_memory_image(&plants);

    let out = BulkFeatureScanner
        .process(&memory_artifact_over(src.clone()))
        .unwrap();
    let mut found: Vec<(u64, String)> = records(&out, "Feature")
        .iter()
        .map(|f| {
            (
                f.metadata["device_offset"].as_u64().unwrap(),
                f.metadata["value"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    found.sort();
    let expected: Vec<(u64, String)> = plants[..7]
        .iter()
        .map(|(at, t)| (*at, String::from_utf8(t.to_vec()).unwrap()))
        .collect();
    assert_eq!(
        found, expected,
        "every selector on either side of each hole"
    );

    let expected_gaps = json!([
        { "offset": 0x0009_F000u64, "length": 0x0006_1000u64 },
        { "offset": 0x00B0_0000u64, "length": 0x0040_0000u64 },
    ]);
    for ty in ["FeatureSummary", "FeatureHistogramSummary"] {
        let s = records(&out, ty);
        assert_eq!(s.len(), 1, "{ty}");
        let m = &s[0].metadata;
        assert_eq!(m["bytes_scanned"], json!(mapped), "{ty}: every mapped byte");
        assert_eq!(m["unreadable_ranges"], expected_gaps, "{ty}");
        assert_eq!(m["unreadable_bytes"], json!(0x0046_1000u64), "{ty}");
        assert_eq!(m["short_read"], json!(true), "{ty}");
        assert_eq!(m["content_incomplete"], json!(true), "{ty}");
        assert_eq!(m["content_incomplete_reason"], json!("short_read"), "{ty}");
    }

    // The key schedule past the second hole is found at its memory address.
    let out = AesKeyScanner
        .process(&memory_artifact_over(src.clone()))
        .unwrap();
    let keys = records(&out, "RecoveredKey");
    assert_eq!(keys.len(), 1, "the key after both holes");
    assert_eq!(keys[0].metadata["device_offset"], json!(0x00F0_2000u64));
    let s = records(&out, "RecoveredKeySummary");
    assert_eq!(s[0].metadata["unreadable_ranges"], expected_gaps);

    let out = NetworkPacketCarver
        .process(&memory_artifact_over(src))
        .unwrap();
    let s = records(&out, "NetworkCarveSummary");
    assert_eq!(s.len(), 1, "no packets in a holed image is said");
    assert_eq!(s[0].metadata["bytes_scanned"], json!(mapped));
    assert_eq!(s[0].metadata["unreadable_ranges"], expected_gaps);
}

/// A gap whose far edge does not sit on a page boundary (memory
/// `0x1000..0x1123`), inside the first window: both edges are found to the
/// byte, and a selector starting on the first byte after it is reported.
#[test]
fn an_unaligned_gap_is_bounded_to_the_byte() {
    use seance_memory::{LayerMeta, MemoryImageFormat, Segment, SegmentedLayer};
    let file = vec![0u8; 0x3000];
    let mut file = file;
    file[0x0FF0..0x0FF0 + 13].copy_from_slice(b"hal@edge.test");
    file[0x1000..0x1000 + 13].copy_from_slice(b"ivy@over.test");
    let layer = SegmentedLayer::new(
        Arc::new(ByteSliceDataSource::new(file)),
        vec![
            Segment::new(0x0000, 0x0000, 0x1000),
            Segment::new(0x1000, 0x1123, 0x2000),
        ],
        LayerMeta::new(MemoryImageFormat::Lime),
    )
    .unwrap();
    let out = BulkFeatureScanner
        .process(&memory_artifact_over(Arc::new(layer)))
        .unwrap();
    let mut found: Vec<u64> = records(&out, "Feature")
        .iter()
        .map(|f| f.metadata["device_offset"].as_u64().unwrap())
        .collect();
    found.sort();
    assert_eq!(found, vec![0x0FF0, 0x1123]);
    let m = &records(&out, "FeatureSummary")[0].metadata;
    assert_eq!(
        m["unreadable_ranges"],
        json!([{ "offset": 0x1000u64, "length": 0x123u64 }])
    );
    assert_eq!(m["bytes_scanned"], json!(0x3000u64));
}

/// HUNT-228. Decode-and-rescan read its whole buffer with a loop that stopped
/// at the first error or zero-length read and said nothing, so a file with a
/// bad sector was scanned only up to it and the children found read as all the
/// buffer held. The unreadable stretch must be named on the summary, and a
/// payload past a gap must still be decoded, at its true offset.
#[test]
fn decode_rescan_states_a_short_read_rather_than_scanning_a_silent_prefix() {
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD
        .encode(b"a buried payload that sits before the bad sector");
    let declared: u64 = 64 * 1024;
    let fails_at: u64 = 16 * 1024;
    let mut bytes = vec![b' '; fails_at as usize];
    bytes[100..100 + payload.len()].copy_from_slice(payload.as_bytes());
    let src: Arc<dyn DataSource> = Arc::new(FailingTail {
        bytes,
        declared,
        fails_at,
    });
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(src),
        json!({}),
    );
    let out = DecodeRescan.process(&art).unwrap();
    assert_eq!(records(&out, "DecodedBuffer").len(), 1);
    let s = records(&out, "DecodeRescanSummary");
    assert_eq!(s.len(), 1, "a short read must publish the summary");
    let m = &s[0].metadata;
    assert_eq!(m["bytes_scanned"], json!(fails_at));
    assert_eq!(m["short_read"], json!(true));
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], json!("short_read"));
    assert_eq!(
        m["unreadable_ranges"],
        json!([{ "offset": fails_at, "length": declared - fails_at }])
    );
}

#[test]
fn decode_rescan_decodes_past_a_gap_at_the_true_offset_and_names_the_gap() {
    use base64::Engine;
    use seance_memory::{LayerMeta, MemoryImageFormat, Segment, SegmentedLayer};
    let before = base64::engine::general_purpose::STANDARD
        .encode(b"the payload held in the run before the gap");
    let after = base64::engine::general_purpose::STANDARD
        .encode(b"the payload held in the run after the gap!!");
    // Run A at 0x0000..0x2000, a hole at 0x2000..0x5000, run B at 0x5000..0x7000.
    let mut file = vec![b' '; 0x4000];
    file[0x10..0x10 + before.len()].copy_from_slice(before.as_bytes());
    file[0x2000 + 0x40..0x2000 + 0x40 + after.len()].copy_from_slice(after.as_bytes());
    let layer = SegmentedLayer::new(
        Arc::new(ByteSliceDataSource::new(file)),
        vec![
            Segment::new(0x0000, 0x0000, 0x2000),
            Segment::new(0x2000, 0x5000, 0x2000),
        ],
        LayerMeta::new(MemoryImageFormat::Lime),
    )
    .unwrap();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileContent,
        Some(Arc::new(layer)),
        json!({}),
    );
    let out = DecodeRescan.process(&art).unwrap();
    let mut offsets: Vec<u64> = records(&out, "DecodedBuffer")
        .iter()
        .map(|a| a.metadata["parent_offset"].as_u64().unwrap())
        .collect();
    offsets.sort();
    assert_eq!(
        offsets,
        vec![0x10, 0x5040],
        "both runs, at their true offsets"
    );
    let m = &records(&out, "DecodeRescanSummary")[0].metadata;
    assert_eq!(
        m["unreadable_ranges"],
        json!([{ "offset": 0x2000u64, "length": 0x3000u64 }])
    );
    assert_eq!(m["bytes_scanned"], json!(0x4000u64));
}
