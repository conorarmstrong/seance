//! The new surfaces over real evidence, as the producing parsers publish it.
//!
//! Each fixture is a file a third party made, read by the parser that owns
//! it, and the artifacts that parser emits are what is handed to this module —
//! so the shapes scanned here are the product's, not a reading of its code.
//!
//! | Gate | Fixture | Surface |
//! |---|---|---|
//! | `SEANCE_HACKSHAW_CORPUS` | `HD001_MFT.dat`, a real `$MFT` (35.8 MiB) whose records hold 216 named `$DATA` streams, 191 of them `Zone.Identifier` marks written by a browser on download | ADS |
//! | `SEANCE_REGISTRY_CORPUS` | `NTUSER.DAT`, a real user hive of 5,602 values across six value types | registry values |
//! | `test_data/dftt/9-fat-label/…/9-fat-label.dd` | DFTT #9, a 10 MB FAT16 volume | unallocated |
//!
//! Absent, each skips and says so; named and missing, it fails — see
//! [`seance_core::test_support::corpus`]. Locally the first two are
//! `reference/hackshaw/test_data` and `reference/plaso/test_data`.

use super::*;
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::test_support::corpus;
use std::sync::Arc;
use tempfile::TempDir;

fn scanner_with(rules: &str) -> (TempDir, YaraScanner) {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("r.yar"), rules).expect("write rules");
    let scanner = YaraScanner::from_rule_path(dir.path()).expect("rules must load");
    (dir, scanner)
}

fn file_artifact(path: &std::path::Path, artifact_type: ArtifactType) -> Artifact {
    let ds: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path.to_path_buf()).expect("open fixture"));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Artifact::new(
        Uuid::new_v4(),
        artifact_type,
        Some(ds),
        json!({ "name": name, "path": path.to_string_lossy() }),
    )
}

fn records_of<'a>(out: &'a [Artifact], kind: &str) -> Vec<&'a Artifact> {
    out.iter().filter(|a| a.metadata["type"] == kind).collect()
}

/// **Alternate data streams from a real `$MFT`.** Every `Zone.Identifier`
/// stream a browser wrote on download begins `[ZoneTransfer]`; a rule for
/// that string must fire on exactly the streams whose bytes carry it, every
/// hit must say it is in a stream and name which, and no hit may be stamped
/// as the base file's own content.
///
/// The expected count is measured independently: the streams' bytes are
/// read back through their own data sources and tested for the string, so
/// the assertion is against the evidence rather than against this module.
///
/// A bare `$MFT` has no volume behind it, so only streams stored resident in
/// their record carry real bytes; a non-resident stream's runs point into a
/// volume this fixture does not include. The resident streams — the ones the
/// $MFT parser published with `resident_data_b64` — are what is scanned and
/// counted. One non-resident stream is scanned too, to pin the other half:
/// a stream whose bytes the fixture cannot serve is reported **not scanned**,
/// never as scanned and clean.
#[test]
fn real_ntfs_alternate_data_streams_are_scanned_as_ads_and_named() {
    let Some(path) = corpus::file("SEANCE_HACKSHAW_CORPUS", "HD001_MFT.dat") else {
        return;
    };
    let produced = seance_plugin_mft::MftParser::new()
        .process(&file_artifact(&path, ArtifactType::FileEntry))
        .expect("the $MFT parses");
    const STREAM_CAP: u64 = 1 << 20;
    let is_stream = |a: &&Artifact| {
        a.artifact_type == ArtifactType::FileEntry && a.metadata["is_ads"] == json!(true)
    };
    let streams: Vec<&Artifact> = produced
        .iter()
        .filter(is_stream)
        .filter(|a| a.metadata.get("resident_data_b64").is_some() && a.data.is_some())
        .collect();
    assert_eq!(
        streams.len(),
        204,
        "this $MFT holds 216 named $DATA streams, 204 of them resident"
    );

    // Ground truth from the bytes themselves.
    let expected: usize = streams
        .iter()
        .filter(|a| {
            let bytes = read_capped(a.data.as_ref().unwrap().as_ref(), STREAM_CAP);
            bytes
                .windows(b"[ZoneTransfer]".len())
                .any(|w| w == b"[ZoneTransfer]")
        })
        .count();
    assert_eq!(
        expected, 191,
        "191 Zone.Identifier streams carry the mark, counted by hand off the records"
    );

    let (_dir, scanner) = scanner_with(
        r#"rule zone_transfer : ads { strings: $z = "[ZoneTransfer]" condition: $z }"#,
    );
    let mut hits = 0usize;
    let mut regions = 0usize;
    for stream in &streams {
        let out = scanner.process(stream).expect("scan");
        for rec in &out {
            assert_eq!(
                rec.metadata["surface"], "ads",
                "every record about a stream is stamped as a stream: {rec:?}"
            );
            assert_eq!(
                rec.metadata["stream_name"], stream.metadata["stream_name"],
                "the record names the stream it is about"
            );
            assert_eq!(rec.metadata["base_file"], stream.metadata["parent_file"]);
            assert_eq!(rec.parent_id, Some(stream.id));
        }
        for m in records_of(&out, "YaraMatch") {
            hits += 1;
            assert_eq!(m.metadata["rule"], "zone_transfer");
            assert_eq!(m.metadata["stream_name"], "Zone.Identifier");
            assert_eq!(
                m.metadata["pattern_matches"][0]["offset_in_region"],
                json!(0u64)
            );
            assert_eq!(
                m.metadata["entropy_bytes"],
                json!(stream.data.as_ref().unwrap().size()),
                "entropy over the whole resident stream"
            );
        }
        let region = records_of(&out, "YaraRegionScanned");
        assert_eq!(
            region.len(),
            1,
            "one region record per stream scanned: {out:?}"
        );
        assert_eq!(region[0].metadata["scan_complete"], json!(true));
        regions += 1;
        assert!(
            records_of(&out, "YaraNotScanned").is_empty()
                && records_of(&out, "YaraScanError").is_empty(),
            "{out:?}"
        );
    }
    assert_eq!(regions, streams.len());
    assert_eq!(
        hits, expected,
        "the rule fired on exactly the streams that carry the string"
    );

    // The other half. `$Tops:$T` is a 1 MiB non-resident stream of the
    // transaction log; its runs name clusters of a volume this fixture does
    // not hold, so the parser's data source serves nothing for it. That must
    // come back as "not scanned", stamped as the stream it is about.
    let unreachable = produced
        .iter()
        .filter(is_stream)
        .find(|a| a.metadata["stream_name"] == "$T" && a.metadata["parent_file"] == "$Tops")
        .expect("the $TxfLog $Tops:$T stream is in this $MFT");
    let out = scanner.process(unreachable).expect("scan");
    let not_scanned = records_of(&out, "YaraNotScanned");
    assert_eq!(not_scanned.len(), 1, "{out:?}");
    assert_eq!(not_scanned[0].metadata["surface"], "ads");
    assert_eq!(not_scanned[0].metadata["stream_name"], "$T");
    assert_eq!(not_scanned[0].metadata["declared_size"], json!(1u64 << 20));
    assert!(
        records_of(&out, "YaraRegionScanned").is_empty()
            && records_of(&out, "YaraMatch").is_empty(),
        "a stream that could not be read is not reported as looked at: {out:?}"
    );
    eprintln!(
        "  HD001 $MFT: {} streams scanned, {hits} Zone.Identifier hits, all stamped ads",
        streams.len()
    );
}

/// **Registry values from a real user hive.** The hive record the registry
/// parser publishes is handed over whole; every value it reproduces is
/// scanned, every value it cannot is counted by reason, and the two sum to
/// the hive's inventory. A wide-string rule fires only on values whose
/// published rendering carries the text — checked value by value against
/// the inventory the hit names — and a narrow rule for the same text fires
/// nowhere, because a REG_SZ is UTF-16 and a scan that found it narrow would
/// be scanning bytes the hive does not hold.
#[test]
fn real_ntuser_hive_values_are_scanned_from_what_the_hive_record_publishes() {
    let Some(path) = corpus::file("SEANCE_REGISTRY_CORPUS", "NTUSER.DAT") else {
        return;
    };
    let produced = seance_plugin_registry::RegistryParser
        .process(&file_artifact(&path, ArtifactType::FileEntry))
        .expect("the hive parses");
    let hive = produced
        .iter()
        .find(|a| a.metadata["type"] == "RegistryHive")
        .expect("the hive record");
    let values = hive.metadata["all_values"]
        .as_array()
        .expect("the value inventory");
    assert_eq!(
        values.len(),
        5602,
        "the hive's inventory, counted off the record"
    );

    let (_dir, scanner) = scanner_with(
        r#"
rule microsoft_wide { strings: $m = "Microsoft" wide condition: $m }
rule microsoft_narrow { strings: $m = "Microsoft" ascii condition: $m }
"#,
    );
    let out = scanner.process(hive).expect("scan");
    let cov = records_of(&out, "YaraRegistryCoverage");
    assert_eq!(cov.len(), 1, "one coverage record per hive");
    let c = &cov[0].metadata;
    assert_eq!(c["hive_type"], hive.metadata["hive_type"]);
    assert_eq!(c["values_total"], json!(5602));
    let scanned = c["values_scanned"].as_u64().unwrap();
    let not_scanned = c["values_not_scanned"].as_u64().unwrap();
    assert_eq!(
        scanned + not_scanned,
        5602,
        "every value is either scanned or counted as not: {c}"
    );
    assert_eq!(c["values_engine_error"], json!(0));
    assert_eq!(c["byte_budget_reached"], json!(false));
    assert!(
        scanned > 5000,
        "a user hive is DWORDs, strings and small binaries, nearly all reproducible: {c}"
    );
    eprintln!(
        "  NTUSER.DAT: {scanned} values scanned ({} exact, {} re-encoded), {not_scanned} not: {}",
        c["values_scanned_exact"], c["values_scanned_reencoded"], c["not_scanned_reasons"]
    );

    let wide = records_of(&out, "YaraMatch")
        .into_iter()
        .filter(|m| m.metadata["rule"] == "microsoft_wide")
        .collect::<Vec<_>>();
    assert!(
        !wide.is_empty(),
        "a user hive names Microsoft in its strings"
    );
    for m in &wide {
        let meta = &m.metadata;
        assert_eq!(meta["surface"], "registry_value");
        assert_eq!(meta["hive_type"], hive.metadata["hive_type"]);
        let named = values
            .iter()
            .find(|v| v["key_path"] == meta["key_path"] && v["value_name"] == meta["value_name"])
            .unwrap_or_else(|| panic!("the hit names a value the inventory holds: {meta}"));
        assert_eq!(meta["value_type"], named["value_type"]);
        assert_eq!(meta["raw_data_size"], named["raw_data_size"]);
        match meta["value_bytes_basis"].as_str().unwrap() {
            "reencoded_utf16le" => {
                assert!(
                    named["value_data"].as_str().unwrap().contains("Microsoft"),
                    "a re-encoded hit is a hit in the published text: {named}"
                );
                assert!(
                    named["value_type"].as_str().unwrap().contains("SZ"),
                    "only string types are re-encoded: {named}"
                );
            }
            "exact" => {
                let bytes = registry_value_bytes(named).expect("reproducible").0;
                let wide_needle: Vec<u8> = "Microsoft"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                assert!(
                    bytes.windows(wide_needle.len()).any(|w| w == wide_needle),
                    "an exact hit is in the reproduced bytes: {named}"
                );
            }
            other => panic!("unknown basis {other}"),
        }
        assert!(meta["entropy_bytes"].as_u64().unwrap() > 0);
    }
    let narrow = records_of(&out, "YaraMatch")
        .into_iter()
        .filter(|m| m.metadata["rule"] == "microsoft_narrow")
        .count();
    assert_eq!(
        narrow, 0,
        "a REG_SZ is UTF-16; a narrow hit would mean bytes the hive does not hold were scanned"
    );
    eprintln!("  NTUSER.DAT: {} wide hits, {narrow} narrow", wide.len());
}

/// **Free space from a real FAT16 volume.** The regions the FAT parser emits
/// from the volume's own allocation table are scanned one by one; each is
/// stamped as unallocated with the offset and basis the region states, its
/// entropy is over every byte the region holds, and a pattern hit is placed
/// in the parent's coordinate space by adding the region's offset.
#[test]
fn real_fat_free_regions_are_scanned_as_unallocated_with_their_offsets() {
    let img = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test_data/dftt/9-fat-label/9-fat-label/9-fat-label.dd");
    if !img.exists() {
        eprintln!("SKIPPED (no corpus): {} is not present", img.display());
        return;
    }
    let produced = seance_plugin_fat::FatParser
        .process(&file_artifact(&img, ArtifactType::FileSystem))
        .expect("the FAT volume parses");
    let regions: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect();
    assert!(
        !regions.is_empty(),
        "a 10 MB volume holding a label has free clusters"
    );

    // A run of zero bytes is what freshly formatted free space is made of;
    // where it is found, the hit is placed on the volume.
    let (_dir, scanner) = scanner_with(
        r#"rule zero_run { strings: $z = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } condition: $z at 0 }"#,
    );
    let mut placed = 0usize;
    for region in &regions {
        let offset = region.metadata["offset_bytes"].as_u64().unwrap();
        let size = region.metadata["size_bytes"].as_u64().unwrap();
        let out = scanner.process(region).expect("scan");
        let rec = records_of(&out, "YaraRegionScanned");
        assert_eq!(rec.len(), 1, "{out:?}");
        let r = &rec[0].metadata;
        assert_eq!(r["surface"], "unallocated");
        assert_eq!(r["region_source"], "allocation_bitmap");
        assert_eq!(r["filesystem"], region.metadata["filesystem"]);
        assert_eq!(r["offset_basis"], region.metadata["offset_basis"]);
        assert_eq!(r["offset_bytes"], json!(offset));
        assert_eq!(
            r["entropy_bytes"],
            json!(size),
            "entropy over the whole region"
        );
        assert_eq!(r["scan_complete"], json!(true));
        for m in records_of(&out, "YaraMatch") {
            assert_eq!(m.metadata["surface"], "unallocated");
            let hit = &m.metadata["pattern_matches"][0];
            assert_eq!(hit["offset_in_region"], json!(0u64));
            assert_eq!(hit["offset_in_parent"], json!(offset));
            assert!(m.metadata["surface_means"]
                .as_str()
                .unwrap()
                .contains("not a match in any live file"));
            placed += 1;
        }
    }
    eprintln!(
        "  DFTT #9: {} free regions scanned, {placed} begin with a zero run",
        regions.len()
    );
}

/// Every rule a DFTT slack keyword needs, one per keyword so a hit names it.
const DFTT_SLACK_RULES: &str = r#"
rule n_slack { strings: $k = "n-slack" condition: $k }
rule k1slack1 { strings: $k = "1slack1" condition: $k }
rule k2slack2 { strings: $k = "2slack2" condition: $k }
rule k3slack3 { strings: $k = "3slack3" condition: $k }
"#;

/// Scan every `SlackSpace` region in `produced`; return each `(rule,
/// base_file, offset_in_parent)` hit, after asserting every record says
/// `slack`, was read whole, and carries the region's own offset and basis.
fn slack_hits(produced: &[Artifact], scanner: &YaraScanner) -> (usize, Vec<(String, String, u64)>) {
    let regions: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
        .collect();
    let mut hits = Vec::new();
    for region in &regions {
        let out = scanner.process(region).expect("scan");
        assert!(records_of(&out, "YaraNotScanned").is_empty(), "{out:?}");
        let rec = records_of(&out, "YaraRegionScanned");
        assert_eq!(rec.len(), 1, "{out:?}");
        assert_eq!(rec[0].metadata["surface"], "slack");
        assert_eq!(rec[0].metadata["scan_complete"], json!(true));
        assert_eq!(
            rec[0].metadata["offset_bytes"],
            region.metadata["offset_bytes"]
        );
        assert_eq!(
            rec[0].metadata["offset_basis"],
            region.metadata["offset_basis"]
        );
        for m in records_of(&out, "YaraMatch") {
            assert_eq!(m.metadata["surface"], "slack");
            for hit in m.metadata["pattern_matches"].as_array().unwrap() {
                hits.push((
                    m.metadata["rule"].as_str().unwrap().to_string(),
                    m.metadata["base_file"].as_str().unwrap_or("").to_string(),
                    hit["offset_in_parent"]
                        .as_u64()
                        .expect("a slack hit is placed in the file system"),
                ));
            }
        }
    }
    (regions.len(), hits)
}

/// A DFTT image under `test_data`, or `None` — announced as a skip — when the
/// corpus is not provisioned. `test_data` is outside git, so a runner without
/// it would otherwise report these grades green having read nothing:
/// `SEANCE_REQUIRE_CORPUS=1` (the workspace's convention,
/// `seance_core::test_support::corpus`) turns the skip into a failure.
fn dftt_image(relative: &str) -> Option<std::path::PathBuf> {
    let img = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    let required = std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty());
    dftt_decide(img, required)
}

/// The skip-or-fail decision, with the environment passed in so it can be
/// tested without mutating the process environment.
fn dftt_decide(img: std::path::PathBuf, required: bool) -> Option<std::path::PathBuf> {
    if img.exists() {
        return Some(img);
    }
    assert!(
        !required,
        "{} is not present, but SEANCE_REQUIRE_CORPUS demands it. This run would have \
         reported a grade having read no evidence.",
        img.display()
    );
    eprintln!("SKIPPED (no corpus): {} is not present", img.display());
    None
}

#[test]
#[should_panic(expected = "SEANCE_REQUIRE_CORPUS")]
fn a_missing_dftt_image_fails_when_the_corpus_is_required() {
    dftt_decide(std::path::PathBuf::from("/nonexistent/dftt.dd"), true);
}

#[test]
fn a_missing_dftt_image_skips_when_the_corpus_is_not_required() {
    assert!(dftt_decide(std::path::PathBuf::from("/nonexistent/dftt.dd"), false).is_none());
}

/// **YARA over file slack, graded on DFTT #3 (NTFS).** The image's own
/// `index.html` places `n-slack` at sector 8062, offset 485, "Slack space of
/// a non-resident allocated file" (`file-n-4.dat`). The image is a whole
/// volume with no partition table, so the file-system offset each hit
/// carries is the image offset the table publishes. Real evidence, a third
/// party's ground truth: the hit must be reported exactly once, as slack,
/// naming that file, at that offset.
#[test]
fn dftt3_n_slack_is_found_once_in_slack_at_its_published_offset() {
    let Some(img) = dftt_image("../test_data/dftt/3-kwsrch-ntfs/3-kwsrch-ntfs/ntfs-img-kw-1.dd")
    else {
        return;
    };
    let mut fs = file_artifact(&img, ArtifactType::FileSystem);
    fs.metadata["filesystem_type"] = json!("NTFS");
    let produced = seance_plugin_mft::MftParser::new()
        .process(&fs)
        .expect("the NTFS volume parses");
    let (_dir, scanner) = scanner_with(DFTT_SLACK_RULES);
    let (regions, hits) = slack_hits(&produced, &scanner);
    let n: Vec<_> = hits.iter().filter(|h| h.0 == "n_slack").collect();
    assert_eq!(n.len(), 1, "{hits:?}");
    assert_eq!(n[0].1, "file-n-4.dat");
    assert_eq!(n[0].2, 8062 * 512 + 485);
    eprintln!(
        "  DFTT #3: {regions} slack regions scanned, {} hit(s)",
        hits.len()
    );
}

/// **YARA over file slack, graded on DFTT #2 (FAT).** Published: `3slack3`
/// at sector 277, offset 385, wholly in `file4.dat`'s slack; `1slack1`
/// (272/396) crossing from a file's content into its slack; and `2slack2`
/// (274/508) crossing from `file3.dat`'s slack into the next cluster. The
/// first is found once, as slack, at its published offset. The two crossing
/// ones are **not** found in slack: each region is scanned on its own, so a
/// string split at a region boundary is not matched whole — a stated limit,
/// pinned here rather than hidden, and the surface's own statement says it.
/// A `volume` scan of the whole image does find all three.
#[test]
fn dftt2_3slack3_is_found_in_slack_and_the_crossing_keywords_are_not() {
    let Some(img) = dftt_image("../test_data/dftt/2-kwsrch-fat/2-kwsrch-fat/fat-img-kw.dd") else {
        return;
    };
    let fs = file_artifact(&img, ArtifactType::FileSystem);
    let produced = seance_plugin_fat::FatParser
        .process(&fs)
        .expect("the FAT volume parses");
    let (_dir, scanner) = scanner_with(DFTT_SLACK_RULES);
    let (regions, hits) = slack_hits(&produced, &scanner);
    let k3: Vec<_> = hits.iter().filter(|h| h.0 == "k3slack3").collect();
    assert_eq!(k3.len(), 1, "{hits:?}");
    assert!(k3[0].1.eq_ignore_ascii_case("file4.dat"), "{:?}", k3[0]);
    assert_eq!(k3[0].2, 277 * 512 + 385);
    for crossing in ["k1slack1", "k2slack2"] {
        assert!(
            hits.iter().all(|h| h.0 != crossing),
            "{crossing} straddles a region boundary and cannot be matched whole in slack: {hits:?}"
        );
    }
    assert!(Surface::Slack.statement().contains("split"));

    // The whole volume, scanned as one region, finds every keyword.
    let out = scanner.process(&fs).expect("volume scan");
    for (rule, at) in [
        ("k1slack1", 272 * 512 + 396),
        ("k2slack2", 274 * 512 + 508),
        ("k3slack3", 277 * 512 + 385),
    ] {
        let m: Vec<_> = records_of(&out, "YaraMatch")
            .into_iter()
            .filter(|m| m.metadata["rule"] == rule)
            .collect();
        assert_eq!(m.len(), 1, "{rule}: {out:?}");
        assert_eq!(m[0].metadata["surface"], "volume");
        let offsets: Vec<u64> = m[0].metadata["pattern_matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["offset_in_region"].as_u64().unwrap())
            .collect();
        assert!(offsets.contains(&(at as u64)), "{rule}: {offsets:?}");
    }
    eprintln!(
        "  DFTT #2: {regions} slack regions scanned, {} hit(s)",
        hits.len()
    );
}
