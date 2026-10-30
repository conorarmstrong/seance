//! The UDF partition kinds and sector sizes on committed, self-made images
//! (see `tests/fixtures/README.md`). They run in every build. They pin the
//! mechanisms on volumes another writer produced; they are not validation
//! on real evidence.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_partition::FilesystemDetector;
use seance_plugin_udf::UdfParser;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn gunzip(name: &str) -> Vec<u8> {
    let f = std::fs::File::open(fixtures().join(name)).expect("fixture");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(f)
        .read_to_end(&mut out)
        .expect("gunzip");
    out
}

fn answer_key() -> BTreeMap<String, String> {
    std::fs::read_to_string(fixtures().join("lean_payload.sha256"))
        .expect("answer key")
        .lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, p)| (p.trim_start_matches('.').to_string(), h.to_string()))
        .collect()
}

fn sha256_of(a: &Artifact) -> String {
    let ds = a.data.as_ref().expect("content attached");
    let mut buf = vec![0u8; ds.size() as usize];
    let mut off = 0;
    while off < buf.len() {
        let n = ds.read_at(off as u64, &mut buf[off..]).expect("read");
        assert!(n > 0, "short read at {off}");
        off += n;
    }
    Sha256::digest(&buf)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read(name: &str) -> (Vec<Artifact>, serde_json::Value) {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(gunzip(name)));
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": name }),
    );
    let fs = FilesystemDetector.process(&raw).expect("detect");
    let udf = fs
        .iter()
        .find(|a| a.metadata["subtype"].as_str() == Some("udf"))
        .unwrap_or_else(|| panic!("{name}: partition layer found no UDF"));
    let out = UdfParser.process(udf).expect("udf");
    let vol = out
        .iter()
        .find(|a| a.metadata["type"].as_str() == Some("udf_volume"))
        .expect("volume record")
        .metadata
        .clone();
    (out, vol)
}

#[test]
fn each_partition_kind_and_sector_size_reads_the_payload_exactly() {
    let key = answer_key();
    assert_eq!(key.len(), 5);
    for (name, kinds, bs, rev) in [
        (
            "lean_vat_cdr_udf150.img.gz",
            &["physical", "virtual"][..],
            2048,
            "1.50",
        ),
        (
            "lean_vat_dvdr_udf201.img.gz",
            &["physical", "virtual"],
            2048,
            "2.01",
        ),
        (
            "lean_sparable_dvdrw_udf201.img.gz",
            &["sparable"],
            2048,
            "2.01",
        ),
        (
            "lean_metadata_bdre_udf250.img.gz",
            &["physical", "metadata"],
            2048,
            "2.50",
        ),
        (
            "lean_metadata_disk_udf250_512.img.gz",
            &["physical", "metadata"],
            512,
            "2.50",
        ),
        (
            "lean_plain_disk_udf201_4k.img.gz",
            &["physical"],
            4096,
            "2.01",
        ),
    ] {
        let (out, vol) = read(name);
        assert!(vol.get("udf_unreadable").is_none(), "{name}: {vol}");
        assert!(
            vol.get("directory_parse_incomplete").is_none(),
            "{name}: {vol}"
        );
        assert_eq!(vol["partition_map_kinds"], json!(kinds), "{name}");
        assert_eq!(vol["block_size"], json!(bs), "{name}");
        assert_eq!(vol["udf_revision"], json!(rev), "{name}");
        let files: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        for (path, hash) in &key {
            let a = files
                .iter()
                .find(|a| a.metadata["path"].as_str() == Some(path.as_str()))
                .unwrap_or_else(|| panic!("{name}: no {path}"));
            assert!(
                a.metadata.get("content_incomplete").is_none(),
                "{name}: {path}"
            );
            assert_eq!(&sha256_of(a), hash, "{name}: {path}");
        }
        // Five files and three directories; the root has no entry.
        assert_eq!(files.len(), 8, "{name}");
    }
}

#[test]
fn vat_volumes_name_where_the_table_was_and_its_form() {
    let (_, v150) = read("lean_vat_cdr_udf150.img.gz");
    assert_eq!(v150["vat_form"], "1.50");
    let (_, v201) = read("lean_vat_dvdr_udf201.img.gz");
    assert_eq!(v201["vat_form"], "2.00+");
    // The 2.00+ header carries counts; they agree with the payload
    // (five files; four directories counting the root).
    assert_eq!(v201["vat_number_of_files"], 5);
    assert_eq!(v201["vat_number_of_directories"], 4);
    for v in [&v150, &v201] {
        assert!(v["vat_block"].is_u64());
        assert!(v.get("partition_extends_past_evidence").is_none());
        assert_eq!(v["partition_unrecorded_after_vat"], true);
    }
}

#[test]
fn empty_closed_vat_volume_from_a_second_writer_reads_as_empty() {
    let (out, vol) = read("mkudffs_vat_cdr_udf150_empty.img.gz");
    assert!(vol.get("udf_unreadable").is_none(), "{vol}");
    assert_eq!(vol["vat_form"], "1.50");
    assert_eq!(
        out.iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .count(),
        0
    );
}

#[test]
fn sparable_volume_names_its_tables() {
    let (_, vol) = read("lean_sparable_dvdrw_udf201.img.gz");
    assert_eq!(vol["sparing_packet_length"], 16);
    assert_eq!(vol["sparing_tables_recorded"], 2);
    assert_eq!(vol["sparing_tables_verified"], 2);
    assert_eq!(vol["sparing_relocated_packets"], 0);
}

/// A hybrid ISO 9660 / UDF disc: both halves read, each from its own tree.
/// The image is `lean_metadata_bdre_udf250` with a hand-written ISO 9660 half
/// spliced into its free system-area sectors (see `fixtures/README.md`), so it
/// pins the mechanism; it is not a real authored disc (`UDF-BRIDGE-1` is).
#[test]
fn hybrid_disc_reads_the_iso_half_and_the_udf_half_separately() {
    let name = "hybrid_iso9660_udf250.img.gz";
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(gunzip(name)));
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": name }),
    );
    let fs = FilesystemDetector.process(&raw).expect("detect");
    let subtypes: Vec<&str> = fs
        .iter()
        .map(|a| a.metadata["subtype"].as_str().unwrap())
        .collect();
    assert_eq!(subtypes, ["iso9660", "udf"]);
    for a in &fs {
        assert_eq!(a.metadata["udf_bridge"], json!(true));
        assert!(a.metadata.get("hidden").is_none());
        assert!(a.metadata.get("overlap_warning").is_none());
    }

    // ISO half: the one file only that half holds.
    let iso = seance_plugin_iso9660::Iso9660Parser
        .process(&fs[0])
        .expect("iso9660");
    let iso_files: Vec<&Artifact> = iso
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();
    assert_eq!(iso_files.len(), 1, "ISO half lists exactly one file");
    let f = iso_files[0];
    assert!(f.metadata["path"]
        .as_str()
        .unwrap()
        .starts_with("/ISO_ONLY.TXT"));
    let ds = f.data.as_ref().expect("content");
    let mut buf = vec![0u8; ds.size() as usize];
    ds.read_at(0, &mut buf).unwrap();
    assert_eq!(
        buf,
        b"ISO 9660 half only: this file is not in the UDF tree.\n"
    );

    // UDF half: the whole payload, and not the ISO-only file.
    let out = UdfParser.process(&fs[1]).expect("udf");
    let key = answer_key();
    for (path, hash) in &key {
        let a = out
            .iter()
            .find(|a| a.metadata["path"].as_str() == Some(path.as_str()))
            .unwrap_or_else(|| panic!("UDF half missing {path}"));
        assert_eq!(&sha256_of(a), hash, "{path}");
    }
    assert!(!out.iter().any(|a| a.metadata["path"]
        .as_str()
        .is_some_and(|p| p.contains("ISO_ONLY"))));
}
