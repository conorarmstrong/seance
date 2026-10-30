//! HUNT-251: on a real NTFS volume the parser publishes the `$MFT`'s own
//! records, read through the `$MFT`'s own run list — not every 1,024-byte
//! slot of the volume that happens to begin with `FILE`.
//!
//! The corpus is dfir_ntfs's `vss_2003.tgz` and `vss_10.tgz` (sparse 128 GiB
//! raws; extract with GNU tar into a directory and point `SEANCE_VSS_CORPUS`
//! at it, as for `seance_plugin_vss/tests/real_vss_test.rs`) and the
//! committed-but-gitignored `ntfs_index.raw.gz`. Absent, the tests skip.
//!
//! The Server 2003 volume holds six shadow copies. Their diff areas preserve
//! older copies of `$MFT` records at volume offsets outside the `$MFT`; a
//! whole-volume scan found them and published each one as a live file under
//! the record number in its header — record 77, deleted (sequence 2) in the
//! real table, was published a second time as an in-use file with sequence 1
//! from the copy at volume offset 2,208,768.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_plugin_mft::volume_mft::locate_volume_mft;
use seance_plugin_mft::MftParser;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

fn corpus(file: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("SEANCE_VSS_CORPUS")?;
    let p = PathBuf::from(dir).join(file);
    p.exists().then_some(p)
}

fn volume_artifact(volume: Arc<dyn DataSource>, name: &str) -> Artifact {
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(volume),
        json!({ "name": name, "filesystem_type": "NTFS" }),
    )
}

fn sparse_volume(image: &str, volume_offset: u64) -> Option<Arc<dyn DataSource>> {
    let Some(path) = corpus(image) else {
        eprintln!("skipping: {image} not under SEANCE_VSS_CORPUS");
        return None;
    };
    let file: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open"));
    let len = file.size() - volume_offset;
    Some(Arc::new(WindowSource::new(file, volume_offset, len)))
}

/// Base (non-ADS) `FileEntry` metadata, with the scan time.
fn base_entries(volume: Arc<dyn DataSource>, name: &str) -> (Vec<Value>, f64) {
    let started = Instant::now();
    let out = MftParser::new()
        .process(&volume_artifact(volume, name))
        .expect("parse");
    let secs = started.elapsed().as_secs_f64();
    let entries: Vec<Value> = out
        .into_iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter(|a| a.metadata.get("is_ads").and_then(Value::as_bool) != Some(true))
        .map(|a| a.metadata)
        .collect();
    (entries, secs)
}

fn by_record(entries: &[Value]) -> HashMap<u64, Vec<&Value>> {
    let mut map: HashMap<u64, Vec<&Value>> = HashMap::new();
    for e in entries {
        if let Some(n) = e.get("record_number").and_then(Value::as_u64) {
            map.entry(n).or_default().push(e);
        }
    }
    map
}

#[test]
fn hunt_251_the_2003_volume_publishes_each_mft_record_once_from_its_own_table() {
    let Some(volume) = sparse_volume("vss_2003.raw", 63 * 512) else {
        return;
    };
    let loc = locate_volume_mft(&volume).expect("the volume's $MFT is located");
    assert!(loc.runs_complete, "record 0's run list is whole");

    let (entries, secs) = base_entries(volume, "vss_2003.raw");
    let records = by_record(&entries);
    eprintln!(
        "vss_2003: {} base FileEntry, {} distinct records, $MFT {} bytes, {:.1}s",
        entries.len(),
        records.len(),
        loc.size,
        secs
    );

    // Every record is published once: a record number is one slot of one table.
    let duplicated: Vec<u64> = records
        .iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(n, _)| *n)
        .collect();
    assert!(
        duplicated.is_empty(),
        "records published more than once: {duplicated:?}"
    );
    assert_eq!(
        entries.len(),
        87,
        "the live $MFT's records with a $FILE_NAME"
    );

    // Record 77 is deleted in the real table, at sequence 2. The older in-use
    // copy (sequence 1) preserved in a diff area is not the live record.
    let r77 = &records[&77][0];
    assert_eq!(r77["sequence_number"], 2, "record 77's sequence");
    assert_eq!(r77["deleted"], true, "record 77 is not in use");

    // Every entry's record sits inside the $MFT's own runs.
    for e in &entries {
        let at = e["mft_offset"].as_u64().expect("mft_offset");
        assert!(
            loc.runs
                .iter()
                .any(|(start, len)| start.is_some_and(|s| at >= s && at < s + len)),
            "record {} published from volume offset {at}, outside the $MFT",
            e["record_number"]
        );
    }
}

#[test]
fn hunt_251_the_windows_10_volume_publishes_each_mft_record_once() {
    let Some(volume) = sparse_volume("vss_10.raw", 2048 * 512) else {
        return;
    };
    let (entries, secs) = base_entries(volume, "vss_10.raw");
    let records = by_record(&entries);
    eprintln!(
        "vss_10: {} base FileEntry, {} distinct records, {:.1}s",
        entries.len(),
        records.len(),
        secs
    );
    let duplicated = records.values().filter(|v| v.len() > 1).count();
    assert_eq!(duplicated, 0, "records published more than once");
}

/// `ntfs_index.raw.gz`: a plain 32 MiB volume (NTFS at sector 128) with no
/// shadow copies. Its count is the regression anchor for an ordinary volume.
#[test]
fn hunt_251_an_ordinary_volume_keeps_its_count() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/dfir_ntfs/test_data/ntfs_index.raw.gz");
    let Ok(file) = std::fs::File::open(&path) else {
        eprintln!("skipping: {} absent", path.display());
        return;
    };
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(file)
        .read_to_end(&mut raw)
        .expect("gunzip");
    let volume: Arc<dyn DataSource> = Arc::new(WindowSource::new(
        Arc::new(ByteSliceDataSource::new(raw.clone())),
        128 * 512,
        raw.len() as u64 - 128 * 512,
    ));
    let (entries, secs) = base_entries(volume, "ntfs_index.raw");
    let records = by_record(&entries);
    eprintln!(
        "ntfs_index: {} base FileEntry, {} distinct records, {:.2}s",
        entries.len(),
        records.len(),
        secs
    );
    assert_eq!(
        records.values().filter(|v| v.len() > 1).count(),
        0,
        "records published more than once"
    );
}
