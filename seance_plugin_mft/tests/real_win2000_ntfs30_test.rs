//! HUNT-256: `$ATTRIBUTE_LIST` extension resolution and bare-`$MFT` slot
//! numbering graded on a real Windows 2000 (NTFS 3.0) volume.
//!
//! The evidence is the Windows 2000 Professional SP3 VHD from archive.org's
//! "Windows2000VHDCollection", reduced to a sparse raw disk that holds only the
//! `$MFT` and the metadata and index clusters (file contents read as zero):
//! `win2k-pro-sp3-ntfs30-metaonly.raw`, sha256 `61ea3bc9…a60624`. Partition 1
//! starts at sector 63; `$VOLUME_INFORMATION` reads 3.0 in `$MFT` and
//! `$MFTMirr`. Every one of its 6,604 FILE records has its update sequence
//! array at 0x2A, so no header carries a record number. Point
//! `SEANCE_WIN2000_NTFS30` at the raw (default:
//! `~/forensic_corpora/win2000_ntfs30_metadata/`); absent, the tests skip.
//!
//! No answer key is published for this image. The key is a second tool: The
//! Sleuth Kit 4.12.1 (`fls -r -p`, `istat`), whose cluster lists are in
//! `tests/data/win2000_ntfs30_tsk_clusters.txt`.
//!
//! What this volume can grade: record numbering, path reconstruction, and the
//! run lists of the four files whose attributes continue in extension records
//! (two registry hives whose `$DATA` is split across two extension records
//! each, a log whose `$DATA` is wholly in one, and a directory whose `$I30`
//! index allocation is wholly in one). What it cannot grade: file content —
//! the data clusters were not fetched, so no hash of a resolved file is
//! checked here — and a non-resident `$ATTRIBUTE_LIST`, which this volume
//! does not have.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_plugin_mft::volume_mft::locate_volume_mft;
use seance_plugin_mft::MftParser;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

const PARTITION_OFFSET: u64 = 63 * 512;
const CLUSTER: u64 = 4096;

fn image() -> Option<PathBuf> {
    let path = std::env::var_os("SEANCE_WIN2000_NTFS30")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                PathBuf::from(h).join(
                    "forensic_corpora/win2000_ntfs30_metadata/win2k-pro-sp3-ntfs30-metaonly.raw",
                )
            })
        })?;
    if path.exists() {
        Some(path)
    } else {
        eprintln!("skipping: {} absent", path.display());
        None
    }
}

fn volume() -> Option<Arc<dyn DataSource>> {
    let file: Arc<dyn DataSource> = Arc::new(FileDataSource::new(image()?).expect("open"));
    let len = file.size() - PARTITION_OFFSET;
    Some(Arc::new(WindowSource::new(file, PARTITION_OFFSET, len)))
}

/// The `$MFT` read out of the volume through its own run list: the bytes a
/// bare-`$MFT` export of this volume holds.
fn bare_mft(volume: &Arc<dyn DataSource>) -> Vec<u8> {
    let loc = locate_volume_mft(volume).expect("the $MFT is located");
    assert!(loc.runs_complete);
    let mut out = Vec::with_capacity(loc.size as usize);
    for (offset, len) in &loc.runs {
        let mut buf = vec![0u8; *len as usize];
        if let Some(at) = offset {
            volume.read_at(*at, &mut buf).expect("read $MFT run");
        }
        out.extend_from_slice(&buf);
    }
    out.truncate(loc.size as usize);
    out
}

fn parse(source: Arc<dyn DataSource>, artifact_type: ArtifactType, meta: Value) -> Vec<Artifact> {
    MftParser::new()
        .process(&Artifact::new(
            uuid::Uuid::new_v4(),
            artifact_type,
            Some(source),
            meta,
        ))
        .expect("parse")
}

/// Base (non-ADS) `FileEntry` metadata by record number.
fn base_entries(out: &[Artifact]) -> HashMap<u64, Value> {
    let mut map = HashMap::new();
    for a in out {
        if a.artifact_type != ArtifactType::FileEntry
            || a.metadata.get("is_ads").and_then(Value::as_bool) == Some(true)
        {
            continue;
        }
        let n = a.metadata["record_number"].as_u64().expect("record_number");
        assert!(
            map.insert(n, a.metadata.clone()).is_none(),
            "record {n} published twice"
        );
    }
    map
}

/// TSK's cluster list for `record`'s `attr` (`DATA` or `I30`).
fn tsk_clusters(record: u64, attr: &str) -> Vec<u64> {
    let key = include_str!("data/win2000_ntfs30_tsk_clusters.txt");
    let line = key
        .lines()
        .find(|l| l.starts_with(&format!("{record} {attr} ")))
        .expect("record in the key");
    line.split_whitespace()
        .skip(2)
        .map(|c| c.parse().unwrap())
        .collect()
}

/// Clusters named by a published run list, a hole counting as cluster 0 (as
/// TSK prints one), within `size` bytes.
fn clusters_of(runs: &[(Option<u64>, u64)]) -> Vec<u64> {
    let mut out = Vec::new();
    for (offset, len) in runs {
        for i in 0..len.div_ceil(CLUSTER) {
            out.push(offset.map_or(0, |o| o / CLUSTER + i));
        }
    }
    out
}

fn runs_of(entry: &Value) -> Vec<(Option<u64>, u64)> {
    entry["data_runs"]
        .as_array()
        .expect("data_runs")
        .iter()
        .map(|r| (r[0].as_u64(), r[1].as_u64().unwrap()))
        .collect()
}

/// The two registry hives whose `$DATA` continues across two extension
/// records each (1849: extents in 2712 at VCN 0 and 2729 at VCN 448; 2745:
/// 4499 at VCN 0 and 1994 at VCN 352), and `software.LOG` (2734), whose
/// `$DATA` is wholly in 4486, resolve to exactly TSK's clusters.
fn assert_extension_data_matches_tsk(entries: &HashMap<u64, Value>) {
    for (record, path) in [
        (1849, "/WINNT/system32/config/system"),
        (2745, "/WINNT/system32/config/SYSTEM.ALT"),
    ] {
        let e = &entries[&record];
        assert_eq!(e["path"], path);
        assert_eq!(e["data_runs_complete"], true, "{path}: runs complete");
        assert_eq!(e["size"], 2_109_440, "{path}: size");
        let runs = runs_of(e);
        assert_eq!(runs.iter().map(|r| r.1).sum::<u64>(), 2_109_440);
        assert_eq!(clusters_of(&runs), tsk_clusters(record, "DATA"), "{path}");
    }
    // 4,096 bytes, of which only the first 1,024 were ever written (init
    // size). TSK prints the unwritten clusters as 0; the parser publishes the
    // unwritten tail as a hole, which reads as the zeros Windows returns.
    let log = &entries[&2734];
    assert_eq!(log["path"], "/WINNT/system32/config/software.LOG");
    assert_eq!(log["data_runs_complete"], true);
    assert_eq!(
        log["data_runs"],
        json!([[2_125_593 * CLUSTER, 1024], [null, 3072]])
    );
}

#[test]
fn hunt_256_the_windows_2000_volume_resolves_extension_records() {
    let Some(volume) = volume() else { return };
    let out = parse(
        volume.clone(),
        ArtifactType::FileSystem,
        json!({ "name": "win2k", "filesystem_type": "NTFS" }),
    );
    let entries = base_entries(&out);
    eprintln!("win2k volume: {} base FileEntry", entries.len());
    assert_extension_data_matches_tsk(&entries);

    // `/WINNT/system32/dllcache` (record 70): its whole `$I30` index
    // allocation, 98 clusters, is in extension record 5,597.
    assert_eq!(entries[&70]["path"], "/WINNT/system32/dllcache");
    let i30 = out
        .iter()
        .find(|a| a.metadata["name"] == "$I30" && a.metadata["parent_file"] == "dllcache")
        .expect("dllcache's $I30 index allocation is published");
    assert!(i30.metadata.get("content_incomplete").is_none());
    let data = i30.data.as_ref().expect("addressable");
    let tsk = tsk_clusters(70, "I30");
    assert_eq!(data.size(), tsk.len() as u64 * CLUSTER);
    // The stream is those clusters in that order: each 4 KiB index block of
    // the stream is the INDX record at TSK's cluster.
    for (vcn, lcn) in tsk.iter().enumerate() {
        let mut ours = [0u8; 64];
        let mut theirs = [0u8; 64];
        data.read_at(vcn as u64 * CLUSTER, &mut ours).unwrap();
        volume.read_at(lcn * CLUSTER, &mut theirs).unwrap();
        assert_eq!(ours, theirs, "$I30 VCN {vcn}");
        assert_eq!(&ours[..4], b"INDX", "$I30 VCN {vcn} is an index record");
    }
}

#[test]
fn hunt_256_a_bare_windows_2000_mft_is_numbered_by_slot() {
    let Some(volume) = volume() else { return };
    let mft = bare_mft(&volume);
    assert_eq!(mft.len(), 6604 * 1024);

    let from_volume = base_entries(&parse(
        volume,
        ArtifactType::FileSystem,
        json!({ "name": "win2k", "filesystem_type": "NTFS" }),
    ));
    let bare_out = parse(
        Arc::new(ByteSliceDataSource::new(mft.clone())),
        ArtifactType::FileEntry,
        json!({ "cluster_size": CLUSTER }),
    );
    let bare = base_entries(&bare_out);

    // Every record, base or stream, is numbered by its slot and says so: no
    // 3.0 header has a number to publish.
    for a in bare_out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
    {
        assert_eq!(a.metadata["record_number_source"], "slot");
        assert!(a.metadata.get("header_record_number").is_none());
    }
    // Each base entry is the record at its slot (a stream entry carries no
    // `mft_offset` of its own).
    for (n, e) in &bare {
        assert_eq!(
            e["mft_offset"].as_u64(),
            Some(n * 1024),
            "record {n} is the record at its slot"
        );
    }
    // The fixup word at 0x2C differs from the slot in all but one record, so
    // reading it as a number would have renumbered the whole table.
    let differs = mft
        .chunks(1024)
        .enumerate()
        .filter(|(i, r)| u32::from_le_bytes(r[0x2C..0x30].try_into().unwrap()) as usize != *i)
        .count();
    assert_eq!(differs, 6603);

    // The same records, names and paths as the volume read.
    assert_eq!(bare.len(), from_volume.len());
    for (n, e) in &from_volume {
        let b = bare
            .get(n)
            .unwrap_or_else(|| panic!("record {n} missing from bare"));
        for field in ["name", "path", "sequence_number", "deleted", "size"] {
            assert_eq!(b.get(field), e.get(field), "record {n} {field}");
        }
    }
    // Extension records are found by slot in a bare table too.
    assert_extension_data_matches_tsk(&bare);
}

/// Every allocated name TSK's `fls -r -p` lists is published at the same
/// record with the same path, from the volume and from the bare `$MFT`.
#[test]
fn hunt_256_paths_agree_with_the_sleuth_kit() {
    let Some(volume) = volume() else { return };
    let entries = base_entries(&parse(
        volume,
        ArtifactType::FileSystem,
        json!({ "name": "win2k", "filesystem_type": "NTFS" }),
    ));
    // A sample of `fls -r -p` rows across the tree, spanning the table.
    for (record, path) in [
        (5, "/"),
        (26, "/WINNT/system32"),
        (27, "/WINNT/system32/config"),
        (70, "/WINNT/system32/dllcache"),
        (2742, "/boot.ini"),
        (2749, "/Documents and Settings"),
        (2751, "/Documents and Settings/All Users"),
        (2819, "/Documents and Settings/All Users/Application Data"),
    ] {
        assert_eq!(entries[&record]["path"], path, "record {record}");
    }
}
