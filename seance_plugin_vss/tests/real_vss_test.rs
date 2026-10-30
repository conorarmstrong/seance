//! Known-answer reconstruction of real shadow copies, through a source that
//! answers in pieces.
//!
//! The corpus is `reference/dfir_ntfs/test_data/vss_10.tgz` and `vss_2003.tgz`
//! (Maxim Suhanov's `dfir_ntfs` test data: a Windows 10 and a Windows Server
//! 2003 volume, each with several shadow copies) with the per-16-KiB-block MD5
//! lists `vss_*_all_hashes.txt` that `dfir_ntfs`'s own tests check against.
//! The images are sparse 128 GiB raws, too large to commit; extract them with
//! GNU tar (`tar xzf vss_10.tgz`, sparse-aware) into a directory and point
//! `SEANCE_VSS_CORPUS` at it. The test skips when the images are absent.
//!
//! HUNT-154: the store builder did one `read_at` per metadata block and failed
//! on a short count, which the `DataSource` contract permits. The source here
//! answers at most 4 KiB per call, so a store that builds and reconstructs
//! every block to its known hash is the evidence the loop is right.

use md5::{Digest, Md5};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_plugin_vss::VssEnumerator;
use serde_json::json;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// Answers at most `chunk` bytes per `read_at`: legal, and what a windowed or
/// network-backed source does.
#[derive(Debug)]
struct Chunked {
    inner: Arc<dyn DataSource>,
    chunk: usize,
}

impl DataSource for Chunked {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.chunk);
        self.inner.read_at(offset, &mut buf[..n])
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

fn corpus(file: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("SEANCE_VSS_CORPUS")?;
    let p = PathBuf::from(dir).join(file);
    p.exists().then_some(p)
}

fn hashes(file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/dfir_ntfs/test_data")
        .join(file);
    std::fs::read_to_string(p).expect("hash list")
}

/// Run the enumerator over the volume at `volume_offset` and check every
/// block the hash list names, returning how many blocks were checked.
fn check(image: &str, volume_offset: u64, hash_list: &str, snapshots: usize) -> Option<usize> {
    let Some(path) = corpus(image) else {
        eprintln!("skipping: {image} not under SEANCE_VSS_CORPUS");
        return None;
    };
    let file: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open"));
    let len = file.size() - volume_offset;
    let volume: Arc<dyn DataSource> = Arc::new(Chunked {
        inner: Arc::new(WindowSource::new(file, volume_offset, len)),
        chunk: 4096,
    });
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(volume),
        json!({ "name": image }),
    );
    let out = VssEnumerator.process(&artifact).expect("enumerate");
    let snaps: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "VssSnapshot")
        .collect();
    assert_eq!(snaps.len(), snapshots, "snapshots listed");

    let mut checked = 0;
    for line in hashes(hash_list).lines() {
        let mut f = line.split('\t');
        let stack: u64 = f.next().unwrap().parse().unwrap();
        let offset: u64 = f.next().unwrap().parse().unwrap();
        // The Windows 10 list suffixes each hash with `_<bytes>`; the 2003
        // list does not.
        let md5s: Vec<&str> = f
            .next_back()
            .unwrap()
            .split(' ')
            .map(|h| h.strip_suffix("_512").unwrap_or(h))
            .collect();
        if md5s[0].contains("invalid") || md5s[0].ends_with("_0") {
            continue; // past the end of the volume; dfir_ntfs skips these too
        }
        let snap = snaps
            .iter()
            .find(|s| s.metadata["stack_position"] == stack)
            .unwrap_or_else(|| panic!("no snapshot at stack position {stack}"));
        assert_eq!(
            snap.metadata["content_reconstruction"], "reconstructed",
            "stack {stack}: the store must build through a short-reading source"
        );
        let ds = snap.data.as_ref().expect("reconstructed data source");
        let mut block = vec![0u8; 16384];
        seance_core::io::read_exact_or_fail(ds.as_ref(), offset, &mut block, "block")
            .unwrap_or_else(|e| panic!("stack {stack} offset {offset}: {e}"));
        let got: Vec<String> = block
            .chunks(512)
            .map(|s| format!("{:x}", Md5::digest(s)))
            .collect();
        assert_eq!(got, md5s, "stack {stack} offset {offset}");
        checked += 1;
    }
    Some(checked)
}

#[test]
fn windows_10_shadow_copies_reconstruct_to_their_known_hashes_through_short_reads() {
    if let Some(n) = check("vss_10.raw", 2048 * 512, "vss_10_all_hashes.txt", 6) {
        assert!(n > 700, "blocks checked: {n}");
    }
}

#[test]
fn windows_2003_shadow_copies_reconstruct_to_their_known_hashes_through_short_reads() {
    if let Some(n) = check("vss_2003.raw", 63 * 512, "vss_2003_all_hashes.txt", 6) {
        assert!(n > 100, "blocks checked: {n}");
    }
}

/// Run the enumerator over the volume at `volume_offset` of `image`, through
/// a whole-block source, returning the volume and every record it produced.
fn enumerate(image: &str, volume_offset: u64) -> Option<(Arc<dyn DataSource>, Vec<Artifact>)> {
    let Some(path) = corpus(image) else {
        eprintln!("skipping: {image} not under SEANCE_VSS_CORPUS");
        return None;
    };
    let file: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open"));
    let len = file.size() - volume_offset;
    let volume: Arc<dyn DataSource> = Arc::new(WindowSource::new(file, volume_offset, len));
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(volume.clone()),
        json!({ "name": image, "filesystem_type": "NTFS" }),
    );
    let out = VssEnumerator.process(&artifact).expect("enumerate");
    Some((volume, out))
}

/// HUNT-154 option B: a shadow copy's `$MFT` records that differ from the live
/// volume's are published, each labelled as a snapshot version, parented to
/// its snapshot, and carrying what differed.
#[test]
fn windows_10_shadow_copies_publish_the_mft_records_that_differ_from_the_live_volume() {
    let Some((_volume, out)) = enumerate("vss_10.raw", 2048 * 512) else {
        return;
    };
    let snaps: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "VssSnapshot")
        .collect();
    let priors: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "VssPriorVersion")
        .collect();
    assert!(
        !priors.is_empty(),
        "no prior version published from {} shadow copies",
        snaps.len()
    );
    for p in &priors {
        let m = &p.metadata;
        let parent = snaps
            .iter()
            .find(|s| Some(s.id) == p.parent_id)
            .expect("a prior version is parented to its snapshot record");
        assert_eq!(m["vss_stack_position"], parent.metadata["stack_position"]);
        assert_eq!(m["vss_snapshot_id"], parent.metadata["snapshot_id"]);
        assert_eq!(m["is_snapshot_version"], true);
        assert!(m["name"].as_str().unwrap().contains("[shadow copy "));
        assert!(m["snapshot_label"]
            .as_str()
            .unwrap()
            .starts_with("SHADOW COPY VERSION, not the live volume"));
        assert!(!m["differences"].as_array().unwrap().is_empty());
        assert_ne!(p.artifact_type, ArtifactType::FileEntry);
    }
    for s in &snaps {
        assert_eq!(s.metadata["prior_versions"]["status"], "compared");
    }
}

fn read_all(ds: &dyn DataSource) -> Vec<u8> {
    let mut b = vec![0u8; ds.size() as usize];
    seance_core::io::read_exact_or_fail(ds, 0, &mut b, "content").expect("read");
    b
}

/// The graded prior version. `dfir_ntfs`'s Server 2003 volume: record 79,
/// `Копия (50) Текстовый документ.txt`, is in use (sequence 1) in the oldest
/// shadow copy (stack 1, 2019-06-04 23:43:01 UTC) and deleted in the live
/// volume (sequence 2), whose clusters 173-174 now hold another file's `3`s.
/// Checked independently: `istat` on the live volume (sequence 2, not
/// allocated) and on the rebuilt stack-1 stream written to a scratch file
/// (sequence 1, allocated, clusters 173-174), and `icat` of that record from
/// the scratch file: 7,106 bytes of `1`, MD5 67e7f704b4d8042333c76b61c322e87f.
///
/// The content must come from the rebuilt snapshot: read from the live volume
/// at the same runs, the bytes are the `3`s.
#[test]
fn a_prior_version_is_served_from_the_snapshot_not_the_live_volume() {
    let Some((volume, out)) = enumerate("vss_2003.raw", 63 * 512) else {
        return;
    };
    let p = out
        .iter()
        .find(|a| {
            a.metadata["type"] == "VssPriorVersion"
                && a.metadata["vss_stack_position"] == 1
                && a.metadata["record_number"] == 79
        })
        .expect("record 79 differs in the stack-1 snapshot");
    let m = &p.metadata;
    assert_eq!(m["file_name"], "Копия (50) Текстовый документ.txt");
    assert_eq!(m["vss_creation_time"], "2019-06-04 23:43:01 UTC");
    assert_eq!(
        m["differences"],
        json!([
            { "field": "sequence_number", "live": 2, "snapshot": 1 },
            { "field": "in_use", "live": false, "snapshot": true },
        ])
    );
    assert_eq!(m["size"], 7106);
    assert_eq!(m["data_runs"], json!([[708608, 7106]]));
    assert!(m.get("content_incomplete").is_none(), "{m}");
    assert!(m.get("volume_not_in_evidence").is_none());

    let served = read_all(p.data.as_ref().expect("content from the snapshot").as_ref());
    assert_eq!(served, vec![b'1'; 7106]);
    assert_eq!(
        format!("{:x}", Md5::digest(&served)),
        "67e7f704b4d8042333c76b61c322e87f"
    );

    let mut live = vec![0u8; 7106];
    seance_core::io::read_exact_or_fail(volume.as_ref(), 708608, &mut live, "live").unwrap();
    assert_eq!(
        live[..40],
        [b'3'; 40],
        "the live clusters hold another file"
    );
    assert_ne!(
        live, served,
        "the prior version is not what the live volume holds"
    );
}

/// A record reused since the snapshot: record 39 on the Windows 10 volume is
/// sequence 1, 34,944 bytes in the oldest snapshot, and sequence 3, 80,640
/// bytes live (`istat` on both, as above).
#[test]
fn a_reused_record_is_published_with_both_sequence_numbers() {
    let Some((_volume, out)) = enumerate("vss_10.raw", 2048 * 512) else {
        return;
    };
    let p = out
        .iter()
        .find(|a| {
            a.metadata["type"] == "VssPriorVersion"
                && a.metadata["vss_stack_position"] == 1
                && a.metadata["record_number"] == 39
        })
        .expect("record 39 differs in the stack-1 snapshot");
    let d = p.metadata["differences"].as_array().unwrap();
    let get = |f: &str| d.iter().find(|x| x["field"] == f).cloned();
    assert_eq!(
        get("sequence_number"),
        Some(json!({ "field": "sequence_number", "live": 3, "snapshot": 1 }))
    );
    assert_eq!(
        get("size"),
        Some(json!({ "field": "size", "live": 80640, "snapshot": 34944 }))
    );
    assert_eq!(p.metadata["data_runs"], json!([[26021888, 34944]]));
    let served = read_all(p.data.as_ref().unwrap().as_ref());
    assert_eq!(
        format!("{:x}", Md5::digest(&served)),
        "4169b85def5a85ec3e35d4996ae22acd"
    );
}
