//! HUNT-174: the module-level behaviour of the SquashFS reader -- what it
//! publishes for a zero timestamp, and that it walks a volume the file-system
//! detector found inside a partition.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_plugin_squashfs::SquashFsParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
struct Bytes(Vec<u8>);

impl DataSource for Bytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = offset as usize;
        if off >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read fixture")
}

fn files(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect()
}

/// `zero_mtime.sqfs` is made by `mksquashfs src zero_mtime.sqfs -comp gzip
/// -all-time 0 -mkfs-time 0 -noappend -all-root` (squashfs-tools 4.7.5), the
/// reproducible-build setting that zeroes every inode time. A zero there is
/// "no time recorded", not the first second of 1970, and must not reach the
/// timeline as one.
#[test]
fn a_zero_mtime_is_published_as_not_recorded_not_as_1970() {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(Arc::new(Bytes(fixture("zero_mtime.sqfs"))) as Arc<dyn DataSource>),
        json!({}),
    );
    let out = SquashFsParser.process(&art).unwrap();
    let files = files(&out);
    assert!(
        files.iter().any(|f| f.metadata["path"] == "etc/issue"),
        "etc/issue missing"
    );
    for f in files {
        assert!(
            f.metadata.get("modified").is_none() && f.metadata.get("mtime").is_none(),
            "{}: a zero mtime was published as a time: {}",
            f.metadata["path"],
            f.metadata
        );
        assert_eq!(f.metadata["mtime_not_recorded"], true, "{}", f.metadata);
    }
}

/// A nonzero mtime is still published under both keys.
#[test]
fn a_nonzero_mtime_is_still_published() {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(Arc::new(Bytes(fixture("tree.sqfs"))) as Arc<dyn DataSource>),
        json!({}),
    );
    let out = SquashFsParser.process(&art).unwrap();
    let readme = files(&out)
        .into_iter()
        .find(|f| f.metadata["path"] == "readme.txt")
        .expect("readme.txt");
    let m = readme.metadata["modified"].as_u64().expect("modified");
    assert!(m > 0);
    assert_eq!(readme.metadata["mtime"], m);
    assert!(readme.metadata.get("mtime_not_recorded").is_none());
}

/// The file-system detector hands a SquashFS volume found inside a partition
/// on as a `FileSystem` with subtype `squashfs`, windowed to the partition --
/// which runs past the image's `bytes_used`. The reader must subscribe to it
/// and walk it.
#[test]
fn a_squashfs_volume_inside_a_partition_is_walked() {
    assert!(SquashFsParser
        .subscribes_to()
        .contains(&ArtifactType::FileSystem));
    let mut window = fixture("tree.sqfs");
    // The partition is larger than the image; the slack after it is zero.
    window.resize(window.len() + 64 * 1024, 0);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(Bytes(window)) as Arc<dyn DataSource>),
        json!({"filesystem_type": "SquashFS", "subtype": "squashfs"}),
    );
    let out = SquashFsParser.process(&art).unwrap();
    let paths: Vec<_> = files(&out)
        .iter()
        .map(|f| f.metadata["path"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(paths.iter().any(|p| p == "docs/note.txt"), "{paths:?}");
}

/// A `FileSystem` the detector named as something else is not this reader's.
#[test]
fn a_filesystem_of_another_subtype_is_declined() {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(Bytes(fixture("tree.sqfs"))) as Arc<dyn DataSource>),
        json!({"filesystem_type": "ext4", "subtype": "ext4"}),
    );
    assert!(SquashFsParser.process(&art).unwrap().is_empty());
}
