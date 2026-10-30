//! End-to-end: a compressed tarball (`.tar.gz` / `.tbz`) is decompressed by the
//! gzip/bzip2 expander into readable bytes, and the tar extractor then windows
//! its inner files out with the correct content. Regression for the gap where
//! gz/bz2 children carried no data source, so `.tbz`/`.tar.gz` inner files were
//! never surfaced.

use seance_container_archive::{Bzip2ExpanderModule, GzipExpanderModule, TarExpanderModule};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
struct MemorySource {
    data: Vec<u8>,
}

impl DataSource for MemorySource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = offset as usize;
        if start >= self.data.len() {
            return Ok(0);
        }
        let end = (start + buf.len()).min(self.data.len());
        buf[..end - start].copy_from_slice(&self.data[start..end]);
        Ok(end - start)
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Build a tar holding `(path, bytes)` entries.
fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *data).unwrap();
    }
    builder.into_inner().unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn bzip2(bytes: &[u8]) -> Vec<u8> {
    use bzip2::{write::BzEncoder, Compression};
    use std::io::Write;
    let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn read_all(src: &Arc<dyn DataSource>) -> Vec<u8> {
    let mut out = vec![0u8; src.size() as usize];
    let n = src.read_at(0, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Decompress `container` -> assert one tar child carrying data -> extract that
/// tar -> return the inner FileEntry artifacts.
fn expand_and_extract(container: Artifact, expander: &dyn ForensicsModule) -> Vec<Artifact> {
    let children = expander.process(&container).unwrap();
    assert_eq!(children.len(), 1, "one decompressed child expected");
    let tar_child = &children[0];
    assert_eq!(tar_child.artifact_type, ArtifactType::Container);
    assert_eq!(tar_child.subtype(), Some("tar"));
    assert!(
        tar_child.data.is_some(),
        "decompressed tar child must carry readable bytes"
    );

    TarExpanderModule.process(tar_child).unwrap()
}

fn assert_inner_files(entries: &[Artifact]) {
    let alpha = entries
        .iter()
        .find(|a| a.metadata["name"] == "alpha.txt")
        .expect("alpha.txt extracted");
    assert_eq!(alpha.metadata["container"], "tar");
    assert_eq!(read_all(alpha.data.as_ref().unwrap()), b"hello alpha world");

    let beta = entries
        .iter()
        .find(|a| a.metadata["name"] == "beta.bin")
        .expect("beta.bin extracted");
    assert_eq!(read_all(beta.data.as_ref().unwrap()), vec![0xABu8; 5000]);
}

#[test]
fn tar_gz_chain_surfaces_inner_files() {
    let tar = make_tar(&[
        ("data/alpha.txt", b"hello alpha world"),
        ("data/beta.bin", &[0xABu8; 5000]),
    ]);
    let container = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::Container,
        Some(Arc::new(MemorySource { data: gzip(&tar) }) as Arc<dyn DataSource>),
        json!({"name": "backup.tar.gz", "subtype": "gzip"}),
    );

    let entries = expand_and_extract(container, &GzipExpanderModule);
    assert_inner_files(&entries);
}

#[test]
fn tbz_chain_surfaces_inner_files() {
    let tar = make_tar(&[
        ("data/alpha.txt", b"hello alpha world"),
        ("data/beta.bin", &[0xABu8; 5000]),
    ]);
    let container = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::Container,
        Some(Arc::new(MemorySource { data: bzip2(&tar) }) as Arc<dyn DataSource>),
        json!({"name": "backup.tbz", "subtype": "bzip2"}),
    );

    let entries = expand_and_extract(container, &Bzip2ExpanderModule);
    assert_inner_files(&entries);
}

#[test]
fn extract_tar_entry_source_reopens_one_file() {
    let tar = make_tar(&[
        ("data/alpha.txt", b"hello alpha world"),
        ("data/beta.bin", &[0xABu8; 5000]),
    ]);
    let src: Arc<dyn DataSource> = Arc::new(MemorySource { data: tar });

    let one = seance_container_archive::extract_tar_entry_source(src.clone(), "data/alpha.txt")
        .expect("entry found by internal path");
    assert_eq!(read_all(&one), b"hello alpha world");

    assert!(
        seance_container_archive::extract_tar_entry_source(src, "data/missing").is_none(),
        "absent entry yields None"
    );
}
