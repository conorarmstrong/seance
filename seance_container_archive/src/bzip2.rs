use crate::backing::TempBackedSource;
use crate::members::{stamp_members, Input, MemberChain};
use crate::status::expansion_failed_status;
use bzip2::bufread::BzDecoder;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::read_full,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::limits::{self, expansion_failure_detail, max_decompressed_bytes};

/// The bzip2 stream header magic (`BZh`).
const BZIP2_MAGIC: &[u8; 3] = b"BZh";

pub struct Bzip2ExpanderModule;

impl ForensicsModule for Bzip2ExpanderModule {
    fn id(&self) -> &str {
        "container.bzip2_expander"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Fast path: check subtype
        if let Some(subtype) = artifact.subtype() {
            if subtype != "bzip2" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".bz2") && !name.ends_with(".tbz2") && !name.ends_with(".tbz") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.bz2")
            .to_string();

        debug!("Bzip2ExpanderModule processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("BZIP2 module requires data source".to_string())
        })?;

        // Is this actually a bzip2 stream? The gate above accepts an extension,
        // which a file may carry without being bzip2 at all. Without this check
        // every mislabelled `.bz2` would be reported below as an archive we
        // failed to expand, and a stamp that fires on files that were never
        // ours tells the examiner nothing.
        let mut magic = [0u8; 3];
        let read = read_full(data_source.as_ref(), 0, &mut magic);
        let claims_bzip2 = read == BZIP2_MAGIC.len() && &magic == BZIP2_MAGIC;

        // Materialize the decompressed stream to a random-access backing store so
        // a downstream tar extractor can window into it (and the API can re-open
        // the inner file later). Bounded by the run's decompression ceiling.
        //
        // Every stream, not the first: `pbzip2`, `cat`-joined files and the
        // Wikipedia dumps are a series of complete bzip2 streams, which
        // `bzcat` prints in full. The ceiling bounds their sum (HUNT-169).
        let mut members = MemberChain::<BzDecoder<Input>>::new(data_source.clone(), BZIP2_MAGIC);
        let backing = match TempBackedSource::from_reader(&mut members, max_decompressed_bytes()) {
            Ok(b) => b,
            Err(e) => {
                // A stream we could not expand is not a stream that held
                // nothing: without this record, a corrupt or bomb-capped .bz2
                // ingests exactly like a file that was never our format
                // (B3-031).
                warn!("Failed to decompress BZIP2 {}: {}", name, e);
                if !claims_bzip2 {
                    // No bzip2 header: this file was simply never ours.
                    return Ok(Vec::new());
                }
                return Ok(vec![expansion_failed_status(
                    artifact,
                    "bzip2",
                    &name,
                    "bzip2_decompress_failed",
                    &expansion_failure_detail(&e),
                )]);
            }
        };
        let decompressed_size = backing.size();
        let backing: Arc<dyn DataSource> = Arc::new(backing);

        let lower_name = name.to_lowercase();
        let inner_name = if lower_name.ends_with(".tar.bz2") {
            name[..name.len() - 4].to_string()
        } else if lower_name.ends_with(".tbz2") {
            format!("{}.tar", &name[..name.len() - 5])
        } else if lower_name.ends_with(".tbz") {
            format!("{}.tar", &name[..name.len() - 4])
        } else if lower_name.ends_with(".bz2") {
            name[..name.len() - 4].to_string()
        } else {
            format!("{}.decompressed", name)
        };

        // Inner content is a TAR iff the ustar magic sits at offset 257.
        let mut magic = [0u8; 5];
        let is_tar = decompressed_size >= 262
            && backing
                .read_at(257, &mut magic)
                .map(|n| n == 5 && &magic == b"ustar")
                .unwrap_or(false);

        let (child_type, subtype) = if is_tar {
            (ArtifactType::Container, Some("tar"))
        } else {
            (ArtifactType::FileEntry, None)
        };

        let mut metadata = json!({
            "name": inner_name,
            "size": decompressed_size,
            "container": "bzip2",
            "container_path": name,
        });

        if let Some(st) = subtype {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert("subtype".to_string(), json!(st));
            }
        }

        // Which ceiling admitted this stream is a fact about the run, and the
        // run is over by the time the case is reported: a reporting process
        // reading the environment for itself would state a number that never
        // governed these bytes. So it rides on the artifact. Once here rather
        // than on every entry, because the expander emits exactly one child per
        // expanded stream while any tar members inside it are emitted
        // separately — one stamp per container, by construction.
        limits::stamp_ceiling(&mut metadata);
        stamp_members(
            &mut metadata,
            data_source.as_ref(),
            "bzip2",
            members.outcome(),
        );

        let child = Artifact::new(artifact.case_id, child_type, Some(backing), metadata)
            .with_parent(artifact.id);

        debug!(
            "BZIP2 decompressed {} -> {} ({} bytes)",
            name, inner_name, decompressed_size
        );

        Ok(vec![child])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
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
            let len = end - start;
            buf[..len].copy_from_slice(&self.data[start..end]);
            Ok(len)
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    fn make_bzip2_data(content: &[u8]) -> Vec<u8> {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;
        let mut encoder = BzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(content).unwrap();
        encoder.finish().unwrap()
    }

    fn fixture_artifact(name: &str, bytes: &[u8]) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource {
                data: bytes.to_vec(),
            }) as Arc<dyn DataSource>),
            json!({"name": name, "subtype": "bzip2"}),
        )
    }

    fn child_bytes(child: &Artifact) -> Vec<u8> {
        let ds = child
            .data
            .as_ref()
            .expect("an expanded child carries its bytes");
        let mut out = vec![0u8; ds.size() as usize];
        assert_eq!(read_full(ds.as_ref(), 0, &mut out), out.len());
        out
    }

    /// HUNT-169. Real `bzip2 -c` output of two files appended with `cat` —
    /// the multi-stream shape `pbzip2` and the Wikipedia dumps use, which
    /// `bzcat` prints in full. The single-stream decoder stopped at the first
    /// end-of-stream and published the first file as the whole.
    #[test]
    fn every_stream_of_a_multi_stream_bzip2_is_expanded() {
        let data = include_bytes!("../tests/fixtures/multi_stream.bz2");
        let out = Bzip2ExpanderModule
            .process(&fixture_artifact("rotated.log.bz2", data))
            .unwrap();
        assert_eq!(out.len(), 1);
        let child = &out[0];
        assert_eq!(
            child_bytes(child),
            b"first member: rotated log line one\nsecond member: appended with cat\n".to_vec(),
            "both streams must reach the child, as `bzcat` shows them"
        );
        assert_eq!(child.metadata["size"], json!(68));
        assert_eq!(child.metadata["compressed_members"], json!(2));
        assert!(child.metadata.get("content_incomplete").is_none());
    }

    /// HUNT-169, the second half: `bzip2 -t` reports "trailing garbage after
    /// EOF ignored" on this real file. The 34 undecoded bytes are recorded
    /// with their offset, and the child says it may not be the whole.
    #[test]
    fn bytes_after_the_last_stream_are_recorded_not_dropped() {
        let data = include_bytes!("../tests/fixtures/multi_stream_trailing_garbage.bz2");
        let out = Bzip2ExpanderModule
            .process(&fixture_artifact("rotated.log.bz2", data))
            .unwrap();
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["compressed_members"], json!(2));
        assert_eq!(m["trailing_bytes_offset"], json!(141));
        assert_eq!(m["trailing_bytes_after_last_member"], json!(34));
        assert_eq!(m["trailing_bytes_all_zero"], json!(false));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
    }

    #[test]
    fn test_bzip2_skip_non_bzip2() {
        let module = Bzip2ExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "file.txt"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_bzip2_decompress_simple() {
        let module = Bzip2ExpanderModule;
        let content = b"Hello bzip2 world!";
        let bz2_data = make_bzip2_data(content);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: bz2_data }) as Arc<dyn DataSource>),
            json!({"name": "test.txt.bz2", "subtype": "bzip2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "test.txt");
        assert_eq!(results[0].metadata["size"], content.len());
        assert_eq!(results[0].metadata["container"], "bzip2");
    }

    #[test]
    fn test_bzip2_tbz2_extension() {
        let module = Bzip2ExpanderModule;
        let bz2_data = make_bzip2_data(b"test");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data: bz2_data }) as Arc<dyn DataSource>),
            json!({"name": "archive.tbz2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "archive.tar");
    }

    #[test]
    fn test_bzip2_tbz_extension() {
        let module = Bzip2ExpanderModule;
        let bz2_data = make_bzip2_data(b"test");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data: bz2_data }) as Arc<dyn DataSource>),
            json!({"name": "archive.tbz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "archive.tar");
    }

    #[test]
    fn test_bzip2_tar_bz2_extension() {
        let module = Bzip2ExpanderModule;
        let bz2_data = make_bzip2_data(b"test");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: bz2_data }) as Arc<dyn DataSource>),
            json!({"name": "data.tar.bz2", "subtype": "bzip2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results[0].metadata["name"], "data.tar");
    }

    /// The counterpart: a `.bz2` name with no `BZh` header was never ours, and
    /// must not be reported as an archive we failed to expand. A stamp that
    /// fires on every mislabelled file on the disk tells an examiner nothing.
    #[test]
    fn test_bzip2_without_magic_is_silent() {
        let module = Bzip2ExpanderModule;
        let data = b"plain text that merely ends in .bz2".to_vec();

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "notreally.bz2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "a file without the bzip2 header is not a failed bzip2 archive"
        );
    }

    /// B3-031: a bzip2 stream that will not decompress must be reported, not
    /// silently dropped.
    ///
    /// What an examiner learns: this `.bz2` exists, could not be expanded, and
    /// its contents are unknown. The wrong answer this guards against is an
    /// empty success, which is indistinguishable from "this file was never a
    /// bzip2 archive".
    #[test]
    fn test_bzip2_corrupted_emits_incompleteness_status() {
        let module = Bzip2ExpanderModule;
        let data = vec![0x42, 0x5A, 0x68, 0x39, 0xFF, 0xFF]; // BZh9 + garbage

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "bad.bz2", "subtype": "bzip2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "a failed expansion must be recorded");
        let status = &results[0];
        assert_eq!(status.metadata["record_type"], json!("archive_scan_status"));
        assert_eq!(status.metadata["content_incomplete"], json!(true));
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            json!("bzip2_decompress_failed")
        );
        assert_eq!(status.metadata["inventory_incomplete"], json!(true));
        assert_eq!(status.parent_id, Some(artifact.id));
    }

    /// The same fact the gzip tier records, for the same reason: the ceiling
    /// that admitted the stream cannot be recovered after the run, so it rides
    /// on the artifact. The three tiers drift when only one of them is tested.
    #[test]
    fn test_bzip2_expanded_child_records_the_ceiling_it_was_admitted_under() {
        let module = Bzip2ExpanderModule;
        let bz2_data = make_bzip2_data(b"admitted under a ceiling");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: bz2_data }) as Arc<dyn DataSource>),
            json!({"name": "payload.txt.bz2", "subtype": "bzip2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].metadata["decompression_ceiling_bytes"],
            json!(max_decompressed_bytes())
        );
        assert!(results[0]
            .metadata
            .get("decompression_ceiling_source")
            .and_then(|v| v.as_str())
            .is_some());
    }
}
