use crate::backing::TempBackedSource;
use crate::members::{stamp_members, Input, MemberChain};
use crate::status::expansion_failed_status;
use flate2::bufread::GzDecoder;
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

/// The gzip member header magic (RFC 1952 `ID1 ID2`).
const GZIP_MAGIC: &[u8; 2] = &[0x1F, 0x8B];

pub struct GzipExpanderModule;

impl ForensicsModule for GzipExpanderModule {
    fn id(&self) -> &str {
        "container.gzip_expander"
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
            if subtype != "gzip" {
                return Ok(Vec::new());
            }
        } else {
            // Fallback: check extension
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".gz") && !name.ends_with(".gzip") && !name.ends_with(".tgz") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.gz")
            .to_string();

        debug!("GzipExpanderModule processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("GZIP module requires data source".to_string())
        })?;

        // Is this actually a gzip member? The gate above accepts an extension,
        // which a file may carry without being gzip at all. Without this, every
        // mislabelled `.gz` on the disk would be reported below as an archive
        // we failed to expand, and a stamp that fires on files that were never
        // ours tells the examiner nothing.
        let mut magic = [0u8; 2];
        let read = read_full(data_source.as_ref(), 0, &mut magic);
        let claims_gzip = read == GZIP_MAGIC.len() && &magic == GZIP_MAGIC;

        // Materialize the decompressed stream to a random-access backing store so
        // a downstream tar extractor can window into it (and the API can re-open
        // the inner file later). Bounded by the run's decompression ceiling.
        //
        // Every member, not the first: a gzip file is a series of members
        // (RFC 1952), and `cat`-rotated logs and parallel compressors write
        // several. The ceiling bounds their sum (HUNT-169).
        let mut members = MemberChain::<GzDecoder<Input>>::new(data_source.clone(), GZIP_MAGIC);
        let backing = match TempBackedSource::from_reader(&mut members, max_decompressed_bytes()) {
            Ok(b) => b,
            Err(e) => {
                // A stream we could not expand is not a stream that held
                // nothing: without this record, a corrupt or bomb-capped .gz
                // ingests exactly like a file that was never our format
                // (B3-031).
                warn!("Failed to decompress GZIP {}: {}", name, e);
                if !claims_gzip {
                    // No gzip header: this file was simply never ours.
                    return Ok(Vec::new());
                }
                return Ok(vec![expansion_failed_status(
                    artifact,
                    "gzip",
                    &name,
                    "gzip_decompress_failed",
                    &expansion_failure_detail(&e),
                )]);
            }
        };
        let decompressed_size = backing.size();
        let backing: Arc<dyn DataSource> = Arc::new(backing);

        // Determine inner file name by stripping .gz/.gzip/.tgz extension
        let lower_name = name.to_lowercase();
        let inner_name = if lower_name.ends_with(".tar.gz") {
            name[..name.len() - 3].to_string() // strip .gz -> foo.tar
        } else if lower_name.ends_with(".tgz") {
            format!("{}.tar", &name[..name.len() - 4]) // .tgz -> .tar
        } else if lower_name.ends_with(".gz") {
            name[..name.len() - 3].to_string()
        } else if lower_name.ends_with(".gzip") {
            name[..name.len() - 5].to_string()
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
            "container": "gzip",
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
            "gzip",
            members.outcome(),
        );

        let child = Artifact::new(artifact.case_id, child_type, Some(backing), metadata)
            .with_parent(artifact.id);

        debug!(
            "GZIP decompressed {} -> {} ({} bytes)",
            name, inner_name, decompressed_size
        );

        Ok(vec![child])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
    use seance_core::io::IncompleteReason;
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

    fn make_gzip_data(content: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(content).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_gzip_skip_non_gzip() {
        let module = GzipExpanderModule;
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
    fn test_gzip_skip_wrong_subtype() {
        let module = GzipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            None,
            json!({"name": "file.zip", "subtype": "zip"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_gzip_no_data_source() {
        let module = GzipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            None,
            json!({"name": "file.gz", "subtype": "gzip"}),
        );
        let result = module.process(&artifact);
        assert!(result.is_err(), "Missing data source should return error");
    }

    #[test]
    fn test_gzip_decompress_simple() {
        let module = GzipExpanderModule;
        let content = b"Hello, world! This is a test file.";
        let gz_data = make_gzip_data(content);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "test.txt.gz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].artifact_type, ArtifactType::FileEntry);
        assert_eq!(results[0].metadata["name"], "test.txt");
        assert_eq!(results[0].metadata["size"], content.len());
        assert_eq!(results[0].metadata["container"], "gzip");
    }

    #[test]
    fn test_gzip_tgz_extension() {
        let module = GzipExpanderModule;
        let content = b"not actually tar";
        let gz_data = make_gzip_data(content);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "archive.tgz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "archive.tar");
    }

    #[test]
    fn test_gzip_tar_gz_inner_name() {
        let module = GzipExpanderModule;
        let content = b"not actually tar";
        let gz_data = make_gzip_data(content);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "data.tar.gz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results[0].metadata["name"], "data.tar");
    }

    /// B3-031: a gzip stream that will not decompress must be reported, not
    /// silently dropped.
    ///
    /// What an examiner learns: this `.gz` exists, could not be expanded, and
    /// its contents are unknown. The wrong answer this guards against is an
    /// empty success — before the fix a corrupt or decompression-bomb-capped
    /// archive produced no artifacts at all, which is exactly what a file that
    /// was never a gzip produces, so the archive read as "nothing inside".
    #[test]
    fn test_gzip_corrupted_data_emits_incompleteness_status() {
        let module = GzipExpanderModule;
        // Valid gzip header but corrupted content
        let data = vec![
            0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF,
        ];

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "corrupted.gz", "subtype": "gzip"}),
        );

        // Should not panic, and must not report an empty success.
        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "a failed expansion must be recorded");
        let status = &results[0];
        assert_eq!(status.metadata["record_type"], json!("archive_scan_status"));
        assert_eq!(status.metadata["content_incomplete"], json!(true));
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            json!("gzip_decompress_failed")
        );
        assert_eq!(status.metadata["inventory_incomplete"], json!(true));
        assert_eq!(status.metadata["container_path"], json!("corrupted.gz"));
        assert_eq!(status.parent_id, Some(artifact.id));
    }

    /// The counterpart: a `.gz` name with no gzip header was never ours, and
    /// must not be reported as an archive we failed to expand. A stamp that
    /// fires on every mislabelled file on the disk tells an examiner nothing.
    #[test]
    fn test_gzip_without_magic_is_silent() {
        let module = GzipExpanderModule;
        let data = b"plain text that merely ends in .gz".to_vec();

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "notreally.gz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "a file without the gzip header is not a failed gzip archive"
        );
    }

    /// The honest counterpart: a stream that expanded fully carries no
    /// incompleteness stamp, so the flag means something when it is present.
    #[test]
    fn test_gzip_complete_stream_is_not_stamped_incomplete() {
        let module = GzipExpanderModule;
        let gz_data = make_gzip_data(b"complete payload");
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "ok.txt.gz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].metadata.get("content_incomplete").is_none());
    }

    #[test]
    fn test_gzip_empty_content() {
        let module = GzipExpanderModule;
        let gz_data = make_gzip_data(b"");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "empty.gz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["size"], 0);
    }

    #[test]
    fn test_gzip_extension_detection() {
        let module = GzipExpanderModule;
        let gz_data = make_gzip_data(b"test");

        // Test .gzip extension
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "file.gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "file");
    }

    /// Every decompressed byte of an expanded child.
    fn child_bytes(child: &Artifact) -> Vec<u8> {
        let ds = child
            .data
            .as_ref()
            .expect("an expanded child carries its bytes");
        let mut out = vec![0u8; ds.size() as usize];
        assert_eq!(read_full(ds.as_ref(), 0, &mut out), out.len());
        out
    }

    fn fixture_artifact(name: &str, bytes: &[u8]) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource {
                data: bytes.to_vec(),
            }) as Arc<dyn DataSource>),
            json!({"name": name, "subtype": "gzip"}),
        )
    }

    /// HUNT-169. Real `gzip -n` output of two files appended with `cat` — the
    /// rotated-log shape, and what `pigz`-style tools and RFC 1952 itself
    /// allow ("a gzip file consists of a series of members"). `zcat` prints
    /// both. The expander used the single-member decoder, so the child held
    /// the first member only and was published as the whole file, with
    /// nothing saying more followed.
    #[test]
    fn every_member_of_a_concatenated_gzip_is_expanded() {
        let data = include_bytes!("../tests/fixtures/multi_member.gz");
        let out = GzipExpanderModule
            .process(&fixture_artifact("rotated.log.gz", data))
            .unwrap();
        assert_eq!(out.len(), 1);
        let child = &out[0];
        assert_eq!(
            child_bytes(child),
            b"first member: rotated log line one\nsecond member: appended with cat\n".to_vec(),
            "both members must reach the child, as `zcat` shows them"
        );
        assert_eq!(child.metadata["size"], json!(68));
        assert_eq!(child.metadata["compressed_members"], json!(2));
        assert!(child
            .metadata
            .get("trailing_bytes_after_last_member")
            .is_none());
        assert!(child.metadata.get("content_incomplete").is_none());
    }

    /// HUNT-169, the second half. `gzip -t` on this real file says
    /// "decompression OK, trailing garbage ignored": 33 bytes follow the last
    /// member and are not a member. They were never decoded, so the record
    /// must say where they start and how many there are — they may be the
    /// remains of a member whose header was overwritten.
    #[test]
    fn bytes_after_the_last_member_are_recorded_not_dropped() {
        let data = include_bytes!("../tests/fixtures/multi_member_trailing_garbage.gz");
        let out = GzipExpanderModule
            .process(&fixture_artifact("rotated.log.gz", data))
            .unwrap();
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["compressed_members"], json!(2));
        assert_eq!(m["trailing_bytes_offset"], json!(108));
        assert_eq!(m["trailing_bytes_after_last_member"], json!(33));
        assert_eq!(m["trailing_bytes_all_zero"], json!(false));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!(IncompleteReason::UnresolvedStructure.as_str())
        );
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("33 bytes"));
    }

    /// Zero padding after the last member (a tape or block-device write) is
    /// counted but is not a gap: zeros cannot hold a member. `gzip -t` is
    /// silent about it, and so is the incompleteness flag.
    #[test]
    fn zero_padding_after_the_last_member_is_counted_but_not_a_gap() {
        let data = include_bytes!("../tests/fixtures/zero_padded.gz");
        let out = GzipExpanderModule
            .process(&fixture_artifact("padded.txt.gz", data))
            .unwrap();
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["compressed_members"], json!(1));
        assert_eq!(m["trailing_bytes_after_last_member"], json!(512));
        assert_eq!(m["trailing_bytes_all_zero"], json!(true));
        assert!(m.get("content_incomplete").is_none());
    }

    /// The ceiling that admitted a stream is a property of the run, and the run
    /// is over by the time anybody reads the report. A reporting process that
    /// re-read the environment would state a number that never governed this
    /// evidence, so the number travels on the artifact the expansion produced.
    #[test]
    fn test_gzip_expanded_child_records_the_ceiling_it_was_admitted_under() {
        let module = GzipExpanderModule;
        let gz_data = make_gzip_data(b"admitted under a ceiling");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: gz_data }) as Arc<dyn DataSource>),
            json!({"name": "payload.txt.gz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].metadata["decompression_ceiling_bytes"],
            json!(max_decompressed_bytes())
        );
        assert!(
            results[0]
                .metadata
                .get("decompression_ceiling_source")
                .and_then(|v| v.as_str())
                .is_some(),
            "the record must also say whether that number was the shipped default or one an \
             examiner set for the run"
        );
    }

    /// The stamp means "this evidence was expanded under that ceiling", never
    /// "a ceiling existed" — which is true of every run and worth nothing. A
    /// refusal already accounts for the cap in its incompleteness detail, so it
    /// must not also be stamped as admitted.
    #[test]
    fn a_refused_stream_is_not_stamped_as_admitted_under_the_ceiling() {
        let module = GzipExpanderModule;
        let data = vec![
            0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF,
        ];

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "corrupted.gz", "subtype": "gzip"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0]
                .metadata
                .get("decompression_ceiling_bytes")
                .is_none(),
            "a stream that was refused was never admitted under the ceiling"
        );
    }
}
