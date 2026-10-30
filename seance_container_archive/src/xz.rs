use crate::backing::TempBackedSource;
use crate::status::expansion_failed_status;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, SourceCursor},
    io::read_full,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};
use xz2::read::XzDecoder;

use crate::limits::{self, expansion_failure_detail, max_decompressed_bytes};

/// The `.xz` container header magic.
const XZ_MAGIC: &[u8; 6] = &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

pub struct XzExpanderModule;

impl ForensicsModule for XzExpanderModule {
    fn id(&self) -> &str {
        "container.xz_expander"
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
            if subtype != "xz" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".xz") && !name.ends_with(".txz") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.xz")
            .to_string();

        debug!("XzExpanderModule processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("XZ module requires data source".to_string())
        })?;

        // Is this actually an xz container? The gate above accepts an extension,
        // which a file may carry without being xz at all. Without this check
        // every mislabelled `.xz` would be reported below as an archive we
        // failed to expand, and a stamp that fires on files that were never
        // ours tells the examiner nothing.
        let mut magic = [0u8; 6];
        let read = read_full(data_source.as_ref(), 0, &mut magic);
        let claims_xz = read == XZ_MAGIC.len() && &magic == XZ_MAGIC;

        // Materialize the decompressed stream to a random-access backing store so
        // a downstream tar extractor can window into it (and the API can re-open
        // the inner file later). Bounded by the run's decompression ceiling.
        let decoder = XzDecoder::new(SourceCursor::new(data_source.clone()));
        let backing = match TempBackedSource::from_reader(decoder, max_decompressed_bytes()) {
            Ok(b) => b,
            Err(e) => {
                // A stream we could not expand is not a stream that held
                // nothing: without this record, a corrupt or bomb-capped .xz
                // ingests exactly like a file that was never our format
                // (B3-031).
                warn!("Failed to decompress XZ {}: {}", name, e);
                if !claims_xz {
                    // No xz header: this file was simply never ours.
                    return Ok(Vec::new());
                }
                return Ok(vec![expansion_failed_status(
                    artifact,
                    "xz",
                    &name,
                    "xz_decompress_failed",
                    &expansion_failure_detail(&e),
                )]);
            }
        };
        let decompressed_size = backing.size();
        let backing: Arc<dyn DataSource> = Arc::new(backing);

        let lower_name = name.to_lowercase();
        let inner_name = if lower_name.ends_with(".tar.xz") {
            name[..name.len() - 3].to_string()
        } else if lower_name.ends_with(".txz") {
            format!("{}.tar", &name[..name.len() - 4])
        } else if lower_name.ends_with(".xz") {
            name[..name.len() - 3].to_string()
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
            "container": "xz",
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

        let child = Artifact::new(artifact.case_id, child_type, Some(backing), metadata)
            .with_parent(artifact.id);

        debug!(
            "XZ decompressed {} -> {} ({} bytes)",
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

    fn make_xz_data(content: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use xz2::write::XzEncoder;
        let mut encoder = XzEncoder::new(Vec::new(), 1);
        encoder.write_all(content).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_xz_skip_non_xz() {
        let module = XzExpanderModule;
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
    fn test_xz_decompress_simple() {
        let module = XzExpanderModule;
        let content = b"Hello xz compression test!";
        let xz_data = make_xz_data(content);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: xz_data }) as Arc<dyn DataSource>),
            json!({"name": "test.txt.xz", "subtype": "xz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "test.txt");
        assert_eq!(results[0].metadata["size"], content.len());
        assert_eq!(results[0].metadata["container"], "xz");
    }

    #[test]
    fn test_xz_txz_extension() {
        let module = XzExpanderModule;
        let xz_data = make_xz_data(b"test");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data: xz_data }) as Arc<dyn DataSource>),
            json!({"name": "archive.txz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["name"], "archive.tar");
    }

    #[test]
    fn test_xz_tar_xz_extension() {
        let module = XzExpanderModule;
        let xz_data = make_xz_data(b"test");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: xz_data }) as Arc<dyn DataSource>),
            json!({"name": "data.tar.xz", "subtype": "xz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results[0].metadata["name"], "data.tar");
    }

    /// The counterpart: an `.xz` name with no xz header was never ours, and
    /// must not be reported as an archive we failed to expand. A stamp that
    /// fires on every mislabelled file on the disk tells an examiner nothing.
    #[test]
    fn test_xz_without_magic_is_silent() {
        let module = XzExpanderModule;
        let data = b"plain text that merely ends in .xz".to_vec();

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "notreally.xz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "a file without the xz header is not a failed xz archive"
        );
    }

    /// B3-031: an xz stream that will not decompress must be reported, not
    /// silently dropped.
    ///
    /// What an examiner learns: this `.xz` exists, could not be expanded, and
    /// its contents are unknown. The wrong answer this guards against is an
    /// empty success, which is indistinguishable from "this file was never an
    /// xz archive".
    #[test]
    fn test_xz_corrupted_emits_incompleteness_status() {
        let module = XzExpanderModule;
        // Valid XZ magic but corrupted
        let data = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0xFF, 0xFF];

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "bad.xz", "subtype": "xz"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "a failed expansion must be recorded");
        let status = &results[0];
        assert_eq!(status.metadata["record_type"], json!("archive_scan_status"));
        assert_eq!(status.metadata["content_incomplete"], json!(true));
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            json!("xz_decompress_failed")
        );
        assert_eq!(status.metadata["inventory_incomplete"], json!(true));
        assert_eq!(status.parent_id, Some(artifact.id));
    }

    /// The third tier of the same fact: what ceiling admitted this stream, kept
    /// where a later process can read it without guessing at an environment it
    /// never shared.
    #[test]
    fn test_xz_expanded_child_records_the_ceiling_it_was_admitted_under() {
        let module = XzExpanderModule;
        let xz_data = make_xz_data(b"admitted under a ceiling");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data: xz_data }) as Arc<dyn DataSource>),
            json!({"name": "payload.txt.xz", "subtype": "xz"}),
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
