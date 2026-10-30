use crate::status::expansion_failed_status;
use cfb::CompoundFile;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource, SourceCursor},
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::io::Read;
use std::sync::Arc;
use tracing::{debug, warn};

/// Hard cap on how many bytes of a single OLE2 stream to materialise into memory
/// so downstream parsers/hashing can read it. Legacy Office streams are small; a
/// stream above this ceiling is left as metadata-only rather than buffered.
const MAX_OLE2_STREAM: u64 = 256 * 1024 * 1024;

/// The OLE2 / CFB file signature.
const OLE2_MAGIC: &[u8; 8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

pub struct Ole2ExpanderModule;

impl ForensicsModule for Ole2ExpanderModule {
    fn id(&self) -> &str {
        "container.ole2_expander"
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
            if subtype != "ole2" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".doc")
                && !name.ends_with(".xls")
                && !name.ends_with(".ppt")
                && !name.ends_with(".ole2")
            {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.ole2")
            .to_string();

        debug!("Ole2ExpanderModule processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("OLE2 module requires data source".to_string())
        })?;

        // Is this actually a compound file? The gate above accepts an
        // extension, which a file may carry without being OLE2 at all.
        let mut magic = [0u8; 8];
        let read = read_full(data_source.as_ref(), 0, &mut magic);
        let claims_ole2 = read == OLE2_MAGIC.len() && &magic == OLE2_MAGIC;

        let cursor = SourceCursor::new(data_source.clone());

        let mut comp = match CompoundFile::open(cursor) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to open OLE2 compound file {}: {}", name, e);
                if !claims_ole2 {
                    // No signature: this file was simply never ours.
                    return Ok(Vec::new());
                }
                // Signature present but the container will not parse. Producing
                // nothing here would be indistinguishable from "not our format",
                // so the examiner would never learn that a real compound
                // document was left unexamined (B3-031, same class).
                return Ok(vec![expansion_failed_status(
                    artifact,
                    "ole2",
                    &name,
                    "ole2_unreadable",
                    &e.to_string(),
                )]);
            }
        };

        let mut produced_artifacts = Vec::new();

        // Walk the directory tree first, collecting owned descriptors so the
        // compound file can then be re-borrowed mutably to read each stream.
        let descriptors: Vec<(String, bool, u64)> = comp
            .walk()
            .map(|e| {
                (
                    e.path().to_string_lossy().to_string(),
                    e.is_stream(),
                    e.len(),
                )
            })
            .collect();

        for (path, is_stream, size) in descriptors {
            // Materialise each stream's bytes so downstream hashing/carving/plugins
            // run on real content (ZIP/TAR attach lazy sources; OLE2 streams are
            // small, so an eager bounded read is simplest). A stream above the cap,
            // or one that reads short/errors, is left as metadata-only rather than
            // serving truncated bytes as complete -- and says so, because a
            // FileEntry carrying the directory's full `size` with no bytes and no
            // explanation reads as an empty stream (B3-030).
            let mut content: Option<Arc<dyn DataSource>> = None;
            // (reason, bytes actually read, decoder detail)
            let mut incomplete: Option<(&'static str, Option<u64>, Option<String>)> = None;

            if is_stream && size > 0 {
                if size > MAX_OLE2_STREAM {
                    warn!(
                        "OLE2 {}: stream {} is {} bytes, above the {}-byte materialisation cap; \
                         emitting it as metadata-only",
                        name, path, size, MAX_OLE2_STREAM
                    );
                    incomplete = Some((IncompleteReason::CapReached.as_str(), None, None));
                } else {
                    match comp.open_stream(&path) {
                        Ok(mut stream) => {
                            let mut buf = Vec::with_capacity(size as usize);
                            match stream.read_to_end(&mut buf) {
                                Ok(_) if buf.len() as u64 == size => {
                                    content = Some(Arc::new(ByteSliceDataSource::new(buf))
                                        as Arc<dyn DataSource>);
                                }
                                Ok(_) => {
                                    warn!(
                                        "OLE2 {}: stream {} claims {} bytes but only {} could be \
                                         read",
                                        name,
                                        path,
                                        size,
                                        buf.len()
                                    );
                                    incomplete = Some((
                                        IncompleteReason::ShortRead.as_str(),
                                        Some(buf.len() as u64),
                                        None,
                                    ));
                                }
                                Err(e) => {
                                    warn!("OLE2 {}: stream {} read failed: {}", name, path, e);
                                    incomplete = Some((
                                        IncompleteReason::ShortRead.as_str(),
                                        Some(buf.len() as u64),
                                        Some(e.to_string()),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            warn!("OLE2 {}: stream {} could not be opened: {}", name, path, e);
                            incomplete = Some((
                                IncompleteReason::UnresolvedStructure.as_str(),
                                None,
                                Some(e.to_string()),
                            ));
                        }
                    }
                }
            }

            let mut metadata = json!({
                "name": path,
                "size": size,
                "is_directory": !is_stream,
                "is_stream": is_stream,
                "container": "ole2",
                "container_path": name,
            });

            if let Some((reason, available, detail)) = incomplete {
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(reason);
                if let Some(available) = available {
                    metadata["available_size"] = json!(available);
                }
                if let Some(detail) = detail {
                    metadata["content_incomplete_detail"] = json!(detail);
                }
            }

            let child = Artifact::new(artifact.case_id, ArtifactType::FileEntry, content, metadata)
                .with_parent(artifact.id);

            produced_artifacts.push(child);
        }

        debug!(
            "Extracted {} streams/entries from OLE2 file {}",
            produced_artifacts.len(),
            name
        );

        Ok(produced_artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
    use seance_core::test_support::TruncatedSource;
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

    #[test]
    fn test_ole2_skip_non_ole2() {
        let module = Ole2ExpanderModule;
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
    fn test_ole2_skip_wrong_subtype() {
        let module = Ole2ExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            None,
            json!({"name": "file.zip", "subtype": "zip"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    /// A file carrying the OLE2 signature that will not open is a compound
    /// document this ingest could not read. Reporting nothing would file it
    /// alongside every non-OLE2 file on the disk, so the examiner would never
    /// learn a document was skipped.
    #[test]
    fn test_ole2_corrupted_data_is_reported_not_silent() {
        let module = Ole2ExpanderModule;
        // OLE2 magic but truncated/corrupted content
        let mut data = vec![0u8; 512];
        data[0..8].copy_from_slice(OLE2_MAGIC);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "corrupted.doc", "subtype": "ole2"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(
            results.len(),
            1,
            "a signed-but-unreadable compound file must be recorded"
        );
        assert_eq!(
            results[0].metadata["record_type"],
            json!("archive_scan_status")
        );
        assert_eq!(results[0].metadata["content_incomplete"], json!(true));
        assert_eq!(
            results[0].metadata["content_incomplete_reason"],
            json!("ole2_unreadable")
        );
    }

    /// The counterpart: a file that merely has a `.doc` name but no OLE2
    /// signature was never ours, and must not be reported as a failed archive.
    #[test]
    fn test_ole2_non_ole2_content_is_silent() {
        let module = Ole2ExpanderModule;
        let data = b"plain text pretending to be a document".to_vec();

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "notreally.doc"}),
        );

        let results = module.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "a file without the OLE2 signature is not a failed OLE2 archive"
        );
    }

    #[test]
    fn test_ole2_no_data_source() {
        let module = Ole2ExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            None,
            json!({"name": "file.doc", "subtype": "ole2"}),
        );
        let result = module.process(&artifact);
        assert!(result.is_err());
    }

    #[test]
    fn test_ole2_attaches_stream_content() {
        // BUG-096: OLE2 stream entries must carry a DataSource with their real
        // bytes so downstream hashing/carving/plugins can run, not metadata only.
        use cfb::CompoundFile;
        use std::io::{Cursor, Write};

        let payload = b"hello ole2 stream content";
        let mut backing = Cursor::new(Vec::new());
        {
            let mut comp = CompoundFile::create(&mut backing).unwrap();
            {
                let mut stream = comp.create_stream("/Contents").unwrap();
                stream.write_all(payload).unwrap();
            }
            comp.flush().unwrap();
        }
        let data = backing.into_inner();

        let module = Ole2ExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "doc.ole2", "subtype": "ole2"}),
        );

        let results = module.process(&artifact).unwrap();
        let stream_entry = results
            .iter()
            .find(|a| a.metadata["is_stream"] == json!(true))
            .expect("a stream entry should be produced");
        let ds = stream_entry
            .data
            .as_ref()
            .expect("stream content should be attached");
        assert_eq!(ds.size(), payload.len() as u64);
        let mut got = vec![0u8; payload.len()];
        let n = ds.read_at(0, &mut got).unwrap();
        assert_eq!(&got[..n], payload);
        // A stream that was materialised in full must carry no incompleteness
        // stamp, so the stamp means something when it is present.
        assert!(
            stream_entry.metadata.get("content_incomplete").is_none(),
            "a fully materialised stream must not be flagged incomplete"
        );
    }
    /// B3-030: an OLE2 stream whose bytes could not be materialised must say so.
    ///
    /// What an examiner learns: this stream is listed at its directory size but
    /// none of its bytes were recovered, and why. The wrong answer this guards
    /// against is a FileEntry carrying the full `size` with no content and no
    /// explanation — which renders identically to a stream that genuinely held
    /// nothing, and hides that the document body was never examined.
    #[test]
    fn test_ole2_unreadable_stream_is_flagged_incomplete() {
        use cfb::CompoundFile;
        use std::io::{Cursor, Write};

        // 16 KiB of payload: past the 4096-byte mini-stream threshold (so the
        // bytes occupy full sectors appended after the header, FAT and
        // directory) but inside one FAT sector's 128 entries, so nothing but
        // stream data lives in the tail.
        let payload = vec![0xABu8; 16 * 1024];
        let mut backing = Cursor::new(Vec::new());
        {
            let mut comp = CompoundFile::create(&mut backing).unwrap();
            {
                let mut stream = comp.create_stream("/Contents").unwrap();
                stream.write_all(&payload).unwrap();
            }
            comp.flush().unwrap();
        }
        let data = backing.into_inner();
        // Cut the last 4 KiB of stream data; the header, FAT and directory at
        // the front still parse, so the container opens and lists the stream.
        let readable = data.len() - 4 * 1024;

        let module = Ole2ExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(TruncatedSource::cut_to(data, readable)) as Arc<dyn DataSource>),
            json!({"name": "truncated.doc", "subtype": "ole2"}),
        );

        let results = module.process(&artifact).unwrap();
        let stream_entry = results
            .iter()
            .find(|a| a.metadata["is_stream"] == json!(true))
            .expect("the truncated container must still list its stream entry");
        assert!(
            stream_entry.data.is_none(),
            "truncated bytes must never be served as the stream's content"
        );
        assert_eq!(stream_entry.metadata["size"], json!(payload.len()));
        assert_eq!(stream_entry.metadata["content_incomplete"], json!(true));
        assert_eq!(
            stream_entry.metadata["content_incomplete_reason"],
            json!("short_read")
        );
    }

    #[test]
    fn test_ole2_extension_matching() {
        let module = Ole2ExpanderModule;
        // Should match .doc, .xls, .ppt, .ole2 extensions
        for ext in &["doc", "xls", "ppt", "ole2"] {
            let artifact = Artifact::new(
                Uuid::new_v4(),
                ArtifactType::FileEntry,
                None,
                json!({"name": format!("file.{}", ext)}),
            );
            // Should not skip (though it will fail on missing data source)
            let result = module.process(&artifact);
            assert!(result.is_err(), "Should try to process .{} files", ext);
        }
    }
}
