#![forbid(unsafe_code)]
//! Per-file hashing module.
//!
//! [`FileHasher`] hashes the content of every [`FileEntry`](ArtifactType::FileEntry)
//! that enters the pipeline, computing MD5, SHA1, and SHA256 in a single
//! streaming pass over the file's attached data source. It emits one
//! `file_hash` [`ParsedRecord`](ArtifactType::ParsedRecord) per file; the
//! orchestrator applies those hashes to the parent artifact (columns +
//! metadata) and drops the record.
//!
//! # Registration
//!
//! Register with the orchestrator like any other automatic module:
//!
//! ```rust,ignore
//! orchestrator.register_module(std::sync::Arc::new(seance_plugin_hash::FileHasher::new()));
//! ```
//!
//! # Honesty
//!
//! Files above [`DEFAULT_MAX_HASH_BYTES`] are emitted with `hash_skipped: "size"`
//! and no digests: hashes are never fabricated or truncated silently. Files whose
//! attached content is not their own bytes — fscrypt/EFS ciphertext, clusters no
//! parser could decompress — are skipped the same way, with the reason carried in
//! `hash_skipped`.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::SourceCursor,
    hashing::compute_hashes_streaming_with_progress,
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;

/// Default cap on the number of content bytes hashed per file (2 GiB).
///
/// Files larger than this are emitted with `hash_skipped: "size"` and no
/// digests, rather than spending unbounded time hashing.
pub const DEFAULT_MAX_HASH_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Streaming read buffer size (1 MiB).
const HASH_BUFFER_SIZE: usize = 1024 * 1024;

/// Hashes file content into MD5/SHA1/SHA256 digests.
pub struct FileHasher {
    max_bytes: u64,
}

impl FileHasher {
    pub fn new() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_HASH_BYTES,
        }
    }

    /// Override the per-file size cap. Primarily for tests.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

impl Default for FileHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Why the artifact's attached content is not the file's own bytes, if the
/// parser that produced it said so.
///
/// fscrypt (ext4/F2FS), NTFS EFS, btrfs per-extent encryption and F2FS
/// compression all attach a readable data source over the on-disk extents and
/// then declare the content opaque — `encrypted` / `content_ciphertext` /
/// `compression_unsupported` for display, the standard `content_incomplete`
/// pair for machines. Streaming through such a source digests ciphertext or
/// compressed clusters and files the result in the same hash columns as a
/// plaintext content hash, where it reads as the file's digest: a known-file
/// lookup then reports a non-match as if the file itself differed (HUNT-013).
fn opaque_content_reason(artifact: &Artifact) -> Option<&'static str> {
    let flag = |key: &str| artifact.metadata.get(key).and_then(|v| v.as_bool()) == Some(true);
    let present = |key: &str| artifact.metadata.get(key).is_some_and(|v| !v.is_null());

    if flag("encrypted") || flag("efs_encrypted") || present("content_ciphertext") {
        return Some(IncompleteReason::Encrypted.as_str());
    }
    if present("compression_unsupported") {
        return Some(IncompleteReason::Compressed.as_str());
    }

    // The markers above are per-parser; the incompleteness pair is the contract
    // every producer writes. Only the two reasons that mean "these are not the
    // file's bytes" suppress the hash — `unmapped`, for instance, describes a
    // sparse file whose content really is the zeros we would hash.
    if flag(CONTENT_INCOMPLETE) {
        return match artifact
            .metadata
            .get(CONTENT_INCOMPLETE_REASON)
            .and_then(|v| v.as_str())
            .and_then(IncompleteReason::from_str)
        {
            Some(IncompleteReason::Encrypted) => Some(IncompleteReason::Encrypted.as_str()),
            Some(IncompleteReason::Compressed) => Some(IncompleteReason::Compressed.as_str()),
            _ => None,
        };
    }

    None
}

impl ForensicsModule for FileHasher {
    fn id(&self) -> &str {
        "plugin.hash.file_hasher"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Directories have no content to hash.
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }

        // Files with no attached data source cannot be hashed (e.g. a
        // metadata-only entry whose content was never resolved).
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let size = data.size();

        // The source is readable but the bytes behind it are not this file's
        // content (ciphertext, or clusters we could not decompress). Record why
        // there is no digest rather than hashing the opaque bytes into columns
        // that are read as the file's content hash (HUNT-013).
        if let Some(reason) = opaque_content_reason(artifact) {
            let record = Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "file_hash",
                    "hash_skipped": reason,
                    "size": size,
                }),
            )
            .with_parent(artifact.id);
            return Ok(vec![record]);
        }

        // Above the cap: emit an honest record with no digests.
        if size > self.max_bytes {
            let record = Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "file_hash",
                    "hash_skipped": "size",
                    "size": size,
                }),
            )
            .with_parent(artifact.id);
            return Ok(vec![record]);
        }

        // Stream the content, computing all three digests in one pass and
        // capturing how many bytes were actually read (the progress callback's
        // final value is the cumulative total).
        let mut cursor = SourceCursor::new(data.clone());
        let mut bytes_hashed = 0u64;
        let hashes =
            compute_hashes_streaming_with_progress(&mut cursor, HASH_BUFFER_SIZE, |done| {
                bytes_hashed = done
            })
            .map_err(ModuleError::IoError)?;

        // The source stopped short of its own declared logical size: a truncated
        // image or an I/O error mid-file. Recording these digests would make a
        // partial read look like the authoritative content hash, and a later
        // re-hash of the same truncated view could falsely "verify". Emit an
        // honest short-read record with no digests instead (BUG-158), mirroring
        // the `hash_skipped: "size"` over-cap path.
        if bytes_hashed < size {
            let record = Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "file_hash",
                    "hash_skipped": "short_read",
                    "size": size,
                    "bytes_hashed": bytes_hashed,
                }),
            )
            .with_parent(artifact.id);
            return Ok(vec![record]);
        }

        let record = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "file_hash",
                "md5": hashes.md5,
                "sha1": hashes.sha1,
                "sha256": hashes.sha256,
            }),
        )
        .with_parent(artifact.id);

        Ok(vec![record])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource, RunListDataSource};
    use std::sync::Arc;
    use uuid::Uuid;

    // "hello" digests.
    const MD5: &str = "5d41402abc4b2a76b9719d911017c592";
    const SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    const SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn file_entry(data: Option<Arc<dyn DataSource>>, metadata: serde_json::Value) -> Artifact {
        Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, data, metadata)
    }

    #[test]
    fn module_id_is_stable() {
        assert_eq!(FileHasher::new().id(), "plugin.hash.file_hasher");
    }

    #[test]
    fn known_bytes_produce_known_digests() {
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let artifact = file_entry(Some(data), json!({ "name": "hello.txt" }));

        let out = FileHasher::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1);
        let rec = &out[0];
        assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(rec.parent_id, Some(artifact.id));
        assert_eq!(
            rec.metadata.get("type").and_then(|v| v.as_str()),
            Some("file_hash")
        );
        assert_eq!(rec.metadata.get("md5").and_then(|v| v.as_str()), Some(MD5));
        assert_eq!(
            rec.metadata.get("sha1").and_then(|v| v.as_str()),
            Some(SHA1)
        );
        assert_eq!(
            rec.metadata.get("sha256").and_then(|v| v.as_str()),
            Some(SHA256)
        );
    }

    #[test]
    fn resident_and_runlist_backed_both_hash() {
        // Resident (in-memory) backing.
        let resident: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let resident_out = FileHasher::new()
            .process(&file_entry(Some(resident), json!({ "name": "a" })))
            .unwrap();

        // Run-list backing: same bytes, fragmented into two runs over an inner
        // source, exactly as a filesystem parser would present a file inside an
        // image.
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let runs = vec![(Some(0u64), 2u64), (Some(2u64), 3u64)];
        let runlist: Arc<dyn DataSource> =
            Arc::new(RunListDataSource::from_allocation(inner, runs));
        assert_eq!(runlist.size(), 5);
        let runlist_out = FileHasher::new()
            .process(&file_entry(Some(runlist), json!({ "name": "b" })))
            .unwrap();

        for out in [&resident_out, &runlist_out] {
            assert_eq!(out.len(), 1);
            assert_eq!(
                out[0].metadata.get("md5").and_then(|v| v.as_str()),
                Some(MD5)
            );
            assert_eq!(
                out[0].metadata.get("sha256").and_then(|v| v.as_str()),
                Some(SHA256)
            );
        }
    }

    #[test]
    fn oversize_file_is_skipped_with_flag() {
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        // Cap below the 5-byte payload triggers the size skip.
        let out = FileHasher::new()
            .with_max_bytes(4)
            .process(&file_entry(Some(data), json!({ "name": "big.bin" })))
            .unwrap();

        assert_eq!(out.len(), 1);
        let rec = &out[0];
        assert_eq!(
            rec.metadata.get("type").and_then(|v| v.as_str()),
            Some("file_hash")
        );
        assert_eq!(
            rec.metadata.get("hash_skipped").and_then(|v| v.as_str()),
            Some("size")
        );
        assert!(
            rec.metadata.get("md5").is_none(),
            "oversize record must carry no digests"
        );
        assert!(rec.metadata.get("sha256").is_none());
    }

    #[test]
    fn short_read_source_records_no_digests() {
        // A run-list source whose declared size (10) exceeds the bytes its inner
        // backing can provide (5) simulates a truncated image / mid-file I/O
        // error. The hasher must emit an honest short-read record, not
        // authoritative digests over the partial content (BUG-158).
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let runs = vec![(Some(0u64), 10u64)];
        let src: Arc<dyn DataSource> = Arc::new(RunListDataSource::from_allocation(inner, runs));
        assert_eq!(src.size(), 10);

        let out = FileHasher::new()
            .process(&file_entry(Some(src), json!({ "name": "truncated.bin" })))
            .unwrap();

        assert_eq!(out.len(), 1);
        let rec = &out[0];
        assert_eq!(
            rec.metadata.get("hash_skipped").and_then(|v| v.as_str()),
            Some("short_read")
        );
        assert_eq!(rec.metadata.get("size").and_then(|v| v.as_u64()), Some(10));
        assert_eq!(
            rec.metadata.get("bytes_hashed").and_then(|v| v.as_u64()),
            Some(5)
        );
        assert!(
            rec.metadata.get("md5").is_none(),
            "short-read record must carry no digests"
        );
        assert!(rec.metadata.get("sha256").is_none());
    }

    #[test]
    fn fscrypt_encrypted_file_is_skipped_with_encrypted_reason() {
        // An ext4 fscrypt inode: the extents are attached and readable, but the
        // bytes behind them are ciphertext. Digesting them would file a hash of
        // ciphertext in the file's hash columns (HUNT-013).
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let out = FileHasher::new()
            .process(&file_entry(
                Some(data),
                json!({
                    "name": "secret.txt",
                    "encrypted": true,
                    "content_ciphertext": "ext4_fscrypt",
                    "content_incomplete": true,
                    "content_incomplete_reason": "encrypted",
                }),
            ))
            .unwrap();

        assert_eq!(out.len(), 1);
        let rec = &out[0];
        assert_eq!(
            rec.metadata.get("hash_skipped").and_then(|v| v.as_str()),
            Some("encrypted")
        );
        assert!(
            rec.metadata.get("md5").is_none(),
            "a ciphertext digest must never be recorded as the file's hash"
        );
        assert!(rec.metadata.get("sha1").is_none());
        assert!(rec.metadata.get("sha256").is_none());
    }

    #[test]
    fn efs_ciphertext_marker_alone_is_enough_to_skip() {
        // NTFS EFS marks `efs_encrypted` + `content_ciphertext` rather than the
        // `encrypted` flag the fscrypt parsers use; either shape must skip.
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let out = FileHasher::new()
            .process(&file_entry(
                Some(data),
                json!({
                    "name": "payroll.xlsx",
                    "efs_encrypted": true,
                    "content_ciphertext": "ntfs_efs",
                }),
            ))
            .unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].metadata.get("hash_skipped").and_then(|v| v.as_str()),
            Some("encrypted")
        );
        assert!(out[0].metadata.get("sha256").is_none());
    }

    #[test]
    fn undecompressed_content_is_skipped_with_compressed_reason() {
        // F2FS compressed inodes keep their block pointers, so the reachable
        // bytes are compressed clusters, not the file's content.
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let out = FileHasher::new()
            .process(&file_entry(
                Some(data),
                json!({
                    "name": "packed.bin",
                    "compression_unsupported": "f2fs",
                    "content_incomplete": true,
                    "content_incomplete_reason": "compressed",
                }),
            ))
            .unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].metadata.get("hash_skipped").and_then(|v| v.as_str()),
            Some("compressed")
        );
        assert!(out[0].metadata.get("md5").is_none());
    }

    #[test]
    fn incompleteness_unrelated_to_opacity_still_hashes() {
        // `unmapped` says a range was never allocated, and a sparse file's
        // content genuinely IS zeros there. The skip covers content that is not
        // the file's bytes, not every incompleteness marker.
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let out = FileHasher::new()
            .process(&file_entry(
                Some(data),
                json!({
                    "name": "sparse.bin",
                    "content_incomplete": true,
                    "content_incomplete_reason": "unmapped",
                }),
            ))
            .unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].metadata.get("md5").and_then(|v| v.as_str()),
            Some(MD5)
        );
        assert!(out[0].metadata.get("hash_skipped").is_none());
    }

    #[test]
    fn directory_is_skipped() {
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"hello".to_vec()));
        let out = FileHasher::new()
            .process(&file_entry(
                Some(data),
                json!({ "name": "dir", "is_directory": true }),
            ))
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn file_without_data_source_is_skipped() {
        let out = FileHasher::new()
            .process(&file_entry(None, json!({ "name": "ghost.txt" })))
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn empty_file_hashes_to_empty_digests() {
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(Vec::new()));
        let out = FileHasher::new()
            .process(&file_entry(Some(data), json!({ "name": "empty" })))
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].metadata.get("md5").and_then(|v| v.as_str()),
            Some("d41d8cd98f00b204e9800998ecf8427e"),
        );
    }
}
