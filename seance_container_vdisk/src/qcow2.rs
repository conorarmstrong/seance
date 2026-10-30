use byteorder::{BigEndian, ByteOrder};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_exact_or_fail, read_full},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::fmt;
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};

// QCOW2 magic: "QFI\xFB"
const QCOW2_MAGIC: u32 = 0x514649FB;

pub struct Qcow2ContainerModule;

impl ForensicsModule for Qcow2ContainerModule {
    fn id(&self) -> &str {
        "container.qcow2_reader"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if let Some(subtype) = artifact.subtype() {
            if subtype != "qcow2" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".qcow2") && !name.ends_with(".qcow") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.qcow2")
            .to_string();

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("QCOW2 module requires data source".to_string())
        })?;

        if data_source.size() < 72 {
            return Ok(Vec::new());
        }

        // Read QCOW2 header (72 bytes minimum for v2, 104 for v3). One `read_at`
        // may legitimately return fewer bytes than asked (a windowed/chunked
        // source), so loop for the honest count instead of mistaking a short
        // return for a too-small file (BUG-284).
        let mut header = [0u8; 104];
        let read = read_full(data_source.as_ref(), 0, &mut header);
        if read < 72 {
            return Ok(Vec::new());
        }

        let magic = BigEndian::read_u32(&header[0..4]);
        if magic != QCOW2_MAGIC {
            return Ok(Vec::new());
        }

        let version = BigEndian::read_u32(&header[4..8]);
        if !(2..=3).contains(&version) {
            warn!("Unsupported QCOW2 version {}: {}", version, name);
            return Ok(Vec::new());
        }

        let backing_file_offset = BigEndian::read_u64(&header[8..16]);
        let cluster_bits = BigEndian::read_u32(&header[20..24]);
        let disk_size = BigEndian::read_u64(&header[24..32]);
        let crypt_method = BigEndian::read_u32(&header[32..36]);
        let l1_size = BigEndian::read_u32(&header[36..40]);
        let l1_table_offset = BigEndian::read_u64(&header[40..48]);

        if crypt_method != 0 {
            return Err(ModuleError::ParsingError(format!(
                "encrypted qcow2 unsupported: {} (crypt_method={})",
                name, crypt_method
            )));
        }

        if version >= 3 {
            if read < 104 {
                return Err(ModuleError::ParsingError(format!(
                    "Truncated qcow2 v3 header in {}: got {} of 104 bytes",
                    name, read
                )));
            }
            // Any incompatible feature bit we do not implement (i.e. all of them)
            // means reads would be misinterpreted — hard-error per the spec.
            let incompatible_features = BigEndian::read_u64(&header[72..80]);
            if incompatible_features != 0 {
                return Err(ModuleError::ParsingError(format!(
                    "qcow2 {} has unsupported incompatible feature bits: 0x{:016X}",
                    name, incompatible_features
                )));
            }
        }

        // QCOW2 spec: cluster_bits must be 9..=21 (512 bytes to 2MB clusters)
        if !(9..=21).contains(&cluster_bits) {
            warn!(
                "QCOW2 {} has invalid cluster_bits={} (must be 9..=21)",
                name, cluster_bits
            );
            return Ok(Vec::new());
        }

        let cluster_size = 1u64 << cluster_bits;

        info!(
            "QCOW2 image: {} (v{}, disk_size={}, cluster_size={})",
            name, version, disk_size, cluster_size
        );

        if backing_file_offset != 0 {
            // Unallocated clusters live in the backing file; reading them as
            // zeros here would fabricate evidence bytes.
            return Err(ModuleError::ParsingError(format!(
                "qcow2 backing file unsupported: {} (differencing image would read as zeros)",
                name
            )));
        }

        let qcow2_source = match Qcow2DataSource::new(
            data_source.clone(),
            disk_size,
            cluster_size,
            cluster_bits,
            l1_size,
            l1_table_offset,
        ) {
            Ok(source) => source,
            Err(e) => {
                return Err(ModuleError::ParsingError(format!(
                    "Failed to parse QCOW2 {}: {}",
                    name, e
                )));
            }
        };

        let metadata = json!({
            "name": name,
            "container": "qcow2",
            "qcow2_version": version,
            "disk_size": disk_size,
            "cluster_size": cluster_size,
            "has_backing_file": backing_file_offset != 0,
        });

        let child = Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(Arc::new(qcow2_source)),
            metadata,
        )
        .with_parent(artifact.id);

        info!("QCOW2 {} -> RawEvidence ({} bytes)", name, disk_size);

        Ok(vec![child])
    }
}

/// DataSource for QCOW2 images.
///
/// Uses two-level lookup:
/// - L1 table: top-level table entries pointing to L2 tables
/// - L2 table: cluster-level entries pointing to data clusters
///
/// Unallocated entries return zeros. Compressed clusters are not supported
/// in this initial implementation.
struct Qcow2DataSource {
    inner: Arc<dyn DataSource>,
    disk_size: u64,
    cluster_size: u64,
    cluster_bits: u32,
    l1_table: Vec<u64>,
    l2_entries_per_table: u64,
}

impl fmt::Debug for Qcow2DataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Qcow2DataSource")
            .field("disk_size", &self.disk_size)
            .field("cluster_size", &self.cluster_size)
            .field("l1_entries", &self.l1_table.len())
            .finish()
    }
}

impl Qcow2DataSource {
    fn new(
        inner: Arc<dyn DataSource>,
        disk_size: u64,
        cluster_size: u64,
        cluster_bits: u32,
        l1_size: u32,
        l1_table_offset: u64,
    ) -> Result<Self, String> {
        // Sanity check: limit L1 table to 1M entries
        if l1_size > 1_048_576 {
            return Err(format!(
                "L1 table too large: {} entries (max 1048576)",
                l1_size
            ));
        }

        // Read L1 table. Fail closed on a short read, but loop first so a source
        // that dribbles bytes is not mistaken for a truncated image (BUG-284).
        let l1_byte_size = l1_size as usize * 8;
        let mut l1_buf = vec![0u8; l1_byte_size];
        read_exact_or_fail(
            inner.as_ref(),
            l1_table_offset,
            &mut l1_buf,
            "qcow2 L1 table",
        )
        .map_err(|e| format!("Failed to read L1 table: {}", e))?;

        let l1_table: Vec<u64> = l1_buf
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| BigEndian::read_u64(c))
            .collect();

        // Each L2 table covers cluster_size/8 entries (each entry is 8 bytes)
        let l2_entries_per_table = cluster_size / 8;

        debug!(
            "QCOW2: l1_entries={}, l2_entries_per_table={}, cluster_size={}",
            l1_table.len(),
            l2_entries_per_table,
            cluster_size
        );

        Ok(Self {
            inner,
            disk_size,
            cluster_size,
            cluster_bits,
            l1_table,
            l2_entries_per_table,
        })
    }

    /// Resolve a logical offset to a physical offset.
    /// Returns None for unallocated clusters.
    fn resolve_offset(&self, logical_offset: u64) -> io::Result<Option<u64>> {
        let cluster_idx = logical_offset >> self.cluster_bits;
        let l1_idx = (cluster_idx / self.l2_entries_per_table) as usize;
        let l2_idx = cluster_idx % self.l2_entries_per_table;

        if l1_idx >= self.l1_table.len() {
            return Ok(None);
        }

        let l1_entry = self.l1_table[l1_idx];
        // Bit 63 is reserved/copy-on-read flag, bits 0-8 reserved
        // The L2 table offset is bits 9-55
        let l2_table_offset = l1_entry & 0x00FFFFFFFFFFFE00;

        if l2_table_offset == 0 {
            return Ok(None); // L2 table not allocated
        }

        // Read the specific L2 entry
        let l2_entry_offset = l2_table_offset + l2_idx * 8;
        let mut l2_buf = [0u8; 8];
        read_exact_or_fail(
            self.inner.as_ref(),
            l2_entry_offset,
            &mut l2_buf,
            "qcow2 L2 entry",
        )?;
        let l2_entry = BigEndian::read_u64(&l2_buf);

        // Bit 62: compressed flag — decompression is not implemented, and
        // returning zeros would fabricate evidence bytes.
        if l2_entry & (1 << 62) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "compressed qcow2 clusters unsupported (cluster at logical offset {})",
                    logical_offset
                ),
            ));
        }

        // Bit 0 (QCOW2 v3): a standard cluster with the "all zeros" flag set
        // reads as zeros regardless of any preallocated host offset. Not
        // honouring it would surface stale preallocated bytes as evidence.
        // On v2 this bit is reserved/zero, so the check is a no-op there.
        if l2_entry & 1 != 0 {
            return Ok(None);
        }

        // Bit 63: standard cluster descriptor
        // Bits 9-55: host cluster offset
        let cluster_offset = l2_entry & 0x00FFFFFFFFFFFE00;
        if cluster_offset == 0 {
            return Ok(None); // Not allocated
        }

        let offset_in_cluster = logical_offset & (self.cluster_size - 1);
        // The 56-bit host-offset mask above already bounds cluster_offset well
        // below u64::MAX, so this cannot wrap today; use checked arithmetic anyway
        // to fail closed on any future change, matching the rest of the container
        // read paths, rather than ever wrapping to unrelated host bytes.
        let physical = cluster_offset
            .checked_add(offset_in_cluster)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "qcow2 host offset overflow: cluster_offset {} + {}",
                        cluster_offset, offset_in_cluster
                    ),
                )
            })?;
        Ok(Some(physical))
    }
}

impl DataSource for Qcow2DataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.disk_size {
            return Ok(0);
        }

        let mut total_read = 0;
        let mut current_offset = offset;

        while total_read < buf.len() && current_offset < self.disk_size {
            let offset_in_cluster = current_offset & (self.cluster_size - 1);
            let remaining_in_cluster = self.cluster_size - offset_in_cluster;
            let to_read = (buf.len() - total_read)
                .min(remaining_in_cluster as usize)
                .min((self.disk_size - current_offset) as usize);

            match self.resolve_offset(current_offset)? {
                Some(physical_offset) => {
                    let read = self
                        .inner
                        .read_at(physical_offset, &mut buf[total_read..total_read + to_read])?;
                    if read < to_read {
                        // Allocated cluster truncated by EOF — never fabricate zeros
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "Short read in allocated cluster: got {} of {} bytes at physical offset {}",
                                read, to_read, physical_offset
                            ),
                        ));
                    }
                }
                None => {
                    buf[total_read..total_read + to_read].fill(0);
                }
            }

            total_read += to_read;
            current_offset += to_read as u64;
        }

        Ok(total_read)
    }

    fn size(&self) -> u64 {
        self.disk_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::module::ForensicsModule;
    use seance_core::test_support::DribbleSource;

    use seance_core::data_source::ByteSliceDataSource;

    fn make_qcow2_header(
        version: u32,
        disk_size: u64,
        cluster_bits: u32,
        l1_size: u32,
        l1_offset: u64,
    ) -> Vec<u8> {
        let mut header = vec![0u8; 104];
        // magic
        header[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        // version
        header[4..8].copy_from_slice(&version.to_be_bytes());
        // backing_file_offset = 0
        // cluster_bits at offset 20
        header[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
        // disk_size at offset 24
        header[24..32].copy_from_slice(&disk_size.to_be_bytes());
        // l1_size at offset 36
        header[36..40].copy_from_slice(&l1_size.to_be_bytes());
        // l1_table_offset at offset 40
        header[40..48].copy_from_slice(&l1_offset.to_be_bytes());
        header
    }

    #[test]
    fn test_qcow2_skip_non_qcow2() {
        let module = Qcow2ContainerModule;
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "file.txt"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_qcow2_skip_too_small() {
        let module = Qcow2ContainerModule;
        let data = vec![0u8; 50];
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "tiny.qcow2", "subtype": "qcow2"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_qcow2_invalid_magic() {
        let module = Qcow2ContainerModule;
        let data = vec![0u8; 512];
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "bad.qcow2", "subtype": "qcow2"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_qcow2_unsupported_version() {
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(1, 1024 * 1024, 16, 1, 512);
        data.resize(1024, 0);

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "old.qcow2", "subtype": "qcow2"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty(), "QCOW2 v1 should be rejected");
    }

    #[test]
    fn test_qcow2_version_4_rejected() {
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(4, 1024 * 1024, 16, 1, 512);
        data.resize(1024, 0);

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "future.qcow2", "subtype": "qcow2"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty(), "QCOW2 v4 should be rejected");
    }

    #[test]
    fn test_qcow2_valid_v2() {
        let module = Qcow2ContainerModule;
        let disk_size = 64 * 1024u64; // 64KB disk
        let cluster_bits = 16u32; // 64KB clusters
        let l1_size = 1u32;
        let l1_offset = 512u64;
        let mut data = make_qcow2_header(2, disk_size, cluster_bits, l1_size, l1_offset);
        data.resize(4096, 0);
        // L1 table at offset 512: single entry = 0 (unallocated)

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "test.qcow2", "subtype": "qcow2"}),
        );
        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].artifact_type, ArtifactType::RawEvidence);
        assert_eq!(results[0].metadata["qcow2_version"], 2);
        assert_eq!(results[0].metadata["disk_size"], disk_size);
    }

    // === Qcow2DataSource edge cases ===

    #[test]
    fn test_qcow2_l1_too_large() {
        let data = vec![0u8; 4096];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let result = Qcow2DataSource::new(
            inner,
            1024 * 1024, // disk_size
            65536,       // cluster_size
            16,          // cluster_bits
            2_000_000,   // l1_size — exceeds 1M limit
            512,         // l1_table_offset
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("L1 table too large"));
    }

    #[test]
    fn test_qcow2_unallocated_read() {
        let data = vec![0u8; 4096];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(
            inner, 65536, // 64KB disk
            65536, // 64KB clusters
            16,    // cluster_bits
            1,     // l1_size
            512,   // l1_table_offset (all zeros = unallocated)
        )
        .unwrap();

        let mut buf = vec![0xFFu8; 512];
        let read = source.read_at(0, &mut buf).unwrap();
        assert_eq!(read, 512);
        assert!(
            buf.iter().all(|&b| b == 0),
            "Unallocated cluster should read as zeros"
        );
    }

    fn make_artifact(data: Vec<u8>) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "test.qcow2", "subtype": "qcow2"}),
        )
    }

    #[test]
    fn test_qcow2_encrypted_rejected() {
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(2, 65536, 16, 1, 512);
        // crypt_method at offset 32: 1 = AES
        data[32..36].copy_from_slice(&1u32.to_be_bytes());
        data.resize(4096, 0);

        let result = module.process(&make_artifact(data));
        let err = result.expect_err("encrypted qcow2 must error, not read as garbage");
        assert!(format!("{}", err).contains("encrypted"), "got: {}", err);
    }

    #[test]
    fn test_qcow2_backing_file_rejected() {
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(2, 65536, 16, 1, 512);
        // backing_file_offset at offset 8
        data[8..16].copy_from_slice(&400u64.to_be_bytes());
        data.resize(4096, 0);

        let result = module.process(&make_artifact(data));
        let err = result.expect_err("qcow2 with backing file must error, not fabricate zeros");
        assert!(format!("{}", err).contains("backing"), "got: {}", err);
    }

    #[test]
    fn test_qcow2_v3_incompatible_features_rejected() {
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(3, 65536, 16, 1, 512);
        // incompatible_features at offset 72: bit 3 = compression type
        data[72..80].copy_from_slice(&(1u64 << 3).to_be_bytes());
        data.resize(4096, 0);

        let result = module.process(&make_artifact(data));
        let err = result.expect_err("qcow2 v3 with incompatible features must error");
        assert!(format!("{}", err).contains("incompatible"), "got: {}", err);
    }

    #[test]
    fn test_qcow2_v3_clean_accepted() {
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(3, 65536, 16, 1, 512);
        data.resize(4096, 0);

        let results = module.process(&make_artifact(data)).unwrap();
        assert_eq!(
            results.len(),
            1,
            "v3 with no incompatible features should be accepted"
        );
    }

    #[test]
    fn test_qcow2_compressed_cluster_read_errors() {
        // L1 -> L2 -> compressed cluster (bit 62): must error, not read as zeros
        let mut data = vec![0u8; 2048];
        // L1 at byte 512: entry -> L2 table at byte 1024
        data[512..520].copy_from_slice(&1024u64.to_be_bytes());
        // L2 entry 0: compressed flag set
        data[1024..1032].copy_from_slice(&((1u64 << 62) | 0x600).to_be_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(inner, 512, 512, 9, 1, 512).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let result = source.read_at(0, &mut buf);
        assert!(
            result.is_err(),
            "compressed cluster must error, not return zeros"
        );
    }

    #[test]
    fn test_qcow2_truncated_l1_errors() {
        let data = vec![0u8; 1024];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        // L1 table at byte 2048, beyond EOF: short read must error
        let result = Qcow2DataSource::new(inner, 65536, 65536, 16, 1, 2048);
        assert!(
            result.is_err(),
            "truncated L1 table must error, not read as zeros"
        );
    }

    #[test]
    fn test_qcow2_truncated_l2_errors() {
        // L1 entry points to an L2 table beyond EOF
        let mut data = vec![0u8; 1024];
        data[512..520].copy_from_slice(&65536u64.to_be_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(inner, 512, 512, 9, 1, 512).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let result = source.read_at(0, &mut buf);
        assert!(
            result.is_err(),
            "truncated L2 table read must error, not read as zeros"
        );
    }

    #[test]
    fn test_qcow2_short_cluster_read_errors() {
        // Allocated cluster truncated by EOF must error, not zero-fill
        let mut data = vec![0u8; 1600];
        // L1 at byte 512 -> L2 at byte 1024
        data[512..520].copy_from_slice(&1024u64.to_be_bytes());
        // L2 entry 0 -> cluster at byte 1536; only 64 bytes exist before EOF
        data[1024..1032].copy_from_slice(&1536u64.to_be_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(inner, 512, 512, 9, 1, 512).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let result = source.read_at(0, &mut buf);
        assert!(
            result.is_err(),
            "short read within an allocated cluster must error, not zero-fill"
        );
    }

    #[test]
    fn test_qcow2_zero_flag_reads_zeros_not_preallocated() {
        // QCOW2 v3 standard cluster with the "all zeros" flag (bit 0) set AND a
        // preallocated host offset pointing at non-zero bytes. The cluster must
        // read as zeros, never the stale preallocated data.
        let mut data = vec![0u8; 2048];
        // L1 at byte 512 -> L2 table at byte 1024
        data[512..520].copy_from_slice(&1024u64.to_be_bytes());
        // Preallocated host cluster at byte 1536 filled with stale 0xAB bytes
        for b in &mut data[1536..2048] {
            *b = 0xAB;
        }
        // L2 entry 0: host offset 1536 with the zero-flag (bit 0) set
        data[1024..1032].copy_from_slice(&(1536u64 | 1).to_be_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(inner, 512, 512, 9, 1, 512).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let read = source.read_at(0, &mut buf).unwrap();
        assert_eq!(read, 512);
        assert!(
            buf.iter().all(|&b| b == 0),
            "zero-flagged cluster must read as zeros, not preallocated 0xAB"
        );
    }

    #[test]
    fn test_qcow2_read_beyond_disk() {
        let data = vec![0u8; 4096];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(inner, 1024, 65536, 16, 1, 512).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let read = source.read_at(source.size(), &mut buf).unwrap();
        assert_eq!(read, 0);
    }

    #[test]
    fn test_qcow2_partial_read_at_end() {
        let data = vec![0u8; 4096];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = Qcow2DataSource::new(inner, 1024, 65536, 16, 1, 512).unwrap();

        // Read starting 256 bytes before the end — should return exactly 256 bytes
        let mut buf = vec![0xFFu8; 512];
        let read = source.read_at(1024 - 256, &mut buf).unwrap();
        assert_eq!(read, 256);
    }
    #[test]
    fn test_qcow2_header_read_loops_over_short_reads() {
        // BUG-284: one `read_at` may return fewer than 72 bytes even though the
        // whole header is present. Treating that as "too small" made a valid
        // image undetectable behind a chunked source.
        let module = Qcow2ContainerModule;
        let mut data = make_qcow2_header(2, 65536, 16, 1, 512);
        data.resize(4096, 0);

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(DribbleSource::new(data, 16)) as Arc<dyn DataSource>),
            json!({"name": "chunked.qcow2", "subtype": "qcow2"}),
        );
        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "a chunked source must still open");
        assert_eq!(results[0].metadata["disk_size"], json!(65536));
    }
}
