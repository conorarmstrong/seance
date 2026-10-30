use byteorder::{ByteOrder, LittleEndian};
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

// VMDK Sparse header magic: "KDMV" (little-endian for VMDK)
const VMDK_SPARSE_MAGIC: u32 = 0x564D444B;

pub struct VmdkContainerModule;

/// Fill `buf` from `ds`, looping over short reads, and report a genuine
/// shortfall as a parse error naming the structure.
///
/// The distinction that matters: a chunked source returning 4 bytes at a time
/// is normal and must be looped over; a source that runs out of bytes is
/// truncated evidence and must not be parsed as a zero-padded structure.
fn read_full_or_parse_error(
    ds: &dyn DataSource,
    offset: u64,
    buf: &mut [u8],
    name: &str,
    what: &str,
) -> Result<(), ModuleError> {
    let got = read_full(ds, offset, buf);
    if got == buf.len() {
        Ok(())
    } else {
        Err(ModuleError::ParsingError(format!(
            "Truncated {} in {}: got {} of {} bytes at offset {}",
            what,
            name,
            got,
            buf.len(),
            offset
        )))
    }
}

impl ForensicsModule for VmdkContainerModule {
    fn id(&self) -> &str {
        "container.vmdk_reader"
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
            if subtype != "vmdk" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".vmdk") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.vmdk")
            .to_string();

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("VMDK module requires data source".to_string())
        })?;

        if data_source.size() < 512 {
            return Ok(Vec::new());
        }

        // Read the header, looping over short reads. A single `read_at` may
        // return fewer bytes than requested (E01/AFF4/archive-backed sources
        // deliver in chunks), so treating one short call as a truncated file
        // rejected perfectly valid sparse VMDKs — the disk simply never opened.
        // VHD and QCOW2 already use the shared loop; this is the same class.
        let mut header = [0u8; 512];
        read_full_or_parse_error(data_source.as_ref(), 0, &mut header, &name, "VMDK header")?;

        let magic = LittleEndian::read_u32(&header[0..4]);
        if magic != VMDK_SPARSE_MAGIC {
            // Could be a descriptor-only VMDK (text file) — not supported as standalone
            // Or a flat VMDK extent — treated as raw
            debug!(
                "VMDK {} does not have sparse magic (got 0x{:08X})",
                name, magic
            );
            return Ok(Vec::new());
        }

        let version = LittleEndian::read_u32(&header[4..8]);
        let flags = LittleEndian::read_u32(&header[8..12]);
        let capacity = LittleEndian::read_u64(&header[12..20]); // in sectors
        let grain_size = LittleEndian::read_u64(&header[20..28]); // in sectors
        let gd_offset = LittleEndian::read_u64(&header[56..64]); // grain directory offset in sectors
        let num_gtes_per_gt = LittleEndian::read_u32(&header[44..48]);
        let overhead = LittleEndian::read_u64(&header[64..72]); // in sectors
        let compress_algorithm = LittleEndian::read_u16(&header[77..79]);

        // Flag bit 16: grains are compressed (streamOptimized). GD offset sentinel
        // 0xFFFFFFFFFFFFFFFF means the grain directory lives in the footer
        // (also streamOptimized). Reading these as plain sparse would fabricate
        // zeros for every grain, so hard-error instead.
        if flags & (1 << 16) != 0 || compress_algorithm != 0 {
            return Err(ModuleError::ParsingError(format!(
                "unsupported VMDK subformat in {}: compressed grains (flags=0x{:08X}, compressAlgorithm={})",
                name, flags, compress_algorithm
            )));
        }
        if gd_offset == u64::MAX {
            return Err(ModuleError::ParsingError(format!(
                "unsupported VMDK subformat in {}: streamOptimized grain directory in footer (GD offset sentinel)",
                name
            )));
        }

        let disk_size = capacity.saturating_mul(512);
        let grain_bytes = grain_size.saturating_mul(512);

        info!(
            "VMDK sparse: {} (v{}, capacity={} sectors, grain={} sectors, disk={})",
            name, version, capacity, grain_size, disk_size
        );

        if grain_size == 0 || gd_offset == 0 {
            warn!("VMDK {} has invalid grain_size or gd_offset", name);
            return Ok(Vec::new());
        }

        let vmdk_source = match VmdkSparseDataSource::new(
            data_source.clone(),
            capacity,
            grain_size,
            gd_offset,
            num_gtes_per_gt,
            overhead,
        ) {
            Ok(source) => source,
            Err(e) => {
                return Err(ModuleError::ParsingError(format!(
                    "Failed to parse VMDK {}: {}",
                    name, e
                )));
            }
        };

        let metadata = json!({
            "name": name,
            "container": "vmdk",
            "vmdk_type": "sparse",
            "vmdk_version": version,
            "disk_size": disk_size,
            "grain_size_bytes": grain_bytes,
        });

        let child = Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(Arc::new(vmdk_source)),
            metadata,
        )
        .with_parent(artifact.id);

        info!("VMDK {} -> RawEvidence ({} bytes)", name, disk_size);

        Ok(vec![child])
    }
}

/// DataSource for VMDK sparse images.
///
/// Uses a two-level grain table structure:
/// - Grain Directory (GD): array of offsets to Grain Tables
/// - Grain Table (GT): array of offsets to grains (data blocks)
///
/// Each grain is `grain_size` sectors of raw data.
struct VmdkSparseDataSource {
    inner: Arc<dyn DataSource>,
    disk_size: u64,
    grain_size_bytes: u64,
    grain_directory: Vec<u32>,
    num_gtes_per_gt: u32,
}

impl fmt::Debug for VmdkSparseDataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmdkSparseDataSource")
            .field("disk_size", &self.disk_size)
            .field("grain_size_bytes", &self.grain_size_bytes)
            .field("gd_entries", &self.grain_directory.len())
            .finish()
    }
}

impl VmdkSparseDataSource {
    fn new(
        inner: Arc<dyn DataSource>,
        capacity_sectors: u64,
        grain_size_sectors: u64,
        gd_offset_sectors: u64,
        num_gtes_per_gt: u32,
        _overhead_sectors: u64,
    ) -> Result<Self, String> {
        let disk_size = capacity_sectors.saturating_mul(512);
        let grain_size_bytes = grain_size_sectors.saturating_mul(512);

        // Reject a zero grain size (division by zero) and compute the grain
        // count with checked arithmetic: capacity/grainSize are attacker
        // controlled header fields and can overflow u64.
        if grain_size_sectors == 0 {
            return Err("VMDK grain size is zero".to_string());
        }
        let total_grains = capacity_sectors
            .checked_add(grain_size_sectors - 1)
            .and_then(|n| n.checked_div(grain_size_sectors))
            .ok_or_else(|| {
                format!(
                    "VMDK grain count overflow (capacity={} sectors, grain={} sectors)",
                    capacity_sectors, grain_size_sectors
                )
            })?;
        // Number of grain table entries per grain table (usually 512)
        let gtes = if num_gtes_per_gt == 0 {
            512
        } else {
            num_gtes_per_gt
        };
        // Number of grain directory entries. u64 ceiling division avoids both
        // truncating the grain count and overflowing the ceiling addition.
        let gd_entries = total_grains.div_ceil(gtes as u64);

        // Sanity check: limit GD entries to 1M
        if gd_entries > 1_048_576 {
            return Err(format!(
                "Grain directory too large: {} entries (max 1048576)",
                gd_entries
            ));
        }

        // Read grain directory
        let gd_byte_offset = gd_offset_sectors.saturating_mul(512);
        let gd_byte_size = gd_entries as usize * 4;
        let mut gd_buf = vec![0u8; gd_byte_size];
        // Loop over short reads; a real shortfall is a truncated grain
        // directory and must not be parsed as zero (unallocated) entries, which
        // would serve zeros for every grain it covers.
        read_exact_or_fail(
            inner.as_ref(),
            gd_byte_offset,
            &mut gd_buf,
            "VMDK grain directory",
        )
        .map_err(|e| format!("Failed to read grain directory: {}", e))?;

        let grain_directory: Vec<u32> = gd_buf
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| LittleEndian::read_u32(c))
            .collect();

        debug!(
            "VMDK: gd_entries={}, gtes_per_gt={}, total_grains={}, grain_bytes={}",
            grain_directory.len(),
            gtes,
            total_grains,
            grain_size_bytes
        );

        Ok(Self {
            inner,
            disk_size,
            grain_size_bytes,
            grain_directory,
            num_gtes_per_gt: gtes,
        })
    }

    /// Resolve a logical offset to a physical offset in the file.
    /// Returns None if the grain is not allocated (sparse — reads as zero).
    fn resolve_offset(&self, logical_offset: u64) -> io::Result<Option<u64>> {
        let grain_idx = logical_offset / self.grain_size_bytes;
        let gd_idx = grain_idx / self.num_gtes_per_gt as u64;
        let gt_idx = grain_idx % self.num_gtes_per_gt as u64;

        if gd_idx as usize >= self.grain_directory.len() {
            return Ok(None); // Beyond grain directory
        }

        let gt_offset_sectors = self.grain_directory[gd_idx as usize];
        if gt_offset_sectors == 0 {
            return Ok(None); // Grain table not allocated
        }

        // Read the specific grain table entry
        let gt_byte_offset = gt_offset_sectors as u64 * 512;
        let gte_byte_offset = gt_byte_offset + gt_idx * 4;
        let mut gte_buf = [0u8; 4];
        read_exact_or_fail(
            self.inner.as_ref(),
            gte_byte_offset,
            &mut gte_buf,
            "VMDK grain table entry",
        )?;
        let grain_offset_sectors = LittleEndian::read_u32(&gte_buf);

        if grain_offset_sectors == 0 {
            return Ok(None); // Grain not allocated
        }

        let offset_in_grain = logical_offset % self.grain_size_bytes;
        // `grain_offset_sectors` is a u32 widened to u64, so the multiply is
        // bounded; the add is not. `grain_size_bytes` comes from a header field
        // via `saturating_mul(512)`, so a crafted geometry can push
        // `offset_in_grain` to the top of the address space. Fail closed on the
        // carry rather than wrap round to unrelated host bytes, matching the
        // rest of the container read paths.
        let physical = (grain_offset_sectors as u64 * 512)
            .checked_add(offset_in_grain)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "VMDK host offset overflow: grain at sector {} + {} bytes into the grain",
                        grain_offset_sectors, offset_in_grain
                    ),
                )
            })?;
        Ok(Some(physical))
    }
}

impl DataSource for VmdkSparseDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.disk_size {
            return Ok(0);
        }

        let mut total_read = 0;
        let mut current_offset = offset;

        while total_read < buf.len() && current_offset < self.disk_size {
            let offset_in_grain = current_offset % self.grain_size_bytes;
            let remaining_in_grain = self.grain_size_bytes - offset_in_grain;
            let to_read = (buf.len() - total_read)
                .min(remaining_in_grain as usize)
                .min((self.disk_size - current_offset) as usize);

            match self.resolve_offset(current_offset)? {
                Some(physical_offset) => {
                    // Loop over short reads; only a genuine shortfall is an
                    // error. Fabricating zeros for an ALLOCATED grain would
                    // present unread disk as real content.
                    let read = read_full(
                        self.inner.as_ref(),
                        physical_offset,
                        &mut buf[total_read..total_read + to_read],
                    );
                    if read < to_read {
                        // Allocated grain truncated by EOF — never fabricate zeros
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "Short read in allocated grain: got {} of {} bytes at physical offset {}",
                                read, to_read, physical_offset
                            ),
                        ));
                    }
                }
                None => {
                    // Sparse grain — return zeros
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

    use seance_core::data_source::ByteSliceDataSource;

    #[test]
    fn test_vmdk_skip_non_vmdk() {
        let module = VmdkContainerModule;
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "document.pdf"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_vmdk_skip_too_small() {
        let module = VmdkContainerModule;
        let data = vec![0u8; 100];
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "tiny.vmdk", "subtype": "vmdk"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_vmdk_invalid_magic() {
        let module = VmdkContainerModule;
        let data = vec![0u8; 1024];
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "bad.vmdk", "subtype": "vmdk"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_vmdk_zero_grain_size() {
        let module = VmdkContainerModule;
        let mut data = vec![0u8; 1024];
        // Set sparse magic
        data[0..4].copy_from_slice(&VMDK_SPARSE_MAGIC.to_le_bytes());
        // version
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // capacity (sectors)
        data[12..20].copy_from_slice(&2048u64.to_le_bytes());
        // grain_size = 0 (invalid)
        data[20..28].copy_from_slice(&0u64.to_le_bytes());
        // gd_offset
        data[56..64].copy_from_slice(&1u64.to_le_bytes());

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "bad.vmdk", "subtype": "vmdk"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty(), "Zero grain_size should be rejected");
    }

    // === VmdkSparseDataSource edge cases ===

    #[test]
    fn test_vmdk_gd_too_large() {
        let data = vec![0u8; 4096];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        // capacity_sectors=2^30, grain_size=1 sector => 2^30 grains, gtes_per_gt=1 => 2^30 GD entries (exceeds 1M)
        let result = VmdkSparseDataSource::new(inner, 1 << 30, 1, 1, 1, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Grain directory too large"));
    }

    #[test]
    fn test_vmdk_sparse_unallocated_read() {
        // Build a minimal valid VMDK sparse source with all-zero GD (unallocated)
        let data = vec![0u8; 8192];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VmdkSparseDataSource::new(
            inner, 2048, // 2048 sectors = 1MB
            128,  // 128 sectors per grain = 64KB grains
            2,    // gd_offset at sector 2
            512,  // gtes per gt
            0,
        )
        .unwrap();

        // Read from unallocated area — should return zeros
        let mut buf = vec![0xFFu8; 512];
        let read = source.read_at(0, &mut buf).unwrap();
        assert_eq!(read, 512);
        assert!(
            buf.iter().all(|&b| b == 0),
            "Unallocated read should return zeros"
        );
    }

    fn make_vmdk_header(capacity: u64, grain_size: u64, gd_offset: u64) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&VMDK_SPARSE_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        data[12..20].copy_from_slice(&capacity.to_le_bytes());
        data[20..28].copy_from_slice(&grain_size.to_le_bytes());
        data[44..48].copy_from_slice(&512u32.to_le_bytes()); // num_gtes_per_gt
        data[56..64].copy_from_slice(&gd_offset.to_le_bytes());
        data
    }

    fn make_artifact(data: Vec<u8>) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "test.vmdk", "subtype": "vmdk"}),
        )
    }

    #[test]
    fn test_vmdk_compressed_flag_rejected() {
        let module = VmdkContainerModule;
        let mut data = make_vmdk_header(2048, 128, 2);
        // Flag bit 16: grains are compressed
        data[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
        data.resize(8192, 0);

        let result = module.process(&make_artifact(data));
        let err = result.expect_err("compressed VMDK must error, not read as zeros");
        assert!(
            format!("{}", err).contains("unsupported VMDK subformat"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_vmdk_compress_algorithm_rejected() {
        let module = VmdkContainerModule;
        let mut data = make_vmdk_header(2048, 128, 2);
        // compressAlgorithm = 1 (deflate)
        data[77..79].copy_from_slice(&1u16.to_le_bytes());
        data.resize(8192, 0);

        let result = module.process(&make_artifact(data));
        let err = result.expect_err("VMDK with compressAlgorithm set must error");
        assert!(
            format!("{}", err).contains("unsupported VMDK subformat"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_vmdk_gd_offset_sentinel_rejected() {
        let module = VmdkContainerModule;
        let mut data = make_vmdk_header(2048, 128, u64::MAX);
        data.resize(8192, 0);

        let result = module.process(&make_artifact(data));
        let err = result.expect_err("streamOptimized GD sentinel must error, not read as zeros");
        assert!(
            format!("{}", err).contains("unsupported VMDK subformat"),
            "got: {}",
            err
        );
    }

    use seance_core::test_support::DribbleSource;

    #[test]
    fn a_chunked_source_still_opens_a_valid_sparse_vmdk() {
        // B2-037: the header was read with ONE `read_at` and any short return
        // treated as a truncated file. Behind a chunked source that rejected
        // perfectly valid evidence — the virtual disk never opened, so nothing
        // inside it was ever examined.
        let module = VmdkContainerModule;
        let mut data = make_vmdk_header(2048, 128, 2);
        data.resize(8192, 0);
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(DribbleSource::new(data, 7)) as Arc<dyn DataSource>),
            json!({"name": "chunked.vmdk", "subtype": "vmdk"}),
        );

        let produced = module
            .process(&artifact)
            .expect("a valid sparse VMDK behind a chunked source must parse");
        assert!(
            !produced.is_empty(),
            "the disk image inside the VMDK must be produced"
        );
    }

    #[test]
    fn test_vmdk_truncated_grain_directory_errors() {
        let module = VmdkContainerModule;
        // GD at sector 4 (byte 2048), but file is only 1024 bytes: GD read is short
        let mut data = make_vmdk_header(2048, 128, 4);
        data.resize(1024, 0);

        let result = module.process(&make_artifact(data));
        assert!(
            result.is_err(),
            "truncated grain directory must error, not read as zeros"
        );
    }

    #[test]
    fn test_vmdk_truncated_grain_table_errors() {
        // GD entry points to a grain table beyond EOF: per-entry read is short
        let mut data = vec![0u8; 2048];
        // GD at byte 1024 (sector 2), single entry pointing to sector 100 (beyond EOF)
        data[1024..1028].copy_from_slice(&100u32.to_le_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VmdkSparseDataSource::new(inner, 1, 1, 2, 512, 0).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let result = source.read_at(0, &mut buf);
        assert!(
            result.is_err(),
            "truncated grain table read must error, not read as zeros"
        );
    }

    #[test]
    fn test_vmdk_short_grain_read_errors() {
        // Allocated grain whose data is truncated by EOF must error, not zero-fill
        let mut data = vec![0u8; 2148];
        // capacity=1 sector, grain=1 sector, GD at sector 2 (byte 1024)
        // GD entry -> GT at sector 3 (byte 1536)
        data[1024..1028].copy_from_slice(&3u32.to_le_bytes());
        // GT entry 0 -> grain at sector 4 (byte 2048); file ends at 2148 so only 100 bytes exist
        data[1536..1540].copy_from_slice(&4u32.to_le_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VmdkSparseDataSource::new(inner, 1, 1, 2, 512, 0).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let result = source.read_at(0, &mut buf);
        assert!(
            result.is_err(),
            "short read within an allocated grain must error, not zero-fill"
        );
    }

    #[test]
    fn test_vmdk_read_beyond_disk() {
        let data = vec![0u8; 8192];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VmdkSparseDataSource::new(inner, 100, 128, 2, 512, 0).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let read = source.read_at(source.size(), &mut buf).unwrap();
        assert_eq!(read, 0, "Reading beyond disk size should return 0 bytes");
    }

    #[test]
    fn test_vmdk_new_zero_grain_size_errors() {
        // grain_size_sectors == 0 must be rejected (division by zero), not panic.
        let inner = Arc::new(ByteSliceDataSource::new(vec![0u8; 4096])) as Arc<dyn DataSource>;
        let result = VmdkSparseDataSource::new(inner, 2048, 0, 1, 512, 0);
        assert!(result.is_err(), "zero grain size must error, not panic");
    }

    #[test]
    fn test_vmdk_new_capacity_plus_grain_overflow_errors() {
        // Reproduces the fuzz crash: capacity + grain_size - 1 overflows u64 at
        // vmdk.rs:188. Must return Err instead of panicking (debug) / wrapping
        // (release). Values taken from the crash reproducer's header.
        let inner = Arc::new(ByteSliceDataSource::new(vec![0u8; 4096])) as Arc<dyn DataSource>;
        let result = VmdkSparseDataSource::new(
            inner,
            0x9d9d_9d9d_9d9d_0000, // capacity sectors
            0x9d9d_9d9d_9d9d_9d9d, // grain_size sectors
            0x9d9d_9d9d_9d9d_9d9d, // gd_offset sectors
            0x9d9d_9d9d,           // num_gtes_per_gt
            0,
        );
        assert!(
            result.is_err(),
            "capacity+grain overflow must error, not panic"
        );
    }

    #[test]
    fn wrapping_grain_host_offset_errors_instead_of_wrapping() {
        // Capacity and grain size are header fields, and both are turned into
        // byte counts with `saturating_mul(512)`. A crafted pair that saturates
        // both to u64::MAX lets `offset_in_grain` reach the top of the address
        // space, so an allocated grain's host offset carries past u64::MAX.
        let mut data = vec![0u8; 4096];
        // GD at sector 2 (byte 1024), single entry -> GT at sector 3 (byte 1536)
        data[1024..1028].copy_from_slice(&3u32.to_le_bytes());
        // GT entry 0 -> an allocated grain at sector 4
        data[1536..1540].copy_from_slice(&4u32.to_le_bytes());
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VmdkSparseDataSource::new(inner, 1 << 55, 1 << 55, 2, 512, 0).unwrap();

        let err = source
            .read_at(u64::MAX - 100, &mut [0u8; 512])
            .expect_err("a host offset past u64::MAX must fail closed");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "a wrapped offset would resolve to unrelated bytes of the file"
        );
    }
}
