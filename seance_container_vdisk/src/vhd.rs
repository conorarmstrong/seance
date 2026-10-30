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

const VHD_FOOTER_MAGIC: &[u8; 8] = b"conectix";
const VHD_FOOTER_SIZE: usize = 512;

// VHD disk types
const VHD_TYPE_FIXED: u32 = 2;
const VHD_TYPE_DYNAMIC: u32 = 3;
const VHD_TYPE_DIFFERENCING: u32 = 4;

pub struct VhdContainerModule;

impl ForensicsModule for VhdContainerModule {
    fn id(&self) -> &str {
        "container.vhd_reader"
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
            if subtype != "vhd" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".vhd") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.vhd")
            .to_string();

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("VHD module requires data source".to_string())
        })?;

        let file_size = data_source.size();
        if file_size < VHD_FOOTER_SIZE as u64 {
            return Ok(Vec::new());
        }

        // Read footer (last 512 bytes). A single `read_at` may return fewer bytes
        // than asked even when the whole footer is present (chunked/windowed
        // sources), which used to make a valid VHD undetectable (BUG-284).
        let mut footer_buf = [0u8; VHD_FOOTER_SIZE];
        let read = read_full(
            data_source.as_ref(),
            file_size - VHD_FOOTER_SIZE as u64,
            &mut footer_buf,
        );
        if read < VHD_FOOTER_SIZE {
            return Ok(Vec::new());
        }

        // Verify magic — parse geometry only from a buffer that passed validation
        let footer = if &footer_buf[0..8] == VHD_FOOTER_MAGIC {
            footer_buf
        } else {
            // Try reading footer from offset 0 (dynamic VHD has a copy there)
            let mut header_footer = [0u8; VHD_FOOTER_SIZE];
            let read = read_full(data_source.as_ref(), 0, &mut header_footer);
            if read < VHD_FOOTER_SIZE || &header_footer[0..8] != VHD_FOOTER_MAGIC {
                return Ok(Vec::new());
            }
            header_footer
        };

        let disk_type = BigEndian::read_u32(&footer[60..64]);
        let disk_size = BigEndian::read_u64(&footer[48..56]);

        info!(
            "VHD image detected: {} (type={}, size={})",
            name, disk_type, disk_size
        );

        let vhd_source: Arc<dyn DataSource> = match disk_type {
            VHD_TYPE_FIXED => {
                // Fixed VHD: the footer's disk_size is the authoritative virtual
                // size. Expose exactly that, not `file_size - 512`: host padding
                // past disk_size must not be served as image, and an undersized
                // /truncated file must still report the footer capacity (reads
                // past the real data then short-read and fail closed).
                Arc::new(seance_core::data_source::WindowSource::new(
                    data_source.clone(),
                    0,
                    disk_size,
                ))
            }
            VHD_TYPE_DYNAMIC => {
                // Dynamic VHD: read dynamic disk header and BAT
                let data_offset = BigEndian::read_u64(&footer[16..24]);

                match VhdDynamicDataSource::new(data_source.clone(), data_offset, disk_size) {
                    Ok(source) => Arc::new(source),
                    Err(e) => {
                        return Err(ModuleError::ParsingError(format!(
                            "Failed to parse dynamic VHD {}: {}",
                            name, e
                        )));
                    }
                }
            }
            VHD_TYPE_DIFFERENCING => {
                // Unallocated blocks live in the parent disk; returning an empty
                // success would look "processed, nothing found" while silently
                // dropping evidence. Fail closed, mirroring QCOW2/VHDX.
                warn!(
                    "VHD differencing disk (parent-backed) not reconstructed: {}",
                    name
                );
                return Err(ModuleError::ParsingError(format!(
                    "VHD {} is a differencing disk; its parent is required and not available",
                    name
                )));
            }
            _ => {
                warn!("Unknown VHD disk type {}: {}", disk_type, name);
                return Ok(Vec::new());
            }
        };

        let type_name = match disk_type {
            VHD_TYPE_FIXED => "fixed",
            VHD_TYPE_DYNAMIC => "dynamic",
            _ => "unknown",
        };

        let metadata = json!({
            "name": name,
            "container": "vhd",
            "vhd_type": type_name,
            "disk_size": disk_size,
        });

        let child = Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(vhd_source),
            metadata,
        )
        .with_parent(artifact.id);

        info!(
            "VHD {} -> RawEvidence ({} bytes, {})",
            name, disk_size, type_name
        );

        Ok(vec![child])
    }
}

/// DataSource for VHD Dynamic disks.
///
/// Uses the Block Allocation Table (BAT) to map logical disk offsets
/// to physical file offsets. Each BAT entry points to a block in the file.
/// Unallocated blocks (0xFFFFFFFF) return zeros.
struct VhdDynamicDataSource {
    inner: Arc<dyn DataSource>,
    bat: Vec<u32>,
    block_size: u32,
    disk_size: u64,
}

impl fmt::Debug for VhdDynamicDataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VhdDynamicDataSource")
            .field("disk_size", &self.disk_size)
            .field("block_size", &self.block_size)
            .field("bat_entries", &self.bat.len())
            .finish()
    }
}

impl VhdDynamicDataSource {
    fn new(inner: Arc<dyn DataSource>, header_offset: u64, disk_size: u64) -> Result<Self, String> {
        // Read dynamic disk header (1024 bytes at header_offset). Loops short
        // reads and still fails closed on a genuinely truncated header.
        let mut header = [0u8; 1024];
        read_exact_or_fail(
            inner.as_ref(),
            header_offset,
            &mut header,
            "VHD dynamic disk header",
        )
        .map_err(|e| format!("Failed to read dynamic header: {}", e))?;

        // Verify "cxsparse" magic
        if &header[0..8] != b"cxsparse" {
            return Err("Invalid dynamic disk header magic".to_string());
        }

        let bat_offset = BigEndian::read_u64(&header[16..24]);
        let block_size = BigEndian::read_u32(&header[32..36]);
        let max_bat_entries = BigEndian::read_u32(&header[28..32]);

        // A dynamic-VHD block is a whole number of 512-byte sectors. A sub-512 or
        // non-sector-multiple block_size makes sectors_per_block (block_size / 512)
        // zero or misaligned, so the per-block sector bitmap covers nothing and
        // every allocated block reads back as all zeros — silent data loss. Reject
        // it rather than fabricate zeros.
        if block_size < 512 || block_size % 512 != 0 || max_bat_entries == 0 {
            return Err("Invalid block size or BAT entry count".to_string());
        }

        // Sanity check: limit BAT entries to 1M (supports up to 2TB with 2MB blocks)
        if max_bat_entries > 1_048_576 {
            return Err(format!(
                "BAT entry count too large: {} (max 1048576)",
                max_bat_entries
            ));
        }

        // Read BAT
        let bat_byte_size = (max_bat_entries as usize) * 4;
        let mut bat_buf = vec![0u8; bat_byte_size];
        read_exact_or_fail(inner.as_ref(), bat_offset, &mut bat_buf, "VHD BAT")
            .map_err(|e| format!("Failed to read BAT: {}", e))?;

        let bat: Vec<u32> = bat_buf
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| BigEndian::read_u32(c))
            .collect();

        debug!(
            "VHD Dynamic: block_size={}, bat_entries={}, disk_size={}",
            block_size,
            bat.len(),
            disk_size
        );

        Ok(Self {
            inner,
            bat,
            block_size,
            disk_size,
        })
    }
}

impl DataSource for VhdDynamicDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.disk_size {
            return Ok(0);
        }

        let block_size = self.block_size as u64;
        // Each block has a sector bitmap before the data.
        // Bitmap size = ceil(block_size / 512) / 8, rounded up to sector boundary
        let sectors_per_block = block_size / 512;
        let bitmap_size = (sectors_per_block.div_ceil(8) + 511) & !511; // round up to 512

        let mut total_read = 0;
        let mut current_offset = offset;

        while total_read < buf.len() && current_offset < self.disk_size {
            let block_idx = (current_offset / block_size) as usize;
            let offset_in_block = current_offset % block_size;
            let remaining_in_block = block_size - offset_in_block;
            let to_read = (buf.len() - total_read)
                .min(remaining_in_block as usize)
                .min((self.disk_size - current_offset) as usize);

            if block_idx >= self.bat.len() || self.bat[block_idx] == 0xFFFFFFFF {
                // Unallocated block — return zeros
                buf[total_read..total_read + to_read].fill(0);
            } else {
                // BAT entry is sector number where the block starts
                let block_physical = self.bat[block_idx] as u64 * 512;
                let data_start = block_physical + bitmap_size;

                // Each block carries a sector bitmap: one bit per sector marking
                // whether that sector holds written data. Absent sectors are not
                // stored in the block and must read as zeros; returning the
                // block's host bytes for them would serve stale/leftover data as
                // evidence. Bits are most-significant-first within each byte.
                let bitmap_bytes = sectors_per_block.div_ceil(8) as usize;
                let mut bitmap = vec![0u8; bitmap_bytes];
                read_exact_or_fail(
                    self.inner.as_ref(),
                    block_physical,
                    &mut bitmap,
                    "VHD block sector bitmap",
                )?;
                let present = |sector: u64| -> bool {
                    bitmap
                        .get((sector / 8) as usize)
                        .map(|b| (b >> (7 - (sector % 8))) & 1 == 1)
                        .unwrap_or(false)
                };

                // Walk the requested range, coalescing consecutive sectors that
                // share a present bit into one host read (present) or zero-fill.
                let mut done = 0usize;
                while done < to_read {
                    let off_in_block = offset_in_block + done as u64;
                    let is_present = present(off_in_block / 512);
                    let mut chunk = (512 - (off_in_block % 512) as usize).min(to_read - done);
                    while done + chunk < to_read {
                        let next_sector = (offset_in_block + (done + chunk) as u64) / 512;
                        if present(next_sector) != is_present {
                            break;
                        }
                        chunk = (chunk + 512).min(to_read - done);
                    }
                    let dst = &mut buf[total_read + done..total_read + done + chunk];
                    if is_present {
                        let read = self.inner.read_at(data_start + off_in_block, dst)?;
                        if read < chunk {
                            // Present sector truncated by EOF — never fabricate zeros
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "Short read in allocated block: got {} of {} bytes at physical offset {}",
                                    read, chunk, data_start + off_in_block
                                ),
                            ));
                        }
                    } else {
                        dst.fill(0);
                    }
                    done += chunk;
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

    fn make_vhd_footer(disk_type: u32, disk_size: u64) -> Vec<u8> {
        let mut footer = vec![0u8; VHD_FOOTER_SIZE];
        footer[0..8].copy_from_slice(VHD_FOOTER_MAGIC);
        // disk_size at offset 48-55 (big-endian)
        footer[48..56].copy_from_slice(&disk_size.to_be_bytes());
        // disk_type at offset 60-63 (big-endian)
        footer[60..64].copy_from_slice(&disk_type.to_be_bytes());
        footer
    }

    #[test]
    fn test_vhd_skip_non_vhd() {
        let module = VhdContainerModule;
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
    fn test_vhd_skip_too_small() {
        let module = VhdContainerModule;
        let data = vec![0u8; 100]; // Way too small
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "tiny.vhd", "subtype": "vhd"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_vhd_invalid_magic() {
        let module = VhdContainerModule;
        let data = vec![0u8; 1024]; // Enough size but no valid magic
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "bad.vhd", "subtype": "vhd"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "Invalid magic should produce no results"
        );
    }

    #[test]
    fn test_vhd_fixed_disk() {
        let module = VhdContainerModule;
        let disk_size = 1024 * 1024; // 1MB disk
        let footer = make_vhd_footer(VHD_TYPE_FIXED, disk_size);

        // Fixed VHD = data + footer at end
        let mut data = vec![0u8; disk_size as usize];
        data.extend_from_slice(&footer);

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "test.vhd", "subtype": "vhd"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].artifact_type, ArtifactType::RawEvidence);
        assert_eq!(results[0].metadata["vhd_type"], "fixed");
        assert_eq!(results[0].metadata["disk_size"], disk_size);
    }

    #[test]
    fn test_vhd_differencing_rejected() {
        let module = VhdContainerModule;
        let footer = make_vhd_footer(VHD_TYPE_DIFFERENCING, 1024 * 1024);
        let mut data = vec![0u8; 1024];
        data.extend_from_slice(&footer);

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "diff.vhd", "subtype": "vhd"}),
        );

        let result = module.process(&artifact);
        assert!(
            matches!(result, Err(ModuleError::ParsingError(_))),
            "Differencing disks must fail closed, not silently succeed empty"
        );
    }

    #[test]
    fn test_vhd_unknown_type() {
        let module = VhdContainerModule;
        let footer = make_vhd_footer(99, 1024 * 1024);
        let mut data = vec![0u8; 1024];
        data.extend_from_slice(&footer);

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "unknown.vhd", "subtype": "vhd"}),
        );

        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_vhd_footer_fallback_parses_validated_copy() {
        // End-of-file footer is garbage; a valid footer copy sits at offset 0.
        // Geometry must be parsed from the validated copy, not the garbage buffer.
        let module = VhdContainerModule;
        let disk_size = 4096u64;
        let mut data = make_vhd_footer(VHD_TYPE_FIXED, disk_size);
        data.resize(512 + disk_size as usize, 0);
        data.extend_from_slice(&[0xABu8; VHD_FOOTER_SIZE]); // garbage trailing footer

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "test.vhd", "subtype": "vhd"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "valid header-copy footer should be used");
        assert_eq!(results[0].metadata["vhd_type"], "fixed");
        assert_eq!(results[0].metadata["disk_size"], disk_size);
    }

    #[test]
    fn test_dynamic_vhd_truncated_bat_errors() {
        // Valid dynamic header but BAT lies beyond EOF: short read must error
        let mut data = vec![0u8; 1024];
        data[0..8].copy_from_slice(b"cxsparse");
        // bat_offset at header+16 = byte 4096 (beyond EOF)
        data[16..24].copy_from_slice(&4096u64.to_be_bytes());
        // max_bat_entries at header+28 = 4
        data[28..32].copy_from_slice(&4u32.to_be_bytes());
        // block_size at header+32 = 2MB
        data[32..36].copy_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());

        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let result = VhdDynamicDataSource::new(inner, 0, 8 * 1024 * 1024);
        assert!(
            result.is_err(),
            "truncated BAT must error, not read as zeros"
        );
    }

    #[test]
    fn test_dynamic_vhd_short_block_read_errors() {
        // Allocated block truncated by EOF must error, not zero-fill
        let mut data = vec![0u8; 2660];
        data[0..8].copy_from_slice(b"cxsparse");
        // bat_offset = 1024
        data[16..24].copy_from_slice(&1024u64.to_be_bytes());
        // max_bat_entries = 1
        data[28..32].copy_from_slice(&1u32.to_be_bytes());
        // block_size = 512
        data[32..36].copy_from_slice(&512u32.to_be_bytes());
        // BAT entry 0 -> sector 4 (byte 2048); bitmap is 512 bytes so data starts
        // at byte 2560, but only 100 bytes exist before EOF
        data[1024..1028].copy_from_slice(&4u32.to_be_bytes());
        // Mark sector 0 present (MSB of the block's bitmap byte at 2048) so the
        // present-sector host read is actually attempted and hits the short read.
        data[2048] = 0x80;

        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VhdDynamicDataSource::new(inner, 0, 512).unwrap();

        let mut buf = vec![0xFFu8; 512];
        let result = source.read_at(0, &mut buf);
        assert!(
            result.is_err(),
            "short read within an allocated block must error, not zero-fill"
        );
    }

    #[test]
    fn test_dynamic_vhd_absent_sector_reads_zeros_not_host_bytes() {
        // BUG-045: within an allocated block, a sector whose bitmap bit is 0 is
        // absent and must read as zeros. Returning the block's host bytes there
        // would serve stale/leftover data as evidence.
        // block_size = 1024 (2 sectors/block); block at sector 4 (byte 2048),
        // bitmap 512 bytes, data at byte 2560.
        let mut data = vec![0u8; 3584];
        data[0..8].copy_from_slice(b"cxsparse");
        data[16..24].copy_from_slice(&1024u64.to_be_bytes()); // bat_offset
        data[28..32].copy_from_slice(&1u32.to_be_bytes()); // max_bat_entries
        data[32..36].copy_from_slice(&1024u32.to_be_bytes()); // block_size
        data[1024..1028].copy_from_slice(&4u32.to_be_bytes()); // BAT[0] -> sector 4
                                                               // Bitmap byte at 2048: sector 0 present (0x80), sector 1 absent.
        data[2048] = 0x80;
        // Data area: sector 0 = 0xAA (present -> returned), sector 1 = 0xBB
        // (absent -> must NOT be returned; expect zeros).
        for b in data[2560..3072].iter_mut() {
            *b = 0xAA;
        }
        for b in data[3072..3584].iter_mut() {
            *b = 0xBB;
        }

        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let source = VhdDynamicDataSource::new(inner, 0, 1024).unwrap();

        let mut buf = vec![0u8; 1024];
        let n = source.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 1024);
        assert!(
            buf[..512].iter().all(|&b| b == 0xAA),
            "present sector must return its host bytes"
        );
        assert!(
            buf[512..].iter().all(|&b| b == 0x00),
            "absent sector must read as zeros, not host leftover 0xBB"
        );
    }

    // === VhdDynamicDataSource edge cases ===

    #[test]
    fn test_dynamic_vhd_invalid_header_magic() {
        let data = vec![0u8; 2048];
        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let result = VhdDynamicDataSource::new(inner, 512, 1024 * 1024);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid dynamic disk header magic"));
    }

    #[test]
    fn test_dynamic_vhd_bat_too_large() {
        let mut data = vec![0u8; 4096];
        let header_offset = 512usize;
        data[header_offset..header_offset + 8].copy_from_slice(b"cxsparse");
        // BAT offset at header+16 (big-endian) = sector 4 = byte 2048
        data[header_offset + 16..header_offset + 24].copy_from_slice(&2048u64.to_be_bytes());
        // max_bat_entries at header+28 (big-endian) = 2M (exceeds 1M limit)
        data[header_offset + 28..header_offset + 32].copy_from_slice(&2_000_000u32.to_be_bytes());
        // block_size at header+32 (big-endian) = 2MB
        data[header_offset + 32..header_offset + 36]
            .copy_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());

        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let result = VhdDynamicDataSource::new(inner, header_offset as u64, 1024 * 1024 * 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BAT entry count too large"));
    }

    #[test]
    fn test_vhd_fixed_honors_footer_disk_size_over_file_padding() {
        // BUG-091: a fixed VHD whose data region carries host padding past
        // disk_size must expose only disk_size (the footer's virtual size), not
        // `file_size - 512`. Padding is not disk image content.
        let module = VhdContainerModule;
        let disk_size = 1024u64;
        // 2048 bytes of raw data (1024 of which is host padding past disk_size)
        // followed by the 512-byte footer.
        let mut data = vec![0xAAu8; 2048];
        data.extend_from_slice(&make_vhd_footer(VHD_TYPE_FIXED, disk_size));

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>),
            json!({"name": "padded.vhd", "subtype": "vhd"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        let src = results[0].data.as_ref().expect("data source attached");
        assert_eq!(
            src.size(),
            disk_size,
            "must expose the footer disk_size, not file_size - 512"
        );
        // A read at disk_size returns 0: host padding is not served as image.
        let mut buf = [0u8; 16];
        assert_eq!(src.read_at(disk_size, &mut buf).unwrap(), 0);
    }

    #[test]
    fn test_dynamic_vhd_sub_sector_block_size_errors() {
        // BUG-090: a non-zero block_size below 512 (or not a 512 multiple) makes
        // sectors_per_block zero, so allocated blocks would read as all zeros.
        // Must fail closed, not silently drop data.
        for bad in [256u32, 511, 513, 1000] {
            let mut data = vec![0u8; 4096];
            let header_offset = 512usize;
            data[header_offset..header_offset + 8].copy_from_slice(b"cxsparse");
            data[header_offset + 28..header_offset + 32].copy_from_slice(&4u32.to_be_bytes());
            data[header_offset + 32..header_offset + 36].copy_from_slice(&bad.to_be_bytes());

            let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
            let result = VhdDynamicDataSource::new(inner, header_offset as u64, 1024 * 1024);
            assert!(
                result.is_err(),
                "block_size {bad} must be rejected, not read as zeros"
            );
            assert!(result.unwrap_err().contains("Invalid block size"));
        }
    }

    #[test]
    fn test_dynamic_vhd_zero_block_size() {
        let mut data = vec![0u8; 4096];
        let header_offset = 512usize;
        data[header_offset..header_offset + 8].copy_from_slice(b"cxsparse");
        // block_size = 0
        data[header_offset + 32..header_offset + 36].copy_from_slice(&0u32.to_be_bytes());
        data[header_offset + 28..header_offset + 32].copy_from_slice(&10u32.to_be_bytes());

        let inner = Arc::new(ByteSliceDataSource::new(data)) as Arc<dyn DataSource>;
        let result = VhdDynamicDataSource::new(inner, header_offset as u64, 1024 * 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid block size"));
    }
    #[test]
    fn test_vhd_footer_read_loops_over_short_reads() {
        // BUG-284: the 512-byte footer arrived in pieces from a chunked source,
        // and the single-shot read gave up, so a valid fixed VHD never opened.
        let module = VhdContainerModule;
        let disk_size = 4096u64;
        let mut data = vec![0u8; disk_size as usize];
        data.extend_from_slice(&make_vhd_footer(VHD_TYPE_FIXED, disk_size));

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(DribbleSource::new(data, 64)) as Arc<dyn DataSource>),
            json!({"name": "chunked.vhd", "subtype": "vhd"}),
        );
        let results = module.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "a chunked source must still open");
        assert_eq!(results[0].metadata["disk_size"], json!(disk_size));
        assert_eq!(results[0].metadata["vhd_type"], json!("fixed"));
    }
}
