//! VHDX (Hyper-V virtual disk v2) reader.
//!
//! Layout: a "vhdxfile" identifier at offset 0, two headers (0x10000/0x20000),
//! two region tables (0x30000/0x40000). The region table points at the BAT
//! (block allocation table) and the metadata region. Metadata gives the block
//! size, virtual size and logical sector size. The BAT maps each virtual block
//! to a physical file offset; a "sector bitmap" BAT entry is interspersed every
//! `chunk_ratio` payload entries. Fully-present blocks (state 6) are read from
//! their physical offset; the not-present/zero states read as zeros; a
//! partially-present block (state 7) carries real sectors selected by a bitmap
//! that this reader does not reconstruct, so it fails closed rather than
//! fabricate zeros. Differencing disks (parent-backed) are not reconstructed.

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::io::{self, Cursor};
use std::sync::Arc;
use tracing::{info, warn};

pub struct VhdxContainerModule;

const REGION_TABLE_OFFSET: u64 = 0x30000;
const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;
// GUIDs as stored on disk (mixed-endian, i.e. uuid bytes_le).
const REGION_BAT: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const REGION_META: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];
const META_FILE_PARAMS: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const META_VIRTUAL_SIZE: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const META_LOGICAL_SECTOR: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];

/// Read exactly `buf.len()` bytes from `src` at `offset`.
fn read_exact_at(src: &dyn DataSource, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut o = 0usize;
    while o < buf.len() {
        match src.read_at(offset + o as u64, &mut buf[o..])? {
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read")),
            n => o += n,
        }
    }
    Ok(())
}

struct VhdxDataSource {
    inner: Arc<dyn DataSource>,
    virtual_size: u64,
    block_size: u64,
    chunk_ratio: u64,
    bat: Vec<u64>,
}

impl std::fmt::Debug for VhdxDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdxDataSource")
            .field("virtual_size", &self.virtual_size)
            .field("block_size", &self.block_size)
            .finish()
    }
}

impl VhdxDataSource {
    fn open(inner: Arc<dyn DataSource>) -> Result<(Self, bool), String> {
        let mut sig = [0u8; 8];
        read_exact_at(inner.as_ref(), 0, &mut sig).map_err(|e| e.to_string())?;
        if &sig != b"vhdxfile" {
            return Err("not a VHDX file".to_string());
        }

        // Region table: header (16 bytes) then 32-byte entries.
        let mut rt = vec![0u8; 64 * 1024];
        read_exact_at(inner.as_ref(), REGION_TABLE_OFFSET, &mut rt).map_err(|e| e.to_string())?;
        if &rt[0..4] != b"regi" {
            return Err("bad VHDX region table signature".to_string());
        }
        let entry_count = LittleEndian::read_u32(&rt[8..12]) as usize;
        let (mut bat_off, mut bat_len, mut meta_off, mut meta_len) = (0u64, 0u32, 0u64, 0u32);
        for i in 0..entry_count.min(2047) {
            let e = &rt[16 + i * 32..16 + (i + 1) * 32];
            let guid: [u8; 16] = e[0..16].try_into().unwrap();
            let file_off = LittleEndian::read_u64(&e[16..24]);
            let len = LittleEndian::read_u32(&e[24..28]);
            if guid == REGION_BAT {
                bat_off = file_off;
                bat_len = len;
            } else if guid == REGION_META {
                meta_off = file_off;
                meta_len = len;
            }
        }
        if bat_off == 0 || meta_off == 0 {
            return Err("VHDX missing BAT or metadata region".to_string());
        }

        let (virtual_size, block_size, logical_sector_size, has_parent) =
            parse_metadata(inner.as_ref(), meta_off, meta_len)?;
        if block_size == 0 || logical_sector_size == 0 {
            return Err("VHDX metadata missing block/sector size".to_string());
        }

        // chunk_ratio: payload entries between interspersed sector-bitmap entries.
        let chunk_ratio = ((1u64 << 23) * logical_sector_size as u64) / block_size;
        let chunk_ratio = chunk_ratio.max(1);

        // Load the BAT.
        let count = (bat_len as usize / 8).min(64 * 1024 * 1024 / 8);
        let mut bat_raw = vec![0u8; count * 8];
        read_exact_at(inner.as_ref(), bat_off, &mut bat_raw).map_err(|e| e.to_string())?;
        let mut bat = Vec::with_capacity(count);
        let mut c = Cursor::new(&bat_raw);
        for _ in 0..count {
            bat.push(c.read_u64::<LittleEndian>().unwrap());
        }

        Ok((
            VhdxDataSource {
                inner,
                virtual_size,
                block_size,
                chunk_ratio,
                bat,
            },
            has_parent,
        ))
    }
}

impl DataSource for VhdxDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.virtual_size || buf.is_empty() {
            return Ok(0);
        }
        let want = (self.virtual_size - offset).min(buf.len() as u64) as usize;
        let mut filled = 0usize;
        while filled < want {
            let voff = offset + filled as u64;
            let block = voff / self.block_size;
            let in_block = voff % self.block_size;
            let n = ((self.block_size - in_block) as usize).min(want - filled);

            // BAT index skips the interspersed sector-bitmap entries.
            let bat_index = (block + block / self.chunk_ratio) as usize;
            // This block lies within the virtual size, so it must have a BAT
            // entry. A missing one means the BAT is truncated: coercing it to
            // "not present" would silently read real evidence back as zeros, so
            // fail the read instead.
            let entry = match self.bat.get(bat_index).copied() {
                Some(e) => e,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "VHDX BAT truncated: no entry {} for block {} within virtual size {}",
                            bat_index, block, self.virtual_size
                        ),
                    ));
                }
            };
            let state = entry & 0x7;
            if state == PAYLOAD_BLOCK_FULLY_PRESENT {
                // The host-offset mask leaves bits up to 63 set, so a crafted BAT
                // entry can sit within one block of u64::MAX. Fail closed on the
                // carry instead of wrapping round to unrelated bytes near the
                // start of the file and presenting them as this block's content,
                // matching the rest of the container read paths.
                let base = entry & 0xFFFF_FFFF_FFF0_0000;
                let phys = base.checked_add(in_block).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "VHDX host offset overflow for block {}: base {} + {}",
                            block, base, in_block
                        ),
                    )
                })?;
                read_exact_at(self.inner.as_ref(), phys, &mut buf[filled..filled + n])?;
            } else if state == PAYLOAD_BLOCK_PARTIALLY_PRESENT {
                // A partially-present block holds real payload sectors selected
                // by a per-block sector bitmap (the interspersed bitmap BAT
                // entry), with the remaining sectors sourced from a parent
                // (differencing) disk. This reader reconstructs neither the
                // bitmap nor a parent, so zero-filling would silently drop the
                // present sectors' real bytes. Fail closed instead of
                // fabricating zeros.
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "VHDX block {} is partially present (state 7); its sector bitmap is not reconstructed",
                        block
                    ),
                ));
            } else {
                for b in &mut buf[filled..filled + n] {
                    *b = 0;
                }
            }
            filled += n;
        }
        Ok(filled)
    }

    fn size(&self) -> u64 {
        self.virtual_size
    }
}

/// Parse the metadata region: returns (virtual_size, block_size,
/// logical_sector_size, has_parent).
fn parse_metadata(
    src: &dyn DataSource,
    meta_off: u64,
    meta_len: u32,
) -> Result<(u64, u64, u32, bool), String> {
    // Metadata items are stored at offsets throughout the region, so read the
    // whole region rather than just its header. Use the region's *declared*
    // length (bounded by a sane max) so a compact region under 64 KiB is not
    // over-read past EOF; the region must at least hold its 32-byte header.
    let size = (meta_len as usize).min(16 * 1024 * 1024);
    if size < 32 {
        return Err("VHDX metadata region too small".to_string());
    }
    let mut hdr = vec![0u8; size];
    read_exact_at(src, meta_off, &mut hdr).map_err(|e| e.to_string())?;
    if &hdr[0..8] != b"metadata" {
        return Err("bad VHDX metadata signature".to_string());
    }
    let entry_count = LittleEndian::read_u16(&hdr[10..12]) as usize;
    let (mut virtual_size, mut block_size, mut sector, mut has_parent) = (0u64, 0u64, 0u32, false);
    for i in 0..entry_count.min(2047) {
        let start = 32 + i * 32;
        if start + 32 > hdr.len() {
            break;
        }
        let e = &hdr[start..start + 32];
        let guid: [u8; 16] = e[0..16].try_into().unwrap();
        let item_off = LittleEndian::read_u32(&e[16..20]) as usize;
        if item_off + 8 > hdr.len() {
            continue;
        }
        let v = &hdr[item_off..];
        if guid == META_VIRTUAL_SIZE {
            virtual_size = LittleEndian::read_u64(&v[0..8]);
        } else if guid == META_FILE_PARAMS {
            block_size = LittleEndian::read_u32(&v[0..4]) as u64;
            has_parent = LittleEndian::read_u32(&v[4..8]) & 0x2 != 0;
        } else if guid == META_LOGICAL_SECTOR {
            sector = LittleEndian::read_u32(&v[0..4]);
        }
    }
    Ok((virtual_size, block_size, sector, has_parent))
}

impl ForensicsModule for VhdxContainerModule {
    fn id(&self) -> &str {
        "container.vhdx_reader"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if let Some(subtype) = artifact.subtype() {
            if subtype != "vhdx" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".vhdx") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.vhdx")
            .to_string();

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("VHDX module requires data source".to_string())
        })?;

        let (source, has_parent) = VhdxDataSource::open(data_source.clone()).map_err(|e| {
            ModuleError::ParsingError(format!("Failed to open VHDX {}: {}", name, e))
        })?;

        if has_parent {
            warn!(
                "VHDX differencing disk (parent-backed) not reconstructed: {}",
                name
            );
            return Err(ModuleError::ParsingError(format!(
                "VHDX {} is a differencing disk; its parent is required and not available",
                name
            )));
        }

        let virtual_size = source.size();
        info!("VHDX image detected: {} ({} bytes)", name, virtual_size);

        let metadata = json!({
            "name": format!("{}_extracted", name),
            "size": virtual_size,
            "subtype": "raw",
            "container": "vhdx",
            "container_path": artifact.metadata.get("path").and_then(|v| v.as_str()),
            "path": artifact.metadata.get("path").and_then(|v| v.as_str()),
        });

        let child = Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(Arc::new(source) as Arc<dyn DataSource>),
            metadata,
        )
        .with_parent(artifact.id);

        Ok(vec![child])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use uuid::Uuid;

    /// Build a minimal dynamic VHDX: one 1 MiB block fully present, filled with
    /// 0xAB. Layout: id@0, region table@0x30000 (BAT@0x100000, META@0x200000),
    /// payload@0x300000.
    fn minimal_vhdx() -> Vec<u8> {
        let bs: u64 = 0x100000; // 1 MiB block
        let bat_off = 0x100000u64;
        let meta_off = 0x200000u64;
        let payload = 0x300000u64;
        let mut d = vec![0u8; (payload + bs) as usize];
        d[0..8].copy_from_slice(b"vhdxfile");

        // Region table @0x30000
        let rt = 0x30000usize;
        d[rt..rt + 4].copy_from_slice(b"regi");
        d[rt + 8..rt + 12].copy_from_slice(&2u32.to_le_bytes()); // entry_count
        let put_region = |d: &mut [u8], i: usize, guid: &[u8; 16], off: u64, len: u32| {
            let e = rt + 16 + i * 32;
            d[e..e + 16].copy_from_slice(guid);
            d[e + 16..e + 24].copy_from_slice(&off.to_le_bytes());
            d[e + 24..e + 28].copy_from_slice(&len.to_le_bytes());
        };
        put_region(&mut d, 0, &REGION_BAT, bat_off, bs as u32);
        put_region(&mut d, 1, &REGION_META, meta_off, 0x10000);

        // BAT @bat_off: block 0 fully present at `payload`.
        let entry = (payload & 0xFFFF_FFFF_FFF0_0000) | PAYLOAD_BLOCK_FULLY_PRESENT;
        d[bat_off as usize..bat_off as usize + 8].copy_from_slice(&entry.to_le_bytes());

        // Metadata @meta_off: header + 3 items, values at +0x1000.
        let m = meta_off as usize;
        d[m..m + 8].copy_from_slice(b"metadata");
        d[m + 10..m + 12].copy_from_slice(&3u16.to_le_bytes()); // entry_count
        let put_meta = |d: &mut [u8], i: usize, guid: &[u8; 16], off: u32, len: u32| {
            let e = m + 32 + i * 32;
            d[e..e + 16].copy_from_slice(guid);
            d[e + 16..e + 20].copy_from_slice(&off.to_le_bytes());
            d[e + 20..e + 24].copy_from_slice(&len.to_le_bytes());
        };
        put_meta(&mut d, 0, &META_FILE_PARAMS, 0x1000, 8);
        put_meta(&mut d, 1, &META_VIRTUAL_SIZE, 0x1008, 8);
        put_meta(&mut d, 2, &META_LOGICAL_SECTOR, 0x1010, 4);
        d[m + 0x1000..m + 0x1004].copy_from_slice(&(bs as u32).to_le_bytes()); // block_size
        d[m + 0x1004..m + 0x1008].copy_from_slice(&0u32.to_le_bytes()); // flags (no parent)
        d[m + 0x1008..m + 0x1010].copy_from_slice(&bs.to_le_bytes()); // virtual_size = 1 block
        d[m + 0x1010..m + 0x1014].copy_from_slice(&512u32.to_le_bytes()); // logical sector

        for b in &mut d[payload as usize..(payload + bs) as usize] {
            *b = 0xAB;
        }
        d
    }

    #[test]
    fn reads_minimal_dynamic_vhdx() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(minimal_vhdx()))),
            json!({ "name": "min.vhdx", "subtype": "vhdx" }),
        );
        let out = VhdxContainerModule.process(&art).expect("process");
        assert_eq!(out.len(), 1);
        let ds = out[0].data.as_ref().unwrap();
        assert_eq!(ds.size(), 0x100000);
        let mut buf = vec![0u8; 0x100000];
        ds.read_at(0, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xAB),
            "block content must round-trip"
        );
        // A block-2 read (past the single present block) is out of range -> 0.
        assert_eq!(ds.read_at(0x100000, &mut [0u8; 16]).unwrap(), 0);
    }

    #[test]
    fn rejects_non_vhdx() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 4096]))),
            json!({ "name": "x.vhdx", "subtype": "vhdx" }),
        );
        assert!(VhdxContainerModule.process(&art).is_err());
    }

    /// Like `minimal_vhdx`, but the virtual disk spans two blocks while the BAT
    /// region only declares one entry. Block 1 is within the virtual size yet has
    /// no BAT entry, modelling a truncated BAT.
    fn truncated_bat_vhdx() -> Vec<u8> {
        let bs: u64 = 0x100000; // 1 MiB block
        let mut d = minimal_vhdx();
        // Virtual size = 2 blocks (metadata VIRTUAL_SIZE value @ meta_off + 0x1008).
        let vsize_at = (0x200000 + 0x1008) as usize;
        d[vsize_at..vsize_at + 8].copy_from_slice(&(2 * bs).to_le_bytes());
        // Shrink the BAT region length to a single 8-byte entry (region table
        // entry 0 length @ rt + 16 + 24).
        let bat_len_at = (0x30000 + 16 + 24) as usize;
        d[bat_len_at..bat_len_at + 4].copy_from_slice(&8u32.to_le_bytes());
        d
    }

    #[test]
    fn truncated_bat_errors_instead_of_zero_filling() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(truncated_bat_vhdx()))),
            json!({ "name": "trunc.vhdx", "subtype": "vhdx" }),
        );
        let out = VhdxContainerModule.process(&art).expect("process");
        let ds = out[0].data.as_ref().unwrap();
        assert_eq!(ds.size(), 0x200000, "virtual size spans two blocks");

        // Block 0 still reads normally.
        let mut buf0 = vec![0u8; 0x100000];
        ds.read_at(0, &mut buf0).unwrap();
        assert!(buf0.iter().all(|&b| b == 0xAB));

        // Block 1 is within the virtual size but has no BAT entry. It must error,
        // not silently read back as zeros.
        let err = ds.read_at(0x100000, &mut [0u8; 16]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// Like `minimal_vhdx`, but block 0's BAT entry carries the highest host
    /// offset the 44-bit mask allows and the block size is 2 MiB. The mask's
    /// granularity is 1 MiB, so only a larger block gives an in-block offset
    /// big enough to carry `base + in_block` past the top of the address space.
    fn wrapping_bat_vhdx() -> Vec<u8> {
        let mut d = minimal_vhdx();
        let m = 0x200000usize; // metadata region
        d[m + 0x1000..m + 0x1004].copy_from_slice(&0x200000u32.to_le_bytes()); // block_size = 2 MiB
        d[m + 0x1008..m + 0x1010].copy_from_slice(&0x200000u64.to_le_bytes()); // virtual_size = 1 block
        let entry = 0xFFFF_FFFF_FFF0_0000u64 | PAYLOAD_BLOCK_FULLY_PRESENT;
        d[0x100000..0x100008].copy_from_slice(&entry.to_le_bytes());
        d
    }

    #[test]
    fn wrapping_bat_host_offset_errors_instead_of_wrapping() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(wrapping_bat_vhdx()))),
            json!({ "name": "wrap.vhdx", "subtype": "vhdx" }),
        );
        let out = VhdxContainerModule.process(&art).expect("process");
        let ds = out[0].data.as_ref().unwrap();

        // 1 MiB into the 2 MiB block, the host offset carries past u64::MAX.
        // That must be a hard error: a wrapped offset would resolve to
        // unrelated bytes near the start of the file and present them as this
        // block's content.
        let err = ds
            .read_at(0x100000, &mut [0u8; 16])
            .expect_err("a host offset past u64::MAX must fail closed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
