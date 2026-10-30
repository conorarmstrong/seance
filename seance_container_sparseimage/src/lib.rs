#![forbid(unsafe_code)]
//! Apple single-file sparse disk image (`.sparseimage`) container reader.
//!
//! `.sparseimage` is what the mainstream Mac acquisition tools (FUJI, RECON,
//! ASLA) write: a file that starts empty and grows a "band" at a time as the
//! disk is written, so the on-disk file is far smaller than the disk it
//! represents. Séance could not open one before this; now it decodes the band
//! map and presents the contained disk as an ordinary [`DataSource`], so the
//! existing partition / filesystem / carving stack runs on it unchanged.
//!
//! # On-disk format
//!
//! Verified against libyal/libmodi (`libmodi_sparse_image_header.c`), the
//! reverse-engineered reference every other tool relies on. All fields are
//! big-endian.
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0x00 | 4 | signature `"sprs"` |
//! | 0x08 | 4 | sectors per band |
//! | 0x10 | 4 | total number of (512-byte) sectors — the *logical* disk size |
//! | 0x40 | 4·N | band index array |
//!
//! The header is a fixed 4096 bytes and band data begins immediately after it
//! at offset 0x1000. `N = ceil(total_sectors / sectors_per_band)` and, because
//! libmodi reads only the 4096-byte header, the array cannot exceed
//! `(4096 - 0x40) / 4 = 1008` entries — a value above that is rejected rather
//! than trusted.
//!
//! The array is indexed by **physical** band position in the file (0-based, in
//! allocation order); each entry's value is the **logical** band it holds
//! (1-based), or 0 for an unused slot. So physical band `p` at file offset
//! `0x1000 + p·band_bytes` belongs to logical band `value - 1`. A logical band
//! with no entry was never written and reads as zeros — the sparseness that
//! makes the file small. A logical band that *is* mapped but whose bytes are
//! missing from a truncated file is an error, never silent zeros (a truncated
//! capture must not read as a sparse one).

use std::sync::Arc;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, DeviceImageSource},
    io::{read_exact_or_fail, read_full},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::info;

/// The fixed header size; band data begins here.
const HEADER_SIZE: u64 = 4096;
/// Offset of the band index array within the header.
const BAND_ARRAY_OFF: usize = 0x40;
/// A sparse image sector is always 512 bytes.
const SECTOR: u64 = 512;
/// The most band-array entries the 4096-byte header can carry (libmodi's bound).
const MAX_BANDS: u64 = (HEADER_SIZE as usize - BAND_ARRAY_OFF) as u64 / 4;

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The decoded band map of a sparse image.
#[derive(Debug)]
struct SparseLayout {
    band_bytes: u64,
    logical_size: u64,
    /// `logical_to_phys[logical_band]` = physical slot, or `None` if the band
    /// was never allocated (reads as zeros).
    logical_to_phys: Vec<Option<u32>>,
}

/// Parse the 4096-byte header into a band map, or explain why it is not a
/// sparse image / cannot be trusted.
fn parse_header(head: &[u8]) -> Result<SparseLayout, String> {
    if head.len() < HEADER_SIZE as usize {
        return Err(format!(
            "header is {} bytes; a sparse image header is {HEADER_SIZE}",
            head.len()
        ));
    }
    if &head[0..4] != b"sprs" {
        return Err("missing the 'sprs' signature".to_string());
    }
    let sectors_per_band = be32(head, 8) as u64;
    if sectors_per_band == 0 {
        return Err("sectors-per-band is zero".to_string());
    }
    let number_of_sectors = be32(head, 0x10) as u64;
    let band_bytes = sectors_per_band
        .checked_mul(SECTOR)
        .ok_or("band size overflows")?;
    let logical_size = number_of_sectors
        .checked_mul(SECTOR)
        .ok_or("logical size overflows")?;

    let number_of_bands = number_of_sectors.div_ceil(sectors_per_band);
    if number_of_bands > MAX_BANDS {
        return Err(format!(
            "band table of {number_of_bands} entries exceeds the {MAX_BANDS}-band \
             header capacity; not a single-file sparse image"
        ));
    }
    let nb = number_of_bands as usize;
    let mut logical_to_phys = vec![None; nb];
    for phys in 0..nb {
        let value = be32(head, BAND_ARRAY_OFF + phys * 4);
        if value == 0 {
            continue; // unused physical slot
        }
        let logical = (value - 1) as usize;
        if logical >= nb {
            return Err(format!(
                "band reference {value} is out of range for {nb} bands"
            ));
        }
        // A logical band can be held by exactly one physical band. A second
        // claim orphans one payload and silently swaps which host bytes back the
        // sector, so refuse the image instead of letting the last writer win.
        if let Some(prev) = logical_to_phys[logical] {
            return Err(format!(
                "logical band {logical} is claimed by physical bands {prev} and {phys}; \
                 the band map is corrupt"
            ));
        }
        logical_to_phys[logical] = Some(phys as u32);
    }
    Ok(SparseLayout {
        band_bytes,
        logical_size,
        logical_to_phys,
    })
}

/// Presents the disk inside a sparse image as a flat byte stream, mapping each
/// logical band to its physical band in the file and zero-filling the bands that
/// were never written.
#[derive(Debug)]
pub struct SparseImageDataSource {
    inner: Arc<dyn DataSource>,
    band_bytes: u64,
    logical_size: u64,
    logical_to_phys: Vec<Option<u32>>,
}

impl SparseImageDataSource {
    fn new(inner: Arc<dyn DataSource>, layout: SparseLayout) -> Self {
        Self {
            inner,
            band_bytes: layout.band_bytes,
            logical_size: layout.logical_size,
            logical_to_phys: layout.logical_to_phys,
        }
    }
}

impl DataSource for SparseImageDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.logical_size || buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < buf.len() {
            let pos = offset + written as u64;
            if pos >= self.logical_size {
                break;
            }
            let band = (pos / self.band_bytes) as usize;
            let within = pos % self.band_bytes;
            let take = ((buf.len() - written) as u64)
                .min(self.band_bytes - within)
                .min(self.logical_size - pos) as usize;
            let dst = &mut buf[written..written + take];
            match self.logical_to_phys.get(band).copied().flatten() {
                Some(p) => {
                    // A present band must deliver its bytes; a short read here
                    // means the file is truncated, which is an error, not a hole.
                    let phys_off = HEADER_SIZE + p as u64 * self.band_bytes + within;
                    read_exact_or_fail(self.inner.as_ref(), phys_off, dst, "sparse image band")?;
                }
                None => dst.fill(0), // unallocated band: genuine logical zeros
            }
            written += take;
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.logical_size
    }
}

/// Detects a `.sparseimage` and emits the disk it contains as `RawEvidence`.
pub struct SparseImageContainerModule;

impl ForensicsModule for SparseImageContainerModule {
    fn id(&self) -> &str {
        "container.sparseimage_reader"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // Container: a file the ingest detector tagged by magic/extension.
        // FileEntry: a .sparseimage found *inside* another filesystem.
        vec![ArtifactType::Container, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Self-select: honour an explicit subtype, else fall back to the name.
        if let Some(subtype) = artifact.subtype() {
            if subtype != "sparseimage" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".sparseimage") {
                return Ok(Vec::new());
            }
        }

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat(
                "sparse image artifact carries no data source to read".to_string(),
            )
        })?;

        let mut head = vec![0u8; HEADER_SIZE as usize];
        let got = read_full(data_source.as_ref(), 0, &mut head);
        if got < HEADER_SIZE as usize {
            return Err(ModuleError::InvalidInputFormat(format!(
                "sparse image header is short: {got} of {HEADER_SIZE} bytes"
            )));
        }
        let layout = parse_header(&head).map_err(ModuleError::InvalidInputFormat)?;

        let logical_size = layout.logical_size;
        let total_bands = layout.logical_to_phys.len();
        let allocated_bands = layout
            .logical_to_phys
            .iter()
            .filter(|b| b.is_some())
            .count();
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("disk.sparseimage")
            .to_string();

        info!(
            "Opened sparse image {name}: {logical_size} bytes logical, \
             {allocated_bands}/{total_bands} bands allocated"
        );

        // Wrap in DeviceImageSource: the decoded stream *is* the acquired disk,
        // so an offset into it is an exact physical device coordinate.
        let source: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(Arc::new(
            SparseImageDataSource::new(Arc::clone(data_source), layout),
        )));

        let metadata = json!({
            "name": name,
            "container": "sparseimage",
            "container_format": "Apple sparse disk image",
            "size": logical_size,
            "allocated_bands": allocated_bands,
            "total_bands": total_bands,
        });

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(source),
            metadata,
        )
        .with_parent(artifact.id)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use uuid::Uuid;

    /// Build a `.sparseimage` from a raw disk, allocating a physical band only
    /// for logical bands that hold non-zero bytes (mirrors how a real imager
    /// grows the file). This is the writer counterpart of the reader and follows
    /// the exact libmodi interpretation, so a real tool would read it too.
    fn build_sparseimage(raw: &[u8], sectors_per_band: u32) -> Vec<u8> {
        let spb = sectors_per_band as usize;
        let band_bytes = spb * SECTOR as usize;
        let total_sectors = raw.len().div_ceil(SECTOR as usize);
        let nbands = total_sectors.div_ceil(spb);
        let mut padded = raw.to_vec();
        padded.resize(nbands * band_bytes, 0);

        let mut header = vec![0u8; HEADER_SIZE as usize];
        header[0..4].copy_from_slice(b"sprs");
        header[4..8].copy_from_slice(&3u32.to_be_bytes()); // version
        header[8..12].copy_from_slice(&sectors_per_band.to_be_bytes());
        header[0x0c..0x10].copy_from_slice(&1u32.to_be_bytes());
        header[0x10..0x14].copy_from_slice(&(total_sectors as u32).to_be_bytes());

        let mut bands = Vec::new();
        let mut phys = 0u32;
        for l in 0..nbands {
            let band = &padded[l * band_bytes..(l + 1) * band_bytes];
            if band.iter().all(|&b| b == 0) {
                continue; // leave unallocated -> logical zeros
            }
            let off = BAND_ARRAY_OFF + phys as usize * 4;
            header[off..off + 4].copy_from_slice(&((l as u32) + 1).to_be_bytes());
            bands.extend_from_slice(band);
            phys += 1;
        }
        header.extend_from_slice(&bands);
        header
    }

    fn open(image: Vec<u8>) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(image))),
            json!({ "name": "disk.sparseimage", "subtype": "sparseimage" }),
        );
        SparseImageContainerModule.process(&art).expect("process")
    }

    fn read_all(src: &Arc<dyn DataSource>, size: u64) -> Vec<u8> {
        let mut buf = vec![0u8; size as usize];
        let mut off = 0u64;
        while off < size {
            let n = src.read_at(off, &mut buf[off as usize..]).unwrap();
            assert!(n > 0, "read stalled at {off}");
            off += n as u64;
        }
        buf
    }

    /// A raw disk with data and deliberately-empty bands round-trips exactly,
    /// and every sub-range read agrees with the original.
    #[test]
    fn round_trips_bytes_including_sparse_bands() {
        for spb in [1u32, 2, 8, 64] {
            let band_bytes = spb as usize * SECTOR as usize;
            let mut raw = Vec::new();
            for l in 0..7usize {
                if l == 1 || l == 4 {
                    raw.extend(std::iter::repeat_n(0u8, band_bytes)); // sparse
                } else {
                    // deterministic, non-zero, band-dependent content
                    raw.extend((0..band_bytes).map(|i| ((i + l * 7) % 251 + 1) as u8));
                }
            }
            let image = build_sparseimage(&raw, spb);
            let out = open(image);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].artifact_type, ArtifactType::RawEvidence);
            let src = out[0].data.as_ref().unwrap();
            assert_eq!(src.size(), raw.len() as u64, "logical size (spb={spb})");
            assert_eq!(
                read_all(src, raw.len() as u64),
                raw,
                "full read (spb={spb})"
            );
            // A spread of sub-range reads across band boundaries.
            for &(o, n) in &[
                (0u64, 3u64),
                (band_bytes as u64 - 2, 5),
                (band_bytes as u64, 1),
                (1, raw.len() as u64 - 2),
            ] {
                let mut b = vec![0u8; n as usize];
                let mut got = 0usize;
                while got < n as usize {
                    let k = src.read_at(o + got as u64, &mut b[got..]).unwrap();
                    if k == 0 {
                        break;
                    }
                    got += k;
                }
                assert_eq!(
                    &b[..got],
                    &raw[o as usize..o as usize + got],
                    "subrange o={o} n={n} spb={spb}"
                );
            }
        }
    }

    /// The sparse bands are genuinely absent from the file (the point of the
    /// format): the image is smaller than a flat copy of the disk.
    #[test]
    fn unallocated_bands_are_not_stored() {
        let band_bytes = 8 * SECTOR as usize;
        let mut raw = vec![0u8; band_bytes * 5]; // 5 bands, all zero...
        raw[band_bytes * 2..band_bytes * 2 + 4].copy_from_slice(b"data"); // ...except band 2
        let image = build_sparseimage(&raw, 8);
        assert!(
            (image.len() as u64) < HEADER_SIZE + raw.len() as u64,
            "only allocated bands are stored ({} vs flat {})",
            image.len(),
            HEADER_SIZE as usize + raw.len()
        );
        let out = open(image);
        let src = out[0].data.as_ref().unwrap();
        let back = read_all(src, raw.len() as u64);
        assert_eq!(back, raw, "zeros for the holes, data where written");
    }

    /// A mapped band whose bytes are missing from a truncated file is an error,
    /// never silent zeros — a truncated capture must not read as a sparse one.
    #[test]
    fn a_truncated_present_band_errors_rather_than_zero_filling() {
        let band_bytes = 8 * SECTOR as usize;
        let raw: Vec<u8> = (0..band_bytes * 2).map(|i| (i % 255 + 1) as u8).collect();
        let mut image = build_sparseimage(&raw, 8);
        image.truncate(HEADER_SIZE as usize + band_bytes + 4); // cut into the 2nd band
        let out = open(image);
        let src = out[0].data.as_ref().unwrap();
        // Band 0 still reads fine.
        let mut b0 = vec![0u8; band_bytes];
        assert!(src.read_at(0, &mut b0).is_ok());
        // Reading into the truncated 2nd band must error, not fabricate zeros.
        let mut b1 = vec![0u8; band_bytes];
        assert!(
            src.read_at(band_bytes as u64, &mut b1).is_err(),
            "a truncated present band must fail closed"
        );
    }

    #[test]
    fn rejects_a_file_without_the_signature() {
        let mut image = build_sparseimage(&vec![1u8; 4096], 8);
        image[0..4].copy_from_slice(b"junk");
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(image))),
            json!({ "name": "x.sparseimage", "subtype": "sparseimage" }),
        );
        assert!(matches!(
            SparseImageContainerModule.process(&art),
            Err(ModuleError::InvalidInputFormat(_))
        ));
    }

    /// Two physical slots claiming the same logical band is not a layout any
    /// writer produces: one payload is orphaned and the other silently backs the
    /// sector, so the image must be refused rather than served from the wrong
    /// place on disk.
    #[test]
    fn a_duplicate_logical_band_map_is_refused_rather_than_last_wins() {
        let band_bytes = 8 * SECTOR as usize;
        let mut raw = Vec::new();
        for l in 0..3usize {
            // Distinct, non-zero content per band, so all three are allocated.
            raw.extend(std::iter::repeat_n((l as u8) + 1, band_bytes));
        }
        let mut image = build_sparseimage(&raw, 8);
        // Physical slot 2 now also claims logical band 0: last-wins would make
        // logical band 0 read physical band 2's bytes and orphan band 2.
        let slot2 = BAND_ARRAY_OFF + 2 * 4;
        image[slot2..slot2 + 4].copy_from_slice(&1u32.to_be_bytes());

        let err = parse_header(&image[..HEADER_SIZE as usize]).unwrap_err();
        assert!(
            err.contains("logical band 0"),
            "the refusal must name the duplicated band; got: {err}"
        );

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(image))),
            json!({ "name": "dup.sparseimage", "subtype": "sparseimage" }),
        );
        assert!(
            matches!(
                SparseImageContainerModule.process(&art),
                Err(ModuleError::InvalidInputFormat(_))
            ),
            "a duplicate band map must not open as a readable disk"
        );
    }

    #[test]
    fn rejects_a_band_table_that_cannot_fit_the_header() {
        // sectors_per_band = 1 with a huge sector count implies > 1008 bands,
        // which cannot fit the fixed header — reject rather than mis-read.
        let mut header = vec![0u8; HEADER_SIZE as usize];
        header[0..4].copy_from_slice(b"sprs");
        header[8..12].copy_from_slice(&1u32.to_be_bytes()); // 1 sector/band
        header[0x10..0x14].copy_from_slice(&5000u32.to_be_bytes()); // 5000 bands
        let err = parse_header(&header).unwrap_err();
        assert!(err.contains("exceeds"), "got: {err}");
    }

    #[test]
    fn emits_rawevidence_with_container_metadata() {
        let raw = vec![7u8; 8 * SECTOR as usize * 3];
        let out = open(build_sparseimage(&raw, 8));
        let md = &out[0].metadata;
        assert_eq!(md["container"], json!("sparseimage"));
        assert_eq!(md["size"], json!(raw.len()));
        assert_eq!(md["allocated_bands"], json!(3));
        assert_eq!(md["total_bands"], json!(3));
    }

    #[test]
    fn ignores_artifacts_that_are_not_sparse_images() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 16]))),
            json!({ "name": "photo.jpg" }),
        );
        assert!(SparseImageContainerModule.process(&art).unwrap().is_empty());
    }
}
