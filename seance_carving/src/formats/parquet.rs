//! Apache Parquet (`.parquet`).
//!
//! # Why it is worth carving
//!
//! Parquet is where analytic and exported data sits: warehouse extracts, data
//! science working sets, the output of a `SELECT` someone ran before leaving.
//! In an exfiltration or IP-theft case that is often the material fact, and a
//! carver that recovers documents and images but not the columnar file holding
//! the exported customer table has missed the thing worth finding.
//!
//! # What makes it checkable, and what is not done
//!
//! The format brackets itself: `PAR1` at the start and `PAR1` at the end, with
//! the footer length in the four bytes before the trailing magic. So unlike
//! most compressed and columnar formats a carve of it can be *checked* rather
//! than merely bounded: [`FileSignature::verify_footer`] returns a real verdict
//! on the tail of an extent.
//!
//! **The end is found from the tail, by a source read** (CARVE-018).
//! `data_check` never returns `Stop`: a block-at-a-time check cannot tell the
//! trailing `PAR1` from one inside compressed column data, and has no view of
//! the footer the trailing length points back to. `extent_from_source`
//! (`FileSignature::extent_from_source`) scans forward for `PAR1`, reads the
//! footer length before each hit and accepts the first whose footer begins
//! with the Thrift `FileMetaData` version field (`0x15`, then zigzag 1 or 2).
//! The carve ends there, sized from the file's own structure, so it carries no
//! `validated` flag; `verify_footer` is not reached on the engine's path. A
//! file with no such footer in the next 1 GiB (a truncated one) stays on the
//! unsized path and runs to the next header, the cap or the end of the source,
//! reported not validated.
//!
//! Limits, stated: a stray `PAR1` in column data passes the footer test about
//! once in 32,768; a Parquet file stored uncompressed in another file's column
//! is sized as the inner file if its footer passes first; a file not
//! contiguous in the source is not found; and every header match that passes
//! the header-block check makes the engine read up to 1 GiB looking for the
//! end.

use crate::engine::CarvingDataSource;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Both the leading and the trailing magic.
const PARQUET_MAGIC: &[u8; 4] = b"PAR1";

/// The smallest possible file: leading magic, footer length, trailing magic.
const MIN_PARQUET: u64 = 12;

struct ParquetSignature;

impl FileSignature for ParquetSignature {
    fn name(&self) -> &str {
        "Parquet"
    }

    fn extensions(&self) -> &[&str] {
        &["parquet"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 4 || &buf[..4] != PARQUET_MAGIC {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: MIN_PARQUET,
            extension: "parquet".to_string(),
            calculated_file_size: None,
        })
    }

    /// The extent: the first trailing `PAR1` whose footer-length field points
    /// back at a plausible `FileMetaData` (CARVE-018).
    ///
    /// Scans forward from the header in 1 MiB chunks for `PAR1` at relative
    /// position `p >= 12`. For each hit the u32 at `p - 4` is the footer
    /// length `L`; the footer starts at `f = p - 4 - L` and must open with the
    /// Thrift field header `0x15` (field 1, `version`, an i32) followed by the
    /// zigzag varint of version 1 or 2. The first hit that passes is the end.
    /// `None` when none passes within [`SCAN_CAP`], so a truncated file stays
    /// on the unsized path.
    ///
    /// Stated limits. A stray `PAR1` in column data passes the test with odds
    /// of about 1 in 32,768, so it can end a carve early. A Parquet file
    /// stored uncompressed inside another file's column is sized as the inner
    /// file when its footer passes first. A file fragmented in the source is
    /// not found. The engine calls this for every header match, so a stray
    /// leading `PAR1` that passes the header block check makes it read up to
    /// [`SCAN_CAP`] bytes.
    fn extent_from_source(&self, source: &dyn CarvingDataSource, offset: u64) -> Option<u64> {
        let window = self
            .max_file_size()
            .min(SCAN_CAP)
            .min(source.size().saturating_sub(offset));
        let mut pos = 4u64; // relative position of the next byte to examine
        let mut carry: Vec<u8> = Vec::new(); // up to 3 bytes before `pos`
        let mut chunk = vec![0u8; CHUNK];
        while pos < window {
            let want = (window - pos).min(CHUNK as u64) as usize;
            let mut got = 0;
            while got < want {
                match source.read_at(offset + pos + got as u64, &mut chunk[got..want]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            if got == 0 {
                return None;
            }
            let mut hay = std::mem::take(&mut carry);
            let base = pos - hay.len() as u64; // relative position of hay[0]
            hay.extend_from_slice(&chunk[..got]);
            for i in 0..hay.len().saturating_sub(3) {
                if &hay[i..i + 4] != PARQUET_MAGIC {
                    continue;
                }
                let p = base + i as u64;
                if p >= MIN_PARQUET - 4 && footer_plausible(source, offset, p) {
                    return Some(p + 4);
                }
            }
            let keep = hay.len().min(3);
            carry = hay[hay.len() - keep..].to_vec();
            pos += got as u64;
            if got < want {
                break;
            }
        }
        None
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray `PAR1` from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        // The end is only findable from the tail, which `verify_footer` sees.
        // Guessing at it from a forward scan would mistake a `PAR1` inside
        // compressed column data for the file's end.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    /// A real verdict on an extent's tail, because this format has a real
    /// terminator: `Some(true)` when the extent ends with `PAR1`, `Some(false)`
    /// when the bytes were read and it does not.
    ///
    /// The engine reaches this only after a `Stop` from `data_check`, which
    /// this signature never returns: the extent comes from
    /// `extent_from_source` instead (see the module notes), so on the engine's
    /// path no Parquet carve is given this verdict.
    fn verify_footer(&self, data: &[u8]) -> Option<bool> {
        if data.len() < 4 {
            return Some(false);
        }
        Some(&data[data.len() - 4..] == PARQUET_MAGIC)
    }

    fn max_file_size(&self) -> u64 {
        2 * 1024 * 1024 * 1024
    }
}

/// The most `extent_from_source` reads looking for the trailing magic.
const SCAN_CAP: u64 = 1024 * 1024 * 1024;

/// Read size of the trailing-magic scan.
const CHUNK: usize = 1024 * 1024;

/// Does the `PAR1` at relative position `p` close a file that began at
/// `offset`? The u32 before it is the footer length; the footer must start
/// after the leading magic and open with `FileMetaData` field 1 (`version`,
/// i32 = Thrift `0x15`) holding zigzag 1 or 2 (version 1 or 2).
fn footer_plausible(source: &dyn CarvingDataSource, offset: u64, p: u64) -> bool {
    let Some(len_at) = p.checked_sub(4) else {
        return false;
    };
    let mut len = [0u8; 4];
    if !read_exact_at(source, offset + len_at, &mut len) {
        return false;
    }
    let footer_len = u32::from_le_bytes(len) as u64;
    if footer_len < 8 {
        return false;
    }
    let Some(footer_start) = len_at.checked_sub(footer_len) else {
        return false;
    };
    if footer_start < 4 {
        return false;
    }
    let mut head = [0u8; 2];
    read_exact_at(source, offset + footer_start, &mut head)
        && head[0] == 0x15
        && matches!(head[1], 0x02 | 0x04)
}

/// Fill `buf` from `offset`; false if the source cannot supply every byte.
fn read_exact_at(source: &dyn CarvingDataSource, offset: u64, buf: &mut [u8]) -> bool {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read_at(offset + filled as u64, &mut buf[filled..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => filled += n,
        }
    }
    true
}

/// Bytes 4.. of a Parquet file are the first column chunk's page header, or,
/// in a file with no row groups, the footer's `FileMetaData`. Both are Thrift
/// compact-protocol structs whose first field (id 1) is an `i32`, so byte 4
/// is the short-form field header `0x15` and byte 5 the zigzag varint of a
/// small non-negative value: a page type (0–3) or a format version (1–2).
fn header_block_plausible(buf: &[u8]) -> bool {
    buf.len() < 6 || (buf[4] == 0x15 && matches!(buf[5], 0x00 | 0x02 | 0x04 | 0x06))
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PARQUET_MAGIC, Arc::new(ParquetSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parquet_header_is_recognised() {
        let sig = ParquetSignature;
        let mut buf = PARQUET_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 32]);
        let init = sig.header_check(&buf, 0).expect("a parquet file");
        assert_eq!(init.extension, "parquet");
        assert_eq!(
            init.min_filesize, MIN_PARQUET,
            "a file shorter than magic + footer length + magic cannot be one"
        );
    }

    #[test]
    fn other_bytes_are_not_parquet() {
        let sig = ParquetSignature;
        assert!(sig.header_check(b"PAR2xxxx", 0).is_none());
        assert!(sig.header_check(b"PK\x03\x04", 0).is_none());
        assert!(sig.header_check(b"PAR", 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
    }

    /// The point of implementing `verify_footer` at all: a carve that reached
    /// the trailing magic is validated, and one that did not must say so rather
    /// than be presented as complete.
    #[test]
    fn the_footer_verdict_distinguishes_a_whole_file_from_a_truncated_one() {
        let sig = ParquetSignature;

        let mut whole = PARQUET_MAGIC.to_vec();
        whole.extend_from_slice(&[0xAB; 64]);
        whole.extend_from_slice(&64u32.to_le_bytes());
        whole.extend_from_slice(PARQUET_MAGIC);
        assert_eq!(sig.verify_footer(&whole), Some(true));

        // Interrupted before the end: the bytes were read and the terminator is
        // not there.
        let truncated = &whole[..whole.len() - 8];
        assert_eq!(
            sig.verify_footer(truncated),
            Some(false),
            "a carve missing its terminator must not be reported as validated"
        );
        assert_eq!(sig.verify_footer(&[]), Some(false));
    }

    // CARVE-018. SYNTHETIC from a real tool: `real_file()` is a Parquet file
    // written by pyarrow 26.0.0 (1000 rows, an int and a string column). It
    // grades the extent only, never a claim about real-world evidence.
    use crate::scan_tests::Mem;

    fn real_file() -> &'static [u8] {
        include_bytes!("../../tests/fixtures/carve018/pyarrow_26_0_0.parquet")
    }

    #[test]
    fn the_extent_of_a_real_pyarrow_file_is_found_from_its_trailing_magic() {
        assert_eq!(real_file().len(), 11_249);
        let mut data = real_file().to_vec();
        data.extend_from_slice(&[0xAA; 4096]);
        assert_eq!(
            ParquetSignature.extent_from_source(&Mem(data), 0),
            Some(11_249)
        );
    }

    #[test]
    fn a_file_cut_before_its_trailing_magic_has_no_extent() {
        let data = real_file()[..real_file().len() - 100].to_vec();
        assert_eq!(ParquetSignature.extent_from_source(&Mem(data), 0), None);
    }

    #[test]
    fn a_stray_par1_whose_length_field_points_nowhere_is_skipped() {
        // Decoy `PAR1` in the body: its preceding u32 points at a byte that is
        // not a 0x15 field header, so the real end is still the one found.
        let mut data = real_file().to_vec();
        let decoy = 2000;
        data[decoy..decoy + 4].copy_from_slice(&200u32.to_le_bytes());
        data[decoy + 4..decoy + 8].copy_from_slice(PARQUET_MAGIC);
        data.extend_from_slice(&[0xAA; 512]);
        assert_eq!(
            ParquetSignature.extent_from_source(&Mem(data), 0),
            Some(11_249)
        );
    }

    #[test]
    fn the_extent_is_relative_to_the_offset_the_file_starts_at() {
        let mut data = vec![0x55; 8192];
        data.extend_from_slice(real_file());
        data.extend_from_slice(&[0xAA; 4096]);
        assert_eq!(
            ParquetSignature.extent_from_source(&Mem(data), 8192),
            Some(11_249)
        );
    }
}
