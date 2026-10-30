use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Phases of the marker-segment walk kept in `FileRecovery::extra_bytes[0]`.
const SEG_MARKER: u8 = 1;
const SEG_CODE: u8 = 2;
const SEG_LEN_HI: u8 = 3;
const SEG_LEN_LO: u8 = 4;
/// Scanning for the EOI (entropy-coded data, or a walk that fell back).
const SEG_SCAN: u8 = 5;
/// Index in `extra_bytes` of the flag that the previous block ended in `FF`, so
/// an EOI split across the block boundary (`FF` | `D9`) is still seen.
const CARRIED_FF: usize = 3;

/// JPEG file signature detector.
/// Header: FF D8 FF at offset 0
/// Footer: FF D9 (EOI marker)
/// Ref: reference/testdisk/src/file_jpg.c
struct JpegSignature;

impl FileSignature for JpegSignature {
    fn name(&self) -> &str {
        "JPEG"
    }

    fn extensions(&self) -> &[&str] {
        &["jpg", "jpeg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 3 && buf[0] == 0xFF && buf[1] == 0xD8 && buf[2] == 0xFF {
            Some(RecoveryInit {
                min_filesize: 100,
                extension: "jpg".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        let base = recovery.file_size;
        let mut scan_from = 0usize;
        if recovery.extra_bytes.is_empty() {
            if base == 0 {
                // Walk the marker segments from just past SOI.
                recovery.extra = 2;
                recovery.extra_bytes = vec![SEG_MARKER, 0, 0, 0];
            } else {
                // No walk state for this carve: scan for the EOI.
                recovery.extra_bytes = vec![SEG_SCAN, 0, 0, 0];
                recovery.extra = base;
            }
        }
        // The marker segments before the first scan are walked by their
        // lengths (ITU-T T.81 B.1.1.4), so an EOI inside one — the end of an
        // Exif thumbnail in APP1 — is not taken for the image's own. From
        // the first SOS on, entropy-coded data cannot hold `FF D9` except as
        // the EOI, and the first one ends the file. A length the walk cannot
        // follow falls back to that scan from where it stood. Bound: a damaged
        // length that still lands on an `FF` byte is followed, and an EOI it
        // jumps over is not seen; the carve then ends at a later EOI or at the
        // next header, and is not footer-validated unless it ends on `FF D9`.
        while recovery.extra_bytes[0] != SEG_SCAN {
            let next = recovery.extra;
            let Some(i) = next.checked_sub(base) else {
                recovery.extra_bytes[0] = SEG_SCAN;
                break;
            };
            let Some(&b) = buf.get(i as usize) else {
                return DataCheckResult::Continue;
            };
            recovery.extra = next + 1;
            match recovery.extra_bytes[0] {
                SEG_MARKER => {
                    if b != 0xFF {
                        recovery.extra = next;
                        recovery.extra_bytes[0] = SEG_SCAN;
                    } else {
                        recovery.extra_bytes[0] = SEG_CODE;
                    }
                }
                SEG_CODE => match b {
                    0xFF => {} // fill
                    0xD9 => return DataCheckResult::Stop(next + 1),
                    // Stand-alone markers carry no length.
                    0x01 | 0xD0..=0xD8 => recovery.extra_bytes[0] = SEG_MARKER,
                    0x00 => {
                        recovery.extra = next;
                        recovery.extra_bytes[0] = SEG_SCAN;
                    }
                    code => {
                        recovery.extra_bytes[2] = u8::from(code == 0xDA);
                        recovery.extra_bytes[0] = SEG_LEN_HI;
                    }
                },
                SEG_LEN_HI => {
                    recovery.extra_bytes[1] = b;
                    recovery.extra_bytes[0] = SEG_LEN_LO;
                }
                SEG_LEN_LO => {
                    let len = u16::from_be_bytes([recovery.extra_bytes[1], b]) as u64;
                    if len < 2 {
                        recovery.extra = next + 1;
                        recovery.extra_bytes[0] = SEG_SCAN;
                        continue;
                    }
                    // The length counts its own two bytes.
                    recovery.extra = next - 1 + len;
                    recovery.extra_bytes[0] = if recovery.extra_bytes[2] == 1 {
                        SEG_SCAN
                    } else {
                        SEG_MARKER
                    };
                }
                _ => recovery.extra_bytes[0] = SEG_SCAN,
            }
        }
        if let Some(i) = recovery.extra.checked_sub(base) {
            scan_from = i as usize;
        }
        // The previous block's last byte was an `FF` the scan had reached: an
        // `FF D9` that straddles the boundary ends here, at this block's first
        // byte.
        let carried_ff = std::mem::take(&mut recovery.extra_bytes[CARRIED_FF]) == 1;
        if carried_ff && scan_from == 0 && buf.first() == Some(&0xD9) {
            return DataCheckResult::Stop(base + 1);
        }
        if scan_from >= buf.len() {
            return DataCheckResult::Continue;
        }
        // Scan for JPEG EOI marker (FF D9)
        for i in scan_from..buf.len().saturating_sub(1) {
            if buf[i] == 0xFF && buf[i + 1] == 0xD9 {
                return DataCheckResult::Stop(base + i as u64 + 2);
            }
        }
        recovery.extra_bytes[CARRIED_FF] = u8::from(buf.last() == Some(&0xFF));
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {
        // Size and extension are settled by data_check; the end-of-image check
        // is reported through verify_footer.
    }

    /// A JPEG ends at its EOI marker (FF D9). The recovered extent must end on
    /// those two bytes; anything else means the carve stopped somewhere the
    /// image does not actually end.
    fn verify_footer(&self, data: &[u8]) -> Option<bool> {
        if data.len() < 2 {
            return Some(false);
        }
        Some(data[data.len() - 2] == 0xFF && data[data.len() - 1] == 0xD9)
    }

    fn max_file_size(&self) -> u64 {
        128 * 1024 * 1024 // 128 MB
    }
}

/// The first marker segment after SOI (ITU-T T.81 B.1.1), and the marker
/// that follows it, as far as this block holds them:
///
/// - the segment opens with `0xFF` (a few extra `0xFF` fill bytes may come
///   first) and a marker code that may appear before a scan: a frame, table,
///   restart-interval, application, comment or extension marker, or SOS,
///   after which entropy-coded data begins and nothing more is checked;
/// - its length counts its own two bytes, and a frame header (SOFn),
///   quantisation table (DQT), Huffman table (DHT) or restart interval (DRI)
///   has the length its fields require, with those fields in range: sample
///   precision 2–16 and a length of 8 + 3 × components; table class 0–1 and
///   destination 0–3;
/// - where it ends, the next marker begins, which is what confirms the
///   length.
///
/// Only the first segment is held to this. One confirmed segment is proof
/// enough that the block is a JPEG, and a JPEG damaged further on is still
/// worth recovering: DFTT #11's `haxor2.jpg` has its second segment's length
/// zeroed and is otherwise intact.
fn header_block_plausible(buf: &[u8]) -> bool {
    /// The marker at `i`, past any fill bytes: `Ok(Some((code, next)))`,
    /// `Ok(None)` when the block ends first, `Err(())` when there is none.
    fn marker(buf: &[u8], mut i: usize) -> Result<Option<(u8, usize)>, ()> {
        let Some(&first) = buf.get(i) else {
            return Ok(None);
        };
        if first != 0xFF {
            return Err(());
        }
        let fill_start = i;
        while i < buf.len() && buf[i] == 0xFF {
            i += 1;
        }
        match buf.get(i) {
            // A long run of 0xFF to the end of the block is not fill.
            None if i - fill_start >= 8 => Err(()),
            None => Ok(None),
            Some(&code @ (0xC0..=0xCF | 0xDA..=0xDF | 0xE0..=0xFE)) => Ok(Some((code, i + 1))),
            Some(_) => Err(()),
        }
    }
    let (code, i) = match marker(buf, 2) {
        Ok(Some(m)) => m,
        Ok(None) => return true,
        Err(()) => return false,
    };
    if code == 0xDA {
        return true;
    }
    let Some(len) = buf
        .get(i..i + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    else {
        return true;
    };
    if len < 2 {
        return false;
    }
    let body = &buf[(i + 2).min(buf.len())..(i + len).min(buf.len())];
    let table_id = |b: &u8| b >> 4 <= 1 && b & 0x0F <= 3;
    let fits = match code {
        0xC4 => len <= 2 + 4 * (17 + 256) && body.first().is_none_or(table_id),
        // JPG and DAC carry no frame; the other C0–CF are SOFn.
        0xC8 | 0xCC => true,
        0xC0..=0xCF => {
            len <= 8 + 3 * 255
                && body.first().is_none_or(|&p| (2..=16).contains(&p))
                && body
                    .get(5)
                    .is_none_or(|&nf| nf >= 1 && len == 8 + 3 * nf as usize)
        }
        0xDB => len <= 2 + 4 * 129 && body.first().is_none_or(table_id),
        0xDD => len == 4,
        _ => true,
    };
    fits && marker(buf, i + len).is_ok()
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0xFF, 0xD8, 0xFF], Arc::new(JpegSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jpeg_header_match() {
        let sig = JpegSignature;
        // Valid JPEG header (FF D8 FF E0 = JFIF)
        let buf = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_jpeg_header_no_match() {
        let sig = JpegSignature;
        let buf = [0x89, 0x50, 0x4E, 0x47]; // PNG header
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_jpeg_footer_detection() {
        let sig = JpegSignature;
        let mut recovery = FileRecovery {
            extension: "jpg".to_string(),
            file_size: 0,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 100,
            extra: 0,
            extra_bytes: Vec::new(),
        };

        // A later block (the header block is checked for its segments,
        // CARVE-015) with the EOI marker at position 4.
        recovery.file_size = 512;
        let buf = [0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9, 0x00, 0x00];
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(result, DataCheckResult::Stop(512 + 6));
    }

    fn fresh() -> FileRecovery {
        FileRecovery {
            extension: "jpg".to_string(),
            file_size: 0,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 100,
            extra: 0,
            extra_bytes: Vec::new(),
        }
    }

    /// A JFIF whose APP1 (Exif) segment carries a whole thumbnail JPEG, EOI
    /// included, ahead of the image's own tables and scan (DFTT #12's
    /// `sherry.jpg` is built this way).
    fn jpeg_with_exif_thumbnail() -> Vec<u8> {
        let mut j = vec![0xFF, 0xD8];
        j.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        j.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        let mut thumb = vec![0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00];
        thumb.extend_from_slice(&[0x12; 40]);
        thumb.extend_from_slice(&[0xFF, 0xD9]);
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend_from_slice(&thumb);
        j.extend_from_slice(&[0xFF, 0xE1]);
        j.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
        j.extend_from_slice(&app1);
        j.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
        j.extend_from_slice(&[0x08; 64]);
        j.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        j.extend_from_slice(&[0x55, 0xFF, 0x00, 0x66, 0xFF, 0xD0, 0x77]); // scan data
        j.extend_from_slice(&[0xFF, 0xD9]);
        j
    }

    /// An EOI whose `FF` ends one block and whose `D9` opens the next is the
    /// image's end, wherever the scan data before it ends.
    #[test]
    fn an_eoi_split_across_two_blocks_is_found() {
        let mut j = jpeg_with_exif_thumbnail();
        j.truncate(j.len() - 2); // drop the EOI
        j.resize(511, 0x11); // scan data up to the last byte of block 0
        j.push(0xFF);
        let mut second = vec![0xD9];
        second.extend_from_slice(&[0u8; 100]);
        let mut recovery = fresh();
        assert_eq!(
            JpegSignature.data_check(&j, &mut recovery),
            DataCheckResult::Continue
        );
        recovery.file_size = 512;
        assert_eq!(
            JpegSignature.data_check(&second, &mut recovery),
            DataCheckResult::Stop(513)
        );
        // A block that does not open with D9 clears the flag, and a later
        // lone D9 is not an EOI.
        let mut recovery = fresh();
        assert_eq!(
            JpegSignature.data_check(&j, &mut recovery),
            DataCheckResult::Continue
        );
        recovery.file_size = 512;
        let miss = [0x00u8, 0xD9, 0x00];
        assert_eq!(
            JpegSignature.data_check(&miss, &mut recovery),
            DataCheckResult::Continue
        );
    }

    #[test]
    fn an_eoi_inside_an_application_segment_is_not_the_end() {
        let j = jpeg_with_exif_thumbnail();
        let mut buf = j.clone();
        buf.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            JpegSignature.data_check(&buf, &mut fresh()),
            DataCheckResult::Stop(j.len() as u64)
        );
    }

    #[test]
    fn the_segment_walk_carries_across_blocks_at_every_split() {
        let j = jpeg_with_exif_thumbnail();
        for split in 30..j.len() - 1 {
            let mut rec = fresh();
            let (a, b) = j.split_at(split);
            let first = JpegSignature.data_check(a, &mut rec);
            if first != DataCheckResult::Continue {
                panic!("split {split}: first block gave {first:?}");
            }
            rec.file_size = a.len() as u64;
            assert_eq!(
                JpegSignature.data_check(b, &mut rec),
                DataCheckResult::Stop(j.len() as u64),
                "split {split}"
            );
        }
    }

    #[test]
    fn a_segment_length_that_makes_no_sense_falls_back_to_the_first_eoi() {
        // A zeroed length (DFTT #11's haxor2.jpg) cannot be walked past; the
        // carve then ends at the first EOI, as it always did.
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        j.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        j.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x00, 0x11, 0x22, 0xFF, 0xD9]);
        assert_eq!(
            JpegSignature.data_check(&j, &mut fresh()),
            DataCheckResult::Stop(j.len() as u64)
        );
    }

    /// The EOI check must be reported, not computed and dropped: the engine
    /// stamps a carve "footer-validated" from this verdict alone (B2-143).
    #[test]
    fn jpeg_footer_verdict_is_returned() {
        let sig = JpegSignature;
        assert_eq!(sig.verify_footer(&[0x11, 0x22, 0xFF, 0xD9]), Some(true));
        // Ends one byte past the EOI: not a validated end of image.
        assert_eq!(sig.verify_footer(&[0x11, 0xFF, 0xD9, 0x00]), Some(false));
        // No EOI anywhere.
        assert_eq!(sig.verify_footer(&[0x11, 0x22, 0x33, 0x44]), Some(false));
        // Too short to carry a marker: absence is not confirmation.
        assert_eq!(sig.verify_footer(&[0xFF]), Some(false));
    }
}
