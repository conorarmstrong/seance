use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// GIF file signature detector.
/// Header: GIF87a (47 49 46 38 37 61) or GIF89a (47 49 46 38 39 61)
/// Footer: trailer byte 0x3B
struct GifSignature;

impl FileSignature for GifSignature {
    fn name(&self) -> &str {
        "GIF"
    }

    fn extensions(&self) -> &[&str] {
        &["gif"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 6
            && &buf[0..4] == b"GIF8"
            && (buf[4] == b'7' || buf[4] == b'9')
            && buf[5] == b'a'
        {
            Some(RecoveryInit {
                min_filesize: 14, // Minimum: header + screen descriptor + trailer
                extension: "gif".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    /// Walk the GIF block structure (GIF89a specification: header, logical
    /// screen descriptor, optional global colour table, then extension and
    /// image blocks made of length-prefixed sub-blocks) to the `0x3B` trailer
    /// that stands where a block introducer is due.
    ///
    /// A bare `0x3B` byte is not the end: compressed image data holds that
    /// byte freely, and stopping at the first one carved most GIFs short (DFTT
    /// #12's `blogo.gif` ended at byte 953 of 18,663). The walk's state is
    /// carried across engine blocks in `recovery.extra` (the file offset of
    /// the next byte to interpret) and `recovery.extra_bytes` (`[phase,
    /// descriptor byte count]`). A byte where no GIF structure can stand ends
    /// the walk as an error, which the engine records as not validated.
    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        const INTRODUCER: u8 = 1;
        const EXT_LABEL: u8 = 2;
        const IMAGE_DESCRIPTOR: u8 = 3;
        const LZW_MIN: u8 = 4;
        const SUB_BLOCK_LEN: u8 = 5;
        let base = recovery.file_size;
        if recovery.extra_bytes.is_empty() {
            // The header block: header (6) + logical screen descriptor (7).
            if base != 0 || buf.len() < 13 {
                return DataCheckResult::Error;
            }
            recovery.extra = 13 + colour_table_len(buf[10]);
            recovery.extra_bytes = vec![INTRODUCER, 0];
        }
        loop {
            let next = recovery.extra;
            let Some(i) = next.checked_sub(base) else {
                return DataCheckResult::Error;
            };
            let Some(&b) = buf.get(i as usize) else {
                return DataCheckResult::Continue;
            };
            let phase = recovery.extra_bytes[0];
            recovery.extra = next + 1;
            match phase {
                INTRODUCER => match b {
                    0x21 => recovery.extra_bytes[0] = EXT_LABEL,
                    0x2C => recovery.extra_bytes = vec![IMAGE_DESCRIPTOR, 0],
                    0x3B => return DataCheckResult::Stop(next + 1),
                    _ => return DataCheckResult::Error,
                },
                EXT_LABEL => recovery.extra_bytes[0] = SUB_BLOCK_LEN,
                IMAGE_DESCRIPTOR => {
                    // left, top, width, height (2 bytes each), then packed.
                    recovery.extra_bytes[1] += 1;
                    if recovery.extra_bytes[1] == 9 {
                        recovery.extra = next + 1 + colour_table_len(b);
                        recovery.extra_bytes[0] = LZW_MIN;
                    }
                }
                LZW_MIN => recovery.extra_bytes[0] = SUB_BLOCK_LEN,
                SUB_BLOCK_LEN => {
                    if b == 0 {
                        recovery.extra_bytes[0] = INTRODUCER;
                    } else {
                        recovery.extra = next + 1 + b as u64;
                    }
                }
                _ => return DataCheckResult::Error,
            }
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        32 * 1024 * 1024 // 32 MB
    }
}

/// Length of the colour table a packed field declares: `3 * 2^(n+1)` bytes
/// when its top bit is set, none otherwise.
fn colour_table_len(packed: u8) -> u64 {
    if packed & 0x80 != 0 {
        3u64 << ((packed & 7) + 1)
    } else {
        0
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    // GIF87a
    registry.register(0, b"GIF87a", Arc::new(GifSignature));
    // GIF89a
    registry.register(0, b"GIF89a", Arc::new(GifSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gif87a_header() {
        let sig = GifSignature;
        assert!(sig.header_check(b"GIF87a\x01\x00", 0).is_some());
    }

    #[test]
    fn test_gif89a_header() {
        let sig = GifSignature;
        assert!(sig.header_check(b"GIF89a\x01\x00", 0).is_some());
    }

    #[test]
    fn test_gif_no_match() {
        let sig = GifSignature;
        assert!(sig.header_check(b"GIF88a\x01\x00", 0).is_none());
        assert!(sig.header_check(b"NOTGIF", 0).is_none());
    }

    /// A GIF89a with a graphic-control extension and one image whose LZW
    /// sub-block holds `0x3B` bytes, as compressed image data often does.
    fn gif_with_semicolons_in_its_image_data() -> Vec<u8> {
        let mut g = b"GIF89a".to_vec();
        g.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]); // 1x1, GCT of 2 entries
        g.extend_from_slice(&[0, 0, 0, 0xFF, 0xFF, 0xFF]); // the GCT
        g.extend_from_slice(&[0x21, 0xF9, 4, 0, 0, 0, 0, 0]); // graphic control ext
        g.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0]); // image descriptor
        g.push(2); // LZW minimum code size
        g.extend_from_slice(&[5, 0x3B, 0x3B, 1, 2, 3]); // a data sub-block
        g.extend_from_slice(&[3, 0x3B, 0x44, 0x3B]);
        g.push(0); // block terminator
        g.push(0x3B); // the trailer
        g
    }

    fn fresh() -> FileRecovery {
        FileRecovery {
            extension: "gif".to_string(),
            file_size: 0,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 14,
            extra: 0,
            extra_bytes: Vec::new(),
        }
    }

    #[test]
    fn a_semicolon_inside_image_data_is_not_the_trailer() {
        let g = gif_with_semicolons_in_its_image_data();
        let mut rec = fresh();
        assert_eq!(
            GifSignature.data_check(&g, &mut rec),
            DataCheckResult::Stop(g.len() as u64)
        );
    }

    #[test]
    fn the_block_walk_carries_across_engine_blocks() {
        let g = gif_with_semicolons_in_its_image_data();
        let mut rec = fresh();
        let (a, b) = g.split_at(33);
        assert_eq!(
            GifSignature.data_check(a, &mut rec),
            DataCheckResult::Continue
        );
        rec.file_size = a.len() as u64;
        assert_eq!(
            GifSignature.data_check(b, &mut rec),
            DataCheckResult::Stop(g.len() as u64)
        );
    }

    #[test]
    fn a_block_that_is_no_gif_structure_ends_the_walk_as_an_error() {
        let mut g = gif_with_semicolons_in_its_image_data();
        g[19] = 0x99; // where the extension introducer should be
        let mut rec = fresh();
        assert_eq!(
            GifSignature.data_check(&g, &mut rec),
            DataCheckResult::Error
        );
    }

    #[test]
    fn test_gif_trailer_detection() {
        // A minimal GIF: header, descriptor, no colour table, trailer.
        let mut g = b"GIF87a".to_vec();
        g.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0x3B]);
        let mut rec = fresh();
        assert_eq!(
            GifSignature.data_check(&g, &mut rec),
            DataCheckResult::Stop(14)
        );
    }
}
