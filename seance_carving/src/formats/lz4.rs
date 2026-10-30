//! LZ4 frame format (`.lz4`).
//!
//! # Why it is worth carving
//!
//! LZ4 is what systems reach for when decompression speed matters more than
//! ratio, which is most of the places a case touches it: kernel and initramfs
//! compression, ZFS and OverlayFS, systemd journal fields, Android OTA
//! payloads, and the session store Firefox writes.
//!
//! Firefox's `.jsonlz4` is handled separately, because Mozilla prefixes the
//! frame with its own `mozLz40` magic and the file is only LZ4 after that.
//!
//! # Extent
//!
//! A frame declares a content size only optionally, and it is the decompressed
//! length in any case, so it cannot bound a carve. The end mark is a zero word
//! that appears freely inside compressed data, so scanning for it would truncate
//! files at the first coincidence. The extent is therefore left to the engine
//! and reported unvalidated — which is what it is.

use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// LZ4 frame magic 0x184D2204, little-endian on disk.
const LZ4_FRAME_MAGIC: &[u8] = &[0x04, 0x22, 0x4D, 0x18];

/// The legacy frame magic 0x184C2102, still written by the kernel build.
const LZ4_LEGACY_MAGIC: &[u8] = &[0x02, 0x21, 0x4C, 0x18];

struct Lz4Signature;

impl FileSignature for Lz4Signature {
    fn name(&self) -> &str {
        "LZ4"
    }

    fn extensions(&self) -> &[&str] {
        &["lz4"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 6 {
            return None;
        }
        if &buf[..4] == LZ4_LEGACY_MAGIC {
            return Some(RecoveryInit {
                min_filesize: 8,
                extension: "lz4".to_string(),
                calculated_file_size: None,
            });
        }
        if &buf[..4] != LZ4_FRAME_MAGIC {
            return None;
        }

        // The Frame Descriptor's first byte carries a two-bit version that the
        // specification fixes at 01, and a reserved bit that must be zero.
        // Checking both costs nothing and removes most of what a four-byte
        // magic admits by chance across a whole image.
        let flg = buf[4];
        if flg >> 6 != 0b01 || flg & 0b0000_0010 != 0 {
            return None;
        }
        // The Block Descriptor's reserved bits — all but the block-maximum-size
        // field — are likewise defined as zero.
        if buf[5] & 0b1000_1111 != 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 8,
            extension: "lz4".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        // The end mark is a zero word, which occurs freely inside compressed
        // data. Stopping on it would truncate files at the first coincidence.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024
    }
}

/// The LZ4 frame format checks its own descriptor: the byte after it is the
/// second byte of the descriptor's XXH32 (seed 0), where the descriptor is
/// `FLG`, `BD`, the content size when `FLG` bit 3 says one is present and the
/// dictionary ID when bit 0 does. A legacy frame opens with its first block's
/// compressed length (u32 LE), which is not zero and not above the bound for
/// its fixed 8 MiB blocks.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 8 {
        return true;
    }
    if buf[..4] == *LZ4_LEGACY_MAGIC {
        let block = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        // LZ4_compressBound(8 MiB) = 8 MiB + 8 MiB / 255 + 16.
        return block != 0 && block <= 8 * 1024 * 1024 + (8 * 1024 * 1024) / 255 + 16;
    }
    let flg = buf[4];
    let descriptor_end =
        6 + if flg & 0b1000 != 0 { 8 } else { 0 } + if flg & 1 != 0 { 4 } else { 0 };
    match buf.get(descriptor_end) {
        Some(&hc) => (crate::checks::xxh32(&buf[4..descriptor_end], 0) >> 8) as u8 == hc,
        None => true,
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, LZ4_FRAME_MAGIC, Arc::new(Lz4Signature));
    registry.register(0, LZ4_LEGACY_MAGIC, Arc::new(Lz4Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_lz4_frame_is_recognised() {
        let sig = Lz4Signature;
        let mut buf = LZ4_FRAME_MAGIC.to_vec();
        buf.push(0b0110_0000); // version 01, no reserved bits
        buf.push(0b0111_0000); // block maximum size only
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(sig.header_check(&buf, 0).unwrap().extension, "lz4");
    }

    #[test]
    fn the_legacy_frame_the_kernel_build_writes_is_recognised() {
        let sig = Lz4Signature;
        let mut buf = LZ4_LEGACY_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(sig.header_check(&buf, 0).unwrap().extension, "lz4");
    }

    /// The version field and the reserved bits are what make a four-byte magic
    /// usable across a whole image.
    #[test]
    fn a_frame_with_a_wrong_version_or_a_reserved_bit_set_is_refused() {
        let sig = Lz4Signature;
        let frame = |flg: u8, bd: u8| {
            let mut b = LZ4_FRAME_MAGIC.to_vec();
            b.push(flg);
            b.push(bd);
            b.extend_from_slice(&[0u8; 16]);
            b
        };
        // Version 00, 10, 11 are all undefined.
        assert!(sig.header_check(&frame(0b0010_0000, 0), 0).is_none());
        assert!(sig.header_check(&frame(0b1010_0000, 0), 0).is_none());
        // FLG reserved bit.
        assert!(sig.header_check(&frame(0b0110_0010, 0), 0).is_none());
        // BD reserved bits.
        assert!(sig
            .header_check(&frame(0b0110_0000, 0b1000_0000), 0)
            .is_none());
        assert!(sig
            .header_check(&frame(0b0110_0000, 0b0000_0001), 0)
            .is_none());
    }

    #[test]
    fn other_bytes_are_not_an_lz4_frame() {
        let sig = Lz4Signature;
        assert!(sig
            .header_check(&[0x28, 0xB5, 0x2F, 0xFD, 0, 0], 0)
            .is_none());
        assert!(sig.header_check(&[0x04, 0x22, 0x4D], 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
    }
}
