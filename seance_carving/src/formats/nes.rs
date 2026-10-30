use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// NES (iNES / iNES 2.0 ROM image) carving signature. Header: "NES\x1a" at offset 0. Size derived
/// from the header:
/// 16 + trainer + prg_size * 0x4000 + chr_size * 0x2000, where prg_size = buf[4],
/// chr_size = buf[5] and the trainer is 512 bytes when flags 6 (buf[6]) bit 2 is
/// set. A header declaring no PRG and no CHR ROM is refused: with only the
/// four-byte magic behind it, it is not a ROM. Size-driven recovery; no footer.
struct NesSignature;

impl FileSignature for NesSignature {
    fn name(&self) -> &str {
        "NES"
    }
    fn extensions(&self) -> &[&str] {
        &["nes"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 7 && &buf[0..4] == b"NES\x1a" {
            let prg_size = buf[4] as u64;
            let chr_size = buf[5] as u64;
            if prg_size == 0 && chr_size == 0 {
                return None;
            }
            // A 512-byte trainer sits between the header and the PRG ROM.
            let trainer = if buf[6] & 0x04 != 0 { 512 } else { 0 };
            let size = 16 + trainer + prg_size * 0x4000 + chr_size * 0x2000;
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "nes".to_string(),
                calculated_file_size: Some(size),
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"NES\x1a", Arc::new(NesSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nes_header_match() {
        let sig = NesSignature;
        // prg_size=1, chr_size=1 -> 16 + 0x4000 + 0x2000 = 24592
        let init = sig
            .header_check(b"NES\x1a\x01\x01\x00", 0)
            .expect("should match");
        assert_eq!(init.calculated_file_size, Some(16 + 0x4000 + 0x2000));
    }

    /// flags 6 bit 2: a 512-byte trainer precedes the PRG ROM.
    #[test]
    fn test_nes_trainer_adds_512_bytes() {
        let init = NesSignature
            .header_check(b"NES\x1a\x01\x01\x04", 0)
            .unwrap();
        assert_eq!(init.calculated_file_size, Some(16 + 512 + 0x4000 + 0x2000));
    }

    /// No PRG and no CHR ROM is not a ROM; the buffer must also hold flags 6.
    #[test]
    fn test_nes_empty_or_short_header_is_refused() {
        assert!(NesSignature
            .header_check(b"NES\x1a\x00\x00\x00", 0)
            .is_none());
        assert!(NesSignature.header_check(b"NES\x1a\x01\x01", 0).is_none());
    }

    #[test]
    fn test_nes_no_match() {
        let sig = NesSignature;
        assert!(sig.header_check(b"NES\x00\x01\x01\x00", 0).is_none());
        assert!(sig.header_check(b"PNG\x1a\x01\x01\x00", 0).is_none());
    }
}
