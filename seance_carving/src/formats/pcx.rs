use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PCX bitmap image carving signature. Header: manufacturer byte 0x0a at offset 0. The single magic
/// byte is weak, so
/// the full 128-byte PCX header is validated (version, encoding, bit depth,
/// frame extents, reserved/filler zeros) exactly as header_check_pcx does.
/// No footer.
struct PcxSignature;

const PCX_MAGIC: &[u8] = &[0x0a];

impl FileSignature for PcxSignature {
    fn name(&self) -> &str {
        "PCX"
    }

    fn extensions(&self) -> &[&str] {
        &["pcx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct pcx_file_entry is 128 bytes; need the whole header to validate.
        if buf.len() < 128 {
            return None;
        }
        let x_min = u16::from_le_bytes([buf[4], buf[5]]);
        let y_min = u16::from_le_bytes([buf[6], buf[7]]);
        let x_max = u16::from_le_bytes([buf[8], buf[9]]);
        let y_max = u16::from_le_bytes([buf[10], buf[11]]);
        let bytes_per_line = u16::from_le_bytes([buf[64], buf[65]]);
        let bits_per_pixel = buf[3];
        let ok = buf[0] == 0x0a
            && (buf[1] <= 5 && buf[1] != 1)
            && buf[2] <= 1
            && (bits_per_pixel == 1
                || bits_per_pixel == 4
                || bits_per_pixel == 8
                || bits_per_pixel == 24)
            && buf[62] == 0 // Reserved
            && x_min <= x_max
            && y_min <= y_max
            && bytes_per_line > 0
            && bytes_per_line.is_multiple_of(2)
            && buf[72] == 0 // Filler[0]
            && buf[73] == 0 // Filler[1]
            && buf[126] == 0 // Filler[54]
            && buf[127] == 0; // Filler[55]
        if ok {
            Some(RecoveryInit {
                min_filesize: 128,
                extension: "pcx".to_string(),
                calculated_file_size: None,
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PCX_MAGIC, Arc::new(PcxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid 128-byte PCX header.
    fn valid_pcx() -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        buf[0] = 0x0a; // Manufacturer
        buf[1] = 5; // Version 3.0
        buf[2] = 1; // Encoding RLE
        buf[3] = 8; // BitsPerPixel
                    // XMin=0 <= XMax=100
        buf[8] = 100;
        // YMin=0 <= YMax=50
        buf[10] = 50;
        buf[64] = 100; // BytesPerLine, even and > 0
        buf
    }

    #[test]
    fn test_pcx_header_match() {
        let sig = PcxSignature;
        assert!(sig.header_check(&valid_pcx(), 0).is_some());
    }

    #[test]
    fn test_pcx_no_match() {
        let sig = PcxSignature;
        // Wrong manufacturer byte.
        let mut bad = valid_pcx();
        bad[0] = 0x00;
        assert!(sig.header_check(&bad, 0).is_none());
        // Too short to validate the full header.
        assert!(sig.header_check(&[0x0a], 0).is_none());
    }
}
