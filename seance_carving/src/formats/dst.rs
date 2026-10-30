use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Tajima embroidery (DST) carving signature. Header: "LA:" at offset 0, "\rST:" at offset 0x13,
/// "\rCO:" at offset 30. The
/// stitch count is parsed from the 7 ASCII bytes at offset 23; the exact file
/// size is 512-byte header + 3 bytes per stitch. No footer (size is calculated).
struct DstSignature;

impl FileSignature for DstSignature {
    fn name(&self) -> &str {
        "DST"
    }
    fn extensions(&self) -> &[&str] {
        &["dst"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 512 {
            return None;
        }
        // "LA:" prefix, "\rST:" at 0x13 (the registered magic), "\rCO:" at 30.
        if &buf[0..3] != b"LA:"
            || buf[0x13] != 0x0d
            || &buf[0x14..0x17] != b"ST:"
            || buf[30] != 0x0d
            || &buf[31..34] != b"CO:"
        {
            return None;
        }
        // Parse the stitch count from the ASCII field at [23..30] (sscanf %u:
        // skip leading whitespace, then read decimal digits).
        let field = &buf[23..30];
        let mut i = 0;
        while i < field.len() && (field[i] == b' ' || field[i] == b'\t') {
            i += 1;
        }
        let mut stitch_count: u64 = 0;
        while i < field.len() && field[i].is_ascii_digit() {
            stitch_count = stitch_count
                .saturating_mul(10)
                .saturating_add((field[i] - b'0') as u64);
            i += 1;
        }
        // No readable count (a blank or damaged field) is not a header-sized
        // 512-byte file: the extent is unknown and the header is not trusted.
        if stitch_count == 0 {
            return None;
        }
        let calculated = 512 + 3 * stitch_count;
        Some(RecoveryInit {
            min_filesize: 512,
            extension: "dst".to_string(),
            calculated_file_size: Some(calculated),
        })
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
    registry.register(0x13, b"\rST:", Arc::new(DstSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(stitch_field: &[u8; 7]) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..3].copy_from_slice(b"LA:");
        buf[0x13] = 0x0d;
        buf[0x14..0x17].copy_from_slice(b"ST:");
        buf[23..30].copy_from_slice(stitch_field);
        buf[30] = 0x0d;
        buf[31..34].copy_from_slice(b"CO:");
        buf
    }

    #[test]
    fn test_dst_header_match() {
        let buf = build_header(b"  10000");
        let init = DstSignature.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(512 + 3 * 10000));
    }

    /// A count field with no digits (damaged or foreign header) must not be
    /// carved as a 512-byte file.
    #[test]
    fn test_dst_blank_or_zero_stitch_count_is_refused() {
        assert!(DstSignature
            .header_check(&build_header(b"       "), 0)
            .is_none());
        assert!(DstSignature
            .header_check(&build_header(b"???????"), 0)
            .is_none());
        assert!(DstSignature
            .header_check(&build_header(b"      0"), 0)
            .is_none());
    }

    #[test]
    fn test_dst_no_match() {
        // Wrong "CO:" marker at offset 30.
        let mut buf = build_header(b"  10000");
        buf[31] = b'X';
        assert!(DstSignature.header_check(&buf, 0).is_none());
        // Too short.
        assert!(DstSignature.header_check(b"LA:", 0).is_none());
    }
}
