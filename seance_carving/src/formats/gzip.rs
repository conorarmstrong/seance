use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// GZIP compressed file signature detector.
/// Header: 1F 8B (2 bytes at offset 0), followed by compression method (08 = deflate).
/// GZIP has no reliable total-size field in the header (ISIZE at the end is mod 2^32).
/// We scan for the next GZIP header or use max-size as cutoff.
/// For single-member GZIP files, the compressed data ends and is followed by CRC32 + ISIZE.
/// Ref: RFC 1952, reference/testdisk/src/file_gz.c
struct GzipSignature;

impl FileSignature for GzipSignature {
    fn name(&self) -> &str {
        "GZIP"
    }

    fn extensions(&self) -> &[&str] {
        &["gz", "tgz"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 10 {
            return None;
        }
        if buf[0] != 0x1F || buf[1] != 0x8B {
            return None;
        }
        // Compression method must be 8 (deflate)
        if buf[2] != 0x08 {
            return None;
        }

        // Flags byte at offset 3
        let flags = buf[3];
        // Validate flags: bits 5-7 must be zero (reserved)
        if flags & 0xE0 != 0 {
            return None;
        }

        // Extra-flags (XFL) at offset 8: real deflate gzip only emits 0
        // (default), 2 (max compression) or 4 (fastest). Other values indicate
        // a coincidental signature, not a gzip member.
        if !matches!(buf[8], 0 | 2 | 4) {
            return None;
        }
        // OS byte at offset 9: 0-13 are assigned; 255 = unknown. Anything else
        // is not a real gzip header. Together with XFL this rejects the vast
        // majority of false-positive hits (which otherwise carve to EOF,
        // producing multi-hundred-MB bogus artifacts, since gzip has no
        // scannable end marker).
        if buf[9] != 255 && buf[9] > 13 {
            return None;
        }

        // Determine extension: check for tar signature if we have enough data
        // A .tar.gz will have the tar header inside, but we can't see it from the
        // compressed header alone. Default to "gz".
        Some(RecoveryInit {
            min_filesize: 18, // Minimum: 10 header + 8 trailer (CRC32 + ISIZE)
            extension: "gz".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // GZIP compressed data has no reliable end marker we can scan for
        // without actually decompressing. Rely on max_file_size or next-header interruption.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2 * 1024 * 1024 * 1024 // 2 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x1F, 0x8B], Arc::new(GzipSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_header_match() {
        let sig = GzipSignature;
        // Minimal valid gzip header: magic(2) + method(1) + flags(1) + mtime(4) + xfl(1) + os(1)
        let buf = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().extension, "gz");
    }

    #[test]
    fn test_gzip_with_flags() {
        let sig = GzipSignature;
        // FHCRC | FNAME flags set
        let buf = [0x1F, 0x8B, 0x08, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_gzip_bad_method() {
        let sig = GzipSignature;
        // Method = 0x09 (not deflate)
        let buf = [0x1F, 0x8B, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_gzip_reserved_flags() {
        let sig = GzipSignature;
        // Reserved bit set in flags
        let buf = [0x1F, 0x8B, 0x08, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_gzip_no_match() {
        let sig = GzipSignature;
        let buf = vec![0u8; 10];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_gzip_too_short() {
        let sig = GzipSignature;
        let buf = [0x1F, 0x8B];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_gzip_bad_xfl_rejected() {
        let sig = GzipSignature;
        // Valid magic/method/flags but XFL = 0x99 (not 0/2/4): coincidental hit.
        let buf = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x03];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_gzip_bad_os_rejected() {
        let sig = GzipSignature;
        // OS = 0x40 (64) is neither 0-13 nor 255.
        let bad = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
        assert!(sig.header_check(&bad, 0).is_none());
        // OS = 255 (unknown) is accepted.
        let ok = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        assert!(sig.header_check(&ok, 0).is_some());
    }
}
