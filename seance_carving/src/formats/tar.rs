use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TAR archive file signature detector.
///
/// TAR headers contain the "ustar" magic at offset 257 within the 512-byte header block.
/// Two variants exist:
/// - POSIX (ustar\0): bytes `75 73 74 61 72 00` with version "00" at offset 263
/// - GNU (ustar ): bytes `75 73 74 61 72 20` with space+null at offset 263
///
/// The carving engine passes `header_check` the buffer from the file/block start
/// (not from the match offset), so the "ustar" magic sits at `buf[257..262]` and
/// the variant byte at `buf[262]` — the same absolute offsets used to register
/// the signature.
///
/// TAR has no single total-size field in the header. Recovery uses max-size cutoff.
/// Ref: IEEE Std 1003.1 (POSIX), GNU tar documentation
struct TarSignature;

/// Byte offset of the "ustar" magic within a 512-byte tar header block.
const TAR_MAGIC_OFF: usize = 257;

impl FileSignature for TarSignature {
    fn name(&self) -> &str {
        "TAR"
    }

    fn extensions(&self) -> &[&str] {
        &["tar"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // The engine hands us the buffer from the file/block start, so every
        // field is at its absolute tar-header offset. Need the magic (5) +
        // variant byte (1) + at least one version byte past offset 257.
        if buf.len() < TAR_MAGIC_OFF + 7 {
            return None;
        }

        // Verify "ustar" magic at offset 257 of the tar header.
        if &buf[TAR_MAGIC_OFF..TAR_MAGIC_OFF + 5] != b"ustar" {
            return None;
        }

        // Validate variant byte at offset 262.
        // POSIX: 0x00 (null), GNU: 0x20 (space)
        let variant_byte = buf[TAR_MAGIC_OFF + 5];
        if variant_byte != 0x00 && variant_byte != 0x20 {
            return None;
        }

        // Validate version field at offset 263-264.
        // POSIX: "00", GNU: " \0" (space + null) or "0\0"
        // Be permissive: just check bytes are printable ASCII or null
        if buf.len() >= TAR_MAGIC_OFF + 8 {
            let v0 = buf[TAR_MAGIC_OFF + 6];
            let v1 = buf[TAR_MAGIC_OFF + 7];
            if !is_tar_version_byte(v0) || !is_tar_version_byte(v1) {
                return None;
            }
        }

        // Additional validation: check owner name field at offset 265 (32 bytes).
        // Should be printable ASCII or null.
        if buf.len() >= TAR_MAGIC_OFF + 40 {
            for &b in &buf[TAR_MAGIC_OFF + 8..TAR_MAGIC_OFF + 40] {
                if b != 0 && !(0x20..=0x7E).contains(&b) {
                    return None;
                }
            }
        }

        // No calculated file size; TAR archives are composed of variable-length
        // entries and must be recovered using max-size cutoff.
        Some(RecoveryInit {
            min_filesize: 512, // Minimum: one 512-byte header block
            extension: "tar".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // TAR has no reliable end-of-archive marker that can be detected without
        // parsing every entry. Rely on max_file_size or next-header interruption.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        10 * 1024 * 1024 * 1024 // 10 GB
    }
}

/// Check whether a byte is valid in the TAR version field.
/// Allows ASCII digits, space, and null.
fn is_tar_version_byte(b: u8) -> bool {
    b == 0x00 || b == 0x20 || b.is_ascii_digit()
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(257, &[0x75, 0x73, 0x74, 0x61, 0x72], Arc::new(TarSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a full 512-byte tar header block as the engine hands it to
    /// header_check: fields sit at their absolute offsets, so "ustar" is at 257.
    /// Layout from 257: [magic(5)] [variant(1)] [version(2)] [owner_name(32)] ...
    fn make_header_buf(variant: u8, version: [u8; 2]) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[TAR_MAGIC_OFF..TAR_MAGIC_OFF + 5].copy_from_slice(b"ustar");
        buf[TAR_MAGIC_OFF + 5] = variant;
        buf[TAR_MAGIC_OFF + 6] = version[0];
        buf[TAR_MAGIC_OFF + 7] = version[1];
        // owner name field (offset 265): printable ASCII, null-padded
        buf[TAR_MAGIC_OFF + 8..TAR_MAGIC_OFF + 12].copy_from_slice(b"root");
        buf
    }

    #[test]
    fn test_tar_posix_ustar_match() {
        let sig = TarSignature;
        // POSIX: variant = 0x00 (null), version = "00"
        let buf = make_header_buf(0x00, *b"00");
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "tar");
        assert_eq!(init.min_filesize, 512);
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_tar_gnu_match() {
        let sig = TarSignature;
        // GNU: variant = 0x20 (space), version = " \0"
        let buf = make_header_buf(0x20, [0x20, 0x00]);
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "tar");
    }

    #[test]
    fn test_tar_no_match_bad_magic() {
        let sig = TarSignature;
        // Wrong magic bytes
        let mut buf = make_header_buf(0x00, *b"00");
        buf[TAR_MAGIC_OFF] = b'x'; // corrupt first magic byte
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tar_no_match_bad_variant() {
        let sig = TarSignature;
        // Invalid variant byte (not 0x00 or 0x20)
        let buf = make_header_buf(0xFF, *b"00");
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tar_no_match_bad_version() {
        let sig = TarSignature;
        // Invalid version byte (non-ASCII control character)
        let buf = make_header_buf(0x00, [0x80, 0x00]);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tar_no_match_bad_owner() {
        let sig = TarSignature;
        // Invalid owner name field (contains non-printable byte)
        let mut buf = make_header_buf(0x00, *b"00");
        buf[TAR_MAGIC_OFF + 10] = 0x01; // non-printable byte in owner name area
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tar_short_buffer() {
        let sig = TarSignature;
        // Buffer too short to even reach the magic offset.
        let buf = b"ustar";
        assert!(sig.header_check(buf, 0).is_none());

        // A full block whose magic offset is just out of reach.
        let buf = [0u8; TAR_MAGIC_OFF + 6];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tar_minimal_valid_buffer() {
        let sig = TarSignature;
        // Smallest buffer that reaches magic + variant + one version byte
        // (offset 257 + 7). The version and owner checks only trigger with more
        // bytes, so this minimal block still matches.
        let mut buf = [0u8; TAR_MAGIC_OFF + 7];
        buf[TAR_MAGIC_OFF..TAR_MAGIC_OFF + 5].copy_from_slice(b"ustar");
        buf[TAR_MAGIC_OFF + 5] = 0x00; // variant (null)
        buf[TAR_MAGIC_OFF + 6] = b'0'; // one version byte
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tar_max_file_size() {
        let sig = TarSignature;
        assert_eq!(sig.max_file_size(), 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_tar_data_check_continues() {
        let sig = TarSignature;
        let mut recovery = FileRecovery {
            extension: "tar".to_string(),
            file_size: 0,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 512,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let buf = vec![0u8; 512];
        assert_eq!(
            sig.data_check(&buf, &mut recovery),
            DataCheckResult::Continue
        );
    }

    #[test]
    fn test_register() {
        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        assert!(!registry.is_empty());
    }

    /// End-to-end regression: the engine matches "ustar" at offset 257 in the
    /// scan block and hands header_check the buffer from the block start. Before
    /// the offset fix, header_check read buf[0..5] and TAR never carved at all.
    #[test]
    fn test_tar_carved_by_engine_from_block_start() {
        use crate::engine::{CarvingDataSource, CarvingEngine};
        use std::io;

        struct Mem(Vec<u8>);
        impl CarvingDataSource for Mem {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
                let off = offset as usize;
                if off >= self.0.len() {
                    return Ok(0);
                }
                let n = buf.len().min(self.0.len() - off);
                buf[..n].copy_from_slice(&self.0[off..off + n]);
                Ok(n)
            }
            fn size(&self) -> u64 {
                self.0.len() as u64
            }
        }

        // A 512-byte tar header block (magic at 257) plus padding.
        let mut data = make_header_buf(0x00, *b"00");
        data.resize(2048, 0);

        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        // Default 512-byte block: the magic at 257 is within the first block.
        let engine = CarvingEngine::new(Arc::new(registry));
        let files = engine.scan(&Mem(data.clone()), data.len() as u64);
        assert!(
            files
                .iter()
                .any(|f| f.signature_name == "TAR" && f.offset == 0),
            "engine must carve a TAR starting at offset 0"
        );
    }
}
