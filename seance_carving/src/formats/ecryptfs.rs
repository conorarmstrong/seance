use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// eCryptfs encrypted file carving signature. Header (offset 0): magic is two zero bytes, but the
/// real match is the eCryptfs
/// marker invariant be32(marker1) ^ be32(marker2) == 0x3c81b7f5 with the header's
/// unencrypted_file_size (be64 at offset 0) giving the plaintext length. That is
/// not the length on disk: the file is a metadata header extent
/// (ECRYPTFS_DEFAULT_HEADER_EXTENT_SIZE, 8192 bytes by default) followed by the
/// ciphertext rounded up to whole extents (4096 bytes by default), so the size
/// carved is `8192 + round_up(unencrypted_file_size, 4096)`. A volume mounted
/// with a different extent size has a different length on disk; that is not
/// detected.
/// Note: PhotoRec's extension is "eCryptfs"; the worklist uses "ecryptfs".
/// PhotoRec's file_check +1MiB clamp is not implemented.
struct EcryptfsSignature;

/// The metadata header extent, in bytes, at the start of an eCryptfs file.
const HEADER_EXTENT: u64 = 8192;
/// The size of each encrypted data extent.
const DATA_EXTENT: u64 = 4096;
const ECRYPTFS_MARKER: u32 = 0x3c81b7f5;

impl FileSignature for EcryptfsSignature {
    fn name(&self) -> &str {
        "eCryptfs"
    }

    fn extensions(&self) -> &[&str] {
        &["ecryptfs"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 16 {
            return None;
        }
        let unencrypted_file_size = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        let marker1 = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let marker2 = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        if (marker1 ^ marker2) != ECRYPTFS_MARKER {
            return None;
        }
        // An empty file is valid: its extent is the header alone.
        let on_disk = unencrypted_file_size
            .checked_next_multiple_of(DATA_EXTENT)?
            .checked_add(HEADER_EXTENT)?;
        Some(RecoveryInit {
            min_filesize: on_disk,
            extension: "ecryptfs".to_string(),
            calculated_file_size: Some(on_disk),
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
    registry.register(0, &[0x00, 0x00], Arc::new(EcryptfsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(size: u64, marker1: u32, marker2: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&size.to_be_bytes());
        v.extend_from_slice(&marker1.to_be_bytes());
        v.extend_from_slice(&marker2.to_be_bytes());
        v.extend_from_slice(&[0u8; 7]); // version, reserved1, reserved2, flags
        v
    }

    #[test]
    fn test_ecryptfs_header_match() {
        let sig = EcryptfsSignature;
        // marker1 ^ marker2 == 0x3c81b7f5
        let buf = make_header(1000, 0x3c81b7f5, 0x00000000);
        let init = sig.header_check(&buf, 0).expect("should match");
        // 1000 plaintext bytes: one 4096-byte extent after the 8192-byte header.
        assert_eq!(init.calculated_file_size, Some(8192 + 4096));
        assert_eq!(init.min_filesize, 8192 + 4096);
    }

    /// The on-disk length of a realistic file: 100000 plaintext bytes round up
    /// to 25 extents of 4096, after the header extent.
    #[test]
    fn test_ecryptfs_size_is_the_on_disk_length() {
        let buf = make_header(100_000, 0x3c81b7f5, 0x00000000);
        let init = EcryptfsSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(8192 + 25 * 4096));
        // An empty file is the header extent alone.
        let empty = make_header(0, 0x3c81b7f5, 0x00000000);
        let init = EcryptfsSignature.header_check(&empty, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(8192));
        // A size that would overflow is refused, not wrapped.
        let huge = make_header(u64::MAX, 0x3c81b7f5, 0x00000000);
        assert!(EcryptfsSignature.header_check(&huge, 0).is_none());
    }

    #[test]
    fn test_ecryptfs_no_match() {
        let sig = EcryptfsSignature;
        // Wrong marker XOR.
        let buf = make_header(1000, 0x11111111, 0x22222222);
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short to hold the markers.
        assert!(sig.header_check(&buf[..15], 0).is_none());
    }
}
