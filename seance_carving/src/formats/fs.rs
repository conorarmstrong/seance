use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Zope FileStorage (.fs) carving signature. Header at offset 0: "FS21", followed by a ZODB
/// transaction_header at offset 4.
/// The transaction length (be64 at offset 12) must be >= 15 and the status byte at
/// offset 20 must be one of ' ', 'p', 'c', 'u'.
struct FsSignature;

const FS_MAGIC: &[u8] = b"FS21";

impl FileSignature for FsSignature {
    fn name(&self) -> &str {
        "FS"
    }
    fn extensions(&self) -> &[&str] {
        &["fs"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 21 && &buf[0..4] == FS_MAGIC {
            // transaction_header sits at buffer[4]; its len field (be64) is at offset 8
            // within the struct => absolute offset 12.
            let len = u64::from_be_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]);
            // sizeof(struct transaction_header) - 8 == 15
            if len < 15 {
                return None;
            }
            let status = buf[20];
            if status != b' ' && status != b'p' && status != b'c' && status != b'u' {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "fs".to_string(),
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
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        200 * 1024 * 1024
    }
}

/// A ZODB FileStorage transaction header (at offset 4) is the transaction id
/// (8 bytes), its length (u64 BE), a status byte, and the user, description
/// and extension lengths (u16 BE each): 23 bytes. The length covers the
/// header and those three strings, so it is at least their sum, and it is a
/// length a file can have (below 2^40).
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 27 {
        return true;
    }
    let tlen = u64::from_be_bytes([
        buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
    ]);
    let be16 = |o: usize| u16::from_be_bytes([buf[o], buf[o + 1]]) as u64;
    tlen >= 23 + be16(21) + be16(23) + be16(25) && tlen < 1 << 40
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FS_MAGIC, Arc::new(FsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(len: u64, status: u8) -> Vec<u8> {
        let mut buf = FS_MAGIC.to_vec(); // offsets 0..4
        buf.extend_from_slice(&[0u8; 8]); // id field, offsets 4..12
        buf.extend_from_slice(&len.to_be_bytes()); // len field, offsets 12..20
        buf.push(status); // status, offset 20
        buf
    }

    #[test]
    fn test_fs_header_match() {
        let sig = FsSignature;
        assert!(sig.header_check(&make_buf(20, b' '), 0).is_some());
        assert!(sig.header_check(&make_buf(15, b'p'), 0).is_some());
    }

    #[test]
    fn test_fs_no_match() {
        let sig = FsSignature;
        // wrong magic
        assert!(sig
            .header_check(
                b"XX21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20",
                0
            )
            .is_none());
        // len too small
        assert!(sig.header_check(&make_buf(10, b' '), 0).is_none());
        // invalid status
        assert!(sig.header_check(&make_buf(20, b'x'), 0).is_none());
    }
}
