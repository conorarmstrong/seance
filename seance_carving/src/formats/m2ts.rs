use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Blu-ray / MPEG transport stream carving signature. Headers: "HDMV"/"HDPR"/"SDVS" at offset 0xd7
/// (BDAV 192-byte TS
/// packets, sync byte at packet offset 4), and "TSHV" at offset 0x18b (188-byte TS
/// packets, sync byte at packet start). PhotoRec's data_check walks the 0x47 sync byte at
/// the packet stride across a double buffer; that strided walk crosses block boundaries
/// and is degraded here to a validated header-magic + strided-sync header check with a
/// max-size carve.
struct M2tsSignature;

const HDMV: &[u8] = b"HDMV";
const HDPR: &[u8] = b"HDPR";
const SDVS: &[u8] = b"SDVS";
const TSHV: &[u8] = b"TSHV";

/// Verify TS sync bytes (0x47) at the given start offset and stride, across the buffer.
fn sync_ok(buf: &[u8], start: usize, stride: usize) -> bool {
    let mut i = start;
    while i < buf.len() {
        if buf[i] != 0x47 {
            return false;
        }
        i += stride;
    }
    true
}

impl FileSignature for M2tsSignature {
    fn name(&self) -> &str {
        "M2TS"
    }

    fn extensions(&self) -> &[&str] {
        &["m2ts", "ts", "m2t", "tod"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // BDAV 192-byte packets: magic at 0xd7, TS sync at packet offset 4, stride 192.
        if buf.len() >= 0xec
            && (&buf[0xd7..0xdb] == HDMV || &buf[0xd7..0xdb] == HDPR || &buf[0xd7..0xdb] == SDVS)
        {
            if !sync_ok(buf, 4, 192) {
                return None;
            }
            // The outer guard has already limited the magic to HDMV, HDPR or SDVS.
            // The same magic again in the second packet confirms the flavour
            // (SDVS is a camcorder's `.tod`); a mismatch is a plain `.ts`.
            let extension = if buf[0xd7..0xdb] != buf[0xe8..0xec] {
                "ts"
            } else if &buf[0xd7..0xdb] == SDVS {
                "tod"
            } else {
                "m2ts"
            };
            return Some(RecoveryInit {
                min_filesize: 192,
                extension: extension.to_string(),
                calculated_file_size: None,
            });
        }
        // 188-byte packets: magic "TSHV" at 0x18b, TS sync at packet start, stride 188.
        if buf.len() >= 0x18f && &buf[0x18b..0x18f] == TSHV {
            if !sync_ok(buf, 0, 188) {
                return None;
            }
            return Some(RecoveryInit {
                min_filesize: 188,
                extension: "m2t".to_string(),
                calculated_file_size: None,
            });
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0xd7, HDMV, Arc::new(M2tsSignature));
    registry.register(0xd7, HDPR, Arc::new(M2tsSignature));
    registry.register(0xd7, SDVS, Arc::new(M2tsSignature));
    registry.register(0x18b, TSHV, Arc::new(M2tsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m2ts_header_match() {
        let sig = M2tsSignature;
        // Build a 192-stride BDAV buffer with HDMV magic and sync bytes.
        let mut buf = vec![0u8; 0x200];
        buf[0xd7..0xdb].copy_from_slice(HDMV);
        buf[0xe8..0xec].copy_from_slice(HDMV);
        let mut i = 4;
        while i < buf.len() {
            buf[i] = 0x47;
            i += 192;
        }
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "m2ts");
    }

    /// A 192-byte-stride buffer with `first` at 0xd7 and `second` at 0xe8.
    fn bdav(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x200];
        buf[0xd7..0xdb].copy_from_slice(first);
        buf[0xe8..0xec].copy_from_slice(second);
        for i in (4..buf.len()).step_by(192) {
            buf[i] = 0x47;
        }
        buf
    }

    #[test]
    fn test_m2ts_extension_by_magic() {
        let sig = M2tsSignature;
        let ext = |buf: &[u8]| sig.header_check(buf, 0).unwrap().extension;
        assert_eq!(ext(&bdav(HDMV, HDMV)), "m2ts");
        assert_eq!(ext(&bdav(HDPR, HDPR)), "m2ts");
        // A camcorder's SDVS is a .tod.
        assert_eq!(ext(&bdav(SDVS, SDVS)), "tod");
        // A second magic that does not repeat the first is a plain transport stream.
        assert_eq!(ext(&bdav(HDMV, SDVS)), "ts");
    }

    /// 188-byte packets with "TSHV" at 0x18b are `.m2t`.
    #[test]
    fn test_m2ts_188_byte_packets_are_m2t() {
        let mut buf = vec![0u8; 0x200];
        buf[0x18b..0x18f].copy_from_slice(TSHV);
        for i in (0..buf.len()).step_by(188) {
            buf[i] = 0x47;
        }
        let init = M2tsSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "m2t");
        assert_eq!(init.min_filesize, 188);
    }

    #[test]
    fn test_m2ts_no_match() {
        let sig = M2tsSignature;
        // HDMV magic present but sync bytes missing.
        let mut buf = vec![0u8; 0x200];
        buf[0xd7..0xdb].copy_from_slice(HDMV);
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"not a transport stream", 0).is_none());
    }
}
