use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Cryptocurrency wallet carving signature. Header: three magic variants at offset 0 -- Armory
/// (0xBA "WALLET" 0x00),
/// MultiBit Bitcoin (0x0A 0x16 "org.bitcoin.production"), and MultiBit Dogecoin
/// (0x0A 0x17 "org.dogecoin.production"). No footer; size not encoded.
struct WalletSignature;

const WALLET_ARMORY: &[u8] = b"\xbaWALLET\x00";
const WALLET_BITCOIN: &[u8] = b"\x0a\x16org.bitcoin.production";
const WALLET_DOGECOIN: &[u8] = b"\x0a\x17org.dogecoin.production";

impl FileSignature for WalletSignature {
    fn name(&self) -> &str {
        "WALLET"
    }
    fn extensions(&self) -> &[&str] {
        &["wallet"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let matches = (buf.len() >= WALLET_ARMORY.len()
            && &buf[0..WALLET_ARMORY.len()] == WALLET_ARMORY)
            || (buf.len() >= WALLET_BITCOIN.len()
                && &buf[0..WALLET_BITCOIN.len()] == WALLET_BITCOIN)
            || (buf.len() >= WALLET_DOGECOIN.len()
                && &buf[0..WALLET_DOGECOIN.len()] == WALLET_DOGECOIN);
        if matches {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "wallet".to_string(),
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
        10 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, WALLET_ARMORY, Arc::new(WalletSignature));
    registry.register(0, WALLET_BITCOIN, Arc::new(WalletSignature));
    registry.register(0, WALLET_DOGECOIN, Arc::new(WalletSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_header_match() {
        assert!(WalletSignature.header_check(WALLET_ARMORY, 0).is_some());
        assert!(WalletSignature.header_check(WALLET_BITCOIN, 0).is_some());
        assert!(WalletSignature.header_check(WALLET_DOGECOIN, 0).is_some());
    }

    #[test]
    fn test_wallet_no_match() {
        assert!(WalletSignature.header_check(b"NOTAWALLET", 0).is_none());
        assert!(WalletSignature.header_check(b"\xba", 0).is_none());
    }
}
