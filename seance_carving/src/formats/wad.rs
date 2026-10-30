use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WAD (Doom) carving signature. Ported from file_wad.c.
/// Header: "PWAD" or "IWAD" at offset 0. numlumps (u32 LE @4) must be nonzero and
/// infotableofs (u32 LE @8) must be >= header size (12). min_filesize = infotableofs.
struct WadSignature;

impl FileSignature for WadSignature {
    fn name(&self) -> &str {
        "WAD"
    }
    fn extensions(&self) -> &[&str] {
        &["wad"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 {
            return None;
        }
        if &buf[0..4] != b"PWAD" && &buf[0..4] != b"IWAD" {
            return None;
        }
        let numlumps = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if numlumps == 0 {
            return None;
        }
        let infotableofs = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
        if infotableofs < 12 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: infotableofs,
            extension: "wad".to_string(),
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
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        // PhotoRec: PHOTOREC_MAX_SIZE_32 == 2^31 - 1.
        (1u64 << 31) - 1
    }
}

/// A WAD's lump directory (at `infotableofs`) is `numlumps` 16-byte entries
/// (position, size, an 8-byte name). Both must fit in the largest WAD this
/// signature carves, and when the first entry lies in this block its name is
/// printable ASCII padded with NUL bytes.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return true;
    }
    let numlumps = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
    let dir = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
    if dir + numlumps * 16 > (1u64 << 31) - 1 {
        return false;
    }
    let dir = dir as usize;
    let Some(name) = buf.get(dir + 8..dir + 16) else {
        return true;
    };
    let len = name.iter().position(|&b| b == 0).unwrap_or(8);
    len > 0
        && name[..len].iter().all(|&b| (0x21..0x7F).contains(&b))
        && name[len..].iter().all(|&b| b == 0)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"PWAD", Arc::new(WadSignature));
    registry.register(0, b"IWAD", Arc::new(WadSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wad_header_match() {
        let sig = WadSignature;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PWAD");
        buf.extend_from_slice(&1u32.to_le_bytes()); // numlumps
        buf.extend_from_slice(&12u32.to_le_bytes()); // infotableofs
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 12);

        let mut iwad = buf.clone();
        iwad[0..4].copy_from_slice(b"IWAD");
        assert!(sig.header_check(&iwad, 0).is_some());
    }

    #[test]
    fn test_wad_no_match() {
        let sig = WadSignature;
        // Wrong magic.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"XWAD");
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&12u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // Zero numlumps.
        let mut z = buf.clone();
        z[0..4].copy_from_slice(b"PWAD");
        z[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(sig.header_check(&z, 0).is_none());
    }
}
