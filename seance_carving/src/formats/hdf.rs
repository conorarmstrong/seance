use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// HDF (Hierarchical Data Format 4) carving signature. Header: magic 0x0e 0x03 0x13 0x01 at offset
/// 0, followed by a non-zero
/// big-endian data-descriptor block size (uint16) at offset 4.
/// PhotoRec's file_check walks the DD-block linked list to size the file; that
/// stateful traversal is not portable to a forward data_check, so the size is
/// bounded by max_file_size instead (see note).
struct HdfSignature;

const HDF_MAGIC: &[u8] = &[0x0e, 0x03, 0x13, 0x01];

impl FileSignature for HdfSignature {
    fn name(&self) -> &str {
        "HDF4"
    }
    fn extensions(&self) -> &[&str] {
        &["hdf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 6 && &buf[0..4] == HDF_MAGIC && u16::from_be_bytes([buf[4], buf[5]]) != 0 {
            Some(RecoveryInit {
                min_filesize: 10,
                extension: "hdf".to_string(),
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
        512 * 1024 * 1024
    }
}

/// After the magic comes the first data-descriptor block (the HDF4
/// specification): the number of descriptors in it (u16 BE, at least one),
/// the offset of the next block (u32 BE), then 12-byte descriptors of tag,
/// reference number, offset and length (u16, u16, u32, u32, all BE). An
/// element's offset and length locate it in a file whose offsets are 32-bit,
/// so for every descriptor in this block that is not an empty one
/// (`DFTAG_NULL`, tag 1, whose offset and length are placeholders) they sum
/// to no more than 2^32 - 1.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 10 {
        return true;
    }
    let ndds = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if ndds == 0 {
        return false;
    }
    let be32 = |o: usize| u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]) as u64;
    (0..ndds)
        .map(|i| 10 + i * 12)
        .take_while(|&dd| dd + 12 <= buf.len())
        .filter(|&dd| u16::from_be_bytes([buf[dd], buf[dd + 1]]) != 1)
        .all(|dd| be32(dd + 4) + be32(dd + 8) <= u32::MAX as u64)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, HDF_MAGIC, Arc::new(HdfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdf_header_match() {
        let sig = HdfSignature;
        // magic + non-zero DD-block size field
        let buf = [0x0e, 0x03, 0x13, 0x01, 0x00, 0x04];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_hdf_no_match() {
        let sig = HdfSignature;
        // wrong magic
        assert!(sig
            .header_check(&[0x0e, 0x03, 0x13, 0x00, 0x00, 0x04], 0)
            .is_none());
        // zero DD-block size field
        assert!(sig
            .header_check(&[0x0e, 0x03, 0x13, 0x01, 0x00, 0x00], 0)
            .is_none());
        // too short
        assert!(sig.header_check(&[0x0e, 0x03], 0).is_none());
    }
}
