use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// XFS filesystem structure carving signature. Headers at offset 0: superblock "XFSB";
/// allocation-group / btree blocks
/// "XAGF","XAGI","ABTB","ABTC","IABT" (each followed by 0,0,0,1); inode "IN"
/// (a version 2 inode validated by di_pad zeroed; a version 3 inode, as v5
/// CRC-enabled XFS writes, validated by its CRC-32C over the whole inode).
/// No footer.
///
/// Limitation: the engine hands `header_check` one carving block (512 bytes
/// by default), so a v3 inode larger than that (`mkfs.xfs -i size=1024` or
/// `2048`) cannot have its CRC checked and is refused unless the carver runs
/// with a block size at least the inode size.
///
/// NOTE: The C superblock path derives calculated_file_size from sb_blocksize
/// via the xfs_sb struct (xfs_struct.h, not available here); that sizing and
/// the data_check_size/stopasap block logic are degraded to a header-magic
/// signature with a bounded max size.
struct XfsSignature;

const XAGF: &[u8] = &[b'X', b'A', b'G', b'F', 0, 0, 0, 1];
const XAGI: &[u8] = &[b'X', b'A', b'G', b'I', 0, 0, 0, 1];
const ABTB: &[u8] = &[b'A', b'B', b'T', b'B', 0, 0, 0, 1];
const ABTC: &[u8] = &[b'A', b'B', b'T', b'C', 0, 0, 0, 1];
const IABT: &[u8] = &[b'I', b'A', b'B', b'T', 0, 0, 0, 1];

impl FileSignature for XfsSignature {
    fn name(&self) -> &str {
        "XFS"
    }

    fn extensions(&self) -> &[&str] {
        &["xfs"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Superblock/AG-header magic, or an inode core (xfs_dinode: di_magic
        // "IN" @0). A version 2 inode is taken on di_pad[8] @22..30 all zero;
        // a version 3 inode (v5 XFS, the mkfs default) on its CRC-32C (HUNT-252).
        // v3 bytes 22..32 are not required zero: di_projid_hi sits at 22 and,
        // under NREXT64, di_big_nextents at 24..32.
        let matched = (buf.len() >= 4 && &buf[0..4] == b"XFSB")
            || (buf.len() >= 8
                && (&buf[0..8] == XAGF
                    || &buf[0..8] == XAGI
                    || &buf[0..8] == ABTB
                    || &buf[0..8] == ABTC
                    || &buf[0..8] == IABT))
            || (buf.len() >= 30
                && &buf[0..2] == b"IN"
                && buf[4] == 2
                && buf[22..30].iter().all(|&b| b == 0))
            || (buf.len() >= 512
                && &buf[0..2] == b"IN"
                && buf[4] == 3
                && buf[5] <= 4
                && v3_inode_crc_ok(buf));
        if matched {
            Some(RecoveryInit {
                min_filesize: 512,
                extension: "xfs".to_string(),
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
        8_000_000_000 // disk/filesystem image
    }
}

/// What a genuine XFS structure carries beyond its magic (the XFS on-disk
/// format):
///
/// - a superblock (`XFSB`) gives its block, sector and inode sizes both as
///   sizes (u32 BE at 4, u16 BE at 102 and 104) and as their base-2
///   logarithms (bytes 120, 121, 122), which agree, within 512 B–64 KiB,
///   512 B–32 KiB and 256 B–2 KiB; its version number's low nibble
///   (u16 BE at 100) is 1–5;
/// - an inode core (`IN`) has a version of 1–3 (byte 4), a data fork format
///   of 0–4 (byte 5), and a mode (u16 BE at 2) that is zero (free) or names
///   a file type.
///
/// The eight-byte allocation-group and btree magics are specific enough.
fn header_block_plausible(buf: &[u8]) -> bool {
    let be16 = |o: usize| u16::from_be_bytes([buf[o], buf[o + 1]]) as u32;
    let pow2_log = |size: u32, log: u8, lo: u32, hi: u32| {
        size.is_power_of_two() && (lo..=hi).contains(&size) && size.trailing_zeros() == log as u32
    };
    if buf.starts_with(b"XFSB") {
        if buf.len() < 123 {
            return true;
        }
        let blocksize = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        return pow2_log(blocksize, buf[120], 512, 65536)
            && pow2_log(be16(102), buf[121], 512, 32768)
            && pow2_log(be16(104), buf[122], 256, 2048)
            && (1..=5).contains(&(be16(100) & 0xF));
    }
    if buf.starts_with(b"IN") {
        if buf.len() < 6 {
            return true;
        }
        let mode = be16(2);
        return (1..=3).contains(&buf[4])
            && buf[5] <= 4
            && (mode == 0
                || matches!(
                    mode & 0xF000,
                    0x1000 | 0x2000 | 0x4000 | 0x6000 | 0x8000 | 0xA000 | 0xC000
                ));
    }
    true
}

/// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78), as XFS v5 uses.
const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0x82F6_3B78 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC32C_TABLE: [u32; 256] = crc32c_table();

fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    data.iter().fold(crc, |c, &b| {
        CRC32C_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8)
    })
}

#[cfg(test)]
fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(!0, data)
}

/// A version 3 inode (v5, CRC-enabled XFS): `di_crc` (u32 LE at 100..104) is
/// the CRC-32C of the whole inode with those four bytes taken as zero. The
/// inode size is not in the core, so each size mkfs.xfs allows on a v5 volume
/// (512, 1024, 2048) that fits in `buf` is tried. A CRC that cannot be checked
/// -- the inode is larger than the block handed in -- is a refusal, never a
/// structure-only match.
fn v3_inode_crc_ok(buf: &[u8]) -> bool {
    let stored = match buf.get(100..104) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => return false,
    };
    [512usize, 1024, 2048]
        .into_iter()
        .filter(|&n| n <= buf.len())
        .any(|n| {
            let c = crc32c_update(!0, &buf[..100]);
            let c = crc32c_update(c, &[0; 4]);
            !crc32c_update(c, &buf[104..n]) == stored
        })
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"XFSB", Arc::new(XfsSignature));
    registry.register(0, XAGF, Arc::new(XfsSignature));
    registry.register(0, XAGI, Arc::new(XfsSignature));
    registry.register(0, ABTB, Arc::new(XfsSignature));
    registry.register(0, ABTC, Arc::new(XfsSignature));
    registry.register(0, IABT, Arc::new(XfsSignature));
    registry.register(0, b"IN", Arc::new(XfsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xfs_header_match() {
        let sig = XfsSignature;
        // Superblock magic
        assert!(sig.header_check(b"XFSB\x00\x00\x00\x00", 0).is_some());
        // Allocation-group block magic
        assert!(sig.header_check(XAGF, 0).is_some());
        // Inode
        let mut inode = vec![0u8; 30];
        inode[0] = b'I';
        inode[1] = b'N';
        inode[4] = 2;
        assert!(sig.header_check(&inode, 0).is_some());
    }

    #[test]
    fn test_xfs_no_match() {
        let sig = XfsSignature;
        assert!(sig.header_check(b"ZZZZ\x00\x00\x00\x00", 0).is_none());
        // "IN" with di_version 1 is refused (only v2, and v3 with a valid CRC)
        let mut inode = vec![0u8; 30];
        inode[0] = b'I';
        inode[1] = b'N';
        inode[4] = 1;
        assert!(sig.header_check(&inode, 0).is_none());
    }

    const V3_ROOT: &[u8] = include_bytes!("../../tests/fixtures/carve015/xfs_inode_v3.bin");

    #[test]
    fn crc32c_known_answer() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn a_real_v3_inode_is_accepted() {
        assert!(XfsSignature.header_check(V3_ROOT, 0).is_some());
    }

    #[test]
    fn a_v3_inode_with_a_bad_crc_is_refused() {
        let mut b = V3_ROOT.to_vec();
        b[200] ^= 0x01;
        assert!(XfsSignature.header_check(&b, 0).is_none());
        let mut b = V3_ROOT.to_vec();
        b[100] ^= 0x01; // the stored CRC itself
        assert!(XfsSignature.header_check(&b, 0).is_none());
    }

    #[test]
    fn a_v3_inode_needs_its_crc_bytes() {
        // The 176-byte v3 core alone: no room to verify a 512-byte inode's CRC.
        assert!(XfsSignature.header_check(&V3_ROOT[..176], 0).is_none());
        // A zeroed v3 core that would have passed the v2 rule is refused.
        let mut b = vec![0u8; 512];
        b[0] = b'I';
        b[1] = b'N';
        b[4] = 3;
        assert!(XfsSignature.header_check(&b, 0).is_none());
    }
}
