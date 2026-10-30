use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MPEG (MPEG-1/MPEG-2 program stream) video carving signature. Headers (offset 0): 00 00 01 B3
/// (sequence), 00 00 01 B5 (MPEG-4 elementary
/// video), 00 00 01 BA (pack), 00 00 01 BB (system). The per-type bit checks and
/// PhotoRec's packet-chain validator (calculate_packet_size / is_valid_packet_size over the
/// first 512 bytes) are ported for the header check. PhotoRec's data_check walks the packet
/// chain across a double buffer to size the file; that walk crosses block boundaries and is
/// degraded here to a max-size carve.
struct MpgSignature;

/// Return the size of the MPEG packet starting at `buf`, or 0 if it is not a valid
/// packet start. Requires `buf.len() >= 14`.
fn calculate_packet_size(buf: &[u8]) -> u32 {
    if buf.len() < 14 {
        return 0;
    }
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 1 {
        return 0;
    }
    match buf[3] {
        // Pack header
        0xBA => {
            if (buf[4] & 0xc4) == 0x44
                && (buf[6] & 4) == 4
                && (buf[8] & 4) == 4
                && (buf[9] & 1) == 1
                && (buf[12] & 3) == 3
            {
                return (buf[13] & 0x7) as u32 + 14;
            }
            if (buf[4] & 0xF1) == 0x21
                && (buf[6] & 1) == 1
                && (buf[8] & 1) == 1
                && (buf[9] & 0x80) == 0x80
                && (buf[11] & 1) == 1
            {
                return 12;
            }
            0
        }
        // Sequence header
        0xB3 => {
            if (buf[10] & 0x20) == 0x20 {
                if (buf[11] & 3) != 0 {
                    return 12 + 64; // quantiser matrix
                }
                return 12;
            }
            0
        }
        // Extension
        0xB5 => {
            if (buf[4] & 0xF0) == 0x10 && (buf[7] & 1) == 1 {
                return 10;
            }
            if (buf[4] & 0xF0) == 0x20 && (buf[4] & 1) == 0 && (buf[6] & 2) == 2 {
                return 9;
            }
            if (buf[4] & 0xF0) == 0x20 && (buf[4] & 1) == 1 && (buf[9] & 2) == 2 {
                return 12;
            }
            if (buf[4] & 0xF0) == 0x40 {
                if (buf[8] & 0x40) == 0 {
                    return 9;
                }
                return 11;
            }
            0
        }
        // Group of Pictures
        0xB8 => {
            if (buf[5] & 0x40) == 0x40 {
                return 8;
            }
            0
        }
        // End of sequence
        0xB9 => 4,
        // Private stream 1, MPEG audio/video streams, system header, padding, private 2
        0xBD | 0xC0..=0xEF | 0xBB | 0xBE | 0xBF => ((buf[4] as u32) << 8) + buf[5] as u32 + 6,
        _ => 0,
    }
}

/// Verify that the first (up to 512) bytes form a valid chain of MPEG packets.
fn is_valid_packet_size(buf: &[u8]) -> bool {
    let limit = buf.len().min(512);
    let mut i = 0usize;
    while i + 14 < limit {
        let ret = calculate_packet_size(&buf[i..]);
        if ret == 0 {
            return false;
        }
        i += ret as usize;
    }
    true
}

fn check_sequence(buf: &[u8]) -> bool {
    ((buf[4] as u32) << 4) + (buf[5] >> 4) as u32 > 0
        && (((buf[5] & 0x0f) as u32) << 8) + buf[6] as u32 > 0
        && (buf[7] >> 4) != 0
        && (buf[7] >> 4) != 15
        && (buf[7] & 0x0f) != 0
        && (buf[7] & 0x0f) != 15
        && (buf[8] != 0 || buf[9] != 0 || (buf[10] & 0xc0) != 0)
        && (buf[10] & 0x20) == 0x20
        && is_valid_packet_size(buf)
}

fn check_elem_video(buf: &[u8]) -> bool {
    (buf[4] & 0xf0) == 0x80
        && (((buf[4] >> 3) & 0x0f) == 1 || ((buf[4] >> 3) & 0x0f) == 2)
        && (buf[4] & 0x7) != 0
        && (buf[5] >> 4) != 0
        && (buf[5] >> 4) != 0x0f
        && is_valid_packet_size(buf)
}

fn check_pack(buf: &[u8]) -> bool {
    if !is_valid_packet_size(buf) {
        return false;
    }
    let mpeg1 = (buf[4] & 0xF1) == 0x21
        && (buf[6] & 1) == 1
        && (buf[8] & 1) == 1
        && (buf[9] & 0x80) == 0x80
        && (buf[11] & 1) == 1;
    let mpeg2 = (buf[4] & 0xc4) == 0x44
        && (buf[6] & 4) == 4
        && (buf[8] & 4) == 4
        && (buf[9] & 1) == 1
        && (buf[12] & 3) == 3;
    mpeg1 || mpeg2
}

fn check_system(buf: &[u8]) -> bool {
    (buf[6] & 0x80) == 0x80
        && (buf[8] & 0x01) == 0x01
        && buf[11] == 0xff
        && is_valid_packet_size(buf)
}

impl FileSignature for MpgSignature {
    fn name(&self) -> &str {
        "MPEG"
    }

    fn extensions(&self) -> &[&str] {
        &["mpg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 14 || buf[0] != 0 || buf[1] != 0 || buf[2] != 1 {
            return None;
        }
        let ok = match buf[3] {
            0xB3 => check_sequence(buf),
            0xB5 => check_elem_video(buf),
            0xBA => check_pack(buf),
            0xBB => check_system(buf),
            _ => false,
        };
        if ok {
            Some(RecoveryInit {
                min_filesize: 14,
                extension: "mpg".to_string(),
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
        2_000_000_000
    }
}

/// A system header (0x000001BB, ISO/IEC 13818-1 2.5.3.5) bounds its audio
/// streams (`audio_bound`, the top six bits of byte 9) at 32 and its video
/// streams (`video_bound`, the low five bits of byte 10) at 16. The other
/// start codes this signature matches are already checked field by field.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 11 || buf[3] != 0xBB {
        return true;
    }
    buf[9] >> 2 <= 32 && buf[10] & 0x1F <= 16
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x00, 0x00, 0x01, 0xB3], Arc::new(MpgSignature));
    registry.register(0, &[0x00, 0x00, 0x01, 0xB5], Arc::new(MpgSignature));
    registry.register(0, &[0x00, 0x00, 0x01, 0xBA], Arc::new(MpgSignature));
    registry.register(0, &[0x00, 0x00, 0x01, 0xBB], Arc::new(MpgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpg_pack_header_match() {
        let sig = MpgSignature;
        // MPEG-1 pack header (00 00 01 BA, 12 bytes) with SCR=0 pattern, then a chain of
        // 4-byte end-of-sequence packets so is_valid_packet_size validates the window.
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x00, 0x00, 0x01, 0xBA]);
        buf[4] = 0x21; // (buf[4]&0xF1)==0x21
        buf[6] = 0x01; // (buf[6]&1)==1
        buf[8] = 0x01; // (buf[8]&1)==1
        buf[9] = 0x80; // (buf[9]&0x80)==0x80
        buf[11] = 0x01; // (buf[11]&1)==1
        let mut p = 12;
        while p + 4 <= buf.len() {
            buf[p..p + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0xB9]);
            p += 4;
        }
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mpg_no_match() {
        let sig = MpgSignature;
        // Right start code, but no valid bit pattern for the pack body.
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&[0x00, 0x00, 0x01, 0xBA]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong start code entirely.
        assert!(sig.header_check(&[0xffu8; 32], 0).is_none());
    }
}
