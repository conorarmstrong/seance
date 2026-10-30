use super::mp4::{plausible_box_type, walk_box_chain};
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// QuickTime atom types valid at the start of a .mov file. `ftyp` is handled by
/// the MP4 signature; here we cover the common non-ftyp layouts (moov-first and
/// pnot preview). `mdat`/`free`/`wide` are deliberately NOT registered as
/// headers — they appear mid-file constantly and would produce false positives.
const MOV_START_ATOMS: [[u8; 4]; 2] = [*b"moov", *b"pnot"];

/// QuickTime (.mov) detector for files that do not start with an `ftyp` box.
struct MovSignature;

impl FileSignature for MovSignature {
    fn name(&self) -> &str {
        "MOV"
    }

    fn extensions(&self) -> &[&str] {
        &["mov"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        if !MOV_START_ATOMS.iter().any(|a| a[..] == buf[4..8]) {
            return None;
        }
        let size0 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        // The leading atom (moov metadata / pnot preview) is bounded; reject
        // absurd sizes, which are almost always spurious mid-stream matches.
        if !(8..=64 * 1024 * 1024).contains(&size0) {
            return None;
        }
        // If the second atom is visible, require it to be a top-level atom the
        // MP4 box walk knows (the same list) — a strong filter against random
        // 4-byte collisions.
        if size0 as usize + 8 <= buf.len()
            && !plausible_box_type(&buf[size0 as usize + 4..size0 as usize + 8])
        {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: size0,
            extension: "mov".to_string(),
            // Total size is the sum of all top-level atoms, not knowable from the
            // header block; `data_check` walks the atom chain to its end.
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
        // The file is a chain of length-prefixed atoms, the same boxes the MP4
        // signature walks: it ends where the chain does, not at the next header.
        walk_box_chain(buf, recovery)
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024
    }
}

/// What the leading atom holds (Apple's QuickTime File Format):
///
/// - a `moov` atom opens with one of its own children, the movie header
///   `mvhd` in practice, or a compressed movie `cmov`;
/// - a `pnot` preview atom is exactly 20 bytes, and its version (u16 at 12)
///   is 0.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 16 {
        return true;
    }
    let size0 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    match &buf[4..8] {
        b"moov" => {
            const MOOV_CHILDREN: [&[u8; 4]; 14] = [
                b"mvhd", b"cmov", b"trak", b"udta", b"iods", b"meta", b"prfl", b"clip", b"ctab",
                b"rmra", b"uuid", b"free", b"skip", b"wide",
            ];
            size0 >= 16 && MOOV_CHILDREN.iter().any(|c| buf[12..16] == c[..])
        }
        b"pnot" => size0 == 20 && buf[12] == 0 && buf[13] == 0,
        _ => true,
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    // Register each start-atom pattern at offset 4 (after the 4-byte size).
    for atom in &MOV_START_ATOMS {
        registry.register(4, atom, Arc::new(MovSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(size: u32, ty: &[u8; 4]) -> Vec<u8> {
        let mut v = size.to_be_bytes().to_vec();
        v.extend_from_slice(ty);
        v
    }

    #[test]
    fn detects_moov_first_with_valid_chain() {
        let mut buf = atom(16, b"moov");
        buf.resize(16, 0);
        buf.extend_from_slice(&atom(8, b"mdat")); // next atom valid
        let init = MovSignature.header_check(&buf, 0).expect("mov");
        assert_eq!(init.extension, "mov");
    }

    #[test]
    fn rejects_moov_with_invalid_next_atom() {
        let mut buf = atom(16, b"moov");
        buf.resize(16, 0);
        buf.extend_from_slice(&atom(8, b"XXXX")); // bogus next atom
        assert!(MovSignature.header_check(&buf, 0).is_none());
    }

    /// A moov-first file ends where its atom chain does: the carve stops there
    /// and does not run on into whatever follows.
    #[test]
    fn a_moov_first_file_stops_at_the_end_of_its_atom_chain() {
        let sig = MovSignature;
        let mut file = atom(32, b"moov");
        file.extend_from_slice(&atom(24, b"mvhd")); // the movie header child
        file.resize(32, 0);
        let mut mdat = atom(300, b"mdat");
        mdat.resize(300, 0x11);
        file.extend_from_slice(&mdat);
        file.extend_from_slice(&atom(8, b"free"));
        let end = file.len() as u64;
        file.extend_from_slice(&[0x55; 2000]); // unrelated data after the chain
        for block in [64usize, 100, 512] {
            let init = sig.header_check(&file, 0).expect("moov-first header");
            let mut recovery = FileRecovery::from_init(&init, 0);
            let mut result = DataCheckResult::Continue;
            for (i, chunk) in file.chunks(block).enumerate() {
                recovery.file_size = (i * block) as u64;
                result = sig.data_check(chunk, &mut recovery);
                if result != DataCheckResult::Continue {
                    break;
                }
            }
            assert_eq!(result, DataCheckResult::Stop(end), "block {block}");
        }
    }

    #[test]
    fn rejects_non_start_atom() {
        assert!(MovSignature.header_check(&atom(16, b"mdat"), 0).is_none());
    }

    #[test]
    fn rejects_absurd_size() {
        assert!(MovSignature
            .header_check(&atom(0xFFFFFFFF, b"moov"), 0)
            .is_none());
    }
}
