//! LZVN block decoder, used by APFS transparent (decmpfs) compression.
//!
//! The opcode set is Apple's, taken from the LZVN reference decoder
//! (`lzvn_decode_base.c` in the LZFSE distribution). Only decoding is
//! implemented: Séance never writes evidence.
//!
//! Every failure returns `Err` and no bytes. A short, corrupt or
//! undefined-opcode stream must never yield the prefix it managed to expand:
//! those bytes would be exported and hashed as though they were the file, and
//! "part of the file" is indistinguishable from "the file" once it reaches a
//! report.

/// End-of-stream opcode. Also used by decmpfs as the leading marker on a
/// resource-fork chunk that was stored uncompressed, which is unambiguous
/// because a real LZVN block can never *begin* with end-of-stream.
pub(crate) const EOS_OPCODE: u8 = 0x06;

/// Extract `width` bits of `x` starting at bit `lsb`.
#[inline]
fn extract(x: u32, lsb: u32, width: u32) -> u32 {
    (x >> lsb) & ((1u32 << width) - 1)
}

/// The opcode classes of the LZVN instruction set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opcode {
    /// `LLMMMDDD DDDDDDDD LITERAL` — literal plus match, 11-bit distance.
    SmallDistance,
    /// `101LLMMM DDDDDDMM DDDDDDDD LITERAL` — literal plus match, 14-bit distance.
    MediumDistance,
    /// `LLMMM111 DDDDDDDD DDDDDDDD LITERAL` — literal plus match, 16-bit distance.
    LargeDistance,
    /// `LLMMM110` — literal plus match, reusing the previous distance.
    PreviousDistance,
    /// `1111MMMM` — match only, previous distance.
    SmallMatch,
    /// `11110000 MMMMMMMM` — match only, previous distance, length biased by 16.
    LargeMatch,
    /// `1110LLLL LITERAL` — literal only.
    SmallLiteral,
    /// `11100000 LLLLLLLL LITERAL` — literal only, length biased by 16.
    LargeLiteral,
    /// No operation.
    Nop,
    /// End of stream.
    EndOfStream,
    /// Not a defined instruction.
    Undefined,
}

/// Map an opcode byte to its class.
///
/// This reproduces the 256-entry dispatch table in Apple's decoder exactly; the
/// arms are ordered so the explicitly-listed opcodes win over the low-three-bit
/// rule that covers the rest.
fn classify(opc: u8) -> Opcode {
    match opc {
        0x06 => Opcode::EndOfStream,
        0x0E | 0x16 => Opcode::Nop,
        0x1E | 0x26 | 0x2E | 0x36 | 0x3E => Opcode::Undefined,
        0x70..=0x7F | 0xD0..=0xDF => Opcode::Undefined,
        0xA0..=0xBF => Opcode::MediumDistance,
        0xE0 => Opcode::LargeLiteral,
        0xE1..=0xEF => Opcode::SmallLiteral,
        0xF0 => Opcode::LargeMatch,
        0xF1..=0xFF => Opcode::SmallMatch,
        _ => match opc & 0x07 {
            7 => Opcode::LargeDistance,
            6 => Opcode::PreviousDistance,
            _ => Opcode::SmallDistance,
        },
    }
}

/// Decode one LZVN block, which must expand to exactly `expected_len` bytes.
///
/// `expected_len` is not a hint: decmpfs stores fixed 64 KiB chunks (the last
/// one short), so the caller always knows the exact size. Enforcing it turns a
/// mis-framed chunk table or a corrupt block into an error instead of content
/// that is quietly the wrong length.
pub(crate) fn decode(src: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    let truncated =
        |pos: usize| format!("LZVN stream is truncated at offset {pos} of {}", src.len());
    let overflow = |pos: usize| {
        format!("LZVN block at offset {pos} expands past its declared {expected_len} bytes")
    };

    let mut dst: Vec<u8> = Vec::with_capacity(expected_len);
    let mut pos = 0usize;
    let mut distance = 0usize;

    loop {
        // Every arm below leaves at least one unread byte, so this cannot
        // underflow and `remaining` is always >= 1 here.
        let remaining = src.len() - pos;
        if remaining == 0 {
            return Err(format!(
                "LZVN stream ended after {} byte(s) without an end-of-stream opcode",
                src.len()
            ));
        }
        let opc = src[pos];
        let word = opc as u32;

        // (literal length, match length, opcode length, distance if this
        // opcode carries one).
        let (literal_len, match_len, opc_len, new_distance): (usize, usize, usize, Option<usize>) =
            match classify(opc) {
                Opcode::SmallDistance => {
                    let opc_len = 2usize;
                    let l = extract(word, 6, 2) as usize;
                    let m = extract(word, 3, 3) as usize + 3;
                    if remaining <= opc_len + l {
                        return Err(truncated(pos));
                    }
                    let d = ((extract(word, 0, 3) as usize) << 8) | src[pos + 1] as usize;
                    (l, m, opc_len, Some(d))
                }
                Opcode::MediumDistance => {
                    let opc_len = 3usize;
                    let l = extract(word, 3, 2) as usize;
                    if remaining <= opc_len + l {
                        return Err(truncated(pos));
                    }
                    let tail = u16::from_le_bytes([src[pos + 1], src[pos + 2]]) as u32;
                    let m = (((extract(word, 0, 3) << 2) | extract(tail, 0, 2)) as usize) + 3;
                    let d = extract(tail, 2, 14) as usize;
                    (l, m, opc_len, Some(d))
                }
                Opcode::LargeDistance => {
                    let opc_len = 3usize;
                    let l = extract(word, 6, 2) as usize;
                    let m = extract(word, 3, 3) as usize + 3;
                    if remaining <= opc_len + l {
                        return Err(truncated(pos));
                    }
                    let d = u16::from_le_bytes([src[pos + 1], src[pos + 2]]) as usize;
                    (l, m, opc_len, Some(d))
                }
                Opcode::PreviousDistance => {
                    let opc_len = 1usize;
                    let l = extract(word, 6, 2) as usize;
                    let m = extract(word, 3, 3) as usize + 3;
                    if remaining <= opc_len + l {
                        return Err(truncated(pos));
                    }
                    (l, m, opc_len, None)
                }
                Opcode::SmallLiteral => {
                    let opc_len = 1usize;
                    let l = extract(word, 0, 4) as usize;
                    if remaining <= opc_len + l {
                        return Err(truncated(pos));
                    }
                    (l, 0, opc_len, None)
                }
                Opcode::LargeLiteral => {
                    let opc_len = 2usize;
                    if remaining <= opc_len {
                        return Err(truncated(pos));
                    }
                    let l = src[pos + 1] as usize + 16;
                    if remaining <= opc_len + l {
                        return Err(truncated(pos));
                    }
                    (l, 0, opc_len, None)
                }
                Opcode::SmallMatch => {
                    let opc_len = 1usize;
                    if remaining <= opc_len {
                        return Err(truncated(pos));
                    }
                    (0, extract(word, 0, 4) as usize, opc_len, None)
                }
                Opcode::LargeMatch => {
                    let opc_len = 2usize;
                    if remaining <= opc_len {
                        return Err(truncated(pos));
                    }
                    (0, src[pos + 1] as usize + 16, opc_len, None)
                }
                Opcode::Nop => {
                    if remaining <= 1 {
                        return Err(truncated(pos));
                    }
                    pos += 1;
                    continue;
                }
                Opcode::EndOfStream => {
                    if remaining < 8 {
                        return Err(truncated(pos));
                    }
                    break;
                }
                Opcode::Undefined => {
                    return Err(format!(
                        "LZVN undefined opcode 0x{opc:02x} at offset {pos}; the block is not a \
                         valid LZVN stream"
                    ));
                }
            };

        pos += opc_len;

        if literal_len > 0 {
            if dst.len() + literal_len > expected_len {
                return Err(overflow(pos));
            }
            // The per-opcode checks above guarantee `pos + literal_len` is
            // still inside `src`.
            dst.extend_from_slice(&src[pos..pos + literal_len]);
            pos += literal_len;
        }

        if let Some(d) = new_distance {
            distance = d;
        }

        if match_len > 0 {
            // A match may not reach behind the start of the block, and a zero
            // distance has no meaning. Apple's decoder relies on the caller's
            // buffer here; we cannot, so both are rejected outright.
            if distance == 0 || distance > dst.len() {
                return Err(format!(
                    "LZVN match distance {distance} at offset {pos} reaches outside the {} byte(s) \
                     decoded so far",
                    dst.len()
                ));
            }
            if dst.len() + match_len > expected_len {
                return Err(overflow(pos));
            }
            // Byte-at-a-time on purpose: overlapping matches (distance < length)
            // are legal and must behave as a byte-order copy, not a memmove.
            for _ in 0..match_len {
                let byte = dst[dst.len() - distance];
                dst.push(byte);
            }
        }
    }

    if dst.len() != expected_len {
        return Err(format!(
            "LZVN block decoded to {} byte(s), but {expected_len} were expected",
            dst.len()
        ));
    }
    Ok(dst)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One 64 KiB-aligned chunk of a real `ditto --hfsCompression` resource
    /// fork: the tail chunk of a 4,200,000-byte file whose content is
    /// "SEANCE decmpfs test. " repeated. Produced by macOS, not by us, so it is
    /// evidence that this decoder agrees with Apple's encoder and not merely
    /// with itself. It exercises large-literal, small-distance, large-match,
    /// small-literal and end-of-stream in one block.
    const REAL_LZVN_TAIL_CHUNK: [u8; 78] = [
        0xe0, 0x05, 0x65, 0x73, 0x74, 0x2e, 0x20, 0x53, 0x45, 0x41, 0x4e, 0x43, 0x45, 0x20, 0x64,
        0x65, 0x63, 0x6d, 0x70, 0x66, 0x73, 0x20, 0x74, 0x38, 0x15, 0xf0, 0xff, 0xf0, 0xff, 0xf0,
        0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff,
        0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0,
        0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xe3, 0xe2, 0x2e, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    pub(crate) const REAL_PATTERN: &[u8] = b"SEANCE decmpfs test. ";
    /// The tail chunk starts 64 * 65536 bytes into the file, which is 16 bytes
    /// into the repeating pattern.
    pub(crate) const REAL_TAIL_PHASE: usize = 16;
    pub(crate) const REAL_TAIL_LEN: usize = 5696;

    /// The bytes the real tail chunk must expand to.
    pub(crate) fn real_tail_expected() -> Vec<u8> {
        (0..REAL_TAIL_LEN)
            .map(|i| REAL_PATTERN[(REAL_TAIL_PHASE + i) % REAL_PATTERN.len()])
            .collect()
    }

    /// The same real chunk the decmpfs tests use, for building resource forks.
    pub(crate) fn real_tail_chunk() -> Vec<u8> {
        REAL_LZVN_TAIL_CHUNK.to_vec()
    }

    #[test]
    fn decodes_a_real_apple_produced_block() {
        let decoded = decode(&REAL_LZVN_TAIL_CHUNK, REAL_TAIL_LEN)
            .expect("a real macOS LZVN block must decode");
        assert_eq!(decoded, real_tail_expected());
    }

    #[test]
    fn literal_only_block() {
        // sml_l L=3, then end-of-stream (8 bytes).
        let src = [0xE3, b'a', b'b', b'c', 0x06, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode(&src, 3).unwrap(), b"abc");
    }

    #[test]
    fn literal_plus_overlapping_match() {
        // sml_d: L=1, M=4, D=1 -> "x" then four copies of the previous byte.
        let src = [0x48, 0x01, b'x', 0x06, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode(&src, 5).unwrap(), b"xxxxx");
    }

    #[test]
    fn undefined_opcode_fails_closed() {
        let src = [0x70, 0x06, 0, 0, 0, 0, 0, 0, 0];
        let err = decode(&src, 4).expect_err("an undefined opcode must not decode");
        assert!(err.contains("undefined opcode"), "{err}");
    }

    #[test]
    fn missing_end_of_stream_fails_closed() {
        // Well-formed literal, but the stream simply stops: the decoder must
        // NOT hand back the three bytes it managed to expand.
        let src = [0xE3, b'a', b'b', b'c'];
        assert!(decode(&src, 3).is_err());
    }

    #[test]
    fn match_before_the_start_of_the_block_fails_closed() {
        // sml_m with no preceding opcode to establish a distance.
        let src = [0xF4, 0x06, 0, 0, 0, 0, 0, 0, 0];
        let err = decode(&src, 4).expect_err("a match with no distance must not decode");
        assert!(err.contains("match distance"), "{err}");
    }

    #[test]
    fn wrong_expected_length_fails_closed() {
        // The block really is 3 bytes; claiming 4 must be an error, not a
        // silently short buffer.
        let src = [0xE3, b'a', b'b', b'c', 0x06, 0, 0, 0, 0, 0, 0, 0];
        assert!(decode(&src, 4).is_err());
        // ... and claiming 2 must not truncate.
        assert!(decode(&src, 2).is_err());
    }

    #[test]
    fn opcode_classes_match_apples_dispatch_table() {
        // Spot-check the boundaries that a hand-written classifier gets wrong:
        // the low-three-bit rule must not swallow the explicitly-listed codes.
        assert_eq!(classify(0x06), Opcode::EndOfStream);
        assert_eq!(classify(0x0E), Opcode::Nop);
        assert_eq!(classify(0x16), Opcode::Nop);
        assert_eq!(classify(0x1E), Opcode::Undefined);
        assert_eq!(classify(0x46), Opcode::PreviousDistance);
        assert_eq!(classify(0x07), Opcode::LargeDistance);
        assert_eq!(classify(0x77), Opcode::Undefined);
        assert_eq!(classify(0xA6), Opcode::MediumDistance);
        assert_eq!(classify(0xBF), Opcode::MediumDistance);
        assert_eq!(classify(0xC6), Opcode::PreviousDistance);
        assert_eq!(classify(0xCF), Opcode::LargeDistance);
        assert_eq!(classify(0xD6), Opcode::Undefined);
        assert_eq!(classify(0xE0), Opcode::LargeLiteral);
        assert_eq!(classify(0xE6), Opcode::SmallLiteral);
        assert_eq!(classify(0xF0), Opcode::LargeMatch);
        assert_eq!(classify(0xF6), Opcode::SmallMatch);
    }
}
