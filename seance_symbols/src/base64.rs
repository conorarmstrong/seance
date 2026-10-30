//! Strict base64 decoding for ISF `constant_data`.
//!
//! # Forensic meaning
//!
//! `constant_data` is how an ISF carries the *bytes of a symbol's value* rather
//! than merely its address. It is what makes Linux and macOS identification
//! possible at all: `linux_banner`'s constant data is the kernel's own version
//! string, and matching it against the banner recovered from the image is the
//! entire identity proof for those platforms (implementation plan §3.4.4,
//! gate 2).
//!
//! The decoder is deliberately strict. A lenient decoder that skips characters
//! it does not understand would turn a corrupt banner into a shorter,
//! well-formed one, and a shorter well-formed banner compares unequal for a
//! reason the examiner can never see. Anything that is not exact, padded,
//! standard-alphabet base64 is an error.

use crate::error::{Result, SymbolError};

/// Sentinel for a byte that is not in the base64 alphabet.
const INVALID: u8 = 0xFF;

/// Decode table for the standard alphabet (RFC 4648, `+` and `/`).
const TABLE: [u8; 256] = build_table();

const fn build_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut i = 0u8;
    while i < 26 {
        table[(b'A' + i) as usize] = i;
        table[(b'a' + i) as usize] = i + 26;
        i += 1;
    }
    let mut d = 0u8;
    while d < 10 {
        table[(b'0' + d) as usize] = d + 52;
        d += 1;
    }
    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table
}

/// Decode standard, padded base64.
///
/// # Errors
///
/// Returns [`SymbolError::Malformed`] for a length that is not a multiple of
/// four, for any character outside the alphabet, and for padding anywhere but
/// the final quantum. The message names the offending offset so a corrupt ISF
/// can be pointed at precisely.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(SymbolError::malformed(format!(
            "base64 constant_data is {} bytes long, which is not a multiple of 4",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0usize;
    while index < bytes.len() {
        let quantum = &bytes[index..index + 4];
        let last = index + 4 == bytes.len();

        let mut pad = 0usize;
        if quantum[3] == b'=' {
            pad += 1;
            if quantum[2] == b'=' {
                pad += 1;
            }
        }
        if pad > 0 && !last {
            return Err(SymbolError::malformed(format!(
                "base64 constant_data has padding at offset {index}, before the end of the data"
            )));
        }
        if quantum[2] == b'=' && quantum[3] != b'=' {
            return Err(SymbolError::malformed(format!(
                "base64 constant_data has misplaced padding at offset {}",
                index + 2
            )));
        }

        let mut acc: u32 = 0;
        for (position, &raw) in quantum.iter().enumerate() {
            let value = if raw == b'=' && position >= 4 - pad {
                0
            } else {
                let decoded = TABLE[raw as usize];
                if decoded == INVALID {
                    return Err(SymbolError::malformed(format!(
                        "base64 constant_data has the non-alphabet byte {raw:#04x} at offset {}",
                        index + position
                    )));
                }
                decoded
            };
            acc = (acc << 6) | u32::from(value);
        }

        // RFC 4648 §3.5: the bits a padded quantum does not carry into the
        // output must be zero. They are discarded on decode, so a decoder that
        // ignores them accepts several distinct encodings of the same bytes —
        // "QQ==" and "QR==" both become "A". For `constant_data` that is the
        // difference between an ISF whose banner really is the kernel's and one
        // whose bytes were altered in a way that survives the comparison. The
        // low 6 bits per '=' are already zero (the pad character decodes to 0),
        // so what is checked here is the tail of the last data character.
        let discarded = match pad {
            1 => acc & 0xFF,
            2 => acc & 0xFFFF,
            _ => 0,
        };
        if discarded != 0 {
            return Err(SymbolError::malformed(format!(
                "base64 constant_data has non-zero padding bits in the final quantum at offset {index}"
            )));
        }

        let triple = acc.to_be_bytes();
        // acc holds 24 bits in the low three bytes of the big-endian form.
        out.push(triple[1]);
        if pad < 2 {
            out.push(triple[2]);
        }
        if pad < 1 {
            out.push(triple[3]);
        }
        index += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_linux_banner_decodes_to_its_exact_bytes() {
        // "Linux version 6.1.0\n\0" — the trailing NUL is the dwarf2json shape
        // that upstream strips inconsistently and Séance normalises on both
        // sides of every comparison.
        let decoded = decode("TGludXggdmVyc2lvbiA2LjEuMAoA").expect("valid base64");
        assert_eq!(decoded, b"Linux version 6.1.0\n\0");
    }

    #[test]
    fn padding_shortens_the_output_by_exactly_the_right_amount() {
        assert_eq!(decode("QQ==").expect("one byte"), b"A");
        assert_eq!(decode("QUI=").expect("two bytes"), b"AB");
        assert_eq!(decode("QUJD").expect("three bytes"), b"ABC");
        assert_eq!(decode("").expect("empty"), Vec::<u8>::new());
    }

    #[test]
    fn a_length_that_is_not_a_multiple_of_four_is_refused() {
        let err = decode("QUJDR").expect_err("truncated base64 must not decode");
        assert!(err.to_string().contains("multiple of 4"), "{err}");
    }

    #[test]
    fn a_character_outside_the_alphabet_is_refused_rather_than_skipped() {
        // Four characters, so the length check passes and the alphabet check is
        // the one that has to catch the embedded space. A longer fixture would
        // be refused for its length and prove nothing about the alphabet.
        let err = decode("QU J").expect_err("whitespace is not base64");
        assert!(err.to_string().contains("non-alphabet"), "{err}");

        let err = decode("QUJ*").expect_err("'*' is not base64");
        assert!(err.to_string().contains("non-alphabet"), "{err}");
    }

    #[test]
    fn padding_before_the_final_quantum_is_refused() {
        let err = decode("QQ==QUJD").expect_err("interior padding must not decode");
        assert!(err.to_string().contains("before the end"), "{err}");
    }

    /// B5-038: RFC 4648 §3.5. Bits that a padded quantum discards must be zero,
    /// or several encodings decode to the same bytes and a corrupted
    /// `constant_data` compares equal to the genuine article.
    #[test]
    fn non_zero_padding_bits_are_refused() {
        // "QQ==" and "QR==" differ only in bits that a lenient decoder throws
        // away: both would yield b"A".
        assert_eq!(decode("QQ==").expect("canonical one byte"), b"A");
        let err = decode("QR==").expect_err("non-zero pad bits must not decode");
        assert!(err.to_string().contains("padding bits"), "{err}");

        // Same for the two-byte case: "QUI=" is canonical, "QUJ=" is not.
        assert_eq!(decode("QUI=").expect("canonical two bytes"), b"AB");
        let err = decode("QUJ=").expect_err("non-zero pad bits must not decode");
        assert!(err.to_string().contains("padding bits"), "{err}");

        // A full quantum discards nothing, so this check must not touch it.
        assert_eq!(decode("QUJD").expect("three bytes"), b"ABC");
    }

    #[test]
    fn misplaced_padding_inside_the_final_quantum_is_refused() {
        let err = decode("Q=BD").expect_err("padding in the middle must not decode");
        assert!(err.to_string().contains("non-alphabet") || err.to_string().contains("misplaced"));
    }
}
