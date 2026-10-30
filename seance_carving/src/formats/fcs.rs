use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FCS (Flow Cytometry Standard 3.0) carving signature. Header: "FCS3.0" at offset 0. The 58-byte
/// header stores ASCII text/data/analysis
/// segment offsets; the exact file size is derived from $ENDDATA / $ENDSTEXT /
/// $ENDANALYSIS, matching PhotoRec's header_check (data_check_size).
struct FcsSignature;

const OVERFLOW_SENTINEL: u64 = 0xffff_ffff_ffff_ffff;
const ASCII_MAX: u64 = 0x1999_9999_9999_9998;

/// Parse a fixed-width ASCII decimal field. Leading spaces are tolerated while the
/// value is still zero; any other non-digit byte invalidates the field (returns 0).
fn ascii2int(s: &[u8]) -> u64 {
    let mut res: u64 = 0;
    for &c in s {
        if c.is_ascii_digit() {
            res = res * 10 + u64::from(c - b'0');
            if res > ASCII_MAX {
                return OVERFLOW_SENTINEL;
            }
        } else if !(c == b' ' && res == 0) {
            return 0;
        }
    }
    res
}

/// Parse an ASCII decimal terminated by `delimiter` (or trailing space after digits).
fn ascii2int2(s: &[u8], delimiter: u8) -> u64 {
    let mut res: u64 = 0;
    for &c in s {
        if c.is_ascii_digit() {
            res = res * 10 + u64::from(c - b'0');
            if res > ASCII_MAX {
                return res;
            }
        } else if c == delimiter || (c == b' ' && res > 0) {
            return res;
        } else if c != b' ' {
            return 0;
        }
    }
    res
}

impl FileSignature for FcsSignature {
    fn name(&self) -> &str {
        "FCS"
    }

    fn extensions(&self) -> &[&str] {
        &["fcs"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 58 || &buf[0..6] != b"FCS3.0" {
            return None;
        }
        let text_start = ascii2int(&buf[10..18]);
        let text_end = ascii2int(&buf[18..26]);
        let data_start = ascii2int(&buf[26..34]);
        let mut data_end = ascii2int(&buf[34..42]);
        let analysis_start = ascii2int(&buf[42..50]);
        let mut analysis_end = ascii2int(&buf[50..58]);
        let mut stext_end: u64 = 0;
        if !(text_start <= text_end && data_start <= data_end && analysis_start <= analysis_end) {
            return None;
        }
        let buffer_size = buf.len() as u64;
        if (data_end == 0 || analysis_end == 0) && text_start < buffer_size {
            let delimiter = buf[text_start as usize];
            let smallest = buffer_size.min(text_end) as usize;
            let mut i = 0usize;
            while i < smallest {
                if buf[i] == delimiter {
                    if i + 1 + 8 + 1 < smallest
                        && &buf[i + 1..i + 9] == b"$ENDDATA"
                        && buf[i + 9] == delimiter
                    {
                        data_end = ascii2int2(&buf[i + 10..smallest], delimiter);
                    } else if i + 1 + 9 + 1 < smallest
                        && &buf[i + 1..i + 10] == b"$ENDSTEXT"
                        && buf[i + 10] == delimiter
                    {
                        stext_end = ascii2int2(&buf[i + 11..smallest], delimiter);
                    } else if i + 1 + 12 + 1 < smallest
                        && &buf[i + 1..i + 13] == b"$ENDANALYSIS"
                        && buf[i + 13] == delimiter
                    {
                        analysis_end = ascii2int2(&buf[i + 14..smallest], delimiter);
                    }
                }
                i += 1;
            }
        }
        let limit = 0x8000_0000_0000_0000u64 - 9;
        if data_end >= limit || analysis_end >= limit || stext_end >= limit {
            return None;
        }
        let mut calc = data_end + 9;
        if calc < analysis_end + 9 {
            calc = analysis_end + 9;
        }
        if calc < stext_end + 9 {
            calc = stext_end + 9;
        }
        // An extent shorter than the header itself came from nothing readable
        // (every offset zero and no keyword in view): it is not a size. Claim
        // none, so the file is recovered by its bounds rather than carved as a
        // few bytes or refused.
        Some(RecoveryInit {
            min_filesize: 58,
            extension: "fcs".to_string(),
            calculated_file_size: (calc >= 58).then_some(calc),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"FCS3.0", Arc::new(FcsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with_data_end(data_end: &[u8]) -> Vec<u8> {
        let mut buf = vec![b' '; 58];
        buf[0..6].copy_from_slice(b"FCS3.0");
        // data_end field at offset 34..42 (8 bytes), right-justified ASCII digits.
        let field = &mut buf[34..42];
        let start = 8 - data_end.len();
        field[start..].copy_from_slice(data_end);
        buf
    }

    #[test]
    fn test_fcs_header_match() {
        let sig = FcsSignature;
        let buf = header_with_data_end(b"1000");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(1000 + 9));
    }

    /// A header whose text offsets point at a TEXT segment but whose data and
    /// analysis end offsets are zero is sized from the `$END*` keywords in it.
    fn header_with_text(text: &[u8], text_start: usize, text_end: usize) -> Vec<u8> {
        let mut buf = vec![b' '; 58];
        buf[0..6].copy_from_slice(b"FCS3.0");
        let put = |buf: &mut Vec<u8>, at: usize, value: usize| {
            let digits = value.to_string();
            let field = &mut buf[at..at + 8];
            field.fill(b' ');
            field[8 - digits.len()..].copy_from_slice(digits.as_bytes());
        };
        put(&mut buf, 10, text_start);
        put(&mut buf, 18, text_end);
        buf[26..58].fill(b'0'); // data and analysis offsets: all zero
        buf.extend_from_slice(text);
        buf
    }

    #[test]
    fn test_fcs_text_segment_keywords_size_the_file() {
        let text = b"|$ENDDATA|2000|$ENDSTEXT|0|$ENDANALYSIS|3000|";
        let buf = header_with_text(text, 58, 58 + text.len() - 1);
        let init = FcsSignature.header_check(&buf, 0).expect("should match");
        // The largest end offset is $ENDANALYSIS, 3000, plus the 9 the format
        // keeps after it.
        assert_eq!(init.calculated_file_size, Some(3000 + 9));
        // $ENDDATA the largest.
        let text = b"|$ENDDATA|5000|$ENDSTEXT|0|$ENDANALYSIS|3000|";
        let buf = header_with_text(text, 58, 58 + text.len() - 1);
        let init = FcsSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(5000 + 9));
    }

    #[test]
    fn test_fcs_ascii_helpers() {
        assert_eq!(ascii2int(b"    1234"), 1234);
        assert_eq!(
            ascii2int(b"12 4"),
            0,
            "an embedded space invalidates the field"
        );
        assert_eq!(ascii2int2(b"2000|rest", b'|'), 2000);
        assert_eq!(ascii2int2(b"  77 more", b'|'), 77);
        assert_eq!(ascii2int2(b"x", b'|'), 0);
    }

    /// An absurd `$ENDDATA` is refused rather than turned into an extent.
    #[test]
    fn test_fcs_huge_end_offset_is_refused() {
        let text = b"|$ENDDATA|9223372036854775807|$ENDSTEXT|0|$ENDANALYSIS|3000|";
        let buf = header_with_text(text, 58, 58 + text.len() - 1);
        assert!(FcsSignature.header_check(&buf, 0).is_none());
    }

    /// A text segment that starts past the block cannot be read: no keyword
    /// gives an extent, and the header claims none (it does not claim 9 bytes,
    /// which is under the 58-byte header and would be refused by the engine).
    #[test]
    fn test_fcs_text_segment_beyond_the_block_claims_no_size() {
        let buf = header_with_text(b"", 100_000, 100_010);
        let init = FcsSignature.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, None);
        assert_eq!(init.min_filesize, 58);
    }

    #[test]
    fn test_fcs_no_match() {
        let sig = FcsSignature;
        assert!(sig
            .header_check(
                b"FCS2.0..................................................xx",
                0
            )
            .is_none());
        assert!(sig.header_check(b"FCS3.0", 0).is_none());
    }
}
