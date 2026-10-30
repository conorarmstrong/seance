use crate::checks::{carry_tail, join_carry};
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PDF file signature detector.
/// Header: 25 50 44 46 (%PDF)
/// Footer: %%EOF
/// Ref: reference/testdisk/src/file_pdf.c
struct PdfSignature;

const PDF_EOF: &[u8] = b"%%EOF";

impl FileSignature for PdfSignature {
    fn name(&self) -> &str {
        "PDF"
    }

    fn extensions(&self) -> &[&str] {
        &["pdf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 4 && &buf[0..4] == b"%PDF" {
            Some(RecoveryInit {
                min_filesize: 100,
                extension: "pdf".to_string(),
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
        // Scan for %%EOF marker. The last four bytes of every block are carried
        // so a marker straddling a block boundary is still found; positions in
        // `data` are `carry_len` ahead of positions in `buf`.
        let (data, carry_len) = join_carry(buf, recovery);
        let buf = &data[..];
        for i in 0..buf.len().saturating_sub(4) {
            if &buf[i..i + 5] == PDF_EOF {
                // Include a newline after %%EOF if present
                let mut end = i + 5;
                if end < buf.len() && (buf[end] == b'\n' || buf[end] == b'\r') {
                    end += 1;
                    if end < buf.len() && buf[end] == b'\n' {
                        end += 1;
                    }
                }
                // A linearized file's first-page section and every
                // incremental update end in `%%EOF` too; the file goes on when
                // another section follows (ISO 32000-1 7.5.6, F.3). Only a
                // section seen in this block continues it: one that would
                // start past the block's end cannot be told from free space
                // here, and the carve ends at this `%%EOF` as it always did.
                if section_follows(buf, end) == Some(true) {
                    continue;
                }
                return DataCheckResult::Stop(recovery.file_size + (end - carry_len) as u64);
            }
        }
        carry_tail(buf, recovery, PDF_EOF.len() - 1);
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {
        // Size and extension are settled by data_check; the %%EOF check is
        // reported through verify_footer.
    }

    /// A complete PDF carries `%%EOF` at the end of its last trailer. Look for
    /// it in the final 1 KiB of the recovered extent; absence means the carve
    /// did not reach a real end-of-file.
    fn verify_footer(&self, data: &[u8]) -> Option<bool> {
        let check_region = if data.len() > 1024 {
            &data[data.len() - 1024..]
        } else {
            data
        };
        Some(check_region.windows(5).any(|w| w == b"%%EOF"))
    }

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024 // 512 MB
    }
}

/// A PDF opens with its version comment, `%PDF-` and then the version as a
/// digit, a full stop and a digit (ISO 32000-1 7.5.2), e.g. `%PDF-1.7`.
fn header_block_plausible(buf: &[u8]) -> bool {
    buf.len() < 8
        || (buf[4] == b'-' && buf[5].is_ascii_digit() && buf[6] == b'.' && buf[7].is_ascii_digit())
}

/// Whether another PDF section starts after an `%%EOF` ending at `from`: past
/// spaces, tabs, form feeds and line ends, an indirect object header
/// (`<num> <num> obj`) or a cross-reference table (`xref`). `None` when the
/// block ends before that can be told.
///
/// NUL is PDF white space too, but it is not skipped: zero fill after an
/// `%%EOF` is the free space that follows a file, not more of it.
fn section_follows(buf: &[u8], from: usize) -> Option<bool> {
    let rest = buf.get(from..)?;
    let start = rest
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C))?;
    let rest = &rest[start..];
    if rest.len() < 24 {
        // Enough for `xref` or `<10 digits> <5 digits> obj`; decide early only
        // when what is there already rules a section out.
        if rest.starts_with(b"xref") {
            return Some(true);
        }
        let fits_so_far = rest
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b' ' | b'o' | b'b' | b'j'))
            || b"xref".starts_with(rest);
        return if fits_so_far { None } else { Some(false) };
    }
    if rest.starts_with(b"xref") {
        return Some(true);
    }
    // <digits> SP <digits> SP "obj"
    let mut i = 0;
    let digits = |i: &mut usize| {
        let s = *i;
        while *i < rest.len() && rest[*i].is_ascii_digit() {
            *i += 1;
        }
        *i > s
    };
    let ok = digits(&mut i)
        && rest.get(i) == Some(&b' ')
        && {
            i += 1;
            digits(&mut i)
        }
        && rest.get(i) == Some(&b' ')
        && rest[i + 1..].starts_with(b"obj");
    Some(ok)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x25, 0x50, 0x44, 0x46], Arc::new(PdfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_header_match() {
        let sig = PdfSignature;
        let buf = b"%PDF-1.7\n";
        assert!(sig.header_check(buf, 0).is_some());
    }

    #[test]
    fn test_pdf_header_no_match() {
        let sig = PdfSignature;
        let buf = b"Not a PDF";
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_pdf_eof_detection() {
        let sig = PdfSignature;
        let mut recovery = FileRecovery {
            extension: "pdf".to_string(),
            file_size: 1000,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 100,
            extra: 0,
            extra_bytes: Vec::new(),
        };

        let buf = b"some data %%EOF\n more";
        let result = sig.data_check(buf, &mut recovery);
        // %%EOF starts at 10, length 5, plus \n = 16
        assert_eq!(result, DataCheckResult::Stop(1016));
    }

    fn fresh() -> FileRecovery {
        FileRecovery {
            extension: "pdf".to_string(),
            file_size: 0,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 100,
            extra: 0,
            extra_bytes: Vec::new(),
        }
    }

    /// A linearized PDF ends its first-page section with `%%EOF`, and the
    /// main body follows (DFTT #12's `lin_test.pdf`). So does an incremental
    /// update. The carve runs to the `%%EOF` after the last section.
    #[test]
    fn an_eof_followed_by_another_section_is_not_the_end() {
        let pdf = b"%PDF-1.3\r1 0 obj\r<<>>\rendobj\rstartxref\r0\r%%EOF\r     \r7 0 obj\r<<>>\rendobj\rxref\r0 1\rtrailer\r<<>>\rstartxref\r9\r%%EOF\r";
        let mut buf = pdf.to_vec();
        buf.extend(vec![0u8; 64]);
        assert_eq!(
            PdfSignature.data_check(&buf, &mut fresh()),
            DataCheckResult::Stop(pdf.len() as u64)
        );
        // An update section opening with `xref` continues it the same way.
        let upd = b"%PDF-1.4\n%%EOF\nxref\n0 1\ntrailer\n%%EOF\n";
        let mut buf = upd.to_vec();
        buf.extend(vec![0u8; 8]);
        assert_eq!(
            PdfSignature.data_check(&buf, &mut fresh()),
            DataCheckResult::Stop(upd.len() as u64)
        );
    }

    /// Bound: a section that would begin past the block holding the
    /// `%%EOF` cannot be seen from it, so the carve ends at that `%%EOF`.
    #[test]
    fn an_eof_whose_successor_is_past_the_block_end_still_ends_the_carve() {
        let first = b"%PDF-1.3\n1 0 obj\n<<>>\nendobj\n%%EOF\n  ";
        assert_eq!(
            PdfSignature.data_check(first, &mut fresh()),
            DataCheckResult::Stop(first.len() as u64 - 2)
        );
    }

    #[test]
    fn a_pdf_followed_by_another_pdf_ends_at_its_own_eof() {
        let mut buf = b"%PDF-1.3\n%%EOF\n".to_vec();
        buf.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n");
        assert_eq!(
            PdfSignature.data_check(&buf, &mut fresh()),
            DataCheckResult::Stop(15)
        );
    }

    /// The %%EOF check must be reported, not computed and dropped: the engine
    /// stamps a carve "footer-validated" from this verdict alone (B2-143).
    #[test]
    fn pdf_footer_verdict_is_returned() {
        let sig = PdfSignature;
        assert_eq!(sig.verify_footer(b"trailer\n%%EOF\n"), Some(true));
        assert_eq!(sig.verify_footer(b"stream data with no end"), Some(false));
        // Only the final 1 KiB counts: an %%EOF far earlier is a previous
        // revision's trailer, not this extent's end.
        let mut far = b"%%EOF".to_vec();
        far.extend(std::iter::repeat_n(b'x', 2048));
        assert_eq!(sig.verify_footer(&far), Some(false));
    }
}
