//! WARC — Web ARChive (ISO 28500), and its ARC predecessor.
//!
//! # Why this is the `.arc` worth carving
//!
//! There are three formats called ARC. The one from 1985 — SEA ARC — is
//! identified by a **single** byte, `0x1A`, followed by a method number. One
//! byte is not a signature: it occurs roughly once every 256 bytes of arbitrary
//! data, so carving on it across an image would emit millions of files and bury
//! everything real in the output. It is also a format nobody has written since
//! the 1990s. It is deliberately not carved, for the same reason the bare JPEG
//! XL codestream is not.
//!
//! The ARC that matters is the Internet Archive's web-archive format and its
//! ISO-standardised successor, WARC. That is where captured web evidence lives:
//! preservation captures, `wget --warc`, Browsertrix, and the archives produced
//! when a page is preserved for proceedings. A WARC holds the full request and
//! response — headers, body, and the capture timestamp — which is exactly what
//! makes it evidence rather than a screenshot.
//!
//! # Recognition
//!
//! A WARC record begins with the version line `WARC/1.0` or `WARC/1.1`, and a
//! file begins with a record. That is eight characters of fixed text, which is
//! a far stronger thing to match on than most binary magic.
//!
//! # Extent
//!
//! Records concatenate, and each carries its own `Content-Length`, but a file
//! is a run of records with no terminator and no count. So the extent is
//! engine-bounded: the carve begins at a real record and runs until another
//! header interrupts it, which for a file of concatenated records is the honest
//! answer rather than a guessed one.

use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// The version line every WARC record opens with.
const WARC_MAGIC: &[u8] = b"WARC/1.";

struct WarcSignature;

impl FileSignature for WarcSignature {
    fn name(&self) -> &str {
        "WARC"
    }

    fn extensions(&self) -> &[&str] {
        &["warc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 10 || &buf[..WARC_MAGIC.len()] != WARC_MAGIC {
            return None;
        }
        // Only 1.0 and 1.1 exist. Accepting any digit would match the version
        // line of a format that merely borrowed the shape.
        if !matches!(buf[7], b'0' | b'1') {
            return None;
        }
        // The version line ends there; a record's fields follow on the next
        // line. Requiring the break distinguishes a record from prose that
        // happens to contain the string.
        if !matches!(buf[8], b'\r' | b'\n') {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 64,
            extension: "warc".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // Records concatenate with no terminator and no count, so nothing here
        // can decide where the file ends.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, WARC_MAGIC, Arc::new(WarcSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(version: &str, terminator: &str) -> Vec<u8> {
        format!(
            "WARC/{version}{terminator}WARC-Type: response{terminator}\
             WARC-Date: 2026-08-05T00:00:00Z{terminator}Content-Length: 12{terminator}{terminator}"
        )
        .into_bytes()
    }

    #[test]
    fn both_warc_versions_are_recognised() {
        let sig = WarcSignature;
        for version in ["1.0", "1.1"] {
            let init = sig
                .header_check(&record(version, "\r\n"), 0)
                .unwrap_or_else(|| panic!("WARC/{version} is a real version"));
            assert_eq!(init.extension, "warc");
        }
        // Bare LF appears in the wild as well as CRLF.
        assert!(sig.header_check(&record("1.0", "\n"), 0).is_some());
    }

    #[test]
    fn a_version_that_does_not_exist_is_refused() {
        let sig = WarcSignature;
        assert!(sig.header_check(&record("1.9", "\r\n"), 0).is_none());
        assert!(sig.header_check(&record("1.5", "\r\n"), 0).is_none());
    }

    /// The string can occur in prose and in logs. Requiring the line break
    /// after the version is what separates a record from a mention of one.
    #[test]
    fn text_that_merely_contains_the_string_is_not_a_record() {
        let sig = WarcSignature;
        assert!(sig
            .header_check(b"WARC/1.0 is the version we used for the capture", 0)
            .is_none());
        assert!(sig.header_check(b"WARC/2.0\r\nWARC-Type: x", 0).is_none());
        assert!(sig.header_check(b"WARC/1.", 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
    }
}
