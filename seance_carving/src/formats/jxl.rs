//! JPEG XL (`.jxl`).
//!
//! # Why only the container form is carved
//!
//! A JPEG XL file takes one of two shapes. The container form opens with a
//! twelve-byte signature box — `00 00 00 0C 4A 58 4C 20 0D 0A 87 0A` — which is
//! as distinctive as any magic in this crate. The bare codestream opens with
//! **two** bytes, `FF 0A`, and that is not a signature: two given bytes recur
//! about once in every 65,536, so sweeping a terabyte image for them would
//! yield millions of matches, essentially all of them wrong.
//!
//! Carving only the container form therefore misses bare codestreams. That is
//! the right trade: a carver that emitted millions of two-byte false positives
//! would bury every real file it found, and an examiner cannot review what they
//! cannot see. The limitation is recorded here rather than left to be
//! rediscovered.
//!
//! The signature box is deliberately constructed to survive transfer damage —
//! `0D 0A` catches CRLF translation and `87 0A` catches 8-bit stripping — which
//! is also what makes it a good thing to carve on.

use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// The JPEG XL signature box: length 12, type `JXL `, then `0D 0A 87 0A`.
const JXL_CONTAINER_MAGIC: &[u8] = &[
    0x00, 0x00, 0x00, 0x0C, b'J', b'X', b'L', b' ', 0x0D, 0x0A, 0x87, 0x0A,
];

struct JpegXlSignature;

impl FileSignature for JpegXlSignature {
    fn name(&self) -> &str {
        "JPEG XL"
    }

    fn extensions(&self) -> &[&str] {
        &["jxl"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < JXL_CONTAINER_MAGIC.len()
            || &buf[..JXL_CONTAINER_MAGIC.len()] != JXL_CONTAINER_MAGIC
        {
            return None;
        }
        // The twelve-byte signature box is the whole check: it is distinctive
        // enough to stand alone (see the module notes). The box that follows it
        // (`ftyp` with the `jxl ` brand) is not read, so a match is not
        // confirmed past the signature box.
        Some(RecoveryInit {
            min_filesize: JXL_CONTAINER_MAGIC.len() as u64,
            extension: "jxl".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, JXL_CONTAINER_MAGIC, Arc::new(JpegXlSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_container_signature_box_is_recognised() {
        let sig = JpegXlSignature;
        let mut buf = JXL_CONTAINER_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]);
        buf.extend_from_slice(b"ftypjxl ");
        let init = sig.header_check(&buf, 0).expect("a JPEG XL container");
        assert_eq!(init.extension, "jxl");
    }

    /// **The deliberate limitation.** A bare codestream begins `FF 0A`, and two
    /// bytes are not a signature: carving on them would produce millions of
    /// false positives across a large image and bury every real finding.
    #[test]
    fn a_bare_two_byte_codestream_is_not_carved() {
        let sig = JpegXlSignature;
        let mut bare = vec![0xFF, 0x0A];
        bare.extend_from_slice(&[0u8; 32]);
        assert!(
            sig.header_check(&bare, 0).is_none(),
            "carving on a two-byte magic would match roughly once every 64 KiB of \
             arbitrary data"
        );
    }

    #[test]
    fn a_near_miss_is_refused() {
        let sig = JpegXlSignature;
        let mut wrong = JXL_CONTAINER_MAGIC.to_vec();
        // The trailing 0x0A that catches 8-bit stripping.
        wrong[11] = 0x0B;
        assert!(sig.header_check(&wrong, 0).is_none());
        // Truncated input is refused, not read past.
        assert!(sig.header_check(&JXL_CONTAINER_MAGIC[..8], 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
    }
}
