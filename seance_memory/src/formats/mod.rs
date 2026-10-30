//! Acquisition-format readers.
//!
//! Each module here answers exactly one question: *which bytes of this file
//! hold which memory addresses?* The answer is a [`crate::segmented::Segment`]
//! list, handed to [`crate::segmented::SegmentedLayer`], which owns the address
//! lookup, the bounds and the hole semantics for every format at once. A reader
//! that produced its own lookup loop would eventually get one of them wrong.
//!
//! ## The rules every reader here obeys
//!
//! - **Structural headers are read with [`seance_core::io::read_exact_or_fail`].**
//!   A short read of a header is a refusal, never a parse of a zero-padded
//!   buffer. Truncated evidence must not become plausible-looking content.
//! - **An unmapped address is a hole, not zeros.** A reader never invents a
//!   segment to cover a gap it did not find in the image.
//! - **Nothing is guessed.** A field that is absent stays absent: no default
//!   architecture, no assumed machine type, no fabricated size.
//! - **Every cap, skip and unsupported construct is recorded** as an
//!   [`seance_core::io::IncompleteReason`] on the layer's
//!   [`crate::meta::LayerMeta`], so "this is all there was" and "we stopped
//!   early" never render the same.

pub mod avml;
pub mod crash;
pub mod elf;
pub mod hibernation;
pub mod lime;
pub mod linux_swap;
pub mod qemu;
pub mod vmware;
pub mod xpress;
use std::io;

use crate::format::MemoryImageFormat;
use crate::layer::LayerError;

/// Why a format reader refused an image.
///
/// The variants are kept apart because they are different findings for an
/// examiner: "this is not that format" is a routing outcome, "this format but
/// broken" is a defect in the evidence, and "this format, valid, but using a
/// construct we cannot read" is a defect in *this tool* and must say so rather
/// than degrade into a partial parse that looks complete.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    /// The source does not carry this format's header. Not an error about the
    /// evidence — just the wrong reader for these bytes.
    #[error("{format}: not this format ({detail})")]
    NotThisFormat {
        format: &'static str,
        detail: String,
    },

    /// The header identifies this format but the structure is invalid.
    #[error("{format}: malformed image ({detail})")]
    Malformed {
        format: &'static str,
        detail: String,
    },

    /// A valid image using a construct this reader does not implement. Named
    /// explicitly so an examiner learns *what* is unsupported, rather than
    /// receiving a silently partial address space.
    #[error("{format}: unsupported ({detail})")]
    Unsupported {
        format: &'static str,
        detail: String,
    },

    /// A second input the format requires could not be reached.
    #[error("{format}: {detail}")]
    MissingCompanion {
        format: &'static str,
        detail: String,
    },

    /// A structural read failed or returned fewer bytes than the structure
    /// requires.
    #[error("{format}: reading {what}: {source}")]
    Io {
        format: &'static str,
        what: String,
        #[source]
        source: io::Error,
    },

    /// The segment list was rejected when the layer was built (overlapping
    /// runs, a zero-length run, too many runs).
    #[error("{format}: {source}")]
    Layer {
        format: &'static str,
        #[source]
        source: LayerError,
    },
}

impl FormatError {
    pub(crate) fn not_this(format: MemoryImageFormat, detail: impl Into<String>) -> Self {
        FormatError::NotThisFormat {
            format: format.as_str(),
            detail: detail.into(),
        }
    }

    pub(crate) fn malformed(format: MemoryImageFormat, detail: impl Into<String>) -> Self {
        FormatError::Malformed {
            format: format.as_str(),
            detail: detail.into(),
        }
    }

    pub(crate) fn unsupported(format: MemoryImageFormat, detail: impl Into<String>) -> Self {
        FormatError::Unsupported {
            format: format.as_str(),
            detail: detail.into(),
        }
    }

    pub(crate) fn missing_companion(format: MemoryImageFormat, detail: impl Into<String>) -> Self {
        FormatError::MissingCompanion {
            format: format.as_str(),
            detail: detail.into(),
        }
    }

    pub(crate) fn io(
        format: MemoryImageFormat,
        what: impl Into<String>,
        source: io::Error,
    ) -> Self {
        FormatError::Io {
            format: format.as_str(),
            what: what.into(),
            source,
        }
    }

    pub(crate) fn layer(format: MemoryImageFormat, source: LayerError) -> Self {
        FormatError::Layer {
            format: format.as_str(),
            source,
        }
    }

    /// The format identifier the error came from, for logs and artifact
    /// metadata.
    pub fn format(&self) -> &'static str {
        match self {
            FormatError::NotThisFormat { format, .. }
            | FormatError::Malformed { format, .. }
            | FormatError::Unsupported { format, .. }
            | FormatError::MissingCompanion { format, .. }
            | FormatError::Io { format, .. }
            | FormatError::Layer { format, .. } => format,
        }
    }

    /// Whether this is merely "wrong reader for these bytes", which a caller
    /// trying several readers should move past silently, as opposed to a
    /// finding about the evidence that must be surfaced.
    pub fn is_not_this_format(&self) -> bool {
        matches!(self, FormatError::NotThisFormat { .. })
    }
}

/// Byte order of a format's integer fields.
///
/// Formats here are not all one endianness and not all fixed: ELF carries it in
/// `EI_DATA` and QEMU's migration stream is big-endian regardless of the guest,
/// so the decode width and the decode order are separate decisions and both are
/// read from the image rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

/// Decode a `u16` at `at`, or `None` if the buffer is too short.
///
/// The accessors return `Option` rather than indexing so a reader can never
/// panic on a buffer it sized wrongly; every caller maps `None` onto a
/// [`FormatError::Malformed`] naming the field.
pub(crate) fn u16_at(bytes: &[u8], at: usize, endian: Endian) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u16::from_le_bytes(raw),
        Endian::Big => u16::from_be_bytes(raw),
    })
}

/// Decode a `u32` at `at`, or `None` if the buffer is too short.
pub(crate) fn u32_at(bytes: &[u8], at: usize, endian: Endian) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(raw),
        Endian::Big => u32::from_be_bytes(raw),
    })
}

/// Decode a `u64` at `at`, or `None` if the buffer is too short.
pub(crate) fn u64_at(bytes: &[u8], at: usize, endian: Endian) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u64::from_le_bytes(raw),
        Endian::Big => u64::from_be_bytes(raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_decode_both_orders() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(u16_at(&bytes, 0, Endian::Little), Some(0x0201));
        assert_eq!(u16_at(&bytes, 0, Endian::Big), Some(0x0102));
        assert_eq!(u32_at(&bytes, 0, Endian::Little), Some(0x0403_0201));
        assert_eq!(u32_at(&bytes, 0, Endian::Big), Some(0x0102_0304));
        assert_eq!(
            u64_at(&bytes, 0, Endian::Little),
            Some(0x0807_0605_0403_0201)
        );
        assert_eq!(u64_at(&bytes, 0, Endian::Big), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn accessors_refuse_to_read_past_the_end_instead_of_panicking() {
        let bytes = [0x01u8, 0x02, 0x03];
        assert_eq!(u32_at(&bytes, 0, Endian::Little), None);
        assert_eq!(u16_at(&bytes, 2, Endian::Little), None);
        assert_eq!(u64_at(&bytes, 0, Endian::Big), None);
        // An offset far past the end must not overflow the range arithmetic.
        assert_eq!(u64_at(&bytes, usize::MAX, Endian::Big), None);
        assert_eq!(u32_at(&[], 0, Endian::Big), None);
    }

    #[test]
    fn errors_carry_their_format_and_classify_routing_failures() {
        let wrong = FormatError::not_this(MemoryImageFormat::ElfCore, "bad magic");
        assert_eq!(wrong.format(), "elf_core");
        assert!(wrong.is_not_this_format());

        let broken = FormatError::malformed(MemoryImageFormat::QemuSaveVm, "bad section");
        assert_eq!(broken.format(), "qemu_savevm");
        assert!(!broken.is_not_this_format());
        assert!(broken.to_string().contains("malformed image"));

        let missing = FormatError::missing_companion(MemoryImageFormat::VmwareSnapshot, "no .vmss");
        assert!(missing.to_string().contains("no .vmss"));
        assert_eq!(Endian::Big.as_str(), "big");
    }
}
