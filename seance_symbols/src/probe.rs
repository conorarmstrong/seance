//! The one thing this crate cannot do for itself: read the memory image.
//!
//! Gate 4 of the admission sequence — "does this candidate table describe *this*
//! image?" — is the only check that needs the evidence rather than the symbol
//! file. Reading typed fields at ISF-derived offsets and requiring the results
//! to be self-consistent is what actually falsifies a wrong-build table: gates
//! 1 to 3 prove the file is well-formed, internally consistent and of the right
//! width, and a table from the *wrong Windows build* passes all three.
//!
//! This crate does not depend on the layer stack, so the image arrives through
//! [`ImageProbe`], defined here and implemented by whichever crate owns the
//! address space. That inversion is deliberate: it keeps the highest-risk
//! subsystem in memory analysis unit-testable with a hand-built fake and no
//! memory image at all, and it stops symbol validation from quietly acquiring a
//! dependency on paging.
//!
//! # What an implementor must and must not do
//!
//! `read_exact` must fail when any byte of the requested range is not backed by
//! the acquisition. It must **never** zero-fill. A page that was swapped out,
//! smeared during capture or never acquired is not a page of zeros, and a gate
//! that reads fabricated zeros through a candidate table will happily conclude
//! that a wrong layout is right — the zeros satisfy almost any sanity check.

/// Result alias for probe operations.
pub type ProbeResult<T> = std::result::Result<T, ProbeError>;

/// Why the image could not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// Some byte of the requested range has nothing behind it: unmapped, not
    /// present, swapped out, or suppressed. The distinction belongs to the
    /// layer that knows it and travels in `reason`.
    #[error("{length} byte(s) at {address:#x} are not backed by the image ({reason})")]
    Unmapped {
        /// First address with no bytes behind it.
        address: u64,
        /// How many bytes were requested.
        length: u64,
        /// The layer's own word for why, e.g. `swapped_out`.
        reason: String,
    },

    /// The image cannot answer this question at all: no kernel space has been
    /// built yet, the address is outside every space, or the check needs
    /// something this image does not carry.
    #[error("the image cannot answer that: {0}")]
    Unavailable(String),

    /// The underlying read failed for an ordinary I/O reason.
    #[error("reading the image failed: {0}")]
    Io(String),
}

impl ProbeError {
    /// Stable machine-readable class, for gate details and artifact metadata.
    pub fn class(&self) -> &'static str {
        match self {
            ProbeError::Unmapped { .. } => "unmapped",
            ProbeError::Unavailable(_) => "unavailable",
            ProbeError::Io(_) => "io",
        }
    }
}

/// A memory image, as much of it as symbol admission needs.
///
/// Object safe: hold it as `&dyn ImageProbe`.
pub trait ImageProbe {
    /// Fill `buf` from `address` in the space these symbols address.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Unmapped`] if any byte of the range is unbacked. Partial
    /// success is a failure: a structure half-read is a structure whose fields
    /// cannot be trusted, and the caller must not see a buffer that is part
    /// evidence and part anything else.
    fn read_exact(&self, address: u64, buf: &mut [u8]) -> ProbeResult<()>;

    /// Pointer width in bytes implied by the paging mode actually selected for
    /// this image.
    ///
    /// Structural, never inferred from the contents of memory. This is the
    /// value gate 3 compares the ISF's `pointer` base type against.
    fn pointer_size(&self) -> u8;

    /// The identity recovered from the image itself: the CodeView triple
    /// `{database}|{GUID}|{age}` on Windows, or the normalised banner on Linux
    /// and macOS.
    ///
    /// `None` means the image has not yielded one — not that any identity will
    /// do. Gate 2 records that it could not be evaluated rather than passing.
    fn image_identifier(&self) -> Option<String>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A probe over a flat byte buffer starting at a chosen base address, with
    /// an optional unmapped window, for exercising the gate-4 read path.
    #[derive(Debug)]
    pub(crate) struct FakeImage {
        pub base: u64,
        pub bytes: Vec<u8>,
        /// Half-open range of addresses that behave as a memory hole.
        pub hole: Option<(u64, u64)>,
        pub pointer_size: u8,
        pub identifier: Option<String>,
    }

    impl FakeImage {
        pub(crate) fn new(base: u64, bytes: Vec<u8>) -> Self {
            Self {
                base,
                bytes,
                hole: None,
                pointer_size: 8,
                identifier: None,
            }
        }

        pub(crate) fn with_hole(mut self, start: u64, end: u64) -> Self {
            self.hole = Some((start, end));
            self
        }
    }

    impl ImageProbe for FakeImage {
        fn read_exact(&self, address: u64, buf: &mut [u8]) -> ProbeResult<()> {
            let length = buf.len() as u64;
            let end = address
                .checked_add(length)
                .ok_or_else(|| ProbeError::Unavailable("address arithmetic overflowed".into()))?;
            if let Some((hole_start, hole_end)) = self.hole {
                if address < hole_end && hole_start < end {
                    return Err(ProbeError::Unmapped {
                        address: hole_start,
                        length: hole_end - hole_start,
                        reason: "unmapped".into(),
                    });
                }
            }
            if address < self.base || end > self.base + self.bytes.len() as u64 {
                return Err(ProbeError::Unmapped {
                    address,
                    length,
                    reason: "outside the fake image".into(),
                });
            }
            let offset = (address - self.base) as usize;
            buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
            Ok(())
        }

        fn pointer_size(&self) -> u8 {
            self.pointer_size
        }

        fn image_identifier(&self) -> Option<String> {
            self.identifier.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeImage;
    use super::*;

    #[test]
    fn a_probe_read_that_lands_in_a_hole_fails_rather_than_yielding_zeros() {
        let image = FakeImage::new(0x1000, vec![0xAA; 0x1000]).with_hole(0x1400, 0x1500);
        let mut buf = [0u8; 8];
        // Straddles the hole boundary: 0x13FC..0x1404 covers four acquired bytes
        // and four unacquired ones. Part-filling the buffer here would hand the
        // caller four real bytes and four zeros with no way to tell them apart.
        let err = image
            .read_exact(0x13FC, &mut buf)
            .expect_err("a read overlapping a hole must fail");
        assert_eq!(err.class(), "unmapped");
        assert!(
            buf.iter().all(|&b| b == 0),
            "the buffer must be left untouched, not part-filled"
        );
    }

    #[test]
    fn a_read_ending_exactly_where_a_hole_begins_is_not_in_the_hole() {
        // Holes are half-open. A read of 0x13F8..0x1400 against a hole at
        // 0x1400 touches the boundary without entering it, and refusing it
        // would discard bytes the acquisition genuinely captured.
        let image = FakeImage::new(0x1000, vec![0xAA; 0x1000]).with_hole(0x1400, 0x1500);
        let mut buf = [0u8; 8];
        image
            .read_exact(0x13F8, &mut buf)
            .expect("the byte before a hole is still acquired evidence");
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn a_probe_read_inside_the_image_returns_the_acquired_bytes() {
        let mut bytes = vec![0u8; 64];
        bytes[16..24].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let image = FakeImage::new(0x2000, bytes);
        let mut buf = [0u8; 8];
        image.read_exact(0x2010, &mut buf).expect("mapped read");
        assert_eq!(u64::from_le_bytes(buf), 0x1122_3344_5566_7788);
    }

    #[test]
    fn a_read_past_the_end_of_the_image_is_an_error_not_a_short_read() {
        let image = FakeImage::new(0, vec![0u8; 16]);
        let mut buf = [0u8; 8];
        assert!(image.read_exact(12, &mut buf).is_err());
        assert!(image.read_exact(u64::MAX, &mut buf).is_err());
    }
}
