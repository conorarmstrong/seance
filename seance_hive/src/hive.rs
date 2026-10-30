//! The base block, and the cell addressing everything else is built on.
//!
//! Layout is taken from Maxim Suhanov's *Windows registry file format
//! specification* (CC BY 4.0, <https://github.com/msuhanov/regf>), which is the
//! public description of the format this crate implements against.

use crate::error::{HiveError, Result};
use crate::key_node::KeyNode;

/// The base block is one page, and the hive-bin data starts after it.
pub(crate) const BASE_BLOCK_BYTES: usize = 4096;

/// A hive bin is a whole number of pages, and so is the data area as a whole.
pub(crate) const BIN_ALIGNMENT: usize = 4096;

/// Cells are allocated in multiples of eight bytes, including the four-byte
/// size field at their head.
pub(crate) const CELL_ALIGNMENT: usize = 8;

/// What a caller is prepared to read past.
///
/// Both of these describe a hive that is structurally sound and incomplete,
/// which is the normal state of a hive lifted off a running machine. Neither
/// is a reason to refuse every key in the file — but a caller that sets one
/// has to carry the qualification onto whatever it reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tolerances {
    /// Accept a hive whose two sequence numbers differ: it was not cleanly
    /// flushed, and its newest writes may exist only in its transaction logs.
    pub dirty: bool,
    /// Accept a hive that declares more hive-bin data than the buffer holds.
    /// Every cell up to the cut is still readable and bounded.
    pub short_data: bool,
}

impl Tolerances {
    /// Tolerate both — the acquisition reality, for a caller that reports what
    /// it tolerated.
    pub fn lenient() -> Self {
        Self {
            dirty: true,
            short_data: true,
        }
    }
}

/// A registry hive, borrowed rather than copied.
#[derive(Clone, Copy, Debug)]
pub struct Hive<'a> {
    bytes: &'a [u8],
}

impl<'a> Hive<'a> {
    /// Open and fully validate a hive.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        let hive = Self::without_validation(bytes)?;
        hive.validate()?;
        Ok(hive)
    }

    /// Open a hive after checking only that it could be one.
    ///
    /// The signature and the base-block length are checked here — reading a
    /// field of a buffer that is not a hive is how a parser ends up asserting
    /// on hostile input — and everything else is left to [`Hive::validate`],
    /// so a caller can decide what to tolerate before it commits.
    pub fn without_validation(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BASE_BLOCK_BYTES {
            return Err(HiveError::Truncated {
                structure: "base block",
                offset: BASE_BLOCK_BYTES,
                available: bytes.len(),
            });
        }
        if &bytes[..4] != b"regf" {
            let mut found = [0u8; 4];
            found.copy_from_slice(&bytes[..4]);
            return Err(HiveError::BadSignature {
                structure: "base block",
                offset: 0,
                expected: "regf",
                found,
            });
        }
        Ok(Self { bytes })
    }

    fn u32_at(&self, offset: usize) -> u32 {
        // Every call site is inside the base block, whose length was checked
        // before this type could exist.
        u32::from_le_bytes([
            self.bytes[offset],
            self.bytes[offset + 1],
            self.bytes[offset + 2],
            self.bytes[offset + 3],
        ])
    }

    /// `(primary, secondary)`. They differ when the hive was not cleanly
    /// flushed.
    pub fn sequence_numbers(&self) -> (u32, u32) {
        (self.u32_at(0x04), self.u32_at(0x08))
    }

    /// The hive's own last-written time, as a Windows FILETIME.
    pub fn last_written_filetime(&self) -> u64 {
        let lo = self.u32_at(0x0C) as u64;
        let hi = self.u32_at(0x10) as u64;
        (hi << 32) | lo
    }

    pub fn major_version(&self) -> u32 {
        self.u32_at(0x14)
    }

    pub fn minor_version(&self) -> u32 {
        self.u32_at(0x18)
    }

    /// 0 for a primary hive; the transaction-log files use other values.
    pub fn file_type(&self) -> u32 {
        self.u32_at(0x1C)
    }

    /// 1 for the only layout this format defines.
    pub fn file_format(&self) -> u32 {
        self.u32_at(0x20)
    }

    /// Offset of the root key node, relative to the start of hive-bin data.
    pub fn root_cell_offset(&self) -> u32 {
        self.u32_at(0x24)
    }

    /// How many bytes of hive-bin data the base block says follow it.
    pub fn declared_data_size(&self) -> usize {
        self.u32_at(0x28) as usize
    }

    /// How many bytes of hive-bin data the buffer actually holds.
    pub fn present_data_size(&self) -> usize {
        self.bytes.len() - BASE_BLOCK_BYTES
    }

    pub fn clustering_factor(&self) -> u32 {
        self.u32_at(0x2C)
    }

    /// The checksum stored in the base block.
    pub fn stored_checksum(&self) -> u32 {
        self.u32_at(0x1FC)
    }

    /// The checksum the base block's own first 508 bytes compute.
    ///
    /// XOR of those bytes as little-endian `u32`s, with the two values that
    /// would be ambiguous mapped away — 0 becomes 1 and `0xFFFFFFFF` becomes
    /// `0xFFFFFFFE`, so that a checksum field of 0 or all-ones always fails.
    pub fn computed_checksum(&self) -> u32 {
        let mut sum: u32 = 0;
        for chunk in self.bytes[..0x1FC].as_chunks::<4>().0 {
            sum ^= u32::from_le_bytes(*chunk);
        }
        match sum {
            0 => 1,
            0xFFFF_FFFF => 0xFFFF_FFFE,
            other => other,
        }
    }

    /// Full validation: every header check this reader makes.
    pub fn validate(&self) -> Result<()> {
        self.validate_allowing(Tolerances::default())
    }

    /// Validation with the named tolerances relaxed, and nothing else.
    ///
    /// A tolerance turns off exactly one check. The structural checks — the
    /// version, the file type and format, the clustering factor, the checksum,
    /// and the alignment of the declared data size — are never relaxed,
    /// because a hive that fails one of those is not an incomplete hive but a
    /// file that is not this format.
    pub fn validate_allowing(&self, tolerate: Tolerances) -> Result<()> {
        if self.major_version() != 1 {
            return Err(HiveError::Unsupported {
                field: "base block major version",
                value: self.major_version() as u64,
            });
        }
        // The specification lists 3, 4, 5 and 6 for a primary file. This
        // reader also accepts 1 and 2, which is where NT 3.x hives sit: their
        // structures are the ones below, and refusing them would lose evidence
        // to a version number rather than to anything unreadable. Anything
        // outside 1..=6 is refused, because at that point the layout is not
        // one this code has been written against.
        if !(1..=6).contains(&self.minor_version()) {
            return Err(HiveError::Unsupported {
                field: "base block minor version",
                value: self.minor_version() as u64,
            });
        }
        if self.file_type() != 0 {
            return Err(HiveError::Unsupported {
                field: "base block file type (0 is a primary hive)",
                value: self.file_type() as u64,
            });
        }
        if self.file_format() != 1 {
            return Err(HiveError::Unsupported {
                field: "base block file format",
                value: self.file_format() as u64,
            });
        }
        // Logical sector size divided by 512, so 1, 2, 4 or 8 for the sector
        // sizes that exist. Windows writes 1. It changes nothing about how the
        // structures below are read — bins are 4096-aligned either way — so
        // this check exists only to reject a buffer that is not a base block,
        // and it is deliberately not narrowed to 1: refusing a hive off a
        // 4K-native disk would lose every key in it over a field this reader
        // does not use.
        if !matches!(self.clustering_factor(), 1 | 2 | 4 | 8) {
            return Err(HiveError::Unsupported {
                field: "base block clustering factor",
                value: self.clustering_factor() as u64,
            });
        }

        let computed = self.computed_checksum();
        if computed != self.stored_checksum() {
            return Err(HiveError::ChecksumMismatch {
                expected: computed,
                found: self.stored_checksum(),
            });
        }

        let declared = self.declared_data_size();
        if declared == 0 || !declared.is_multiple_of(BIN_ALIGNMENT) {
            return Err(HiveError::InvalidSizeField {
                structure: "hive-bin data size",
                offset: 0x28,
                value: declared as u64,
            });
        }

        if !tolerate.dirty {
            let (primary, secondary) = self.sequence_numbers();
            if primary != secondary {
                return Err(HiveError::SequenceNumberMismatch { primary, secondary });
            }
        }

        if !tolerate.short_data && declared > self.present_data_size() {
            return Err(HiveError::InvalidSizeField {
                structure: "hive-bin data size",
                offset: 0x28,
                value: declared as u64,
            });
        }

        Ok(())
    }

    /// The hive-bin data: everything after the base block.
    ///
    /// Bounded by what the buffer holds, never by what the base block claims,
    /// so a hive cut short reads up to the cut and no further.
    pub(crate) fn data(&self) -> &'a [u8] {
        &self.bytes[BASE_BLOCK_BYTES..]
    }

    /// The contents of the cell at `offset`, without its size field.
    ///
    /// Every bound is checked here so that no structure above has to: an
    /// offset out of range, a size field that is not a sane multiple of eight,
    /// or a cell that runs past the end of the data is an error naming the
    /// cell, not a panic.
    pub(crate) fn cell_data(&self, offset: u32) -> Result<&'a [u8]> {
        let data = self.data();
        let start = offset as usize;
        if start.checked_add(4).is_none_or(|end| end > data.len()) {
            return Err(HiveError::CellOutOfBounds {
                offset,
                data_size: data.len(),
            });
        }
        let raw = i32::from_le_bytes([
            data[start],
            data[start + 1],
            data[start + 2],
            data[start + 3],
        ]);
        if raw >= 0 {
            return Err(HiveError::CellNotAllocated { offset });
        }
        let size = raw.unsigned_abs() as usize;
        if size < CELL_ALIGNMENT || !size.is_multiple_of(CELL_ALIGNMENT) {
            return Err(HiveError::InvalidSizeField {
                structure: "cell",
                offset: start,
                value: size as u64,
            });
        }
        let end = match start.checked_add(size) {
            Some(end) if end <= data.len() => end,
            _ => {
                return Err(HiveError::CellOutOfBounds {
                    offset,
                    data_size: data.len(),
                })
            }
        };
        Ok(&data[start + 4..end])
    }

    /// The hive's root key.
    /// Every distinct security descriptor in the hive.
    ///
    /// Walked from the root key's descriptor around the `sk` ring, which is how
    /// the descriptor population is enumerated without visiting every key: on
    /// `reference/plaso/test_data/SOFTWARE` that is 289 reads rather than
    /// 117,488.
    ///
    /// A hive that records no security at all yields an empty ring, which is an
    /// answer and not a failure. A ring that does not close yields what was
    /// read with `is_incomplete()` set, never a silently short population.
    pub fn security_descriptors(&self) -> Result<crate::security::SecurityRing<'a>> {
        let root = self.root_key_node()?;
        match root.security_offset() {
            Some(start) => crate::security::walk_ring(*self, start),
            None => crate::security::walk_ring_empty(),
        }
    }

    pub fn root_key_node(&self) -> Result<KeyNode<'a>> {
        KeyNode::from_cell_offset(*self, self.root_cell_offset())
    }

    /// Walk the hive's *unallocated* space for `nk`/`vk`-shaped cells: keys
    /// and values a deletion marked free but did not overwrite.
    ///
    /// This is the deliberate exception to the rule `cell_data` enforces
    /// everywhere else in this crate — that a cell whose size field says free
    /// is refused, not read. Nothing this returns can be produced
    /// by [`Self::root_key_node`]'s own iterators, and each result is
    /// labelled [`crate::unallocated::RecoveredCell`] so a caller cannot fold
    /// it into a live listing by accident. See the module for the labelling
    /// rule and [`crate::unallocated::UnallocatedCells::is_incomplete`] and
    /// [`crate::unallocated::UnallocatedCells::is_capped`] for the two ways a
    /// result can be short of every unallocated cell the hive holds.
    pub fn unallocated_cells(&self) -> crate::unallocated::UnallocatedCells<'a> {
        crate::unallocated::UnallocatedCells::new(*self)
    }
}
