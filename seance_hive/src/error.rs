//! What this reader refuses, and what it says when it does.
//!
//! Every variant names the byte it is talking about. A hive that will not read
//! is a finding an examiner may have to explain, so "invalid hive" is not an
//! answer: the offset and the value that was there belong in the message.

use core::fmt;

/// A refusal, with the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiveError {
    /// The buffer is shorter than the structure being read.
    Truncated {
        /// What was being read when the buffer ran out.
        structure: &'static str,
        /// The offset the read needed.
        offset: usize,
        /// How many bytes the buffer actually holds.
        available: usize,
    },
    /// A signature field does not hold what it must.
    BadSignature {
        structure: &'static str,
        offset: usize,
        expected: &'static str,
        found: [u8; 4],
    },
    /// The base block's checksum does not match its first 508 bytes.
    ChecksumMismatch { expected: u32, found: u32 },
    /// The two sequence numbers differ: the hive was not cleanly flushed and
    /// its newest writes are still only in the transaction logs.
    ///
    /// Callers that would rather have a stale hive than no hive catch this
    /// variant by name, so it must stay distinguishable from every other
    /// header fault.
    SequenceNumberMismatch { primary: u32, secondary: u32 },
    /// A size or offset field is not one this format allows.
    ///
    /// Also the variant for a base block that declares more hive-bin data than
    /// the buffer holds, which callers catch by name to tolerate a truncated
    /// acquisition.
    InvalidSizeField {
        structure: &'static str,
        offset: usize,
        value: u64,
    },
    /// A header field holds a version, type or format this reader does not
    /// claim to understand. Refusing is the honest answer: reading it anyway
    /// would produce records nobody could stand over.
    Unsupported { field: &'static str, value: u64 },
    /// A cell offset points outside the hive-bin data.
    CellOutOfBounds { offset: u32, data_size: usize },
    /// A cell that should be in use is marked free.
    CellNotAllocated { offset: u32 },
    /// Structures point at each other in a cycle, or nest deeper than any real
    /// hive does. A registry read must terminate on hostile input.
    StructureTooDeep { limit: usize },
}

impl fmt::Display for HiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                structure,
                offset,
                available,
            } => write!(
                f,
                "{structure} needs byte {offset}, but the hive holds only {available} bytes"
            ),
            Self::BadSignature {
                structure,
                offset,
                expected,
                found,
            } => write!(
                f,
                "{structure} at offset {offset:#x} has signature {:?}, not {expected:?}",
                String::from_utf8_lossy(found)
            ),
            Self::ChecksumMismatch { expected, found } => write!(
                f,
                "base block checksum is {found:#010x}; its first 508 bytes compute {expected:#010x}"
            ),
            Self::SequenceNumberMismatch { primary, secondary } => write!(
                f,
                "sequence numbers differ ({primary} and {secondary}): the hive was not cleanly \
                 flushed and its newest writes may be in its transaction logs"
            ),
            Self::InvalidSizeField {
                structure,
                offset,
                value,
            } => write!(
                f,
                "{structure} at offset {offset:#x} declares size {value}, which this format does \
                 not allow"
            ),
            Self::Unsupported { field, value } => {
                write!(f, "{field} is {value}, which this reader does not support")
            }
            Self::CellOutOfBounds { offset, data_size } => write!(
                f,
                "cell offset {offset:#x} is outside the {data_size} bytes of hive-bin data"
            ),
            Self::CellNotAllocated { offset } => {
                write!(f, "the cell at offset {offset:#x} is marked free")
            }
            Self::StructureTooDeep { limit } => {
                write!(
                    f,
                    "hive structures nest deeper than {limit}; refusing to follow"
                )
            }
        }
    }
}

impl std::error::Error for HiveError {}

/// The crate's result type.
pub type Result<T> = core::result::Result<T, HiveError>;
