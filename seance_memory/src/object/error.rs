//! [`ObjError`]: why a typed read could not be made, in terms an artifact can
//! carry.
//!
//! Every variant here exists because the alternative is a row that silently
//! never appears. A plugin that skipped a process because one member landed in
//! an unmapped page produces a process list that is *short* and looks
//! *complete*, and no reader of the report can tell the difference. So each
//! failure names what could not be read and maps onto an
//! [`IncompleteReason`] that travels onto the artifact:
//!
//! | Failure | `IncompleteReason` | What the examiner learns |
//! |---|---|---|
//! | The symbol table has no such type or member | `UnresolvedStructure` | This build does not have that field |
//! | The bytes are in a memory hole | `ShortRead` | Those bytes were never acquired |
//! | The address space ends first | `ShortRead` | The evidence stops there |
//! | A cap fired | `CapReached` | We stopped, the data did not |

use std::io;

use seance_core::io::IncompleteReason;
use seance_symbols::SymbolError;

use crate::layer::{LayerError, MemoryHole};
use crate::meta::Incomplete;

/// A typed read through the object model could not be completed.
///
/// Never returned alongside a value: there is no partial success here, because
/// a structure half-read is a structure whose fields cannot be trusted.
#[derive(Debug, thiserror::Error)]
pub enum ObjError {
    /// The symbol table could not answer: no such type, no such member, an
    /// unresolved type reference, or a member that is not the kind of thing the
    /// operation needs.
    ///
    /// This is the "this build does not have that field" error, and it must
    /// never be turned into offset zero by a caller.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// The bytes the read needed have nothing behind them in the acquisition.
    ///
    /// Carries the exact unmapped range, so the artifact can record *which*
    /// bytes were missing rather than only that something failed.
    #[error(transparent)]
    Hole(#[from] MemoryHole),

    /// The address space ended before the read was satisfied.
    ///
    /// Distinct from [`ObjError::Hole`]: nothing is missing from inside the
    /// evidence, the evidence simply stops here.
    #[error("{what} at {address:#x} needs {length} byte(s), and the address space ends first")]
    Truncated {
        /// What was being read, in the examiner's terms.
        what: String,
        /// Where the read started.
        address: u64,
        /// How many bytes it needed.
        length: u64,
    },

    /// The address is above the top of the address space, so there is no such
    /// address at all — as opposed to an address whose bytes were not captured.
    #[error("address {address:#x} is above the top of the address space ({max_address:#x})")]
    AboveAddressSpace {
        /// The address that was asked for.
        address: u64,
        /// The highest addressable byte in the layer.
        max_address: u64,
    },

    /// The underlying source failed for an ordinary I/O reason.
    #[error("reading {what} at {address:#x} failed: {source}")]
    Io {
        /// What was being read.
        what: String,
        /// Where the read started.
        address: u64,
        /// The underlying failure.
        source: io::Error,
    },

    /// The memory layer refused the request for a structural reason that is
    /// neither a hole nor an out-of-range address.
    #[error(transparent)]
    Layer(LayerError),

    /// Arithmetic on an address or an ISF-declared offset overflowed.
    ///
    /// Always an error: a wrapped address is a wrong address, and following one
    /// would read a structure out of an unrelated part of memory.
    #[error("arithmetic on an address or an ISF-declared offset overflowed: {0}")]
    Overflow(String),

    /// A bound was reached. The work stopped; the data did not run out.
    #[error("{what} exceeded its cap of {cap}")]
    Cap {
        /// What was being bounded.
        what: &'static str,
        /// The cap that fired.
        cap: u64,
    },

    /// An array index is outside the element count the symbol table declares.
    ///
    /// Refused rather than clamped: reading element 40 of a 16-element array
    /// returns whatever follows the array, and it parses.
    #[error("index {index} is outside '{type_name}.{member}', which has {count} element(s)")]
    IndexOutOfBounds {
        /// The aggregate the array belongs to.
        type_name: String,
        /// The array member.
        member: String,
        /// The index that was asked for.
        index: u64,
        /// The count the symbol table declares.
        count: u64,
    },

    /// A pointer type declares a width that is neither 4 nor 8 bytes, so the
    /// document does not describe any addressable machine.
    #[error("{what} declares a pointer width of {size} byte(s), which is neither 4 nor 8")]
    PointerWidth {
        /// What declared it.
        what: String,
        /// The declared width.
        size: u64,
    },

    /// A list walk reached an address it had already visited.
    ///
    /// The list is either corrupt or was being modified while the image was
    /// acquired. Either way the walk stops here rather than looping forever or
    /// reporting the same entry twice.
    #[error("the list link at {address:#x} was already visited: the list does not terminate")]
    Cycle {
        /// The address the walk returned to.
        address: u64,
    },

    /// A list link was null where the list structure requires one.
    #[error("the forward link read from {address:#x} is null, so the list does not close")]
    NullLink {
        /// The link whose forward pointer was null.
        address: u64,
    },
}

impl ObjError {
    /// Classify an [`io::Error`] raised by a layer read into the right variant,
    /// preserving a [`MemoryHole`] payload rather than flattening it.
    ///
    /// `length` and `what` describe the read that failed, so the error names the
    /// field an examiner asked for rather than an anonymous byte range.
    pub fn from_read(address: u64, length: u64, what: &str, err: io::Error) -> Self {
        if let Some(hole) = MemoryHole::from_io(&err) {
            return ObjError::Hole(hole);
        }
        if err.kind() == io::ErrorKind::UnexpectedEof {
            return ObjError::Truncated {
                what: what.to_string(),
                address,
                length,
            };
        }
        ObjError::Io {
            what: what.to_string(),
            address,
            source: err,
        }
    }

    /// The unmapped range this failure was caused by, if it was caused by one.
    ///
    /// Lets a caller record the exact bytes the acquisition never held, instead
    /// of only knowing that a field could not be read.
    pub fn hole(&self) -> Option<MemoryHole> {
        match self {
            ObjError::Hole(hole) => Some(*hole),
            ObjError::Layer(err) => err.hole(),
            _ => None,
        }
    }

    /// The [`IncompleteReason`] a caller stamps onto the artifact this read was
    /// feeding.
    ///
    /// The mapping is the point of the whole type: a failure here must survive
    /// into the record as a stated gap, never as a row that quietly never
    /// appeared.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            ObjError::Hole(_)
            | ObjError::Truncated { .. }
            | ObjError::AboveAddressSpace { .. }
            | ObjError::Io { .. }
            | ObjError::Layer(_) => IncompleteReason::ShortRead,
            ObjError::Cap { .. } => IncompleteReason::CapReached,
            ObjError::Symbols(_)
            | ObjError::Overflow(_)
            | ObjError::IndexOutOfBounds { .. }
            | ObjError::PointerWidth { .. }
            | ObjError::Cycle { .. }
            | ObjError::NullLink { .. } => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as an [`Incomplete`], ready to attach to layer metadata or
    /// an artifact.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            ObjError::Symbols(_) => "symbols",
            ObjError::Hole(_) => "hole",
            ObjError::Truncated { .. } => "truncated",
            ObjError::AboveAddressSpace { .. } => "above_address_space",
            ObjError::Io { .. } => "io",
            ObjError::Layer(_) => "layer",
            ObjError::Overflow(_) => "overflow",
            ObjError::Cap { .. } => "cap",
            ObjError::IndexOutOfBounds { .. } => "index_out_of_bounds",
            ObjError::PointerWidth { .. } => "pointer_width",
            ObjError::Cycle { .. } => "cycle",
            ObjError::NullLink { .. } => "null_link",
        }
    }
}

impl From<LayerError> for ObjError {
    /// Unwrap the two layer failures that have a precise meaning here, so a
    /// caller can still ask [`ObjError::hole`] and get an answer, and keep the
    /// rest intact rather than flattening them into a string.
    fn from(err: LayerError) -> Self {
        match err {
            LayerError::Hole(hole) => ObjError::Hole(hole),
            LayerError::OutOfRange {
                address,
                max_address,
            } => ObjError::AboveAddressSpace {
                address,
                max_address,
            },
            other => ObjError::Layer(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::HoleReason;

    #[test]
    fn a_hole_reaches_the_caller_with_the_range_it_could_not_read() {
        let hole = MemoryHole {
            address: 0xFFFF_8000_0000_2000,
            length: 0x1000,
            reason: HoleReason::SwappedOut,
        };
        let err = ObjError::from_read(0xFFFF_8000_0000_2000, 8, "_EPROCESS.Peb", hole.into_io());
        assert_eq!(err.hole(), Some(hole));
        assert_eq!(err.class(), "hole");
        assert_eq!(err.incomplete_reason(), IncompleteReason::ShortRead);
    }

    #[test]
    fn the_end_of_the_evidence_is_not_mistaken_for_a_hole() {
        let err = ObjError::from_read(
            0x3FF8,
            8,
            "task_struct.pid",
            io::Error::new(io::ErrorKind::UnexpectedEof, "short read"),
        );
        assert!(err.hole().is_none(), "EOF is not an unmapped region");
        assert_eq!(err.class(), "truncated");
        assert!(err.to_string().contains("task_struct.pid"), "{err}");
    }

    #[test]
    fn an_ordinary_io_failure_stays_an_io_failure() {
        let err = ObjError::from_read(0x1000, 4, "a member", io::Error::other("disk on fire"));
        assert_eq!(err.class(), "io");
        assert!(err.hole().is_none());
        assert_eq!(err.incomplete_reason(), IncompleteReason::ShortRead);
    }

    #[test]
    fn a_missing_member_is_an_unresolved_structure_not_a_short_read() {
        // The distinction that stops "this build has no such field" from being
        // reported as "the bytes were missing".
        let err = ObjError::from(SymbolError::UnknownMember {
            type_name: "_EPROCESS".into(),
            member: "UniqueProcessId".into(),
        });
        assert_eq!(err.class(), "symbols");
        assert_eq!(
            err.incomplete_reason(),
            IncompleteReason::UnresolvedStructure
        );
        assert!(err.to_string().contains("UniqueProcessId"), "{err}");
    }

    #[test]
    fn a_cap_is_reported_as_a_cap_so_nobody_reads_it_as_the_end_of_the_data() {
        let err = ObjError::Cap {
            what: "list entries",
            cap: 65_536,
        };
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
        let incomplete = err.to_incomplete();
        assert_eq!(incomplete.reason, IncompleteReason::CapReached);
        assert!(incomplete.detail.contains("65536"), "{}", incomplete.detail);
    }

    #[test]
    fn a_layer_error_keeps_its_hole_and_its_out_of_range_meaning() {
        let hole = MemoryHole::unmapped(0x2000, 0x1000);
        let err = ObjError::from(LayerError::Hole(hole));
        assert_eq!(err.hole(), Some(hole));

        let err = ObjError::from(LayerError::OutOfRange {
            address: 0x1_0000,
            max_address: 0x3FFF,
        });
        assert_eq!(err.class(), "above_address_space");
        assert!(err.hole().is_none(), "past the top is not a hole");

        let err = ObjError::from(LayerError::EmptySource);
        assert_eq!(err.class(), "layer");
    }

    #[test]
    fn every_variant_names_an_incomplete_reason() {
        // A failure with no reason would become a silently dropped row.
        let cases = [
            ObjError::Overflow("offset".into()),
            ObjError::IndexOutOfBounds {
                type_name: "proc".into(),
                member: "slots".into(),
                index: 9,
                count: 4,
            },
            ObjError::PointerWidth {
                what: "pointer".into(),
                size: 2,
            },
            ObjError::Cycle { address: 0x1000 },
            ObjError::NullLink { address: 0x1000 },
            ObjError::AboveAddressSpace {
                address: 0x1_0000,
                max_address: 0xFFF,
            },
        ];
        for case in cases {
            let incomplete = case.to_incomplete();
            assert!(!incomplete.detail.is_empty(), "{case}");
            assert!(!case.class().is_empty());
        }
    }
}
