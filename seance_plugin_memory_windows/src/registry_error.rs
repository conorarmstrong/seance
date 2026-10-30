//! [`RegistryError`]: why a registry structure in memory could not be read, in
//! terms an artifact and a witness statement can both carry.
//!
//! The registry is the part of a Windows memory image where a quiet failure is
//! most expensive. A key that was not found because its subkey-list cell was
//! paged out looks exactly like a key that never existed; a value that decoded
//! to an empty string because its data cell was unavailable looks exactly like
//! a value the suspect cleared. Every variant here exists to keep one of those
//! pairs apart, and each maps onto an [`IncompleteReason`] so the distinction
//! survives into the record rather than dying in a log line.
//!
//! Upstream Volatility catches `InvalidAddressException` around most registry
//! reads and continues with a default — a zero-padded buffer, a root cell of
//! `0x20`, a skipped subkey. That is the right trade for a triage tool and the
//! wrong one for evidence, so nothing in this module does it.

use seance_core::io::IncompleteReason;
use seance_memory::layer::MemoryHole;
use seance_memory::meta::Incomplete;
use seance_memory::object::ObjError;
use seance_symbols::SymbolError;

/// A registry structure could not be read, or could be read and is not what it
/// claims to be.
///
/// Never returned alongside a partial value. A half-read `_CM_KEY_VALUE` is not
/// a value with some fields missing, it is a value whose fields cannot be
/// trusted at all, because the ones that did read came from the same bytes as
/// the ones that did not.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A typed read through the object model failed: a member this build does
    /// not have, bytes that were never acquired, or arithmetic that would have
    /// wrapped.
    ///
    /// Carries the underlying [`ObjError`] intact so the exact unmapped range
    /// and the exact member name both reach the examiner.
    #[error(transparent)]
    Obj(#[from] ObjError),

    /// The structure at this address does not carry `0xBEE0BEE0` in
    /// `_HHIVE.Signature`, so it is not a hive.
    ///
    /// A wrong answer here is a whole tree of registry keys attributed to a
    /// structure that was never a hive, so this is refused rather than parsed
    /// hopefully.
    #[error(
        "the structure at {address:#x} declares the hive signature {found:#010x}, not \
         {expected:#010x}, so it is not a _CMHIVE"
    )]
    HiveSignature {
        /// Address of the candidate `_CMHIVE`.
        address: u64,
        /// The signature actually found.
        found: u64,
        /// The signature a hive carries.
        expected: u64,
    },

    /// A cell index points past the end of the store it selects.
    ///
    /// The hive's own `_DUAL.Length` says how far the store runs; an index
    /// beyond it addresses nothing, and translating it anyway would land on
    /// whatever `_HMAP_TABLE` entry happened to be there.
    #[error(
        "cell index {index:#010x} lies {past} byte(s) past the end of the {store} store, \
         which is {length:#x} byte(s) long"
    )]
    CellOutOfRange {
        /// The cell index as it was read, including the store bit.
        index: u32,
        /// `"stable"` or `"volatile"`.
        store: &'static str,
        /// The store's declared length.
        length: u64,
        /// How far past the end the index lies.
        past: u64,
    },

    /// The hive's storage map has no entry for this cell index.
    ///
    /// The `_HMAP_DIRECTORY` slot or the `_HMAP_TABLE` entry it names is null,
    /// which means the bin this index belongs to is not mapped in this hive.
    #[error("the hive's storage map has no bin for cell index {index:#010x}: {detail}")]
    UnmappedCell {
        /// The cell index that could not be translated.
        index: u32,
        /// Which part of the map was empty.
        detail: String,
    },

    /// A cell carries a signature this reader does not know.
    ///
    /// Reported rather than skipped: an unknown signature in the middle of a
    /// subkey list means either the cell is not what the list said it was, or
    /// this build uses a cell type Séance does not decode. Both are findings.
    #[error("the cell at index {index:#010x} carries the signature {signature}, which is not a registry cell this reader decodes")]
    UnknownCell {
        /// The cell index.
        index: u32,
        /// The two signature bytes, rendered printably.
        signature: String,
    },

    /// A cell is a valid registry cell of the wrong kind.
    #[error(
        "the cell at index {index:#010x} is a '{found}' cell, where a {expected} was required"
    )]
    WrongCell {
        /// The cell index.
        index: u32,
        /// The signature that was found.
        found: String,
        /// What the caller needed.
        expected: &'static str,
    },

    /// A bound fired. The work stopped; the registry did not.
    #[error("{what} exceeded its cap of {cap}")]
    Cap {
        /// What was being bounded.
        what: &'static str,
        /// The cap that fired.
        cap: u64,
    },

    /// A value marked as stored inline declares more data than fits inline.
    ///
    /// The inline form stores the data in the four bytes of `_CM_KEY_VALUE.Data`
    /// itself. A declared length above four means the high bit was set on a
    /// length that was never an inline length, and reading `Data` as a cell
    /// index instead would follow a number that is not an address.
    #[error("an inline registry value declares {length} byte(s) of data, and only 4 fit inside the cell")]
    InlineTooLong {
        /// The declared inline length, with the inline bit already stripped.
        length: u64,
    },

    /// A key path names a key that is not there.
    ///
    /// `found` is how far the walk got, so an examiner can tell "the path is
    /// wrong" from "the path is right and this machine did not have that key".
    ///
    /// `certainty` is the part that matters in a report. A key that is missing
    /// from a subkey index that was read **in full** is a key the machine did
    /// not have. A key that is missing from an index whose cells were partly
    /// paged out is a key that *may* have been there, and reporting the two the
    /// same way turns a gap in the acquisition into a statement about the
    /// suspect's machine.
    #[error("no subkey named '{missing}' under '{found}': {certainty}")]
    KeyNotFound {
        /// The path prefix that did resolve.
        found: String,
        /// The first component that did not.
        missing: String,
        /// Whether the search that failed was itself complete.
        certainty: &'static str,
    },

    /// Arithmetic on a cell index or a hive-space address overflowed.
    ///
    /// Always an error: a wrapped cell index selects the other store, and every
    /// key read through it comes from the wrong half of the hive.
    #[error("arithmetic on a cell index or a hive-space address overflowed: {0}")]
    Overflow(String),

    /// The structure read is self-contradictory in a way that has no other
    /// variant: a declared count that cannot be right, a symbol table that
    /// describes a registry type the format does not permit.
    #[error("{0}")]
    Malformed(String),
}

impl From<SymbolError> for RegistryError {
    fn from(err: SymbolError) -> Self {
        RegistryError::Obj(ObjError::Symbols(err))
    }
}

impl RegistryError {
    /// The unmapped range this failure was caused by, if it was caused by one.
    ///
    /// Lets a caller record the exact bytes the acquisition never held rather
    /// than only that a key could not be read.
    pub fn hole(&self) -> Option<MemoryHole> {
        match self {
            RegistryError::Obj(err) => err.hole(),
            _ => None,
        }
    }

    /// How the artifact should record this failure.
    ///
    /// The mapping is the point of the type: "the page was never acquired"
    /// ([`IncompleteReason::ShortRead`]), "this build has no such member"
    /// ([`IncompleteReason::UnresolvedStructure`]) and "we stopped counting"
    /// ([`IncompleteReason::CapReached`]) are three different things to say in
    /// a report, and collapsing them loses the only information an examiner can
    /// act on.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            RegistryError::Obj(err) => err.incomplete_reason(),
            RegistryError::Cap { .. } => IncompleteReason::CapReached,
            RegistryError::HiveSignature { .. }
            | RegistryError::CellOutOfRange { .. }
            | RegistryError::UnmappedCell { .. }
            | RegistryError::UnknownCell { .. }
            | RegistryError::WrongCell { .. }
            | RegistryError::InlineTooLong { .. }
            | RegistryError::KeyNotFound { .. }
            | RegistryError::Overflow(_)
            | RegistryError::Malformed(_) => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as an [`Incomplete`], ready to attach to an artifact.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            RegistryError::Obj(err) => err.class(),
            RegistryError::HiveSignature { .. } => "hive_signature",
            RegistryError::CellOutOfRange { .. } => "cell_out_of_range",
            RegistryError::UnmappedCell { .. } => "unmapped_cell",
            RegistryError::UnknownCell { .. } => "unknown_cell",
            RegistryError::WrongCell { .. } => "wrong_cell",
            RegistryError::Cap { .. } => "cap",
            RegistryError::InlineTooLong { .. } => "inline_too_long",
            RegistryError::KeyNotFound { .. } => "key_not_found",
            RegistryError::Overflow(_) => "overflow",
            RegistryError::Malformed(_) => "malformed",
        }
    }
}

/// Render two signature bytes printably, for an error message an examiner can
/// match against a hex dump.
///
/// ASCII bytes come back as themselves because every signature the format
/// defines is ASCII (`nk`, `vk`, `lf`, `lh`, `li`, `ri`, `sk`, `db`); anything
/// else comes back as hex, because a signature that is not ASCII is the whole
/// point of the message.
pub fn render_signature(bytes: [u8; 2]) -> String {
    if bytes.iter().all(|b| b.is_ascii_graphic()) {
        format!("'{}{}'", bytes[0] as char, bytes[1] as char)
    } else {
        format!("{:#04x} {:#04x}", bytes[0], bytes[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_paged_out_registry_cell_is_reported_as_a_short_read_carrying_its_range() {
        let hole = MemoryHole::unmapped(0xE1EC_D000, 0x1000);
        let err = RegistryError::from(ObjError::Hole(hole));
        assert_eq!(err.hole(), Some(hole));
        assert_eq!(err.incomplete_reason(), IncompleteReason::ShortRead);
        assert_eq!(err.class(), "hole");
    }

    #[test]
    fn a_missing_member_is_an_unresolved_structure_not_a_cell_that_was_absent() {
        let err = RegistryError::from(SymbolError::UnknownMember {
            type_name: "_CMHIVE".into(),
            member: "FileFullPath".into(),
        });
        assert_eq!(
            err.incomplete_reason(),
            IncompleteReason::UnresolvedStructure
        );
        assert!(err.to_string().contains("FileFullPath"), "{err}");
    }

    #[test]
    fn every_variant_names_a_class_and_an_incomplete_reason() {
        // A failure with no reason becomes a key that quietly never appeared.
        let cases = [
            RegistryError::HiveSignature {
                address: 0xE1EC_D008,
                found: 0,
                expected: 0xBEE0_BEE0,
            },
            RegistryError::CellOutOfRange {
                index: 0x0000_4000,
                store: "stable",
                length: 0x3000,
                past: 0x1000,
            },
            RegistryError::UnmappedCell {
                index: 0x20,
                detail: "the directory slot is null".into(),
            },
            RegistryError::UnknownCell {
                index: 0x20,
                signature: "'zz'".into(),
            },
            RegistryError::WrongCell {
                index: 0x20,
                found: "'vk'".into(),
                expected: "a key node",
            },
            RegistryError::Cap {
                what: "subkeys",
                cap: 65_536,
            },
            RegistryError::InlineTooLong { length: 9 },
            RegistryError::KeyNotFound {
                found: "ROOT".into(),
                missing: "Software".into(),
                certainty: "the index was read in full",
            },
            RegistryError::Overflow("a cell index".into()),
            RegistryError::Malformed("a count of zero".into()),
        ];
        for case in cases {
            assert!(!case.class().is_empty());
            let incomplete = case.to_incomplete();
            assert!(!incomplete.detail.is_empty(), "{case}");
            assert!(case.hole().is_none(), "{case}");
        }
    }

    #[test]
    fn a_cap_is_reported_as_a_cap_so_it_is_never_read_as_the_end_of_the_keys() {
        let err = RegistryError::Cap {
            what: "subkeys of one key",
            cap: 65_536,
        };
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
        assert!(err.to_string().contains("65536"), "{err}");
    }

    #[test]
    fn a_signature_renders_printably_when_it_is_ascii_and_as_hex_when_it_is_not() {
        assert_eq!(render_signature(*b"nk"), "'nk'");
        assert_eq!(render_signature([0x00, 0xFF]), "0x00 0xff");
    }
}
