//! Everything that can go wrong turning ISF bytes into a trusted type database.
//!
//! Every variant here exists because the alternative — a default, a zero, a
//! guess — would produce evidence. A symbol table that quietly substitutes `0`
//! for a member it could not find does not fail; it emits a full, plausible,
//! wrong process list. So each failure mode is named, carries the offending
//! type or member, and is returned rather than absorbed.

use crate::isf::Version;
use crate::validate::AdmissionReport;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, SymbolError>;

/// A failure loading, validating or querying an ISF symbol table.
#[derive(Debug, thiserror::Error)]
pub enum SymbolError {
    /// Reading the symbol file (or the memory image behind a probe) failed.
    #[error("reading the symbol file failed: {0}")]
    Io(#[from] std::io::Error),

    /// The bytes are not well-formed JSON, or a block does not deserialise into
    /// the ISF model. `context` names the block so an examiner is not left with
    /// "line 1 column 4,110,233" and nothing else.
    #[error("the symbol file is not valid ISF JSON ({context}): {source}")]
    Json {
        /// Which part of the document failed, in the examiner's terms.
        context: String,
        /// The underlying serde failure, with its line and column.
        #[source]
        source: serde_json::Error,
    },

    /// The document is syntactically fine but is not an ISF document, or a
    /// structure inside it is self-contradictory.
    #[error("the symbol file is not a usable ISF document: {0}")]
    Malformed(String),

    /// The declared ISF format version is one this reader does not implement.
    ///
    /// Below the floor, upstream *guesses* x86 versus x64 from base-type sizes;
    /// above the ceiling the schema may have changed in ways this reader would
    /// silently misread. Both are refused rather than approximated.
    #[error("ISF format version {found} is outside the supported range {floor} to {ceiling}")]
    UnsupportedFormat {
        /// The version the file declares.
        found: Version,
        /// Lowest version this reader implements.
        floor: Version,
        /// Highest version this reader implements.
        ceiling: Version,
    },

    /// A bounded resource was exhausted. Failing to load is correct behaviour;
    /// being OOM-killed halfway through a case is not.
    #[error("{what} exceeded its limit of {limit} bytes")]
    SizeLimit {
        /// What was being read or built.
        what: &'static str,
        /// The configured ceiling, in bytes.
        limit: u64,
    },

    /// A compressed symbol file expanded far beyond any plausible ratio, which
    /// is the classic decompression-bomb shape.
    #[error(
        "the symbol file expanded from {input} to {output} bytes, \
         a ratio of {ratio} beyond the permitted {limit}"
    )]
    CompressionRatio {
        /// Compressed input length.
        input: u64,
        /// Decompressed output length.
        output: u64,
        /// Observed expansion ratio.
        ratio: u64,
        /// Permitted expansion ratio.
        limit: u64,
    },

    /// The compiled arena would exceed the configured ceiling.
    #[error("the compiled symbol table needs about {needed} bytes, beyond the limit of {limit}")]
    TableTooLarge {
        /// Estimated arena size in bytes.
        needed: u64,
        /// Configured ceiling in bytes.
        limit: u64,
    },

    /// The admission gate refused the table. The report names every failing
    /// check, so the finding written into the case record can say precisely why
    /// no symbol-dependent analysis ran.
    #[error("the symbol table was refused by the admission gate: {0}")]
    Rejected(Box<AdmissionReport>),

    /// No type of that name exists in this table. Never substituted with a
    /// nearest match: there is no near-match tier anywhere in this crate.
    #[error("no type named '{0}' in this symbol table")]
    UnknownType(String),

    /// The type exists but has no such member. The caller must treat this as
    /// "this build does not have that field", never as offset zero.
    #[error("type '{type_name}' has no member named '{member}'")]
    UnknownMember {
        /// The aggregate that was searched.
        type_name: String,
        /// The member that was asked for.
        member: String,
    },

    /// The name resolves to more than one member, so it addresses none of them.
    ///
    /// Distinct from [`SymbolError::UnknownMember`] on purpose: that one says
    /// this build never had the field, and a caller is right to move on. This
    /// one says the field is there and the table cannot say which bytes are
    /// its, which is a damaged reading, not an absent one. Collapsing the two
    /// would report a member that exists as one that does not.
    #[error(
        "type '{type_name}' has {count} members named '{member}' once anonymous members are \
         lifted into it, so that name does not address any one of them"
    )]
    AmbiguousMember {
        /// The aggregate that was searched.
        type_name: String,
        /// The name that resolves to more than one member.
        member: String,
        /// How many members carry it.
        count: usize,
    },

    /// The named type exists but is not the kind of type the operation needs,
    /// e.g. asking for a member of a base type.
    // `expected` carries its own article, because the alternatives do not all
    // take the same one: "a pointer member" but "an array member". The template
    // supplying "a " produced "not a a pointer member" and "not a an array
    // member" on most of the callers (HUNT-083, found beside it).
    #[error("type '{name}' is a {actual}, not {expected}")]
    WrongTypeKind {
        /// The type that was looked up.
        name: String,
        /// What it actually is.
        actual: &'static str,
        /// What the operation required.
        expected: &'static str,
    },

    /// No symbol of that name exists in this table.
    #[error("no symbol named '{0}' in this symbol table")]
    UnknownSymbol(String),

    /// A type reference could not be bound during compilation, so nothing about
    /// its layout is known. Collected as a compile-time diagnostic and failed
    /// here at the point of use, rather than being discovered mid-plugin.
    #[error("type reference '{reference}' was never resolved (referenced by {referenced_by})")]
    UnresolvedType {
        /// The unresolved reference, including any `table!` prefix.
        reference: String,
        /// The type or symbol that referenced it.
        referenced_by: String,
    },

    /// The ISF gives function types no size, subtype, return type or argument
    /// list, so a pointer-to-function carries no signature. Stated as an error
    /// rather than answered with a plausible number.
    #[error("type '{0}' is opaque: the ISF gives function types no size and no signature")]
    OpaqueType(String),

    /// Arithmetic on a value taken from the file overflowed. Always an error:
    /// a wrapped or saturated offset is a wrong offset.
    #[error("arithmetic on an ISF-declared value overflowed: {0}")]
    Overflow(String),

    /// Reading through a candidate table from the memory image failed.
    #[error("reading {what} from the memory image failed: {detail}")]
    Probe {
        /// What was being read, in the examiner's terms.
        what: String,
        /// Why it could not be read.
        detail: String,
    },
}

impl SymbolError {
    /// Build a [`SymbolError::Json`] with the block name as context.
    pub fn json(context: impl Into<String>, source: serde_json::Error) -> Self {
        SymbolError::Json {
            context: context.into(),
            source,
        }
    }

    /// Build a [`SymbolError::Malformed`] from anything string-like.
    pub fn malformed(detail: impl Into<String>) -> Self {
        SymbolError::Malformed(detail.into())
    }

    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            SymbolError::Io(_) => "io",
            SymbolError::Json { .. } => "json",
            SymbolError::Malformed(_) => "malformed",
            SymbolError::UnsupportedFormat { .. } => "unsupported_format",
            SymbolError::SizeLimit { .. } => "size_limit",
            SymbolError::CompressionRatio { .. } => "compression_ratio",
            SymbolError::TableTooLarge { .. } => "table_too_large",
            SymbolError::Rejected(_) => "rejected",
            SymbolError::UnknownType(_) => "unknown_type",
            SymbolError::UnknownMember { .. } => "unknown_member",
            SymbolError::AmbiguousMember { .. } => "ambiguous_member",
            SymbolError::WrongTypeKind { .. } => "wrong_type_kind",
            SymbolError::UnknownSymbol(_) => "unknown_symbol",
            SymbolError::UnresolvedType { .. } => "unresolved_type",
            SymbolError::OpaqueType(_) => "opaque_type",
            SymbolError::Overflow(_) => "overflow",
            SymbolError::Probe { .. } => "probe",
        }
    }

    /// The admission report this error carries, if it was a gate rejection.
    pub fn report(&self) -> Option<&AdmissionReport> {
        match self {
            SymbolError::Rejected(report) => Some(report),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_member_names_both_the_type_and_the_member() {
        let err = SymbolError::UnknownMember {
            type_name: "_EPROCESS".into(),
            member: "UniqueProcessId".into(),
        };
        let text = err.to_string();
        assert!(text.contains("_EPROCESS"), "{text}");
        assert!(text.contains("UniqueProcessId"), "{text}");
        assert_eq!(err.class(), "unknown_member");
    }

    #[test]
    fn an_unsupported_format_states_the_range_it_fell_outside() {
        let err = SymbolError::UnsupportedFormat {
            found: Version::new(3, 9, 0),
            floor: crate::isf::MIN_SUPPORTED_FORMAT,
            ceiling: crate::isf::MAX_SUPPORTED_FORMAT,
        };
        let text = err.to_string();
        assert!(text.contains("3.9.0"), "{text}");
        assert!(text.contains("4.0.0"), "{text}");
        assert!(text.contains("6.3.0"), "{text}");
    }

    #[test]
    fn an_opaque_function_type_is_an_error_not_a_size_of_zero() {
        let err = SymbolError::OpaqueType("void ()".into());
        assert!(err.to_string().contains("no size"));
        assert_eq!(err.class(), "opaque_type");
    }
}
