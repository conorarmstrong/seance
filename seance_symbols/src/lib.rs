//! Intermediate Symbol Format (ISF) type database for memory forensics.
//!
//! Given the bytes of an ISF JSON file, this crate yields a *validated* type
//! database: struct layouts, member offsets, enum values and kernel symbol
//! addresses. It has no dependency on the layer stack, so the highest-risk
//! subsystem in memory analysis is unit-testable without a memory image.
//!
//! # The two jobs, and the second is the important one
//!
//! Turning ISF JSON into a fast type database is mechanical. Proving that the
//! database describes *this* image is not, and it is why this crate exists as
//! its own thing:
//!
//! > A **wrong** symbol table does not crash and does not look wrong. It
//! > produces a full process list with plausible PIDs, plausible names and
//! > plausible timestamps, all of them garbage, because
//! > `_EPROCESS.UniqueProcessId` was read at the offset a *different* Windows
//! > build uses.
//!
//! Reading the right bytes against the wrong layout cannot be caught
//! downstream: the bytes were genuinely there. So every check in [`validate`]
//! ends in a refusal, never a warning, and a compiled table carries the whole
//! [`AdmissionReport`] so a report can state how far it was proved.
//!
//! # The pipeline
//!
//! ```text
//!    ISF bytes (.json / .json.gz / .json.xz)
//!         |
//!         |-- Stage A: IDENTIFY   one structural pass, no DOM, bounded memory
//!         |     -> IsfIdentity { os, identifier, format, producer, sha256, counts }
//!         |
//!         |-- Stage B: COMPILE    validate, then resolve into one flat arena
//!         |
//!         |-- Stage C: QUERY      member offsets, symbol addresses, enum names
//! ```
//!
//! Stage A ([`identify`]) runs against every candidate ISF while a lab indexes
//! its symbol packs. It answers "which of these describes this image?" without
//! parsing the file: a tens-of-megabyte ISF is walked once, structurally, and
//! only the `metadata` block and a named banner symbol are ever deserialised.
//!
//! Stage B ([`SymbolTable::compile`]) is where the gate runs. It happens at
//! most once per distinct file, and a table that fails is not returned in any
//! form.
//!
//! # Worked shape
//!
//! ```no_run
//! use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable, ValidationOptions};
//!
//! # fn main() -> seance_symbols::Result<()> {
//! let options = CompileOptions {
//!     validation: ValidationOptions::new()
//!         .expect_identifier("Linux version 6.1.0"), // recovered from the image
//!     ..CompileOptions::default()
//! };
//! let table = SymbolTable::compile_path(
//!     std::path::Path::new("vmlinux-6.1.0.json.xz"),
//!     &DecompressLimits::default(),
//!     &options,
//! )?;
//!
//! // An absent member is absent, never offset zero.
//! if table.has_member("task_struct", "cap_ambient") {
//!     let offset = table.member_offset("task_struct", "cap_ambient")?;
//!     let _ = offset;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What this crate refuses to do
//!
//! Nearest-build fallback; try-until-it-works across a pack of candidates;
//! built-in offset tables for common builds; synthesising a missing member as
//! `0`; zero-padding a short read behind a typed field; and admitting a table
//! at the examiner's insistence after a gate refused it. Each of those produces
//! output that enters the case record indistinguishable from verified output.
//!
//! # Fidelity note
//!
//! No copy of the Volatility 3 source tree was present in this repository when
//! this crate was written (`reference/volatility3/` does not exist), so the
//! model follows the documented shape of the Volatility 3 schema.
//! `.json.bz2` and `.zip` pack members are not implemented:
//! this crate has no bzip2 or zip dependency, and a container it cannot read is
//! reported as such rather than guessed at.
#![forbid(unsafe_code)]

pub(crate) mod base64;
pub mod error;
pub mod identify;
pub mod isf;
pub mod probe;
pub mod source;
pub mod table;
pub mod validate;

pub use error::{Result, SymbolError};
pub use identify::{
    identify, identify_path, identify_reader, normalize_banner, IdentifierSource, IdentifyOptions,
    IsfCounts, IsfIdentity,
};
pub use isf::{
    AggKind, Architecture, BaseKind, Endian, IsfDocument, IsfMetadata, IsfOs, Version,
    MAX_SUPPORTED_FORMAT, MIN_SUPPORTED_FORMAT,
};
pub use probe::{ImageProbe, ProbeError, ProbeResult};
pub use source::{
    load, load_path, load_slice, sha256_hex, Compression, DecompressLimits, IsfProvenance,
    IsfSource,
};
pub use table::{
    AggInfo, CompileOptions, Diagnostics, EnumInfo, Member, SymbolEntry, SymbolTable, TypeEntry,
    TypeId, TypeKind,
};
pub use validate::{
    AdmissionReport, AdmissionState, Gate, GateOutcome, GateResult, ValidationOptions,
};
