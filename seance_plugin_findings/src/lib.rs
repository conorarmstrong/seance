//! The findings / triage layer (`ROADMAP.md` §2.2).
//!
//! The jump from "2M parsed objects" to "the fifteen things that look wrong,
//! ranked, each with the evidence it rests on".
//!
//! # These modules detect nothing
//!
//! That is deliberate and it is the whole design. Every signal a finding rests
//! on is already established by the parser that read the evidence: the MFT
//! parser weighs the `$SI`/`$FN` asymmetry against the copies and renames that
//! produce it innocently, the PE plugin checks Authenticode and computes
//! section entropy, ASEP categorises an autostart. Those are transcriptions,
//! made by the code that understands the format.
//!
//! A detection module here **reads what a parser concluded and raises a lead**.
//! It never re-derives a signal, for two reasons. A second implementation of
//! the `$SI`/`$FN` rule would drift from the first, and the first is the one
//! with a measured false-positive rate against a real corpus (`HUNT-051`:
//! the naive rule flagged a sixth of a stock Windows XP install). And a
//! finding that disagreed with the record it points at would be indefensible
//! on the stand — two numbers for one fact, from one tool.
//!
//! # What a detection module owes
//!
//! Every [`Finding`] it raises carries its own grade, the values it rests on,
//! and what it does **not** establish. See [`seance_core::finding`] for why the
//! observation and the inference are separate fields, and why the
//! qualification is not optional.
#![forbid(unsafe_code)]

use seance_core::{
    artifact::{Artifact, ArtifactType},
    finding::Finding,
    module::ModuleError,
};
use uuid::Uuid;

mod asep;
pub mod cross_view;
mod hive;
mod kernel_tamper;
mod pe;
mod timestomp;
pub use asep::AsepFindings;
pub use hive::HiveFindings;
pub use kernel_tamper::{KernelTamperFindings, MODULE_ID as KERNEL_TAMPER_MODULE_ID};
pub use pe::PeFindings;
pub use timestomp::TimestompFindings;

#[cfg(test)]
mod asep_tests;
#[cfg(test)]
mod cross_view_tests;
#[cfg(test)]
mod hive_tests;
#[cfg(test)]
mod kernel_tamper_tests;
#[cfg(test)]
mod pe_tests;
#[cfg(test)]
mod tests;

/// Read a string from an artifact's metadata.
fn meta_str(artifact: &Artifact, key: &str) -> Option<String> {
    artifact
        .metadata
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// The subject a finding about this artifact should name.
///
/// A parsed record points at the file it was parsed from where it knows it, so
/// a triage list opens the file rather than the record about the file. Falls
/// back to the record itself, which is always openable.
fn subject_of(artifact: &Artifact) -> Uuid {
    artifact.parent_id.unwrap_or(artifact.id)
}

/// The backing-device offset a finding should carry, when the artifact knows
/// one. Absent is absent: offset 0 is a real place on the device and must
/// never stand in for "not known".
fn device_offset_of(artifact: &Artifact) -> Option<u64> {
    for key in [
        "device_offset",
        "physical_offset",
        "carving_offset_absolute",
        "offset",
    ] {
        if let Some(v) = artifact.metadata.get(key).and_then(|v| v.as_u64()) {
            return Some(v);
        }
    }
    None
}

/// Build the artifact that carries a finding.
///
/// A finding is a `ParsedRecord` like any other output, so it reaches the
/// database, the search index, the record viewers and the pivot through the
/// paths that already exist — the roadmap's "findings feed timeline and search
/// for free". Its `type` discriminator is what makes it a finding.
fn finding_artifact(case_id: Uuid, parent: Uuid, finding: &Finding) -> Artifact {
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        finding.to_metadata(),
    )
    .with_parent(parent)
}

/// Shared plumbing for a detection module: turn findings into artifacts.
fn emit(artifact: &Artifact, findings: Vec<Finding>) -> Result<Vec<Artifact>, ModuleError> {
    Ok(findings
        .iter()
        .map(|f| finding_artifact(artifact.case_id, artifact.id, f))
        .collect())
}

/// Re-exported so a detection module in another crate can use the same shape.
pub use seance_core::finding::FINDING_RECORD_TYPE;

/// Everything a detection module needs from this crate.
pub(crate) mod prelude {
    pub(crate) use super::{device_offset_of, emit, meta_str, subject_of};
    pub(crate) use seance_core::{
        artifact::{Artifact, ArtifactType},
        finding::{Confidence, EvidenceItem, Finding},
        module::{ForensicsModule, InputCapability, ModuleError},
    };
}
