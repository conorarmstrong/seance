//! What a memory analysis stage is called, on the wire and in the coverage
//! view.
//!
//! Lifted out of the Windows tier so the Linux and macOS tiers file their
//! findings under the same identity, and so the build binding can name the
//! stage in a failure without depending on any one OS crate.

use serde_json::json;

/// Record type of the manifest an analysis publishes alongside its findings,
/// listing every stage that build could have run.
///
/// # Why the manifest exists
///
/// `seance_api::memory::get_memory_coverage` has its own stage table, because
/// the API crate deliberately does not depend on the analysis crates. Two
/// tables drift, and when they did the Coverage lens went silent about seven
/// stages that ran — silence an examiner reads as "nothing to find". Coverage
/// reads a record of this type and gives a row to every stage named in it,
/// describing an unfamiliar one in the analysis's own words, so a stage added
/// to a tier's stage table reaches the examiner on the day it is added.
///
/// # The consumer, so this can be checked rather than believed
///
/// `GET /api/v1/cases/:id/memory/coverage` (routed in `seance_api::lib` to
/// `seance_api::memory::get_memory_coverage`) fetches records of this type and
/// hands them to `seance_api::memory::declared_stages`, which reads each entry
/// of the `stages` array by the field names [`StageId::to_json`] writes:
/// `stage`, `record_type`, `per_process` and `describes`. Renaming any of them
/// on this side does not fail a build; it makes the coverage row for a stage
/// the API does not know about silently disappear, or arrive with nothing said
/// about what the stage establishes.
pub const MEMORY_STAGE_MANIFEST_RECORD: &str = "MemoryStageManifest";

/// One analysis stage's identity on the wire.
///
/// Three facts used to be written out separately at every emit site: the stage
/// label, the record type, and whether the stage produces one record per
/// process. When they drifted apart nothing failed — the analysis ran, wrote
/// its records, and the API served `did_not_run` over them, because it was
/// looking for a record type the analysis had stopped emitting under a stage
/// name it had never used. Binding the three together means an emit site cannot
/// name one without the others.
///
/// # What an examiner learns
///
/// Indirectly, everything: this is the identity every memory finding is filed
/// under, and the key the coverage view answers "did this run?" against. A
/// wrong answer here does not corrupt a finding, it hides one — the analysis
/// reports a hidden DLL and the screen says the DLL stage never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageId {
    /// Stable key. The same string the API's coverage table keys this stage on,
    /// and the value carried in each record's `stage` field.
    pub key: &'static str,
    /// `type` / `record_type` of the records this stage emits on success.
    pub record_type: &'static str,
    /// Whether the stage emits one record per process, tagged with that
    /// process's id, rather than one record for the whole image.
    pub per_process: bool,
    /// What an examiner learns from this stage, in one sentence.
    pub describes: &'static str,
}

impl StageId {
    /// One stage's identity.
    ///
    /// `const` so a tier can declare its stage table as a `const` slice and a
    /// [`crate::binding::MemberSet`] can name the stage it belongs to without
    /// any runtime construction.
    pub const fn new(
        key: &'static str,
        record_type: &'static str,
        per_process: bool,
        describes: &'static str,
    ) -> Self {
        Self {
            key,
            record_type,
            per_process,
            describes,
        }
    }

    /// Serializable form, for the stage manifest.
    ///
    /// The four field names are the contract described on
    /// [`MEMORY_STAGE_MANIFEST_RECORD`]. Renaming one hides a stage from
    /// Coverage without failing anything.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "stage": self.key,
            "record_type": self.record_type,
            "per_process": self.per_process,
            "describes": self.describes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: StageId = StageId::new(
        "pool_scan",
        "MemoryPoolScan",
        false,
        "Process objects found by scanning the kernel pool.",
    );

    /// The coverage reader looks the manifest rows up by these exact names. A
    /// rename here is invisible to a build and blanks a coverage row.
    #[test]
    fn the_manifest_row_uses_the_field_names_the_coverage_reader_looks_for() {
        let json = DEMO.to_json();
        assert_eq!(json["stage"], "pool_scan");
        assert_eq!(json["record_type"], "MemoryPoolScan");
        assert_eq!(json["per_process"], false);
        assert!(json["describes"]
            .as_str()
            .is_some_and(|text| text.contains("kernel pool")));
    }

    #[test]
    fn a_stage_id_is_const_constructible_so_a_tier_can_declare_a_table() {
        const TABLE: &[StageId] = &[DEMO];
        assert_eq!(TABLE[0].key, "pool_scan");
    }
}
