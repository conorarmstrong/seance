//! Findings: the fifteen things that look wrong, ranked, each with the evidence
//! it rests on (`ROADMAP.md` §2.2).
//!
//! # Why a finding is not a record
//!
//! Every other artifact in this pipeline is a *transcription*: the MFT said
//! this, the registry held that. A finding is different in kind — it is this
//! tool's own claim that a pattern in the evidence is worth an examiner's
//! attention. `documentation/REPORTING_DESIGN.md` and Part VI of the roadmap
//! set the condition on anything of that sort: it may not be rendered beside a
//! parsed artifact as though the two were established the same way.
//!
//! So a [`Finding`] is built to keep two things apart that a "detection" would
//! normally merge:
//!
//! * the **observation** — the invariant that broke, stated as a fact, with the
//!   values it rests on. `$SI` modified is 2019-03-02T11:14:08Z and `$FN`
//!   modified is 2021-07-19T08:02:55Z. An examiner, or an opponent, can check
//!   that against the evidence and it will either hold or not.
//! * the **inference** — what the pattern may indicate. "A file's `$SI` times
//!   predating its `$FN` times is what backdating a file's metadata looks
//!   like." That is opinion: it is reached by reasoning that cannot be shown to
//!   a court step by step, and it is labelled, never asserted.
//!
//! A finding with no observation is not a finding. A finding whose inference is
//! presented as an observation is the failure this module exists to prevent.
//!
//! # And why every one carries a qualification
//!
//! Each finding names what it does **not** establish. A timestomp finding does
//! not establish that anyone timestomped anything: a restore from backup, an
//! archive extraction and a filesystem-level copy all reorder those timestamps
//! innocently. Saying so is not hedging — it is the difference between a lead
//! an examiner can act on and a conclusion an opponent can dismantle.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The metadata `type` discriminator every finding record carries, so the
/// record viewers, the search index and the pivot all group them as one kind.
pub const FINDING_RECORD_TYPE: &str = "Finding";

/// How strongly the evidence supports a finding.
///
/// Deliberately coarse. A numeric score (0.87) invites a reader to treat it as
/// a measurement, and nothing here measures anything — these are three
/// statements about how much room there is for an innocent explanation, and
/// three is as fine as the underlying reasoning actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The pattern has an ordinary explanation at least as likely as a
    /// suspicious one, and is surfaced because it is cheap to check, not
    /// because it is probably wrong. Ranked last.
    Weak,
    /// The pattern is unusual and worth explaining, but a legitimate cause is
    /// known and common.
    Notable,
    /// The pattern is hard to produce by ordinary use of the machine. Still a
    /// lead: "hard to produce innocently" is not "produced deliberately".
    Strong,
}

impl Confidence {
    /// Stable machine token, as stored and as the API reports it.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Weak => "weak",
            Confidence::Notable => "notable",
            Confidence::Strong => "strong",
        }
    }

    /// Rank for ordering, highest confidence first.
    pub fn rank(self) -> u8 {
        match self {
            Confidence::Strong => 0,
            Confidence::Notable => 1,
            Confidence::Weak => 2,
        }
    }
}

/// One checkable value a finding rests on.
///
/// Pairs rather than prose because these are what an examiner re-reads against
/// the evidence, and what an opponent will. "The two timestamps differ" is an
/// argument; `si_modified = 2019-03-02T11:14:08Z` is a fact with an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// What this value is, in the vocabulary of the artifact it came from.
    pub name: String,
    /// The value itself, rendered as the artifact holds it.
    pub value: String,
}

impl EvidenceItem {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// A pattern in the evidence worth an examiner's attention.
///
/// See the module documentation for why the observation and the inference are
/// separate fields and not one `description`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable machine token for the kind of finding: `timestomp`,
    /// `execution_of_absent_binary`, `pe_in_ads`. Never shown to a reader on
    /// its own; it is what a filter, a test and a citation use.
    pub kind: String,
    /// Short human label for a list: "Timestamps reordered on 4 files".
    pub title: String,
    /// The artifact this finding is about. Every finding has exactly one
    /// subject, so a triage list can always open the thing it names.
    pub subject_artifact: Uuid,
    /// How much room there is for an innocent explanation.
    pub confidence: Confidence,
    /// **The invariant that broke, as a fact.** Checkable against the evidence.
    pub observation: String,
    /// The values the observation rests on.
    pub evidence: Vec<EvidenceItem>,
    /// **What the pattern may indicate.** Opinion, and labelled as such
    /// wherever it is rendered. `None` where the observation speaks for itself
    /// and any reading of it would be this tool's invention.
    pub inference: Option<String>,
    /// What this finding does **not** establish, and the ordinary causes that
    /// would produce the same pattern. Never empty: a finding with nothing to
    /// qualify has not been thought about.
    pub qualification: String,
    /// Byte offset on the backing device, where the subject has one. `None`
    /// for a finding about something with no single location (a registry key
    /// spread across a hive, a cross-view inconsistency).
    pub device_offset: Option<u64>,
    /// The module that raised it, so a finding can be traced to the code that
    /// made the claim.
    pub source_module: String,
}

impl Finding {
    /// The metadata document for this finding's artifact.
    ///
    /// Written through one function so every finding record has the same shape
    /// — the viewers, the report and the export read one vocabulary — and so
    /// that the honesty fields cannot be forgotten by a new detection: the
    /// grade and the qualification are not optional here.
    pub fn to_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "type": FINDING_RECORD_TYPE,
            "finding_kind": self.kind,
            // `name` is what the generic record table and the search index
            // show for a row (LIVE-022), so it must be the human label.
            "name": self.title,
            "subject_artifact_id": self.subject_artifact.to_string(),
            "confidence": self.confidence.as_str(),
            "confidence_rank": self.confidence.rank(),
            "observation": self.observation,
            "evidence": self
                .evidence
                .iter()
                .map(|e| serde_json::json!({ "name": e.name, "value": e.value }))
                .collect::<Vec<_>>(),
            "inference": self.inference,
            "qualification": self.qualification,
            "device_offset": self.device_offset,
            "source_module": self.source_module,
            // Read by the report and by every screen that renders a finding.
            // A finding is this tool's own claim about the evidence, not a
            // transcription of it, and it may never be presented as though it
            // were (REPORTING_DESIGN.md; ROADMAP Part VI).
            "grade": "investigative_lead",
            "grade_note":
                "An investigative lead raised by Séance, not a transcription of the evidence. \
                 The observation is checkable against the artifact it names; any inference \
                 drawn from it is this tool's reading and is labelled as such. Read the \
                 qualification before relying on it.",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> Finding {
        Finding {
            kind: "timestomp".into(),
            title: "Timestamps reordered on notes.txt".into(),
            subject_artifact: Uuid::nil(),
            confidence: Confidence::Notable,
            observation: "$SI modified (2019-03-02T11:14:08Z) precedes $FN modified \
                          (2021-07-19T08:02:55Z)."
                .into(),
            evidence: vec![
                EvidenceItem::new("si_modified", "2019-03-02T11:14:08Z"),
                EvidenceItem::new("fn_modified", "2021-07-19T08:02:55Z"),
            ],
            inference: Some("This is what backdating a file's metadata looks like.".into()),
            qualification: "It is also what a restore from backup looks like.".into(),
            device_offset: Some(4096),
            source_module: "plugin.findings.timestomp".into(),
        }
    }

    #[test]
    fn confidence_ranks_strongest_first_and_round_trips() {
        assert!(Confidence::Strong.rank() < Confidence::Notable.rank());
        assert!(Confidence::Notable.rank() < Confidence::Weak.rank());
        // Ord on the enum is declaration order (Weak < Strong), which is the
        // opposite of display rank; callers must sort by `rank()`. Pinned so a
        // future reorder of the variants cannot silently invert a triage list.
        assert!(Confidence::Weak < Confidence::Strong);
        for c in [Confidence::Weak, Confidence::Notable, Confidence::Strong] {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Confidence>(&json).unwrap(), c);
        }
        assert_eq!(Confidence::Strong.as_str(), "strong");
    }

    /// The metadata a finding writes is what the viewers, the report and the
    /// export all read. The honesty fields are the point of the shape.
    #[test]
    fn a_finding_record_carries_its_grade_and_its_qualification() {
        let m = finding().to_metadata();
        assert_eq!(m["type"], FINDING_RECORD_TYPE);
        assert_eq!(m["finding_kind"], "timestomp");
        // The grade is fixed: a finding is never an observation of the
        // evidence, whatever a detection author might prefer.
        assert_eq!(m["grade"], "investigative_lead");
        assert!(m["grade_note"]
            .as_str()
            .unwrap()
            .contains("not a transcription"));
        // The observation and the inference stay separate, so a renderer
        // cannot present the second as the first.
        assert!(m["observation"].as_str().unwrap().contains("$SI modified"));
        assert!(m["inference"].as_str().unwrap().contains("backdating"));
        assert!(m["qualification"]
            .as_str()
            .unwrap()
            .contains("restore from backup"));
        // The values it rests on travel with it, addressable by name.
        let ev = m["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0]["name"], "si_modified");
        assert_eq!(ev[0]["value"], "2019-03-02T11:14:08Z");
        // `name` is the human label, because that is what a record table and
        // the search index show for the row.
        assert_eq!(m["name"], "Timestamps reordered on notes.txt");
        assert_eq!(m["confidence"], "notable");
        assert_eq!(m["confidence_rank"], 1);
        assert_eq!(m["device_offset"], 4096);
    }

    /// A finding about something with no single location says so rather than
    /// reporting offset 0, which is a real place on the device.
    #[test]
    fn an_unlocated_finding_reports_no_offset_rather_than_zero() {
        let mut f = finding();
        f.device_offset = None;
        f.inference = None;
        let m = f.to_metadata();
        assert!(m["device_offset"].is_null());
        assert!(m["inference"].is_null());
    }
}
