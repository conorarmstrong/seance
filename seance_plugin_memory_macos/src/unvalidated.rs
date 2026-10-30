//! The marker every record this crate emits must carry.
//!
//! # Why this module exists at all
//!
//! No macOS memory image and no macOS oracle was available anywhere in this
//! repository when this tier was written. Every line of it was derived from the
//! Kernel Debug Kit symbol packs under
//! `reference/volatility3/volatility3/symbols` and from Volatility 3's macOS
//! plugins read as source. Not one result has ever been compared against a
//! capture of a real Mac.
//!
//! That is a fact about the *tool*, and an examiner cannot infer it from the
//! output. A process list produced by unvalidated code looks exactly like a
//! process list produced by code that has been run against a hundred images —
//! same fields, same plausible PIDs, same plausible names. In a report that
//! difference is the whole question, so it travels on the record rather than in
//! a changelog nobody reads at 2am.
//!
//! # The rule
//!
//! **Every artifact this crate emits carries [`unvalidated_stamp`].** Four
//! functions build artifacts — `module::stage_record`, `module::stage_failure`,
//! `module::stage_manifest_record` and `module::discovery_failure_record` — and
//! nothing else constructs an `Artifact` anywhere in this crate. The first three
//! stamp through the single private `module::stamp`, which calls
//! [`stamp_unvalidated`] **last**, so nothing earlier can weaken it; the fourth
//! calls [`stamp_unvalidated`] directly.
//!
//! What the tests in `module` assert, precisely: that `stamp` emits the marker,
//! that the manifest record carries it, and that a discovery-failure record
//! carries it. The two record builders that need a discovered profile are
//! covered structurally — they have no stamping code of their own, they call
//! `stamp` — rather than by a test, because constructing a `MacProfile` needs a
//! compiled symbol pack and a translated address space, which is exactly the
//! macOS capture this crate does not have. That gap is stated here rather than
//! papered over.
//!
//! # What would clear it
//!
//! Nothing in this crate. The marker comes off when this tier has been run
//! against a real macOS capture whose ground truth is known independently — a
//! live `ps`/`kextstat` taken beside the acquisition, or an image an established
//! tool has already been agreed to parse correctly — and the comparison is
//! recorded. Until then, removing it would be a claim, not a change.

use serde_json::{json, Map, Value};

/// Wire value of `validation_state`. Deliberately a sentence-shaped key rather
/// than `"none"`: it is read by humans in a report column, and "none" invites
/// the reading "no problems".
pub const VALIDATION_STATE: &str = "never_validated_against_a_real_capture";

/// What the analysis was built from, in place of evidence.
pub const VALIDATION_BASIS: &str =
    "Apple Kernel Debug Kit symbol definitions (ISF) and Volatility 3's macOS plugins read as \
     source; no macOS memory capture was available to test against";

/// The sentence an examiner reads.
pub const VALIDATION_NOTICE: &str =
    "This result was produced by a macOS memory analysis that has never been run against a real \
     macOS memory capture. Its structure walks are derived from kernel symbol definitions alone. \
     Treat every value here as unverified: it may be correct, and nothing in this tool has \
     established that it is. Do not rely on it in a report without independent corroboration.";

/// The fields every record this crate emits carries.
pub fn unvalidated_stamp() -> Value {
    json!({
        "validation_state": VALIDATION_STATE,
        "validated_against_real_capture": false,
        "validation_basis": VALIDATION_BASIS,
        "validation_notice": VALIDATION_NOTICE,
    })
}

/// Stamp the marker onto a record body.
///
/// Overwrites rather than merges: a stage that had somehow set one of these
/// keys itself must not be able to weaken the marker.
pub fn stamp_unvalidated(object: &mut Map<String, Value>) {
    for (key, value) in unvalidated_stamp()
        .as_object()
        .expect("unvalidated_stamp is an object literal")
    {
        object.insert(key.clone(), value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_says_false_rather_than_saying_nothing() {
        // A missing key reads as "not applicable" to a consumer that does not
        // know to look for it. An explicit `false` cannot be misread.
        let stamp = unvalidated_stamp();
        assert_eq!(stamp["validated_against_real_capture"], json!(false));
        assert_eq!(stamp["validation_state"], json!(VALIDATION_STATE));
        assert!(stamp["validation_notice"]
            .as_str()
            .is_some_and(|text| text.contains("never been run against a real")));
    }

    #[test]
    fn stamping_overwrites_a_weaker_claim_already_on_the_record() {
        let mut object = Map::new();
        object.insert("validated_against_real_capture".into(), json!(true));
        stamp_unvalidated(&mut object);
        assert_eq!(object["validated_against_real_capture"], json!(false));
    }
}
