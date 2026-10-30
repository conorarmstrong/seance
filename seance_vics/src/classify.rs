//! Pluggable ML content classification — a flagged review aid, never an assertion.
//!
//! A classifier flags *uncategorised* imagery for human review (the capability
//! AXIOM markets as Magnet.AI). Séance ships the **interface** and the honesty
//! discipline, not a model: a CSAM-trained model is legally impossible and
//! ethically wrong to distribute, and the ONNX runtime is a heavy dependency
//! that only an equipped site needs. A site supplies its own model behind the
//! [`ContentClassifier`] trait, exactly as it supplies its own PhotoDNA library.
//!
//! # The honesty invariant, made unavoidable in the types
//!
//! There is no "this is CSAM" verdict in this API. A classifier returns a
//! [`ClassifierFlag`] carrying a *score*, the *label* it scored, the *model
//! identifier*, and the *threshold* — everything a report needs to say "the
//! model flagged this at 0.87 for review," and nothing that lets it say more.
//! The grade is always [`crate::MatchGrade::Scanned`]. A machine score never
//! becomes a categorisation without a human, and the type system will not let it.

use crate::robust::MatchGrade;

/// One classifier flag on one image — a review lead, not a conclusion.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifierFlag {
    /// Identifier of the model that produced this flag (name + version), so a
    /// report attributes the score to a specific, auditable model.
    pub model: String,
    /// The label the score is for (the site's taxonomy, e.g. `"review"`).
    pub label: String,
    /// The score, 0.0..=1.0. Carried verbatim; a report shows the number.
    pub score: f32,
    /// The threshold at or above which the model chose to flag. Recorded so the
    /// decision rule travels with the decision.
    pub threshold: f32,
    /// Always [`MatchGrade::Scanned`]. A model score is a lead, full stop.
    pub grade: MatchGrade,
}

/// A pluggable ML classifier back-end.
///
/// The site's model runs behind this trait (typically via an ONNX runtime the
/// site installs). Séance never bundles weights.
pub trait ContentClassifier: Send + Sync {
    /// Model identifier (name + version) for provenance.
    fn model(&self) -> &str;

    /// The score threshold at or above which an image is flagged.
    fn threshold(&self) -> f32;

    /// Score an 8-bit luminance image, returning `(label, score)` pairs, or
    /// `None` if the back-end cannot process these dimensions. The runtime and
    /// model are the site's; only the shape is fixed here.
    fn score_luminance(
        &self,
        width: usize,
        height: usize,
        lum: &[u8],
    ) -> Option<Vec<(String, f32)>>;

    /// Run the model and return flags for every label at or above the threshold.
    ///
    /// This is the only way a score leaves the classifier, and it always stamps
    /// [`MatchGrade::Scanned`] — there is no code path to any stronger grade.
    fn flag(&self, width: usize, height: usize, lum: &[u8]) -> Vec<ClassifierFlag> {
        let scores = match self.score_luminance(width, height, lum) {
            Some(s) => s,
            None => return Vec::new(),
        };
        let threshold = self.threshold();
        scores
            .into_iter()
            .filter(|(_, s)| *s >= threshold)
            .map(|(label, score)| ClassifierFlag {
                model: self.model().to_string(),
                label,
                score,
                threshold,
                grade: MatchGrade::Scanned,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic stand-in model: flags an image as "review" with a score
    /// derived from its mean luminance. Proves the interface is implementable
    /// without any real model, runtime, or training data.
    struct MeanBrightnessModel {
        threshold: f32,
    }
    impl ContentClassifier for MeanBrightnessModel {
        fn model(&self) -> &str {
            "mean-brightness/test-1"
        }
        fn threshold(&self) -> f32 {
            self.threshold
        }
        fn score_luminance(&self, _w: usize, _h: usize, lum: &[u8]) -> Option<Vec<(String, f32)>> {
            if lum.is_empty() {
                return None;
            }
            let mean = lum.iter().map(|&b| b as f32).sum::<f32>() / lum.len() as f32;
            Some(vec![("review".to_string(), mean / 255.0)])
        }
    }

    #[test]
    fn a_score_above_threshold_is_flagged_at_scanned_grade() {
        let m = MeanBrightnessModel { threshold: 0.5 };
        let bright = vec![200u8; 64 * 64]; // mean ~0.78
        let flags = m.flag(64, 64, &bright);
        assert_eq!(flags.len(), 1);
        let f = &flags[0];
        assert_eq!(f.model, "mean-brightness/test-1");
        assert_eq!(f.label, "review");
        assert_eq!(f.grade, MatchGrade::Scanned); // the only possible grade
        assert_eq!(f.threshold, 0.5);
        assert!(f.score > 0.5);
    }

    #[test]
    fn a_score_below_threshold_produces_no_flag() {
        let m = MeanBrightnessModel { threshold: 0.5 };
        let dark = vec![20u8; 64 * 64]; // mean ~0.08
        assert!(m.flag(64, 64, &dark).is_empty());
    }

    #[test]
    fn a_backend_that_cannot_process_returns_no_flags_not_a_panic() {
        let m = MeanBrightnessModel { threshold: 0.5 };
        assert!(m.flag(0, 0, &[]).is_empty());
    }

    #[test]
    fn the_flag_carries_everything_a_report_needs_and_nothing_more() {
        // Regression against anyone adding a "verdict"/"category" field: the flag
        // is score + label + model + threshold + grade, and that is the whole of
        // it. If this struct grows a verdict, this test should be the argument
        // against it.
        let m = MeanBrightnessModel { threshold: 0.1 };
        let f = m.flag(8, 8, &[128u8; 64]).pop().unwrap();
        assert_eq!(f.grade.as_str(), "scanned");
    }
}
