//! Robust-hash matching and the pluggable PhotoDNA back-end.
//!
//! Two robust-hash families matter for VIC/CAID work: PDQ (open, implemented in
//! [`crate::pdq`]) and PhotoDNA (Microsoft-licensed). This module defines the
//! [`RobustHasher`] trait so a site that holds a PhotoDNA licence can plug its
//! own implementation in, and the [`MatchGrade`] discipline that keeps every
//! match honest about how much it proves.

/// How strongly a media match is established. The wire names match the memory
/// tier's `Evidence` enum so an examiner reads one vocabulary across the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchGrade {
    /// An exact cryptographic-hash match (MD5/SHA-1/SHA-256). A collision is not
    /// a defence, so this is the one grade awarded automatically.
    Confirmed,
    /// A perceptual/robust-hash "near" match under a distance threshold. A lead
    /// for human review, never an identification.
    Scanned,
}

impl MatchGrade {
    /// Stable identifier for artifact metadata and report columns.
    pub fn as_str(self) -> &'static str {
        match self {
            MatchGrade::Confirmed => "confirmed",
            MatchGrade::Scanned => "scanned",
        }
    }
}

/// One robust-hash match against a known-media set.
#[derive(Debug, Clone, PartialEq)]
pub struct RobustMatch {
    /// The algorithm family that produced the match, e.g. `"pdq"` or
    /// `"photodna"`.
    pub algorithm: String,
    /// The exact pipeline that computed the probe hash — see
    /// [`RobustHasher::variant`]. Carried because a distance is only meaningful
    /// between hashes the *same* pipeline produced: a Séance PDQ hash scored
    /// against an externally-supplied PDQ set is a lead about two pipelines that
    /// have never been shown to agree, and the record has to say which pipeline
    /// it was. Equal to [`Self::algorithm`] for a back-end that is the family's
    /// reference implementation.
    pub variant: String,
    /// Hamming (or algorithm-native) distance between the probe and the known
    /// hash. Always carried, because a match at distance 2 and a match at
    /// distance 30 warrant very different attention.
    pub distance: u32,
    /// The threshold the match was accepted under. Recorded so a report states
    /// the decision rule, not just its outcome.
    pub threshold: u32,
    /// Always [`MatchGrade::Scanned`] for a robust match.
    pub grade: MatchGrade,
}

/// A pluggable robust-hash back-end.
///
/// PDQ is provided in-tree. PhotoDNA is **not**: it is licence-restricted and
/// provisioned to law enforcement through forensic-tool developers, so a site
/// implements this trait against its own licensed library and Séance never
/// bundles the algorithm. The interface is deliberately minimal — compute a hash
/// from luminance, and score two hashes — so any robust family fits.
pub trait RobustHasher: Send + Sync {
    /// Algorithm family for provenance (`"photodna"`, `"pdq"`, …).
    fn algorithm(&self) -> &str;

    /// The exact pipeline behind [`Self::algorithm`], for provenance.
    ///
    /// The family name is what an examiner recognises; it is not what computed
    /// the hash. Where an in-tree implementation is not bit-compatible with the
    /// family's reference — which is the case for [`PdqBackend`], see
    /// [`crate::pdq::PDQ_VARIANT`] — a match labelled only with the family name
    /// reads as interoperable and invites a comparison against another tool's
    /// hash set that this code cannot support. Defaults to the family name,
    /// which is the honest answer for a back-end that *is* the reference (a
    /// site's licensed PhotoDNA library, say) and which such a back-end should
    /// narrow to its own build identifier if it can.
    fn variant(&self) -> &str {
        self.algorithm()
    }

    /// Compute the robust hash of an 8-bit luminance image, or `None` if the
    /// back-end cannot process these dimensions.
    fn hash_luminance(&self, width: usize, height: usize, lum: &[u8]) -> Option<Vec<u8>>;

    /// Distance between two hashes this back-end produced. Lower is more similar.
    fn distance(&self, a: &[u8], b: &[u8]) -> Option<u32>;

    /// The default "same image" threshold this back-end recommends.
    fn default_threshold(&self) -> u32;

    /// Score a probe hash against a known hash, returning a match iff within
    /// `threshold`. The default implementation is correct for any back-end that
    /// implements [`Self::distance`]; there is no need to override it.
    fn matches(&self, probe: &[u8], known: &[u8], threshold: u32) -> Option<RobustMatch> {
        let distance = self.distance(probe, known)?;
        if distance <= threshold {
            Some(RobustMatch {
                algorithm: self.algorithm().to_string(),
                variant: self.variant().to_string(),
                distance,
                threshold,
                grade: MatchGrade::Scanned,
            })
        } else {
            None
        }
    }
}

/// The in-tree PDQ back-end, wrapping [`crate::pdq::PdqHash`] behind the trait
/// so PDQ and a licensed PhotoDNA are interchangeable at the call site.
#[derive(Debug, Default, Clone, Copy)]
pub struct PdqBackend;

impl RobustHasher for PdqBackend {
    fn algorithm(&self) -> &str {
        "pdq"
    }

    /// Not the bare family name: this is Séance's PDQ pipeline, which has never
    /// been run against Meta's reference vectors (see [`crate::pdq`]).
    fn variant(&self) -> &str {
        crate::pdq::PDQ_VARIANT
    }

    fn hash_luminance(&self, width: usize, height: usize, lum: &[u8]) -> Option<Vec<u8>> {
        crate::pdq::PdqHash::from_luminance(width, height, lum).map(|h| h.0.to_vec())
    }

    fn distance(&self, a: &[u8], b: &[u8]) -> Option<u32> {
        if a.len() != 32 || b.len() != 32 {
            return None;
        }
        Some(
            a.iter()
                .zip(b.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum(),
        )
    }

    fn default_threshold(&self) -> u32 {
        31
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdq::PdqHash;

    /// Perceptually rich fixture, sampled from a continuous function so the same
    /// picture can be produced at different resolutions (mirrors the pdq tests).
    fn photo(width: usize, height: usize) -> Vec<u8> {
        use std::f32::consts::PI;
        let mut v = vec![0u8; width * height];
        for y in 0..height {
            let vv = (y as f32 + 0.5) / height as f32;
            for x in 0..width {
                let uu = (x as f32 + 0.5) / width as f32;
                let mut val = 128.0;
                val += 55.0 * (2.0 * PI * 3.0 * uu).sin();
                val += 45.0 * (2.0 * PI * 2.0 * vv).cos();
                val += 35.0 * (2.0 * PI * 5.0 * (uu + vv)).sin();
                v[y * width + x] = val.clamp(0.0, 255.0) as u8;
            }
        }
        v
    }

    #[test]
    fn grades_have_stable_wire_names() {
        assert_eq!(MatchGrade::Confirmed.as_str(), "confirmed");
        assert_eq!(MatchGrade::Scanned.as_str(), "scanned");
    }

    #[test]
    fn pdq_backend_matches_identical_and_carries_distance() {
        let b = PdqBackend;
        let img = photo(128, 128);
        let h = b.hash_luminance(128, 128, &img).unwrap();
        let m = b.matches(&h, &h, b.default_threshold()).expect("match");
        assert_eq!(m.algorithm, "pdq");
        assert_eq!(m.distance, 0);
        assert_eq!(m.threshold, 31);
        assert_eq!(m.grade, MatchGrade::Scanned); // never Confirmed for robust
    }

    /// A match record carrying only `"pdq"` reads as Meta's reference output, so
    /// an examiner scoring a Séance hash against an externally-supplied PDQ set
    /// would take a non-match as a non-match rather than as two pipelines that
    /// have never been shown to agree. The pipeline travels on the record.
    #[test]
    fn a_pdq_match_names_the_pipeline_that_computed_the_probe() {
        let b = PdqBackend;
        assert_eq!(b.algorithm(), "pdq", "the family stays recognisable");
        assert_eq!(b.variant(), crate::pdq::PDQ_VARIANT);
        assert_ne!(
            b.variant(),
            "pdq",
            "the bare family name claims reference-faithful interop"
        );

        let h = b.hash_luminance(128, 128, &photo(128, 128)).unwrap();
        let m = b.matches(&h, &h, b.default_threshold()).expect("match");
        assert_eq!(m.variant, crate::pdq::PDQ_VARIANT);
    }

    #[test]
    fn pdq_backend_rejects_beyond_threshold() {
        let b = PdqBackend;
        let a = b.hash_luminance(128, 128, &photo(128, 128)).unwrap();
        // Stripes are far from the gradient (asserted in pdq tests).
        let stripes: Vec<u8> = (0..128 * 128)
            .map(|i| {
                if (i / 128 + i % 128) % 16 < 8 {
                    20
                } else {
                    235
                }
            })
            .collect();
        let c = b.hash_luminance(128, 128, &stripes).unwrap();
        // With a tiny threshold there is no match.
        assert!(b.matches(&a, &c, 5).is_none());
    }

    #[test]
    fn pdq_backend_distance_agrees_with_pdqhash() {
        let b = PdqBackend;
        let x = PdqHash::from_luminance(64, 64, &photo(64, 64)).unwrap();
        let y = PdqHash::from_luminance(60, 60, &photo(60, 60)).unwrap();
        assert_eq!(
            b.distance(&x.0, &y.0),
            Some(x.distance(&y)),
            "trait distance must equal PdqHash::distance"
        );
    }

    #[test]
    fn wrong_length_hashes_do_not_match() {
        let b = PdqBackend;
        assert_eq!(b.distance(&[0u8; 10], &[0u8; 32]), None);
    }

    /// A stand-in for a licensed back-end proves the trait is implementable
    /// without touching the real PhotoDNA algorithm — which is the whole point.
    struct FakePhotoDna;
    impl RobustHasher for FakePhotoDna {
        fn algorithm(&self) -> &str {
            "photodna"
        }
        fn hash_luminance(&self, _w: usize, _h: usize, lum: &[u8]) -> Option<Vec<u8>> {
            // A trivial 144-byte "hash" — shape only; not the real algorithm.
            let mut v = vec![0u8; 144];
            for (i, b) in lum.iter().enumerate() {
                v[i % 144] ^= *b;
            }
            Some(v)
        }
        fn distance(&self, a: &[u8], b: &[u8]) -> Option<u32> {
            if a.len() != b.len() {
                return None;
            }
            Some(a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum())
        }
        fn default_threshold(&self) -> u32 {
            1800
        }
    }

    #[test]
    fn a_third_party_backend_plugs_in_through_the_trait() {
        let b = FakePhotoDna;
        let img = photo(100, 100);
        let h = b.hash_luminance(100, 100, &img).unwrap();
        let m = b.matches(&h, &h, b.default_threshold()).unwrap();
        assert_eq!(m.algorithm, "photodna");
        assert_eq!(m.grade, MatchGrade::Scanned);
        assert_eq!(m.distance, 0);
        // A back-end that says nothing about its build reports the family name
        // as its variant — no fabricated pipeline identifier, and the field is
        // never absent for a consumer that reads it.
        assert_eq!(m.variant, "photodna");
    }
}
