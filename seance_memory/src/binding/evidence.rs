//! How a fact about an image was established.
//!
//! Lifted out of the Windows tier because it is not a Windows idea. Every OS
//! tier discovers the same class of thing — a page-table base, a kernel load
//! address, a symbol match — and every one of them can arrive by reading a
//! structure the image itself points at, or by scanning until something looks
//! right. Those support very different confidence in everything downstream, and
//! an examiner is entitled to see which one applies.

/// How a fact about the image was established.
///
/// Ordered from strongest to weakest, and [`Ord`] follows that order, so
/// `min()` over the evidence behind several facts is the weakest link.
///
/// # What an examiner learns
///
/// How much of the analysis rests on a scan. "The directory table base was read
/// from the debugger data block and then confirmed by using it" and "the
/// directory table base was the best of nine candidates from a
/// self-referencing-entry scan" produce the same process list and warrant very
/// different cross-examination. A fact recorded as [`Evidence::Confirmed`] when
/// it was in truth scanned overstates the whole analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Evidence {
    /// Read directly out of a kernel structure the image itself points at, and
    /// then confirmed by using it.
    Confirmed,
    /// Derived by scanning, then validated against an independent check.
    Validated,
    /// Derived by scanning, with no independent confirmation available.
    Scanned,
    /// Supplied by the examiner rather than discovered.
    Supplied,
}

impl Evidence {
    /// Stable identifier for artifact metadata and report columns.
    pub fn as_str(self) -> &'static str {
        match self {
            Evidence::Confirmed => "confirmed",
            Evidence::Validated => "validated",
            Evidence::Scanned => "scanned",
            Evidence::Supplied => "supplied",
        }
    }
}

/// One discovered fact and the evidence behind it.
///
/// The pairing is the point: a bare `u64` for a page-table base loses how it
/// was obtained the moment it is passed anywhere, and nothing downstream can
/// recover it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found<T> {
    /// The value.
    pub value: T,
    /// How it was established.
    pub evidence: Evidence,
}

impl<T> Found<T> {
    /// Record a value together with how it was established.
    pub fn new(value: T, evidence: Evidence) -> Self {
        Self { value, evidence }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire names are report columns; a rename changes what an examiner
    /// reads about how much of the analysis rests on a scan.
    #[test]
    fn each_grade_has_a_stable_wire_name() {
        assert_eq!(Evidence::Confirmed.as_str(), "confirmed");
        assert_eq!(Evidence::Validated.as_str(), "validated");
        assert_eq!(Evidence::Scanned.as_str(), "scanned");
        assert_eq!(Evidence::Supplied.as_str(), "supplied");
    }

    /// Weakest-link ordering: a chain of facts is only as good as its worst
    /// step, and the ordering is what lets a caller say so with `min`.
    #[test]
    fn stronger_evidence_orders_before_weaker() {
        assert!(Evidence::Confirmed < Evidence::Scanned);
        assert!(Evidence::Validated < Evidence::Supplied);
        let chain = [Evidence::Confirmed, Evidence::Scanned, Evidence::Validated];
        assert_eq!(chain.into_iter().max(), Some(Evidence::Scanned));
    }

    #[test]
    fn a_found_value_carries_its_provenance() {
        let dtb = Found::new(0x1a_b000u64, Evidence::Scanned);
        assert_eq!(dtb.value, 0x1a_b000);
        assert_eq!(dtb.evidence.as_str(), "scanned");
    }
}
