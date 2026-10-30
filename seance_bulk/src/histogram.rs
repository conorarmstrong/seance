//! Frequency histogram over feature hits.
//!
//! `features::FeatureScanner` emits one [`FeatureHit`](crate::features::FeatureHit)
//! per *occurrence* — the same email address found five times in a scan is five
//! separate hits, each with its own offset. bulk_extractor's classic second
//! deliverable, alongside a raw feature file, is the histogram: `email.txt` plus
//! `email_histogram.txt` showing which address recurred and how often. This
//! module is that aggregation step — a per-(kind, value) frequency count built
//! from the same hits the scanner already produces, so "most-common" reporting
//! (ROADMAP §2.1) has a count to read instead of re-tallying raw hits itself.

use crate::features::FeatureHit;
use std::collections::{BTreeMap, HashMap};

/// Ceiling on the number of distinct `(kind, value)` pairs one [`FeatureHistogram`]
/// holds in memory at once.
///
/// A scan's occurrence count is bounded by the source size, but its *distinct*
/// value count is not — a case built from a large corpus can legitimately carry
/// far more unique values than fit in RAM (the task that motivated this ceiling
/// named "a case with billions of distinct emails"). Without a cap, aggregating
/// such a scan would grow the map without bound. 100,000 distinct values is
/// already an enormous "most common" table for a report to render or an examiner
/// to read; a scan that finds more than that is disclosed via
/// [`FeatureHistogram::hits_dropped`] rather than silently losing entries past
/// this point.
pub const MAX_DISTINCT_VALUES: usize = 100_000;

/// One distinct feature value's frequency, as reported by [`FeatureHistogram::entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramEntry {
    /// Selector kind this value was found under (`"email"`, `"ccn"`, …).
    pub kind: &'static str,
    /// The distinct feature value.
    pub value: String,
    /// How many times this exact `(kind, value)` occurred.
    pub count: u64,
}

/// One selector kind's share of a histogram, as reported by
/// [`FeatureHistogram::by_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KindTotals {
    /// Every hit recorded under this kind, including any turned away at the
    /// ceiling — the same basis as [`FeatureHistogram::total_hits`].
    pub hits: u64,
    /// Distinct values tracked under this kind. On a capped histogram this is
    /// the number tracked, not the number the scan contained.
    pub distinct_values: usize,
}

/// A count-and-frequency summary of feature values seen across a scan, keyed by
/// `(selector kind, value)` so the same text under two different selectors is
/// counted separately.
///
/// Built incrementally with [`record`](Self::record), so a caller streaming a
/// large source in overlapping windows (as `seance_plugin_bulk`'s scanners
/// already do) can feed hits in as they are found rather than holding the whole
/// hit list first.
#[derive(Debug, Default)]
pub struct FeatureHistogram {
    counts: HashMap<(&'static str, String), u64>,
    /// Hits for a value not already being tracked, received after
    /// `MAX_DISTINCT_VALUES` distinct values were already held. Counted per
    /// hit, not per distinct value: telling two never-before-tracked values
    /// apart at that point would itself require the unbounded map this ceiling
    /// exists to avoid, so what is reported is the exact number of hits turned
    /// away, never an estimate of how many distinct values they represented.
    hits_dropped: u64,
    /// Every hit recorded under each kind, dropped ones included, so a capped
    /// histogram still states how many hits the scan produced per selector.
    hits_by_kind: BTreeMap<&'static str, u64>,
}

impl FeatureHistogram {
    /// An empty histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one occurrence of a feature hit.
    ///
    /// A hit for a value already being tracked always increments its count,
    /// even after the ceiling is reached — the cap bounds how many *distinct*
    /// values are tracked, not how high any one count can climb. Only a hit
    /// that would introduce a *new* distinct value once the ceiling is already
    /// full is turned away.
    pub fn record(&mut self, hit: &FeatureHit) {
        // One hashmap probe, not two (`contains_key` then `entry`) — a
        // code-review pass on 2026-09-18 caught this doubling the
        // hashing/probing cost on the histogram's hot aggregation path,
        // which exists specifically to be fast at exactly this. The
        // ceiling only ever applies to the Vacant case: an already-tracked
        // value's count climbs regardless of how full the table is.
        *self.hits_by_kind.entry(hit.kind).or_insert(0) += 1;
        let key = (hit.kind, hit.value.clone());
        let at_capacity = self.counts.len() >= MAX_DISTINCT_VALUES;
        match self.counts.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                *e.get_mut() += 1;
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                if at_capacity {
                    self.hits_dropped += 1;
                } else {
                    e.insert(1);
                }
            }
        }
    }

    /// Record every hit in `hits`, in order.
    pub fn record_all<'a>(&mut self, hits: impl IntoIterator<Item = &'a FeatureHit>) {
        for hit in hits {
            self.record(hit);
        }
    }

    /// Every distinct value tracked, with its count. Ordered most-common
    /// first (ROADMAP §2.1's "most-common" histogram), ties broken by kind
    /// then value so output is deterministic.
    pub fn entries(&self) -> Vec<HistogramEntry> {
        let mut entries: Vec<HistogramEntry> = self
            .counts
            .iter()
            .map(|((kind, value), count)| HistogramEntry {
                kind,
                value: value.clone(),
                count: *count,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.kind.cmp(b.kind))
                .then(a.value.cmp(&b.value))
        });
        entries
    }

    /// The `n` most common entries, in [`entries`](Self::entries) order —
    /// fewer when fewer are tracked.
    pub fn top(&self, n: usize) -> Vec<HistogramEntry> {
        let mut entries = self.entries();
        entries.truncate(n);
        entries
    }

    /// Number of distinct `(kind, value)` pairs currently tracked.
    pub fn distinct_values(&self) -> usize {
        self.counts.len()
    }

    /// Every hit ever recorded, tracked or turned away: the tracked counts
    /// plus [`hits_dropped`](Self::hits_dropped).
    pub fn total_hits(&self) -> u64 {
        self.hits_by_kind.values().sum()
    }

    /// Per-kind totals, ordered by kind so output is deterministic. A kind
    /// appears here from its first recorded hit even if that hit was turned
    /// away at the ceiling, so `hits` sums to [`total_hits`](Self::total_hits).
    pub fn by_kind(&self) -> BTreeMap<&'static str, KindTotals> {
        let mut by_kind: BTreeMap<&'static str, KindTotals> = self
            .hits_by_kind
            .iter()
            .map(|(kind, hits)| {
                (
                    *kind,
                    KindTotals {
                        hits: *hits,
                        distinct_values: 0,
                    },
                )
            })
            .collect();
        for (kind, _) in self.counts.keys() {
            by_kind.entry(kind).or_default().distinct_values += 1;
        }
        by_kind
    }

    /// Hits excluded because `MAX_DISTINCT_VALUES` was already reached when
    /// they were recorded — the exact shortfall to report on the record, never
    /// an estimate.
    pub fn hits_dropped(&self) -> u64 {
        self.hits_dropped
    }

    /// Whether the ceiling was ever hit. A record built from this histogram
    /// must say so rather than let a full table read as an exhaustive one.
    pub fn is_capped(&self) -> bool {
        self.hits_dropped > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(kind: &'static str, value: &str) -> FeatureHit {
        FeatureHit {
            kind,
            value: value.to_string(),
            offset: 0,
        }
    }

    #[test]
    fn counts_repeated_values_exactly() {
        // Known input: three of one email, one of another, two of a URL.
        let hits = vec![
            hit("email", "a@example.com"),
            hit("email", "b@example.com"),
            hit("email", "a@example.com"),
            hit("url", "http://evil.test/x"),
            hit("email", "a@example.com"),
            hit("url", "http://evil.test/x"),
        ];
        let mut h = FeatureHistogram::new();
        h.record_all(&hits);

        let entries = h.entries();
        let a = entries
            .iter()
            .find(|e| e.kind == "email" && e.value == "a@example.com")
            .expect("a@example.com tracked");
        assert_eq!(a.count, 3);
        let b = entries
            .iter()
            .find(|e| e.kind == "email" && e.value == "b@example.com")
            .expect("b@example.com tracked");
        assert_eq!(b.count, 1);
        let url = entries
            .iter()
            .find(|e| e.kind == "url" && e.value == "http://evil.test/x")
            .expect("url tracked");
        assert_eq!(url.count, 2);

        assert_eq!(h.distinct_values(), 3);
        assert_eq!(h.hits_dropped(), 0);
        assert!(!h.is_capped());
    }

    #[test]
    fn same_text_under_different_kinds_counted_separately() {
        let mut h = FeatureHistogram::new();
        // Same literal string, two different selector kinds — must not collide.
        h.record(&hit("email", "192.168.1.55"));
        h.record(&hit("ipv4", "192.168.1.55"));
        h.record(&hit("ipv4", "192.168.1.55"));

        assert_eq!(h.distinct_values(), 2);
        let entries = h.entries();
        let email = entries.iter().find(|e| e.kind == "email").unwrap();
        let ip = entries.iter().find(|e| e.kind == "ipv4").unwrap();
        assert_eq!(email.count, 1);
        assert_eq!(ip.count, 2);
    }

    #[test]
    fn entries_ordered_most_common_first_deterministically() {
        let mut h = FeatureHistogram::new();
        for _ in 0..2 {
            h.record(&hit("email", "rare@example.com"));
        }
        for _ in 0..5 {
            h.record(&hit("email", "common@example.com"));
        }
        let entries = h.entries();
        assert_eq!(entries[0].value, "common@example.com");
        assert_eq!(entries[0].count, 5);
        assert_eq!(entries[1].value, "rare@example.com");
        assert_eq!(entries[1].count, 2);

        // Determinism: same input, same order, every time.
        let mut h2 = FeatureHistogram::new();
        for _ in 0..2 {
            h2.record(&hit("email", "rare@example.com"));
        }
        for _ in 0..5 {
            h2.record(&hit("email", "common@example.com"));
        }
        assert_eq!(entries, h2.entries());
    }

    #[test]
    fn empty_histogram_has_no_entries_and_is_not_capped() {
        let h = FeatureHistogram::new();
        assert!(h.entries().is_empty());
        assert_eq!(h.distinct_values(), 0);
        assert_eq!(h.hits_dropped(), 0);
        assert!(!h.is_capped());
    }

    /// A case with more distinct values than `MAX_DISTINCT_VALUES` must be
    /// capped with the shortfall stated, never silently truncated.
    #[test]
    fn over_limit_distinct_values_are_capped_with_shortfall_stated() {
        let mut h = FeatureHistogram::new();
        for i in 0..MAX_DISTINCT_VALUES {
            h.record(&hit("email", &format!("user{i}@example.com")));
        }
        assert_eq!(h.distinct_values(), MAX_DISTINCT_VALUES);
        assert_eq!(h.hits_dropped(), 0);
        assert!(!h.is_capped());

        // Three more distinct values arrive once the ceiling is already full.
        h.record(&hit("email", "over1@example.com"));
        h.record(&hit("email", "over2@example.com"));
        h.record(&hit("email", "over3@example.com"));

        assert_eq!(
            h.distinct_values(),
            MAX_DISTINCT_VALUES,
            "the map must not grow past the ceiling"
        );
        assert_eq!(h.hits_dropped(), 3, "the exact shortfall, not an estimate");
        assert!(h.is_capped());
        assert!(
            !h.entries().iter().any(|e| e.value.starts_with("over")),
            "a dropped value must not silently appear"
        );
    }

    /// The total is every hit ever recorded, whether or not it was tracked:
    /// a capped histogram still knows how many hits the scan produced.
    #[test]
    fn total_hits_counts_every_recorded_hit_including_those_turned_away() {
        let mut h = FeatureHistogram::new();
        for i in 0..MAX_DISTINCT_VALUES {
            h.record(&hit("email", &format!("user{i}@example.com")));
        }
        h.record(&hit("email", "over@example.com"));
        h.record(&hit("email", "user0@example.com"));
        assert_eq!(h.total_hits(), MAX_DISTINCT_VALUES as u64 + 2);
        assert_eq!(h.hits_dropped(), 1);
    }

    /// Per-kind totals: hits (every occurrence, dropped ones included) and the
    /// distinct values tracked under that kind, ordered by kind.
    #[test]
    fn by_kind_totals_give_hits_and_distinct_values_per_kind() {
        let mut h = FeatureHistogram::new();
        h.record(&hit("url", "http://a.test/"));
        h.record(&hit("email", "a@example.com"));
        h.record(&hit("email", "a@example.com"));
        h.record(&hit("email", "b@example.com"));
        let by_kind = h.by_kind();
        let kinds: Vec<&str> = by_kind.keys().copied().collect();
        assert_eq!(kinds, vec!["email", "url"], "ordered by kind");
        assert_eq!(by_kind["email"].hits, 3);
        assert_eq!(by_kind["email"].distinct_values, 2);
        assert_eq!(by_kind["url"].hits, 1);
        assert_eq!(by_kind["url"].distinct_values, 1);
        assert_eq!(h.total_hits(), 4);
    }

    /// `top(n)` is the first `n` of `entries()` — most-common first — and no
    /// more than there are.
    #[test]
    fn top_returns_at_most_n_entries_in_most_common_order() {
        let mut h = FeatureHistogram::new();
        for _ in 0..3 {
            h.record(&hit("email", "three@example.com"));
        }
        for _ in 0..2 {
            h.record(&hit("email", "two@example.com"));
        }
        h.record(&hit("email", "one@example.com"));
        let top = h.top(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].value, "three@example.com");
        assert_eq!(top[1].value, "two@example.com");
        assert_eq!(h.top(10).len(), 3, "never more than the distinct count");
        assert!(h.top(0).is_empty());
    }

    /// A value tracked before the ceiling was reached keeps counting normally
    /// afterwards — the cap bounds distinct values, not any one count.
    #[test]
    fn already_tracked_value_keeps_counting_after_ceiling_reached() {
        let mut h = FeatureHistogram::new();
        h.record(&hit("email", "first@example.com"));
        for i in 1..MAX_DISTINCT_VALUES {
            h.record(&hit("email", &format!("user{i}@example.com")));
        }
        assert_eq!(h.distinct_values(), MAX_DISTINCT_VALUES);

        // The ceiling is full, but "first@example.com" is already tracked.
        h.record(&hit("email", "first@example.com"));
        h.record(&hit("email", "first@example.com"));

        let entries = h.entries();
        let first = entries
            .iter()
            .find(|e| e.value == "first@example.com")
            .unwrap();
        assert_eq!(first.count, 3);
        assert_eq!(h.hits_dropped(), 0, "no new distinct value was rejected");
    }
}
