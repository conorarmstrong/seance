//! Near-duplicate clustering of perceptual hashes.
//!
//! Given a set of images each carrying a [`PdqHash`], group them so that any two
//! images within `threshold` Hamming bits land in the same cluster. Matching is
//! transitive (union-find): if A≈B and B≈C, all three cluster together even when
//! A and C are just over the threshold. That is what a triage examiner wants — a
//! run of re-encodes and light crops of one picture collapses into a single group
//! to review, rather than a chain of pairwise hits.
//!
//! The clustering is a pure function of the hashes, so it is deterministic and
//! testable without a database or images.

use crate::pdq::PdqHash;

/// Disjoint-set (union-find) with path compression and union by size.
struct DisjointSet {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl DisjointSet {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            size: vec![1; n],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]]; // path halving
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return;
        }
        let (big, small) = if self.size[ra] >= self.size[rb] {
            (ra, rb)
        } else {
            (rb, ra)
        };
        self.parent[small] = big;
        self.size[big] += self.size[small];
    }
}

/// Group `items` into near-duplicate clusters by PDQ Hamming distance.
///
/// Any two items whose hashes are within `threshold` bits are merged into the
/// same cluster, transitively. Returns every cluster (including singletons); the
/// caller filters to `len() >= 2` for "these are duplicates of each other".
/// Each returned cluster preserves the input order of its members, and the
/// clusters themselves are ordered by their first member's input index, so the
/// result is deterministic.
///
/// Complexity is O(n²) in the number of items — the caller must cap `items`
/// (this is triage over a bounded record scan, not the whole disk).
pub fn cluster_pdq<T>(items: Vec<(T, PdqHash)>, threshold: u32) -> Vec<Vec<T>> {
    let n = items.len();
    let mut ds = DisjointSet::new(n);
    for i in 0..n {
        for j in (i + 1)..n {
            if items[i].1.distance(&items[j].1) <= threshold {
                ds.union(i, j);
            }
        }
    }
    // Bucket members by their set root, keeping first-seen order for both the
    // clusters and the members within each.
    let mut order: Vec<usize> = Vec::new();
    let mut index_of: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut buckets: Vec<Vec<T>> = Vec::new();
    for (i, (payload, _)) in items.into_iter().enumerate() {
        let root = ds.find(i);
        let bi = *index_of.entry(root).or_insert_with(|| {
            order.push(buckets.len());
            buckets.push(Vec::new());
            buckets.len() - 1
        });
        buckets[bi].push(payload);
    }
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(bytes: [u8; 32]) -> PdqHash {
        PdqHash(bytes)
    }

    /// A hash that differs from `base` in exactly the first `bits` bit positions,
    /// spread across bytes (bit i → byte i/8). Flipping distinct bits keeps the
    /// Hamming distance exactly `bits` (a single u8 only holds 8, so spreading is
    /// required for distances above 8).
    fn near(base: &PdqHash, bits: u32) -> PdqHash {
        let mut b = base.0;
        for i in 0..bits as usize {
            b[i / 8] ^= 1 << (i % 8);
        }
        h(b)
    }

    #[test]
    fn identical_and_near_hashes_cluster_together() {
        let base = h([0xAA; 32]);
        let a = base;
        let b = near(&base, 3); // 3 bits away
        let c = near(&base, 5); // 5 bits away
        let clusters = cluster_pdq(vec![("a", a), ("b", b), ("c", c)], 8);
        assert_eq!(clusters.len(), 1, "all within threshold → one cluster");
        assert_eq!(clusters[0], vec!["a", "b", "c"]);
    }

    #[test]
    fn distant_hashes_stay_separate() {
        let a = h([0x00; 32]);
        let b = h([0xFF; 32]); // 256 bits away
        let clusters = cluster_pdq(vec![("a", a), ("b", b)], 31);
        assert_eq!(clusters.len(), 2, "far apart → two singleton clusters");
    }

    #[test]
    fn matching_is_transitive_across_the_threshold() {
        // A—B within threshold, B—C within threshold, but A—C just over it.
        // Transitive clustering must still group all three.
        let a = h([0x00; 32]);
        let b = near(&a, 5); // bits 0..5 flipped
        let c = near(&a, 10); // bits 0..10 flipped → 10 bits from A, 5 bits from B
        assert!(
            a.distance(&c) > 6,
            "A and C are over the threshold directly"
        );
        assert_eq!(b.distance(&c), 5, "B and C are within the threshold");
        let clusters = cluster_pdq(vec![("a", a), ("b", b), ("c", c)], 6);
        assert_eq!(clusters.len(), 1, "transitivity groups A,B,C");
        assert_eq!(clusters[0], vec!["a", "b", "c"]);
    }

    #[test]
    fn preserves_input_order_and_is_deterministic() {
        let g1 = h([0x11; 32]);
        let g2 = h([0x88; 32]); // far from g1
        let items = vec![
            (0, g1),
            (1, g2),
            (2, near(&g1, 2)),
            (3, near(&g2, 2)),
            (4, g1),
        ];
        let clusters = cluster_pdq(items, 8);
        // Two clusters, ordered by first appearance; members in input order.
        assert_eq!(clusters, vec![vec![0, 2, 4], vec![1, 3]]);
    }

    #[test]
    fn empty_input_yields_no_clusters() {
        let clusters: Vec<Vec<u32>> = cluster_pdq(Vec::new(), 31);
        assert!(clusters.is_empty());
    }
}
