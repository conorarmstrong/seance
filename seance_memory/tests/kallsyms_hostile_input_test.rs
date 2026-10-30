//! `Kallsyms::find_in` against bytes that are not a symbol table.
//!
//! # Why this exists
//!
//! This parser is pointed at raw memory. Every window it reads is unvalidated
//! by construction — most of a capture is not a kallsyms table, and some of it
//! is data an examined machine's own attacker chose. A panic here aborts the
//! sweep and, in a tool an examiner runs against evidence, turns a hostile page
//! into a denial of the whole analysis. Returning `None` is the only acceptable
//! answer for input that is not a table.
//!
//! The decoder indexes and slices in twenty-odd places, and its structural walk
//! subtracts offsets found in the data. Those are the operations that panic on
//! bytes chosen to make them, so they are what this exercises: garbage, and
//! then garbage shaped to get past the cheap filter and into the expensive
//! walk.
//!
//! Determinism matters more than breadth. A fixed generator means a failure
//! reproduces from the seed printed in the assertion rather than being a report
//! that something, once, went wrong.

use seance_memory::kallsyms::Kallsyms;

/// A fixed pseudo-random generator, so any failure reproduces.
struct Lcg(u64);

impl Lcg {
    fn next_byte(&mut self) -> u8 {
        // Numerical Recipes' constants; the choice does not matter, the
        // reproducibility does.
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u8
    }

    fn fill(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_byte()).collect()
    }
}

/// Random bytes are not a symbol table, and must not be treated as one.
#[test]
fn random_bytes_yield_no_table_and_do_not_panic() {
    for seed in 0..64u64 {
        let mut rng = Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for &len in &[0usize, 1, 2, 511, 512, 513, 4096, 64 * 1024] {
            let data = rng.fill(len);
            assert!(
                Kallsyms::find_in(&data).is_none(),
                "seed {seed} produced a {len}-byte buffer that decoded as a \
                 symbol table; either the validation is far too weak or this \
                 is a genuine collision worth understanding"
            );
        }
    }
}

/// Buffers too short to hold a token index at all.
///
/// The cheap filter reads 512 bytes before it decides anything. Every length
/// below that has to be refused by a bounds check rather than by an index that
/// happens to land inside the allocation.
#[test]
fn buffers_shorter_than_a_token_index_are_refused() {
    for len in 0..600usize {
        let zeros = vec![0u8; len];
        assert!(Kallsyms::find_in(&zeros).is_none(), "{len} zero bytes");

        // 0x00 0x01 repeating looks like a strictly-growing u16 run, which is
        // the shape the filter looks for.
        let growing: Vec<u8> = (0..len).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        assert!(Kallsyms::find_in(&growing).is_none(), "{len} growing bytes");
    }
}

/// A token index the cheap filter accepts, with nothing valid behind it.
///
/// This is the case that matters. The filter's job is to be cheap and let the
/// structural walk reject; so the walk is what runs here, on a buffer where
/// every offset it computes points at arbitrary bytes. The table is placed at
/// several distances from the start so the backward walk — for the token table,
/// then the markers, then the name stream — is made to run off the front of the
/// buffer, which is where an unchecked subtraction would underflow.
#[test]
fn a_plausible_token_index_with_nothing_behind_it_is_refused() {
    for lead in [0usize, 1, 8, 256, 1024, 4096, 32 * 1024] {
        for step in [1u16, 2, 3, 17, 64] {
            let mut data = vec![0u8; lead];
            // 256 strictly-growing u16s, last offset inside the plausible band
            // for a token table.
            let mut offset = 0u16;
            for i in 0..256 {
                data.extend_from_slice(&offset.to_le_bytes());
                if i + 1 < 256 {
                    offset = offset.saturating_add(step);
                }
            }
            // Trailing bytes so the decode has somewhere to go forward, too.
            data.extend_from_slice(&[0xAB; 8192]);

            // No assertion on the result beyond "it returned": a collision that
            // decodes is astronomically unlikely but not impossible, and the
            // property under test is that the walk terminates without panicking
            // on bytes that were never a table.
            let _ = Kallsyms::find_in(&data);
        }
    }
}

/// A plausible token index butted against the end of the buffer.
///
/// Everything the decoder needs lies *behind* the index, so a table found with
/// nothing after it is the boundary case for the forward reads, and one found
/// with nothing before it is the boundary case for the backward ones.
#[test]
fn a_token_index_at_either_edge_is_refused_cleanly() {
    let mut index = Vec::new();
    let mut offset = 0u16;
    for i in 0..256 {
        index.extend_from_slice(&offset.to_le_bytes());
        if i + 1 < 256 {
            offset += 2;
        }
    }

    // Flush against the end: no bytes follow.
    assert!(Kallsyms::find_in(&index).is_none(), "index alone");

    // Flush against the start, with plausible-looking data after it.
    let mut trailing = index.clone();
    trailing.extend_from_slice(&vec![0x41u8; 16 * 1024]);
    let _ = Kallsyms::find_in(&trailing);

    // One byte short of a whole index.
    assert!(
        Kallsyms::find_in(&index[..index.len() - 1]).is_none(),
        "a truncated index must not decode"
    );
}

/// Many near-miss candidates in one window must not take unbounded time.
///
/// Each candidate the cheap filter admits costs a full structural walk. A
/// window engineered to hold thousands of them is the shape that turns a sweep
/// into a hang — the same failure the strict-growth filter was introduced to
/// fix, arrived at deliberately rather than by accident.
#[test]
fn a_window_full_of_near_miss_candidates_still_completes() {
    // A repeating strictly-growing run: overlapping offsets in it satisfy the
    // filter at many different starting points.
    let mut data = Vec::with_capacity(4 * 1024 * 1024);
    while data.len() < 4 * 1024 * 1024 {
        let mut offset = 0u16;
        for i in 0..256 {
            data.extend_from_slice(&offset.to_le_bytes());
            if i + 1 < 256 {
                offset += 4;
            }
        }
    }

    let started = std::time::Instant::now();
    let _ = Kallsyms::find_in(&data);
    let elapsed = started.elapsed();

    // A real sweep reads windows of 64 MiB. If 4 MiB of adversarial data costs
    // more than a few seconds, a capture cannot be swept at all.
    assert!(
        elapsed.as_secs() < 30,
        "4 MiB of near-miss candidates took {elapsed:?}; a sweep reads windows \
         sixteen times this size, so this is a hang, not a slow test"
    );
}
