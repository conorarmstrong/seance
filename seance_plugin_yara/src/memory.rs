//! YARA over an address space rather than a file (`ROADMAP` §5.3).
//!
//! # What this adds, and what it deliberately does not
//!
//! The rest of this crate scans **file bytes**: an artifact's data source, whole
//! and contiguous. A memory image is neither. Its address space has holes, a
//! process's own space is assembled through page tables, and it is far too
//! large to hand to an engine in one buffer. `seance_memory::scan` already
//! solves that for byte and regex scanning — chunking that never spans a hole,
//! a straddling hit reported once by the chunk that owns its first byte, and
//! offsets that do not shift on a short read. This module is the missing
//! [`Scanner`] implementation, so a YARA rule set can be driven through that
//! machinery instead of a second one.
//!
//! # A rule is evaluated against each chunk, not against the image
//!
//! This is the limitation that matters and it is not the usual one. A YARA rule
//! is a *condition* over pattern matches, and this scanner evaluates it against
//! one chunk at a time. So:
//!
//! * `$a and $b` fires only where both strings are in the **same** chunk. A rule
//!   whose two strings sit either side of a chunk boundary does not fire, and a
//!   rule whose strings are megabytes apart never will.
//! * `filesize`, and any condition resting on it, is meaningless: there is no
//!   file. The chunk's length is not a file's length and this scanner does not
//!   pretend it is.
//! * A count like `#a > 10` counts within a chunk.
//!
//! None of that can be fixed by a larger chunk — only moved. So it is stated on
//! every outcome through [`MemoryYaraScanner::condition_scope`] rather than
//! implied, and a rule set written for whole-file scanning must be read with it
//! in mind. What *is* reliable is the individual string match, which is what a
//! memory hunt is nearly always written around.
//!
//! # The engine is constructed once per chunk, and that is not a choice
//!
//! [`Scanner`] is `Send + Sync`, because the driver is written so that a
//! parallel version of it needs no locking. `yara_x::Scanner` is neither: its
//! scan context holds an `Rc` and a boxed `FnMut`, so it cannot be put behind a
//! `Mutex` on a `Send + Sync` type. One engine reused across chunks is
//! therefore unavailable, and each chunk builds its own.
//!
//! Measured here: 200 fresh scanners over a 64 KiB buffer took 79 ms against
//! 1.8 ms for one reused — about 0.4 ms of construction per chunk against
//! 9 us. With the default 16 MiB chunk that is noise against the read and the
//! scan; over an address space whose mapped runs are single pages it is the
//! dominant cost, which is why the stage driving this reports how many
//! sections it scanned rather than only how many bytes.
//!
//! # An engine failure is not a clean scan
//!
//! [`Scanner::scan_chunk`] cannot return an error, and a chunk the engine
//! refused must not be indistinguishable from a chunk that matched nothing.
//! Failures are counted and kept on the scanner
//! ([`MemoryYaraScanner::failures`]), and the stage driving it publishes them
//! beside the hits. A scan that reports "no matches" over an image whose engine
//! errored on half the chunks is the false absence this project is shaped
//! against.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use seance_memory::scan::{Hit, RefusedChunk, ScanControl, Scanner, ScannerDiagnostics};

use crate::YaraScanner;

/// How long the engine gets for one chunk.
///
/// Per chunk, not per image: a rule set with a pathological regex would
/// otherwise stall a scan of a ten-gigabyte capture indefinitely, and the
/// per-chunk bound turns that into a counted failure on the chunks it affects.
const CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One chunk the engine would not scan.
#[derive(Debug, Clone)]
pub struct ChunkFailure {
    /// Address of the chunk's first byte.
    pub address: u64,
    /// Bytes offered to the engine.
    pub bytes: usize,
    /// What the engine said.
    pub detail: String,
}

/// A compiled rule set, as a [`Scanner`] over an address space.
#[derive(Debug)]
pub struct MemoryYaraScanner {
    name: String,
    /// Shared with the file-scanning module, deliberately. One compiled rule
    /// set behind both drivers: compiling twice would be two rule sets, and a
    /// rule the engine treated differently in one of them would make the file
    /// scan and the memory scan disagree about what was looked for.
    inner: Arc<YaraScanner>,
    /// Rule identifiers in set order, so a [`Hit::pattern_id`] names a rule.
    rule_names: Vec<String>,
    /// Chunks the engine refused. Interior mutability because the trait's
    /// `scan_chunk` takes `&self` — and losing these to that signature is not
    /// an option.
    failures: Mutex<Vec<ChunkFailure>>,
    /// Rules that matched a chunk without any string of theirs matching in it.
    ///
    /// A rule can be true without a pattern being found — `condition: true`, a
    /// condition over `filesize` alone, one over a module's fields. There is no
    /// address to report for such a match, so this scanner emits no hit for it
    /// and names the rule here instead. Silence would be the wrong answer
    /// twice: the examiner's rule fired and no row said so, and `filesize`
    /// means nothing over a chunk of an address space in the first place.
    matched_without_pattern: Mutex<BTreeSet<String>>,
}

/// What a rule's condition was evaluated over, stated on every outcome.
pub const CONDITION_SCOPE: &str =
    "Each rule was evaluated against one CHUNK of the address space at a time, not against the \
     image. An individual string match is reliable and is what these hits are. A condition \
     joining two strings (`$a and $b`) fires only where both fall in the same chunk, so a rule \
     whose strings sit either side of a chunk boundary -- or megabytes apart -- does not fire. \
     `filesize` is meaningless here: there is no file, and the chunk's length is not \
     substituted for one. A count (`#a > 10`) counts within a chunk. A larger chunk moves these \
     boundaries rather than removing them.";

impl MemoryYaraScanner {
    /// Wrap a compiled rule set.
    pub fn new(name: impl Into<String>, inner: Arc<YaraScanner>) -> Self {
        let rule_names = inner.rule_identifiers();
        Self {
            name: name.into(),
            inner,
            rule_names,
            failures: Mutex::new(Vec::new()),
            matched_without_pattern: Mutex::new(BTreeSet::new()),
        }
    }

    /// Rules in the set.
    pub fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }

    /// The rule a [`Hit::pattern_id`] refers to.
    pub fn rule_name(&self, pattern_id: u32) -> Option<&str> {
        self.rule_names.get(pattern_id as usize).map(String::as_str)
    }

    /// Every rule in the set, in the order `pattern_id` indexes.
    pub fn rule_names(&self) -> &[String] {
        &self.rule_names
    }

    /// Chunks the engine refused, in the order they were met.
    ///
    /// **Read this before reading an empty hit list as a clean image.**
    pub fn failures(&self) -> Vec<ChunkFailure> {
        self.failures
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// The same, **and clears them**, so the next scan's record carries only
    /// what the next scan met. See [`ScannerDiagnostics::take_refused_chunks`]:
    /// one compiled rule set drives every process of an image and then the next
    /// image, and a fault republished on later records is a fault attributed to
    /// a scan that did not have it.
    pub fn take_failures(&self) -> Vec<ChunkFailure> {
        self.failures
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    /// Rules that matched without any string of theirs matching.
    ///
    /// These produced **no hit**, because there is no address to report for
    /// them. See the field's own documentation for why they are named rather
    /// than dropped.
    pub fn rules_matched_without_pattern(&self) -> Vec<String> {
        self.matched_without_pattern
            .lock()
            .map(|guard| guard.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The same, **and clears them**, for the reason
    /// [`Self::take_failures`] gives.
    pub fn take_rules_matched_without_pattern(&self) -> Vec<String> {
        self.matched_without_pattern
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard).into_iter().collect())
            .unwrap_or_default()
    }

    /// What a rule's condition was evaluated over.
    pub fn condition_scope(&self) -> &'static str {
        CONDITION_SCOPE
    }
}

impl Scanner for MemoryYaraScanner {
    fn name(&self) -> &str {
        &self.name
    }

    /// **Unbounded**, like the regex scanner's.
    ///
    /// A YARA string can be a regex or a hex pattern with jumps, so no bound on
    /// a match's length is knowable from the rule set. The driver publishes
    /// `pattern_may_exceed_overlap` rather than quietly missing a match that
    /// straddles a chunk boundary.
    fn max_match_len(&self) -> Option<u64> {
        None
    }

    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl) {
        let mut scanner = yara_x::Scanner::new(self.inner.rules());
        scanner.set_timeout(CHUNK_TIMEOUT);
        let results = match scanner.scan(chunk) {
            Ok(results) => results,
            Err(err) => {
                // Counted, never swallowed: see the module comment.
                if let Ok(mut failures) = self.failures.lock() {
                    failures.push(ChunkFailure {
                        address: base,
                        bytes: chunk.len(),
                        detail: err.to_string(),
                    });
                }
                return;
            }
        };
        for rule in results.matching_rules() {
            let pattern_id = self
                .rule_names
                .iter()
                .position(|name| name == rule.identifier())
                .unwrap_or(0) as u32;
            if rule.patterns().all(|pattern| pattern.matches().len() == 0) {
                // True without a string of its own being found. Named, because
                // no hit can carry it.
                if let Ok(mut named) = self.matched_without_pattern.lock() {
                    named.insert(rule.identifier().to_string());
                }
            }
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    let range = m.range();
                    let Some(address) = base.checked_add(range.start as u64) else {
                        continue;
                    };
                    let hit = Hit {
                        address,
                        pattern_id,
                        length: u32::try_from(range.len()).unwrap_or(u32::MAX),
                    };
                    if sink(hit) == ScanControl::Stop {
                        return;
                    }
                }
            }
        }
    }
}

/// The two things the hit list cannot carry: a chunk the engine refused, and a
/// rule that fired with no string of its own found.
impl ScannerDiagnostics for MemoryYaraScanner {
    fn take_refused_chunks(&self) -> Vec<RefusedChunk> {
        self.take_failures()
            .into_iter()
            .map(|failure| RefusedChunk {
                address: failure.address,
                bytes: failure.bytes,
                detail: failure.detail,
            })
            .collect()
    }

    fn take_matched_without_address(&self) -> Vec<String> {
        self.take_rules_matched_without_pattern()
    }
}
