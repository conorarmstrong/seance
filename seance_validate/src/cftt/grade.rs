//! Grading a CFTT string-search expectation against what a tool reported.
//!
//! # The mapping, and why each status is the one it is
//!
//! CFTT's own model is that an assertion is **conditional on a feature**: "if a
//! feature is not present, then requirements for those features will not be
//! tested". That is what decides which of four statuses an expectation earns,
//! and getting it wrong in either direction is the whole risk of this file —
//! one way reports defects the tool does not have, the other way hides the ones
//! it does.
//!
//! | the expectation | the status | why |
//! |---|---|---|
//! | is in unallocated space | **not applicable** | Séance offers no unallocated-space search. The assertion is conditional on a feature that is not present, which is CFTT's own concept and is not a pass. |
//! | is contradicted by the image's own bytes at its offset (`--image`) | **not assessed** | A fault in the key, not the tool: the evidence says the row is wrong, so it can grade nothing. One real row, 7010 (VAL-002). A row pointing at the publisher's own `<id> <====` marker is not a contradiction. |
//! | names a file that is not at its offset, which Sleuth Kit places in another (`--key-files`) | graded against **that** file | Owner decision (a), 2026-09-26: the offset is the publisher's primary claim, the name a label. Stated on the row and counted beside the headline. Fourteen real rows (VAL-002). |
//! | names no file, and the tool reports no offsets | **not assessed** | The run reached the question and cannot compare the answers: the key states a position and the tool states artifacts. Neither a pass nor a defect. |
//! | is in a live filesystem and the term was found there | **pass** | |
//! | is in a live filesystem and it was not | **fail** | Including where the cause is a known limitation of an offered feature — a CJK or Korean term stored as UTF-16, `SEARCH-002`. The run reached the question and the tool answered wrongly, and calling that "not assessed" would hide a real gap behind a status invented for the opposite case. |
//!
//! The third row's distinction is the one worth restating: **a miss caused by a
//! limitation of a feature the tool does offer is a fail.** `NotAssessed`
//! exists for "could not look", not for "looked with a tool that cannot see
//! this".
//!
//! # And the order the four are decided in
//!
//! **Not-applicable is settled before the state of the run**, because whether
//! an assertion is applicable is a property of the tool's feature set and of
//! the key: it is true whether or not a search ran. The order was the other
//! way round first, and grading the real key against an empty result set then
//! reported "921 not assessed" when 134 of those were never assessable by this
//! tool at all.
//!
//! Everything after that does depend on the run, so an incomplete search
//! settles every remaining expectation before any comparison is attempted.

use crate::cftt::string_search::{Expectation, Locus, RowVerdict};
use crate::CaseStatus;

/// What a tool reported for one search term.
///
/// Séance's search returns **artifacts**, not byte offsets, so `offsets` is
/// empty for it. The field exists because the comparison a grader can make
/// depends on which the tool gives, and a grader that assumed offsets would
/// grade every Séance result as not comparable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportedHits {
    /// Artifact names or paths the search returned, as the tool spelled them.
    pub artifact_names: Vec<String>,
    /// Byte offsets, for a tool that reports them.
    pub offsets: Vec<u64>,
    /// Set when the search itself did not complete, so an empty result is not
    /// read as "the term is not there".
    pub search_incomplete: Option<String>,
}

impl ReportedHits {
    /// Whether the tool reported anything at all for the term.
    pub fn any(&self) -> bool {
        !self.artifact_names.is_empty() || !self.offsets.is_empty()
    }

    /// Whether a reported artifact's name is the one the key expects.
    ///
    /// Compared on the **base name**, case-insensitively: a tool reports a
    /// path and the key names a file, and `LIVE-plot-fat-ascii.txt` is the same
    /// file whether it arrives as itself or as
    /// `/img/p1/LIVE-plot-fat-ascii.txt`.
    pub fn names(&self, file_name: &str) -> bool {
        let want = base_name(file_name);
        self.artifact_names
            .iter()
            .any(|got| base_name(got).eq_ignore_ascii_case(&want))
    }
}

fn base_name(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_string()
}

/// One graded expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graded {
    /// The published hit id.
    pub id: String,
    pub term: String,
    /// The CFTT assertion this row serves, when the runner knows it.
    pub assertion: Option<String>,
    pub status: CaseStatus,
    /// What the key asked for, in words.
    pub expected: String,
    /// What was observed, or the reason there is nothing to observe.
    pub actual: String,
    /// The file this row was graded against **instead of the one the key
    /// names**, when the key's file is not on the image and a reference tool
    /// placed the key's byte offset in this one (VAL-002, owner decision
    /// 2026-09-26). `None` for every row graded as published.
    pub graded_against: Option<String>,
}

/// What the tool recovered, so a miss can be attributed to the right half of
/// the tool.
///
/// **A term not found in a file the tool never recovered is a file-recovery
/// finding, not a search finding**, and reporting both as "not found" sends an
/// examiner to the wrong half of the product.
///
/// **But the key's file name is a claim to check, not a fact** (VAL-002). The
/// 2026-09-15 run compared the key's names with this inventory and blamed
/// file recovery for fifteen rows. Checked with Sleuth Kit on 2026-09-26, none
/// of the fifteen was a recovery gap: twelve key names
/// (`LIVE-LOUDBIRD-fat-ascii.txt`, `LIVE-WADI-fat-utf-8.txt`, ...) are aliases
/// no partition holds -- the bytes at their offsets are in
/// `LIVE-thunderbird-fat-ascii.txt`, `LIVE-cañón-fat-utf-8.txt` and so on --
/// two were `FRAG-UNKNOWN` read as a file name, and one (row 7010) points at
/// zeroed unallocated space. So a recovery claim is made only against the file
/// a reference tool places at the row's offset ([`Expectation::image_file`]);
/// without that resolution a missing name is not attributed either way.
#[derive(Debug, Clone, Default)]
pub struct Recovered {
    /// Base names of every file the tool produced, lower-cased.
    names: std::collections::BTreeSet<String>,
    /// Unset when no inventory was collected, in which case no attribution is
    /// made either way rather than one being guessed.
    known: bool,
}

impl Recovered {
    /// An inventory of the files the tool recovered.
    pub fn from_names<I: IntoIterator<Item = String>>(names: I) -> Self {
        Self {
            names: names
                .into_iter()
                .map(|n| base_name(&n).to_ascii_lowercase())
                .collect(),
            known: true,
        }
    }

    /// No inventory was collected.
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Whether the tool recovered a file of this name. `None` when no
    /// inventory was collected -- which is not the same as "no".
    pub fn has(&self, file_name: &str) -> Option<bool> {
        self.known.then(|| {
            self.names
                .contains(&base_name(file_name).to_ascii_lowercase())
        })
    }
}

/// Grade one expectation against what the tool reported for its term.
pub fn grade(
    expectation: &Expectation,
    reported: &ReportedHits,
    assertion: Option<&str>,
) -> Graded {
    grade_with_inventory(expectation, reported, assertion, &Recovered::unknown())
}

/// Grade one expectation, attributing a miss with the help of what the tool
/// recovered.
pub fn grade_with_inventory(
    expectation: &Expectation,
    reported: &ReportedHits,
    assertion: Option<&str>,
    recovered: &Recovered,
) -> Graded {
    let id = expectation.id.clone();
    let term = expectation.term.clone();
    let assertion = assertion.map(str::to_string);
    let at = match expectation.position.offsets().as_slice() {
        [] => "no published offset".to_string(),
        [one] => format!("byte {one}"),
        many => format!(
            "bytes {}",
            many.iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" and ")
        ),
    };
    let expected = format!(
        "{term:?} ({}) at {at} in {}",
        expectation.encoding,
        expectation
            .file_name
            .as_deref()
            .unwrap_or("a file the key does not name")
    );

    // Unallocated space first, BEFORE the state of the run. Whether an
    // assertion is applicable is a property of the tool's feature set and of
    // the key -- it is true whether or not a search ran -- so a failed or
    // unfinished run must not convert 134 never-applicable expectations into
    // 134 unanswered questions. This ordering was the other way round first,
    // and a run over an empty result set reported "921 not assessed" when 134
    // of them were never assessable by this tool at all.
    if !expectation.locus.is_gradeable() {
        let where_ = match &expectation.locus {
            Locus::Unallocated => "unallocated space".to_string(),
            other => format!("a locus this build does not recognise ({})", other.as_str()),
        };
        return Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::NotApplicable,
            expected,
            actual: format!(
                "This expectation is in {where_}. Séance searches parsed records and the content \
                 of files it could read; it offers no search of unallocated space, so the \
                 assertion is conditional on a feature that is not present. That is not a pass \
                 and it is not a defect."
            ),
        };
    }

    // Then the key itself. A row whose own claim the image contradicts -- the
    // term's bytes are not at its offset -- cannot grade the tool either way
    // (VAL-002: row 7010 points at an unallocated NTFS cluster of zeros).
    // Like applicability, this is a property of the key and the image, so it
    // is settled before the state of the run.
    if let Some(RowVerdict::BytesDiffer { at: fault, found }) = &expectation.image_check {
        let shown: String = found
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        return Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::NotAssessed,
            expected,
            actual: format!(
                "Fault in the publisher's row, not in the tool: the image does not hold this \
                 term ({}) at byte {fault} -- it holds `{shown}` there. A row whose own claim \
                 the evidence contradicts cannot grade a tool, so this is unassessed; it is \
                 neither a pass nor a failure of Séance.",
                expectation.encoding
            ),
        };
    }

    // Now the state of the run. A search that did not complete cannot be read
    // as an absence, so it settles every remaining expectation before any
    // comparison is attempted.
    if let Some(why) = &reported.search_incomplete {
        return Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::NotAssessed,
            expected,
            actual: format!(
                "The search did not complete ({why}), so nothing it returned or did not return \
                 is evidence about this expectation."
            ),
        };
    }

    // An expectation with no published offset is graded on presence alone: the
    // publisher says the term is inside a compressed container and states no
    // position, so "was it found at all" is the only question it asks.
    if !expectation.position.is_comparable() {
        return if reported.any() {
            Graded {
                id,
                term,
                assertion,
                graded_against: None,
                status: CaseStatus::Pass,
                expected,
                actual: format!(
                    "Found. The key publishes no offset for this term -- it is inside a \
                     compressed container -- so this grades presence only, and presence is what \
                     it asks for. {} artifact(s) returned.",
                    reported.artifact_names.len()
                ),
            }
        } else {
            Graded {
                id,
                term,
                assertion,
                graded_against: None,
                status: CaseStatus::Fail,
                expected,
                actual: "Not found. The key asks for this term inside a compressed container and \
                         the search returned nothing for it."
                    .to_string(),
            }
        };
    }

    // Where the key's named file is not the file at the key's own offset --
    // an alias the image does not hold (`LIVE-LOUDBIRD-fat-ascii.txt`), or a
    // `FRAG-UNKNOWN` label -- and a reference tool placed the offset in a
    // file, the row is graded against THAT file, and says so (VAL-002, owner
    // decision (a) 2026-09-26: the offset is the publisher's primary claim,
    // the name a label). A bare `UNKNOWN` (`META`) row is not substituted: its
    // hit may be in a directory entry or MFT record, not a file's content.
    let substitute: Option<&str> = match (
        expectation.image_file.as_deref(),
        expectation.file_name.as_deref(),
    ) {
        (Some(on_image), Some(named))
            if !base_name(on_image).eq_ignore_ascii_case(&base_name(named)) =>
        {
            Some(on_image)
        }
        (Some(on_image), None)
            if !expectation
                .file_label
                .trim()
                .eq_ignore_ascii_case("UNKNOWN") =>
        {
            Some(on_image)
        }
        _ => None,
    };
    let finish = |mut g: Graded| -> Graded {
        if let Some(on_image) = substitute {
            // Say what the key names -- or that it names none (`FRAG-UNKNOWN`)
            // -- and credit only what the grader was given: `--key-files`,
            // whose rows record per row how each file was resolved.
            let named = match &expectation.file_name {
                Some(n) => format!("The key names `{n}`"),
                None => format!("The key names no file (`{}`)", expectation.file_label),
            };
            g.actual = format!(
                "{named}; the offset resolution given to the grader (`--key-files`) places \
                 {at} in `{on_image}`, and the key's name is not on the image at that offset, \
                 so this row is graded against `{on_image}` (owner decision 2026-09-26). {}",
                g.actual
            );
            g.graded_against = Some(on_image.to_string());
        }
        g
    };

    // A file name is what a Séance result can be compared against, because it
    // returns artifacts and not offsets. Without one, the run reached the
    // question and cannot answer it.
    let Some(file_name) = substitute.or(expectation.file_name.as_deref()) else {
        return Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::NotAssessed,
            expected,
            actual: format!(
                "The key states {at} and does not name the file the term is in; this tool \
                 reports the artifacts a term was found in and not byte offsets. There is \
                 nothing to compare, so this is unassessed rather than passed or failed. \
                 {} artifact(s) were returned for the term.",
                reported.artifact_names.len()
            ),
        };
    };

    if reported.names(file_name) {
        return finish(Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::Pass,
            expected,
            actual: format!("Found in {file_name}."),
        });
    }

    // Not found. Attribute it to the right half of the tool before anything
    // else: a term missing from a file the tool never recovered is a
    // FILE-RECOVERY finding, and calling it a search finding sends an examiner
    // to the wrong place.
    //
    // That claim needs the file's name ON THE IMAGE (VAL-002): twelve of the
    // key's names are aliases no partition holds, so a key name missing from
    // the inventory proves nothing unless a reference tool resolved the
    // row's offset to a file (`image_file`). Without that, the miss is not
    // attributed either way.
    if recovered.has(file_name) == Some(false) && expectation.image_file.is_none() {
        return Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::Fail,
            expected,
            actual: format!(
                "Not found in {file_name}, and no file of that name is in this case. That is \
                 not attributed to recovery or to search: a file name in the key is the \
                 publisher's label, not a name checked on the image (VAL-002), and no \
                 reference tool resolved this row's offset to a file. The search returned {} artifact(s) for \
                 the term.",
                reported.artifact_names.len()
            ),
        };
    }
    if recovered.has(file_name) == Some(false) {
        return finish(Graded {
            id,
            term,
            assertion,
            graded_against: None,
            status: CaseStatus::Fail,
            expected,
            actual: format!(
                "Not found, and `{file_name}` is not in this case at all -- the tool did not \
                 recover that file, so this is a FILE-RECOVERY failure and not a search one. \
                 The search returned {} artifact(s) for the term, so the term itself is \
                 reachable where the tool could read it.",
                reported.artifact_names.len()
            ),
        });
    }
    let recovered_note = match recovered.has(file_name) {
        Some(true) => format!(
            " `{file_name}` WAS recovered, so this is a search failure inside a file the tool \
             could read."
        ),
        // No inventory: no attribution is made rather than one being guessed.
        _ => String::new(),
    };

    // Where the cause is a limitation this build has recorded, the reason is
    // named -- and it is still a fail, because the run reached the question and
    // the tool answered wrongly.
    let known = known_limitation(expectation);
    finish(Graded {
        id,
        term,
        assertion,
        graded_against: None,
        status: CaseStatus::Fail,
        expected,
        actual: match known {
            Some(why) => format!(
                "Not found in {file_name}. {why} This is recorded as a failure and not as \
                 unassessed: the run reached the question and the tool did not find a term that \
                 is there.{}{recovered_note}",
                if reported.any() {
                    format!(
                        " The search returned {} other artifact(s) for the term.",
                        reported.artifact_names.len()
                    )
                } else {
                    String::new()
                }
            ),
            None => format!(
                "Not found in {file_name}. The search returned {} artifact(s) for this term, \
                 none of them that file.{recovered_note}",
                reported.artifact_names.len()
            ),
        },
    })
}

/// A limitation of this build that explains a miss, when one does.
///
/// Naming it is not excusing it: the grade stays a failure. What it buys is
/// that the report says which defect a run's failures are, rather than leaving
/// a reader to guess from a list of terms.
fn known_limitation(expectation: &Expectation) -> Option<String> {
    let wide = expectation.encoding.starts_with("utf-16");
    if !wide || utf16_index_reaches(&expectation.term) {
        return None;
    }
    const SWEEP: &str = "The case-wide byte sweep searches it.";
    // Three different causes, and only the first is the owner's decision
    // (2026-09-26): the reason printed on a graded row must not lend the
    // other two that decision's authority.
    if expectation.term.chars().any(is_cjk_or_hangul) {
        return Some(format!(
            "The term is stored as UTF-16 and contains CJK ideographs or Korean Hangul, which \
             this build's content indexer does not index in UTF-16 -- excluded by decision \
             (2026-09-26), `SEARCH-002` in BUGS.md. {SWEEP}"
        ));
    }
    // A character the passes accept in no position. Tested after an ASCII
    // letter so that a combining mark is judged as the attached mark it is.
    if let Some(c) = expectation
        .term
        .chars()
        .find(|c| !utf16_index_reaches(&format!("a{c}")))
    {
        return Some(format!(
            "The term is stored as UTF-16 and contains U+{:04X} ({c}), which is in no block \
             this build's content indexer accepts in UTF-16. This is the open remainder of \
             `SEARCH-002` in BUGS.md, not the decided CJK/Hangul exclusion. {SWEEP}",
            c as u32
        ));
    }
    Some(format!(
        "The term is stored as UTF-16 and mixes letters from two alphabets, which this build's \
         content indexer splits into separate runs where the alphabet changes -- the open \
         remainder of `SEARCH-002` in BUGS.md, not the decided CJK/Hangul exclusion. {SWEEP}"
    ))
}

/// CJK ideographs (with extension A and the compatibility block), and Korean
/// Hangul syllables and jamo -- what owner decision (1) of 2026-09-26 keeps
/// out of the UTF-16 index.
fn is_cjk_or_hangul(c: char) -> bool {
    matches!(
        c as u32,
        0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFAFF
            | 0x20000..=0x3FFFF
            | 0xAC00..=0xD7A3
            | 0x1100..=0x11FF
            | 0x3130..=0x318F
    )
}

/// Whether the content indexer's UTF-16 passes can index `term` as one run.
///
/// A restatement of `seance_search`'s `utf16_runs` rule (`SEARCH-002`, owner
/// decision 2026-09-26), kept here rather than imported because this crate
/// does not link the search index at run time. Its tests do:
/// `the_utf16_reach_rule_matches_the_indexer` puts a fixed term list, and the
/// real-key test every UTF-16 term on the CFTT key (when `SEANCE_CFTT_SS` is
/// set), through `seance_search::utf16_indexed_text` and fails on any term
/// where this prediction and the indexer disagree. Reached: ASCII, the Latin-1
/// letters U+00C0–U+00FE less `×`/`÷`, combining marks U+0300–U+036F after a
/// character, and letters from ONE of the blocks Greek (0x03), Cyrillic
/// (0x04), Cyrillic Supplement/Armenian/Hebrew (0x05), Arabic (0x06) and kana
/// (0x30, from U+3041) per run —
/// which leaves CJK ideographs, Hangul and every other script out.
pub fn utf16_index_reaches(term: &str) -> bool {
    const BLOCKS: [u32; 5] = [0x03, 0x04, 0x05, 0x06, 0x30];
    let mut lock: Option<u32> = None;
    let mut chars = 0usize;
    for c in term.chars() {
        let u = c as u32;
        let zero_high = (u < 0x80
            && (c == '\t' || c == '\n' || c == '\r' || (' '..='~').contains(&c)))
            || ((0xC0..=0xFE).contains(&u) && u != 0xD7 && u != 0xF7);
        let generic_mark = (0x0300..=0x036F).contains(&u);
        if zero_high || (generic_mark && chars > 0) {
            chars += 1;
            continue;
        }
        let high = u >> 8;
        // The kana block starts at U+3041: U+3000–U+3040 is refused.
        if u > 0xFFFF
            || !BLOCKS.contains(&high)
            || (high == 0x30 && u < 0x3041)
            || lock.is_some_and(|l| l != high)
        {
            return false;
        }
        // Letters, digits and (after a character) the block's own marks; the
        // block's punctuation is a separator in the indexer, so not reached.
        let is_mark =
            chars > 0 && lock == Some(high) && unicode_normalization::char::is_combining_mark(c);
        if !(c.is_alphanumeric() || is_mark) {
            return false;
        }
        lock = Some(high);
        chars += 1;
    }
    true
}

/// What a whole set of grades says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GradeSummary {
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub not_assessed: usize,
    /// Assessed rows graded against the file at the key's offset rather
    /// than the file the key names ([`Graded::graded_against`]).
    pub substituted: usize,
}

impl GradeSummary {
    pub fn of(grades: &[Graded]) -> Self {
        let mut s = Self::default();
        for g in grades {
            match g.status {
                CaseStatus::Pass => s.passed += 1,
                CaseStatus::Fail => s.failed += 1,
                CaseStatus::NotApplicable => s.not_applicable += 1,
                CaseStatus::NotAssessed => s.not_assessed += 1,
                // A grade is never produced as skipped: a skip is the absence
                // of the image, which the framework decides before any of this
                // runs.
                CaseStatus::Skipped => s.not_assessed += 1,
            }
            if g.graded_against.is_some() {
                s.substituted += 1;
            }
        }
        s
    }

    /// The total the four counts must add to.
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.not_applicable + self.not_assessed
    }

    /// The sentence a report needs. **The denominator is the assessed ones**,
    /// because a percentage over the whole set silently counts a
    /// not-applicable as a success for the tool.
    pub fn describe(&self) -> String {
        let assessed = self.passed + self.failed;
        let mut s = format!(
            "{} of {} assessed expectations were found ({} not found).",
            self.passed, assessed, self.failed
        );
        if assessed == 0 {
            s = "No expectation was assessed at all, so this run establishes nothing about the \
                 tool."
                .to_string();
        }
        if self.substituted > 0 {
            s.push_str(&format!(
                " {} of these were graded against the file the offset resolution \
                 (`--key-files`) places at the key's byte offset, because the file the key names is not on the image there (owner \
                 decision 2026-09-26); each such row says so.",
                self.substituted
            ));
        }
        if self.not_applicable > 0 {
            s.push_str(&format!(
                " {} were not applicable -- they are conditional on a feature this tool does not \
                 offer -- and are counted in neither number above, because counting them as \
                 passes would credit the tool for a search it does not perform.",
                self.not_applicable
            ));
        }
        if self.not_assessed > 0 {
            s.push_str(&format!(
                " {} were not assessed: the run reached the question and could not compare the \
                 answers.",
                self.not_assessed
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cftt::string_search::parse_answer_key;

    fn one(row: &str) -> Expectation {
        let key = parse_answer_key(row);
        assert!(key.rejected.is_empty(), "{:?}", key.rejected);
        key.expectations
            .into_iter()
            .next()
            .expect("one expectation")
    }

    fn found_in(names: &[&str]) -> ReportedHits {
        ReportedHits {
            artifact_names: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// The ordinary pass: the key names a file and the search returned it.
    #[test]
    fn a_term_found_in_the_file_the_key_names_is_a_pass() {
        let e = one("0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8\n");
        let g = grade(
            &e,
            &found_in(&["LIVE-plot-fat-ascii.txt"]),
            Some("FT-SS-01"),
        );
        assert_eq!(g.status, CaseStatus::Pass);
        assert_eq!(g.assertion.as_deref(), Some("FT-SS-01"));
        assert!(g.expected.contains("byte 9438368"), "{}", g.expected);
        assert!(
            g.expected.contains("\"plan \""),
            "the term's trailing space is visible in the report: {}",
            g.expected
        );
        assert!(g.actual.contains("Found in LIVE-plot-fat-ascii.txt"));
    }

    /// A tool reports a path; the key names a file. The same file.
    #[test]
    fn a_reported_path_matches_the_file_the_key_names() {
        let e = one("0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8\n");
        for reported in [
            "/img/p1/LIVE-plot-fat-ascii.txt",
            "\\img\\p1\\live-plot-fat-ascii.txt",
        ] {
            assert_eq!(
                grade(&e, &found_in(&[reported]), None).status,
                CaseStatus::Pass,
                "{reported}"
            );
        }
    }

    /// The ordinary failure: the search returned other files and not that one.
    #[test]
    fn a_term_not_found_in_the_named_file_is_a_failure() {
        let e = one("0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8\n");
        let g = grade(&e, &found_in(&["something-else.txt", "another.txt"]), None);
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(
            g.actual.contains("returned 2 artifact(s)") && g.actual.contains("none of them"),
            "{}",
            g.actual
        );
    }

    /// **Unallocated space is not applicable, not a failure.** Séance offers
    /// no search of it, so the assertion is conditional on a feature that is
    /// not present — CFTT's own concept.
    #[test]
    fn an_unallocated_expectation_is_not_applicable_and_is_not_a_pass() {
        let e = one("7000:SecretKey:15427:30:LIVE-MFT-Hidden-mft-ascii.txt:unalloc:utf-8\n");
        let g = grade(&e, &ReportedHits::default(), Some("SS-CA-02"));
        assert_eq!(g.status, CaseStatus::NotApplicable);
        assert!(
            g.actual.contains("offers no search of unallocated space")
                && g.actual.contains("not a pass"),
            "{}",
            g.actual
        );
        // And it stays not-applicable even when the term WAS found elsewhere:
        // finding it somewhere else is not finding it there.
        assert_eq!(
            grade(&e, &found_in(&["somewhere.txt"]), None).status,
            CaseStatus::NotApplicable
        );
    }

    /// **A row that names no file is unassessed**, because this tool reports
    /// artifacts and the key states a position. 77 real rows are like this.
    #[test]
    fn a_row_that_names_no_file_is_unassessed_rather_than_guessed() {
        let e = one("META:cañón:1000741041:1954572:UNKNOWN:exfat:utf-16-be\n");
        let g = grade(&e, &found_in(&["anything.txt"]), None);
        assert_eq!(g.status, CaseStatus::NotAssessed);
        assert!(
            g.actual.contains("nothing to compare")
                && g.actual.contains("unassessed rather than passed or failed"),
            "{}",
            g.actual
        );
        assert!(
            g.expected.contains("a file the key does not name"),
            "{}",
            g.expected
        );
    }

    /// **A row with no published offset grades presence only**, which is what
    /// it asks: the term is inside a compressed container.
    #[test]
    fn a_row_with_no_published_offset_grades_presence_only() {
        let e = one("9004:peroxide:zipped:zipped:FMT-explosive-docx-win.docx:fat32:UTF\n");
        let found = grade(&e, &found_in(&["anything-at-all.bin"]), None);
        assert_eq!(
            found.status,
            CaseStatus::Pass,
            "presence is the whole question: {}",
            found.actual
        );
        assert!(
            found.actual.contains("grades presence only"),
            "{}",
            found.actual
        );

        let missing = grade(&e, &ReportedHits::default(), None);
        assert_eq!(missing.status, CaseStatus::Fail);
        assert!(
            missing.actual.contains("compressed container"),
            "{}",
            missing.actual
        );
    }

    /// **A miss caused by a known limitation is still a failure**, and the
    /// limitation is named so a reader knows which defect the failures are.
    ///
    /// `NotAssessed` exists for "could not look", not for "looked with a tool
    /// that cannot see this".
    #[test]
    fn a_miss_caused_by_a_known_limitation_is_a_failure_that_names_it() {
        let e = one("1:東京:1000741041:1954572:LIVE-x-exfat-utf16.txt:exfat:utf-16-be\n");
        let g = grade(&e, &ReportedHits::default(), None);
        assert_eq!(
            g.status,
            CaseStatus::Fail,
            "a limitation of an offered feature is a defect, not an unasked question"
        );
        assert!(
            g.actual.contains("SEARCH-002") && g.actual.contains("CJK"),
            "{}",
            g.actual
        );
        assert!(
            g.actual
                .contains("recorded as a failure and not as unassessed"),
            "{}",
            g.actual
        );
    }

    /// A term outside the UTF-16 reach for a reason the owner decision did not
    /// cover -- the U+FB01 ligature in `inﬁnity` -- is named with its real
    /// cause and is not attributed to that decision, which covered CJK and
    /// Hangul only.
    #[test]
    fn a_miss_outside_the_decided_exclusion_does_not_claim_the_decision() {
        let e = one("1:in\u{FB01}nity:1000741041:1954572:LIVE-x-fat-utf16.txt:fat32:utf-16-le\n");
        let g = grade(&e, &ReportedHits::default(), None);
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(g.actual.contains("SEARCH-002"), "{}", g.actual);
        assert!(
            g.actual.contains("U+FB01"),
            "the character must be named: {}",
            g.actual
        );
        assert!(
            !g.actual.contains("by decision") && g.actual.contains("not the decided"),
            "the ligature is not what the decision excluded: {}",
            g.actual
        );
    }

    /// Accented Latin and the single-block alphabets in UTF-16 are indexed
    /// since 2026-09-26, so a miss there is an unexplained failure and must
    /// not borrow the `SEARCH-002` reason either.
    #[test]
    fn a_reachable_non_ascii_term_in_utf16_does_not_borrow_the_search_002_reason() {
        for row in [
            "1:cañón:1000741041:1954572:LIVE-x-exfat-utf16.txt:exfat:utf-16-be\n",
            "1:Россия:1000741041:1954572:LIVE-x-fat-utf16.txt:fat32:utf-16-le\n",
            "1:みつびし:1000741041:1954572:LIVE-x-fat-utf16.txt:fat32:utf-16-be\n",
            "1:man\u{303}ana:1000741041:1954572:LIVE-x-fat-utf16.txt:fat32:utf-16-le\n",
        ] {
            let g = grade(&one(row), &ReportedHits::default(), None);
            assert_eq!(g.status, CaseStatus::Fail);
            assert!(!g.actual.contains("SEARCH-002"), "{row}: {}", g.actual);
        }
    }

    /// Whether the real indexer's UTF-16 passes take `term` whole, in both
    /// byte orders, when it is stored between spaces in otherwise binary
    /// bytes -- the question `utf16_index_reaches` predicts. Lowercased on
    /// both sides because the index and the query are.
    pub(super) fn the_indexer_takes(term: &str) -> bool {
        let spaced = format!(" {term} ");
        [true, false].iter().all(|&le| {
            let mut bytes = vec![0xFF, 0x00, 0xFF];
            for u in spaced.encode_utf16() {
                bytes.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
            }
            bytes.extend_from_slice(&[0xFF, 0x00, 0xFF]);
            seance_search::utf16_indexed_text(&bytes)
                .to_lowercase()
                .contains(&term.to_lowercase())
        })
    }

    /// The terms the reach rule is held against: the indexer's own test terms,
    /// every non-ASCII term on the CFTT key, and the kinds of term that sit on
    /// the rule's edges (a mixed-block phrase, a ligature, a Supplement letter).
    const REACH_TERMS: &[&str] = &[
        "SecretKey",
        "cañón",
        "Schönheit",
        "garçon",
        "Mäuse",
        "libertà",
        "mañana",
        "man\u{303}ana",
        "Пароль",
        "Россия",
        "Сибирь",
        "الكسكس",
        "فلافل",
        "みつびし",
        "スバル",
        // U+3000–U+3040 is not kana and is refused (ASCII digit text).
        "あ〱あい",
        "Ελλάδα",
        "שלום",
        "==> Россия 1063",
        "密码文件",
        "東京都庁",
        "서울특별시",
        "東京",
        "中国",
        "中國",
        "서울",
        "Россия الكسكس",
        "in\u{FB01}nity",
        "Ԁобрый",
        "straße",
        "naïve café",
    ];

    /// The grader's restatement of the UTF-16 reach rule agrees with the
    /// indexer itself, term for term: it is compared with what
    /// `seance_search::utf16_indexed_text` actually returns, so a change to
    /// the indexer that the restatement does not follow fails here.
    #[test]
    fn the_utf16_reach_rule_matches_the_indexer() {
        let mut disagree = Vec::new();
        for term in REACH_TERMS {
            let predicted = utf16_index_reaches(term);
            let actual = the_indexer_takes(term);
            if predicted != actual {
                disagree.push(format!("{term:?}: predicted {predicted}, indexer {actual}"));
            }
        }
        assert!(disagree.is_empty(), "{disagree:#?}");
        // The rule is not vacuous: both answers occur.
        assert!(REACH_TERMS.iter().any(|t| utf16_index_reaches(t)));
        assert!(REACH_TERMS.iter().any(|t| !utf16_index_reaches(t)));
    }

    /// An ASCII term in UTF-16 has no such excuse: that case was fixed, so a
    /// miss there is an unexplained failure and must not borrow the reason.
    #[test]
    fn an_ascii_term_in_utf16_does_not_borrow_the_non_ascii_reason() {
        let e = one("1:SecretKey:1000741041:1954572:LIVE-x-ntfs-utf16.txt:ntfs:utf-16-be\n");
        let g = grade(&e, &ReportedHits::default(), None);
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(
            !g.actual.contains("SEARCH-002"),
            "UTF-16BE of an ASCII term is findable since 2026-09-15: {}",
            g.actual
        );
    }

    /// **A search that did not complete is not an absence**, whatever the
    /// expectation says.
    #[test]
    fn an_incomplete_search_is_unassessed_and_not_a_miss() {
        let e = one("0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8\n");
        let g = grade(
            &e,
            &ReportedHits {
                search_incomplete: Some("the index reported index_incomplete".to_string()),
                ..Default::default()
            },
            None,
        );
        assert_eq!(g.status, CaseStatus::NotAssessed);
        assert!(
            g.actual.contains("is evidence about this expectation"),
            "{}",
            g.actual
        );
        // But an unallocated row stays NOT APPLICABLE even when the run did
        // not complete: whether the assertion applies to this tool is a
        // property of the tool's feature set and of the key, not of the run.
        // The other order was tried, and grading the real key against an empty
        // result set then reported "921 not assessed" when 134 of them were
        // never assessable by this tool at all.
        let unalloc = one("7000:SecretKey:15427:30:LIVE-MFT-Hidden-mft-ascii.txt:unalloc:utf-8\n");
        assert_eq!(
            grade(
                &unalloc,
                &ReportedHits {
                    search_incomplete: Some("cut off".to_string()),
                    ..Default::default()
                },
                None
            )
            .status,
            CaseStatus::NotApplicable
        );
    }

    // --- the summary -------------------------------------------------------

    /// **The denominator is the assessed expectations.** A percentage over the
    /// whole set counts a not-applicable as a success for the tool.
    #[test]
    fn the_summary_divides_by_what_was_assessed_and_says_so() {
        let e = one("0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8\n");
        let u = one("7000:SecretKey:15427:30:LIVE-MFT-Hidden.txt:unalloc:utf-8\n");
        let m = one("META:x:1000741041:1954572:UNKNOWN:exfat:utf-8\n");
        let grades = vec![
            grade(&e, &found_in(&["LIVE-plot-fat-ascii.txt"]), None),
            grade(&e, &found_in(&["no.txt"]), None),
            grade(&u, &ReportedHits::default(), None),
            grade(&u, &ReportedHits::default(), None),
            grade(&m, &found_in(&["x.txt"]), None),
        ];
        let s = GradeSummary::of(&grades);
        assert_eq!(s.passed, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.not_applicable, 2);
        assert_eq!(s.not_assessed, 1);
        assert_eq!(s.total(), 5);
        let said = s.describe();
        assert!(said.contains("1 of 2 assessed"), "{said}");
        assert!(said.contains("counted in neither number above"), "{said}");
        assert!(said.contains("2 were not applicable"), "{said}");
        assert!(said.contains("1 were not assessed"), "{said}");
    }

    /// A run that assessed nothing establishes nothing, and says that rather
    /// than reporting "0 of 0".
    #[test]
    fn a_run_that_assessed_nothing_says_it_established_nothing() {
        let u = one("7000:x:15427:30:f:unalloc:utf-8\n");
        let s = GradeSummary::of(&[grade(&u, &ReportedHits::default(), None)]);
        assert_eq!(s.passed, 0);
        assert_eq!(s.failed, 0);
        assert!(
            s.describe().contains("establishes nothing about the tool"),
            "{}",
            s.describe()
        );
    }

    /// Every status a grade can carry is one of the four, and never `Skipped`:
    /// a skip is the absence of the image, which the framework decides before
    /// any grading happens.
    #[test]
    fn a_grade_never_reports_a_skip() {
        let rows = [
            "0144:plan :9438368:18434:f.txt:fat32:utf-8\n",
            "7000:x:15427:30:f.txt:unalloc:utf-8\n",
            "META:x:1:0:UNKNOWN:ntfs:utf-8\n",
            "9004:x:zipped:zipped:f.docx:fat32:UTF\n",
        ];
        for row in rows {
            let e = one(row);
            for reported in [ReportedHits::default(), found_in(&["f.txt"])] {
                let g = grade(&e, &reported, None);
                assert_ne!(g.status, CaseStatus::Skipped, "{row}");
            }
        }
    }
}

#[cfg(test)]
mod against_the_real_key {
    use super::*;
    use crate::cftt::string_search::parse_answer_key;

    fn real_key() -> Option<crate::cftt::string_search::AnswerKey> {
        let dir = seance_core::test_support::corpus::dir("SEANCE_CFTT_SS")?;
        let path = dir
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019")
            .join("win_string_doc.txt");
        let text = std::fs::read_to_string(&path).ok()?;
        Some(parse_answer_key(&text))
    }

    /// **What a run would report before any search is performed at all.**
    ///
    /// Grading the whole real key against an empty result set is worth doing
    /// on its own, because it fixes the shape of the run's floor and ceiling:
    /// how many expectations are not applicable to this tool whatever it finds,
    /// how many cannot be compared, and therefore how many a run can actually
    /// speak to. A run whose ceiling nobody measured can report a good
    /// percentage over a denominator that quietly excludes the hard cases.
    #[test]
    fn the_real_keys_floor_and_ceiling_are_measured() {
        let Some(key) = real_key() else { return };
        let grades: Vec<Graded> = key
            .expectations
            .iter()
            .map(|e| grade(e, &ReportedHits::default(), None))
            .collect();
        let s = GradeSummary::of(&grades);
        assert_eq!(s.total(), 921);

        // Not applicable whatever the tool finds: the 134 unallocated rows.
        assert_eq!(
            s.not_applicable, 134,
            "Séance offers no unallocated-space search, so these are conditional on an absent \
             feature however the run goes"
        );
        // Not comparable: the rows naming no file -- 77 `UNKNOWN` (72 NTFS,
        // 4 exFAT, 1 FAT32; none unallocated) and, since VAL-002, the two
        // `FRAG-UNKNOWN` rows (6000, 6006, FAT32), which were read as a file
        // name and graded as a missing file until then. With `--key-files`
        // the two FRAG-UNKNOWN rows are graded against the file Sleuth Kit
        // places at their offset (owner decision 2026-09-26) and the figures
        // return to 77 and 710 -- `the_frag_unknown_rows_return_with_key_files`.
        assert_eq!(
            s.not_assessed, 79,
            "rows stating a position and naming no file, which a tool reporting artifacts \
             cannot be compared against"
        );
        // So the run's CEILING -- the most it could ever pass -- is what is
        // left, and that number belongs in the report rather than 921.
        let assessable = s.passed + s.failed;
        assert_eq!(
            assessable, 708,
            "the most this tool could ever be graded on, out of 921 published expectations"
        );
        assert_eq!(assessable + s.not_applicable + s.not_assessed, 921);

        // With an empty result set every assessable expectation fails, which
        // is the floor and is the right answer for a run that searched nothing.
        assert_eq!(s.failed, 708);
        assert_eq!(s.passed, 0);
        let said = s.describe();
        assert!(said.contains("0 of 708 assessed"), "{said}");
        assert!(
            said.contains("counted in neither number above"),
            "the not-applicable rows must not be credited to the tool: {said}"
        );
    }

    /// The fourteen rows whose named file is not the file at their offset,
    /// resolved with Sleuth Kit on 2026-09-26 (`mmls`, then `ifind -d` and
    /// `ffind` at each published sector of `ss-win-07-25-18.dd`) -- the same
    /// table `scripts/cftt/run-string-search.sh` writes to `key-files.json`.
    pub(super) const TSK_KEY_FILES: [(&str, &str); 14] = [
        ("0928", "LIVE-thunderbird-fat-ascii.txt"),
        ("0929", "DELETED-thunderbird-fat-ascii.txt"),
        ("0930", "LIVE-thunderbird-exfat-ascii.txt"),
        ("0931", "DELETED-thunderbird-exfat-ascii.txt"),
        ("0932", "LIVE-thunderbird-ntfs-ascii.txt"),
        ("0933", "DELETED-thunderbird-ntfs-ascii.txt"),
        ("2625", "LIVE-cañón-fat-utf-8.txt"),
        ("2629", "DELETED-cañón-fat-utf-8.txt"),
        ("2633", "LIVE-cañón-exfat-utf-8.txt"),
        ("2637", "DELETED-cañón-exfat-utf-8.txt"),
        ("2641", "LIVE-cañón-ntfs-utf-8.txt"),
        ("2645", "DELETED-cañón-ntfs-utf-8.txt"),
        ("6000", "FRAG-fat-Sacramento-split-512.txt"),
        ("6006", "FRAG-fat-Olympia-split-32k.txt"),
    ];

    /// With the offsets resolved, the two `FRAG-UNKNOWN` rows are gradeable
    /// again and the fourteen substitutions are counted, not hidden.
    #[test]
    fn the_frag_unknown_rows_return_with_key_files() {
        let Some(mut key) = real_key() else { return };
        for e in &mut key.expectations {
            if let Some((_, f)) = TSK_KEY_FILES.iter().find(|(id, _)| *id == e.id) {
                e.image_file = Some(f.to_string());
            }
        }
        let grades: Vec<Graded> = key
            .expectations
            .iter()
            .map(|e| grade(e, &ReportedHits::default(), None))
            .collect();
        let s = GradeSummary::of(&grades);
        assert_eq!(s.not_assessed, 77);
        assert_eq!(s.passed + s.failed, 710);
        assert_eq!(s.substituted, 14, "every substitution is counted");
        assert!(s.describe().contains("14 of these"), "{}", s.describe());

        // And with the image's bytes checked too (`--image`), row 7010 -- the
        // one row the image contradicts -- leaves the assessable set: the
        // run's full denominator is 709, and less the 60 SEARCH-002 rows the
        // realistic ceiling is 649.
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_SS") else {
            return;
        };
        let Ok(mut img) = std::fs::File::open(
            dir.join(
                "string-search-federated-testing-data-set-version-1-1-revised-september-27-2019",
            )
            .join("copy-to-test-computer")
            .join("ss-win-07-25-18.dd"),
        ) else {
            eprintln!("skipped: the image is not present");
            return;
        };
        for e in &mut key.expectations {
            e.image_check = Some(crate::cftt::string_search::verify_row(e, &mut img));
        }
        let grades: Vec<Graded> = key
            .expectations
            .iter()
            .map(|e| grade(e, &ReportedHits::default(), None))
            .collect();
        let s = GradeSummary::of(&grades);
        assert_eq!((s.not_applicable, s.not_assessed), (134, 78));
        assert_eq!(s.passed + s.failed, 709);
        let blocked = key
            .expectations
            .iter()
            .zip(&grades)
            .filter(|(e, g)| {
                g.status == CaseStatus::Fail
                    && e.encoding.starts_with("utf-16")
                    && !utf16_index_reaches(&e.term)
            })
            .count();
        assert_eq!(
            709 - blocked,
            649,
            "the realistic ceiling with the key checked"
        );
    }

    /// How many of the assessable expectations are in an encoding this build
    /// is known not to reach — so the run's realistic ceiling is stated rather
    /// than discovered afterwards.
    #[test]
    fn the_expectations_a_known_limitation_will_fail_are_counted_in_advance() {
        let Some(key) = real_key() else { return };
        let blocked = key
            .gradeable()
            .filter(|e| e.file_name.is_some() && e.position.is_comparable())
            .filter(|e| e.encoding.starts_with("utf-16") && !utf16_index_reaches(&e.term))
            .count();
        let non_ascii_wide = key
            .gradeable()
            .filter(|e| e.file_name.is_some() && e.position.is_comparable())
            .filter(|e| e.encoding.starts_with("utf-16") && !e.term.is_ascii())
            .count();
        // Terms stored wide in a script the UTF-16 passes do not index:
        // SEARCH-002, and each will be a real failure with that reason.
        //
        // Until 2026-09-26 that was every non-ASCII term stored wide, 228 of
        // 710 -- very nearly a third of everything this run can be graded on,
        // and a ceiling of 482. Measured again 2026-09-26 against the real key
        // (SEANCE_CFTT_SS) after the Latin-1 and single-block widening: of
        // those 228, 168 are now in reach (Schönheit, garçon, Mäuse, libertà,
        // mañana in both normal forms, Россия, Сибирь, الكسكس, فلافل, みつびし,
        // スバル; 12 rows each) and 60 are not -- 東京, 中国, 中國 and 서울,
        // excluded by decision, and `inﬁnity`, whose U+FB01 ligature is in no
        // accepted block. 12 rows each. The ceiling is therefore 710 - 60 =
        // 650. It is a prediction about reach, not a result: the re-run in
        // VALIDATION.md is what says how many pass.
        assert_eq!(
            non_ascii_wide, 228,
            "every non-ASCII term stored wide, the pre-2026-09-26 blocked count"
        );
        assert_eq!(
            blocked, 60,
            "of the 710 assessable expectations, this many will fail for SEARCH-002 -- stated \
             before the run rather than explained after it"
        );
        assert_eq!(710 - blocked, 650, "the run's realistic ceiling");

        // The prediction is the indexer's, not a copy's: every term stored
        // wide on the key is put through the real UTF-16 passes.
        let mut disagree: Vec<String> = key
            .gradeable()
            .filter(|e| e.encoding.starts_with("utf-16"))
            .map(|e| e.term.clone())
            .filter(|t| utf16_index_reaches(t) != super::tests::the_indexer_takes(t))
            .collect();
        disagree.dedup();
        assert!(
            disagree.is_empty(),
            "prediction and indexer differ on {disagree:?}"
        );

        // And the ASCII-in-UTF-16 ones, which the same day's fix made
        // reachable: they are the measurable benefit of that fix. 78 of them
        // were unfindable in big-endian, because every run lost its last
        // character.
        let wide_ascii = key
            .gradeable()
            .filter(|e| e.file_name.is_some() && e.position.is_comparable())
            .filter(|e| e.encoding.starts_with("utf-16") && e.term.is_ascii())
            .count();
        assert_eq!(
            wide_ascii, 78,
            "expectations in UTF-16 whose terms are ASCII -- roughly half of them big-endian, \
             and unfindable there before 2026-09-15 because every run lost its last character"
        );
    }
}

#[cfg(test)]
mod attribution {
    use super::*;
    use crate::cftt::string_search::parse_answer_key;

    fn one(row: &str) -> Expectation {
        parse_answer_key(row)
            .expectations
            .into_iter()
            .next()
            .expect("one expectation")
    }

    fn hits(names: &[&str]) -> ReportedHits {
        ReportedHits {
            artifact_names: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// **A term missing from a file the tool never recovered is a
    /// file-recovery failure, not a search failure.**
    ///
    /// Reporting those as search failures sends an examiner to the wrong half
    /// of the product. Since VAL-002 the claim needs the file's name **on the
    /// image**: the 2026-09-15 run made it for the key's LOUDBIRD/WADI names,
    /// which are aliases the image does not hold, so it is now made only when
    /// a reference tool has resolved the row's offset to a file
    /// (`image_file`) and that file is absent from the inventory.
    #[test]
    fn a_miss_in_a_file_that_was_never_recovered_is_attributed_to_recovery() {
        let mut e =
            one("0928:thunderbird:9647288:18842:LIVE-thunderbird-fat-ascii.txt:fat32:utf-8\n");
        e.image_file = Some("LIVE-thunderbird-fat-ascii.txt".to_string());
        // The term WAS found, in a differently named file.
        let reported = hits(&["LIVE-thunderbird-ntfs-ascii.txt"]);
        let recovered = Recovered::from_names(["LIVE-thunderbird-ntfs-ascii.txt".to_string()]);
        let g = grade_with_inventory(&e, &reported, None, &recovered);
        assert_eq!(g.status, CaseStatus::Fail, "it is still a failure");
        assert!(
            g.actual
                .contains("FILE-RECOVERY failure and not a search one"),
            "{}",
            g.actual
        );
        assert!(
            g.actual.contains("is not in this case at all"),
            "{}",
            g.actual
        );
    }

    /// **And a miss in a file that WAS recovered is a search failure**, said in
    /// those words so the two are never confused.
    ///
    /// Real: `crossbow` is expected in `FMT-bolt-htmlfmt-win.html`, which the
    /// run did recover, and was not found in it — the term is broken up by
    /// markup, which is what the data set's format cases exist to probe.
    #[test]
    fn a_miss_in_a_file_that_was_recovered_is_attributed_to_the_search() {
        let e = one("9007:crossbow:8770962:17130:FMT-bolt-htmlfmt-win.html:fat32:utf-8\n");
        let recovered = Recovered::from_names([
            "FMT-bolt-htmlfmt-win.html".to_string(),
            "FMT-bolt-htmlfmt-win.txt".to_string(),
        ]);
        let g = grade_with_inventory(&e, &hits(&["FMT-bolt-htmlfmt-win.txt"]), None, &recovered);
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(
            g.actual.contains("WAS recovered")
                && g.actual
                    .contains("search failure inside a file the tool could read"),
            "{}",
            g.actual
        );
    }

    /// **With no inventory, no attribution is made either way.** An absent
    /// inventory is not evidence that a file was absent.
    #[test]
    fn with_no_inventory_no_attribution_is_guessed() {
        let e = one("0928:thunderbird:9647288:18842:LIVE-LOUDBIRD-fat-ascii.txt:fat32:utf-8\n");
        let g = grade_with_inventory(&e, &hits(&["other.txt"]), None, &Recovered::unknown());
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(
            !g.actual.contains("FILE-RECOVERY") && !g.actual.contains("WAS recovered"),
            "an absent inventory must not become a claim about the file: {}",
            g.actual
        );
    }

    fn loudbird(image_file: Option<&str>) -> Expectation {
        let mut e = one("0928:thunderbird:9647288:18842:LIVE-LOUDBIRD-fat-ascii.txt:fat32:utf-8\n");
        e.image_file = image_file.map(str::to_string);
        e
    }

    /// **A key alias is attributed by the file at its offset** (VAL-002).
    /// `LIVE-LOUDBIRD-fat-ascii.txt` is on no partition of the image; Sleuth
    /// Kit's `ifind -d`/`ffind` at sector 18842 give
    /// `/fat/LIVE-thunderbird-fat-ascii.txt`. A name check against the
    /// inventory could never find the key's name, so "not recovered" was
    /// wrong for all twelve such rows.
    #[test]
    fn a_key_alias_is_attributed_by_the_file_at_its_offset() {
        let e = loudbird(Some("LIVE-thunderbird-fat-ascii.txt"));
        let recovered = Recovered::from_names(["LIVE-thunderbird-fat-ascii.txt".to_string()]);
        let g = grade_with_inventory(
            &e,
            &hits(&["LIVE-thunderbird-ntfs-ascii.txt"]),
            None,
            &recovered,
        );
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(!g.actual.contains("FILE-RECOVERY"), "{}", g.actual);
        assert!(
            g.actual.contains("LIVE-LOUDBIRD-fat-ascii.txt")
                && g.actual.contains("LIVE-thunderbird-fat-ascii.txt")
                && g.actual.contains("WAS recovered"),
            "{}",
            g.actual
        );
    }

    /// **And graded against it** -- owner decision (a), 2026-09-26: the byte
    /// offset is the publisher's primary claim and the name a label that
    /// does not match the image. The substitution is stated on the row and
    /// counted in the summary.
    #[test]
    fn a_key_alias_is_graded_against_the_file_at_its_offset() {
        let e = loudbird(Some("LIVE-thunderbird-fat-ascii.txt"));
        let g = grade(&e, &hits(&["/fat/LIVE-thunderbird-fat-ascii.txt"]), None);
        assert_eq!(g.status, CaseStatus::Pass, "{}", g.actual);
        assert_eq!(
            g.graded_against.as_deref(),
            Some("LIVE-thunderbird-fat-ascii.txt")
        );
        assert!(
            g.actual.contains("LIVE-LOUDBIRD-fat-ascii.txt")
                && g.actual.contains("not on the image"),
            "the substitution is stated on the row: {}",
            g.actual
        );
        let s = GradeSummary::of(&[g]);
        assert_eq!(s.substituted, 1);
        assert!(s.describe().contains("1 of these"), "{}", s.describe());
    }

    /// **With no reconciliation, no recovery claim is made.** Once aliases are
    /// known to exist, a key name missing from the inventory is not evidence
    /// that the tool failed to recover a file.
    #[test]
    fn with_no_reconciliation_the_alias_attribution_is_withheld() {
        let e = loudbird(None);
        let recovered = Recovered::from_names(["LIVE-thunderbird-fat-ascii.txt".to_string()]);
        let g = grade_with_inventory(&e, &hits(&["other.txt"]), None, &recovered);
        assert_eq!(g.status, CaseStatus::Fail);
        assert!(!g.actual.contains("FILE-RECOVERY"), "{}", g.actual);
        assert!(g.actual.contains("not attributed"), "{}", g.actual);
        assert_eq!(g.graded_against, None);
    }

    /// The two `FRAG-UNKNOWN` rows are graded against the file at their
    /// offset too (row 6000, sector 8266: `FRAG-fat-Sacramento-split-512.txt`).
    #[test]
    fn a_frag_unknown_row_is_graded_against_the_file_at_its_offset() {
        let mut e = one("6000:California:4232700:8266:FRAG-UNKNOWN:fat32:utf-8\n");
        e.image_file = Some("FRAG-fat-Sacramento-split-512.txt".to_string());
        let g = grade(&e, &hits(&["FRAG-fat-Sacramento-split-512.txt"]), None);
        assert_eq!(g.status, CaseStatus::Pass, "{}", g.actual);
        assert!(g.actual.contains("FRAG-UNKNOWN"), "{}", g.actual);
        // The key names no file here -- that is why the row needed a
        // resolution at all -- so the sentence must not say it names one.
        assert!(
            g.actual.contains("names no file") && !g.actual.contains("names `FRAG-UNKNOWN`"),
            "{}",
            g.actual
        );
    }

    /// **The substitution credits only what the grader was told.** The grader
    /// reads `--key-files` and does not know which tool, or which path of
    /// it (`ifind -d`, or the FILE record number for MFT-resident data),
    /// produced a row; `key-files.json` carries that per row.
    #[test]
    fn the_substitution_does_not_name_a_tool_the_grader_was_not_told() {
        let e = loudbird(Some("LIVE-thunderbird-fat-ascii.txt"));
        let g = grade(&e, &hits(&["LIVE-thunderbird-fat-ascii.txt"]), None);
        assert!(
            !g.actual.contains("Sleuth Kit") && !g.actual.contains("ifind"),
            "{}",
            g.actual
        );
        assert!(g.actual.contains("--key-files"), "{}", g.actual);
        let said = GradeSummary::of(&[g]).describe();
        assert!(
            !said.contains("Sleuth Kit") && said.contains("--key-files"),
            "{said}"
        );
    }

    /// **The withheld attribution states no one image's measurement.** "Twelve
    /// are aliases" is a fact about `ss-win-07-25-18.dd`; the same sentence
    /// is printed for `--image unix`, where nobody measured it.
    #[test]
    fn the_withheld_attribution_quotes_no_image_specific_count() {
        let e = loudbird(None);
        let recovered = Recovered::from_names(["LIVE-thunderbird-fat-ascii.txt".to_string()]);
        let g = grade_with_inventory(&e, &hits(&["other.txt"]), None, &recovered);
        assert!(g.actual.contains("not attributed"), "{}", g.actual);
        assert!(!g.actual.contains("twelve"), "{}", g.actual);
    }

    /// A bare `UNKNOWN` (`META`) row is not substituted: the decision covers
    /// rows whose named file is not on the image, and a `META` hit may be in
    /// a directory entry or MFT record rather than a file's content.
    #[test]
    fn a_bare_unknown_row_is_not_substituted() {
        let mut e = one("META:cañón:1000741041:1954572:UNKNOWN:exfat:utf-16-be\n");
        e.image_file = Some("x.txt".to_string());
        let g = grade(&e, &hits(&["x.txt"]), None);
        assert_eq!(g.status, CaseStatus::NotAssessed, "{}", g.actual);
        assert_eq!(g.graded_against, None);
    }

    /// **A `FRAG-UNKNOWN` row is never a file-recovery failure** (VAL-002):
    /// the key names no file, so there is no file whose absence could be
    /// blamed. Graded as a name it was, twice, on the 2026-09-15 run.
    #[test]
    fn a_frag_unknown_row_is_never_a_file_recovery_failure() {
        let e = one("6000:California:4232700:8266:FRAG-UNKNOWN:fat32:utf-8\n");
        let recovered = Recovered::from_names(["other.txt".to_string()]);
        let g = grade_with_inventory(&e, &hits(&["other.txt"]), None, &recovered);
        assert_eq!(g.status, CaseStatus::NotAssessed, "{}", g.actual);
        assert!(!g.actual.contains("FILE-RECOVERY"), "{}", g.actual);
    }

    /// The inventory matches on the base name, case-insensitively, because a
    /// tool reports a path and the key names a file.
    #[test]
    fn the_inventory_matches_on_the_base_name() {
        let e = one("1:x:512:1:LIVE-Plot-Fat-Ascii.txt:fat32:utf-8\n");
        let recovered = Recovered::from_names(["/img/p1/live-plot-fat-ascii.txt".to_string()]);
        assert_eq!(recovered.has("LIVE-Plot-Fat-Ascii.txt"), Some(true));
        let g = grade_with_inventory(&e, &hits(&["nothing.txt"]), None, &recovered);
        assert!(
            g.actual.contains("WAS recovered"),
            "the file is there under a path: {}",
            g.actual
        );
    }
}

#[cfg(test)]
mod image_verification {
    use super::*;
    use crate::cftt::string_search::{parse_answer_key, RowVerdict};

    /// **A row the image contradicts is the key's fault, not the tool's**
    /// (VAL-002). Row 7010 points at NTFS cluster 43456, which Sleuth Kit's
    /// `blkstat` calls unallocated and whose bytes are all zero; it was
    /// graded as Séance failing to recover a file.
    #[test]
    fn a_row_pointing_at_zeros_does_not_verify_and_is_not_assessed() {
        let mut e = parse_answer_key(
            "7010:bear:1677997552:3277338:LIVE-MFT-Ursa-mft-utf-16-be.txt:ntfs:utf-16-le\n",
        )
        .expectations
        .remove(0);
        e.image_check = Some(RowVerdict::BytesDiffer {
            at: 1677997552,
            found: vec![0; 8],
        });
        let recovered = Recovered::from_names(["other.txt".to_string()]);
        let g = grade_with_inventory(&e, &ReportedHits::default(), None, &recovered);
        assert_eq!(g.status, CaseStatus::NotAssessed, "{}", g.actual);
        assert!(
            g.actual.contains("the publisher's row")
                && g.actual.contains("byte 1677997552")
                && !g.actual.contains("FILE-RECOVERY"),
            "{}",
            g.actual
        );
    }

    /// A row that verified, or was not checked, grades as before.
    #[test]
    fn a_verified_or_unchecked_row_grades_as_before() {
        for check in [
            None,
            Some(RowVerdict::Verified),
            Some(RowVerdict::NotChecked("no image".into())),
        ] {
            let mut e = parse_answer_key("1:x:512:1:a.txt:fat32:utf-8\n")
                .expectations
                .remove(0);
            e.image_check = check;
            let g = grade(
                &e,
                &ReportedHits {
                    artifact_names: vec!["a.txt".into()],
                    ..Default::default()
                },
                None,
            );
            assert_eq!(g.status, CaseStatus::Pass);
        }
    }
}

#[cfg(test)]
mod key_file_resolver {
    /// **The resolver that writes `key-files.json` is under a gate** (VAL-002
    /// review). The corpus-gated grade tests use the hard-coded
    /// [`super::against_the_real_key::TSK_KEY_FILES`], so a regression in
    /// `scripts/cftt/resolve-key-files.py` -- it once passed partition
    /// sectors to `ifind -d` on Ext4 and HFS+, which Sleuth Kit addresses by
    /// block, and reported "no file there" for all 926 unix rows -- would
    /// pass every Rust test. This runs the script's own tests: synthetic
    /// data-unit geometry always, and with `SEANCE_CFTT_SS` and Sleuth Kit
    /// present both real images, asserting the Windows image's fourteen
    /// substitutions equal that table.
    #[test]
    fn the_resolver_scripts_tests_pass() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/cftt/test_resolve_key_files.py");
        let out = match std::process::Command::new("python3").arg(&script).output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!(
                    "skipped: python3 could not be run ({e}), so the resolver was not tested"
                );
                return;
            }
        };
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
