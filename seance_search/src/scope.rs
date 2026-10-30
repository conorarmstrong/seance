//! What a case search can reach — the **search universe** — stated from the
//! same constants the indexer applies, so the sentence cannot drift from them.
//!
//! A search that returns nothing is read as "the term is absent from the
//! evidence". Séance states the completeness of an enumeration everywhere
//! (`index_incomplete`, `count_is_lower_bound`, `truncated`), and until
//! `SEARCH-002` it said nothing anywhere about the SCOPE being enumerated:
//! which bytes were indexed at all, and in which encodings. This module is
//! that statement, and the API returns it with every search page.

use seance_core::artifact::ArtifactType;
use serde::{Deserialize, Serialize};

use crate::{CONTENT_INDEX_CAP, MIN_STRING_LEN, UTF16_SCRIPT_BLOCKS};

/// Artifact types whose resolved bytes are read into the content index.
///
/// The indexer tests membership of this list, so the statement below and the
/// behaviour are one fact. Every other type — slack, unallocated space, raw
/// images, parsed records — is indexed by its metadata JSON only.
pub const CONTENT_INDEXED_TYPES: &[ArtifactType] =
    &[ArtifactType::FileEntry, ArtifactType::FileContent];

/// Artifact types the ingest pipeline does not re-dispatch to any module,
/// the indexer included.
///
/// A restatement of the filter in `seance_core::orchestrator` (the re-queue
/// step keeps every produced artifact except a `TimelineEvent`). The indexer
/// declares `TimelineEvent` among its subscriptions and never receives one:
/// one measured case indexed 8,134 of its 11,390 artifacts, and the gap was
/// exactly its timeline. The backfill, which walks the database, does add
/// them. If the orchestrator's filter changes, this list must change with it.
pub const NOT_DISPATCHED_TO_INDEXER: &[ArtifactType] = &[ArtifactType::TimelineEvent];

/// The route that re-indexes a case from its stored artifacts.
pub const BACKFILL_ROUTE: &str = "POST /api/v1/cases/:id/search/backfill";

/// The route that searches bytes rather than the text index, and which does
/// search a term as UTF-16LE and UTF-16BE in any script.
pub const BYTE_SWEEP_ROUTE: &str = "POST /api/v1/cases/:id/search/sweep";

/// The version of the text extractor this build indexes file bytes with.
///
/// The statement below describes THIS extractor. A case's documents were built
/// by whichever build ingested it, and the text in them is what that build's
/// extractor read — so the statement is only true of a case's index when the
/// case's documents were built by this version. The service records, per case,
/// which versions built its file documents ([`IndexTextProvenance`]).
///
/// * `1` — every build before 2026-09-26. UTF-16 text was indexed only where
///   every code unit was ASCII. These builds recorded no version at all, so a
///   document they wrote is known only by the absence of a record.
/// * `2` — from 2026-09-26 (`SEARCH-002`): also the Latin-1 letters and the
///   single-block alphabets of [`UTF16_SCRIPT_BLOCKS`] in UTF-16.
///
/// Change it whenever `extract_searchable_text` reads bytes differently.
pub const TEXT_EXTRACTOR_VERSION: u32 = 2;

/// The date the extractor behind [`TEXT_EXTRACTOR_VERSION`] took effect, for
/// the sentence that tells an examiner an older index read less.
const TEXT_EXTRACTOR_SINCE: &str = "2026-09-26";

/// Which text extractor built a case's file documents in the index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexTextExtractor {
    /// Every file document this case has in the index was built by this
    /// build's extractor, so the text coverage stated is the index's own.
    Current,
    /// Some or all of the case's file documents were built by an earlier
    /// extractor — recorded as such, or written before versions were recorded.
    /// The stated UTF-16 coverage does not hold for them.
    Earlier,
    /// The index holds no file documents for this case, so no file text was
    /// extracted and none can be stale.
    NoFileDocuments,
    /// Not checked against any case's index: the statement describes this
    /// build only.
    #[default]
    NotAssessed,
}

/// What the index records about the extractor behind one case's documents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexTextProvenance {
    pub status: IndexTextExtractor,
    /// The extractor versions recorded for the case, lowest first. Empty for
    /// a case whose documents predate recording.
    pub recorded_versions: Vec<u32>,
}

impl IndexTextProvenance {
    /// For a statement not tied to any case's index.
    pub fn not_assessed() -> Self {
        Self::default()
    }
}

/// How a query is matched, which the statement has to follow: a fuzzy search
/// is not an exact-form one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MatchMode {
    /// Keyword or query-syntax search: case-folded, otherwise exact-form.
    #[default]
    Exact,
    /// Levenshtein matching at the given (unclamped) distance.
    Fuzzy(u8),
    /// A regular expression.
    Regex,
}

impl MatchMode {
    /// The mode the engine will run `options` in. Regex takes precedence over
    /// fuzzy, as it does in the engine.
    pub fn of(options: &crate::SearchOptions) -> Self {
        if options.use_regex {
            Self::Regex
        } else if let Some(d) = options.fuzzy {
            Self::Fuzzy(d)
        } else {
            Self::Exact
        }
    }
}

/// What a case search reaches, stated with every search response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchUniverse {
    /// The whole statement as one sentence-level paragraph, for a screen or
    /// an exhibit.
    pub statement: String,
    /// Artifact types whose bytes are indexed, by name.
    pub content_artifact_types: Vec<String>,
    /// How many bytes of each such artifact are read, at most.
    pub content_bytes_per_artifact: u64,
    /// The shortest text run kept, in characters.
    pub min_run_chars: usize,
    /// What is indexed in UTF-8.
    pub utf8: String,
    /// What is indexed in UTF-16 (both byte orders).
    pub utf16: String,
    /// What is known NOT to be reached by the text index.
    pub not_covered: Vec<String>,
    /// The route that searches bytes instead, and reaches what this cannot.
    pub byte_sweep_route: String,
    /// How a query is matched against the indexed text.
    pub matching: String,
    /// The text extractor version of this build ([`TEXT_EXTRACTOR_VERSION`]).
    #[serde(default)]
    pub text_extractor_version: u32,
    /// Whether this case's documents were built by that extractor.
    #[serde(default)]
    pub index_text_extractor: IndexTextExtractor,
    /// The extractor versions the index records for this case.
    #[serde(default)]
    pub index_text_extractor_versions: Vec<u32>,
    /// Known ways the index returns a hit that is not the text it seems to be.
    #[serde(default)]
    pub known_false_matches: Vec<String>,
}

/// The search universe of this build, not checked against any case's index.
pub fn search_universe() -> SearchUniverse {
    search_universe_for(&IndexTextProvenance::not_assessed(), MatchMode::Exact)
}

/// The search universe of one search: this build's extractor, the extractor
/// that actually built the case's documents, and the match mode in force.
///
/// The coverage sentences describe the extractor of THIS build. Whether they
/// describe the index that answered depends on `provenance` — a case ingested
/// by an earlier build holds text that build read, and the statement says so
/// instead of claiming this build's coverage for it.
pub fn search_universe_for(provenance: &IndexTextProvenance, mode: MatchMode) -> SearchUniverse {
    let types: Vec<String> = CONTENT_INDEXED_TYPES
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
    let mib = CONTENT_INDEX_CAP / (1024 * 1024);
    let utf8 = "any script: letters and digits in every alphabet, ASCII punctuation and \
                spaces"
        .to_string();
    let utf16 = utf16_coverage();
    let mut not_covered = vec![
        format!(
            "{not_dispatched} artifacts: the ingest pipeline does not hand them to the indexer, \
             so their metadata is indexed only once the case has been re-indexed with the \
             backfill ({BACKFILL_ROUTE})",
            not_dispatched = NOT_DISPATCHED_TO_INDEXER
                .iter()
                .map(|t| format!("{t:?}"))
                .collect::<Vec<_>>()
                .join(" and "),
        ),
        "file text of a document the backfill added: an artifact loaded from the database \
         carries no data source, so such a document holds metadata only"
            .to_string(),
        "any artifact of a case ingested with a profile that leaves the indexer out (such a \
         case has no documents, and is not marked incomplete)"
            .to_string(),
        "slack space (no file's slack is indexed)".to_string(),
        "unallocated space and other raw regions (indexed by their metadata only)".to_string(),
        format!("bytes past the first {mib} MiB of a file"),
        format!("text runs shorter than {MIN_STRING_LEN} characters"),
        format!("UTF-16 text outside {}", utf16_reach_short()),
        "a UTF-16 word whose letters come from two alphabets of that list (for example a \
         Cyrillic word containing a Cyrillic Supplement letter, U+0500–U+052F): it is split \
         where the alphabet changes"
            .to_string(),
    ];
    // Whether the coverage above is the index's own. Named in `not_covered`
    // whenever it may not be, so the list read alone does not overstate.
    let index_sentence = match provenance.status {
        IndexTextExtractor::Current => format!(
            "Every file document this case has in the index was built by this build's text \
             extractor (version {TEXT_EXTRACTOR_VERSION}), so the text coverage above is that \
             of this index."
        ),
        IndexTextExtractor::Earlier => {
            not_covered.push(earlier_extractor_gap());
            format!(
                "Some or all of this case's file documents were indexed by an earlier build of \
                 Séance, whose text extractor read UTF-16 as ASCII only (the Latin-1 letters and \
                 the alphabets above were added on {TEXT_EXTRACTOR_SINCE}, text extractor \
                 version {TEXT_EXTRACTOR_VERSION}). In those documents the UTF-16 coverage above \
                 does not hold: a UTF-16 term outside ASCII may be present in the evidence and \
                 still not be found. Re-indexing with the backfill does not change that, because \
                 it adds metadata only; a re-ingest of the evidence does, and the byte sweep \
                 searches those bytes now."
            )
        }
        IndexTextExtractor::NoFileDocuments => "The index holds no file documents for this \
             case, so no file text was searched: only metadata."
            .to_string(),
        IndexTextExtractor::NotAssessed => {
            not_covered.push(earlier_extractor_gap());
            format!(
                "The text coverage above is that of this build's text extractor (version \
                 {TEXT_EXTRACTOR_VERSION}), and holds only for documents indexed by this build; \
                 it was not checked against the index of any case."
            )
        }
    };
    let matching = match mode {
        MatchMode::Exact => "case-insensitive (the index and the query are both lowercased) \
                             but otherwise exact-form: no Unicode normalisation is applied to \
                             the index or the query, so a precomposed (NFC) spelling does not \
                             find a decomposed (NFD) one"
            .to_string(),
        MatchMode::Fuzzy(d) => format!(
            "approximate: this is a fuzzy search, so each query term matches any indexed word \
             within Levenshtein edit distance {} of it (an edit is one character inserted, \
             deleted or substituted, or two adjacent characters swapped), after both are \
             lowercased; a hit need not contain the term as typed. No Unicode normalisation \
             is applied, so a precomposed (NFC) and a decomposed (NFD) spelling differ by \
             their extra characters",
            crate::clamp_fuzzy_distance(d)
        ),
        MatchMode::Regex => "a regular expression, matched case-insensitively against the \
                             same indexed text; the pattern, not this sentence, says what it \
                             matches, and no Unicode normalisation is applied"
            .to_string(),
    };
    let known_false_matches = vec![
        "a kana search can hit ASCII hex text: hex digits stored one byte each, such as \
         0D0A0D0A, are byte for byte the UTF-16 encoding of hiragana, so they are indexed as \
         kana. A kana hit in a file that holds hex text should be checked against its bytes \
         before it is read as Japanese"
            .to_string(),
    ];
    let statement = format!(
        "This search covers the metadata of the artifacts the ingest handed to the search \
         indexer, plus text read from the first {mib} MiB of the bytes of {types} artifacts \
         only. Text is indexed as runs of \
         at least {MIN_STRING_LEN} characters: in UTF-8, {utf8}; in UTF-16 (both byte orders), \
         {utf16}. {index_sentence} It does not cover {not}. Matching is {matching}. It is known \
         to return matches that are not what they seem: {false_matches}. A search that finds \
         nothing has not looked outside that scope: to search bytes in any encoding, including \
         UTF-16 in any script and unallocated space, use the case-wide byte sweep \
         ({BYTE_SWEEP_ROUTE}).",
        types = types.join(" and "),
        not = not_covered.join("; "),
        false_matches = known_false_matches.join("; "),
    );
    SearchUniverse {
        statement,
        content_artifact_types: types,
        content_bytes_per_artifact: CONTENT_INDEX_CAP as u64,
        min_run_chars: MIN_STRING_LEN,
        utf8,
        utf16,
        not_covered,
        byte_sweep_route: BYTE_SWEEP_ROUTE.to_string(),
        matching,
        text_extractor_version: TEXT_EXTRACTOR_VERSION,
        index_text_extractor: provenance.status,
        index_text_extractor_versions: provenance.recorded_versions.clone(),
        known_false_matches,
    }
}

/// The `not_covered` entry for documents an earlier extractor built.
fn earlier_extractor_gap() -> String {
    format!(
        "file text indexed by an earlier build, whose text extractor read UTF-16 as ASCII \
         only: the UTF-16 coverage stated here holds only for documents indexed by this build \
         (text extractor version {TEXT_EXTRACTOR_VERSION}, from {TEXT_EXTRACTOR_SINCE}), and \
         only a re-ingest brings older documents up to it"
    )
}

/// What the UTF-16 passes accept, in words, built from the indexer's own
/// block list so the two cannot disagree.
fn utf16_coverage() -> String {
    let blocks: Vec<&str> = UTF16_SCRIPT_BLOCKS.iter().map(|(_, name)| *name).collect();
    format!(
        "ASCII, the Latin-1 letters U+00C0–U+00FE (less × and ÷), and letters from one of \
         these alphabets per run: {}. CJK ideographs, Korean Hangul and every other script \
         are not indexed in UTF-16",
        blocks.join(", ")
    )
}

/// The UTF-16 reach, as a noun phrase.
fn utf16_reach_short() -> String {
    "ASCII, Latin-1 letters and the single-block alphabets above — CJK ideographs and Korean \
     Hangul among what is excluded"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_search_universe_statement_is_built_from_the_constants() {
        let u = search_universe();
        let mib = CONTENT_INDEX_CAP / (1024 * 1024);
        assert_eq!(u.content_bytes_per_artifact, CONTENT_INDEX_CAP as u64);
        assert_eq!(u.min_run_chars, MIN_STRING_LEN);
        assert_eq!(u.content_artifact_types, vec!["FileEntry", "FileContent"]);
        assert_eq!(u.byte_sweep_route, BYTE_SWEEP_ROUTE);
        let s = &u.statement;
        for needed in [
            format!("{mib} MiB"),
            format!("{MIN_STRING_LEN} characters"),
            "FileEntry".to_string(),
            "FileContent".to_string(),
            "metadata".to_string(),
            "slack".to_string(),
            "unallocated".to_string(),
            "UTF-8".to_string(),
            "UTF-16".to_string(),
            BYTE_SWEEP_ROUTE.to_string(),
            "exact-form".to_string(),
        ] {
            assert!(s.contains(&needed), "statement must name {needed:?}: {s}");
        }
        // What UTF-16 does not reach is named, not left to be inferred.
        assert!(
            u.not_covered.iter().any(|n| n.contains("UTF-16")),
            "{:?}",
            u.not_covered
        );
        assert!(u.utf16.contains("ASCII"), "{}", u.utf16);
        // Every block the indexer locks a run to is named, and the decided
        // exclusion (CJK, Hangul) is stated with the route that reaches it.
        for (_, block) in UTF16_SCRIPT_BLOCKS {
            assert!(s.contains(block), "statement must name {block}: {s}");
        }
        assert!(s.contains("CJK") && s.contains("Hangul"), "{s}");
    }

    /// The statement must not claim more than the pipeline delivers. The
    /// orchestrator does not re-dispatch a `TimelineEvent` to the indexer
    /// (one measured case indexed 8,134 of its 11,390 artifacts, the gap its
    /// timeline), and a document the backfill adds carries metadata only
    /// (`B5-001`). Both are named, and "every artifact" is not said.
    #[test]
    fn the_search_universe_does_not_claim_every_artifact() {
        let u = search_universe();
        let s = &u.statement;
        assert!(!s.contains("every artifact"), "{s}");
        assert!(
            u.not_covered
                .iter()
                .any(|n| n.contains("TimelineEvent") && n.contains("backfill")),
            "timeline events must be named as not covered: {:?}",
            u.not_covered
        );
        assert!(
            u.not_covered
                .iter()
                .any(|n| n.contains("file text") && n.contains("backfill")),
            "backfilled documents' missing file text must be named: {:?}",
            u.not_covered
        );
    }

    /// "Exact-form" in an exhibit reads as case-sensitive. It is not: the
    /// index and the query are both lowercased. The field says so.
    #[test]
    fn the_matching_statement_says_case_is_folded() {
        let u = search_universe();
        assert!(u.matching.contains("case-insensitive"), "{}", u.matching);
        assert!(u.statement.contains("case-insensitive"), "{}", u.statement);
    }

    fn provenance(status: IndexTextExtractor, versions: &[u32]) -> IndexTextProvenance {
        IndexTextProvenance {
            status,
            recorded_versions: versions.to_vec(),
        }
    }

    /// A case ingested before the 2026-09-26 widening holds UTF-16 text read
    /// as ASCII only. Its statement must not claim the widened coverage as
    /// the index's own, and must say that only a re-ingest repairs it (the
    /// backfill adds metadata, not file text).
    #[test]
    fn a_case_indexed_by_an_earlier_extractor_is_told_its_coverage_does_not_hold() {
        let u = search_universe_for(
            &provenance(IndexTextExtractor::Earlier, &[]),
            MatchMode::Exact,
        );
        assert_eq!(u.index_text_extractor, IndexTextExtractor::Earlier);
        assert_eq!(u.text_extractor_version, TEXT_EXTRACTOR_VERSION);
        let s = &u.statement;
        assert!(s.contains("earlier build"), "{s}");
        assert!(s.contains("re-ingest"), "{s}");
        assert!(s.contains(TEXT_EXTRACTOR_SINCE), "{s}");
        assert!(
            u.not_covered.iter().any(|n| n.contains("earlier build")),
            "{:?}",
            u.not_covered
        );
    }

    /// A case whose documents this build made is told so, and not warned.
    #[test]
    fn a_case_indexed_by_this_extractor_is_not_warned() {
        let u = search_universe_for(
            &provenance(IndexTextExtractor::Current, &[TEXT_EXTRACTOR_VERSION]),
            MatchMode::Exact,
        );
        assert_eq!(u.index_text_extractor, IndexTextExtractor::Current);
        assert_eq!(
            u.index_text_extractor_versions,
            vec![TEXT_EXTRACTOR_VERSION]
        );
        assert!(!u.statement.contains("earlier build"), "{}", u.statement);
        assert!(
            u.statement.contains("this build's text extractor"),
            "{}",
            u.statement
        );
    }

    /// Without a case, the statement describes the build and says it was not
    /// checked against any index — never silently "covered".
    #[test]
    fn the_build_statement_says_it_holds_only_for_documents_this_build_indexed() {
        let u = search_universe();
        assert_eq!(u.index_text_extractor, IndexTextExtractor::NotAssessed);
        assert!(
            u.statement
                .contains("only for documents indexed by this build"),
            "{}",
            u.statement
        );
    }

    /// A fuzzy search is approximate; calling it exact-form is false.
    #[test]
    fn a_fuzzy_search_is_not_described_as_exact_form() {
        let u = search_universe_for(&IndexTextProvenance::not_assessed(), MatchMode::Fuzzy(9));
        assert!(!u.matching.contains("exact-form"), "{}", u.matching);
        // The distance stated is the one the engine clamps to.
        assert!(u.matching.contains("edit distance 2"), "{}", u.matching);
        assert!(!u.statement.contains("exact-form"), "{}", u.statement);
        let r = search_universe_for(&IndexTextProvenance::not_assessed(), MatchMode::Regex);
        assert!(r.matching.contains("regular expression"), "{}", r.matching);
    }

    /// The statement lists what is missed, and also the junk it is known to
    /// add: ASCII hex text such as `0D0A0D0A` is byte-for-byte UTF-16 kana.
    #[test]
    fn the_known_kana_false_match_is_stated() {
        let u = search_universe();
        assert!(
            u.known_false_matches
                .iter()
                .any(|m| m.contains("kana") && m.contains("hex")),
            "{:?}",
            u.known_false_matches
        );
        assert!(u.statement.contains("0D0A0D0A"), "{}", u.statement);
    }

    /// U+0500–U+052F is Cyrillic Supplement, not Armenian; the label for the
    /// 0x05 block must name it, and the split a Cyrillic word takes at a
    /// Supplement letter must be stated.
    #[test]
    fn the_0x05_block_is_labelled_with_every_script_it_holds() {
        let label = UTF16_SCRIPT_BLOCKS
            .iter()
            .find(|(b, _)| *b == 0x05)
            .map(|(_, l)| *l)
            .expect("0x05 block");
        assert!(label.contains("Cyrillic Supplement"), "{label}");
        assert!(
            search_universe()
                .not_covered
                .iter()
                .any(|n| n.contains("two alphabets")),
            "the mixed-block split must be named"
        );
    }
}
