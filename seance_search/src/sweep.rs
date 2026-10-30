//! Case-wide byte sweep (`ROADMAP` §1.2).
//!
//! The per-artifact byte-search route answers "where does this hex pattern
//! occur in *this* object". A case has hundreds of thousands of objects, and
//! an examiner asking "where in the evidence is this string" cannot press that
//! route a hundred thousand times. This module answers the case-wide question:
//! it takes an ordered stream of objects — each an artifact id and a
//! [`DataSource`] — and a set of patterns, and streams every match back with
//! the object, the offset, and the encoding the bytes were matched under.
//!
//! # What a result is entitled to claim
//!
//! A sweep is bounded, so every bound is reported **as a number**, and the
//! result carries a cursor that resumes it. A sweep that stopped is not a
//! sweep that found nothing further; the two are told apart by
//! [`SweepResponse::next_cursor`] and [`SweepResponse::complete`].
//!
//! A sweep only searches what it was handed. The [`SearchScope`] says which
//! kinds of object and which regions of the evidence were admitted, and the
//! response echoes it — with the regions that were **not** searched named
//! ([`SweepResponse::regions_not_searched`]) — so a reader can tell "absent
//! from the live files" apart from "absent from the evidence". Slack and
//! unallocated space are regions other crates publish; this module does not
//! discover them, it admits or excludes what the caller offers and counts
//! what it was offered per region, so a scope that names slack and was
//! offered no slack objects says so.
//!
//! An object the sweep could not read to its declared end is listed with the
//! number of bytes it did read ([`SweepResponse::short_reads`]); an object
//! that failed outright is listed with the error
//! ([`SweepResponse::read_failures`]). Neither is silently "no hits".
//!
//! An object is its declared size: the sweep reads bytes `0..declared_size`
//! and nothing past them. When the source holds more, the object is listed
//! in [`SweepResponse::beyond_declared_size`] with the number of bytes that
//! were not searched, and the coverage statement says so; `complete` still
//! speaks for the declared extents, so a reader who wants those bytes
//! searched offers them as an object of their own (a slack region, say).
//!
//! The object counts add up on a sweep that no ceiling stopped:
//! `objects_offered` is `objects_searched` + `objects_empty` +
//! `objects_excluded` + `objects_skipped_by_cursor`. When the byte ceiling
//! stops a sweep at an object boundary, `objects_offered` also counts the one
//! object that was pulled and left for the next page (the one the cursor names),
//! which is in none of the other four, so offered exceeds their sum by one.
//!
//! # Encodings
//!
//! A text pattern is searched as UTF-8, UTF-16LE and UTF-16BE, plus any
//! single-byte code pages the caller names (resolved by `encoding_rs`, which
//! follows the WHATWG Encoding Standard's label table). A hit says which
//! encodings its bytes are consistent with. That is a **list**, because pure
//! ASCII text has the same bytes in UTF-8 and in every ASCII-compatible code
//! page, and reporting such a hit as "UTF-8" would present an inference as an
//! observation. A code page the resolver does not know is reported as absent,
//! never approximated; a code page that cannot represent the pattern's
//! characters is reported as skipped for that pattern.
//!
//! ## UTF-16 endian aliases
//!
//! The UTF-16LE and UTF-16BE forms of a string whose code units share one
//! high byte — all of Latin-1, so nearly all Western text — are the same
//! bytes shifted by one: `00 63 00 69 ...` read from the next byte is
//! `63 00 69 00 ...`. So a UTF-16BE string followed by one more such code
//! unit *contains* the UTF-16LE form one byte later, and a UTF-16LE string
//! preceded by one contains the UTF-16BE form one byte earlier. Both are
//! real occurrences of the bytes, but they are one string, and the bytes
//! alone do not say which endianness wrote it. On the NIST CFTT string-search
//! image, of the 43 UTF-16 key rows for the four terms
//! `seance_search/tests/byte_sweep_cftt_test.rs` sweeps (the key holds 437
//! UTF-16 rows in all), 29 have such a twin and 14 do not.
//!
//! The sweep therefore checks every UTF-16 match for the opposite reading
//! one byte before and after it. A pair that stands apart is reported as
//! **one** hit at the earlier reading's offset, its `encodings` naming both
//! endiannesses and its [`SweepHit::endian_aliases`] naming the later
//! reading as `folded`; the later reading is not a hit of its own and is
//! counted in [`SweepResponse::endian_aliases_folded`]. The hit's offset is
//! the earlier reading's, so a string the writer put down as UTF-16LE at
//! byte `o` is reported at `o - 1` with `utf-16le` at `o` as its alias.
//! Inside a run of one repeated code unit (the pattern `aa` in `aaaa`) the
//! readings alternate at every byte and no pair can be told from the next,
//! so every reading is reported, each naming the readings beside it as
//! aliases that are not folded; nothing is dropped and nothing is pinned.
//! A hit with any alias is [`SweepHit::endian_ambiguous`], counted in
//! [`SweepResponse::hits_endian_ambiguous`], and a report must quote both
//! readings, never one. A match with no opposite reading beside it — the
//! next code unit has a different high byte, or the object ends — is pinned
//! to its encoding, because the bytes do pin it.
//!
//! The check needs two bytes of context either side of a match. The carry
//! between read windows supplies the bytes before; two bytes are peeked past
//! each window for the bytes after, not searched and not charged to the byte
//! ceiling. When the peek cannot be read the match is reported as pinned and
//! the failed read is reported by the next window as a read failure or short
//! read, so `complete` is false and the pin is not quoted as certain.
//!
//! # What the sweep does not do
//!
//! It searches for exactly the bytes of the forms it was given. It does not
//! normalise Unicode (`ma\u{f1}ana` in NFC and `man\u{303}ana` in NFD are two
//! patterns, and a caller who wants both must give both), does not fold
//! case, does not search for a code page it was not named, and does not
//! discover slack or unallocated regions itself. A miss is a miss for the
//! byte forms searched, under the scope and bounds echoed on the result, and
//! nothing wider.
//!
//! # Hit grouping
//!
//! The same file is frequently present several times in a case — in a
//! shadow copy, a backup, a mail attachment and the live tree. Hits with the
//! same pattern in objects with the same content hash are grouped into one
//! [`HitGroup`] carrying every location; no location is dropped. An object
//! whose content hash is not known (the scan of it was cut, or resumed part
//! way) cannot be matched to a copy, so its hits group by the object's own
//! identity and the group says so. Both the grouped and the ungrouped counts
//! are reported.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use seance_core::data_source::DataSource;

/// Longest byte form any one pattern may take. Bounds automaton size and the
/// carry between chunks.
pub const MAX_PATTERN_BYTES: usize = 1024;

/// Most distinct byte forms one sweep will search for at once, across every
/// pattern and every encoding.
pub const MAX_NEEDLES: usize = 4096;

/// Read window when the caller does not choose one.
pub const DEFAULT_CHUNK_BYTES: usize = 1 << 20;

/// Hit ceiling when the caller does not choose one.
pub const DEFAULT_MAX_HITS: usize = 10_000;

/// Byte ceiling when the caller does not choose one: 4 GiB per call.
pub const DEFAULT_MAX_BYTES: u64 = 4 << 30;

/// The three encodings every text pattern is always searched under.
pub const BUILT_IN_TEXT_ENCODINGS: [&str; 3] = ["utf-8", "utf-16le", "utf-16be"];

/// Name a raw byte pattern's hit carries in place of a text encoding.
pub const RAW_ENCODING: &str = "raw";

// ---------------------------------------------------------------------------
// Regions and scope
// ---------------------------------------------------------------------------

/// Which kind of evidence region an object's bytes come from.
///
/// The distinction is carried on the object and on every hit, by type, so a
/// hit in a carved file cannot be mistaken for a hit in a live one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// The allocated content of a live file, as the filesystem presents it.
    Live,
    /// The unused tail of a live file's last cluster. Published by the caller
    /// per file; this module does not compute it.
    Slack,
    /// Space the filesystem or partition table marks as not in use
    /// (`ArtifactType::UnallocatedSpace`).
    Unallocated,
    /// Content recovered by carving or deleted-entry reconstruction — bytes
    /// that no live filesystem structure vouches for.
    Recovered,
    /// The whole of a device, partition or image: live, slack, unallocated
    /// and recovered bytes alike, undifferentiated. A hit here is located by
    /// offset only and is not attributed to a file. A scope that names only
    /// `live` does not admit a raw image, because most of a raw image is not
    /// live content.
    Raw,
}

impl RegionKind {
    /// Every region kind, in the order they are reported.
    pub const ALL: [RegionKind; 5] = [
        RegionKind::Live,
        RegionKind::Slack,
        RegionKind::Unallocated,
        RegionKind::Recovered,
        RegionKind::Raw,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RegionKind::Live => "live",
            RegionKind::Slack => "slack",
            RegionKind::Unallocated => "unallocated",
            RegionKind::Recovered => "recovered",
            RegionKind::Raw => "raw",
        }
    }
}

impl std::fmt::Display for RegionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a sweep admits. Everything is optional except `regions`, which
/// defaults to every kind so that excluding one is a deliberate act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchScope {
    /// Artifact type names (as `ArtifactType`'s `Display`, e.g. `FileContent`)
    /// to admit. `None` admits every type.
    #[serde(default)]
    pub artifact_types: Option<Vec<String>>,
    /// File extensions to admit, compared case-insensitively and without the
    /// dot. `None` admits every object; `Some` excludes objects with no name.
    #[serde(default)]
    pub extensions: Option<Vec<String>>,
    /// Admit only objects whose path starts with this string (byte-wise,
    /// case-sensitive). An object with no path is excluded when set.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Admit only objects whose whole path matches this glob. `*` does not
    /// cross a separator; `**` does. Both `/` and `\` are separators, in the
    /// glob and in the path, and either matches the other, because the
    /// filesystem plugins build `/`-separated paths while registry and
    /// shell-item paths carry backslashes. A backslash is never an escape
    /// character. An object with no path is excluded when set.
    #[serde(default)]
    pub path_glob: Option<String>,
    /// Region kinds to admit. Every kind by default.
    #[serde(default = "all_regions")]
    pub regions: Vec<RegionKind>,
}

fn all_regions() -> Vec<RegionKind> {
    RegionKind::ALL.to_vec()
}

impl Default for SearchScope {
    fn default() -> Self {
        SearchScope {
            artifact_types: None,
            extensions: None,
            path_prefix: None,
            path_glob: None,
            regions: all_regions(),
        }
    }
}

/// Why the scope refused an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeExclusion {
    ArtifactType,
    Extension,
    Path,
    Region,
}

/// A scope whose glob has been parsed and whose sets are ready to test.
#[derive(Debug, Clone)]
pub struct CompiledScope {
    scope: SearchScope,
    artifact_types: Option<BTreeSet<String>>,
    extensions: Option<BTreeSet<String>>,
    glob: Option<globset::GlobMatcher>,
    regions: BTreeSet<RegionKind>,
}

/// A scope that could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// The path glob did not parse; the text is globset's own message.
    InvalidGlob(String),
    /// `regions` was empty: a sweep of nothing is a request error, not an
    /// empty result.
    NoRegions,
    /// `artifact_types` was an empty list, which admits no object: a sweep of
    /// nothing is a request error. Omit the field to admit every type.
    EmptyArtifactTypes,
    /// `extensions` was an empty list, which admits no object. Omit the field
    /// to admit every extension.
    EmptyExtensions,
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::InvalidGlob(msg) => write!(f, "path_glob does not parse: {msg}"),
            ScopeError::NoRegions => f.write_str("scope admits no region kind"),
            ScopeError::EmptyArtifactTypes => f.write_str(
                "scope artifact_types is an empty list, which admits no object; omit it to admit every type",
            ),
            ScopeError::EmptyExtensions => f.write_str(
                "scope extensions is an empty list, which admits no object; omit it to admit every extension",
            ),
        }
    }
}

impl std::error::Error for ScopeError {}

impl SearchScope {
    /// Parse the glob and normalise the sets.
    pub fn compile(&self) -> Result<CompiledScope, ScopeError> {
        let regions: BTreeSet<RegionKind> = self.regions.iter().copied().collect();
        if regions.is_empty() {
            return Err(ScopeError::NoRegions);
        }
        if self.artifact_types.as_ref().is_some_and(Vec::is_empty) {
            return Err(ScopeError::EmptyArtifactTypes);
        }
        if self.extensions.as_ref().is_some_and(Vec::is_empty) {
            return Err(ScopeError::EmptyExtensions);
        }
        let artifact_types = self.artifact_types.as_ref().map(|types| {
            types
                .iter()
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<BTreeSet<String>>()
        });
        let extensions = self.extensions.as_ref().map(|exts| {
            exts.iter()
                .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
                .collect::<BTreeSet<String>>()
        });
        let glob = match &self.path_glob {
            None => None,
            Some(pattern) => Some(
                globset::GlobBuilder::new(&glob_separators(pattern))
                    .literal_separator(true)
                    .backslash_escape(false)
                    .build()
                    .map_err(|e| ScopeError::InvalidGlob(e.to_string()))?
                    .compile_matcher(),
            ),
        };
        Ok(CompiledScope {
            scope: self.clone(),
            artifact_types,
            extensions,
            glob,
            regions,
        })
    }

    /// The region kinds this scope does not admit, in reporting order.
    pub fn excluded_regions(&self) -> Vec<RegionKind> {
        let admitted: BTreeSet<RegionKind> = self.regions.iter().copied().collect();
        RegionKind::ALL
            .iter()
            .copied()
            .filter(|kind| !admitted.contains(kind))
            .collect()
    }

    /// The sentence a result carries about what was and was not searched.
    pub fn statement(&self) -> String {
        let admitted: BTreeSet<RegionKind> = self.regions.iter().copied().collect();
        let names = |kinds: &[RegionKind]| {
            kinds
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let searched: Vec<RegionKind> = RegionKind::ALL
            .iter()
            .copied()
            .filter(|k| admitted.contains(k))
            .collect();
        let excluded = self.excluded_regions();
        let mut parts = vec![format!("Regions searched: {}.", names(&searched))];
        if excluded.is_empty() {
            parts.push("Every region kind was admitted.".to_string());
        } else {
            parts.push(format!("Regions NOT searched: {}.", names(&excluded)));
        }
        match &self.artifact_types {
            Some(types) if !types.is_empty() => {
                parts.push(format!("Artifact types: {}.", types.join(", ")))
            }
            Some(_) => parts.push("No artifact type admitted.".to_string()),
            None => parts.push("Every artifact type.".to_string()),
        }
        match &self.extensions {
            Some(exts) if !exts.is_empty() => parts.push(format!(
                "Extensions: {} (objects without a name were excluded).",
                exts.join(", ")
            )),
            Some(_) => parts.push("No extension admitted.".to_string()),
            None => parts.push("Every extension.".to_string()),
        }
        if let Some(prefix) = &self.path_prefix {
            parts.push(format!("Path prefix: {prefix}."));
        }
        if let Some(glob) = &self.path_glob {
            parts.push(format!("Path glob: {glob}."));
        }
        parts.join(" ")
    }
}

impl CompiledScope {
    pub fn scope(&self) -> &SearchScope {
        &self.scope
    }

    /// `Ok(())` when the object is admitted, else why not. The first failing
    /// test in the order type, extension, path, region is the one reported.
    pub fn admits(&self, target: &SweepTarget) -> Result<(), ScopeExclusion> {
        if let Some(types) = &self.artifact_types {
            if !types.contains(&target.artifact_type.trim().to_ascii_lowercase()) {
                return Err(ScopeExclusion::ArtifactType);
            }
        }
        if let Some(exts) = &self.extensions {
            let ext = target
                .name
                .as_deref()
                .and_then(|name| name.rsplit_once('.'))
                .map(|(_, ext)| ext.to_ascii_lowercase());
            match ext {
                Some(ext) if exts.contains(&ext) => {}
                _ => return Err(ScopeExclusion::Extension),
            }
        }
        if let Some(prefix) = &self.scope.path_prefix {
            match target.path.as_deref() {
                Some(path) if path.starts_with(prefix.as_str()) => {}
                _ => return Err(ScopeExclusion::Path),
            }
        }
        if let Some(glob) = &self.glob {
            match target.path.as_deref() {
                Some(path) if glob.is_match(glob_separators(path)) => {}
                _ => return Err(ScopeExclusion::Path),
            }
        }
        if !self.regions.contains(&target.region) {
            return Err(ScopeExclusion::Region);
        }
        Ok(())
    }
}

/// Backslashes as `/`, so that globset's single separator stands for both
/// and a `*` stops at either.
fn glob_separators(path: &str) -> String {
    path.replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// One object offered to the sweep.
pub struct SweepTarget {
    pub artifact_id: Uuid,
    /// `ArtifactType` display name, e.g. `FileContent`.
    pub artifact_type: String,
    /// The object's file name, used for the extension test. `None` for an
    /// object that has no name (an unallocated region).
    pub name: Option<String>,
    /// The object's full path, used for the prefix and glob tests.
    pub path: Option<String>,
    pub region: RegionKind,
    /// The size the object is recorded as having; the sweep searches bytes
    /// `0..declared_size` and no others. When the source ends before this,
    /// the object is reported as a short read. When the source is larger,
    /// the bytes past `declared_size` are not searched and the object is
    /// listed in [`SweepResponse::beyond_declared_size`] with their number.
    pub declared_size: u64,
    /// The object's content hash (SHA-256, lowercase hex), when the caller
    /// already holds one. When absent the sweep computes one over the bytes
    /// it reads — only if it reads every byte from the start.
    pub content_hash: Option<String>,
    pub source: Arc<dyn DataSource>,
}

impl std::fmt::Debug for SweepTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SweepTarget")
            .field("artifact_id", &self.artifact_id)
            .field("artifact_type", &self.artifact_type)
            .field("name", &self.name)
            .field("path", &self.path)
            .field("region", &self.region)
            .field("declared_size", &self.declared_size)
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/// What kind of thing a pattern is. Part of a hit's grouping key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    /// A raw byte sequence, given as hex.
    Bytes,
    /// Text, searched under every encoding the set was built with.
    Text,
}

/// A pattern as the caller states it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatternSpec {
    pub kind: PatternKind,
    /// Hex digits (separators allowed) for [`PatternKind::Bytes`]; the text
    /// itself for [`PatternKind::Text`].
    pub value: String,
}

impl PatternSpec {
    pub fn bytes(hex: impl Into<String>) -> Self {
        PatternSpec {
            kind: PatternKind::Bytes,
            value: hex.into(),
        }
    }

    pub fn text(text: impl Into<String>) -> Self {
        PatternSpec {
            kind: PatternKind::Text,
            value: text.into(),
        }
    }
}

/// A code page label the caller asked for, and what it resolved to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodepageResolution {
    /// The label as given.
    pub label: String,
    /// The canonical name of the encoding the label resolved to. The WHATWG
    /// table folds some labels together — `latin1` and `iso-8859-1` both
    /// resolve to `windows-1252` — so a reader must see the name, not only
    /// the label.
    pub name: String,
    /// True when the label resolved to one of the encodings every text
    /// pattern is searched under anyway, so naming it changed nothing.
    pub built_in: bool,
}

/// A code page that could not be used for one pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEncoding {
    pub pattern_index: usize,
    pub encoding: String,
    pub reason: String,
}

/// Why a pattern set could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    NoPatterns,
    EmptyPattern {
        index: usize,
    },
    BadHex {
        index: usize,
        detail: String,
    },
    TooLong {
        index: usize,
        encoding: String,
        bytes: usize,
        limit: usize,
    },
    TooManyNeedles {
        needles: usize,
        limit: usize,
    },
    /// Two patterns have the same kind and the same bytes, so every hit of
    /// one would be a hit of the other and be reported twice.
    Duplicate {
        index: usize,
        duplicate_of: usize,
    },
    /// The automaton could not be built; the text is aho-corasick's own.
    Automaton(String),
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternError::NoPatterns => f.write_str("no patterns given"),
            PatternError::EmptyPattern { index } => write!(f, "pattern {index} is empty"),
            PatternError::BadHex { index, detail } => {
                write!(f, "pattern {index} is not valid hex: {detail}")
            }
            PatternError::TooLong {
                index,
                encoding,
                bytes,
                limit,
            } => write!(
                f,
                "pattern {index} is {bytes} bytes as {encoding}; the limit is {limit}"
            ),
            PatternError::TooManyNeedles { needles, limit } => write!(
                f,
                "{needles} distinct byte forms across patterns and encodings; the limit is {limit}"
            ),
            PatternError::Duplicate {
                index,
                duplicate_of,
            } => write!(
                f,
                "pattern {index} is the same as pattern {duplicate_of}, so its hits would be \
                 reported twice"
            ),
            PatternError::Automaton(msg) => write!(f, "could not build matcher: {msg}"),
        }
    }
}

impl std::error::Error for PatternError {}

/// One distinct byte form the automaton searches for.
#[derive(Debug, Clone)]
struct Needle {
    bytes: Vec<u8>,
    pattern_index: usize,
    encodings: Vec<String>,
    /// The needle holding the same pattern under the opposite UTF-16
    /// endianness, when this one is a UTF-16 form and the two forms differ.
    /// Such a pair can read as each other one byte apart; see
    /// [`EndianAlias`].
    utf16_opposite: Option<usize>,
}

/// Which UTF-16 form a needle is, if either.
fn utf16_side(needle: &Needle) -> Option<&'static str> {
    if needle.encodings.iter().any(|e| e == "utf-16le") {
        Some("utf-16le")
    } else if needle.encodings.iter().any(|e| e == "utf-16be") {
        Some("utf-16be")
    } else {
        None
    }
}

/// The compiled pattern set: every distinct byte form of every pattern under
/// every encoding, with the record of what could not be encoded.
#[derive(Debug, Clone)]
pub struct PatternSet {
    specs: Vec<PatternSpec>,
    needles: Vec<Needle>,
    automaton: AhoCorasick,
    longest_needle: usize,
    encodings_searched: Vec<String>,
    codepages_resolved: Vec<CodepageResolution>,
    codepages_absent: Vec<String>,
    encodings_skipped: Vec<SkippedEncoding>,
}

impl PatternSet {
    /// Build the set. Text patterns are encoded as UTF-8, UTF-16LE, UTF-16BE
    /// and each of `codepages` (WHATWG labels, e.g. `windows-1252`).
    pub fn compile(
        specs: &[PatternSpec],
        codepages: &[String],
    ) -> Result<PatternSet, PatternError> {
        if specs.is_empty() {
            return Err(PatternError::NoPatterns);
        }

        let mut codepages_resolved = Vec::new();
        let mut codepages_absent = Vec::new();
        let mut codepage_encodings: Vec<&'static encoding_rs::Encoding> = Vec::new();
        for label in codepages {
            let trimmed = label.trim();
            let Some(encoding) = encoding_rs::Encoding::for_label(trimmed.as_bytes()) else {
                codepages_absent.push(label.clone());
                continue;
            };
            let name = encoding.name().to_ascii_lowercase();
            // The replacement "encoding" decodes everything to U+FFFD; there
            // is no byte form of a pattern under it, so it is not a code page
            // anything can be searched as.
            if name == "replacement" {
                codepages_absent.push(label.clone());
                continue;
            }
            let built_in = BUILT_IN_TEXT_ENCODINGS.contains(&name.as_str());
            codepages_resolved.push(CodepageResolution {
                label: label.clone(),
                name: name.clone(),
                built_in,
            });
            if !built_in
                && !codepage_encodings
                    .iter()
                    .any(|e| std::ptr::eq(*e, encoding))
            {
                codepage_encodings.push(encoding);
            }
        }
        let mut encodings_searched: Vec<String> = BUILT_IN_TEXT_ENCODINGS
            .iter()
            .map(|s| s.to_string())
            .collect();
        encodings_searched.extend(
            codepage_encodings
                .iter()
                .map(|e| e.name().to_ascii_lowercase()),
        );

        let mut encodings_skipped = Vec::new();
        // (pattern index, bytes) -> position in `needles`, so one pattern's
        // identical forms under several encodings become one needle that
        // names them all.
        let mut by_form: HashMap<(usize, Vec<u8>), usize> = HashMap::new();
        let mut needles: Vec<Needle> = Vec::new();
        let mut add_form = |index: usize,
                            encoding: &str,
                            bytes: Vec<u8>,
                            needles: &mut Vec<Needle>|
         -> Result<(), PatternError> {
            if bytes.is_empty() {
                return Err(PatternError::EmptyPattern { index });
            }
            if bytes.len() > MAX_PATTERN_BYTES {
                return Err(PatternError::TooLong {
                    index,
                    encoding: encoding.to_string(),
                    bytes: bytes.len(),
                    limit: MAX_PATTERN_BYTES,
                });
            }
            match by_form.get(&(index, bytes.clone())) {
                Some(&at) => needles[at].encodings.push(encoding.to_string()),
                None => {
                    by_form.insert((index, bytes.clone()), needles.len());
                    needles.push(Needle {
                        bytes,
                        pattern_index: index,
                        encodings: vec![encoding.to_string()],
                        utf16_opposite: None,
                    });
                }
            }
            Ok(())
        };

        let mut seen: HashMap<(PatternKind, Vec<u8>), usize> = HashMap::new();
        for (index, spec) in specs.iter().enumerate() {
            let identity = match spec.kind {
                PatternKind::Bytes => parse_hex(index, &spec.value)?,
                PatternKind::Text => spec.value.as_bytes().to_vec(),
            };
            if let Some(&duplicate_of) = seen.get(&(spec.kind, identity.clone())) {
                return Err(PatternError::Duplicate {
                    index,
                    duplicate_of,
                });
            }
            seen.insert((spec.kind, identity), index);
            match spec.kind {
                PatternKind::Bytes => {
                    let bytes = parse_hex(index, &spec.value)?;
                    add_form(index, RAW_ENCODING, bytes, &mut needles)?;
                }
                PatternKind::Text => {
                    if spec.value.is_empty() {
                        return Err(PatternError::EmptyPattern { index });
                    }
                    add_form(index, "utf-8", spec.value.as_bytes().to_vec(), &mut needles)?;
                    let units: Vec<u16> = spec.value.encode_utf16().collect();
                    add_form(
                        index,
                        "utf-16le",
                        units.iter().flat_map(|u| u.to_le_bytes()).collect(),
                        &mut needles,
                    )?;
                    add_form(
                        index,
                        "utf-16be",
                        units.iter().flat_map(|u| u.to_be_bytes()).collect(),
                        &mut needles,
                    )?;
                    for encoding in &codepage_encodings {
                        let name = encoding.name().to_ascii_lowercase();
                        let (bytes, _, had_errors) = encoding.encode(&spec.value);
                        if had_errors {
                            // The encoder substitutes a numeric character
                            // reference for what it cannot represent, which
                            // would search for text the examiner never typed.
                            encodings_skipped.push(SkippedEncoding {
                                pattern_index: index,
                                encoding: name.clone(),
                                reason: format!(
                                    "{name} cannot represent every character of the pattern, \
                                     so the pattern was not searched under it"
                                ),
                            });
                            continue;
                        }
                        add_form(index, &name, bytes.into_owned(), &mut needles)?;
                    }
                }
            }
        }

        if needles.len() > MAX_NEEDLES {
            return Err(PatternError::TooManyNeedles {
                needles: needles.len(),
                limit: MAX_NEEDLES,
            });
        }
        // Pair each pattern's two UTF-16 forms so a hit can be checked for
        // the opposite reading beside it.
        let mut utf16_forms: HashMap<(usize, &'static str), usize> = HashMap::new();
        for (at, needle) in needles.iter().enumerate() {
            if let Some(side) = utf16_side(needle) {
                utf16_forms.insert((needle.pattern_index, side), at);
            }
        }
        for (at, needle) in needles.iter_mut().enumerate() {
            let Some(side) = utf16_side(needle) else {
                continue;
            };
            let other = if side == "utf-16le" {
                "utf-16be"
            } else {
                "utf-16le"
            };
            match utf16_forms.get(&(needle.pattern_index, other)) {
                Some(&opposite) if opposite != at => needle.utf16_opposite = Some(opposite),
                _ => {}
            }
        }
        let longest_needle = needles.iter().map(|n| n.bytes.len()).max().unwrap_or(0);
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(needles.iter().map(|n| &n.bytes))
            .map_err(|e| PatternError::Automaton(e.to_string()))?;

        Ok(PatternSet {
            specs: specs.to_vec(),
            needles,
            automaton,
            longest_needle,
            encodings_searched,
            codepages_resolved,
            codepages_absent,
            encodings_skipped,
        })
    }

    pub fn specs(&self) -> &[PatternSpec] {
        &self.specs
    }

    /// How many distinct byte forms the automaton holds.
    pub fn needle_count(&self) -> usize {
        self.needles.len()
    }

    /// The encodings text patterns were searched under, built-ins first.
    pub fn encodings_searched(&self) -> &[String] {
        &self.encodings_searched
    }

    /// What each requested code page label resolved to.
    pub fn codepages_resolved(&self) -> &[CodepageResolution] {
        &self.codepages_resolved
    }

    /// Requested labels the resolver does not know. Nothing was searched
    /// under these.
    pub fn codepages_absent(&self) -> &[String] {
        &self.codepages_absent
    }

    /// (pattern, encoding) pairs that were not searched, with the reason.
    pub fn encodings_skipped(&self) -> &[SkippedEncoding] {
        &self.encodings_skipped
    }
}

/// Hex digits with any mix of spaces, colons, dashes and commas between
/// them.
fn parse_hex(index: usize, value: &str) -> Result<Vec<u8>, PatternError> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, ':' | '-' | ','))
        .collect();
    if cleaned.is_empty() {
        return Err(PatternError::EmptyPattern { index });
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(PatternError::BadHex {
            index,
            detail: format!("{} hex digits is an odd number", cleaned.len()),
        });
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| PatternError::BadHex {
                index,
                detail: format!("'{}' is not a hex byte", &cleaned[i..i + 2]),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Bounds, cursor, request
// ---------------------------------------------------------------------------

/// The ceilings one call runs under. Each is reported back with its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepBounds {
    /// Stop after this many hits. The count may exceed it by the matches
    /// that end at the same byte as the last one counted, so a resume never
    /// loses a match that shares an end offset with the last reported.
    #[serde(default = "default_max_hits")]
    pub max_hits: usize,
    /// Stop after reading this many fresh bytes across every object.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Read window. Matches are found across window edges.
    #[serde(default = "default_chunk_bytes")]
    pub chunk_bytes: usize,
}

fn default_max_hits() -> usize {
    DEFAULT_MAX_HITS
}
fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}
fn default_chunk_bytes() -> usize {
    DEFAULT_CHUNK_BYTES
}

impl Default for SweepBounds {
    fn default() -> Self {
        SweepBounds {
            max_hits: DEFAULT_MAX_HITS,
            max_bytes: DEFAULT_MAX_BYTES,
            chunk_bytes: DEFAULT_CHUNK_BYTES,
        }
    }
}

/// Where a sweep stopped and where the next one starts: this object, this
/// byte. Every match ending at or before `offset` in `artifact_id` has been
/// reported; resuming here reports the rest and then moves on to the objects
/// after it in the caller's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepCursor {
    pub artifact_id: Uuid,
    pub offset: u64,
}

/// One call's scope, bounds and starting point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SweepRequest {
    #[serde(default)]
    pub scope: SearchScope,
    #[serde(default)]
    pub bounds: SweepBounds,
    /// Resume from a cursor an earlier call returned. The object it names
    /// must appear in this call's stream, or the call is refused rather than
    /// silently restarted.
    #[serde(default)]
    pub resume: Option<SweepCursor>,
}

// ---------------------------------------------------------------------------
// Hits and results
// ---------------------------------------------------------------------------

/// One match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepHit {
    pub artifact_id: Uuid,
    pub artifact_type: String,
    pub region: RegionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Byte offset of the match within the object.
    pub offset: u64,
    /// Length of the matched bytes.
    pub length: u64,
    /// Index into the pattern set's specs.
    pub pattern_index: usize,
    pub pattern_kind: PatternKind,
    pub pattern_value: String,
    /// Every encoding the hit is consistent with: each encoding under which
    /// the pattern has exactly these bytes, plus — when an entry of
    /// [`SweepHit::endian_aliases`] is `folded` — the opposite UTF-16
    /// endianness, whose form of the pattern lies one byte away in the same
    /// run of bytes. One entry when the bytes pin the encoding; several for
    /// ASCII-only text, which is identical in UTF-8 and in every
    /// ASCII-compatible code page, and for a folded UTF-16 pair.
    /// [`RAW_ENCODING`] for a byte pattern.
    pub encodings: Vec<String>,
    /// Readings of the same bytes as the same pattern under the opposite
    /// UTF-16 endianness, one byte before or after this hit. Empty for every
    /// hit that is not a UTF-16 form or has no such reading beside it. When
    /// non-empty the bytes alone cannot say which endianness the writer
    /// used, and a report must not quote one; see
    /// [`SweepHit::endian_ambiguous`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endian_aliases: Vec<EndianAlias>,
}

impl SweepHit {
    /// True when the same bytes also read as the pattern under the opposite
    /// UTF-16 endianness one byte away, so the encoding is not determined by
    /// the bytes: a report must name both readings, never one.
    pub fn endian_ambiguous(&self) -> bool {
        !self.endian_aliases.is_empty()
    }
}

/// A reading of the same run of bytes as the same pattern under the
/// opposite UTF-16 endianness, one byte away from the hit that carries it.
///
/// UTF-16BE text followed by any code unit with the same high byte contains
/// the UTF-16LE byte form of the same text one byte later, and UTF-16LE text
/// preceded by such a code unit contains the UTF-16BE form one byte earlier;
/// for Latin-1 text that high byte is `00`, so on real evidence nearly every
/// UTF-16 string has its opposite-endian twin beside it. The twin is a real
/// occurrence of the bytes, but it is the same string, not a second one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndianAlias {
    /// `utf-16le` or `utf-16be`: the endianness of the other reading.
    pub encoding: String,
    /// Where the other reading starts: the hit's offset plus or minus one.
    pub offset: u64,
    /// True when the other reading was folded into the hit that carries
    /// this alias and is not reported as a hit of its own; the hit's
    /// `encodings` then lists both endiannesses. False when the other
    /// reading is reported as its own hit, which happens only inside a run
    /// of one repeated code unit, where every reading has a neighbour on
    /// both sides and no pair can be told from the next.
    pub folded: bool,
}

/// What a group of hits was joined on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "basis")]
pub enum GroupingBasis {
    /// The objects share this SHA-256, so they are copies of one another.
    ContentHash { sha256: String },
    /// No content hash was available for the object, so it could not be
    /// matched to any copy; the group is this object alone.
    ArtifactIdentity { artifact_id: Uuid, reason: String },
}

/// Hits with one pattern in objects that are copies of one another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitGroup {
    pub pattern_index: usize,
    pub pattern_kind: PatternKind,
    pub pattern_value: String,
    pub basis: GroupingBasis,
    /// Distinct objects in the group, in first-seen order.
    pub artifact_ids: Vec<Uuid>,
    /// Every hit in the group, in the order they were found. Never fewer
    /// than the hits that went in.
    pub locations: Vec<SweepHit>,
}

/// Grouped hits with both counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grouping {
    pub groups: Vec<HitGroup>,
    /// Hits before grouping.
    pub hit_count: usize,
    /// Groups after grouping.
    pub group_count: usize,
    /// Hits that could only be grouped by artifact identity because the
    /// object's content hash was not available.
    pub hits_without_content_hash: usize,
}

/// An object that ended before its declared size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortRead {
    pub artifact_id: Uuid,
    pub declared_size: u64,
    pub bytes_read: u64,
}

/// An object whose source holds more bytes than its declared size. The
/// bytes past `declared_size` were not searched: the declared extent is the
/// object, and what lies beyond it is not vouched for as part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeyondDeclaredSize {
    pub artifact_id: Uuid,
    pub declared_size: u64,
    pub source_size: u64,
    pub bytes_beyond: u64,
}

/// An object whose read returned an error. The sweep moved on to the next
/// object; nothing past `offset` in this one was searched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFailure {
    pub artifact_id: Uuid,
    pub offset: u64,
    pub error: String,
}

/// Objects the scope refused, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionCounts {
    pub artifact_type: usize,
    pub extension: usize,
    pub path: usize,
    pub region: usize,
}

impl ExclusionCounts {
    pub fn total(&self) -> usize {
        self.artifact_type + self.extension + self.path + self.region
    }
}

/// The record of one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepResponse {
    /// Every hit, ungrouped, in the order found.
    pub hits: Vec<SweepHit>,
    /// The same hits grouped across copies.
    pub grouping: Grouping,

    /// The scope as requested.
    pub scope: SearchScope,
    /// The scope in a sentence, naming what was NOT searched.
    pub scope_statement: String,
    pub regions_searched: Vec<RegionKind>,
    pub regions_not_searched: Vec<RegionKind>,

    /// Objects the caller's stream produced before the sweep finished or
    /// stopped, including ones skipped or excluded. Not the size of the
    /// case: a sweep that stopped at a ceiling did not pull the rest of the
    /// stream.
    pub objects_offered: usize,
    /// Objects passed over to reach the resume cursor, including the
    /// cursor's own object when the cursor sits at its declared end.
    pub objects_skipped_by_cursor: usize,
    pub objects_excluded: ExclusionCounts,
    /// Admitted objects with a declared size of zero: nothing to read.
    pub objects_empty: usize,
    /// Objects whose bytes the sweep set out to read. One whose very first
    /// read failed is counted here and listed in `read_failures`.
    /// On a sweep no ceiling stopped, `objects_offered` is the sum of this,
    /// `objects_empty`, `objects_excluded` and `objects_skipped_by_cursor`. A
    /// byte ceiling reached at an object boundary leaves the cursor's object
    /// offered but in none of them, so offered is then one greater.
    pub objects_searched: usize,
    /// Objects offered per region, before the scope was applied. A region
    /// the scope admits but that shows zero here was never on offer, and the
    /// result cannot speak for it.
    pub objects_offered_by_region: BTreeMap<RegionKind, usize>,
    pub objects_searched_by_region: BTreeMap<RegionKind, usize>,

    /// Bytes read this call. Across pages, the bytes between a hit-ceiling
    /// cursor and the end of the read window it fell in are read by both
    /// pages and counted by both.
    pub bytes_scanned: u64,
    /// Sum of the declared sizes of the objects searched.
    pub bytes_declared: u64,
    /// Searched objects whose source is larger than their declared size,
    /// each with the number of bytes past the declared end that were not
    /// searched.
    pub beyond_declared_size: Vec<BeyondDeclaredSize>,
    /// Sum of `bytes_beyond` over `beyond_declared_size`.
    pub bytes_beyond_declared_size: u64,

    /// Hits whose bytes also read as the pattern under the opposite UTF-16
    /// endianness one byte away ([`SweepHit::endian_ambiguous`]).
    pub hits_endian_ambiguous: usize,
    /// Opposite-endian readings folded into the hit one byte before them
    /// and therefore not counted in `hits`. Without folding, every such
    /// pair would be two hits each pinning a different encoding.
    pub endian_aliases_folded: usize,

    pub max_hits: usize,
    pub hit_cap_reached: bool,
    pub max_bytes: u64,
    pub byte_cap_reached: bool,

    /// Where to resume; `None` means the stream was exhausted.
    pub next_cursor: Option<SweepCursor>,
    /// True only when the stream was exhausted, no ceiling bit, and every
    /// searched object was read to its declared end without error. It
    /// speaks for the declared extents: bytes past a declared size are
    /// listed in `beyond_declared_size` and were not searched.
    pub complete: bool,
    /// The sentence that says how far the sweep got.
    pub coverage_statement: String,

    pub short_reads: Vec<ShortRead>,
    pub read_failures: Vec<ReadFailure>,

    pub patterns: Vec<PatternSpec>,
    pub encodings_searched: Vec<String>,
    pub codepages_resolved: Vec<CodepageResolution>,
    pub codepages_absent: Vec<String>,
    pub encodings_skipped: Vec<SkippedEncoding>,

    pub elapsed_ms: u64,
}

/// Why a call was refused before any byte was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepError {
    Scope(ScopeError),
    /// The resume cursor named an object the stream never produced. The call
    /// is refused rather than restarted from the top, because a restart
    /// would re-report hits the caller has already recorded.
    ResumePointNotFound {
        artifact_id: Uuid,
    },
}

impl std::fmt::Display for SweepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SweepError::Scope(e) => write!(f, "{e}"),
            SweepError::ResumePointNotFound { artifact_id } => write!(
                f,
                "resume cursor names object {artifact_id}, which the stream did not produce"
            ),
        }
    }
}

impl std::error::Error for SweepError {}

impl From<ScopeError> for SweepError {
    fn from(e: ScopeError) -> Self {
        SweepError::Scope(e)
    }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// Run a sweep over `targets`, in the caller's order, calling `on_hit` for
/// each match as it is found and returning the full record at the end.
pub fn sweep_with<I>(
    targets: I,
    patterns: &PatternSet,
    request: &SweepRequest,
    on_hit: &mut dyn FnMut(&SweepHit),
) -> Result<SweepResponse, SweepError>
where
    I: IntoIterator<Item = SweepTarget>,
{
    let started = Instant::now();
    let compiled = request.scope.compile()?;
    let bounds = request.bounds;
    let max_hits = bounds.max_hits.max(1);
    let chunk = if bounds.chunk_bytes == 0 {
        DEFAULT_CHUNK_BYTES
    } else {
        bounds.chunk_bytes
    };
    // The carry between windows is one byte longer than the longest needle
    // (a straddling match needs `longest - 1`; the endian check on a match
    // looks two bytes before it, and the earliest new match in a window
    // starts one byte after the carry).
    let keep = patterns.longest_needle + 1;

    let mut state = SweepState {
        hits: Vec::new(),
        objects_offered: 0,
        objects_skipped_by_cursor: 0,
        objects_excluded: ExclusionCounts::default(),
        objects_empty: 0,
        objects_searched: 0,
        objects_offered_by_region: RegionKind::ALL.iter().map(|k| (*k, 0)).collect(),
        objects_searched_by_region: RegionKind::ALL.iter().map(|k| (*k, 0)).collect(),
        bytes_scanned: 0,
        bytes_declared: 0,
        beyond_declared_size: Vec::new(),
        hits_endian_ambiguous: 0,
        endian_aliases_folded: 0,
        budget: bounds.max_bytes,
        hit_cap_reached: false,
        byte_cap_reached: false,
        next_cursor: None,
        short_reads: Vec::new(),
        read_failures: Vec::new(),
        content_hashes: HashMap::new(),
        unhashed_reasons: HashMap::new(),
    };
    let mut resume = request.resume;

    for target in targets {
        state.objects_offered += 1;
        *state
            .objects_offered_by_region
            .entry(target.region)
            .or_insert(0) += 1;

        let mut start_offset = 0u64;
        if let Some(cursor) = resume {
            if target.artifact_id != cursor.artifact_id {
                state.objects_skipped_by_cursor += 1;
                continue;
            }
            resume = None;
            start_offset = cursor.offset;
        }
        if let Err(reason) = compiled.admits(&target) {
            match reason {
                ScopeExclusion::ArtifactType => state.objects_excluded.artifact_type += 1,
                ScopeExclusion::Extension => state.objects_excluded.extension += 1,
                ScopeExclusion::Path => state.objects_excluded.path += 1,
                ScopeExclusion::Region => state.objects_excluded.region += 1,
            }
            continue;
        }
        if target.declared_size == 0 {
            state.objects_empty += 1;
            continue;
        }
        if start_offset >= target.declared_size {
            // The previous page stopped exactly at this object's end.
            state.objects_skipped_by_cursor += 1;
            continue;
        }
        if state.budget == 0 {
            state.byte_cap_reached = true;
            state.next_cursor = Some(SweepCursor {
                artifact_id: target.artifact_id,
                offset: start_offset,
            });
            break;
        }

        state.objects_searched += 1;
        *state
            .objects_searched_by_region
            .entry(target.region)
            .or_insert(0) += 1;
        state.bytes_declared = state.bytes_declared.saturating_add(target.declared_size);
        let source_size = target.source.size();
        if source_size > target.declared_size {
            state.beyond_declared_size.push(BeyondDeclaredSize {
                artifact_id: target.artifact_id,
                declared_size: target.declared_size,
                source_size,
                bytes_beyond: source_size - target.declared_size,
            });
        }

        let outcome = scan_object(
            &target,
            start_offset,
            keep,
            chunk,
            max_hits,
            patterns,
            &mut state,
            on_hit,
        );

        match target.content_hash.clone() {
            Some(hash) => {
                state.content_hashes.insert(target.artifact_id, hash);
            }
            None => match outcome.hash {
                Some(hash) => {
                    state.content_hashes.insert(target.artifact_id, hash);
                }
                None => {
                    state
                        .unhashed_reasons
                        .insert(target.artifact_id, outcome.unhashed_reason(&target));
                }
            },
        }
        if let Some((offset, error)) = &outcome.error {
            state.read_failures.push(ReadFailure {
                artifact_id: target.artifact_id,
                offset: *offset,
                error: error.clone(),
            });
        } else if outcome.stop.is_none() && outcome.reached < target.declared_size {
            state.short_reads.push(ShortRead {
                artifact_id: target.artifact_id,
                declared_size: target.declared_size,
                bytes_read: outcome.reached,
            });
        }
        match outcome.stop {
            None => {}
            Some(Stop::HitCap { at }) => {
                state.hit_cap_reached = true;
                state.next_cursor = Some(SweepCursor {
                    artifact_id: target.artifact_id,
                    offset: at,
                });
                break;
            }
            Some(Stop::ByteCap) => {
                state.byte_cap_reached = true;
                state.next_cursor = Some(SweepCursor {
                    artifact_id: target.artifact_id,
                    offset: outcome.reached,
                });
                break;
            }
        }
    }

    if let Some(cursor) = resume {
        return Err(SweepError::ResumePointNotFound {
            artifact_id: cursor.artifact_id,
        });
    }

    let grouping = group_hits(&state.hits, &state.content_hashes, &state.unhashed_reasons);
    let scope = request.scope.clone();
    let regions_not_searched = scope.excluded_regions();
    let regions_searched: Vec<RegionKind> = RegionKind::ALL
        .iter()
        .copied()
        .filter(|k| !regions_not_searched.contains(k))
        .collect();
    let scope_statement = format!(
        "{} Objects offered per region: {}.",
        scope.statement(),
        RegionKind::ALL
            .iter()
            .map(|k| format!("{}: {}", k, state.objects_offered_by_region[k]))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let complete = state.next_cursor.is_none()
        && state.short_reads.is_empty()
        && state.read_failures.is_empty();
    let coverage_statement = coverage_statement(&state, max_hits, bounds.max_bytes, complete);
    let bytes_beyond_declared_size = state
        .beyond_declared_size
        .iter()
        .fold(0u64, |sum, b| sum.saturating_add(b.bytes_beyond));

    Ok(SweepResponse {
        hits: state.hits,
        grouping,
        scope,
        scope_statement,
        regions_searched,
        regions_not_searched,
        objects_offered: state.objects_offered,
        objects_skipped_by_cursor: state.objects_skipped_by_cursor,
        objects_excluded: state.objects_excluded,
        objects_empty: state.objects_empty,
        objects_searched: state.objects_searched,
        objects_offered_by_region: state.objects_offered_by_region,
        objects_searched_by_region: state.objects_searched_by_region,
        bytes_scanned: state.bytes_scanned,
        bytes_declared: state.bytes_declared,
        beyond_declared_size: state.beyond_declared_size,
        bytes_beyond_declared_size,
        hits_endian_ambiguous: state.hits_endian_ambiguous,
        endian_aliases_folded: state.endian_aliases_folded,
        max_hits,
        hit_cap_reached: state.hit_cap_reached,
        max_bytes: bounds.max_bytes,
        byte_cap_reached: state.byte_cap_reached,
        next_cursor: state.next_cursor,
        complete,
        coverage_statement,
        short_reads: state.short_reads,
        read_failures: state.read_failures,
        patterns: patterns.specs.clone(),
        encodings_searched: patterns.encodings_searched.clone(),
        codepages_resolved: patterns.codepages_resolved.clone(),
        codepages_absent: patterns.codepages_absent.clone(),
        encodings_skipped: patterns.encodings_skipped.clone(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// Everything one call accumulates.
struct SweepState {
    hits: Vec<SweepHit>,
    objects_offered: usize,
    objects_skipped_by_cursor: usize,
    objects_excluded: ExclusionCounts,
    objects_empty: usize,
    objects_searched: usize,
    objects_offered_by_region: BTreeMap<RegionKind, usize>,
    objects_searched_by_region: BTreeMap<RegionKind, usize>,
    bytes_scanned: u64,
    bytes_declared: u64,
    beyond_declared_size: Vec<BeyondDeclaredSize>,
    hits_endian_ambiguous: usize,
    endian_aliases_folded: usize,
    budget: u64,
    hit_cap_reached: bool,
    byte_cap_reached: bool,
    next_cursor: Option<SweepCursor>,
    short_reads: Vec<ShortRead>,
    read_failures: Vec<ReadFailure>,
    content_hashes: HashMap<Uuid, String>,
    unhashed_reasons: HashMap<Uuid, String>,
}

/// Why an object's scan ended before its declared end.
enum Stop {
    /// The hit ceiling bit; every match ending at or before `at` is reported.
    HitCap { at: u64 },
    /// The byte budget ran out.
    ByteCap,
}

struct ObjectOutcome {
    /// The absolute offset the scan reached: every byte before it was read.
    reached: u64,
    stop: Option<Stop>,
    error: Option<(u64, String)>,
    /// SHA-256 of the object, when every byte from 0 to the declared end was
    /// read in this call.
    hash: Option<String>,
    started_at: u64,
}

impl ObjectOutcome {
    fn unhashed_reason(&self, target: &SweepTarget) -> String {
        let declared = target.declared_size;
        if self.started_at > 0 {
            return format!(
                "the scan resumed at byte {} of {declared}, so the object's content was not hashed",
                self.started_at
            );
        }
        if let Some((offset, error)) = &self.error {
            return format!(
                "the read failed at byte {offset} of {declared} ({error}), so the object's content \
                 was not hashed"
            );
        }
        match self.stop {
            Some(Stop::ByteCap) => format!(
                "the byte ceiling cut the scan at {} of {declared} bytes, so the object's content \
                 was not hashed",
                self.reached
            ),
            Some(Stop::HitCap { at }) => format!(
                "the hit ceiling stopped the scan at byte {at} of {declared}, so the object's \
                 content was not hashed"
            ),
            None => format!(
                "the object ended after {} of {declared} declared bytes, so the object's content \
                 was not hashed",
                self.reached
            ),
        }
    }
}

/// Fill `buf` from `offset`, looping over short reads; `Ok(n < buf.len())`
/// means the source ended.
fn read_fully(source: &dyn DataSource, mut offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = source.read_at(offset, &mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
        match offset.checked_add(n as u64) {
            Some(next) => offset = next,
            None => break,
        }
    }
    Ok(total)
}

#[allow(clippy::too_many_arguments)]
fn scan_object(
    target: &SweepTarget,
    start_offset: u64,
    keep: usize,
    chunk: usize,
    max_hits: usize,
    patterns: &PatternSet,
    state: &mut SweepState,
    on_hit: &mut dyn FnMut(&SweepHit),
) -> ObjectOutcome {
    let declared = target.declared_size;
    let source: &dyn DataSource = target.source.as_ref();
    let mut outcome = ObjectOutcome {
        reached: start_offset,
        stop: None,
        error: None,
        hash: None,
        started_at: start_offset,
    };
    let mut hasher = (target.content_hash.is_none() && start_offset == 0).then(Sha256::new);

    // `window` is the carried tail of what was already searched, then fresh
    // bytes, then up to `LOOKAHEAD` bytes peeked past them. Every match
    // ending inside the first `carry_len` bytes was reported already — by
    // the previous window, or by the page that minted the cursor — so only
    // matches ending past it and within the fresh bytes are new; a match
    // ending in the peek is left for the next window, which re-reads those
    // bytes as fresh. The carry is one byte longer than the longest needle,
    // so a straddling match is seen whole and the endian check can look two
    // bytes before any new match; the peek lets it look two bytes after.
    let mut window: Vec<u8> = Vec::new();
    let mut base: u64;
    let mut carry_len: usize;
    if start_offset > 0 {
        let back = (keep as u64).min(start_offset);
        base = start_offset - back;
        let mut carried = vec![0u8; back as usize];
        match read_fully(source, base, &mut carried) {
            Ok(n) if n == carried.len() => {}
            Ok(n) => {
                outcome.error = Some((
                    base + n as u64,
                    format!(
                        "could not re-read the {back} bytes before the resume offset {start_offset}"
                    ),
                ));
                return outcome;
            }
            Err(e) => {
                outcome.error = Some((base, e.to_string()));
                return outcome;
            }
        }
        window = carried;
        carry_len = window.len();
    } else {
        base = 0;
        carry_len = 0;
    }

    let mut read_pos = start_offset;
    loop {
        if read_pos >= declared {
            break;
        }
        if state.budget == 0 {
            outcome.stop = Some(Stop::ByteCap);
            break;
        }
        let want = (declared - read_pos).min(chunk as u64).min(state.budget) as usize;
        let mut fresh = vec![0u8; want];
        let n = match read_fully(source, read_pos, &mut fresh) {
            Ok(n) => n,
            Err(e) => {
                outcome.error = Some((read_pos, e.to_string()));
                break;
            }
        };
        if n == 0 {
            break;
        }
        fresh.truncate(n);
        if let Some(h) = hasher.as_mut() {
            h.update(&fresh);
        }
        read_pos += n as u64;
        outcome.reached = read_pos;
        state.budget -= n as u64;
        state.bytes_scanned += n as u64;
        window.extend_from_slice(&fresh);
        let emit_limit = window.len();

        // The peek is not searched for matches and not charged to the
        // budget; it only tells the endian check what follows a match. A
        // peek that cannot be read is treated as absent, and the next read
        // of those bytes reports the failure or the short read.
        let peek_want = (declared - read_pos).min(LOOKAHEAD as u64) as usize;
        if peek_want > 0 {
            let mut peek = vec![0u8; peek_want];
            if let Ok(got) = read_fully(source, read_pos, &mut peek) {
                window.extend_from_slice(&peek[..got]);
            }
        }

        // Overlapping iteration is exhaustive but runs without the
        // automaton's SIMD prefilter, an order of magnitude slower than the
        // non-overlapping search. `is_match` is the fast one, and a window it
        // rejects holds no occurrence of any needle, so only windows that
        // actually contain something pay for the exhaustive pass.
        //
        // Matches arrive in order of end offset. When the ceiling bites, the
        // rest of the matches ending at that same byte are still reported,
        // so a cursor at that byte loses nothing.
        let mut cap_end: Option<usize> = None;
        if patterns.automaton.is_match(&window) {
            for m in patterns.automaton.find_overlapping_iter(&window) {
                if m.end() <= carry_len {
                    continue;
                }
                if m.end() > emit_limit {
                    // Matches arrive in order of end offset; the rest end
                    // in the peek.
                    break;
                }
                if let Some(end) = cap_end {
                    if m.end() != end {
                        break;
                    }
                }
                let needle = &patterns.needles[m.pattern().as_usize()];
                let spec = &patterns.specs[needle.pattern_index];
                let (encodings, aliases) =
                    match endian_reading(patterns, needle, &window, m.start()) {
                        EndianReading::Pinned => (needle.encodings.clone(), Vec::new()),
                        EndianReading::FoldedTwin => continue,
                        EndianReading::Primary { twin } => {
                            let mut encodings = needle.encodings.clone();
                            for e in twin.encodings {
                                if !encodings.contains(e) {
                                    encodings.push(e.clone());
                                }
                            }
                            state.endian_aliases_folded += 1;
                            (
                                encodings,
                                vec![EndianAlias {
                                    encoding: twin.side.to_string(),
                                    offset: base + m.start() as u64 + 1,
                                    folded: true,
                                }],
                            )
                        }
                        EndianReading::ChainMember { before, after } => {
                            let mut aliases = Vec::new();
                            if let Some(side) = before {
                                aliases.push(EndianAlias {
                                    encoding: side.to_string(),
                                    offset: base + m.start() as u64 - 1,
                                    folded: false,
                                });
                            }
                            if let Some(side) = after {
                                aliases.push(EndianAlias {
                                    encoding: side.to_string(),
                                    offset: base + m.start() as u64 + 1,
                                    folded: false,
                                });
                            }
                            (needle.encodings.clone(), aliases)
                        }
                    };
                if !aliases.is_empty() {
                    state.hits_endian_ambiguous += 1;
                }
                let hit = SweepHit {
                    artifact_id: target.artifact_id,
                    artifact_type: target.artifact_type.clone(),
                    region: target.region,
                    path: target.path.clone(),
                    offset: base + m.start() as u64,
                    length: needle.bytes.len() as u64,
                    pattern_index: needle.pattern_index,
                    pattern_kind: spec.kind,
                    pattern_value: spec.value.clone(),
                    encodings,
                    endian_aliases: aliases,
                };
                on_hit(&hit);
                state.hits.push(hit);
                if state.hits.len() >= max_hits && cap_end.is_none() {
                    cap_end = Some(m.end());
                }
            }
        }
        if let Some(end) = cap_end {
            outcome.stop = Some(Stop::HitCap {
                at: base + end as u64,
            });
            break;
        }

        // Discard the peek (it is re-read as fresh) and all but the carry.
        window.truncate(emit_limit);
        let drop = window.len().saturating_sub(keep);
        base += drop as u64;
        window.drain(..drop);
        carry_len = window.len();
    }

    if outcome.stop.is_none() && outcome.error.is_none() && read_pos == declared {
        if let Some(h) = hasher {
            outcome.hash = Some(format!("{:x}", h.finalize()));
        }
    }
    outcome
}

/// Bytes peeked past each window for the endian check: the opposite
/// reading one byte after a match, and the same reading two bytes after it.
const LOOKAHEAD: usize = 2;

/// The opposite-endian reading beside a UTF-16 match, if any.
struct Twin<'a> {
    side: &'static str,
    encodings: &'a [String],
}

enum EndianReading<'a> {
    /// Not a UTF-16 form, or no opposite reading one byte away: the
    /// encodings on the needle are what the bytes say.
    Pinned,
    /// The opposite reading one byte later exists and neither has any other
    /// neighbour: fold it into this hit.
    Primary { twin: Twin<'a> },
    /// The opposite reading one byte earlier is a `Primary` that folded this
    /// one: report nothing.
    FoldedTwin,
    /// Inside a run of one repeated code unit, where readings alternate at
    /// every byte and no pair stands apart: report the hit with the
    /// neighbouring readings named and nothing folded.
    ChainMember {
        before: Option<&'static str>,
        after: Option<&'static str>,
    },
}

/// Classify the match of `needle` at `at` (a window offset) by the
/// opposite-endian readings one byte either side of it. `window` holds at
/// least two bytes before any new match and, unless the object ends, two
/// bytes after it, so every reading that exists is visible.
fn endian_reading<'a>(
    patterns: &'a PatternSet,
    needle: &'a Needle,
    window: &[u8],
    at: usize,
) -> EndianReading<'a> {
    let Some(opposite_index) = needle.utf16_opposite else {
        return EndianReading::Pinned;
    };
    let opposite = &patterns.needles[opposite_index];
    let reads_as = |start: isize, form: &[u8]| -> bool {
        start >= 0 && {
            let start = start as usize;
            window.len() >= start + form.len() && &window[start..start + form.len()] == form
        }
    };
    let at = at as isize;
    let before = reads_as(at - 1, &opposite.bytes);
    let after = reads_as(at + 1, &opposite.bytes);
    if !before && !after {
        return EndianReading::Pinned;
    }
    let side = utf16_side(opposite).unwrap_or(RAW_ENCODING);
    // A pair stands apart when neither reading has a further neighbour:
    // the same reading as this one two bytes away on the far side.
    let before_has_own = reads_as(at - 2, &needle.bytes);
    let after_has_own = reads_as(at + 2, &needle.bytes);
    if before && !after && !before_has_own {
        return EndianReading::FoldedTwin;
    }
    if after && !before && !after_has_own {
        return EndianReading::Primary {
            twin: Twin {
                side,
                encodings: &opposite.encodings,
            },
        };
    }
    EndianReading::ChainMember {
        before: before.then_some(side),
        after: after.then_some(side),
    }
}

fn coverage_statement(
    state: &SweepState,
    max_hits: usize,
    max_bytes: u64,
    complete: bool,
) -> String {
    let mut parts = vec![format!(
        "Searched {} object(s), {} byte(s), of {} offered; {} excluded by scope; {} skipped to \
         reach the cursor.",
        state.objects_searched,
        state.bytes_scanned,
        state.objects_offered,
        state.objects_excluded.total(),
        state.objects_skipped_by_cursor
    )];
    let cursor = |c: &SweepCursor| format!("object {} byte {}", c.artifact_id, c.offset);
    if state.hit_cap_reached {
        parts.push(format!(
            "Stopped at the hit ceiling of {max_hits} ({} hit(s) reported){}.",
            state.hits.len(),
            state
                .next_cursor
                .as_ref()
                .map(|c| format!("; resume at {}", cursor(c)))
                .unwrap_or_default()
        ));
    }
    if state.byte_cap_reached {
        parts.push(format!(
            "Stopped at the byte ceiling of {max_bytes} ({} byte(s) read){}.",
            state.bytes_scanned,
            state
                .next_cursor
                .as_ref()
                .map(|c| format!("; resume at {}", cursor(c)))
                .unwrap_or_default()
        ));
    }
    const LISTED: usize = 10;
    if !state.short_reads.is_empty() {
        let listed: Vec<String> = state
            .short_reads
            .iter()
            .take(LISTED)
            .map(|s| {
                format!(
                    "{} read {} of {} bytes",
                    s.artifact_id, s.bytes_read, s.declared_size
                )
            })
            .collect();
        let more = state.short_reads.len().saturating_sub(LISTED);
        parts.push(format!(
            "{} object(s) ended before their declared size, so bytes past the end were not \
             searched: {}{}.",
            state.short_reads.len(),
            listed.join("; "),
            if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            }
        ));
    }
    if !state.read_failures.is_empty() {
        let listed: Vec<String> = state
            .read_failures
            .iter()
            .take(LISTED)
            .map(|f| format!("{} at byte {} ({})", f.artifact_id, f.offset, f.error))
            .collect();
        let more = state.read_failures.len().saturating_sub(LISTED);
        parts.push(format!(
            "{} object(s) could not be read, so bytes past the failure were not searched: {}{}.",
            state.read_failures.len(),
            listed.join("; "),
            if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            }
        ));
    }
    if !state.beyond_declared_size.is_empty() {
        let listed: Vec<String> = state
            .beyond_declared_size
            .iter()
            .take(LISTED)
            .map(|b| {
                format!(
                    "{} holds {} byte(s) beyond its declared {}",
                    b.artifact_id, b.bytes_beyond, b.declared_size
                )
            })
            .collect();
        let more = state.beyond_declared_size.len().saturating_sub(LISTED);
        let total: u64 = state
            .beyond_declared_size
            .iter()
            .fold(0u64, |sum, b| sum.saturating_add(b.bytes_beyond));
        parts.push(format!(
            "{} object(s) hold {total} byte(s) beyond their declared size, which were not \
             searched: {}{}.",
            state.beyond_declared_size.len(),
            listed.join("; "),
            if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            }
        ));
    }
    if state.hits_endian_ambiguous > 0 {
        parts.push(format!(
            "{} hit(s) read as the pattern under both UTF-16 endiannesses one byte apart, so \
             the bytes do not pin which was written; {} opposite-endian reading(s) were folded \
             into the hit one byte before them and are not counted as hits.",
            state.hits_endian_ambiguous, state.endian_aliases_folded
        ));
    }
    if complete {
        parts.push(
            "Complete: the stream was exhausted and every admitted object was read to its \
             declared end."
                .to_string(),
        );
    }
    parts.join(" ")
}

/// [`sweep_with`] without a streaming sink.
pub fn sweep<I>(
    targets: I,
    patterns: &PatternSet,
    request: &SweepRequest,
) -> Result<SweepResponse, SweepError>
where
    I: IntoIterator<Item = SweepTarget>,
{
    sweep_with(targets, patterns, request, &mut |_| {})
}

/// Group hits across copies. `content_hashes` maps each object to its
/// SHA-256 where one is known; `unhashed_reasons` says why the others have
/// none.
pub fn group_hits(
    hits: &[SweepHit],
    content_hashes: &HashMap<Uuid, String>,
    unhashed_reasons: &HashMap<Uuid, String>,
) -> Grouping {
    #[derive(PartialEq, Eq, Hash)]
    enum Join {
        Hash(String),
        Identity(Uuid),
    }
    let mut index: HashMap<(PatternKind, String, Join), usize> = HashMap::new();
    let mut groups: Vec<HitGroup> = Vec::new();
    let mut hits_without_content_hash = 0;

    for hit in hits {
        let (join, basis) = match content_hashes.get(&hit.artifact_id) {
            Some(sha256) => (
                Join::Hash(sha256.clone()),
                GroupingBasis::ContentHash {
                    sha256: sha256.clone(),
                },
            ),
            None => {
                hits_without_content_hash += 1;
                (
                    Join::Identity(hit.artifact_id),
                    GroupingBasis::ArtifactIdentity {
                        artifact_id: hit.artifact_id,
                        reason: unhashed_reasons
                            .get(&hit.artifact_id)
                            .cloned()
                            .unwrap_or_else(|| {
                                "no content hash was available for the object".to_string()
                            }),
                    },
                )
            }
        };
        let key = (hit.pattern_kind, hit.pattern_value.clone(), join);
        let at = match index.get(&key) {
            Some(&at) => at,
            None => {
                index.insert(key, groups.len());
                groups.push(HitGroup {
                    pattern_index: hit.pattern_index,
                    pattern_kind: hit.pattern_kind,
                    pattern_value: hit.pattern_value.clone(),
                    basis,
                    artifact_ids: Vec::new(),
                    locations: Vec::new(),
                });
                groups.len() - 1
            }
        };
        let group = &mut groups[at];
        if !group.artifact_ids.contains(&hit.artifact_id) {
            group.artifact_ids.push(hit.artifact_id);
        }
        group.locations.push(hit.clone());
    }

    Grouping {
        group_count: groups.len(),
        groups,
        hit_count: hits.len(),
        hits_without_content_hash,
    }
}
