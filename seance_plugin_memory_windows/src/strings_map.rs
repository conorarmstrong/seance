//! `strings` over memory (`ROADMAP` §5.3 — upstream's `windows.strings`): which
//! processes, and the kernel, have a given **physical** offset mapped.
//!
//! # What this stage is
//!
//! The examiner runs `strings -t d` over the raw image themselves — their own
//! tool, their own minimum length, their own encoding choices — and brings the
//! resulting file of byte offsets. Each offset is a physical address, and by
//! itself it says only that the machine held those bytes somewhere. This stage
//! turns each one into the finding: *whose* memory it was in, and at what
//! virtual address in each of them.
//!
//! Nothing here searches for anything. Séance does not choose what an examiner
//! is looking for, and with no strings file named this stage reports that it
//! **did not run**, with that reason, rather than emitting an empty result: an
//! empty answer from a route that was never given a file is indistinguishable,
//! on screen, from one that looked and found nothing.
//!
//! # The route is a reverse mapping, and it is built rather than guessed
//!
//! Answering needs the inverse of a page-table walk — physical frame to the
//! address spaces that reach it — which is [`seance_memory::reverse`] over the
//! downward enumeration in [`seance_memory::translate::enumerate`]. Every
//! process's tables are walked, plus the kernel's, and each wanted frame is
//! recorded against every space that maps it.
//!
//! # What upstream does here, measured
//!
//! Volatility 3's `windows.strings` builds the same index and its per-process
//! branch keys it by the **virtual** page number, because that branch unpacks
//! `Intel.mapping()`'s tuple in a different order from its kernel branch
//! (`strings.py:183-191` against `:150-155`). Run against this project's Win11
//! corpus on 2026-09-15 with offsets taken from pages those processes really
//! map, every one came back `FREE MEMORY`; physical `0x7ffe0000` came back
//! attributed to 123 of the 130 live processes, because `0x7ffe0` is
//! `KUSER_SHARED_DATA`'s *virtual* page in each of them. Its kernel column is
//! correct and is the only part of it that is.
//!
//! So this stage is shaped against those three failures by construction: the
//! index is keyed on physical frames only, the physical offset and the virtual
//! address are fields at different levels of the record, and a frame reached
//! through the shared kernel half is one owner naming the spaces that reach it
//! rather than one hundred and thirty findings.
//!
//! # The radix is declared, never inferred
//!
//! `strings -t x` writes hexadecimal offsets. Read as decimal, `3f0000` is
//! rejected for its `f` — but `100500000` parses cleanly as one hundred
//! million and names a frame four gigabytes from the truth, and nothing about
//! the row looks wrong. A wrong radix cannot be detected from the offsets that
//! *parse*, so it is not guessed: the examiner states it, the record says which
//! was used, and the proportion of lines rejected under it is published beside
//! the answer so a mismatch shows up as what it is.

use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::reverse::{Attribution, FrameSet, ReverseMap, Verdict};
use seance_memory::translate::enumerate::{EnumerateLimits, RootParity};
use seance_memory::translate::{PageWalk, TableCache};
use seance_memory::Incomplete;
use serde_json::{json, Map, Value};

use crate::modules::{paging_spec, ModuleSymbols, ModuleWalkConfig, ModulesError, ProcessSpace};
use crate::process::{ProcessList, ProcessRecord};
use crate::profile::WindowsProfile;

/// Lines this build will read from a strings file.
///
/// `strings -n 8` over a 16 GiB image yields tens of millions of lines. Five
/// million offsets is what a *scoped* file looks like — one produced from a
/// region, or filtered to a pattern — and is 40 MiB held. Past it the record
/// says how many lines were read and that the rest were never looked up: the
/// walk costs the same either way, so nothing is saved by hiding it.
pub const MAX_OFFSETS: usize = 5_000_000;

/// Offsets given a row of their own in the record.
///
/// The counts and the histogram stay exact for every offset looked up; this
/// bounds only how many are listed individually, because a record is read by a
/// person.
pub const MAX_LISTED_ANSWERS: usize = 10_000;

/// Address spaces this build will walk.
///
/// One process is one to two thousand page tables of its own, so four thousand
/// processes is of the order of four million table reads — the same ceiling the
/// enumeration carries per space. A list longer than this is reported with the
/// number walked beside the number listed, and every offset with no owner says
/// that some space was never walked.
pub const MAX_PROCESSES_WALKED: usize = 4_096;

/// How the offsets in a strings file are written.
///
/// Stated by the examiner, because it cannot be established from the file: see
/// the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Radix {
    /// `strings -t d`, the default and the form the manual page documents
    /// first.
    #[default]
    Decimal,
    /// `strings -t x`.
    Hexadecimal,
    /// `strings -t o`.
    Octal,
}

impl Radix {
    /// The name a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Radix::Decimal => "decimal",
            Radix::Hexadecimal => "hexadecimal",
            Radix::Octal => "octal",
        }
    }

    /// The `strings -t` flag that produces it.
    pub fn strings_flag(self) -> &'static str {
        match self {
            Radix::Decimal => "-t d",
            Radix::Hexadecimal => "-t x",
            Radix::Octal => "-t o",
        }
    }

    /// Parse a radix an examiner named.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "d" | "dec" | "decimal" => Some(Radix::Decimal),
            "x" | "hex" | "hexadecimal" => Some(Radix::Hexadecimal),
            "o" | "oct" | "octal" => Some(Radix::Octal),
            _ => None,
        }
    }

    fn base(self) -> u32 {
        match self {
            Radix::Decimal => 10,
            Radix::Hexadecimal => 16,
            Radix::Octal => 8,
        }
    }
}

/// One line of a strings file: a physical offset and the text found there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringsEntry {
    /// The physical byte offset, as the named radix reads it.
    pub offset: u64,
    /// The text, truncated to [`MAX_TEXT_BYTES`] for the record.
    pub text: String,
}

/// Bytes of one string kept for the record.
///
/// A strings file can hold a line megabytes long. The offset is the finding;
/// the text is there so an examiner recognises the row.
pub const MAX_TEXT_BYTES: usize = 512;

/// A strings file, parsed.
///
/// Parsed at the registration site rather than in the stage, the way a YARA
/// rule set is: a file the examiner **named** and that will not read must fail
/// the run, and a stage that quietly reported "nothing was named" would hide
/// that.
#[derive(Debug, Clone, Default)]
pub struct StringsSource {
    /// Where it came from, for the record.
    pub path: String,
    /// The radix the examiner stated.
    pub radix: Radix,
    /// Lines read from the file.
    pub lines_read: u64,
    /// Lines that did not parse as an offset and a string under that radix.
    pub malformed_lines: u64,
    /// Whether reading stopped at [`MAX_OFFSETS`].
    pub lines_capped: bool,
    /// The offsets, in the order the file gave them.
    pub entries: Vec<StringsEntry>,
}

impl StringsSource {
    /// Read a strings file: lines of `<offset> <text>`, as `strings -t`
    /// writes them.
    ///
    /// Leading whitespace is skipped, since `strings` right-aligns its offsets.
    /// A line whose offset does not parse **under the named radix** is counted
    /// as malformed and not guessed at in another base.
    ///
    /// # Errors
    ///
    /// Any I/O failure reading the file. A file the examiner named and that
    /// will not read is a failed run, not an empty result.
    pub fn read(path: impl Into<String>, radix: Radix, source: impl Read) -> std::io::Result<Self> {
        let mut out = Self {
            path: path.into(),
            radix,
            ..Self::default()
        };
        // Bytes, not `lines()`.
        //
        // `strings` emits whatever encoding it found in the image, and an
        // image holds arbitrary bytes: `BufRead::lines` returns
        // `InvalidData` on the first one that is not UTF-8, which would abort
        // the whole run over a single byte in a five-million-line file. Every
        // line is decoded lossily instead, and a line that would not decode is
        // still a line whose offset parses.
        //
        // And the read is bounded per line. One unterminated line is one
        // allocation the size of the file, which a hostile or truncated file
        // makes trivially: `strings` on a binary can emit a very long run, and
        // nothing in the format bounds it. A line past the ceiling is counted
        // as malformed and its tail discarded rather than held.
        let mut reader = BufReader::new(source);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = read_bounded_line(&mut reader, &mut line, MAX_LINE_BYTES)?;
            if read == 0 {
                break;
            }
            out.lines_read += 1;
            if out.entries.len() >= MAX_OFFSETS {
                out.lines_capped = true;
                break;
            }
            let text = String::from_utf8_lossy(&line);
            match parse_line(&text, radix) {
                Some(entry) => out.entries.push(entry),
                None => out.malformed_lines += 1,
            }
        }
        Ok(out)
    }

    /// How many offsets were parsed.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no offset parsed, in which case there is nothing to look up.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether so many lines were rejected that the named radix is doubtful.
    ///
    /// The **only** honest signal of a wrong radix, and it works in one
    /// direction: a hexadecimal file read as decimal loses every line with a
    /// letter in it, which is most of them. The lines that survive parse into
    /// the wrong frames and cannot be told apart from correct ones, which is
    /// why this is a warning on the record and not a correction.
    pub fn radix_is_doubtful(&self) -> bool {
        self.lines_read > 8 && self.malformed_lines * 2 > self.lines_read
    }

    fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "radix": self.radix.as_str(),
            "radix_produced_by": self.radix.strings_flag(),
            "lines_read": self.lines_read,
            "offsets_parsed": self.entries.len(),
            "malformed_lines": self.malformed_lines,
            "lines_capped": self.lines_capped,
            "line_cap": MAX_OFFSETS,
            "radix_is_doubtful": self.radix_is_doubtful(),
        })
    }
}

/// Bytes of one line this build will hold.
///
/// A strings file is one line per finding, and a finding in an image can be
/// very long — but a line longer than this is not one an examiner reads, and
/// one *unterminated* line is otherwise an allocation the size of the whole
/// file. 64 KiB is eight times the longest line any run over this project's
/// corpora produced.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Read one `\n`-terminated line, keeping at most `limit` bytes of it and
/// discarding the rest of that line.
///
/// Returns the bytes consumed from the reader, so `0` is end of file and a
/// line that was cut is still one line. The terminator is not kept, and a
/// trailing `\r` is dropped so a file written on Windows parses.
fn read_bounded_line(
    reader: &mut impl BufRead,
    out: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<usize> {
    let mut consumed = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        match available.iter().position(|b| *b == b'\n') {
            Some(at) => {
                let take = (limit.saturating_sub(out.len())).min(at);
                out.extend_from_slice(&available[..take]);
                reader.consume(at + 1);
                consumed += at + 1;
                break;
            }
            None => {
                let len = available.len();
                let take = (limit.saturating_sub(out.len())).min(len);
                out.extend_from_slice(&available[..take]);
                reader.consume(len);
                consumed += len;
            }
        }
    }
    if out.last() == Some(&b'\r') {
        out.pop();
    }
    Ok(consumed)
}

/// One line of a strings file.
fn parse_line(line: &str, radix: Radix) -> Option<StringsEntry> {
    let trimmed = line.trim_start();
    let digits: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if digits.is_empty() {
        return None;
    }
    let offset = u64::from_str_radix(&digits, radix.base()).ok()?;
    let rest = trimmed[digits.len()..].trim_start();
    if rest.is_empty() {
        return None;
    }
    Some(StringsEntry {
        offset,
        text: cut_to(rest, MAX_TEXT_BYTES),
    })
}

/// Truncate on a character boundary, so a multi-byte character is never cut in
/// half into invalid UTF-8.
fn cut_to(text: &str, bytes: usize) -> String {
    if text.len() <= bytes {
        return text.to_string();
    }
    let mut end = bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// What this stage was asked to do, and what it may spend.
#[derive(Debug, Clone)]
pub struct StringsMapConfig {
    /// How the per-process address spaces are built.
    pub modules: ModuleWalkConfig,
    /// Address spaces to walk. See [`MAX_PROCESSES_WALKED`].
    pub max_processes: usize,
    /// Offsets given a row of their own. See [`MAX_LISTED_ANSWERS`].
    pub max_listed: usize,
    /// Whether to walk the kernel's own address space as well.
    ///
    /// On by default, and the record says so either way: a great deal of what
    /// a strings file finds is in paged pool or the file cache, which belongs
    /// to no process at all.
    pub include_kernel: bool,
}

impl Default for StringsMapConfig {
    fn default() -> Self {
        Self {
            modules: ModuleWalkConfig::default(),
            max_processes: MAX_PROCESSES_WALKED,
            max_listed: MAX_LISTED_ANSWERS,
            include_kernel: true,
        }
    }
}

/// Why this stage could not run.
#[derive(Debug)]
pub enum StringsMapError {
    /// This build cannot read the image this way at all — no paging mode, or
    /// no `_EPROCESS` member naming a directory table base.
    Unsupported(String),
}

impl std::fmt::Display for StringsMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringsMapError::Unsupported(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for StringsMapError {}

impl From<ModulesError> for StringsMapError {
    fn from(err: ModulesError) -> Self {
        StringsMapError::Unsupported(err.to_string())
    }
}

/// One offset's answer, ready for the record.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The text the examiner's own tool found there.
    pub text: String,
    /// What the map is entitled to say.
    pub attribution: Attribution,
}

/// What the stage established.
#[derive(Debug)]
pub struct StringsMap {
    /// The file, or `None` where none was named.
    source: Option<StringsSource>,
    /// The map, or `None` where the stage did not run.
    map: Option<ReverseMap>,
    /// One answer per offset looked up, cut at the listing cap.
    answers: Vec<Answer>,
    /// How many offsets were looked up, whether or not they are listed.
    looked_up: u64,
    /// The verdict histogram over every offset looked up.
    mapped: u64,
    mapped_coverage_short: u64,
    no_mapping: u64,
    not_assessed: u64,
    /// Processes the list held, and how many were walked.
    /// Processes the list held, or `None` where the list did not walk — which
    /// is not a machine with no processes on it.
    processes_listed: Option<usize>,
    processes_walked: usize,
    /// Processes whose own address space could not be built, with the reason.
    processes_refused: Vec<(String, String)>,
    /// Whether the kernel's space was walked.
    kernel_walked: bool,
    /// Top-level subtrees declined because the kernel's own walk had already
    /// covered the identical entry. The measure of what the parity saved.
    shared_subtrees: u64,
    /// Table reads spent.
    tables_read: u64,
    table_bytes_read: u64,
    prototype_hops: u64,
    prototype_entries: u64,
    prototypes_unresolved: u64,
}

impl StringsMap {
    /// The answer for an offset, by position in the listing.
    pub fn answers(&self) -> &[Answer] {
        &self.answers
    }

    /// Whether every offset was looked up against every address space, with
    /// nothing blind, capped or unwalked anywhere.
    pub fn is_complete(&self) -> bool {
        let Some(source) = self.source.as_ref() else {
            return false;
        };
        let Some(map) = self.map.as_ref() else {
            return false;
        };
        // Every condition `incomplete()` reports, and in the same order, so
        // the two cannot drift: a record that says it is complete while
        // carrying an `incomplete` entry is the contradiction an examiner
        // would have to notice for themselves.
        !source.lines_capped
            && source.malformed_lines == 0
            && self.kernel_walked
            && map.every_space_complete()
            && self.processes_refused.is_empty()
            && self.processes_listed == Some(self.processes_walked)
            && self.answers.len() as u64 == self.looked_up
    }

    /// What this stage could not establish, in the record's own vocabulary.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        let Some(source) = self.source.as_ref() else {
            out.push(Incomplete::new(
                IncompleteReason::Unvalidated,
                "no strings file was named for this run, so no physical offset was looked up. \
                 Séance does not choose what an examiner is searching for: run `strings -t d` \
                 over the image and name the file with SEANCE_MEMORY_STRINGS. Nothing here is a \
                 statement about what this image holds.",
            ));
            return out;
        };
        if source.lines_capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the strings file was read to its ceiling of {MAX_OFFSETS} offsets after \
                     {} lines, so offsets past that line were never looked up",
                    source.lines_read
                ),
            ));
        }
        if source.malformed_lines > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} of {} lines did not parse as a {} offset and were not looked up{}",
                    source.malformed_lines,
                    source.lines_read,
                    source.radix.as_str(),
                    if source.radix_is_doubtful() {
                        " -- more than half the file, which is what a strings file written in \
                         another radix looks like; the offsets that DID parse under this radix \
                         name the wrong frames and cannot be told apart from correct ones"
                    } else {
                        ""
                    }
                ),
            ));
        }
        if !self.kernel_walked {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the kernel's own address space was not walked, so an offset in paged pool, in \
                 the file cache or in a driver's memory has no owner here -- which is not the \
                 same as belonging to no process",
            ));
        }
        match self.processes_listed {
            None => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the process list did not walk, so no process address space was searched at \
                 all and no number here is a count of the processes this machine had",
            )),
            Some(listed) if self.processes_walked < listed => out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} of the {listed} processes listed were walked, so an offset mapped only \
                     by one of the others is reported with no owner",
                    self.processes_walked
                ),
            )),
            Some(_) => {}
        }
        for (label, reason) in &self.processes_refused {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("{label}'s own address space could not be built, so it was not searched: {reason}"),
            ));
        }
        if let Some(map) = self.map.as_ref() {
            for shortfall in map.shortfalls() {
                out.push(Incomplete::new(
                    shortfall.reason,
                    format!("{}: {}", shortfall.label, shortfall.detail),
                ));
            }
        }
        if self.answers.len() as u64 != self.looked_up {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} of {} offsets are listed individually; every count beside them is over \
                     all {} that were looked up",
                    self.answers.len(),
                    self.looked_up,
                    self.looked_up
                ),
            ));
        }
        out
    }

    /// The sentence a record carries when nothing was searched for.
    pub fn describe(&self) -> &'static str {
        if self.source.is_none() {
            "No strings file was named, so this stage did not run. It searches for nothing of \
             its own: the offsets come from the examiner's own run of `strings` over the image. \
             That is not a statement about what is in this image."
        } else {
            "Each physical offset from the examiner's strings file, and every address space \
             whose page tables reach it."
        }
    }

    /// The record.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("name".into(), json!("Memory analysis: strings over memory"));
        out.insert("describes".into(), json!(self.describe()));
        out.insert(
            "source".into(),
            self.source
                .as_ref()
                .map(StringsSource::to_json)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "spaces".into(),
            json!({
                "kernel_walked": self.kernel_walked,
                "processes_listed": self.processes_listed,
                "process_list_walked": self.processes_listed.is_some(),
                "processes_walked": self.processes_walked,
                "process_cap": MAX_PROCESSES_WALKED,
                "processes_refused": self.processes_refused.len(),
                "shared_subtrees_declined": self.shared_subtrees,
                "declared": self.map.as_ref().map(|m| m.spaces().len()).unwrap_or(0),
                "every_space_complete": self
                    .map
                    .as_ref()
                    .map(ReverseMap::every_space_complete)
                    .unwrap_or(false),
            }),
        );
        out.insert(
            "cost".into(),
            json!({
                "tables_read": self.tables_read,
                "table_bytes_read": self.table_bytes_read,
                "prototype_hops": self.prototype_hops,
                "prototype_entries": self.prototype_entries,
                "prototypes_unresolved": self.prototypes_unresolved,
                "mappings_recorded": self.map.as_ref().map(ReverseMap::recorded).unwrap_or(0),
                "frames_wanted": self.map.as_ref().map(|m| m.wanted().len()).unwrap_or(0),
                "frames_with_an_owner": self
                    .map
                    .as_ref()
                    .map(ReverseMap::frames_with_an_owner)
                    .unwrap_or(0),
            }),
        );
        out.insert(
            "answers".into(),
            json!({
                "looked_up": self.looked_up,
                "listed": self.answers.len(),
                "listing_cap": MAX_LISTED_ANSWERS,
                "mapped": self.mapped,
                "mapped_coverage_short": self.mapped_coverage_short,
                "no_mapping_every_space_assessed": self.no_mapping,
                "not_assessed": self.not_assessed,
            }),
        );
        out.insert(
            "offsets".into(),
            Value::Array(
                self.answers
                    .iter()
                    .map(|answer| self.answer_json(answer))
                    .collect(),
            ),
        );
        out.insert(
            "coverage_shortfalls".into(),
            Value::Array(
                self.map
                    .as_ref()
                    .map(|map| {
                        map.shortfalls()
                            .into_iter()
                            .map(|s| {
                                json!({
                                    "space": s.label,
                                    "reason": s.reason.as_str(),
                                    "detail": s.detail,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
        );
        out.insert(
            "incomplete".into(),
            Value::Array(self.incomplete().iter().map(Incomplete::to_json).collect()),
        );
        out.insert("content_complete".into(), json!(self.is_complete()));
        Value::Object(out)
    }

    fn answer_json(&self, answer: &Answer) -> Value {
        let attribution = &answer.attribution;
        let owners: Vec<Value> = attribution
            .owners
            .iter()
            .map(|owner| {
                let label = self
                    .map
                    .as_ref()
                    .and_then(|map| map.space(owner.space))
                    .map(|space| space.label.clone())
                    .unwrap_or_else(|| format!("space {}", owner.space));
                let also: Vec<String> = owner
                    .also_reached_from
                    .iter()
                    .filter_map(|&handle| {
                        self.map
                            .as_ref()
                            .and_then(|map| map.space(handle))
                            .map(|space| space.label.clone())
                    })
                    .collect();
                json!({
                    "space": label,
                    "virtual_address": format!("{:#x}", owner.virtual_address),
                    "page_virtual_base": format!("{:#x}", owner.page_virtual_base),
                    "page_bytes": owner.page_bytes,
                    "reached_via": owner.via.as_str(),
                    "shared_page": owner.via.is_shared(),
                    "virtual_address_enumerated": owner.virtual_address_enumerated,
                    "also_reached_from": also,
                })
            })
            .collect();
        json!({
            "physical_offset": format!("{:#x}", attribution.physical_offset),
            "physical_offset_decimal": attribution.physical_offset,
            "frame": format!("{:#x}", attribution.frame << 12),
            "text": answer.text,
            "verdict": attribution.verdict.as_str(),
            "verdict_statement": attribution.verdict.statement(),
            "owners": owners,
            "owners_total": attribution.owners_total,
            "owners_listed_capped": attribution.owners_listed_capped,
            "not_assessed_in": attribution
                .not_assessed_in
                .iter()
                .map(|s| json!({"space": s.label, "reason": s.reason.as_str(), "detail": s.detail}))
                .collect::<Vec<_>>(),
        })
    }
}

/// Run the stage.
///
/// `source` is `None` where no strings file was named, which is the ordinary
/// case: the result then reports that the stage did not run, with that reason.
///
/// # Errors
///
/// [`StringsMapError::Unsupported`] where this build cannot read the image this
/// way at all — the paging mode was never established, or this `_EPROCESS` does
/// not declare a directory table base. Neither is a fact about the evidence and
/// both are reported as the stage not running.
pub fn map_strings(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    processes: Option<&ProcessList>,
    source: Option<&StringsSource>,
    config: &StringsMapConfig,
) -> Result<StringsMap, StringsMapError> {
    let Some(source) = source else {
        return Ok(StringsMap {
            source: None,
            map: None,
            answers: Vec::new(),
            looked_up: 0,
            mapped: 0,
            mapped_coverage_short: 0,
            no_mapping: 0,
            not_assessed: 0,
            processes_listed: processes.map(|list| list.processes.len()),
            processes_walked: 0,
            processes_refused: Vec::new(),
            kernel_walked: false,
            shared_subtrees: 0,
            tables_read: 0,
            table_bytes_read: 0,
            prototype_hops: 0,
            prototype_entries: 0,
            prototypes_unresolved: 0,
        });
    };

    let spec = paging_spec(profile, &config.modules)?;
    let cache = config
        .modules
        .page_table_cache
        .clone()
        .unwrap_or_else(|| Arc::new(TableCache::new()));
    let suppressed = AtomicU64::new(0);
    let walk = PageWalk::new(
        profile.physical.as_ref(),
        &spec,
        cache.as_ref(),
        config.modules.translation,
        &suppressed,
    );

    let wanted = FrameSet::from_offsets(source.entries.iter().map(|entry| entry.offset));
    let mut map = ReverseMap::new(spec, wanted);
    let mut tables_read = 0u64;
    let mut table_bytes_read = 0u64;
    let mut prototype_hops = 0u64;
    let mut prototype_entries = 0u64;
    let mut prototypes_unresolved = 0u64;
    let mut shared_subtrees = 0u64;

    // The kernel's space first, and its top table becomes the parity every
    // process is compared against: each process maps the same kernel through
    // the same top-level entries, so walking it once is the difference between
    // ten thousand tables and ten thousand times the number of processes.
    let mut parity = None;
    let mut kernel_walked = false;
    // The handle the parity came from, so a pruned process's declined
    // subtrees can be recorded against it.
    let mut kernel_space: Option<usize> = None;
    if config.include_kernel {
        let kernel_dtb = profile.dtb.value;
        let handle = map.declare_space("kernel", kernel_dtb);
        kernel_space = Some(handle);
        let outcome = {
            let mut sink = map.sink_for(handle);
            walk.enumerate(kernel_dtb, &EnumerateLimits::default(), &mut sink)
        };
        tables_read += outcome.tables_read;
        table_bytes_read += outcome.table_bytes_read;
        prototype_hops += outcome.prototype_hops;
        prototype_entries += outcome.prototype_entries;
        prototypes_unresolved += outcome.prototypes_unresolved;
        kernel_walked = !outcome.root_unreadable;
        if kernel_walked {
            if let Ok(mut read) = RootParity::of(&walk, kernel_dtb) {
                // Only a subtree the kernel walk FINISHED may be pruned
                // against: an index it was capped or blinded under holds
                // mappings that were never reported, and pruning a process
                // there would drop every owner beneath it.
                for &index in &outcome.incomplete_top_indices {
                    read.mark_incomplete(index);
                }
                parity = Some(read);
            }
        }
        map.record_outcome(handle, outcome);
    }

    let mut processes_walked = 0usize;
    let mut processes_refused = Vec::new();
    // `None` is "the process list did not walk", which is NOT a machine with
    // no processes running on it. Zero would say the second, and would let
    // every offset's answer read as having been checked against every address
    // space there was.
    let listed = processes.map(|list| list.processes.len());
    if let Some(list) = processes {
        let past_cap = list.processes.len().saturating_sub(config.max_processes);
        for record in list.processes.iter().take(config.max_processes) {
            let label = process_label(record);
            // Declared BEFORE its space is built. A process that is declared
            // and never walked shortens every answer this map gives; one that
            // was never declared cannot, so a process whose page tables will
            // not build would otherwise leave the strongest negative verdict
            // in place -- "no address space maps this frame" -- while an
            // address space nobody looked at sat right there in the list.
            let handle = map.declare_space(label.clone(), 0);
            let space = match ProcessSpace::build(profile, symbols, record.address, &config.modules)
            {
                Ok(space) => space,
                Err(err) => {
                    processes_refused.push((label, err.to_string()));
                    continue;
                }
            };
            let dtb = space.dtb();
            map.set_space_dtb(handle, dtb);
            let limits = EnumerateLimits {
                prune_against: parity.as_ref(),
                ..EnumerateLimits::default()
            };
            let outcome = {
                // The sink is told which space the parity came from, so every
                // subtree the walk declines is recorded against it as the walk
                // declines it. Deriving the set afterwards by re-reading both
                // top tables got the 32-bit modes' entry count wrong and
                // counted every index absent from both spaces as shared.
                let mut sink = match (kernel_space, parity.as_ref()) {
                    (Some(reference), Some(_)) => map.sink_for_pruned_against(handle, reference),
                    _ => map.sink_for(handle),
                };
                walk.enumerate(dtb, &limits, &mut sink)
            };
            tables_read += outcome.tables_read;
            table_bytes_read += outcome.table_bytes_read;
            prototype_hops += outcome.prototype_hops;
            prototype_entries += outcome.prototype_entries;
            prototypes_unresolved += outcome.prototypes_unresolved;
            processes_walked += 1;
            shared_subtrees += outcome.shared_subtrees;
            map.record_outcome(handle, outcome);
        }
        // And the ones the cap never reached. Each is an address space that
        // exists and was not looked at, so each has to be in the map for the
        // answer to be short.
        for record in list.processes.iter().skip(config.max_processes) {
            map.declare_space(process_label(record), 0);
        }
        let _ = past_cap;
    }

    let mut out = StringsMap {
        source: Some(source.clone()),
        map: Some(map),
        answers: Vec::new(),
        looked_up: 0,
        mapped: 0,
        mapped_coverage_short: 0,
        no_mapping: 0,
        not_assessed: 0,
        processes_listed: listed,
        processes_walked,
        processes_refused,
        kernel_walked,
        shared_subtrees,
        tables_read,
        table_bytes_read,
        prototype_hops,
        prototype_entries,
        prototypes_unresolved,
    };
    let map = out.map.as_ref().expect("just set");
    let mut answers = Vec::new();
    for entry in &source.entries {
        let attribution = map.attribute(entry.offset);
        out.looked_up += 1;
        match attribution.verdict {
            Verdict::Mapped => out.mapped += 1,
            Verdict::MappedAndCoverageShort => out.mapped_coverage_short += 1,
            Verdict::NoMappingAndEverySpaceAssessed => out.no_mapping += 1,
            Verdict::NotAssessed => out.not_assessed += 1,
        }
        if answers.len() < config.max_listed {
            answers.push(Answer {
                text: entry.text.clone(),
                attribution,
            });
        }
    }
    out.answers = answers;
    Ok(out)
}

/// How a report names one process.
fn process_label(record: &ProcessRecord) -> String {
    let name = record
        .image_file_name
        .known()
        .cloned()
        .unwrap_or_else(|| "<unnamed>".to_string());
    match record.pid.known() {
        Some(pid) => format!("{name} ({pid})"),
        None => format!("{name} (_EPROCESS {:#x})", record.address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str, radix: Radix) -> StringsSource {
        StringsSource::read("test.strings", radix, text.as_bytes()).expect("in-memory read")
    }

    #[test]
    fn a_decimal_strings_file_is_read_the_way_strings_writes_it() {
        // `strings -t d` right-aligns its offsets in a column, so the leading
        // whitespace is part of the format rather than a malformed line.
        let source = read(
            // forensic-lint: allow RAGGED-STRING — real `strings -t d` output, padding included.
            "      4128768 A_EXPLORER_STRING\n   4132864 another one\n0 at the very start\n",
            Radix::Decimal,
        );
        assert_eq!(source.lines_read, 3);
        assert_eq!(source.malformed_lines, 0);
        assert_eq!(
            source
                .entries
                .iter()
                .map(|e| (e.offset, e.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (4_128_768, "A_EXPLORER_STRING"),
                (4_132_864, "another one"),
                (0, "at the very start"),
            ]
        );
        assert!(!source.radix_is_doubtful());
    }

    #[test]
    fn a_hexadecimal_file_read_as_hexadecimal_gives_the_offsets_it_names() {
        let source = read(
            "  3f0000 explorer\n100500000 ntoskrnl text\n",
            Radix::Hexadecimal,
        );
        assert_eq!(source.malformed_lines, 0);
        assert_eq!(
            source.entries.iter().map(|e| e.offset).collect::<Vec<_>>(),
            vec![0x3f_0000, 0x1_0050_0000]
        );
    }

    #[test]
    fn a_hexadecimal_file_read_as_decimal_is_doubted_rather_than_corrected() {
        // The failure this warning exists for, and the reason it is a warning.
        // `3f0000` is rejected for its `f`; `100500000` parses cleanly as one
        // hundred million and names a frame four gigabytes from the truth with
        // nothing on the row to show it. A radix cannot be recovered from the
        // offsets that DO parse, so the file is reported as doubtful and the
        // offsets are not silently re-read in another base.
        let source = read(
            "3f0000 a\n1a2b3c b\n100500000 c\nbeef d\ncafe e\n2b3c4d f\n7fff g\nabcdef h\n12345 i\n",
            Radix::Decimal,
        );
        assert_eq!(source.lines_read, 9);
        assert_eq!(source.malformed_lines, 7, "every line with a letter in it");
        assert!(
            source.radix_is_doubtful(),
            "more than half the file rejected is what a wrong radix looks like"
        );
        assert_eq!(
            source.entries.iter().map(|e| e.offset).collect::<Vec<_>>(),
            vec![100_500_000, 12_345],
            "and the survivors are wrong, which is why this is a warning and not a fix"
        );
    }

    #[test]
    fn a_short_file_is_never_doubted_on_the_strength_of_a_few_lines() {
        // Two malformed lines out of three is a proportion, not evidence: a
        // strings file can legitimately hold a line that is only an offset.
        let source = read("100 a\nnot an offset at all\n", Radix::Decimal);
        assert_eq!(source.malformed_lines, 1);
        assert!(!source.radix_is_doubtful());
    }

    #[test]
    fn a_line_with_no_text_is_not_an_offset_to_look_up() {
        // `strings` never writes one, and an offset with nothing at it is a
        // row an examiner cannot read.
        let source = read("4096\n4096   \n4096 x\n", Radix::Decimal);
        assert_eq!(source.entries.len(), 1);
        assert_eq!(source.malformed_lines, 2);
    }

    #[test]
    fn a_very_long_string_is_cut_on_a_character_boundary() {
        // A strings file can hold a line megabytes long, and cutting a
        // multi-byte character in half would produce invalid UTF-8 in a record
        // that is quoted.
        let long = "é".repeat(MAX_TEXT_BYTES);
        let source = read(&format!("4096 {long}\n"), Radix::Decimal);
        let text = &source.entries[0].text;
        assert!(text.len() <= MAX_TEXT_BYTES);
        assert!(
            text.chars().all(|c| c == 'é'),
            "no character was cut in half"
        );
    }

    #[test]
    fn a_file_under_the_ceiling_is_not_reported_as_capped() {
        let mut text = String::new();
        for index in 0..8 {
            text.push_str(&format!("{} line {index}\n", index * 4096));
        }
        let source = StringsSource::read("t", Radix::Decimal, text.as_bytes()).expect("read");
        assert_eq!(source.entries.len(), 8);
        assert!(!source.lines_capped);
    }

    #[test]
    fn one_byte_that_is_not_utf8_does_not_end_the_run() {
        // `strings` emits whatever encoding it found in the image, and an
        // image holds arbitrary bytes. Reading through `BufRead::lines` gave
        // up on the first such byte, which would abandon a five-million-line
        // file over one of them.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"4096 before\n");
        bytes.extend_from_slice(b"8192 caf\xff\xfe here\n");
        bytes.extend_from_slice(b"12288 after\n");
        let source = StringsSource::read("t", Radix::Decimal, bytes.as_slice()).expect("no abort");
        assert_eq!(source.lines_read, 3);
        assert_eq!(source.malformed_lines, 0);
        assert_eq!(
            source.entries.iter().map(|e| e.offset).collect::<Vec<_>>(),
            vec![4096, 8192, 12288],
            "the line with the undecodable byte is still a line whose offset parses"
        );
        assert!(
            source.entries[1].text.contains('\u{FFFD}'),
            "and its text is decoded lossily rather than dropped: {:?}",
            source.entries[1].text
        );
    }

    #[test]
    fn one_unterminated_line_is_not_read_whole_into_memory() {
        // A strings run over a binary can emit a very long line, and nothing
        // in the format bounds it. Without a per-line ceiling one line with no
        // terminator is one allocation the size of the file.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"4096 short\n");
        bytes.extend_from_slice(b"8192 ");
        bytes.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES * 4));
        let source = StringsSource::read("t", Radix::Decimal, bytes.as_slice()).expect("read");
        assert_eq!(source.lines_read, 2, "the unterminated tail is one line");
        assert_eq!(source.entries.len(), 2);
        assert!(
            source.entries[1].text.len() <= MAX_TEXT_BYTES,
            "the retained text is bounded: {}",
            source.entries[1].text.len()
        );
        assert_eq!(
            source.entries[1].offset, 8192,
            "and its offset still parses"
        );
    }

    #[test]
    fn a_file_written_on_windows_parses() {
        // `strings` on Windows, or a file moved through a Windows editor,
        // terminates with CRLF. A trailing carriage return left on the text
        // would be in every record.
        let source = StringsSource::read(
            "t",
            Radix::Decimal,
            "4096 first\r\n8192 second\r\n".as_bytes(),
        )
        .expect("read");
        assert_eq!(source.malformed_lines, 0);
        assert_eq!(
            source
                .entries
                .iter()
                .map(|e| e.text.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn the_offset_ceiling_stops_the_read_and_says_how_far_it_got() {
        // The cap path, which the test named for it did not exercise: it built
        // eight lines against a five-million ceiling and asserted the ceiling
        // had not fired.
        let mut text = String::new();
        for index in 0..8 {
            text.push_str(&format!("{} line {index}\n", index * 4096));
        }
        let source = StringsSource::read("t", Radix::Decimal, text.as_bytes()).expect("read");
        assert!(
            !source.lines_capped,
            "eight lines is under any real ceiling"
        );

        // And with the ceiling reached, the read stops and the record says so.
        let mut capped = StringsSource {
            path: "t".into(),
            radix: Radix::Decimal,
            ..StringsSource::default()
        };
        capped.entries = (0..MAX_OFFSETS)
            .map(|i| StringsEntry {
                offset: i as u64 * 4096,
                text: String::new(),
            })
            .collect();
        capped.lines_capped = true;
        capped.lines_read = MAX_OFFSETS as u64 + 1;
        let stage = StringsMap {
            source: Some(capped),
            map: None,
            answers: Vec::new(),
            looked_up: 0,
            mapped: 0,
            mapped_coverage_short: 0,
            no_mapping: 0,
            not_assessed: 0,
            processes_listed: Some(0),
            processes_walked: 0,
            processes_refused: Vec::new(),
            kernel_walked: true,
            shared_subtrees: 0,
            tables_read: 0,
            table_bytes_read: 0,
            prototype_hops: 0,
            prototype_entries: 0,
            prototypes_unresolved: 0,
        };
        assert!(!stage.is_complete(), "a capped read is not a complete one");
        let said: Vec<String> = stage
            .incomplete()
            .iter()
            .map(|i| {
                i.to_json()["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        assert!(
            said.iter()
                .any(|d| d.contains("ceiling") && d.contains("never looked up")),
            "the ceiling is reported with what it cost: {said:?}"
        );
    }

    #[test]
    fn a_record_never_says_it_is_complete_while_carrying_a_reason_it_is_not() {
        // The contradiction an examiner would otherwise have to notice
        // themselves. `is_complete` had omitted the kernel condition that
        // `incomplete()` reports, so a run with the kernel space unwalked
        // could be published as a complete answer with a sentence beneath it
        // saying an offset in paged pool has no owner here.
        let stage = StringsMap {
            source: Some(read("4096 x\n", Radix::Decimal)),
            map: None,
            answers: Vec::new(),
            looked_up: 0,
            mapped: 0,
            mapped_coverage_short: 0,
            no_mapping: 0,
            not_assessed: 0,
            processes_listed: Some(0),
            processes_walked: 0,
            processes_refused: Vec::new(),
            kernel_walked: false,
            shared_subtrees: 0,
            tables_read: 0,
            table_bytes_read: 0,
            prototype_hops: 0,
            prototype_entries: 0,
            prototypes_unresolved: 0,
        };
        assert!(
            !stage.incomplete().is_empty(),
            "the kernel space was not walked, which incomplete() reports"
        );
        assert!(
            !stage.is_complete(),
            "so is_complete must not say otherwise"
        );
        assert_eq!(stage.to_json()["content_complete"], false);
    }

    #[test]
    fn a_process_list_that_did_not_walk_is_not_a_machine_with_no_processes() {
        // Zero would say the second, and would let every offset's answer read
        // as having been checked against every address space there was.
        let stage = StringsMap {
            source: Some(read("4096 x\n", Radix::Decimal)),
            map: None,
            answers: Vec::new(),
            looked_up: 1,
            mapped: 0,
            mapped_coverage_short: 0,
            no_mapping: 0,
            not_assessed: 1,
            processes_listed: None,
            processes_walked: 0,
            processes_refused: Vec::new(),
            kernel_walked: true,
            shared_subtrees: 0,
            tables_read: 1,
            table_bytes_read: 4096,
            prototype_hops: 0,
            prototype_entries: 0,
            prototypes_unresolved: 0,
        };
        assert!(!stage.is_complete());
        let json = stage.to_json();
        assert_eq!(json["spaces"]["process_list_walked"], false);
        assert_eq!(json["spaces"]["processes_listed"], Value::Null);
        let said: Vec<String> = stage
            .incomplete()
            .iter()
            .map(|i| {
                i.to_json()["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        assert!(
            said.iter().any(|d| d.contains("process list did not walk")),
            "{said:?}"
        );
    }

    #[test]
    fn a_radix_an_examiner_names_is_recognised_in_the_forms_strings_uses() {
        for (name, radix) in [
            ("d", Radix::Decimal),
            ("decimal", Radix::Decimal),
            ("  DEC ", Radix::Decimal),
            ("x", Radix::Hexadecimal),
            ("hex", Radix::Hexadecimal),
            ("o", Radix::Octal),
            ("octal", Radix::Octal),
        ] {
            assert_eq!(Radix::parse(name), Some(radix), "{name}");
        }
        assert_eq!(Radix::parse("base64"), None, "and nothing is guessed at");
        assert_eq!(Radix::parse(""), None);
    }

    #[test]
    fn each_radix_names_the_strings_flag_that_produces_it() {
        // So that a record an examiner disputes says how to reproduce the file
        // it was read from.
        assert_eq!(Radix::Decimal.strings_flag(), "-t d");
        assert_eq!(Radix::Hexadecimal.strings_flag(), "-t x");
        assert_eq!(Radix::Octal.strings_flag(), "-t o");
    }

    #[test]
    fn with_no_strings_file_the_stage_says_it_did_not_run_and_claims_nothing() {
        // The most important state of the three. An empty table of offsets
        // from a run that was never given a file is indistinguishable, on
        // screen, from a run that looked and found no owners -- so it is not
        // rendered as one.
        let mapped = StringsMap {
            source: None,
            map: None,
            answers: Vec::new(),
            looked_up: 0,
            mapped: 0,
            mapped_coverage_short: 0,
            no_mapping: 0,
            not_assessed: 0,
            processes_listed: Some(0),
            processes_walked: 0,
            processes_refused: Vec::new(),
            kernel_walked: false,
            shared_subtrees: 0,
            tables_read: 0,
            table_bytes_read: 0,
            prototype_hops: 0,
            prototype_entries: 0,
            prototypes_unresolved: 0,
        };
        assert!(
            !mapped.is_complete(),
            "a stage that did not run is not complete"
        );
        let said = mapped.describe();
        assert!(said.contains("did not run"), "{said}");
        assert!(
            said.contains("not a statement about what is in this image"),
            "{said}"
        );
        let incomplete = mapped.incomplete();
        assert_eq!(incomplete.len(), 1);
        let json = mapped.to_json();
        assert_eq!(json["source"], Value::Null);
        assert_eq!(json["content_complete"], false);
        assert_eq!(json["answers"]["looked_up"], 0);
        assert_eq!(
            json["offsets"].as_array().map(Vec::len),
            Some(0),
            "no rows, and the record says why rather than showing an empty table"
        );
    }

    #[test]
    fn the_record_states_the_radix_it_read_and_how_much_of_the_file_it_rejected() {
        // An examiner disputing a row has to be able to see which radix
        // produced it.
        let source = read("3f0000 a\nbeef b\n12345 c\n", Radix::Decimal);
        let json = source.to_json();
        assert_eq!(json["radix"], "decimal");
        assert_eq!(json["radix_produced_by"], "-t d");
        assert_eq!(json["lines_read"], 3);
        assert_eq!(json["malformed_lines"], 2);
        assert_eq!(json["offsets_parsed"], 1);
    }
}
