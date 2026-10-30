//! Examiner-supplied patterns over the address spaces this build can assemble
//! (`ROADMAP` §5.3 — upstream's `yarascan`, `vadyarascan`, `regexscan` and
//! `vadregexscan`).
//!
//! # What this stage is
//!
//! An examiner's own YARA rules, or a regular expression, run over each
//! process's **own** virtual address space — through the page tables this build
//! recovered from the image, not over the raw file — with every match
//! attributed to the allocation that held it. And over the kernel's space,
//! which has no allocations of that kind and says so rather than leaving the
//! omission to be noticed.
//!
//! It is the one memory stage that asks a question this product did not choose.
//! Every other stage looks for a structure the kernel defines; this one looks
//! for whatever the examiner brought. That makes the honesty requirements
//! sharper rather than looser, because "your rules matched nothing" is the
//! answer most likely to be read as "there is nothing here".
//!
//! # Nothing is searched for unless an examiner named it
//!
//! Séance ships no rules — `seance_plugin_yara`'s own documentation says why —
//! so with no rule set and no pattern named this stage has nothing to look for.
//! It then reports that it **did not run**, with that reason, rather than
//! emitting an empty result: an empty match list from a scan that never had a
//! pattern is indistinguishable, on screen, from an empty match list from a
//! scan that had one.
//!
//! # The allocation is part of the finding
//!
//! A match is reported with the virtual address descriptor whose range it fell
//! in, because "a match somewhere in this process" is not something an examiner
//! can act on. The same bytes in private, executable, unbacked memory and in
//! the read-only section of a mapped system DLL mean entirely different things,
//! and the difference is in the VAD rather than in the bytes.
//!
//! So the scan is planned from the VAD tree and from nothing else. A process
//! whose tree will not walk is reported as **not scanned**, naming the reason,
//! rather than swept as one flat range: a row saying "matched at this address,
//! attribution unavailable" is a row an examiner cannot read, and putting it in
//! front of one as evidence is worse than saying plainly that the process was
//! not examined.
//!
//! A tree that walked *partly* is used as far as it went, and its own
//! incompleteness travels with the result: allocations below a node the walk
//! could not follow were never planned, so they were never searched.
//!
//! # What was mapped, and what was merely reserved
//!
//! Each VAD's range is probed for the memory that actually exists before
//! anything is read, so a 2 GiB reserved region costs a probe rather than
//! 2 GiB of reads that would come back as "not examined". The two quantities
//! are then reported apart: bytes that were **mapped and would not read** are
//! evidence possibly missed, and bytes that were **never mapped** could not
//! have held anything. A record that added them together would bury a 200 KiB
//! hole in a process's heap under two terabytes of reserved address space —
//! this project has already shipped that once.
//!
//! # Every ceiling is stated with the address it fired at
//!
//! A byte ceiling per process, a byte ceiling for the image, a hit ceiling per
//! space and a ceiling on individually recorded rows. Each one that fires names
//! the address from which nothing was examined, or the exact count the rows are
//! a sample of. A scan that stopped at a limit and reads as a scan that
//! finished is the defect this crate is written against.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::scan::{Hit, RefusedChunk};

/// The pattern set, the per-space result and the scanning itself live in
/// `seance_memory::patterns`, beside the scanner they drive: this stage, the
/// kernel-space sweep and the whole-image scan share one definition of the
/// planning, the ceilings and the coverage arithmetic. Re-exported so a caller
/// of this stage need not know which crate owns which half.
pub use seance_memory::patterns::{
    scan_space, scan_whole_layer, trim_to_budget, PatternCaps, PatternSet, SpaceScan,
    MAX_BYTES_PER_SPACE, MAX_HITS_PER_SPACE, MAX_RECORDED_MATCHES, MAX_SECTIONS_PER_SPACE,
    REGEX_SCOPE,
};
use seance_memory::translate::TableCache;
use seance_memory::Incomplete;
use serde_json::{json, Value};

use crate::process::{ProcessInventory, ProcessList, ProcessRecord, ProcessSymbols};
use crate::profile::WindowsProfile;
use crate::vad::{MappedFile, ProtectionTable, Vad, VadSymbols, VadTree, VadWalkConfig};

/// Bytes across the whole image, over every space and every pattern set.
pub const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

/// What went wrong that stops the stage entirely.
#[derive(Debug, Clone)]
pub enum PatternScanError {
    /// This build cannot be asked the question at all.
    Unsupported { detail: String },
}

impl PatternScanError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            Self::Unsupported { .. } => IncompleteReason::UnresolvedStructure,
        }
    }
}

impl std::fmt::Display for PatternScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { detail } => write!(f, "{detail}"),
        }
    }
}

/// Caps and scope for one run of the stage.
#[derive(Debug, Clone)]
pub struct PatternScanConfig {
    /// The ceilings and chunk geometry every pass observes, shared with the
    /// whole-image scan.
    pub caps: PatternCaps,
    /// How each process's VAD tree is walked. Carries the kernel's protection
    /// table, so an allocation's protection can be named.
    pub vad: VadWalkConfig,
    /// Bytes across the whole image, over every space and every pattern set.
    pub max_total_bytes: u64,
    /// Process ids to examine. `None` is every process on the list handed in;
    /// a list is the examiner having scoped the hunt, and the record says which
    /// of the ids were found.
    pub pids: Option<Vec<u64>>,
    /// Whether the kernel's own address space is scanned as well.
    pub include_kernel: bool,
}

impl Default for PatternScanConfig {
    fn default() -> Self {
        Self {
            caps: PatternCaps::default(),
            vad: VadWalkConfig::default(),
            max_total_bytes: MAX_TOTAL_BYTES,
            pids: None,
            include_kernel: true,
        }
    }
}

/// The allocation a match fell in.
#[derive(Debug, Clone)]
pub struct RegionRef {
    pub start: u64,
    pub end: u64,
    pub tag: String,
    /// The protection as an examiner reads it. `None` means the kernel's
    /// protection table could not be read — never "no protection".
    pub protection: Option<String>,
    /// Whether the allocation is private rather than shared. `None` means the
    /// member could not be read.
    pub private_memory: Option<bool>,
    /// The file mapped into the range, or the reason there is not one to name.
    pub mapped_file: MappedFile,
}

impl RegionRef {
    fn of(vad: &Vad) -> Self {
        Self {
            start: vad.start,
            end: vad.end,
            tag: vad.tag.clone(),
            protection: vad.protection_names.clone(),
            private_memory: vad.private_memory,
            mapped_file: vad.file.clone(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "start": self.start,
            "start_hex": format!("{:#x}", self.start),
            "end": self.end,
            "end_hex": format!("{:#x}", self.end),
            "size": self.end.saturating_sub(self.start).saturating_add(1),
            "tag": self.tag,
            "protection": self.protection,
            "private_memory": self.private_memory,
            "mapped_file": self.mapped_file.to_json(),
        })
    }
}

/// Which space a match was found in.
#[derive(Debug, Clone)]
pub enum MatchScope {
    /// The kernel's own address space, which has no virtual address
    /// descriptors: they describe a process's user memory.
    Kernel,
    /// One process's own address space.
    Process {
        process: u64,
        pid: Option<u64>,
        name: Option<String>,
    },
}

impl MatchScope {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Process { .. } => "process",
        }
    }
}

/// One match.
#[derive(Debug, Clone)]
pub struct MatchRow {
    /// The pattern that matched — a YARA rule's identifier, or the regex.
    pub pattern: String,
    /// Which kind of pattern it was.
    pub kind: &'static str,
    /// Address of the match's first byte, in the space named by `scope`.
    pub address: u64,
    /// Bytes the match spans.
    pub length: u32,
    pub scope: MatchScope,
    /// The allocation the address falls in. `None` in the kernel's space, where
    /// there are none of this kind.
    pub region: Option<RegionRef>,
}

impl MatchRow {
    pub fn to_json(&self) -> Value {
        let (process, pid, name) = match &self.scope {
            MatchScope::Kernel => (None, None, None),
            MatchScope::Process { process, pid, name } => {
                (Some(*process), *pid, name.as_ref().cloned())
            }
        };
        json!({
            "pattern": self.pattern,
            "pattern_kind": self.kind,
            "address": self.address,
            // Exact beside the number: JSON numbers are IEEE doubles, and a
            // user-space address above 2^53 can reach a client rounded by a
            // kilobyte -- which names a different page.
            "address_hex": format!("{:#x}", self.address),
            "length": self.length,
            "scope": self.scope.as_str(),
            "process": process.map(|p| format!("{p:#018x}")),
            "pid": pid,
            "process_name": name,
            "region": self.region.as_ref().map(RegionRef::to_json),
            "attribution": match &self.scope {
                MatchScope::Kernel =>
                    "The kernel's own address space. Virtual address descriptors describe a \
                     process's user memory, so there is no allocation of that kind to name here.",
                MatchScope::Process { .. } =>
                    "The allocation whose range this address falls in. The scan was planned from \
                     this process's virtual address descriptors, so every match reported here is \
                     inside one of them.",
            },
        })
    }
}

/// One process's pass.
#[derive(Debug, Clone)]
pub struct ProcessScan {
    pub process: u64,
    pub pid: Option<u64>,
    pub name: Option<String>,
    /// Allocations the tree held.
    pub vads: usize,
    /// Whether the tree was walked end to end with nothing skipped.
    pub vad_tree_complete: bool,
    /// Why the tree is not a total, when it is not.
    pub vad_incomplete: Vec<Incomplete>,
    /// The pass, one per pattern set, in the order the sets were given.
    pub passes: Vec<SpaceScan>,
    /// Why this process was not examined at all.
    pub not_scanned: Option<String>,
    /// Matches found in it — exact, even past the recorded-row ceiling.
    pub matches: u64,
}

impl ProcessScan {
    /// A process nothing could be read for, and why.
    ///
    /// A row rather than an omission: "there is no record for that process"
    /// reads as a process examined and found unremarkable.
    pub fn not_examined(
        process: u64,
        pid: Option<u64>,
        name: Option<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            process,
            pid,
            name,
            vads: 0,
            vad_tree_complete: false,
            vad_incomplete: Vec::new(),
            passes: Vec::new(),
            not_scanned: Some(reason.into()),
            matches: 0,
        }
    }

    fn skipped(entry: &ProcessRecord, reason: String) -> Self {
        Self::not_examined(
            entry.address,
            entry.pid.known().copied(),
            entry.image_file_name.known().cloned(),
            reason,
        )
    }

    /// Whether this process's memory was examined in full.
    pub fn is_complete(&self) -> bool {
        self.not_scanned.is_none()
            && self.vad_tree_complete
            && self.passes.iter().all(SpaceScan::is_complete)
    }

    pub fn bytes_scanned(&self) -> u64 {
        self.passes
            .iter()
            .fold(0u64, |acc, p| acc.saturating_add(p.bytes_scanned))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "process": format!("{:#018x}", self.process),
            "pid": self.pid,
            "name": self.name,
            "vads": self.vads,
            "vad_tree_complete": self.vad_tree_complete,
            "vad_incomplete": self.vad_incomplete.iter().map(Incomplete::to_json)
                .collect::<Vec<_>>(),
            "passes": self.passes.iter().map(SpaceScan::to_json).collect::<Vec<_>>(),
            "bytes_scanned": self.bytes_scanned(),
            "matches": self.matches,
            "not_scanned": self.not_scanned,
            "complete": self.is_complete(),
        })
    }
}

/// What the stage needs from this build's symbols.
#[derive(Debug, Clone)]
pub struct PatternScanSymbols {
    pub vad: VadSymbols,
    pub process: ProcessSymbols,
    /// The kernel's protection table, when it could be read. `None` renders
    /// every allocation's protection as unknown rather than as none.
    pub protections: Option<Arc<ProtectionTable>>,
}

impl PatternScanSymbols {
    /// Resolve from a profile, failing closed when the image cannot support the
    /// stage at all.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, PatternScanError> {
        let vad = VadSymbols::from_profile(profile)
            .map_err(|e| PatternScanError::unsupported(e.to_string()))?;
        let process = ProcessSymbols::from_profile(profile)
            .map_err(|e| PatternScanError::unsupported(e.to_string()))?;
        // Absent is not fatal: an allocation whose protection cannot be named
        // is still an allocation, and refusing the whole hunt over the
        // rendering of one field would be the wrong trade.
        let protections = ProtectionTable::from_profile(profile).ok().map(Arc::new);
        Ok(Self {
            vad,
            process,
            protections,
        })
    }
}

/// Everything the stage found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct PatternScanSurvey {
    /// What was looked for.
    pub sets: Vec<PatternSet>,
    /// Per-process passes, including the processes nothing could be read for.
    pub processes: Vec<ProcessScan>,
    /// The kernel space's passes, one per set.
    pub kernel: Vec<SpaceScan>,
    /// Why the kernel space was not scanned, when it was not.
    pub kernel_not_scanned: Option<String>,
    /// Matches as rows, up to [`PatternScanConfig::max_recorded_matches`].
    pub matches: Vec<MatchRow>,
    /// Matches in total — exact even when the rows above were capped.
    pub matches_total: u64,
    /// Matches per pattern, exact past the row cap.
    pub matches_by_pattern: BTreeMap<String, u64>,
    /// Whether the row cap fired.
    pub rows_capped: bool,
    /// Whether the image-wide byte ceiling stopped the scan.
    pub budget_exhausted: bool,
    /// Bytes examined across every space and every set.
    pub bytes_scanned: u64,
    /// Process ids the examiner named that the list did not hold.
    pub pids_not_found: Vec<u64>,
    /// Chunks an engine refused, by pattern set.
    pub refused_chunks: Vec<(String, RefusedChunk)>,
    /// Patterns that matched with no address to report, by pattern set.
    pub matched_without_address: Vec<(String, String)>,
    /// The process list this survey was handed, or `None` when there was no
    /// list to hand it: the kernel's own space is still searched, and no
    /// process's is.
    pub inventory: Option<ProcessInventory>,
}

impl PatternScanSurvey {
    /// A survey that has found nothing yet.
    pub fn new(sets: Vec<PatternSet>, inventory: Option<ProcessInventory>) -> Self {
        Self {
            sets,
            processes: Vec::new(),
            kernel: Vec::new(),
            kernel_not_scanned: None,
            matches: Vec::new(),
            matches_total: 0,
            matches_by_pattern: BTreeMap::new(),
            rows_capped: false,
            budget_exhausted: false,
            bytes_scanned: 0,
            pids_not_found: Vec::new(),
            refused_chunks: Vec::new(),
            matched_without_address: Vec::new(),
            inventory,
        }
    }

    /// Whether every byte this stage planned to examine was examined.
    pub fn is_complete(&self) -> bool {
        !self.sets.is_empty()
            && !self.rows_capped
            && !self.budget_exhausted
            && self.pids_not_found.is_empty()
            && self.refused_chunks.is_empty()
            && self.kernel_not_scanned.is_none()
            && self.kernel.iter().all(SpaceScan::is_complete)
            && self.processes.iter().all(ProcessScan::is_complete)
            && self
                .inventory
                .as_ref()
                .is_some_and(ProcessInventory::is_complete)
    }

    /// Processes whose memory was examined.
    pub fn processes_scanned(&self) -> usize {
        self.processes
            .iter()
            .filter(|p| p.not_scanned.is_none())
            .count()
    }

    /// Processes that could not be examined at all.
    pub fn processes_not_scanned(&self) -> usize {
        self.processes.len() - self.processes_scanned()
    }

    /// What this stage did, in one paragraph an examiner can read.
    pub fn describe(&self) -> String {
        if self.sets.is_empty() {
            return "No YARA rule set and no pattern was named for this run, so nothing was \
                    searched for in memory. That is not a statement about what is in this \
                    image."
                .to_string();
        }
        let mut out = format!(
            "{} match(es) for {} pattern(s) across {} of {} process(es){}. {} byte(s) of mapped \
             memory were examined.",
            self.matches_total,
            self.sets
                .iter()
                .map(|s| s.pattern_names.len())
                .sum::<usize>(),
            self.processes_scanned(),
            self.processes.len(),
            if self.kernel.is_empty() {
                ""
            } else {
                ", and the kernel's own address space"
            },
            self.bytes_scanned,
        );
        if self.matches_total == 0 {
            out.push_str(
                " No match is not the same as nothing to find: it is this pattern set, over the \
                 memory this capture holds and this build could read.",
            );
        }
        match &self.inventory {
            None => out.push_str(
                " The active process list could not be walked, so no process's own address space \
                 was searched at all.",
            ),
            Some(inventory) if !inventory.is_complete() => out.push_str(
                " The process list this scan was handed did not walk end to end, so the \
                 processes searched are a floor rather than every process on the machine.",
            ),
            Some(_) => {}
        }
        if self.processes_not_scanned() > 0 {
            out.push_str(&format!(
                " {} process(es) were not examined at all; each says why.",
                self.processes_not_scanned()
            ));
        }
        out
    }

    /// Everything a report must declare about this scan.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.sets.is_empty() {
            out.push(Incomplete::new(
                IncompleteReason::Unvalidated,
                "no YARA rule set and no pattern was named, so nothing was searched for."
                    .to_string(),
            ));
            return out;
        }
        match &self.inventory {
            None => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the active process list could not be walked, so no process's own address space \
                 was searched. Only the kernel's own space was, and nothing here is a statement \
                 about the memory of any process."
                    .to_string(),
            )),
            // A list that exists and fell short is the case this stage most
            // needs to declare: every process it was handed may have been
            // searched in full, and the process doing the hiding may never have
            // been on the list at all. Its own reasons travel with it rather
            // than being summarised away.
            Some(inventory) if !inventory.is_complete() => {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the process list this scan was handed held {} process(es) and did not \
                         walk end to end, so the processes searched here are a floor. A process \
                         the list never reached was not searched, and nothing here is a \
                         statement about its memory.",
                        inventory.listed
                    ),
                ));
                out.extend(inventory.incomplete.iter().cloned());
            }
            Some(_) => {}
        }
        if self.rows_capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} match(es) were found and {} are listed individually; the totals are \
                     exact and the rows are a sample.",
                    self.matches_total,
                    self.matches.len()
                ),
            ));
        }
        if self.budget_exhausted {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the scan reached its image-wide ceiling of {} byte(s), so the spaces below \
                     were searched and those above it were not.",
                    self.bytes_scanned
                ),
            ));
        }
        for pid in &self.pids_not_found {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "process {pid} was named for this scan and the process list does not hold \
                     it, so its memory was never searched."
                ),
            ));
        }
        for (set, chunk) in &self.refused_chunks {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the engine for {set} refused {} byte(s) at {:#x}: {}. Those bytes were \
                     read and not searched.",
                    chunk.bytes, chunk.address, chunk.detail
                ),
            ));
        }
        if let Some(reason) = &self.kernel_not_scanned {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the kernel's own address space was not searched: {reason}"),
            ));
        }
        for (index, pass) in self.kernel.iter().enumerate() {
            if let Some(capped) = &pass.capped {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!("the kernel-space pass for pattern set {index}: {capped}"),
                ));
            }
            if pass.unreadable_bytes > 0 {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "{} byte(s) of mapped kernel memory would not read, so they were not \
                         searched.",
                        pass.unreadable_bytes
                    ),
                ));
            }
        }
        let unscanned = self.processes_not_scanned();
        if unscanned > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{unscanned} process(es) could not be examined, so nothing here is a \
                     statement about their memory."
                ),
            ));
        }
        let short: Vec<&ProcessScan> = self
            .processes
            .iter()
            .filter(|p| p.not_scanned.is_none() && !p.is_complete())
            .collect();
        if !short.is_empty() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} process(es) were examined in part: an allocation tree that stopped, a \
                     ceiling that fired, or memory that would not read. Each row says which.",
                    short.len()
                ),
            ));
        }
        out
    }

    pub fn to_json(&self) -> Value {
        json!({
            "patterns": self.sets.iter().map(PatternSet::to_json).collect::<Vec<_>>(),
            "pattern_sets": self.sets.len(),
            "scope_notes": self.sets.iter().filter_map(|s| s.scope_note.clone())
                .collect::<Vec<_>>(),
            "matches": self.matches.iter().map(MatchRow::to_json).collect::<Vec<_>>(),
            "matches_total": self.matches_total,
            "matches_recorded": self.matches.len(),
            "matches_by_pattern": self.matches_by_pattern.iter()
                .map(|(k, v)| (k.clone(), json!(v))).collect::<serde_json::Map<_, _>>(),
            "rows_capped": self.rows_capped,
            "processes": self.processes.iter().map(ProcessScan::to_json).collect::<Vec<_>>(),
            "processes_walked": self.processes.len(),
            "processes_scanned": self.processes_scanned(),
            "processes_not_scanned": self.processes_not_scanned(),
            "kernel": self.kernel.iter().map(SpaceScan::to_json).collect::<Vec<_>>(),
            "kernel_not_scanned": self.kernel_not_scanned,
            "bytes_scanned": self.bytes_scanned,
            "budget_exhausted": self.budget_exhausted,
            "pids_not_found": self.pids_not_found,
            "refused_chunks": self.refused_chunks.iter().map(|(set, chunk)| json!({
                "pattern_set": set,
                "address": chunk.address,
                "address_hex": format!("{:#x}", chunk.address),
                "bytes": chunk.bytes,
                "detail": chunk.detail,
            })).collect::<Vec<_>>(),
            "matched_without_address": self.matched_without_address.iter()
                .map(|(set, pattern)| json!({
                    "pattern_set": set,
                    "pattern": pattern,
                    "why": "The pattern matched with none of its own strings found, so there is \
                            no address to report for it. A YARA rule whose condition is true \
                            without a string match -- one resting on `filesize`, say, which \
                            means nothing over a chunk of an address space -- has this shape.",
                })).collect::<Vec<_>>(),
            "process_inventory": self.inventory.as_ref().map(ProcessInventory::to_json),
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Run every pattern set over every process's own address space, and over the
/// kernel's.
///
/// One unexaminable process never costs the others: it becomes a row saying so.
///
/// # Errors
///
/// [`PatternScanError::Unsupported`] only through
/// [`PatternScanSymbols::from_profile`] — a build whose VAD or process layout
/// this build cannot describe. Everything else is a row.
pub fn scan_patterns(
    profile: &WindowsProfile,
    symbols: &PatternScanSymbols,
    list: Option<&ProcessList>,
    sets: &[PatternSet],
    config: &PatternScanConfig,
) -> PatternScanSurvey {
    let mut survey = PatternScanSurvey::new(sets.to_vec(), list.map(|list| list.inventory()));
    if sets.is_empty() {
        // Nothing was named, so nothing is searched for and nothing is claimed.
        // The record's own statement says so; see `describe`.
        return survey;
    }

    // The protection table travels on the walk config, so that an allocation's
    // protection can be named on the row a match sits in.
    let mut vad_config = config.vad.clone();
    if vad_config.protections.is_none() {
        vad_config.protections = symbols.protections.clone();
    }

    let cache = Arc::new(TableCache::new());
    let mut budget = config.max_total_bytes;

    // Which processes, and which of the named ids the list actually holds.
    let listed: &[ProcessRecord] = list.map(|list| list.processes.as_slice()).unwrap_or(&[]);
    let selected: Vec<&ProcessRecord> = match &config.pids {
        None => listed.iter().collect(),
        Some(pids) => {
            let mut found = Vec::new();
            for entry in listed {
                if entry.pid.known().is_some_and(|pid| pids.contains(pid)) {
                    found.push(entry);
                }
            }
            for pid in pids {
                if !found.iter().any(|entry| entry.pid.known() == Some(&(*pid))) {
                    survey.pids_not_found.push(*pid);
                }
            }
            found
        }
    };

    for entry in selected {
        if budget == 0 {
            survey.budget_exhausted = true;
            survey.processes.push(ProcessScan::skipped(
                entry,
                "the scan's image-wide byte ceiling had already fired when this process was \
                 reached, so its memory was not searched"
                    .to_string(),
            ));
            continue;
        }

        let tree = match crate::vad::list_vads(profile, &symbols.vad, entry.address, &vad_config) {
            Ok(tree) => tree,
            Err(err) => {
                survey.processes.push(ProcessScan::skipped(
                    entry,
                    format!(
                        "this process's allocation tree would not walk, so there were no \
                         allocations to search and no allocation to attribute a match to: {err}"
                    ),
                ));
                continue;
            }
        };
        let layer = match crate::process::process_address_space(
            profile,
            &symbols.process,
            entry.address,
            &cache,
        ) {
            Ok(layer) => layer,
            Err(err) => {
                survey.processes.push(ProcessScan::skipped(
                    entry,
                    format!(
                        "this process has no readable address space, so its memory could not be \
                         searched: {err}"
                    ),
                ));
                continue;
            }
        };

        let ranges: Vec<Range<u64>> = tree
            .vads
            .iter()
            .filter_map(|vad| vad.end.checked_add(1).map(|end| vad.start..end))
            .collect();

        let mut scan = ProcessScan {
            process: entry.address,
            pid: entry.pid.known().copied(),
            name: entry.image_file_name.known().cloned(),
            vads: tree.vads.len(),
            vad_tree_complete: tree.is_complete(),
            vad_incomplete: tree.incomplete(),
            passes: Vec::new(),
            not_scanned: None,
            matches: 0,
        };

        for set in sets {
            let per_process = config.caps.max_bytes_per_space.min(budget);
            let pass = scan_space(layer.as_ref(), &ranges, set, per_process, &config.caps);
            budget = budget.saturating_sub(pass.bytes_scanned);
            survey.bytes_scanned = survey.bytes_scanned.saturating_add(pass.bytes_scanned);
            scan.matches = scan.matches.saturating_add(pass.hits.len() as u64);
            record_hits(
                &mut survey,
                set,
                &pass.hits,
                &MatchScope::Process {
                    process: entry.address,
                    pid: scan.pid,
                    name: scan.name.clone(),
                },
                Some(&tree),
                config,
            );
            scan.passes.push(pass);
        }
        survey.processes.push(scan);
    }

    if config.include_kernel {
        scan_kernel_space(profile, sets, config, &mut survey, &mut budget);
    }

    // The engines' own account of what they could not do, asked for once the
    // scanning is over. It cannot come through the hit list: see
    // `ScannerDiagnostics`.
    for set in sets {
        if let Some(diagnostics) = &set.diagnostics {
            for chunk in diagnostics.take_refused_chunks() {
                survey.refused_chunks.push((set.source.clone(), chunk));
            }
            for pattern in diagnostics.take_matched_without_address() {
                survey
                    .matched_without_address
                    .push((set.source.clone(), pattern));
            }
        }
    }

    survey
}

/// The kernel's own space, which is upstream's `yarascan` rather than its
/// `vadyarascan`.
fn scan_kernel_space(
    profile: &WindowsProfile,
    sets: &[PatternSet],
    config: &PatternScanConfig,
    survey: &mut PatternScanSurvey,
    budget: &mut u64,
) {
    let layer = Arc::clone(&profile.kernel_space);

    for set in sets {
        if *budget == 0 {
            survey.budget_exhausted = true;
            survey.kernel_not_scanned = Some(
                "the scan's image-wide byte ceiling had already fired when the kernel's space \
                 was reached, so it was not searched"
                    .to_string(),
            );
            return;
        }
        match scan_whole_layer(layer.as_ref(), set, *budget, &config.caps) {
            Ok(pass) => {
                *budget = budget.saturating_sub(pass.bytes_scanned);
                survey.bytes_scanned = survey.bytes_scanned.saturating_add(pass.bytes_scanned);
                record_hits(survey, set, &pass.hits, &MatchScope::Kernel, None, config);
                survey.kernel.push(pass);
            }
            // The space itself will not enumerate. Stated, not rendered as a
            // space that was searched and held nothing.
            Err(err) => {
                survey.kernel_not_scanned = Some(format!(
                    "the kernel's own address space could not be enumerated, so it was not \
                     searched: {err}"
                ));
                return;
            }
        }
    }
}

/// Turn one pass's hits into rows and counts.
///
/// The counts are taken from every hit; the rows stop at the ceiling. A record
/// whose rows and whose totals came from the same capped list would report the
/// ceiling as the number of matches.
pub(crate) fn record_hits(
    survey: &mut PatternScanSurvey,
    set: &PatternSet,
    hits: &[Hit],
    scope: &MatchScope,
    tree: Option<&VadTree>,
    config: &PatternScanConfig,
) {
    for hit in hits {
        let pattern = set.pattern_name(hit.pattern_id);
        survey.matches_total = survey.matches_total.saturating_add(1);
        *survey
            .matches_by_pattern
            .entry(pattern.clone())
            .or_insert(0) += 1;

        if survey.matches.len() >= config.caps.max_recorded_matches {
            survey.rows_capped = true;
            continue;
        }
        survey.matches.push(MatchRow {
            pattern,
            kind: set.kind,
            address: hit.address,
            length: hit.length,
            scope: scope.clone(),
            region: tree
                .and_then(|tree| tree.containing(hit.address))
                .map(RegionRef::of),
        });
    }
}
