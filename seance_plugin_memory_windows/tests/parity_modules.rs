//! Parity for loaded DLLs and drivers, against Volatility 3 on real captures.
//!
//! Three stages are compared here, and they are not three variations of the
//! same claim:
//!
//! * **`dlllist`** — what each process had mapped, from the loader's own
//!   load-order chain. The failure this catches is the one that looks like
//!   success: a list of the right *length* whose bases are wrong. A count alone
//!   would pass it, so the comparison is over the **set of `(pid, base)`
//!   pairs**, and the module names are compared on top of that.
//! * **`ldrmodules`** — the most valuable of the three, because it is itself a
//!   cross-check. Every mapped image carries three booleans, one per PEB list,
//!   and the three lists thread through three *different* `_LIST_ENTRY` members
//!   of `_LDR_DATA_TABLE_ENTRY`. Walking one member three times produces a table
//!   in which every module is in every list — perfectly plausible, entirely
//!   useless, and it silently destroys the only finding the stage exists for.
//!   So the booleans are compared per `(pid, base)` against Volatility's
//!   `InLoad`/`InInit`/`InMem`, the 89 rows where the answers legitimately
//!   *differ* between lists are asserted as a set of their own, and the symbol
//!   layout is asserted to resolve three distinct member offsets.
//! * **`modules`** — the kernel's own list, compared as a set of driver base
//!   addresses and loader-entry offsets.
//!
//! Every expectation is read out of the Volatility 3.2.28.2 CSVs on disk. None
//! of it is hand-derived and none of it comes from Séance. Where Séance
//! deliberately answers differently — it says *unknown* where Volatility prints
//! `False` having read no list at all — the divergence is asserted explicitly
//! rather than tolerated by loosening a comparison.
//!
//! The images are large and not committed, so these tests skip when they are
//! absent. See `tests/common/mod.rs` for the environment they need.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use seance_memory::translate::TableCache;
use seance_plugin_memory_windows::modules::{
    self, ModuleSymbols, ModuleWalkConfig, NameField, ProcessSpace, TYPE_LDR_DATA_TABLE_ENTRY,
};
use seance_plugin_memory_windows::process::{self, ProcessListConfig, ProcessSymbols};
use seance_plugin_memory_windows::vad::{self, MappedFile, VadSymbols, VadWalkConfig};
use seance_plugin_memory_windows::WindowsProfile;

/// Oracle directory for the Windows XP SP2 capture.
const XP_ORACLE: &str = "oracle";

/// Oracle directory for the Windows 11 22000 capture.
const WIN11_ORACLE: &str = "oracle_win11";

/// How many differing items a failure message lists before it stops.
///
/// Enough to see the shape of a disagreement; not so many that the real message
/// scrolls off the top of a terminal.
const REPORTED: usize = 20;

// ── Oracle columns ──────────────────────────────────────────────────────────
//
// Read from the CSV headers rather than assumed:
//   windows.dlllist     TreeDepth,PID,Process,Base,Size,Name,Path,LoadCount,LoadTime,File output
//   windows.ldrmodules  TreeDepth,Pid,Process,Base,InLoad,InInit,InMem,MappedPath
//   windows.modules     TreeDepth,Offset,Base,Size,Name,Path,File output

/// `PID` in `windows.dlllist`.
const DLL_PID: usize = 1;
/// `Base` in `windows.dlllist`.
const DLL_BASE: usize = 3;
/// `Name` in `windows.dlllist` — the entry's `BaseDllName`.
const DLL_NAME: usize = 5;

/// `Pid` in `windows.ldrmodules`.
const LDR_PID: usize = 1;
/// `Base` in `windows.ldrmodules`.
const LDR_BASE: usize = 3;
/// `InLoad` in `windows.ldrmodules`.
const LDR_IN_LOAD: usize = 4;
/// `InInit` in `windows.ldrmodules`.
const LDR_IN_INIT: usize = 5;
/// `InMem` in `windows.ldrmodules`.
const LDR_IN_MEM: usize = 6;
/// `MappedPath` in `windows.ldrmodules`.
const LDR_MAPPED_PATH: usize = 7;

/// `Offset` in `windows.modules` — the loader entry's own address.
const MOD_OFFSET: usize = 1;
/// `Base` in `windows.modules`.
const MOD_BASE: usize = 2;
/// `Name` in `windows.modules`.
const MOD_NAME: usize = 4;

// `windows.vadinfo` TreeDepth,PID,Process,Offset,Start VPN,End VPN,Tag,
//                   Protection,CommitCharge,PrivateMemory,Parent,File,File output

/// `PID` in `windows.vadinfo`.
const VAD_PID: usize = 1;
/// `Start VPN` in `windows.vadinfo` — the range's first address.
const VAD_START: usize = 4;
/// `PrivateMemory` in `windows.vadinfo`. Zero means the range is shared, which
/// is what a mapped image is.
const VAD_PRIVATE: usize = 9;
/// `File` in `windows.vadinfo` — the file the range maps, when it maps one.
const VAD_FILE: usize = 11;

// ── Reading the oracle ──────────────────────────────────────────────────────

/// The oracle CSV a test compares against, or a panic naming the file.
///
/// A missing CSV is not a reason to skip: the image was present, so the oracle
/// should be too, and quietly passing a test that compared nothing is the one
/// outcome worse than failing.
fn require_oracle(dir: &str, plugin: &str) -> Vec<Vec<String>> {
    common::oracle(dir, plugin).unwrap_or_else(|| {
        panic!("{dir}/{plugin}.csv is the oracle this test compares against and it is not on disk")
    })
}

/// One field of an oracle row, or a panic naming the row.
fn field<'a>(row: &'a [String], index: usize, what: &str) -> &'a str {
    row.get(index).map(String::as_str).unwrap_or_else(|| {
        panic!("the oracle row {row:?} has no column {index}, so its {what} cannot be read")
    })
}

/// A `0x`-prefixed hexadecimal field.
fn hex_field(row: &[String], index: usize, what: &str) -> u64 {
    let raw = field(row, index, what);
    let digits = raw.strip_prefix("0x").unwrap_or_else(|| {
        panic!("the oracle prints {what} as '{raw}', which is not a hexadecimal address")
    });
    u64::from_str_radix(digits, 16)
        .unwrap_or_else(|err| panic!("the oracle's {what} '{raw}' is not readable: {err}"))
}

/// A decimal field.
fn int_field(row: &[String], index: usize, what: &str) -> u64 {
    let raw = field(row, index, what);
    raw.parse()
        .unwrap_or_else(|err| panic!("the oracle's {what} '{raw}' is not a number: {err}"))
}

/// A `True`/`False` field. Anything else is a column read at the wrong index.
fn bool_field(row: &[String], index: usize, what: &str) -> bool {
    match field(row, index, what) {
        "True" => true,
        "False" => false,
        other => panic!("the oracle prints {what} as '{other}', which is not a boolean"),
    }
}

/// A text field, with the CSV writer's doubled backslashes undone.
///
/// Volatility renders `\Windows\System32\ntdll.dll` as `\\Windows\\System32\\…`
/// in its CSV. Comparing that against a path read out of memory would fail on
/// every single row for a reason that has nothing to do with forensics.
fn path_field(row: &[String], index: usize, what: &str) -> String {
    field(row, index, what).replace("\\\\", "\\")
}

// ── Séance's side ───────────────────────────────────────────────────────────

/// Everything a walk of one reference image needs, resolved once.
struct Corpus {
    profile: WindowsProfile,
    processes: ProcessSymbols,
    modules: ModuleSymbols,
    cache: Arc<TableCache>,
}

impl Corpus {
    /// Discover a reference image, or `None` when it is not present.
    ///
    /// A build whose loader entries the symbols cannot describe is a panic and
    /// not a skip: the symbols were found, so failing to describe them is a
    /// defect in Séance rather than a missing corpus.
    fn open(image: &str) -> Option<Self> {
        let profile = common::profile(image)?;
        let processes = ProcessSymbols::from_profile(&profile)
            .unwrap_or_else(|err| panic!("{image}: the process layout is not describable: {err}"));
        let modules = ModuleSymbols::from_profile(&profile)
            .unwrap_or_else(|err| panic!("{image}: the loader layout is not describable: {err}"));
        Some(Self {
            profile,
            processes,
            modules,
            cache: Arc::new(TableCache::new()),
        })
    }

    /// A walk configuration sharing one page-table memo across every process.
    fn config(&self) -> ModuleWalkConfig {
        ModuleWalkConfig {
            page_table_cache: Some(Arc::clone(&self.cache)),
            ..ModuleWalkConfig::default()
        }
    }

    /// The processes worth comparing, as `(pid, _EPROCESS address)`, and a note
    /// for every row the list walk would not vouch for.
    ///
    /// The Windows 11 capture's `ActiveProcessLinks` chain is smeared and runs
    /// off into data that is not a `_LIST_ENTRY`. Séance annotates what it finds
    /// past the end; those rows are not processes and have no DLLs, so they are
    /// not carried into a comparison of loaded modules. Skipping them silently
    /// would turn a wrongly-annotated *real* process into a set of rows missing
    /// for no visible reason, so each one is recorded and travels into any
    /// failure message.
    fn believable(&self) -> (Vec<(u64, u64)>, Vec<String>) {
        let list = process::list_processes(
            &self.profile,
            &self.processes,
            &ProcessListConfig::default(),
        )
        .expect("the active process list is walkable");

        let mut kept = Vec::new();
        let mut skipped = Vec::new();
        for record in &list.processes {
            match (record.notes.is_empty(), record.pid.known()) {
                (true, Some(pid)) => kept.push((*pid, record.address)),
                (_, pid) => skipped.push(format!(
                    "the row at {:#x} (pid {pid:?}) is annotated rather than vouched for, so its \
                     modules were not walked: {:?}",
                    record.address, record.notes
                )),
            }
        }
        (kept, skipped)
    }
}

/// One row of Séance's `dlllist`, reduced to what parity compares.
struct OurDll {
    pid: u64,
    base: u64,
    /// `BaseDllName` in full, not flattened to `Option<String>`.
    ///
    /// The three outcomes are not interchangeable here. Where a loader entry
    /// sits in reallocated pool the comparison against Volatility is waived,
    /// and the only assertion left is about *how* Séance declined the name —
    /// "there was no string" and "the string is not a name" support different
    /// conclusions, and flattening them to `None` would let the first pass as
    /// the second in the one branch where nothing else is being checked.
    name: NameField,
}

/// One row of Séance's `ldrmodules`, reduced to what parity compares.
struct OurLdr {
    pid: u64,
    base: u64,
    in_load: Option<bool>,
    in_init: Option<bool>,
    in_mem: Option<bool>,
    mapped_file: MappedFile,
    /// How many gaps Séance declared for the process this row came from. A row
    /// carrying an unknown answer must have at least one.
    declarations: usize,
}

/// One row of Séance's kernel `modules`.
struct OurDriver {
    entry: u64,
    base: u64,
    name: Option<String>,
}

/// A walk of one image, with everything it declined to do.
///
/// The refusals are carried into failure messages rather than dropped: a
/// missing row and a process Séance could not open are the same finding seen
/// from two ends, and an examiner reading a failure needs both.
struct Survey<T> {
    rows: Vec<T>,
    refusals: Vec<String>,
}

impl<T> Survey<T> {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            refusals: Vec::new(),
        }
    }
}

/// Walk every believable process's load-order module list.
fn survey_dlls(image: &str) -> Option<Survey<OurDll>> {
    let corpus = Corpus::open(image)?;
    let config = corpus.config();
    let (believable, skipped) = corpus.believable();
    let mut survey = Survey::new();
    survey.refusals.extend(skipped);

    for (pid, address) in believable {
        let space = match ProcessSpace::build(&corpus.profile, &corpus.modules, address, &config) {
            Ok(space) => space,
            Err(err) => {
                survey.refusals.push(format!(
                    "pid {pid} at {address:#x} has no readable address space: {err}"
                ));
                continue;
            }
        };
        let list =
            match modules::list_dlls(&corpus.profile, &corpus.modules, address, &space, &config) {
                Ok(list) => list,
                Err(err) => {
                    survey.refusals.push(format!(
                        "pid {pid} at {address:#x}: the DLL walk refused: {err}"
                    ));
                    continue;
                }
            };
        for module in &list.modules {
            let Some(base) = module.base else {
                survey.refusals.push(format!(
                    "pid {pid}: the loader entry at {:#x} has no readable DllBase",
                    module.entry
                ));
                continue;
            };
            survey.rows.push(OurDll {
                pid,
                base: common::truncate_to_48(base),
                name: module.base_name.clone(),
            });
        }
    }
    Some(survey)
}

/// Cross-reference every believable process's mapped images against its three
/// loader lists.
fn survey_ldr(image: &str) -> Option<Survey<OurLdr>> {
    let corpus = Corpus::open(image)?;
    let vad_symbols = VadSymbols::from_profile(&corpus.profile)
        .unwrap_or_else(|err| panic!("{image}: the VAD layout is not describable: {err}"));
    let config = corpus.config();
    let vad_config = VadWalkConfig::default();
    let (believable, skipped) = corpus.believable();
    let mut survey = Survey::new();
    survey.refusals.extend(skipped);

    for (pid, address) in believable {
        let tree = match vad::list_vads(&corpus.profile, &vad_symbols, address, &vad_config) {
            Ok(tree) => tree,
            Err(err) => {
                survey.refusals.push(format!(
                    "pid {pid} at {address:#x}: the VAD walk refused: {err}"
                ));
                continue;
            }
        };
        let space = match ProcessSpace::build(&corpus.profile, &corpus.modules, address, &config) {
            Ok(space) => space,
            Err(err) => {
                survey.refusals.push(format!(
                    "pid {pid} at {address:#x} has no readable address space: {err}"
                ));
                continue;
            }
        };
        let cross = match modules::ldr_modules(
            &corpus.profile,
            &corpus.modules,
            address,
            &space,
            &tree,
            &config,
        ) {
            Ok(cross) => cross,
            Err(err) => {
                survey.refusals.push(format!(
                    "pid {pid} at {address:#x}: the cross-reference refused: {err}"
                ));
                continue;
            }
        };
        let declarations = cross.incomplete().len();
        for module in &cross.modules {
            survey.rows.push(OurLdr {
                pid,
                base: common::truncate_to_48(module.base),
                in_load: module.in_load,
                in_init: module.in_init,
                in_mem: module.in_mem,
                mapped_file: module.mapped_file.clone(),
                declarations,
            });
        }
    }
    Some(survey)
}

/// Walk the kernel's own loaded-module list.
fn survey_drivers(image: &str) -> Option<Survey<OurDriver>> {
    let corpus = Corpus::open(image)?;
    let list = modules::list_kernel_modules(&corpus.profile, &corpus.modules, &corpus.config())
        .unwrap_or_else(|err| panic!("{image}: the kernel module list refused: {err}"));

    let mut survey = Survey::new();
    assert!(
        list.is_complete(),
        "{image}: the kernel module walk stopped early ({}), so any set of drivers it produced is \
         a floor rather than an answer",
        list.stop.as_str()
    );
    for module in &list.modules {
        let Some(base) = module.base else {
            survey.refusals.push(format!(
                "the driver entry at {:#x} has no readable DllBase",
                module.entry
            ));
            continue;
        };
        survey.rows.push(OurDriver {
            entry: common::truncate_to_48(module.entry),
            base: common::truncate_to_48(base),
            name: module.base_name.name().map(str::to_string),
        });
    }
    Some(survey)
}

// ── Memoised surveys ────────────────────────────────────────────────────────
//
// Each survey re-runs discovery and every walk, which on the Windows 11 capture
// means 102 VAD trees and 17,405 mapped ranges. Integration tests share one
// process, so the work is done once and the named tests below read it.

/// Séance's `dlllist` for the XP capture.
fn xp_dlls() -> Option<&'static Survey<OurDll>> {
    static CELL: OnceLock<Option<Survey<OurDll>>> = OnceLock::new();
    CELL.get_or_init(|| survey_dlls(common::XP)).as_ref()
}

/// Séance's `dlllist` for the Windows 11 capture.
fn win11_dlls() -> Option<&'static Survey<OurDll>> {
    static CELL: OnceLock<Option<Survey<OurDll>>> = OnceLock::new();
    CELL.get_or_init(|| survey_dlls(common::WIN11)).as_ref()
}

/// Séance's `ldrmodules` for the Windows 11 capture.
fn win11_ldr() -> Option<&'static Survey<OurLdr>> {
    static CELL: OnceLock<Option<Survey<OurLdr>>> = OnceLock::new();
    CELL.get_or_init(|| survey_ldr(common::WIN11)).as_ref()
}

/// Séance's kernel `modules` for the XP capture.
fn xp_drivers() -> Option<&'static Survey<OurDriver>> {
    static CELL: OnceLock<Option<Survey<OurDriver>>> = OnceLock::new();
    CELL.get_or_init(|| survey_drivers(common::XP)).as_ref()
}

/// Séance's kernel `modules` for the Windows 11 capture.
fn win11_drivers() -> Option<&'static Survey<OurDriver>> {
    static CELL: OnceLock<Option<Survey<OurDriver>>> = OnceLock::new();
    CELL.get_or_init(|| survey_drivers(common::WIN11)).as_ref()
}

// ── Comparison ──────────────────────────────────────────────────────────────

/// The first [`REPORTED`] of a list, for a failure message.
fn head(items: &[String]) -> &[String] {
    &items[..items.len().min(REPORTED)]
}

/// Assert two keyed sets are the same, saying **which** items differ.
///
/// A bare count mismatch tells an examiner nothing: "1667 against 1668" does not
/// say whether a DLL is missing, an extra one was invented, or both happened at
/// once and cancelled out. Every failure here names the items on both sides.
fn assert_same_set<K: Ord>(
    what: &str,
    ours: &BTreeMap<K, String>,
    theirs: &BTreeMap<K, String>,
    render: impl Fn(&K, &str) -> String,
    refusals: &[String],
) {
    let missing: Vec<String> = theirs
        .iter()
        .filter(|(key, _)| !ours.contains_key(*key))
        .map(|(key, name)| render(key, name.as_str()))
        .collect();
    let extra: Vec<String> = ours
        .iter()
        .filter(|(key, _)| !theirs.contains_key(*key))
        .map(|(key, name)| render(key, name.as_str()))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{what}: Séance and Volatility name different items.\n  \
         ours = {} item(s), Volatility = {} item(s)\n  \
         {} in Volatility's answer and missing from ours: {:?}\n  \
         {} in ours and not in Volatility's: {:?}\n  \
         walks Séance refused, which may account for a gap: {:?}",
        ours.len(),
        theirs.len(),
        missing.len(),
        head(&missing),
        extra.len(),
        head(&extra),
        head(refusals),
    );
}

/// Volatility's `dlllist` as `(pid, base) -> BaseDllName`.
fn oracle_dlls(dir: &str) -> BTreeMap<(u64, u64), String> {
    require_oracle(dir, "windows.dlllist")
        .iter()
        .map(|row| {
            (
                (
                    int_field(row, DLL_PID, "a process id"),
                    hex_field(row, DLL_BASE, "a module base"),
                ),
                field(row, DLL_NAME, "a module name").to_string(),
            )
        })
        .collect()
}

/// Volatility's `ldrmodules` as `(pid, base) -> (InLoad, InInit, InMem, path)`.
fn oracle_ldr(dir: &str) -> BTreeMap<(u64, u64), (bool, bool, bool, String)> {
    require_oracle(dir, "windows.ldrmodules")
        .iter()
        .map(|row| {
            (
                (
                    int_field(row, LDR_PID, "a process id"),
                    hex_field(row, LDR_BASE, "a module base"),
                ),
                (
                    bool_field(row, LDR_IN_LOAD, "InLoad"),
                    bool_field(row, LDR_IN_INIT, "InInit"),
                    bool_field(row, LDR_IN_MEM, "InMem"),
                    path_field(row, LDR_MAPPED_PATH, "a mapped path"),
                ),
            )
        })
        .collect()
}

/// Volatility's `vadinfo` as `(pid, start) -> mapped path`, for the ranges it
/// says are backed by a file.
///
/// The corroboration behind
/// [`win11_ldrmodules_finds_every_mapped_image_volatility_does_and_more_it_can_justify`]:
/// `ldrmodules` drops a range whose first page it cannot read, but `vadinfo`
/// still lists that range, its protection and the file mapped there. A row
/// Séance reports and upstream's `ldrmodules` does not is therefore checkable
/// against upstream's own evidence rather than against Séance's.
fn oracle_file_backed_vads(dir: &str) -> BTreeMap<(u64, u64), String> {
    require_oracle(dir, "windows.vadinfo")
        .iter()
        .filter(|row| int_field(row, VAD_PRIVATE, "the private-memory flag") == 0)
        .map(|row| {
            (
                (
                    int_field(row, VAD_PID, "a process id"),
                    hex_field(row, VAD_START, "a range start"),
                ),
                path_field(row, VAD_FILE, "a mapped path"),
            )
        })
        .collect()
}

/// Volatility's `modules` as `base -> (offset, name)`.
fn oracle_drivers(dir: &str) -> BTreeMap<u64, (u64, String)> {
    require_oracle(dir, "windows.modules")
        .iter()
        .map(|row| {
            (
                hex_field(row, MOD_BASE, "a driver base"),
                (
                    hex_field(row, MOD_OFFSET, "a loader entry offset"),
                    field(row, MOD_NAME, "a driver name").to_string(),
                ),
            )
        })
        .collect()
}

/// The processes Volatility listed mapped images for while reading no loader
/// list at all.
///
/// Derived from the two oracles rather than typed: a process that appears in
/// `ldrmodules` and contributes no row to `dlllist` is one whose PEB or loader
/// data Volatility could not read. It printed `False` in all three columns for
/// every one of that process's images anyway — an assertion of absence built on
/// nothing. Séance answers *unknown* there, and that is the documented
/// divergence these tests pin down.
fn processes_volatility_read_no_list_for(dir: &str) -> BTreeSet<u64> {
    let with_dlls: BTreeSet<u64> = oracle_dlls(dir).keys().map(|(pid, _)| *pid).collect();
    oracle_ldr(dir)
        .keys()
        .map(|(pid, _)| *pid)
        .filter(|pid| !with_dlls.contains(pid))
        .collect()
}

// ── dlllist ─────────────────────────────────────────────────────────────────

/// Compare one image's DLL list against its oracle, by `(pid, base)`.
fn compare_dlls(what: &str, survey: &Survey<OurDll>, dir: &str) {
    let ours: BTreeMap<(u64, u64), String> = survey
        .rows
        .iter()
        .map(|row| {
            (
                (row.pid, row.base),
                row.name
                    .name()
                    .map(str::to_string)
                    .unwrap_or_else(|| "name unavailable".to_string()),
            )
        })
        .collect();
    assert_eq!(
        ours.len(),
        survey.rows.len(),
        "{what}: Séance reported the same (pid, base) twice, so the set comparison below would \
         hide a duplicated module"
    );
    assert_same_set(
        what,
        &ours,
        &oracle_dlls(dir),
        |(pid, base), name| format!("pid {pid} base {base:#x} ({name})"),
        &survey.refusals,
    );
}

#[test]
fn xp_dlllist_finds_the_same_process_and_base_pairs_volatility_does() {
    let Some(survey) = xp_dlls() else {
        return;
    };
    compare_dlls("Windows XP SP2 windows.dlllist", survey, XP_ORACLE);
}

#[test]
fn win11_dlllist_finds_the_same_process_and_base_pairs_volatility_does() {
    let Some(survey) = win11_dlls() else {
        return;
    };
    compare_dlls("Windows 11 22000 windows.dlllist", survey, WIN11_ORACLE);
}

/// Compare the names on top of the bases: a right-length list of right bases
/// read at a wrong `BaseDllName` offset would still pass the set comparison.
fn compare_dll_names(what: &str, survey: &Survey<OurDll>, dir: &str) {
    let theirs = oracle_dlls(dir);
    let mut wrong: Vec<String> = Vec::new();
    let mut unread: Vec<String> = Vec::new();
    let mut torn: Vec<String> = Vec::new();

    for row in &survey.rows {
        let Some(their_name) = theirs.get(&(row.pid, row.base)) else {
            continue;
        };
        // Volatility renders a name it could not read as `-`; there is nothing
        // to compare against, and Séance saying so too is agreement.
        if their_name.as_str() == "-" {
            continue;
        }
        // An *empty* name is not a name Volatility read: `get_string` truncates
        // a `_UNICODE_STRING` at its first NUL, so a blank cell means the buffer
        // began with one. The Windows 11 image has exactly one such entry, and
        // Volatility's own `Path` column for it is mojibake, which is how we
        // know both tools read the same torn structure. There is nothing here to
        // agree with, so the only thing asserted is that Séance did not invent a
        // name out of the damage.
        if their_name.is_empty() {
            if let Some(ours) = row.name.name() {
                torn.push(format!(
                    "pid {} base {:#x}: Volatility's name is empty because the buffer began with \
                     a NUL, and Séance published '{ours}'",
                    row.pid, row.base
                ));
            }
            continue;
        }
        // The same torn structure, one column further along. Where the buffer
        // begins with a NUL the block above catches it; where it holds
        // reallocated bytes instead, `get_string` decodes them as UTF-16 and
        // Volatility publishes the result as a module name.
        //
        // The test is that the string holds no ASCII printable character at
        // all, which is narrower than "is not ASCII" on purpose. A loaded
        // module's `BaseDllName` carries a file extension, and every extension
        // a Windows loader maps is ASCII — `.dll`, `.exe`, `.sys`, `.ocx`. A
        // name with nothing printable and ASCII in it is therefore not a name
        // that was ever written there; a name that merely contains a non-ASCII
        // character still has to match, because that is where a `BaseDllName`
        // read at a wrong offset would show up. Across both reference images
        // 7,462 of the 7,465 named rows carry an ASCII printable; the three
        // that do not are all in one process (pid 6216), whose loader entries
        // sit in reallocated pool.
        //
        // Séance reading nothing here is the correct answer, not a miss: a
        // module list is what an examiner searches for a malicious DLL, and a
        // row of mojibake in it is worse than an absent row, because it looks
        // like a finding. Asserting parity on it would demand that Séance
        // reproduce another tool's mistake.
        //
        // What is asserted is not merely that Séance published nothing. It is
        // that Séance read the same buffer and *declined* it. Volatility got
        // sixteen characters out of this `_UNICODE_STRING`, so its `Length` and
        // its `Buffer` were both in the capture; an answer of "there was no
        // string here" would mean Séance read a different `Length` than the
        // other tool did, and accepting that as agreement would let a
        // `BaseDllName` read at the wrong offset pass through this branch
        // untouched.
        if !their_name.chars().any(|c| c.is_ascii_graphic()) {
            match &row.name {
                NameField::Name(ours) => torn.push(format!(
                    "pid {} base {:#x}: Volatility decoded the torn buffer as '{their_name}' and \
                     Séance published '{ours}' rather than declining it",
                    row.pid, row.base
                )),
                NameField::Empty => torn.push(format!(
                    "pid {} base {:#x}: Volatility decoded '{their_name}' out of this buffer, so \
                     the bytes were in the capture, and Séance called the string zero-length \
                     rather than unreadable",
                    row.pid, row.base
                )),
                NameField::Unavailable(_) => {}
            }
            continue;
        }
        match row.name.name() {
            Some(ours) if ours == their_name => {}
            Some(ours) => wrong.push(format!(
                "pid {} base {:#x}: ours '{ours}', Volatility '{their_name}'",
                row.pid, row.base
            )),
            None => unread.push(format!(
                "pid {} base {:#x}: Volatility read '{their_name}' and Séance read nothing ({:?})",
                row.pid, row.base, row.name
            )),
        }
    }

    assert!(
        wrong.is_empty(),
        "{what}: {} module(s) carry a different name in Séance than in Volatility, which is what \
         a BaseDllName read at the wrong offset looks like: {:?}",
        wrong.len(),
        head(&wrong),
    );
    assert!(
        unread.is_empty(),
        "{what}: {} module name(s) Volatility read out of this image, Séance did not: {:?}",
        unread.len(),
        head(&unread),
    );
    assert!(
        torn.is_empty(),
        "{what}: {} torn module name(s) were not reported as unreadable; mojibake in a module \
         name is worse than an absent one, and a silently blank one is worse still, because an \
         examiner can act on 'unreadable' and cannot act on either: {:?}",
        torn.len(),
        head(&torn),
    );
}

#[test]
fn xp_dlllist_reads_the_same_module_names_volatility_does() {
    let Some(survey) = xp_dlls() else {
        return;
    };
    compare_dll_names("Windows XP SP2 windows.dlllist", survey, XP_ORACLE);
}

#[test]
fn win11_dlllist_reads_the_same_module_names_volatility_does() {
    let Some(survey) = win11_dlls() else {
        return;
    };
    compare_dll_names("Windows 11 22000 windows.dlllist", survey, WIN11_ORACLE);
}

// ── ldrmodules ──────────────────────────────────────────────────────────────

/// Every mapped image Volatility reports is one Séance reports, and every image
/// Séance reports beyond them is a range Volatility's own `vadinfo` calls a
/// file-backed mapping.
///
/// **Not an equality, deliberately.** Upstream's `ldrmodules` builds its row set
/// by reading the first two bytes at each VAD's start and keeping the ranges
/// whose `e_magic` is `MZ`; a range whose first page it cannot read is caught by
/// `InvalidAddressException` and silently skipped
/// (`framework/plugins/windows/malware/ldrmodules.py`). Séance applies the same
/// `MZ` rule but resolves transition and prototype PTEs, so it reads first pages
/// upstream cannot, and confirms 647 more mapped images on this capture —
/// `version.dll`, `mpr.dll`, `urlmon.dll`, Edge's `msedge.dll` and
/// `vk_swiftshader.dll` among them, each `PAGE_EXECUTE_WRITECOPY` with
/// `PrivateMemory 0` in Volatility's own VAD table.
///
/// The direction matters in both directions and is asserted in both. This is the
/// plugin that surfaces unlinked modules: an invented row is a false rootkit
/// finding, and a missing row hides a real one. So an extra is admitted only
/// when Volatility itself lists a file-backed VAD at exactly that process and
/// start address — which no invention could satisfy — and nothing of
/// Volatility's may be missing at all.
#[test]
fn win11_ldrmodules_finds_every_mapped_image_volatility_does_and_more_it_can_justify() {
    let Some(survey) = win11_ldr() else {
        return;
    };
    let theirs = oracle_ldr(WIN11_ORACLE);
    let ours: BTreeMap<(u64, u64), String> = survey
        .rows
        .iter()
        .map(|row| {
            (
                (row.pid, row.base),
                row.mapped_file
                    .name()
                    .unwrap_or("no readable mapped file")
                    .to_string(),
            )
        })
        .collect();
    assert_eq!(
        ours.len(),
        survey.rows.len(),
        "Séance reported the same (pid, base) twice, so the comparison below would hide a \
         duplicated range"
    );

    let missing: Vec<String> = theirs
        .iter()
        .filter(|(key, _)| !ours.contains_key(*key))
        .map(|((pid, base), (_, _, _, path))| format!("pid {pid} base {base:#x} ({path})"))
        .collect();
    assert!(
        missing.is_empty(),
        "Windows 11 22000 windows.ldrmodules: {} mapped image(s) Volatility reports are absent \
         from Séance's answer, and this is the plugin that surfaces unlinked modules: {:?}\n  \
         walks Séance refused, which may account for a gap: {:?}",
        missing.len(),
        head(&missing),
        head(&survey.refusals),
    );

    // Volatility's own VAD table, as `(pid, start) -> mapped path`.
    let file_backed = oracle_file_backed_vads(WIN11_ORACLE);
    let mut unjustified: Vec<String> = Vec::new();
    let mut extra = 0usize;
    for (key, path) in &ours {
        if theirs.contains_key(key) {
            continue;
        }
        extra += 1;
        let (pid, base) = *key;
        match file_backed.get(key) {
            Some(their_path) if !their_path.is_empty() && their_path.as_str() != "N/A" => {}
            Some(_) => unjustified.push(format!(
                "pid {pid} base {base:#x} ({path}): Volatility's vadinfo has this range and names \
                 no file for it, so it is not a mapped image"
            )),
            None => unjustified.push(format!(
                "pid {pid} base {base:#x} ({path}): Volatility's vadinfo has no file-backed range \
                 starting here, so this row rests on nothing but Séance's own reading"
            )),
        }
    }
    assert!(
        unjustified.is_empty(),
        "Windows 11 22000 windows.ldrmodules: {} of {extra} image(s) Séance reports beyond \
         Volatility are not backed by a file-mapped VAD in Volatility's own table, which is what \
         a manufactured module looks like: {:?}",
        unjustified.len(),
        head(&unjustified),
    );
    assert!(
        extra > 0,
        "Séance reached no first page upstream could not, on a capture where 647 mapped images \
         are only reachable through transition and prototype PTEs; the extra coverage this test \
         exists to record has been lost"
    );
}

#[test]
fn win11_ldrmodules_agrees_with_volatility_on_every_answer_it_is_prepared_to_give() {
    let Some(survey) = win11_ldr() else {
        return;
    };
    let theirs = oracle_ldr(WIN11_ORACLE);
    let silent = processes_volatility_read_no_list_for(WIN11_ORACLE);

    let mut contradictions: Vec<String> = Vec::new();
    let mut answered: BTreeSet<(u64, u64)> = BTreeSet::new();

    for row in &survey.rows {
        let Some((in_load, in_init, in_mem, _)) = theirs.get(&(row.pid, row.base)) else {
            continue;
        };
        for (column, ours, upstream) in [
            ("InLoad", row.in_load, *in_load),
            ("InInit", row.in_init, *in_init),
            ("InMem", row.in_mem, *in_mem),
        ] {
            if let Some(ours) = ours {
                if ours != upstream {
                    contradictions.push(format!(
                        "pid {} base {:#x} {column}: ours {ours}, Volatility {upstream}",
                        row.pid, row.base
                    ));
                }
            }
        }
        if row.in_load.is_some() && row.in_init.is_some() && row.in_mem.is_some() {
            answered.insert((row.pid, row.base));
        }
    }

    assert!(
        contradictions.is_empty(),
        "{} module(s) are in a different set of PEB lists according to Séance than according to \
         Volatility. One direction accuses a legitimate DLL of having been unlinked; the other \
         clears a hidden one: {:?}",
        contradictions.len(),
        head(&contradictions),
    );

    // Agreement on the answers given is only half of it. Séance must also *give*
    // an answer everywhere Volatility actually walked a list — otherwise a
    // regression that answered `None` for everything would agree vacuously.
    let expected: Vec<String> = theirs
        .keys()
        .filter(|(pid, _)| !silent.contains(pid))
        .filter(|key| !answered.contains(*key))
        .map(|(pid, base)| format!("pid {pid} base {base:#x}"))
        .collect();
    assert!(
        expected.is_empty(),
        "{} module(s) belong to processes whose loader lists Volatility read end to end, and \
         Séance gave no answer for them: {:?}",
        expected.len(),
        head(&expected),
    );
}

#[test]
fn win11_ldrmodules_says_unknown_only_where_volatility_asserted_absence_from_nothing() {
    let Some(survey) = win11_ldr() else {
        return;
    };
    let theirs = oracle_ldr(WIN11_ORACLE);
    let silent = processes_volatility_read_no_list_for(WIN11_ORACLE);
    assert!(
        !silent.is_empty(),
        "this capture is supposed to hold processes Volatility printed False for without reading \
         a list; if it no longer does, the divergence below is untested"
    );

    let mut unknown_over_true: Vec<String> = Vec::new();
    let mut undeclared: Vec<String> = Vec::new();
    let mut declined: BTreeSet<u64> = BTreeSet::new();

    for row in &survey.rows {
        let Some((in_load, in_init, in_mem, _)) = theirs.get(&(row.pid, row.base)) else {
            continue;
        };
        let mut any_unknown = false;
        for (column, ours, upstream) in [
            ("InLoad", row.in_load, *in_load),
            ("InInit", row.in_init, *in_init),
            ("InMem", row.in_mem, *in_mem),
        ] {
            if ours.is_none() {
                any_unknown = true;
                // Declining to answer is honest. Declining where Volatility
                // found the module *present* would mean Séance failed to walk a
                // list it should have walked, which is a defect wearing the
                // costume of caution.
                if upstream {
                    unknown_over_true.push(format!(
                        "pid {} base {:#x} {column}: Volatility found it in the list and Séance \
                         could not say",
                        row.pid, row.base
                    ));
                }
            }
        }
        if any_unknown {
            declined.insert(row.pid);
            if row.declarations == 0 {
                undeclared.push(format!("pid {} base {:#x}", row.pid, row.base));
            }
        }
    }

    assert!(
        unknown_over_true.is_empty(),
        "{} answer(s) Séance declined to give were answers Volatility gave as True: {:?}",
        unknown_over_true.len(),
        head(&unknown_over_true),
    );
    assert!(
        undeclared.is_empty(),
        "{} module(s) carry an unknown answer with no declared reason. An examiner reading that \
         table cannot tell 'not in the list' from 'the list was never read': {:?}",
        undeclared.len(),
        head(&undeclared),
    );

    // Every process Volatility printed False for without reading a list must be
    // one Séance declines on. This is the divergence, asserted rather than
    // tolerated: upstream renders absence it did not establish, Séance does not.
    let not_declined: Vec<String> = silent
        .iter()
        .filter(|pid| !declined.contains(*pid))
        .map(|pid| format!("pid {pid}"))
        .collect();
    assert!(
        not_declined.is_empty(),
        "Volatility reported these processes' images as absent from all three loader lists having \
         read no list at all, and Séance made the same unsupported claim rather than declining: \
         {not_declined:?}",
    );

    // And every row belonging to such a process must be unknown in all three
    // columns, not just one: no list was read, so nothing about any of them is
    // established.
    let half_answered: Vec<String> = survey
        .rows
        .iter()
        .filter(|row| silent.contains(&row.pid))
        .filter(|row| row.in_load.is_some() || row.in_init.is_some() || row.in_mem.is_some())
        .map(|row| format!("pid {} base {:#x}", row.pid, row.base))
        .collect();
    assert!(
        half_answered.is_empty(),
        "{} module(s) belong to a process whose loader lists were never read, and Séance still \
         answered for at least one list: {:?}",
        half_answered.len(),
        head(&half_answered),
    );
}

#[test]
fn win11_ldrmodules_finds_the_images_that_are_in_two_lists_and_not_the_third() {
    let Some(survey) = win11_ldr() else {
        return;
    };
    let theirs = oracle_ldr(WIN11_ORACLE);

    // A process's own executable is linked into the load-order and memory-order
    // lists and never into the initialisation-order list: the loader does not
    // run DllMain on it. These rows are the corpus's own proof that the three
    // columns are three different questions. If every module in the capture
    // carried the same three booleans, that would be the signature of one list
    // walked three times through the same container member — the failure mode
    // this whole stage is built to avoid — so their absence would be alarming
    // rather than reassuring.
    let theirs_split: BTreeMap<(u64, u64), String> = theirs
        .iter()
        .filter(|(_, (in_load, in_init, in_mem, _))| *in_load && !*in_init && *in_mem)
        .map(|(key, (_, _, _, path))| (*key, path.clone()))
        .collect();
    assert!(
        !theirs_split.is_empty(),
        "Volatility's answer holds no module that is in the load and memory lists and not the \
         initialisation list, so this capture cannot prove the three lists were walked separately"
    );

    let ours_split: BTreeMap<(u64, u64), String> = survey
        .rows
        .iter()
        .filter(|row| {
            row.in_load == Some(true) && row.in_init == Some(false) && row.in_mem == Some(true)
        })
        .map(|row| {
            (
                (row.pid, row.base),
                row.mapped_file.name().unwrap_or("unnamed").to_string(),
            )
        })
        .collect();

    assert_same_set(
        "Windows 11 22000 windows.ldrmodules, images in the load and memory lists only",
        &ours_split,
        &theirs_split,
        |(pid, base), path| format!("pid {pid} base {base:#x} ({path})"),
        &survey.refusals,
    );
}

#[test]
fn win11_ldrmodules_names_the_same_mapped_file_volatility_does() {
    let Some(survey) = win11_ldr() else {
        return;
    };
    let theirs = oracle_ldr(WIN11_ORACLE);
    let mut wrong: Vec<String> = Vec::new();
    let mut unbacked: Vec<String> = Vec::new();
    let mut unread: Vec<String> = Vec::new();

    for row in &survey.rows {
        let Some((_, _, _, path)) = theirs.get(&(row.pid, row.base)) else {
            continue;
        };
        match &row.mapped_file {
            MappedFile::Name(ours) if ours == path => {}
            MappedFile::Name(ours) => wrong.push(format!(
                "pid {} base {:#x}: ours '{ours}', Volatility '{path}'",
                row.pid, row.base
            )),
            // The dangerous one. "This range maps no file" is the signature of
            // injected code; saying it about a range Volatility read a path out
            // of would manufacture a finding.
            file if file.is_definitely_unbacked() => unbacked.push(format!(
                "pid {} base {:#x}: Volatility read '{path}' and Séance reports no mapped file",
                row.pid, row.base
            )),
            _ => unread.push(format!(
                "pid {} base {:#x}: Volatility read '{path}' and Séance could not",
                row.pid, row.base
            )),
        }
    }

    assert!(
        unbacked.is_empty(),
        "{} mapped image(s) Séance reports as backed by no file at all, which is the signature of \
         injected code, and Volatility read a path for every one of them: {:?}",
        unbacked.len(),
        head(&unbacked),
    );
    assert!(
        wrong.is_empty(),
        "{} mapped image(s) are attributed to a different file by Séance than by Volatility: {:?}",
        wrong.len(),
        head(&wrong),
    );
    assert!(
        unread.is_empty(),
        "{} mapped file name(s) Volatility read out of this image, Séance did not: {:?}",
        unread.len(),
        head(&unread),
    );
}

// ── The three lists are three different members ─────────────────────────────

/// Assert one image's loader layout threads three lists through three members.
///
/// This is the structural half of the `ldrmodules` cross-check. The booleans
/// agreeing with Volatility proves the answers; this proves they were *obtained*
/// three different ways, so a future change that walked the load-order chain
/// three times could not pass by producing three identical columns.
fn assert_three_distinct_lists(what: &str, image: &str) {
    let Some(corpus) = Corpus::open(image) else {
        return;
    };
    let lists = corpus.modules.peb_lists();
    let [load, memory, init] = lists;
    let load = load.unwrap_or_else(|| panic!("{what}: this build declares no load-order list"));
    let memory =
        memory.unwrap_or_else(|| panic!("{what}: this build declares no memory-order list"));
    let init =
        init.unwrap_or_else(|| panic!("{what}: this build declares no initialisation-order list"));

    let heads: BTreeSet<&str> = [load.head.as_str(), memory.head.as_str(), init.head.as_str()]
        .into_iter()
        .collect();
    assert_eq!(
        heads.len(),
        3,
        "{what}: the three lists were taken from {heads:?}, so at least two walks started from the \
         same head"
    );

    let offset = |member: &str| {
        corpus
            .profile
            .symbols
            .member_offset(TYPE_LDR_DATA_TABLE_ENTRY, member)
            .unwrap_or_else(|err| {
                panic!("{what}: '{TYPE_LDR_DATA_TABLE_ENTRY}.{member}' has no offset: {err}")
            })
    };
    let load_at = offset(load.links.as_str());
    let memory_at = offset(memory.links.as_str());
    let init_at = offset(init.links.as_str());

    let distinct: BTreeSet<u64> = [load_at, memory_at, init_at].into_iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "{what}: the three lists thread through offsets {load_at:#x} ({}), {memory_at:#x} ({}) and \
         {init_at:#x} ({}). Two of them are the same member, so at least two of the three columns \
         are the same list walked twice and an unlinked module would read as linked",
        load.links,
        memory.links,
        init.links,
    );

    // The layout every NT build has: three consecutive `_LIST_ENTRY` members at
    // the top of the entry. Asserting the spacing rather than only the
    // distinctness catches a symbol table that resolved three different members
    // which are not these three.
    let link = corpus
        .profile
        .pointer_size()
        .checked_mul(2)
        .expect("a `_LIST_ENTRY` is two pointers");
    assert_eq!(
        memory_at,
        load_at.saturating_add(link),
        "{what}: InMemoryOrderLinks should be one `_LIST_ENTRY` past InLoadOrderLinks"
    );
    assert_eq!(
        init_at,
        load_at.saturating_add(link).saturating_add(link),
        "{what}: InInitializationOrderLinks should be two `_LIST_ENTRY`s past InLoadOrderLinks"
    );
}

#[test]
fn xp_reads_the_three_loader_lists_through_three_different_members() {
    assert_three_distinct_lists("Windows XP SP2", common::XP);
}

#[test]
fn win11_reads_the_three_loader_lists_through_three_different_members() {
    assert_three_distinct_lists("Windows 11 22000", common::WIN11);
}

#[test]
fn neither_reference_image_holds_a_wow64_process_so_a_second_peb_cannot_explain_a_gap() {
    // Upstream walks a 32-bit PEB as well as the 64-bit one for any process
    // running under WoW64, and would emit loader entries Séance's single walk
    // never reaches. Both comparisons above would then be measuring that
    // difference rather than the code under test. Neither capture holds such a
    // process, and this asserts it rather than assuming it.
    for image in [common::XP, common::WIN11] {
        let Some(corpus) = Corpus::open(image) else {
            continue;
        };
        let list = process::list_processes(
            &corpus.profile,
            &corpus.processes,
            &ProcessListConfig::default(),
        )
        .expect("the active process list is walkable");
        let wow64: Vec<String> = list
            .processes
            .iter()
            .filter(|record| record.notes.is_empty())
            .filter(|record| record.wow64.known() == Some(&true))
            .map(|record| {
                format!(
                    "pid {:?} {:?}",
                    record.pid.known(),
                    record.image_file_name.known()
                )
            })
            .collect();
        assert!(
            wow64.is_empty(),
            "{image} holds {} WoW64 process(es), whose 32-bit PEB Volatility walks and Séance does \
             not, so the DLL comparisons in this file are no longer comparing like with like: \
             {wow64:?}",
            wow64.len(),
        );
    }
}

// ── modules ─────────────────────────────────────────────────────────────────

/// Compare one image's kernel module list against its oracle, by base address.
fn compare_drivers(what: &str, survey: &Survey<OurDriver>, dir: &str) {
    let theirs = oracle_drivers(dir);
    let ours: BTreeMap<u64, String> = survey
        .rows
        .iter()
        .map(|row| {
            (
                row.base,
                row.name
                    .clone()
                    .unwrap_or_else(|| "name unavailable".to_string()),
            )
        })
        .collect();
    assert_eq!(
        ours.len(),
        survey.rows.len(),
        "{what}: Séance reported the same driver base twice, so the set comparison below would \
         hide a duplicated entry"
    );

    let named: BTreeMap<u64, String> = theirs
        .iter()
        .map(|(base, (_, name))| (*base, name.clone()))
        .collect();
    assert_same_set(
        what,
        &ours,
        &named,
        |base, name| format!("{base:#x} ({name})"),
        &survey.refusals,
    );

    // The bases agreeing is not enough on its own: a list threaded through the
    // wrong link member could land on the right images by way of the wrong
    // structures. The loader entry's own address pins the arithmetic.
    let mut wrong_entry: Vec<String> = Vec::new();
    let mut wrong_name: Vec<String> = Vec::new();
    for row in &survey.rows {
        let Some((entry, name)) = theirs.get(&row.base) else {
            continue;
        };
        if row.entry != *entry {
            wrong_entry.push(format!(
                "base {:#x}: our entry {:#x}, Volatility's {entry:#x}",
                row.base, row.entry
            ));
        }
        if name.as_str() != "-" && row.name.as_deref() != Some(name.as_str()) {
            wrong_name.push(format!(
                "base {:#x}: ours {:?}, Volatility '{name}'",
                row.base, row.name
            ));
        }
    }
    assert!(
        wrong_entry.is_empty(),
        "{what}: {} driver(s) were read from a different loader entry than Volatility read them \
         from, so the container arithmetic differs even though the bases matched: {:?}",
        wrong_entry.len(),
        head(&wrong_entry),
    );
    assert!(
        wrong_name.is_empty(),
        "{what}: {} driver(s) carry a different name in Séance than in Volatility: {:?}",
        wrong_name.len(),
        head(&wrong_name),
    );
}

#[test]
fn xp_modules_finds_the_same_driver_bases_volatility_does() {
    let Some(survey) = xp_drivers() else {
        return;
    };
    compare_drivers("Windows XP SP2 windows.modules", survey, XP_ORACLE);
}

#[test]
fn win11_modules_finds_the_same_driver_bases_volatility_does() {
    let Some(survey) = win11_drivers() else {
        return;
    };
    compare_drivers("Windows 11 22000 windows.modules", survey, WIN11_ORACLE);
}

#[test]
fn a_driver_list_read_at_sixty_four_bits_does_not_quietly_produce_thirty_two_bit_bases() {
    let Some(survey) = win11_drivers() else {
        return;
    };
    // Every driver on this build is mapped in kernel space, above the 32-bit
    // boundary once the sign extension is stripped. A base that fits in 32 bits
    // would mean a pointer was read four bytes wide, which yields a
    // plausible-looking list of entirely wrong images.
    for row in &survey.rows {
        assert!(
            row.base > u64::from(u32::MAX),
            "the driver {:?} at entry {:#x} has base {:#x}, which looks like a truncated pointer",
            row.name,
            row.entry,
            row.base,
        );
    }
}
