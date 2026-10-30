//! Execution history held in RAM: the Amcache hive and the AppCompatCache.
//!
//! Windows keeps two records of programs that have been *on* the machine, and
//! both of them outlive the process that ran. Neither is a log the user can
//! clear from a menu, and both are frequently the only surviving evidence that
//! a deleted executable was ever present:
//!
//! * **Amcache** (`C:\Windows\AppCompat\Programs\Amcache.hve`) is a registry
//!   hive the Application Experience service writes. Under `Root` it records,
//!   per installed program and per executable file, the program's name, its
//!   publisher, the full path it was seen at, the file's SHA-1, the PE link
//!   date and the install date. A path with a SHA-1 beside it is an
//!   identification of a *specific binary*, not merely of a file name, which is
//!   why it is the first thing an examiner reaches for when the binary itself
//!   has been deleted.
//! * **AppCompatCache**, universally called the **Shimcache**, is a kernel
//!   structure — `ahcache.sys` from Windows 8.1, the kernel itself before that
//!   — holding the last few hundred to a thousand executables the shim engine
//!   examined, each with the file's `$STANDARD_INFORMATION` modification time
//!   and, on some builds, a flag saying the file was actually executed. On disk
//!   it is a single `AppCompatCache` registry value that is only written at
//!   shutdown; in memory it is *live*, so it holds everything since the last
//!   boot that the disk copy does not.
//!
//! # Why this is a memory stage and not a registry stage
//!
//! Both are readable from a disk image, and Séance reads them from disk
//! elsewhere. What this stage adds is the part that only exists while the
//! machine is running:
//!
//! * The Shimcache's on-disk value is written at shutdown. On a machine that
//!   was imaged live, or that crashed, the on-disk value is stale by everything
//!   that happened since boot. The in-memory list is not.
//! * `Amcache.hve` is mapped and modified in place. Volatile keys, and keys
//!   written since the hive was last flushed, exist only in RAM.
//!
//! # What a wrong answer looks like
//!
//! The Shimcache entry structure changed at nearly every Windows release, and
//! no public symbol file declares it: `ahcache.sys` ships without symbols and
//! the structure is not in `ntoskrnl.pdb`. A layout applied to the wrong build
//! does not fail — it produces a full list of plausible-looking paths and
//! timestamps read from the wrong offsets, which is the worst possible outcome
//! for evidence. So this module:
//!
//! 1. resolves everything it *can* through the symbol table — `_LIST_ENTRY`,
//!    `_UNICODE_STRING`, `_ERESOURCE`, `_RTL_AVL_TABLE` are all real kernel
//!    types the PDB declares;
//! 2. selects the entry layout from the kernel build number and the pointer
//!    width, and **refuses** a build it has no catalogued layout for
//!    ([`AmcacheError::Unsupported`]) rather than picking the nearest one;
//! 3. cross-checks the catalogued layout against the symbol table, so a build
//!    whose `_UNICODE_STRING` or `_LIST_ENTRY` is not the size the layout
//!    assumes is refused too.
//!
//! # Absent, unreadable and unset are three different findings
//!
//! Every field of every entry is a [`Field`], which distinguishes "this Windows
//! version does not record it", "the key did not carry it", "the value was
//! there and its data page was not acquired", "the data is not the shape the
//! field must be" and "the value holds the format's never-set sentinel". A
//! report that rendered all five as an empty cell would let a gap in the
//! acquisition read as a statement about the suspect's machine.
//!
//! # Entry point
//!
//! [`collect_execution_history`] is the whole stage: it takes a profile, the
//! layout resolved by [`AmcacheSymbols::from_profile`] and an
//! [`AmcacheConfig`], and returns both sources in one [`ExecutionHistory`].

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::ObjError;
use seance_memory::Incomplete;
use seance_symbols::SymbolError;

use crate::modules::ModulesError;
use crate::profile::WindowsProfile;
use crate::registry::RegistryError;

#[path = "amcache_hive.rs"]
pub mod hive;
#[path = "amcache_shim.rs"]
pub mod shim;

#[cfg(test)]
#[path = "amcache_test_support.rs"]
pub(crate) mod test_support;

pub use hive::{
    read_amcache_from_listing, read_amcache_hive, select_amcache_hive, AmcacheEntry, AmcacheHive,
    AmcacheKeySection, AmcacheSource, HiveLayout, HiveStatus, KeyStatus, ALL_SOURCES,
    AMCACHE_FILE_NAME, AMCACHE_ROOT,
};
pub use shim::{
    entry_layout_for, read_shimcache, section_range, SectionRange, ShimEntry, ShimEntryLayout,
    ShimLayout, ShimSection, ShimStatus, ShimVariant, SHIMCACHE_HOST_MODULES,
    SHIMCACHE_KERNEL_MODULES,
};

/// The `_CMHIVE` type name, checked before the hive half of this stage runs.
pub const TYPE_CMHIVE: &str = "_CMHIVE";

/// The key-node type the hive half decodes every Amcache key through.
pub const TYPE_CM_KEY_NODE: &str = "_CM_KEY_NODE";

/// Ceiling on entries taken from any one Amcache key.
///
/// `Root\InventoryApplicationFile` on a long-lived workstation holds a few
/// thousand entries. Sixty-five thousand is far beyond anything genuine and far
/// below what a corrupt subkey index could ask this stage to allocate. Reaching
/// it is reported as a cap, never as the end of the key.
pub const MAX_ENTRIES_PER_KEY: usize = 65_536;

/// Ceiling on individually recorded notes. The *counts* stay exact.
pub const MAX_RECORDED_NOTES: usize = 256;

/// Ceiling on Shimcache entries one list walk will report.
///
/// The cache itself holds 96 entries on Windows XP, 512 on Vista through 7 and
/// 1024 on Windows 8 and later. Four thousand is well past every real limit, so
/// reaching it means the list is not terminating.
pub const MAX_SHIM_ENTRIES: usize = 4_096;

/// Ceiling on pointer-aligned probes one `.data` section sweep will make while
/// looking for the Shimcache handle.
///
/// `ahcache.sys`'s `.data` section is a few kilobytes; the kernel's is a few
/// hundred. A quarter of a million probes covers a two-megabyte section on x64
/// and is reached only when a section header claims a size no real image has,
/// which is exactly the case where an unbounded sweep would hang an ingest.
pub const MAX_SHIM_PROBES: usize = 262_144;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops this stage producing execution history worth reading.
///
/// Note what is *not* here: a key that is not in the hive, a hive that is not
/// loaded, or a `.data` section that holds no Shimcache handle. Those are facts
/// about the machine, and they land on the outcome where an examiner can see
/// which of them applied.
#[derive(Debug, thiserror::Error)]
pub enum AmcacheError {
    /// Neither source can be read on this build, and no partial answer would be
    /// honest. The message names what is missing for each of them.
    #[error("execution history cannot be read on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// A registry read failed in a way that invalidates the hive half.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// The loaded-module list, which the Shimcache is found through, could not
    /// be described.
    #[error(transparent)]
    Modules(#[from] ModulesError),

    /// A typed read failed for a reason that invalidates the whole stage.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question this stage depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),
}

impl AmcacheError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            AmcacheError::Unsupported { .. } => "unsupported_build",
            AmcacheError::Registry(err) => err.class(),
            AmcacheError::Modules(err) => err.class(),
            AmcacheError::Object(err) => err.class(),
            AmcacheError::Symbols(_) => "symbols",
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            AmcacheError::Registry(err) => err.incomplete_reason(),
            AmcacheError::Modules(err) => err.incomplete_reason(),
            AmcacheError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be read" refusal.
    pub fn unsupported(detail: impl Into<String>) -> AmcacheError {
        AmcacheError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Fields ──────────────────────────────────────────────────────────────────

/// One field of one entry, together with why it has no value when it has none.
///
/// The whole point of the type. An examiner asked "what was this program's
/// publisher?" must be able to tell apart:
///
/// * [`Field::NotApplicable`] — this Windows version does not record a
///   publisher for this kind of entry at all;
/// * [`Field::Absent`] — the key exists and carries no such value, so the
///   machine did not record one;
/// * [`Field::Unreadable`] — the value is there and the page holding its data
///   was never acquired, so the machine may well have recorded one;
/// * [`Field::Unparsable`] — the data is there and is not the shape the field
///   must be, which is itself a finding about what wrote it;
/// * [`Field::Unset`] — the value holds the format's never-set sentinel, most
///   often a zero FILETIME.
///
/// Rendering any two of those the same way turns a gap in the evidence into a
/// statement about the suspect's machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field<T> {
    /// This Windows version records no such field here.
    NotApplicable,
    /// The field is one this version records, and this entry did not have it.
    Absent,
    /// The field was present and could not be read. Carries the reason.
    Unreadable(String),
    /// The field was present and is not the shape it must be. Carries what is
    /// wrong.
    Unparsable(String),
    /// The field was present and holds the format's "never set" sentinel.
    Unset,
    /// The field's value.
    Present(T),
}

impl<T> Field<T> {
    /// The value, when there is one.
    pub fn value(&self) -> Option<&T> {
        match self {
            Field::Present(value) => Some(value),
            _ => None,
        }
    }

    /// Whether this field carries a value.
    pub fn is_present(&self) -> bool {
        matches!(self, Field::Present(_))
    }

    /// Whether the absence of a value here is a fact about the machine rather
    /// than about the acquisition.
    ///
    /// True for [`Field::NotApplicable`], [`Field::Absent`] and [`Field::Unset`]
    /// — the three states in which the machine genuinely recorded nothing.
    /// False for [`Field::Unreadable`] and [`Field::Unparsable`], where
    /// something was recorded and this stage could not turn it into a value.
    pub fn absence_is_a_fact(&self) -> bool {
        matches!(self, Field::NotApplicable | Field::Absent | Field::Unset)
    }

    /// Stable identifier for artifact metadata and report columns.
    pub fn status(&self) -> &'static str {
        match self {
            Field::NotApplicable => "not_applicable",
            Field::Absent => "absent",
            Field::Unreadable(_) => "unreadable",
            Field::Unparsable(_) => "unparsable",
            Field::Unset => "unset",
            Field::Present(_) => "present",
        }
    }

    /// Why the field has no value, when that was recorded.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Field::Unreadable(detail) | Field::Unparsable(detail) => Some(detail.as_str()),
            _ => None,
        }
    }

    /// Serializable form, rendering the value with `render`.
    ///
    /// The status travels with the value in every case, so a consumer that
    /// reads only `value` still cannot mistake an unreadable field for an empty
    /// one: `value` is `null` and `status` says which kind of nothing it is.
    pub fn to_json_with<F>(&self, render: F) -> serde_json::Value
    where
        F: Fn(&T) -> serde_json::Value,
    {
        serde_json::json!({
            "status": self.status(),
            "detail": self.detail(),
            "value": self.value().map(render),
        })
    }
}

/// Serializable form of a text field.
pub fn text_field_json(field: &Field<String>) -> serde_json::Value {
    field.to_json_with(|text| serde_json::json!(text))
}

/// Serializable form of an unsigned-integer field.
pub fn number_field_json(field: &Field<u64>) -> serde_json::Value {
    field.to_json_with(|value| serde_json::json!(value))
}

/// Serializable form of a boolean field.
pub fn flag_field_json(field: &Field<bool>) -> serde_json::Value {
    field.to_json_with(|value| serde_json::json!(value))
}

// ── Time ────────────────────────────────────────────────────────────────────

/// Seconds between the Windows FILETIME epoch, 1601-01-01, and the Unix epoch.
///
/// Used to bring the Unix-epoch timestamps Amcache stores for PE compile times
/// onto the same base as everything else, so one converter renders every time
/// this stage reports.
pub const FILETIME_EPOCH_SECONDS: u64 = 11_644_473_600;

/// 100 ns ticks in one second, which is the FILETIME unit.
pub const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

/// An instant, kept both as the image held it and as a report prints it.
///
/// The raw FILETIME travels with the rendered string so a disputed timestamp
/// can be re-derived from the number rather than from a formatted date whose
/// time zone somebody has to reconstruct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinTime {
    /// 100 ns ticks since 1601-01-01, exactly as the structure held it.
    pub filetime: u64,
    /// The same instant in RFC 3339, UTC.
    pub rfc3339: String,
}

impl WinTime {
    /// A FILETIME as a rendered instant.
    ///
    /// `None` for the zero sentinel and for any value below the Unix epoch,
    /// which no machine recorded: rendering those produces a 1601 date beside
    /// a real file path, and an examiner cannot tell it from a real one.
    pub fn from_filetime(filetime: u64) -> Option<WinTime> {
        seance_core::time::filetime_to_rfc3339(filetime)
            .map(|rfc3339| WinTime { filetime, rfc3339 })
    }

    /// Seconds since the Unix epoch as a rendered instant.
    ///
    /// Amcache stores PE link times and driver timestamps this way — the value
    /// out of the PE header's `TimeDateStamp` — while everything else in the
    /// hive is a FILETIME. Both end up here so a report has one time type.
    ///
    /// `None` when the value is zero, negative, or so large that converting it
    /// to a FILETIME would wrap.
    pub fn from_unix_seconds(seconds: i64) -> Option<WinTime> {
        let seconds = u64::try_from(seconds).ok()?;
        if seconds == 0 {
            return None;
        }
        let filetime = seconds
            .checked_add(FILETIME_EPOCH_SECONDS)?
            .checked_mul(FILETIME_TICKS_PER_SECOND)?;
        WinTime::from_filetime(filetime)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"filetime": self.filetime, "utc": self.rfc3339})
    }
}

/// Serializable form of a timestamp field.
pub fn time_field_json(field: &Field<WinTime>) -> serde_json::Value {
    field.to_json_with(WinTime::to_json)
}

/// A wall-clock reading with no time zone attached to it.
///
/// Amcache's `InstallDate` and `LinkDate` are stored as text in the machine's
/// **local** time, in `MM/DD/YYYY HH:MM:SS` form, with nothing recording which
/// zone that was. Converting one to UTC would require inventing the offset, so
/// this type keeps the reading as a normalised ISO-8601 local time and keeps
/// the original text beside it. A report must present it as local time; an
/// examiner who needs UTC has to supply the machine's zone from elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallClock {
    /// The text exactly as the registry held it.
    pub raw: String,
    /// The same reading as `YYYY-MM-DDTHH:MM:SS`, with **no** zone designator,
    /// because there is no zone to designate.
    pub local_iso8601: String,
}

impl WallClock {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "raw": self.raw,
            "local_iso8601": self.local_iso8601,
            "zone": "unknown_machine_local",
        })
    }
}

/// Serializable form of a local wall-clock field.
pub fn wallclock_field_json(field: &Field<WallClock>) -> serde_json::Value {
    field.to_json_with(WallClock::to_json)
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Everything both halves of this stage need resolved before either can run.
///
/// Resolved once per image and checked once, so a build that cannot be read
/// fails here naming what is missing rather than at entry three thousand having
/// already emitted paths decoded at the wrong offsets.
///
/// The two halves are independent: a machine can have `Amcache.hve` loaded and
/// a Shimcache this stage has no layout for, or the reverse. Each is therefore
/// resolved separately and its failure recorded rather than raised, in the same
/// shape [`crate::modules::ModuleSymbols`] uses for the `_PEB`. Only when
/// **neither** can be read does [`AmcacheSymbols::from_profile`] fail, because
/// only then is there nothing to report.
#[derive(Debug, Clone)]
pub struct AmcacheSymbols {
    /// How to reach the Amcache hive, when it can be reached.
    pub hive: Option<HiveLayout>,
    /// Why the Amcache hive cannot be reached on this build.
    pub hive_unavailable: Option<String>,
    /// How to read the Shimcache, when this build's layout is known.
    pub shim: Option<ShimLayout>,
    /// Why the Shimcache cannot be read on this build.
    pub shim_unavailable: Option<String>,
}

impl AmcacheSymbols {
    /// Resolve every layout fact this stage needs.
    ///
    /// # Errors
    ///
    /// [`AmcacheError::Unsupported`] naming both reasons, when neither the
    /// Amcache hive nor the Shimcache can be read on this build. Returning an
    /// empty outcome there would be a claim that the machine had no execution
    /// history, which is never true.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, AmcacheError> {
        let (hive, hive_unavailable) = match HiveLayout::from_profile(profile) {
            Ok(layout) => (Some(layout), None),
            Err(detail) => (None, Some(detail)),
        };
        let (shim, shim_unavailable) = match ShimLayout::from_profile(profile) {
            Ok(layout) => (Some(layout), None),
            Err(detail) => (None, Some(detail)),
        };
        if hive.is_none() && shim.is_none() {
            let hive_detail = hive_unavailable.unwrap_or_default();
            let shim_detail = shim_unavailable.unwrap_or_default();
            return Err(AmcacheError::unsupported(format!(
                "the Amcache hive cannot be reached ({hive_detail}) and the Shimcache cannot be \
                 read ({shim_detail}), so neither record of executed programs is available"
            )));
        }
        Ok(Self {
            hive,
            hive_unavailable,
            shim,
            shim_unavailable,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "amcache_hive": self.hive.as_ref().map(HiveLayout::to_json),
            "amcache_hive_unavailable": self.hive_unavailable,
            "shimcache": self.shim.as_ref().map(ShimLayout::to_json),
            "shimcache_unavailable": self.shim_unavailable,
        })
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps for one run of this stage.
#[derive(Debug, Clone)]
pub struct AmcacheConfig {
    /// Ceiling on entries taken from any one Amcache key.
    pub max_entries_per_key: usize,
    /// Ceiling on individually recorded notes. Counts stay exact past it.
    pub max_recorded_notes: usize,
    /// Ceiling on Shimcache entries one list walk reports.
    pub max_shim_entries: usize,
    /// Ceiling on pointer-aligned probes one `.data` sweep makes.
    pub max_shim_probes: usize,
}

impl Default for AmcacheConfig {
    fn default() -> Self {
        Self {
            max_entries_per_key: MAX_ENTRIES_PER_KEY,
            max_recorded_notes: MAX_RECORDED_NOTES,
            max_shim_entries: MAX_SHIM_ENTRIES,
            max_shim_probes: MAX_SHIM_PROBES,
        }
    }
}

// ── Outcome ─────────────────────────────────────────────────────────────────

/// Both records of executed programs, and everything neither could say.
#[derive(Debug, Clone)]
pub struct ExecutionHistory {
    /// The Amcache hive's entries, or why there are none.
    pub amcache: AmcacheHive,
    /// The Shimcache's entries, or why there are none.
    pub shimcache: ShimSection,
}

impl ExecutionHistory {
    /// Whether both records were read in full.
    ///
    /// The question a report must ask before writing "this machine has no
    /// record of that program having run": a stage that could read neither
    /// source, or that stopped at a cap, says nothing about what it did not
    /// reach.
    pub fn is_complete(&self) -> bool {
        self.amcache.is_complete() && self.shimcache.is_complete()
    }

    /// How many entries were recovered across both sources.
    pub fn entry_count(&self) -> usize {
        self.amcache.entry_count() + self.shimcache.entries.len()
    }

    /// Everything a report must declare about this stage.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.amcache.incomplete();
        out.extend(self.shimcache.incomplete());
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "amcache": self.amcache.to_json(),
            "shimcache": self.shimcache.to_json(),
            "entry_count": self.entry_count(),
            "complete": self.is_complete(),
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

// ── The stage ───────────────────────────────────────────────────────────────

/// Read both records of executed programs out of a Windows memory image.
///
/// # What an examiner learns
///
/// Every program the Amcache hive names, with its publisher, its path, its
/// SHA-1 and its install and link dates; and every executable the shim engine
/// examined since boot, with the path, the file's last-modified time and — on
/// the builds that record it — whether the file was actually executed. A path
/// present in the Shimcache but absent from every filesystem in the case is a
/// deleted executable that ran on this machine.
///
/// # What a wrong answer looks like
///
/// A Shimcache layout applied to the wrong build yields a complete-looking list
/// of paths and timestamps read from the wrong offsets — evidence about files
/// that were never on the machine. That is what
/// [`AmcacheSymbols::from_profile`] refusing an uncatalogued build prevents,
/// and why an unknown build produces [`ShimSection`] with a stated reason
/// rather than an empty list.
///
/// # Errors
///
/// Only for failures that make the whole stage meaningless: a build where
/// neither source can be read at all. A hive that is not loaded, a key that is
/// not present and a `.data` section with no Shimcache handle in it are facts
/// about the machine, and each lands on the outcome with the evidence for it.
pub fn collect_execution_history(
    profile: &WindowsProfile,
    symbols: &AmcacheSymbols,
    config: &AmcacheConfig,
) -> Result<ExecutionHistory, AmcacheError> {
    let amcache = match &symbols.hive {
        Some(layout) => read_amcache_hive(profile, layout, config),
        None => AmcacheHive::unavailable(
            symbols
                .hive_unavailable
                .clone()
                .unwrap_or_else(|| "the Amcache hive layout was not resolved".to_string()),
        ),
    };
    let shimcache = match &symbols.shim {
        Some(layout) => read_shimcache(profile, layout, config),
        None => ShimSection::unavailable(
            symbols
                .shim_unavailable
                .clone()
                .unwrap_or_else(|| "the Shimcache layout was not resolved".to_string()),
        ),
    };
    Ok(ExecutionHistory { amcache, shimcache })
}

/// Push a note, keeping the total exact once the recorded list is capped.
pub(crate) fn push_note(notes: &mut Vec<String>, total: &mut usize, cap: usize, note: String) {
    *total = total.saturating_add(1);
    if notes.len() < cap {
        notes.push(note);
    }
}

/// Read a `u32` out of `bytes` at `offset`, or `None` when it does not fit.
pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read a `u16` out of `bytes` at `offset`, or `None` when it does not fit.
pub(crate) fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Read a `u64` out of `bytes` at `offset`, or `None` when it does not fit.
pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

/// Read a pointer of `width` bytes out of `bytes` at `offset`.
pub(crate) fn pointer_at(bytes: &[u8], offset: usize, width: u64) -> Option<u64> {
    match width {
        8 => u64_at(bytes, offset),
        4 => u32_at(bytes, offset).map(u64::from),
        _ => None,
    }
}

/// The kernel address space wrapped in a struct reader, which both halves use.
pub(crate) fn kernel_reader(profile: &WindowsProfile) -> seance_memory::object::StructReader {
    seance_memory::object::StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_support::xp_profile;

    #[test]
    fn a_field_that_was_never_recorded_does_not_look_like_one_that_could_not_be_read() {
        let absent: Field<String> = Field::Absent;
        let unreadable: Field<String> = Field::Unreadable("the page was not acquired".into());
        assert_eq!(absent.status(), "absent");
        assert_eq!(unreadable.status(), "unreadable");
        assert!(absent.absence_is_a_fact());
        assert!(!unreadable.absence_is_a_fact());
        // Both render with a null value, so the status is the only thing that
        // separates them and it is always present.
        assert_eq!(text_field_json(&absent)["value"], serde_json::Value::Null);
        assert_eq!(
            text_field_json(&unreadable)["value"],
            serde_json::Value::Null
        );
        assert_ne!(
            text_field_json(&absent)["status"],
            text_field_json(&unreadable)["status"]
        );
        assert_eq!(
            text_field_json(&unreadable)["detail"],
            serde_json::json!("the page was not acquired")
        );
    }

    #[test]
    fn every_field_state_has_its_own_stable_identifier() {
        let states: Vec<&'static str> = vec![
            Field::<u64>::NotApplicable.status(),
            Field::<u64>::Absent.status(),
            Field::<u64>::Unreadable(String::new()).status(),
            Field::<u64>::Unparsable(String::new()).status(),
            Field::<u64>::Unset.status(),
            Field::<u64>::Present(1).status(),
        ];
        let mut unique = states.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), states.len(), "{states:?}");
    }

    #[test]
    fn a_zero_filetime_is_not_rendered_as_a_1601_date() {
        assert_eq!(WinTime::from_filetime(0), None);
        // A value below the 1601-to-1970 gap is not a time any machine recorded.
        assert_eq!(WinTime::from_filetime(1), None);
        let time = WinTime::from_filetime(129_067_776_000_000_000).expect("2010 is a real time");
        assert!(time.rfc3339.starts_with("2010-01-01T00:00:00"));
        assert_eq!(time.filetime, 129_067_776_000_000_000);
    }

    #[test]
    fn a_unix_epoch_compile_time_lands_on_the_same_base_as_a_filetime() {
        // 2010-01-01T00:00:00Z is 1_262_304_000 in Unix seconds.
        let from_unix = WinTime::from_unix_seconds(1_262_304_000).expect("a real compile time");
        let from_filetime =
            WinTime::from_filetime(129_067_776_000_000_000).expect("the same instant");
        assert_eq!(from_unix, from_filetime);
        // Sentinels and impossible values are refused rather than rendered.
        assert_eq!(WinTime::from_unix_seconds(0), None);
        assert_eq!(WinTime::from_unix_seconds(-1), None);
        assert_eq!(WinTime::from_unix_seconds(i64::MAX), None);
    }

    #[test]
    fn a_note_cap_keeps_the_total_exact_after_it_stops_recording() {
        let mut notes = Vec::new();
        let mut total = 0usize;
        for step in 0..10 {
            push_note(&mut notes, &mut total, 3, format!("note {step}"));
        }
        assert_eq!(notes.len(), 3);
        assert_eq!(total, 10);
    }

    #[test]
    fn little_endian_readers_refuse_to_run_off_the_end_of_a_buffer() {
        let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(u32_at(&bytes, 0), Some(1));
        assert_eq!(u32_at(&bytes, 4), Some(2));
        assert_eq!(u32_at(&bytes, 5), None);
        assert_eq!(u16_at(&bytes, 7), None);
        assert_eq!(u64_at(&bytes, 1), None);
        assert_eq!(pointer_at(&bytes, 0, 4), Some(1));
        assert_eq!(pointer_at(&bytes, 0, 8), Some(0x0000_0002_0000_0001));
        // A pointer width this stage does not know is refused rather than
        // guessed: a wrong width shifts every subsequent field.
        assert_eq!(pointer_at(&bytes, 0, 2), None);
    }

    #[test]
    fn a_build_that_can_read_neither_source_fails_closed_naming_both_reasons() {
        // The 32-bit registry fixture declares no loader entry type and no
        // Shimcache-shaped kernel types, so the Shimcache half cannot run; it
        // does declare CmpHiveListHead, so the hive half can, and the stage
        // must therefore still be constructible.
        let profile = xp_profile();
        let symbols = AmcacheSymbols::from_profile(&profile)
            .expect("the fixture can at least reach the hive list");
        assert!(symbols.hive.is_some());
        assert!(
            symbols.shim.is_none(),
            "the registry fixture declares no Shimcache-shaped kernel types"
        );
        let reason = symbols
            .shim_unavailable
            .as_deref()
            .expect("a refusal always states its reason");
        assert!(!reason.is_empty());
    }

    #[test]
    fn the_stage_runs_end_to_end_and_says_why_each_source_produced_nothing() {
        let profile = xp_profile();
        let symbols = AmcacheSymbols::from_profile(&profile).expect("the hive half resolves");
        let history =
            collect_execution_history(&profile, &symbols, &AmcacheConfig::default()).expect("run");

        // The fixture's only hive is an NTUSER.DAT, so there is no Amcache hive
        // to read; that is a fact about the image and must not read as "this
        // machine ran no programs".
        assert_eq!(history.entry_count(), 0);
        assert!(
            !history.is_complete(),
            "no execution history was read, so nothing may be asserted about the machine"
        );
        assert!(
            !history.incomplete().is_empty(),
            "an incomplete stage must say what it could not do"
        );
        let json = history.to_json();
        assert_eq!(json["complete"], serde_json::json!(false));
        assert_eq!(json["entry_count"], serde_json::json!(0));
    }
}
