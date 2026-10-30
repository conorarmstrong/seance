//! `MmUnloadedDrivers` — the drivers the kernel has unloaded (`ROADMAP` §5.3).
//!
//! # What an examiner learns
//!
//! A driver that loaded, did its work and unloaded leaves no entry in the
//! loaded-module list and no file necessarily on disk. The kernel keeps the
//! last fifty in a table, with each one's name, the address range it occupied
//! and the time it went. That is how a driver which ran for four seconds two
//! hours ago is still nameable.
//!
//! **And the forensic point is the cross-reference, not the listing.** A
//! callback target, a timer's DPC routine or a kernel thread's start address
//! that falls inside the range of a driver the kernel has *unloaded* is a
//! pointer into memory nothing owns any more. Reported with both sides and
//! never as a verdict: the range was reused the moment it was freed, so an
//! address inside it is a lead and not a finding.
//!
//! # The layout, measured rather than assumed
//!
//! The record layout is almost never in the symbols. Measured across **1,724**
//! `ntkrnlmp.pdb` ISFs on this machine: `MmUnloadedDrivers` and
//! `MmLastUnloadedDriver` are declared in 22 of a 24-ISF random sample, and the
//! type `_UNLOADED_DRIVERS` in **46 of all 1,724**.
//!
//! All 46 are x64 (`machine_type` 34404) and **all 46 agree on exactly one
//! layout**: size 40, `Name` at 0x00, `StartAddress` at 0x10, `EndAddress` at
//! 0x18, `CurrentTime` at 0x20. So the x64 fallback below is not merely
//! documented — it is **validated against 46 real symbol files**, and a record
//! read through it says which layout answered.
//!
//! **No x86 ISF in that corpus declares the type at all**, so the x86 fallback
//! is documented and unvalidated, and a record read through it is stamped
//! `Unvalidated` and says so. That is the difference between the two, and it is
//! on the record rather than in this comment alone.
//!
//! # The table is circular, and that is the thing to get right
//!
//! Capacity is fifty. `MmLastUnloadedDriver` is a **monotonic write count**,
//! not an index: the next slot to be written is `count % 50`, the newest entry
//! is `(count - 1) % 50`, and a count above fifty means the table has wrapped
//! and all fifty slots are populated. A machine up for hours always has all
//! fifty. Reading `count` as a length would report a 63-entry table on a
//! machine that had unloaded 63 drivers, thirteen of them from slots that had
//! been overwritten.
//!
//! A slot whose start and end are both zero has never been written. It is an
//! **empty slot**, not a range from 0 to 0 — and certainly not one that
//! "contains" every null pointer, which is what a range check without that
//! guard would say.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::StructReader;
use serde_json::{json, Value};

use crate::kernel_hooks::{ModuleMap, Ownership};
use crate::profile::WindowsProfile;
use crate::tamper::{TamperError, UnloadedSymbols};

/// How many entries the kernel's table holds.
pub const TABLE_CAPACITY: usize = 50;

/// Which layout a record was read through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordLayout {
    /// The build's own symbols declared `_UNLOADED_DRIVERS`.
    Isf,
    /// The x64 layout, validated against 46 real ISFs that do declare it.
    DocumentedX64,
    /// The x86 layout. **No ISF in the corpus declares it**, so this one is
    /// documented and unvalidated.
    DocumentedX86,
}

impl RecordLayout {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Isf => "isf",
            Self::DocumentedX64 => "documented_x64",
            Self::DocumentedX86 => "documented_x86",
        }
    }

    /// What a reader needs to know about this layout's standing.
    pub fn basis(&self) -> &'static str {
        match self {
            Self::Isf => {
                "This build's own symbols declare `_UNLOADED_DRIVERS`, and the record was read \
                 at the offsets they give."
            }
            Self::DocumentedX64 => {
                "This build's symbols do not declare `_UNLOADED_DRIVERS`, which is the ordinary \
                 case -- 46 of the 1,724 ntkrnlmp ISFs on this machine declare it. The record \
                 was read at the x64 layout those 46 carry, and all 46 agree on it exactly: \
                 size 40, Name at 0x00, StartAddress at 0x10, EndAddress at 0x18, CurrentTime \
                 at 0x20."
            }
            Self::DocumentedX86 => {
                "This build's symbols do not declare `_UNLOADED_DRIVERS` and NO x86 ISF in the \
                 corpus this layout was checked against declares it either, so the offsets used \
                 here are documented and UNVALIDATED. Treat the addresses and the time on this \
                 record as unverified."
            }
        }
    }

    /// Whether a record read through this layout is validated.
    pub fn is_validated(&self) -> bool {
        matches!(self, Self::Isf | Self::DocumentedX64)
    }
}

/// Where each field sits in one record.
#[derive(Debug, Clone, Copy)]
pub struct Fields {
    pub layout: RecordLayout,
    pub size: usize,
    pub name: usize,
    pub start: usize,
    pub end: usize,
    pub time: usize,
    /// Bytes in a pointer, which is also the width of `StartAddress`.
    pub pointer: usize,
    /// Set when the build DID declare `_UNLOADED_DRIVERS` and the declaration
    /// was refused, so a fallback answered.
    ///
    /// Kept because the two cases are different sentences: "this build does not
    /// declare the type" and "this build declares it as something these
    /// records cannot be read at" are not the same fact about the evidence,
    /// and the second is the one a symbol problem would show up as.
    pub isf_rejected: Option<&'static str>,
}

impl Fields {
    /// The x64 layout all 46 declaring ISFs agree on.
    pub const X64: Self = Self {
        layout: RecordLayout::DocumentedX64,
        size: 0x28,
        name: 0x00,
        start: 0x10,
        end: 0x18,
        time: 0x20,
        pointer: 8,
        isf_rejected: None,
    };

    /// The x86 layout, documented and unvalidated.
    pub const X86: Self = Self {
        layout: RecordLayout::DocumentedX86,
        size: 0x18,
        name: 0x00,
        start: 0x08,
        end: 0x0c,
        time: 0x10,
        pointer: 4,
        isf_rejected: None,
    };

    /// Resolve the layout: the build's own symbols where it declares the type,
    /// otherwise the fallback for its pointer width.
    pub fn resolve(reader: &StructReader) -> Self {
        let pointer = reader.pointer_size().unwrap_or(8) as usize;
        let from_isf = || -> Option<Self> {
            let size = reader.size_of("_UNLOADED_DRIVERS").ok()?.bytes() as usize;
            let at = |path: &str| -> Option<usize> {
                Some(
                    reader
                        .member_offset("_UNLOADED_DRIVERS", path)
                        .ok()?
                        .bytes() as usize,
                )
            };
            let candidate = Self {
                layout: RecordLayout::Isf,
                size,
                name: at("Name")?,
                start: at("StartAddress")?,
                end: at("EndAddress")?,
                time: at("CurrentTime")?,
                pointer,
                isf_rejected: None,
            };
            // A declared size that does not contain the members it declares is
            // not a record layout. The stride matters most: a size of zero
            // would read slot 0 fifty times and publish fifty copies of one
            // driver as fifty unloads.
            let needed = candidate
                .time
                .max(candidate.start)
                .max(candidate.end)
                .saturating_add(8)
                .max(candidate.name.saturating_add(2 * pointer));
            if candidate.size == 0 || candidate.size < needed {
                return None;
            }
            Some(candidate)
        };
        let fallback = if pointer == 4 { Self::X86 } else { Self::X64 };
        match from_isf() {
            Some(from_symbols) => from_symbols,
            None => Self {
                // Only a type that IS declared can have been refused, so the
                // note is set from whether the declaration exists rather than
                // from whether it parsed.
                isf_rejected: reader.size_of("_UNLOADED_DRIVERS").is_ok().then_some(
                    "this build declares `_UNLOADED_DRIVERS`, and the declaration was refused: \
                     its members or its size are not a record these fields can be read at. The \
                     documented fallback answered instead, and which layout answered is on every \
                     record.",
                ),
                ..fallback
            },
        }
    }
}

/// 100-nanosecond units in a year, for the uptime bound below.
const UNITS_PER_YEAR: u64 = 10_000_000 * 60 * 60 * 24 * 365;

/// The longest interval this build will read a `CurrentTime` value as an
/// uptime.
///
/// Twenty-five years is far beyond any Windows machine's uptime and far below
/// the FILETIME floor (1970 is 0x019D_B1DE_D53E_8000), so the two cases cannot
/// overlap and a value between them is claimed as neither.
pub const MAX_SINCE_BOOT: u64 = 25 * UNITS_PER_YEAR;

/// What the record's time field turned out to be.
///
/// # Why this is not simply a FILETIME
///
/// The field is named `CurrentTime` and every tool in this space, Volatility 3
/// included, renders it with a FILETIME conversion. On the Windows 11 26200
/// capture in this corpus that is wrong, and measurably so: the nine populated
/// slots hold 0x00e393cb through 0x03728e86, monotonically increasing with the
/// order the drivers unloaded — 1.491 to 5.784 seconds in 100-nanosecond units,
/// which is an interval since boot. Read as FILETIMEs they are nine unloads on
/// 1601-01-01, six seconds apart, which is what Volatility 3 prints.
///
/// **A date of 1601-01-01 on a 2026 machine is not a harmless rendering
/// artefact.** It sorts to the top of a timeline, it reads as a timestomp, and
/// `HUNT-051` is this project's own lesson about what a rule built on one of
/// those costs: 4,054 false timestomps on a stock XP machine. So the number is
/// classified before it is rendered, and an interval is published as an
/// interval.
///
/// No absolute time is derived from an interval. That would need the boot time
/// and a validated relation between it and the kernel's interrupt time — the
/// interrupt time is biased by the time the machine spends asleep — and
/// neither is established here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnloadTime {
    /// Zero: the slot's time was never written.
    NeverWritten,
    /// A plausible FILETIME, rendered.
    Absolute(String),
    /// An interval since boot, in 100-nanosecond units.
    SinceBoot { units: u64 },
    /// Neither. Reported raw, interpreted as nothing.
    Unrenderable,
}

impl UnloadTime {
    /// Classify one raw `CurrentTime` value.
    pub fn classify(raw: u64) -> Self {
        if raw == 0 {
            return Self::NeverWritten;
        }
        if let Some(rendered) = seance_core::time::filetime_to_rfc3339(raw) {
            return Self::Absolute(rendered);
        }
        if raw <= MAX_SINCE_BOOT {
            return Self::SinceBoot { units: raw };
        }
        Self::Unrenderable
    }
}

/// One entry in the table.
#[derive(Debug, Clone)]
pub struct UnloadedDriver {
    /// Slot index, so a record can be traced back to the table.
    pub slot: usize,
    /// Whether this is the most recently written slot.
    pub newest: bool,
    pub name: Option<String>,
    /// Why there is no name, when there is not.
    pub name_unavailable: Option<String>,
    pub start: u64,
    pub end: u64,
    /// The raw FILETIME.
    pub unloaded_filetime: u64,
    pub layout: RecordLayout,
}

impl UnloadedDriver {
    /// Whether the entry's range is usable for a containment test.
    ///
    /// A slot that has never been written holds zeros, and a range of 0..0 is
    /// not a range — a containment test against it would match every null
    /// pointer in the kernel.
    pub fn has_range(&self) -> bool {
        !(self.start == 0 && self.end == 0) && self.end > self.start
    }

    pub fn contains(&self, address: u64) -> bool {
        self.has_range() && address >= self.start && address < self.end
    }

    /// What this slot's time field is — see [`UnloadTime`].
    pub fn unload_time(&self) -> UnloadTime {
        UnloadTime::classify(self.unloaded_filetime)
    }

    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("MemoryUnloadedDriver"));
        m.insert(
            "name".into(),
            json!(self
                .name
                .clone()
                .unwrap_or_else(|| format!("(unnamed, slot {})", self.slot))),
        );
        m.insert("driver_name".into(), json!(self.name));
        m.insert(
            "name_unavailable_reason".into(),
            json!(self.name_unavailable),
        );
        m.insert("slot".into(), json!(self.slot));
        m.insert("is_newest".into(), json!(self.newest));
        m.insert(
            "start_address".into(),
            json!(format!("{:#018x}", self.start)),
        );
        m.insert("end_address".into(), json!(format!("{:#018x}", self.end)));
        m.insert("has_range".into(), json!(self.has_range()));
        if !self.has_range() {
            m.insert(
                "range_note".into(),
                json!(
                    "This slot's start and end addresses are both zero, or its end is not above \
                     its start: it has never been written, or was not read. It is an EMPTY SLOT \
                     and not a range, and nothing is tested against it -- a containment test \
                     against 0..0 would match every null pointer in the kernel."
                ),
            );
        }
        m.insert("unloaded_time_raw".into(), json!(self.unloaded_filetime));
        match self.unload_time() {
            UnloadTime::Absolute(rendered) => {
                m.insert("unloaded_at".into(), json!(rendered));
                m.insert(
                    "unloaded_time_basis".into(),
                    json!("The time field holds a plausible FILETIME and is rendered as one."),
                );
            }
            UnloadTime::SinceBoot { units } => {
                m.insert("unloaded_at".into(), Value::Null);
                m.insert(
                    "unloaded_seconds_after_boot".into(),
                    json!(units as f64 / 10_000_000.0),
                );
                m.insert(
                    "unloaded_time_basis".into(),
                    json!(format!(
                        "The time field holds {:#018x}, which is {:.3} seconds in \
                         100-nanosecond units and is an interval SINCE BOOT, not a FILETIME. \
                         Read as a FILETIME it would date this unload to 1601-01-01, which is \
                         what tools that convert this field unconditionally print. No absolute \
                         time is claimed: deriving one needs the boot time and a validated \
                         relation to the kernel's interrupt time, which is biased by the time \
                         the machine spends asleep.",
                        units,
                        units as f64 / 10_000_000.0
                    )),
                );
            }
            UnloadTime::NeverWritten => {
                m.insert("unloaded_at".into(), Value::Null);
                m.insert(
                    "unloaded_at_absent_reason".into(),
                    json!(
                        "This slot's time field is zero: it has never been written. No unload \
                         time is claimed for it."
                    ),
                );
            }
            UnloadTime::Unrenderable => {
                m.insert("unloaded_at".into(), Value::Null);
                m.insert(
                    "unloaded_at_absent_reason".into(),
                    json!(format!(
                        "This slot's time field holds {:#018x}, which is neither a FILETIME this \
                         build will render nor a credible interval since boot. It is reported as \
                         it was read and interpreted as nothing.",
                        self.unloaded_filetime
                    )),
                );
            }
        }
        m.insert("record_layout".into(), json!(self.layout.as_str()));
        m.insert("record_layout_basis".into(), json!(self.layout.basis()));
        if !self.layout.is_validated() {
            m.insert("content_incomplete".into(), json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                json!(IncompleteReason::Unvalidated.as_str()),
            );
        }
        Value::Object(m)
    }
}

/// An address that falls inside the range of a driver the kernel has unloaded.
///
/// **A lead, never a verdict.** The range was freed the moment the driver
/// unloaded and could have been reused by anything since, so both sides are
/// reported and no conclusion is drawn.
#[derive(Debug, Clone)]
pub struct UnloadedRangeHit {
    /// What the address was found as — a callback target, a DPC routine, a
    /// thread start.
    pub what: String,
    pub address: u64,
    pub driver: String,
    pub driver_start: u64,
    pub driver_end: u64,
    pub unloaded_at: Option<String>,
    /// What the loaded-module map says about the same address, so the two
    /// answers are side by side.
    pub also_owned_by: Ownership,
}

impl UnloadedRangeHit {
    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryUnloadedDriverRangeHit",
            "name": format!("{} in unloaded {}", self.what, self.driver),
            "what": self.what,
            "address": format!("{:#018x}", self.address),
            "unloaded_driver": self.driver,
            "unloaded_driver_start": format!("{:#018x}", self.driver_start),
            "unloaded_driver_end": format!("{:#018x}", self.driver_end),
            "unloaded_at": self.unloaded_at,
            "also_owned_by": self.also_owned_by.to_json(),
            "is_a_verdict": false,
            "basis":
                "This address falls inside the range a driver occupied before the kernel \
                 unloaded it. That range was FREED when the driver unloaded and may have been \
                 reused by anything since, so this is a lead to follow and not a finding: it \
                 does not establish that the unloaded driver placed the pointer, and it does \
                 not establish that anything is wrong. Both sides are reported so an examiner \
                 can judge.",
        })
    }
}

/// What the table yielded.
#[derive(Debug, Clone)]
pub struct UnloadedTable {
    pub drivers: Vec<UnloadedDriver>,
    /// The raw write counter, which is not a length.
    pub write_count: u64,
    /// Whether the table has wrapped, so entries have been overwritten.
    pub wrapped: bool,
    pub layout: RecordLayout,
    pub hits: Vec<UnloadedRangeHit>,
    pub capped: Option<String>,
    /// Anything about the read the caller must state — at present, a refused
    /// `_UNLOADED_DRIVERS` declaration.
    pub notes: Vec<String>,
}

impl UnloadedTable {
    /// The sentence a record carries about the counter.
    pub fn describe(&self) -> String {
        let populated = self.drivers.iter().filter(|d| d.has_range()).count();
        let mut s = format!(
            "The kernel's unloaded-driver table holds {TABLE_CAPACITY} entries and this one has \
             been written {} time(s); {} of the {} slots read carry a range.",
            self.write_count,
            populated,
            self.drivers.len()
        );
        if self.wrapped {
            s.push_str(&format!(
                " The count is above the table's capacity, so the table has WRAPPED: {} earlier \
                 unload(s) have been overwritten and are not recoverable from it. A driver that \
                 unloaded and is not listed here may simply have been pushed out.",
                self.write_count.saturating_sub(TABLE_CAPACITY as u64)
            ));
        } else {
            s.push_str(
                " The count is within the table's capacity, so nothing has been overwritten and \
                 this is every unload the kernel has recorded since it booted.",
            );
        }
        s
    }

    pub fn to_json(&self) -> Value {
        json!({
            "drivers": self.drivers.iter().map(UnloadedDriver::to_json).collect::<Vec<_>>(),
            "drivers_total": self.drivers.len(),
            "drivers_with_a_range": self.drivers.iter().filter(|d| d.has_range()).count(),
            "table_capacity": TABLE_CAPACITY,
            "write_count": self.write_count,
            "write_count_basis":
                "`MmLastUnloadedDriver` is a MONOTONIC WRITE COUNT, not an index and not a \
                 length. The next slot to be written is count % 50 and the newest entry is \
                 (count - 1) % 50. Reading it as a length would report a table longer than the \
                 fifty entries the kernel keeps.",
            "wrapped": self.wrapped,
            "statement": self.describe(),
            "record_layout": self.layout.as_str(),
            "record_layout_basis": self.layout.basis(),
            "range_hits": self.hits.iter().map(UnloadedRangeHit::to_json).collect::<Vec<_>>(),
            "range_hits_total": self.hits.len(),
            "notes": self.notes,
            "content_incomplete": self.capped.is_some() || !self.layout.is_validated(),
            "content_incomplete_reason": if self.capped.is_some() {
                Some(IncompleteReason::CapReached.as_str())
            } else if !self.layout.is_validated() {
                Some(IncompleteReason::Unvalidated.as_str())
            } else {
                None
            },
            "cap_detail": self.capped,
        })
    }
}

/// Read the `_UNICODE_STRING` at the head of one record.
///
/// Read by hand rather than through [`crate::poolscan::unicode_string`], for
/// two reasons that are not stylistic:
///
/// * The `_UNICODE_STRING` this reader needs is the **first member of the
///   record**, not a named member of a declared type, and the object reader
///   addresses members by path. There is no path to "the structure itself".
/// * The x86 fallback exists precisely for builds whose ISF does not declare
///   `_UNLOADED_DRIVERS`, and the buffer pointer is four bytes wide there.
///   Resolving the string through a 64-bit type would read four bytes of the
///   following field into the pointer.
///
/// The rules are the ones `unicode_string` documents, kept deliberately
/// identical: `Length` counts bytes, the length is capped before anything is
/// allocated, `MaximumLength` below `Length` is not a string, no NUL
/// terminator is assumed, and text that is not text is refused rather than
/// published as a name.
fn read_name(reader: &StructReader, at: u64, fields: Fields) -> (Option<String>, Option<String>) {
    let unavailable = |detail: String| (None, Some(detail));
    // `Length` and `MaximumLength` are two `USHORT`s, and `Buffer` is aligned
    // to the pointer width — so it sits at offset 4 on a 32-bit build and at
    // offset 8 on a 64-bit one, with four bytes of padding between. Reading it
    // at offset 4 on x64 yields the padding and the pointer's low half.
    let mut header = [0u8; 16];
    let buffer_at = fields.pointer;
    let header_bytes = buffer_at + fields.pointer;
    if let Err(e) = reader.read_into(at, &mut header[..header_bytes]) {
        return unavailable(format!(
            "the name's `_UNICODE_STRING` would not be read at {at:#018x}: {e}"
        ));
    }
    let length = u16::from_le_bytes([header[0], header[1]]) as u64;
    let maximum = u16::from_le_bytes([header[2], header[3]]) as u64;
    let mut buf = [0u8; 8];
    buf[..fields.pointer].copy_from_slice(&header[buffer_at..header_bytes]);
    let buffer = u64::from_le_bytes(buf);
    if length == 0 {
        return (
            None,
            Some("this slot's name is empty, which is what an unwritten slot holds".to_string()),
        );
    }
    if !length.is_multiple_of(2) || length > crate::poolscan::MAX_UNICODE_STRING_BYTES {
        return unavailable(format!(
            "the name at {at:#018x} declares {length} byte(s) of UTF-16 text, which is not a \
             length a `_UNICODE_STRING` can hold"
        ));
    }
    if maximum < length {
        return unavailable(format!(
            "the name at {at:#018x} declares {length} byte(s) of text in a buffer of {maximum}"
        ));
    }
    if buffer == 0 {
        return unavailable(format!(
            "the name at {at:#018x} declares {length} byte(s) of text and a null buffer"
        ));
    }
    match reader.read_bytes(buffer, length) {
        Ok(bytes) => {
            let text = crate::poolscan::decode_utf16le(&bytes);
            match crate::poolscan::name_damage(&text) {
                None => (Some(text), None),
                Some(damage) => unavailable(format!(
                    "the name at {at:#018x} points at {buffer:#x}, where {damage}, so these \
                     bytes are not the name they were read as"
                )),
            }
        }
        Err(e) => unavailable(format!(
            "the name's buffer at {buffer:#018x} would not be read: {e}"
        )),
    }
}

/// Where one slot's members are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotAddresses {
    pub name: u64,
    pub start: u64,
    pub end: u64,
    pub time: u64,
}

/// The addresses of one slot's members.
pub fn slot_addresses(
    table_at: u64,
    slot: usize,
    fields: Fields,
) -> Result<SlotAddresses, TamperError> {
    // `table_at` is the pointer `MmUnloadedDrivers` held, read from the
    // image, so every step from it is checked (`MEM-052`'s audit).
    let past = || {
        TamperError::read(format!(
            "slot {slot} of the table `MmUnloadedDrivers` points at ({table_at:#018x}) would lie \
             past the top of the address space, so that pointer is not the table"
        ))
    };
    let at = slot
        .checked_mul(fields.size)
        .and_then(|o| table_at.checked_add(o as u64))
        .ok_or_else(past)?;
    let member = |off: usize| at.checked_add(off as u64).ok_or_else(past);
    Ok(SlotAddresses {
        name: member(fields.name)?,
        start: member(fields.start)?,
        end: member(fields.end)?,
        time: member(fields.time)?,
    })
}

/// Read the unloaded-driver table.
pub fn read_table(
    profile: &WindowsProfile,
    symbols: &UnloadedSymbols,
    max_records: usize,
) -> Result<UnloadedTable, TamperError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let fields = Fields::resolve(&reader);
    let mut notes: Vec<String> = Vec::new();
    if let Some(rejected) = fields.isf_rejected {
        notes.push(rejected.to_string());
    }

    let read_ptr = |at: u64| -> Result<u64, TamperError> {
        let mut buf = [0u8; 8];
        reader
            .read_into(at, &mut buf[..fields.pointer])
            .map_err(|e| {
                TamperError::read(format!("the pointer at {at:#018x} would not read: {e}"))
            })?;
        Ok(u64::from_le_bytes(buf))
    };

    // `MmUnloadedDrivers` is a POINTER to the table, not the table.
    let table_at = read_ptr(symbols.table_pointer)?;
    if table_at == 0 {
        // A null pointer is the kernel saying the table was never allocated,
        // which is an answer and not a failure.
        return Ok(UnloadedTable {
            drivers: Vec::new(),
            write_count: 0,
            wrapped: false,
            layout: fields.layout,
            hits: Vec::new(),
            notes,
            capped: Some(
                "`MmUnloadedDrivers` is null in this image: the kernel had not allocated the \
                 table, so it records no unloads. That is an absence in the evidence and not a \
                 failure to read it."
                    .to_string(),
            ),
        });
    }

    let mut count_buf = [0u8; 8];
    reader
        .read_into(symbols.counter, &mut count_buf[..fields.pointer])
        .map_err(|e| TamperError::read(format!("`MmLastUnloadedDriver` would not read: {e}")))?;
    let write_count = u64::from_le_bytes(count_buf);

    // The count is a WRITE COUNT. Slots populated is min(count, capacity).
    let wrapped = write_count > TABLE_CAPACITY as u64;
    let populated = (write_count as usize).min(TABLE_CAPACITY);
    let to_read = populated.min(max_records);
    let capped = (to_read < populated).then(|| {
        format!(
            "the record cap of {max_records} stopped this read at {to_read} of {populated} \
             populated slots"
        )
    });
    // The newest slot is (count - 1) % capacity.
    let newest_slot = write_count
        .checked_sub(1)
        .map(|c| (c % TABLE_CAPACITY as u64) as usize);

    let mut drivers = Vec::with_capacity(to_read);
    for slot in 0..to_read {
        let at = slot_addresses(table_at, slot, fields)?;
        let start = read_ptr(at.start)?;
        let end = read_ptr(at.end)?;
        let mut time_buf = [0u8; 8];
        let unloaded_filetime = match reader.read_into(at.time, &mut time_buf) {
            Ok(()) => u64::from_le_bytes(time_buf),
            Err(_) => 0,
        };
        let (name, name_unavailable) = read_name(&reader, at.name, fields);
        drivers.push(UnloadedDriver {
            slot,
            newest: newest_slot == Some(slot),
            name,
            name_unavailable,
            start,
            end,
            unloaded_filetime,
            layout: fields.layout,
        });
    }

    Ok(UnloadedTable {
        drivers,
        write_count,
        wrapped,
        layout: fields.layout,
        hits: Vec::new(),
        notes,
        capped,
    })
}

/// Cross-reference addresses against the unloaded ranges.
///
/// `candidates` are `(what, address)` pairs — a callback target, a timer's DPC
/// routine, a kernel thread's start. `modules` is the loaded-module map, so
/// each hit carries what the *loaded* modules say about the same address
/// beside what the unloaded table says.
pub fn cross_reference(
    table: &mut UnloadedTable,
    candidates: &[(String, u64)],
    modules: &ModuleMap,
) {
    for (what, address) in candidates {
        // A null address is not a pointer into anything.
        if *address == 0 {
            continue;
        }
        for d in &table.drivers {
            if !d.contains(*address) {
                continue;
            }
            table.hits.push(UnloadedRangeHit {
                what: what.clone(),
                address: *address,
                driver: d
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("(unnamed, slot {})", d.slot)),
                driver_start: d.start,
                driver_end: d.end,
                unloaded_at: seance_core::time::filetime_to_rfc3339(d.unloaded_filetime),
                also_owned_by: modules.attribute(*address),
            });
        }
    }
}
