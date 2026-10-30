//! The per-processor timer tables and what their DPC routines point at
//! (`ROADMAP` §5.3).
//!
//! # What an examiner learns
//!
//! A kernel timer is how code arranges to run later without a thread of its
//! own. Each timer may carry a `_KDPC`, and that DPC's `DeferredRoutine` is an
//! address the kernel will call. A routine that lands in **no loaded module**
//! is the signal: something arranged to be called at a place the loader list
//! cannot account for.
//!
//! It is a signal and not a verdict, and this stage reports it as one. A
//! driver that has since unloaded, a hot-patched routine and a legitimately
//! pool-allocated thunk all produce the same shape, which is why the
//! unloaded-driver table (`tamper_unloaded`) is read first and offered as the
//! second source for exactly these addresses.
//!
//! # The two table shapes, measured
//!
//! Across the **1,724** `ntkrnlmp.pdb` ISFs on this machine the two shapes are
//! **exactly complementary** — no ISF declares both:
//!
//! | Shape | ISFs | How the table is reached |
//! |---|---:|---|
//! | Per-processor | **1,233** | `_KPRCB.TimerTable`, an embedded `_KTIMER_TABLE` (embedded in all 1,233; never a pointer) |
//! | Legacy global | **427** | the `KiTimerTableListHead` symbol, an array of `_KTIMER_TABLE_ENTRY` whose length nothing declares |
//! | Neither | **64** | the group does not run, and says which symbols were absent |
//!
//! `KiProcessorBlock` and `KeNumberProcessors` are declared in **all 1,724**.
//!
//! # The bucket count is the product of the declared dimensions
//!
//! `_KTIMER_TABLE.TimerEntries` is declared `[2][256]` on Windows 11 build
//! 26200 and `[256]` on every one of the 1,233 older ISFs that declare the
//! type. **512 buckets against 256 is not a rounding error**: a reader that
//! took the outer dimension would walk 2 of 512 buckets on the newer build,
//! find real timers in both, and produce a result with nothing about it
//! looking wrong. The count therefore comes from
//! [`seance_memory::object::ArrayShape`], which multiplies every dimension, and
//! the dimensions themselves are on the record.
//!
//! # `_KTIMER.Dpc` is encoded on x64, and is decoded and checked
//!
//! On an x64 build that declares `KiWaitNever` and `KiWaitAlways` (1,059 of
//! the 3,015 kernel ISFs in the pack; 70 x86 ISFs declare them too) the timer
//! does not hold its `_KDPC` pointer as declared. Until `MEM-052` the walk
//! read the field as a pointer: on Case 001's Server 2012 R2 capture that
//! panicked adding a member offset to it, and on every such build it published
//! the encoded value as a DPC address with no routine read — so the "0
//! routines outside a module" baselines on those builds measured nothing.
//! [`DpcEncoding`] states the decode, its published sources, and the check
//! every decoded pointer must pass. Every address computed from an evidence
//! value in this module is checked arithmetic.
//!
//! # `DueTime` is not reported, and that is deliberate
//!
//! `_KTIMER.DueTime` is declared on every build that declares `_KTIMER`, and
//! its encoding on modern x64 is not established by any source in this tree:
//! `KiWaitNever` and `KiWaitAlways` — the two globals an obfuscation of that
//! field would use — are declared on the Windows 11 26200 ISF and on most of
//! the pack. Trying transforms until the output looks like a plausible date is
//! fabrication, so the field is **not published in any form** and the record
//! says so. [`TimerTable::to_json`] carries that sentence, and a test fails if
//! a `due_time` ever appears on a record.
//!
//! The adjacent member was assessed rather than ignored:
//! `_KTIMER_TABLE_ENTRY.Time` is declared wherever the entry type is (1,556 of
//! the ISFs that declare it), it is the **bucket's** own time and not the
//! timer's, and it is published as the raw number it is with no epoch claimed.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_memory::object::{ArrayShape, ListSpec, ListStop, StructReader};
use serde_json::{json, Value};

use crate::kernel_hooks::{ModuleMap, Ownership};
use crate::profile::WindowsProfile;
use crate::tamper::{DpcKeySymbols, TamperError, TimerSymbols};

/// Processor slots this build will read.
///
/// Windows' own architectural ceiling is 2,048 logical processors. A declared
/// or read count above it is refused rather than clamped: such a number is
/// wrong, not merely large.
pub const MAX_PROCESSORS: u64 = 2048;

/// Buckets one table may declare.
///
/// The largest real declaration measured is 512. A symbol file declaring more
/// than this is refused, because the count is attacker-controlled the moment a
/// pack comes from outside the lab.
pub const MAX_BUCKETS: u64 = 4096;

/// Entries one bucket's list walk will return.
///
/// A bucket holds a handful of timers on a real machine. This is a ceiling on
/// a corrupt chain, and reaching it is reported as a cap.
pub const MAX_PER_BUCKET: usize = 4096;

/// Where each field sits, as this build declares it.
///
/// Every offset is resolved from the symbol table. Nothing here is a constant:
/// `_KTIMER_TABLE_ENTRY.Entry` is at offset 8 on 830 of the ISFs measured, at
/// 4 on 403, and at **0** on 323 — so a hardcoded 8 would read the lock word
/// as a list head on a fifth of the builds in the pack.
#[derive(Debug, Clone)]
pub struct TimerLayout {
    /// How the table is reached.
    pub shape: TableShape,
    /// `_KTIMER_TABLE_ENTRY` size, and where its list head and time sit.
    pub entry_size: u64,
    pub entry_list_offset: u64,
    pub entry_time_offset: Option<u64>,
    /// Whether the bucket is a declared `_KTIMER_TABLE_ENTRY` or, on NT 5.1,
    /// a bare `_LIST_ENTRY` head — see [`BucketEntry`].
    pub entry: BucketEntry,
    /// `_KTIMER` members.
    pub timer_size: u64,
    pub timer_list_entry: u64,
    pub timer_dpc: u64,
    pub timer_period: Option<u64>,
    /// `_KDPC` members.
    pub dpc_routine: u64,
    pub dpc_context: Option<u64>,
    pub pointer: usize,
}

/// What one bucket of the table is.
///
/// Every build that declares `_KPRCB.TimerTable` also declares
/// `_KTIMER_TABLE_ENTRY`. The NT 5.1 kernels do not declare the entry type at
/// all — XP SP2's `ntkrnlpa.pdb` (`BD8F451F3E754ED8A34B50560CEB08E3-1`) has
/// `KiTimerTableListHead` and no `_KTIMER_TABLE_ENTRY` — because on them each
/// bucket IS the list head. Measured 2026-09-24 on the Malware Cookbook's XP
/// SP2 captures, which the group refused outright until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketEntry {
    /// `_KTIMER_TABLE_ENTRY`, with its declared size and member offsets.
    Declared,
    /// A bare `_LIST_ENTRY`: the stride is that type's declared size and the
    /// head sits at offset 0. Used only for the legacy global table on a build
    /// that declares no entry type, and checked by the evidence: the extent
    /// probe accepts a bucket only when it is a self-referential head or one
    /// whose first link points back at it, so a wrong stride fails at bucket 1.
    BareListHead,
}

impl BucketEntry {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared_ktimer_table_entry",
            Self::BareListHead => "bare_list_entry",
        }
    }

    fn basis(self) -> &'static str {
        match self {
            Self::Declared => {
                "Each bucket is this build's declared `_KTIMER_TABLE_ENTRY`: the stride is its \
                 size and the list head is its `Entry` member."
            }
            Self::BareListHead => {
                "This build declares no `_KTIMER_TABLE_ENTRY` (the NT 5.1 kernels do not), so \
                 each bucket of `KiTimerTableListHead` is a bare `_LIST_ENTRY` head: the stride \
                 is `_LIST_ENTRY`'s declared size, the head is at offset 0, and there is no \
                 bucket time. The evidence checks the stride: the extent probe accepts a bucket \
                 only if it is a self-referential head or one whose first link points back at \
                 it, so a wrong stride would stop the table at its first bucket."
            }
        }
    }
}

/// Which of the two shapes this build has.
#[derive(Debug, Clone)]
pub enum TableShape {
    /// `_KPRCB.TimerTable`, with the bucket count the symbols declare.
    PerProcessor {
        table_offset: u64,
        entries_offset: u64,
        buckets: u64,
        /// The declared dimensions, so the record can say `[2][256]` rather
        /// than only `512`.
        dims: Vec<u64>,
    },
    /// The `KiTimerTableListHead` global. **Nothing declares its length**, so
    /// the extent is derived from the evidence — see [`probe_legacy_extent`].
    LegacyGlobal { head: u64 },
}

impl TableShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PerProcessor { .. } => "per_processor",
            Self::LegacyGlobal { .. } => "legacy_global",
        }
    }
}

impl TimerLayout {
    /// Resolve every offset the walk needs, or say which member was absent.
    ///
    /// # Errors
    ///
    /// [`TamperError::Unsupported`] naming the member, for a build that
    /// declares neither table shape or lacks `_KTIMER` / `_KDPC`.
    pub fn resolve(reader: &StructReader, symbols: &TimerSymbols) -> Result<Self, TamperError> {
        let pointer = reader.pointer_size().unwrap_or(8) as usize;
        let offset = |ty: &str, member: &str| -> Result<u64, TamperError> {
            reader
                .member_offset(ty, member)
                .map(|o| o.bytes())
                .map_err(|e| {
                    TamperError::unsupported(format!(
                        "this build does not declare `{ty}.{member}`, which the timer walk reads: \
                         {e}. Without it a timer's own fields cannot be read, so no DPC routine \
                         can be recovered and nothing is said about what the kernel would call."
                    ))
                })
        };
        let timer_size = reader
            .size_of("_KTIMER")
            .map(|s| s.bytes())
            .map_err(|e| TamperError::unsupported(format!("no `_KTIMER` on this build: {e}")))?;
        let timer_list_entry = offset("_KTIMER", "TimerListEntry")?;
        let timer_dpc = offset("_KTIMER", "Dpc")?;
        let timer_period = reader
            .member_offset("_KTIMER", "Period")
            .ok()
            .map(|o| o.bytes());
        let dpc_routine = offset("_KDPC", "DeferredRoutine")?;
        let dpc_context = reader
            .member_offset("_KDPC", "DeferredContext")
            .ok()
            .map(|o| o.bytes());

        // The two shapes, in the order the measurement found them. They are
        // complementary across the whole pack, so this is not a preference: a
        // build has one or the other.
        let shape = if reader.has_member("_KPRCB", "TimerTable") {
            let table_offset = offset("_KPRCB", "TimerTable")?;
            let entries = reader
                .array_shape_capped("_KTIMER_TABLE", "TimerEntries", MAX_BUCKETS)
                .map_err(|e| {
                    TamperError::unsupported(format!(
                        "this build declares `_KPRCB.TimerTable` and its `TimerEntries` array \
                         could not be resolved: {e}. The bucket count must come from the declared \
                         dimensions, and a walk of a guessed count is a walk of a fraction of the \
                         table with nothing to show that it was."
                    ))
                })?;
            let ArrayShape {
                dims,
                total,
                offset: entries_offset,
                ..
            } = entries;
            TableShape::PerProcessor {
                table_offset,
                entries_offset,
                buckets: total,
                dims,
            }
        } else if let Some(head) = symbols.legacy_table_head {
            TableShape::LegacyGlobal { head }
        } else {
            return Err(TamperError::unsupported(
                "this build declares neither `_KPRCB.TimerTable` nor the `KiTimerTableListHead` \
                 symbol. 64 of the 1,724 ntkrnlmp ISFs measured on this machine are in that \
                 state; on such a build no timer table can be located at all, so a timer whose \
                 DPC routine points outside every loaded module cannot be found and this group \
                 establishes nothing."
                    .to_string(),
            ));
        };

        // The bucket. A declared `_KTIMER_TABLE_ENTRY` is always preferred;
        // only the legacy global table on a build declaring no entry type
        // (NT 5.1) falls to the bare list head, whose stride and head offset
        // still come from this build's own `_LIST_ENTRY`.
        let declared_entry = reader.size_of("_KTIMER_TABLE_ENTRY").map(|s| s.bytes());
        let (entry, entry_size, entry_list_offset, entry_time_offset) =
            match (declared_entry, &shape) {
                (Ok(size), _) => (
                    BucketEntry::Declared,
                    size,
                    offset("_KTIMER_TABLE_ENTRY", "Entry")?,
                    reader
                        .member_offset("_KTIMER_TABLE_ENTRY", "Time")
                        .ok()
                        .map(|o| o.bytes()),
                ),
                (Err(_), TableShape::LegacyGlobal { .. }) => {
                    let size = reader
                        .size_of("_LIST_ENTRY")
                        .map(|s| s.bytes())
                        .map_err(|e| {
                            TamperError::unsupported(format!(
                                "this build declares neither `_KTIMER_TABLE_ENTRY` nor \
                                 `_LIST_ENTRY`: {e}. The bucket stride of the legacy table is \
                                 one of those sizes, and a guessed stride reads the middle of \
                                 one bucket as the head of the next."
                            ))
                        })?;
                    (BucketEntry::BareListHead, size, 0, None)
                }
                (Err(e), TableShape::PerProcessor { .. }) => {
                    return Err(TamperError::unsupported(format!(
                        "this build does not declare `_KTIMER_TABLE_ENTRY`: {e}. The bucket \
                         stride is that type's size, and a guessed stride reads the middle of \
                         one bucket as the head of the next."
                    )))
                }
            };

        Ok(Self {
            shape,
            entry,
            entry_size,
            entry_list_offset,
            entry_time_offset,
            timer_size,
            timer_list_entry,
            timer_dpc,
            timer_period,
            dpc_routine,
            dpc_context,
            pointer,
        })
    }

    pub fn to_json(&self) -> Value {
        let (buckets, dims) = match &self.shape {
            TableShape::PerProcessor { buckets, dims, .. } => (Some(*buckets), Some(dims.clone())),
            TableShape::LegacyGlobal { .. } => (None, None),
        };
        json!({
            "shape": self.shape.as_str(),
            "buckets_declared": buckets,
            "bucket_dimensions": dims,
            "bucket_dimensions_note":
                "`_KTIMER_TABLE.TimerEntries` is declared [2][256] on Windows 11 build 26200 and \
                 [256] on the 1,233 older ISFs measured. The bucket count is the PRODUCT of the \
                 declared dimensions; taking the outer one would walk 2 of 512 buckets and find \
                 real timers in both.",
            "entry": self.entry.as_str(),
            "entry_basis": self.entry.basis(),
            "entry_size": self.entry_size,
            "entry_list_offset": self.entry_list_offset,
            "entry_time_offset": self.entry_time_offset,
            "timer_list_entry_offset": self.timer_list_entry,
            "timer_dpc_offset": self.timer_dpc,
            "timer_period_offset": self.timer_period,
            "dpc_routine_offset": self.dpc_routine,
            "dpc_context_offset": self.dpc_context,
            "offsets_basis":
                "Every offset here was resolved from this build's own symbol table. \
                 `_KTIMER_TABLE_ENTRY.Entry` sits at 8 on 830 of the ISFs measured, at 4 on 403 \
                 and at 0 on 323, so a constant would read a lock word as a list head on a fifth \
                 of them.",
        })
    }
}

/// One timer, as read.
#[derive(Debug, Clone)]
pub struct TimerRecord {
    /// Which processor's table it was in. `None` for the legacy global table,
    /// which is not per-processor.
    pub processor: Option<u64>,
    pub bucket: u64,
    /// Address of the `_KTIMER`, recovered by `CONTAINING_RECORD` from the list
    /// link — never the link address itself.
    pub timer: u64,
    pub period_ms: Option<u32>,
    /// The `_KDPC` address. `None` when the timer carries no DPC, which is the
    /// ordinary case.
    pub dpc: Option<u64>,
    pub routine: Option<u64>,
    pub context: Option<u64>,
    /// What the loaded-module map says about the routine.
    pub ownership: Option<Ownership>,
    /// The bucket's own `Time` member, as read. See the module comment: this is
    /// the bucket's time and not the timer's `DueTime`, and no epoch is claimed
    /// for it.
    pub bucket_time_raw: Option<u64>,
    /// `_KTIMER.Dpc` exactly as read, when it was non-zero. On an x64 build
    /// that encodes it this is NOT an address; [`Self::dpc`] is what it
    /// decoded to.
    pub dpc_field_raw: Option<u64>,
    /// Why a non-zero `Dpc` field could not be turned into a `_KDPC` that was
    /// read, when it could not (`MEM-052`).
    pub dpc_unreadable: Option<String>,
    /// The build's pointer width in bytes, from its own symbols: what the
    /// alignment and canonicality tests of [`Self::patchguard_shaped`] are
    /// measured against.
    pub pointer_size: u8,
    /// Every `(processor, bucket)` whose list reached this `_KTIMER`, in the
    /// order the walk reached them. The first is [`Self::processor`] /
    /// [`Self::bucket`]; a timer reached from more than one list is still one
    /// row (`MEM-055`).
    pub reached_from: Vec<(Option<u64>, u64)>,
    /// Why this timer was reached from more than one list, when the walk's own
    /// evidence establishes it, or the sentence saying it does not. `None` for
    /// a timer reached once.
    pub reached_more_than_once_reason: Option<String>,
}

impl TimerRecord {
    /// Whether this row is the signal: a routine the kernel would call that
    /// lands in no loaded module.
    ///
    /// **Only when the module map is authoritative.** An `Undetermined`
    /// ownership means the map could not answer, and reporting that as "outside
    /// every module" would manufacture a rootkit out of an incomplete
    /// acquisition.
    ///
    /// A row with PatchGuard's shape ([`Self::patchguard_shaped`]) is not the
    /// signal: it is published, named and counted on its own (`MEM-054`).
    pub fn is_signal(&self) -> bool {
        self.routine_outside_any_module() && !self.patchguard_shaped()
    }

    fn routine_outside_any_module(&self) -> bool {
        self.ownership
            .as_ref()
            .is_some_and(Ownership::is_outside_any_module)
    }

    /// Whether this row has the shape of PatchGuard's own timer (`MEM-054`,
    /// owner decision 2026-09-26): **all three** of
    ///
    /// 1. the `_KTIMER` address is not aligned to the build's pointer width;
    /// 2. the routine lands in no loaded module, on an authoritative map;
    /// 3. `DeferredContext` is not a canonical address for the build.
    ///
    /// The conjunction is the rule, because any one condition alone is too
    /// broad: an unloaded driver or a pool thunk gives (2), and a context
    /// that is a plain integer gives (3). It is a **shape, not an
    /// identification** — a rootkit can imitate it — so the row is published
    /// ungraded and counted separately, never suppressed.
    ///
    /// Measured on DFIR Madness Case 001's desktop (Windows 10): the one timer
    /// outside every module is at 0xffffbe8e7105d5ab with its `_KDPC` at
    /// +0x40 and `DeferredContext` 0x5a474314a0a22080.
    pub fn patchguard_shaped(&self) -> bool {
        let width = u64::from(self.pointer_size.max(1));
        let unaligned = !self.timer.is_multiple_of(width);
        let context_non_canonical = self
            .context
            .is_some_and(|c| !seance_memory::object::is_canonical(c, self.pointer_size));
        unaligned && context_non_canonical && self.routine_outside_any_module()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryKernelTimer",
            "name": match (&self.routine, &self.dpc) {
                (Some(routine), _) => format!("timer at {:#018x} -> {routine:#018x}", self.timer),
                (None, _) => format!("timer at {:#018x}, no DPC", self.timer),
            },
            "processor": self.processor,
            "bucket": self.bucket,
            "timer_address": format!("{:#018x}", self.timer),
            "period_ms": self.period_ms,
            "periodic": self.period_ms.map(|p| p > 0),
            "dpc_address": self.dpc.map(|d| format!("{d:#018x}")),
            "dpc_field_raw": self.dpc_field_raw.map(|d| format!("{d:#018x}")),
            "dpc_unreadable": self.dpc_unreadable,
            "deferred_routine": self.routine.map(|r| format!("{r:#018x}")),
            "deferred_context": self.context.map(|c| format!("{c:#018x}")),
            "routine_ownership": self.ownership.as_ref().map(Ownership::to_json),
            "no_dpc_note": (self.dpc.is_none() && self.dpc_unreadable.is_none()).then_some(
                "This timer carries no DPC, which is ordinary: most timers signal an event and \
                 name no routine. It is not a finding, and a rule that flagged it would fire \
                 thousands of times on a clean machine."
            ),
            "is_signal": self.is_signal(),
            "patchguard_shaped": self.patchguard_shaped(),
            "patchguard_shape_basis": self.patchguard_shaped().then_some(PATCHGUARD_SHAPE_BASIS),
            "signal_basis":
                "A row is a signal only when the routine lands in NO loaded module AND the \
                 loaded-module list was complete enough for that to be a statement about the \
                 machine, AND the row does not have PatchGuard's shape (an unaligned `_KTIMER`, \
                 a routine in no module and a non-canonical `DeferredContext`, all three): such \
                 a row is published ungraded with `patchguard_shaped: true` and its own basis. \
                 A signal is not a verdict: a driver that has since unloaded, a hot patch and a \
                 pool-allocated thunk all produce it, which is why the unloaded-driver table is \
                 offered as a second source for these addresses -- for graded and \
                 PatchGuard-shaped rows alike.",
            "reached_from": self.reached_from.iter()
                .map(|(processor, bucket)| json!({"processor": processor, "bucket": bucket}))
                .collect::<Vec<_>>(),
            "reached_more_than_once_reason": self.reached_more_than_once_reason,
            "bucket_time_raw": self.bucket_time_raw,
            "bucket_time_note": self.bucket_time_raw.map(|_| BUCKET_TIME_NOTE),
            "due_time_note": DUE_TIME_NOTE,
        })
    }
}

/// What a PatchGuard-shaped row is, and is not (`MEM-054`).
pub const PATCHGUARD_SHAPE_BASIS: &str =
    "This timer has the shape of PatchGuard's own timer: its `_KTIMER` is not aligned to the \
     pointer width, its routine lands in no loaded module on a complete module list, and its \
     `DeferredContext` is not a canonical address. All three hold; any one alone is not \
     enough. It is published and NOT graded: this is a shape, not an identification, and a \
     rootkit could imitate it, which is why the row stays on the record with every value as \
     read rather than being dropped, and why its routine is still offered to the \
     unloaded-driver cross-reference exactly as a graded row's is. The rule has not been \
     tested against a timer rootkit imitating the shape.";

/// Why no `DueTime` appears on any record.
pub const DUE_TIME_NOTE: &str =
    "`_KTIMER.DueTime` is declared on this build and is NOT reported, in any form. Its encoding \
     on modern x64 is not established by any source in this tree -- `KiWaitNever` and \
     `KiWaitAlways`, the globals an obfuscation of that field would use, are declared on the \
     builds measured -- and trying transforms until the output looks like a plausible date is \
     fabrication. The forensic value of a timer is its DPC routine, which does not depend on it.";

/// What the bucket's own `Time` member is, and is not.
pub const BUCKET_TIME_NOTE: &str =
    "This is `_KTIMER_TABLE_ENTRY.Time`, the BUCKET's own time member, read as the raw number it \
     holds. It is not this timer's `DueTime` and no epoch is claimed for it: it is published so \
     that an examiner can see what was there rather than being told a date this build cannot \
     establish.";

/// What one walk of the tables produced.
#[derive(Debug, Clone)]
pub struct TimerTable {
    pub layout: TimerLayout,
    /// Processors whose table was walked, and the count the kernel claimed.
    pub processors_walked: u64,
    pub processors_claimed: Option<u64>,
    /// Why the claimed count was not used, when it was not.
    pub processor_count_note: Option<String>,
    /// Buckets actually walked, summed over processors.
    pub buckets_walked: u64,
    pub timers: Vec<TimerRecord>,
    /// Sightings: every list item the bucket walks reached, counting a timer
    /// reached from two lists twice (`MEM-055`), including the one a cap fired on.
    pub timers_total: u64,
    pub notes: Vec<String>,
    pub capped: Option<String>,
    /// How this build stores `_KTIMER.Dpc`, and whether it could be decoded.
    pub dpc_encoding: DpcEncoding,
    /// Legacy-table list items skipped because their dispatcher header is not a timer's
    /// (`MEM-059`): a torn list that ran into memory that is no `_KTIMER`.
    pub not_timers: u64,
}

impl TimerTable {
    /// Rows where the routine lands in no loaded module.
    pub fn signals(&self) -> usize {
        self.timers.iter().filter(|t| t.is_signal()).count()
    }

    /// `(what, routine)` pairs offered to the unloaded-driver cross-reference:
    /// every graded row, and every PatchGuard-shaped row too. Not grading the
    /// shape must not also hide its routine from the check that would name an
    /// unloaded driver whose range holds it, or a rootkit that imitated the
    /// shape would escape both. A shaped row's pair says it is one.
    pub fn unloaded_cross_reference_candidates(&self) -> Vec<(String, u64)> {
        self.timers
            .iter()
            .filter(|t| t.is_signal() || t.patchguard_shaped())
            .filter_map(|row| {
                let kind = if row.patchguard_shaped() {
                    "a PatchGuard-shaped timer's DPC routine, published ungraded"
                } else {
                    "a timer's DPC routine"
                };
                row.routine.map(|routine| {
                    (
                        format!("{kind} (timer {:#018x}, bucket {})", row.timer, row.bucket),
                        routine,
                    )
                })
            })
            .collect()
    }

    /// Rows with PatchGuard's shape, published and not graded (`MEM-054`).
    pub fn patchguard_shaped(&self) -> usize {
        self.timers.iter().filter(|t| t.patchguard_shaped()).count()
    }

    /// Timers carrying a DPC that was located: a `_KDPC` address this walk
    /// could read through.
    pub fn with_dpc(&self) -> usize {
        self.timers.iter().filter(|t| t.dpc.is_some()).count()
    }

    /// Timers whose non-zero `Dpc` field could not be turned into a `_KDPC`.
    pub fn dpc_unreadable(&self) -> usize {
        self.timers
            .iter()
            .filter(|t| t.dpc_unreadable.is_some())
            .count()
    }

    /// Timers whose `Dpc` field was decoded and verified.
    pub fn dpc_decoded(&self) -> usize {
        if !matches!(self.dpc_encoding, DpcEncoding::Decoded { .. }) {
            return 0;
        }
        self.with_dpc()
    }

    /// Every sighting of every timer: the rows the bucket walks produced
    /// before they were de-duplicated by `_KTIMER` address (`MEM-055`).
    pub fn rows_walked(&self) -> usize {
        self.timers.iter().map(|t| t.reached_from.len()).sum()
    }

    /// Timers reached from more than one bucket list.
    pub fn reached_more_than_once(&self) -> usize {
        self.timers
            .iter()
            .filter(|t| t.reached_from.len() > 1)
            .count()
    }

    /// The sentence a record carries.
    pub fn describe(&self) -> String {
        format!(
            "{} distinct timer(s) were read from {} bucket(s) across {} processor table(s), \
             from {} row(s) walked: {} timer(s) were reached from more than one bucket list and \
             each is reported once, with every place it was reached in `reached_from` \
             (`MEM-055`). Every count here is of distinct timers. {} carry a DPC \
             that was located and {} of those routines land in no loaded module and are graded; \
             {} more have the shape of PatchGuard's own timer and are published ungraded \
             (see `patchguard_shape_basis` on each row). {} carry a DPC \
             field that could not be turned into a readable `_KDPC` (see `dpc_unreadable` on each \
             row): nothing is said about where those would call. A timer with no DPC is \
             ordinary. No due time is reported for any of them -- see `due_time_note`.",
            self.timers.len(),
            self.buckets_walked,
            self.processors_walked,
            self.rows_walked(),
            self.reached_more_than_once(),
            self.with_dpc(),
            self.signals(),
            self.patchguard_shaped(),
            self.dpc_unreadable()
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "layout": self.layout.to_json(),
            "processors_walked": self.processors_walked,
            "processors_claimed": self.processors_claimed,
            "processor_count_note": self.processor_count_note,
            "buckets_walked": self.buckets_walked,
            "timers": self.timers.iter().map(TimerRecord::to_json).collect::<Vec<_>>(),
            "timers_reported": self.timers.len(),
            "rows_walked": self.rows_walked(),
            "timers_reached_more_than_once": self.reached_more_than_once(),
            "items_not_timers": self.not_timers,
            "timers_reported_basis":
                "`timers_reported` and every count beside it are DISTINCT `_KTIMER`s: a timer \
                 reached from more than one bucket list is one row, with each place it was \
                 reached in its `reached_from`. `rows_walked` is every sighting before that \
                 de-duplication, and `timers_total` counts sightings too (`MEM-055`).",
            "timers_total": self.timers_total,
            "timers_with_a_dpc": self.with_dpc(),
            "dpc_encoding": self.dpc_encoding.to_json(),
            "dpc_pointers_decoded": self.dpc_decoded(),
            "dpc_unreadable": self.dpc_unreadable(),
            "routines_outside_any_module": self.signals(),
            "patchguard_shaped": self.patchguard_shaped(),
            "statement": self.describe(),
            "due_time_note": DUE_TIME_NOTE,
            "notes": self.notes,
            "content_incomplete": self.capped.is_some(),
            "content_incomplete_reason": self
                .capped
                .as_ref()
                .map(|_| seance_core::io::IncompleteReason::CapReached.as_str()),
            "cap_detail": self.capped,
        })
    }
}

/// How many processors to read, and what to say about the number.
///
/// `KeNumberProcessors` carries **no declared type** in any of the 1,724 ISFs
/// measured — only an address — so its width cannot be read from the symbols.
/// It is read as four bytes and then **validated**, because a count is the loop
/// bound and a wrong one is either a walk of one processor's table on a
/// 32-processor machine or a walk of four billion.
///
/// The validation is the evidence rather than the number: each `_KPRCB` pointer
/// is read, and a slot that is null or outside kernel space ends the walk. On
/// the smeared Lone Wolf and Magnet 2020 captures `KeNumberProcessors` reads 0,
/// which is why a claimed count of zero is not the end of it.
fn processor_slots(
    reader: &StructReader,
    symbols: &TimerSymbols,
) -> (Vec<u64>, Option<u64>, Option<String>) {
    let mut claimed_bytes = [0u8; 4];
    let claimed = reader
        .read_into(symbols.processor_count, &mut claimed_bytes)
        .ok()
        .map(|()| u32::from_le_bytes(claimed_bytes) as u64);

    // The array is probed regardless of the claim, and the two are compared.
    let pointer = reader.pointer_size().unwrap_or(8) as u64;
    let mut slots: Vec<u64> = Vec::new();
    for index in 0..MAX_PROCESSORS {
        let Some(at) = index
            .checked_mul(pointer)
            .and_then(|o| symbols.prcb_array.checked_add(o))
        else {
            break;
        };
        let Ok(prcb) = reader.read_pointer_at(at) else {
            break;
        };
        if prcb == 0 || !seance_memory::object::is_canonical(prcb, pointer as u8) {
            break;
        }
        slots.push(prcb);
    }

    let note = match claimed {
        Some(count) if count as usize == slots.len() => None,
        Some(count) => Some(format!(
            "`KeNumberProcessors` reads {count} and the `KiProcessorBlock` array holds {} usable \
             pointer(s). The array is what was walked: the count carries no declared type in any \
             ISF measured, so its width is not knowable from the symbols, and on the smeared \
             captures in this corpus it reads 0 on machines that plainly had processors.",
            slots.len()
        )),
        None => Some(format!(
            "`KeNumberProcessors` could not be read; the `KiProcessorBlock` array was probed \
             instead and holds {} usable pointer(s).",
            slots.len()
        )),
    };
    (slots, claimed, note)
}

/// Derive how far the legacy global table extends.
///
/// **Nothing declares its length.** `KiTimerTableListHead` is an untyped symbol
/// in all 427 ISFs that have it, and the documented constant (256 before
/// Windows Vista, 512 after) is not a source this tree can cite. So the extent
/// is taken from the evidence: a `_LIST_ENTRY` bucket head in a live kernel is
/// always initialised, so it either points at itself (empty) or at a link whose
/// own `Blink` points back at the head. The probe stops at the first entry that
/// is not a list head at all, the extent ends at the last well-formed head
/// before it, and the derived count goes on the record.
///
/// **The probe alone overshoots on real bytes.** On XP SP2 and SP3 the 256
/// buckets are followed directly by `KiDispatcherReadyListHead`, 32 more
/// `_LIST_ENTRY` heads that are self-referential when empty, so a heads-only
/// probe derived 288 on every capture measured (2026-09-24). `limit` is the
/// bound the symbol table supplies — the distance to the next symbol this build
/// declares — and the probe never walks past it.
///
/// **A torn head is not the end of the table** (`MEM-058`, found 2026-09-27 on
/// the Cookbook's `prolaco.vmem`). A capture taken while the kernel was
/// relinking timers can hold a bucket head whose first link's `Blink` names a
/// different bucket. When the symbol table bounds the array (`bounded`), such a
/// head is counted as a bucket if a well-formed head follows it inside the
/// bound, and its index is returned so the record can name it. Without a bound
/// nothing but the bytes says where the array ends, so a torn head still ends
/// the probe.
///
/// A torn run that **no** well-formed head follows inside the bound (it runs
/// to the bound, or into something that is not a head) is not counted: the
/// bytes do not show the table reaches it. It is returned as the third value
/// so the record names it -- those heads may be real buckets whose timers were
/// not reached -- and so a list that runs into one of them stops there.
fn probe_legacy_extent(
    reader: &StructReader,
    head: u64,
    layout: &TimerLayout,
    limit: u64,
    bounded: bool,
) -> (u64, Vec<u64>, Vec<u64>) {
    let mut buckets = 0u64;
    let mut torn: Vec<u64> = Vec::new();
    let mut pending: Vec<u64> = Vec::new();
    let mut index = 0u64;
    while index < limit.min(MAX_BUCKETS) {
        match classify_legacy_head(reader, head, layout, index) {
            LegacyHead::WellFormed => {
                torn.append(&mut pending);
                buckets = index + 1;
            }
            LegacyHead::Torn if bounded => pending.push(index),
            LegacyHead::Torn | LegacyHead::NotAHead => break,
        }
        index += 1;
    }
    (buckets, torn, pending)
}

/// What one slot of the legacy table holds.
enum LegacyHead {
    /// Self-referential, or its first link points back at it.
    WellFormed,
    /// A canonical first link whose readable `Blink` names somewhere else.
    Torn,
    /// Not a list head: null, non-canonical, unreadable, or past the top of
    /// the address space.
    NotAHead,
}

fn classify_legacy_head(
    reader: &StructReader,
    head: u64,
    layout: &TimerLayout,
    index: u64,
) -> LegacyHead {
    // Checked: `head` is a symbol, but every step past it is arithmetic on a
    // count the evidence drives (`MEM-052`).
    let Some(at) = index
        .checked_mul(layout.entry_size)
        .and_then(|o| head.checked_add(o))
        .and_then(|a| a.checked_add(layout.entry_list_offset))
    else {
        return LegacyHead::NotAHead;
    };
    let Ok(flink) = reader.read_pointer_at(at) else {
        return LegacyHead::NotAHead;
    };
    if flink == at {
        // An empty bucket, initialised to point at itself.
        return LegacyHead::WellFormed;
    }
    if flink == 0 || !seance_memory::object::is_canonical(flink, layout.pointer as u8) {
        return LegacyHead::NotAHead;
    }
    // A populated bucket: the first link's `Blink` must point back here.
    // `flink` is a value read from the image: a canonical link at the top of
    // the address space has no `Blink` after it.
    let Some(blink_at) = flink.checked_add(layout.pointer as u64) else {
        return LegacyHead::NotAHead;
    };
    let Ok(blink) = reader.read_pointer_at(blink_at) else {
        return LegacyHead::NotAHead;
    };
    if blink == at {
        LegacyHead::WellFormed
    } else {
        LegacyHead::Torn
    }
}

/// The next symbol this build declares above the legacy table, and how many
/// bytes away it is.
///
/// A global array cannot run into the next global, so this is an upper bound
/// on the table's extent taken from the build's own symbol table rather than
/// from a constant. `None` when the head has no symbol entry or nothing is
/// declared above it; the probe then decides alone, and the record says so.
fn next_symbol_above(reader: &StructReader) -> Option<(String, u64)> {
    let table = reader.symbols();
    let head = table.symbol_address(LEGACY_HEAD_SYMBOL).ok()?;
    table
        .symbols()
        .iter()
        .filter_map(|entry| {
            let at = table.symbol_address(&entry.name).ok()?;
            (at > head).then(|| (at - head, entry.name.to_string()))
        })
        .min()
        .map(|(distance, name)| (name, distance))
}

/// `_DISPATCHER_HEADER.Type` of a notification timer and of a synchronisation timer.
const TIMER_NOTIFICATION: u64 = 8;
const TIMER_SYNCHRONIZATION: u64 = 9;

/// The legacy table's symbol.
const LEGACY_HEAD_SYMBOL: &str = "KiTimerTableListHead";

/// The kernel variable holding the legacy table's bucket count, where a build declares it.
const LEGACY_SIZE_SYMBOL: &str = "KiTimerTableSize";

/// The bucket count the kernel itself keeps in `KiTimerTableSize`, when this build declares the
/// variable, the image holds a plausible value in it, and the table it describes fits in the room
/// the symbol table leaves above the head (`limit` buckets). `None` otherwise, and the extent is
/// derived from the heads instead.
fn declared_table_size(profile: &WindowsProfile, limit: u64) -> Option<u64> {
    let at = profile
        .kernel_base
        .value
        .checked_add(profile.symbols.symbol_address(LEGACY_SIZE_SYMBOL).ok()?)?;
    let mut raw = [0u8; 4];
    seance_core::io::read_exact_or_fail(
        profile.kernel_space.as_data_source(),
        at,
        &mut raw,
        "KiTimerTableSize",
    )
    .ok()?;
    let count = u64::from(u32::from_le_bytes(raw));
    // A power of two between 2 and the cap, and no more than the room the next symbol leaves: the
    // two documented sizes are 256 and 512, and a value that is neither a count nor fits is the
    // bytes of something else.
    (count.is_power_of_two() && count >= 2 && count <= limit.min(MAX_BUCKETS)).then_some(count)
}

/// With the extent given by the kernel, the buckets whose heads are not well-formed: named, still
/// counted, still walked from their heads.
fn declared_extent_torn_heads(
    reader: &StructReader,
    head: u64,
    layout: &TimerLayout,
    count: u64,
) -> Vec<u64> {
    (0..count)
        .filter(|&i| {
            !matches!(
                classify_legacy_head(reader, head, layout, i),
                LegacyHead::WellFormed
            )
        })
        .collect()
}

/// Walk the timer tables.
///
/// # Errors
///
/// [`TamperError::Unsupported`] when this build declares neither table shape,
/// or lacks a member the walk reads.
pub fn read_timers(
    profile: &WindowsProfile,
    symbols: &TimerSymbols,
    modules: &ModuleMap,
    max_timers: usize,
) -> Result<TimerTable, TamperError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let layout = TimerLayout::resolve(&reader, symbols)?;
    // Torn heads past the last counted legacy bucket (`MEM-058`): not walked,
    // but a list that runs into one stops there, as at any other head.
    let mut trailing_torn_heads: Vec<(u64, u64)> = Vec::new();

    let mut out = TimerTable {
        processors_walked: 0,
        processors_claimed: None,
        processor_count_note: None,
        buckets_walked: 0,
        timers: Vec::new(),
        timers_total: 0,
        notes: Vec::new(),
        capped: None,
        layout: layout.clone(),
        dpc_encoding: DpcEncoding::resolve(&reader, symbols.dpc_keys, layout.pointer),
        not_timers: 0,
    };

    // One (processor, table base) pair per table to walk, and the bucket count
    // for it.
    let tables: Vec<(Option<u64>, u64, u64)> = match &layout.shape {
        TableShape::PerProcessor {
            table_offset,
            entries_offset,
            buckets,
            ..
        } => {
            let (slots, claimed, note) = processor_slots(&reader, symbols);
            out.processors_claimed = claimed;
            out.processor_count_note = note;
            if slots.is_empty() {
                out.notes.push(
                    "the `KiProcessorBlock` array held no usable `_KPRCB` pointer, so no \
                     per-processor timer table could be reached. Nothing is said about this \
                     machine's timers."
                        .to_string(),
                );
            }
            let mut tables = Vec::with_capacity(slots.len());
            // `MEM-055` (i): a slot naming a `_KPRCB` an earlier slot already
            // named is the same table. Walking it again reports every timer
            // in it twice, so it is walked once and the repeat is stated.
            let mut first_slot: BTreeMap<u64, usize> = BTreeMap::new();
            for (i, prcb) in slots.iter().enumerate() {
                if let Some(&first) = first_slot.get(prcb) {
                    out.notes.push(format!(
                        "`KiProcessorBlock` slot {i} holds {prcb:#018x}, the same `_KPRCB` as \
                         slot {first}, so that processor table was walked once and not again: \
                         a second walk would report every timer in it twice (`MEM-055`). Two \
                         processors cannot share a `_KPRCB`, so the array is not as the kernel \
                         wrote it at one instant; slot {i}'s own processor, if it had one, was \
                         not reached and nothing is said about its timers."
                    ));
                    continue;
                }
                first_slot.insert(*prcb, i);
                // `prcb` is a value read from the image (`MEM-052`).
                match prcb
                    .checked_add(*table_offset)
                    .and_then(|a| a.checked_add(*entries_offset))
                {
                    Some(base) => tables.push((Some(i as u64), base, *buckets)),
                    None => out.notes.push(format!(
                        "processor {i}'s `_KPRCB` pointer reads {prcb:#018x}, and its timer \
                         table ({table_offset} + {entries_offset} bytes in) would lie past the top \
                         of the address space, so that pointer is not a `_KPRCB` and its table \
                         was not walked. Nothing is said about that processor's timers."
                    )),
                }
            }
            tables
        }
        TableShape::LegacyGlobal { head } => {
            let bound = next_symbol_above(&reader);
            let limit = bound
                .as_ref()
                .map_or(MAX_BUCKETS, |(_, bytes)| bytes / layout.entry_size.max(1));
            // The kernel's own bucket count, when the build declares the variable and the image holds
            // a value that fits inside the room the symbol table leaves: it is the extent, and a
            // torn head near its end is a bucket the capture caught mid-relink, not the end of the
            // table (`MEM-059`). Otherwise the extent is derived from the heads' shape.
            let kernel_count = declared_table_size(profile, limit);
            let (buckets, torn, trailing) = match kernel_count {
                Some(count) => (
                    count,
                    declared_extent_torn_heads(&reader, *head, &layout, count),
                    Vec::new(),
                ),
                None => probe_legacy_extent(&reader, *head, &layout, limit, bound.is_some()),
            };
            trailing_torn_heads = trailing
                .iter()
                .filter_map(|b| {
                    b.checked_mul(layout.entry_size)
                        .and_then(|o| head.checked_add(o))
                        .and_then(|e| e.checked_add(layout.entry_list_offset))
                        .map(|at| (at, *b))
                })
                .collect();
            let bound_sentence = match &bound {
                Some((name, bytes)) if buckets == limit => format!(
                    "The probe was stopped by the symbol table, not by the bytes: the next symbol \
                     this build declares, `{name}`, starts {bytes} byte(s) above the head, which \
                     is room for {limit} bucket(s), and heads beyond it belong to that symbol."
                ),
                Some((name, bytes)) => format!(
                    "The bytes ended the table before the symbol table's bound: the next symbol \
                     this build declares, `{name}`, starts {bytes} byte(s) above the head, room \
                     for {limit} bucket(s)."
                ),
                None => "No symbol is declared above the head, so nothing bounded the probe but \
                         the bytes themselves."
                    .to_string(),
            };
            let heads_clause = if torn.is_empty() {
                "hold a list head that is either self-referential or whose first link points back \
                 at it"
                    .to_string()
            } else {
                format!(
                    "hold a list head, {} of them torn (named below) and every other one either \
                     self-referential or with a first link that points back at it",
                    torn.len()
                )
            };
            if let Some(count) = kernel_count {
                out.notes.push(format!(
                    "the legacy global timer table's length is the kernel's own: `{LEGACY_SIZE_SYMBOL}` \
                     holds {count} in this image, so {count} bucket(s) at {head:#018x} are walked \
                     whatever their heads look like, and a head that is not well-formed is named \
                     below instead of ending the table (`MEM-059`). {bound_sentence}"
                ));
            } else {
                out.notes.push(format!(
                    "the legacy global timer table's length is declared by nothing, so its extent was \
                     DERIVED from the evidence: {buckets} consecutive bucket(s) at {head:#018x} \
                     {heads_clause}. {bound_sentence} The documented constants are 256 and 512, and this build cites \
                     neither -- the number here is what the image and its symbols support."
                ));
            }
            if !torn.is_empty() {
                let named: Vec<String> = torn.iter().map(|b| format!("bucket {b}")).collect();
                out.notes.push(format!(
                    "{} bucket head(s) inside the table are torn ({}): the head's first link \
                     has a `Blink` that does not point back at it, which is what a capture taken \
                     while the kernel was relinking timers holds. They are counted as buckets, \
                     because well-formed heads follow them inside the bound the symbol table \
                     gives, and each is walked from its head; what a torn bucket's list holds \
                     may be incomplete, and no timer is claimed missing or present because of it \
                     (`MEM-058`).",
                    torn.len(),
                    named.join(", ")
                ));
            }
            if !trailing.is_empty() {
                let named: Vec<String> = trailing.iter().map(|b| format!("bucket {b}")).collect();
                out.notes.push(format!(
                    "the last head(s) read before the table ended are torn and were not walked \
                     ({}): each has a first link whose `Blink` does not point back at it, and no \
                     well-formed head follows them inside the symbol table's bound, so nothing \
                     in the bytes shows the table reaches them and they are not counted as \
                     buckets. They may be real buckets whose timers were not reached; no timer \
                     is claimed missing or present because of them, and a list that runs into \
                     one of their heads stops there (`MEM-058`).",
                    named.join(", ")
                ));
            }
            vec![(None, *head, buckets)]
        }
    };
    out.processors_walked = tables.len() as u64;

    let spec = ListSpec {
        link_type: "_LIST_ENTRY".to_string(),
        forward: "Flink".to_string(),
        container: Some(("_KTIMER".to_string(), "TimerListEntry".to_string())),
        max_entries: MAX_PER_BUCKET,
    };
    let mut stops: BTreeMap<String, u64> = BTreeMap::new();
    // One row per `_KTIMER` (`MEM-055`): the address a timer was first
    // reached at names its row, and each later sighting is added to it.
    let mut rows_by_address: BTreeMap<u64, usize> = BTreeMap::new();
    // Every bucket head in every table walked, so that a list which leads
    // into ANOTHER bucket's head stops there (`MEM-055` (ii)). That head is a
    // `_LIST_ENTRY` inside a `_KTIMER_TABLE_ENTRY`, not a timer; walked on, it
    // was published as a "timer" at `head - TimerListEntry` and the walk
    // ended in a cycle.
    let mut heads: BTreeMap<u64, Place> = BTreeMap::new();
    for (processor, base, buckets) in &tables {
        for bucket in 0..*buckets {
            if let Some(head) = bucket
                .checked_mul(layout.entry_size)
                .and_then(|o| base.checked_add(o))
                .and_then(|e| e.checked_add(layout.entry_list_offset))
            {
                heads.entry(head).or_insert((*processor, bucket));
            }
        }
    }
    for (at, bucket) in &trailing_torn_heads {
        heads.entry(*at).or_insert((None, *bucket));
    }
    // Which bucket's list led into which other bucket's head.
    let mut entered: BTreeMap<Place, Place> = BTreeMap::new();
    let check_header_type = matches!(layout.shape, TableShape::LegacyGlobal { .. })
        && reader.has_member("_KTIMER", "Header");

    'tables: for (processor, base, buckets) in tables {
        for bucket in 0..buckets {
            let Some((entry_at, head)) = bucket
                .checked_mul(layout.entry_size)
                .and_then(|o| base.checked_add(o))
                .and_then(|e| Some((e, e.checked_add(layout.entry_list_offset)?)))
            else {
                out.notes.push(format!(
                    "bucket {bucket} of the table at {base:#018x} would lie past the top of the \
                     address space; the walk of that table stopped there."
                ));
                break;
            };
            out.buckets_walked += 1;
            let bucket_time_raw = layout.entry_time_offset.and_then(|off| {
                let mut buf = [0u8; 8];
                reader
                    .read_into(entry_at.checked_add(off)?, &mut buf)
                    .ok()?;
                Some(u64::from_le_bytes(buf))
            });

            let walk = match reader.walk_list(head, &spec) {
                Ok(walk) => walk,
                Err(e) => {
                    return Err(TamperError::unsupported(format!(
                        "the timer list walk could not be started: {e}"
                    )))
                }
            };
            let mut walked = walk;
            for item in walked.by_ref() {
                let Ok(timer) = item else {
                    // The walk records its own stop reason below; a failed
                    // item is not a timer.
                    break;
                };
                let address = timer.address();
                let here: Place = (processor, bucket);
                if let Some(&other) = address
                    .checked_add(layout.timer_list_entry)
                    .and_then(|link| heads.get(&link))
                    .filter(|other| **other != here)
                {
                    // Not a timer: this list has joined another bucket's,
                    // and the item is that bucket's head.
                    entered.insert(here, other);
                    break;
                }
                // A legacy-table list item is a timer only if its dispatcher header says so:
                // notification (8) or synchronisation (9), the test Volatility applies. A torn list
                // that runs into other memory is stopped there. Where the build declares no
                // `_KTIMER.Header.Type` nothing is checked (`MEM-059`).
                if check_header_type {
                    if let Ok(kind) = timer.unsigned("Header.Type") {
                        if kind != TIMER_NOTIFICATION && kind != TIMER_SYNCHRONIZATION {
                            out.not_timers += 1;
                            continue;
                        }
                    }
                }
                out.timers_total += 1;
                // The cap counts sightings, not distinct timers, so that it
                // bounds the work a corrupt chain can cause and `capped`
                // means what it did before rows were de-duplicated.
                if out.timers_total > max_timers as u64 {
                    out.capped = Some(format!(
                        "the timer cap of {max_timers} was reached after {} bucket(s); the table \
                         holds more timers than are reported here, and this is a cap rather than \
                         the end of the table.",
                        out.buckets_walked
                    ));
                    break 'tables;
                }
                if let Some(&row) = rows_by_address.get(&address) {
                    out.timers[row].reached_from.push((processor, bucket));
                    continue;
                }
                rows_by_address.insert(address, out.timers.len());
                // The field as read. On an x64 build that encodes it, this is
                // not an address, and nothing is read through it until
                // `locate_dpc` has decoded and checked it (`MEM-052`).
                let field = timer.pointer("Dpc").ok().filter(|d| *d != 0);
                let located = field
                    .map(|field| locate_dpc(&reader, &layout, &out.dpc_encoding, address, field));
                let (dpc, dpc_unreadable) = match located {
                    Some(Ok(dpc)) => (dpc, None),
                    Some(Err(why)) => (None, Some(why)),
                    None => (None, None),
                };
                let (routine, context) = match dpc {
                    Some(dpc) => {
                        // `locate_dpc` has already checked that both members'
                        // addresses exist; `checked_add` states it again here
                        // rather than trusting the distance between the two.
                        let routine = dpc
                            .checked_add(layout.dpc_routine)
                            .and_then(|at| reader.read_pointer_at(at).ok())
                            .filter(|r| *r != 0);
                        let context = layout
                            .dpc_context
                            .and_then(|off| reader.read_pointer_at(dpc.checked_add(off)?).ok());
                        (routine, context)
                    }
                    None => (None, None),
                };
                out.timers.push(TimerRecord {
                    processor,
                    bucket,
                    timer: address,
                    // `int`, not `unsigned`: XP SP2 declares `Period` as
                    // `long`, and an unsigned-only read dropped every period
                    // on that build (2026-09-24). A negative period is not a
                    // period and is not published as one.
                    period_ms: timer
                        .int("Period")
                        .ok()
                        .and_then(|p| u32::try_from(p.as_i128()).ok()),
                    dpc,
                    routine,
                    context,
                    ownership: routine.map(|r| modules.attribute(r)),
                    bucket_time_raw,
                    dpc_field_raw: field,
                    dpc_unreadable,
                    pointer_size: layout.pointer as u8,
                    reached_from: vec![(processor, bucket)],
                    reached_more_than_once_reason: None,
                });
            }
            // `Wrapped` is the normal ending: the walk came back to its head
            // having seen every entry. Anything else means the bucket may hold
            // timers this walk did not reach, and the count of each kind goes
            // on the record.
            match walked.stop() {
                None | Some(ListStop::Wrapped) => {}
                Some(other) => {
                    *stops.entry(other.as_str().to_string()).or_default() += 1;
                }
            }
        }
    }

    for row in out.timers.iter_mut().filter(|t| t.reached_from.len() > 1) {
        row.reached_more_than_once_reason =
            Some(reached_more_than_once_reason(&row.reached_from, &entered));
    }
    if !entered.is_empty() {
        const SHOWN: usize = 16;
        let pairs: Vec<String> = entered
            .iter()
            .take(SHOWN)
            .map(|(from, into)| format!("{} -> {}", place(*from), place(*into)))
            .collect();
        let more = entered.len().saturating_sub(SHOWN);
        out.notes.push(format!(
            "{} bucket list(s) ended with `entered_another_bucket`: each led into the head of a \
             different bucket ({}{}). That head is a list head inside `_KTIMER_TABLE_ENTRY`, not \
             a timer, so the walk of the bucket stopped there and the head was not reported as a \
             timer; a timer reached on the way is reported once, with both places in \
             `reached_from` (`MEM-055`). Two buckets' lists joined in one image is what a timer \
             relinked while the image was being acquired leaves behind.",
            entered.len(),
            pairs.join("; "),
            if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            }
        ));
    }

    if out.not_timers > 0 {
        out.notes.push(format!(
            "{} list item(s) reached from the legacy table were not timers: the dispatcher header's \
             type is neither a notification (8) nor a synchronisation (9) timer's, so each was \
             skipped, as Volatility skips it, and the walk of its bucket went on; none is reported as a timer. A \
             list that runs into memory that is no `_KTIMER` is what a capture taken while the \
             kernel relinked timers leaves behind (`MEM-059`).",
            out.not_timers
        ));
    }

    for (reason, count) in stops {
        out.notes.push(format!(
            "{count} bucket list(s) ended with `{reason}` rather than at their head, so those \
             buckets may hold timers this walk did not reach."
        ));
    }
    Ok(out)
}

/// Where a timer was reached: `(processor, bucket)`, the processor `None` for
/// the legacy global table.
type Place = (Option<u64>, u64);

fn place((processor, bucket): Place) -> String {
    match processor {
        Some(p) => format!("processor {p}'s bucket {bucket}"),
        None => format!("bucket {bucket} of the global table"),
    }
}

/// Why a timer was reached from each of `sightings`, from what the walk saw:
/// a later sighting is explained when one of the two lists was seen to lead
/// into the other's head. Nothing else is claimed.
fn reached_more_than_once_reason(sightings: &[Place], entered: &BTreeMap<Place, Place>) -> String {
    let mut joined = Vec::new();
    let mut unexplained = Vec::new();
    for (j, later) in sightings.iter().enumerate().skip(1) {
        let pair = sightings[..j].iter().find_map(|earlier| {
            if entered.get(earlier) == Some(later) {
                Some((*earlier, *later))
            } else if entered.get(later) == Some(earlier) {
                Some((*later, *earlier))
            } else {
                None
            }
        });
        match pair {
            Some((from, into)) => joined.push(format!("{} led into {}", place(from), place(into))),
            None => unexplained.push(place(*later)),
        }
    }
    if joined.is_empty() {
        return REASON_NOT_ESTABLISHED.to_string();
    }
    let mut text = format!(
        "This `_KTIMER` was reached from more than one bucket list because the lists are joined \
         in this image: {}. The walk stopped at the other bucket's head, so this is one timer, \
         reported once. Joined lists are what a timer relinked while the image was being \
         acquired leaves behind; which bucket it belonged to at any one instant is not \
         established.",
        joined.join("; ")
    );
    if !unexplained.is_empty() {
        text.push_str(&format!(
            " Its sighting(s) from {} have no reason the walk established.",
            unexplained.join(", ")
        ));
    }
    text
}

/// What a timer reached from more than one list says when the walk's own
/// evidence does not show why.
pub const REASON_NOT_ESTABLISHED: &str =
    "This `_KTIMER` was reached from more than one bucket list, and the reason is not \
     established: no list this walk followed was seen to lead into another bucket's head. It is \
     one timer, reported once, with every place it was reached in `reached_from`.";

/// How this build stores `_KTIMER.Dpc` (`MEM-052`).
///
/// On x64 Windows the kernel does not store the `_KDPC` pointer in a timer as
/// the pointer it is declared as. It stores it encoded with two boot-random
/// globals, `KiWaitNever` and `KiWaitAlways`, and the timer's own address. The
/// decode is published outside this tree and outside any copyleft source —
/// Skape, *Uninformed* vol. 8 article 5 ("Timer List Obfuscation"), and
/// debugwar.com, "Iterate DPC timers from Win7 to Win11" — as: XOR
/// `KiWaitNever`, rotate left by `KiWaitNever`'s low byte, XOR the `_KTIMER`'s
/// address, byte-swap, XOR `KiWaitAlways`.
///
/// **Which builds encode is taken from the build, and each result is checked
/// against the evidence**: the build must declare both keys, and every decoded
/// pointer must land on a structure whose `Type` byte is one of this build's
/// own `_KOBJECTS.DpcObject` / `ThreadedDpcObject` values. A result that fails
/// is published as unreadable with the reason, and never falls back to the
/// undecoded value — trying transforms until one looks plausible is the
/// fabrication `DUE_TIME_NOTE` already refuses.
///
/// Found on DFIR Madness Case 001, 2026-09-24: `citadeldc01.mem` (Server 2012
/// R2) panicked adding a member offset to an encoded value, and on
/// `DESKTOP-SDN1RPT.mem` (Windows 10) 359 encoded fields were published as DPC
/// addresses with no routine read from any of them.
#[derive(Debug, Clone)]
pub enum DpcEncoding {
    /// The build declares neither key: the field is the pointer it is declared
    /// as. Every XP-era and x86 ISF measured is here.
    Plain,
    /// The build declares both keys and this is a 32-bit build. The
    /// obfuscation is published for x64 only, so the field is read as
    /// declared — and, because the keys are declared, every value is checked
    /// against `_KDPC.Type` before anything is read through it.
    PlainChecked { check: KdpcCheck },
    /// x64, both keys read: each field is decoded and checked.
    Decoded {
        wait_never: u64,
        wait_always: u64,
        check: KdpcCheck,
    },
    /// The build encodes the field and it cannot be decoded here. Every
    /// non-zero `Dpc` field is unreadable, with this reason.
    Unusable { state: &'static str, reason: String },
}

/// What a `_KDPC` must look like on this build, from its own symbols.
#[derive(Debug, Clone)]
pub struct KdpcCheck {
    /// `_KDPC.Type`'s offset.
    pub type_offset: u64,
    /// The `_KOBJECTS` constants a DPC's `Type` byte may hold, by name.
    pub accepted: Vec<(String, u8)>,
}

impl KdpcCheck {
    fn resolve(reader: &StructReader) -> Result<Self, String> {
        let type_offset = reader
            .member_offset("_KDPC", "Type")
            .map(|o| o.bytes())
            .map_err(|e| format!("this build does not declare `_KDPC.Type`: {e}"))?;
        let table = reader.symbols();
        let mut accepted = Vec::new();
        for name in ["DpcObject", "ThreadedDpcObject"] {
            if let Ok(value) = table.enum_value("_KOBJECTS", name) {
                if let Ok(byte) = u8::try_from(value) {
                    accepted.push((name.to_string(), byte));
                }
            }
        }
        if accepted.is_empty() {
            return Err(
                "this build declares no `_KOBJECTS.DpcObject`, so a decoded pointer cannot be \
                 checked against the structure it must point at"
                    .to_string(),
            );
        }
        Ok(Self {
            type_offset,
            accepted,
        })
    }

    /// Whether `dpc` points at a `_KDPC` of this build, or why not.
    fn verify(&self, reader: &StructReader, dpc: u64) -> Result<(), String> {
        let at = dpc.checked_add(self.type_offset).ok_or_else(|| {
            format!("its `Type` byte would lie past the top of the address space ({dpc:#018x})")
        })?;
        let mut byte = [0u8; 1];
        reader
            .read_into(at, &mut byte)
            .map_err(|e| format!("its `_KDPC.Type` byte at {at:#018x} would not read: {e}"))?;
        if self.accepted.iter().any(|(_, v)| *v == byte[0]) {
            return Ok(());
        }
        Err(format!(
            "the structure there has `Type` {:#04x}, and this build's `_KOBJECTS` declares a DPC \
             as {}, so it is not a `_KDPC`",
            byte[0],
            self.accepted
                .iter()
                .map(|(n, v)| format!("{n} = {v:#04x}"))
                .collect::<Vec<_>>()
                .join(" or ")
        ))
    }

    fn to_json(&self) -> Value {
        json!({
            "kdpc_type_offset": self.type_offset,
            "accepted_types": self.accepted.iter()
                .map(|(n, v)| json!({"name": n, "value": v}))
                .collect::<Vec<_>>(),
        })
    }
}

impl DpcEncoding {
    fn resolve(reader: &StructReader, keys: Option<DpcKeySymbols>, pointer: usize) -> Self {
        let Some(keys) = keys else {
            return Self::Plain;
        };
        let check = match KdpcCheck::resolve(reader) {
            Ok(check) => check,
            Err(why) => {
                return Self::Unusable {
                    state: "unverifiable",
                    reason: format!(
                        "this build declares `KiWaitNever` and `KiWaitAlways`, the keys the \
                         kernel encodes `_KTIMER.Dpc` with, and {why}. No DPC field is read \
                         through, decoded or not."
                    ),
                }
            }
        };
        if pointer != 8 {
            return Self::PlainChecked { check };
        }
        let read = |at: u64| -> Result<u64, String> {
            let mut buf = [0u8; 8];
            reader
                .read_into(at, &mut buf)
                .map(|()| u64::from_le_bytes(buf))
                .map_err(|e| e.to_string())
        };
        match (read(keys.wait_never), read(keys.wait_always)) {
            (Ok(wait_never), Ok(wait_always)) => Self::Decoded {
                wait_never,
                wait_always,
                check,
            },
            (a, b) => Self::Unusable {
                state: "keys_unreadable",
                reason: format!(
                    "this build encodes `_KTIMER.Dpc` with `KiWaitNever` ({:#018x}) and \
                     `KiWaitAlways` ({:#018x}), and {} would not read from this image, so no \
                     encoded DPC field can be decoded. Nothing is said about where these timers \
                     would call.",
                    keys.wait_never,
                    keys.wait_always,
                    match (a.err(), b.err()) {
                        (Some(e), None) => format!("`KiWaitNever` ({e})"),
                        (None, Some(e)) => format!("`KiWaitAlways` ({e})"),
                        (Some(e), Some(_)) => format!("neither key ({e})"),
                        (None, None) => "neither key".to_string(),
                    }
                ),
            },
        }
    }

    fn state(&self) -> &'static str {
        match self {
            Self::Plain => "not_encoded",
            Self::PlainChecked { .. } => "not_encoded_checked",
            Self::Decoded { .. } => "decoded",
            Self::Unusable { state, .. } => state,
        }
    }

    pub fn to_json(&self) -> Value {
        let basis = match self {
            Self::Plain => {
                "This build declares neither `KiWaitNever` nor `KiWaitAlways`, so `_KTIMER.Dpc` \
                 is read as the pointer it is declared as."
                    .to_string()
            }
            Self::PlainChecked { .. } => {
                "This 32-bit build declares `KiWaitNever` and `KiWaitAlways`. The published \
                 timer-DPC obfuscation is x64-only, so the field is read as declared; because \
                 the keys are declared, every value is checked against `_KDPC.Type` first."
                    .to_string()
            }
            Self::Decoded { .. } => DPC_DECODE_BASIS.to_string(),
            Self::Unusable { reason, .. } => reason.clone(),
        };
        let (never, always, check) = match self {
            Self::Decoded {
                wait_never,
                wait_always,
                check,
            } => (
                Some(format!("{wait_never:#018x}")),
                Some(format!("{wait_always:#018x}")),
                Some(check.to_json()),
            ),
            Self::PlainChecked { check } => (None, None, Some(check.to_json())),
            _ => (None, None, None),
        };
        json!({
            "state": self.state(),
            "basis": basis,
            "ki_wait_never": never,
            "ki_wait_always": always,
            "kdpc_check": check,
        })
    }
}

/// What a decoded row's record says about where its DPC address came from.
pub const DPC_DECODE_BASIS: &str =
    "This x64 build stores `_KTIMER.Dpc` encoded with the boot-random globals `KiWaitNever` and \
     `KiWaitAlways` (both declared and read from this image) and the timer's own address. Each \
     field was decoded as published by Skape (Uninformed vol. 8, art. 5) and debugwar.com: XOR \
     KiWaitNever, rotate left by its low byte, XOR the _KTIMER address, byte-swap, XOR \
     KiWaitAlways. Every result was then checked: it must land on a structure whose `Type` byte \
     is one of this build's `_KOBJECTS` DPC values, or the row is published as unreadable with \
     the reason and nothing is read through it. `dpc_field_raw` is the field as stored.";

/// The published decode (see [`DpcEncoding`]).
pub fn decode_dpc(field: u64, timer: u64, wait_never: u64, wait_always: u64) -> u64 {
    let x = (field ^ wait_never).rotate_left(u32::from(wait_never as u8));
    (x ^ timer).swap_bytes() ^ wait_always
}

/// Turn a non-zero `_KTIMER.Dpc` field into a `_KDPC` address this walk may
/// read through, or say why it cannot be one.
fn locate_dpc(
    reader: &StructReader,
    layout: &TimerLayout,
    encoding: &DpcEncoding,
    timer: u64,
    field: u64,
) -> Result<Option<u64>, String> {
    let (dpc, check, what) = match encoding {
        DpcEncoding::Plain => (field, None, "the field"),
        DpcEncoding::PlainChecked { check } => (field, Some(check), "the field"),
        DpcEncoding::Decoded {
            wait_never,
            wait_always,
            check,
        } => (
            decode_dpc(field, timer, *wait_never, *wait_always),
            Some(check),
            "the decoded field",
        ),
        DpcEncoding::Unusable { reason, .. } => return Err(reason.clone()),
    };
    // A timer naming no DPC stores the ENCODING of null, which is non-zero;
    // it decodes to exactly 0 and is an ordinary timer, not an unreadable one
    // (157 of 209 timers on the Windows 11 26200 capture).
    if dpc == 0 {
        return Ok(None);
    }
    let prefix = format!(
        "the `Dpc` field reads {field:#018x}; {what} is {dpc:#018x}, which is not a `_KDPC` \
         this walk can read through:"
    );
    if !seance_memory::object::is_canonical(dpc, layout.pointer as u8) {
        return Err(format!(
            "{prefix} it is not a canonical address for this build's {}-bit pointers.",
            layout.pointer * 8
        ));
    }
    // Every member the walk reads must have an address. An evidence value
    // near the top of the address space plus a member offset overflows, and
    // on Case 001's domain controller that overflow was a panic that took the
    // whole memory pipeline with it (`MEM-052`).
    let last = layout
        .dpc_context
        .map_or(layout.dpc_routine, |c| c.max(layout.dpc_routine));
    if dpc
        .checked_add(last)
        .and_then(|a| a.checked_add(layout.pointer as u64))
        .is_none()
    {
        return Err(format!(
            "{prefix} adding `_KDPC`'s member offsets to it overflows the address space, so its \
             members have no address."
        ));
    }
    if let Some(check) = check {
        check
            .verify(reader, dpc)
            .map_err(|why| format!("{prefix} {why}."))?;
    }
    Ok(Some(dpc))
}
