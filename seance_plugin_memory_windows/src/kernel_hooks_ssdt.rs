//! The system service descriptor table: where each system call enters the
//! kernel.
//!
//! `KiServiceTable` is the array the `syscall` instruction dispatches through.
//! Every entry ought to point inside `ntoskrnl.exe`. An entry that points
//! somewhere else means something has redirected a system call — historically
//! the defining rootkit technique, and still what a hypervisor-assisted or
//! boot-time patch looks like from inside the image.
//!
//! # The entries are not pointers on 64-bit Windows
//!
//! This is the one thing everybody gets wrong. On 32-bit Windows the table holds
//! plain unsigned pointers. On 64-bit Windows it holds **signed 32-bit offsets**
//! from the table's own address, with the bottom four bits used for the
//! argument-stack count, so the routine is at
//!
//! ```text
//! KiServiceTable + (entry >> 4)      // arithmetic shift: entries are signed
//! ```
//!
//! Three ways to get this wrong, each producing a full table of plausible
//! addresses:
//!
//! * reading the entry as unsigned — every negative offset becomes a four-gigabyte
//!   forward jump, and every one of those addresses lands outside ntoskrnl, so
//!   the table reads as entirely hooked;
//! * shifting logically rather than arithmetically — the same failure for
//!   negative entries only, so *part* of the table reads as hooked;
//! * forgetting the shift — every address is sixteen times too far from the
//!   table.
//!
//! The architecture decides which form applies, and it comes from the profile
//! rather than from the host Séance happens to be running on.
//!
//! # A limit that came out of the image
//!
//! `KiServiceLimit` says how many entries the table has. It is read from memory,
//! so it is attacker-influenced: a limit of four billion would make this stage
//! read for a very long time. It is capped at [`MAX_SERVICE_ENTRIES`], and a
//! limit above that is reported as a cap rather than followed, because such a
//! table is *wrong* and its first few thousand entries are a prefix of nonsense.

use std::sync::Arc;

use seance_memory::object::StructReader;
use seance_memory::Architecture;

use crate::kernel_hooks::{
    push_note, read_u32, symbol_address, KernelHookConfig, KernelHookError, ModuleMap, Ownership,
};
use crate::profile::WindowsProfile;

/// Symbol naming the native system service table.
pub const SYMBOL_SERVICE_TABLE: &str = "KiServiceTable";

/// Symbol naming how many entries that table has.
pub const SYMBOL_SERVICE_LIMIT: &str = "KiServiceLimit";

/// Bytes per table entry, on every architecture Windows runs on.
///
/// The entries are 32 bits wide on both 32-bit and 64-bit Windows: on the
/// latter they are offsets rather than pointers, which is precisely why they
/// fit in four bytes.
pub const SERVICE_ENTRY_BYTES: u64 = 4;

/// How far a 64-bit entry is shifted to recover its offset.
///
/// The bottom four bits hold the number of stack arguments the call takes, so
/// the offset is the entry arithmetically shifted right by four.
pub const SERVICE_ENTRY_SHIFT: u32 = 4;

/// Ceiling on entries this stage will read.
///
/// Windows 11 has around 500 native system calls. A limit above this came out of
/// the image and is not a service limit.
pub const MAX_SERVICE_ENTRIES: u64 = 4_096;

// ── Layout ──────────────────────────────────────────────────────────────────

/// Where the service table is and how its entries are encoded.
#[derive(Debug, Clone)]
pub struct SsdtSymbols {
    /// The table's address in the kernel address space.
    pub table: u64,
    /// Where the entry count is.
    pub limit_at: u64,
    /// Whether the entries are signed offsets from the table (64-bit) rather
    /// than absolute pointers (32-bit).
    pub offsets_from_table: bool,
    /// Where the kernel image is loaded, so an entry can be asked whether it
    /// still enters ntoskrnl.
    pub kernel_base: u64,
}

impl SsdtSymbols {
    /// Locate the service table for this build.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] naming whichever of the two symbols is
    /// missing. Returning an empty table would be a claim that the kernel
    /// exports no system calls.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let table = symbol_address(profile, SYMBOL_SERVICE_TABLE).map_err(|err| {
            KernelHookError::unsupported(format!(
                "the system service table cannot be located: {err}"
            ))
        })?;
        let limit_at = symbol_address(profile, SYMBOL_SERVICE_LIMIT).map_err(|err| {
            KernelHookError::unsupported(format!(
                "the system service table was located and how many entries it has cannot be: {err}"
            ))
        })?;
        // The encoding follows the *kernel's* pointer width, which the profile
        // recorded, and never the host's. There is no `X86_64`: the variants are
        // `X86`, `X64` and `Arm64`.
        let offsets_from_table = matches!(
            profile.architecture,
            Architecture::X64 | Architecture::Arm64
        );
        Ok(Self {
            table,
            limit_at,
            offsets_from_table,
            kernel_base: profile.kernel_base.value,
        })
    }

    /// The address entry `index` names, from the raw value stored in it.
    ///
    /// `None` when the arithmetic would leave the address space, which is a
    /// rejection rather than a wrapped address that would attribute to some
    /// unrelated module.
    pub fn target_of(&self, raw: i64) -> Option<u64> {
        if !self.offsets_from_table {
            // 32-bit Windows stores the routine's address outright.
            return u64::try_from(raw).ok();
        }
        // Arithmetic shift: a negative entry names a routine *below* the table,
        // and a logical shift would turn it into a four-gigabyte forward jump.
        self.table.checked_add_signed(raw >> SERVICE_ENTRY_SHIFT)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "table": self.table,
            "limit_at": self.limit_at,
            "offsets_from_table": self.offsets_from_table,
            "kernel_base": self.kernel_base,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One system service table entry.
#[derive(Debug, Clone)]
pub struct SsdtEntry {
    /// The system call number.
    pub index: u64,
    /// The value stored in the table, before it is decoded. Kept because a
    /// disputed address is settled by the bytes that were actually there.
    pub raw: i64,
    /// The routine the entry names.
    pub target: u64,
    /// Which module owns the target.
    pub ownership: Ownership,
    /// Whether the target lies inside the kernel image. `None` means the
    /// question could not be answered — never "no".
    pub in_kernel: Option<bool>,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl SsdtEntry {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "index": self.index,
            "raw": self.raw,
            "target": self.target,
            "ownership": self.ownership.to_json(),
            "module": self.ownership.module(),
            "in_kernel": self.in_kernel,
            "outside_any_module": self.ownership.is_outside_any_module(),
            "notes": self.notes,
        })
    }
}

/// What one reading of the service table found, and what it could not do.
#[derive(Debug, Clone, Default)]
pub struct ServiceTableSweep {
    /// The entries, in system call number order.
    pub entries: Vec<SsdtEntry>,
    /// The limit the kernel declared, when it was read.
    pub limit: Option<u64>,
    /// Notes, capped by [`KernelHookConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes were raised in total.
    pub notes_total: usize,
    /// Whether a cap fired, or the table was not read to its declared end.
    pub capped: bool,
}

// ── The group ───────────────────────────────────────────────────────────────

/// Read the system service descriptor table.
///
/// # What an examiner learns
///
/// Every system call number, the routine it dispatches to, the module that owns
/// that routine, and whether it is still inside the kernel image. An entry
/// pointing into a third-party driver is a redirected system call; that is a
/// signal and not a verdict, since some legitimate products still patch here.
///
/// # What a wrong answer looks like
///
/// A table where every entry reads as hooked, which is what reading 64-bit
/// entries as unsigned produces, or one where every address is sixteen times
/// too far from the table, which is what forgetting the shift produces. Both
/// look like findings and neither is.
pub fn read_service_table(
    profile: &WindowsProfile,
    symbols: &SsdtSymbols,
    modules: &ModuleMap,
    config: &KernelHookConfig,
) -> ServiceTableSweep {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut sweep = ServiceTableSweep::default();

    let declared = match read_u32(&reader, symbols.limit_at) {
        Ok(limit) => u64::from(limit),
        Err(err) => {
            push_note(
                &mut sweep.notes,
                &mut sweep.notes_total,
                config.max_recorded_notes,
                format!(
                    "'{SYMBOL_SERVICE_LIMIT}' could not be read, so it is not known how many \
                     system calls this kernel has and none were read: {err}"
                ),
            );
            sweep.capped = true;
            return sweep;
        }
    };
    sweep.limit = Some(declared);
    if declared == 0 {
        push_note(
            &mut sweep.notes,
            &mut sweep.notes_total,
            config.max_recorded_notes,
            format!(
                "'{SYMBOL_SERVICE_LIMIT}' holds zero, and no Windows kernel has an empty system \
                 service table, so the value is not a limit"
            ),
        );
        sweep.capped = true;
        return sweep;
    }
    let count = declared.min(MAX_SERVICE_ENTRIES);
    if count < declared {
        push_note(
            &mut sweep.notes,
            &mut sweep.notes_total,
            config.max_recorded_notes,
            format!(
                "'{SYMBOL_SERVICE_LIMIT}' declares {declared} system calls, above the \
                 {MAX_SERVICE_ENTRIES} this stage will read, so the table was not read to its \
                 declared end"
            ),
        );
        sweep.capped = true;
    }

    // The kernel's own range, so an entry can be asked whether it still enters
    // ntoskrnl. Absent when the module map cannot place the kernel, which makes
    // every `in_kernel` answer `None` rather than `false`.
    let kernel_range = modules.owner_of(symbols.kernel_base);
    if kernel_range.is_none() {
        push_note(
            &mut sweep.notes,
            &mut sweep.notes_total,
            config.max_recorded_notes,
            format!(
                "the loaded-module list holds no module covering the kernel base {:#x}, so no \
                 entry can be said to leave or to stay inside the kernel image",
                symbols.kernel_base
            ),
        );
    }

    for index in 0..count {
        let Some(at) = index
            .checked_mul(SERVICE_ENTRY_BYTES)
            .and_then(|within| symbols.table.checked_add(within))
        else {
            push_note(
                &mut sweep.notes,
                &mut sweep.notes_total,
                config.max_recorded_notes,
                format!("entry {index} lies past the end of the address space"),
            );
            sweep.capped = true;
            break;
        };
        let word = match read_u32(&reader, at) {
            Ok(word) => word,
            Err(err) => {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "the service table could not be read from entry {index} onwards, so the \
                         remaining {} entr(y/ies) are not listed: {err}",
                        count.saturating_sub(index)
                    ),
                );
                sweep.capped = true;
                break;
            }
        };
        // Signed on 64-bit, unsigned on 32-bit. Reinterpreting the same four
        // bytes the wrong way round is what turns a whole table into findings.
        let raw = if symbols.offsets_from_table {
            i64::from(word as i32)
        } else {
            i64::from(word)
        };
        let Some(target) = symbols.target_of(raw) else {
            push_note(
                &mut sweep.notes,
                &mut sweep.notes_total,
                config.max_recorded_notes,
                format!(
                    "entry {index} holds {raw:#x}, which names an address outside the 64-bit \
                     address space, so no routine could be attributed to it"
                ),
            );
            continue;
        };
        let in_kernel = kernel_range.map(|range| range.contains(target));
        sweep.entries.push(SsdtEntry {
            index,
            raw,
            target,
            ownership: modules.attribute(target),
            in_kernel,
            notes: Vec::new(),
        });
    }
    sweep
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_hooks::test_support::{
        hook_isf, hook_profile, populated_image, FLT_NAME, HIDDEN_NAME, NT_NAME, NT_ROUTINE,
        SERVICE_FLT_TARGET, SERVICE_HIDDEN_TARGET, SERVICE_LIMIT_AT, SERVICE_LOW_TARGET,
        SERVICE_TABLE,
    };
    use crate::kernel_hooks::ModuleMap;
    use crate::poolscan::test_support::IMAGE_SIZE;

    fn read(profile: &WindowsProfile) -> ServiceTableSweep {
        let modules = ModuleMap::from_profile(profile);
        let symbols = SsdtSymbols::from_profile(profile).expect("a describable build");
        read_service_table(profile, &symbols, &modules, &KernelHookConfig::default())
    }

    // ── The entry encoding ──────────────────────────────────────────────────

    #[test]
    fn a_sixty_four_bit_entry_is_an_offset_from_the_table_shifted_by_four() {
        let symbols = SsdtSymbols {
            table: 0x1000,
            limit_at: 0x2000,
            offsets_from_table: true,
            kernel_base: 0,
        };
        // 0x40 >> 4 is 4, so the routine is four bytes past the table.
        assert_eq!(symbols.target_of(0x40), Some(0x1004));
    }

    #[test]
    fn a_negative_entry_names_a_routine_below_the_table() {
        // The single most consequential line in this module. A logical shift
        // turns this into a four-gigabyte forward jump, which lands outside
        // every module and reports the entry as hooked.
        let symbols = SsdtSymbols {
            table: 0x1000,
            limit_at: 0x2000,
            offsets_from_table: true,
            kernel_base: 0,
        };
        assert_eq!(symbols.target_of(-0x40), Some(0x0FFC));
    }

    #[test]
    fn a_thirty_two_bit_entry_is_the_routines_address_outright() {
        let symbols = SsdtSymbols {
            table: 0x1000,
            limit_at: 0x2000,
            offsets_from_table: false,
            kernel_base: 0,
        };
        assert_eq!(symbols.target_of(0x8_0000), Some(0x8_0000));
    }

    #[test]
    fn an_entry_that_would_leave_the_address_space_names_no_routine() {
        let symbols = SsdtSymbols {
            table: 0,
            limit_at: 0,
            offsets_from_table: true,
            kernel_base: 0,
        };
        // The lowest possible offset from address zero cannot be reached.
        assert_eq!(symbols.target_of(i64::MIN), None);
    }

    // ── Reading the fixture's table ─────────────────────────────────────────

    #[test]
    fn every_declared_entry_is_read_and_the_limit_is_reported_beside_them() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let sweep = read(&profile);
        assert_eq!(sweep.limit, Some(4));
        assert_eq!(sweep.entries.len(), 4, "{:?}", sweep);
        assert!(!sweep.capped, "{:?}", sweep.notes);
    }

    #[test]
    fn an_entry_still_inside_the_kernel_is_ordinary_and_says_so() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let sweep = read(&profile);
        let entry = &sweep.entries[0];
        assert_eq!(entry.target, NT_ROUTINE);
        assert_eq!(entry.in_kernel, Some(true));
        assert_eq!(entry.ownership.module(), Some(NT_NAME));
    }

    #[test]
    fn an_entry_leaving_the_kernel_for_no_loaded_module_is_the_finding() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let sweep = read(&profile);
        let entry = &sweep.entries[1];
        assert_eq!(entry.target, SERVICE_HIDDEN_TARGET);
        assert_eq!(entry.in_kernel, Some(false));
        assert!(entry.ownership.is_outside_any_module());
        assert_eq!(HIDDEN_NAME, "hidden.sys", "the fixture's unlisted driver");
    }

    #[test]
    fn a_negative_entry_in_the_image_resolves_below_the_table_and_stays_in_the_kernel() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let sweep = read(&profile);
        let entry = &sweep.entries[2];
        assert!(entry.raw < 0, "the fixture stores a negative offset");
        assert_eq!(entry.target, SERVICE_LOW_TARGET);
        assert!(entry.target < SERVICE_TABLE);
        assert_eq!(entry.in_kernel, Some(true));
    }

    #[test]
    fn an_entry_in_another_loaded_driver_leaves_the_kernel_without_leaving_the_module_list() {
        // The common case for a legitimately patched table, and the reason
        // `in_kernel` and `outside_any_module` are two different columns.
        let profile = hook_profile(populated_image(), &hook_isf());
        let sweep = read(&profile);
        let entry = &sweep.entries[3];
        assert_eq!(entry.target, SERVICE_FLT_TARGET);
        assert_eq!(entry.in_kernel, Some(false));
        assert!(!entry.ownership.is_outside_any_module());
        assert_eq!(entry.ownership.module(), Some(FLT_NAME));
    }

    // ── Failure paths ───────────────────────────────────────────────────────

    #[test]
    fn a_zero_limit_is_refused_rather_than_reported_as_a_kernel_with_no_system_calls() {
        let mut image = populated_image();
        image.put_u32(SERVICE_LIMIT_AT, 0);
        let profile = hook_profile(image, &hook_isf());
        let sweep = read(&profile);
        assert!(sweep.entries.is_empty());
        assert!(sweep.capped);
        assert!(
            sweep.notes.iter().any(|note| note.contains("holds zero")),
            "{:?}",
            sweep.notes
        );
    }

    #[test]
    fn a_limit_above_the_cap_is_reported_as_a_cap_and_never_followed_to_its_end() {
        // The limit came out of the image, so it is attacker-influenced.
        let mut image = populated_image();
        image.put_u32(SERVICE_LIMIT_AT, 100_000);
        let profile = hook_profile(image, &hook_isf());
        let sweep = read(&profile);
        assert_eq!(sweep.limit, Some(100_000));
        assert!(sweep.capped);
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains("declares 100000 system calls")),
            "{:?}",
            sweep.notes
        );
        assert!(sweep.entries.len() <= MAX_SERVICE_ENTRIES as usize);
    }

    #[test]
    fn a_table_that_runs_off_the_end_of_the_image_stops_and_says_where() {
        // The table is at the very end of the fixture image, so the read fails
        // part-way. Stopping silently would report a short table as a complete
        // one.
        //
        // The address is computed from `IMAGE_SIZE` rather than written out. It
        // was written out once, and when the fixture image grew from 128 KiB to
        // 192 KiB the address moved *inside* it: the table then read back as
        // eight zeroed entries and the test stopped exercising a short read at
        // all.
        let isf = hook_isf().replace(
            r#""KiServiceTable": {"address": 1856}"#,
            &format!(
                r#""KiServiceTable": {{"address": {}}}"#,
                IMAGE_SIZE as u64 - 8
            ),
        );
        let mut image = populated_image();
        image.put_u32(SERVICE_LIMIT_AT, 8);
        let profile = hook_profile(image, &isf);
        let sweep = read(&profile);
        assert!(sweep.capped);
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains("could not be read from entry")),
            "{:?}",
            sweep.notes
        );
    }

    #[test]
    fn a_build_without_the_table_symbols_is_refused_naming_the_one_that_is_missing() {
        let isf = hook_isf().replace(
            r#""KiServiceLimit": {"address": 1872}"#,
            r#""KiServiceLimitX": {"address": 1872}"#,
        );
        let profile = hook_profile(populated_image(), &isf);
        let err = SsdtSymbols::from_profile(&profile).expect_err("the limit is unreachable");
        assert!(err.to_string().contains(SYMBOL_SERVICE_LIMIT), "{err}");
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn without_a_module_covering_the_kernel_no_entry_is_said_to_leave_it() {
        // `in_kernel: None` and `in_kernel: Some(false)` are opposite claims,
        // and only one of them is a finding.
        let profile = hook_profile(populated_image(), &hook_isf());
        let symbols = SsdtSymbols::from_profile(&profile).expect("a describable build");
        let unusable = ModuleMap::unavailable("the module list was never walked");
        let sweep = read_service_table(&profile, &symbols, &unusable, &KernelHookConfig::default());
        assert!(!sweep.entries.is_empty());
        assert!(sweep.entries.iter().all(|entry| entry.in_kernel.is_none()));
        assert!(sweep
            .entries
            .iter()
            .all(|entry| !entry.ownership.is_outside_any_module()));
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains("no module covering the kernel base")),
            "{:?}",
            sweep.notes
        );
    }

    #[test]
    fn an_entry_row_carries_the_bytes_it_was_decoded_from() {
        // A disputed address is settled by what was actually in the table.
        let profile = hook_profile(populated_image(), &hook_isf());
        let sweep = read(&profile);
        let value = sweep.entries[1].to_json();
        assert_eq!(value["index"], 1);
        assert_eq!(value["target"], SERVICE_HIDDEN_TARGET);
        assert_eq!(value["in_kernel"], false);
        assert_eq!(value["outside_any_module"], true);
        assert!(value["raw"].is_i64());
    }
}
