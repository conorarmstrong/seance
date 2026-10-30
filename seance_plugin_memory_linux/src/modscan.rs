//! A second way to find loaded kernel modules, so the first one can be checked.
//!
//! # Why this exists
//!
//! [`crate::lsmod`] enumerates modules by walking the kernel's module list.
//! Unlinking a `struct module` from that list is the oldest and commonest Linux
//! rootkit technique — the module goes on running, its code stays mapped, and
//! the walk simply does not reach it. A list walk cannot detect that; nothing
//! about correctly traversing a list reveals an entry removed from it.
//!
//! This is the module-side counterpart of [`crate::taskscan`], and it closes
//! the same gap for the enumeration where hiding is most often *the point*: a
//! rootkit hides its own module first.
//!
//! # What makes a candidate believable
//!
//! Two fields the kernel constrains tightly, checked together:
//!
//! 1. **`state` is one of four values.** `enum module_state` is `LIVE`(0),
//!    `COMING`(1), `GOING`(2), `UNFORMED`(3), and it is the **first** member of
//!    `struct module`. Three of every four bytes fail this immediately, and
//!    over four bytes the odds of arbitrary memory passing are about one in
//!    a billion.
//! 2. **`name` is a plausible module name.** NUL-terminated within
//!    `MODULE_NAME_LEN`, non-empty, and drawn from the characters a module name
//!    may actually contain — `modprobe` refuses anything else, so this is a
//!    constraint the kernel enforces rather than a convention.
//!
//! Taken together these are strong. Taken separately neither is: a zero byte is
//! common, and short printable strings are everywhere.
//!
//! # What this is not
//!
//! A module found here and absent from the list is **not** proof of a rootkit.
//! It is equally what a module part-way through unloading looks like, and what
//! a stale structure from a module already unloaded looks like. The verdict
//! says all three.

use crate::lsmod::ModuleList;
use seance_memory::binding::BuildBinding;
use serde_json::json;

/// `MODULE_NAME_LEN` on 64-bit Linux: `64 - sizeof(unsigned long)`.
pub const MODULE_NAME_LEN: usize = 56;

/// The highest value `enum module_state` takes — `MODULE_STATE_UNFORMED`.
pub const MAX_MODULE_STATE: u32 = 3;

/// Whether `value` is a state the kernel actually assigns.
pub fn plausible_state(value: u32) -> bool {
    value <= MAX_MODULE_STATE
}

/// Whether `bytes` are a plausible `struct module.name`.
///
/// A module name reaches the kernel through `modprobe` and the ELF `.modinfo`
/// section, and both constrain it: letters, digits, underscore and hyphen are
/// what survive. Accepting the wider "printable" set here would admit ordinary
/// text, which memory is full of.
pub fn plausible_module_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() < MODULE_NAME_LEN {
        return None;
    }
    let end = bytes[..MODULE_NAME_LEN].iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    let name = &bytes[..end];
    if !name
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

/// One structure the scan believes is a `struct module`.
#[derive(Debug, Clone)]
pub struct ScannedModule {
    pub address: u64,
    pub name: String,
    /// The raw `state` value, not a label: the enum's *names* are stable but a
    /// report that printed "GOING" for a value it guessed at would be asserting
    /// a lifecycle stage from four bytes.
    pub state: u32,
}

impl ScannedModule {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "name": self.name,
            "state": self.state,
            "state_label": state_label(self.state),
        })
    }
}

/// The kernel's own name for a state value, or `None` for one it does not
/// define — which this scan refuses anyway, and which a caller should not print
/// a guess for.
pub fn state_label(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("live"),
        1 => Some("coming"),
        2 => Some("going"),
        3 => Some("unformed"),
        _ => None,
    }
}

/// What the cross-view concluded about one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleVerdict {
    Both,
    ListOnly,
    /// Found by the scan, absent from the kernel's list.
    ScanOnly,
}

impl ModuleVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleVerdict::Both => "both",
            ModuleVerdict::ListOnly => "list_only",
            ModuleVerdict::ScanOnly => "scan_only",
        }
    }

    pub fn meaning(self) -> &'static str {
        match self {
            ModuleVerdict::Both => {
                "Both the module-list walk and the independent scan found this module."
            }
            ModuleVerdict::ListOnly => {
                "The module-list walk found this module and the scan did not. That is not a \
                 finding about the module: the scan examines the region it was given, and a \
                 structure outside that region is out of its reach."
            }
            ModuleVerdict::ScanOnly => {
                "An independent scan found this structure and the kernel's module list does \
                 not contain it. UNLINKING a module from that list is the oldest and \
                 commonest way of hiding a loaded kernel module on Linux, and the module goes \
                 on running. It is also what a module part-way through loading or unloading \
                 looks like, and what a stale structure from a module already unloaded looks \
                 like. This is worth examining; it is not by itself proof of any of the three."
            }
        }
    }
}

/// One module, as both methods saw it.
#[derive(Debug, Clone)]
pub struct ModuleCrossRow {
    pub address: u64,
    pub name: Option<String>,
    pub verdict: ModuleVerdict,
    pub scanned_state: Option<u32>,
}

impl ModuleCrossRow {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "name": self.name,
            "verdict": self.verdict.as_str(),
            "verdict_meaning": self.verdict.meaning(),
            "scanned_state": self.scanned_state,
            "scanned_state_label": self.scanned_state.and_then(state_label),
        })
    }
}

/// Everything the module cross-view establishes.
#[derive(Debug, Clone)]
pub struct ModuleCrossView {
    pub rows: Vec<ModuleCrossRow>,
    pub scan_only: usize,
    pub scan_ran: bool,
}

/// Where a listed module's structure physically is.
///
/// # Why the comparison happens in physical space
///
/// A `task_struct` is slab memory, and slab memory lives in the direct map,
/// where one measured constant converts a physical offset to the kernel address
/// for it. A `struct module` is **not**: it is allocated by `module_alloc` into
/// the module region, which is vmalloc space and is mapped page by page rather
/// than linearly. There is no constant to apply, and applying the task scan's
/// produced a cross-view that correlated **0 of 83 modules** on a real capture.
///
/// So the direction is reversed. The scan already works in physical space; each
/// listed module's virtual address is translated down through the page tables
/// and the two are compared there. That is correct wherever the structure
/// lives, which makes it the better answer for the slab case too.
pub fn physical_address_of(
    profile: &crate::profile::LinuxProfile,
    virtual_address: u64,
) -> Option<u64> {
    let runs = profile.kernel_space.mapping(virtual_address, 1).ok()?;
    let run = runs.first()?;
    // `mapping` reports the run's start, so the offset within the page has to
    // be added back or every address collapses onto its page boundary.
    Some(run.mapped_offset + virtual_address.checked_sub(run.offset)?)
}

impl ModuleCrossView {
    /// Correlate, keyed on **physical** address.
    ///
    /// `listed` pairs each module with where it physically is, or `None` when
    /// its structure could not be translated — an untranslatable entry is
    /// reported as list-only rather than silently matched or dropped.
    pub fn build_physical(
        list: &ModuleList,
        listed: &[(u64, Option<u64>)],
        scanned: &[ScannedModule],
        scan_ran: bool,
    ) -> Self {
        use std::collections::BTreeMap;
        let mut by_physical: BTreeMap<u64, usize> = BTreeMap::new();
        let mut rows: Vec<ModuleCrossRow> = Vec::new();

        for (i, module) in list.modules.iter().enumerate() {
            let physical = listed.get(i).and_then(|(_, p)| *p);
            if let Some(p) = physical {
                by_physical.insert(p, rows.len());
            }
            rows.push(ModuleCrossRow {
                address: module.address,
                name: module_name(module),
                verdict: ModuleVerdict::ListOnly,
                scanned_state: None,
            });
        }

        let mut scan_only = 0usize;
        for found in scanned {
            match by_physical.get(&found.address) {
                Some(&i) => {
                    rows[i].verdict = ModuleVerdict::Both;
                    rows[i].scanned_state = Some(found.state);
                }
                None => scan_only += 1,
            }
        }

        Self {
            rows,
            scan_only,
            scan_ran,
        }
    }

    pub fn build(list: &ModuleList, scanned: &[ScannedModule], scan_ran: bool) -> Self {
        use std::collections::BTreeMap;
        let mut rows: BTreeMap<u64, ModuleCrossRow> = BTreeMap::new();

        for module in &list.modules {
            rows.insert(
                module.address,
                ModuleCrossRow {
                    address: module.address,
                    name: module_name(module),
                    verdict: ModuleVerdict::ListOnly,
                    scanned_state: None,
                },
            );
        }
        for found in scanned {
            rows.entry(found.address)
                .and_modify(|row| {
                    row.verdict = ModuleVerdict::Both;
                    row.scanned_state = Some(found.state);
                })
                .or_insert_with(|| ModuleCrossRow {
                    address: found.address,
                    name: Some(found.name.clone()),
                    verdict: ModuleVerdict::ScanOnly,
                    scanned_state: Some(found.state),
                });
        }

        let rows: Vec<_> = rows.into_values().collect();
        let scan_only = rows
            .iter()
            .filter(|r| r.verdict == ModuleVerdict::ScanOnly)
            .count();
        Self {
            rows,
            scan_only,
            scan_ran,
        }
    }

    /// Modules the list found that the scan independently confirmed.
    ///
    pub fn corroborated(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.verdict == ModuleVerdict::Both)
            .count()
    }

    /// **Only the rows the list walk also found.**
    ///
    /// Scan-only structures are counted and not reported, for the reason the
    /// `hidden_module_detection` key states.
    fn reportable_rows(&self) -> Vec<serde_json::Value> {
        self.rows
            .iter()
            .filter(|r| r.verdict != ModuleVerdict::ScanOnly)
            .map(ModuleCrossRow::to_json)
            .collect()
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "scan_ran": self.scan_ran,
            "rows": self.reportable_rows(),
            "modules_from_list": self.rows.iter().filter(|r| r.verdict != ModuleVerdict::ScanOnly).count(),
            "corroborated_by_scan": self.corroborated(),
            "corroboration_note": if self.scan_ran {
                "Each module in the kernel's module list was looked for a second time by \
                 scanning physical memory for struct module signatures, independently of the \
                 list. A module both methods found is one whose presence does not rest on the \
                 module list being honest."
            } else {
                "No independent scan ran, so this list is NOT corroborated. A module unlinked \
                 from the kernel's module list would not appear in it and nothing here would \
                 show that."
            },
            "scan_only_count": self.scan_only,
            "hidden_module_detection": if self.scan_ran {
                "NOT PERFORMED. This scan corroborates the module list; it does NOT enumerate \
                 modules hidden from it. The signature reproduces the modules that are really \
                 loaded, but it also matches structures that are not modules, and listing \
                 those as candidate hidden modules would bury any real one among them. \
                 `scan_only_count` is given as a measure of the scan's noise and the \
                 structures behind it are deliberately not reported as findings. A module \
                 unlinked from the module list would therefore NOT be surfaced here."
            } else {
                "NOT PERFORMED: no scan ran."
            },
        })
    }
}

fn module_name(module: &crate::lsmod::ModuleRecord) -> Option<String> {
    match &module.name {
        seance_memory::binding::Field::Known(name) => Some(name.clone()),
        _ => None,
    }
}

/// Read the fields a candidate would have, if it is a module.
pub fn candidate_from_bytes(
    bytes: &[u8],
    state_offset: usize,
    name_offset: usize,
) -> Option<(String, u32)> {
    let raw = bytes.get(state_offset..state_offset.checked_add(4)?)?;
    let state = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if !plausible_state(state) {
        return None;
    }
    let name = plausible_module_name(bytes.get(name_offset..)?)?;
    Some((name, state))
}

/// Whether the `list` member at `list_offset` holds pointers a module's link
/// could hold, and if so what they are.
///
/// # Why the name and state are not enough
///
/// They were, in the version of this module that was never wired. The task scan
/// then measured what a comparable signature actually admits across a real
/// capture — tens of thousands of structures — and the fix was to require the
/// candidate's own list links to be a `list_head`. The same applies here, for
/// the same reason: a name and a four-value enum are cheap to satisfy by
/// accident, and two aligned canonical kernel pointers are not.
pub fn classify_links(bytes: &[u8], list_offset: usize) -> LinkShape {
    let Some(window) = bytes.get(list_offset..list_offset.saturating_add(16)) else {
        return LinkShape::NotLinks;
    };
    let next = u64::from_le_bytes(window[..8].try_into().expect("eight bytes"));
    let prev = u64::from_le_bytes(window[8..16].try_into().expect("eight bytes"));

    if next == crate::taskscan::LIST_POISON1 && prev == crate::taskscan::LIST_POISON2 {
        return LinkShape::Poisoned;
    }
    if next >= crate::taskscan::KERNEL_SPACE_FLOOR
        && prev >= crate::taskscan::KERNEL_SPACE_FLOOR
        && next % 8 == 0
        && prev % 8 == 0
    {
        return LinkShape::Kernel { next, prev };
    }
    LinkShape::NotLinks
}

/// What a candidate's own list links say about it, before any is followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkShape {
    /// Both pointers are the values `list_del` writes: removed from a list.
    Poisoned,
    /// Both are plausible kernel addresses; `next` is worth following.
    Kernel { next: u64, prev: u64 },
    /// Neither, so this is not a `struct module` however plausible its name.
    NotLinks,
}

/// Whether `next` really is the next module in the module list.
///
/// # Doing this without a reverse page-table walk
///
/// The invariant to check is that the entry `next` points at points back here.
/// The sweep knows where a candidate is *physically*; the pointers hold
/// *virtual* addresses, and recovering a virtual address from a physical one
/// would need a reverse lookup this has no way to perform.
///
/// It does not need one. Translating in the direction the page tables already
/// run is enough: follow `next` down to physical, read the neighbour's `prev`,
/// translate that down as well, and check it lands on this candidate's own link
/// member. Both sides end up in physical space, which is the space the sweep and
/// the cross-view both work in.
///
/// The neighbour must also read as a module. That is what separates the module
/// list from every other list in a kernel built out of them.
fn next_is_a_module(
    physical: &dyn seance_memory::layer::MemoryLayer,
    translate: &dyn Fn(u64) -> Option<u64>,
    offsets: ModScanOffsets,
    next: u64,
    here_physical: u64,
) -> bool {
    let Some(next_phys) = translate(next) else {
        return false;
    };

    // `list_head` is { next, prev }; read the neighbour's `prev`.
    let mut back = [0u8; 8];
    if seance_core::io::read_full(
        physical.as_data_source(),
        next_phys.wrapping_add(8),
        &mut back,
    ) != 8
    {
        return false;
    }
    let Some(back_phys) = translate(u64::from_le_bytes(back)) else {
        return false;
    };
    if back_phys != here_physical.wrapping_add(offsets.list as u64) {
        return false;
    }

    // And the structure that link belongs to must itself be a module.
    let Some(neighbour) = next_phys.checked_sub(offsets.list as u64) else {
        return false;
    };
    let mut buf = vec![0u8; offsets.size];
    if seance_core::io::read_full(physical.as_data_source(), neighbour, &mut buf) != offsets.size {
        return false;
    }
    candidate_from_bytes(&buf, offsets.state, offsets.name).is_some()
}

/// Offsets the module scan needs, from the build's own layout.
#[derive(Debug, Clone, Copy)]
pub struct ModScanOffsets {
    pub state: usize,
    pub name: usize,
    /// Offset of the `list` member — the `list_head` linking the module list.
    pub list: usize,
    pub size: usize,
}

impl ModScanOffsets {
    pub fn resolve(layout: &BuildBinding, module_size: u64) -> Option<Self> {
        fn at(layout: &BuildBinding, key: &'static str) -> Option<usize> {
            layout.member(key).ok()?.offset().map(|o| o as usize)
        }
        Some(Self {
            state: at(layout, "state")?,
            name: at(layout, "name")?,
            list: at(layout, "list")?,
            size: module_size as usize,
        })
    }
}

/// Sweep physical memory for `struct module` signatures.
pub fn scan_physical(
    physical: &dyn seance_memory::layer::MemoryLayer,
    offsets: ModScanOffsets,
    translate: &dyn Fn(u64) -> Option<u64>,
    max_bytes: u64,
    max_candidates: usize,
) -> (Vec<ScannedModule>, bool) {
    const STRIDE: usize = 8;
    const WINDOW: u64 = 8 * 1024 * 1024;

    // Mapped sections, not a flat range — see `taskscan::scan_physical` for
    // what a flat sweep over a capture with a quarter of a million segments
    // actually examines, which is almost none of it.
    let plan = match seance_memory::scan::derive_sections(
        physical,
        &seance_memory::scan::ScanConfig::default(),
    ) {
        Ok(plan) => plan,
        Err(_) => return (Vec::new(), true),
    };

    let mut buffer = vec![0u8; WINDOW as usize];
    let mut found = Vec::new();
    let mut scanned = 0u64;
    let mut truncated = plan.truncated_at.is_some();

    'sections: for section in &plan.sections {
        let mut at = section.start;
        while at < section.end {
            if found.len() >= max_candidates || scanned >= max_bytes {
                truncated = true;
                break 'sections;
            }
            let want = WINDOW.min(section.end - at) as usize;
            let read =
                seance_core::io::read_full(physical.as_data_source(), at, &mut buffer[..want]);
            if read == 0 {
                break;
            }
            scanned = scanned.saturating_add(read as u64);

            let last = read.saturating_sub(offsets.size);
            let mut cursor = 0usize;
            while cursor <= last {
                if found.len() >= max_candidates {
                    truncated = true;
                    break 'sections;
                }
                let candidate = &buffer[cursor..cursor + offsets.size];
                // Links first: it is the narrow test, so most addresses cost
                // two loads rather than a string scan.
                let shape = classify_links(candidate, offsets.list);
                if shape == LinkShape::NotLinks {
                    cursor += STRIDE;
                    continue;
                }
                if let Some((name, state)) =
                    candidate_from_bytes(candidate, offsets.state, offsets.name)
                {
                    // Physical, because that is the space the sweep works in and
                    // the space the cross-view compares in.
                    let here = at.wrapping_add(cursor as u64);
                    let believable = match shape {
                        LinkShape::Poisoned => true,
                        // `mine` is the candidate's own link member as a
                        // VIRTUAL address, since that is what a neighbour's
                        // `prev` pointer holds.
                        LinkShape::Kernel { next, .. } => {
                            next_is_a_module(physical, translate, offsets, next, here)
                        }
                        LinkShape::NotLinks => false,
                    };
                    if believable {
                        found.push(ScannedModule {
                            address: here,
                            name,
                            state,
                        });
                    }
                }
                cursor += STRIDE;
            }
            let advance = (read as u64).saturating_sub(offsets.size as u64).max(1);
            at = at.saturating_add(advance);
        }
    }
    (found, truncated)
}

#[cfg(test)]
mod tests;
