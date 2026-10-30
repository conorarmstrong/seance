//! Each process's virtual memory areas (VMAs), from `mm_struct.mmap` (pre-6.1)
//! or the `mm_struct.mm_mt` maple tree (6.1+).
//!
//! At parity with Volatility 3's `linux.proc.Maps`. For every process the task
//! walk reached, this opens its memory descriptor and walks the list of
//! `vm_area_struct`s, reporting each region's address range, permissions, and —
//! where the region is file-backed — the path of the file behind it. It is the
//! map an examiner reads to find executable memory with no file behind it, or a
//! writable-executable region, which is the shape of injected code.
//!
//! ## What this walks, and what it does not
//!
//! Every structure read here — `mm_struct`, `vm_area_struct`, `file`, `dentry`,
//! `qstr` — lives in the **kernel** address space, so unlike the environment and
//! bash stages this never opens a process's own page tables and is not defeated
//! by a user page that was swapped out. Only the acquisition capturing kernel
//! memory matters.
//!
//! Linux 6.1 (commit d4af56c5c7c6) moved the VMA set from the `mmap` linked list
//! into `mm_struct.mm_mt`, a maple tree; both are walked (see the [`maple`]
//! module for the tree). Two shapes are still refused **by name** rather than
//! reported as an empty map, because a blank there would read as a process with
//! no memory:
//!
//! * **A maple tree that cannot be read as a tree** — its types absent from the
//!   symbols, or its root unreadable — is reported not-walked with the reason,
//!   never as a process that had no mapped memory.
//! * **A build with no `vm_next`.** The pre-6.1 list is singly linked through
//!   `vm_next`; a build that declares none leaves only the first region
//!   reachable, which is stated, not silently presented as the whole map.
//!
//! Paths are reconstructed by [`crate::paths`]: the mount-crossing walk up to
//! the process's own root where the build allows it, the reduced in-mount walk
//! otherwise, and which one each record got rides on that record as
//! `path_scope` — see [`crate::paths::PATH_SCOPE_NOTE_MOUNT_CROSSING`].

use std::collections::HashSet;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::Obj;

use crate::error::StageError;
use crate::module::STAGE_LINUX_PROCESS_MAPS;
use crate::paths::{self, PathKind, PathResult, PathScope, ProcessRoot};
use crate::profile::LinuxProfile;
use crate::read::signed_to_json;
use crate::space::{self, SpaceRefusal};
use crate::tasks::TaskList;

/// `log2(PAGE)` of an x86-64 kernel and of a 4 KiB-granule arm64 one:
/// `vm_pgoff` is in pages, and a file offset is `pgoff << page_shift`. The
/// shift in force for a profile is its paging spec's own
/// (`PagingSpec::page_offset_bits`: 12 on Intel, the granule's on arm64), so a
/// 16 or 64 KiB arm64 kernel scales by 14 or 16.
#[cfg(test)]
const PAGE_SHIFT: u64 = 12;

/// Ceiling on VMAs one process's walk will report.
///
/// The kernel's own default `vm.max_map_count` is 65530, so a process past this
/// has a corrupt list, not a busy one. Reaching it is a stop reason, never the
/// end of the list.
pub const MAX_VMAS_PER_PROCESS: usize = 65_536;

/// Everything the process-maps stage needs out of the symbol table.
pub const PROC_MAPS_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_PROCESS_MAPS,
    &[
        TypeSpec::new("mm", &["mm_struct"]).required(
            "this kernel declares no memory-descriptor type, so no process's memory map could be \
             reached at all",
        ),
        TypeSpec::new("vma", &["vm_area_struct"]).required(
            "this kernel declares no virtual-memory-area type, so no memory region could be \
             described",
        ),
        // Not required: without it, a file-backed region's path is reported as
        // unavailable rather than the stage refusing to run.
        paths::TYPE_DENTRY,
        paths::TYPE_MOUNT_ENTRY,
        paths::TYPE_DENTRY_OPERATIONS,
        paths::TYPE_INODE,
    ],
    &[
        MemberSpec::new("mm", &["task_struct"], &["mm"]).required(
            "a task structure has no pointer to its memory descriptor, so no process's regions \
             could be reached",
        ),
        MemberSpec::new("vm_start", &["vm_area_struct"], &["vm_start"]).required(
            "a memory region has no start address, so nothing about the process's address space \
             could be stated",
        ),
        MemberSpec::new("vm_end", &["vm_area_struct"], &["vm_end"])
            .required("a memory region has no end address, so its extent could not be established"),
        // The VMA-list head, and the 6.1+ maple-tree member that replaced it.
        // Declared so the stage can *say* the kernel uses the tree rather than
        // leave the map blank.
        MemberSpec::new("mmap", &["mm_struct"], &["mmap"]),
        MemberSpec::new("mm_mt", &["mm_struct"], &["mm_mt"]),
        MemberSpec::new("vm_next", &["vm_area_struct"], &["vm_next"]),
        MemberSpec::new("vm_flags", &["vm_area_struct"], &["vm_flags"]),
        MemberSpec::new("vm_pgoff", &["vm_area_struct"], &["vm_pgoff"]),
        MemberSpec::new("vm_file", &["vm_area_struct"], &["vm_file"]),
        // Path reconstruction. See `crate::paths`.
        paths::SPEC_FILE_DENTRY,
        paths::SPEC_FILE_MNT,
        paths::SPEC_MOUNT_MNT,
        paths::SPEC_MNT_PARENT,
        paths::SPEC_MNT_MOUNTPOINT,
        paths::SPEC_MNT_ROOT,
        paths::SPEC_TASK_FS,
        paths::SPEC_FS_ROOT_DENTRY,
        paths::SPEC_FS_ROOT_MNT,
        paths::SPEC_D_PARENT,
        paths::SPEC_D_NAME_PTR,
        paths::SPEC_D_NAME_LEN,
        paths::SPEC_D_INAME,
        paths::SPEC_D_OP,
        paths::SPEC_D_DNAME,
        paths::SPEC_D_INODE,
        paths::SPEC_I_INO,
    ],
);

/// Caps for one process-maps survey.
#[derive(Debug, Clone)]
pub struct ProcessMapsConfig {
    /// Ceiling on VMAs reported per process.
    pub max_vmas: usize,
}

impl Default for ProcessMapsConfig {
    fn default() -> Self {
        Self {
            max_vmas: MAX_VMAS_PER_PROCESS,
        }
    }
}

/// How a region walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkStop {
    /// `vm_next` was null: the list's natural, complete terminator.
    CompletedNull,
    /// The per-process cap fired. A floor, not the region count.
    CapReached,
    /// `vm_next` pointed back to a VMA already seen.
    Cycle(u64),
    /// A `vm_area_struct` or its `vm_next` would not read; the chain cannot be
    /// followed past this point.
    Unreadable(String),
    /// This build declares no `vm_next`, so only the first region was reachable.
    NoForwardLink,
}

impl WalkStop {
    /// Whether the walk ended short of enumerating the whole list.
    fn is_a_gap(&self) -> bool {
        !matches!(self, WalkStop::CompletedNull)
    }

    fn as_str(&self) -> &'static str {
        match self {
            WalkStop::CompletedNull => "completed_null",
            WalkStop::CapReached => "cap_reached",
            WalkStop::Cycle(_) => "cycle",
            WalkStop::Unreadable(_) => "unreadable",
            WalkStop::NoForwardLink => "no_forward_link",
        }
    }

    fn incomplete(&self, task_address: u64) -> Option<Incomplete> {
        let reason = match self {
            WalkStop::CompletedNull => return None,
            WalkStop::CapReached => IncompleteReason::CapReached,
            WalkStop::Cycle(_) | WalkStop::NoForwardLink => IncompleteReason::ShortRead,
            WalkStop::Unreadable(_) => IncompleteReason::ShortRead,
        };
        let detail = match self {
            WalkStop::CompletedNull => unreachable!(),
            WalkStop::CapReached => format!(
                "the VMA walk for the task_struct at {task_address:#x} stopped at its cap of \
                 {MAX_VMAS_PER_PROCESS}; the region count is a floor"
            ),
            WalkStop::Cycle(at) => format!(
                "the VMA list for the task_struct at {task_address:#x} looped back to {at:#x}; the \
                 remaining regions could not be enumerated"
            ),
            WalkStop::Unreadable(detail) => format!(
                "the VMA list for the task_struct at {task_address:#x} could not be followed to \
                 its end: {detail}"
            ),
            WalkStop::NoForwardLink => format!(
                "this kernel build declares no vm_next, so only the first region of the \
                 task_struct at {task_address:#x} was reachable"
            ),
        };
        Some(Incomplete::new(reason, detail))
    }
}

/// Why a process contributed the regions it did — or none.
#[derive(Debug, Clone)]
pub enum MapsOutcome {
    /// The VMA list was walked. It may be empty (a null list head on a live
    /// descriptor), which is a genuine zero, not a gap.
    Walked,
    /// A kernel thread: no user address space, so there was never a map. Not a
    /// gap.
    KernelThread,
    /// The memory descriptor exists but its bytes, or its VMA list head, would
    /// not read. A gap.
    DescriptorUnreadable(String),
    /// The VMAs live in `mm_mt`, a maple tree that could not be read *as a tree*
    /// (its types are absent from the symbols, or the root pointer would not
    /// read). A gap, refused by name — distinct from an empty tree, which is a
    /// walked, genuinely-empty map.
    MapleTreeUnwalked,
    /// This build declares neither `mmap` nor `mm_mt`, so the VMA set could not
    /// be located. A gap.
    NoVmaMemberDeclared,
}

impl MapsOutcome {
    fn is_a_gap(&self) -> bool {
        !matches!(self, MapsOutcome::Walked | MapsOutcome::KernelThread)
    }

    fn class(&self) -> &'static str {
        match self {
            MapsOutcome::Walked => "walked",
            MapsOutcome::KernelThread => "kernel_thread",
            MapsOutcome::DescriptorUnreadable(_) => "descriptor_unreadable",
            MapsOutcome::MapleTreeUnwalked => "maple_tree_unwalked",
            MapsOutcome::NoVmaMemberDeclared => "no_vma_member_declared",
        }
    }

    fn detail(&self) -> String {
        match self {
            MapsOutcome::Walked => "the VMA list was walked".to_string(),
            MapsOutcome::KernelThread => {
                "this task has no user address space, so it never had a memory map".to_string()
            }
            MapsOutcome::DescriptorUnreadable(detail) => detail.clone(),
            MapsOutcome::MapleTreeUnwalked => {
                "this kernel stores VMAs in mm_struct.mm_mt, a maple tree that could not be read as \
                 a tree here (its node types are absent from the symbols, or its root would not \
                 read); the region list is therefore absent and is NOT a statement that the \
                 process has no mapped memory"
                    .to_string()
            }
            MapsOutcome::NoVmaMemberDeclared => {
                "this kernel build declares neither mm_struct.mmap nor mm_struct.mm_mt, so the VMA \
                 set could not be located"
                    .to_string()
            }
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "class": self.class(),
            "detail": self.detail(),
            "is_a_gap": self.is_a_gap(),
        })
    }
}

/// One virtual memory area.
#[derive(Debug, Clone)]
pub struct VmaRegion {
    /// Address of the `vm_area_struct`.
    pub address: u64,
    /// Start of the region in the process's address space.
    pub vm_start: Field<u64>,
    /// End of the region (exclusive).
    pub vm_end: Field<u64>,
    /// The raw protection/flags word.
    pub vm_flags: Field<u64>,
    /// The page offset into the backing file, in pages.
    pub vm_pgoff: Field<u64>,
    /// The byte offset into the backing file (`vm_pgoff << 12`), or
    /// [`Field::NotApplicable`] for an anonymous region.
    pub file_offset: Field<u64>,
    /// Whether the region has no backing file.
    pub anonymous: bool,
    /// The path of the backing file, or the reason there is none.
    pub path: Field<String>,
    /// Whether every path component was valid UTF-8.
    pub path_well_formed: bool,
    /// Whether the path walk was cut short (depth bound or cycle).
    pub path_truncated: bool,
    /// Which walk produced the path, and how it ended.
    pub path_scope: PathScope,
    /// What the path names.
    pub path_kind: PathKind,
    /// Whether the region passes Volatility's validity gate. A smeared region
    /// (start past end, or a length that is not a page multiple) is kept and
    /// flagged rather than dropped.
    pub is_valid: bool,
    /// Anything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl VmaRegion {
    /// The names of the fields that exist on this build and could not be read.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, unavailable) in [
            ("vm_start", self.vm_start.is_unavailable()),
            ("vm_end", self.vm_end.is_unavailable()),
            ("vm_flags", self.vm_flags.is_unavailable()),
            ("vm_pgoff", self.vm_pgoff.is_unavailable()),
            ("path", self.path.is_unavailable()),
        ] {
            if unavailable {
                out.push(name);
            }
        }
        out
    }

    /// Permissions decoded from `vm_flags`, when it was read.
    ///
    /// A build with no `vm_flags` member yields the field's absence, never
    /// all-false: "this region has no permissions" and "this build does not
    /// record permissions" are different claims.
    fn permissions_json(&self) -> serde_json::Value {
        match &self.vm_flags {
            Field::Known(flags) => serde_json::json!({
                "read": flags & 0x1 != 0,
                "write": flags & 0x2 != 0,
                "exec": flags & 0x4 != 0,
                "shared": flags & 0x8 != 0,
            }),
            Field::NotDeclared { member } => serde_json::json!({ "not_declared": member }),
            Field::NotApplicable => serde_json::json!({ "not_applicable": true }),
            Field::Unavailable(detail) => serde_json::json!({ "unavailable": detail }),
        }
    }

    /// The `/proc/pid/maps` style protection string (`r-xp`), when flags were
    /// read.
    fn protection(&self) -> Option<String> {
        self.vm_flags.known().map(|flags| {
            let bit = |mask: u64, ch: char| if flags & mask != 0 { ch } else { '-' };
            format!(
                "{}{}{}{}",
                bit(0x1, 'r'),
                bit(0x2, 'w'),
                bit(0x4, 'x'),
                if flags & 0x8 != 0 { 's' } else { 'p' },
            )
        })
    }

    /// Serializable form for one region.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "vm_start": self.vm_start.to_json_address(),
            "vm_end": self.vm_end.to_json_address(),
            "vm_flags": self.vm_flags.to_json(),
            "permissions": self.permissions_json(),
            "protection": self.protection(),
            "vm_pgoff": self.vm_pgoff.to_json(),
            "file_offset": self.file_offset.to_json_address(),
            "anonymous": self.anonymous,
            "is_valid": self.is_valid,
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        });
        PathResult {
            path: self.path.clone(),
            well_formed: self.path_well_formed,
            truncated: self.path_truncated,
            scope: self.path_scope.clone(),
            kind: self.path_kind.clone(),
        }
        .stamp(&mut value);
        value
    }
}

/// One process's memory map.
#[derive(Debug, Clone)]
pub struct ProcessMaps {
    /// Address of the `task_struct`.
    pub task_address: u64,
    /// The process id.
    pub pid: Field<i64>,
    /// The parent process id.
    pub ppid: Field<i64>,
    /// The process name.
    pub comm: Field<String>,
    /// The regions, in the order the list gave them.
    pub regions: Vec<VmaRegion>,
    /// Why these regions (or none).
    pub outcome: MapsOutcome,
    /// How the region walk ended (meaningful only when `outcome` is `Walked`).
    pub walk_stop: WalkStop,
    /// The process's root directory, which its paths were walked up to — or
    /// why it could not be established.
    pub root: ProcessRoot,
}

impl ProcessMaps {
    /// Regions that pass the validity gate.
    fn valid_count(&self) -> usize {
        self.regions.iter().filter(|region| region.is_valid).count()
    }

    /// Whether this process contributed everything it should have.
    fn is_a_gap(&self) -> bool {
        self.outcome.is_a_gap()
            || (matches!(self.outcome, MapsOutcome::Walked) && self.walk_stop.is_a_gap())
            || self
                .regions
                .iter()
                .any(|region| !region.unreadable_fields().is_empty())
    }

    /// This process's reasons for being short.
    fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let MapsOutcome::Walked = self.outcome {
            if let Some(reason) = self.walk_stop.incomplete(self.task_address) {
                out.push(reason);
            }
        } else if self.outcome.is_a_gap() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the process at the task_struct at {:#x} has no readable memory map: {}",
                    self.task_address,
                    self.outcome.detail()
                ),
            ));
        }
        for region in &self.regions {
            let unreadable = region.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the vm_area_struct at {:#x} has field(s) that exist on this build and \
                         could not be read: {}",
                        region.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for one process.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task_address": self.task_address,
            "task_address_hex": format!("{:#x}", self.task_address),
            "pid": signed_to_json(&self.pid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "vma_count": self.valid_count(),
            "vma_count_including_smeared": self.regions.len(),
            "regions": self.regions.iter().map(VmaRegion::to_json).collect::<Vec<_>>(),
            "outcome": self.outcome.to_json(),
            "walk_stop": self.walk_stop.as_str(),
            "root": crate::lsof::root_json(&self.root),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Every process's memory map, and everything that qualifies the list.
#[derive(Debug, Clone)]
pub struct ProcessMapsSurvey {
    /// One entry per process the task walk reached.
    pub processes: Vec<ProcessMaps>,
    /// What this kernel build provided for the stage.
    pub layout: serde_json::Value,
    /// Which walk the survey attempted for every path, and the sentence that
    /// explains it. Each record carries its own scope; this is the summary.
    pub path_scope: &'static str,
    pub path_scope_note: &'static str,
    /// Whether the task-list walk this rests on finished end to end.
    task_complete: bool,
    /// The task walk's own reasons for being short.
    task_incomplete: Vec<Incomplete>,
}

impl ProcessMapsSurvey {
    /// The number of processes surveyed.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Total valid regions across every process.
    pub fn region_count(&self) -> usize {
        self.processes.iter().map(ProcessMaps::valid_count).sum()
    }

    /// Whether the walk finished and every process's map was fully established.
    pub fn is_complete(&self) -> bool {
        self.task_complete && !self.processes.iter().any(ProcessMaps::is_a_gap)
    }

    /// Everything a report must declare.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.task_incomplete.clone();
        for process in &self.processes {
            out.extend(process.incomplete());
        }
        out
    }

    /// Serializable form for the process-maps artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process_count": self.process_count(),
            "region_count": self.region_count(),
            "complete": self.is_complete(),
            "path_scope": self.path_scope,
            "path_scope_note": self.path_scope_note,
            "path_scope_is_per_record": true,
            "processes": self.processes.iter().map(ProcessMaps::to_json).collect::<Vec<_>>(),
            "layout": self.layout,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Bind the process-maps stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(PROC_MAPS_LAYOUT.bind(&reader)?)
}

/// Walk every process's memory map.
///
/// # Errors
///
/// Only when the stage could not run at all — a required type or member is
/// absent, which binding already refused. A process whose map could not be read
/// is a [`ProcessMaps`] whose outcome says why, not an error.
pub fn survey_process_maps(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &ProcessMapsConfig,
) -> Result<ProcessMapsSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    survey_with_reader(
        &reader,
        layout,
        tasks,
        config,
        profile.paging.page_offset_bits(),
    )
}

/// The walk itself, over a reader the caller supplies.
///
/// Split from [`survey_process_maps`] so the walk can be driven over a synthetic
/// kernel image in a unit test — the reader is the only thing it needs from a
/// profile, and a test has no profile.
fn survey_with_reader(
    reader: &seance_memory::object::StructReader,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &ProcessMapsConfig,
    page_shift: u32,
) -> Result<ProcessMapsSurvey, StageError> {
    let task_type = layout
        .member("mm")?
        .type_name()
        .expect("a required member is declared or binding refused the stage");
    let vma_type = layout
        .type_of("vma")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");

    let mut processes = Vec::with_capacity(tasks.tasks.len());
    for task in &tasks.tasks {
        let task_obj = match reader.object(task.address, task_type) {
            Ok(obj) => obj,
            Err(err) => {
                processes.push(ProcessMaps {
                    task_address: task.address,
                    pid: task.pid.clone(),
                    ppid: task.ppid.clone(),
                    comm: task.comm.clone(),
                    regions: Vec::new(),
                    outcome: MapsOutcome::DescriptorUnreadable(format!(
                        "the task_struct could not be reopened to read its memory descriptor: {err}"
                    )),
                    walk_stop: WalkStop::CompletedNull,
                    root: ProcessRoot::Unavailable(
                        "the task_struct could not be reopened".to_string(),
                    ),
                });
                continue;
            }
        };

        let root = paths::process_root(layout, &task_obj)?;
        let (outcome, regions, walk_stop) = walk_one(
            reader,
            layout,
            &task_obj,
            vma_type,
            config.max_vmas,
            &root,
            page_shift,
        )?;
        processes.push(ProcessMaps {
            task_address: task.address,
            pid: task.pid.clone(),
            ppid: task.ppid.clone(),
            comm: task.comm.clone(),
            regions,
            outcome,
            walk_stop,
            root,
        });
    }

    let (path_scope, path_scope_note) = paths::survey_scope(layout);
    Ok(ProcessMapsSurvey {
        processes,
        layout: layout.to_json(),
        path_scope,
        path_scope_note,
        task_complete: tasks.is_complete(),
        task_incomplete: tasks.incomplete(),
    })
}

/// Walk one process's VMA list, resolving where the list lives first.
fn walk_one(
    reader: &seance_memory::object::StructReader,
    layout: &BuildBinding,
    task_obj: &Obj,
    vma_type: &'static str,
    max_vmas: usize,
    root: &ProcessRoot,
    page_shift: u32,
) -> Result<(MapsOutcome, Vec<VmaRegion>, WalkStop), StageError> {
    // The memory descriptor, or why there is none.
    let mm = match space::memory_descriptor(layout, task_obj, "mm")? {
        Ok(mm) => mm,
        Err(SpaceRefusal::NoUserAddressSpace) => {
            return Ok((
                MapsOutcome::KernelThread,
                Vec::new(),
                WalkStop::CompletedNull,
            ));
        }
        Err(refusal) => {
            return Ok((
                MapsOutcome::DescriptorUnreadable(refusal.detail()),
                Vec::new(),
                WalkStop::CompletedNull,
            ));
        }
    };

    // Where the VMA set lives. A null head on a live descriptor is a genuine
    // zero; a build with only the maple tree is refused by name.
    let head = match layout.read_pointer(&mm, "mmap")? {
        Field::Known(0) | Field::NotApplicable => {
            return Ok((MapsOutcome::Walked, Vec::new(), WalkStop::CompletedNull));
        }
        Field::Known(address) => address,
        Field::Unavailable(detail) => {
            return Ok((
                MapsOutcome::DescriptorUnreadable(detail),
                Vec::new(),
                WalkStop::CompletedNull,
            ));
        }
        Field::NotDeclared { .. } => {
            // Kernel 6.1+ moved the VMA set into `mm_struct.mm_mt`, a maple tree.
            // Walk it if the type information is present; only refuse by name when
            // it is genuinely unreachable.
            let has_mt = layout
                .member("mm_mt")
                .map(|bound| bound.is_declared())
                .unwrap_or(false);
            if !has_mt {
                return Ok((
                    MapsOutcome::NoVmaMemberDeclared,
                    Vec::new(),
                    WalkStop::CompletedNull,
                ));
            }
            return maple::walk_maple_vmas(
                reader, layout, vma_type, &mm, max_vmas, root, page_shift,
            );
        }
    };

    let (regions, stop) = walk_vmas(reader, layout, vma_type, head, max_vmas, root, page_shift)?;
    Ok((MapsOutcome::Walked, regions, stop))
}

/// The bespoke VMA walk.
///
/// Unlike a `list_head` walk, `vm_next` is a NULL-terminated singly linked
/// chain: a null pointer is the natural, **complete** end, not truncation. The
/// visited set guards against a cycle, and the cap against a corrupt list.
fn walk_vmas(
    reader: &seance_memory::object::StructReader,
    layout: &BuildBinding,
    vma_type: &'static str,
    head: u64,
    max_vmas: usize,
    root: &ProcessRoot,
    page_shift: u32,
) -> Result<(Vec<VmaRegion>, WalkStop), StageError> {
    let mut regions: Vec<VmaRegion> = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut current = Some(head);

    let stop = loop {
        let Some(address) = current else {
            break WalkStop::CompletedNull;
        };
        if regions.len() >= max_vmas {
            break WalkStop::CapReached;
        }
        if !visited.insert(address) {
            break WalkStop::Cycle(address);
        }
        let vma = match reader.object(address, vma_type) {
            Ok(obj) => obj,
            Err(err) => {
                break WalkStop::Unreadable(crate::read::unreadable_detail(
                    "a vm_area_struct",
                    address,
                    &err,
                ));
            }
        };

        regions.push(read_region(reader, layout, &vma, root, page_shift)?);

        // Advance. A null forward pointer is the complete terminator.
        match layout.read_pointer(&vma, "vm_next")? {
            Field::Known(0) | Field::NotApplicable => break WalkStop::CompletedNull,
            Field::Known(next) => current = Some(next),
            Field::NotDeclared { .. } => break WalkStop::NoForwardLink,
            Field::Unavailable(detail) => break WalkStop::Unreadable(detail),
        }
    };

    Ok((regions, stop))
}

/// Read one `vm_area_struct` into a region row. Never fails on a field: each way
/// of not getting a value is a variant on the row.
fn read_region(
    reader: &seance_memory::object::StructReader,
    layout: &BuildBinding,
    vma: &Obj,
    root: &ProcessRoot,
    page_shift: u32,
) -> Result<VmaRegion, StageError> {
    let vm_start = layout.read_unsigned(vma, "vm_start")?;
    let vm_end = layout.read_unsigned(vma, "vm_end")?;
    let vm_flags = layout.read_unsigned(vma, "vm_flags")?;
    let vm_pgoff = layout.read_unsigned(vma, "vm_pgoff")?;

    let (anonymous, path, file_offset) =
        resolve_backing(reader, layout, vma, &vm_pgoff, root, page_shift)?;
    let is_valid = validity(&vm_start, &vm_end, page_shift);

    let mut notes = Vec::new();
    if let (Some(start), Some(end)) = (vm_start.known(), vm_end.known()) {
        if !is_valid {
            notes.push(format!(
                "this region does not pass the validity gate (start {start:#x}, end {end:#x}); it \
                 is kept and flagged rather than dropped"
            ));
        }
    }

    Ok(VmaRegion {
        address: vma.address(),
        vm_start,
        vm_end,
        vm_flags,
        vm_pgoff,
        file_offset,
        anonymous,
        path: path.path,
        path_well_formed: path.well_formed,
        path_truncated: path.truncated,
        path_scope: path.scope,
        path_kind: path.kind,
        is_valid,
        notes,
    })
}

/// Resolve the backing file: whether the region is anonymous, its path, and its
/// file offset.
fn resolve_backing(
    reader: &seance_memory::object::StructReader,
    layout: &BuildBinding,
    vma: &Obj,
    vm_pgoff: &Field<u64>,
    root: &ProcessRoot,
    page_shift: u32,
) -> Result<(bool, PathResult, Field<u64>), StageError> {
    let vm_file_member = layout.member("vm_file")?.member();
    Ok(match layout.read_pointer(vma, "vm_file")? {
        // No such member on this build: the path is not-declared, and the region
        // cannot be called anonymous (we did not read a null file — we could not
        // ask). File offset is likewise not-declared.
        Field::NotDeclared { member } => (
            false,
            PathResult::from_field(Field::NotDeclared { member }),
            Field::NotDeclared { member },
        ),
        // A null backing file: the region is anonymous. An answer, not a gap.
        Field::Known(0) | Field::NotApplicable => (
            true,
            PathResult::from_field(Field::NotApplicable),
            Field::NotApplicable,
        ),
        Field::Unavailable(detail) => (
            false,
            PathResult::from_field(Field::Unavailable(detail.clone())),
            Field::Unavailable(detail),
        ),
        Field::Known(_) => {
            // File-backed. Follow to the file and reconstruct the path.
            let member = vm_file_member.expect("a Known pointer read means the member is declared");
            let path = match vma.follow(member) {
                Ok(Some(file)) => paths::path_for_file(reader, layout, &file, root),
                Ok(None) => PathResult::unavailable(
                    "the region names a backing file whose pointer read back null",
                ),
                Err(err) => {
                    PathResult::unavailable(format!("the backing file could not be read: {err}"))
                }
            };
            let file_offset = scale_pgoff_to_bytes(vm_pgoff, page_shift);
            (false, path, file_offset)
        }
    })
}

/// The byte offset into a backing file for a page offset: `pgoff * PAGE`,
/// with `PAGE = 1 << page_shift`, the kernel's own page size.
///
/// Multiplying (rather than shifting) is what makes the overflow real: a page
/// offset with high bits set returns [`Field::Unavailable`] instead of silently
/// dropping those bits, which `checked_shl` — a shift-*amount* guard, not a
/// value guard — would have done.
fn scale_pgoff_to_bytes(vm_pgoff: &Field<u64>, page_shift: u32) -> Field<u64> {
    match vm_pgoff {
        Field::Known(pages) => match 1u64
            .checked_shl(page_shift)
            .and_then(|page| pages.checked_mul(page))
        {
            Some(offset) => Field::Known(offset),
            None => Field::Unavailable(
                "the page offset does not scale to a byte offset without overflowing".to_string(),
            ),
        },
        Field::NotDeclared { member } => Field::NotDeclared { member },
        Field::NotApplicable => Field::NotApplicable,
        Field::Unavailable(detail) => Field::Unavailable(detail.clone()),
    }
}

/// Volatility's validity gate: `start <= end`, not the `(0, 0)` region, and a
/// page-aligned length.
fn validity(vm_start: &Field<u64>, vm_end: &Field<u64>, page_shift: u32) -> bool {
    match (vm_start.known(), vm_end.known()) {
        (Some(&start), Some(&end)) => {
            let page_mask = (1u64 << page_shift) - 1;
            start <= end && !(start == 0 && end == 0) && (end - start) & page_mask == 0
        }
        // A region whose extent could not be read is not asserted valid.
        _ => false,
    }
}

/// The 6.1+ maple-tree VMA walk (`mm_struct.mm_mt`).
///
/// Linux 6.1 (commit d4af56c5c7c6) replaced the `mmap` linked list with a maple
/// tree, so a walk of `vm_next` yields nothing on every modern kernel. The tree
/// stores each `vm_area_struct` pointer in a leaf slot, keyed by address range.
///
/// The recursion, the mask/shift constants, and the type/leaf classification are
/// transcribed from Volatility 3's `maple_tree.get_slot_iter`
/// (`framework/symbols/linux/extensions/__init__.py`); the struct offsets and
/// slot counts are read from the **image's own** `maple_node` / `maple_range_64`
/// / `maple_arange_64` types, never assumed. Every node's stored parent pointer
/// is checked against the parent it was reached from, so a slot that does not
/// point at a real child of this node is dropped rather than followed into
/// fabricated regions.
mod maple {
    use super::{read_region, BuildBinding, MapsOutcome, ProcessRoot, VmaRegion, WalkStop};
    use crate::error::StageError;
    use seance_memory::object::{Obj, StructReader};
    use std::collections::HashSet;

    // Node-pointer encoding (include/linux/maple_tree.h): the low byte carries
    // type and flags; the node address is the pointer with that byte cleared.
    const NODE_POINTER_MASK: u64 = 0xFF;
    const NODE_TYPE_SHIFT: u64 = 3;
    const NODE_TYPE_MASK: u64 = 0x0F;
    // Tree height lives in ma_flags, bounding the recursion.
    const FLAGS_HEIGHT_MASK: u64 = 0x7C;
    const FLAGS_HEIGHT_OFFSET: u64 = 2;

    const MAPLE_DENSE: u64 = 0;
    const MAPLE_LEAF_64: u64 = 1;
    const MAPLE_RANGE_64: u64 = 2;
    const MAPLE_ARANGE_64: u64 = 3;

    // The height field is five bits; a tree taller than this is corrupt, and the
    // bound also stops a pointer cycle the visited-set somehow missed.
    const MAX_DEPTH: u32 = 32;
    // A single node holds at most 32 pointer slots (256-byte node / 8); refuse a
    // symbol table that claims more before iterating it.
    const MAX_SLOTS: u64 = 64;

    /// Walk the maple tree at `mm_struct.mm_mt` and read every VMA it stores.
    pub fn walk_maple_vmas(
        reader: &StructReader,
        layout: &BuildBinding,
        vma_type: &'static str,
        mm: &Obj,
        max_vmas: usize,
        root: &ProcessRoot,
        page_shift: u32,
    ) -> Result<(MapsOutcome, Vec<VmaRegion>, WalkStop), StageError> {
        // The tree is embedded in the descriptor; its own address is what each
        // node records as the ultimate parent.
        let mm_mt_off = match reader.member_offset("mm_struct", "mm_mt") {
            Ok(off) => off.bytes(),
            Err(e) => return Ok(unavailable(format!("mm_struct.mm_mt offset: {e}"))),
        };
        let tree_addr = mm.address().wrapping_add(mm_mt_off);
        let tree = match reader.object(tree_addr, "maple_tree") {
            Ok(t) => t,
            Err(e) => return Ok(unavailable(format!("maple_tree at {tree_addr:#x}: {e}"))),
        };
        let ma_flags = tree.unsigned("ma_flags").unwrap_or(0);
        let ma_root = match tree.pointer("ma_root") {
            Ok(r) => r,
            Err(e) => return Ok(unavailable(format!("maple_tree.ma_root: {e}"))),
        };
        // An empty tree, or a tree whose single entry is a value rather than a
        // node, holds no VMA the linked-list era would have had: report an empty,
        // walked map (a genuine zero) rather than a gap.
        if ma_root == 0 {
            return Ok((MapsOutcome::Walked, Vec::new(), WalkStop::CompletedNull));
        }
        let expected_depth = ((ma_flags & FLAGS_HEIGHT_MASK) >> FLAGS_HEIGHT_OFFSET) as u32;
        let tree_self = tree_addr & !NODE_POINTER_MASK;

        let mut walk = Walk {
            reader,
            leaves: Vec::new(),
            seen: HashSet::new(),
            cap: max_vmas,
            capped: false,
            cycle: None,
            skipped: 0,
        };
        walk.descend(ma_root, tree_self, expected_depth, 1);

        // Materialise the leaf pointers into regions. A slot that will not read as
        // a vm_area_struct is skipped (the maple tree keeps freed slots), never
        // reported as a region.
        let mut regions: Vec<VmaRegion> = Vec::new();
        let mut stop = if walk.capped {
            WalkStop::CapReached
        } else if let Some(at) = walk.cycle {
            WalkStop::Cycle(at)
        } else {
            WalkStop::CompletedNull
        };
        let mut placed: HashSet<u64> = HashSet::new();
        for &addr in &walk.leaves {
            if addr < 0x1000 || !placed.insert(addr) {
                continue;
            }
            if regions.len() >= max_vmas {
                stop = WalkStop::CapReached;
                break;
            }
            if let Ok(vma) = reader.object(addr, vma_type) {
                regions.push(read_region(reader, layout, &vma, root, page_shift)?);
            }
        }
        Ok((MapsOutcome::Walked, regions, stop))
    }

    fn unavailable(detail: String) -> (MapsOutcome, Vec<VmaRegion>, WalkStop) {
        (
            MapsOutcome::MapleTreeUnwalked,
            Vec::new(),
            WalkStop::Unreadable(detail),
        )
    }

    struct Walk<'a> {
        reader: &'a StructReader,
        /// Leaf slot values: the `vm_area_struct` pointers.
        leaves: Vec<u64>,
        /// Node addresses already descended, guarding against a pointer cycle.
        seen: HashSet<u64>,
        cap: usize,
        capped: bool,
        cycle: Option<u64>,
        /// Nodes dropped for a parent-pointer mismatch or an unreadable slot.
        skipped: u32,
    }

    impl Walk<'_> {
        fn descend(&mut self, entry: u64, parent: u64, expected_depth: u32, depth: u32) {
            if self.capped || self.leaves.len() >= self.cap {
                self.capped = true;
                return;
            }
            let node = entry & !NODE_POINTER_MASK;
            let node_type = (entry >> NODE_TYPE_SHIFT) & NODE_TYPE_MASK;
            if node < 0x1000 {
                return;
            }
            if !self.seen.insert(node) {
                self.cycle.get_or_insert(node);
                return;
            }
            if depth > MAX_DEPTH || depth > expected_depth.saturating_add(1) {
                self.skipped += 1;
                return;
            }
            // The node's first field is its parent MTE; its top bits must match
            // the node we reached this one from, or this slot pointed at
            // something that is not a child of this node.
            match self.reader.read_pointer_at(node) {
                Ok(parent_mte) if (parent_mte & !NODE_POINTER_MASK) == parent => {}
                _ => {
                    self.skipped += 1;
                    return;
                }
            }

            match node_type {
                MAPLE_LEAF_64 => self.harvest_leaves(node, "mr64.slot"),
                MAPLE_DENSE => self.harvest_dense(node),
                MAPLE_RANGE_64 => self.recurse(node, "mr64.slot", expected_depth, depth),
                MAPLE_ARANGE_64 => self.recurse(node, "ma64.slot", expected_depth, depth),
                _ => {
                    self.skipped += 1;
                }
            }
        }

        /// Read a leaf node's slots as stored values (`vm_area_struct` pointers).
        fn harvest_leaves(&mut self, node: u64, path: &str) {
            for slot in self.slots(node, path) {
                // A non-empty slot has bits above the low nibble set.
                if slot & !NODE_TYPE_MASK != 0 {
                    if self.leaves.len() >= self.cap {
                        self.capped = true;
                        return;
                    }
                    self.leaves.push(slot);
                }
            }
        }

        /// A dense node stores values in the anonymous first slot array, right
        /// after the parent pointer. VMA trees do not use dense nodes, so this is
        /// a cold path kept for completeness.
        fn harvest_dense(&mut self, node: u64) {
            let ptr = self.reader.pointer_size().unwrap_or(8) as u64;
            let count = self
                .reader
                .size_of("maple_node")
                .map(|s| (s.bytes().saturating_sub(ptr)) / ptr)
                .unwrap_or(0)
                .min(MAX_SLOTS);
            for i in 0..count {
                if let Ok(slot) = self.reader.read_pointer_at(node + ptr + i * ptr) {
                    if slot & !NODE_TYPE_MASK != 0 {
                        if self.leaves.len() >= self.cap {
                            self.capped = true;
                            return;
                        }
                        self.leaves.push(slot);
                    }
                }
            }
        }

        /// Recurse into an internal node's child slots.
        fn recurse(&mut self, node: u64, path: &str, expected_depth: u32, depth: u32) {
            for slot in self.slots(node, path) {
                if slot & !NODE_TYPE_MASK != 0 {
                    self.descend(slot, node, expected_depth, depth + 1);
                    if self.capped {
                        return;
                    }
                }
            }
        }

        /// Read a node's slot array (pointer per slot) from the image's own type.
        fn slots(&self, node: u64, path: &str) -> Vec<u64> {
            let Ok(obj) = self.reader.object(node, "maple_node") else {
                return Vec::new();
            };
            let Ok(count) = obj.array_len_capped(path, MAX_SLOTS) else {
                return Vec::new();
            };
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                match obj
                    .element_address(path, i)
                    .and_then(|addr| self.reader.read_pointer_at(addr))
                {
                    Ok(v) => out.push(v),
                    Err(_) => break,
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(vm_start: Field<u64>, vm_end: Field<u64>, vm_flags: Field<u64>) -> VmaRegion {
        VmaRegion {
            address: 0xFFFF_8800_1234_0000,
            vm_start,
            vm_end,
            vm_flags,
            vm_pgoff: Field::Known(0),
            file_offset: Field::NotApplicable,
            anonymous: true,
            path: Field::NotApplicable,
            path_well_formed: true,
            path_truncated: false,
            path_scope: PathScope::MountRelative("test".into()),
            path_kind: PathKind::File,
            is_valid: true,
            notes: Vec::new(),
        }
    }

    #[test]
    fn permissions_decode_from_the_flags_word() {
        // VM_READ|VM_EXEC, private: an executable code mapping.
        let r = region(
            Field::Known(0x400000),
            Field::Known(0x401000),
            Field::Known(0x1 | 0x4),
        );
        let json = r.to_json();
        assert_eq!(json["permissions"]["read"], true);
        assert_eq!(json["permissions"]["write"], false);
        assert_eq!(json["permissions"]["exec"], true);
        assert_eq!(json["permissions"]["shared"], false);
        assert_eq!(json["protection"], "r-xp");
    }

    #[test]
    fn a_writable_executable_region_reads_as_wx() {
        let r = region(
            Field::Known(0x7f0000),
            Field::Known(0x7f1000),
            Field::Known(0x1 | 0x2 | 0x4 | 0x8),
        );
        assert_eq!(r.to_json()["protection"], "rwxs");
    }

    #[test]
    fn a_build_with_no_flags_member_does_not_read_as_no_permissions() {
        // The distinction the whole tier is built on: "this build does not record
        // permissions" must not render as a region with r/w/x all clear.
        let r = region(
            Field::Known(0x1000),
            Field::Known(0x2000),
            Field::NotDeclared { member: "vm_flags" },
        );
        let json = r.to_json();
        assert_eq!(json["permissions"]["not_declared"], "vm_flags");
        assert!(
            json["permissions"].get("read").is_none(),
            "an absent flags word has no permission booleans: {}",
            json["permissions"]
        );
        assert!(json["protection"].is_null());
    }

    #[test]
    fn the_validity_gate_matches_volatility() {
        // start <= end, not (0,0), page-aligned length.
        assert!(validity(&Field::Known(0x1000), &Field::Known(0x3000), 12));
        assert!(
            !validity(&Field::Known(0x3000), &Field::Known(0x1000), 12),
            "start past end"
        );
        assert!(
            !validity(&Field::Known(0), &Field::Known(0), 12),
            "the (0,0) region"
        );
        assert!(
            !validity(&Field::Known(0x1000), &Field::Known(0x1800), 12),
            "length not a page multiple"
        );
        // A region whose extent could not be read is not asserted valid.
        assert!(!validity(
            &Field::Unavailable("hole".into()),
            &Field::Known(0x2000),
            12
        ));
    }

    #[test]
    fn a_smeared_region_is_kept_and_flagged_not_dropped() {
        let r = region(
            Field::Known(0x5000),
            Field::Known(0x2000), // end before start
            Field::Known(0x1),
        );
        assert!(!validity(&r.vm_start, &r.vm_end, 12));
    }

    #[test]
    fn an_anonymous_region_has_no_path_and_no_file_offset_but_that_is_not_a_gap() {
        let r = region(
            Field::Known(0x1000),
            Field::Known(0x2000),
            Field::Known(0x3),
        );
        let json = r.to_json();
        assert_eq!(json["anonymous"], true);
        assert_eq!(json["path"]["kind"], "not_applicable");
        assert_eq!(json["file_offset"]["kind"], "not_applicable");
        assert!(
            r.unreadable_fields().is_empty(),
            "an anonymous region is complete, not damaged"
        );
    }

    #[test]
    fn a_region_whose_extent_did_not_read_is_a_gap() {
        let r = region(
            Field::Unavailable("the page was not acquired".into()),
            Field::Known(0x2000),
            Field::Known(0x1),
        );
        assert_eq!(r.unreadable_fields(), vec!["vm_start"]);
    }

    #[test]
    fn a_kernel_thread_is_not_a_gap_but_an_unreadable_descriptor_is() {
        let kthread = ProcessMaps {
            task_address: 0x1000,
            pid: Field::Known(2),
            ppid: Field::Known(0),
            comm: Field::Known("kthreadd".into()),
            regions: Vec::new(),
            outcome: MapsOutcome::KernelThread,
            walk_stop: WalkStop::CompletedNull,
            root: ProcessRoot::NoFs,
        };
        assert!(!kthread.is_a_gap());
        assert!(!kthread.outcome.is_a_gap());

        let broken = ProcessMaps {
            outcome: MapsOutcome::DescriptorUnreadable("mm would not read".into()),
            ..kthread.clone()
        };
        assert!(broken.is_a_gap());
    }

    #[test]
    fn the_maple_tree_is_refused_by_name_never_shown_as_an_empty_map() {
        let maple = ProcessMaps {
            task_address: 0x2000,
            pid: Field::Known(100),
            ppid: Field::Known(1),
            comm: Field::Known("systemd".into()),
            regions: Vec::new(),
            outcome: MapsOutcome::MapleTreeUnwalked,
            walk_stop: WalkStop::CompletedNull,
            root: ProcessRoot::NoFs,
        };
        assert!(
            maple.is_a_gap(),
            "an unwalked maple tree is a gap, not zero regions"
        );
        let json = maple.to_json();
        assert_eq!(json["outcome"]["class"], "maple_tree_unwalked");
        assert!(json["outcome"]["detail"]
            .as_str()
            .unwrap()
            .contains("maple tree"));
        assert_eq!(json["vma_count"], 0);
    }

    #[test]
    fn a_null_forward_link_is_the_complete_terminator() {
        assert!(!WalkStop::CompletedNull.is_a_gap());
        assert!(WalkStop::CapReached.is_a_gap());
        assert!(WalkStop::Cycle(0x1000).is_a_gap());
        assert!(WalkStop::Unreadable("hole".into()).is_a_gap());
        assert!(WalkStop::NoForwardLink.is_a_gap());
    }

    #[test]
    fn a_page_offset_too_large_to_scale_overflows_rather_than_dropping_bits() {
        // A hostile/corrupt vm_pgoff with high bits set must not silently lose
        // them to a wrong Known value; it is Unavailable.
        assert!(scale_pgoff_to_bytes(&Field::Known(u64::MAX), 12).is_unavailable());
        assert!(scale_pgoff_to_bytes(&Field::Known(1u64 << 60), 12).is_unavailable());
        // A normal offset still scales.
        assert_eq!(
            scale_pgoff_to_bytes(&Field::Known(0x10), 12),
            Field::Known(0x10 << PAGE_SHIFT)
        );
        // Absence kinds pass through unchanged.
        assert!(scale_pgoff_to_bytes(&Field::NotApplicable, 12).eq(&Field::NotApplicable));
    }

    /// `vm_pgoff` counts the kernel's own pages (`PAGE_SIZE`): an arm64 kernel
    /// with a 16 or 64 KiB granule scales by 14 or 16 bits, not 12. Reading it
    /// as 4 KiB pages would put every file-backed region's offset a factor of 4
    /// or 16 too small.
    #[test]
    fn the_page_offset_scales_by_the_kernels_own_page_size() {
        assert_eq!(
            scale_pgoff_to_bytes(&Field::Known(0x10), 12),
            Field::Known(0x1_0000)
        );
        assert_eq!(
            scale_pgoff_to_bytes(&Field::Known(0x10), 14),
            Field::Known(0x4_0000)
        );
        assert_eq!(
            scale_pgoff_to_bytes(&Field::Known(0x10), 16),
            Field::Known(0x10_0000)
        );
        // The overflow guard holds at every page size.
        assert!(scale_pgoff_to_bytes(&Field::Known(1u64 << 50), 16).is_unavailable());
    }

    /// A region's length is a multiple of the kernel's page, not of 4 KiB: on
    /// a 16 KiB kernel a 4 KiB-multiple length is a smeared region.
    #[test]
    fn validity_requires_a_multiple_of_the_kernels_page() {
        let (start, long, short) = (
            Field::Known(0x40_0000),
            Field::Known(0x40_8000),
            Field::Known(0x40_1000),
        );
        assert!(validity(&start, &long, 14), "0x8000 is two 16 KiB pages");
        assert!(!validity(&start, &short, 14), "0x1000 is a quarter page");
        assert!(validity(&start, &short, 12));
        assert!(!validity(&start, &long, 16), "0x8000 is half a 64 KiB page");
    }

    #[test]
    fn the_file_offset_is_the_page_offset_scaled_to_bytes() {
        // vm_pgoff is in pages; the byte offset is pgoff << 12.
        let mut r = region(
            Field::Known(0x1000),
            Field::Known(0x2000),
            Field::Known(0x1),
        );
        r.anonymous = false;
        r.file_offset = Field::Known(0x10 << PAGE_SHIFT);
        assert_eq!(r.to_json()["file_offset"]["value"], 0x10000);
    }
}

/// The walk driven over a synthetic kernel image whose structures sit at the
/// real Debian 3.2 x86-64 offsets. Unlike the tests above — which exercise the
/// row logic on hand-built `Field`s — these place bytes in a memory image and
/// prove the walk reads them back: the VMA chain, the permission decode, and the
/// dentry-by-dentry path reconstruction end to end.
#[cfg(test)]
mod walk_tests {
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::object::{ListStop, StructReader};
    use seance_memory::{MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use super::*;
    use crate::tasks::{TaskList, TaskRecord};

    // Structure addresses (== physical offsets in the flat image).
    const TASK: u64 = 0x1000;
    const MM: u64 = 0x2000;
    const VMA1: u64 = 0x3000; // file-backed, r-x
    const VMA2: u64 = 0x3200; // anonymous, rw
    const FILE: u64 = 0x4000;
    const DENTRY_BASH: u64 = 0x5000;
    const DENTRY_BIN: u64 = 0x5200;
    const DENTRY_ROOT: u64 = 0x5400;
    const NAME_BASH: u64 = 0x6000;
    const NAME_BIN: u64 = 0x6040;

    /// An ISF declaring exactly the types the stage reads, at the Debian 3.2
    /// x86-64 offsets extracted from the vendored symbol pack.
    const FIXTURE_ISF: &str = r#"{
      "metadata": {"format":"6.2.0","producer":{"name":"seance-proc-maps-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
      "base_types": {
        "pointer": {"size":8,"signed":false,"kind":"int","endian":"little"},
        "unsigned long": {"size":8,"signed":false,"kind":"int","endian":"little"},
        "int": {"size":4,"signed":true,"kind":"int","endian":"little"},
        "unsigned int": {"size":4,"signed":false,"kind":"int","endian":"little"},
        "char": {"size":1,"signed":true,"kind":"char","endian":"little"},
        "void": {"size":0,"signed":false,"kind":"void","endian":"little"}
      },
      "user_types": {
        "qstr": {"size":16,"kind":"struct","fields":{
          "hash":{"offset":0,"type":{"kind":"base","name":"unsigned int"}},
          "len":{"offset":4,"type":{"kind":"base","name":"unsigned int"}},
          "name":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}}
        }},
        "path": {"size":16,"kind":"struct","fields":{
          "mnt":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
          "dentry":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}}
        }},
        "dentry": {"size":192,"kind":"struct","fields":{
          "d_parent":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "d_name":{"offset":32,"type":{"kind":"struct","name":"qstr"}},
          "d_iname":{"offset":56,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}}
        }},
        "file": {"size":208,"kind":"struct","fields":{
          "f_path":{"offset":16,"type":{"kind":"struct","name":"path"}}
        }},
        "vm_area_struct": {"size":176,"kind":"struct","fields":{
          "vm_mm":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"mm_struct"}}},
          "vm_start":{"offset":8,"type":{"kind":"base","name":"unsigned long"}},
          "vm_end":{"offset":16,"type":{"kind":"base","name":"unsigned long"}},
          "vm_next":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vm_area_struct"}}},
          "vm_flags":{"offset":48,"type":{"kind":"base","name":"unsigned long"}},
          "vm_pgoff":{"offset":144,"type":{"kind":"base","name":"unsigned long"}},
          "vm_file":{"offset":152,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"file"}}}
        }},
        "mm_struct": {"size":920,"kind":"struct","fields":{
          "mmap":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vm_area_struct"}}}
        }},
        "task_struct": {"size":1784,"kind":"struct","fields":{
          "mm":{"offset":424,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"mm_struct"}}}
        }}
      },
      "enums": {},
      "symbols": {}
    }"#;

    struct Image {
        bytes: Vec<u8>,
    }

    impl Image {
        fn new() -> Self {
            Self {
                bytes: vec![0u8; 0x8000],
            }
        }
        fn put(&mut self, address: u64, data: &[u8]) {
            let at = address as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
        }
        fn put_u64(&mut self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }
        fn put_u32(&mut self, address: u64, value: u32) {
            self.put(address, &value.to_le_bytes());
        }
    }

    /// Build the fixture: one task, its descriptor, a file-backed r-x VMA whose
    /// dentry chain spells `/bin/bash`, and an anonymous rw VMA that terminates
    /// the list.
    fn reader() -> StructReader {
        let mut image = Image::new();

        image.put_u64(TASK + 424, MM); // task.mm
        image.put_u64(MM, VMA1); // mm.mmap -> first VMA

        // VMA1: 0x400000..0x401000, r-x private, backed by FILE.
        image.put_u64(VMA1 + 8, 0x40_0000);
        image.put_u64(VMA1 + 16, 0x40_1000);
        image.put_u64(VMA1 + 24, VMA2); // vm_next
        image.put_u64(VMA1 + 48, 0x1 | 0x4); // VM_READ | VM_EXEC
        image.put_u64(VMA1 + 144, 0); // vm_pgoff
        image.put_u64(VMA1 + 152, FILE); // vm_file

        // VMA2: anonymous rw, vm_next null -> the complete terminator.
        image.put_u64(VMA2 + 8, 0x7f00_0000_0000);
        image.put_u64(VMA2 + 16, 0x7f00_0000_1000);
        image.put_u64(VMA2 + 24, 0); // vm_next null
        image.put_u64(VMA2 + 48, 0x1 | 0x2); // VM_READ | VM_WRITE
        image.put_u64(VMA2 + 144, 0);
        image.put_u64(VMA2 + 152, 0); // vm_file null -> anonymous

        // FILE.f_path.dentry (file+16+8) -> the file's own dentry.
        image.put_u64(FILE + 24, DENTRY_BASH);

        // dentry "bash" -> parent "bin".
        image.put_u64(DENTRY_BASH + 24, DENTRY_BIN); // d_parent
        image.put_u32(DENTRY_BASH + 36, 4); // d_name.len
        image.put_u64(DENTRY_BASH + 40, NAME_BASH); // d_name.name
        image.put(DENTRY_BASH + 56, b"bash\0"); // d_iname

        // dentry "bin" -> parent root.
        image.put_u64(DENTRY_BIN + 24, DENTRY_ROOT);
        image.put_u32(DENTRY_BIN + 36, 3);
        image.put_u64(DENTRY_BIN + 40, NAME_BIN);
        image.put(DENTRY_BIN + 56, b"bin\0");

        // Root dentry: d_parent points at itself, ending the walk.
        image.put_u64(DENTRY_ROOT + 24, DENTRY_ROOT);

        image.put(NAME_BASH, b"bash\0");
        image.put(NAME_BIN, b"bin\0");

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(image.bytes));
        let layer: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"));
        let symbols = {
            let src =
                seance_symbols::load_slice(FIXTURE_ISF.as_bytes(), &DecompressLimits::default())
                    .expect("the fixture ISF loads");
            Arc::new(
                SymbolTable::compile_source(src, &CompileOptions::default())
                    .expect("the fixture ISF compiles"),
            )
        };
        StructReader::new(layer, symbols)
    }

    fn one_task_list() -> TaskList {
        let mut task = TaskRecord::address_only_for_test(TASK);
        task.pid = Field::Known(1000);
        task.ppid = Field::Known(1);
        task.comm = Field::Known("bash".into());
        TaskList {
            init_task: 0xFFFF_FFFF_8160_0000,
            head: 0xFFFF_FFFF_8160_0170,
            links_offset: 368,
            tasks: vec![task],
            stop: ListStop::Wrapped,
            layout: serde_json::json!({}),
        }
    }

    #[test]
    fn the_walk_reads_the_vma_chain_permissions_and_reconstructs_the_path() {
        let reader = reader();
        let layout = PROC_MAPS_LAYOUT.bind(&reader).expect("the fixture binds");
        let tasks = one_task_list();

        let survey =
            super::survey_with_reader(&reader, &layout, &tasks, &ProcessMapsConfig::default(), 12)
                .expect("the survey runs");

        assert_eq!(survey.process_count(), 1);
        assert_eq!(survey.region_count(), 2, "two valid regions");
        assert_eq!(survey.to_json()["path_scope"], "dentry_tree_relative");

        let process = &survey.processes[0];
        assert!(
            matches!(process.outcome, MapsOutcome::Walked),
            "{:?}",
            process.outcome
        );
        assert_eq!(process.walk_stop, WalkStop::CompletedNull);
        assert!(
            !process.is_a_gap(),
            "a fully-read map is not a gap: {:?}",
            process.incomplete()
        );
        assert_eq!(process.regions.len(), 2);

        // Region 1: the file-backed r-x mapping of /bin/bash.
        let code = &process.regions[0];
        assert_eq!(code.vm_start.known(), Some(&0x40_0000));
        assert_eq!(code.vm_end.known(), Some(&0x40_1000));
        assert!(!code.anonymous);
        assert_eq!(code.path.known().map(String::as_str), Some("/bin/bash"));
        assert!(code.path_well_formed);
        assert!(code.is_valid);
        assert_eq!(code.to_json()["protection"], "r-xp");

        // Region 2: the anonymous rw mapping, and the null terminator behind it.
        let anon = &process.regions[1];
        assert!(anon.anonymous);
        assert_eq!(anon.path, Field::NotApplicable);
        assert_eq!(anon.to_json()["protection"], "rw-p");
    }

    #[test]
    fn a_kernel_thread_yields_no_regions_and_is_not_a_gap() {
        // A task whose mm pointer is null is a kernel thread: no map, not a gap.
        let reader = reader();
        let layout = PROC_MAPS_LAYOUT.bind(&reader).expect("binds");
        let mut task = TaskRecord::address_only_for_test(0x1500); // task.mm reads 0
        task.pid = Field::Known(2);
        task.comm = Field::Known("kthreadd".into());
        let tasks = TaskList {
            init_task: 0,
            head: 0,
            links_offset: 0,
            tasks: vec![task],
            stop: ListStop::Wrapped,
            layout: serde_json::json!({}),
        };

        let survey =
            super::survey_with_reader(&reader, &layout, &tasks, &ProcessMapsConfig::default(), 12)
                .expect("runs");
        let process = &survey.processes[0];
        assert!(matches!(process.outcome, MapsOutcome::KernelThread));
        assert!(process.regions.is_empty());
        assert!(!process.is_a_gap());
    }
}
