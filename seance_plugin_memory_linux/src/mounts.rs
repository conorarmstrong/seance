//! Filesystems mounted at the moment of capture, per mount namespace.
//!
//! At parity with Volatility 3's `linux.mountinfo`. Each task belongs to a mount
//! namespace (`task → nsproxy → mnt_ns`); this reaches the namespace from the
//! task list, deduplicates namespaces shared between tasks (which on a
//! single-namespace machine is all of them), and walks each namespace's mount
//! list, reporting per mount: device name, mount point, filesystem root and the
//! decoded mount flags.
//!
//! ## Two shapes, and what is not crossed
//!
//! Before Linux 3.3 the mount list is a list of `vfsmount` linked by `mnt_list`;
//! from 3.3 it is a list of `struct mount` whose `mnt` member is the embedded
//! `vfsmount`. Both are bound by ordered candidates. From Linux 6.8 the mounts
//! live in an `rb_root`, which this build does not walk and refuses **by name**
//! rather than reporting an empty list.
//!
//! The **mount point** is reconstructed by the mount-crossing walk
//! ([`crate::paths::path_for_mount`], Volatility's `get_path_mnt`): from the
//! mount's own root straight across into its parent and up to the root of the
//! task the namespace was reached from, so a nested or bind mount shows its
//! absolute mount point. Each record carries which walk it got and where it
//! ended (`mount_point_scope`), and a record whose chain would not read falls
//! back to the reduced in-mount walk and says so. The **filesystem root** uses
//! the reduced walk that Volatility itself uses for its ROOT column, so it is
//! exact parity.

use std::collections::HashSet;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::{ListSpec, ListStop, Obj, StructReader};

use crate::error::StageError;
use crate::module::STAGE_LINUX_MOUNTS;
use crate::paths::{self, PathResult, PathScope, ProcessRoot};
use crate::profile::LinuxProfile;
use crate::read::{read_c_string_member, read_integer, signed_to_json};
use crate::tasks::TaskList;

/// Longest device-name string this stage will follow.
pub const MAX_DEVNAME: usize = 255;

/// Ceiling on mounts one namespace walk will report. More than this is a corrupt
/// list, not a busy machine.
pub const MAX_MOUNTS_PER_NAMESPACE: usize = 65_536;

/// Mount flags (`MNT_*`), from `<linux/mount.h>`.
const MNT_NOSUID: i64 = 0x01;
const MNT_NODEV: i64 = 0x02;
const MNT_NOEXEC: i64 = 0x04;
const MNT_NOATIME: i64 = 0x08;
const MNT_NODIRATIME: i64 = 0x10;
const MNT_RELATIME: i64 = 0x20;
const MNT_READONLY: i64 = 0x40;
const MNT_SHARED: i64 = 0x1000;
const MNT_UNBINDABLE: i64 = 0x2000;

/// Everything the mount stage needs out of the symbol table.
pub const MOUNTS_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_MOUNTS,
    &[
        // On 3.2 this resolves to `vfsmount`; on >=3.3 to `struct mount`.
        TypeSpec::new("mount_entry", &["mount", "vfsmount"]).required(
            "this kernel declares no mount type, so no mounted filesystem could be described",
        ),
        TypeSpec::new("list_link", &["list_head"]).required(
            "the kernel's list links cannot be sized, so the mount list could not be walked",
        ),
        paths::TYPE_DENTRY,
    ],
    &[
        MemberSpec::new("task_nsproxy", &["task_struct"], &["nsproxy"])
            .required("a task has no namespace proxy, so its mount namespace could not be reached"),
        MemberSpec::new("mnt_ns", &["nsproxy"], &["mnt_ns"]).required(
            "the namespace proxy has no mount namespace, so no mount list could be located",
        ),
        MemberSpec::new("list_next", &["list_head"], &["next"])
            .required("a list link has no forward pointer, so the mount list could not be walked"),
        // The mount-list head on the namespace, and the 6.8+ rb_root that
        // replaced it. Declared so the stage can say the kernel uses the tree.
        MemberSpec::new("mount_list", &["mnt_namespace"], &["list"]),
        MemberSpec::new("mount_rbtree", &["mnt_namespace"], &["mounts"]),
        MemberSpec::new("mnt_list", &["mount", "vfsmount"], &["mnt_list"]),
        MemberSpec::new("mnt_devname", &["mount", "vfsmount"], &["mnt_devname"]),
        MemberSpec::new(
            "mnt_flags",
            &["mount", "vfsmount"],
            &["mnt.mnt_flags", "mnt_flags"],
        ),
        // Path reconstruction (shared with proc_maps/lsof). The mount-chain
        // members double as the walk's own columns.
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
    ],
);

/// Caps for one mount survey.
#[derive(Debug, Clone)]
pub struct MountsConfig {
    /// Most mounts one namespace walk will report.
    pub max_mounts: usize,
}

impl Default for MountsConfig {
    fn default() -> Self {
        Self {
            max_mounts: MAX_MOUNTS_PER_NAMESPACE,
        }
    }
}

/// Why a namespace contributed the mounts it did — or none.
#[derive(Debug, Clone)]
pub enum NamespaceOutcome {
    /// The mount list was walked.
    Walked,
    /// The mounts live in an `rb_root` (Linux 6.8+) this build does not walk.
    RbTreeUnwalked,
    /// This build declares no mount-list member at all.
    NoMountListMember,
    /// The namespace or its list head would not read.
    DescriptorUnreadable(String),
}

impl NamespaceOutcome {
    fn is_a_gap(&self) -> bool {
        !matches!(self, NamespaceOutcome::Walked)
    }
    fn class(&self) -> &'static str {
        match self {
            NamespaceOutcome::Walked => "walked",
            NamespaceOutcome::RbTreeUnwalked => "rb_tree_unwalked",
            NamespaceOutcome::NoMountListMember => "no_mount_list_member",
            NamespaceOutcome::DescriptorUnreadable(_) => "descriptor_unreadable",
        }
    }
    fn detail(&self) -> String {
        match self {
            NamespaceOutcome::Walked => "the mount list was walked".to_string(),
            NamespaceOutcome::RbTreeUnwalked => {
                "this kernel stores mounts in mnt_namespace.mounts, a red-black tree this build of \
                 Séance does not walk; the mount list is therefore absent and is NOT a statement \
                 that nothing is mounted"
                    .to_string()
            }
            NamespaceOutcome::NoMountListMember => {
                "this kernel build declares no mount-list member on the mount namespace".to_string()
            }
            NamespaceOutcome::DescriptorUnreadable(detail) => detail.clone(),
        }
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "class": self.class(), "detail": self.detail(), "is_a_gap": self.is_a_gap() })
    }
}

/// One mounted filesystem.
#[derive(Debug, Clone)]
pub struct MountRecord {
    /// Address of the mount / vfsmount structure.
    pub address: u64,
    /// The backing device name.
    pub devname: Field<String>,
    /// The mount point, walked across parent mounts up to the source task's
    /// root (`mount_point_scope` says which walk it got and where it ended).
    pub mount_point: Field<String>,
    pub mount_point_well_formed: bool,
    pub mount_point_truncated: bool,
    pub mount_point_scope: PathScope,
    /// The filesystem root (reduced dentry-tree path of `mnt_root`).
    pub fs_root: Field<String>,
    pub fs_root_well_formed: bool,
    pub fs_root_truncated: bool,
    /// The raw mount-flags word.
    pub mnt_flags: Field<i64>,
    /// Whether the mount passes a relaxed validity gate (root and parent read).
    pub is_valid: bool,
    /// Anything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl MountRecord {
    /// The fields that exist on this build and read `Unavailable`.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, unavailable) in [
            ("devname", self.devname.is_unavailable()),
            ("mount_point", self.mount_point.is_unavailable()),
            ("fs_root", self.fs_root.is_unavailable()),
            ("mnt_flags", self.mnt_flags.is_unavailable()),
        ] {
            if unavailable {
                out.push(name);
            }
        }
        out
    }

    fn flags_json(&self) -> serde_json::Value {
        match &self.mnt_flags {
            Field::Known(flags) => {
                let mut options = Vec::new();
                for (bit, name) in [
                    (MNT_NOSUID, "nosuid"),
                    (MNT_NODEV, "nodev"),
                    (MNT_NOEXEC, "noexec"),
                    (MNT_NOATIME, "noatime"),
                    (MNT_NODIRATIME, "nodiratime"),
                    (MNT_RELATIME, "relatime"),
                ] {
                    if flags & bit != 0 {
                        options.push(name);
                    }
                }
                serde_json::json!({
                    "access": if flags & MNT_READONLY != 0 { "ro" } else { "rw" },
                    "options": options,
                    "shared": flags & MNT_SHARED != 0,
                    "unbindable": flags & MNT_UNBINDABLE != 0,
                })
            }
            Field::NotDeclared { member } => serde_json::json!({ "not_declared": member }),
            Field::NotApplicable => serde_json::json!({ "not_applicable": true }),
            Field::Unavailable(detail) => serde_json::json!({ "unavailable": detail }),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "mount_address": self.address,
            "mount_address_hex": format!("{:#x}", self.address),
            "devname": self.devname.to_json(),
            "mount_point": self.mount_point.to_json(),
            "mount_point_well_formed": self.mount_point_well_formed,
            "mount_point_truncated": self.mount_point_truncated,
            "mount_point_scope": self.mount_point_scope.as_str(),
            "mount_point_scope_detail": self.mount_point_scope.detail(),
            "fs_root": self.fs_root.to_json(),
            "fs_root_well_formed": self.fs_root_well_formed,
            "fs_root_truncated": self.fs_root_truncated,
            "mnt_flags": signed_to_json(&self.mnt_flags),
            "flags": self.flags_json(),
            "is_valid": self.is_valid,
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        })
    }
}

/// One mount namespace and its mounts.
#[derive(Debug, Clone)]
pub struct MountNamespace {
    /// A task that belongs to this namespace (its handle in the case).
    pub source_task_address: u64,
    /// Address of the `mnt_namespace` (the dedup key).
    pub mnt_ns_address: u64,
    /// The mounts, in list order.
    pub mounts: Vec<MountRecord>,
    /// How the walk ended.
    pub walk_stop: ListStop,
    /// Why these mounts (or none).
    pub outcome: NamespaceOutcome,
    /// The root directory of the task the namespace was reached from, which
    /// every mount point above was walked up to.
    pub root: ProcessRoot,
}

impl MountNamespace {
    fn is_a_gap(&self) -> bool {
        self.outcome.is_a_gap()
            || !self.walk_stop.is_complete()
            || self
                .mounts
                .iter()
                .any(|m| !m.unreadable_fields().is_empty())
    }

    fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.outcome.is_a_gap() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the mount namespace at {:#x} yielded no mount list: {}",
                    self.mnt_ns_address,
                    self.outcome.detail()
                ),
            ));
        }
        if let Some(incomplete) = self.walk_stop.incomplete() {
            out.push(Incomplete::new(
                incomplete.reason,
                format!(
                    "walking the mount list of the namespace at {:#x}: {}",
                    self.mnt_ns_address, incomplete.detail
                ),
            ));
        }
        for mount in &self.mounts {
            let unreadable = mount.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the mount at {:#x} has field(s) that exist on this build and could not be \
                         read: {}",
                        mount.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source_task_address": self.source_task_address,
            "source_task_address_hex": format!("{:#x}", self.source_task_address),
            "mnt_ns_address": self.mnt_ns_address,
            "mnt_ns_address_hex": format!("{:#x}", self.mnt_ns_address),
            "mount_count": self.mounts.len(),
            "mounts": self.mounts.iter().map(MountRecord::to_json).collect::<Vec<_>>(),
            "outcome": self.outcome.to_json(),
            "walk_stop": self.walk_stop.as_str(),
            "root": crate::lsof::root_json(&self.root),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Every mount namespace, and everything that qualifies the list.
#[derive(Debug, Clone)]
pub struct MountSurvey {
    pub namespaces: Vec<MountNamespace>,
    pub layout: serde_json::Value,
    /// Which walk the survey attempted for every mount point, and the sentence
    /// that explains it. Each record carries its own scope; this is the summary.
    pub path_scope: &'static str,
    pub path_scope_note: &'static str,
    task_complete: bool,
    task_incomplete: Vec<Incomplete>,
    /// Tasks whose mount namespace could not be reached because a pointer on the
    /// way (`nsproxy` / `mnt_ns`) would not read — damaged evidence, kept apart
    /// from a task that genuinely has no namespace (a null pointer). A namespace
    /// reachable only through such tasks would otherwise vanish with the list
    /// still reported complete.
    unreadable_sources: Vec<String>,
}

impl MountSurvey {
    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }
    pub fn mount_count(&self) -> usize {
        self.namespaces.iter().map(|n| n.mounts.len()).sum()
    }
    pub fn is_complete(&self) -> bool {
        self.task_complete
            && self.unreadable_sources.is_empty()
            && !self.namespaces.iter().any(MountNamespace::is_a_gap)
    }
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.task_incomplete.clone();
        for source in &self.unreadable_sources {
            out.push(Incomplete::new(IncompleteReason::ShortRead, source.clone()));
        }
        for namespace in &self.namespaces {
            out.extend(namespace.incomplete());
        }
        out
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "namespace_count": self.namespace_count(),
            "mount_count": self.mount_count(),
            "complete": self.is_complete(),
            "path_scope": self.path_scope,
            "path_scope_note": self.path_scope_note,
            "path_scope_is_per_record": true,
            // The mount point is walked across parent mounts; the filesystem
            // root column is the in-mount walk Volatility's ROOT column uses.
            "mount_point_is_mount_crossing": self.path_scope == paths::PATH_SCOPE_MOUNT_CROSSING,
            "fs_root_is_mount_crossing": false,
            "namespaces": self.namespaces.iter().map(MountNamespace::to_json).collect::<Vec<_>>(),
            "unreadable_namespace_sources": self.unreadable_sources,
            "layout": self.layout,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Bind the mount stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(MOUNTS_LAYOUT.bind(&reader)?)
}

/// Walk every mount namespace reachable from the task list.
pub fn survey_mounts(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &MountsConfig,
) -> Result<MountSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    survey_with_reader(&reader, layout, tasks, config)
}

fn survey_with_reader(
    reader: &StructReader,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &MountsConfig,
) -> Result<MountSurvey, StageError> {
    let task_type = layout
        .member("task_nsproxy")?
        .type_name()
        .expect("a required member is declared or binding refused the stage");
    let mount_entry_type = layout
        .type_of("mount_entry")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let link_type = layout
        .type_of("list_link")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let list_next = layout
        .member("list_next")?
        .member()
        .expect("a required member is declared or binding refused the stage");
    let nsproxy_member = layout.member("task_nsproxy")?.member().expect("required");
    let mnt_ns_member = layout.member("mnt_ns")?.member().expect("required");

    let mut seen_ns: HashSet<u64> = HashSet::new();
    let mut namespaces: Vec<MountNamespace> = Vec::new();
    let mut unreadable_sources: Vec<String> = Vec::new();

    for task in &tasks.tasks {
        let task_obj = match reader.object(task.address, task_type) {
            Ok(obj) => obj,
            // The task-list walk already read this task, so a re-open failing is
            // damaged evidence, not a task with no namespace — record it.
            Err(err) => {
                unreadable_sources.push(format!(
                    "the task_struct at {:#x} could not be reopened to reach its mount \
                     namespace: {err}",
                    task.address
                ));
                continue;
            }
        };
        // task -> nsproxy -> mnt_ns. A NULL on the way is a kernel-thread-like
        // task with no namespace to read (Volatility skips it too); an
        // UNREADABLE pointer is damaged evidence and must not be skipped as if
        // it were the former, or a namespace reached only through such tasks
        // vanishes with the list still reported complete.
        let mnt_ns = match follow_chain(&task_obj, &[nsproxy_member, mnt_ns_member]) {
            ChainResult::Reached(obj) => obj,
            ChainResult::Null => continue,
            ChainResult::Unreadable(detail) => {
                unreadable_sources.push(format!(
                    "the mount namespace of the task_struct at {:#x} could not be reached: {detail}",
                    task.address
                ));
                continue;
            }
        };
        let mnt_ns_addr = mnt_ns.address();
        if !seen_ns.insert(mnt_ns_addr) {
            continue; // a namespace shared with an earlier task
        }

        let root = paths::process_root(layout, &task_obj)?;
        namespaces.push(walk_namespace(
            reader,
            layout,
            &mnt_ns,
            task.address,
            mount_entry_type,
            link_type,
            list_next,
            config.max_mounts,
            root,
        )?);
    }

    let (path_scope, path_scope_note) = mount_survey_scope(layout);
    Ok(MountSurvey {
        namespaces,
        layout: layout.to_json(),
        path_scope,
        path_scope_note,
        task_complete: tasks.is_complete(),
        task_incomplete: tasks.incomplete(),
        unreadable_sources,
    })
}

/// The survey-level scope: the mount stage has no `file.f_path.mnt` to bind
/// (it starts from the mount itself), so the crossing walk needs only the
/// mount-chain and task-root members.
fn mount_survey_scope(layout: &BuildBinding) -> (&'static str, &'static str) {
    let bound = ["mnt_parent", "mnt_mountpoint", "mnt_root", "task_fs"]
        .iter()
        .all(|key| layout.member(key).map(|b| b.is_declared()).unwrap_or(false));
    if bound {
        (
            paths::PATH_SCOPE_MOUNT_CROSSING,
            paths::PATH_SCOPE_NOTE_MOUNT_CROSSING,
        )
    } else {
        (paths::PATH_SCOPE, paths::PATH_SCOPE_NOTE)
    }
}

/// The outcome of following a pointer chain: reached the target, hit a genuine
/// null (an answer), or hit an unreadable pointer (damaged evidence).
enum ChainResult {
    Reached(Obj),
    Null,
    Unreadable(String),
}

/// Follow a chain of pointer members, keeping a null apart from an unreadable
/// pointer so the caller can treat "no namespace" and "namespace unreadable" as
/// the different findings they are.
fn follow_chain(start: &Obj, members: &[&str]) -> ChainResult {
    let mut current = match start.follow(members[0]) {
        Ok(Some(obj)) => obj,
        Ok(None) => return ChainResult::Null,
        Err(err) => return ChainResult::Unreadable(err.to_string()),
    };
    for member in &members[1..] {
        current = match current.follow(member) {
            Ok(Some(obj)) => obj,
            Ok(None) => return ChainResult::Null,
            Err(err) => return ChainResult::Unreadable(err.to_string()),
        };
    }
    ChainResult::Reached(current)
}

#[allow(clippy::too_many_arguments)]
fn walk_namespace(
    reader: &StructReader,
    layout: &BuildBinding,
    mnt_ns: &Obj,
    source_task: u64,
    mount_entry_type: &'static str,
    link_type: &'static str,
    list_next: &'static str,
    max_mounts: usize,
    root: ProcessRoot,
) -> Result<MountNamespace, StageError> {
    let namespace = |outcome, mounts, walk_stop, root| MountNamespace {
        source_task_address: source_task,
        mnt_ns_address: mnt_ns.address(),
        mounts,
        walk_stop,
        outcome,
        root,
    };

    // Where the mount list lives.
    let list_bound = layout.member("mount_list")?;
    let mnt_list_bound = layout.member("mnt_list")?;
    if !list_bound.is_declared() || !mnt_list_bound.is_declared() {
        let outcome = if layout
            .member("mount_rbtree")
            .map(|b| b.is_declared())
            .unwrap_or(false)
        {
            NamespaceOutcome::RbTreeUnwalked
        } else {
            NamespaceOutcome::NoMountListMember
        };
        return Ok(namespace(outcome, Vec::new(), ListStop::Wrapped, root));
    }
    let list_offset = list_bound
        .offset()
        .expect("a declared member has an offset");
    let mnt_list_member = mnt_list_bound.member().expect("declared");

    let Some(head) = mnt_ns.address().checked_add(list_offset) else {
        return Ok(namespace(
            NamespaceOutcome::DescriptorUnreadable(
                "the mount-list head address does not fit in the address space".to_string(),
            ),
            Vec::new(),
            ListStop::Wrapped,
            root,
        ));
    };

    let spec = ListSpec::new(link_type, list_next)
        .in_container(mount_entry_type, mnt_list_member)
        .with_max_entries(max_mounts);
    let walk = reader.walk_list(head, &spec)?;
    let (entries, stop) = walk.walk_to_end();

    let mounts = entries
        .iter()
        .map(|obj| read_mount(reader, layout, obj, &root))
        .collect::<Result<Vec<_>, StageError>>()?;

    Ok(namespace(NamespaceOutcome::Walked, mounts, stop, root))
}

/// Read one mount / vfsmount structure into a row.
fn read_mount(
    reader: &StructReader,
    layout: &BuildBinding,
    mount: &Obj,
    task_root: &ProcessRoot,
) -> Result<MountRecord, StageError> {
    let devname = read_c_string_member(layout, mount, "mnt_devname", MAX_DEVNAME)?;
    let mnt_flags = read_integer(layout, mount, "mnt_flags")?;

    let mountpoint = paths::path_for_mount(reader, layout, mount, task_root);
    let root = path_of_pointer(reader, layout, mount, "mnt_root")?;
    let mnt_parent = layout.read_pointer(mount, "mnt_parent")?;

    let is_valid =
        matches!(root.path, Field::Known(_)) && matches!(mnt_parent, Field::Known(p) if p != 0);
    let mut notes = Vec::new();
    if !is_valid {
        notes.push(
            "this mount did not pass the validity gate (its root or parent could not be \
             established); it is kept and flagged rather than dropped"
                .to_string(),
        );
    }

    Ok(MountRecord {
        address: mount.address(),
        devname,
        mount_point: mountpoint.path,
        mount_point_well_formed: mountpoint.well_formed,
        mount_point_truncated: mountpoint.truncated,
        mount_point_scope: mountpoint.scope,
        fs_root: root.path,
        fs_root_well_formed: root.well_formed,
        fs_root_truncated: root.truncated,
        mnt_flags,
        is_valid,
        notes,
    })
}

/// Reconstruct a path from a dentry-pointer member of the mount, by the
/// reduced in-mount walk.
fn path_of_pointer(
    reader: &StructReader,
    layout: &BuildBinding,
    mount: &Obj,
    key: &'static str,
) -> Result<PathResult, StageError> {
    Ok(match layout.read_pointer(mount, key)? {
        Field::Known(0) => {
            PathResult::unavailable(format!("the mount's {key} dentry pointer is null"))
        }
        Field::Known(address) => paths::path_from_dentry(reader, layout, address),
        Field::NotDeclared { member } => PathResult::from_field(Field::NotDeclared { member }),
        Field::NotApplicable => PathResult::from_field(Field::NotApplicable),
        Field::Unavailable(detail) => PathResult::from_field(Field::Unavailable(detail)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(mnt_flags: Field<i64>) -> MountRecord {
        MountRecord {
            address: 0xFFFF_8800_2000_0000,
            devname: Field::Known("/dev/sda1".into()),
            mount_point: Field::Known("/".into()),
            mount_point_well_formed: true,
            mount_point_truncated: false,
            mount_point_scope: PathScope::MountRelative("test".into()),
            fs_root: Field::Known("/".into()),
            fs_root_well_formed: true,
            fs_root_truncated: false,
            mnt_flags,
            is_valid: true,
            notes: Vec::new(),
        }
    }

    #[test]
    fn flags_decode_to_access_and_options() {
        let m = mount(Field::Known(
            MNT_READONLY | MNT_NOSUID | MNT_NODEV | MNT_RELATIME,
        ));
        let json = m.to_json();
        assert_eq!(json["flags"]["access"], "ro");
        let options = json["flags"]["options"].as_array().unwrap();
        assert!(options.iter().any(|o| o == "nosuid"));
        assert!(options.iter().any(|o| o == "nodev"));
        assert!(options.iter().any(|o| o == "relatime"));
    }

    #[test]
    fn a_read_write_mount_has_no_readonly() {
        let m = mount(Field::Known(0));
        assert_eq!(m.to_json()["flags"]["access"], "rw");
    }

    #[test]
    fn absent_flags_do_not_read_as_read_write_with_no_options() {
        let m = mount(Field::NotDeclared {
            member: "mnt_flags",
        });
        let json = m.to_json();
        assert_eq!(json["flags"]["not_declared"], "mnt_flags");
        assert!(json["flags"].get("access").is_none());
    }

    #[test]
    fn an_unreadable_mountpoint_is_a_named_gap() {
        let mut m = mount(Field::Known(0));
        m.mount_point = Field::Unavailable("the dentry page was not acquired".into());
        assert_eq!(m.unreadable_fields(), vec!["mount_point"]);
    }

    #[test]
    fn the_rb_tree_is_refused_by_name() {
        let ns = MountNamespace {
            source_task_address: 0x1000,
            mnt_ns_address: 0x2000,
            mounts: Vec::new(),
            walk_stop: ListStop::Wrapped,
            outcome: NamespaceOutcome::RbTreeUnwalked,
            root: ProcessRoot::NoFs,
        };
        assert!(ns.is_a_gap());
        let json = ns.to_json();
        assert_eq!(json["outcome"]["class"], "rb_tree_unwalked");
        assert!(json["outcome"]["detail"]
            .as_str()
            .unwrap()
            .contains("red-black tree"));
    }
}

#[cfg(test)]
mod walk_tests {
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::object::ListStop;
    use seance_memory::{MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use super::*;
    use crate::tasks::{TaskList, TaskRecord};

    const TASK: u64 = 0x1000;
    /// A task whose nsproxy points at an address the image does not cover.
    const TASK_BAD_NS: u64 = 0x1500;
    const NSPROXY: u64 = 0x2000;
    const MNTNS: u64 = 0x2200;
    const VM_ROOT: u64 = 0x3000; // vfsmount for /
    const VM_PROC: u64 = 0x3200; // vfsmount for /proc
    const D_ROOT: u64 = 0x4000; // "/" self-parent
    const D_PROC: u64 = 0x4200; // "proc" under root
    const D_PROC_ROOT: u64 = 0x4400; // proc fs root, "/" self-parent
    const NAME_SDA: u64 = 0x5000;
    const NAME_PROC_DEV: u64 = 0x5040;
    const NAME_PROC: u64 = 0x5080;

    const FIXTURE_ISF: &str = r#"{
      "metadata": {"format":"6.2.0","producer":{"name":"seance-mounts-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
      "base_types": {
        "pointer": {"size":8,"signed":false,"kind":"int","endian":"little"},
        "int": {"size":4,"signed":true,"kind":"int","endian":"little"},
        "unsigned int": {"size":4,"signed":false,"kind":"int","endian":"little"},
        "char": {"size":1,"signed":true,"kind":"char","endian":"little"},
        "void": {"size":0,"signed":false,"kind":"void","endian":"little"}
      },
      "user_types": {
        "list_head": {"size":16,"kind":"struct","fields":{
          "next":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"list_head"}}},
          "prev":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"list_head"}}}
        }},
        "qstr": {"size":16,"kind":"struct","fields":{
          "len":{"offset":4,"type":{"kind":"base","name":"unsigned int"}},
          "name":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}}
        }},
        "dentry": {"size":192,"kind":"struct","fields":{
          "d_parent":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "d_name":{"offset":32,"type":{"kind":"struct","name":"qstr"}},
          "d_iname":{"offset":56,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}}
        }},
        "vfsmount": {"size":240,"kind":"struct","fields":{
          "mnt_parent":{"offset":16,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vfsmount"}}},
          "mnt_mountpoint":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "mnt_root":{"offset":32,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "mnt_flags":{"offset":96,"type":{"kind":"base","name":"int"}},
          "mnt_devname":{"offset":112,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}},
          "mnt_list":{"offset":120,"type":{"kind":"struct","name":"list_head"}}
        }},
        "mnt_namespace": {"size":64,"kind":"struct","fields":{
          "root":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vfsmount"}}},
          "list":{"offset":16,"type":{"kind":"struct","name":"list_head"}}
        }},
        "nsproxy": {"size":48,"kind":"struct","fields":{
          "mnt_ns":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"mnt_namespace"}}}
        }},
        "task_struct": {"size":1784,"kind":"struct","fields":{
          "nsproxy":{"offset":1160,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"nsproxy"}}}
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
        fn put(&mut self, a: u64, d: &[u8]) {
            let at = a as usize;
            self.bytes[at..at + d.len()].copy_from_slice(d);
        }
        fn u64(&mut self, a: u64, v: u64) {
            self.put(a, &v.to_le_bytes());
        }
        fn u32(&mut self, a: u64, v: u32) {
            self.put(a, &v.to_le_bytes());
        }
        fn dentry(&mut self, at: u64, parent: u64, name_ptr: u64, len: u32) {
            self.u64(at + 24, parent);
            self.u32(at + 36, len);
            self.u64(at + 40, name_ptr);
        }
    }

    fn reader() -> StructReader {
        let mut m = Image::new();
        m.u64(TASK + 1160, NSPROXY); // task.nsproxy
                                     // A second task whose nsproxy pointer is valid-looking but points into
                                     // memory the image never captured, so following it fails to READ (an
                                     // Unavailable), as opposed to a genuine null.
        m.u64(TASK_BAD_NS + 1160, 0x0090_0000);
        m.u64(NSPROXY + 24, MNTNS); // nsproxy.mnt_ns

        // mnt_namespace.list (list_head @16) -> circular list of vfsmount.mnt_list (@120).
        let head = MNTNS + 16;
        let l1 = VM_ROOT + 120;
        let l2 = VM_PROC + 120;
        m.u64(head, l1); // head.next -> vm_root.mnt_list
        m.u64(l1, l2); // vm_root.mnt_list.next -> vm_proc.mnt_list
        m.u64(l2, head); // vm_proc.mnt_list.next -> head (closes)

        // vfsmount /
        m.u64(VM_ROOT + 16, VM_ROOT); // mnt_parent -> itself
        m.u64(VM_ROOT + 24, D_ROOT); // mnt_mountpoint
        m.u64(VM_ROOT + 32, D_ROOT); // mnt_root
        m.u32(VM_ROOT + 96, 0); // mnt_flags rw
        m.u64(VM_ROOT + 112, NAME_SDA); // mnt_devname

        // vfsmount /proc, read-only
        m.u64(VM_PROC + 16, VM_ROOT); // mnt_parent -> /
        m.u64(VM_PROC + 24, D_PROC); // mnt_mountpoint -> /proc dentry
        m.u64(VM_PROC + 32, D_PROC_ROOT); // mnt_root
        m.u32(VM_PROC + 96, MNT_READONLY as u32);
        m.u64(VM_PROC + 112, NAME_PROC_DEV);

        // dentries
        m.dentry(D_ROOT, D_ROOT, 0, 1); // "/" self-parent (name via iname empty -> "/")
        m.put(D_ROOT + 56, b"/\0");
        m.dentry(D_PROC, D_ROOT, NAME_PROC, 4); // "proc" under /
        m.dentry(D_PROC_ROOT, D_PROC_ROOT, 0, 1); // proc fs root, self-parent
        m.put(D_PROC_ROOT + 56, b"/\0");

        m.put(NAME_SDA, b"/dev/sda1\0");
        m.put(NAME_PROC_DEV, b"proc\0");
        m.put(NAME_PROC, b"proc\0");

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(m.bytes));
        let layer: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"));
        let symbols = Arc::new(
            SymbolTable::compile_source(
                seance_symbols::load_slice(FIXTURE_ISF.as_bytes(), &DecompressLimits::default())
                    .expect("loads"),
                &CompileOptions::default(),
            )
            .expect("compiles"),
        );
        StructReader::new(layer, symbols)
    }

    fn task_list(addresses: &[u64]) -> TaskList {
        let tasks = addresses
            .iter()
            .enumerate()
            .map(|(i, &addr)| {
                let mut t = TaskRecord::address_only_for_test(addr);
                t.pid = Field::Known(i as i64 + 1);
                t.comm = Field::Known("proc".into());
                t
            })
            .collect();
        TaskList {
            init_task: 0,
            head: 0,
            links_offset: 0,
            tasks,
            stop: ListStop::Wrapped,
            layout: serde_json::json!({}),
        }
    }

    #[test]
    fn the_walk_lists_mounts_with_device_mountpoint_and_flags() {
        let reader = reader();
        let layout = MOUNTS_LAYOUT.bind(&reader).expect("the fixture binds");
        let tasks = task_list(&[TASK]);

        let survey = super::survey_with_reader(&reader, &layout, &tasks, &MountsConfig::default())
            .expect("the survey runs");

        assert_eq!(survey.namespace_count(), 1);
        assert_eq!(survey.mount_count(), 2);

        let ns = &survey.namespaces[0];
        assert!(matches!(ns.outcome, NamespaceOutcome::Walked));
        assert_eq!(ns.walk_stop, ListStop::Wrapped);

        let root = &ns.mounts[0];
        assert_eq!(root.devname.known().map(String::as_str), Some("/dev/sda1"));
        assert_eq!(root.mount_point.known().map(String::as_str), Some("/"));
        assert_eq!(root.fs_root.known().map(String::as_str), Some("/"));
        assert!(root.is_valid);

        let proc = &ns.mounts[1];
        assert_eq!(proc.devname.known().map(String::as_str), Some("proc"));
        assert_eq!(proc.mount_point.known().map(String::as_str), Some("/proc"));
        assert_eq!(proc.to_json()["flags"]["access"], "ro");
    }

    #[test]
    fn namespaces_shared_between_tasks_are_walked_once() {
        let reader = reader();
        let layout = MOUNTS_LAYOUT.bind(&reader).expect("binds");
        // Three tasks, all in the one namespace.
        let tasks = task_list(&[TASK, TASK, TASK]);

        let survey = super::survey_with_reader(&reader, &layout, &tasks, &MountsConfig::default())
            .expect("runs");
        assert_eq!(
            survey.namespace_count(),
            1,
            "one namespace despite three tasks sharing it"
        );
        assert_eq!(survey.mount_count(), 2, "mounts counted once, not per task");
    }

    #[test]
    fn a_task_whose_namespace_is_unreadable_is_a_gap_not_a_silent_skip() {
        // Regression: an unreadable nsproxy/mnt_ns was treated like a genuine
        // null and skipped, so a namespace reachable only through such tasks
        // vanished with the survey still reporting complete. It must now lower
        // completeness and name the source.
        let reader = reader();
        let layout = MOUNTS_LAYOUT.bind(&reader).expect("binds");
        let tasks = task_list(&[TASK_BAD_NS, TASK]);

        let survey = super::survey_with_reader(&reader, &layout, &tasks, &MountsConfig::default())
            .expect("runs");

        // TASK's namespace is still found; TASK_BAD_NS is recorded as a gap.
        assert_eq!(survey.namespace_count(), 1);
        assert!(
            !survey.is_complete(),
            "an unreadable namespace pointer must make the survey a floor"
        );
        let json = survey.to_json();
        let unreadable = json["unreadable_namespace_sources"]
            .as_array()
            .expect("the field is present");
        assert_eq!(unreadable.len(), 1, "one task's namespace was unreadable");
        assert_eq!(json["complete"], false);
    }
}
