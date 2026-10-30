//! Reconstructing a file's path from its `dentry` and its mount, in kernel
//! memory.
//!
//! The process-maps, open-files and mount stages each reach a `struct file` (or
//! a mount) and need the path it names. A file's path is not stored as a string
//! anywhere; it is walked, `dentry` by `dentry`, from the file's own directory
//! entry up through each mount point to the root of the process that holds it,
//! joining each `d_name` with a slash.
//!
//! # Two walks, and which one a record got
//!
//! **The mount-crossing walk** ([`path_for_file`], [`path_for_mount`]) is the
//! kernel's `prepend_path` and Volatility's `do_get_path`: it climbs `d_parent`
//! until it reaches the root of the dentry's mount, then steps to the parent
//! mount through the `vfsmount` / `struct mount` chain (`mnt_parent`,
//! `mnt_mountpoint`) and carries on, until it meets the process's own root
//! (`task->fs->root`) or the global root. A file on a non-root mount therefore
//! shows its absolute path as the process saw it — `/dev/null`, not `/null`.
//!
//! **The reduced walk** ([`path_from_dentry`]) is the kernel's `__dentry_path`
//! and Volatility's `dentry.path()`: `d_parent` up to the self-referential root
//! of the dentry's own tree, never leaving the mount. It is what a record falls
//! back to when the crossing walk cannot be made — the build declares no
//! `f_path.mnt`, the mount would not read, the process has no `fs_struct` — and
//! every such record says so in its [`PathScope`].
//!
//! Which walk produced a path is a property of **the record**, not of the
//! stage: the same survey can hold both, so the scope rides on every path and
//! a report must not infer it from a survey-level flag.
//!
//! # Pseudo-files
//!
//! A socket, a pipe and an anonymous inode have a dentry whose `d_op->d_dname`
//! renders the name at `readlink` time — `socket:[1234]`, `pipe:[5678]`,
//! `anon_inode:[eventpoll]` — and whose `d_name` is not a path at all. Those are
//! recognised by which kernel function `d_dname` points at, decoded the way the
//! kernel does (the inode number for sockets and pipes; the dentry name for
//! anonymous inodes), and typed as such in [`PathKind`]. No directory walk is
//! made for them and none is claimed: their `path_scope` is `pseudo`, not a
//! mount walk that crossed nothing. A `d_dname` that points at a function this
//! module does not know is reported by that function's name with the raw
//! dentry walk beside it, never as a plain file path.
//!
//! # The four ways there is no path
//!
//! Kept apart, because a report that renders them alike is making four different
//! claims with one blank cell:
//!
//! * **Anonymous** — the region or descriptor has no backing file at all. That is
//!   the caller's to detect (a null `vm_file`/`file`), not this module's.
//! * **[`Field::NotDeclared`]** — this kernel build declares no `f_path.dentry`,
//!   so the question could not be put.
//! * **[`Field::Unavailable`]** — the file is backed and the dentry bytes were
//!   not acquired, or a pointer would not read. The evidence is damaged here.
//! * **[`Field::Known`]** — the path, possibly with `truncated` set if the
//!   chain hit its depth bound, a cycle, or a disconnected dentry before
//!   reaching a root.

use std::collections::HashSet;

use seance_memory::binding::{BuildBinding, Field, MemberSpec, TypeSpec};
use seance_memory::object::{Obj, StructReader};

use crate::error::StageError;
use crate::read::{self, decode_nul_terminated, MAX_C_STRING};

/// The member keys a stage must declare for the reduced walk to work.
///
/// Every stage that reconstructs paths declares these on its own `MemberSet`,
/// so this module can read them out of the resolved binding by name without
/// owning a binding of its own.
pub const PATH_MEMBER_KEYS: [&str; 4] = ["d_parent", "d_name_ptr", "d_name_len", "d_iname"];

/// The type key a stage must declare so parent dentries can be read.
pub const DENTRY_TYPE_KEY: &str = "dentry";

/// The member key naming a `struct file`'s dentry.
pub const FILE_DENTRY_KEY: &str = "file_dentry";

// ── The declarations a stage copies into its own MemberSet ─────────────────
//
// Declared once here so the three stages that reconstruct paths bind the same
// names, and so a stage that forgets one binds `NotDeclared` for it and falls
// back to the reduced walk with the reason on the record — never a wrong path.

/// The mount / vfsmount type — `struct mount` from Linux 3.3, `vfsmount`
/// before, when the parent and mountpoint lived on the `vfsmount` itself.
pub const TYPE_MOUNT_ENTRY: TypeSpec = TypeSpec::new("mount_entry", &["mount", "vfsmount"]);
/// The dentry type.
pub const TYPE_DENTRY: TypeSpec = TypeSpec::new(DENTRY_TYPE_KEY, &["dentry"]);
/// The operations table a pseudo-file's dentry carries.
pub const TYPE_DENTRY_OPERATIONS: TypeSpec =
    TypeSpec::new("dentry_operations", &["dentry_operations"]);
/// The inode type, for the number a pseudo-path prints.
pub const TYPE_INODE: TypeSpec = TypeSpec::new("inode", &["inode"]);

/// `file.f_path.dentry`.
pub const SPEC_FILE_DENTRY: MemberSpec =
    MemberSpec::new(FILE_DENTRY_KEY, &["file"], &["f_path.dentry"]);
/// `file.f_path.mnt` — the `vfsmount *` the file was opened through.
pub const SPEC_FILE_MNT: MemberSpec = MemberSpec::new("file_mnt", &["file"], &["f_path.mnt"]);
/// The embedded `vfsmount` inside `struct mount` (3.3+); its offset is what
/// turns a `vfsmount *` back into the `struct mount` that owns it. Absent on
/// a pre-3.3 build, where the two are the same structure.
pub const SPEC_MOUNT_MNT: MemberSpec = MemberSpec::new("mount_mnt", &["mount"], &["mnt"]);
/// `mount.mnt_parent` / `vfsmount.mnt_parent`.
pub const SPEC_MNT_PARENT: MemberSpec =
    MemberSpec::new("mnt_parent", &["mount", "vfsmount"], &["mnt_parent"]);
/// `mount.mnt_mountpoint` / `vfsmount.mnt_mountpoint`: the dentry in the
/// parent mount this one is mounted on.
pub const SPEC_MNT_MOUNTPOINT: MemberSpec = MemberSpec::new(
    "mnt_mountpoint",
    &["mount", "vfsmount"],
    &["mnt_mountpoint"],
);
/// `mount.mnt.mnt_root` / `vfsmount.mnt_root`: the root dentry of the mounted
/// filesystem.
pub const SPEC_MNT_ROOT: MemberSpec = MemberSpec::new(
    "mnt_root",
    &["mount", "vfsmount"],
    &["mnt.mnt_root", "mnt_root"],
);
/// `task_struct.fs`.
pub const SPEC_TASK_FS: MemberSpec = MemberSpec::new("task_fs", &["task_struct"], &["fs"]);
/// `fs_struct.root.dentry`: the process's root directory.
pub const SPEC_FS_ROOT_DENTRY: MemberSpec =
    MemberSpec::new("fs_root_dentry", &["fs_struct"], &["root.dentry"]);
/// `fs_struct.root.mnt`: the mount the process's root directory is on.
pub const SPEC_FS_ROOT_MNT: MemberSpec =
    MemberSpec::new("fs_root_mnt", &["fs_struct"], &["root.mnt"]);
/// `dentry.d_parent`.
pub const SPEC_D_PARENT: MemberSpec = MemberSpec::new("d_parent", &["dentry"], &["d_parent"]);
/// `dentry.d_name.name`.
pub const SPEC_D_NAME_PTR: MemberSpec =
    MemberSpec::new("d_name_ptr", &["dentry"], &["d_name.name"]);
/// `dentry.d_name.len`.
pub const SPEC_D_NAME_LEN: MemberSpec = MemberSpec::new("d_name_len", &["dentry"], &["d_name.len"]);
/// `dentry.d_iname`, the inline short-name store.
pub const SPEC_D_INAME: MemberSpec = MemberSpec::new("d_iname", &["dentry"], &["d_iname"]);
/// `dentry.d_op`.
pub const SPEC_D_OP: MemberSpec = MemberSpec::new("d_op", &["dentry"], &["d_op"]);
/// `dentry_operations.d_dname`: the function a pseudo-file renders its name
/// with.
pub const SPEC_D_DNAME: MemberSpec =
    MemberSpec::new("d_dname", &["dentry_operations"], &["d_dname"]);
/// `dentry.d_inode`.
pub const SPEC_D_INODE: MemberSpec = MemberSpec::new("d_inode", &["dentry"], &["d_inode"]);
/// `inode.i_ino`.
pub const SPEC_I_INO: MemberSpec = MemberSpec::new("i_ino", &["inode"], &["i_ino"]);

/// The member keys the mount-crossing walk reads. A stage whose binding lacks
/// any of them still runs; its paths fall back to the reduced walk and say so.
pub const MOUNT_CROSSING_MEMBER_KEYS: [&str; 5] = [
    "file_mnt",
    "mnt_parent",
    "mnt_mountpoint",
    "mnt_root",
    "task_fs",
];

/// The kernel functions a pseudo-file's `d_dname` may point at, and what each
/// renders.
const SOCKFS_DNAME: &str = "sockfs_dname";
const PIPEFS_DNAME: &str = "pipefs_dname";
const ANON_INODEFS_DNAME: &str = "anon_inodefs_dname";

/// Longest dentry chain this walks before calling the result truncated.
///
/// A real path is nowhere near this deep; reaching it means the chain did not
/// terminate at a root, which is corruption or a cycle the visited set did not
/// happen to catch first.
pub const MAX_PATH_DEPTH: usize = 256;

/// Stable label for the reduced reconstruction method, carried on every record
/// it produced.
pub const PATH_SCOPE: &str = "dentry_tree_relative";

/// Stable label for the mount-crossing reconstruction, carried on every record
/// it produced.
pub const PATH_SCOPE_MOUNT_CROSSING: &str = "mount_crossing";

/// Stable label for a pseudo-file rendered by its `d_dname` (a socket, a pipe,
/// an anonymous inode): no directory walk was made, because there is no
/// directory path to walk.
pub const PATH_SCOPE_PSEUDO: &str = "pseudo";

/// The sentence an examiner reads about a survey whose paths are mount-crossing
/// where the build allowed it.
pub const PATH_SCOPE_NOTE_MOUNT_CROSSING: &str =
    "Paths are reconstructed the way the kernel's prepend_path does it: each file's dentry is \
     walked up to the root of its mount, then across the mount point into the parent mount, \
     and so on until the process's own root directory (task->fs->root) or the global root is \
     reached. Every path record carries its own `path_scope`: `mount_crossing` when that walk \
     completed, `dentry_tree_relative` when the record fell back to the reduced walk within \
     one mount and `path_scope_detail` says why, and `pseudo` for a socket, pipe or anonymous \
     inode, which is rendered from its `d_dname` with no directory walk at all. Only a \
     `mount_crossing` path is the absolute path as the process saw it.";

/// The sentence an examiner reads about a survey whose build could not cross
/// mounts at all.
pub const PATH_SCOPE_NOTE: &str =
    "Paths are reconstructed by walking each file's dentry up to the root of its own mount, \
     joining the directory-entry names. Mount points are not crossed: a file on a non-root mount \
     (a bind mount, a container layer, a separate filesystem) shows its path within that mount \
     without the mount-point prefix. The path is therefore relative to its mount root, not the \
     absolute path as seen from the process's root.";

/// Which walk produced a path, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScope {
    /// The mount-crossing walk ran.
    MountCrossing {
        /// How many mount points the walk stepped across.
        mounts_crossed: usize,
        /// Where the walk ended.
        ended: WalkEnd,
        /// When the walk ended at the global root because no process root was
        /// available to end at, why the root was unavailable.
        root_note: Option<String>,
    },
    /// The reduced walk, within one mount. The string says why the crossing
    /// walk could not be made for this record.
    MountRelative(String),
    /// No walk at all: the dentry renders its own name through `d_dname` (a
    /// socket, a pipe, an anonymous inode) and has no directory path, so
    /// nothing was climbed and no mount was crossed or not crossed.
    Pseudo {
        /// The kernel function `d_dname` points at, which decided the form.
        d_dname: String,
        /// What the record is (`socket`, `pipe`, `anon_inode`), for the
        /// sentence.
        kind: String,
    },
}

/// Where a mount-crossing walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    /// At the process's own root directory: the path is exactly what the
    /// process would have seen.
    ProcessRoot,
    /// At the global root without meeting the process's root — the file is
    /// outside the process's root directory (a chroot), or no process root was
    /// available to compare against and the path is relative to the global
    /// root instead.
    GlobalRoot,
    /// At a dentry that is the root of its own tree but not the root of its
    /// mount: a disconnected (unlinked or escaped) dentry. The path is a
    /// suffix of what it was.
    Disconnected,
    /// The depth bound or the cycle guard stopped it. The path is a suffix.
    Bound,
}

impl WalkEnd {
    fn as_str(self) -> &'static str {
        match self {
            WalkEnd::ProcessRoot => "process_root",
            WalkEnd::GlobalRoot => "global_root",
            WalkEnd::Disconnected => "disconnected",
            WalkEnd::Bound => "bound",
        }
    }
}

impl PathScope {
    /// Stable machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            PathScope::MountCrossing { .. } => PATH_SCOPE_MOUNT_CROSSING,
            PathScope::MountRelative(_) => PATH_SCOPE,
            PathScope::Pseudo { .. } => PATH_SCOPE_PSEUDO,
        }
    }

    /// One sentence an examiner reads.
    pub fn detail(&self) -> String {
        match self {
            PathScope::MountCrossing {
                mounts_crossed,
                ended,
                root_note,
            } => {
                let end = match ended {
                    WalkEnd::ProcessRoot => "ended at the process's root directory",
                    WalkEnd::GlobalRoot => {
                        "ended at the global root without meeting the process's root directory, \
                         so it is relative to the global root"
                    }
                    WalkEnd::Disconnected => {
                        "stopped at a dentry that is the root of its tree but not of its mount \
                         (disconnected), so the path is a suffix of the original"
                    }
                    WalkEnd::Bound => {
                        "stopped at the depth bound or a cycle before reaching a root, so the \
                         path is a suffix of the original"
                    }
                };
                match root_note {
                    Some(note) => {
                        format!("crossed {mounts_crossed} mount point(s) and {end}; {note}")
                    }
                    None => format!("crossed {mounts_crossed} mount point(s) and {end}"),
                }
            }
            PathScope::MountRelative(reason) => {
                format!("reconstructed within one mount only (mount points not crossed): {reason}")
            }
            PathScope::Pseudo { d_dname, kind } => format!(
                "rendered from the dentry's d_dname ({d_dname}) the way the kernel renders a \
                 {kind}; no directory walk was made, because a {kind} has no directory path"
            ),
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            PathScope::MountCrossing {
                mounts_crossed,
                ended,
                root_note,
            } => serde_json::json!({
                "scope": self.as_str(),
                "mounts_crossed": mounts_crossed,
                "ended": ended.as_str(),
                "root_note": root_note,
                "detail": self.detail(),
            }),
            PathScope::MountRelative(_) => serde_json::json!({
                "scope": self.as_str(),
                "detail": self.detail(),
            }),
            PathScope::Pseudo { d_dname, .. } => serde_json::json!({
                "scope": self.as_str(),
                "d_dname": d_dname,
                "detail": self.detail(),
            }),
        }
    }
}

/// What kind of object a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    /// An ordinary file-system object; the path is a directory path.
    File,
    /// A socket: `socket:[inode]`, as the kernel's `sockfs_dname` renders it.
    Socket,
    /// A pipe: `pipe:[inode]`, as `pipefs_dname` renders it.
    Pipe,
    /// An anonymous inode: `anon_inode:<name>`, as `anon_inodefs_dname`
    /// renders it.
    AnonInode,
    /// The dentry renders its own name through a `d_dname` function this
    /// module does not decode. The path is the raw dentry walk, and the string
    /// names the function so an examiner knows what it is not.
    PseudoUnresolved {
        /// The symbol `d_dname` points at, or the address when no symbol
        /// covers it.
        d_dname: String,
    },
}

impl PathKind {
    /// Stable machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            PathKind::File => "file",
            PathKind::Socket => "socket",
            PathKind::Pipe => "pipe",
            PathKind::AnonInode => "anon_inode",
            PathKind::PseudoUnresolved { .. } => "pseudo_unresolved",
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            PathKind::PseudoUnresolved { d_dname } => serde_json::json!({
                "kind": self.as_str(),
                "d_dname": d_dname,
                "detail": format!(
                    "the dentry renders its name through {d_dname}, which this build of Séance \
                     does not decode; the path shown is the raw dentry walk, not what the \
                     process would have seen"
                ),
            }),
            _ => serde_json::json!({ "kind": self.as_str() }),
        }
    }
}

/// A reconstructed path, and what qualifies it.
#[derive(Debug, Clone)]
pub struct PathResult {
    /// The path, or the reason there is none.
    pub path: Field<String>,
    /// Whether every component before its NUL was valid UTF-8. `false` means
    /// bytes were replaced to render it and a name in the image differed — worth
    /// an examiner's attention, because a path component is attacker-chosen.
    pub well_formed: bool,
    /// Whether the walk hit its depth bound, a cycle or a disconnected dentry
    /// before reaching a root, so the path is a suffix of the true one rather
    /// than the whole of it.
    pub truncated: bool,
    /// Which walk produced it.
    pub scope: PathScope,
    /// What the path names.
    pub kind: PathKind,
}

impl PathResult {
    /// The build declares no `f_path.dentry`, so no path could be sought.
    fn not_declared(member: &'static str) -> Self {
        Self {
            path: Field::NotDeclared { member },
            well_formed: true,
            truncated: false,
            scope: PathScope::MountRelative(format!("this build declares no {member}")),
            kind: PathKind::File,
        }
    }

    /// The file is backed but the path evidence would not read.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            path: Field::Unavailable(detail.clone()),
            well_formed: true,
            truncated: false,
            scope: PathScope::MountRelative(detail),
            kind: PathKind::File,
        }
    }

    /// A path field that carries no walk at all — for a record whose backing
    /// pointer answered before any dentry was reached.
    pub fn from_field(path: Field<String>) -> Self {
        let reason = match &path {
            Field::Known(_) => "no walk was made".to_string(),
            Field::NotApplicable => "there is no file behind this record".to_string(),
            Field::NotDeclared { member } => format!("this build declares no {member}"),
            Field::Unavailable(detail) => detail.clone(),
        };
        Self {
            path,
            well_formed: true,
            truncated: false,
            scope: PathScope::MountRelative(reason),
            kind: PathKind::File,
        }
    }

    /// The path-qualifying fields a record publishes, inserted under the
    /// standard names so every stage's rows read alike.
    pub fn stamp(&self, value: &mut serde_json::Value) {
        if let Some(map) = value.as_object_mut() {
            map.insert("path".into(), self.path.to_json());
            map.insert(
                "path_well_formed".into(),
                serde_json::json!(self.well_formed),
            );
            map.insert("path_truncated".into(), serde_json::json!(self.truncated));
            map.insert("path_scope".into(), serde_json::json!(self.scope.as_str()));
            map.insert(
                "path_scope_detail".into(),
                serde_json::json!(self.scope.detail()),
            );
            map.insert("path_kind".into(), serde_json::json!(self.kind.as_str()));
            if let PathKind::PseudoUnresolved { .. } = &self.kind {
                map.insert(
                    "path_kind_detail".into(),
                    self.kind.to_json()["detail"].clone(),
                );
            }
        }
    }
}

/// Whether a binding declares everything the mount-crossing walk reads, so a
/// survey can say up front which walk its records were attempted with.
pub fn mount_crossing_bound(layout: &BuildBinding) -> bool {
    MOUNT_CROSSING_MEMBER_KEYS
        .iter()
        .all(|key| layout.member(key).map(|b| b.is_declared()).unwrap_or(false))
}

/// The survey-level scope label and note for a binding.
pub fn survey_scope(layout: &BuildBinding) -> (&'static str, &'static str) {
    if mount_crossing_bound(layout) {
        (PATH_SCOPE_MOUNT_CROSSING, PATH_SCOPE_NOTE_MOUNT_CROSSING)
    } else {
        (PATH_SCOPE, PATH_SCOPE_NOTE)
    }
}

/// A process's root directory, as `task->fs->root` names it — or why it could
/// not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessRoot {
    /// The root, as a `(dentry, vfsmount)` pair.
    Known {
        /// `fs_struct.root.dentry`.
        dentry: u64,
        /// `fs_struct.root.mnt`, a `vfsmount *`.
        vfsmnt: u64,
    },
    /// The task has no `fs_struct` (a null `task->fs`): a kernel thread, or a
    /// task past exit that dropped it. Paths are then walked to the global
    /// root and say so.
    NoFs,
    /// This build declares no way to reach the root.
    NotDeclared(&'static str),
    /// The `fs_struct` or its root would not read.
    Unavailable(String),
}

impl ProcessRoot {
    /// Why a walk that used this root could not end at the process root — or
    /// `None` when it can.
    fn fallback_reason(&self) -> Option<String> {
        match self {
            ProcessRoot::Known { .. } => None,
            ProcessRoot::NoFs => Some(
                "the task has no fs_struct, so its root directory is unknown and the walk ends \
                 at the global root"
                    .to_string(),
            ),
            ProcessRoot::NotDeclared(member) => Some(format!(
                "this build declares no {member}, so the process's root directory could not be \
                 read and the walk ends at the global root"
            )),
            ProcessRoot::Unavailable(detail) => Some(format!(
                "the process's root directory could not be read ({detail}), so the walk ends at \
                 the global root"
            )),
        }
    }
}

/// Establish a task's root directory for path reconstruction.
///
/// `task` is an object of the kernel `task_struct` type; `layout` must declare
/// [`SPEC_TASK_FS`], [`SPEC_FS_ROOT_DENTRY`] and [`SPEC_FS_ROOT_MNT`] (a layout
/// that omits them yields [`ProcessRoot::NotDeclared`]).
///
/// # Errors
///
/// Only for a key the stage never declared, which is a programming error.
pub fn process_root(layout: &BuildBinding, task: &Obj) -> Result<ProcessRoot, StageError> {
    let fs_bound = layout.member("task_fs")?;
    let Some(fs_member) = fs_bound.member() else {
        return Ok(ProcessRoot::NotDeclared(fs_bound.candidates()[0]));
    };
    let fs = match task.follow(fs_member) {
        Ok(Some(fs)) => fs,
        Ok(None) => return Ok(ProcessRoot::NoFs),
        Err(err) => {
            return Ok(ProcessRoot::Unavailable(format!(
                "the task's fs_struct could not be read: {err}"
            )))
        }
    };
    let dentry = match layout.read_pointer(&fs, "fs_root_dentry")? {
        Field::Known(value) => value,
        Field::NotDeclared { member } => return Ok(ProcessRoot::NotDeclared(member)),
        Field::NotApplicable => return Ok(ProcessRoot::NoFs),
        Field::Unavailable(detail) => return Ok(ProcessRoot::Unavailable(detail)),
    };
    let vfsmnt = match layout.read_pointer(&fs, "fs_root_mnt")? {
        Field::Known(value) => value,
        Field::NotDeclared { member } => return Ok(ProcessRoot::NotDeclared(member)),
        Field::NotApplicable => return Ok(ProcessRoot::NoFs),
        Field::Unavailable(detail) => return Ok(ProcessRoot::Unavailable(detail)),
    };
    if dentry == 0 || vfsmnt == 0 {
        return Ok(ProcessRoot::Unavailable(format!(
            "the fs_struct at {:#x} holds a null root (dentry {dentry:#x}, mnt {vfsmnt:#x})",
            fs.address()
        )));
    }
    Ok(ProcessRoot::Known { dentry, vfsmnt })
}

/// Reconstruct the path of an open `struct file`, crossing mount points.
///
/// `file` is an object of the kernel `file` type; `layout` is the stage's
/// resolved binding, which must declare [`FILE_DENTRY_KEY`], [`DENTRY_TYPE_KEY`]
/// and [`PATH_MEMBER_KEYS`], and — for the crossing walk and the pseudo-path
/// decode — the `SPEC_*` declarations above. `root` is the process's root as
/// [`process_root`] established it. The caller has already established that the
/// file is non-null; a null *backing* file is the caller's "anonymous" case and
/// never reaches here.
///
/// A pseudo-file (socket, pipe, anonymous inode) is recognised before any walk
/// and rendered the way the kernel renders it. A build or a record for which the
/// crossing walk cannot be made falls back to the reduced walk, with the reason
/// in the result's [`PathScope`].
pub fn path_for_file(
    reader: &StructReader,
    layout: &BuildBinding,
    file: &Obj,
    root: &ProcessRoot,
) -> PathResult {
    let Some(dentry_member) = layout
        .member(FILE_DENTRY_KEY)
        .ok()
        .and_then(|bound| bound.member())
    else {
        return PathResult::not_declared("f_path.dentry");
    };

    let start = match file.pointer(dentry_member) {
        Ok(0) => return PathResult::unavailable("the open file has a null dentry"),
        Ok(address) => address,
        Err(err) => {
            return PathResult::unavailable(format!(
                "the file's dentry pointer could not be read: {err}"
            ))
        }
    };

    if let Some(pseudo) = pseudo_path(reader, layout, start) {
        return pseudo;
    }

    let vfsmnt = match layout.member("file_mnt").ok().map(|bound| bound.member()) {
        None => {
            return fall_back(
                reader,
                layout,
                start,
                "the stage did not declare file.f_path.mnt".to_string(),
            )
        }
        Some(None) => {
            return fall_back(
                reader,
                layout,
                start,
                "this build declares no file.f_path.mnt, so the file's mount is unknown"
                    .to_string(),
            )
        }
        Some(Some(member)) => match file.pointer(member) {
            Ok(0) => {
                return fall_back(
                    reader,
                    layout,
                    start,
                    "the file's f_path.mnt is null, so its mount is unknown".to_string(),
                )
            }
            Ok(address) => address,
            Err(err) => {
                return fall_back(
                    reader,
                    layout,
                    start,
                    format!("the file's f_path.mnt could not be read: {err}"),
                )
            }
        },
    };

    crossing_walk(reader, layout, start, vfsmnt, root)
}

/// Reconstruct the path of a mount's mount point, crossing parent mounts.
///
/// `mount` is an object of the bound `mount_entry` type (`struct mount`, or
/// `vfsmount` before 3.3). The walk starts at the mount's own root and steps
/// straight across into the parent, so the result is the mount point's absolute
/// path as `root` sees it — the mounts stage's parity with Volatility's
/// `get_path_mnt`.
pub fn path_for_mount(
    reader: &StructReader,
    layout: &BuildBinding,
    mount: &Obj,
    root: &ProcessRoot,
) -> PathResult {
    let mnt_offset = mount_mnt_offset(layout);
    let Some(vfsmnt) = mount.address().checked_add(mnt_offset) else {
        return PathResult::unavailable("the mount's vfsmount address overflows");
    };
    let mnt_root = match layout.read_pointer(mount, "mnt_root") {
        Ok(Field::Known(0)) => return PathResult::unavailable("the mount's root dentry is null"),
        Ok(Field::Known(address)) => address,
        Ok(Field::NotDeclared { member }) => return PathResult::not_declared(member),
        Ok(Field::NotApplicable) => {
            return PathResult::unavailable("the mount states it has no root dentry")
        }
        Ok(Field::Unavailable(detail)) => return PathResult::unavailable(detail),
        Err(err) => return PathResult::unavailable(err.to_string()),
    };
    crossing_walk(reader, layout, mnt_root, vfsmnt, root)
}

/// The reduced walk, tagged with why the crossing one was not made.
fn fall_back(
    reader: &StructReader,
    layout: &BuildBinding,
    start: u64,
    reason: String,
) -> PathResult {
    let mut result = path_from_dentry(reader, layout, start);
    result.scope = PathScope::MountRelative(reason);
    result
}

/// The offset of the embedded `vfsmount` inside `struct mount`, or zero on a
/// build where a `vfsmount *` is the mount itself.
fn mount_mnt_offset(layout: &BuildBinding) -> u64 {
    layout
        .member("mount_mnt")
        .ok()
        .and_then(|bound| bound.offset())
        .unwrap_or(0)
}

/// The kernel's `prepend_path`, from a `(dentry, vfsmount)` pair up to `root`.
fn crossing_walk(
    reader: &StructReader,
    layout: &BuildBinding,
    start_dentry: u64,
    start_vfsmnt: u64,
    root: &ProcessRoot,
) -> PathResult {
    let Some(dentry_type) = layout
        .type_of(DENTRY_TYPE_KEY)
        .ok()
        .and_then(|bound| bound.type_name())
    else {
        return PathResult::unavailable(
            "this kernel build declares no dentry type, so a path could not be walked",
        );
    };
    let (Some(parent_member), Some(mount_type)) = (
        layout
            .member("d_parent")
            .ok()
            .and_then(|bound| bound.member()),
        layout
            .member("mnt_parent")
            .ok()
            .and_then(|bound| bound.type_name()),
    ) else {
        return fall_back(
            reader,
            layout,
            start_dentry,
            "this build declares no dentry.d_parent or no mount.mnt_parent, so mounts cannot be \
             crossed"
                .to_string(),
        );
    };
    let mnt_offset = mount_mnt_offset(layout);
    let root_pair = match root {
        ProcessRoot::Known { dentry, vfsmnt } => Some((*dentry, *vfsmnt)),
        _ => None,
    };

    let mut components: Vec<String> = Vec::new();
    let mut well_formed = true;
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut dentry = start_dentry;
    let mut vfsmnt = start_vfsmnt;
    let mut mounts_crossed = 0usize;
    let mut ended = WalkEnd::Bound;

    for _ in 0..MAX_PATH_DEPTH {
        if root_pair == Some((dentry, vfsmnt)) {
            ended = WalkEnd::ProcessRoot;
            break;
        }
        if !seen.insert((dentry, vfsmnt)) {
            ended = WalkEnd::Bound;
            break;
        }
        let dentry_obj = match reader.object(dentry, dentry_type) {
            Ok(obj) => obj,
            Err(err) => return unavailable_partial(&components, well_formed, dentry, &err),
        };
        let parent = match dentry_obj.pointer(parent_member) {
            Ok(address) => address,
            Err(err) => {
                return PathResult {
                    path: Field::Unavailable(format!(
                        "the d_parent of the dentry at {dentry:#x} could not be read: {err}{}",
                        recovered_so_far(&components)
                    )),
                    well_formed,
                    truncated: true,
                    scope: PathScope::MountCrossing {
                        mounts_crossed,
                        ended: WalkEnd::Bound,
                        root_note: None,
                    },
                    kind: PathKind::File,
                }
            }
        };
        let is_root = parent == dentry || parent == 0;

        // The mount this dentry is reached through, for its root and parent.
        let mount_addr = vfsmnt.wrapping_sub(mnt_offset);
        let mount_obj = match reader.object(mount_addr, mount_type) {
            Ok(obj) => obj,
            Err(err) => {
                return unavailable_partial_mount(&components, well_formed, mount_addr, &err)
            }
        };
        let mnt_root = match layout.read_pointer(&mount_obj, "mnt_root") {
            Ok(Field::Known(address)) => address,
            other => {
                return PathResult {
                    path: Field::Unavailable(format!(
                        "the root dentry of the mount at {mount_addr:#x} could not be read: {}{}",
                        field_reason(&other),
                        recovered_so_far(&components)
                    )),
                    well_formed,
                    truncated: true,
                    scope: PathScope::MountCrossing {
                        mounts_crossed,
                        ended: WalkEnd::Bound,
                        root_note: None,
                    },
                    kind: PathKind::File,
                }
            }
        };

        if dentry == mnt_root || is_root {
            if dentry != mnt_root {
                ended = WalkEnd::Disconnected;
                break;
            }
            let parent_mount = match layout.read_pointer(&mount_obj, "mnt_parent") {
                Ok(Field::Known(address)) => address,
                other => {
                    return PathResult {
                        path: Field::Unavailable(format!(
                            "the parent of the mount at {mount_addr:#x} could not be read: {}{}",
                            field_reason(&other),
                            recovered_so_far(&components)
                        )),
                        well_formed,
                        truncated: true,
                        scope: PathScope::MountCrossing {
                            mounts_crossed,
                            ended: WalkEnd::Bound,
                            root_note: None,
                        },
                        kind: PathKind::File,
                    }
                }
            };
            if parent_mount == mount_addr || parent_mount == 0 {
                ended = WalkEnd::GlobalRoot;
                break;
            }
            let mountpoint = match layout.read_pointer(&mount_obj, "mnt_mountpoint") {
                Ok(Field::Known(address)) if address != 0 => address,
                other => {
                    return PathResult {
                        path: Field::Unavailable(format!(
                            "the mount point of the mount at {mount_addr:#x} could not be read: \
                             {}{}",
                            field_reason(&other),
                            recovered_so_far(&components)
                        )),
                        well_formed,
                        truncated: true,
                        scope: PathScope::MountCrossing {
                            mounts_crossed,
                            ended: WalkEnd::Bound,
                            root_note: None,
                        },
                        kind: PathKind::File,
                    }
                }
            };
            dentry = mountpoint;
            vfsmnt = parent_mount.wrapping_add(mnt_offset);
            mounts_crossed += 1;
            continue;
        }

        let (name, name_well_formed) = component_name(reader, layout, &dentry_obj);
        if !name_well_formed {
            well_formed = false;
        }
        if !name.is_empty() && name != "/" {
            components.push(name);
        }
        dentry = parent;
    }

    let path = if components.is_empty() {
        "/".to_string()
    } else {
        join_components(&components)
    };
    // A walk that reached the global root while a process root was known did
    // not meet it: the file lies outside the process's root directory. When no
    // process root was known, the reason travels with the scope so the record
    // says why the path is global-root relative.
    let root_note = if ended == WalkEnd::GlobalRoot {
        root.fallback_reason()
    } else {
        None
    };
    PathResult {
        path: Field::Known(path),
        well_formed,
        truncated: !matches!(ended, WalkEnd::ProcessRoot | WalkEnd::GlobalRoot),
        scope: PathScope::MountCrossing {
            mounts_crossed,
            ended,
            root_note,
        },
        kind: PathKind::File,
    }
}

/// The reason a `Field` read yielded no value, for a message.
fn field_reason(field: &Result<Field<u64>, seance_memory::binding::BindError>) -> String {
    match field {
        Ok(Field::Known(value)) => format!("read {value:#x}"),
        Ok(Field::NotApplicable) => "the member states it has no value".to_string(),
        Ok(Field::NotDeclared { member }) => format!("this build declares no {member}"),
        Ok(Field::Unavailable(detail)) => detail.clone(),
        Err(err) => err.to_string(),
    }
}

/// Recognise a pseudo-file by its `d_op->d_dname` and render it the way the
/// kernel does. `None` for an ordinary dentry (no `d_op`, or a `d_op` with no
/// `d_dname`), and for a build whose binding cannot ask the question.
fn pseudo_path(reader: &StructReader, layout: &BuildBinding, dentry: u64) -> Option<PathResult> {
    let dentry_type = layout.type_of(DENTRY_TYPE_KEY).ok()?.type_name()?;
    let d_op_member = layout.member("d_op").ok()?.member()?;
    let d_dname_member = layout.member("d_dname").ok()?.member()?;
    let dentry_obj = reader.object(dentry, dentry_type).ok()?;
    let d_op = match dentry_obj.follow(d_op_member) {
        Ok(Some(ops)) => ops,
        _ => return None,
    };
    let d_dname = match d_op.pointer(d_dname_member) {
        Ok(0) | Err(_) => return None,
        Ok(address) => address,
    };

    let symbols = reader.symbols();
    let symbol = symbols
        .nearest_symbol(d_dname)
        .filter(|(_, distance)| *distance == 0)
        .map(|(entry, _)| entry.name.to_string());
    let ino = inode_number(layout, &dentry_obj);
    let (name, name_well_formed) = component_name(reader, layout, &dentry_obj);

    let pseudo_scope = |d_dname: &str, kind: &PathKind| PathScope::Pseudo {
        d_dname: d_dname.to_string(),
        kind: kind.as_str().to_string(),
    };
    let render_ino = |d_dname: &str, prefix: &str, kind: PathKind| -> PathResult {
        let scope = pseudo_scope(d_dname, &kind);
        match ino {
            Ok(ino) => PathResult {
                path: Field::Known(format!("{prefix}:[{ino}]")),
                well_formed: true,
                truncated: false,
                scope,
                kind,
            },
            Err(reason) => PathResult {
                path: Field::Unavailable(format!(
                    "the descriptor is a {} whose inode number could not be read: {reason}",
                    kind.as_str()
                )),
                well_formed: true,
                truncated: false,
                scope,
                kind,
            },
        }
    };

    Some(match symbol.as_deref() {
        Some(SOCKFS_DNAME) => render_ino(SOCKFS_DNAME, "socket", PathKind::Socket),
        Some(PIPEFS_DNAME) => render_ino(PIPEFS_DNAME, "pipe", PathKind::Pipe),
        Some(ANON_INODEFS_DNAME) => PathResult {
            path: Field::Known(format!("anon_inode:{name}")),
            well_formed: name_well_formed,
            truncated: false,
            scope: pseudo_scope(ANON_INODEFS_DNAME, &PathKind::AnonInode),
            kind: PathKind::AnonInode,
        },
        other => {
            let label = match other {
                Some(symbol) => symbol.to_string(),
                None => format!("{d_dname:#x} (no symbol covers it)"),
            };
            let mut raw = path_from_dentry(reader, layout, dentry);
            raw.kind = PathKind::PseudoUnresolved { d_dname: label };
            raw
        }
    })
}

/// The inode number behind a dentry, or why it could not be read.
fn inode_number(layout: &BuildBinding, dentry: &Obj) -> Result<u64, String> {
    let d_inode = layout
        .member("d_inode")
        .map_err(|e| e.to_string())?
        .member()
        .ok_or_else(|| "this build declares no dentry.d_inode".to_string())?;
    let inode = match dentry.follow(d_inode) {
        Ok(Some(inode)) => inode,
        Ok(None) => return Err("the dentry has no inode".to_string()),
        Err(err) => return Err(format!("the inode could not be read: {err}")),
    };
    match layout.read_unsigned(&inode, "i_ino") {
        Ok(Field::Known(ino)) => Ok(ino),
        Ok(Field::NotDeclared { member }) => Err(format!("this build declares no {member}")),
        Ok(Field::NotApplicable) => Err("the inode states it has no number".to_string()),
        Ok(Field::Unavailable(detail)) => Err(detail),
        Err(err) => Err(err.to_string()),
    }
}

/// Reconstruct a path from a `dentry` pointer, walking `d_parent` to the root of
/// its own tree — the reduced walk.
///
/// Given the address of any dentry — a file's own, or a mount's mountpoint or
/// filesystem root — walk up its tree, joining `d_name`, with the depth bound,
/// cycle guard and `d_iname` fallback. Mount points are not crossed; the result's
/// scope says so. `layout` must declare [`DENTRY_TYPE_KEY`] and
/// [`PATH_MEMBER_KEYS`].
pub fn path_from_dentry(reader: &StructReader, layout: &BuildBinding, start: u64) -> PathResult {
    let Some(dentry_type) = layout
        .type_of(DENTRY_TYPE_KEY)
        .ok()
        .and_then(|bound| bound.type_name())
    else {
        return PathResult::unavailable(
            "this kernel build declares no dentry type, so a path could not be walked",
        );
    };

    let parent_member = layout
        .member("d_parent")
        .ok()
        .and_then(|bound| bound.member());

    let mut components: Vec<String> = Vec::new();
    let mut well_formed = true;
    let mut truncated = false;
    let mut seen: HashSet<u64> = HashSet::new();
    let mut current = start;

    for _ in 0..MAX_PATH_DEPTH {
        if !seen.insert(current) {
            truncated = true; // a cycle in the dentry chain
            break;
        }
        let dentry = match reader.object(current, dentry_type) {
            Ok(obj) => obj,
            Err(err) => {
                return unavailable_partial(&components, well_formed, current, &err);
            }
        };

        // The self-referential root ends the walk: its name is the mount root
        // ("/"), which the join supplies, so it is not pushed. A build with no
        // `d_parent` cannot ascend, which is a truncated path, not a wrong one.
        let Some(parent_path) = parent_member else {
            truncated = true;
            break;
        };
        let parent = match dentry.pointer(parent_path) {
            Ok(address) => address,
            Err(_) => {
                truncated = true;
                break;
            }
        };
        if parent == current || parent == 0 {
            break;
        }

        let (name, name_well_formed) = component_name(reader, layout, &dentry);
        if !name_well_formed {
            well_formed = false;
        }
        // A dentry with an empty name contributes nothing (the join must not
        // produce a double slash), and a stray "/" is never a component.
        if !name.is_empty() && name != "/" {
            components.push(name);
        }
        current = parent;
    }

    let path = if components.is_empty() {
        "/".to_string()
    } else {
        join_components(&components)
    };

    PathResult {
        path: Field::Known(path),
        well_formed,
        truncated,
        scope: PathScope::MountRelative("the reduced dentry walk was requested".to_string()),
        kind: PathKind::File,
    }
}

/// Join path components gathered leaf-first into absolute-path text.
///
/// The walk collects components from the dentry up towards the root, so the
/// vector is leaf-first; this reverses it and joins with `/` separators, e.g.
/// `["bar", "foo"]` → `/foo/bar`. An empty list yields an empty string — the
/// caller decides whether that means the root `/`. Shared by the full-path and
/// partial-path builders so both render a recovered path the same way (CR-007).
fn join_components(components: &[String]) -> String {
    let mut out = String::new();
    for component in components.iter().rev() {
        out.push('/');
        out.push_str(component);
    }
    out
}

/// The components gathered before a walk failed, for a message.
fn recovered_so_far(components: &[String]) -> String {
    if components.is_empty() {
        String::new()
    } else {
        format!(" (recovered so far: {})", join_components(components))
    }
}

/// A path whose walk failed part way: the components gathered so far are real
/// evidence, so they are reported as a partial path with the reason attached,
/// rather than discarded for a blank.
fn unavailable_partial(
    components: &[String],
    well_formed: bool,
    at: u64,
    err: &seance_memory::object::ObjError,
) -> PathResult {
    let detail = read::unreadable_detail("a dentry in the path chain", at, err);
    let detail = format!("{detail}{}", recovered_so_far(components));
    PathResult {
        path: Field::Unavailable(detail.clone()),
        well_formed,
        truncated: true,
        scope: PathScope::MountRelative(detail),
        kind: PathKind::File,
    }
}

/// As [`unavailable_partial`], for a mount structure on the chain.
fn unavailable_partial_mount(
    components: &[String],
    well_formed: bool,
    at: u64,
    err: &seance_memory::object::ObjError,
) -> PathResult {
    let detail = read::unreadable_detail("a mount in the path chain", at, err);
    let detail = format!("{detail}{}", recovered_so_far(components));
    PathResult {
        path: Field::Unavailable(detail.clone()),
        well_formed,
        truncated: true,
        scope: PathScope::MountRelative(detail),
        kind: PathKind::File,
    }
}

/// One path component: the `d_name` string, with the inline `d_iname` fast path
/// as a fallback.
///
/// A short name is stored inline in `dentry.d_iname` and `d_name.name` points at
/// it; a long name is heap-allocated and `d_name.name` points there. Reading the
/// pointer covers both, and the inline array is the fallback for when the pointer
/// will not read but the name is short enough to have stayed inline.
fn component_name(reader: &StructReader, layout: &BuildBinding, dentry: &Obj) -> (String, bool) {
    let len = layout
        .member("d_name_len")
        .ok()
        .and_then(|bound| bound.member())
        .and_then(|path| dentry.unsigned(path).ok());
    let pointer = layout
        .member("d_name_ptr")
        .ok()
        .and_then(|bound| bound.member())
        .and_then(|path| dentry.pointer(path).ok());

    if let Some(pointer) = pointer {
        if pointer != 0 {
            let want = len
                .map(|l| (l as usize).saturating_add(1))
                .unwrap_or(256)
                .min(MAX_C_STRING);
            if let Ok((text, well_formed)) =
                read::read_c_string(&**reader.native_layer(), pointer, want)
            {
                if !text.is_empty() {
                    return (text, well_formed);
                }
            }
        }
    }

    // Fallback: the name stored inline in the dentry itself.
    if let Some(path) = layout
        .member("d_iname")
        .ok()
        .and_then(|bound| bound.member())
    {
        if let Ok(bytes) = dentry.bytes(path) {
            return decode_nul_terminated(&bytes);
        }
    }

    (String::new(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crossing_scope_states_the_mounts_crossed_and_where_it_ended() {
        let scope = PathScope::MountCrossing {
            mounts_crossed: 2,
            ended: WalkEnd::ProcessRoot,
            root_note: None,
        };
        assert_eq!(scope.as_str(), "mount_crossing");
        let json = scope.to_json();
        assert_eq!(json["mounts_crossed"], 2);
        assert_eq!(json["ended"], "process_root");
        assert!(json["detail"]
            .as_str()
            .unwrap()
            .contains("crossed 2 mount point(s)"));
    }

    #[test]
    fn a_walk_to_the_global_root_with_no_process_root_says_why() {
        let scope = PathScope::MountCrossing {
            mounts_crossed: 0,
            ended: WalkEnd::GlobalRoot,
            root_note: ProcessRoot::NoFs.fallback_reason(),
        };
        let detail = scope.detail();
        assert!(detail.contains("global root"), "{detail}");
        assert!(detail.contains("no fs_struct"), "{detail}");
    }

    #[test]
    fn a_mount_relative_scope_carries_its_reason_and_the_old_label() {
        let scope = PathScope::MountRelative("this build declares no file.f_path.mnt".into());
        assert_eq!(scope.as_str(), PATH_SCOPE);
        assert_eq!(scope.as_str(), "dentry_tree_relative");
        assert!(scope.detail().contains("not crossed"));
        assert!(scope.detail().contains("f_path.mnt"));
    }

    #[test]
    fn an_unresolved_pseudo_path_names_the_function_it_did_not_decode() {
        let kind = PathKind::PseudoUnresolved {
            d_dname: "ns_dname".into(),
        };
        let json = kind.to_json();
        assert_eq!(json["kind"], "pseudo_unresolved");
        assert_eq!(json["d_dname"], "ns_dname");
        assert!(json["detail"].as_str().unwrap().contains("does not decode"));
    }

    #[test]
    fn a_pseudo_scope_says_no_walk_was_made_and_names_the_renderer() {
        let scope = PathScope::Pseudo {
            d_dname: "sockfs_dname".into(),
            kind: "socket".into(),
        };
        assert_eq!(scope.as_str(), PATH_SCOPE_PSEUDO);
        assert_eq!(scope.as_str(), "pseudo");
        let detail = scope.detail();
        assert!(detail.contains("no directory walk was made"), "{detail}");
        assert!(detail.contains("sockfs_dname"), "{detail}");
        assert!(detail.contains("socket"), "{detail}");
        assert!(
            !detail.contains("crossed") && !detail.contains("root"),
            "a pseudo-path must not describe a mount walk: {detail}"
        );
        let json = scope.to_json();
        assert_eq!(json["scope"], "pseudo");
        assert_eq!(json["d_dname"], "sockfs_dname");
        assert!(json.get("mounts_crossed").is_none());
        assert!(json.get("ended").is_none());
    }

    #[test]
    fn the_stamp_publishes_scope_and_kind_beside_the_path() {
        let result = PathResult {
            path: Field::Known("socket:[77]".into()),
            well_formed: true,
            truncated: false,
            scope: PathScope::Pseudo {
                d_dname: "sockfs_dname".into(),
                kind: "socket".into(),
            },
            kind: PathKind::Socket,
        };
        let mut value = serde_json::json!({ "fd": 3 });
        result.stamp(&mut value);
        assert_eq!(value["path"]["value"], "socket:[77]");
        assert_eq!(value["path_scope"], "pseudo");
        assert_eq!(value["path_kind"], "socket");
        assert!(value["path_scope_detail"].is_string());
        assert_eq!(value["fd"], 3, "the stamp adds fields and removes none");
    }
}

#[cfg(test)]
mod walk_tests {
    //! The kernel's `prepend_path` over a synthetic image, in both mount
    //! shapes. The fixture layouts are written from the kernel's own structure
    //! definitions (fs/mount.h, include/linux/mount.h, include/linux/dcache.h),
    //! not copied from a capture; the real-capture tests under `tests/` are
    //! what grade the walk against evidence.
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::binding::MemberSet;
    use seance_memory::{MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use super::*;
    use crate::module::STAGE_LINUX_OPEN_FILES;

    const LAYOUT: MemberSet = MemberSet::new(
        STAGE_LINUX_OPEN_FILES,
        &[
            TypeSpec::new("file", &["file"]),
            TYPE_DENTRY,
            TYPE_MOUNT_ENTRY,
            TYPE_DENTRY_OPERATIONS,
            TYPE_INODE,
        ],
        &[
            SPEC_FILE_DENTRY,
            SPEC_FILE_MNT,
            SPEC_MOUNT_MNT,
            SPEC_MNT_PARENT,
            SPEC_MNT_MOUNTPOINT,
            SPEC_MNT_ROOT,
            SPEC_TASK_FS,
            SPEC_FS_ROOT_DENTRY,
            SPEC_FS_ROOT_MNT,
            SPEC_D_PARENT,
            SPEC_D_NAME_PTR,
            SPEC_D_NAME_LEN,
            SPEC_D_INAME,
            SPEC_D_OP,
            SPEC_D_DNAME,
            SPEC_D_INODE,
            SPEC_I_INO,
        ],
    );

    // Dentries.
    const D_ROOT: u64 = 0x1000; // "/" of the root filesystem, self-parent
    const D_DEV: u64 = 0x1100; // "dev" under D_ROOT — the mount point of devtmpfs
    const D_DEVROOT: u64 = 0x1200; // "/" of devtmpfs, self-parent
    const D_NULL: u64 = 0x1300; // "null" under D_DEVROOT
    const D_ETC: u64 = 0x1400; // "etc" under D_ROOT
    const D_PASSWD: u64 = 0x1500; // "passwd" under D_ETC
    const D_SOCK: u64 = 0x1600; // a socket dentry, d_op -> OPS_SOCK
    const D_ORPHAN: u64 = 0x1700; // self-parent but not any mount's root
    const D_ANON: u64 = 0x1800; // "[eventpoll]" anon inode, d_op -> OPS_ANON
    const D_CHROOT: u64 = 0x1900; // "jail" under D_ROOT — a chroot's root
    const D_JAILED: u64 = 0x1a00; // "secret" under D_CHROOT
                                  // Mounts (struct mount; the embedded vfsmount sits at +32).
    const M_ROOT: u64 = 0x2000;
    const M_DEV: u64 = 0x2100;
    const MNT_OFF: u64 = 32;
    // Files.
    const F_NULL: u64 = 0x3000;
    const F_PASSWD: u64 = 0x3100;
    const F_SOCK: u64 = 0x3200;
    const F_ORPHAN: u64 = 0x3300;
    const F_ANON: u64 = 0x3400;
    const F_JAILED: u64 = 0x3500;
    // Task and fs_struct.
    const TASK: u64 = 0x4000;
    const FS: u64 = 0x4800;
    const TASK_NOFS: u64 = 0x4900;
    const TASK_JAIL: u64 = 0x4a00;
    const FS_JAIL: u64 = 0x4b00;
    // Operations and inodes.
    const OPS_SOCK: u64 = 0x5000;
    const OPS_ANON: u64 = 0x5100;
    const OPS_ODD: u64 = 0x5200;
    const INODE_SOCK: u64 = 0x5300;
    // Symbol addresses (kernel functions).
    const SYM_SOCKFS_DNAME: u64 = 0x6000;
    const SYM_ANON_DNAME: u64 = 0x6100;
    const SYM_NS_DNAME: u64 = 0x6200;
    // Names.
    const N_DEV: u64 = 0x7000;
    const N_NULL: u64 = 0x7010;
    const N_ETC: u64 = 0x7020;
    const N_PASSWD: u64 = 0x7030;
    const N_ORPHAN: u64 = 0x7040;
    const N_ANON: u64 = 0x7050;
    const N_JAIL: u64 = 0x7060;
    const N_SECRET: u64 = 0x7070;

    const FIXTURE_ISF: &str = r#"{
      "metadata": {"format":"6.2.0","producer":{"name":"seance-paths-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
      "base_types": {
        "pointer": {"size":8,"signed":false,"kind":"int","endian":"little"},
        "unsigned long": {"size":8,"signed":false,"kind":"int","endian":"little"},
        "unsigned int": {"size":4,"signed":false,"kind":"int","endian":"little"},
        "int": {"size":4,"signed":true,"kind":"int","endian":"little"},
        "char": {"size":1,"signed":true,"kind":"char","endian":"little"},
        "void": {"size":0,"signed":false,"kind":"void","endian":"little"}
      },
      "user_types": {
        "qstr": {"size":16,"kind":"struct","fields":{
          "len":{"offset":4,"type":{"kind":"base","name":"unsigned int"}},
          "name":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}}
        }},
        "path": {"size":16,"kind":"struct","fields":{
          "mnt":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vfsmount"}}},
          "dentry":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}}
        }},
        "dentry_operations": {"size":64,"kind":"struct","fields":{
          "d_dname":{"offset":48,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}}
        }},
        "inode": {"size":128,"kind":"struct","fields":{
          "i_ino":{"offset":64,"type":{"kind":"base","name":"unsigned long"}}
        }},
        "dentry": {"size":192,"kind":"struct","fields":{
          "d_parent":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "d_name":{"offset":32,"type":{"kind":"struct","name":"qstr"}},
          "d_inode":{"offset":48,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"inode"}}},
          "d_iname":{"offset":56,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}},
          "d_op":{"offset":96,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry_operations"}}}
        }},
        "vfsmount": {"size":32,"kind":"struct","fields":{
          "mnt_root":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "mnt_sb":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
          "mnt_flags":{"offset":16,"type":{"kind":"base","name":"int"}}
        }},
        "mount": {"size":256,"kind":"struct","fields":{
          "mnt_parent":{"offset":16,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"mount"}}},
          "mnt_mountpoint":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "mnt":{"offset":32,"type":{"kind":"struct","name":"vfsmount"}}
        }},
        "file": {"size":208,"kind":"struct","fields":{
          "f_path":{"offset":16,"type":{"kind":"struct","name":"path"}}
        }},
        "fs_struct": {"size":56,"kind":"struct","fields":{
          "root":{"offset":24,"type":{"kind":"struct","name":"path"}}
        }},
        "task_struct": {"size":1784,"kind":"struct","fields":{
          "fs":{"offset":1144,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"fs_struct"}}}
        }}
      },
      "enums": {},
      "symbols": {
        "sockfs_dname": {"address": 24576},
        "anon_inodefs_dname": {"address": 24832},
        "ns_dname": {"address": 25088}
      }
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
        fn dentry(&mut self, at: u64, parent: u64, name: u64, text: &[u8]) {
            self.u64(at + 24, parent);
            self.u32(at + 36, text.len() as u32);
            self.u64(at + 40, name);
            self.put(name, text);
            self.put(name + text.len() as u64, b"\0");
        }
        fn mount(&mut self, at: u64, parent: u64, mountpoint: u64, root: u64) {
            self.u64(at + 16, parent);
            self.u64(at + 24, mountpoint);
            self.u64(at + MNT_OFF, root);
        }
        fn file(&mut self, at: u64, mount: u64, dentry: u64) {
            self.u64(at + 16, mount + MNT_OFF);
            self.u64(at + 24, dentry);
        }
    }

    fn image() -> Image {
        let mut m = Image::new();
        // The root filesystem: / , /dev (a directory that is a mount point),
        // /etc/passwd, /jail/secret.
        m.u64(D_ROOT + 24, D_ROOT);
        m.dentry(D_DEV, D_ROOT, N_DEV, b"dev");
        m.dentry(D_ETC, D_ROOT, N_ETC, b"etc");
        m.dentry(D_PASSWD, D_ETC, N_PASSWD, b"passwd");
        m.dentry(D_CHROOT, D_ROOT, N_JAIL, b"jail");
        m.dentry(D_JAILED, D_CHROOT, N_SECRET, b"secret");
        // devtmpfs: its own root, with "null" directly under it.
        m.u64(D_DEVROOT + 24, D_DEVROOT);
        m.dentry(D_NULL, D_DEVROOT, N_NULL, b"null");
        // A dentry that is the root of its tree but no mount's root.
        m.dentry(D_ORPHAN, D_ORPHAN, N_ORPHAN, b"orphan");
        // Mounts: the root mount is its own parent; devtmpfs hangs off /dev.
        m.mount(M_ROOT, M_ROOT, D_ROOT, D_ROOT);
        m.mount(M_DEV, M_ROOT, D_DEV, D_DEVROOT);
        // Files.
        m.file(F_NULL, M_DEV, D_NULL);
        m.file(F_PASSWD, M_ROOT, D_PASSWD);
        m.file(F_ORPHAN, M_DEV, D_ORPHAN);
        m.file(F_JAILED, M_ROOT, D_JAILED);
        // A socket: d_op->d_dname == sockfs_dname, inode 4242.
        m.u64(D_SOCK + 24, D_SOCK);
        m.u64(D_SOCK + 48, INODE_SOCK);
        m.u64(D_SOCK + 96, OPS_SOCK);
        m.u64(OPS_SOCK + 48, SYM_SOCKFS_DNAME);
        m.u64(INODE_SOCK + 64, 4242);
        m.file(F_SOCK, M_ROOT, D_SOCK);
        // An anonymous inode named "[eventpoll]".
        m.dentry(D_ANON, D_ANON, N_ANON, b"[eventpoll]");
        m.u64(D_ANON + 96, OPS_ANON);
        m.u64(OPS_ANON + 48, SYM_ANON_DNAME);
        m.file(F_ANON, M_ROOT, D_ANON);
        // An operations table whose d_dname this module does not decode.
        m.u64(OPS_ODD + 48, SYM_NS_DNAME);
        // Tasks: one rooted at /, one with no fs_struct, one chrooted to /jail.
        m.u64(TASK + 1144, FS);
        m.u64(FS + 24, M_ROOT + MNT_OFF);
        m.u64(FS + 32, D_ROOT);
        m.u64(TASK_NOFS + 1144, 0);
        m.u64(TASK_JAIL + 1144, FS_JAIL);
        m.u64(FS_JAIL + 24, M_ROOT + MNT_OFF);
        m.u64(FS_JAIL + 32, D_CHROOT);
        m
    }

    fn reader_over(m: Image) -> StructReader {
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

    fn root_of(reader: &StructReader, layout: &BuildBinding, task: u64) -> ProcessRoot {
        let task = reader.object(task, "task_struct").expect("the task reads");
        process_root(layout, &task).expect("declared keys")
    }

    fn walk(
        reader: &StructReader,
        layout: &BuildBinding,
        file: u64,
        root: &ProcessRoot,
    ) -> PathResult {
        let file = reader.object(file, "file").expect("the file reads");
        path_for_file(reader, layout, &file, root)
    }

    #[test]
    fn a_file_on_a_child_mount_gets_its_mount_point_prefix() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        assert!(mount_crossing_bound(&layout));
        let root = root_of(&reader, &layout, TASK);
        assert!(matches!(root, ProcessRoot::Known { .. }), "{root:?}");

        let result = walk(&reader, &layout, F_NULL, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/dev/null"));
        assert!(!result.truncated);
        assert_eq!(result.kind, PathKind::File);
        assert_eq!(
            result.scope,
            PathScope::MountCrossing {
                mounts_crossed: 1,
                ended: WalkEnd::ProcessRoot,
                root_note: None,
            }
        );
    }

    #[test]
    fn a_file_on_the_root_mount_crosses_nothing_and_ends_at_the_process_root() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_PASSWD, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/etc/passwd"));
        assert_eq!(
            result.scope,
            PathScope::MountCrossing {
                mounts_crossed: 0,
                ended: WalkEnd::ProcessRoot,
                root_note: None,
            }
        );
    }

    #[test]
    fn a_chrooted_process_sees_its_files_relative_to_its_own_root() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let jail = root_of(&reader, &layout, TASK_JAIL);
        let result = walk(&reader, &layout, F_JAILED, &jail);
        assert_eq!(
            result.path.known().map(String::as_str),
            Some("/secret"),
            "inside the jail the file is /secret, not /jail/secret"
        );
        assert!(matches!(
            result.scope,
            PathScope::MountCrossing {
                ended: WalkEnd::ProcessRoot,
                ..
            }
        ));

        // A file outside the jail walks to the global root and says it never
        // met the process root — the sign of a path outside the chroot.
        let outside = walk(&reader, &layout, F_PASSWD, &jail);
        assert_eq!(
            outside.path.known().map(String::as_str),
            Some("/etc/passwd")
        );
        assert!(matches!(
            outside.scope,
            PathScope::MountCrossing {
                ended: WalkEnd::GlobalRoot,
                ..
            }
        ));
    }

    #[test]
    fn a_task_with_no_fs_struct_walks_to_the_global_root_and_says_so() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK_NOFS);
        assert_eq!(root, ProcessRoot::NoFs);
        let result = walk(&reader, &layout, F_NULL, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/dev/null"));
        match &result.scope {
            PathScope::MountCrossing {
                mounts_crossed: 1,
                ended: WalkEnd::GlobalRoot,
                root_note: Some(note),
            } => assert!(note.contains("no fs_struct"), "{note}"),
            other => panic!("expected a global-root walk with a root note: {other:?}"),
        }
        assert!(
            !result.truncated,
            "a global-root path is whole, not a suffix"
        );
    }

    #[test]
    fn a_disconnected_dentry_is_a_truncated_path_not_a_wrong_one() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_ORPHAN, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/"));
        assert!(result.truncated);
        assert!(matches!(
            result.scope,
            PathScope::MountCrossing {
                ended: WalkEnd::Disconnected,
                ..
            }
        ));
    }

    #[test]
    fn a_socket_is_rendered_by_its_inode_number_and_typed_as_one() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_SOCK, &root);
        assert_eq!(
            result.path.known().map(String::as_str),
            Some("socket:[4242]")
        );
        assert_eq!(result.kind, PathKind::Socket);
        assert!(!result.truncated);
        assert_eq!(
            result.scope,
            PathScope::Pseudo {
                d_dname: "sockfs_dname".into(),
                kind: "socket".into(),
            },
            "no mount walk is made for a socket, and the record must not describe one"
        );
    }

    #[test]
    fn an_anonymous_inode_is_rendered_by_its_dentry_name() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_ANON, &root);
        assert_eq!(
            result.path.known().map(String::as_str),
            Some("anon_inode:[eventpoll]")
        );
        assert_eq!(result.kind, PathKind::AnonInode);
        assert_eq!(result.scope.as_str(), PATH_SCOPE_PSEUDO);
    }

    #[test]
    fn an_unknown_d_dname_is_named_and_the_raw_walk_is_kept() {
        let mut m = image();
        // Point the passwd dentry's d_op at an operations table whose d_dname
        // is ns_dname, which this module does not decode.
        m.u64(D_PASSWD + 96, OPS_ODD);
        let reader = reader_over(m);
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_PASSWD, &root);
        assert_eq!(
            result.kind,
            PathKind::PseudoUnresolved {
                d_dname: "ns_dname".into()
            }
        );
        assert_eq!(
            result.path.known().map(String::as_str),
            Some("/etc/passwd"),
            "the raw dentry walk is kept beside the name of what it is not"
        );
        assert_eq!(result.scope.as_str(), PATH_SCOPE);
    }

    #[test]
    fn a_null_vfsmount_falls_back_to_the_reduced_walk_and_says_so() {
        let mut m = image();
        m.u64(F_NULL + 16, 0); // f_path.mnt = NULL
        let reader = reader_over(m);
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_NULL, &root);
        assert_eq!(
            result.path.known().map(String::as_str),
            Some("/null"),
            "without its mount the file's path is relative to the devtmpfs root"
        );
        match &result.scope {
            PathScope::MountRelative(reason) => assert!(reason.contains("f_path.mnt"), "{reason}"),
            other => panic!("expected the reduced walk: {other:?}"),
        }
    }

    #[test]
    fn a_mount_whose_bytes_are_missing_yields_the_partial_path_and_the_reason() {
        let mut m = image();
        // Send the devtmpfs mount's parent pointer off the end of the image, so
        // the walk names "null", crosses the mount, and then cannot read on.
        m.u64(M_DEV + 16, 0x9_0000);
        let reader = reader_over(m);
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_NULL, &root);
        match &result.path {
            Field::Unavailable(detail) => {
                assert!(detail.contains("mount"), "{detail}");
                assert!(detail.contains("recovered so far: /null"), "{detail}");
            }
            other => panic!("an unreadable mount must not yield a confident path: {other:?}"),
        }
        assert!(result.truncated);
    }

    #[test]
    fn the_mount_point_of_a_mount_is_its_absolute_path_in_the_parent() {
        let reader = reader_over(image());
        let layout = LAYOUT.bind(&reader).expect("binds");
        let root = root_of(&reader, &layout, TASK);
        let mount = reader.object(M_DEV, "mount").expect("the mount reads");
        let result = path_for_mount(&reader, &layout, &mount, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/dev"));
        assert!(matches!(
            result.scope,
            PathScope::MountCrossing {
                mounts_crossed: 1,
                ended: WalkEnd::ProcessRoot,
                ..
            }
        ));
        let root_mount = reader.object(M_ROOT, "mount").expect("reads");
        let result = path_for_mount(&reader, &layout, &root_mount, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/"));
    }

    /// The pre-3.3 shape: no `struct mount`, the `vfsmount` carries its own
    /// parent and mountpoint, and `f_path.mnt` points straight at it.
    #[test]
    fn a_pre_3_3_vfsmount_chain_is_crossed_with_no_container_offset() {
        const OLD_ISF: &str = r#"{
          "metadata": {"format":"6.2.0","producer":{"name":"seance-paths-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
          "base_types": {
            "pointer": {"size":8,"signed":false,"kind":"int","endian":"little"},
            "unsigned int": {"size":4,"signed":false,"kind":"int","endian":"little"},
            "char": {"size":1,"signed":true,"kind":"char","endian":"little"},
            "void": {"size":0,"signed":false,"kind":"void","endian":"little"}
          },
          "user_types": {
            "qstr": {"size":16,"kind":"struct","fields":{
              "len":{"offset":4,"type":{"kind":"base","name":"unsigned int"}},
              "name":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}}
            }},
            "path": {"size":16,"kind":"struct","fields":{
              "mnt":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vfsmount"}}},
              "dentry":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}}
            }},
            "dentry": {"size":192,"kind":"struct","fields":{
              "d_parent":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
              "d_name":{"offset":32,"type":{"kind":"struct","name":"qstr"}},
              "d_iname":{"offset":56,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}}
            }},
            "vfsmount": {"size":256,"kind":"struct","fields":{
              "mnt_parent":{"offset":16,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"vfsmount"}}},
              "mnt_mountpoint":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
              "mnt_root":{"offset":32,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}}
            }},
            "file": {"size":208,"kind":"struct","fields":{
              "f_path":{"offset":16,"type":{"kind":"struct","name":"path"}}
            }},
            "fs_struct": {"size":56,"kind":"struct","fields":{
              "root":{"offset":24,"type":{"kind":"struct","name":"path"}}
            }},
            "task_struct": {"size":1784,"kind":"struct","fields":{
              "fs":{"offset":1144,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"fs_struct"}}}
            }}
          },
          "enums": {},
          "symbols": {}
        }"#;
        // The same image, but each mount's mnt_root lives at +32 of the mount
        // itself (which is where the fixture already put the embedded
        // vfsmount's mnt_root) and the file's mnt pointer names the mount.
        let mut m = image();
        m.u64(F_NULL + 16, M_DEV);
        m.u64(FS + 24, M_ROOT);
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(m.bytes));
        let layer: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).expect("image"));
        let symbols = Arc::new(
            SymbolTable::compile_source(
                seance_symbols::load_slice(OLD_ISF.as_bytes(), &DecompressLimits::default())
                    .expect("loads"),
                &CompileOptions::default(),
            )
            .expect("compiles"),
        );
        let reader = StructReader::new(layer, symbols);
        let layout = LAYOUT.bind(&reader).expect("binds");
        assert!(
            !layout.member("mount_mnt").unwrap().is_declared(),
            "the old shape has no struct mount"
        );
        assert_eq!(
            layout.member("mnt_root").unwrap().member(),
            Some("mnt_root"),
            "on the old shape the root is a direct member of the vfsmount"
        );
        let root = root_of(&reader, &layout, TASK);
        let result = walk(&reader, &layout, F_NULL, &root);
        assert_eq!(result.path.known().map(String::as_str), Some("/dev/null"));
        assert!(matches!(
            result.scope,
            PathScope::MountCrossing {
                mounts_crossed: 1,
                ended: WalkEnd::ProcessRoot,
                ..
            }
        ));
    }
}
