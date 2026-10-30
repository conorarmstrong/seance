//! Each process's open files, walked from `task_struct.files`.
//!
//! At parity with Volatility 3's `linux.lsof`. For every process the task walk
//! reached, this follows the file table — `files_struct` → `fdtable` → the `fd[]`
//! array of `struct file *` — and reports each open descriptor: its number, the
//! path of the file behind it, and its mode and flags.
//!
//! ## Scope, stated on the record
//!
//! Paths are reconstructed by [`crate::paths`]: the mount-crossing walk (the
//! kernel's `prepend_path`, Volatility's `do_get_path`) from each file's dentry
//! and `vfsmount` up to the process's own root (`task->fs->root`), so a file on
//! a non-root mount shows its absolute path as the process saw it. A record for
//! which that walk could not be made — the build declares no `f_path.mnt`, the
//! mount would not read — falls back to the reduced in-mount walk and carries
//! `path_scope: dentry_tree_relative` with the reason. Sockets, pipes and
//! anonymous inodes are decoded the way the kernel's `d_dname` renders them
//! (`socket:[inode]`, `pipe:[inode]`, `anon_inode:<name>`) and typed by
//! `path_kind`, never left as a raw dentry name that reads like a file.
//!
//! `mode` and `flags` are the raw `file.f_mode` / `file.f_flags` words, not
//! Volatility's inode-derived mode string, so the two are not directly
//! comparable; the survey states this (`mode_is_raw_f_mode`).

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::{Obj, StructReader};

use crate::error::StageError;
use crate::module::STAGE_LINUX_OPEN_FILES;
use crate::paths::{self, PathKind, PathResult, PathScope, ProcessRoot};
use crate::profile::LinuxProfile;
use crate::read::signed_to_json;
use crate::tasks::TaskList;

/// Volatility's own corruption bound on `max_fds`. A file table claiming more
/// open descriptors than this is corrupt, not busy.
pub const MAX_FDS_PER_TASK: u64 = 500_000;

/// Everything the open-files stage needs out of the symbol table.
pub const OPEN_FILES_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_OPEN_FILES,
    &[
        TypeSpec::new("file", &["file"]).required(
            "this kernel declares no open-file type, so no open file could be described at all",
        ),
        // Not required: without it the path is unavailable, not the stage dead.
        paths::TYPE_DENTRY,
        paths::TYPE_MOUNT_ENTRY,
        paths::TYPE_DENTRY_OPERATIONS,
        paths::TYPE_INODE,
    ],
    &[
        MemberSpec::new("files", &["task_struct"], &["files"]).required(
            "a task structure has no pointer to its open-file table, so no process's open files \
             could be reached",
        ),
        MemberSpec::new("fdt", &["files_struct"], &["fdt"]).required(
            "the file table has no descriptor table, so the array of open files could not be \
             located",
        ),
        MemberSpec::new("max_fds", &["fdtable"], &["max_fds"]).required(
            "the descriptor table declares no size, so the open-file array could not be bounded",
        ),
        MemberSpec::new("fd", &["fdtable"], &["fd"]).required(
            "the descriptor table has no pointer to the open-file array, so no open file could be \
             read",
        ),
        MemberSpec::new("f_mode", &["file"], &["f_mode"]),
        MemberSpec::new("f_flags", &["file"], &["f_flags"]),
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

/// Caps for one open-files survey.
#[derive(Debug, Clone)]
pub struct OpenFilesConfig {
    /// Most descriptors one task's table will be walked for.
    pub max_fds: u64,
}

impl Default for OpenFilesConfig {
    fn default() -> Self {
        Self {
            max_fds: MAX_FDS_PER_TASK,
        }
    }
}

/// Why a process contributed the descriptors it did — or none.
#[derive(Debug, Clone)]
pub enum FilesOutcome {
    /// The file table was walked. It may be empty (a process with no open
    /// descriptors), which is a genuine zero, not a gap.
    Walked,
    /// The task has no file table (`task_struct.files` is null): a kernel thread
    /// or a task past exit that dropped it. There was never anything to read —
    /// not a gap.
    NoFileTable,
    /// The file table exists but its bytes, its `fdt`, or the `fd` array base
    /// would not read. A gap.
    TableUnreadable(String),
    /// `max_fds` exceeds the corruption bound; no rows were emitted for the task.
    /// A gap, refused on the record rather than presented as a real fd list.
    CorruptFdTable {
        /// The nonsensical descriptor count the table claimed.
        max_fds: i64,
    },
}

impl FilesOutcome {
    fn is_a_gap(&self) -> bool {
        !matches!(self, FilesOutcome::Walked | FilesOutcome::NoFileTable)
    }

    fn class(&self) -> &'static str {
        match self {
            FilesOutcome::Walked => "walked",
            FilesOutcome::NoFileTable => "no_file_table",
            FilesOutcome::TableUnreadable(_) => "table_unreadable",
            FilesOutcome::CorruptFdTable { .. } => "corrupt_fd_table",
        }
    }

    fn detail(&self) -> String {
        match self {
            FilesOutcome::Walked => "the file table was walked".to_string(),
            FilesOutcome::NoFileTable => {
                "this task has no open-file table, so it never had open files to read".to_string()
            }
            FilesOutcome::TableUnreadable(detail) => detail.clone(),
            FilesOutcome::CorruptFdTable { max_fds } => format!(
                "the descriptor table claims {max_fds} open descriptors, past the corruption bound \
                 of {MAX_FDS_PER_TASK}; the table was not walked"
            ),
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

/// One open file descriptor.
#[derive(Debug, Clone)]
pub struct OpenFile {
    /// The descriptor number.
    pub fd: u64,
    /// Address of the `struct file`.
    pub file_address: u64,
    /// `file.f_mode`.
    pub f_mode: Field<u64>,
    /// `file.f_flags`.
    pub f_flags: Field<u64>,
    /// The path of the file, or the reason there is none.
    pub path: Field<String>,
    /// Whether every path component was valid UTF-8.
    pub path_well_formed: bool,
    /// Whether the path walk was cut short.
    pub path_truncated: bool,
    /// Which walk produced the path, and how it ended.
    pub path_scope: PathScope,
    /// What the path names: a file, or a socket / pipe / anonymous inode.
    pub path_kind: PathKind,
    /// Anything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl OpenFile {
    /// The names of the fields that exist on this build and could not be read.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, unavailable) in [
            ("path", self.path.is_unavailable()),
            ("f_mode", self.f_mode.is_unavailable()),
            ("f_flags", self.f_flags.is_unavailable()),
        ] {
            if unavailable {
                out.push(name);
            }
        }
        out
    }

    fn path_result(&self) -> PathResult {
        PathResult {
            path: self.path.clone(),
            well_formed: self.path_well_formed,
            truncated: self.path_truncated,
            scope: self.path_scope.clone(),
            kind: self.path_kind.clone(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "fd": self.fd,
            "file_address": self.file_address,
            "file_address_hex": format!("{:#x}", self.file_address),
            "f_mode": self.f_mode.to_json(),
            "f_flags": self.f_flags.to_json(),
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        });
        self.path_result().stamp(&mut value);
        value
    }
}

/// One process's open files.
#[derive(Debug, Clone)]
pub struct ProcessFiles {
    /// Address of the `task_struct`.
    pub task_address: u64,
    /// The process id.
    pub pid: Field<i64>,
    /// The parent process id.
    pub ppid: Field<i64>,
    /// The process name.
    pub comm: Field<String>,
    /// The open descriptors, in fd order.
    pub files: Vec<OpenFile>,
    /// Why these descriptors (or none).
    pub outcome: FilesOutcome,
    /// A note if the fd loop stopped early (e.g. address overflow).
    pub loop_note: Option<String>,
    /// The process's root directory as `task->fs->root` named it, or why it
    /// could not be established. Paths below were walked up to it.
    pub root: ProcessRoot,
}

impl ProcessFiles {
    fn is_a_gap(&self) -> bool {
        self.outcome.is_a_gap()
            || self.loop_note.is_some()
            || self
                .files
                .iter()
                .any(|file| !file.unreadable_fields().is_empty())
    }

    fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.outcome.is_a_gap() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the process at the task_struct at {:#x} has no readable open-file table: {}",
                    self.task_address,
                    self.outcome.detail()
                ),
            ));
        }
        if let Some(note) = &self.loop_note {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the fd walk for the task_struct at {:#x} stopped early: {note}",
                    self.task_address
                ),
            ));
        }
        for file in &self.files {
            let unreadable = file.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "fd {} of the task_struct at {:#x} has field(s) that exist on this build \
                         and could not be read: {}",
                        file.fd,
                        self.task_address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task_address": self.task_address,
            "task_address_hex": format!("{:#x}", self.task_address),
            "pid": signed_to_json(&self.pid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "open_file_count": self.files.len(),
            "files": self.files.iter().map(OpenFile::to_json).collect::<Vec<_>>(),
            "outcome": self.outcome.to_json(),
            "loop_note": self.loop_note,
            "root": root_json(&self.root),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// A process root's wire form, shared with the maps and mount stages.
pub fn root_json(root: &ProcessRoot) -> serde_json::Value {
    match root {
        ProcessRoot::Known { dentry, vfsmnt } => serde_json::json!({
            "class": "known",
            "dentry_hex": format!("{dentry:#x}"),
            "vfsmount_hex": format!("{vfsmnt:#x}"),
        }),
        ProcessRoot::NoFs => serde_json::json!({
            "class": "no_fs_struct",
            "detail": "the task has no fs_struct, so it has no root directory of its own; paths \
                       are relative to the global root",
        }),
        ProcessRoot::NotDeclared(member) => serde_json::json!({
            "class": "not_declared",
            "member": member,
            "detail": format!("this build declares no {member}, so the process root could not be \
                               read; paths are relative to the global root"),
        }),
        ProcessRoot::Unavailable(detail) => serde_json::json!({
            "class": "unavailable",
            "detail": detail,
        }),
    }
}

/// Every process's open files, and everything that qualifies the list.
#[derive(Debug, Clone)]
pub struct OpenFilesSurvey {
    /// One entry per process the task walk reached.
    pub processes: Vec<ProcessFiles>,
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

impl OpenFilesSurvey {
    /// The number of processes surveyed.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Total open descriptors across every process.
    pub fn open_file_count(&self) -> usize {
        self.processes.iter().map(|p| p.files.len()).sum()
    }

    /// Whether the walk finished and every process's file table was fully read.
    pub fn is_complete(&self) -> bool {
        self.task_complete && !self.processes.iter().any(ProcessFiles::is_a_gap)
    }

    /// Everything a report must declare.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.task_incomplete.clone();
        for process in &self.processes {
            out.extend(process.incomplete());
        }
        out
    }

    /// Serializable form for the open-files artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process_count": self.process_count(),
            "open_file_count": self.open_file_count(),
            "complete": self.is_complete(),
            "path_scope": self.path_scope,
            "path_scope_note": self.path_scope_note,
            "path_scope_is_per_record": true,
            // Which pseudo-files are rendered the way the kernel renders them;
            // any other `d_dname` is reported by name on the row, not decoded.
            "pseudo_paths_decoded": ["socket", "pipe", "anon_inode"],
            // Stated so `mode`/`flags` are not equated with Volatility's
            // inode-derived mode column.
            "mode_is_raw_f_mode": true,
            "processes": self.processes.iter().map(ProcessFiles::to_json).collect::<Vec<_>>(),
            "layout": self.layout,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Bind the open-files stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(OPEN_FILES_LAYOUT.bind(&reader)?)
}

/// Walk every process's open files.
///
/// # Errors
///
/// Only when the stage could not run at all — a required type or member is
/// absent (binding refused), or the pointer size could not be established. A
/// process whose file table could not be read is a [`ProcessFiles`] whose
/// outcome says why, not an error.
pub fn survey_open_files(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &OpenFilesConfig,
) -> Result<OpenFilesSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    survey_with_reader(&reader, layout, tasks, config)
}

/// The walk itself, over a reader the caller supplies. Split from
/// [`survey_open_files`] so it can be driven over a synthetic image in a test.
fn survey_with_reader(
    reader: &StructReader,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &OpenFilesConfig,
) -> Result<OpenFilesSurvey, StageError> {
    let task_type = layout
        .member("files")?
        .type_name()
        .expect("a required member is declared or binding refused the stage");
    let file_type = layout
        .type_of("file")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let pointer_size = u64::from(reader.pointer_size()?);

    let mut processes = Vec::with_capacity(tasks.tasks.len());
    for task in &tasks.tasks {
        let task_obj = match reader.object(task.address, task_type) {
            Ok(obj) => obj,
            Err(err) => {
                processes.push(ProcessFiles {
                    task_address: task.address,
                    pid: task.pid.clone(),
                    ppid: task.ppid.clone(),
                    comm: task.comm.clone(),
                    files: Vec::new(),
                    outcome: FilesOutcome::TableUnreadable(format!(
                        "the task_struct could not be reopened to read its file table: {err}"
                    )),
                    loop_note: None,
                    root: ProcessRoot::Unavailable(
                        "the task_struct could not be reopened".to_string(),
                    ),
                });
                continue;
            }
        };

        let root = paths::process_root(layout, &task_obj)?;
        let (outcome, files, loop_note) = walk_one(
            reader,
            layout,
            &task_obj,
            file_type,
            pointer_size,
            config.max_fds,
            &root,
        )?;
        processes.push(ProcessFiles {
            task_address: task.address,
            pid: task.pid.clone(),
            ppid: task.ppid.clone(),
            comm: task.comm.clone(),
            files,
            outcome,
            loop_note,
            root,
        });
    }

    let (path_scope, path_scope_note) = paths::survey_scope(layout);
    Ok(OpenFilesSurvey {
        processes,
        layout: layout.to_json(),
        path_scope,
        path_scope_note,
        task_complete: tasks.is_complete(),
        task_incomplete: tasks.incomplete(),
    })
}

/// Walk one process's file table.
#[allow(clippy::too_many_arguments)]
fn walk_one(
    reader: &StructReader,
    layout: &BuildBinding,
    task_obj: &Obj,
    file_type: &'static str,
    pointer_size: u64,
    max_fds_cap: u64,
    root: &ProcessRoot,
) -> Result<(FilesOutcome, Vec<OpenFile>, Option<String>), StageError> {
    use crate::fdtable::{walk_fd_table, FdSlot, FdTableOutcome};

    // Every descriptor becomes a row: an open file read in full, or a per-row
    // gap for a slot whose pointer would not read (never a reason to abandon the
    // rest of the table).
    let mut files_out: Vec<OpenFile> = Vec::new();
    let (outcome, loop_note) = walk_fd_table(
        reader,
        layout,
        task_obj,
        pointer_size,
        max_fds_cap,
        |slot| {
            match slot {
                FdSlot::Open { fd, filp } => {
                    files_out.push(read_open_file(reader, layout, file_type, fd, filp, root)?);
                }
                FdSlot::Unreadable { fd, slot, err } => {
                    files_out.push(unread_file(
                        fd,
                        0,
                        format!("the fd-array slot at {slot:#x} could not be read: {err}"),
                    ));
                }
            }
            Ok(())
        },
    )?;

    let outcome = match outcome {
        FdTableOutcome::Walked => FilesOutcome::Walked,
        FdTableOutcome::NoFileTable => FilesOutcome::NoFileTable,
        FdTableOutcome::Unreadable(detail) => FilesOutcome::TableUnreadable(detail),
        FdTableOutcome::Corrupt { max_fds } => FilesOutcome::CorruptFdTable { max_fds },
    };
    Ok((outcome, files_out, loop_note))
}

/// A row for a descriptor whose `struct file` was never read.
fn unread_file(fd: u64, file_address: u64, detail: String) -> OpenFile {
    let path = PathResult::unavailable(detail);
    OpenFile {
        fd,
        file_address,
        f_mode: Field::Unavailable("not read".into()),
        f_flags: Field::Unavailable("not read".into()),
        path: path.path,
        path_well_formed: path.well_formed,
        path_truncated: path.truncated,
        path_scope: path.scope,
        path_kind: path.kind,
        notes: Vec::new(),
    }
}

/// Read one open `struct file` into a descriptor row.
fn read_open_file(
    reader: &StructReader,
    layout: &BuildBinding,
    file_type: &'static str,
    fd: u64,
    filp: u64,
    root: &ProcessRoot,
) -> Result<OpenFile, StageError> {
    let file_obj = match reader.object(filp, file_type) {
        Ok(obj) => obj,
        Err(err) => {
            return Ok(unread_file(
                fd,
                filp,
                crate::read::unreadable_detail("the open file", filp, &err),
            ))
        }
    };

    let f_mode = layout.read_unsigned(&file_obj, "f_mode")?;
    let f_flags = layout.read_unsigned(&file_obj, "f_flags")?;
    let PathResult {
        path,
        well_formed,
        truncated,
        scope,
        kind,
    } = paths::path_for_file(reader, layout, &file_obj, root);

    Ok(OpenFile {
        fd,
        file_address: filp,
        f_mode,
        f_flags,
        path,
        path_well_formed: well_formed,
        path_truncated: truncated,
        path_scope: scope,
        path_kind: kind,
        notes: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(fd: u64, path: Field<String>) -> OpenFile {
        OpenFile {
            fd,
            file_address: 0xFFFF_8800_0000_0000 + fd,
            f_mode: Field::Known(0x1d),
            f_flags: Field::Known(0o2),
            path,
            path_well_formed: true,
            path_truncated: false,
            path_scope: PathScope::MountRelative("test".into()),
            path_kind: PathKind::File,
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_null_file_table_is_not_a_gap_but_an_unreadable_one_is() {
        let kthread = ProcessFiles {
            task_address: 0x1000,
            pid: Field::Known(2),
            ppid: Field::Known(0),
            comm: Field::Known("kthreadd".into()),
            files: Vec::new(),
            outcome: FilesOutcome::NoFileTable,
            loop_note: None,
            root: ProcessRoot::NoFs,
        };
        assert!(!kthread.is_a_gap());
        assert!(!kthread.outcome.is_a_gap());

        let broken = ProcessFiles {
            outcome: FilesOutcome::TableUnreadable("fdt would not read".into()),
            ..kthread.clone()
        };
        assert!(broken.is_a_gap());
    }

    #[test]
    fn a_corrupt_fd_count_is_refused_on_the_record_not_walked() {
        let corrupt = ProcessFiles {
            task_address: 0x2000,
            pid: Field::Known(100),
            ppid: Field::Known(1),
            comm: Field::Known("evil".into()),
            files: Vec::new(),
            outcome: FilesOutcome::CorruptFdTable { max_fds: 9_000_000 },
            loop_note: None,
            root: ProcessRoot::NoFs,
        };
        assert!(corrupt.is_a_gap());
        let json = corrupt.to_json();
        assert_eq!(json["outcome"]["class"], "corrupt_fd_table");
        assert!(json["outcome"]["detail"]
            .as_str()
            .unwrap()
            .contains("corruption bound"));
        assert_eq!(json["open_file_count"], 0);
    }

    #[test]
    fn an_absent_mode_member_is_not_read_as_zero() {
        let mut f = file(3, Field::Known("/etc/passwd".into()));
        f.f_mode = Field::NotDeclared { member: "f_mode" };
        let json = f.to_json();
        assert_eq!(json["f_mode"]["kind"], "not_declared");
        assert!(json["f_mode"].get("value").is_none());
        // NotDeclared is not an unreadable field.
        assert!(f.unreadable_fields().is_empty());
    }

    #[test]
    fn an_unreadable_path_is_a_named_gap() {
        let f = file(
            4,
            Field::Unavailable("the dentry page was not acquired".into()),
        );
        assert_eq!(f.unreadable_fields(), vec!["path"]);
    }

    #[test]
    fn the_survey_states_its_path_and_mode_scope() {
        let survey = OpenFilesSurvey {
            processes: Vec::new(),
            layout: serde_json::json!({}),
            path_scope: paths::PATH_SCOPE,
            path_scope_note: paths::PATH_SCOPE_NOTE,
            task_complete: true,
            task_incomplete: Vec::new(),
        };
        let json = survey.to_json();
        assert_eq!(
            json["pseudo_paths_decoded"],
            serde_json::json!(["socket", "pipe", "anon_inode"])
        );
        assert_eq!(json["mode_is_raw_f_mode"], true);
        assert_eq!(json["path_scope"], "dentry_tree_relative");
        assert_eq!(json["path_scope_is_per_record"], true);
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

    pub(super) const TASK: u64 = 0x1000;
    const FILES: u64 = 0x2000;
    const FDT: u64 = 0x2400;
    const FD_ARRAY: u64 = 0x2500; // three slots: 0=stdin file, 1=null, 2=passwd file
    const FILE0: u64 = 0x3000;
    const FILE2: u64 = 0x3200;
    const DENTRY_NULL: u64 = 0x4000; // "null" under /dev
    const DENTRY_DEV: u64 = 0x4200;
    const DENTRY_PASSWD: u64 = 0x4400; // "passwd" under /etc
    const DENTRY_ETC: u64 = 0x4600;
    const DENTRY_ROOT: u64 = 0x4800;
    const NAME_NULL: u64 = 0x5000;
    const NAME_DEV: u64 = 0x5040;
    const NAME_PASSWD: u64 = 0x5080;
    const NAME_ETC: u64 = 0x50C0;

    const FIXTURE_ISF: &str = r#"{
      "metadata": {"format":"6.2.0","producer":{"name":"seance-lsof-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
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
          "mnt":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
          "dentry":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}}
        }},
        "dentry": {"size":192,"kind":"struct","fields":{
          "d_parent":{"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}},
          "d_name":{"offset":32,"type":{"kind":"struct","name":"qstr"}},
          "d_iname":{"offset":56,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}}
        }},
        "file": {"size":208,"kind":"struct","fields":{
          "f_path":{"offset":16,"type":{"kind":"struct","name":"path"}},
          "f_flags":{"offset":56,"type":{"kind":"base","name":"unsigned int"}},
          "f_mode":{"offset":60,"type":{"kind":"base","name":"unsigned int"}}
        }},
        "fdtable": {"size":56,"kind":"struct","fields":{
          "max_fds":{"offset":0,"type":{"kind":"base","name":"unsigned int"}},
          "fd":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"pointer","subtype":{"kind":"struct","name":"file"}}}}
        }},
        "files_struct": {"size":704,"kind":"struct","fields":{
          "fdt":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"fdtable"}}}
        }},
        "task_struct": {"size":1784,"kind":"struct","fields":{
          "files":{"offset":1152,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"files_struct"}}}
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
        /// A dentry with a name and a parent.
        fn put_dentry(&mut self, at: u64, parent: u64, name_ptr: u64, len: u32, inline: &[u8]) {
            self.put_u64(at + 24, parent);
            self.put_u32(at + 36, len);
            self.put_u64(at + 40, name_ptr);
            self.put(at + 56, inline);
        }
    }

    pub(super) fn reader() -> StructReader {
        let mut image = Image::new();

        image.put_u64(TASK + 1152, FILES); // task.files
        image.put_u64(FILES + 8, FDT); // files.fdt
        image.put_u32(FDT, 3); // fdt.max_fds = 3
        image.put_u64(FDT + 8, FD_ARRAY); // fdt.fd -> array

        // fd[0] -> FILE0 (/dev/null), fd[1] -> NULL (closed), fd[2] -> FILE2 (/etc/passwd).
        image.put_u64(FD_ARRAY, FILE0);
        image.put_u64(FD_ARRAY + 8, 0);
        image.put_u64(FD_ARRAY + 16, FILE2);

        // FILE0: /dev/null, read-write.
        image.put_u64(FILE0 + 24, DENTRY_NULL); // f_path.dentry (file+16+8)
        image.put_u32(FILE0 + 56, 0o2); // f_flags
        image.put_u32(FILE0 + 60, 0x1d); // f_mode
                                         // FILE2: /etc/passwd, read-only.
        image.put_u64(FILE2 + 24, DENTRY_PASSWD);
        image.put_u32(FILE2 + 56, 0);
        image.put_u32(FILE2 + 60, 0x1);

        image.put_dentry(DENTRY_NULL, DENTRY_DEV, NAME_NULL, 4, b"null\0");
        image.put_dentry(DENTRY_DEV, DENTRY_ROOT, NAME_DEV, 3, b"dev\0");
        image.put_dentry(DENTRY_PASSWD, DENTRY_ETC, NAME_PASSWD, 6, b"passwd\0");
        image.put_dentry(DENTRY_ETC, DENTRY_ROOT, NAME_ETC, 3, b"etc\0");
        // Root: parent is itself.
        image.put_u64(DENTRY_ROOT + 24, DENTRY_ROOT);

        image.put(NAME_NULL, b"null\0");
        image.put(NAME_DEV, b"dev\0");
        image.put(NAME_PASSWD, b"passwd\0");
        image.put(NAME_ETC, b"etc\0");

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

    pub(super) fn one_task_list(task_address: u64) -> TaskList {
        let mut task = TaskRecord::address_only_for_test(task_address);
        task.pid = Field::Known(1234);
        task.ppid = Field::Known(1);
        task.comm = Field::Known("cat".into());
        TaskList {
            init_task: 0,
            head: 0,
            links_offset: 0,
            tasks: vec![task],
            stop: ListStop::Wrapped,
            layout: serde_json::json!({}),
        }
    }

    #[test]
    fn the_walk_lists_open_files_skips_the_closed_slot_and_reconstructs_paths() {
        let reader = reader();
        let layout = OPEN_FILES_LAYOUT.bind(&reader).expect("the fixture binds");
        let tasks = one_task_list(TASK);

        let survey =
            super::survey_with_reader(&reader, &layout, &tasks, &OpenFilesConfig::default())
                .expect("the survey runs");

        assert_eq!(survey.process_count(), 1);
        // Two open descriptors; the null slot at fd 1 is closed and skipped.
        assert_eq!(survey.open_file_count(), 2);

        let process = &survey.processes[0];
        assert!(matches!(process.outcome, FilesOutcome::Walked));
        assert_eq!(process.files.len(), 2);

        let fd0 = &process.files[0];
        assert_eq!(fd0.fd, 0);
        assert_eq!(fd0.path.known().map(String::as_str), Some("/dev/null"));
        assert_eq!(fd0.f_mode.known(), Some(&0x1d));

        let fd2 = &process.files[1];
        assert_eq!(fd2.fd, 2, "the closed fd 1 is skipped, not renumbered");
        assert_eq!(fd2.path.known().map(String::as_str), Some("/etc/passwd"));

        assert!(!process.is_a_gap());
        assert!(survey.to_json()["complete"] == true || !tasks.is_complete());
    }

    #[test]
    fn a_kernel_thread_with_no_file_table_is_not_a_gap() {
        let reader = reader();
        let layout = OPEN_FILES_LAYOUT.bind(&reader).expect("binds");
        // A task whose files pointer reads 0.
        let tasks = one_task_list(0x1500);

        let survey =
            super::survey_with_reader(&reader, &layout, &tasks, &OpenFilesConfig::default())
                .expect("runs");
        let process = &survey.processes[0];
        assert!(matches!(process.outcome, FilesOutcome::NoFileTable));
        assert!(process.files.is_empty());
        assert!(!process.is_a_gap());
    }

    #[test]
    fn a_corrupt_max_fds_is_refused_without_walking() {
        let mut image = Image::new();
        image.put_u64(TASK + 1152, FILES);
        image.put_u64(FILES + 8, FDT);
        image.put_u32(FDT, 4_000_000); // past the corruption bound
        image.put_u64(FDT + 8, FD_ARRAY);
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(image.bytes));
        let layer: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).expect("image"));
        let symbols = Arc::new(
            SymbolTable::compile_source(
                seance_symbols::load_slice(FIXTURE_ISF.as_bytes(), &DecompressLimits::default())
                    .unwrap(),
                &CompileOptions::default(),
            )
            .unwrap(),
        );
        let reader = StructReader::new(layer, symbols);
        let layout = OPEN_FILES_LAYOUT.bind(&reader).expect("binds");
        let tasks = one_task_list(TASK);

        let survey =
            super::survey_with_reader(&reader, &layout, &tasks, &OpenFilesConfig::default())
                .expect("runs");
        let process = &survey.processes[0];
        assert!(matches!(
            process.outcome,
            FilesOutcome::CorruptFdTable { .. }
        ));
        assert!(process.files.is_empty(), "a corrupt table is not walked");
        assert!(process.is_a_gap());
    }
}

#[cfg(test)]
mod record_shape_tests {
    //! The wire shape a record carries about its path, over the same fixture
    //! as the walk tests: a build with no mount chain at all, so every path
    //! must say it is mount-relative and why, rather than look absolute.
    use super::*;

    #[test]
    fn a_record_on_a_build_with_no_mount_chain_says_its_path_is_mount_relative() {
        let reader = walk_tests::reader();
        let layout = OPEN_FILES_LAYOUT.bind(&reader).expect("binds");
        assert!(!paths::mount_crossing_bound(&layout));
        let tasks = walk_tests::one_task_list(walk_tests::TASK);
        let survey =
            super::survey_with_reader(&reader, &layout, &tasks, &OpenFilesConfig::default())
                .expect("runs");
        let json = survey.to_json();
        assert_eq!(json["path_scope"], paths::PATH_SCOPE);
        let file = &json["processes"][0]["files"][0];
        assert_eq!(file["path"]["value"], "/dev/null");
        assert_eq!(file["path_scope"], "dentry_tree_relative");
        assert!(file["path_scope_detail"]
            .as_str()
            .unwrap()
            .contains("f_path.mnt"));
        assert_eq!(file["path_kind"], "file");
        assert_eq!(
            json["processes"][0]["root"]["class"], "not_declared",
            "the fixture's task_struct has no fs member"
        );
    }
}
