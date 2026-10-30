//! Each process's command line, read from its own address space.
//!
//! The kernel keeps no copy of a process's arguments. It keeps two addresses —
//! `mm_struct.arg_start` and `mm_struct.arg_end` — bracketing the run of
//! NUL-terminated argument strings the loader placed near the top of the stack,
//! in the process's *own* memory. So, like the environment stage, every row here
//! required opening that process's page tables: the bracket is read through the
//! process's `pgd`, never from the kernel address space.
//!
//! ## What is and is not claimed
//!
//! * **A kernel thread has no command line**, because it has no user address
//!   space. That is a fact about the machine, recorded on the row and excluded
//!   from the stage's incompleteness. `ps` shows such a task as `[comm]`; this
//!   stage shows `comm` and says why there is no command line, rather than
//!   inventing the brackets.
//! * **A process whose argument pages were not captured** has a command line
//!   this image cannot show. That is a gap and is recorded as one. When only
//!   part of the bracket was captured, the arguments in the run from
//!   `arg_start` are reported with `argv_short_read` and the number of bytes
//!   missing; a run cut mid-argument by a missing page is a fragment
//!   (`last_argument_cut`), never evidence that the process rewrote its
//!   arguments.
//! * **A process that rewrote its own argument area** (`setproctitle`, the way
//!   `sshd` and `postgres` label themselves) leaves a bracket whose last byte is
//!   not a NUL. The kernel's `/proc/<pid>/cmdline` then reads on past `arg_end`
//!   into the environment area; this stage reports the bracket as the kernel
//!   recorded it, flags the row `argv_rewritten`, and does not read on — what
//!   lies past the bracket is the environment stage's to report as environment.
//! * **The bracket is read verbatim.** Arguments are split at NUL; an empty
//!   argument in the middle is kept, because `cmd ""` is a real command line;
//!   only the terminator's trailing empty string is dropped.

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::Obj;

use crate::error::StageError;
use crate::module::STAGE_LINUX_COMMAND_LINES;
use crate::profile::LinuxProfile;
use crate::read::signed_to_json;
use crate::space::{self, SpaceRefusal};
use crate::tasks::{TaskInventory, TaskList, TaskRecord};

/// Largest argument bracket this stage will read for one process.
///
/// Volatility's `linux.psaux` refuses the same span. A process's arguments are a
/// few hundred bytes; `MAX_ARG_STRLEN` lets a single argument reach 128 KiB, but
/// a declared bracket past this bound is far more often a process that has
/// rewritten `arg_start`/`arg_end` (or a smeared descriptor) than a genuine
/// command line, and reading it would put unrelated stack into the record as
/// arguments. A refused bracket is reported with the number it hit.
pub const MAX_COMMAND_LINE_BYTES: u64 = 4096;

/// Everything the command-line stage needs out of the symbol table.
pub const COMMAND_LINES_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_COMMAND_LINES,
    &[TypeSpec::new("mm", &["mm_struct"]).required(
        "a process's memory descriptor cannot be located, so no process's own address space can \
         be opened and no command line can be read for any process on the machine",
    )],
    &[
        MemberSpec::new("mm", &["task_struct"], &["mm"]).required(
            "a task carries no pointer to its memory descriptor, so no process's own address \
             space can be reached",
        ),
        MemberSpec::new("pgd", &["mm_struct"], &["pgd"]).required(
            "a process's page-table root cannot be found, so its own address space cannot be \
             opened and the argument area cannot be read",
        ),
        MemberSpec::new("arg_start", &["mm_struct"], &["arg_start"]).required(
            "the kernel records no start for the argument area, so there is no range to read and \
             an empty result would read as a machine whose processes had no arguments",
        ),
        MemberSpec::new("arg_end", &["mm_struct"], &["arg_end"]).required(
            "the kernel records no end for the argument area, so the range to read has no length",
        ),
    ],
);

/// Caps for one command-line survey.
#[derive(Debug, Clone)]
pub struct CommandLinesConfig {
    /// Largest argument bracket read for one process.
    pub max_bytes: u64,
}

impl Default for CommandLinesConfig {
    fn default() -> Self {
        Self {
            max_bytes: MAX_COMMAND_LINE_BYTES,
        }
    }
}

/// One process's arguments, as the bracket held them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    /// The arguments, `argv[0]` first, split at NUL.
    pub arguments: Vec<String>,
    /// Whether every byte of the bracket was valid UTF-8. `false` means bytes
    /// were replaced to render it and an argument in the image differed.
    pub well_formed: bool,
    /// Whether the bracket's last byte was not a NUL — the mark of a process
    /// that rewrote its argument area after starting (`setproctitle`). The
    /// arguments are then what remains of that rewrite, not what the process
    /// was started with. `None` when the bracket's last byte was not read
    /// (`argv_short_read`): the question cannot be answered from this image,
    /// and a missing page is never reported as a rewrite.
    pub argv_rewritten: Option<bool>,
    /// Whether the acquisition holds less than the whole bracket, so the
    /// arguments are those in the run that begins at `arg_start` and nothing
    /// is claimed about the rest.
    pub argv_short_read: bool,
    /// Bytes of the bracket that were not read. Zero unless `argv_short_read`.
    pub bytes_missing: u64,
    /// Whether the last argument listed ends where the acquired run ends
    /// rather than at a NUL, so it is a fragment cut by the missing page.
    /// Only ever `true` on a short read.
    pub last_argument_cut: bool,
}

impl CommandLine {
    /// The arguments joined with single spaces, the way `ps` prints them.
    pub fn text(&self) -> String {
        self.arguments.join(" ")
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "text": self.text(),
            "arguments": self.arguments,
            "argument_count": self.arguments.len(),
            "well_formed": self.well_formed,
            "argv_rewritten": self.argv_rewritten,
            "argv_short_read": self.argv_short_read,
            "bytes_missing": self.bytes_missing,
            "last_argument_cut": self.last_argument_cut,
        })
    }
}

/// What happened when this stage looked at one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdlineOutcome {
    /// The bracket was read end to end.
    Read,
    /// The bracket was not read. The refusal says why, and whether that is a
    /// gap; a kernel thread is the one refusal that is not.
    NotRead(SpaceRefusal),
    /// The kernel records a bracket of no length. Nothing was missed: this
    /// process's argument area really is empty as the kernel describes it.
    Empty,
    /// The declared bracket is larger than this stage will read.
    OverSized {
        /// The declared length.
        bytes: u64,
        /// The cap that refused it.
        cap: u64,
    },
    /// The bracket's bounds could not be read from the memory descriptor.
    BoundsUnavailable(String),
    /// Part of the bracket was not captured by the acquisition; the arguments
    /// reported are those in the run that begins at `arg_start`, and the
    /// command line carries `argv_short_read` with the byte count missing.
    Partial {
        /// Bytes read.
        read: u64,
        /// Bytes that could not be read.
        unread: u64,
    },
}

impl CmdlineOutcome {
    /// Whether this outcome means evidence is missing, as opposed to there
    /// being none to miss.
    pub fn is_a_gap(&self) -> bool {
        match self {
            CmdlineOutcome::Read | CmdlineOutcome::Empty => false,
            CmdlineOutcome::NotRead(refusal) => refusal.is_a_gap(),
            CmdlineOutcome::OverSized { .. }
            | CmdlineOutcome::BoundsUnavailable(_)
            | CmdlineOutcome::Partial { .. } => true,
        }
    }

    /// Stable machine-readable class.
    pub fn class(&self) -> &'static str {
        match self {
            CmdlineOutcome::Read => "read",
            CmdlineOutcome::NotRead(_) => "not_read",
            CmdlineOutcome::Empty => "empty",
            CmdlineOutcome::OverSized { .. } => "over_sized",
            CmdlineOutcome::BoundsUnavailable(_) => "bounds_unavailable",
            CmdlineOutcome::Partial { .. } => "partial",
        }
    }

    /// One sentence an examiner reads.
    pub fn detail(&self) -> String {
        match self {
            CmdlineOutcome::Read => "the argument area was read end to end".to_string(),
            CmdlineOutcome::NotRead(refusal) => refusal.detail(),
            CmdlineOutcome::Empty => {
                "the kernel records an argument area of no length for this process".to_string()
            }
            CmdlineOutcome::OverSized { bytes, cap } => format!(
                "the kernel records an argument area of {bytes} bytes, above this stage's cap of \
                 {cap}; a span that large is not a command line, so it was not read as one"
            ),
            CmdlineOutcome::BoundsUnavailable(detail) => format!(
                "the argument area's bounds could not be read from this process's memory \
                 descriptor: {detail}"
            ),
            CmdlineOutcome::Partial { read, unread } => format!(
                "{read} byte(s) of the argument area were read and {unread} were not captured by \
                 the acquisition, so the arguments below are a floor and whether the process \
                 rewrote its argument area cannot be told"
            ),
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "class": self.class(),
            "detail": self.detail(),
            "is_a_gap": self.is_a_gap(),
        })
    }
}

/// One process's command line, and what the stage could establish about it.
#[derive(Debug, Clone)]
pub struct ProcessCommandLine {
    /// Address of the `task_struct`.
    pub task_address: u64,
    /// The process id, as the task list read it.
    pub pid: Field<i64>,
    /// The parent's process id.
    pub ppid: Field<i64>,
    /// The process name.
    pub comm: Field<String>,
    /// The command line, when the bracket was read.
    pub command_line: Option<CommandLine>,
    /// What happened.
    pub outcome: CmdlineOutcome,
}

impl ProcessCommandLine {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task_address": self.task_address,
            "task_address_hex": format!("{:#x}", self.task_address),
            "pid": signed_to_json(&self.pid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "command_line": self.command_line.as_ref().map(CommandLine::to_json),
            "outcome": self.outcome.to_json(),
        })
    }
}

/// Every process's command line, and everything the stage could not establish.
#[derive(Debug, Clone)]
pub struct CommandLinesSurvey {
    /// One entry per process on the list the stage was handed, including the
    /// ones with nothing to read.
    pub processes: Vec<ProcessCommandLine>,
    /// How complete the list the stage walked was.
    pub inventory: TaskInventory,
    /// Which structure layout produced these figures.
    pub layout: serde_json::Value,
}

impl CommandLinesSurvey {
    /// Processes whose bracket was read (in full or in part).
    pub fn read_count(&self) -> usize {
        self.processes
            .iter()
            .filter(|p| p.command_line.is_some())
            .count()
    }

    /// Whether every process on the list was examined and nothing was missed.
    pub fn is_complete(&self) -> bool {
        self.inventory.is_complete() && !self.processes.iter().any(|p| p.outcome.is_a_gap())
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        for process in &self.processes {
            if !process.outcome.is_a_gap() {
                continue;
            }
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the command line of the process at {:#x} could not be established in full: {}",
                    process.task_address,
                    process.outcome.detail()
                ),
            ));
        }
        out
    }

    /// Serializable form for the command-line artifact.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "process_count": self.processes.len(),
            "read_count": self.read_count(),
            "complete": self.is_complete(),
            "max_bytes_per_process": MAX_COMMAND_LINE_BYTES,
            "layout": self.layout,
            "processes": self
                .processes
                .iter()
                .map(ProcessCommandLine::to_json)
                .collect::<Vec<_>>(),
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        });
        self.inventory.stamp(&mut value);
        value
    }
}

/// Bind the command-line stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(COMMAND_LINES_LAYOUT.bind(&reader)?)
}

/// Read every process's command line.
///
/// # Errors
///
/// Only for a lookup the stage never declared, which is a programming error.
/// Every way a real process can fail to yield a command line is a variant on
/// its row.
pub fn survey_command_lines(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &CommandLinesConfig,
) -> Result<CommandLinesSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    let task_type = layout
        .member("mm")?
        .type_name()
        .expect("a required member is declared or binding refused the stage");

    let mut processes = Vec::with_capacity(tasks.tasks.len());
    for task in &tasks.tasks {
        let obj = match reader.object(task.address, task_type) {
            Ok(obj) => obj,
            Err(err) => {
                processes.push(row(
                    task,
                    None,
                    CmdlineOutcome::NotRead(SpaceRefusal::Unreadable(err.to_string())),
                ));
                continue;
            }
        };
        let (command_line, outcome) = read_command_line(profile, layout, &obj, config)?;
        processes.push(row(task, command_line, outcome));
    }

    Ok(CommandLinesSurvey {
        processes,
        layout: layout.to_json(),
        inventory: tasks.inventory(),
    })
}

fn row(
    task: &TaskRecord,
    command_line: Option<CommandLine>,
    outcome: CmdlineOutcome,
) -> ProcessCommandLine {
    ProcessCommandLine {
        task_address: task.address,
        pid: task.pid.clone(),
        ppid: task.ppid.clone(),
        comm: task.comm.clone(),
        command_line,
        outcome,
    }
}

/// Read one process's argument bracket.
fn read_command_line(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    task: &Obj,
    config: &CommandLinesConfig,
) -> Result<(Option<CommandLine>, CmdlineOutcome), StageError> {
    let mm = match space::memory_descriptor(layout, task, "mm")? {
        Ok(mm) => mm,
        Err(refusal) => return Ok((None, CmdlineOutcome::NotRead(refusal))),
    };

    let bound = |key: &'static str| -> Result<Result<u64, CmdlineOutcome>, StageError> {
        Ok(match layout.read_unsigned(&mm, key)? {
            Field::Known(value) => Ok(value),
            // The members are declared `required`, so this cannot arise from
            // binding; it is kept as a stated gap rather than an expect().
            Field::NotDeclared { member } => Err(CmdlineOutcome::BoundsUnavailable(format!(
                "this build declares no {member}"
            ))),
            Field::NotApplicable => Err(CmdlineOutcome::Empty),
            Field::Unavailable(detail) => Err(CmdlineOutcome::BoundsUnavailable(detail)),
        })
    };
    let start = match bound("arg_start")? {
        Ok(value) => value,
        Err(outcome) => return Ok((None, outcome)),
    };
    let end = match bound("arg_end")? {
        Ok(value) => value,
        Err(outcome) => return Ok((None, outcome)),
    };

    let Some(length) = end.checked_sub(start) else {
        return Ok((
            None,
            CmdlineOutcome::BoundsUnavailable(format!(
                "the kernel records an argument area ending at {end:#x}, below its start at \
                 {start:#x}, so it does not describe a range"
            )),
        ));
    };
    if length == 0 {
        return Ok((None, CmdlineOutcome::Empty));
    }
    if length > config.max_bytes {
        return Ok((
            None,
            CmdlineOutcome::OverSized {
                bytes: length,
                cap: config.max_bytes,
            },
        ));
    }

    let opened = match space::open(profile, layout, &mm, "pgd")? {
        Ok(opened) => opened,
        Err(refusal) => return Ok((None, CmdlineOutcome::NotRead(refusal))),
    };
    let runs = space::read_runs(&*opened.layer, start, length, config.max_bytes);
    if runs.runs.is_empty() {
        return Ok((
            None,
            CmdlineOutcome::NotRead(SpaceRefusal::Unreadable(format!(
                "none of the {length} byte(s) of the argument area at {start:#x} were captured by \
                 this acquisition"
            ))),
        ));
    }
    // Only the run that begins where the kernel says the bracket does is
    // parsed: a run starting later has lost the head of an argument, and
    // parsing it would report the tail of one argument as a whole one.
    let (run_start, run_bytes) = &runs.runs[0];
    let head: &[u8] = if *run_start == start { run_bytes } else { &[] };
    let bytes_missing = length.saturating_sub(head.len() as u64);
    let command_line = parse_command_line(head, bytes_missing);

    let outcome = if !runs.is_complete() {
        CmdlineOutcome::Partial {
            read: runs.bytes_read,
            unread: runs.bytes_unread,
        }
    } else {
        CmdlineOutcome::Read
    };
    Ok((Some(command_line), outcome))
}

/// Split an argument bracket at NUL into arguments.
///
/// `bytes` is the run that begins at `arg_start`; `bytes_missing` is how much
/// of the bracket past it the acquisition did not hold. An empty argument
/// between two NULs is kept; the empty string after the final terminator is
/// not an argument and is dropped.
///
/// A run whose last byte is not NUL means one of two things, and they are kept
/// apart: when the whole bracket was read it is the mark of a process that
/// rewrote its argument area (`argv_rewritten: Some(true)`), and the final
/// unterminated run is kept as the last argument since those bytes were in the
/// bracket; when bytes are missing, the run was cut by the acquisition, the
/// final run is a fragment (`last_argument_cut`), and whether the process
/// rewrote its arguments is not knowable (`argv_rewritten: None`).
pub fn parse_command_line(bytes: &[u8], bytes_missing: u64) -> CommandLine {
    let argv_short_read = bytes_missing > 0;
    if bytes.is_empty() {
        return CommandLine {
            arguments: Vec::new(),
            well_formed: true,
            argv_rewritten: if argv_short_read { None } else { Some(false) },
            argv_short_read,
            bytes_missing,
            last_argument_cut: false,
        };
    }
    let unterminated = bytes.last() != Some(&0);
    let (argv_rewritten, last_argument_cut) = if argv_short_read {
        (None, unterminated)
    } else {
        (Some(unterminated), false)
    };
    let body = if unterminated {
        bytes
    } else {
        &bytes[..bytes.len() - 1]
    };
    let mut well_formed = true;
    let arguments = body
        .split(|&b| b == 0)
        .map(|argument| match std::str::from_utf8(argument) {
            Ok(text) => text.to_string(),
            Err(_) => {
                well_formed = false;
                String::from_utf8_lossy(argument).into_owned()
            }
        })
        .collect();
    CommandLine {
        arguments,
        well_formed,
        argv_rewritten,
        argv_short_read,
        bytes_missing,
        last_argument_cut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_split_at_nul_and_the_terminator_is_not_an_argument() {
        let parsed = parse_command_line(b"python3\0swaptest.py\0", 0);
        assert_eq!(parsed.arguments, vec!["python3", "swaptest.py"]);
        assert_eq!(parsed.text(), "python3 swaptest.py");
        assert!(parsed.well_formed);
        assert_eq!(parsed.argv_rewritten, Some(false));
        assert!(!parsed.argv_short_read);
        assert_eq!(parsed.bytes_missing, 0);
    }

    #[test]
    fn an_empty_argument_in_the_middle_is_kept() {
        let parsed = parse_command_line(b"cmd\0\0last\0", 0);
        assert_eq!(parsed.arguments, vec!["cmd", "", "last"]);
    }

    #[test]
    fn a_bracket_with_no_final_nul_is_flagged_as_rewritten_not_repaired() {
        let parsed = parse_command_line(b"sshd: user [priv]", 0);
        assert_eq!(parsed.argv_rewritten, Some(true));
        assert!(!parsed.argv_short_read);
        assert!(!parsed.last_argument_cut);
        assert_eq!(parsed.arguments, vec!["sshd: user [priv]"]);
        assert_eq!(parsed.to_json()["argv_rewritten"], true);
    }

    #[test]
    fn a_bracket_cut_by_an_unacquired_page_is_a_short_read_not_a_rewrite() {
        // The acquisition holds the first page of the bracket and not the
        // second: the run stops mid-argument. That is a fact about the image,
        // not about the process, and must not read as setproctitle.
        let parsed = parse_command_line(b"/usr/bin/python3\0/tmp/swap", 4084);
        assert!(parsed.argv_short_read);
        assert_eq!(parsed.bytes_missing, 4084);
        assert_eq!(
            parsed.argv_rewritten, None,
            "the bracket's last byte was not read, so whether it is a NUL is unknown"
        );
        assert!(parsed.last_argument_cut);
        assert_eq!(parsed.arguments, vec!["/usr/bin/python3", "/tmp/swap"]);
        let json = parsed.to_json();
        assert_eq!(json["argv_short_read"], true);
        assert_eq!(json["bytes_missing"], 4084);
        assert!(json["argv_rewritten"].is_null());
        assert_eq!(json["last_argument_cut"], true);
    }

    #[test]
    fn a_short_read_that_stops_on_a_nul_keeps_its_last_argument_whole() {
        let parsed = parse_command_line(b"cmd\0first\0", 100);
        assert!(parsed.argv_short_read);
        assert!(!parsed.last_argument_cut);
        assert_eq!(parsed.argv_rewritten, None);
        assert_eq!(parsed.arguments, vec!["cmd", "first"]);
    }

    #[test]
    fn a_bracket_none_of_whose_head_was_read_has_no_arguments_and_all_bytes_missing() {
        let parsed = parse_command_line(b"", 64);
        assert!(parsed.arguments.is_empty());
        assert!(parsed.argv_short_read);
        assert_eq!(parsed.bytes_missing, 64);
        assert_eq!(parsed.argv_rewritten, None);
        assert!(!parsed.last_argument_cut);
    }

    #[test]
    fn bytes_that_are_not_utf8_are_reported_rather_than_silently_replaced() {
        let parsed = parse_command_line(&[0x61, 0xFF, 0x62, 0x00], 0);
        assert!(!parsed.well_formed);
        assert_eq!(parsed.arguments.len(), 1);
    }

    #[test]
    fn an_empty_bracket_is_no_arguments() {
        let parsed = parse_command_line(b"", 0);
        assert!(parsed.arguments.is_empty());
        assert_eq!(parsed.argv_rewritten, Some(false));
        assert!(!parsed.argv_short_read);
    }

    #[test]
    fn a_kernel_thread_is_not_a_gap_but_an_unread_bracket_is() {
        assert!(!CmdlineOutcome::NotRead(SpaceRefusal::NoUserAddressSpace).is_a_gap());
        assert!(CmdlineOutcome::NotRead(SpaceRefusal::Unreadable("x".into())).is_a_gap());
        assert!(!CmdlineOutcome::Empty.is_a_gap());
        assert!(CmdlineOutcome::Partial { read: 4, unread: 4 }.is_a_gap());
    }

    #[test]
    fn an_over_sized_bracket_is_refused_with_the_number_it_hit() {
        let outcome = CmdlineOutcome::OverSized {
            bytes: 9000,
            cap: MAX_COMMAND_LINE_BYTES,
        };
        assert!(outcome.is_a_gap());
        let detail = outcome.detail();
        assert!(detail.contains("9000"), "{detail}");
        assert!(detail.contains("4096"), "{detail}");
        assert_eq!(outcome.to_json()["class"], "over_sized");
    }

    #[test]
    fn a_row_with_no_command_line_says_why_rather_than_showing_a_blank() {
        let row = ProcessCommandLine {
            task_address: 0x1000,
            pid: Field::Known(2),
            ppid: Field::Known(0),
            comm: Field::Known("kthreadd".into()),
            command_line: None,
            outcome: CmdlineOutcome::NotRead(SpaceRefusal::NoUserAddressSpace),
        };
        let json = row.to_json();
        assert!(json["command_line"].is_null());
        assert_eq!(json["outcome"]["class"], "not_read");
        assert_eq!(json["outcome"]["is_a_gap"], false);
        assert!(json["outcome"]["detail"].as_str().unwrap().len() > 20);
    }

    #[test]
    fn the_layout_requires_both_bounds_and_states_what_is_lost_without_them() {
        for key in ["arg_start", "arg_end", "pgd", "mm"] {
            let spec = COMMAND_LINES_LAYOUT
                .members
                .iter()
                .find(|m| m.key == key)
                .expect("declared");
            assert!(spec.necessity.is_required(), "{key} must be required");
        }
    }
}
