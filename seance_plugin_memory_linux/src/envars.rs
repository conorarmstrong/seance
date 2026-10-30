//! Each process's environment variables, read from its own address space.
//!
//! The kernel does not keep a process's environment. It keeps two addresses —
//! `mm_struct.env_start` and `mm_struct.env_end` — bracketing a run of
//! NUL-separated `KEY=VALUE` strings near the top of the process's stack, in the
//! process's *own* memory. So this stage cannot be done from the kernel address
//! space at all: every row here required opening the process's page tables.
//!
//! ## Two things that look like emptiness and are not
//!
//! **A kernel thread has no environment**, because it has no user address space.
//! That is a fact about the machine and not a gap, so it is recorded on the row
//! and excluded from the stage's incompleteness.
//!
//! **A process whose environment pages were not captured** has an environment
//! that this image cannot show. That *is* a gap, it is recorded as one, and it
//! is why the stage's completeness is not "did every row parse".
//!
//! ## Where the parse stops, and why it stops rather than skips
//!
//! A pair with no `=` in it ends the parse for that process. Programs that
//! rewrite `argv` in place — `avahi-daemon` is the usual example — overrun into
//! the contiguous environment area, so everything after the first malformed pair
//! is the wreckage of that overwrite rather than environment. Skipping the bad
//! pair and carrying on would put strings in the record that were never
//! environment variables; stopping, and saying the parse stopped, does not.

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::Obj;

use crate::error::StageError;
use crate::module::STAGE_LINUX_ENVIRONMENT;
use crate::profile::LinuxProfile;
use crate::read::signed_to_json;
use crate::space::{self, SpaceRefusal};
use crate::tasks::{TaskInventory, TaskList, TaskRecord};

/// Largest environment area this stage will read for one process.
///
/// Volatility 3 uses the same figure and skips a process whose declared area is
/// larger. The bound is not arbitrary: `MAX_ARG_STRLEN` caps a single argument
/// at 128 KiB, but the environment area of a normal process is a few kilobytes,
/// and a declared span far larger than that means `env_start`/`env_end` are not
/// bracketing an environment — usually because the process rewrote its own
/// `argv` over them. Reading it anyway would put megabytes of unrelated stack
/// into the record as environment variables.
pub const MAX_ENVIRONMENT_BYTES: u64 = 8192;

/// Everything the environment stage needs out of the symbol table.
pub const ENVIRONMENT_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_ENVIRONMENT,
    &[TypeSpec::new("mm", &["mm_struct"]).required(
        "a process's memory descriptor cannot be located, so no process's own address space can \
         be opened and no environment variable can be read for any process on the machine",
    )],
    &[
        MemberSpec::new("mm", &["task_struct"], &["mm"]).required(
            "a task carries no pointer to its memory descriptor, so no process's own address \
             space can be reached",
        ),
        MemberSpec::new("pgd", &["mm_struct"], &["pgd"]).required(
            "a process's page-table root cannot be found, so its own address space cannot be \
             opened and the environment area cannot be read",
        ),
        MemberSpec::new("env_start", &["mm_struct"], &["env_start"]).required(
            "the kernel records no start for the environment area, so there is no range to read \
             and an empty result would read as a machine whose processes had no environment",
        ),
        MemberSpec::new("env_end", &["mm_struct"], &["env_end"]).required(
            "the kernel records no end for the environment area, so the range to read has no \
             length",
        ),
    ],
);

/// Caps for one environment survey.
#[derive(Debug, Clone)]
pub struct EnvironmentConfig {
    /// Largest environment area read for one process.
    pub max_area_bytes: u64,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            max_area_bytes: MAX_ENVIRONMENT_BYTES,
        }
    }
}

/// One environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// The name, everything before the first `=`.
    pub key: String,
    /// The value, everything after it. May itself contain `=`.
    pub value: String,
    /// Whether the pair's bytes were valid UTF-8. A `false` means bytes were
    /// replaced to render it and the value in the image differed.
    pub well_formed: bool,
}

impl EnvVar {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "key": self.key,
            "value": self.value,
            "well_formed": self.well_formed,
        })
    }
}

/// What happened when this stage looked at one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvOutcome {
    /// The environment area was read end to end.
    Read,
    /// The area was read and the parse stopped inside it. The string says where
    /// and why.
    ParseStopped(String),
    /// The area was not read. The refusal says why, and whether that is a gap.
    NotRead(SpaceRefusal),
    /// The kernel records an area of no length. Nothing was missed: this
    /// process's environment really is empty as the kernel describes it.
    Empty,
    /// The declared area is larger than this stage will read.
    OverSized {
        /// The declared length.
        bytes: u64,
        /// The cap that refused it.
        cap: u64,
    },
    /// The area's bounds could not be read from the memory descriptor.
    BoundsUnavailable(String),
    /// This build declares no bounds for the environment area.
    BoundsNotDeclared {
        /// The member the build does not have.
        member: &'static str,
    },
    /// Part of the area was not captured by the acquisition.
    Partial {
        /// Bytes read.
        read: u64,
        /// Bytes that could not be read.
        unread: u64,
    },
}

impl EnvOutcome {
    /// Whether this outcome means evidence is missing, as opposed to there
    /// being none to miss.
    pub fn is_a_gap(&self) -> bool {
        match self {
            EnvOutcome::Read | EnvOutcome::Empty => false,
            EnvOutcome::NotRead(refusal) => refusal.is_a_gap(),
            EnvOutcome::ParseStopped(_)
            | EnvOutcome::OverSized { .. }
            | EnvOutcome::BoundsUnavailable(_)
            | EnvOutcome::Partial { .. } => true,
            // A build with no `env_start` has no environment area to miss, but
            // the stage declares those members `required`, so this variant can
            // only arise from a later build change. Treated as a gap because
            // the stage would then be reporting nothing while the kernel does
            // hold an environment somewhere else.
            EnvOutcome::BoundsNotDeclared { .. } => true,
        }
    }

    /// Stable machine-readable class.
    pub fn class(&self) -> &'static str {
        match self {
            EnvOutcome::Read => "read",
            EnvOutcome::ParseStopped(_) => "parse_stopped",
            EnvOutcome::NotRead(_) => "not_read",
            EnvOutcome::Empty => "empty",
            EnvOutcome::OverSized { .. } => "over_sized",
            EnvOutcome::BoundsUnavailable(_) => "bounds_unavailable",
            EnvOutcome::BoundsNotDeclared { .. } => "bounds_not_declared",
            EnvOutcome::Partial { .. } => "partial",
        }
    }

    /// One sentence an examiner reads.
    pub fn detail(&self) -> String {
        match self {
            EnvOutcome::Read => "the environment area was read end to end".to_string(),
            EnvOutcome::ParseStopped(detail) => detail.clone(),
            EnvOutcome::NotRead(refusal) => refusal.detail(),
            EnvOutcome::Empty => {
                "the kernel records an environment area of no length for this process".to_string()
            }
            EnvOutcome::OverSized { bytes, cap } => format!(
                "the kernel records an environment area of {bytes} bytes, above this stage's cap \
                 of {cap}; a span that large is not an environment, so it was not read as one"
            ),
            EnvOutcome::BoundsUnavailable(detail) => format!(
                "the environment area's bounds could not be read from this process's memory \
                 descriptor: {detail}"
            ),
            EnvOutcome::BoundsNotDeclared { member } => format!(
                "this kernel build's memory descriptor declares no '{member}', so the \
                 environment area could not be located"
            ),
            EnvOutcome::Partial { read, unread } => format!(
                "{read} byte(s) of the environment area were read and {unread} were not captured \
                 by the acquisition, so the variables below are a floor"
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

/// One process's environment, and what the stage could establish about it.
#[derive(Debug, Clone)]
pub struct ProcessEnvironment {
    /// Address of the `task_struct`.
    pub task_address: u64,
    /// The process id, as the task list read it.
    pub pid: Field<i64>,
    /// The parent's process id.
    pub ppid: Field<i64>,
    /// The process name.
    pub comm: Field<String>,
    /// The variables that were read, in the order the kernel held them.
    pub variables: Vec<EnvVar>,
    /// What happened.
    pub outcome: EnvOutcome,
}

impl ProcessEnvironment {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task_address": self.task_address,
            "task_address_hex": format!("{:#x}", self.task_address),
            "pid": signed_to_json(&self.pid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "count": self.variables.len(),
            "variables": self.variables.iter().map(EnvVar::to_json).collect::<Vec<_>>(),
            "outcome": self.outcome.to_json(),
        })
    }
}

/// Every process's environment, and everything the stage could not establish.
#[derive(Debug, Clone)]
pub struct EnvironmentSurvey {
    /// One entry per process on the list the stage was handed, including the
    /// ones with nothing to read. A process with no entry would be
    /// indistinguishable from a process nobody looked at.
    pub processes: Vec<ProcessEnvironment>,
    /// How complete the list the stage walked was.
    pub inventory: TaskInventory,
    /// Which structure layout produced these figures — see the same field on
    /// `BashSurvey` for why both stages now carry it.
    pub layout: serde_json::Value,
}

impl EnvironmentSurvey {
    /// Total variables read across every process.
    pub fn variable_count(&self) -> usize {
        self.processes.iter().map(|p| p.variables.len()).sum()
    }

    /// Whether every process on the list was examined and nothing was missed.
    ///
    /// The conjunction of two independent facts: this stage's own work, and the
    /// completeness of the list it was handed. A stage that read the environment
    /// of every process it was given is still short by whatever the task walk
    /// never reached.
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
                    "the environment of the process at {:#x} could not be established in full: {}",
                    process.task_address,
                    process.outcome.detail()
                ),
            ));
        }
        out
    }

    /// Serializable form for the environment artifact.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "process_count": self.processes.len(),
            "variable_count": self.variable_count(),
            "complete": self.is_complete(),
            "layout": self.layout,
            "processes": self
                .processes
                .iter()
                .map(ProcessEnvironment::to_json)
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

/// Bind the environment stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(ENVIRONMENT_LAYOUT.bind(&reader)?)
}

/// Read every process's environment.
///
/// # Errors
///
/// Only for a lookup the stage never declared, which is a programming error.
/// Every way a real process can fail to yield an environment is a variant on its
/// row, because one unreadable process must not cost the examiner the other
/// ninety.
pub fn survey_environment(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &EnvironmentConfig,
) -> Result<EnvironmentSurvey, StageError> {
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
                    Vec::new(),
                    EnvOutcome::NotRead(SpaceRefusal::Unreadable(err.to_string())),
                ));
                continue;
            }
        };
        let (variables, outcome) = read_environment(profile, layout, &obj, config)?;
        processes.push(row(task, variables, outcome));
    }

    Ok(EnvironmentSurvey {
        processes,
        layout: layout.to_json(),
        inventory: tasks.inventory(),
    })
}

/// One row, carrying the identity the task list already established.
fn row(task: &TaskRecord, variables: Vec<EnvVar>, outcome: EnvOutcome) -> ProcessEnvironment {
    ProcessEnvironment {
        task_address: task.address,
        pid: task.pid.clone(),
        ppid: task.ppid.clone(),
        comm: task.comm.clone(),
        variables,
        outcome,
    }
}

/// Read one process's environment area.
fn read_environment(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    task: &Obj,
    config: &EnvironmentConfig,
) -> Result<(Vec<EnvVar>, EnvOutcome), StageError> {
    let mm = match space::memory_descriptor(layout, task, "mm")? {
        Ok(mm) => mm,
        Err(refusal) => return Ok((Vec::new(), EnvOutcome::NotRead(refusal))),
    };

    let start = match layout.read_unsigned(&mm, "env_start")? {
        Field::Known(value) => value,
        Field::NotDeclared { member } => {
            return Ok((Vec::new(), EnvOutcome::BoundsNotDeclared { member }))
        }
        Field::NotApplicable => return Ok((Vec::new(), EnvOutcome::Empty)),
        Field::Unavailable(detail) => {
            return Ok((Vec::new(), EnvOutcome::BoundsUnavailable(detail)))
        }
    };
    let end = match layout.read_unsigned(&mm, "env_end")? {
        Field::Known(value) => value,
        Field::NotDeclared { member } => {
            return Ok((Vec::new(), EnvOutcome::BoundsNotDeclared { member }))
        }
        Field::NotApplicable => return Ok((Vec::new(), EnvOutcome::Empty)),
        Field::Unavailable(detail) => {
            return Ok((Vec::new(), EnvOutcome::BoundsUnavailable(detail)))
        }
    };

    let Some(length) = end.checked_sub(start) else {
        return Ok((
            Vec::new(),
            EnvOutcome::BoundsUnavailable(format!(
                "the kernel records an environment area ending at {end:#x}, below its start at \
                 {start:#x}, so it does not describe a range"
            )),
        ));
    };
    if length == 0 {
        return Ok((Vec::new(), EnvOutcome::Empty));
    }
    if length > config.max_area_bytes {
        return Ok((
            Vec::new(),
            EnvOutcome::OverSized {
                bytes: length,
                cap: config.max_area_bytes,
            },
        ));
    }

    let opened = match space::open(profile, layout, &mm, "pgd")? {
        Ok(opened) => opened,
        Err(refusal) => return Ok((Vec::new(), EnvOutcome::NotRead(refusal))),
    };
    let runs = space::read_runs(&*opened.layer, start, length, config.max_area_bytes);
    if runs.runs.is_empty() {
        return Ok((
            Vec::new(),
            EnvOutcome::NotRead(SpaceRefusal::Unreadable(format!(
                "none of the {length} byte(s) of the environment area at {start:#x} were captured \
                 by this acquisition"
            ))),
        ));
    }
    // The environment is one contiguous run of NUL-separated strings. A hole
    // inside it means a pair straddles bytes that were never captured, so only
    // the first acquired run is parsed and the rest is declared missing —
    // stitching the runs together would join the head of one variable to the
    // tail of another and produce a value the machine never held.
    // …and only when that run begins where the kernel says the area does. A run
    // starting later is a run whose first variable had its head cut off, and
    // parsing it would report the tail of a value as a variable name.
    let (run_start, run_bytes) = &runs.runs[0];
    let head: &[u8] = if *run_start == start { run_bytes } else { &[] };
    let (variables, stopped) = parse_environment(head);

    let outcome = if !runs.is_complete() {
        EnvOutcome::Partial {
            read: runs.bytes_read,
            unread: runs.bytes_unread,
        }
    } else if let Some(reason) = stopped {
        EnvOutcome::ParseStopped(reason)
    } else {
        EnvOutcome::Read
    };
    Ok((variables, outcome))
}

/// Split an environment area into pairs, stopping at the first that is not one.
///
/// Returns the variables and, when the parse stopped early, why. Stopping rather
/// than skipping is deliberate: see this module's own documentation.
pub fn parse_environment(bytes: &[u8]) -> (Vec<EnvVar>, Option<String>) {
    let mut out = Vec::new();
    // Trailing NULs are the padding between the last variable and the end of the
    // area, not empty variables.
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|last| last + 1)
        .unwrap_or(0);
    for (index, pair) in bytes[..end].split(|&b| b == 0).enumerate() {
        if pair.is_empty() {
            continue;
        }
        let (text, well_formed) = match std::str::from_utf8(pair) {
            Ok(text) => (text.to_string(), true),
            Err(_) => (String::from_utf8_lossy(pair).into_owned(), false),
        };
        let Some((key, value)) = text.split_once('=') else {
            return (
                out,
                Some(format!(
                    "the environment area holds an entry at position {index} with no '=' in it, \
                     which is what a process that rewrote its own argument vector leaves behind; \
                     the parse stopped there rather than report the remaining bytes as \
                     environment variables"
                )),
            );
        };
        out.push(EnvVar {
            key: key.to_string(),
            value: value.to_string(),
            well_formed,
        });
    }
    (out, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(pairs: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for pair in pairs {
            out.extend_from_slice(pair.as_bytes());
            out.push(0);
        }
        out
    }

    #[test]
    fn pairs_split_on_the_first_equals_so_a_value_may_contain_one() {
        let (vars, stopped) = parse_environment(&area(&[
            "HOME=/root",
            "LS_COLORS=rs=0:di=01;34",
            "PATH=/usr/bin",
        ]));
        assert_eq!(stopped, None);
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].key, "HOME");
        assert_eq!(vars[0].value, "/root");
        assert_eq!(vars[1].key, "LS_COLORS");
        assert_eq!(
            vars[1].value, "rs=0:di=01;34",
            "only the first '=' separates; the rest is value"
        );
    }

    /// The `avahi-daemon` case. Everything after an entry with no `=` is the
    /// wreckage of a process rewriting its own argument vector over the
    /// contiguous environment area. Reporting it as environment would put
    /// strings in the case record that were never environment variables.
    #[test]
    fn a_malformed_entry_stops_the_parse_and_says_so() {
        let (vars, stopped) = parse_environment(&area(&[
            "HOME=/root",
            "avahi-daemon: running",
            "PATH=/usr/bin",
        ]));
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].key, "HOME");
        let reason = stopped.expect("the parse stopped and must say so");
        assert!(reason.contains("no '='"), "{reason}");
        assert!(reason.contains("argument vector"), "{reason}");
    }

    #[test]
    fn trailing_padding_is_not_a_row_of_empty_variables() {
        let mut bytes = area(&["HOME=/root"]);
        bytes.extend_from_slice(&[0u8; 64]);
        let (vars, stopped) = parse_environment(&bytes);
        assert_eq!(vars.len(), 1);
        assert_eq!(stopped, None);

        // An area of nothing but padding yields nothing and does not "stop".
        let (vars, stopped) = parse_environment(&[0u8; 32]);
        assert!(vars.is_empty());
        assert_eq!(stopped, None);
    }

    #[test]
    fn a_value_that_was_not_utf8_is_flagged_rather_than_silently_repaired() {
        let mut bytes = b"PS1=".to_vec();
        bytes.push(0xFF);
        bytes.push(0);
        let (vars, _) = parse_environment(&bytes);
        assert_eq!(vars.len(), 1);
        assert!(
            !vars[0].well_formed,
            "the bytes were not text and the report must say so"
        );
    }

    fn survey(outcomes: Vec<EnvOutcome>, inventory_complete: bool) -> EnvironmentSurvey {
        EnvironmentSurvey {
            layout: serde_json::json!({}),
            processes: outcomes
                .into_iter()
                .enumerate()
                .map(|(index, outcome)| ProcessEnvironment {
                    task_address: 0xFFFF_8800_0000_0000 + index as u64 * 0x1000,
                    pid: Field::Known(index as i64 + 1),
                    ppid: Field::Known(1),
                    comm: Field::Known("sshd".into()),
                    variables: vec![EnvVar {
                        key: "HOME".into(),
                        value: "/root".into(),
                        well_formed: true,
                    }],
                    outcome,
                })
                .collect(),
            inventory: TaskInventory {
                head: 0xFFFF_FFFF_8160_D190,
                listed: 3,
                complete: inventory_complete,
                incomplete: if inventory_complete {
                    Vec::new()
                } else {
                    vec![Incomplete::new(
                        IncompleteReason::CapReached,
                        "the walk stopped at its cap",
                    )]
                },
            },
        }
    }

    /// A kernel thread with no user memory is not a hole in the evidence.
    /// Counting it as one would tell an examiner that environment variables were
    /// missed on a task that never had any.
    #[test]
    fn a_kernel_thread_does_not_make_the_survey_incomplete() {
        let s = survey(
            vec![
                EnvOutcome::Read,
                EnvOutcome::NotRead(SpaceRefusal::NoUserAddressSpace),
                EnvOutcome::Empty,
            ],
            true,
        );
        assert!(s.is_complete());
        assert!(s.incomplete().is_empty());
    }

    #[test]
    fn a_process_whose_environment_was_not_captured_does() {
        let s = survey(
            vec![
                EnvOutcome::Read,
                EnvOutcome::NotRead(SpaceRefusal::RootNotAcquired("not captured".into())),
            ],
            true,
        );
        assert!(!s.is_complete());
        assert_eq!(s.incomplete().len(), 1);
        assert!(s.incomplete()[0]
            .detail
            .contains("could not be established"));
    }

    /// The reason the inventory travels onto this stage: a survey that examined
    /// every process it was handed is still a floor when the task walk stopped
    /// short, and "no environment variables for that PID" would otherwise read
    /// as a process examined and found bare.
    #[test]
    fn a_complete_survey_over_a_short_task_list_is_not_complete() {
        let s = survey(vec![EnvOutcome::Read], false);
        assert!(!s.is_complete());
        let json = s.to_json();
        assert_eq!(json["complete"], false);
        assert_eq!(json["task_inventory"]["count_is_floor"], true);
    }

    #[test]
    fn every_outcome_reads_as_a_sentence_and_grades_itself() {
        for outcome in [
            EnvOutcome::Read,
            EnvOutcome::ParseStopped("stopped".into()),
            EnvOutcome::NotRead(SpaceRefusal::NoUserAddressSpace),
            EnvOutcome::Empty,
            EnvOutcome::OverSized {
                bytes: 1 << 30,
                cap: MAX_ENVIRONMENT_BYTES,
            },
            EnvOutcome::BoundsUnavailable("x".into()),
            EnvOutcome::BoundsNotDeclared {
                member: "env_start",
            },
            EnvOutcome::Partial {
                read: 4096,
                unread: 4096,
            },
        ] {
            assert!(!outcome.class().is_empty());
            assert!(!outcome.detail().is_empty());
            assert_eq!(outcome.to_json()["is_a_gap"], outcome.is_a_gap());
        }
        assert!(!EnvOutcome::Read.is_a_gap());
        assert!(!EnvOutcome::Empty.is_a_gap());
        assert!(EnvOutcome::Partial { read: 1, unread: 1 }.is_a_gap());
    }

    #[test]
    fn every_key_the_stage_reads_is_a_key_the_stage_declared() {
        const READ_KEYS: &[&str] = &["mm", "pgd", "env_start", "env_end"];
        for key in READ_KEYS {
            assert!(
                ENVIRONMENT_LAYOUT
                    .members
                    .iter()
                    .any(|spec| spec.key == *key),
                "{key} is read by the stage and declared nowhere"
            );
        }
        assert_eq!(ENVIRONMENT_LAYOUT.members.len(), READ_KEYS.len());
        assert_eq!(ENVIRONMENT_LAYOUT.stage.key, STAGE_LINUX_ENVIRONMENT.key);
    }
}
