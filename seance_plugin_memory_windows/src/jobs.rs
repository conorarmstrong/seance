//! Job objects and their members (`ROADMAP` §5.3, upstream's `joblinks`).
//!
//! # What an examiner learns
//!
//! Which processes were confined to a job object, and what that job was
//! configured to hold. A job is how Windows groups processes for limits and
//! accounting, and it is how a sandbox shows up in memory: a browser's renderer
//! processes, a packaged app's, and a container's are all in one. It also shows
//! the reverse — a process that *ought* to be in a job and is not.
//!
//! # A process with no job is the ordinary case
//!
//! Most processes on a Windows machine have `_EPROCESS.Job` null. That is not a
//! finding, it is not reported as a row, and the record says how many processes
//! were in that state so an empty list cannot read as a walk that failed.
//!
//! # The same job is reached from several processes, and that is not several
//! jobs
//!
//! Upstream's `joblinks` iterates processes and prints a row per process that
//! has a job, then that job's member list under it — so a job holding three
//! processes is printed three times, with its members repeated three times.
//! Here each `_EJOB` is one record, with **every** process that pointed at it
//! named, because two rows for one kernel object is two answers to one
//! question. The per-process view is still recoverable from the record, and the
//! difference in row counts against upstream is stated rather than left to look
//! like a disagreement about what is on the machine.
//!
//! # The counter and the list are both reported
//!
//! `_EJOB` carries `TotalProcesses`, `ActiveProcesses` and
//! `TotalTerminatedProcesses`; the member list is walked separately. They are
//! **different facts** and a disagreement between them is worth an examiner's
//! attention rather than a silent preference for one — a job whose counter says
//! four and whose list holds two is either mid-teardown or has had a member
//! unlinked.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::first_member;
use seance_memory::object::{ListSpec, ListStop, StructReader};
use seance_memory::Incomplete;
use serde_json::{json, Value};

use crate::process::{ProcessList, ProcessRecord};
use crate::profile::WindowsProfile;

/// Members of one job the walk will return.
///
/// A real job holds a handful to a few dozen. This bounds a corrupt chain, and
/// reaching it is reported as a cap.
pub const MAX_JOB_MEMBERS: usize = 4096;

/// What went wrong that stopped the whole survey.
#[derive(Debug, Clone)]
pub enum JobError {
    /// This build cannot be asked the question at all.
    Unsupported { detail: String },
}

impl JobError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn class(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported_build",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Unsupported { detail } => detail.clone(),
        }
    }

    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            Self::Unsupported { .. } => IncompleteReason::UnresolvedStructure,
        }
    }
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail())
    }
}

/// The members this build's job objects are read through.
#[derive(Debug, Clone)]
pub struct JobSymbols {
    /// `_EPROCESS` path to the job pointer.
    pub job: String,
    /// `_EPROCESS` path to the link the job's member list threads through.
    pub job_links: String,
    /// `_EJOB` path to the member-list head.
    pub process_list_head: String,
    /// The accounting members, each optional and each `None` rather than zero
    /// when this build does not declare it.
    pub session_id: Option<String>,
    pub total_processes: Option<String>,
    pub active_processes: Option<String>,
    pub total_terminated: Option<String>,
    /// Byte offset of `JobLinks` inside `_EPROCESS`, for `CONTAINING_RECORD`.
    pub job_links_offset: u64,
}

impl JobSymbols {
    /// Resolve what this build declares.
    ///
    /// # Errors
    ///
    /// [`JobError::Unsupported`] naming the member, for a build without the
    /// three the walk cannot do without. Measured across the 1,724
    /// `ntkrnlmp.pdb` ISFs on this machine: all 1,650 that declare `_EPROCESS`
    /// declare `Job`, `JobLinks` and `_EJOB.ProcessListHead`, and all 1,650
    /// declare the three counters too — so an absence here is a build unlike
    /// anything measured, and is answered rather than assumed.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, JobError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type("_EJOB") {
            return Err(JobError::unsupported(
                "this build's symbol table has no '_EJOB', so there is no job object to read and \
                 nothing can be said about which processes were confined to one",
            ));
        }
        let required =
            |type_name: &'static str, candidates: &'static [&'static str], what: &str| {
                match first_member(&reader, type_name, candidates) {
                    Ok(Some(path)) => Ok(path.to_string()),
                    Ok(None) => Err(JobError::unsupported(format!(
                        "this build declares no {type_name}.{}, so {what}",
                        candidates.join(" or ")
                    ))),
                    Err(err) => Err(JobError::unsupported(format!(
                        "the symbol table could not answer for {type_name}.{}: {err}. That is not \
                     the same as the member being absent, and nothing is claimed about it",
                        candidates.join(" or ")
                    ))),
                }
            };

        let job = required(
            "_EPROCESS",
            &["Job"],
            "no process can be asked which job it belongs to",
        )?;
        let job_links = required(
            "_EPROCESS",
            &["JobLinks"],
            "a job's member list cannot be walked: the link is what each member is recovered from",
        )?;
        let process_list_head = required(
            "_EJOB",
            &["ProcessListHead"],
            "a job's members cannot be enumerated at all",
        )?;
        let job_links_offset = reader
            .member_offset("_EPROCESS", &job_links)
            .map(|o| o.bytes())
            .map_err(|err| {
                JobError::unsupported(format!(
                    "'_EPROCESS.{job_links}' has no readable offset: {err}"
                ))
            })?;

        let optional = |candidates: &'static [&'static str]| -> Option<String> {
            first_member(&reader, "_EJOB", candidates)
                .ok()
                .flatten()
                .map(str::to_string)
        };
        Ok(Self {
            job,
            job_links,
            process_list_head,
            session_id: optional(&["SessionId"]),
            total_processes: optional(&["TotalProcesses"]),
            active_processes: optional(&["ActiveProcesses"]),
            total_terminated: optional(&["TotalTerminatedProcesses"]),
            job_links_offset,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "job_path": self.job,
            "job_links_path": self.job_links,
            "job_links_offset": self.job_links_offset,
            "process_list_head_path": self.process_list_head,
            "session_id_path": self.session_id,
            "total_processes_path": self.total_processes,
            "active_processes_path": self.active_processes,
            "total_terminated_path": self.total_terminated,
            "basis":
                "Every path resolved from this build's own symbol table. `JobLinks`' offset is \
                 published because every member address in this record rests on it: a member is \
                 recovered from its link by CONTAINING_RECORD, and a wrong offset yields a \
                 structure that is not an _EPROCESS but reads like one.",
        })
    }
}

/// One process named as a member of a job.
#[derive(Debug, Clone)]
pub struct JobMember {
    /// The `_EPROCESS`, recovered by `CONTAINING_RECORD` from its link.
    pub process: u64,
    pub pid: Option<u64>,
    pub name: Option<String>,
    /// Whether the active process list also holds this process. A member the
    /// process list does not carry is the interesting case, and it is only a
    /// statement when that list was walked end to end.
    pub in_the_process_list: Option<bool>,
}

impl JobMember {
    pub fn to_json(&self) -> Value {
        json!({
            "process": format!("{:#018x}", self.process),
            "pid": self.pid,
            "name": self.name,
            "in_the_process_list": self.in_the_process_list,
        })
    }
}

/// One job object.
#[derive(Debug, Clone)]
pub struct JobRecord {
    /// The `_EJOB`.
    pub job: u64,
    /// Every process whose `Job` pointer named this object, in list order.
    /// Upstream prints one row per entry here; this record is one.
    pub named_by: Vec<u64>,
    pub session_id: Option<u64>,
    pub total_processes: Option<u64>,
    pub active_processes: Option<u64>,
    pub total_terminated: Option<u64>,
    pub members: Vec<JobMember>,
    /// Why the member walk ended. Only a wrap means it was enumerated whole.
    pub stop: Option<String>,
}

impl JobRecord {
    /// Whether the job's own counter agrees with the members walked.
    ///
    /// `None` when the build declares no counter to compare, which is not
    /// agreement.
    pub fn counter_agrees(&self) -> Option<bool> {
        self.active_processes
            .map(|active| active == self.members.len() as u64)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryJob",
            "name": format!(
                "job at {:#018x} with {} member(s)",
                self.job,
                self.members.len()
            ),
            "job": format!("{:#018x}", self.job),
            "named_by": self
                .named_by
                .iter()
                .map(|p| format!("{p:#018x}"))
                .collect::<Vec<_>>(),
            "named_by_total": self.named_by.len(),
            "session_id": self.session_id,
            "total_processes": self.total_processes,
            "active_processes": self.active_processes,
            "total_terminated_processes": self.total_terminated,
            "members": self.members.iter().map(JobMember::to_json).collect::<Vec<_>>(),
            "members_walked": self.members.len(),
            "counter_agrees_with_the_list": self.counter_agrees(),
            "counter_basis":
                "`ActiveProcesses` is the kernel's own count and the member list is a walk of \
                 `ProcessListHead`. They are different facts and both are reported: a job whose \
                 counter exceeds its list is either mid-teardown or has had a member unlinked, \
                 and preferring one number silently would hide that.",
            "walk_stop": self.stop,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct JobSurvey {
    pub symbols: JobSymbols,
    pub jobs: Vec<JobRecord>,
    /// Processes the survey looked at.
    pub processes_walked: u64,
    /// Processes whose `Job` pointer was null — the ordinary case.
    pub processes_without_a_job: u64,
    /// Processes whose `Job` pointer could not be read at all.
    pub processes_unreadable: u64,
    /// Whether the process list this survey was handed was itself complete.
    pub process_list_complete: bool,
    pub notes: Vec<String>,
    pub capped: Option<String>,
}

impl JobSurvey {
    /// Members named by a job that the active process list does not hold.
    ///
    /// Only a statement when the process list was walked end to end; otherwise
    /// every member is `None` on that question and this is zero because
    /// nothing was established, not because nothing was found.
    pub fn members_outside_the_process_list(&self) -> usize {
        self.jobs
            .iter()
            .flat_map(|job| job.members.iter())
            .filter(|m| m.in_the_process_list == Some(false))
            .count()
    }

    pub fn processes_in_a_job(&self) -> u64 {
        self.jobs.iter().map(|j| j.named_by.len() as u64).sum()
    }

    pub fn describe(&self) -> String {
        format!(
            "{} distinct job object(s) were reached from {} of the {} processes walked; {} \
             process(es) belong to no job, which is the ordinary case on Windows. The jobs hold \
             {} member(s) between them.{}",
            self.jobs.len(),
            self.processes_in_a_job(),
            self.processes_walked,
            self.processes_without_a_job,
            self.jobs.iter().map(|j| j.members.len()).sum::<usize>(),
            if self.process_list_complete {
                String::new()
            } else {
                " The process list this survey was handed did not walk end to end, so whether a \
                 member is also in it could not be established for any of them."
                    .to_string()
            }
        )
    }

    pub fn is_complete(&self) -> bool {
        self.capped.is_none()
            && self.processes_unreadable == 0
            && self.jobs.iter().all(|j| j.stop.is_none())
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(capped) = &self.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                capped.clone(),
            ));
        }
        if self.processes_unreadable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} process(es) had no readable `Job` pointer, so whether they belong to a \
                     job was never established -- which is not the same as belonging to none.",
                    self.processes_unreadable
                ),
            ));
        }
        for job in self.jobs.iter().filter(|j| j.stop.is_some()) {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the member list of the job at {:#018x} ended with `{}` rather than at its \
                     head, so it may hold members this walk did not reach.",
                    job.job,
                    job.stop.clone().unwrap_or_default()
                ),
            ));
        }
        out
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "jobs": self.jobs.iter().map(JobRecord::to_json).collect::<Vec<_>>(),
            "jobs_total": self.jobs.len(),
            "processes_walked": self.processes_walked,
            "processes_in_a_job": self.processes_in_a_job(),
            "processes_without_a_job": self.processes_without_a_job,
            "processes_unreadable": self.processes_unreadable,
            "process_list_complete": self.process_list_complete,
            "members_outside_the_process_list": self.members_outside_the_process_list(),
            "row_shape_note":
                "One record per DISTINCT job object, naming every process that pointed at it. \
                 Upstream's `joblinks` prints one row per process that has a job and repeats \
                 that job's members under each, so its row count is higher for the same machine \
                 -- a job holding three processes is printed three times. Two rows for one \
                 kernel object would be two answers to one question.",
            "statement": self.describe(),
            "notes": self.notes,
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Survey the job objects every process names.
///
/// # Errors
///
/// [`JobError::Unsupported`] when this build declares no `_EJOB` or none of the
/// three members the walk needs.
pub fn survey_jobs(
    profile: &WindowsProfile,
    symbols: &JobSymbols,
    processes: &ProcessList,
) -> Result<JobSurvey, JobError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let process_list_complete = processes.forward_stop.is_complete();
    let known: std::collections::BTreeSet<u64> =
        processes.processes.iter().map(|p| p.address).collect();

    let mut out = JobSurvey {
        symbols: symbols.clone(),
        jobs: Vec::new(),
        processes_walked: processes.processes.len() as u64,
        processes_without_a_job: 0,
        processes_unreadable: 0,
        process_list_complete,
        notes: Vec::new(),
        capped: None,
    };

    // Job address -> the processes that named it, in the order the process
    // list gave them.
    let mut named: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for entry in &processes.processes {
        match read_job_pointer(&reader, symbols, entry) {
            Ok(Some(job)) => named.entry(job).or_default().push(entry.address),
            Ok(None) => out.processes_without_a_job += 1,
            Err(reason) => {
                out.processes_unreadable += 1;
                if out.notes.len() < 64 {
                    out.notes.push(reason);
                }
            }
        }
    }

    for (job, named_by) in named {
        out.jobs.push(read_job(
            &reader,
            symbols,
            job,
            named_by,
            &known,
            process_list_complete,
        ));
    }
    Ok(out)
}

/// Read one process's `Job` pointer. `Ok(None)` is a process in no job.
fn read_job_pointer(
    reader: &StructReader,
    symbols: &JobSymbols,
    entry: &ProcessRecord,
) -> Result<Option<u64>, String> {
    let object = reader.object(entry.address, "_EPROCESS").map_err(|err| {
        format!(
            "the process structure at {:#018x} could not be read, so its job pointer was never \
             read: {err}",
            entry.address
        )
    })?;
    let value = object.pointer(&symbols.job).map_err(|err| {
        format!(
            "'_EPROCESS.{}' would not read on the process at {:#018x}: {err}",
            symbols.job, entry.address
        )
    })?;
    Ok((value != 0).then_some(value))
}

/// Read one job object and walk its member list.
fn read_job(
    reader: &StructReader,
    symbols: &JobSymbols,
    job: u64,
    named_by: Vec<u64>,
    known: &std::collections::BTreeSet<u64>,
    process_list_complete: bool,
) -> JobRecord {
    let mut record = JobRecord {
        job,
        named_by,
        session_id: None,
        total_processes: None,
        active_processes: None,
        total_terminated: None,
        members: Vec::new(),
        stop: None,
    };
    let Ok(object) = reader.object(job, "_EJOB") else {
        record.stop = Some(format!("the _EJOB at {job:#018x} could not be read"));
        return record;
    };
    let unsigned = |path: &Option<String>| -> Option<u64> {
        path.as_deref().and_then(|p| object.unsigned(p).ok())
    };
    record.session_id = unsigned(&symbols.session_id);
    record.total_processes = unsigned(&symbols.total_processes);
    record.active_processes = unsigned(&symbols.active_processes);
    record.total_terminated = unsigned(&symbols.total_terminated);

    // The head is EMBEDDED in the `_EJOB`, so its address is the member's
    // address rather than a value read out of it. Following it as a pointer
    // would take the first member's link as the head and never wrap.
    let Ok(head) = object.member_address(&symbols.process_list_head) else {
        record.stop = Some(format!(
            "'_EJOB.{}' has no address on the job at {job:#018x}",
            symbols.process_list_head
        ));
        return record;
    };

    let spec = ListSpec {
        link_type: "_LIST_ENTRY".to_string(),
        forward: "Flink".to_string(),
        container: Some(("_EPROCESS".to_string(), symbols.job_links.clone())),
        max_entries: MAX_JOB_MEMBERS,
    };
    let mut walk = match reader.walk_list(head, &spec) {
        Ok(walk) => walk,
        Err(err) => {
            record.stop = Some(format!("the member walk could not be started: {err}"));
            return record;
        }
    };
    for item in walk.by_ref() {
        let Ok(member) = item else { break };
        let address = member.address();
        record.members.push(JobMember {
            process: address,
            pid: member.pointer("UniqueProcessId").ok(),
            // Read through the same helper the process list uses, so a name
            // here and a name there cannot differ: the member is a fixed-width
            // array that is NOT guaranteed to be NUL-terminated.
            name: member
                .bytes(crate::process::MEMBER_IMAGE_FILE_NAME)
                .ok()
                .map(|raw| crate::poolscan::image_file_name(&raw))
                .filter(|name| !name.is_empty()),
            in_the_process_list: process_list_complete.then(|| known.contains(&address)),
        });
    }
    match walk.stop() {
        None | Some(ListStop::Wrapped) => {}
        Some(other) => record.stop = Some(other.as_str().to_string()),
    }
    record
}
