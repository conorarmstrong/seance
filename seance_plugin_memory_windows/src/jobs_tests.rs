//! Job objects: one record per job, the counter beside the list, and the two
//! things an empty answer must not mean.

use super::jobs::*;
use crate::image_fixture::{Image, BASE_TYPES_X64};
use crate::poolscan::test_support::{profile, table};
use crate::process::{list_processes, ProcessListConfig, ProcessSymbols};
use seance_memory::Architecture;

// Where the fixture puts things.
const PS_ACTIVE_HEAD: u64 = 0x200;
const PROCESS_A: u64 = 0x1000;
const PROCESS_B: u64 = 0x2000;
const PROCESS_C: u64 = 0x3000;
const JOB_A: u64 = 0x8000;

// `_EPROCESS` offsets the fixture declares.
const EP_PID: u64 = 0;
const EP_NAME: u64 = 8;
const EP_LINKS: u64 = 48;
const EP_JOB: u64 = 72;
const EP_JOB_LINKS: u64 = 80;
const EP_DTB: u64 = 96;

// `_EJOB` offsets.
const EJ_PROCESS_LIST: u64 = 8;
const EJ_TOTAL: u64 = 40;
const EJ_ACTIVE: u64 = 44;
const EJ_TERMINATED: u64 = 48;
const EJ_SESSION: u64 = 52;

/// Which optional members this build declares.
#[derive(Clone, Copy)]
struct Declares {
    counters: bool,
    ejob: bool,
    job_links: bool,
}

impl Default for Declares {
    fn default() -> Self {
        Self {
            counters: true,
            ejob: true,
            job_links: true,
        }
    }
}

fn isf(d: Declares) -> String {
    let counters = if d.counters {
        format!(
            r#","TotalProcesses": {{"offset": {EJ_TOTAL}, "type": {{"kind": "base",
                         "name": "unsigned long"}}}},
      "ActiveProcesses": {{"offset": {EJ_ACTIVE}, "type": {{"kind": "base",
                          "name": "unsigned long"}}}},
      "TotalTerminatedProcesses": {{"offset": {EJ_TERMINATED}, "type": {{"kind": "base",
                                   "name": "unsigned long"}}}},
      "SessionId": {{"offset": {EJ_SESSION}, "type": {{"kind": "base",
                    "name": "unsigned long"}}}}"#
        )
    } else {
        String::new()
    };
    let ejob = if d.ejob {
        format!(
            r#""_EJOB": {{"size": 64, "kind": "struct", "fields": {{
      "ProcessListHead": {{"offset": {EJ_PROCESS_LIST}, "type": {{"kind": "struct",
                          "name": "_LIST_ENTRY"}}}}{counters}
    }}}},"#
        )
    } else {
        String::new()
    };
    let job_links = if d.job_links {
        format!(
            r#","JobLinks": {{"offset": {EP_JOB_LINKS}, "type": {{"kind": "struct",
                   "name": "_LIST_ENTRY"}}}}"#
        )
    } else {
        String::new()
    };
    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base},
  "user_types": {{
    "_LIST_ENTRY": {{"size": 16, "kind": "struct", "fields": {{
      "Flink": {{"offset": 0, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}},
      "Blink": {{"offset": 8, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_LARGE_INTEGER": {{"size": 8, "kind": "union", "fields": {{
      "QuadPart": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    {ejob}
    "_EPROCESS": {{"size": 256, "kind": "struct", "fields": {{
      "UniqueProcessId": {{"offset": {ep_pid}, "type": {{"kind": "pointer",
                          "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ImageFileName": {{"offset": {ep_name}, "type": {{"kind": "array", "count": 15,
                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "CreateTime": {{"offset": 32, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "ActiveProcessLinks": {{"offset": {ep_links}, "type": {{"kind": "struct",
                             "name": "_LIST_ENTRY"}}}},
      "Job": {{"offset": {ep_job}, "type": {{"kind": "pointer",
              "subtype": {{"kind": "struct", "name": "_EJOB"}}}}}},
      "DirectoryTableBase": {{"offset": {ep_dtb}, "type": {{"kind": "base",
                             "name": "unsigned long long"}}}}{job_links}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{"PsActiveProcessHead": {{"address": {head}}}}}
}}"#,
        base = BASE_TYPES_X64,
        ejob = ejob,
        ep_pid = EP_PID,
        ep_name = EP_NAME,
        ep_links = EP_LINKS,
        ep_job = EP_JOB,
        ep_dtb = EP_DTB,
        job_links = job_links,
        head = PS_ACTIVE_HEAD,
    )
}

/// `(address, pid, name, job pointer)` per process.
fn image(processes: &[(u64, u64, &str, u64)], job: Option<(u64, u64, u64, u64, &[u64])>) -> Image {
    let mut img = Image::sized(0x2_0000);
    // The active process list, in order, closing back on the head.
    let mut previous = PS_ACTIVE_HEAD;
    for (address, pid, name, job_pointer) in processes {
        let link = address + EP_LINKS;
        img.put_u64(previous, link);
        img.put_u64(link + 8, previous);
        previous = link;
        img.put_u64(address + EP_PID, *pid);
        img.write(address + EP_NAME, name.as_bytes());
        img.put_u8(address + EP_NAME + name.len() as u64, 0);
        img.put_u64(address + EP_JOB, *job_pointer);
        img.put_u64(address + EP_DTB, 0x1000);
    }
    img.put_u64(previous, PS_ACTIVE_HEAD);
    img.put_u64(PS_ACTIVE_HEAD + 8, previous);

    if let Some((job, total, active, terminated, members)) = job {
        img.put_u32(job + EJ_TOTAL, total as u32);
        img.put_u32(job + EJ_ACTIVE, active as u32);
        img.put_u32(job + EJ_TERMINATED, terminated as u32);
        img.put_u32(job + EJ_SESSION, 1);
        // The member list threads through `_EPROCESS.JobLinks`.
        let head = job + EJ_PROCESS_LIST;
        let mut previous = head;
        for member in members {
            let link = member + EP_JOB_LINKS;
            img.put_u64(previous, link);
            img.put_u64(link + 8, previous);
            previous = link;
        }
        img.put_u64(previous, head);
        img.put_u64(head + 8, previous);
    }
    img
}

fn survey(
    processes: &[(u64, u64, &str, u64)],
    job: Option<(u64, u64, u64, u64, &[u64])>,
    d: Declares,
) -> Result<JobSurvey, JobError> {
    let isf_text = isf(d);
    let profile = profile(
        image(processes, job).layer(),
        table(&isf_text),
        Architecture::X64,
        10,
        0,
        Some(22000),
    );
    let symbols = JobSymbols::from_profile(&profile)?;
    let ps = ProcessSymbols::from_profile(&profile).expect("process symbols");
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).expect("the list");
    survey_jobs(&profile, &symbols, &list)
}

/// **A process with no job is the ordinary case**, is not a row, and is
/// counted — so an empty list cannot read as a walk that failed.
#[test]
fn processes_with_no_job_are_counted_and_not_reported() {
    let out = survey(
        &[(PROCESS_A, 100, "a.exe", 0), (PROCESS_B, 200, "b.exe", 0)],
        None,
        Declares::default(),
    )
    .expect("the survey runs");
    assert!(out.jobs.is_empty());
    assert_eq!(out.processes_walked, 2);
    assert_eq!(out.processes_without_a_job, 2);
    assert_eq!(out.processes_in_a_job(), 0);
    let j = out.to_json();
    assert_eq!(j["processes_without_a_job"], serde_json::json!(2));
    assert!(
        out.describe().contains("ordinary case"),
        "got {}",
        out.describe()
    );
}

/// A job with two members is one record naming both.
#[test]
fn a_job_is_one_record_with_its_members_walked() {
    let out = survey(
        &[
            (PROCESS_A, 100, "a.exe", JOB_A),
            (PROCESS_B, 200, "b.exe", JOB_A),
            (PROCESS_C, 300, "c.exe", 0),
        ],
        Some((JOB_A, 2, 2, 0, &[PROCESS_A, PROCESS_B])),
        Declares::default(),
    )
    .expect("survey");

    assert_eq!(out.jobs.len(), 1, "one record per distinct job object");
    let job = &out.jobs[0];
    assert_eq!(job.job, JOB_A);
    assert_eq!(job.named_by, vec![PROCESS_A, PROCESS_B]);
    assert_eq!(job.members.len(), 2);
    assert_eq!(job.members[0].process, PROCESS_A);
    assert_eq!(job.members[0].pid, Some(100));
    assert_eq!(job.members[0].name.as_deref(), Some("a.exe"));
    assert_eq!(job.session_id, Some(1));
    assert_eq!(job.total_processes, Some(2));
    assert_eq!(job.active_processes, Some(2));
    assert_eq!(job.counter_agrees(), Some(true));
    assert_eq!(out.processes_without_a_job, 1);
    assert!(out.is_complete());
    // And the record says why it is one row where upstream prints two.
    assert!(
        out.to_json()["row_shape_note"]
            .as_str()
            .unwrap_or_default()
            .contains("printed three times"),
        "the row-shape difference from upstream is stated"
    );
}

/// **The counter and the list are both reported, and a disagreement is
/// visible.** A job whose counter exceeds its list is mid-teardown or has had
/// a member unlinked.
#[test]
fn a_counter_that_disagrees_with_the_list_is_reported_rather_than_preferred() {
    let out = survey(
        &[(PROCESS_A, 100, "a.exe", JOB_A)],
        // The kernel claims four active; the list holds one.
        Some((JOB_A, 4, 4, 0, &[PROCESS_A])),
        Declares::default(),
    )
    .expect("survey");
    let job = &out.jobs[0];
    assert_eq!(job.active_processes, Some(4));
    assert_eq!(job.members.len(), 1);
    assert_eq!(job.counter_agrees(), Some(false));
    let j = job.to_json();
    assert_eq!(j["counter_agrees_with_the_list"], serde_json::json!(false));
    assert!(
        j["counter_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("different facts"),
        "got {:?}",
        j["counter_basis"]
    );
}

/// **A member the active process list does not hold is the interesting case**,
/// and it is only a statement when that list walked end to end.
#[test]
fn a_member_outside_the_process_list_is_named_only_when_the_list_was_complete() {
    let out = survey(
        &[(PROCESS_A, 100, "a.exe", JOB_A)],
        // The job names a process the active list never linked.
        Some((JOB_A, 2, 2, 0, &[PROCESS_A, PROCESS_C])),
        Declares::default(),
    )
    .expect("survey");
    assert!(out.process_list_complete, "this fixture's list wraps");
    let job = &out.jobs[0];
    assert_eq!(job.members.len(), 2);
    let outside: Vec<u64> = job
        .members
        .iter()
        .filter(|m| m.in_the_process_list == Some(false))
        .map(|m| m.process)
        .collect();
    assert_eq!(outside, vec![PROCESS_C]);
    assert_eq!(out.members_outside_the_process_list(), 1);
}

/// **A build with no `_EJOB` is refused, not answered with an empty list.**
#[test]
fn a_build_without_the_job_type_is_refused_with_the_reason() {
    let err = survey(
        &[(PROCESS_A, 100, "a.exe", 0)],
        None,
        Declares {
            ejob: false,
            ..Declares::default()
        },
    )
    .expect_err("no _EJOB means no job can be read");
    assert_eq!(err.class(), "unsupported_build");
    assert!(err.detail().contains("_EJOB"), "got {}", err.detail());
    assert!(
        err.detail().contains("nothing can be said"),
        "got {}",
        err.detail()
    );
}

/// A build with `_EJOB` but no `JobLinks` is refused too: without the link the
/// member list cannot be walked, and a job with no members would be a wrong
/// answer rather than a short one.
#[test]
fn a_build_without_the_member_link_is_refused() {
    let err = survey(
        &[(PROCESS_A, 100, "a.exe", 0)],
        None,
        Declares {
            job_links: false,
            ..Declares::default()
        },
    )
    .expect_err("no JobLinks means no member can be recovered");
    assert!(err.detail().contains("JobLinks"), "got {}", err.detail());
}

/// A build with no counters still reads the members, and the counter
/// comparison is `None` — which is not agreement.
#[test]
fn without_the_counters_the_comparison_is_unavailable_rather_than_agreement() {
    let out = survey(
        &[(PROCESS_A, 100, "a.exe", JOB_A)],
        Some((JOB_A, 1, 1, 0, &[PROCESS_A])),
        Declares {
            counters: false,
            ..Declares::default()
        },
    )
    .expect("survey");
    let job = &out.jobs[0];
    assert_eq!(job.active_processes, None);
    assert_eq!(job.total_processes, None);
    assert_eq!(
        job.counter_agrees(),
        None,
        "no counter to compare is not a counter that agrees"
    );
    assert_eq!(job.members.len(), 1, "the members are still walked");
}

/// A member list that never returns to its head is stated, and the survey is
/// not complete.
#[test]
fn a_member_list_that_does_not_wrap_is_stated() {
    let isf_text = isf(Declares::default());
    let mut img = image(
        &[(PROCESS_A, 100, "a.exe", JOB_A)],
        Some((JOB_A, 1, 1, 0, &[PROCESS_A])),
    );
    // Point the one member's link at itself: a chain that never comes back.
    img.put_u64(PROCESS_A + EP_JOB_LINKS, PROCESS_A + EP_JOB_LINKS);
    let profile = profile(
        img.layer(),
        table(&isf_text),
        Architecture::X64,
        10,
        0,
        Some(22000),
    );
    let symbols = JobSymbols::from_profile(&profile).expect("symbols");
    let ps = ProcessSymbols::from_profile(&profile).expect("process symbols");
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).expect("list");
    let out = survey_jobs(&profile, &symbols, &list).expect("survey");
    let job = &out.jobs[0];
    assert!(job.stop.is_some(), "the abnormal ending is recorded");
    assert!(!out.is_complete());
    assert!(!out.incomplete().is_empty());
}

/// Every resolved path is on the record, including `JobLinks`' offset — which
/// every member address rests on.
#[test]
fn the_resolved_paths_and_the_containing_record_offset_are_published() {
    let out = survey(&[(PROCESS_A, 100, "a.exe", 0)], None, Declares::default()).expect("survey");
    let j = out.symbols.to_json();
    assert_eq!(j["job_path"], serde_json::json!("Job"));
    assert_eq!(j["job_links_path"], serde_json::json!("JobLinks"));
    assert_eq!(j["job_links_offset"], serde_json::json!(EP_JOB_LINKS));
    assert_eq!(
        j["process_list_head_path"],
        serde_json::json!("ProcessListHead")
    );
    assert!(
        j["basis"]
            .as_str()
            .unwrap_or_default()
            .contains("CONTAINING_RECORD"),
        "got {:?}",
        j["basis"]
    );
}
