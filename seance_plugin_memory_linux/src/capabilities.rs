//! Linux process capability sets: interpreting `cred.cap_*` bitmasks.
//!
//! A `kernel_cap_t` is a 64-bit mask over the POSIX capabilities; bit *n* is the
//! capability whose number is *n* in `<linux/capability.h>`. On every kernel
//! this reader supports the mask is 8 bytes little-endian at the member offset —
//! the historical `struct { __u32 cap[2] }` stores cap[0] (caps 0–31) then cap[1]
//! (caps 32–63), which read as one little-endian `u64` is exactly the modern
//! `struct { u64 val }`. So the *value* needs no per-build type distinction; only
//! the member *offset* is build-specific, and that comes from the symbols.
//!
//! This module is the interpretation the rest of the tier's `Field` machinery
//! feeds: given a mask, which named capabilities are held. It is the worked
//! example the crate docs keep pointing at.

use seance_core::io::IncompleteReason;
use seance_memory::binding::Field;
use seance_memory::meta::Incomplete;

use crate::read::signed_to_json;
use crate::tasks::{CapabilityFields, TaskList, TaskRecord};

/// Capability names indexed by bit number, from `<linux/capability.h>`.
/// `CAP_LAST_CAP` is 40 (CAP_CHECKPOINT_RESTORE) as of Linux 5.9.
pub const CAP_NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// The mask with every currently-defined capability set — what a fully
/// privileged process (e.g. `init`) carries in its effective set.
pub fn full_mask() -> u64 {
    (0..CAP_NAMES.len()).fold(0u64, |m, i| m | (1u64 << i))
}

/// Decode a capability mask into the names of the capabilities it holds, in bit
/// order. A bit above the known range is rendered as `CAP_<n>` rather than
/// dropped, so a newer kernel's capability is reported, not silently lost.
pub fn decode(mask: u64) -> Vec<String> {
    let mut out = Vec::new();
    for bit in 0..64 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        match CAP_NAMES.get(bit) {
            Some(name) => out.push((*name).to_string()),
            None => out.push(format!("CAP_{bit}")),
        }
    }
    out
}

/// Whether `mask` holds the capability with the given bit number.
pub fn holds(mask: u64, bit: usize) -> bool {
    bit < 64 && mask & (1u64 << bit) != 0
}

// ── The capabilities stage ──────────────────────────────────────────────────
//
// Everything above interprets a mask. Everything below is the analysis stage
// that projects each process's five masks — read once, during the task-list
// walk — into a record at parity with Volatility's `linux.capabilities`.

/// What a capability list projected from the task walk can and cannot claim.
///
/// Attached to the artifact rather than kept in documentation, for the reason
/// every scope note in this crate is: records are read individually, and a
/// caveat that lives elsewhere is one that gets separated from the finding it
/// qualifies.
pub const CAPABILITY_SCOPE_NOTE: &str =
    "These capability sets were read from each process's `cred` during the task-list walk, so \
     this list covers exactly the processes that walk reached. A `task_struct` unlinked from the \
     kernel's task list — the standard way of hiding a process on Linux — keeps running with \
     whatever capabilities the kernel granted it, and does not appear here. A set shown as \
     not-declared is one this kernel build never had (the ambient set does not exist before \
     Linux 4.3); that is a fact about the kernel, and is not the same as a process holding no \
     capabilities in that set.";

/// One process's capability sets.
///
/// The sets are read once, in [`crate::tasks`], and re-presented here per
/// process; this stage reads no kernel memory of its own. Re-reading would be a
/// second chance to disagree with the process list about the same bytes.
#[derive(Debug, Clone)]
pub struct CapabilityRow {
    /// Address of the `task_struct`, the handle every memory finding shares.
    pub address: u64,
    /// The POSIX process id (`tgid`) — what `ps` prints.
    pub pid: Field<i64>,
    /// The thread id (`task_struct.pid`), which Volatility's
    /// `linux.capabilities` prints beside the process id.
    pub tid: Field<i64>,
    /// The parent process id, one of Volatility's columns.
    pub ppid: Field<i64>,
    /// The process name.
    pub comm: Field<String>,
    /// The effective user id — the privilege the capability sets qualify.
    pub euid: Field<i64>,
    /// The five capability sets, exactly as the task walk read them.
    pub capabilities: CapabilityFields,
}

impl CapabilityRow {
    fn from_task(task: &TaskRecord) -> Self {
        Self {
            address: task.address,
            pid: task.pid.clone(),
            tid: task.tid.clone(),
            ppid: task.ppid.clone(),
            comm: task.comm.clone(),
            euid: task.euid.clone(),
            capabilities: task.capabilities.clone(),
        }
    }

    /// Serializable form for the capabilities artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "pid": signed_to_json(&self.pid),
            "tid": signed_to_json(&self.tid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "euid": signed_to_json(&self.euid),
            "capabilities": self.capabilities.to_json(),
            "unreadable_capability_sets": self.capabilities.unreadable(),
        })
    }
}

/// Every process's capability sets, and everything that qualifies the list.
#[derive(Debug, Clone)]
pub struct CapabilitySurvey {
    /// One row per process the task-list walk reached.
    pub rows: Vec<CapabilityRow>,
    /// Whether the task-list walk this rests on finished end to end with every
    /// field read.
    task_complete: bool,
    /// The task walk's own reasons for being short, folded in because a
    /// projection of that walk can be no more complete than the walk itself.
    task_incomplete: Vec<Incomplete>,
}

/// Project the already-walked task list into per-process capability rows.
///
/// Takes no reader and reads no kernel memory: the masks were read during the
/// task-list walk, and this only re-presents them.
pub fn survey_capabilities(tasks: &TaskList) -> CapabilitySurvey {
    CapabilitySurvey {
        rows: tasks.tasks.iter().map(CapabilityRow::from_task).collect(),
        task_complete: tasks.is_complete(),
        task_incomplete: tasks.incomplete(),
    }
}

impl CapabilitySurvey {
    /// The number of processes whose capabilities are listed.
    pub fn count(&self) -> usize {
        self.rows.len()
    }

    /// Whether the walk finished and every process had every capability set
    /// read.
    ///
    /// A set this kernel never had — the ambient set before Linux 4.3 — is
    /// [`Field::NotDeclared`], an answer rather than a gap, and does not make the
    /// list incomplete. Only a set whose bytes should have read and did not
    /// does, which is why this consults [`CapabilityFields::unreadable`] rather
    /// than [`TaskList::is_complete`] alone — the task list does not look at
    /// capability fields at all.
    pub fn is_complete(&self) -> bool {
        self.task_complete
            && self
                .rows
                .iter()
                .all(|row| row.capabilities.unreadable().is_empty())
    }

    /// Everything a report must declare: the task walk's own shortfalls, plus
    /// any process whose capability sets could not be read.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.task_incomplete.clone();
        for row in &self.rows {
            let unreadable = row.capabilities.unreadable();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the cred at the task_struct at {:#x} has capability set(s) that exist on \
                         this build and could not be read: {}",
                        row.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for the capabilities artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.rows.len(),
            "complete": self.is_complete(),
            "enumeration_method": "task_list_projection",
            "enumeration_scope_note": CAPABILITY_SCOPE_NOTE,
            "corroborated_by_second_method": false,
            "processes": self.rows.iter().map(CapabilityRow::to_json).collect::<Vec<_>>(),
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_bits_map_to_the_right_names() {
        // Anchored to <linux/capability.h>, not to our own output.
        assert_eq!(CAP_NAMES[0], "CAP_CHOWN");
        assert_eq!(CAP_NAMES[21], "CAP_SYS_ADMIN");
        assert_eq!(CAP_NAMES[13], "CAP_NET_RAW");
        assert_eq!(CAP_NAMES[40], "CAP_CHECKPOINT_RESTORE");
    }

    #[test]
    fn decode_lists_held_capabilities_in_order() {
        // Bits 0 (CHOWN), 21 (SYS_ADMIN), 13 (NET_RAW).
        let mask = (1 << 0) | (1 << 13) | (1 << 21);
        assert_eq!(
            decode(mask),
            vec!["CAP_CHOWN", "CAP_NET_RAW", "CAP_SYS_ADMIN"]
        );
    }

    #[test]
    fn an_empty_mask_holds_nothing() {
        assert!(decode(0).is_empty());
    }

    #[test]
    fn the_full_mask_decodes_to_every_named_capability() {
        let decoded = decode(full_mask());
        assert_eq!(decoded.len(), CAP_NAMES.len());
        assert_eq!(decoded[0], "CAP_CHOWN");
        assert_eq!(decoded.last().unwrap(), "CAP_CHECKPOINT_RESTORE");
    }

    #[test]
    fn a_bit_above_the_known_range_is_reported_not_dropped() {
        // A future kernel defines CAP 41; we do not know its name but must not
        // pretend the process lacks it.
        let decoded = decode(1u64 << 45);
        assert_eq!(decoded, vec!["CAP_45"]);
    }

    #[test]
    fn holds_checks_a_single_bit() {
        let mask = 1u64 << 21;
        assert!(holds(mask, 21));
        assert!(!holds(mask, 20));
        assert!(!holds(mask, 200));
    }

    #[test]
    fn little_endian_two_word_layout_reads_as_one_mask() {
        // The historical struct { u32 cap[2] }: cap[0]=caps 0-31, cap[1]=caps
        // 32-63. Bytes on disk for {cap[0]=0x00000001, cap[1]=0x00000100} are
        // 01 00 00 00 00 01 00 00; as one LE u64 that is bit 0 and bit 40.
        let bytes = [0x01, 0, 0, 0, 0x00, 0x01, 0, 0];
        let mask = u64::from_le_bytes(bytes);
        assert!(holds(mask, 0)); // CAP_CHOWN
        assert!(holds(mask, 40)); // CAP_CHECKPOINT_RESTORE (bit 8 of cap[1])
        assert_eq!(decode(mask), vec!["CAP_CHOWN", "CAP_CHECKPOINT_RESTORE"]);
    }
}

#[cfg(test)]
mod stage_tests {
    use super::*;
    use seance_memory::object::ListStop;

    /// A `CapabilityFields` with the five sets set as named.
    fn caps(
        effective: Field<u64>,
        permitted: Field<u64>,
        inheritable: Field<u64>,
        bounding: Field<u64>,
        ambient: Field<u64>,
    ) -> CapabilityFields {
        CapabilityFields {
            effective,
            permitted,
            inheritable,
            bounding,
            ambient,
        }
    }

    /// The five sets of a fully privileged process on a pre-4.3 kernel: every
    /// set full, ambient not declared because the kernel never had it.
    fn root_caps_pre_4_3() -> CapabilityFields {
        caps(
            Field::Known(full_mask()),
            Field::Known(full_mask()),
            Field::Known(0),
            Field::Known(full_mask()),
            Field::NotDeclared {
                member: "cap_ambient",
            },
        )
    }

    /// A task with every field the task list checks for completeness read, so
    /// that a `TaskList` built from it is complete unless a test makes it
    /// otherwise. Only the capability sets vary between tests.
    fn clean_task(
        address: u64,
        pid: i64,
        comm: &str,
        capabilities: CapabilityFields,
    ) -> TaskRecord {
        let mut task = TaskRecord::address_only_for_test(address);
        task.tid = Field::Known(pid);
        task.pid = Field::Known(pid);
        task.ppid = Field::Known(0);
        task.comm = Field::Known(comm.to_string());
        task.state = Field::Known(0);
        task.exit_state = Field::Known(0);
        task.flags = Field::Known(0);
        task.kernel_thread = Field::Known(false);
        task.mm = Field::Known(0);
        task.uid = Field::Known(0);
        task.gid = Field::Known(0);
        task.euid = Field::Known(0);
        task.egid = Field::Known(0);
        task.start_time = Field::Known(0);
        task.capabilities = capabilities;
        task
    }

    fn task_list(tasks: Vec<TaskRecord>, stop: ListStop) -> TaskList {
        TaskList {
            init_task: 0xFFFF_FFFF_8160_0000,
            head: 0xFFFF_FFFF_8160_0170,
            links_offset: 368,
            tasks,
            stop,
            layout: serde_json::json!({"stage": "linux_processes"}),
        }
    }

    #[test]
    fn each_process_row_carries_its_decoded_capability_sets() {
        let survey = survey_capabilities(&task_list(
            vec![clean_task(
                0x1000,
                1,
                "init",
                caps(
                    Field::Known((1 << 21) | (1 << 0)), // CAP_SYS_ADMIN, CAP_CHOWN
                    Field::Known(full_mask()),
                    Field::Known(0),
                    Field::Known(full_mask()),
                    Field::NotDeclared {
                        member: "cap_ambient",
                    },
                ),
            )],
            ListStop::Wrapped,
        ));

        assert_eq!(survey.count(), 1);
        let json = survey.to_json();
        assert_eq!(json["count"], 1);
        let row = &json["processes"][0];
        assert_eq!(row["pid"]["value"], 1);
        assert_eq!(row["tid"]["value"], 1);
        assert_eq!(row["comm"]["value"], "init");

        let effective = row["capabilities"]["effective"]["capabilities"]
            .as_array()
            .expect("effective is a Known set with a decoded list");
        assert!(effective.iter().any(|v| v == "CAP_SYS_ADMIN"));
        assert!(effective.iter().any(|v| v == "CAP_CHOWN"));
    }

    #[test]
    fn a_capability_set_this_kernel_never_had_is_an_answer_not_a_gap() {
        // Ambient does not exist before Linux 4.3. It must render as
        // not_declared — never as an empty capability list, which would say the
        // process holds no ambient capabilities when the truth is the set does
        // not exist on this kernel — and it must not make the list incomplete.
        let survey = survey_capabilities(&task_list(
            vec![clean_task(0x1000, 1, "init", root_caps_pre_4_3())],
            ListStop::Wrapped,
        ));

        assert!(
            survey.is_complete(),
            "a set the kernel never had is not a gap: {:?}",
            survey.incomplete()
        );
        let row = survey.to_json();
        assert_eq!(
            row["processes"][0]["capabilities"]["ambient"]["not_declared"],
            "cap_ambient"
        );
        assert!(
            row["processes"][0]["capabilities"]["ambient"]
                .get("capabilities")
                .is_none(),
            "an absent set has no decoded list to show"
        );
    }

    #[test]
    fn a_capability_set_whose_bytes_did_not_read_is_a_gap_named_on_the_row() {
        // A set that exists on this build and whose bytes were not acquired is
        // damage, and must be counted against completeness and named — the one
        // process an examiner most wants to see is the one whose cred did not
        // read.
        let survey = survey_capabilities(&task_list(
            vec![clean_task(
                0x2000,
                42,
                "sneaky",
                caps(
                    Field::Unavailable("the cred page was not acquired".into()),
                    Field::Known(0),
                    Field::Known(0),
                    Field::Known(0),
                    Field::NotDeclared {
                        member: "cap_ambient",
                    },
                ),
            )],
            ListStop::Wrapped,
        ));

        assert!(!survey.is_complete());
        let reasons = survey.incomplete();
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].detail.contains("cap_effective"),
            "the unreadable set must be named: {:?}",
            reasons[0]
        );

        let json = survey.to_json();
        assert_eq!(json["complete"], false);
        assert_eq!(
            json["processes"][0]["unreadable_capability_sets"][0],
            "cap_effective"
        );
    }

    #[test]
    fn the_list_is_no_more_complete_than_the_walk_it_projects() {
        // Every capability set read, but the underlying task walk stopped short
        // of enumerating the whole list. The projection cannot be more complete
        // than its source, and must fold in the walk's own reason.
        let survey = survey_capabilities(&task_list(
            vec![clean_task(0x3000, 1, "init", root_caps_pre_4_3())],
            ListStop::NullLink { at: 0x1000 },
        ));

        assert!(!survey.is_complete());
        assert!(
            survey
                .incomplete()
                .iter()
                .any(|reason| reason.detail.contains("task list")),
            "the walk's own shortfall must be carried: {:?}",
            survey.incomplete()
        );
    }

    #[test]
    fn the_record_states_it_cannot_see_a_process_hidden_from_the_task_list() {
        let survey = survey_capabilities(&task_list(Vec::new(), ListStop::Wrapped));
        let json = survey.to_json();

        assert_eq!(json["count"], 0);
        assert_eq!(json["enumeration_method"], "task_list_projection");
        assert_eq!(json["corroborated_by_second_method"], false);
        let note = json["enumeration_scope_note"]
            .as_str()
            .expect("a scope note");
        assert!(note.contains("unlinked"), "must name the technique: {note}");
        assert!(
            note.contains("4.3"),
            "must explain the ambient not-declared case: {note}"
        );
    }
}
