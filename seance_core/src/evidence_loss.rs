//! A record of evidence this process could not persist.
//!
//! # The problem this exists for
//!
//! The artifact writer buffers and retries. If the database stays unavailable
//! long enough for the buffer to exceed its cap, the oldest unpersisted
//! artifacts are dropped — there is no third option once memory is bounded, and
//! it is logged at `error!` naming every identifier.
//!
//! A log line is not enough. The case database is the only thing a report is
//! built from, and an artifact that never reached it is invisible there: the
//! report renders a complete-looking account of an examination that silently
//! lost part of its evidence. `documentation/REPORTING_DESIGN.md` states the
//! rule this breaks — *a report must never be silent about a limitation that
//! would change how a finding is read* — and nothing is more that than
//! "some of what was found is not in here".
//!
//! # Why a process-global counter rather than a database row
//!
//! Because the database is the thing that failed. Recording the loss where the
//! loss occurred would require the write path that just proved it does not
//! work.
//!
//! So it is held in memory, for the life of the process, and read by the
//! reporting layer when a report is generated — which necessarily happens with
//! a working database, because a report cannot be built without one. The
//! trade-off is explicit: a loss followed by a crash before any report is
//! generated leaves only the log. That is strictly better than the log alone,
//! and the alternative — a durable queue that survives the database being down
//! — is a subsystem, not a release fix.
//!
//! # What it must never do
//!
//! Fail, block, or allocate unboundedly on the path that reports a loss. This
//! is called from an error handler during a failure; anything it does that can
//! itself fail would turn a recorded loss into an unrecorded one.

use std::sync::Mutex;

/// Identifiers retained per cause for the report. A cap, because the losing
/// path may run many times and this holds memory during an incident that is
/// already about resource exhaustion. The *count* is exact regardless.
const MAX_RETAINED_IDS: usize = 256;

/// Why evidence was lost. The causes are different findings and a report must
/// not state one in the words of another: a task-queue spill failure has
/// nothing to do with the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossCause {
    /// Artifacts the writer could not persist and discarded: its bounded buffer
    /// overflowed, its final flush failed, or its channel closed.
    NotWritten,
    /// Artifacts that were found and queued but never processed, because the
    /// queue could not read them back.
    NeverProcessed,
    /// Processing-log rows (the record of which modules ran) that could not be
    /// saved. The artifacts those modules produced are not part of this loss.
    ProcessingLog,
}

impl LossCause {
    fn slot(self) -> usize {
        self as usize
    }
}

/// What one cause has lost.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CauseLoss {
    /// Items lost for this cause. Exact.
    pub dropped: u64,
    /// What the first failure for this cause reported.
    pub first_reason: Option<String>,
    /// Identifiers of the lost items, capped at [`MAX_RETAINED_IDS`];
    /// `ids_truncated` says when the list is short.
    pub ids: Vec<String>,
    /// True when more were lost than are listed.
    pub ids_truncated: bool,
}

static STATE: Mutex<[CauseLoss; 3]> = Mutex::new([
    CauseLoss {
        dropped: 0,
        first_reason: None,
        ids: Vec::new(),
        ids_truncated: false,
    },
    CauseLoss {
        dropped: 0,
        first_reason: None,
        ids: Vec::new(),
        ids_truncated: false,
    },
    CauseLoss {
        dropped: 0,
        first_reason: None,
        ids: Vec::new(),
        ids_truncated: false,
    },
]);

/// Record that `count` items were lost for `cause`.
///
/// `reason` should say what failed; the first one seen per cause is kept,
/// because the first failure is the one that explains the incident and later
/// ones are usually the same cause restated.
pub fn record(cause: LossCause, count: usize, reason: &str, ids: impl IntoIterator<Item = String>) {
    if count == 0 {
        return;
    }
    // `unwrap_or_else(into_inner)`: a poisoned lock means another thread
    // panicked while recording a loss. Refusing to record this one because of
    // that would compound the very failure being reported.
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let slot = &mut state[cause.slot()];
    slot.dropped += count as u64;
    if slot.first_reason.is_none() {
        slot.first_reason = Some(reason.to_string());
    }
    for id in ids {
        if slot.ids.len() >= MAX_RETAINED_IDS {
            break;
        }
        slot.ids.push(id);
    }
    slot.ids_truncated = slot.dropped > slot.ids.len() as u64;
}

/// What this process has lost, if anything, by cause.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceLoss {
    /// Artifacts the writer could not persist.
    pub not_written: CauseLoss,
    /// Artifacts found but never processed.
    pub never_processed: CauseLoss,
    /// Processing-log rows that could not be saved.
    pub processing_log: CauseLoss,
}

fn first_failure(loss: &CauseLoss) -> String {
    match &loss.first_reason {
        Some(why) => format!(" The first failure reported: {why}."),
        None => String::new(),
    }
}

impl EvidenceLoss {
    /// Whether anything was lost.
    pub fn occurred(&self) -> bool {
        self.not_written.dropped + self.never_processed.dropped + self.processing_log.dropped > 0
    }

    /// The heading a report puts over [`Self::statement`]. It names the cause
    /// when exactly one occurred, so a queue read-back failure is not headed
    /// "artifacts could not be saved" and a lost processing-log row is not
    /// headed as lost artifacts (CR-047). Several causes get the general one.
    pub fn subject(&self) -> &'static str {
        match (
            self.not_written.dropped > 0,
            self.never_processed.dropped > 0,
            self.processing_log.dropped > 0,
        ) {
            (true, false, false) => "Incomplete record \u{2014} artifacts could not be saved",
            (false, true, false) => "Incomplete record \u{2014} artifacts not processed",
            (false, false, true) => "Incomplete record \u{2014} processing log not saved",
            _ => "Incomplete record \u{2014} evidence lost",
        }
    }

    /// What a report should say, one passage per cause that occurred, each in
    /// its own words. Written to be read aloud.
    pub fn statement(&self) -> String {
        let mut passages: Vec<String> = Vec::new();
        let l = &self.not_written;
        if l.dropped > 0 {
            passages.push(format!(
                "During this examination {} artifact(s) could not be written to the case \
                 database and were discarded: the writer could not persist them (the database \
                 was unavailable for long enough that the writer's bounded buffer overflowed, \
                 or the writer stopped).{} This report is therefore incomplete by that number \
                 of records, and the findings it does contain should be read as a subset of \
                 what the examination produced. The affected identifiers are recorded in the \
                 tool's log. Re-running the ingest against the same evidence, with the \
                 database available, should recover them; confirm that the re-run reports no \
                 such loss.",
                l.dropped,
                first_failure(l)
            ));
        }
        let l = &self.never_processed;
        if l.dropped > 0 {
            passages.push(format!(
                "During this examination {} artifact(s) were found but never processed: they \
                 were queued, and the queue could not read them back.{} No module examined \
                 them, so anything they would have produced is absent from this report, and the \
                 findings it does contain should be read as a subset. The affected identifiers \
                 are recorded in the tool's log. Re-running the ingest may examine them, but \
                 only if the fault on the queue's spill storage does not recur.",
                l.dropped,
                first_failure(l)
            ));
        }
        let l = &self.processing_log;
        if l.dropped > 0 {
            passages.push(format!(
                "During this examination {} processing-log row(s) could not be saved.{} The \
                 artifacts that those modules produced are not affected, but this report's \
                 account of which modules ran, and of any module error, is incomplete: a module \
                 with no entry here may have run.",
                l.dropped,
                first_failure(l)
            ));
        }
        passages.join(" ")
    }
}

/// Read what has been lost so far.
pub fn snapshot() -> EvidenceLoss {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let [not_written, never_processed, processing_log] = state;
    EvidenceLoss {
        not_written,
        never_processed,
        processing_log,
    }
}

/// The state is process-global, so tests that read or reset it run under this
/// one lock rather than racing each other into false results.
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

/// Reset. **Tests only** — a process that clears this in production would be
/// erasing the record of an incident.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = Default::default();
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::TEST_SERIAL as SERIAL;

    #[test]
    fn a_clean_process_reports_no_loss() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        let snap = snapshot();
        assert!(!snap.occurred());
        assert_eq!(snap.not_written.dropped, 0);
    }

    #[test]
    fn a_loss_is_counted_exactly_and_explains_itself() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        record(
            LossCause::NotWritten,
            3,
            "database is locked",
            ["a".into(), "b".into(), "c".into()],
        );
        record(
            LossCause::NotWritten,
            2,
            "a later, different failure",
            ["d".into(), "e".into()],
        );

        let snap = snapshot();
        assert!(snap.occurred());
        assert_eq!(
            snap.not_written.dropped, 5,
            "the count must be exact across both"
        );
        assert_eq!(
            snap.not_written.first_reason.as_deref(),
            Some("database is locked"),
            "the FIRST failure explains the incident; later ones restate it"
        );
        assert!(!snap.not_written.ids_truncated);
        assert_eq!(snap.not_written.ids.len(), 5);

        let statement = snap.statement();
        assert!(statement.contains('5'));
        assert!(
            statement.contains("incomplete"),
            "a report reading this must be told the account is not complete"
        );
        assert!(
            statement.contains("database is locked"),
            "the cause belongs in the statement"
        );
    }

    /// CR-047. The heading follows the cause. SYNTHETIC values, built directly
    /// so the process-global state is not touched.
    #[test]
    fn the_heading_names_the_cause_that_occurred() {
        let lost = |n| CauseLoss {
            dropped: n,
            ..Default::default()
        };
        let only = |nw, np, pl| EvidenceLoss {
            not_written: lost(nw),
            never_processed: lost(np),
            processing_log: lost(pl),
        };
        assert!(only(1, 0, 0)
            .subject()
            .ends_with("artifacts could not be saved"));
        assert!(only(0, 1, 0).subject().ends_with("artifacts not processed"));
        assert!(only(0, 0, 1)
            .subject()
            .ends_with("processing log not saved"));
        assert!(only(1, 1, 0).subject().ends_with("evidence lost"));
        assert!(only(0, 1, 1).subject().ends_with("evidence lost"));
    }

    /// A task-queue spill failure is not a database failure, and the report
    /// must not say it was.
    #[test]
    fn a_spill_only_loss_does_not_mention_the_database() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        record(
            LossCause::NeverProcessed,
            1,
            "task-queue spill read-back failed: short read",
            ["x".into()],
        );
        let statement = snapshot().statement();
        assert!(statement.contains("never processed"), "{statement}");
        assert!(statement.contains("short read"), "{statement}");
        assert!(
            !statement.to_lowercase().contains("database"),
            "{statement}"
        );
        assert!(!statement.contains("could not be written"), "{statement}");
    }

    /// Each cause that occurred is stated in its own words, and only those.
    #[test]
    fn each_cause_is_worded_separately() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        record(LossCause::ProcessingLog, 4, "database is locked", []);
        let only_log = snapshot().statement();
        assert!(only_log.contains("processing-log row"), "{only_log}");
        assert!(!only_log.contains("artifact(s)"), "{only_log}");

        record(LossCause::NotWritten, 1, "closed", ["id".into()]);
        let both = snapshot().statement();
        assert!(both.contains("processing-log row"), "{both}");
        assert!(both.contains("could not be written"), "{both}");
    }

    /// A zero-count call is not a loss and must not create one.
    #[test]
    fn recording_nothing_records_nothing() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        record(LossCause::NotWritten, 0, "nothing happened", []);
        assert!(!snapshot().occurred());
    }

    /// **The count stays exact when the identifier list is capped.**
    ///
    /// The list is bounded because this holds memory during an incident that is
    /// already about resource exhaustion. Letting the cap bound the *count*
    /// would understate the loss, which is the one number that must not be
    /// wrong.
    #[test]
    fn capping_the_identifier_list_does_not_cap_the_count() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        let many: Vec<String> = (0..MAX_RETAINED_IDS + 500).map(|i| i.to_string()).collect();
        record(
            LossCause::NotWritten,
            many.len(),
            "sustained failure",
            many.clone(),
        );

        let snap = snapshot().not_written;
        assert_eq!(snap.dropped, many.len() as u64, "the count must be exact");
        assert_eq!(snap.ids.len(), MAX_RETAINED_IDS, "the list is bounded");
        assert!(
            snap.ids_truncated,
            "a truncated list must say so, or it reads as the whole of the loss"
        );
    }
}
