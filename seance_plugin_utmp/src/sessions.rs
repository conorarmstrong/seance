//! Reconstruction of login sessions, and of the boot/shutdown brackets that
//! contain them, from a stream of `struct utmp` records.
//!
//! A `wtmp` file does not store sessions; it stores the two ends of one. Pairing
//! a `USER_PROCESS` with the `DEAD_PROCESS` that closed the same terminal is
//! what turns a pile of records into "alice was on pts/1 from 09:00 to 10:00
//! from 10.0.4.22" — the sentence an examiner actually needs. The pairing rules
//! here follow util-linux `last(1)`, so output can be compared against it line
//! for line. They live in `seance_login_sessions`, shared with the Apple
//! System Log reader, so the two readers of this evidence cannot drift apart;
//! what stays here is [`classify`], the reading of this dialect's records.
//!
//! The one thing this module refuses to do is invent an end. A session closed
//! by a reboot has no recorded logout; `last` prints a duration for it anyway by
//! assuming the machine went down at the boot record. Here that time is carried
//! as an explicit upper bound ([`LoginSession::bounded_before`]) and the
//! `logout_time` stays absent, because a logout that was never written must not
//! be presented as one that was.

use crate::record::{
    ut_type_name, TypeDialect, UtmpRecord, UT_BOOT_TIME, UT_DARWIN_NEW_TIME, UT_DARWIN_OLD_TIME,
    UT_DARWIN_SHUTDOWN_TIME, UT_DARWIN_SIGNATURE, UT_DEAD_PROCESS, UT_NEW_TIME, UT_OLD_TIME,
    UT_RUN_LVL,
};
use seance_login_sessions::SessionPairer;
use std::net::IpAddr;

/// What a record means once the pseudo-user and pseudo-terminal conventions
/// have been applied.
///
/// `ut_type` alone is not enough: boots, shutdowns and clock changes are
/// distinguished by `ut_line == "~"` plus a pseudo-user, and a long tail of
/// login programs writes a login without setting `USER_PROCESS`. Reading the
/// type field literally therefore loses real logins and mislabels shutdowns as
/// run-level noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// An interactive login on `ut_line`.
    Login,
    /// A logout: the session on `ut_line` ended.
    Logout,
    /// The system booted.
    Boot,
    /// The system was brought down cleanly.
    Shutdown,
    /// A run-level change that is not a shutdown.
    Runlevel,
    /// The wall clock was set; the value recorded is the *new* time.
    ClockSetNew,
    /// The wall clock was set; the value recorded is the *old* time.
    ClockSetOld,
    /// Bookkeeping the login history does not describe (`INIT_PROCESS`, an
    /// idle getty, `ACCOUNTING`). Counted, never rendered as a session.
    Bookkeeping,
    /// Darwin's `SIGNATURE` record: the file stating its own format version.
    ///
    /// Kept apart from [`RecordKind::Bookkeeping`] because it is not a record
    /// *about* login activity at all, and because it is the one record in
    /// either dialect that carries no timestamp — so it must never reach a
    /// timeline, where it would land at the epoch or at no time at all.
    FormatSignature,
}

impl RecordKind {
    /// Stable label for the emitted artifact.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Login => "login",
            RecordKind::Logout => "logout",
            RecordKind::Boot => "boot",
            RecordKind::Shutdown => "shutdown",
            RecordKind::Runlevel => "runlevel",
            RecordKind::ClockSetNew => "clock_change_new",
            RecordKind::ClockSetOld => "clock_change_old",
            RecordKind::Bookkeeping => "bookkeeping",
            RecordKind::FormatSignature => "format_signature",
        }
    }
}

/// The run-level a `RUN_LVL` record moved the system to, if it is legible.
///
/// The two levels are packed into the low two bytes of `ut_pid`: the new level
/// in the low byte, the previous one in the next. Returns `None` when those
/// bytes are not printable, rather than reporting a control character as a
/// run-level.
pub fn runlevel_of(rec: &UtmpRecord) -> Option<char> {
    let byte = (rec.pid as u32) & 0xff;
    let ch = char::from(byte as u8);
    if ch.is_ascii_graphic() {
        Some(ch)
    } else {
        None
    }
}

/// Previous run-level, packed into the second byte of `ut_pid`.
pub fn previous_runlevel_of(rec: &UtmpRecord) -> Option<char> {
    let byte = ((rec.pid as u32) >> 8) & 0xff;
    let ch = char::from(byte as u8);
    if ch.is_ascii_graphic() {
        Some(ch)
    } else {
        None
    }
}

/// Classify a record the way `last(1)` does.
///
/// The rules, in order:
/// * `ut_line == "~"` with pseudo-user `reboot` / `shutdown` / `runlevel`
///   identifies boots, clean shutdowns and run-level changes.
/// * user `date` on line `{` or `|` identifies the two halves of a clock change.
/// * an empty `ut_user` on a real terminal is a logout, whatever the type says.
/// * a non-empty user other than the getty placeholder `LOGIN` is a login, even
///   when the writing program left `ut_type` at `INIT_PROCESS` — a large amount
///   of real history would otherwise be dropped.
/// * a run-level of `0` or `6` (halt / reboot) counts as a shutdown.
/// * `ut_type` three and four are read against the record's own dialect, since
///   Darwin swaps the two halves of a clock change relative to Linux; Darwin's
///   `SHUTDOWN_TIME` and `SIGNATURE` are recognised only on Darwin records.
pub fn classify(rec: &UtmpRecord) -> RecordKind {
    let line = rec.line.as_str();
    let user = rec.user.as_str();

    if line.starts_with('~') {
        if user.starts_with("shutdown") {
            return RecordKind::Shutdown;
        }
        if user.starts_with("reboot") {
            return RecordKind::Boot;
        }
        if user.starts_with("runlevel") {
            return match runlevel_of(rec) {
                Some('0') | Some('6') => RecordKind::Shutdown,
                _ => RecordKind::Runlevel,
            };
        }
    }

    if user == "date" {
        if line.starts_with('{') {
            return RecordKind::ClockSetNew;
        }
        if line.starts_with('|') {
            return RecordKind::ClockSetOld;
        }
    }

    match rec.ut_type {
        UT_BOOT_TIME => return RecordKind::Boot,
        UT_RUN_LVL => {
            return match runlevel_of(rec) {
                Some('0') | Some('6') => RecordKind::Shutdown,
                _ => RecordKind::Runlevel,
            }
        }
        _ => {}
    }
    // Three and four are the two halves of a clock change in both dialects,
    // but Darwin orders them the other way round; ten and eleven exist only on
    // Darwin. Reading either against the wrong enumeration is a silent error,
    // so the dialect decides.
    match rec.dialect {
        TypeDialect::Linux => match rec.ut_type {
            UT_NEW_TIME => return RecordKind::ClockSetNew,
            UT_OLD_TIME => return RecordKind::ClockSetOld,
            _ => {}
        },
        TypeDialect::Darwin => match rec.ut_type {
            UT_DARWIN_NEW_TIME => return RecordKind::ClockSetNew,
            UT_DARWIN_OLD_TIME => return RecordKind::ClockSetOld,
            UT_DARWIN_SHUTDOWN_TIME => return RecordKind::Shutdown,
            UT_DARWIN_SIGNATURE => return RecordKind::FormatSignature,
            _ => {}
        },
    }

    if user.is_empty() {
        // A null username on a terminal means "logout on that terminal"; with
        // no terminal either, there is nothing to attribute.
        return if line.is_empty() {
            RecordKind::Bookkeeping
        } else {
            RecordKind::Logout
        };
    }
    if rec.ut_type == UT_DEAD_PROCESS {
        return RecordKind::Logout;
    }
    if line.is_empty() || user == "LOGIN" {
        return RecordKind::Bookkeeping;
    }
    RecordKind::Login
}

// How a session ended and what closed it are the shared pairing engine's
// vocabulary (ROADMAP §5.11, lifted 2026-09-26), re-exported so this crate's
// public surface is unchanged.
pub use seance_login_sessions::{ClosedBy, SessionStatus};

/// One reconstructed interactive login session.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginSession {
    /// Account that logged in.
    pub user: String,
    /// Terminal, without the `/dev/` prefix.
    pub line: String,
    /// inittab / terminal id from the login record.
    pub id: String,
    /// Remote host as recorded. Empty for a local console login.
    pub host: String,
    /// Source address, when the login record carried one.
    pub addr: Option<IpAddr>,
    /// PID of the login process.
    pub pid: i32,
    /// Session id from the login record.
    pub session: i32,
    /// `ut_type` of the login record, so the classification can be audited.
    pub login_ut_type: u16,
    /// Enumeration `login_ut_type` is to be read against.
    pub dialect: TypeDialect,
    /// Index of the login record in the file.
    pub login_index: usize,
    /// Login time, UTC Unix seconds. `None` when the login record's timestamp
    /// was not usable — the session is still reported, without a date.
    pub start: Option<i64>,
    /// The login record's seconds field exactly as stored, so an unusable
    /// timestamp can be shown as the value it really is instead of vanishing.
    pub start_raw: u64,
    /// Sub-second part of the login time.
    pub start_usec: Option<u32>,
    /// Logout time, UTC Unix seconds. Present **only** when a logout record was
    /// actually read.
    pub end: Option<i64>,
    /// Observed duration, present only when both ends were observed and the
    /// logout is not before the login.
    pub duration: Option<i64>,
    /// An upper bound on when the session ended, taken from the boot or
    /// shutdown record that closed it. This is inference, not a recorded
    /// logout, and is reported under its own name for that reason.
    pub bounded_before: Option<i64>,
    /// Longest the session can have lasted, given `bounded_before`.
    pub max_duration: Option<i64>,
    /// How the session ended.
    pub status: SessionStatus,
    /// What closed it.
    pub closed_by: ClosedBy,
}

impl LoginSession {
    /// Human-readable source of the login: hostname if there is one, else the
    /// numeric address, else nothing (a local login).
    pub fn source(&self) -> Option<String> {
        if !self.host.is_empty() {
            Some(self.host.clone())
        } else {
            self.addr.map(|a| a.to_string())
        }
    }
}

/// A boot, shutdown, run-level change or clock change.
#[derive(Debug, Clone, PartialEq)]
pub struct BootEvent {
    /// Which of the four it is.
    pub kind: RecordKind,
    /// Event time, UTC Unix seconds, or `None` when the record's timestamp was
    /// not usable.
    pub time: Option<i64>,
    /// Kernel release string, which these records carry in `ut_host`.
    pub kernel: Option<String>,
    /// Run-level entered, for `RUN_LVL` records where it is legible.
    pub runlevel: Option<char>,
    /// Run-level left, for `RUN_LVL` records where it is legible.
    pub previous_runlevel: Option<char>,
    /// `ut_type` of the source record.
    pub ut_type: u16,
    /// Enumeration `ut_type` is to be read against.
    pub dialect: TypeDialect,
    /// Index of the source record in the file.
    pub index: usize,
}

impl BootEvent {
    /// Name of the source record's raw type, for provenance.
    pub fn ut_type_name(&self) -> &'static str {
        ut_type_name(self.dialect, self.ut_type)
    }
}

/// Everything reconstructed from one file's records.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Reconstruction {
    /// Sessions, in the order they were closed (still-open ones last, ordered
    /// by login time so output is deterministic).
    pub sessions: Vec<LoginSession>,
    /// Boot/shutdown/run-level/clock events, in file order.
    pub boots: Vec<BootEvent>,
    /// Logout records that closed no known session — normal at the head of a
    /// rotated `wtmp`, whose matching logins are in the previous file.
    pub unpaired_logouts: usize,
    /// Records that describe no login activity.
    pub bookkeeping: usize,
    /// Format version string the file declared about itself, when it carries
    /// one.
    ///
    /// Only Darwin's `utmpx` does: its first record is a `SIGNATURE` whose
    /// `ut_user` holds the literal `utmpx-1.00`. It is worth reporting because
    /// it is the only case in this family where the file corroborates the
    /// layout the detector chose, instead of the choice resting entirely on
    /// field plausibility.
    pub format_version: Option<String>,
    /// True when the session cap was reached and later logins were not
    /// reconstructed.
    pub session_cap_reached: bool,
}

/// Reconstruct sessions and boot brackets from records in file order.
///
/// `max_sessions` bounds how many sessions are built, so a hostile file cannot
/// grow this unboundedly; reaching it sets
/// [`Reconstruction::session_cap_reached`], which the caller must carry onto the
/// artifacts. A capped reconstruction that claimed to be complete would tell an
/// examiner that an account's later sessions do not exist.
pub fn reconstruct(records: &[UtmpRecord], max_sessions: usize) -> Reconstruction {
    let mut out = Reconstruction::default();
    // The pairing rules are shared with the Apple System Log reader; only the
    // classification of a record is this dialect's own.
    let mut pairer: SessionPairer<LoginSession> = SessionPairer::new(max_sessions);

    for rec in records {
        let kind = classify(rec);
        match kind {
            RecordKind::Login => pairer.login(
                &rec.line,
                rec.tv_sec,
                rec.index,
                LoginSession {
                    user: rec.user.clone(),
                    line: rec.line.clone(),
                    id: rec.id.clone(),
                    host: rec.host.clone(),
                    addr: rec.addr,
                    pid: rec.pid,
                    session: rec.session,
                    login_ut_type: rec.ut_type,
                    dialect: rec.dialect,
                    login_index: rec.index,
                    start: rec.tv_sec,
                    start_raw: rec.tv_sec_raw,
                    start_usec: rec.tv_usec,
                    end: None,
                    duration: None,
                    bounded_before: None,
                    max_duration: None,
                    status: SessionStatus::StillLoggedIn,
                    closed_by: ClosedBy::EndOfFile,
                },
            ),
            RecordKind::Logout => {
                pairer.logout(&rec.line, rec.tv_sec);
            }
            RecordKind::Boot | RecordKind::Shutdown => {
                let closed_by = if kind == RecordKind::Boot {
                    ClosedBy::Boot
                } else {
                    ClosedBy::Shutdown
                };
                pairer.machine_down(rec.tv_sec, closed_by);
                out.boots.push(boot_event(rec, kind));
            }
            RecordKind::Runlevel | RecordKind::ClockSetNew | RecordKind::ClockSetOld => {
                out.boots.push(boot_event(rec, kind));
            }
            RecordKind::Bookkeeping => out.bookkeeping = out.bookkeeping.saturating_add(1),
            RecordKind::FormatSignature => {
                out.bookkeeping = out.bookkeeping.saturating_add(1);
                // First one wins: a second signature record would mean two
                // files were concatenated, and the head of the file is what
                // the detector read.
                if out.format_version.is_none() && !rec.user.is_empty() {
                    out.format_version = Some(rec.user.clone());
                }
            }
        }
    }

    let pairing = pairer.finish();
    out.unpaired_logouts = pairing.unpaired_logouts;
    out.session_cap_reached = pairing.session_cap_reached;
    out.sessions = pairing
        .sessions
        .into_iter()
        .map(|p| LoginSession {
            end: p.end,
            duration: p.duration,
            bounded_before: p.bounded_before,
            max_duration: p.max_duration,
            status: p.status,
            closed_by: p.closed_by,
            ..p.login
        })
        .collect();
    out
}

pub(crate) fn boot_event(rec: &UtmpRecord, kind: RecordKind) -> BootEvent {
    let is_runlevel = matches!(kind, RecordKind::Runlevel | RecordKind::Shutdown);
    BootEvent {
        kind,
        time: rec.tv_sec,
        kernel: if rec.host.is_empty() {
            None
        } else {
            Some(rec.host.clone())
        },
        runlevel: if is_runlevel { runlevel_of(rec) } else { None },
        previous_runlevel: if is_runlevel {
            previous_runlevel_of(rec)
        } else {
            None
        },
        ut_type: rec.ut_type,
        dialect: rec.dialect,
        index: rec.index,
    }
}

/// Render a duration the way an examiner reads it: `3d04h`, `1h00m`, `12m05s`,
/// `42s`. Never used in place of a missing duration.
pub fn humanize_duration(seconds: i64) -> String {
    let secs = seconds.max(0);
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let rest = secs % 60;
    if days > 0 {
        format!("{days}d{hours:02}h")
    } else if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else if minutes > 0 {
        format!("{minutes}m{rest:02}s")
    } else {
        format!("{rest}s")
    }
}

/// `timestamp_desc` for the timeline row a record produces, or `None` for
/// records that describe no dated event.
///
/// The parenthesised name is the raw `ut_type` the classification rests on, so
/// the dialect is needed: a Darwin shutdown is a `SHUTDOWN_TIME` record, not
/// the level-0 `RUN_LVL` that means the same thing on Linux.
pub fn timeline_desc(
    kind: RecordKind,
    dialect: TypeDialect,
    failed_login: bool,
) -> Option<&'static str> {
    if failed_login && kind == RecordKind::Login {
        return Some("Failed login");
    }
    match kind {
        RecordKind::Login => Some("Login (USER_PROCESS)"),
        RecordKind::Logout => Some("Logout (DEAD_PROCESS)"),
        RecordKind::Boot => Some("System boot (BOOT_TIME)"),
        RecordKind::Shutdown => match dialect {
            TypeDialect::Linux => Some("Shutdown (RUN_LVL)"),
            TypeDialect::Darwin => Some("Shutdown (SHUTDOWN_TIME)"),
        },
        RecordKind::Runlevel => Some("Run-level change (RUN_LVL)"),
        RecordKind::ClockSetNew | RecordKind::ClockSetOld => Some("Clock change"),
        RecordKind::Bookkeeping => None,
        // The signature record states the file's format version and nothing
        // that happened; it carries no timestamp, so it has no timeline row.
        RecordKind::FormatSignature => None,
    }
}
