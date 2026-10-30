//! The login-session pairing rules, shared by every reader of `utmp`-shaped
//! records.
//!
//! A `wtmp` file, and the `utmpx` records the Apple System Log carries, do not
//! store sessions; they store the two ends of one. Pairing a login with the
//! logout that closed the same terminal is what turns a pile of records into
//! "alice was on pts/1 from 09:00 to 10:00" — the sentence an examiner needs.
//! The rules follow util-linux `last(1)`:
//!
//! * a login opens a session on its terminal (`ut_line`); at most one session
//!   is open per terminal;
//! * a second login on a terminal that is still open closes the first as
//!   **superseded**, bounded by the second login's time — never as a logout;
//! * a logout on a terminal closes the open session there with an observed
//!   end and, when the end is not before the start, an observed duration;
//! * a logout on a terminal with nothing open is **counted** as unpaired and
//!   never turned into a session with an invented start (normal at the head of
//!   a rotated file, whose login is in the previous one);
//! * a boot or a shutdown closes everything still open with an upper **bound**
//!   (`bounded_before`), never a logout, because none was written;
//! * whatever is still open at the end of the input is reported open.
//!
//! What a record *means* — which records are logins, logouts, boots — is not
//! decided here. That depends on the record's dialect (binary `struct utmp`
//! against Darwin's textual `utmpx`, a Linux `ut_type` enumeration against
//! Darwin's), so each reader keeps its own classification and hands this
//! engine the result. Before 2026-09-26 the pairing itself existed twice, in
//! `seance_plugin_utmp::sessions` and `seance_plugin_macos_artifacts::asl`, and
//! the copies had drifted: the ASL copy opened sessions past its cap and
//! folded unpaired logouts into an "unhandled" count. One engine removes the
//! chance of a correction to one copy leaving the other wrong (ROADMAP §5.11).
//!
//! The one thing this engine refuses to do is invent an end. A session closed
//! by a reboot has no recorded logout; `last` prints a duration for it anyway
//! by assuming the machine went down at the boot record. Here that time is an
//! explicit bound and `end` stays absent.

#![forbid(unsafe_code)]

use std::collections::HashMap;

/// How a session ended, as far as the records say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// A logout record closed it. Start, end and duration are all observed.
    LoggedOut,
    /// It was still open when the records ended — on a live `utmp` that means
    /// the account was logged in at acquisition time.
    StillLoggedIn,
    /// No logout was ever written: the machine rebooted or went down under it,
    /// or another login took the terminal. `last` prints this as
    /// "gone - no logout".
    GoneNoLogout,
}

impl SessionStatus {
    /// Stable label emitted as `status`.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStatus::LoggedOut => "logged_out",
            SessionStatus::StillLoggedIn => "still_logged_in",
            SessionStatus::GoneNoLogout => "gone_no_logout",
        }
    }
}

/// Why an open session stopped being open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedBy {
    /// A logout record on the same terminal.
    LogoutRecord,
    /// A boot record: the machine came up with the session still open, so it
    /// died in an unclean stop.
    Boot,
    /// A clean shutdown record.
    Shutdown,
    /// Another login claimed the same terminal without this one being closed.
    Superseded,
    /// The records ended with the session open.
    EndOfFile,
}

impl ClosedBy {
    /// Stable label emitted as `closed_by`.
    pub fn as_str(self) -> &'static str {
        match self {
            ClosedBy::LogoutRecord => "logout_record",
            ClosedBy::Boot => "boot",
            ClosedBy::Shutdown => "shutdown",
            ClosedBy::Superseded => "superseded_by_new_login",
            ClosedBy::EndOfFile => "end_of_file",
        }
    }
}

/// One paired session: the reader's own login payload plus what the pairing
/// established about its end.
#[derive(Debug, Clone, PartialEq)]
pub struct PairedSession<L> {
    /// Whatever the reader keeps about the login record.
    pub login: L,
    /// Terminal the session was keyed on.
    pub line: String,
    /// Login time, UTC Unix seconds, when the login record's time was usable.
    pub start: Option<i64>,
    /// Position of the login record in its input (index or byte offset); the
    /// last tie-breaker, so output order is deterministic.
    pub order: usize,
    /// Logout time. Present **only** when a logout record was read.
    pub end: Option<i64>,
    /// Observed duration, only when both ends were observed and the logout is
    /// not before the login.
    pub duration: Option<i64>,
    /// Upper bound on the end, from the boot, shutdown or superseding login
    /// that closed it. Inference, not a logout.
    pub bounded_before: Option<i64>,
    /// Longest the session can have lasted, given `bounded_before`.
    pub max_duration: Option<i64>,
    /// How the session ended.
    pub status: SessionStatus,
    /// What closed it.
    pub closed_by: ClosedBy,
}

/// Everything the pairing established over one input.
#[derive(Debug, Clone, PartialEq)]
pub struct Pairing<L> {
    /// Sessions in the order they were closed; those still open at the end
    /// come last, ordered by (start, line, order).
    pub sessions: Vec<PairedSession<L>>,
    /// Logouts that closed no known session. Counted, never given a start.
    pub unpaired_logouts: usize,
    /// True when the session cap was reached: later logins were not
    /// reconstructed, and the reader must say so on its records.
    pub session_cap_reached: bool,
}

/// The pairing state machine. Feed it records in input order, then
/// [`SessionPairer::finish`].
#[derive(Debug)]
pub struct SessionPairer<L> {
    open: HashMap<String, PairedSession<L>>,
    sessions: Vec<PairedSession<L>>,
    unpaired_logouts: usize,
    session_cap_reached: bool,
    max_sessions: usize,
}

impl<L> SessionPairer<L> {
    /// A pairer that builds at most `max_sessions` sessions, so a hostile file
    /// cannot grow it without bound. Reaching the cap is reported, never
    /// silent: a capped reconstruction that claimed to be complete would tell
    /// an examiner an account's later sessions do not exist.
    pub fn new(max_sessions: usize) -> Self {
        SessionPairer {
            open: HashMap::new(),
            sessions: Vec::new(),
            unpaired_logouts: 0,
            session_cap_reached: false,
            max_sessions,
        }
    }

    /// A login on `line` at `time`. A session already open on the line is
    /// closed as superseded, bounded by this login's time. Once the cap is
    /// reached no new session is opened, so a later logout on the line is
    /// counted unpaired rather than closing a session that will be dropped.
    pub fn login(&mut self, line: &str, time: Option<i64>, order: usize, login: L) {
        if let Some(mut previous) = self.open.remove(line) {
            previous.status = SessionStatus::GoneNoLogout;
            previous.closed_by = ClosedBy::Superseded;
            previous.bounded_before = time;
            previous.max_duration = observed_span(previous.start, time);
            self.push(previous);
        }
        if self.sessions.len() >= self.max_sessions {
            self.session_cap_reached = true;
            return;
        }
        self.open.insert(
            line.to_string(),
            PairedSession {
                login,
                line: line.to_string(),
                start: time,
                order,
                end: None,
                duration: None,
                bounded_before: None,
                max_duration: None,
                status: SessionStatus::StillLoggedIn,
                closed_by: ClosedBy::EndOfFile,
            },
        );
    }

    /// A logout on `line` at `time`. Returns whether it closed a session;
    /// when it did not, it is counted in [`Pairing::unpaired_logouts`].
    pub fn logout(&mut self, line: &str, time: Option<i64>) -> bool {
        match self.open.remove(line) {
            Some(mut session) => {
                session.status = SessionStatus::LoggedOut;
                session.closed_by = ClosedBy::LogoutRecord;
                session.end = time;
                session.duration = observed_span(session.start, time);
                self.push(session);
                true
            }
            None => {
                self.unpaired_logouts = self.unpaired_logouts.saturating_add(1);
                false
            }
        }
    }

    /// The machine booted or shut down at `time`: every open session died with
    /// it, and gets `time` as a bound — never as a logout. `closed_by` names
    /// which of the two it was.
    pub fn machine_down(&mut self, time: Option<i64>, closed_by: ClosedBy) {
        let mut still_open: Vec<PairedSession<L>> = self.open.drain().map(|(_, s)| s).collect();
        sort_open(&mut still_open);
        for mut session in still_open {
            session.status = SessionStatus::GoneNoLogout;
            session.closed_by = closed_by;
            session.bounded_before = time;
            session.max_duration = observed_span(session.start, time);
            self.push(session);
        }
    }

    /// The input ended. Whatever is still open is reported open.
    pub fn finish(mut self) -> Pairing<L> {
        let mut remaining: Vec<PairedSession<L>> =
            std::mem::take(&mut self.open).into_values().collect();
        sort_open(&mut remaining);
        for session in remaining {
            self.push(session);
        }
        Pairing {
            sessions: self.sessions,
            unpaired_logouts: self.unpaired_logouts,
            session_cap_reached: self.session_cap_reached,
        }
    }

    fn push(&mut self, session: PairedSession<L>) {
        if self.sessions.len() >= self.max_sessions {
            self.session_cap_reached = true;
            return;
        }
        self.sessions.push(session);
    }
}

/// Open sessions leave in a stable order — a `HashMap` drain has none.
fn sort_open<L>(sessions: &mut [PairedSession<L>]) {
    sessions.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.order.cmp(&b.order))
    });
}

/// Duration between two observed times, or `None` when either is missing or
/// the end precedes the start. A negative duration means the clock moved;
/// reporting it as a length would be a fabricated fact.
pub fn observed_span(start: Option<i64>, end: Option<i64>) -> Option<i64> {
    let span = end?.checked_sub(start?)?;
    if span >= 0 {
        Some(span)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(
        max: usize,
        feed: impl FnOnce(&mut SessionPairer<&'static str>),
    ) -> Pairing<&'static str> {
        let mut p = SessionPairer::new(max);
        feed(&mut p);
        p.finish()
    }

    #[test]
    fn login_then_logout_on_same_line_is_logged_out_with_duration() {
        let out = run(10, |p| {
            p.login("tty1", Some(100), 0, "alice");
            assert!(p.logout("tty1", Some(160)));
        });
        assert_eq!(out.sessions.len(), 1);
        let s = &out.sessions[0];
        assert_eq!(s.login, "alice");
        assert_eq!(s.status, SessionStatus::LoggedOut);
        assert_eq!(s.closed_by, ClosedBy::LogoutRecord);
        assert_eq!(
            (s.start, s.end, s.duration),
            (Some(100), Some(160), Some(60))
        );
        assert_eq!(s.bounded_before, None);
        assert_eq!(s.max_duration, None);
    }

    #[test]
    fn a_logout_before_its_login_gets_no_duration() {
        let out = run(10, |p| {
            p.login("tty1", Some(100), 0, "alice");
            p.logout("tty1", Some(90));
        });
        assert_eq!(out.sessions[0].end, Some(90));
        assert_eq!(out.sessions[0].duration, None, "the clock moved; no length");
    }

    #[test]
    fn second_login_on_a_line_supersedes_the_first_as_a_bound() {
        let out = run(10, |p| {
            p.login("pts/0", Some(100), 0, "alice");
            p.login("pts/0", Some(130), 1, "bob");
        });
        assert_eq!(out.sessions.len(), 2);
        let first = &out.sessions[0];
        assert_eq!(first.login, "alice");
        assert_eq!(first.status, SessionStatus::GoneNoLogout);
        assert_eq!(first.closed_by, ClosedBy::Superseded);
        assert_eq!(first.end, None, "a superseding login is not a logout");
        assert_eq!(first.bounded_before, Some(130));
        assert_eq!(first.max_duration, Some(30));
        assert_eq!(out.sessions[1].status, SessionStatus::StillLoggedIn);
        assert_eq!(out.sessions[1].closed_by, ClosedBy::EndOfFile);
    }

    #[test]
    fn boot_or_shutdown_closes_open_sessions_as_bound_never_logout() {
        let out = run(10, |p| {
            p.login("tty2", Some(200), 1, "bob");
            p.login("tty1", Some(100), 0, "alice");
            p.machine_down(Some(500), ClosedBy::Boot);
            p.login("tty1", Some(600), 2, "carol");
            p.machine_down(Some(700), ClosedBy::Shutdown);
        });
        let got: Vec<_> = out
            .sessions
            .iter()
            .map(|s| {
                (
                    s.login,
                    s.closed_by,
                    s.end,
                    s.bounded_before,
                    s.max_duration,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("alice", ClosedBy::Boot, None, Some(500), Some(400)),
                ("bob", ClosedBy::Boot, None, Some(500), Some(300)),
                ("carol", ClosedBy::Shutdown, None, Some(700), Some(100)),
            ]
        );
        assert!(out
            .sessions
            .iter()
            .all(|s| s.status == SessionStatus::GoneNoLogout && s.duration.is_none()));
    }

    #[test]
    fn logout_with_no_open_session_is_counted_unpaired_not_invented() {
        let out = run(10, |p| {
            assert!(!p.logout("tty1", Some(50)));
            p.login("tty1", Some(100), 1, "alice");
            p.logout("tty1", Some(110));
            assert!(!p.logout("tty1", Some(120)));
        });
        assert_eq!(out.sessions.len(), 1);
        assert_eq!(out.unpaired_logouts, 2);
    }

    #[test]
    fn no_session_opens_after_the_cap_and_the_cap_is_flagged() {
        let out = run(1, |p| {
            p.login("tty1", Some(100), 0, "alice");
            p.logout("tty1", Some(110));
            // The cap is reached: this login must not open, so its logout is
            // unpaired rather than closing a session that would be dropped.
            p.login("tty2", Some(200), 2, "bob");
            p.logout("tty2", Some(210));
        });
        assert_eq!(out.sessions.len(), 1);
        assert_eq!(out.sessions[0].login, "alice");
        assert!(out.session_cap_reached);
        assert_eq!(out.unpaired_logouts, 1);
    }

    #[test]
    fn remaining_open_sessions_sort_by_start_line_index() {
        let out = run(10, |p| {
            p.login("tty3", Some(300), 0, "c");
            p.login("tty2", Some(100), 1, "b2");
            p.login("tty1", Some(100), 2, "b1");
            p.login("tty0", None, 3, "undated");
        });
        let order: Vec<_> = out.sessions.iter().map(|s| s.login).collect();
        assert_eq!(order, vec!["undated", "b1", "b2", "c"]);
        assert!(!out.session_cap_reached);
    }

    #[test]
    fn a_session_with_no_usable_start_is_reported_without_a_duration() {
        let out = run(10, |p| {
            p.login("tty1", None, 0, "alice");
            p.logout("tty1", Some(100));
        });
        assert_eq!(out.sessions[0].status, SessionStatus::LoggedOut);
        assert_eq!(out.sessions[0].end, Some(100));
        assert_eq!(out.sessions[0].duration, None);
    }

    #[test]
    fn the_labels_are_the_ones_both_readers_emitted_before_the_lift() {
        assert_eq!(SessionStatus::LoggedOut.as_str(), "logged_out");
        assert_eq!(SessionStatus::StillLoggedIn.as_str(), "still_logged_in");
        assert_eq!(SessionStatus::GoneNoLogout.as_str(), "gone_no_logout");
        assert_eq!(ClosedBy::LogoutRecord.as_str(), "logout_record");
        assert_eq!(ClosedBy::Boot.as_str(), "boot");
        assert_eq!(ClosedBy::Shutdown.as_str(), "shutdown");
        assert_eq!(ClosedBy::Superseded.as_str(), "superseded_by_new_login");
        assert_eq!(ClosedBy::EndOfFile.as_str(), "end_of_file");
    }
}
