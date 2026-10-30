//! OpenBSM audit trails — `/var/audit/*`.
//!
//! macOS keeps the `utmpx` half of the login-accounting family and nothing
//! else: there is no `btmp`, and since 10.5 no on-disk `wtmpx` or `lastlogx`.
//! `/var/run/utmpx` therefore answers "who was logged in when the image was
//! taken" and cannot answer "who logged in last Tuesday, and who tried and
//! failed". **The audit trail is where that answer is**, and it is a better one
//! than `btmp`: every record carries the account, the process, the terminal,
//! the remote address, whether the attempt succeeded, and — on Darwin — the
//! code-signing identity of the binary that asked.
//!
//! # The format validates itself, and that is how it is read
//!
//! A trail is a flat sequence of records; a record is a sequence of
//! length-prefixed *tokens*. Two independent facts bracket every record:
//!
//! * the **header** token, which every record begins with, states the record's
//!   total byte count; and
//! * the **trailer** token, which every record ends with, carries the magic
//!   `0xB105` and *repeats* that byte count.
//!
//! So the record boundaries never have to be guessed, and a record whose
//! tokens do not tile exactly into the space between its header and its
//! trailer is **reported as unresolved rather than believed**. That check is
//! what makes the remaining token lengths safe: a mistake in any one of them
//! shifts everything after it, and the trailer then fails to land on the last
//! seven bytes. See [`RecordFlaw`].
//!
//! It is also why this reader **self-selects by content**: a file whose first
//! record validates on both counts is an audit trail, whatever it is called,
//! and a file that does not is passed over in silence. The name
//! (`<start>.<end>`, `<start>.not_terminated`, `<start>.crash_recovery`) is
//! never required.
//!
//! # Where the offsets and lengths come from
//!
//! The token structures are OpenBSM's (`bsm/libbsm.h`), and every length used
//! here was checked against the nine real trails in the Magnet 2021 macOS
//! image: **4,327 records, and the token walk ends exactly on the trailer in
//! every one of them, with no unknown token and no length that overruns.** The
//! nine token types those records use are therefore corroborated 4,327 times
//! over; the rest are from the specification, and the tiling check above is
//! what stops an untested one from producing a quiet wrong answer.
//!
//! The header's second time field is **milliseconds**, which is also measured
//! rather than assumed: across those 4,327 records its maximum value is 998
//! and it never once reaches 1,000. A microsecond field would have spread
//! uniformly to 999,999.
//!
//! # What is deliberately not done
//!
//! * **No sessions are reconstructed.** BSM records events. A loginwindow
//!   login and the logout that ended it are written by *different processes*
//!   (pid 107 and pid 150 on the corpus image), so pairing them would be
//!   inference dressed as a record. The events are reported as events.
//! * **No account name is invented from a daemon's prose.** The trail
//!   identifies an account by number (`auid`, `euid`, `ruid`), and that is what
//!   is reported. `sshd`'s own message — `invalid password for user eliflatt` —
//!   is quoted verbatim as the text token it is, not parsed into a `user`
//!   field, because its wording is not specified anywhere and resolving 501 to
//!   a name needs a file this reader is not given.
//! * **Event names come from a shipped table of identifiers**, not from the
//!   image's `/etc/security/audit_event`, which is a different file than the
//!   one this reader is handed. The table covers the login, authentication and
//!   administration classes — the whole surface a login question is answered
//!   from. An event outside it is reported by number with the name **absent**,
//!   marked `unmapped`, rather than guessed at.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use tracing::debug;

use crate::{basename_lower, stamp_incomplete, to_rfc3339_nanos, Staged};

/// Largest trail this reader stages. Trails are rotated by `auditd` well below
/// this; the cap stops a corrupt or hostile size from staging a whole disk.
const MAX_TRAIL_BYTES: u64 = 512 * 1024 * 1024;
/// Largest number of records read from one trail.
const MAX_RECORDS: usize = 2_000_000;
/// Largest number of tokens walked within one record. A record is bounded by
/// its own byte count, so this only bites on a pathological one built entirely
/// of one-byte tokens.
const MAX_TOKENS_PER_RECORD: usize = 8_192;
/// Largest number of text, path and argument tokens carried onto a record.
/// Beyond this the list is truncated and the record says so.
const MAX_LIST_ITEMS: usize = 64;
/// Longest string rendered from one token. The token's own length prefix is
/// always reported, so a truncated string is visible as a truncation.
const MAX_STRING_BYTES: usize = 4096;

// --- token identifiers (OpenBSM `bsm/libbsm.h`) ------------------------------

/// `AUT_TRAILER` — the last token of every record.
const AUT_TRAILER: u8 = 0x13;
/// `AUT_HEADER32` — 32-bit time, no machine address.
const AUT_HEADER32: u8 = 0x14;
/// `AUT_HEADER32_EX` — 32-bit time, with the machine's address.
const AUT_HEADER32_EX: u8 = 0x15;
/// `AUT_HEADER64` — 64-bit time, no machine address.
const AUT_HEADER64: u8 = 0x74;
/// `AUT_HEADER64_EX` — 64-bit time, with the machine's address.
const AUT_HEADER64_EX: u8 = 0x79;

const AUT_DATA: u8 = 0x21;
const AUT_IPC: u8 = 0x22;
const AUT_PATH: u8 = 0x23;
const AUT_SUBJECT32: u8 = 0x24;
const AUT_PROCESS32: u8 = 0x26;
const AUT_RETURN32: u8 = 0x27;
const AUT_TEXT: u8 = 0x28;
const AUT_OPAQUE: u8 = 0x29;
const AUT_IN_ADDR: u8 = 0x2a;
const AUT_IP: u8 = 0x2b;
const AUT_IPORT: u8 = 0x2c;
const AUT_ARG32: u8 = 0x2d;
const AUT_SOCKET: u8 = 0x2e;
const AUT_SEQ: u8 = 0x2f;
const AUT_IPC_PERM: u8 = 0x32;
const AUT_GROUPS: u8 = 0x34;
const AUT_PRIV: u8 = 0x38;
const AUT_UPRIV: u8 = 0x39;
const AUT_NEWGROUPS: u8 = 0x3b;
const AUT_EXEC_ARGS: u8 = 0x3c;
const AUT_EXEC_ENV: u8 = 0x3d;
const AUT_ATTR32: u8 = 0x3e;
const AUT_CMD: u8 = 0x51;
const AUT_EXIT: u8 = 0x52;
const AUT_ZONENAME: u8 = 0x60;
const AUT_ARG64: u8 = 0x71;
const AUT_RETURN64: u8 = 0x72;
const AUT_ATTR64: u8 = 0x73;
const AUT_SUBJECT64: u8 = 0x75;
const AUT_PROCESS64: u8 = 0x77;
const AUT_SUBJECT32_EX: u8 = 0x7a;
const AUT_PROCESS32_EX: u8 = 0x7b;
const AUT_SUBJECT64_EX: u8 = 0x7c;
const AUT_PROCESS64_EX: u8 = 0x7d;
const AUT_IN_ADDR_EX: u8 = 0x7e;
const AUT_SOCKET_EX: u8 = 0x7f;
const AUT_SOCKINET32: u8 = 0x80;
const AUT_SOCKINET128: u8 = 0x81;
const AUT_SOCKUNIX: u8 = 0x82;
/// `AUT_IDENTITY` — Darwin's code-signing identity token: which signed binary
/// asked for the audited operation.
const AUT_IDENTITY: u8 = 0xed;

/// The trailer token's magic. Present on every record ever written by
/// `auditd`; its absence at the byte count the header declared is the single
/// strongest signal that a stride is wrong.
const TRAILER_MAGIC: u16 = 0xb105;

/// Smallest record: a bare `AUT_HEADER32` (18 bytes) and its trailer (7).
const MIN_RECORD_BYTES: usize = 25;

// --- event classes -----------------------------------------------------------

/// The audit class an event belongs to, as `/etc/security/audit_class` names
/// them.
///
/// Only the three that bear on "who was on this machine" are modelled. The
/// class is what makes a record a login record: `AUE_openssh` and
/// `AUE_lw_login` have nothing in common structurally, and nothing in either
/// record says "this is a login" — the class does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    /// `lo` — login / logout.
    LoginLogout,
    /// `aa` — authentication and authorization.
    AuthAuthorize,
    /// `ad` — administrative.
    Administrative,
}

impl EventClass {
    /// The two-letter class name `audit_class` uses, emitted verbatim.
    pub fn as_str(self) -> &'static str {
        match self {
            EventClass::LoginLogout => "lo",
            EventClass::AuthAuthorize => "aa",
            EventClass::Administrative => "ad",
        }
    }

    /// Longer form, for a screen.
    pub fn description(self) -> &'static str {
        match self {
            EventClass::LoginLogout => "login/logout",
            EventClass::AuthAuthorize => "authentication and authorization",
            EventClass::Administrative => "administrative",
        }
    }
}

/// One event identifier, its symbolic name, its class, and whether it is an
/// event at which a **secret was offered**.
struct EventDef {
    id: u32,
    symbol: &'static str,
    class: EventClass,
    /// True where the event records an attempt to prove an identity — a
    /// password, a key, a `sudo` challenge.
    ///
    /// This is the line a `FailedLogin` record is drawn on, and it is **not**
    /// the class. The `aa` class also holds Security Server *authorization*
    /// decisions (`AUE_ssauthorize`, `AUE_ssauthmech`, `AUE_ssconn`): "is this
    /// process allowed to do X", which is policy, not credentials, and which
    /// fails routinely — 387 times across the nine trails in the corpus, on a
    /// machine nobody attacked. Reporting those as failed logins would put 387
    /// rows on the screen an examiner reads to answer "was there a brute
    /// force" and bury the two attempts that were real.
    ///
    /// Logouts and session-lifecycle events are excluded for the same reason:
    /// no secret is offered at either.
    credential_attempt: bool,
}

macro_rules! ev {
    ($id:expr, $sym:literal, $class:ident) => {
        EventDef {
            id: $id,
            symbol: $sym,
            class: EventClass::$class,
            credential_attempt: false,
        }
    };
    ($id:expr, $sym:literal, $class:ident, credential) => {
        EventDef {
            id: $id,
            symbol: $sym,
            class: EventClass::$class,
            credential_attempt: true,
        }
    };
}

/// The login, authentication and administration events, by identifier.
///
/// These are interface constants — a number and the symbol that names it — and
/// the set is the whole surface a "who logged in" question is answered from:
/// every `lo` and `aa` event OpenBSM and Darwin define, plus the `ad` events in
/// the Darwin and OpenBSM user ranges and the few low-numbered kernel `ad`
/// events that move a login timeline (a reboot, a clock change, an audit-id
/// change, a kernel module load).
///
/// Events outside this set are reported by **number**, with `event_name`
/// absent and `unmapped` recorded — never by a guessed name. The nine trails
/// in the corpus use twenty-one distinct identifiers and every one of them is
/// here.
///
/// The `credential` marker names the events at which a secret was offered; see
/// [`EventDef::credential_attempt`] for why that, and not the class, is what a
/// failed-login record is drawn from.
const EVENTS: &[EventDef] = &[
    // Kernel events that bear on a login timeline.
    ev!(20, "AUE_REBOOT", Administrative),
    ev!(37, "AUE_SETTIMEOFDAY", Administrative),
    ev!(131, "AUE_SETAUID", Administrative),
    ev!(135, "AUE_SETUSERAUDIT", Administrative),
    ev!(243, "AUE_MODLOAD", Administrative),
    ev!(244, "AUE_MODUNLOAD", Administrative),
    ev!(287, "AUE_CLOCK_SETTIME", Administrative),
    ev!(288, "AUE_NTP_ADJTIME", Administrative),
    ev!(308, "AUE_DARWIN_REBOOT", Administrative),
    ev!(313, "AUE_DARWIN_SETTIMEOFDAY", Administrative),
    ev!(352, "AUE_DARWIN_AUDITCTL", Administrative),
    // Solaris-range user events, which OpenBSM keeps.
    ev!(6144, "AUE_at_create", Administrative),
    ev!(6145, "AUE_at_delete", Administrative),
    ev!(6147, "AUE_cron_invoke", Administrative),
    ev!(6148, "AUE_crontab_create", Administrative),
    ev!(6149, "AUE_crontab_delete", Administrative),
    ev!(6152, "AUE_login", LoginLogout, credential),
    ev!(6153, "AUE_logout", LoginLogout),
    ev!(6154, "AUE_telnet", LoginLogout, credential),
    ev!(6155, "AUE_rlogin", LoginLogout, credential),
    ev!(6158, "AUE_rshd", LoginLogout, credential),
    ev!(6159, "AUE_su", LoginLogout, credential),
    ev!(6160, "AUE_halt", Administrative),
    ev!(6161, "AUE_reboot", Administrative),
    ev!(6162, "AUE_rexecd", LoginLogout, credential),
    ev!(6163, "AUE_passwd", LoginLogout, credential),
    ev!(6164, "AUE_rexd", LoginLogout, credential),
    ev!(6165, "AUE_ftpd", LoginLogout, credential),
    ev!(6166, "AUE_init", LoginLogout),
    // 6168 carries two names in Apple's own table, `AUE_shutdown` and
    // `AUE_poweroff`; see `AMBIGUOUS_EVENTS`.
    ev!(6168, "AUE_poweroff", Administrative),
    ev!(6170, "AUE_crontab_mod", Administrative),
    // 6171 and 6172 likewise: the pre-10.5 Darwin names for the audit
    // startup/shutdown events collide with OpenBSM's ftpd-logout and ssh.
    ev!(6171, "AUE_DARWIN_audit_startup", Administrative),
    ev!(6172, "AUE_DARWIN_audit_shutdown", Administrative),
    ev!(6173, "AUE_role_login", LoginLogout, credential),
    ev!(6180, "AUE_prof_cmd", Administrative),
    ev!(6181, "AUE_filesystem_add", Administrative),
    ev!(6182, "AUE_filesystem_delete", Administrative),
    ev!(6183, "AUE_filesystem_modify", Administrative),
    ev!(6207, "AUE_create_user", Administrative),
    ev!(6208, "AUE_modify_user", Administrative),
    ev!(6209, "AUE_delete_user", Administrative),
    ev!(6210, "AUE_disable_user", Administrative),
    ev!(6211, "AUE_enable_user", Administrative),
    ev!(6212, "AUE_newgrp_login", LoginLogout, credential),
    ev!(6213, "AUE_admin_authenticate", LoginLogout, credential),
    // Pre-10.5 Darwin user events, kept because a trail from an older machine
    // still uses them.
    ev!(6300, "AUE_DARWIN_sudo", Administrative, credential),
    ev!(6501, "AUE_DARWIN_modify_password", Administrative),
    ev!(6511, "AUE_DARWIN_create_group", Administrative),
    ev!(6512, "AUE_DARWIN_delete_group", Administrative),
    ev!(6513, "AUE_DARWIN_modify_group", Administrative),
    ev!(6514, "AUE_DARWIN_add_to_group", Administrative),
    ev!(6515, "AUE_DARWIN_remove_from_group", Administrative),
    ev!(6600, "AUE_DARWIN_lw_login", LoginLogout, credential),
    ev!(6601, "AUE_DARWIN_lw_logout", LoginLogout),
    ev!(7000, "AUE_DARWIN_auth_user", AuthAuthorize, credential),
    ev!(7001, "AUE_DARWIN_ssconn", AuthAuthorize),
    ev!(7002, "AUE_DARWIN_ssauthorize", AuthAuthorize),
    ev!(7003, "AUE_DARWIN_ssauthint", AuthAuthorize),
    // OpenSSH's own event, in the third-party range.
    ev!(32800, "AUE_openssh", LoginLogout, credential),
    ev!(43042, "AUE_AUDITCTL", Administrative),
    ev!(43116, "AUE_SYSCTL_WRITE", Administrative),
    ev!(43127, "AUE_MAC_SYSCALL", Administrative),
    // Darwin's session events.
    ev!(44901, "AUE_SESSION_START", AuthAuthorize),
    ev!(44902, "AUE_SESSION_UPDATE", AuthAuthorize),
    ev!(44903, "AUE_SESSION_END", AuthAuthorize),
    ev!(44904, "AUE_SESSION_CLOSE", AuthAuthorize),
    // Current Darwin user events.
    ev!(45000, "AUE_audit_startup", Administrative),
    ev!(45001, "AUE_audit_shutdown", Administrative),
    ev!(45014, "AUE_modify_password", Administrative),
    ev!(45015, "AUE_create_group", Administrative),
    ev!(45016, "AUE_delete_group", Administrative),
    ev!(45017, "AUE_modify_group", Administrative),
    ev!(45018, "AUE_add_to_group", Administrative),
    ev!(45019, "AUE_remove_from_group", Administrative),
    ev!(45021, "AUE_lw_login", LoginLogout, credential),
    ev!(45022, "AUE_lw_logout", LoginLogout),
    ev!(45023, "AUE_auth_user", AuthAuthorize, credential),
    ev!(45024, "AUE_ssconn", AuthAuthorize),
    ev!(45025, "AUE_ssauthorize", AuthAuthorize),
    ev!(45026, "AUE_ssauthint", AuthAuthorize),
    ev!(45027, "AUE_calife", Administrative),
    ev!(45028, "AUE_sudo", AuthAuthorize, credential),
    ev!(45029, "AUE_audit_recovery", Administrative),
    ev!(45030, "AUE_ssauthmech", AuthAuthorize),
    ev!(45031, "AUE_sec_assessment", AuthAuthorize),
];

/// Identifiers that Apple's own event table gives more than one symbolic name.
///
/// The record carries a number, so it cannot say which name was meant. Both
/// are reported and the record says the format does not distinguish them —
/// rather than the reader picking one and presenting it as the event's name.
const AMBIGUOUS_EVENTS: &[(u32, &[&str])] = &[
    (6168, &["AUE_shutdown", "AUE_poweroff"]),
    (6171, &["AUE_ftpd_logout", "AUE_DARWIN_audit_startup"]),
    (6172, &["AUE_ssh", "AUE_DARWIN_audit_shutdown"]),
];

fn event_def(id: u32) -> Option<&'static EventDef> {
    EVENTS.iter().find(|e| e.id == id)
}

fn ambiguous_names(id: u32) -> Option<&'static [&'static str]> {
    AMBIGUOUS_EVENTS
        .iter()
        .find(|(eid, _)| *eid == id)
        .map(|(_, names)| *names)
}

// --- primitive reads ---------------------------------------------------------

fn u8_at(b: &[u8], p: usize) -> Option<u8> {
    b.get(p).copied()
}
fn u16_at(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]))
}
fn u32_at(b: &[u8], p: usize) -> Option<u32> {
    let s = b.get(p..p.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], p: usize) -> Option<u64> {
    let s = b.get(p..p.checked_add(8)?)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// A counted string token's text, up to [`MAX_STRING_BYTES`], with the trailing
/// NUL removed.
///
/// Decoded lossily: a text token holding a non-UTF-8 byte must not make the
/// record — and with it the login it records — disappear.
fn counted_string(b: &[u8], off: usize, len: usize) -> String {
    let end = off.saturating_add(len.min(MAX_STRING_BYTES));
    let raw = b.get(off..end.min(b.len())).unwrap_or_default();
    let cut = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..cut]).into_owned()
}

/// Length in bytes of an audit address of the given `ad_type`, which BSM gives
/// as a byte count rather than a family: 4 for IPv4, 16 for IPv6.
fn addr_len(ad_type: u32) -> Option<usize> {
    match ad_type {
        4 => Some(4),
        16 => Some(16),
        _ => None,
    }
}

/// Render an audit address of `ad_type` bytes at `off`.
fn addr_text(b: &[u8], off: usize, ad_type: u32) -> Option<String> {
    let len = addr_len(ad_type)?;
    let raw = b.get(off..off.checked_add(len)?)?;
    Some(match len {
        4 => std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string(),
        _ => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            std::net::Ipv6Addr::from(octets).to_string()
        }
    })
}

// --- token lengths -----------------------------------------------------------

/// Total byte length of the token beginning at `p`, or `None` when this reader
/// cannot say.
///
/// `None` is the honest answer in two different situations and the caller must
/// treat them the same way — stop walking and report — because both leave the
/// rest of the record unreachable:
///
/// * the token identifier is not one this reader knows; or
/// * it is known, but its own length fields run past the end of the record.
///
/// Nothing is skipped on a guess. A token of unknown length cannot be stepped
/// over, because the next byte after it is only knowable by knowing where it
/// ended.
fn token_len(rec: &[u8], p: usize) -> Option<usize> {
    let id = u8_at(rec, p)?;
    let len = match id {
        AUT_TRAILER => 7,
        AUT_HEADER32 => 18,
        AUT_HEADER64 => 26,
        AUT_HEADER32_EX => 1 + 4 + 1 + 2 + 2 + 4 + addr_len(u32_at(rec, p + 10)?)? + 4 + 4,
        AUT_HEADER64_EX => 1 + 4 + 1 + 2 + 2 + 4 + addr_len(u32_at(rec, p + 10)?)? + 8 + 8,
        AUT_DATA => {
            // unit_print, unit_type, unit_count, then count items of the size
            // the unit type names.
            let unit = u8_at(rec, p + 2)?;
            let count = u8_at(rec, p + 3)? as usize;
            let size = match unit {
                // AUR_BYTE / AUR_CHAR, AUR_SHORT, AUR_INT32, AUR_INT64.
                0 | 1 => 1,
                2 => 2,
                3 => 4,
                4 => 8,
                _ => return None,
            };
            4 + count.checked_mul(size)?
        }
        AUT_IPC => 6,
        AUT_PATH | AUT_TEXT | AUT_OPAQUE | AUT_ZONENAME => 3 + u16_at(rec, p + 1)? as usize,
        AUT_SUBJECT32 | AUT_PROCESS32 => 37,
        AUT_SUBJECT64 | AUT_PROCESS64 => 41,
        AUT_SUBJECT32_EX | AUT_PROCESS32_EX => 37 + addr_len(u32_at(rec, p + 33)?)?,
        AUT_SUBJECT64_EX | AUT_PROCESS64_EX => 41 + addr_len(u32_at(rec, p + 37)?)?,
        AUT_RETURN32 => 6,
        AUT_RETURN64 => 10,
        AUT_IN_ADDR => 5,
        AUT_IN_ADDR_EX => 21,
        AUT_IP => 21,
        AUT_IPORT => 3,
        AUT_ARG32 => 8 + u16_at(rec, p + 6)? as usize,
        AUT_ARG64 => 12 + u16_at(rec, p + 10)? as usize,
        AUT_SOCKET => 15,
        AUT_SOCKET_EX => {
            let at = u16_at(rec, p + 5)? as usize;
            if at != 4 && at != 16 {
                return None;
            }
            9 + 2 * at
        }
        AUT_SOCKINET32 => 9,
        AUT_SOCKINET128 => 21,
        AUT_SOCKUNIX => {
            // Family, then a NUL-terminated path. An unterminated one is a
            // length this reader cannot state.
            let start = p + 3;
            let rel = rec.get(start..)?.iter().position(|&c| c == 0)?;
            3 + rel + 1
        }
        AUT_SEQ => 5,
        AUT_ATTR32 => 29,
        AUT_ATTR64 => 33,
        AUT_GROUPS | AUT_NEWGROUPS => 3 + 4 * u16_at(rec, p + 1)? as usize,
        AUT_PRIV | AUT_UPRIV => 4 + u16_at(rec, p + 2)? as usize,
        AUT_EXEC_ARGS | AUT_EXEC_ENV => {
            let count = u32_at(rec, p + 1)? as usize;
            let mut q = p + 5;
            for _ in 0..count {
                let rel = rec.get(q..)?.iter().position(|&c| c == 0)?;
                q = q.checked_add(rel)?.checked_add(1)?;
            }
            q.checked_sub(p)?
        }
        AUT_CMD => {
            let mut q = p + 1;
            for _ in 0..2 {
                let n = u16_at(rec, q)? as usize;
                q = q.checked_add(2)?;
                for _ in 0..n {
                    let l = u16_at(rec, q)? as usize;
                    q = q.checked_add(2)?.checked_add(l)?;
                }
            }
            q.checked_sub(p)?
        }
        AUT_EXIT => 9,
        AUT_IPC_PERM => 29,
        AUT_IDENTITY => {
            let mut q = p.checked_add(5)?;
            // Signing id and team id each carry a counted string followed by a
            // one-byte "was it truncated" flag; the cdhash carries only the
            // counted bytes.
            for trailing_flag in [1usize, 1, 0] {
                let l = u16_at(rec, q)? as usize;
                q = q
                    .checked_add(2)?
                    .checked_add(l)?
                    .checked_add(trailing_flag)?;
            }
            q.checked_sub(p)?
        }
        _ => return None,
    };
    // A length that runs past the record is not a length. Reporting it would
    // read the next record's bytes as this record's fields.
    if len == 0 || p.checked_add(len)? > rec.len() {
        return None;
    }
    Some(len)
}

/// True when this token identifier begins a record.
fn is_header(id: u8) -> bool {
    matches!(
        id,
        AUT_HEADER32 | AUT_HEADER32_EX | AUT_HEADER64 | AUT_HEADER64_EX
    )
}

// --- decoded pieces ----------------------------------------------------------

/// The `AUT_SUBJECT*` token: the process and account the audited operation is
/// attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Audit user id — the account the *session* is attributed to, which
    /// survives a `su` where `euid` does not. `None` where the field holds
    /// `AU_DEFAUDITID` (`-1`), meaning the operation was never attributed to a
    /// logged-in user.
    pub audit_uid: Option<u32>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub real_uid: u32,
    pub real_gid: u32,
    pub pid: u32,
    /// Audit session id, which Darwin's session events key on.
    pub session_id: u32,
    /// Terminal id's port. On a network login this is the **remote** port.
    pub terminal_port: u64,
    /// Terminal id's machine address, when the token carries one and it is not
    /// all zero.
    ///
    /// `None` for a local login: `0.0.0.0` there is the absence of a peer, and
    /// printing it would name an address nothing came from.
    pub terminal_address: Option<String>,
}

/// `AUT_IDENTITY`, Darwin's code-signing token: which signed binary asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub signer_type: u32,
    pub signing_id: String,
    pub signing_id_truncated: bool,
    pub team_id: String,
    pub team_id_truncated: bool,
    /// Lower-case hex of the code directory hash, which identifies the exact
    /// binary rather than its name.
    pub cdhash: String,
}

/// Why a record's tokens could not be accounted for.
///
/// Each of these means the same thing to an examiner — *some of this record
/// was not read* — and each is reported with the offset it happened at, so the
/// claim can be checked against the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordFlaw {
    /// A token identifier this reader does not know. Everything after it in
    /// the record is unreachable, because its length is what says where the
    /// next token starts.
    UnknownToken { id: u8, offset: usize },
    /// A known token whose own length fields run past the end of the record.
    TokenOverrunsRecord { id: u8, offset: usize },
    /// The tokens tiled, but stopped short of the record's end.
    WalkEndedShort {
        ended_at: usize,
        record_bytes: usize,
    },
    /// The last seven bytes are not a trailer carrying `0xB105`.
    TrailerMissing,
    /// The trailer's byte count disagrees with the header's — the two
    /// independent statements of the record's length do not match.
    TrailerCountDisagrees { header: u32, trailer: u32 },
    /// [`MAX_TOKENS_PER_RECORD`] stopped the walk.
    TokenCapReached,
}

impl RecordFlaw {
    /// Machine-readable tag emitted on the record.
    pub fn tag(&self) -> &'static str {
        match self {
            RecordFlaw::UnknownToken { .. } => "unknown_token",
            RecordFlaw::TokenOverrunsRecord { .. } => "token_overruns_record",
            RecordFlaw::WalkEndedShort { .. } => "token_walk_ended_short",
            RecordFlaw::TrailerMissing => "trailer_missing",
            RecordFlaw::TrailerCountDisagrees { .. } => "trailer_count_disagrees",
            RecordFlaw::TokenCapReached => "token_cap_reached",
        }
    }

    /// The sentence an examiner reads.
    pub fn detail(&self) -> String {
        match self {
            RecordFlaw::UnknownToken { id, offset } => format!(
                "token identifier 0x{id:02x} at offset {offset} within the record is not one this \
                 reader knows, and a token of unknown length cannot be stepped over, so every \
                 field after it was not read"
            ),
            RecordFlaw::TokenOverrunsRecord { id, offset } => format!(
                "token 0x{id:02x} at offset {offset} within the record declares a length that \
                 runs past the record's own byte count, so it and everything after it were not \
                 read"
            ),
            RecordFlaw::WalkEndedShort {
                ended_at,
                record_bytes,
            } => format!(
                "the tokens accounted for {ended_at} of the record's {record_bytes} bytes; the \
                 remainder was not read, and a field decoded from a record that does not tile \
                 may have been read at the wrong offset"
            ),
            RecordFlaw::TrailerMissing => "the record's last seven bytes are not a trailer token \
                 carrying the 0xB105 magic, so its length was stated only once and the fields \
                 decoded from it are uncorroborated"
                .to_string(),
            RecordFlaw::TrailerCountDisagrees { header, trailer } => format!(
                "the header states {header} bytes and the trailer states {trailer}; the two \
                 independent statements of this record's length disagree, so where it ends is \
                 not established"
            ),
            RecordFlaw::TokenCapReached => format!(
                "the token walk stopped at the reader's cap of {MAX_TOKENS_PER_RECORD} tokens in \
                 one record; the rest of the record was not read"
            ),
        }
    }
}

/// One decoded audit record.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    /// Offset of the record within the trail, so a claim can be checked.
    pub offset: usize,
    /// Byte count the header declares.
    pub bytes: u32,
    /// Audit record version. 11 on Darwin.
    pub version: u8,
    /// Numeric event identifier.
    pub event: u32,
    /// Event modifier bits.
    pub modifier: u16,
    /// Event time, UTC Unix seconds. The kernel writes UTC; no conversion is
    /// applied.
    pub seconds: i64,
    /// The header's second time field, in **milliseconds** — measured from the
    /// corpus, see the module docs. `None` when it is 1,000 or more, which is
    /// out of range for the field and therefore not folded into the timestamp.
    pub millis: Option<u32>,
    /// The host's own address, on the `_EX` header forms that carry one.
    pub machine_address: Option<String>,
    pub subject: Option<Subject>,
    /// `AUT_RETURN*`: the error status byte and the return value.
    pub status: Option<u8>,
    pub return_value: Option<i64>,
    pub texts: Vec<String>,
    pub paths: Vec<String>,
    /// `AUT_ARG*`: argument number, value, and the label the writer gave it.
    pub args: Vec<(u8, u64, String)>,
    pub identity: Option<Identity>,
    /// Token identifiers seen, in order, so the record's shape is auditable
    /// even where a field was not modelled.
    pub token_ids: Vec<u8>,
    /// True when a text, path or argument list hit [`MAX_LIST_ITEMS`].
    pub lists_truncated: bool,
    /// Why part of the record was not read, if any.
    pub flaw: Option<RecordFlaw>,
}

impl AuditRecord {
    /// Symbolic event name, or `None` when the identifier is outside the
    /// shipped table.
    pub fn event_name(&self) -> Option<&'static str> {
        event_def(self.event).map(|d| d.symbol)
    }

    /// Event class, or `None` when the identifier is outside the table.
    pub fn event_class(&self) -> Option<EventClass> {
        event_def(self.event).map(|d| d.class)
    }

    /// Whether the audited operation succeeded, as the return token states it.
    ///
    /// `None` when there is no return token: silence about an outcome is not
    /// success, and a record with no `AUT_RETURN` must not be shown as one
    /// that succeeded.
    pub fn succeeded(&self) -> Option<bool> {
        self.status.map(|s| s == 0)
    }

    /// True when the event is one at which a secret was offered.
    pub fn is_credential_attempt(&self) -> bool {
        event_def(self.event).is_some_and(|d| d.credential_attempt)
    }

    /// True when this record is a **refused credential attempt** — somebody
    /// offered a password or a key and the system said no.
    ///
    /// Requires all three: an event at which a secret was offered, a return
    /// token, and a non-zero status. A refused Security Server *authorization*
    /// is not one of these (see [`EventDef::credential_attempt`]), an
    /// administrative failure is not, and a record whose outcome was never
    /// written is not either.
    pub fn is_failed_authentication(&self) -> bool {
        self.is_credential_attempt() && self.succeeded() == Some(false)
    }
}

// --- record decoding ---------------------------------------------------------

/// Decode the header at the start of `rec`, returning the fields and the
/// header's own length.
fn decode_header(rec: &[u8]) -> Option<(AuditRecord, usize)> {
    let id = u8_at(rec, 0)?;
    if !is_header(id) {
        return None;
    }
    let bytes = u32_at(rec, 1)?;
    let version = u8_at(rec, 5)?;
    let event = u16_at(rec, 6)? as u32;
    let modifier = u16_at(rec, 8)?;

    // The `_EX` forms insert the host's address between the modifier and the
    // time, so the time's offset depends on the form and on the address size.
    let (machine_address, time_off) = match id {
        AUT_HEADER32 | AUT_HEADER64 => (None, 10),
        _ => {
            let ad_type = u32_at(rec, 10)?;
            let len = addr_len(ad_type)?;
            (addr_text(rec, 14, ad_type), 14 + len)
        }
    };
    let wide_time = matches!(id, AUT_HEADER64 | AUT_HEADER64_EX);
    let (seconds, millis_raw, header_len) = if wide_time {
        (
            i64::try_from(u64_at(rec, time_off)?).ok()?,
            u64_at(rec, time_off + 8)?,
            time_off + 16,
        )
    } else {
        (
            i64::from(u32_at(rec, time_off)?),
            u64::from(u32_at(rec, time_off + 4)?),
            time_off + 8,
        )
    };
    // A milliseconds field at or past a full second is out of range for what
    // this field is. It is reported as absent rather than folded into the
    // timestamp, which would move the event.
    let millis = u32::try_from(millis_raw).ok().filter(|m| *m < 1000);

    Some((
        AuditRecord {
            offset: 0,
            bytes,
            version,
            event,
            modifier,
            seconds,
            millis,
            machine_address,
            subject: None,
            status: None,
            return_value: None,
            texts: Vec::new(),
            paths: Vec::new(),
            args: Vec::new(),
            identity: None,
            token_ids: Vec::new(),
            lists_truncated: false,
            flaw: None,
        },
        header_len,
    ))
}

/// Decode an `AUT_SUBJECT*` / `AUT_PROCESS*` token.
fn decode_subject(rec: &[u8], p: usize, id: u8) -> Option<Subject> {
    let f = |i: usize| u32_at(rec, p + 1 + 4 * i);
    let audit_uid = f(0)?;
    let (terminal_port, after_port) = match id {
        AUT_SUBJECT64 | AUT_PROCESS64 | AUT_SUBJECT64_EX | AUT_PROCESS64_EX => {
            (u64_at(rec, p + 29)?, p + 37)
        }
        _ => (u64::from(u32_at(rec, p + 29)?), p + 33),
    };
    let terminal_address = match id {
        AUT_SUBJECT32 | AUT_PROCESS32 | AUT_SUBJECT64 | AUT_PROCESS64 => {
            // The plain forms carry a bare 4-byte machine address.
            addr_text(rec, after_port, 4)
        }
        _ => {
            let ad_type = u32_at(rec, after_port)?;
            addr_text(rec, after_port + 4, ad_type)
        }
    };
    Some(Subject {
        // `-1` is AU_DEFAUDITID: not attributed to any logged-in account.
        audit_uid: (audit_uid != u32::MAX).then_some(audit_uid),
        effective_uid: f(1)?,
        effective_gid: f(2)?,
        real_uid: f(3)?,
        real_gid: f(4)?,
        pid: f(5)?,
        session_id: f(6)?,
        terminal_port,
        // An all-zero terminal address is the absence of a peer, not the
        // address 0.0.0.0.
        terminal_address: terminal_address.filter(|a| a != "0.0.0.0" && a != "::"),
    })
}

/// Decode `AUT_IDENTITY`.
fn decode_identity(rec: &[u8], p: usize) -> Option<Identity> {
    let signer_type = u32_at(rec, p + 1)?;
    let mut q = p + 5;
    let sid_len = u16_at(rec, q)? as usize;
    let signing_id = counted_string(rec, q + 2, sid_len);
    q += 2 + sid_len;
    let signing_id_truncated = u8_at(rec, q)? != 0;
    q += 1;
    let tid_len = u16_at(rec, q)? as usize;
    let team_id = counted_string(rec, q + 2, tid_len);
    q += 2 + tid_len;
    let team_id_truncated = u8_at(rec, q)? != 0;
    q += 1;
    let hash_len = u16_at(rec, q)? as usize;
    let raw = rec.get(q + 2..q + 2 + hash_len)?;
    let mut cdhash = String::with_capacity(hash_len * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in raw {
        cdhash.push(char::from(HEX[usize::from(byte >> 4)]));
        cdhash.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Some(Identity {
        signer_type,
        signing_id,
        signing_id_truncated,
        team_id,
        team_id_truncated,
        cdhash,
    })
}

/// Decode one whole record from `rec`, whose length is the byte count its
/// header declared.
fn decode_record(rec: &[u8], offset: usize) -> Option<AuditRecord> {
    let (mut out, header_len) = decode_header(rec)?;
    out.offset = offset;
    out.token_ids.push(rec[0]);

    // The trailer is checked first and independently of the token walk: it is
    // the record's second, separate statement of its own length, and it is
    // what makes the walk's result trustworthy rather than merely consistent
    // with itself.
    let trailer_off = rec.len().saturating_sub(7);
    let trailer_ok = u8_at(rec, trailer_off) == Some(AUT_TRAILER)
        && u16_at(rec, trailer_off + 1) == Some(TRAILER_MAGIC);
    if !trailer_ok {
        out.flaw = Some(RecordFlaw::TrailerMissing);
    } else {
        let count = u32_at(rec, trailer_off + 3).unwrap_or(0);
        if count as usize != rec.len() {
            out.flaw = Some(RecordFlaw::TrailerCountDisagrees {
                header: out.bytes,
                trailer: count,
            });
        }
    }

    let mut p = header_len;
    let mut tokens = 1usize;
    while p < rec.len() {
        if tokens >= MAX_TOKENS_PER_RECORD {
            out.flaw = out.flaw.or(Some(RecordFlaw::TokenCapReached));
            return Some(out);
        }
        let id = rec[p];
        let Some(len) = token_len(rec, p) else {
            // Two different causes, one consequence: the walk cannot continue.
            let flaw = if token_len_is_known(id) {
                RecordFlaw::TokenOverrunsRecord { id, offset: p }
            } else {
                RecordFlaw::UnknownToken { id, offset: p }
            };
            out.flaw = out.flaw.or(Some(flaw));
            return Some(out);
        };
        out.token_ids.push(id);
        tokens += 1;

        match id {
            AUT_TEXT => push_capped(
                &mut out.texts,
                counted_string(rec, p + 3, len - 3),
                &mut out.lists_truncated,
            ),
            AUT_PATH => push_capped(
                &mut out.paths,
                counted_string(rec, p + 3, len - 3),
                &mut out.lists_truncated,
            ),
            AUT_SUBJECT32 | AUT_SUBJECT64 | AUT_SUBJECT32_EX | AUT_SUBJECT64_EX => {
                // First subject wins: it is the one the header's event is
                // attributed to.
                if out.subject.is_none() {
                    out.subject = decode_subject(rec, p, id);
                }
            }
            AUT_RETURN32 => {
                out.status = u8_at(rec, p + 1);
                out.return_value = u32_at(rec, p + 2).map(|v| i64::from(v as i32));
            }
            AUT_RETURN64 => {
                out.status = u8_at(rec, p + 1);
                out.return_value = u64_at(rec, p + 2).map(|v| v as i64);
            }
            AUT_ARG32 => {
                if let (Some(no), Some(v), Some(l)) =
                    (u8_at(rec, p + 1), u32_at(rec, p + 2), u16_at(rec, p + 6))
                {
                    let text = counted_string(rec, p + 8, l as usize);
                    push_capped(
                        &mut out.args,
                        (no, u64::from(v), text),
                        &mut out.lists_truncated,
                    );
                }
            }
            AUT_ARG64 => {
                if let (Some(no), Some(v), Some(l)) =
                    (u8_at(rec, p + 1), u64_at(rec, p + 2), u16_at(rec, p + 10))
                {
                    let text = counted_string(rec, p + 12, l as usize);
                    push_capped(&mut out.args, (no, v, text), &mut out.lists_truncated);
                }
            }
            // First identity wins, for the same reason the first subject
            // does: it is the one the header's event is attributed to.
            AUT_IDENTITY if out.identity.is_none() => {
                out.identity = decode_identity(rec, p);
            }
            _ => {}
        }
        p += len;
    }

    if out.flaw.is_none() && p != rec.len() {
        out.flaw = Some(RecordFlaw::WalkEndedShort {
            ended_at: p,
            record_bytes: rec.len(),
        });
    }
    Some(out)
}

/// True when `id` names a token whose length rule this reader has, regardless
/// of whether that rule succeeded on the bytes at hand.
///
/// This is what tells "we do not know this token" apart from "we know it and
/// its length is impossible here" — two different findings for an examiner.
fn token_len_is_known(id: u8) -> bool {
    matches!(
        id,
        AUT_TRAILER
            | AUT_HEADER32
            | AUT_HEADER32_EX
            | AUT_HEADER64
            | AUT_HEADER64_EX
            | AUT_DATA
            | AUT_IPC
            | AUT_PATH
            | AUT_TEXT
            | AUT_OPAQUE
            | AUT_ZONENAME
            | AUT_SUBJECT32
            | AUT_SUBJECT64
            | AUT_SUBJECT32_EX
            | AUT_SUBJECT64_EX
            | AUT_PROCESS32
            | AUT_PROCESS64
            | AUT_PROCESS32_EX
            | AUT_PROCESS64_EX
            | AUT_RETURN32
            | AUT_RETURN64
            | AUT_IN_ADDR
            | AUT_IN_ADDR_EX
            | AUT_IP
            | AUT_IPORT
            | AUT_ARG32
            | AUT_ARG64
            | AUT_SOCKET
            | AUT_SOCKET_EX
            | AUT_SOCKINET32
            | AUT_SOCKINET128
            | AUT_SOCKUNIX
            | AUT_SEQ
            | AUT_ATTR32
            | AUT_ATTR64
            | AUT_GROUPS
            | AUT_NEWGROUPS
            | AUT_PRIV
            | AUT_UPRIV
            | AUT_EXEC_ARGS
            | AUT_EXEC_ENV
            | AUT_CMD
            | AUT_EXIT
            | AUT_IPC_PERM
            | AUT_IDENTITY
    )
}

fn push_capped<T>(list: &mut Vec<T>, item: T, truncated: &mut bool) {
    if list.len() >= MAX_LIST_ITEMS {
        *truncated = true;
        return;
    }
    list.push(item);
}

// --- trail walking -----------------------------------------------------------

/// What a whole trail came to.
#[derive(Debug, Default)]
struct TrailWalk {
    records: Vec<AuditRecord>,
    /// Bytes the walk accounted for.
    bytes_walked: usize,
    /// True when [`MAX_RECORDS`] stopped the walk.
    record_cap_reached: bool,
    /// Bytes left at the end that are not a whole record — a trail cut off
    /// mid-record, which is what a `.not_terminated` file can be and what a
    /// carved fragment usually is.
    trailing_bytes: usize,
    /// Why the walk stopped early, if it did.
    stop_reason: Option<&'static str>,
}

/// Walk `data` as a sequence of records.
///
/// Returns `None` when the first bytes are not a record — which is how this
/// reader declines a file that is not a trail. There is deliberately no
/// resynchronisation: scanning forward for the next plausible header would
/// turn a fragment of some other file into a set of confident audit records.
fn walk_trail(data: &[u8]) -> Option<TrailWalk> {
    if data.len() < MIN_RECORD_BYTES || !is_header(data[0]) {
        return None;
    }
    let mut out = TrailWalk::default();
    let mut off = 0usize;
    while off < data.len() {
        if out.records.len() >= MAX_RECORDS {
            out.record_cap_reached = true;
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_cap_reached");
            break;
        }
        let Some(id) = u8_at(data, off) else { break };
        if !is_header(id) {
            // The previous record's byte count did not land on a header, so
            // where the next record begins is not established. Stop: the
            // alternative is guessing.
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("next_record_does_not_begin_with_a_header");
            break;
        }
        // The byte count sits one byte in, after the token identifier.
        let Some(bytes) = u32_at(data, off + 1) else {
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_header_is_truncated");
            break;
        };
        let bytes = bytes as usize;
        if bytes < MIN_RECORD_BYTES {
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_byte_count_is_below_one_record");
            break;
        }
        let Some(rec) = data.get(off..off.saturating_add(bytes)) else {
            // The trail ends inside a record. Normal for a trail still being
            // written, and for a carved fragment.
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("trail_ends_mid_record");
            break;
        };
        let Some(record) = decode_record(rec, off) else {
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_header_could_not_be_decoded");
            break;
        };
        out.records.push(record);
        out.bytes_walked = off + bytes;
        off += bytes;
    }
    // A first record that does not validate on either count is not a trail.
    // One structural coincidence is possible; both together are not.
    let first_is_real = out
        .records
        .first()
        .is_some_and(|r| !matches!(r.flaw, Some(RecordFlaw::TrailerMissing)));
    if !first_is_real {
        return None;
    }
    Some(out)
}

// --- artifact emission -------------------------------------------------------

pub struct OpenBsmParser;

/// True when a name looks like an audit trail's.
///
/// Used only to decide whether a file that *failed* to parse is worth a
/// refusal record. Selection itself is by content, so a trail under any name
/// is still read.
fn named_as_trail(name: &str, path: &str) -> bool {
    if path.contains("/var/audit/") || path.contains("\\var\\audit\\") {
        return true;
    }
    let base = basename_lower(name);
    base.ends_with(".not_terminated")
        || base.ends_with(".crash_recovery")
        || base == "current"
        || (base.len() == 29
            && base.as_bytes()[14] == b'.'
            && base
                .bytes()
                .enumerate()
                .all(|(i, c)| i == 14 || c.is_ascii_digit()))
}

fn provenance(meta: &mut Map<String, Value>, file_name: &str) {
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert("source_format".into(), json!("openbsm_audit_trail"));
}

/// The record an examiner reads for one audit event.
fn event_artifact(artifact: &Artifact, file_name: &str, rec: &AuditRecord) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("AuditEvent"));
    meta.insert("subtype".into(), json!("openbsm_audit_event"));
    provenance(&mut meta, file_name);
    meta.insert("record_offset".into(), json!(rec.offset));
    meta.insert("record_bytes".into(), json!(rec.bytes));
    meta.insert("record_version".into(), json!(rec.version));
    meta.insert("event_id".into(), json!(rec.event));
    meta.insert("event_modifier".into(), json!(rec.modifier));

    let mut reasons = Vec::new();
    match rec.event_name() {
        Some(symbol) => {
            meta.insert("event_name".into(), json!(symbol));
            if let Some(names) = ambiguous_names(rec.event) {
                // The record carries a number, and Apple's table gives that
                // number more than one name. Both are shown; neither is
                // presented as the event's name.
                meta.insert("event_name_alternatives".into(), json!(names));
                meta.insert(
                    "event_name_note".into(),
                    json!(format!(
                        "event {} is given more than one symbolic name ({}), and the record \
                         carries only the number, so which was meant is not established by this \
                         file",
                        rec.event,
                        names.join(" / ")
                    )),
                );
            }
        }
        // No name is invented for a number outside the table. The identifier
        // is what the file holds and is enough to look up.
        None => reasons.push((
            IncompleteReason::Unmapped,
            format!(
                "event identifier {} is outside this reader's event table, so the record is \
                 reported by number and its class — which is what decides whether it is a login \
                 record — is unknown",
                rec.event
            ),
        )),
    }
    if let Some(class) = rec.event_class() {
        meta.insert("event_class".into(), json!(class.as_str()));
        meta.insert("event_class_description".into(), json!(class.description()));
        // Whether a secret was offered here, which is not the same question as
        // the class: a refused Security Server authorization is an `aa` event
        // and is not a credential attempt.
        meta.insert(
            "credential_attempt".into(),
            json!(rec.is_credential_attempt()),
        );
    }

    meta.insert("timestamp".into(), json!(rec.seconds));
    meta.insert("date".into(), json!(rec.seconds));
    if let Some(ms) = rec.millis {
        meta.insert("timestamp_millis".into(), json!(ms));
        if let Some(text) = to_rfc3339_nanos(rec.seconds, ms * 1_000_000) {
            meta.insert("timestamp_rfc3339".into(), json!(text));
        }
    } else if let Some(text) = to_rfc3339_nanos(rec.seconds, 0) {
        meta.insert("timestamp_rfc3339".into(), json!(text));
    }

    match rec.succeeded() {
        Some(true) => meta.insert("outcome".into(), json!("succeeded")),
        Some(false) => meta.insert("outcome".into(), json!("failed")),
        // Silence about an outcome is not success.
        None => meta.insert("outcome".into(), json!("not_recorded")),
    };
    if let Some(status) = rec.status {
        meta.insert("return_status".into(), json!(status));
    }
    if let Some(value) = rec.return_value {
        meta.insert("return_value".into(), json!(value));
    }
    if let Some(addr) = &rec.machine_address {
        meta.insert("host_address".into(), json!(addr));
    }

    if let Some(s) = &rec.subject {
        match s.audit_uid {
            Some(uid) => meta.insert("audit_user_id".into(), json!(uid)),
            // AU_DEFAUDITID: the operation was never attributed to a
            // logged-in account. Absent, not zero — zero is root.
            None => meta.insert(
                "audit_user_id_absent".into(),
                json!(
                    "the record carries AU_DEFAUDITID, so it is attributed to no logged-in \
                       account"
                ),
            ),
        };
        meta.insert("effective_uid".into(), json!(s.effective_uid));
        meta.insert("effective_gid".into(), json!(s.effective_gid));
        meta.insert("real_uid".into(), json!(s.real_uid));
        meta.insert("real_gid".into(), json!(s.real_gid));
        meta.insert("pid".into(), json!(s.pid));
        meta.insert("audit_session_id".into(), json!(s.session_id));
        meta.insert("terminal_port".into(), json!(s.terminal_port));
        if let Some(addr) = &s.terminal_address {
            meta.insert("source_address".into(), json!(addr));
        }
    }

    if !rec.texts.is_empty() {
        meta.insert("texts".into(), json!(rec.texts));
        // The daemon's own words, quoted rather than parsed. Their wording is
        // not specified anywhere, so no field is derived from them.
        meta.insert("message".into(), json!(rec.texts.join(" | ")));
    }
    if !rec.paths.is_empty() {
        meta.insert("paths".into(), json!(rec.paths));
    }
    if !rec.args.is_empty() {
        let args: Vec<Value> = rec
            .args
            .iter()
            .map(|(no, value, label)| json!({"argument": no, "value": value, "label": label}))
            .collect();
        meta.insert("arguments".into(), json!(args));
    }
    if let Some(id) = &rec.identity {
        meta.insert("signing_id".into(), json!(id.signing_id));
        meta.insert("signer_type".into(), json!(id.signer_type));
        if !id.team_id.is_empty() {
            meta.insert("team_id".into(), json!(id.team_id));
        }
        meta.insert("cdhash".into(), json!(id.cdhash));
        if id.signing_id_truncated || id.team_id_truncated {
            reasons.push((
                IncompleteReason::CapReached,
                "the writer marked the code-signing identity truncated, so the signing or team \
                 id shown is a prefix of the real one"
                    .to_string(),
            ));
        }
    }
    meta.insert(
        "token_ids".into(),
        json!(rec
            .token_ids
            .iter()
            .map(|t| format!("0x{t:02x}"))
            .collect::<Vec<_>>()),
    );

    if rec.lists_truncated {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "more than {MAX_LIST_ITEMS} text, path or argument tokens in one record; the \
                 lists shown are the first of them"
            ),
        ));
    }
    if let Some(flaw) = &rec.flaw {
        meta.insert("structure_flaw".into(), json!(flaw.tag()));
        reasons.push((IncompleteReason::UnresolvedStructure, flaw.detail()));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    meta.insert("name".into(), json!(event_name_line(rec)));
    meta.insert("short_desc".into(), json!(event_short_desc(rec)));
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("openbsm_audit_event")
}

fn event_name_line(rec: &AuditRecord) -> String {
    let what = match rec.event_name() {
        Some(symbol) => symbol.to_string(),
        None => format!("audit event {}", rec.event),
    };
    match rec.subject.as_ref().and_then(|s| s.audit_uid) {
        Some(uid) => format!("{what} (uid {uid})"),
        None => what,
    }
}

fn event_short_desc(rec: &AuditRecord) -> String {
    let mut parts = Vec::new();
    parts.push(match rec.event_name() {
        Some(symbol) => symbol.to_string(),
        None => format!("audit event {}", rec.event),
    });
    match rec.succeeded() {
        Some(true) => parts.push("succeeded".into()),
        Some(false) => parts.push("FAILED".into()),
        None => parts.push("outcome not recorded".into()),
    }
    if let Some(s) = &rec.subject {
        if let Some(uid) = s.audit_uid {
            parts.push(format!("uid {uid}"));
        }
        if let Some(addr) = &s.terminal_address {
            parts.push(format!("from {addr}"));
        }
    }
    if let Some(text) = rec.texts.first() {
        parts.push(format!("\"{text}\""));
    }
    parts.join("; ")
}

/// A failed authentication, emitted as the same record type `btmp` produces so
/// that "was there a brute force" is answered in one place on both platforms.
///
/// No account **name** is set: the trail identifies the account by number, and
/// the daemon's prose is quoted rather than parsed (see the module docs).
fn failed_login_artifact(artifact: &Artifact, file_name: &str, rec: &AuditRecord) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("FailedLogin"));
    meta.insert("subtype".into(), json!("openbsm_failed_login"));
    provenance(&mut meta, file_name);
    // The existing FailedLogin producer is btmp; this one says where it came
    // from so the two are never confused on a screen that shows both.
    meta.insert("source_file".into(), json!("audit_trail"));
    meta.insert("time".into(), json!(rec.seconds));
    meta.insert("date".into(), json!(rec.seconds));
    meta.insert("event_id".into(), json!(rec.event));
    if let Some(symbol) = rec.event_name() {
        meta.insert("event_name".into(), json!(symbol));
        meta.insert("ut_type".into(), json!(symbol));
    }
    if let Some(class) = rec.event_class() {
        meta.insert("event_class".into(), json!(class.as_str()));
    }
    if let Some(status) = rec.status {
        meta.insert("return_status".into(), json!(status));
    }
    if let Some(value) = rec.return_value {
        meta.insert("return_value".into(), json!(value));
    }
    if let Some(s) = &rec.subject {
        if let Some(uid) = s.audit_uid {
            meta.insert("user_id".into(), json!(uid));
        }
        meta.insert("effective_uid".into(), json!(s.effective_uid));
        meta.insert("pid".into(), json!(s.pid));
        meta.insert("terminal_port".into(), json!(s.terminal_port));
        if let Some(addr) = &s.terminal_address {
            meta.insert("ip".into(), json!(addr));
        }
    }
    if let Some(text) = rec.texts.first() {
        meta.insert("message".into(), json!(text));
    }
    if let Some(id) = &rec.identity {
        meta.insert("signing_id".into(), json!(id.signing_id));
    }
    meta.insert(
        "attribution_note".into(),
        json!(
            "the audit trail names the account by number, not by name; the daemon's own \
               message is quoted verbatim and no account name is derived from it"
        ),
    );
    if let Some(flaw) = &rec.flaw {
        meta.insert("structure_flaw".into(), json!(flaw.tag()));
        let _ = stamp_incomplete(
            &mut meta,
            "content",
            &[(IncompleteReason::UnresolvedStructure, flaw.detail())],
        );
    }
    let who = match rec.subject.as_ref().and_then(|s| s.audit_uid) {
        Some(uid) => format!("uid {uid}"),
        None => "an unattributed session".to_string(),
    };
    let from = match rec
        .subject
        .as_ref()
        .and_then(|s| s.terminal_address.as_ref())
    {
        Some(addr) => format!(" from {addr}"),
        None => String::new(),
    };
    meta.insert(
        "name".into(),
        json!(format!("Failed authentication: {who}{from}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(match rec.texts.first() {
            Some(text) => format!("Failed authentication ({who}{from}): {text}"),
            None => format!("Failed authentication ({who}{from})"),
        }),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("openbsm_failed_login")
}

/// The provenance row: what was read, what it held, and what was not read.
fn status_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    walk: &TrailWalk,
    events_emitted: usize,
    failed_logins: usize,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("AuditTrailStatus"));
    meta.insert("subtype".into(), json!("openbsm_trail_status"));
    provenance(&mut meta, file_name);
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("bytes_walked".into(), json!(walk.bytes_walked));
    meta.insert("records_decoded".into(), json!(walk.records.len()));
    meta.insert("audit_events".into(), json!(events_emitted));
    meta.insert("refused_credential_attempts".into(), json!(failed_logins));

    // Refusals that are not credential attempts — Security Server
    // authorization denials, mostly. Counted so that "no failed logins" is
    // never read as "nothing was refused".
    let other_refusals = walk
        .records
        .iter()
        .filter(|r| r.succeeded() == Some(false) && !r.is_credential_attempt())
        .count();
    meta.insert("other_refused_operations".into(), json!(other_refusals));
    meta.insert(
        "refusal_note".into(),
        json!(
            "A refused credential attempt is somebody offering a password or a key and being \
               told no. A refused operation counted separately is policy — a Security Server \
               authorization denied, an administrative call refused — which happens routinely on \
               a machine nobody attacked and is not a login attempt."
        ),
    );

    let flawed = walk.records.iter().filter(|r| r.flaw.is_some()).count();
    meta.insert("records_with_structure_flaws".into(), json!(flawed));
    let unmapped = walk
        .records
        .iter()
        .filter(|r| r.event_name().is_none())
        .count();
    meta.insert("records_with_unmapped_event".into(), json!(unmapped));

    // The event histogram, which is what an examiner scans first: it says
    // whether this trail holds logins at all before any of them is opened.
    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    for rec in &walk.records {
        let key = match rec.event_name() {
            Some(symbol) => symbol.to_string(),
            None => format!("event_{}", rec.event),
        };
        *histogram.entry(key).or_default() += 1;
    }
    meta.insert("event_counts".into(), json!(histogram));
    if let (Some(first), Some(last)) = (walk.records.first(), walk.records.last()) {
        meta.insert("first_record_time".into(), json!(first.seconds));
        meta.insert("last_record_time".into(), json!(last.seconds));
    }
    meta.insert(
        "session_note".into(),
        json!(
            "An audit trail records events, not sessions. A login and the logout that ended it \
               are written by different processes, so no session is reconstructed here and no \
               duration is reported."
        ),
    );

    let mut reasons = Vec::new();
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(file_name)));
    }
    if walk.record_cap_reached {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "the walk stopped at the reader's cap of {MAX_RECORDS} records; the rest of the \
                 trail was not read"
            ),
        ));
    }
    if walk.trailing_bytes > 0 {
        meta.insert("trailing_bytes".into(), json!(walk.trailing_bytes));
        if let Some(why) = walk.stop_reason {
            meta.insert("walk_stop_reason".into(), json!(why));
        }
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} byte(s) at the end of the trail are not a whole record ({}); they were not \
                 read, and a trail still being written or recovered from a crash ends this way \
                 legitimately",
                walk.trailing_bytes,
                walk.stop_reason.unwrap_or("reason not recorded")
            ),
        ));
    }
    if flawed > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!("{flawed} record(s) did not account for all of their own bytes; each says why"),
        ));
    }
    if unmapped > 0 {
        reasons.push((
            IncompleteReason::Unmapped,
            format!(
                "{unmapped} record(s) carry an event identifier outside this reader's table and \
                 are reported by number; their class, which decides whether they are login \
                 records, is unknown"
            ),
        ));
    }
    let detail = stamp_incomplete(&mut meta, "content", &reasons);

    meta.insert(
        "name".into(),
        json!(format!("Audit trail parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(match &detail {
            Some(text) => format!(
                "{file_name}: {} records, {failed_logins} refused credential attempts — {text}",
                walk.records.len()
            ),
            None => format!(
                "{file_name}: {} records, {failed_logins} refused credential attempts",
                walk.records.len()
            ),
        }),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("openbsm_trail_status")
}

/// The record that says a file living where trails live was not read.
///
/// Without it a wiped or truncated `/var/audit` entry leaves no trace, which
/// reads exactly like a machine nobody ever logged into.
fn refusal_artifact(artifact: &Artifact, file_name: &str, staged: &Staged, why: &str) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("AuditTrailStatus"));
    meta.insert("subtype".into(), json!("openbsm_trail_not_parsed"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(false));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("failure_reason".into(), json!(why));
    meta.insert(
        "message".into(),
        json!(
            "This file sits where audit trails live but its contents could not be confirmed \
               as one, so nothing was parsed from it. Absence of audit records here is NOT \
               evidence that nothing was audited."
        ),
    );
    let reason = staged
        .incomplete_reason()
        .unwrap_or(IncompleteReason::UnresolvedStructure);
    let _ = stamp_incomplete(
        &mut meta,
        "content",
        &[(reason, format!("{}; {why}", staged.detail(file_name)))],
    );
    meta.insert(
        "name".into(),
        json!(format!("Audit trail not parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!("{file_name} was not parsed: {why}")),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("openbsm_trail_not_parsed")
}

impl ForensicsModule for OpenBsmParser {
    fn id(&self) -> &str {
        "macos.openbsm"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let file_name = if name.is_empty() {
            basename_lower(path)
        } else {
            name.to_string()
        };
        let named = named_as_trail(name, path);
        // A zero-byte file in /var/audit is itself notable: a wiped trail is a
        // classic anti-forensic move, and silence about it is the opposite of
        // what this reader is for.
        if ds.size() == 0 {
            if !named {
                return Ok(Vec::new());
            }
            let staged = Staged {
                bytes: Vec::new(),
                declared: 0,
                got: 0,
                capped: false,
            };
            return Ok(vec![refusal_artifact(
                artifact,
                &file_name,
                &staged,
                "the file is empty",
            )]);
        }

        let staged = Staged::read(ds.as_ref(), MAX_TRAIL_BYTES);
        let Some(walk) = walk_trail(&staged.bytes) else {
            if !named {
                return Ok(Vec::new());
            }
            debug!(
                artifact = %artifact.id,
                file = %file_name,
                "named as an audit trail but its first record does not validate"
            );
            return Ok(vec![refusal_artifact(
                artifact,
                &file_name,
                &staged,
                "the first bytes are not a record whose trailer confirms the byte count its \
                 header declares",
            )]);
        };

        let mut out: Vec<Artifact> = Vec::with_capacity(walk.records.len() + 1);
        let mut failed = 0usize;
        for rec in &walk.records {
            out.push(event_artifact(artifact, &file_name, rec));
            if rec.is_failed_authentication() {
                out.push(failed_login_artifact(artifact, &file_name, rec));
                failed += 1;
            }
        }
        out.push(status_artifact(
            artifact,
            &file_name,
            &staged,
            &walk,
            walk.records.len(),
            failed,
        ));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    // --- fixture construction ------------------------------------------------
    //
    // Records are written from literal offsets rather than through the
    // reader's own length table, so a mistake in that table cannot make a test
    // agree with itself.

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    fn be64(v: u64) -> [u8; 8] {
        v.to_be_bytes()
    }

    /// `AUT_HEADER32` with the byte count left for [`record`] to fill.
    fn header32(event: u16, secs: u32, millis: u32) -> Vec<u8> {
        let mut t = vec![0x14u8];
        t.extend_from_slice(&be32(0)); // byte count, filled in below
        t.push(11); // version, as Darwin writes it
        t.extend_from_slice(&be16(event));
        t.extend_from_slice(&be16(0)); // modifier
        t.extend_from_slice(&be32(secs));
        t.extend_from_slice(&be32(millis));
        t
    }

    /// `AUT_HEADER64`: the same fields with 64-bit time.
    fn header64(event: u16, secs: u64, millis: u64) -> Vec<u8> {
        let mut t = vec![0x74u8];
        t.extend_from_slice(&be32(0));
        t.push(11);
        t.extend_from_slice(&be16(event));
        t.extend_from_slice(&be16(0));
        t.extend_from_slice(&be64(secs));
        t.extend_from_slice(&be64(millis));
        t
    }

    /// `AUT_HEADER32_EX`: the host's own address sits between the modifier and
    /// the time, which is what moves every later field.
    fn header32_ex(event: u16, secs: u32, millis: u32, host: [u8; 4]) -> Vec<u8> {
        let mut t = vec![0x15u8];
        t.extend_from_slice(&be32(0));
        t.push(11);
        t.extend_from_slice(&be16(event));
        t.extend_from_slice(&be16(0));
        t.extend_from_slice(&be32(4)); // ad_type: four bytes of address
        t.extend_from_slice(&host);
        t.extend_from_slice(&be32(secs));
        t.extend_from_slice(&be32(millis));
        t
    }

    #[derive(Clone, Copy)]
    struct Subj {
        auid: u32,
        euid: u32,
        egid: u32,
        ruid: u32,
        rgid: u32,
        pid: u32,
        sid: u32,
        port: u32,
        addr: [u8; 4],
    }

    impl Default for Subj {
        fn default() -> Self {
            Subj {
                auid: 501,
                euid: 501,
                egid: 20,
                ruid: 501,
                rgid: 20,
                pid: 628,
                sid: 628,
                port: 62864,
                addr: [0, 0, 0, 0],
            }
        }
    }

    fn subject32(s: Subj) -> Vec<u8> {
        let mut t = vec![0x24u8];
        for v in [s.auid, s.euid, s.egid, s.ruid, s.rgid, s.pid, s.sid] {
            t.extend_from_slice(&be32(v));
        }
        t.extend_from_slice(&be32(s.port));
        t.extend_from_slice(&s.addr);
        t
    }

    fn subject32_ex(s: Subj) -> Vec<u8> {
        let mut t = vec![0x7au8];
        for v in [s.auid, s.euid, s.egid, s.ruid, s.rgid, s.pid, s.sid] {
            t.extend_from_slice(&be32(v));
        }
        t.extend_from_slice(&be32(s.port));
        t.extend_from_slice(&be32(4));
        t.extend_from_slice(&s.addr);
        t
    }

    fn subject64(s: Subj, port: u64) -> Vec<u8> {
        let mut t = vec![0x75u8];
        for v in [s.auid, s.euid, s.egid, s.ruid, s.rgid, s.pid, s.sid] {
            t.extend_from_slice(&be32(v));
        }
        t.extend_from_slice(&be64(port));
        t.extend_from_slice(&s.addr);
        t
    }

    fn return32(status: u8, value: i32) -> Vec<u8> {
        let mut t = vec![0x27u8, status];
        t.extend_from_slice(&be32(value as u32));
        t
    }

    fn counted(id: u8, text: &str) -> Vec<u8> {
        let mut t = vec![id];
        let bytes = text.as_bytes();
        t.extend_from_slice(&be16(bytes.len() as u16 + 1));
        t.extend_from_slice(bytes);
        t.push(0);
        t
    }

    fn text(s: &str) -> Vec<u8> {
        counted(0x28, s)
    }
    fn path(s: &str) -> Vec<u8> {
        counted(0x23, s)
    }

    fn arg32(no: u8, value: u32, label: &str) -> Vec<u8> {
        let mut t = vec![0x2du8, no];
        t.extend_from_slice(&be32(value));
        let bytes = label.as_bytes();
        t.extend_from_slice(&be16(bytes.len() as u16 + 1));
        t.extend_from_slice(bytes);
        t.push(0);
        t
    }

    fn identity(signing_id: &str, team_id: &str, cdhash: &[u8]) -> Vec<u8> {
        let mut t = vec![0xedu8];
        t.extend_from_slice(&be32(1)); // signer type
        t.extend_from_slice(&be16(signing_id.len() as u16 + 1));
        t.extend_from_slice(signing_id.as_bytes());
        t.push(0);
        t.push(0); // not truncated
        t.extend_from_slice(&be16(team_id.len() as u16 + 1));
        t.extend_from_slice(team_id.as_bytes());
        t.push(0);
        t.push(0);
        t.extend_from_slice(&be16(cdhash.len() as u16));
        t.extend_from_slice(cdhash);
        t
    }

    /// Assemble one record: the header (whose byte count is filled in), the
    /// tokens, and a trailer repeating that byte count.
    fn record(header: Vec<u8>, tokens: &[Vec<u8>]) -> Vec<u8> {
        let body: usize = tokens.iter().map(|t| t.len()).sum();
        let size = header.len() + body + 7;
        let mut out = header;
        out[1..5].copy_from_slice(&be32(size as u32));
        for t in tokens {
            out.extend_from_slice(t);
        }
        out.push(0x13);
        out.extend_from_slice(&be16(0xb105));
        out.extend_from_slice(&be32(size as u32));
        out
    }

    /// A plausible `AUE_openssh` record, the shape the corpus holds.
    fn ssh_record(secs: u32, status: u8, value: i32, message: &str, from: [u8; 4]) -> Vec<u8> {
        record(
            header32(32800, secs, 519),
            &[
                text(message),
                return32(status, value),
                subject32_ex(Subj {
                    addr: from,
                    ..Subj::default()
                }),
                identity("com.apple.sshd", "", &[0xb8, 0xeb, 0xfa, 0x4d]),
            ],
        )
    }

    fn run(bytes: Vec<u8>, name: &str, path_str: &str) -> Vec<Artifact> {
        run_source(Arc::new(ByteSliceDataSource::new(bytes)), name, path_str)
    }

    fn run_source(src: Arc<dyn DataSource>, name: &str, path_str: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": name, "path": path_str }),
        );
        OpenBsmParser
            .process(&art)
            .expect("never fails the pipeline")
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    fn status_of(out: &[Artifact]) -> &Value {
        of_type(out, "AuditTrailStatus")
            .first()
            .copied()
            .expect("every read or refused trail produces a status row")
    }

    fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|x| x.as_str())
    }
    fn n(v: &Value, key: &str) -> Option<i64> {
        v.get(key).and_then(|x| x.as_i64())
    }

    const TRAIL_PATH: &str = "/private/var/audit/20210405200450.not_terminated";

    // --- token and record decoding -------------------------------------------

    #[test]
    fn a_hand_written_record_decodes_field_by_field_at_the_documented_offsets() {
        let bytes = record(
            header32(45023, 1_617_653_227, 519),
            &[
                text("Verify password for record type Users 'eliflatt'"),
                return32(255, 5000),
                subject32(Subj {
                    auid: 501,
                    euid: 92,
                    egid: 92,
                    ruid: 92,
                    rgid: 92,
                    pid: 330,
                    sid: 100_006,
                    port: 837,
                    addr: [10, 0, 0, 4],
                }),
                path("/Local/Default"),
                arg32(1, 7, "attempt"),
                identity(
                    "com.apple.opendirectoryd",
                    "ABCDE12345",
                    &[0xde, 0xad, 0xbe, 0xef],
                ),
            ],
        );
        let rec = decode_record(&bytes, 0).expect("decodes");
        assert_eq!(rec.flaw, None, "a well-formed record has nothing to report");
        assert_eq!(rec.bytes as usize, bytes.len());
        assert_eq!(rec.version, 11);
        assert_eq!(rec.event, 45023);
        assert_eq!(rec.event_name(), Some("AUE_auth_user"));
        assert_eq!(rec.event_class(), Some(EventClass::AuthAuthorize));
        assert_eq!(rec.seconds, 1_617_653_227);
        assert_eq!(rec.millis, Some(519));
        assert_eq!(rec.status, Some(255));
        assert_eq!(rec.return_value, Some(5000));
        assert_eq!(rec.succeeded(), Some(false));
        assert!(rec.is_failed_authentication());
        assert_eq!(
            rec.texts,
            vec!["Verify password for record type Users 'eliflatt'"]
        );
        assert_eq!(rec.paths, vec!["/Local/Default"]);
        assert_eq!(rec.args, vec![(1u8, 7u64, "attempt".to_string())]);

        let subj = rec.subject.as_ref().expect("the subject token decodes");
        assert_eq!(subj.audit_uid, Some(501));
        assert_eq!(subj.effective_uid, 92);
        assert_eq!(subj.real_gid, 92);
        assert_eq!(subj.pid, 330);
        assert_eq!(subj.session_id, 100_006);
        assert_eq!(subj.terminal_port, 837);
        assert_eq!(subj.terminal_address.as_deref(), Some("10.0.0.4"));

        let id = rec.identity.as_ref().expect("the identity token decodes");
        assert_eq!(id.signing_id, "com.apple.opendirectoryd");
        assert_eq!(id.team_id, "ABCDE12345");
        assert_eq!(id.cdhash, "deadbeef");
        assert!(!id.signing_id_truncated);
    }

    #[test]
    fn the_sixty_four_bit_header_and_subject_forms_decode_at_their_own_offsets() {
        let bytes = record(
            header64(6153, 1_617_653_227, 42),
            &[return32(0, 0), subject64(Subj::default(), 50_331_650)],
        );
        let rec = decode_record(&bytes, 0).expect("decodes");
        assert_eq!(rec.flaw, None);
        assert_eq!(rec.seconds, 1_617_653_227);
        assert_eq!(rec.millis, Some(42));
        assert_eq!(rec.event_name(), Some("AUE_logout"));
        assert_eq!(
            rec.subject.as_ref().expect("subject").terminal_port,
            50_331_650,
            "the 64-bit subject form carries a 64-bit terminal port"
        );
    }

    #[test]
    fn the_extended_header_carries_the_hosts_own_address() {
        let bytes = record(
            header32_ex(45021, 1_617_653_227, 7, [192, 168, 1, 10]),
            &[return32(0, 0), subject32(Subj::default())],
        );
        let rec = decode_record(&bytes, 0).expect("decodes");
        assert_eq!(rec.flaw, None, "the address must not shift the time field");
        assert_eq!(rec.seconds, 1_617_653_227);
        assert_eq!(rec.machine_address.as_deref(), Some("192.168.1.10"));
        assert_eq!(rec.event_name(), Some("AUE_lw_login"));
    }

    #[test]
    fn a_record_whose_trailer_disagrees_with_its_header_is_reported_not_believed() {
        let mut bytes = record(header32(45021, 1_617_653_227, 1), &[return32(0, 0)]);
        // Rewrite only the trailer's count, leaving the magic in place: the
        // record's two independent statements of its own length now differ.
        let at = bytes.len() - 4;
        bytes[at..].copy_from_slice(&be32(9999));
        let rec = decode_record(&bytes, 0).expect("the header still decodes");
        assert!(matches!(
            rec.flaw,
            Some(RecordFlaw::TrailerCountDisagrees { trailer: 9999, .. })
        ));
        assert!(rec.flaw.as_ref().unwrap().detail().contains("disagree"));
    }

    #[test]
    fn a_record_with_no_trailer_magic_is_reported() {
        let mut bytes = record(header32(45021, 1_617_653_227, 1), &[return32(0, 0)]);
        let at = bytes.len() - 6;
        bytes[at..at + 2].copy_from_slice(&be16(0x0000));
        let rec = decode_record(&bytes, 0).expect("the header still decodes");
        assert_eq!(rec.flaw, Some(RecordFlaw::TrailerMissing));
    }

    #[test]
    fn a_record_with_an_unknown_token_stops_there_and_says_so() {
        // 0x66 is not a BSM token. Its length is therefore unknowable, and the
        // fields after it cannot be reached — which must be reported, not
        // silently skipped.
        let bytes = record(
            header32(45023, 1_617_653_227, 1),
            &[text("before"), vec![0x66, 0, 0, 0], return32(0, 0)],
        );
        let rec = decode_record(&bytes, 0).expect("decodes");
        match rec.flaw {
            Some(RecordFlaw::UnknownToken { id, offset }) => {
                assert_eq!(id, 0x66);
                assert_eq!(offset, 18 + text("before").len());
            }
            other => panic!("expected an unknown-token flaw, got {other:?}"),
        }
        assert_eq!(rec.texts, vec!["before"], "what was read is still reported");
        assert_eq!(
            rec.status, None,
            "the return token sits past the unknown one and was never read; the outcome must \
             not be reported"
        );
        assert_eq!(
            rec.succeeded(),
            None,
            "an outcome that was not read is not a success"
        );
        assert!(
            !rec.is_failed_authentication(),
            "a record whose outcome was never reached is not evidence of a failed login"
        );
    }

    #[test]
    fn a_token_whose_length_runs_past_the_record_is_distinguished_from_an_unknown_one() {
        // A text token claiming far more bytes than the record holds. The
        // token IS known; its length is impossible here. Those are two
        // different findings.
        let mut oversize = vec![0x28u8];
        oversize.extend_from_slice(&be16(4096));
        oversize.extend_from_slice(b"short\0");
        let bytes = record(header32(45023, 1_617_653_227, 1), &[oversize]);
        let rec = decode_record(&bytes, 0).expect("decodes");
        match rec.flaw {
            Some(RecordFlaw::TokenOverrunsRecord { id, offset }) => {
                assert_eq!(id, 0x28);
                assert_eq!(offset, 18);
            }
            other => panic!("expected a token-overrun flaw, got {other:?}"),
        }
        assert!(
            rec.flaw.as_ref().unwrap().detail().contains("runs past"),
            "the sentence must say the length is impossible, not that the token is unknown"
        );
    }

    #[test]
    fn a_milliseconds_field_at_or_past_a_full_second_is_not_folded_into_the_timestamp() {
        // Measured on the corpus: across 4,327 records the field never reaches
        // 1,000. A value that does is out of range for what the field is, and
        // adding it to the timestamp would move the event by up to sixteen
        // minutes.
        let bytes = record(header32(45021, 1_617_653_227, 999_999), &[return32(0, 0)]);
        let rec = decode_record(&bytes, 0).expect("decodes");
        assert_eq!(rec.seconds, 1_617_653_227, "the seconds field is untouched");
        assert_eq!(rec.millis, None);

        let out = run(bytes, "20210405200450.not_terminated", TRAIL_PATH);
        let ev = of_type(&out, "AuditEvent");
        assert_eq!(n(ev[0], "timestamp"), Some(1_617_653_227));
        assert!(
            ev[0].get("timestamp_millis").is_none(),
            "an out-of-range sub-second field is absent, not shown as a value"
        );
    }

    #[test]
    fn an_all_zero_terminal_address_is_absent_rather_than_zero_zero_zero_zero() {
        let bytes = record(
            header32(45021, 1_617_653_227, 1),
            &[return32(0, 0), subject32(Subj::default())],
        );
        let rec = decode_record(&bytes, 0).expect("decodes");
        assert_eq!(
            rec.subject.as_ref().expect("subject").terminal_address,
            None,
            "an all-zero terminal address is the absence of a peer; printing 0.0.0.0 would name \
             an address nothing came from"
        );
        let out = run(bytes, "current", "/private/var/audit/current");
        assert!(of_type(&out, "AuditEvent")[0]
            .get("source_address")
            .is_none());
    }

    #[test]
    fn the_audit_default_id_is_reported_as_absent_rather_than_as_root() {
        let bytes = record(
            header32(45029, 1_617_653_090, 57),
            &[
                return32(0, 0),
                subject32(Subj {
                    auid: u32::MAX,
                    euid: 0,
                    ..Subj::default()
                }),
            ],
        );
        let rec = decode_record(&bytes, 0).expect("decodes");
        assert_eq!(
            rec.subject.as_ref().expect("subject").audit_uid,
            None,
            "AU_DEFAUDITID means the operation is attributed to no logged-in account; zero is \
             root, which is a different claim"
        );
        let out = run(bytes, "current", "/private/var/audit/current");
        let ev = of_type(&out, "AuditEvent");
        assert!(ev[0].get("audit_user_id").is_none());
        assert!(s(ev[0], "audit_user_id_absent").is_some());
    }

    // --- event naming ---------------------------------------------------------

    #[test]
    fn an_event_outside_the_table_is_reported_by_number_and_marked_unmapped() {
        let bytes = record(header32(1234, 1_617_653_227, 1), &[return32(0, 0)]);
        let out = run(bytes, "current", "/private/var/audit/current");
        let ev = of_type(&out, "AuditEvent");
        assert_eq!(n(ev[0], "event_id"), Some(1234));
        assert!(
            ev[0].get("event_name").is_none(),
            "no name is invented for a number outside the table"
        );
        assert!(ev[0].get("event_class").is_none());
        assert_eq!(s(ev[0], "content_incomplete_reason"), Some("unmapped"));
        assert_eq!(n(status_of(&out), "records_with_unmapped_event"), Some(1));
    }

    #[test]
    fn an_event_number_that_carries_two_names_shows_both() {
        // Apple's own table gives 6168 to both AUE_shutdown and AUE_poweroff.
        // The record carries only the number, so which was meant is not
        // established by the file.
        let bytes = record(header32(6168, 1_617_653_227, 1), &[return32(0, 25)]);
        let out = run(bytes, "current", "/private/var/audit/current");
        let ev = of_type(&out, "AuditEvent");
        assert_eq!(s(ev[0], "event_name"), Some("AUE_poweroff"));
        let alts = ev[0]["event_name_alternatives"]
            .as_array()
            .expect("both names are listed");
        assert_eq!(alts.len(), 2);
        assert!(s(ev[0], "event_name_note")
            .expect("a note")
            .contains("more than one symbolic name"));
    }

    #[test]
    fn every_identifier_in_the_event_table_appears_once() {
        let mut seen = std::collections::BTreeSet::new();
        for def in EVENTS {
            assert!(
                seen.insert(def.id),
                "event {} ({}) is listed twice; a second entry is unreachable and the reader \
                 would silently prefer the first",
                def.id,
                def.symbol
            );
        }
        for (id, names) in AMBIGUOUS_EVENTS {
            assert!(
                seen.contains(id),
                "event {id} is listed as ambiguous but has no entry, so it would be reported as \
                 unmapped and the alternatives never shown"
            );
            assert!(names.len() >= 2, "an ambiguous event needs both names");
        }
    }

    #[test]
    fn every_corpus_event_identifier_is_in_the_table() {
        // The twenty-one identifiers the nine real trails in the Magnet 2021
        // image use. Pinned so a future trim of the table cannot quietly make
        // the graded corpus read as unmapped numbers.
        for id in [
            6153u32, 6168, 6207, 6208, 32800, 44901, 44902, 44903, 44904, 45000, 45014, 45015,
            45017, 45018, 45019, 45021, 45023, 45025, 45026, 45029, 45030,
        ] {
            assert!(
                event_def(id).is_some(),
                "event {id} appears in the graded corpus and must be named"
            );
        }
    }

    // --- failed authentications ----------------------------------------------

    #[test]
    fn a_failed_authentication_becomes_a_failed_login_record_and_a_successful_one_does_not() {
        let mut trail = ssh_record(
            1_617_653_554,
            0,
            0,
            "successful login eliflatt",
            [184, 171, 149, 138],
        );
        trail.extend_from_slice(&ssh_record(
            1_617_653_600,
            4,
            -1,
            "invalid password for user eliflatt",
            [184, 171, 149, 138],
        ));
        let out = run(trail, "20210405200450.not_terminated", TRAIL_PATH);

        assert_eq!(
            of_type(&out, "AuditEvent").len(),
            2,
            "both events are reported"
        );
        let failed = of_type(&out, "FailedLogin");
        assert_eq!(
            failed.len(),
            1,
            "only the refused attempt is a failed login"
        );
        assert_eq!(n(failed[0], "time"), Some(1_617_653_600));
        assert_eq!(n(failed[0], "user_id"), Some(501));
        assert_eq!(s(failed[0], "ip"), Some("184.171.149.138"));
        assert_eq!(s(failed[0], "event_name"), Some("AUE_openssh"));
        assert_eq!(s(failed[0], "source_file"), Some("audit_trail"));
        assert_eq!(
            s(failed[0], "message"),
            Some("invalid password for user eliflatt")
        );
        assert!(
            failed[0].get("user").is_none(),
            "the trail names the account by number; a name parsed out of the daemon's prose \
             would be a guess"
        );
        assert!(s(failed[0], "attribution_note").is_some());
        assert_eq!(n(status_of(&out), "refused_credential_attempts"), Some(1));
    }

    /// The distinction this reader would be worst without.
    ///
    /// `AUE_ssauthorize` and `AUE_ssauthmech` are in the `aa` class and fail
    /// **387 times** between them across the nine real trails, on a machine
    /// nobody attacked: it is the Security
    /// Server deciding whether a process may do something, not somebody
    /// offering a password. Drawing the failed-login line on the class would
    /// put those rows on the screen an examiner reads to answer "was there a
    /// brute force" and bury the two attempts that were real.
    #[test]
    fn a_refused_security_server_authorization_is_not_a_failed_login() {
        for event in [45025u16, 45030, 45024, 45031] {
            let bytes = record(
                header32(event, 1_617_653_227, 1),
                &[return32(1, -1), subject32(Subj::default())],
            );
            let out = run(bytes, "current", "/private/var/audit/current");
            let ev = of_type(&out, "AuditEvent");
            assert_eq!(
                s(ev[0], "event_class"),
                Some("aa"),
                "event {event} really is in the authentication and authorization class"
            );
            assert_eq!(
                s(ev[0], "outcome"),
                Some("failed"),
                "and the refusal is still reported"
            );
            assert_eq!(
                ev[0]["credential_attempt"],
                json!(false),
                "but no secret was offered at it"
            );
            assert!(
                of_type(&out, "FailedLogin").is_empty(),
                "event {event} must not produce a failed-login record"
            );
            let st = status_of(&out);
            assert_eq!(n(st, "refused_credential_attempts"), Some(0));
            assert_eq!(
                n(st, "other_refused_operations"),
                Some(1),
                "the refusal is counted, so \"no failed logins\" is never read as \"nothing was \
                 refused\""
            );
        }
    }

    /// And the events where a secret *is* offered do produce one.
    #[test]
    fn a_refused_password_or_key_is_a_failed_login_whichever_daemon_took_it() {
        for (event, name) in [
            (32800u16, "AUE_openssh"),
            (45023, "AUE_auth_user"),
            (45021, "AUE_lw_login"),
            (45028, "AUE_sudo"),
            (6159, "AUE_su"),
        ] {
            let bytes = record(
                header32(event, 1_617_653_227, 1),
                &[return32(4, -1), subject32(Subj::default())],
            );
            let out = run(bytes, "current", "/private/var/audit/current");
            assert_eq!(s(of_type(&out, "AuditEvent")[0], "event_name"), Some(name));
            assert_eq!(
                of_type(&out, "FailedLogin").len(),
                1,
                "{name} is an event at which a secret was offered"
            );
        }
    }

    /// A logout is not a credential attempt, so a logout that reported a
    /// failure is not a failed login.
    #[test]
    fn a_failed_logout_or_session_event_is_not_a_failed_login() {
        for event in [6153u16, 45022, 44901, 44903, 44904] {
            let bytes = record(
                header32(event, 1_617_653_227, 1),
                &[return32(1, -1), subject32(Subj::default())],
            );
            let out = run(bytes, "current", "/private/var/audit/current");
            assert!(
                of_type(&out, "FailedLogin").is_empty(),
                "no secret is offered at event {event}"
            );
        }
    }

    #[test]
    fn an_administrative_failure_is_not_reported_as_a_failed_login() {
        // A refused sysctl write is not somebody trying a password.
        let bytes = record(
            header32(43116, 1_617_653_227, 1),
            &[return32(1, -1), subject32(Subj::default())],
        );
        let out = run(bytes, "current", "/private/var/audit/current");
        assert_eq!(s(of_type(&out, "AuditEvent")[0], "outcome"), Some("failed"));
        assert!(
            of_type(&out, "FailedLogin").is_empty(),
            "only the login and authentication classes produce failed-login records"
        );
    }

    #[test]
    fn a_record_with_no_return_token_says_the_outcome_was_not_recorded() {
        let bytes = record(
            header32(45023, 1_617_653_227, 1),
            &[subject32(Subj::default())],
        );
        let out = run(bytes, "current", "/private/var/audit/current");
        let ev = of_type(&out, "AuditEvent");
        assert_eq!(
            s(ev[0], "outcome"),
            Some("not_recorded"),
            "silence about an outcome is not success"
        );
        assert!(ev[0].get("return_status").is_none());
        assert!(
            of_type(&out, "FailedLogin").is_empty(),
            "a record with no outcome is not evidence of a failure either"
        );
    }

    // --- selection and refusal ------------------------------------------------

    #[test]
    fn a_file_that_is_not_a_trail_is_passed_over_in_silence() {
        for bytes in [
            b"#!/bin/sh\necho hello\n".to_vec(),
            vec![0u8; 4096],
            b"SQLite format 3\0".to_vec(),
        ] {
            let out = run(bytes, "notes.txt", "/Users/eliflatt/notes.txt");
            assert!(
                out.is_empty(),
                "a file that is not a trail and is not named as one produces nothing"
            );
        }
    }

    #[test]
    fn a_file_named_as_a_trail_that_will_not_parse_is_reported_rather_than_dropped() {
        let out = run(
            vec![0x81u8; 4096],
            "20210405200450.not_terminated",
            TRAIL_PATH,
        );
        assert_eq!(out.len(), 1);
        let st = status_of(&out);
        assert_eq!(st["detected"], json!(false));
        assert!(s(st, "failure_reason")
            .expect("a reason")
            .contains("trailer"));
        assert!(s(st, "message")
            .expect("a message")
            .contains("NOT evidence that nothing was audited"));
    }

    #[test]
    fn an_empty_file_where_trails_live_is_reported_because_a_wiped_trail_is_a_finding() {
        let out = run(Vec::new(), "20210405200450.not_terminated", TRAIL_PATH);
        assert_eq!(out.len(), 1);
        assert_eq!(
            s(status_of(&out), "failure_reason"),
            Some("the file is empty")
        );
    }

    #[test]
    fn an_empty_file_elsewhere_is_not_claimed() {
        let out = run(Vec::new(), "notes.txt", "/Users/eliflatt/notes.txt");
        assert!(out.is_empty());
    }

    #[test]
    fn a_record_that_validates_is_read_whatever_the_file_is_called() {
        // Selection is by content: a trail carved out of free space, or one
        // renamed, is still a trail.
        let bytes = ssh_record(
            1_617_653_554,
            0,
            0,
            "successful login eliflatt",
            [10, 0, 0, 9],
        );
        let out = run(bytes, "carved-000123.bin", "/carved/carved-000123.bin");
        assert_eq!(of_type(&out, "AuditEvent").len(), 1);
        assert_eq!(
            s(of_type(&out, "AuditEvent")[0], "source_address"),
            Some("10.0.0.9")
        );
    }

    // --- trail-level behaviour ------------------------------------------------

    #[test]
    fn a_trail_that_ends_mid_record_reports_the_trailing_bytes_rather_than_completing_them() {
        let mut trail = ssh_record(
            1_617_653_554,
            0,
            0,
            "successful login eliflatt",
            [10, 0, 0, 9],
        );
        let second = ssh_record(
            1_617_653_600,
            0,
            0,
            "successful login eliflatt",
            [10, 0, 0, 9],
        );
        let keep = second.len() / 2;
        trail.extend_from_slice(&second[..keep]);
        let out = run(trail, "20210405200450.not_terminated", TRAIL_PATH);

        assert_eq!(
            of_type(&out, "AuditEvent").len(),
            1,
            "the whole record is read and the partial one is not invented"
        );
        let st = status_of(&out);
        assert_eq!(n(st, "trailing_bytes"), Some(keep as i64));
        assert_eq!(s(st, "walk_stop_reason"), Some("trail_ends_mid_record"));
        assert_eq!(
            s(st, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
        assert!(s(st, "content_incomplete_detail")
            .expect("a sentence")
            .contains("not a whole record"));
    }

    #[test]
    fn a_short_read_is_reported_rather_than_read_as_the_whole_trail() {
        let mut trail = ssh_record(
            1_617_653_554,
            0,
            0,
            "successful login eliflatt",
            [10, 0, 0, 9],
        );
        trail.extend_from_slice(&ssh_record(
            1_617_653_600,
            0,
            0,
            "successful login eliflatt",
            [10, 0, 0, 9],
        ));
        let full = trail.len();
        // Twenty bytes short of what the source declares: the second record is
        // cut off and the reader must say so rather than report one trail.
        trail.truncate(full - 20);
        let src = Arc::new(TruncatedSource::new(trail, full as u64));
        let out = run_source(src, "20210405200450.not_terminated", TRAIL_PATH);
        let st = status_of(&out);
        assert_eq!(n(st, "declared_size"), Some(full as i64));
        assert!(n(st, "bytes_staged").unwrap() < full as i64);
        assert!(st.get("content_incomplete").is_some());
    }

    #[test]
    fn the_status_row_counts_the_events_by_name_so_a_trail_can_be_scanned_before_it_is_opened() {
        let mut trail = ssh_record(
            1_617_653_554,
            0,
            0,
            "successful login eliflatt",
            [10, 0, 0, 9],
        );
        trail.extend_from_slice(&ssh_record(
            1_617_653_600,
            4,
            -1,
            "invalid password for user eliflatt",
            [10, 0, 0, 9],
        ));
        trail.extend_from_slice(&record(
            header32(45021, 1_617_653_700, 3),
            &[return32(0, 0), subject32(Subj::default())],
        ));
        let out = run(trail, "20210405200450.not_terminated", TRAIL_PATH);
        let st = status_of(&out);
        assert_eq!(n(st, "records_decoded"), Some(3));
        assert_eq!(st["event_counts"]["AUE_openssh"], json!(2));
        assert_eq!(st["event_counts"]["AUE_lw_login"], json!(1));
        assert_eq!(n(st, "first_record_time"), Some(1_617_653_554));
        assert_eq!(n(st, "last_record_time"), Some(1_617_653_700));
        assert!(
            s(st, "session_note")
                .expect("a note")
                .contains("not sessions"),
            "the row must say why no duration is reported"
        );
        assert!(
            st.get("content_incomplete").is_none(),
            "a whole trail with no flawed record is not stamped incomplete"
        );
    }

    #[test]
    fn every_emitted_record_names_its_source_file_and_format() {
        let bytes = ssh_record(1_617_653_554, 4, -1, "invalid password", [10, 0, 0, 9]);
        let out = run(bytes, "20210405200450.not_terminated", TRAIL_PATH);
        assert_eq!(
            out.len(),
            3,
            "the event, the failed login and the status row"
        );
        for a in &out {
            assert_eq!(
                s(&a.metadata, "source_format"),
                Some("openbsm_audit_trail"),
                "an artifact that does not name the format it was read under cannot be traced"
            );
            assert_eq!(
                s(&a.metadata, "source_file_name"),
                Some("20210405200450.not_terminated")
            );
        }
    }

    // --- the real trails ------------------------------------------------------

    /// **The nine real audit trails from the Magnet 2021 macOS image**, read
    /// through the production path.
    ///
    /// This is the known answer the layout was derived against: 4,327 records
    /// across nine trails, and the token walk lands exactly on the trailer in
    /// every one. The specific answers asserted here — a user logging in over
    /// SSH from one address, with two refused password attempts among the
    /// successes — are the ones an examiner would put in a report.
    #[test]
    fn the_real_macos_audit_trails_read_as_the_logins_they_recorded() {
        let dir = home("ctf-evidence/macos2021/tree/private/var/audit");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            eprintln!(
                "skipping: {} not present (gitignored corpus)",
                dir.display()
            );
            return;
        };
        let mut files: Vec<std::path::PathBuf> =
            entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        files.sort();
        assert_eq!(files.len(), 9, "nine trails are held");

        let mut records = 0i64;
        let mut flawed = 0i64;
        let mut unmapped = 0i64;
        let mut trailing = 0i64;
        let mut ssh_ok = 0usize;
        let mut ssh_failed: Vec<(i64, String, String)> = Vec::new();
        let mut logins = 0usize;
        let mut refused_credentials = 0i64;
        let mut other_refusals = 0i64;
        let mut failed_login_records = 0usize;

        for file in &files {
            let bytes = std::fs::read(file).expect("the corpus file reads");
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            let out = run(bytes, &name, &format!("/private/var/audit/{name}"));
            let st = status_of(&out);
            records += n(st, "records_decoded").unwrap_or(0);
            flawed += n(st, "records_with_structure_flaws").unwrap_or(0);
            unmapped += n(st, "records_with_unmapped_event").unwrap_or(0);
            trailing += n(st, "trailing_bytes").unwrap_or(0);
            refused_credentials += n(st, "refused_credential_attempts").unwrap_or(0);
            other_refusals += n(st, "other_refused_operations").unwrap_or(0);
            failed_login_records += of_type(&out, "FailedLogin").len();

            for ev in of_type(&out, "AuditEvent") {
                match s(ev, "event_name") {
                    Some("AUE_openssh") => match s(ev, "outcome") {
                        Some("succeeded") => ssh_ok += 1,
                        _ => ssh_failed.push((
                            n(ev, "timestamp").unwrap_or(0),
                            s(ev, "source_address").unwrap_or_default().to_string(),
                            s(ev, "message").unwrap_or_default().to_string(),
                        )),
                    },
                    Some("AUE_lw_login") => logins += 1,
                    _ => {}
                }
            }
        }

        assert_eq!(records, 4327, "every record in all nine trails");
        assert_eq!(
            flawed, 0,
            "the token walk lands exactly on the trailer in every real record; a flaw here means \
             a token length is wrong"
        );
        assert_eq!(
            unmapped, 0,
            "the corpus uses twenty-one event identifiers and every one is named"
        );
        assert_eq!(
            trailing, 0,
            "every trail, the .not_terminated one included, holds whole records"
        );

        assert_eq!(
            refused_credentials, 109,
            "107 refused password verifications and two refused SSH passwords"
        );
        assert_eq!(
            failed_login_records, 109,
            "one FailedLogin record per refused credential attempt and no others"
        );
        assert_eq!(
            other_refusals, 388,
            "387 Security Server authorization denials (244 AUE_ssauthorize and 143 \
             AUE_ssauthmech) plus one refused account modification, on a machine nobody \
             attacked. Drawing the failed-login line on the audit class instead of on whether a \
             secret was offered would have put every one of these on the brute-force screen"
        );

        assert_eq!(logins, 10, "ten loginwindow logins across the nine trails");
        assert_eq!(ssh_ok, 18, "eighteen accepted SSH logins");
        assert_eq!(
            ssh_failed.len(),
            2,
            "two refused SSH password attempts, which is what a btmp would have held"
        );
        for (when, from, message) in &ssh_failed {
            assert_eq!(from, "184.171.155.71", "both came from the same address");
            assert_eq!(message, "invalid password for user eliflatt");
            assert!(
                (1_616_630_000..1_616_640_000).contains(when),
                "both fall on 2021-03-25, got {when}"
            );
        }
    }
}
