//! Apple System Log stores — `/var/log/asl/*.asl`.
//!
//! # This is where macOS's `wtmpx` went
//!
//! `utmpx(5)` on macOS says it in as many words: *"Traditionally, separate
//! files would be used to store the running log of the logins and logouts
//! (`wtmpx`), and the last login of each user (`lastlogx`). With the
//! availability of the Apple system log facility these separate files can be
//! replaced with log entries, which are automatically generated when `utmpx`
//! entries are written."*
//!
//! That is not a footnote. `/var/run/utmpx` holds only the sessions open at
//! the moment of acquisition; there is no `btmp` and no on-disk `wtmpx`. The
//! **history** — every boot, every shutdown, every console login and logout,
//! and every SSH session with the address it came from — is in this store,
//! under the facilities `com.apple.system.utmpx` and
//! `com.apple.system.lastlog`, as text records carrying the very
//! `struct utmpx` members `seance_plugin_utmp` decodes from the binary file.
//!
//! On the reference image that is 19 `utmpx` and 13 `lastlog` records across
//! eleven stores: six boots, four clean shutdowns, console sessions for
//! `eliflatt` on five separate days, and **SSH sessions from
//! `184.171.155.71` and `184.171.149.230` with both ends recorded**, so a
//! duration can be stated rather than bounded.
//!
//! It also corroborates two things this project had taken from a header rather
//! than from evidence: Darwin's `ut_type` **11 is `SHUTDOWN_TIME`** (the store
//! carries `SHUTDOWN_TIME:` beside `ut_type = 11`), and the `console` record's
//! `ut_id` really is the four opaque bytes `2f 00 01 01` — which Apple's own
//! logger renders as `0x2f 0x00 0x01 0x01`, the same choice made in
//! `seance_plugin_utmp`.
//!
//! # The format, and what corroborates it
//!
//! A store is an 80-byte header followed by a flat sequence of records, each
//! `u16` type and `u32` length then its payload. Type 1 is a **string**; type 0
//! is a **message**, and messages are a doubly-linked list through their first
//! and last eight bytes.
//!
//! Four independent checks fix the layout, and all four hold across the whole
//! corpus — **7,022 message records and 5,774 string records in eleven
//! stores**:
//!
//! * the records **tile exactly** from offset 80 to the last byte of every
//!   file, with no unknown record type;
//! * the header's `first` field equals the offset of the first message in
//!   every file;
//! * a message's length is exactly `116 + 8 × its own key/value slot count`
//!   in every one of the 7,022 — which is what fixes the fixed part at 60
//!   bytes, the six reference slots at 48, and the trailing `prev` at 8;
//! * the `next`/`prev` chain is consistent **in both directions** for every
//!   record, with no break.
//!
//! The field meanings are corroborated from content rather than assumed: the
//! first record's `time` equals the header's, its `pid` 1191 matches the
//! `objc[1191]` in its own message text, and its `uid` 501 and `gid` 20 are
//! the account's.
//!
//! # What it will not do
//!
//! * **No resynchronisation.** A store whose records stop tiling stops being
//!   read, and the remaining bytes are reported as a count with the reason.
//!   Scanning forward for a plausible record would turn a fragment of another
//!   file into confident log entries.
//! * **No session is invented across stores.** Logins are paired with logouts
//!   *within one store*, on the terminal and pid the records name, exactly as
//!   the binary `wtmp` reader does. A login whose logout is in the next day's
//!   store is reported as `gone_no_logout` / `end_of_file` — not given a
//!   duration.
//! * **The `AUX.<date>/` directories are not read.** They hold the payloads
//!   some messages point at, and a message that references one says so rather
//!   than appearing complete.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_login_sessions::{ClosedBy, SessionPairer};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use tracing::debug;

use crate::{basename_lower, stamp_incomplete, to_rfc3339_nanos, Staged};

/// Largest store this reader stages. The corpus's largest is 373 KB; a busy
/// server's daily store reaches single-digit megabytes.
const MAX_ASL_BYTES: u64 = 256 * 1024 * 1024;
/// Largest number of message records read from one store.
const MAX_RECORDS: usize = 2_000_000;
/// Largest number of key/value slots one message may carry. The corpus's
/// largest is 354.
const MAX_KV_SLOTS: usize = 8_192;
/// Longest string rendered from one reference. The declared length is always
/// reported, so a truncation is visible as one.
const MAX_STRING_BYTES: usize = 64 * 1024;
/// Largest number of sessions reconstructed from one store.
const MAX_SESSIONS: usize = 100_000;

/// `ASL DB` at offset 0 of every store.
const ASL_MAGIC: &[u8; 6] = b"ASL DB";
/// The only version this reader has been shown, and the one macOS 11 writes.
const ASL_VERSION: u32 = 2;
/// Bytes of header before the first record.
const HEADER_BYTES: usize = 80;
/// Record type of a message.
const TYPE_MESSAGE: u16 = 0;
/// Record type of a string.
const TYPE_STRING: u16 = 1;
/// Bytes of a message payload before its reference slots.
const MESSAGE_FIXED_BYTES: usize = 60;
/// The six references every message carries: host, sender, facility, message,
/// referenced process and session.
const MESSAGE_REFERENCES: usize = 6;
/// Width of one reference slot, and of the trailing `prev` pointer.
const SLOT_BYTES: usize = 8;
/// Bytes of a message payload that are not key/value slots:
/// `60 + 6 × 8 + 8`.
const MESSAGE_OVERHEAD: usize = MESSAGE_FIXED_BYTES + MESSAGE_REFERENCES * SLOT_BYTES + SLOT_BYTES;

/// Facilities under which the login history is written. Both are used, and
/// which one a given record lands in is not consistent — a console login is
/// `lastlog` and its logout is `utmpx` — so both are read and neither is
/// treated as authoritative over the other.
const UTMPX_FACILITIES: [&str; 2] = ["com.apple.system.utmpx", "com.apple.system.lastlog"];

/// `ut_type` values Darwin writes, as the store spells them out.
const UT_BOOT_TIME: u32 = 2;
const UT_USER_PROCESS: u32 = 7;
const UT_DEAD_PROCESS: u32 = 8;
const UT_SHUTDOWN_TIME: u32 = 11;

// --- primitive reads ---------------------------------------------------------

fn be_u16(data: &[u8], at: usize) -> Option<u16> {
    let s = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(data: &[u8], at: usize) -> Option<u32> {
    let s = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be_u64(data: &[u8], at: usize) -> Option<u64> {
    let s = data.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Syslog severity, as ASL numbers them.
fn level_name(level: u16) -> Option<&'static str> {
    Some(match level {
        0 => "emergency",
        1 => "alert",
        2 => "critical",
        3 => "error",
        4 => "warning",
        5 => "notice",
        6 => "info",
        7 => "debug",
        _ => return None,
    })
}

/// A string reference, resolved.
///
/// A slot is eight bytes. When its first byte has the high bit set the string
/// is **inline**, with its length in the low seven bits and its bytes
/// following — which is how nine thousand of the corpus's references are
/// stored. Otherwise the slot is a big-endian offset of a string record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reference {
    /// The slot was zero: the field is not present on this message.
    Absent,
    /// A string carried in the slot itself.
    Inline(String),
    /// A string record elsewhere in the file, resolved.
    Resolved { text: String, at: u64 },
    /// A non-zero offset that does not name a string record. Reported rather
    /// than rendered as an empty field: an unresolvable reference means the
    /// store is not laid out the way this reader read it, and an empty string
    /// would hide that.
    Unresolved { at: u64 },
}

impl Reference {
    fn text(&self) -> Option<&str> {
        match self {
            Reference::Inline(t) | Reference::Resolved { text: t, .. } => Some(t.as_str()),
            _ => None,
        }
    }

    fn is_unresolved(&self) -> bool {
        matches!(self, Reference::Unresolved { .. })
    }
}

/// Read the string record at `at`, or `None` when that offset does not hold
/// one.
fn string_at(data: &[u8], at: usize) -> Option<(String, u32)> {
    if be_u16(data, at)? != TYPE_STRING {
        return None;
    }
    let declared = be_u32(data, at + 2)?;
    let take = (declared as usize).min(MAX_STRING_BYTES);
    let raw = data.get(at + 6..at.checked_add(6)?.checked_add(take)?)?;
    let cut = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Some((String::from_utf8_lossy(&raw[..cut]).into_owned(), declared))
}

/// Resolve the reference slot at `at`.
fn reference(data: &[u8], at: usize) -> Reference {
    let Some(first) = data.get(at).copied() else {
        return Reference::Absent;
    };
    if first & 0x80 != 0 {
        let len = usize::from(first & 0x7f);
        let raw = data
            .get(at + 1..at + 1 + len.min(SLOT_BYTES - 1))
            .unwrap_or_default();
        return Reference::Inline(String::from_utf8_lossy(raw).into_owned());
    }
    let Some(off) = be_u64(data, at) else {
        return Reference::Absent;
    };
    if off == 0 {
        return Reference::Absent;
    }
    match usize::try_from(off).ok().and_then(|o| string_at(data, o)) {
        Some((text, _)) => Reference::Resolved { text, at: off },
        None => Reference::Unresolved { at: off },
    }
}

// --- one message -------------------------------------------------------------

/// One decoded ASL message.
#[derive(Debug, Clone)]
struct Message {
    /// Offset of the record within the store.
    at: usize,
    /// Offsets of the next and previous messages, as the record states them.
    next: u64,
    prev: u64,
    /// Message id, which ASL assigns in order.
    mid: u64,
    seconds: i64,
    nanos: u32,
    level: u16,
    flags: u16,
    pid: u32,
    /// Sending process's effective uid, or `None` where the field holds the
    /// unset sentinel.
    uid: Option<u32>,
    gid: Option<u32>,
    /// The uid allowed to read this message, or `None` for the `-1` that means
    /// "anyone". This is an **access-control** field, not the sender's real
    /// uid: it is `-1` in all 7,022 corpus records while `read_gid` is 80
    /// (`admin`) in all of them, which is what a default ASL read policy looks
    /// like.
    read_uid: Option<u32>,
    read_gid: Option<u32>,
    host: Reference,
    sender: Reference,
    facility: Reference,
    text: Reference,
    /// The process a message was forwarded on behalf of.
    referenced_process: Reference,
    session: Reference,
    /// Key/value pairs, in order. A key with no value is carried with `None`
    /// rather than an empty string.
    pairs: Vec<(String, Option<String>)>,
    /// True when the key/value slots do not account for cleanly. Either the
    /// count the record declares disagrees with the count its own length
    /// implies, or that count is odd so the last key has no value slot.
    /// Either way a pair may have lost its value.
    pair_structure_suspect: bool,
    /// True when any reference in this message pointed at something that is
    /// not a string record.
    unresolved_reference: bool,
    /// True when [`MAX_KV_SLOTS`] stopped the pair walk.
    pairs_capped: bool,
}

impl Message {
    fn value_of(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }

    /// True when this message is one of the `utmpx` login-history records.
    fn is_utmpx(&self) -> bool {
        self.facility
            .text()
            .is_some_and(|f| UTMPX_FACILITIES.contains(&f))
    }

    /// The `ut_type` the record states, when it states one.
    fn ut_type(&self) -> Option<u32> {
        self.value_of("ut_type")?.parse().ok()
    }

    /// The `utmpx` record's own timestamp, which is **not** the same as the
    /// message's: the message is timed when `syslogd` wrote it, and
    /// `ut_tv.tv_sec` is when the session event happened. The two differ by
    /// seconds in the corpus and by minutes in one case, so the session's own
    /// time is the one used and the message's is kept beside it.
    fn ut_time(&self) -> Option<(i64, u32)> {
        let secs: i64 = self.value_of("ut_tv.tv_sec")?.parse().ok()?;
        let usec: u32 = self
            .value_of("ut_tv.tv_usec")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Some((secs, usec.min(999_999)))
    }
}

/// `u32::MAX` and `u32::MAX - 1` both appear as "not recorded" in these
/// fields: `-1` for an unset id and `-2` (`nobody`) for a message whose sender
/// ASL could not attribute. Neither is a real account, and reporting either as
/// one would put uid 4294967294 on a screen.
fn real_id(raw: u32) -> Option<u32> {
    (raw < u32::MAX - 1).then_some(raw)
}

/// Decode the message record whose payload starts at `at` and runs `len`
/// bytes.
fn decode_message(data: &[u8], record_at: usize, at: usize, len: usize) -> Option<Message> {
    if len < MESSAGE_OVERHEAD {
        return None;
    }
    let kv_bytes = len - MESSAGE_OVERHEAD;
    if !kv_bytes.is_multiple_of(SLOT_BYTES) {
        return None;
    }
    let declared_slots = be_u32(data, at + 56)? as usize;
    let mut slots = kv_bytes / SLOT_BYTES;
    // The record states its own slot count and its own length; the two agree
    // in every corpus record. Where they do not, the length is believed —
    // it is what the record walk already used to find the next record — and
    // the shortfall is reported.
    let count_disagrees = declared_slots != slots;
    let pairs_capped = slots > MAX_KV_SLOTS;
    if pairs_capped {
        slots = MAX_KV_SLOTS;
    }

    let refs_at = at + MESSAGE_FIXED_BYTES;
    let host = reference(data, refs_at);
    let sender = reference(data, refs_at + SLOT_BYTES);
    let facility = reference(data, refs_at + 2 * SLOT_BYTES);
    let text = reference(data, refs_at + 3 * SLOT_BYTES);
    let referenced_process = reference(data, refs_at + 4 * SLOT_BYTES);
    let session = reference(data, refs_at + 5 * SLOT_BYTES);

    let kv_at = refs_at + MESSAGE_REFERENCES * SLOT_BYTES;
    let mut pairs = Vec::new();
    let mut unresolved = [
        &host,
        &sender,
        &facility,
        &text,
        &referenced_process,
        &session,
    ]
    .iter()
    .any(|r| r.is_unresolved());
    let mut i = 0usize;
    while i < slots {
        let key = reference(data, kv_at + i * SLOT_BYTES);
        unresolved |= key.is_unresolved();
        let Some(key_text) = key.text().map(str::to_string) else {
            i += 2;
            continue;
        };
        let value = if i + 1 < slots {
            let v = reference(data, kv_at + (i + 1) * SLOT_BYTES);
            unresolved |= v.is_unresolved();
            v.text().map(str::to_string)
        } else {
            None
        };
        pairs.push((key_text, value));
        i += 2;
    }

    Some(Message {
        at: record_at,
        next: be_u64(data, at)?,
        mid: be_u64(data, at + 8)?,
        seconds: i64::try_from(be_u64(data, at + 16)?).ok()?,
        nanos: be_u32(data, at + 24)?.min(999_999_999),
        level: be_u16(data, at + 28)?,
        flags: be_u16(data, at + 30)?,
        pid: be_u32(data, at + 32)?,
        uid: real_id(be_u32(data, at + 36)?),
        gid: real_id(be_u32(data, at + 40)?),
        read_uid: real_id(be_u32(data, at + 44)?),
        read_gid: real_id(be_u32(data, at + 48)?),
        prev: be_u64(data, at + len - SLOT_BYTES)?,
        host,
        sender,
        facility,
        text,
        referenced_process,
        session,
        pairs,
        pair_structure_suspect: !slots.is_multiple_of(2) || count_disagrees,
        unresolved_reference: unresolved,
        pairs_capped,
    })
}

// --- the store ---------------------------------------------------------------

/// Why a store was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Empty,
    NotAStore,
    UnknownVersion(u32),
    NoRecords,
}

impl Refusal {
    fn tag(self) -> &'static str {
        match self {
            Refusal::Empty => "empty_file",
            Refusal::NotAStore => "no_asl_db_magic",
            Refusal::UnknownVersion(_) => "unknown_store_version",
            Refusal::NoRecords => "no_record_decoded",
        }
    }

    fn detail(self) -> String {
        match self {
            Refusal::Empty => "the file is empty".to_string(),
            Refusal::NotAStore => {
                "the first six bytes are not `ASL DB`, so this is not an Apple System Log store"
                    .to_string()
            }
            Refusal::UnknownVersion(v) => format!(
                "the store declares version {v}, which this reader has not been shown and will \
                 not guess the layout of"
            ),
            Refusal::NoRecords => {
                "the header is a store's but the first record does not decode, so nothing could \
                 be read without guessing where records begin"
                    .to_string()
            }
        }
    }
}

/// What a whole store came to.
#[derive(Debug, Default)]
struct StoreWalk {
    messages: Vec<Message>,
    strings: usize,
    /// Offset the header declares the first message sits at.
    declared_first: u64,
    /// Time the header carries, which is the store's own day.
    header_time: u64,
    bytes_walked: usize,
    trailing_bytes: usize,
    stop_reason: Option<&'static str>,
    record_cap_reached: bool,
    /// Messages whose `next`/`prev` do not name their neighbours in file
    /// order. The chain is a second, independent statement of the record
    /// order, so a break is worth reporting.
    chain_breaks: usize,
    /// True when the header's `first` does not equal the first message's
    /// offset.
    first_disagrees: bool,
}

fn walk_store(data: &[u8]) -> Result<StoreWalk, Refusal> {
    if data.is_empty() {
        return Err(Refusal::Empty);
    }
    if data.len() < HEADER_BYTES || data.get(0..6) != Some(&ASL_MAGIC[..]) {
        return Err(Refusal::NotAStore);
    }
    let version = be_u32(data, 12).ok_or(Refusal::NotAStore)?;
    if version != ASL_VERSION {
        return Err(Refusal::UnknownVersion(version));
    }
    let mut out = StoreWalk {
        declared_first: be_u64(data, 16).unwrap_or(0),
        header_time: be_u64(data, 24).unwrap_or(0),
        ..Default::default()
    };

    let mut off = HEADER_BYTES;
    while off < data.len() {
        if out.messages.len() >= MAX_RECORDS {
            out.record_cap_reached = true;
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_cap_reached");
            break;
        }
        let Some(kind) = be_u16(data, off) else {
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_header_is_truncated");
            break;
        };
        let Some(len) = be_u32(data, off + 2) else {
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_header_is_truncated");
            break;
        };
        let len = len as usize;
        let Some(end) = off.checked_add(6).and_then(|a| a.checked_add(len)) else {
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("record_length_overflows");
            break;
        };
        if end > data.len() {
            // Normal at the tail of a store still being written, and of a
            // carved fragment.
            out.trailing_bytes = data.len() - off;
            out.stop_reason = Some("store_ends_mid_record");
            break;
        }
        match kind {
            TYPE_STRING => out.strings += 1,
            TYPE_MESSAGE => match decode_message(data, off, off + 6, len) {
                Some(message) => out.messages.push(message),
                None => {
                    out.trailing_bytes = data.len() - off;
                    out.stop_reason = Some("message_record_does_not_fit_its_own_length");
                    break;
                }
            },
            _ => {
                // A record type this reader does not know has an unknown
                // meaning but a known length, so the walk could step over it —
                // and deliberately does not. A store holding a third record
                // type is not the format this reader was shown, and reading
                // the rest of it would be reading it against a guess.
                out.trailing_bytes = data.len() - off;
                out.stop_reason = Some("unknown_record_type");
                break;
            }
        }
        out.bytes_walked = end;
        off = end;
    }

    if out.messages.is_empty() && out.strings == 0 {
        return Err(Refusal::NoRecords);
    }
    if let Some(first) = out.messages.first() {
        out.first_disagrees = out.declared_first != first.at as u64;
    }
    for (i, message) in out.messages.iter().enumerate() {
        let expected_prev = if i == 0 {
            0
        } else {
            out.messages[i - 1].at as u64
        };
        let expected_next = out
            .messages
            .get(i + 1)
            .map(|m| m.at as u64)
            .unwrap_or_default();
        if message.prev != expected_prev || message.next != expected_next {
            out.chain_breaks += 1;
        }
    }
    Ok(out)
}

// --- the login history -------------------------------------------------------

/// One reconstructed login session, from the `utmpx` records in one store.
///
/// The pairing rules are not applied here: they are
/// [`seance_login_sessions::SessionPairer`]'s, the same engine
/// `seance_plugin_utmp` pairs a binary `wtmp` with (ROADMAP §5.11, lifted
/// 2026-09-26). A `USER_PROCESS` opens a session on a terminal, a
/// `DEAD_PROCESS` on the same terminal closes it, and a boot or shutdown closes
/// whatever is still open with an upper **bound** rather than a logout. What
/// stays here is the classification: which of Darwin's textual `ut_type`
/// values is a login, a logout or a bracket.
#[derive(Debug, Clone)]
struct Session {
    user: String,
    line: String,
    id: String,
    host: Option<String>,
    pid: u32,
    start: i64,
    start_usec: u32,
    end: Option<i64>,
    /// Observed duration, when both ends were read and the logout is not
    /// before the login.
    duration: Option<i64>,
    /// Upper bound on the end, from the boot or shutdown that closed it. Not a
    /// logout, and reported under its own name for that reason.
    bounded_before: Option<i64>,
    /// Longest the session can have lasted, given `bounded_before`.
    max_duration: Option<i64>,
    status: &'static str,
    closed_by: &'static str,
    /// Offset of the login record, so the claim can be checked.
    login_at: usize,
}

/// What the store's login record says about the login, before pairing.
#[derive(Debug, Clone)]
struct AslLogin {
    user: String,
    id: String,
    host: Option<String>,
    pid: u32,
    start: i64,
    start_usec: u32,
}

/// A boot, shutdown or other bracketing event.
#[derive(Debug, Clone)]
struct Bracket {
    kind: &'static str,
    ut_type: u32,
    time: i64,
    usec: u32,
    pid: Option<u32>,
    at: usize,
}

/// Pair the store's `utmpx` records into sessions and brackets.
///
/// Returns the sessions, the brackets, whether the session cap was reached,
/// and how many login-history records were counted without becoming a session
/// or a bracket: a logout whose login is in another store, and a record whose
/// type or time this reader cannot read.
fn reconstruct(messages: &[Message]) -> (Vec<Session>, Vec<Bracket>, bool, usize) {
    reconstruct_capped(messages, MAX_SESSIONS)
}

/// [`reconstruct`] under an explicit session cap, so the cap rule can be
/// exercised without a hundred thousand fixtures.
fn reconstruct_capped(
    messages: &[Message],
    max_sessions: usize,
) -> (Vec<Session>, Vec<Bracket>, bool, usize) {
    let mut pairer: SessionPairer<AslLogin> = SessionPairer::new(max_sessions);
    let mut brackets: Vec<Bracket> = Vec::new();
    // Records that name a `ut_type` this reader does not bracket or pair, or
    // carry no readable type or time.
    let mut unhandled = 0usize;

    for message in messages.iter().filter(|m| m.is_utmpx()) {
        let Some(ut_type) = message.ut_type() else {
            unhandled += 1;
            continue;
        };
        let Some((secs, usec)) = message.ut_time() else {
            unhandled += 1;
            continue;
        };
        match ut_type {
            UT_BOOT_TIME | UT_SHUTDOWN_TIME => {
                let (kind, closed_by) = if ut_type == UT_BOOT_TIME {
                    ("boot", ClosedBy::Boot)
                } else {
                    ("shutdown", ClosedBy::Shutdown)
                };
                // Everything still open died with the machine. The time is
                // carried as a bound, never as a logout.
                pairer.machine_down(Some(secs), closed_by);
                brackets.push(Bracket {
                    kind,
                    ut_type,
                    time: secs,
                    usec,
                    pid: message.value_of("ut_pid").and_then(|v| v.parse().ok()),
                    at: message.at,
                });
            }
            UT_USER_PROCESS => {
                let line = message.value_of("ut_line").unwrap_or_default();
                let login = AslLogin {
                    user: message.value_of("ut_user").unwrap_or_default().to_string(),
                    id: message.value_of("ut_id").unwrap_or_default().to_string(),
                    host: message.value_of("ut_host").map(str::to_string),
                    pid: message
                        .value_of("ut_pid")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0),
                    start: secs,
                    start_usec: usec,
                };
                pairer.login(line, Some(secs), message.at, login);
            }
            UT_DEAD_PROCESS => {
                let line = message.value_of("ut_line").unwrap_or_default();
                // A logout with nothing open is normal at the head of a store:
                // the login is in the previous day's. The pairer counts it; it
                // is never turned into a session with an invented start.
                pairer.logout(line, Some(secs));
            }
            _ => unhandled += 1,
        }
    }

    let pairing = pairer.finish();
    let sessions = pairing
        .sessions
        .into_iter()
        .map(|p| Session {
            user: p.login.user,
            line: p.line,
            id: p.login.id,
            host: p.login.host,
            pid: p.login.pid,
            start: p.login.start,
            start_usec: p.login.start_usec,
            end: p.end,
            duration: p.duration,
            bounded_before: p.bounded_before,
            max_duration: p.max_duration,
            status: p.status.as_str(),
            closed_by: p.closed_by.as_str(),
            login_at: p.order,
        })
        .collect();
    let counted = unhandled.saturating_add(pairing.unpaired_logouts);
    (sessions, brackets, pairing.session_cap_reached, counted)
}

// --- artifact emission -------------------------------------------------------

pub struct AslParser;

/// True when a name is an ASL store's.
///
/// Used only to decide whether a file that failed to parse deserves a refusal
/// record; selection itself is by the `ASL DB` magic.
fn named_as_store(name: &str, path: &str) -> bool {
    let base = basename_lower(name);
    base.ends_with(".asl") || path.to_ascii_lowercase().contains("/var/log/asl/")
}

fn provenance(meta: &mut Map<String, Value>, file_name: &str) {
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert("source_format".into(), json!("apple_system_log_v2"));
}

fn stamp_time(meta: &mut Map<String, Value>, secs: i64, nanos: u32) {
    meta.insert("timestamp".into(), json!(secs));
    meta.insert("date".into(), json!(secs));
    if let Some(text) = to_rfc3339_nanos(secs, nanos) {
        meta.insert("timestamp_rfc3339".into(), json!(text));
    }
}

fn reference_value(meta: &mut Map<String, Value>, key: &str, reference: &Reference) {
    match reference {
        Reference::Inline(text) | Reference::Resolved { text, .. } => {
            if !text.is_empty() {
                meta.insert(key.into(), json!(text));
            }
        }
        // An unresolvable reference is reported as the offset it named. An
        // empty field would hide that the store is not laid out as read.
        Reference::Unresolved { at } => {
            meta.insert(format!("{key}_unresolved_offset"), json!(at));
        }
        Reference::Absent => {}
    }
}

fn message_artifact(artifact: &Artifact, file_name: &str, message: &Message) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("AslMessage"));
    meta.insert("subtype".into(), json!("asl_message"));
    provenance(&mut meta, file_name);
    meta.insert("record_offset".into(), json!(message.at));
    meta.insert("message_id".into(), json!(message.mid));
    stamp_time(&mut meta, message.seconds, message.nanos);
    meta.insert("level".into(), json!(message.level));
    match level_name(message.level) {
        Some(name) => meta.insert("level_name".into(), json!(name)),
        // No name is invented for a severity outside the syslog scale.
        None => meta.insert(
            "level_note".into(),
            json!(format!(
                "level {} is outside the syslog severity scale and is reported as the number \
                 the store holds",
                message.level
            )),
        ),
    };
    meta.insert("flags".into(), json!(message.flags));
    meta.insert("pid".into(), json!(message.pid));
    if let Some(uid) = message.uid {
        meta.insert("uid".into(), json!(uid));
    }
    if let Some(gid) = message.gid {
        meta.insert("gid".into(), json!(gid));
    }
    // Access control, not identity: who may read the message.
    if let Some(uid) = message.read_uid {
        meta.insert("read_uid".into(), json!(uid));
    }
    if let Some(gid) = message.read_gid {
        meta.insert("read_gid".into(), json!(gid));
    }
    reference_value(&mut meta, "host", &message.host);
    reference_value(&mut meta, "sender", &message.sender);
    reference_value(&mut meta, "facility", &message.facility);
    reference_value(&mut meta, "message", &message.text);
    reference_value(&mut meta, "referenced_process", &message.referenced_process);
    reference_value(&mut meta, "session", &message.session);

    if !message.pairs.is_empty() {
        let pairs: Vec<Value> = message
            .pairs
            .iter()
            .map(|(k, v)| match v {
                Some(v) => json!({"key": k, "value": v}),
                None => json!({"key": k}),
            })
            .collect();
        meta.insert("values".into(), json!(pairs));
        // The expiry ASL writes on a message it is allowed to discard. Its
        // presence is why the `BB.*` stores exist, and it is a fact about the
        // record's lifetime worth carrying.
        if let Some(expiry) = message.value_of("ASLExpireTime") {
            meta.insert("expire_time".into(), json!(expiry));
        }
    }

    let mut reasons = Vec::new();
    if message.pair_structure_suspect {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            "the record's key/value slots do not account for cleanly — either the count it \
             declares disagrees with the count its own length implies, or that count is odd — so \
             a pair may have lost its value"
                .to_string(),
        ));
    }
    if message.unresolved_reference {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            "a reference in this record named an offset that does not hold a string record; the \
             offset is reported in place of the value"
                .to_string(),
        ));
    }
    if message.pairs_capped {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "the record declares more than {MAX_KV_SLOTS} key/value slots; the pairs shown \
                 are the first of them"
            ),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    let sender = message.sender.text().unwrap_or("unknown sender");
    let text = message.text.text().unwrap_or("");
    let first_line = text.lines().next().unwrap_or("");
    meta.insert("name".into(), json!(format!("{sender}: {first_line}")));
    meta.insert(
        "short_desc".into(),
        json!(match level_name(message.level) {
            Some(level) => format!("[{level}] {sender}[{}]: {first_line}", message.pid),
            None => format!(
                "[level {}] {sender}[{}]: {first_line}",
                message.level, message.pid
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
    .with_subtype("asl_message")
}

fn session_artifact(artifact: &Artifact, file_name: &str, session: &Session) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("LoginSession"));
    meta.insert("subtype".into(), json!("asl_utmpx_session"));
    provenance(&mut meta, file_name);
    // The same field names the binary reader writes, so macOS login history
    // reaches the screen an examiner already reads for Linux's.
    meta.insert("source_file".into(), json!("asl_utmpx"));
    meta.insert("user".into(), json!(session.user));
    meta.insert("tty".into(), json!(session.line));
    if !session.id.is_empty() {
        meta.insert("ut_id".into(), json!(session.id));
    }
    if let Some(host) = &session.host {
        meta.insert("host".into(), json!(host));
    }
    meta.insert("pid".into(), json!(session.pid));
    meta.insert("login_time".into(), json!(session.start));
    meta.insert("date".into(), json!(session.start));
    if session.start_usec > 0 {
        meta.insert("login_time_usec".into(), json!(session.start_usec));
    }
    meta.insert("record_offset".into(), json!(session.login_at));
    if let Some(end) = session.end {
        meta.insert("logout_time".into(), json!(end));
        if let Some(duration) = session.duration {
            meta.insert("duration_seconds".into(), json!(duration));
        }
    }
    if let Some(bound) = session.bounded_before {
        // Not a logout: the time of the boot or shutdown the session did not
        // survive. Named separately so it can never be read as one.
        meta.insert("bounded_before_time".into(), json!(bound));
        if let Some(max) = session.max_duration {
            meta.insert("max_duration_seconds".into(), json!(max));
        }
    }
    meta.insert("status".into(), json!(session.status));
    meta.insert("closed_by".into(), json!(session.closed_by));
    if session.status == "still_logged_in" {
        meta.insert(
            "status_note".into(),
            json!(
                "This store held the login and no logout. A session whose logout is in the \
                   next day's store is reported open rather than given a duration; sessions are \
                   not paired across stores."
            ),
        );
    }
    let source = session
        .host
        .clone()
        .filter(|h| !h.is_empty())
        .map(|h| format!(" from {h}"))
        .unwrap_or_default();
    meta.insert(
        "name".into(),
        json!(format!("{} @ {}{source}", session.user, session.line)),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "Login session: {}{source} on {} ({})",
            session.user, session.line, session.status
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("asl_utmpx_session")
}

fn bracket_artifact(artifact: &Artifact, file_name: &str, bracket: &Bracket) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("BootEvent"));
    meta.insert("subtype".into(), json!("asl_utmpx_bracket"));
    provenance(&mut meta, file_name);
    meta.insert("source_file".into(), json!("asl_utmpx"));
    meta.insert("kind".into(), json!(bracket.kind));
    meta.insert("ut_type_raw".into(), json!(bracket.ut_type));
    meta.insert(
        "ut_type".into(),
        json!(if bracket.ut_type == UT_BOOT_TIME {
            "BOOT_TIME"
        } else {
            "SHUTDOWN_TIME"
        }),
    );
    stamp_time(&mut meta, bracket.time, bracket.usec.saturating_mul(1000));
    meta.insert("time".into(), json!(bracket.time));
    if let Some(pid) = bracket.pid {
        meta.insert("pid".into(), json!(pid));
    }
    meta.insert("record_offset".into(), json!(bracket.at));
    let name = if bracket.ut_type == UT_BOOT_TIME {
        "System boot"
    } else {
        "System shutdown"
    };
    meta.insert("name".into(), json!(name));
    meta.insert("short_desc".into(), json!(name));
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("asl_utmpx_bracket")
}

#[allow(clippy::too_many_arguments)]
fn status_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    walk: &StoreWalk,
    sessions: usize,
    brackets: usize,
    sessions_capped: bool,
    unhandled_utmpx: usize,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("AslStatus"));
    meta.insert("subtype".into(), json!("asl_store_status"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(true));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("bytes_walked".into(), json!(walk.bytes_walked));
    meta.insert("messages".into(), json!(walk.messages.len()));
    meta.insert("strings".into(), json!(walk.strings));
    meta.insert("store_time".into(), json!(walk.header_time));
    meta.insert("login_sessions".into(), json!(sessions));
    meta.insert("boot_and_shutdown_events".into(), json!(brackets));
    let utmpx = walk.messages.iter().filter(|m| m.is_utmpx()).count();
    meta.insert("utmpx_history_records".into(), json!(utmpx));
    if utmpx > 0 {
        meta.insert(
            "utmpx_note".into(),
            json!(
                "macOS keeps no on-disk wtmpx: the login and logout history is written into \
                   this store under com.apple.system.utmpx and com.apple.system.lastlog, and \
                   these records are that history. /var/run/utmpx holds only the sessions open \
                   at acquisition."
            ),
        );
    }

    // Senders and facilities, which is what an examiner scans before opening
    // anything: whether this store holds login history at all.
    let mut senders: BTreeMap<String, usize> = BTreeMap::new();
    let mut facilities: BTreeMap<String, usize> = BTreeMap::new();
    let mut levels: BTreeMap<String, usize> = BTreeMap::new();
    for message in &walk.messages {
        if let Some(sender) = message.sender.text() {
            *senders.entry(sender.to_string()).or_default() += 1;
        }
        if let Some(facility) = message.facility.text() {
            *facilities.entry(facility.to_string()).or_default() += 1;
        }
        let key = level_name(message.level)
            .map(str::to_string)
            .unwrap_or_else(|| format!("level_{}", message.level));
        *levels.entry(key).or_default() += 1;
    }
    meta.insert("facility_counts".into(), json!(facilities));
    meta.insert("level_counts".into(), json!(levels));
    meta.insert("sender_count".into(), json!(senders.len()));
    if let (Some(first), Some(last)) = (walk.messages.first(), walk.messages.last()) {
        meta.insert("first_message_time".into(), json!(first.seconds));
        meta.insert("last_message_time".into(), json!(last.seconds));
    }

    let mut reasons = Vec::new();
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(file_name)));
    }
    if walk.record_cap_reached {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "the walk stopped at the reader's cap of {MAX_RECORDS} messages; the rest of the \
                 store was not read"
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
                "{} byte(s) at the end of the store are not a whole record ({}); they were not \
                 read, and a store still being written ends this way legitimately",
                walk.trailing_bytes,
                walk.stop_reason.unwrap_or("reason not recorded")
            ),
        ));
    }
    if walk.chain_breaks > 0 {
        meta.insert("chain_breaks".into(), json!(walk.chain_breaks));
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} message(s) name a next or previous record that is not their neighbour in \
                 file order; the chain is the store's second statement of its own record order, \
                 so a break means one of the two readings is wrong",
                walk.chain_breaks
            ),
        ));
    }
    if walk.first_disagrees {
        meta.insert("header_first_disagrees".into(), json!(true));
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "the header says the first message is at offset {} and the first message found \
                 is elsewhere; messages before that offset may have been missed",
                walk.declared_first
            ),
        ));
    }
    if sessions_capped {
        reasons.push((
            IncompleteReason::CapReached,
            format!("more than {MAX_SESSIONS} sessions; later logins were not reconstructed"),
        ));
    }
    if unhandled_utmpx > 0 {
        meta.insert("utmpx_records_unpaired".into(), json!(unhandled_utmpx));
        reasons.push((
            IncompleteReason::Unmapped,
            format!(
                "{unhandled_utmpx} login-history record(s) were counted but not turned into a \
                 session or a bracket — a logout whose login is in the previous day's store, or \
                 a ut_type this reader does not pair. Counted rather than dropped, and never \
                 given an invented start"
            ),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    meta.insert(
        "name".into(),
        json!(format!("Apple System Log parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "{file_name}: {} messages, {utmpx} login-history records, {sessions} session(s)",
            walk.messages.len()
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("asl_store_status")
}

fn refusal_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    refusal: Refusal,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("AslStatus"));
    meta.insert("subtype".into(), json!("asl_store_not_parsed"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(false));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("failure_reason".into(), json!(refusal.tag()));
    meta.insert("failure_detail".into(), json!(refusal.detail()));
    meta.insert(
        "message".into(),
        json!(
            "This file sits where Apple System Log stores live but was not read, so nothing \
               is reported from it. On macOS this store is where the login and logout history \
               is, so absence here is NOT evidence that nobody logged in."
        ),
    );
    let reason = staged
        .incomplete_reason()
        .unwrap_or(IncompleteReason::UnresolvedStructure);
    let _ = stamp_incomplete(
        &mut meta,
        "content",
        &[(
            reason,
            format!("{}; {}", staged.detail(file_name), refusal.detail()),
        )],
    );
    meta.insert(
        "name".into(),
        json!(format!("Apple System Log not parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!("{file_name} was not parsed: {}", refusal.detail())),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("asl_store_not_parsed")
}

impl ForensicsModule for AslParser {
    fn id(&self) -> &str {
        "macos.asl"
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
        let named = named_as_store(name, path);

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
                Refusal::Empty,
            )]);
        }

        let staged = Staged::read(ds.as_ref(), MAX_ASL_BYTES);
        let walk = match walk_store(&staged.bytes) {
            Ok(walk) => walk,
            Err(refusal) => {
                if !named {
                    return Ok(Vec::new());
                }
                debug!(
                    artifact = %artifact.id,
                    file = %file_name,
                    reason = refusal.tag(),
                    "named as an Apple System Log store but was not read"
                );
                return Ok(vec![refusal_artifact(
                    artifact, &file_name, &staged, refusal,
                )]);
            }
        };

        let (sessions, brackets, sessions_capped, unhandled) = reconstruct(&walk.messages);
        let mut out: Vec<Artifact> = Vec::with_capacity(walk.messages.len() + sessions.len() + 2);
        for message in &walk.messages {
            out.push(message_artifact(artifact, &file_name, message));
        }
        for session in &sessions {
            out.push(session_artifact(artifact, &file_name, session));
        }
        for bracket in &brackets {
            out.push(bracket_artifact(artifact, &file_name, bracket));
        }
        out.push(status_artifact(
            artifact,
            &file_name,
            &staged,
            &walk,
            sessions.len(),
            brackets.len(),
            sessions_capped,
            unhandled,
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
    // A store is written from literal offsets rather than through the reader's
    // own structures, so a mistake in those cannot make a test agree with
    // itself.

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    fn be64(v: u64) -> [u8; 8] {
        v.to_be_bytes()
    }

    /// A store under construction: strings are appended and their offsets
    /// handed back, then messages are appended referencing them.
    struct Store {
        body: Vec<u8>,
        first_message: Option<u64>,
    }

    impl Store {
        fn new() -> Self {
            Store {
                body: Vec::new(),
                first_message: None,
            }
        }

        fn offset(&self) -> u64 {
            (HEADER_BYTES + self.body.len()) as u64
        }

        /// Append a string record and return the offset it landed at.
        fn string(&mut self, text: &str) -> u64 {
            let at = self.offset();
            let mut bytes = text.as_bytes().to_vec();
            bytes.push(0);
            self.body.extend_from_slice(&be16(TYPE_STRING));
            self.body.extend_from_slice(&be32(bytes.len() as u32));
            self.body.extend_from_slice(&bytes);
            at
        }

        /// Append a message record. `slots` are the six references followed by
        /// the key/value slots, already encoded.
        #[allow(clippy::too_many_arguments)]
        fn message(
            &mut self,
            mid: u64,
            secs: u64,
            nanos: u32,
            level: u16,
            pid: u32,
            uid: u32,
            gid: u32,
            refs: [Vec<u8>; 6],
            kv: &[Vec<u8>],
        ) -> u64 {
            let at = self.offset();
            if self.first_message.is_none() {
                self.first_message = Some(at);
            }
            let len = MESSAGE_OVERHEAD + kv.len() * SLOT_BYTES;
            let mut p = Vec::new();
            p.extend_from_slice(&be64(0)); // next, patched below
            p.extend_from_slice(&be64(mid));
            p.extend_from_slice(&be64(secs));
            p.extend_from_slice(&be32(nanos));
            p.extend_from_slice(&be16(level));
            p.extend_from_slice(&be16(2)); // flags
            p.extend_from_slice(&be32(pid));
            p.extend_from_slice(&be32(uid));
            p.extend_from_slice(&be32(gid));
            p.extend_from_slice(&be32(u32::MAX)); // read_uid: anyone
            p.extend_from_slice(&be32(80)); // read_gid: admin
            p.extend_from_slice(&be32(0)); // referenced pid
            p.extend_from_slice(&be32(kv.len() as u32)); // key/value slot count
            assert_eq!(p.len(), MESSAGE_FIXED_BYTES);
            for r in &refs {
                assert_eq!(r.len(), SLOT_BYTES);
                p.extend_from_slice(r);
            }
            for slot in kv {
                assert_eq!(slot.len(), SLOT_BYTES);
                p.extend_from_slice(slot);
            }
            p.extend_from_slice(&be64(0)); // prev, patched below
            assert_eq!(p.len(), len);
            self.body.extend_from_slice(&be16(TYPE_MESSAGE));
            self.body.extend_from_slice(&be32(len as u32));
            self.body.extend_from_slice(&p);
            at
        }

        /// Append a record of an unknown type, to exercise the refusal.
        fn unknown_record(&mut self) {
            self.body.extend_from_slice(&be16(7));
            self.body.extend_from_slice(&be32(4));
            self.body.extend_from_slice(&[0u8; 4]);
        }

        /// Finish the store, patching the `next`/`prev` chain so it is
        /// consistent — the reader checks it, so a fixture must build it
        /// correctly or every test would report a break.
        fn finish(self) -> Vec<u8> {
            self.finish_versioned(ASL_VERSION)
        }

        fn finish_versioned(self, version: u32) -> Vec<u8> {
            let mut out = ASL_MAGIC.to_vec();
            out.extend_from_slice(&[0u8; 6]); // cookie padding
            out.extend_from_slice(&be32(version));
            out.extend_from_slice(&be64(self.first_message.unwrap_or(0)));
            out.extend_from_slice(&be64(1_617_681_600)); // store time
            out.extend_from_slice(&be32(0)); // string cache size
            out.extend_from_slice(&be64(0)); // last
            out.resize(HEADER_BYTES, 0);
            out.extend_from_slice(&self.body);
            patch_chain(&mut out);
            out
        }
    }

    /// Walk the finished store and write each message's `next` and `prev`.
    fn patch_chain(store: &mut [u8]) {
        let mut messages = Vec::new();
        let mut off = HEADER_BYTES;
        while off + 6 <= store.len() {
            let kind = u16::from_be_bytes([store[off], store[off + 1]]);
            let len = u32::from_be_bytes([
                store[off + 2],
                store[off + 3],
                store[off + 4],
                store[off + 5],
            ]) as usize;
            if off + 6 + len > store.len() {
                break;
            }
            if kind == TYPE_MESSAGE {
                messages.push((off, len));
            }
            off += 6 + len;
        }
        for (i, (at, len)) in messages.iter().enumerate() {
            let payload = at + 6;
            let next = messages.get(i + 1).map(|(a, _)| *a as u64).unwrap_or(0);
            let prev = if i == 0 { 0 } else { messages[i - 1].0 as u64 };
            store[payload..payload + 8].copy_from_slice(&be64(next));
            let tail = payload + len - SLOT_BYTES;
            store[tail..tail + 8].copy_from_slice(&be64(prev));
        }
    }

    /// A reference slot naming a string record.
    fn at(off: u64) -> Vec<u8> {
        be64(off).to_vec()
    }
    /// An empty reference slot.
    fn none() -> Vec<u8> {
        be64(0).to_vec()
    }
    /// A reference slot carrying its string inline, which is how Apple stores
    /// anything up to seven bytes.
    fn inline(text: &str) -> Vec<u8> {
        assert!(text.len() <= 7, "an inline string is at most seven bytes");
        let mut out = vec![0x80 | text.len() as u8];
        out.extend_from_slice(text.as_bytes());
        out.resize(SLOT_BYTES, 0);
        out
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
        AslParser.process(&art).expect("never fails the pipeline")
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    fn status_of(out: &[Artifact]) -> &Value {
        of_type(out, "AslStatus")
            .first()
            .copied()
            .expect("every read or refused store produces a status row")
    }

    fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|x| x.as_str())
    }
    fn n(v: &Value, key: &str) -> Option<i64> {
        v.get(key).and_then(|x| x.as_i64())
    }

    const STORE_PATH: &str = "/private/var/log/asl/2021.04.06.G80.asl";

    /// A `utmpx`-facility message, the shape the real store holds.
    #[allow(clippy::too_many_arguments)]
    fn utmpx_message(
        store: &mut Store,
        mid: u64,
        msg_secs: u64,
        sender: &str,
        facility: &str,
        text: &str,
        pairs: &[(&str, &str)],
    ) {
        let host = store.string("stu-21-155-171-184");
        let sender_at = store.string(sender);
        let facility_at = store.string(facility);
        let text_at = store.string(text);
        let mut kv = Vec::new();
        for (k, v) in pairs {
            let k_at = store.string(k);
            let v_at = store.string(v);
            kv.push(at(k_at));
            kv.push(at(v_at));
        }
        store.message(
            mid,
            msg_secs,
            0,
            5,
            0,
            u32::MAX - 1,
            u32::MAX - 1,
            [
                at(host),
                at(sender_at),
                at(facility_at),
                at(text_at),
                none(),
                none(),
            ],
            &kv,
        );
    }

    // --- decoding -------------------------------------------------------------

    #[test]
    fn a_hand_written_store_decodes_field_by_field_at_the_documented_offsets() {
        let mut store = Store::new();
        let host = store.string("stu-21-155-171-184");
        let facility = store.string("user");
        let text = store.string("objc[1191]: Class REMCDChangeTrackingState is implemented twice");
        let key = store.string("SenderMachUUID");
        let value = store.string("103DFC0A-3A8E-386B-A5FB-6442C4A60572");
        store.message(
            17_202,
            1_617_681_600,
            55_689_976,
            3,
            1191,
            501,
            20,
            [
                at(host),
                // The sender is short enough for Apple to store inline, and
                // nine thousand of the corpus's references are stored that
                // way, so the fixture uses both forms.
                inline("remindd"),
                at(facility),
                at(text),
                none(),
                none(),
            ],
            &[at(key), at(value)],
        );
        let out = run(store.finish(), "2021.04.06.G80.asl", STORE_PATH);

        let messages = of_type(&out, "AslMessage");
        assert_eq!(messages.len(), 1);
        let m = messages[0];
        assert_eq!(n(m, "message_id"), Some(17_202));
        assert_eq!(n(m, "timestamp"), Some(1_617_681_600));
        assert_eq!(n(m, "level"), Some(3));
        assert_eq!(s(m, "level_name"), Some("error"));
        assert_eq!(n(m, "pid"), Some(1191));
        assert_eq!(n(m, "uid"), Some(501));
        assert_eq!(n(m, "gid"), Some(20));
        assert_eq!(s(m, "host"), Some("stu-21-155-171-184"));
        assert_eq!(
            s(m, "sender"),
            Some("remindd"),
            "an inline reference decodes to the same thing a record reference does"
        );
        assert_eq!(s(m, "facility"), Some("user"));
        assert!(s(m, "message").expect("the text").contains("REMCD"));
        assert_eq!(m["values"][0]["key"], json!("SenderMachUUID"));
        assert_eq!(
            m["values"][0]["value"],
            json!("103DFC0A-3A8E-386B-A5FB-6442C4A60572")
        );
        // The read uid and gid are access control, not identity: -1 means
        // anyone, so it is reported absent, and 80 is the admin group.
        assert!(m.get("read_uid").is_none());
        assert_eq!(n(m, "read_gid"), Some(80));
        assert!(
            m.get("content_incomplete").is_none(),
            "a well-formed record has nothing to report"
        );

        let st = status_of(&out);
        assert_eq!(n(st, "messages"), Some(1));
        assert_eq!(n(st, "strings"), Some(5));
        assert!(st.get("chain_breaks").is_none());
        assert!(st.get("header_first_disagrees").is_none());
    }

    #[test]
    fn an_unattributed_sender_is_reported_without_a_uid_rather_than_as_account_4294967294() {
        let mut store = Store::new();
        let text = store.string("a launchd message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            0,
            // -2 is `nobody`: ASL could not attribute the sender.
            u32::MAX - 1,
            u32::MAX - 1,
            [
                none(),
                inline("launchd"),
                inline("daemon"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let out = run(store.finish(), "2021.04.06.G80.asl", STORE_PATH);
        let m = of_type(&out, "AslMessage")[0];
        assert!(
            m.get("uid").is_none() && m.get("gid").is_none(),
            "uid 4294967294 is not an account, and putting it on a screen would invent one"
        );
        assert_eq!(s(m, "sender"), Some("launchd"));
    }

    #[test]
    fn a_severity_outside_the_syslog_scale_is_reported_as_the_number_the_store_holds() {
        let mut store = Store::new();
        let text = store.string("odd severity");
        store.message(
            1,
            1_617_681_600,
            0,
            99,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let out = run(store.finish(), "2021.04.06.G80.asl", STORE_PATH);
        let m = of_type(&out, "AslMessage")[0];
        assert_eq!(n(m, "level"), Some(99));
        assert!(m.get("level_name").is_none(), "no name is invented for it");
        assert!(s(m, "level_note").expect("a note").contains("outside"));
    }

    #[test]
    fn a_reference_that_names_no_string_record_is_reported_as_the_offset_it_named() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                // An offset well past anything in this store.
                at(999_999),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let out = run(store.finish(), "2021.04.06.G80.asl", STORE_PATH);
        let m = of_type(&out, "AslMessage")[0];
        assert!(
            m.get("host").is_none(),
            "an unresolvable reference must not render as an empty field"
        );
        assert_eq!(n(m, "host_unresolved_offset"), Some(999_999));
        assert_eq!(
            s(m, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
    }

    // --- the login history ----------------------------------------------------

    /// The whole point of reading this store: macOS keeps no on-disk `wtmpx`,
    /// so a console login, its logout and the shutdown that bracketed them are
    /// only here.
    #[test]
    fn a_console_login_and_its_logout_become_one_session_with_a_duration() {
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_613_095_025,
            "bootlog",
            "com.apple.system.utmpx",
            "BOOT_TIME 1613095025 80993",
            &[
                ("ut_id", "0x00 0x00 0x00 0x00"),
                ("ut_pid", "1"),
                ("ut_type", "2"),
                ("ut_tv.tv_sec", "1613095025"),
                ("ut_tv.tv_usec", "80993"),
            ],
        );
        utmpx_message(
            &mut store,
            2,
            1_613_095_042,
            "loginwindow",
            "com.apple.system.lastlog",
            "USER_PROCESS: 124 console",
            &[
                ("ut_user", "eliflatt"),
                ("ut_id", "0x2f 0x00 0x01 0x01"),
                ("ut_line", "console"),
                ("ut_pid", "124"),
                ("ut_type", "7"),
                ("ut_tv.tv_sec", "1613095042"),
                ("ut_tv.tv_usec", "570027"),
            ],
        );
        utmpx_message(
            &mut store,
            3,
            1_613_095_748,
            "sessionlogoutd",
            "com.apple.system.utmpx",
            "DEAD_PROCESS: 124 console",
            &[
                ("ut_user", "eliflatt"),
                ("ut_id", "0x2f 0x00 0x01 0x01"),
                ("ut_line", "console"),
                ("ut_pid", "124"),
                ("ut_type", "8"),
                ("ut_tv.tv_sec", "1613095748"),
                ("ut_tv.tv_usec", "807844"),
            ],
        );
        utmpx_message(
            &mut store,
            4,
            1_613_095_748,
            "shutdown",
            "com.apple.system.utmpx",
            "SHUTDOWN_TIME: 1613095748 844611",
            &[
                ("ut_id", "0x00 0x00 0x00 0x00"),
                ("ut_type", "11"),
                ("ut_tv.tv_sec", "1613095748"),
                ("ut_tv.tv_usec", "844611"),
            ],
        );
        let out = run(store.finish(), "2021.02.12.G80.asl", STORE_PATH);

        let sessions = of_type(&out, "LoginSession");
        assert_eq!(sessions.len(), 1);
        let session = sessions[0];
        assert_eq!(s(session, "user"), Some("eliflatt"));
        assert_eq!(s(session, "tty"), Some("console"));
        assert_eq!(n(session, "pid"), Some(124));
        assert_eq!(n(session, "login_time"), Some(1_613_095_042));
        assert_eq!(n(session, "logout_time"), Some(1_613_095_748));
        assert_eq!(n(session, "duration_seconds"), Some(706));
        assert_eq!(s(session, "status"), Some("logged_out"));
        assert_eq!(s(session, "closed_by"), Some("logout_record"));
        assert_eq!(
            s(session, "source_file"),
            Some("asl_utmpx"),
            "the record says where it came from, so it is never confused with a binary wtmp"
        );
        assert!(
            session.get("bounded_before_time").is_none(),
            "a session with a real logout needs no bound"
        );

        let brackets = of_type(&out, "BootEvent");
        assert_eq!(brackets.len(), 2);
        let kinds: Vec<&str> = brackets.iter().filter_map(|b| s(b, "kind")).collect();
        assert!(kinds.contains(&"boot") && kinds.contains(&"shutdown"));
        let shutdown = brackets
            .iter()
            .find(|b| s(b, "kind") == Some("shutdown"))
            .expect("the shutdown");
        assert_eq!(
            s(shutdown, "ut_type"),
            Some("SHUTDOWN_TIME"),
            "the store spells the name out beside ut_type 11, which is what corroborates the \
             Darwin mapping the binary reader had only from a header"
        );
        assert_eq!(n(shutdown, "ut_type_raw"), Some(11));

        let st = status_of(&out);
        assert_eq!(n(st, "utmpx_history_records"), Some(4));
        assert_eq!(n(st, "login_sessions"), Some(1));
        assert!(s(st, "utmpx_note")
            .expect("a note")
            .contains("no on-disk wtmpx"));
    }

    /// An SSH session's `ut_host` is the address it came from, which is the
    /// answer the binary `utmpx` cannot give at all.
    #[test]
    fn an_ssh_session_carries_the_address_it_came_from() {
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_616_637_498,
            "sshd: eliflatt [priv]",
            "com.apple.system.lastlog",
            "USER_PROCESS: 1601 ttys001",
            &[
                ("ut_user", "eliflatt"),
                ("ut_id", "s001"),
                ("ut_line", "ttys001"),
                ("ut_pid", "1601"),
                ("ut_type", "7"),
                ("ut_tv.tv_sec", "1616637498"),
                ("ut_tv.tv_usec", "318060"),
                ("ut_host", "184.171.155.71"),
            ],
        );
        utmpx_message(
            &mut store,
            2,
            1_616_637_529,
            "sshd: eliflatt [priv]",
            "com.apple.system.utmpx",
            "DEAD_PROCESS: 1601 ttys001",
            &[
                ("ut_user", "eliflatt"),
                ("ut_line", "ttys001"),
                ("ut_pid", "1601"),
                ("ut_type", "8"),
                ("ut_tv.tv_sec", "1616637529"),
                ("ut_tv.tv_usec", "502032"),
            ],
        );
        let out = run(store.finish(), "2021.03.25.G80.asl", STORE_PATH);
        let session = of_type(&out, "LoginSession")[0];
        assert_eq!(s(session, "host"), Some("184.171.155.71"));
        assert_eq!(s(session, "tty"), Some("ttys001"));
        assert_eq!(s(session, "ut_id"), Some("s001"));
        assert_eq!(n(session, "duration_seconds"), Some(31));
        assert!(s(session, "name")
            .expect("a name")
            .contains("from 184.171.155.71"));
    }

    #[test]
    fn a_login_whose_logout_is_in_another_store_is_left_open_and_not_given_a_duration() {
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_617_653_306,
            "login",
            "com.apple.system.lastlog",
            "USER_PROCESS: 562 ttys000",
            &[
                ("ut_user", "eliflatt"),
                ("ut_line", "ttys000"),
                ("ut_pid", "562"),
                ("ut_type", "7"),
                ("ut_tv.tv_sec", "1617653306"),
            ],
        );
        let out = run(store.finish(), "2021.04.05.G80.asl", STORE_PATH);
        let session = of_type(&out, "LoginSession")[0];
        assert_eq!(s(session, "status"), Some("still_logged_in"));
        assert_eq!(s(session, "closed_by"), Some("end_of_file"));
        assert!(session.get("logout_time").is_none());
        assert!(session.get("duration_seconds").is_none());
        assert!(s(session, "status_note")
            .expect("a note")
            .contains("not paired across stores"));
    }

    #[test]
    fn a_session_the_machine_went_down_under_gets_a_bound_and_not_a_logout() {
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_613_095_042,
            "loginwindow",
            "com.apple.system.lastlog",
            "USER_PROCESS: 124 console",
            &[
                ("ut_user", "eliflatt"),
                ("ut_line", "console"),
                ("ut_pid", "124"),
                ("ut_type", "7"),
                ("ut_tv.tv_sec", "1613095042"),
            ],
        );
        utmpx_message(
            &mut store,
            2,
            1_613_095_748,
            "shutdown",
            "com.apple.system.utmpx",
            "SHUTDOWN_TIME: 1613095748 844611",
            &[("ut_type", "11"), ("ut_tv.tv_sec", "1613095748")],
        );
        let out = run(store.finish(), "2021.02.12.G80.asl", STORE_PATH);
        let session = of_type(&out, "LoginSession")[0];
        assert_eq!(s(session, "status"), Some("gone_no_logout"));
        assert_eq!(s(session, "closed_by"), Some("shutdown"));
        assert_eq!(n(session, "bounded_before_time"), Some(1_613_095_748));
        assert_eq!(n(session, "max_duration_seconds"), Some(706));
        assert!(
            session.get("logout_time").is_none(),
            "no logout was written, so none may be reported"
        );
        assert!(
            session.get("duration_seconds").is_none(),
            "an observed duration needs two observed ends"
        );
    }

    #[test]
    fn a_logout_whose_login_is_in_another_store_is_counted_and_not_invented() {
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_616_705_262,
            "sshd: eliflatt [priv]",
            "com.apple.system.utmpx",
            "DEAD_PROCESS: 1616 ttys001",
            &[
                ("ut_user", "eliflatt"),
                ("ut_line", "ttys001"),
                ("ut_type", "8"),
                ("ut_tv.tv_sec", "1616705262"),
            ],
        );
        let out = run(store.finish(), "2021.03.26.G80.asl", STORE_PATH);
        assert!(
            of_type(&out, "LoginSession").is_empty(),
            "a logout with no login must not become a session with an invented start"
        );
        let st = status_of(&out);
        assert_eq!(n(st, "utmpx_records_unpaired"), Some(1));
        assert_eq!(s(st, "content_incomplete_reason"), Some("unmapped"));
    }

    /// ROADMAP §5.11: the ASL copy of the pairing rules had drifted from the
    /// `wtmp` reader's. Once the cap is reached no new session may open, so a
    /// later logout is counted unpaired, exactly as `seance_plugin_utmp` does,
    /// rather than closing a session that is then silently dropped.
    #[test]
    fn past_the_session_cap_a_login_opens_nothing_and_its_logout_is_unpaired_as_in_wtmp() {
        let mut store = Store::new();
        let mut mid = 0;
        for (secs, ty, line) in [
            (1_616_705_000u64, "7", "ttys001"),
            (1_616_705_100, "8", "ttys001"),
            (1_616_705_200, "7", "ttys002"),
            (1_616_705_300, "8", "ttys002"),
        ] {
            mid += 1;
            let secs_text = secs.to_string();
            utmpx_message(
                &mut store,
                mid,
                secs,
                "login",
                "com.apple.system.utmpx",
                "utmpx",
                &[
                    ("ut_user", "eliflatt"),
                    ("ut_line", line),
                    ("ut_type", ty),
                    ("ut_tv.tv_sec", secs_text.as_str()),
                ],
            );
        }
        let walk = walk_store(&store.finish()).expect("a well-formed store");
        let (sessions, _brackets, capped, unpaired) = reconstruct_capped(&walk.messages, 1);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].line, "ttys001");
        assert!(capped);
        assert_eq!(
            unpaired, 1,
            "the second logout closes no session once the cap stopped its login opening"
        );
    }

    #[test]
    fn the_sessions_own_time_is_used_and_not_the_time_syslogd_wrote_the_message() {
        // The record's `ut_tv.tv_sec` is when the session event happened; the
        // message is timed when syslogd wrote it. Using the wrong one moves a
        // login on the timeline.
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_616_189_400, // syslogd wrote it later
            "login",
            "com.apple.system.lastlog",
            "USER_PROCESS: 553 ttys000",
            &[
                ("ut_user", "eliflatt"),
                ("ut_line", "ttys000"),
                ("ut_type", "7"),
                ("ut_tv.tv_sec", "1616189376"),
            ],
        );
        let out = run(store.finish(), "2021.03.19.G80.asl", STORE_PATH);
        assert_eq!(
            n(of_type(&out, "LoginSession")[0], "login_time"),
            Some(1_616_189_376)
        );
        assert_eq!(
            n(of_type(&out, "AslMessage")[0], "timestamp"),
            Some(1_616_189_400),
            "the message keeps its own time, so both are on the record"
        );
    }

    #[test]
    fn a_message_outside_the_login_facilities_produces_no_session() {
        let mut store = Store::new();
        // The same key names in a facility that is not the login history: a
        // reader keying on the keys rather than the facility would invent a
        // session from it.
        utmpx_message(
            &mut store,
            1,
            1_617_681_600,
            "some-daemon",
            "user",
            "not a login record",
            &[
                ("ut_user", "root"),
                ("ut_line", "console"),
                ("ut_type", "7"),
            ],
        );
        let out = run(store.finish(), "2021.04.06.G80.asl", STORE_PATH);
        assert!(of_type(&out, "LoginSession").is_empty());
        assert_eq!(n(status_of(&out), "utmpx_history_records"), Some(0));
    }

    // --- selection and refusal ------------------------------------------------

    #[test]
    fn a_file_that_is_not_a_store_is_passed_over_in_silence() {
        for bytes in [b"#!/bin/sh\n".to_vec(), vec![0u8; 4096], b"ASL DB".to_vec()] {
            let out = run(bytes, "notes.txt", "/Users/eliflatt/notes.txt");
            assert!(out.is_empty());
        }
    }

    #[test]
    fn a_file_named_as_a_store_that_will_not_parse_is_reported_rather_than_dropped() {
        let out = run(vec![0x81u8; 4096], "2021.04.06.G80.asl", STORE_PATH);
        assert_eq!(out.len(), 1);
        let st = status_of(&out);
        assert_eq!(st["detected"], json!(false));
        assert_eq!(s(st, "failure_reason"), Some("no_asl_db_magic"));
        assert!(s(st, "message")
            .expect("a message")
            .contains("NOT evidence that nobody logged in"));
    }

    #[test]
    fn an_empty_store_is_reported_because_a_wiped_log_is_a_finding() {
        let out = run(Vec::new(), "2021.04.06.G80.asl", STORE_PATH);
        assert_eq!(out.len(), 1);
        assert_eq!(s(status_of(&out), "failure_reason"), Some("empty_file"));
    }

    #[test]
    fn an_unknown_store_version_is_refused_rather_than_guessed_at() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let out = run(store.finish_versioned(3), "2021.04.06.G80.asl", STORE_PATH);
        let st = status_of(&out);
        assert_eq!(s(st, "failure_reason"), Some("unknown_store_version"));
        assert!(s(st, "failure_detail")
            .expect("a detail")
            .contains("will not guess the layout"));
        assert!(of_type(&out, "AslMessage").is_empty());
    }

    #[test]
    fn a_store_under_any_name_is_read_because_selection_is_by_content() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let out = run(store.finish(), "carved-0001.bin", "/carved/carved-0001.bin");
        assert_eq!(of_type(&out, "AslMessage").len(), 1);
    }

    #[test]
    fn a_store_that_ends_mid_record_reports_the_trailing_bytes_rather_than_completing_them() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let text2 = store.string("a second message");
        store.message(
            2,
            1_617_681_601,
            0,
            5,
            2,
            0,
            0,
            [
                none(),
                inline("y"),
                inline("user"),
                at(text2),
                none(),
                none(),
            ],
            &[],
        );
        let mut bytes = store.finish();
        let keep = bytes.len() - 40;
        bytes.truncate(keep);
        let out = run(bytes, "2021.04.06.G80.asl", STORE_PATH);
        let st = status_of(&out);
        assert_eq!(
            of_type(&out, "AslMessage").len(),
            1,
            "the whole record is read and the partial one is not invented"
        );
        assert_eq!(s(st, "walk_stop_reason"), Some("store_ends_mid_record"));
        assert!(n(st, "trailing_bytes").unwrap() > 0);
        assert!(s(st, "content_incomplete_detail")
            .expect("a sentence")
            .contains("not a whole record"));
    }

    #[test]
    fn a_record_type_this_reader_does_not_know_stops_the_walk_rather_than_being_skipped() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        store.unknown_record();
        let text2 = store.string("past the unknown record");
        store.message(
            2,
            1_617_681_601,
            0,
            5,
            2,
            0,
            0,
            [
                none(),
                inline("y"),
                inline("user"),
                at(text2),
                none(),
                none(),
            ],
            &[],
        );
        let out = run(store.finish(), "2021.04.06.G80.asl", STORE_PATH);
        let st = status_of(&out);
        assert_eq!(
            of_type(&out, "AslMessage").len(),
            1,
            "a store holding a third record type is not the format this reader was shown; \
             reading past it would be reading it against a guess"
        );
        assert_eq!(s(st, "walk_stop_reason"), Some("unknown_record_type"));
        assert!(n(st, "trailing_bytes").unwrap() > 0);
    }

    #[test]
    fn a_short_read_is_reported_rather_than_read_as_the_whole_store() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let mut bytes = store.finish();
        let full = bytes.len();
        bytes.truncate(full - 8);
        let out = run_source(
            Arc::new(TruncatedSource::new(bytes, full as u64)),
            "2021.04.06.G80.asl",
            STORE_PATH,
        );
        let st = status_of(&out);
        assert_eq!(n(st, "declared_size"), Some(full as i64));
        assert!(n(st, "bytes_staged").unwrap() < full as i64);
        assert!(st.get("content_incomplete").is_some());
    }

    #[test]
    fn a_broken_next_or_prev_chain_is_reported_because_it_is_a_second_statement_of_the_order() {
        let mut store = Store::new();
        let text = store.string("a message");
        store.message(
            1,
            1_617_681_600,
            0,
            5,
            1,
            0,
            0,
            [
                none(),
                inline("x"),
                inline("user"),
                at(text),
                none(),
                none(),
            ],
            &[],
        );
        let text2 = store.string("a second message");
        store.message(
            2,
            1_617_681_601,
            0,
            5,
            2,
            0,
            0,
            [
                none(),
                inline("y"),
                inline("user"),
                at(text2),
                none(),
                none(),
            ],
            &[],
        );
        let mut bytes = store.finish();
        // Corrupt the first message's `next`, leaving everything else intact.
        let first = HEADER_BYTES + 6;
        let mut off = HEADER_BYTES;
        loop {
            let kind = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            let len = u32::from_be_bytes([
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
            ]) as usize;
            if kind == TYPE_MESSAGE {
                bytes[off + 6..off + 14].copy_from_slice(&be64(0xdead));
                break;
            }
            off += 6 + len;
        }
        let _ = first;
        let out = run(bytes, "2021.04.06.G80.asl", STORE_PATH);
        let st = status_of(&out);
        assert_eq!(n(st, "chain_breaks"), Some(1));
        assert!(s(st, "content_incomplete_detail")
            .expect("a sentence")
            .contains("second statement of its own record order"));
        // The records are still reported: they were read, and the caveat
        // travels on the status row.
        assert_eq!(of_type(&out, "AslMessage").len(), 2);
    }

    #[test]
    fn every_emitted_record_names_its_source_file_and_format() {
        let mut store = Store::new();
        utmpx_message(
            &mut store,
            1,
            1_613_095_042,
            "loginwindow",
            "com.apple.system.lastlog",
            "USER_PROCESS: 124 console",
            &[
                ("ut_user", "eliflatt"),
                ("ut_line", "console"),
                ("ut_type", "7"),
                ("ut_tv.tv_sec", "1613095042"),
            ],
        );
        let out = run(store.finish(), "2021.02.12.G80.asl", STORE_PATH);
        assert_eq!(out.len(), 3, "the message, the session and the status row");
        for a in &out {
            assert_eq!(s(&a.metadata, "source_format"), Some("apple_system_log_v2"));
            assert_eq!(
                s(&a.metadata, "source_file_name"),
                Some("2021.02.12.G80.asl")
            );
        }
    }

    // --- the real stores ------------------------------------------------------

    /// **The eleven real ASL stores from the Magnet 2021 macOS image**, read
    /// through the production path.
    ///
    /// This is the known answer the layout was derived against, and the
    /// structural figures are pinned so that a change to any token length
    /// fails loudly: 7,022 messages and 5,774 strings, every store tiling
    /// exactly, every `next`/`prev` chain intact, and every header's `first`
    /// agreeing with the first message found.
    ///
    /// The login history it recovers is the answer `/var/run/utmpx` cannot
    /// give, and it agrees with that file where the two overlap.
    #[test]
    fn the_real_macos_asl_stores_hold_the_login_history_utmpx_cannot_give() {
        let dir = home("ctf-evidence/macos2021/tree/private/var/log/asl");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            eprintln!(
                "skipping: {} not present (gitignored corpus)",
                dir.display()
            );
            return;
        };
        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "asl"))
            .collect();
        files.sort();
        assert_eq!(files.len(), 11, "eleven stores are held");

        let mut messages = 0i64;
        let mut strings = 0i64;
        let mut trailing = 0i64;
        let mut chain_breaks = 0i64;
        let mut first_disagrees = 0usize;
        let mut utmpx = 0i64;
        let mut sessions: Vec<(String, String, Option<String>, Option<i64>)> = Vec::new();
        let mut boots = 0usize;
        let mut shutdowns = 0usize;

        for file in &files {
            let bytes = std::fs::read(file).expect("the corpus file reads");
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            let out = run(bytes, &name, &format!("/private/var/log/asl/{name}"));
            let st = status_of(&out);
            messages += n(st, "messages").unwrap_or(0);
            strings += n(st, "strings").unwrap_or(0);
            trailing += n(st, "trailing_bytes").unwrap_or(0);
            chain_breaks += n(st, "chain_breaks").unwrap_or(0);
            if st.get("header_first_disagrees").is_some() {
                first_disagrees += 1;
            }
            utmpx += n(st, "utmpx_history_records").unwrap_or(0);
            for session in of_type(&out, "LoginSession") {
                sessions.push((
                    s(session, "user").unwrap_or_default().to_string(),
                    s(session, "tty").unwrap_or_default().to_string(),
                    s(session, "host").map(str::to_string),
                    n(session, "duration_seconds"),
                ));
            }
            for bracket in of_type(&out, "BootEvent") {
                match s(bracket, "kind") {
                    Some("boot") => boots += 1,
                    Some("shutdown") => shutdowns += 1,
                    _ => {}
                }
            }
        }

        assert_eq!(messages, 7022, "every message record in all eleven stores");
        assert_eq!(strings, 5774, "and every string record");
        assert_eq!(
            trailing, 0,
            "every store tiles exactly from offset 80 to its last byte; a trailing count here \
             means a record length is being read wrongly"
        );
        assert_eq!(
            chain_breaks, 0,
            "the next/prev chain is the store's second statement of its own record order and it \
             agrees with file order in all 7,022"
        );
        assert_eq!(
            first_disagrees, 0,
            "every header's `first` is the first message"
        );

        assert_eq!(
            utmpx, 32,
            "19 com.apple.system.utmpx and 13 com.apple.system.lastlog records — the login \
             history macOS keeps nowhere else"
        );
        assert_eq!(boots, 6, "six boots");
        assert_eq!(shutdowns, 4, "four clean shutdowns");

        // Every session belongs to the one interactive account on this image.
        assert!(
            sessions.iter().all(|(user, ..)| user == "eliflatt"),
            "got {sessions:?}"
        );
        let terminals: std::collections::BTreeSet<&str> =
            sessions.iter().map(|(_, tty, ..)| tty.as_str()).collect();
        assert!(
            terminals.contains("console")
                && terminals.contains("ttys000")
                && terminals.contains("ttys001"),
            "console, a local terminal and an SSH terminal; got {terminals:?}"
        );

        // The SSH sessions, which are the ones carrying an address — and the
        // answer the binary utmpx cannot give at all.
        let remote: Vec<&(String, String, Option<String>, Option<i64>)> =
            sessions.iter().filter(|(.., h, _)| h.is_some()).collect();
        assert_eq!(
            remote.len(),
            3,
            "three sessions name the address they came from"
        );
        let addresses: std::collections::BTreeSet<&str> = remote
            .iter()
            .filter_map(|(.., h, _)| h.as_deref())
            .collect();
        assert_eq!(
            addresses,
            ["184.171.149.230", "184.171.155.71"]
                .into_iter()
                .collect::<std::collections::BTreeSet<&str>>()
        );
        // Both ends recorded, so a duration is stated rather than bounded.
        let longest = remote
            .iter()
            .filter_map(|(.., d)| *d)
            .max()
            .expect("at least one SSH session has both ends");
        assert!(
            longest > 30_000,
            "the longest SSH session ran for hours, not seconds: {longest}s"
        );
    }
}
