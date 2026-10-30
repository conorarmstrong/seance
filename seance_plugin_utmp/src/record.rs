//! Fixed-size binary record decoding, and layout detection, for the
//! login-accounting family: Linux `utmp` / `wtmp` / `btmp` (`struct utmp`) and
//! `lastlog` (`struct lastlog`), and macOS `utmpx` (Darwin's `struct utmpx`).
//!
//! These files carry no magic number. A parser therefore has to work out, from
//! the bytes alone, which C struct layout wrote them and in which byte order —
//! and the cost of getting that wrong is not a parse error, it is a *plausible
//! looking wrong answer*: usernames sliced out of hostnames, and login times
//! read from the middle of an IP address. Everything in this module is built so
//! that a layout we cannot positively confirm is refused rather than guessed at.
//!
//! Getting the *layout* right is not the whole of it: two records can share a
//! stride and still disagree about what a field means. Darwin's `ut_type`
//! enumeration swaps two of Linux's values and adds two of its own, so the
//! enumeration travels with the layout as a [`TypeDialect`] rather than being
//! assumed from the record size.
//!
//! What an examiner gets from a correct decode: who logged in, on which
//! terminal, from which host and IP, with which PID, and exactly when (UTC Unix
//! seconds, the kernel's own convention — no timezone conversion is applied or
//! needed). What a wrong answer looks like: a session attributed to the wrong
//! account, an attacker's source IP decoded as a different address, or a
//! timestamp read at the wrong offset that places an intrusion hours or years
//! away from when it happened.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

// --- ut_type values (utmp(5)) ------------------------------------------------

/// `EMPTY` — an unused slot. A record that is entirely zero is legitimate
/// padding, not corruption. Zero in both dialects.
pub const UT_EMPTY: u16 = 0;
/// `RUN_LVL` — a run-level change; also how a clean shutdown is recorded.
/// One in both dialects.
pub const UT_RUN_LVL: u16 = 1;
/// `BOOT_TIME` — the system booted (on Linux `ut_line` is `~` and `ut_user` is
/// `reboot`; Darwin writes both empty). Two in both dialects.
pub const UT_BOOT_TIME: u16 = 2;
/// `NEW_TIME` — the wall clock was set (value *after* the change).
///
/// **Linux only.** Three here; Darwin puts `OLD_TIME` at three. See
/// [`TypeDialect`].
pub const UT_NEW_TIME: u16 = 3;
/// `OLD_TIME` — the wall clock was set (value *before* the change).
///
/// **Linux only.** Four here; Darwin puts `NEW_TIME` at four. See
/// [`TypeDialect`].
pub const UT_OLD_TIME: u16 = 4;
/// `INIT_PROCESS` — a process spawned by init. Five in both dialects.
pub const UT_INIT_PROCESS: u16 = 5;
/// `LOGIN_PROCESS` — a getty waiting for a login on a terminal. Six in both
/// dialects.
pub const UT_LOGIN_PROCESS: u16 = 6;
/// `USER_PROCESS` — an interactive login. The record an examiner cares about.
/// Seven in both dialects.
pub const UT_USER_PROCESS: u16 = 7;
/// `DEAD_PROCESS` — a terminated session, i.e. the logout. Eight in both
/// dialects.
pub const UT_DEAD_PROCESS: u16 = 8;
/// `ACCOUNTING` — reserved by the standard, never written in practice. Nine in
/// both dialects.
pub const UT_ACCOUNTING: u16 = 9;
/// `OLD_TIME` on Darwin — the wall clock was set (value *before* the change).
///
/// The same numeric value Linux gives `NEW_TIME`. Kept as a separate named
/// constant rather than reusing [`UT_NEW_TIME`] so that no call site can read
/// a clock change in the wrong direction by accident.
pub const UT_DARWIN_OLD_TIME: u16 = 3;
/// `NEW_TIME` on Darwin — the wall clock was set (value *after* the change).
///
/// The same numeric value Linux gives `OLD_TIME`; see [`UT_DARWIN_OLD_TIME`].
pub const UT_DARWIN_NEW_TIME: u16 = 4;
/// `SIGNATURE` — the file's own version stamp, which Linux has not got.
///
/// **Darwin only.** It is the first record of every `utmpx`, it carries the
/// literal string `utmpx-1.00` in `ut_user`, and every numeric field including
/// the timestamp is zero. It is not an event: it records nothing that happened
/// and belongs on no timeline.
pub const UT_DARWIN_SIGNATURE: u16 = 10;
/// `SHUTDOWN_TIME` — the system was brought down. **Darwin only.**
///
/// Darwin's equivalent of the Linux convention of a `RUN_LVL` record entering
/// level 0 or 6, and the record that brackets the sessions a shutdown ended.
///
/// **Corroborated on disk** since the Apple System Log reader landed: the
/// stores in `/var/log/asl` carry the same records as text, and each shutdown
/// reads `SHUTDOWN_TIME: <seconds> <microseconds>` beside `ut_type = 11` —
/// macOS naming the value itself, four times over on the corpus image. This
/// value was previously taken from Apple's header alone.
pub const UT_DARWIN_SHUTDOWN_TIME: u16 = 11;

/// Which `ut_type` enumeration a record's type field is read against.
///
/// The two enumerations are not the same, and the difference is not confined to
/// a tail of extra values: **Darwin swaps `OLD_TIME` and `NEW_TIME` relative to
/// Linux.** A macOS clock-change record read against `utmp(5)` therefore
/// reports the wall clock as having moved in the opposite direction — a
/// timeline error with no visible symptom. Darwin also defines two values Linux
/// has not got, `SIGNATURE` and `SHUTDOWN_TIME`, and a Linux-only reading
/// rejects the first record of every macOS `utmpx` as out of range.
///
/// # Provenance
///
/// The Linux values are `utmp(5)` and glibc's `<bits/utmp.h>`, corroborated
/// against util-linux's own little- and big-endian `wtmp` test corpus.
///
/// The Darwin values are Apple's `<utmpx.h>`, whose lineage is NetBSD's — the
/// `utmpx(5)` man page shipped on macOS is NetBSD's file, copyright notice and
/// all. Two of them are **corroborated on disk**:
///
/// * `SIGNATURE` = 10, by the first record of the real
///   `/private/var/run/utmpx` in the corpus, which carries type 10 and the
///   version string `utmpx-1.00` — that record and nothing else;
/// * `SHUTDOWN_TIME` = 11, by the Apple System Log stores in `/var/log/asl`,
///   which carry the same login-accounting records as text: each shutdown
///   reads `SHUTDOWN_TIME: <seconds> <microseconds>` beside `ut_type = 11`.
///   Four of them on the corpus image, and the same stores write
///   `USER_PROCESS`/`DEAD_PROCESS` beside 7 and 8.
///
/// The `OLD_TIME`/`NEW_TIME` swap is still taken from the header: the corpus
/// holds no macOS clock-change record, and that is recorded here rather than
/// left implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDialect {
    /// The Linux enumeration, `utmp(5)`: glibc and musl both write it.
    Linux,
    /// The Darwin enumeration, Apple's `<utmpx.h>`.
    Darwin,
}

impl TypeDialect {
    /// Stable label recorded alongside the decoded type, so an examiner can see
    /// which enumeration produced the name in front of them.
    pub fn as_str(self) -> &'static str {
        match self {
            TypeDialect::Linux => "linux-utmp",
            TypeDialect::Darwin => "darwin-utmpx",
        }
    }

    /// True when `ut_type` is a value a real login-accounting record of this
    /// dialect carries.
    ///
    /// `EMPTY` is excluded in both: a wholly-zero record is caught earlier as
    /// padding, so a record with content but a zero type is evidence of a
    /// mis-detected layout. `ACCOUNTING` is excluded in both: it is reserved by
    /// the standard and written by no shipping init or login program, so seeing
    /// it is evidence of a wrong layout rather than of a rare record. The two
    /// Darwin-only values are accepted **only** under the Darwin dialect, so a
    /// glibc file carrying type 10 is still reported as anomalous.
    pub fn is_plausible_type(self, ut_type: u16) -> bool {
        if (UT_RUN_LVL..=UT_DEAD_PROCESS).contains(&ut_type) {
            return true;
        }
        match self {
            TypeDialect::Linux => false,
            TypeDialect::Darwin => {
                ut_type == UT_DARWIN_SIGNATURE || ut_type == UT_DARWIN_SHUTDOWN_TIME
            }
        }
    }

    /// True when a record of this type carries no timestamp at all, so a zero
    /// seconds field is the format's own convention and not an anomaly.
    ///
    /// Only Darwin's `SIGNATURE` qualifies. Every other record in both dialects
    /// is written by something that just happened and is timestamped; treating
    /// a zero there as normal would let a fabricated or wiped record pass the
    /// sanity filter.
    pub fn records_no_time(self, ut_type: u16) -> bool {
        matches!(self, TypeDialect::Darwin) && ut_type == UT_DARWIN_SIGNATURE
    }
}

/// Symbolic name of a `ut_type` value under a given dialect, for display and
/// for `full_details`.
///
/// Returns `"UNKNOWN"` for anything outside that dialect's enumeration; the raw
/// numeric value is always carried alongside so an examiner is never shown a
/// name that was invented for an out-of-range value. The dialect is required
/// rather than defaulted because three and four mean opposite things in the two
/// enumerations — see [`TypeDialect`].
pub fn ut_type_name(dialect: TypeDialect, ut_type: u16) -> &'static str {
    match dialect {
        TypeDialect::Linux => match ut_type {
            UT_EMPTY => "EMPTY",
            UT_RUN_LVL => "RUN_LVL",
            UT_BOOT_TIME => "BOOT_TIME",
            UT_NEW_TIME => "NEW_TIME",
            UT_OLD_TIME => "OLD_TIME",
            UT_INIT_PROCESS => "INIT_PROCESS",
            UT_LOGIN_PROCESS => "LOGIN_PROCESS",
            UT_USER_PROCESS => "USER_PROCESS",
            UT_DEAD_PROCESS => "DEAD_PROCESS",
            UT_ACCOUNTING => "ACCOUNTING",
            _ => "UNKNOWN",
        },
        TypeDialect::Darwin => match ut_type {
            UT_EMPTY => "EMPTY",
            UT_RUN_LVL => "RUN_LVL",
            UT_BOOT_TIME => "BOOT_TIME",
            UT_DARWIN_OLD_TIME => "OLD_TIME",
            UT_DARWIN_NEW_TIME => "NEW_TIME",
            UT_INIT_PROCESS => "INIT_PROCESS",
            UT_LOGIN_PROCESS => "LOGIN_PROCESS",
            UT_USER_PROCESS => "USER_PROCESS",
            UT_DEAD_PROCESS => "DEAD_PROCESS",
            UT_ACCOUNTING => "ACCOUNTING",
            UT_DARWIN_SIGNATURE => "SIGNATURE",
            UT_DARWIN_SHUTDOWN_TIME => "SHUTDOWN_TIME",
            _ => "UNKNOWN",
        },
    }
}

// --- plausibility window -----------------------------------------------------

/// Earliest timestamp accepted as a real login time: 1980-01-01T00:00:00Z.
///
/// Records written by a machine whose clock was never set land at or near the
/// epoch; treating those as real dates would put fabricated 1970 rows on the
/// timeline.
pub const MIN_PLAUSIBLE_UNIX: i64 = 315_532_800;

/// Latest timestamp accepted as a real login time: 2106-02-07T06:28:15Z, the
/// ceiling of an *unsigned* 32-bit seconds count.
///
/// `ut_tv.tv_sec` is a 32-bit field. Reading it as unsigned (rather than signed)
/// means a system still running past 2038 is read as 2038..2106 rather than as
/// a negative date in 1901. That is a deliberate, documented choice: it cannot
/// misdate any evidence written before 2038, and it keeps post-2038 evidence
/// readable.
pub const MAX_PLAUSIBLE_UNIX: i64 = 4_294_967_295;

/// Convert a raw seconds field to a timestamp we are willing to put on a
/// timeline, or `None` when it is outside the plausible window.
///
/// `None` means "this record carries no usable time", which callers must render
/// differently from "this record has no time field" — never as 1970.
pub fn plausible_unix(raw: u64) -> Option<i64> {
    let secs = i64::try_from(raw).ok()?;
    if (MIN_PLAUSIBLE_UNIX..=MAX_PLAUSIBLE_UNIX).contains(&secs) {
        Some(secs)
    } else {
        None
    }
}

// --- byte order --------------------------------------------------------------

/// Byte order of the machine that wrote the file.
///
/// Little-endian covers x86/x86-64/ARM/RISC-V; big-endian covers s390x and
/// older MIPS/PowerPC/SPARC. Guessing wrong turns a 2013 login into a date in
/// the far future, so the order is detected from the data (see [`detect`]) and
/// never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Least significant byte first.
    Le,
    /// Most significant byte first.
    Be,
}

impl Endian {
    /// Stable label recorded on every emitted artifact, so an examiner can see
    /// which interpretation produced the values in front of them.
    pub fn as_str(self) -> &'static str {
        match self {
            Endian::Le => "little-endian",
            Endian::Be => "big-endian",
        }
    }

    fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Endian::Le => u16::from_le_bytes(bytes),
            Endian::Be => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Endian::Le => u32::from_le_bytes(bytes),
            Endian::Be => u32::from_be_bytes(bytes),
        }
    }

    fn u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            Endian::Le => u64::from_le_bytes(bytes),
            Endian::Be => u64::from_be_bytes(bytes),
        }
    }
}

/// Copy `N` bytes out of `rec` at `off`, or `None` if that would run past the
/// end. Every field read in this module goes through here: an offset table and
/// a short buffer must produce a refusal, not a panic and not a read of
/// adjacent record bytes.
fn take<const N: usize>(rec: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    rec.get(off..end)?.try_into().ok()
}

// --- struct utmp layouts -----------------------------------------------------

/// Where each `struct utmp` member sits within one on-disk record.
///
/// The layout is data, not code, because the same file format is written by
/// more than one C library with different member widths and padding. A layout
/// that is not in [`KNOWN_UTMP_LAYOUTS`] is refused outright rather than parsed
/// at a nearby stride — a stride that is wrong by even four bytes yields
/// records that look superficially sane and are entirely fictional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtmpLayout {
    /// Stable identifier recorded on every artifact this layout produced.
    pub name: &'static str,
    /// Which `ut_type` enumeration this layout's type field is read against.
    /// Not derivable from the offsets: three and four mean opposite things in
    /// the two enumerations, so the dialect travels with the layout.
    pub type_dialect: TypeDialect,
    /// Bytes per record; also the file's required size granularity.
    pub record_size: usize,
    /// Offset of `ut_type` (16-bit; the following 2 bytes are alignment pad).
    pub ut_type: usize,
    /// Offset of `ut_pid` (32-bit).
    pub ut_pid: usize,
    /// Offset and length of `ut_line`, the terminal with no `/dev/` prefix.
    pub ut_line: (usize, usize),
    /// Offset and length of `ut_id`, the inittab / tty suffix.
    pub ut_id: (usize, usize),
    /// True where `ut_id` holds opaque bytes rather than a NUL-terminated
    /// string.
    ///
    /// Darwin's does: the `console` record in the corpus carries
    /// `2f 00 01 01`. Decoded as text that is the single character `/`, and the
    /// bytes after the NUL make the field fail the text-cleanliness check —
    /// which would flag the one login record an examiner most wants as
    /// anomalous, for a field the format does not use as text. Where this is
    /// set, a non-textual `ut_id` is rendered as hex instead (see
    /// [`decode_utmp`]) and its cleanliness is not a sanity signal.
    pub ut_id_opaque: bool,
    /// Offset and length of `ut_user`.
    pub ut_user: (usize, usize),
    /// Offset and length of `ut_host` (remote host, or kernel release on
    /// `BOOT_TIME`/`RUN_LVL`).
    pub ut_host: (usize, usize),
    /// Offset of `ut_session` on a little-endian build.
    pub ut_session_le: usize,
    /// Offset of `ut_session` on a big-endian build. musl orders `ut_session`
    /// and its padding word by byte order, so the two differ there.
    pub ut_session_be: usize,
    /// Offset and width in bytes of `ut_tv.tv_sec`.
    pub tv_sec: (usize, usize),
    /// Offset and width in bytes of the `ut_tv.tv_usec` slot. Where the slot is
    /// 8 bytes the *field* may be 4 (32-bit `suseconds_t` plus padding), so the
    /// decoder probes both widths and validates the result (see
    /// [`UtmpLayout::read_usec`]).
    pub tv_usec: (usize, usize),
    /// Offset of `ut_addr_v6`, 16 raw bytes — or `None` where the layout has
    /// no such field.
    ///
    /// Darwin's `utmpx` has none: what sits in that part of the record is
    /// `ut_pad[16]`, sixty-four bytes of zeroes. Reading them as an address
    /// would put an IP on a login that never came from one — and on the
    /// commonest case, an all-zero pad, `decode_addr` would return `None` and
    /// the mistake would be invisible until the one record whose pad was not
    /// zero produced a confident, fictional remote host.
    pub ut_addr: Option<usize>,
    /// Offset and length of the zero-filled reserved trailer. A non-zero
    /// trailer is one of the strongest signals that a candidate layout is
    /// wrong.
    pub reserved: (usize, usize),
}

/// glibc `struct utmp` — 384 bytes, the layout of essentially every Linux
/// `utmp`/`wtmp`/`btmp` in the field.
///
/// glibc deliberately fixes `ut_session` and both `ut_tv` members at 32 bits so
/// that 32-bit and 64-bit builds agree byte for byte; there is therefore no
/// separate "32-bit glibc" layout to detect. Offsets below were verified
/// against util-linux's own little- and big-endian `wtmp` test corpus.
pub const GLIBC_UTMP_384: UtmpLayout = UtmpLayout {
    name: "glibc-utmp-384",
    type_dialect: TypeDialect::Linux,
    record_size: 384,
    ut_type: 0,
    ut_pid: 4,
    ut_line: (8, 32),
    ut_id: (40, 4),
    ut_id_opaque: false,
    ut_user: (44, 32),
    ut_host: (76, 256),
    ut_session_le: 336,
    ut_session_be: 336,
    tv_sec: (340, 4),
    tv_usec: (344, 4),
    ut_addr: Some(348),
    reserved: (364, 20),
};

/// musl `struct utmpx` — 400 bytes.
///
/// musl keeps `ut_tv` as a real `struct timeval`, so `tv_sec` is 64-bit and the
/// whole tail shifts by 16 bytes relative to glibc; it also swaps `ut_session`
/// with its padding word by byte order. A musl-written file parsed with the
/// glibc offsets reads its login times out of `ut_addr_v6`, which is why the
/// stride and the offsets are detected together rather than assumed.
pub const MUSL_UTMPX_400: UtmpLayout = UtmpLayout {
    name: "musl-utmpx-400",
    type_dialect: TypeDialect::Linux,
    record_size: 400,
    ut_type: 0,
    ut_pid: 4,
    ut_line: (8, 32),
    ut_id: (40, 4),
    ut_id_opaque: false,
    ut_user: (44, 32),
    ut_host: (76, 256),
    ut_session_le: 336,
    ut_session_be: 340,
    tv_sec: (344, 8),
    tv_usec: (352, 8),
    ut_addr: Some(360),
    reserved: (376, 20),
};

/// Darwin `struct utmpx` — 628 bytes, and the only macOS login record there is.
///
/// A different record from either Linux layout, not a variant of them: the
/// strings come **first** and are far longer (`ut_user` and `ut_host` are 256
/// bytes each against glibc's 32 and 256), `ut_type` sits at 296 rather than at
/// 0, and there is no `ut_addr_v6`, no `ut_session` and no `ut_exit`. Parsed at
/// glibc's offsets a Darwin record reads its type out of the middle of a
/// username.
///
/// # Where these offsets come from
///
/// Derived from a real `/private/var/run/utmpx` — the Magnet 2021 macOS image,
/// 2,512 bytes, which is **exactly four** 628-byte records — and every one of
/// them corroborated by something in the file itself rather than assumed:
///
/// * the record size divides the file exactly, and `308 + 256 + 64 = 628`
///   accounts for every byte, so there is no slack for a different tail;
/// * the first record is `SIGNATURE` carrying the literal string
///   `utmpx-1.00` in `ut_user`, which is the format naming its own version —
///   the strongest self-identification any of these three layouts has;
/// * `tv_sec` is a **32-bit** `time_t` at 300, found by scanning the record for
///   any 4- or 8-byte value in a plausible range and taking the one that agreed
///   with the file's own modification time. The 64-bit reading at that offset
///   gives 1808401892601184, and a 64-bit field at the 8-aligned 304 would push
///   `ut_host` past the end of the record;
/// * the four records then read as a coherent session: boot at 20:04:48 with
///   `ut_pid` 1, a `console` login for `eliflatt` at 20:07:07, and `ttys000`
///   for the same user at 20:08:26 — a GUI login followed by a terminal, in
///   that order.
///
/// `ut_id` is **not** a string here. On the `console` record it is
/// `2f 00 01 01`, so it is read as bytes and rendered only when it is
/// printable; treating it as text would put a control character in a record
/// that is quoted.
///
/// # What is deliberately absent
///
/// `ut_addr` is `None`, `ut_session_*` point at the pad, and `ut_exit` does not
/// exist. Darwin records no remote address in `utmpx`: a login over SSH is
/// attributed by `ut_host`, and where that is empty the honest answer is that
/// the file does not say.
pub const DARWIN_UTMPX_628: UtmpLayout = UtmpLayout {
    name: "darwin-utmpx-628",
    type_dialect: TypeDialect::Darwin,
    record_size: 628,
    ut_type: 296,
    ut_pid: 292,
    ut_line: (260, 32),
    ut_id: (256, 4),
    ut_id_opaque: true,
    ut_user: (0, 256),
    ut_host: (308, 256),
    // No `ut_session` in this struct. Both point into `ut_pad`, which is
    // zero, so the decoded session is 0 — which for Darwin is the truth: the
    // field is not recorded.
    ut_session_le: 564,
    ut_session_be: 564,
    tv_sec: (300, 4),
    tv_usec: (304, 4),
    ut_addr: None,
    // `ut_pad[16]`: sixty-four bytes the format requires to be zero, which
    // makes it the same layout check the other two get from their reserved
    // trailers.
    reserved: (564, 64),
};

/// Every `struct utmp` layout this parser can positively identify. A file whose
/// size is not a whole number of records of one of these is refused: see
/// [`DetectFailure::NotAWholeNumberOfRecords`].
pub const KNOWN_UTMP_LAYOUTS: [&UtmpLayout; 3] =
    [&GLIBC_UTMP_384, &MUSL_UTMPX_400, &DARWIN_UTMPX_628];

impl UtmpLayout {
    /// Read the microseconds field, tolerating the two widths a
    /// `suseconds_t`-sized slot can hold.
    ///
    /// Returns `None` when neither reading yields a legal microsecond value;
    /// callers treat that as a sanity failure rather than clamping, because a
    /// microsecond field that cannot be read at all usually means the stride or
    /// the byte order is wrong.
    fn read_usec(&self, rec: &[u8], endian: Endian) -> Option<u32> {
        let (off, width) = self.tv_usec;
        let wide = if width >= 8 {
            take::<8>(rec, off).map(|b| endian.u64(b))
        } else {
            None
        };
        if let Some(v) = wide {
            if v <= 999_999 {
                return u32::try_from(v).ok();
            }
        }
        // A 4-byte `suseconds_t` inside an 8-byte slot occupies the first word
        // and is followed by padding, in either byte order.
        let narrow = take::<4>(rec, off).map(|b| endian.u32(b))?;
        if narrow <= 999_999 {
            Some(narrow)
        } else {
            None
        }
    }
}

// --- decoded records ---------------------------------------------------------

/// A text member of a record, plus whether it was well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextField {
    /// Printable prefix up to the first NUL or first non-printable byte. Never
    /// contains control characters, so it is safe to place in JSON and in a UI.
    pub value: String,
    /// True when the whole field is printable ASCII followed only by NULs —
    /// what a C `strncpy` into a zeroed struct produces. False means the bytes
    /// at this offset do not look like the field the layout claims is here.
    pub clean: bool,
}

fn decode_text(rec: &[u8], field: (usize, usize)) -> Option<TextField> {
    let (off, len) = field;
    let end = off.checked_add(len)?;
    let bytes = rec.get(off..end)?;
    let nul = bytes.iter().position(|&b| b == 0);
    let head = match nul {
        Some(i) => &bytes[..i],
        None => bytes,
    };
    let tail = match nul {
        Some(i) => &bytes[i..],
        None => &bytes[bytes.len()..],
    };
    let printable = head.iter().all(|&b| (0x20..=0x7e).contains(&b));
    let tail_clean = tail.iter().all(|&b| b == 0);
    let value: String = head
        .iter()
        .copied()
        .take_while(|&b| (0x20..=0x7e).contains(&b))
        .map(char::from)
        .collect();
    Some(TextField {
        value,
        clean: printable && tail_clean,
    })
}

/// Render a fixed-width byte field as `0x` followed by lower-case hex, for a
/// field the format does not hold text in.
///
/// Trailing NULs are kept rather than trimmed: the field's width is part of
/// what the layout asserts, and a rendering that dropped them would make two
/// different four-byte ids look alike.
fn hex_field(rec: &[u8], field: (usize, usize)) -> Option<String> {
    let (off, len) = field;
    let end = off.checked_add(len)?;
    let bytes = rec.get(off..end)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    Some(out)
}

/// Decode `ut_addr_v6` into an IP address.
///
/// The 16 bytes are stored in **network** byte order whatever the host's
/// endianness — verified against util-linux's matched little- and big-endian
/// `wtmp` fixtures, in which these bytes are byte-for-byte identical. Swapping
/// them with the record's byte order would silently rewrite an attacker's
/// source address.
///
/// * all-zero: a local login with no remote peer — returns `None` so no `ip`
///   field is emitted, rather than `0.0.0.0`.
/// * only the first word set: IPv4, taken as `a.b.c.d` from the raw bytes.
/// * otherwise: a full IPv6 address.
pub fn decode_addr(raw: [u8; 16]) -> Option<IpAddr> {
    if raw.iter().all(|&b| b == 0) {
        return None;
    }
    if raw[4..].iter().all(|&b| b == 0) {
        return Some(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])));
    }
    Some(IpAddr::V6(Ipv6Addr::from(raw)))
}

/// A structural reason a record could not be decoded at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecordReject {
    /// The buffer ends before the record does. Parsing stops here; the
    /// remaining bytes are reported as a trailing partial record rather than
    /// zero-filled into a fabricated entry.
    #[error("record extends past the end of the available bytes")]
    Truncated,
    /// Every byte of the record is zero: legitimate `EMPTY` padding, skipped
    /// without counting against the file's sanity score.
    #[error("record is entirely zero (EMPTY padding)")]
    Empty,
    /// A layout offset does not fit inside its own record size. Only reachable
    /// via a malformed layout table, and refused rather than silently ignored.
    #[error("layout offset lies outside the record")]
    BadLayout,
}

/// A field-level reason a record fails the utmp sanity filter.
///
/// During detection a fault means "this candidate layout is probably wrong".
/// After detection a fault means "this individual record is anomalous" — the
/// record is still emitted, flagged, because a corrupt or hand-edited record in
/// the middle of a `wtmp` is itself evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SanityFault {
    /// `ut_type` is outside the range real records use.
    #[error("ut_type {0} is not a login-accounting record type (expected 1..=8)")]
    UtType(u16),
    /// A text member is not printable-ASCII-then-NUL.
    #[error("{0} is not NUL-terminated printable ASCII")]
    Text(&'static str),
    /// `ut_tv.tv_sec` is outside the plausible window.
    #[error("timestamp {0} is outside the plausible 1980..2106 window")]
    Time(u64),
    /// `ut_tv.tv_usec` is not a legal microsecond count.
    #[error("tv_usec is not in 0..=999999")]
    Usec,
    /// The reserved trailer carries data.
    #[error("the reserved trailer is not zero-filled")]
    Reserved,
    /// `ut_pid` is negative.
    #[error("ut_pid {0} is negative")]
    Pid(i32),
}

impl SanityFault {
    /// Stable machine-readable tag stored on flagged artifacts.
    pub fn tag(self) -> &'static str {
        match self {
            SanityFault::UtType(_) => "ut_type_out_of_range",
            SanityFault::Text(_) => "non_printable_text_field",
            SanityFault::Time(_) => "implausible_timestamp",
            SanityFault::Usec => "tv_usec_out_of_range",
            SanityFault::Reserved => "reserved_bytes_not_zero",
            SanityFault::Pid(_) => "negative_pid",
        }
    }
}

/// One decoded `struct utmp` record.
///
/// Field names mirror utmp(5) so an examiner can line the output up against
/// `last -aiFw` / `lastb -aiF` output field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtmpRecord {
    /// Zero-based index of this record within its file — the only handle an
    /// examiner has on a record's physical position.
    pub index: usize,
    /// Which enumeration `ut_type` is to be read against. Carried on the
    /// record rather than looked up later, because a type value on its own
    /// does not say which of the two dialects wrote it.
    pub dialect: TypeDialect,
    /// Raw `ut_type` value.
    pub ut_type: u16,
    /// PID of the login process.
    pub pid: i32,
    /// Terminal, without the `/dev/` prefix (`pts/1`, `tty1`, `:0`, `~`).
    pub line: String,
    /// inittab id / terminal suffix. On a layout whose `ut_id` is opaque bytes
    /// this is the hex rendering when the field is not text; see
    /// [`UtmpRecord::id_is_hex`].
    pub id: String,
    /// True when [`UtmpRecord::id`] is a hex rendering of opaque bytes rather
    /// than the text the file holds.
    ///
    /// It can be told apart from a textual id without this flag — a four-byte
    /// field yields at most four characters of text, and the hex form of four
    /// bytes is always the ten characters `0x` plus eight digits — but a
    /// consumer should not have to count characters to know what it is
    /// quoting.
    pub id_is_hex: bool,
    /// Account name. Empty on a logout record.
    pub user: String,
    /// Remote host, or the kernel release on `BOOT_TIME`/`RUN_LVL`.
    pub host: String,
    /// Session id (`getsid`).
    pub session: i32,
    /// Record time in UTC Unix seconds, or `None` when the stored value is not
    /// a plausible date. `None` must never be rendered as an epoch date.
    pub tv_sec: Option<i64>,
    /// The seconds field exactly as stored, kept even when implausible so the
    /// examiner can see what the file actually holds.
    pub tv_sec_raw: u64,
    /// Sub-second component, when legal.
    pub tv_usec: Option<u32>,
    /// Source address of the login, when the record carries one.
    pub addr: Option<IpAddr>,
    /// The first sanity problem found, if any.
    pub fault: Option<SanityFault>,
}

impl UtmpRecord {
    /// True when the record passed every field-sanity check.
    pub fn is_sane(&self) -> bool {
        self.fault.is_none()
    }
}

/// Decode the record at `off` under a specific layout and byte order.
///
/// Returns [`RecordReject::Empty`] for zero padding and
/// [`RecordReject::Truncated`] at a short tail; neither is an error in the file,
/// but both must be visible to the caller so a truncated file is never
/// completed with zeros.
pub fn decode_utmp(
    buf: &[u8],
    off: usize,
    index: usize,
    layout: &UtmpLayout,
    endian: Endian,
) -> Result<UtmpRecord, RecordReject> {
    let end = off
        .checked_add(layout.record_size)
        .ok_or(RecordReject::Truncated)?;
    let rec = buf.get(off..end).ok_or(RecordReject::Truncated)?;
    if rec.iter().all(|&b| b == 0) {
        return Err(RecordReject::Empty);
    }

    let dialect = layout.type_dialect;
    let ut_type = endian.u16(take::<2>(rec, layout.ut_type).ok_or(RecordReject::BadLayout)?);
    let pid = endian.u32(take::<4>(rec, layout.ut_pid).ok_or(RecordReject::BadLayout)?) as i32;
    let line = decode_text(rec, layout.ut_line).ok_or(RecordReject::BadLayout)?;
    let id_text = decode_text(rec, layout.ut_id).ok_or(RecordReject::BadLayout)?;
    // On an opaque-id layout a field that is not clean text is rendered as the
    // bytes it is, so the examiner sees `0x2f000101` rather than `/`.
    let id_is_hex = layout.ut_id_opaque && !id_text.clean;
    let id = if id_is_hex {
        hex_field(rec, layout.ut_id).ok_or(RecordReject::BadLayout)?
    } else {
        id_text.value.clone()
    };
    let user = decode_text(rec, layout.ut_user).ok_or(RecordReject::BadLayout)?;
    let host = decode_text(rec, layout.ut_host).ok_or(RecordReject::BadLayout)?;
    let session_off = match endian {
        Endian::Le => layout.ut_session_le,
        Endian::Be => layout.ut_session_be,
    };
    let session = endian.u32(take::<4>(rec, session_off).ok_or(RecordReject::BadLayout)?) as i32;
    let (sec_off, sec_width) = layout.tv_sec;
    let tv_sec_raw = if sec_width >= 8 {
        endian.u64(take::<8>(rec, sec_off).ok_or(RecordReject::BadLayout)?)
    } else {
        u64::from(endian.u32(take::<4>(rec, sec_off).ok_or(RecordReject::BadLayout)?))
    };
    let tv_usec = layout.read_usec(rec, endian);
    let addr = match layout.ut_addr {
        Some(off) => decode_addr(take::<16>(rec, off).ok_or(RecordReject::BadLayout)?),
        // No field, so no address. Not "the address was zero": this layout
        // does not record one at all.
        None => None,
    };
    let (res_off, res_len) = layout.reserved;
    let res_end = res_off
        .checked_add(res_len)
        .ok_or(RecordReject::BadLayout)?;
    let reserved_zero = rec
        .get(res_off..res_end)
        .ok_or(RecordReject::BadLayout)?
        .iter()
        .all(|&b| b == 0);

    let tv_sec = plausible_unix(tv_sec_raw);

    // Order matters only for which fault is reported first; every check runs
    // against the same record, and any one failing marks it anomalous.
    let fault = if !dialect.is_plausible_type(ut_type) {
        Some(SanityFault::UtType(ut_type))
    } else if pid < 0 {
        Some(SanityFault::Pid(pid))
    } else if !line.clean {
        Some(SanityFault::Text("ut_line"))
    } else if !id_text.clean && !layout.ut_id_opaque {
        Some(SanityFault::Text("ut_id"))
    } else if !user.clean {
        Some(SanityFault::Text("ut_user"))
    } else if !host.clean {
        Some(SanityFault::Text("ut_host"))
    } else if !reserved_zero {
        Some(SanityFault::Reserved)
    } else if tv_sec.is_none() && !dialect.records_no_time(ut_type) {
        Some(SanityFault::Time(tv_sec_raw))
    } else if tv_usec.is_none() {
        Some(SanityFault::Usec)
    } else {
        None
    };

    Ok(UtmpRecord {
        index,
        dialect,
        ut_type,
        pid,
        line: line.value,
        id,
        id_is_hex,
        user: user.value,
        host: host.value,
        session,
        tv_sec,
        tv_sec_raw,
        tv_usec,
        addr,
        fault,
    })
}

// --- struct lastlog ----------------------------------------------------------

/// Where each `struct lastlog` member sits within one record.
///
/// `lastlog` has no type field and no username: the record's *index* is the
/// UID. Reading it at the wrong stride therefore attributes one account's last
/// login to a different account, with nothing in the output to reveal the swap
/// — which is why the stride must divide the file size exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastlogLayout {
    /// Stable identifier recorded on every artifact this layout produced.
    pub name: &'static str,
    /// Bytes per record; also the UID stride.
    pub record_size: usize,
    /// Offset of `ll_time` (32-bit Unix seconds).
    pub ll_time: usize,
    /// Offset and length of `ll_line`.
    pub ll_line: (usize, usize),
    /// Offset and length of `ll_host`.
    pub ll_host: (usize, usize),
}

/// Modern glibc `struct lastlog` — 292 bytes (`int32` + `char[32]` +
/// `char[256]`), identical on 32- and 64-bit builds.
pub const LASTLOG_292: LastlogLayout = LastlogLayout {
    name: "glibc-lastlog-292",
    record_size: 292,
    ll_time: 0,
    ll_line: (4, 32),
    ll_host: (36, 256),
};

/// Legacy Linux 2.2-era `struct lastlog` — 28 bytes (`int32` + `char[8]` +
/// `char[16]`). Rare, but a file written with it is a whole multiple of 28 and
/// not of 292, so accepting only 292 would silently refuse real evidence.
pub const LASTLOG_28: LastlogLayout = LastlogLayout {
    name: "legacy-lastlog-28",
    record_size: 28,
    ll_time: 0,
    ll_line: (4, 8),
    ll_host: (12, 16),
};

/// Every `struct lastlog` layout this parser can identify, most-likely first.
pub const KNOWN_LASTLOG_LAYOUTS: [&LastlogLayout; 2] = [&LASTLOG_292, &LASTLOG_28];

/// One decoded `struct lastlog` record, tagged with the UID it is indexed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastlogRecord {
    /// The UID this record describes — recovered from the record's position in
    /// the file, because the record itself does not store it.
    pub uid: u32,
    /// Last login time in UTC Unix seconds, or `None` when the stored value is
    /// not plausible. A zero record means "never logged in" and is not decoded
    /// at all.
    pub ll_time: Option<i64>,
    /// The seconds field exactly as stored.
    pub ll_time_raw: u32,
    /// Terminal of the last login.
    pub line: String,
    /// Remote host of the last login, as text.
    pub host: String,
    /// The host field parsed as an IP literal, when it is one. `lastlog` stores
    /// no numeric address field, so this is `None` for named hosts rather than
    /// a resolved address.
    pub addr: Option<IpAddr>,
    /// The first sanity problem found, if any.
    pub fault: Option<SanityFault>,
}

/// Decode the `lastlog` record for `uid` out of `rec`.
///
/// `rec` must be exactly one record. Returns [`RecordReject::Empty`] for an
/// all-zero record: that UID has never logged in, and emitting a row for it
/// would invent an event.
pub fn decode_lastlog(
    rec: &[u8],
    uid: u32,
    layout: &LastlogLayout,
    endian: Endian,
) -> Result<LastlogRecord, RecordReject> {
    if rec.len() < layout.record_size {
        return Err(RecordReject::Truncated);
    }
    if rec[..layout.record_size].iter().all(|&b| b == 0) {
        return Err(RecordReject::Empty);
    }
    let ll_time_raw = endian.u32(take::<4>(rec, layout.ll_time).ok_or(RecordReject::BadLayout)?);
    let line = decode_text(rec, layout.ll_line).ok_or(RecordReject::BadLayout)?;
    let host = decode_text(rec, layout.ll_host).ok_or(RecordReject::BadLayout)?;
    let ll_time = plausible_unix(u64::from(ll_time_raw));
    let fault = if !line.clean {
        Some(SanityFault::Text("ll_line"))
    } else if !host.clean {
        Some(SanityFault::Text("ll_host"))
    } else if ll_time.is_none() {
        Some(SanityFault::Time(u64::from(ll_time_raw)))
    } else {
        None
    };
    let addr = host.value.parse::<IpAddr>().ok();
    Ok(LastlogRecord {
        uid,
        ll_time,
        ll_time_raw,
        line: line.value,
        host: host.value,
        addr,
        fault,
    })
}

// --- filename role hint ------------------------------------------------------

/// Which member of the family a file's name claims it is.
///
/// The three `struct utmp` files are byte-for-byte the same format; only the
/// name says whether its records are current sessions, historical sessions, or
/// **failed** attempts. Nothing in the content can tell them apart, so this hint
/// is load-bearing — and its absence is recorded on every artifact rather than
/// papered over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleHint {
    /// `/var/run/utmp` — sessions open at acquisition time.
    Utmp,
    /// `/var/log/wtmp` — login/logout history.
    Wtmp,
    /// `/var/log/btmp` — failed login attempts.
    Btmp,
    /// `/var/log/lastlog` — per-UID last login.
    Lastlog,
    /// The name says nothing about login accounting.
    Unknown,
}

/// The role this parser will actually apply to a `struct utmp` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtmpRole {
    /// Current sessions.
    Utmp,
    /// Session history. Also the conservative default for a structurally valid
    /// file whose name is unknown: history semantics state only what the
    /// records state, whereas defaulting to `Btmp` would invent failed logins.
    Wtmp,
    /// Failed login attempts.
    Btmp,
}

impl UtmpRole {
    /// Stable label emitted as `source_file`.
    pub fn as_str(self) -> &'static str {
        match self {
            UtmpRole::Utmp => "utmp",
            UtmpRole::Wtmp => "wtmp",
            UtmpRole::Btmp => "btmp",
        }
    }
}

/// Classify a file by name (and full path) alone.
///
/// Matching is on the lower-cased basename and tolerates rotation suffixes
/// (`wtmp.1`, `btmp-20260101`, `wtmp.2` handed over by the gz/xz expanders).
/// `btmp` is tested first because a name mentioning several of these must not
/// be allowed to downgrade a failed-login log into a session log.
pub fn role_hint(name: &str, path: &str) -> RoleHint {
    let basename = |s: &str| s.rsplit('/').next().unwrap_or(s).to_ascii_lowercase();
    let candidates = [basename(name), basename(path)];
    for c in &candidates {
        if c.contains("lastlog") {
            return RoleHint::Lastlog;
        }
    }
    for c in &candidates {
        if c.contains("btmp") {
            return RoleHint::Btmp;
        }
    }
    for c in &candidates {
        if c.contains("wtmp") {
            return RoleHint::Wtmp;
        }
    }
    for c in &candidates {
        if c.contains("utmp") {
            return RoleHint::Utmp;
        }
    }
    RoleHint::Unknown
}

// --- detection ---------------------------------------------------------------

/// Records sampled from the head of a file when scoring a candidate layout.
const DETECT_SAMPLE_RECORDS: usize = 64;
/// Minimum share of non-empty sampled records that must pass the sanity filter
/// before a candidate layout is accepted.
const MIN_VALID_RATIO: f32 = 0.70;
/// Minimum number of sane records required, so that a one-record file cannot
/// score 1.0 by coincidence.
const MIN_VALID_RECORDS: usize = 2;
/// Stricter ratio demanded of a file whose size is *not* a whole number of
/// records, since a wrong stride is exactly what a size mismatch hints at.
const MIN_VALID_RATIO_PARTIAL: f32 = 0.90;
/// Minimum sane records demanded of a file with a trailing partial record.
const MIN_VALID_RECORDS_PARTIAL: usize = 4;

/// Why a file was not accepted as login accounting.
///
/// Every refusal names its reason. "We looked and this is not a utmp file" and
/// "this is named wtmp but we could not read it" are different statements, and
/// a file that our own caps or thresholds turned away must never be reported
/// the same way as a file that genuinely holds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DetectFailure {
    /// Zero bytes. For a file named `wtmp`/`btmp` this is itself notable: a
    /// zeroed login log is a classic anti-forensic artefact.
    #[error("file is empty")]
    Empty,
    /// Smaller than a single record of any known layout.
    #[error("file is smaller than one record of any known layout")]
    TooSmall,
    /// The size does not divide by any known record size, so any stride we
    /// chose would be a guess.
    #[error("file size is not a whole number of records of any known layout")]
    NotAWholeNumberOfRecords,
    /// The sampled window is entirely zero — the size is right but there is no
    /// evidence of what wrote it.
    #[error("every sampled record is zero-filled")]
    AllRecordsZero,
    /// The stride fits but the fields do not survive the sanity filter.
    #[error("sampled records do not pass the utmp field-sanity filter")]
    FailedSanity,
    /// No bytes could be read from the source.
    #[error("no content could be read from the source")]
    Unreadable,
}

impl DetectFailure {
    /// Stable machine-readable tag stored on the status artifact.
    pub fn tag(self) -> &'static str {
        match self {
            DetectFailure::Empty => "empty_file",
            DetectFailure::TooSmall => "smaller_than_one_record",
            DetectFailure::NotAWholeNumberOfRecords => "size_not_a_record_multiple",
            DetectFailure::AllRecordsZero => "all_sampled_records_zero",
            DetectFailure::FailedSanity => "failed_field_sanity",
            DetectFailure::Unreadable => "unreadable",
        }
    }
}

/// An accepted `struct utmp` file and the evidence for that decision.
#[derive(Debug, Clone, PartialEq)]
pub struct UtmpDetection {
    /// The layout whose offsets will be used.
    pub layout: &'static UtmpLayout,
    /// The byte order the fields will be read in.
    pub endian: Endian,
    /// Session / history / failed-attempt semantics.
    pub role: UtmpRole,
    /// False when the role came from the conservative default rather than from
    /// the file's name; carried onto every artifact.
    pub role_from_filename: bool,
    /// Non-empty records examined while scoring.
    pub sampled: usize,
    /// Sampled records that passed the sanity filter.
    pub valid: usize,
    /// Share of sampled records that passed.
    pub score: f32,
    /// Bytes of a final, incomplete record — non-zero only for a truncated
    /// file, and always surfaced as an incompleteness flag.
    pub trailing_partial_bytes: u64,
}

/// An accepted `lastlog` file and the evidence for that decision.
#[derive(Debug, Clone, PartialEq)]
pub struct LastlogDetection {
    /// The layout whose offsets will be used.
    pub layout: &'static LastlogLayout,
    /// The byte order `ll_time` will be read in.
    pub endian: Endian,
    /// Non-zero records examined while scoring.
    pub sampled: usize,
    /// Sampled records that passed the sanity filter.
    pub valid: usize,
    /// True when the detection window held no non-zero record, so the layout
    /// follows from the file's name and size alone. Recorded on the status
    /// artifact so the reader knows the stride was never confirmed against
    /// data.
    pub layout_unconfirmed: bool,
}

/// The outcome of looking at a file.
#[derive(Debug, Clone, PartialEq)]
pub enum Detected {
    /// A `utmp`/`wtmp`/`btmp` file.
    Utmp(UtmpDetection),
    /// A `lastlog` file.
    Lastlog(LastlogDetection),
    /// Not login accounting, with the reason it was turned away.
    NotRecognized(DetectFailure),
}

struct Probe {
    valid: usize,
    sampled: usize,
    score: f32,
    trailing_partial_bytes: u64,
}

/// Score one (layout, byte order) candidate over the head of the file.
///
/// `allow_partial` relaxes the "whole number of records" rule, and is only used
/// on a second pass when no exact-multiple candidate matched at all.
fn probe_utmp(
    buf: &[u8],
    declared_size: u64,
    layout: &UtmpLayout,
    endian: Endian,
    allow_partial: bool,
) -> Option<Probe> {
    let rs = layout.record_size as u64;
    if declared_size < rs {
        return None;
    }
    let remainder = declared_size % rs;
    if remainder != 0 && !allow_partial {
        return None;
    }
    let available = (buf.len() / layout.record_size).min(DETECT_SAMPLE_RECORDS);
    if available == 0 {
        return None;
    }
    let mut valid = 0usize;
    let mut considered = 0usize;
    for i in 0..available {
        let off = i.checked_mul(layout.record_size)?;
        match decode_utmp(buf, off, i, layout, endian) {
            Ok(rec) => {
                considered = considered.saturating_add(1);
                if rec.is_sane() {
                    valid = valid.saturating_add(1);
                }
            }
            // Zero padding says nothing either way about the layout.
            Err(RecordReject::Empty) => {}
            Err(_) => break,
        }
    }
    if considered == 0 {
        return None;
    }
    let score = valid as f32 / considered as f32;
    let (min_ratio, min_records) = if remainder == 0 {
        (MIN_VALID_RATIO, MIN_VALID_RECORDS)
    } else {
        (MIN_VALID_RATIO_PARTIAL, MIN_VALID_RECORDS_PARTIAL)
    };
    if valid < min_records || score < min_ratio {
        return None;
    }
    Some(Probe {
        valid,
        sampled: considered,
        score,
        trailing_partial_bytes: remainder,
    })
}

fn best_utmp_candidate(
    buf: &[u8],
    declared_size: u64,
    allow_partial: bool,
) -> Option<UtmpDetection> {
    let mut best: Option<(Probe, &'static UtmpLayout, Endian)> = None;
    for layout in KNOWN_UTMP_LAYOUTS {
        for endian in [Endian::Le, Endian::Be] {
            let Some(probe) = probe_utmp(buf, declared_size, layout, endian, allow_partial) else {
                continue;
            };
            let better = match &best {
                None => true,
                // Strictly greater, so the first candidate in the fixed
                // iteration order wins a tie and detection is deterministic.
                Some((cur, _, _)) => {
                    probe.score > cur.score || (probe.score == cur.score && probe.valid > cur.valid)
                }
            };
            if better {
                best = Some((probe, layout, endian));
            }
        }
    }
    best.map(|(probe, layout, endian)| UtmpDetection {
        layout,
        endian,
        // Overwritten by `detect` once the filename hint is applied.
        role: UtmpRole::Wtmp,
        role_from_filename: false,
        sampled: probe.sampled,
        valid: probe.valid,
        score: probe.score,
        trailing_partial_bytes: probe.trailing_partial_bytes,
    })
}

fn probe_lastlog(
    buf: &[u8],
    declared_size: u64,
    layout: &LastlogLayout,
    endian: Endian,
) -> Option<(usize, usize)> {
    let rs = layout.record_size as u64;
    if declared_size < rs || !declared_size.is_multiple_of(rs) {
        return None;
    }
    let available = (buf.len() / layout.record_size).min(DETECT_SAMPLE_RECORDS * 4);
    let mut valid = 0usize;
    let mut considered = 0usize;
    for i in 0..available {
        let off = i.checked_mul(layout.record_size)?;
        let end = off.checked_add(layout.record_size)?;
        let Some(rec) = buf.get(off..end) else { break };
        let uid = u32::try_from(i).unwrap_or(u32::MAX);
        match decode_lastlog(rec, uid, layout, endian) {
            Ok(r) => {
                considered = considered.saturating_add(1);
                if r.fault.is_none() {
                    valid = valid.saturating_add(1);
                }
            }
            Err(RecordReject::Empty) => {}
            Err(_) => break,
        }
    }
    Some((valid, considered))
}

/// Decide what a file is, from its content, its declared size, and the role its
/// name claims.
///
/// `buf` is the detection window read from the head of the file; `declared_size`
/// is the file's full size, which is what the "whole number of records" rule is
/// applied to.
///
/// `lastlog` is only ever considered when the *name* says `lastlog`. It has no
/// type field and no per-record structure to speak of, so a content-only
/// acceptance would claim any file that happens to divide by 292 — the
/// conservative rule costs nothing on real evidence, where the file is at
/// `/var/log/lastlog`.
pub fn detect(buf: &[u8], declared_size: u64, hint: RoleHint) -> Detected {
    if declared_size == 0 {
        return Detected::NotRecognized(DetectFailure::Empty);
    }
    if buf.is_empty() {
        return Detected::NotRecognized(DetectFailure::Unreadable);
    }

    if hint == RoleHint::Lastlog {
        let mut fallback: Option<LastlogDetection> = None;
        for layout in KNOWN_LASTLOG_LAYOUTS {
            for endian in [Endian::Le, Endian::Be] {
                let Some((valid, considered)) = probe_lastlog(buf, declared_size, layout, endian)
                else {
                    continue;
                };
                if considered > 0 && valid >= 1 && valid * 10 >= considered * 7 {
                    return Detected::Lastlog(LastlogDetection {
                        layout,
                        endian,
                        sampled: considered,
                        valid,
                        layout_unconfirmed: false,
                    });
                }
                if considered == 0 && fallback.is_none() && endian == Endian::Le {
                    // Size fits and the window is all zeros: a lastlog on which
                    // no early UID has ever logged in. Accept the stride from
                    // the name and size, and say so.
                    fallback = Some(LastlogDetection {
                        layout,
                        endian,
                        sampled: 0,
                        valid: 0,
                        layout_unconfirmed: true,
                    });
                }
            }
        }
        if let Some(d) = fallback {
            return Detected::Lastlog(d);
        }
    }

    if let Some(mut d) = best_utmp_candidate(buf, declared_size, false)
        .or_else(|| best_utmp_candidate(buf, declared_size, true))
    {
        let (role, from_name) = match hint {
            RoleHint::Btmp => (UtmpRole::Btmp, true),
            RoleHint::Wtmp => (UtmpRole::Wtmp, true),
            RoleHint::Utmp => (UtmpRole::Utmp, true),
            // A structurally valid file we cannot name is read as history. We
            // never promote an unnamed file to "failed logins": that would
            // manufacture an intrusion signal out of a filename we do not have.
            RoleHint::Lastlog | RoleHint::Unknown => (UtmpRole::Wtmp, false),
        };
        d.role = role;
        d.role_from_filename = from_name;
        return Detected::Utmp(d);
    }

    Detected::NotRecognized(classify_failure(buf, declared_size))
}

/// Work out the most informative reason nothing matched.
fn classify_failure(buf: &[u8], declared_size: u64) -> DetectFailure {
    let smallest = KNOWN_UTMP_LAYOUTS
        .iter()
        .map(|l| l.record_size as u64)
        .min()
        .unwrap_or(u64::MAX);
    if declared_size < smallest {
        return DetectFailure::TooSmall;
    }
    let size_fits = KNOWN_UTMP_LAYOUTS
        .iter()
        .any(|l| declared_size.is_multiple_of(l.record_size as u64));
    if !size_fits {
        return DetectFailure::NotAWholeNumberOfRecords;
    }
    if buf.iter().all(|&b| b == 0) {
        return DetectFailure::AllRecordsZero;
    }
    DetectFailure::FailedSanity
}
