//! Unit tests for the login-accounting parser: Linux `utmp`/`wtmp`/`btmp`/
//! `lastlog` and macOS `utmpx`.
//!
//! Fixtures are hand-built byte arrays so the suite is hermetic. The glibc
//! offsets pinned by [`a_hand_written_record_decodes_field_by_field_at_the_documented_offsets`]
//! were checked against util-linux's own little- and big-endian `wtmp` test
//! corpus, so a future edit to the layout table that moves a field will fail
//! here rather than silently re-attributing evidence.
//!
//! Failure paths are tested as hard as success paths: refusing a file, refusing
//! a timestamp and flagging a cap are the behaviours that keep the output
//! honest, and each has its own test.

use super::*;
use crate::record::{
    TypeDialect, DARWIN_UTMPX_628, UT_DARWIN_SHUTDOWN_TIME, UT_DARWIN_SIGNATURE, UT_USER_PROCESS,
};
use seance_core::data_source::DataSource;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn home(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
}

// --- fixture construction ----------------------------------------------------

/// One record's worth of field values, written out under any known layout and
/// byte order.
#[derive(Debug, Clone)]
struct Spec {
    ut_type: u16,
    pid: i32,
    line: String,
    id: String,
    user: String,
    host: String,
    session: i32,
    sec: u64,
    usec: u64,
    addr: [u8; 16],
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            ut_type: record::UT_USER_PROCESS,
            pid: 1000,
            line: "pts/0".into(),
            id: "ts/0".into(),
            user: "alice".into(),
            host: String::new(),
            session: 0,
            sec: 1_377_694_800,
            usec: 0,
            addr: [0u8; 16],
        }
    }
}

impl Spec {
    fn login(user: &str, line: &str, sec: u64) -> Spec {
        Spec {
            ut_type: record::UT_USER_PROCESS,
            user: user.into(),
            line: line.into(),
            sec,
            ..Spec::default()
        }
    }

    fn logout(line: &str, sec: u64) -> Spec {
        Spec {
            ut_type: record::UT_DEAD_PROCESS,
            user: String::new(),
            line: line.into(),
            sec,
            ..Spec::default()
        }
    }

    fn boot(sec: u64, kernel: &str) -> Spec {
        Spec {
            ut_type: record::UT_BOOT_TIME,
            user: "reboot".into(),
            line: "~".into(),
            host: kernel.into(),
            sec,
            ..Spec::default()
        }
    }

    fn shutdown(sec: u64) -> Spec {
        Spec {
            ut_type: record::UT_RUN_LVL,
            user: "shutdown".into(),
            line: "~".into(),
            sec,
            ..Spec::default()
        }
    }

    // A builder step on a test fixture, not a conversion: it consumes and
    // returns `Spec` so the fixtures read as one expression.
    #[allow(clippy::wrong_self_convention)]
    fn from_ipv4(mut self, octets: [u8; 4], host: &str) -> Spec {
        self.addr = [0u8; 16];
        self.addr[..4].copy_from_slice(&octets);
        self.host = host.into();
        self
    }

    fn build(&self, layout: &UtmpLayout, endian: Endian) -> Vec<u8> {
        let mut rec = vec![0u8; layout.record_size];
        put_u16(&mut rec, layout.ut_type, self.ut_type, endian);
        put_u32(&mut rec, layout.ut_pid, self.pid as u32, endian);
        put_text(&mut rec, layout.ut_line, &self.line);
        put_text(&mut rec, layout.ut_id, &self.id);
        put_text(&mut rec, layout.ut_user, &self.user);
        put_text(&mut rec, layout.ut_host, &self.host);
        let session_off = match endian {
            Endian::Le => layout.ut_session_le,
            Endian::Be => layout.ut_session_be,
        };
        put_u32(&mut rec, session_off, self.session as u32, endian);
        let (sec_off, sec_width) = layout.tv_sec;
        if sec_width >= 8 {
            put_u64(&mut rec, sec_off, self.sec, endian);
        } else {
            put_u32(&mut rec, sec_off, self.sec as u32, endian);
        }
        let (usec_off, usec_width) = layout.tv_usec;
        if usec_width >= 8 {
            put_u64(&mut rec, usec_off, self.usec, endian);
        } else {
            put_u32(&mut rec, usec_off, self.usec as u32, endian);
        }
        // A layout with no `ut_addr` has nowhere to put one, and a fixture
        // that wrote into the pad instead would be testing a field the format
        // does not have.
        if let Some(off) = layout.ut_addr {
            rec[off..off + 16].copy_from_slice(&self.addr);
        }
        rec
    }
}

fn put_u16(buf: &mut [u8], off: usize, value: u16, endian: Endian) {
    let bytes = match endian {
        Endian::Le => value.to_le_bytes(),
        Endian::Be => value.to_be_bytes(),
    };
    buf[off..off + 2].copy_from_slice(&bytes);
}

fn put_u32(buf: &mut [u8], off: usize, value: u32, endian: Endian) {
    let bytes = match endian {
        Endian::Le => value.to_le_bytes(),
        Endian::Be => value.to_be_bytes(),
    };
    buf[off..off + 4].copy_from_slice(&bytes);
}

fn put_u64(buf: &mut [u8], off: usize, value: u64, endian: Endian) {
    let bytes = match endian {
        Endian::Le => value.to_le_bytes(),
        Endian::Be => value.to_be_bytes(),
    };
    buf[off..off + 8].copy_from_slice(&bytes);
}

fn put_text(buf: &mut [u8], field: (usize, usize), value: &str) {
    let (off, len) = field;
    let bytes = value.as_bytes();
    let n = bytes.len().min(len.saturating_sub(1));
    buf[off..off + n].copy_from_slice(&bytes[..n]);
}

fn file_of(specs: &[Spec], layout: &UtmpLayout, endian: Endian) -> Vec<u8> {
    let mut out = Vec::new();
    for spec in specs {
        out.extend_from_slice(&spec.build(layout, endian));
    }
    out
}

fn glibc_file(specs: &[Spec]) -> Vec<u8> {
    file_of(specs, &GLIBC_UTMP_384, Endian::Le)
}

fn darwin_file(specs: &[Spec]) -> Vec<u8> {
    file_of(specs, &DARWIN_UTMPX_628, Endian::Le)
}

/// The `SIGNATURE` record that opens every macOS `utmpx`: the version string
/// in `ut_user` and every numeric field, timestamp included, left at zero —
/// which is what the real file in the corpus holds.
fn darwin_signature() -> Spec {
    Spec {
        ut_type: UT_DARWIN_SIGNATURE,
        pid: 0,
        line: String::new(),
        id: String::new(),
        user: "utmpx-1.00".into(),
        host: String::new(),
        sec: 0,
        usec: 0,
        ..Spec::default()
    }
}

/// Darwin's boot and shutdown records carry no pseudo-user and no `~`
/// terminal; the type field is all there is to go on.
fn darwin_event(ut_type: u16, pid: i32, sec: u64) -> Spec {
    Spec {
        ut_type,
        pid,
        line: String::new(),
        id: String::new(),
        user: String::new(),
        host: String::new(),
        sec,
        ..Spec::default()
    }
}

fn lastlog_bytes(time: u32, line: &str, host: &str) -> Vec<u8> {
    let mut rec = vec![0u8; LASTLOG_292.record_size];
    put_u32(&mut rec, LASTLOG_292.ll_time, time, Endian::Le);
    put_text(&mut rec, LASTLOG_292.ll_line, line);
    put_text(&mut rec, LASTLOG_292.ll_host, host);
    rec
}

// --- data sources ------------------------------------------------------------

#[derive(Debug)]
struct MockSource {
    data: Vec<u8>,
    /// Size this source claims, which may exceed what it can actually return.
    declared: u64,
}

impl MockSource {
    fn new(data: Vec<u8>) -> Self {
        let declared = data.len() as u64;
        MockSource { data, declared }
    }

    fn claiming(data: Vec<u8>, declared: u64) -> Self {
        MockSource { data, declared }
    }
}

impl DataSource for MockSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - offset);
        buf[..n].copy_from_slice(&self.data[offset..offset + n]);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.declared
    }
}

/// A sparse `lastlog`: gigabytes of holes with a handful of populated UIDs,
/// synthesised on read so the test never materialises the file.
#[derive(Debug)]
struct SparseLastlog {
    populated: HashMap<u32, Vec<u8>>,
    record_size: u64,
    declared: u64,
    largest_read: AtomicUsize,
}

impl DataSource for SparseLastlog {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.largest_read.fetch_max(buf.len(), Ordering::SeqCst);
        if offset >= self.declared {
            return Ok(0);
        }
        let n = ((self.declared - offset) as usize).min(buf.len());
        for byte in buf[..n].iter_mut() {
            *byte = 0;
        }
        for (uid, rec) in &self.populated {
            let start = u64::from(*uid) * self.record_size;
            let lo = start.max(offset);
            let hi = (start + rec.len() as u64).min(offset + n as u64);
            if lo < hi {
                let dst = (lo - offset) as usize;
                let src = (lo - start) as usize;
                let len = (hi - lo) as usize;
                buf[dst..dst + len].copy_from_slice(&rec[src..src + len]);
            }
        }
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.declared
    }
}

fn artifact_named(name: &str, source: Arc<dyn DataSource>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({"name": name, "path": format!("/var/log/{name}")}),
    )
}

fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let artifact = artifact_named(name, Arc::new(MockSource::new(bytes)));
    UtmpParser
        .process(&artifact)
        .expect("the parser never fails the pipeline on evidence content")
}

/// Run a Darwin `utmpx` through the production path from the path it lives at.
fn darwin_run(specs: &[Spec]) -> Vec<Artifact> {
    UtmpParser
        .process(&at_path(
            "utmpx",
            "/private/var/run/utmpx",
            darwin_file(specs),
        ))
        .expect("the parser never fails the pipeline on evidence content")
}

// --- output accessors --------------------------------------------------------

fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .map(|a| &a.metadata)
        .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
        .collect()
}

fn timeline(out: &[Artifact]) -> Vec<&Value> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .map(|a| &a.metadata)
        .collect()
}

fn status(out: &[Artifact]) -> &Value {
    of_type(out, "UtmpParseStatus")
        .first()
        .copied()
        .expect("every recognised or name-claimed file produces a status record")
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn num(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_i64())
}

// --- record decoding ---------------------------------------------------------

#[test]
fn a_hand_written_record_decodes_field_by_field_at_the_documented_offsets() {
    // Written with literal offsets rather than through the layout table, so a
    // mistake in the table cannot make this test agree with itself.
    let mut rec = vec![0u8; 384];
    rec[0..2].copy_from_slice(&7u16.to_le_bytes());
    rec[4..8].copy_from_slice(&20481i32.to_le_bytes());
    rec[8..13].copy_from_slice(b"pts/1");
    rec[40..44].copy_from_slice(b"ts/1");
    rec[44..49].copy_from_slice(b"alice");
    rec[76..80].copy_from_slice(b"work");
    rec[336..340].copy_from_slice(&4242i32.to_le_bytes());
    rec[340..344].copy_from_slice(&1_751_970_000u32.to_le_bytes());
    rec[344..348].copy_from_slice(&123_456u32.to_le_bytes());
    rec[348..352].copy_from_slice(&[10, 0, 4, 22]);

    let decoded = decode_utmp(&rec, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.ut_type, record::UT_USER_PROCESS);
    assert_eq!(decoded.pid, 20481);
    assert_eq!(decoded.line, "pts/1");
    assert_eq!(decoded.id, "ts/1");
    assert_eq!(decoded.user, "alice");
    assert_eq!(decoded.host, "work");
    assert_eq!(decoded.session, 4242);
    assert_eq!(decoded.tv_sec, Some(1_751_970_000));
    assert_eq!(decoded.tv_usec, Some(123_456));
    assert_eq!(
        decoded.addr.map(|a| a.to_string()).as_deref(),
        Some("10.0.4.22")
    );
    assert!(decoded.is_sane());
}

#[test]
fn a_big_endian_record_decodes_to_the_same_values_as_its_little_endian_twin() {
    let spec = Spec::login("bob", "tty1", 1_377_694_800).from_ipv4([198, 41, 0, 4], "dns-server");
    let le = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let be = spec.build(&GLIBC_UTMP_384, Endian::Be);
    assert_ne!(le, be, "the fixtures must genuinely differ on disk");

    let left = decode_utmp(&le, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("le decodes");
    let right = decode_utmp(&be, 0, 0, &GLIBC_UTMP_384, Endian::Be).expect("be decodes");
    assert_eq!(left, right);
    assert_eq!(
        left.addr.map(|a| a.to_string()).as_deref(),
        Some("198.41.0.4")
    );
}

#[test]
fn the_address_bytes_are_read_in_network_order_whatever_the_records_byte_order() {
    // util-linux's matched LE and BE wtmp fixtures store ut_addr_v6 with
    // identical bytes; swapping them with the record byte order would rewrite
    // an attacker's source address.
    let spec = Spec::login("bob", "tty1", 1_377_694_800).from_ipv4([203, 0, 113, 9], "");
    let le = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let be = spec.build(&GLIBC_UTMP_384, Endian::Be);
    let addr_off = GLIBC_UTMP_384.ut_addr.expect("glibc records an address");
    assert_eq!(&le[addr_off..addr_off + 16], &be[addr_off..addr_off + 16]);
    let decoded = decode_utmp(&be, 0, 0, &GLIBC_UTMP_384, Endian::Be).expect("decodes");
    assert_eq!(
        decoded.addr.map(|a| a.to_string()).as_deref(),
        Some("203.0.113.9")
    );
}

#[test]
fn a_full_sixteen_byte_address_decodes_as_ipv6() {
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&[
        0x20, 0x01, 0x05, 0x03, 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30,
    ]);
    assert_eq!(
        decode_addr(raw).map(|a| a.to_string()).as_deref(),
        Some("2001:503:ba3e::2:30")
    );
}

#[test]
fn an_all_zero_address_yields_no_ip_at_all_rather_than_a_zero_address() {
    assert_eq!(decode_addr([0u8; 16]), None);
}

#[test]
fn an_all_zero_record_is_reported_as_empty_padding_not_as_a_record() {
    let rec = vec![0u8; 384];
    assert_eq!(
        decode_utmp(&rec, 0, 0, &GLIBC_UTMP_384, Endian::Le),
        Err(RecordReject::Empty)
    );
}

#[test]
fn a_record_that_runs_past_the_buffer_is_refused_as_truncated() {
    let short = vec![1u8; 100];
    assert_eq!(
        decode_utmp(&short, 0, 0, &GLIBC_UTMP_384, Endian::Le),
        Err(RecordReject::Truncated)
    );
}

#[test]
fn a_timestamp_before_1980_is_refused_and_leaves_the_record_without_a_date() {
    let spec = Spec {
        sec: 0,
        ..Spec::login("rick", "long", 0)
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.tv_sec, None);
    assert_eq!(decoded.tv_sec_raw, 0);
    assert_eq!(decoded.fault, Some(SanityFault::Time(0)));
}

#[test]
fn a_timestamp_past_the_unsigned_32_bit_ceiling_is_refused() {
    assert_eq!(plausible_unix(4_294_967_296), None);
    assert_eq!(plausible_unix(2_147_483_647), Some(2_147_483_647));
    assert_eq!(plausible_unix(4_294_967_295), Some(4_294_967_295));
}

#[test]
fn a_tv_usec_beyond_one_million_is_a_sanity_fault() {
    let spec = Spec {
        usec: 1_500_000,
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.tv_usec, None);
    assert_eq!(decoded.fault, Some(SanityFault::Usec));
}

#[test]
fn a_non_zero_reserved_trailer_is_a_sanity_fault() {
    let mut bytes = Spec::default().build(&GLIBC_UTMP_384, Endian::Le);
    bytes[370] = 0x41;
    let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.fault, Some(SanityFault::Reserved));
}

#[test]
fn a_text_field_carrying_data_after_its_nul_is_a_sanity_fault() {
    let mut bytes = Spec::default().build(&GLIBC_UTMP_384, Endian::Le);
    // "alice\0" then more text further into ut_user: not what a C strncpy into
    // a zeroed struct produces.
    bytes[60..65].copy_from_slice(b"eve!!");
    let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.fault, Some(SanityFault::Text("ut_user")));
    assert_eq!(
        decoded.user, "alice",
        "the value stops at the NUL and never carries the trailing bytes"
    );
}

#[test]
fn a_control_character_in_a_terminal_name_is_a_sanity_fault() {
    let mut bytes = Spec::default().build(&GLIBC_UTMP_384, Endian::Le);
    bytes[8] = 0x07;
    let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.fault, Some(SanityFault::Text("ut_line")));
    assert!(
        decoded.line.is_empty(),
        "a non-printable byte never reaches the emitted value"
    );
}

#[test]
fn a_negative_pid_is_a_sanity_fault() {
    let spec = Spec {
        pid: -5,
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(decoded.fault, Some(SanityFault::Pid(-5)));
}

#[test]
fn ut_type_zero_and_nine_are_not_accepted_as_real_login_records() {
    for bad in [0u16, 9u16, 12u16] {
        let spec = Spec {
            ut_type: bad,
            ..Spec::default()
        };
        let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
        let decoded = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
        assert_eq!(
            decoded.fault,
            Some(SanityFault::UtType(bad)),
            "ut_type {bad} must not pass the sanity filter"
        );
    }
}

#[test]
fn ut_type_names_never_invent_a_label_for_an_unknown_value() {
    for dialect in [TypeDialect::Linux, TypeDialect::Darwin] {
        assert_eq!(ut_type_name(dialect, 7), "USER_PROCESS");
        assert_eq!(ut_type_name(dialect, 8), "DEAD_PROCESS");
        assert_eq!(ut_type_name(dialect, 2), "BOOT_TIME");
        assert_eq!(ut_type_name(dialect, 77), "UNKNOWN");
    }
    // Ten and eleven exist only on Darwin, so on Linux they stay UNKNOWN
    // rather than borrowing Darwin's names.
    assert_eq!(ut_type_name(TypeDialect::Linux, 10), "UNKNOWN");
    assert_eq!(ut_type_name(TypeDialect::Linux, 11), "UNKNOWN");
    assert_eq!(ut_type_name(TypeDialect::Darwin, 10), "SIGNATURE");
    assert_eq!(ut_type_name(TypeDialect::Darwin, 11), "SHUTDOWN_TIME");
}

/// The one difference between the two enumerations that produces a wrong
/// answer rather than no answer: three and four are the two halves of a clock
/// change in both, and they mean **opposite** things.
///
/// Provenance is documented on [`TypeDialect`]: the Linux order is `utmp(5)`,
/// the Darwin order is Apple's `<utmpx.h>`. No macOS clock-change record is
/// held in the corpus, so this pins the header's claim rather than an observed
/// one — and it will fail loudly if anyone changes the mapping without new
/// evidence.
#[test]
fn the_two_halves_of_a_clock_change_are_swapped_between_the_dialects() {
    assert_eq!(ut_type_name(TypeDialect::Linux, 3), "NEW_TIME");
    assert_eq!(ut_type_name(TypeDialect::Linux, 4), "OLD_TIME");
    assert_eq!(ut_type_name(TypeDialect::Darwin, 3), "OLD_TIME");
    assert_eq!(ut_type_name(TypeDialect::Darwin, 4), "NEW_TIME");

    for (layout, three, four) in [
        (
            &GLIBC_UTMP_384,
            RecordKind::ClockSetNew,
            RecordKind::ClockSetOld,
        ),
        (
            &MUSL_UTMPX_400,
            RecordKind::ClockSetNew,
            RecordKind::ClockSetOld,
        ),
        (
            &DARWIN_UTMPX_628,
            RecordKind::ClockSetOld,
            RecordKind::ClockSetNew,
        ),
    ] {
        for (ut_type, expected) in [(3u16, three), (4u16, four)] {
            let spec = Spec {
                ut_type,
                // Not the `date` pseudo-user: that path classifies a clock
                // change from `ut_line` and would hide the type mapping.
                user: String::new(),
                line: "ttyS0".into(),
                ..Spec::default()
            };
            let bytes = spec.build(layout, Endian::Le);
            let rec = decode_utmp(&bytes, 0, 0, layout, Endian::Le).expect("decodes");
            assert_eq!(classify(&rec), expected, "{} type {ut_type}", layout.name);
        }
    }
}

/// A type value Darwin defines must not make a glibc file look normal.
#[test]
fn a_linux_record_carrying_a_darwin_only_type_is_still_anomalous() {
    for ut_type in [UT_DARWIN_SIGNATURE, UT_DARWIN_SHUTDOWN_TIME] {
        let spec = Spec {
            ut_type,
            ..Spec::default()
        };
        let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
        let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
        assert!(
            !rec.is_sane(),
            "glibc has no type {ut_type}; a file carrying one is mis-detected, not rare"
        );

        let bytes = spec.build(&DARWIN_UTMPX_628, Endian::Le);
        let rec = decode_utmp(&bytes, 0, 0, &DARWIN_UTMPX_628, Endian::Le).expect("decodes");
        assert!(
            rec.is_sane(),
            "the same value is a real record under the Darwin enumeration"
        );
    }
}

#[test]
fn a_musl_record_decodes_from_its_own_four_hundred_byte_layout() {
    let spec = Spec::login("carol", "pts/3", 1_751_970_000);
    let bytes = spec.build(&MUSL_UTMPX_400, Endian::Le);
    assert_eq!(bytes.len(), 400);

    let decoded = decode_utmp(&bytes, 0, 0, &MUSL_UTMPX_400, Endian::Le).expect("decodes");
    assert_eq!(decoded.user, "carol");
    assert_eq!(decoded.line, "pts/3");
    assert_eq!(decoded.tv_sec, Some(1_751_970_000));

    // Read with the glibc offsets instead, the same bytes must NOT pass sanity:
    // that is the whole point of detecting the layout rather than assuming it.
    let misread = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert!(
        !misread.is_sane(),
        "musl bytes read at the glibc offsets must be rejected, not silently mis-dated"
    );
}

#[test]
fn a_musl_record_with_a_thirty_two_bit_microseconds_field_still_reads_it() {
    // 32-bit musl stores a 4-byte suseconds_t in the 8-byte slot, followed by
    // padding. In big-endian that value is in the FIRST word, so an 8-byte read
    // yields a nonsense number and the decoder must fall back.
    let mut bytes = Spec::login("dave", "tty2", 1_751_970_000).build(&MUSL_UTMPX_400, Endian::Be);
    let (usec_off, _) = MUSL_UTMPX_400.tv_usec;
    bytes[usec_off..usec_off + 8].copy_from_slice(&[0u8; 8]);
    put_u32(&mut bytes, usec_off, 654_321, Endian::Be);

    let decoded = decode_utmp(&bytes, 0, 0, &MUSL_UTMPX_400, Endian::Be).expect("decodes");
    assert_eq!(decoded.tv_usec, Some(654_321));
    assert!(decoded.is_sane());
}

#[test]
fn a_musl_big_endian_record_finds_its_session_id_in_the_swapped_slot() {
    let spec = Spec {
        session: 90210,
        ..Spec::login("erin", "pts/9", 1_751_970_000)
    };
    let bytes = spec.build(&MUSL_UTMPX_400, Endian::Be);
    let decoded = decode_utmp(&bytes, 0, 0, &MUSL_UTMPX_400, Endian::Be).expect("decodes");
    assert_eq!(decoded.session, 90210);
}

// --- detection ---------------------------------------------------------------

#[test]
fn a_glibc_wtmp_is_detected_as_little_endian_384_byte_records() {
    let bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_377_694_800),
        Spec::logout("pts/1", 1_377_698_400),
        Spec::login("bob", "tty1", 1_377_700_000),
    ]);
    let declared = bytes.len() as u64;
    match detect(&bytes, declared, RoleHint::Wtmp) {
        Detected::Utmp(d) => {
            assert_eq!(d.layout.record_size, 384);
            assert_eq!(d.endian, Endian::Le);
            assert_eq!(d.role, UtmpRole::Wtmp);
            assert!(d.role_from_filename);
            assert_eq!(d.trailing_partial_bytes, 0);
        }
        other => panic!("expected a utmp-family detection, got {other:?}"),
    }
}

#[test]
fn a_big_endian_wtmp_is_detected_as_big_endian_and_not_as_little() {
    let specs = [
        Spec::login("alice", "pts/1", 1_377_694_800),
        Spec::logout("pts/1", 1_377_698_400),
        Spec::login("bob", "tty1", 1_377_700_000),
    ];
    let bytes = file_of(&specs, &GLIBC_UTMP_384, Endian::Be);
    let declared = bytes.len() as u64;
    match detect(&bytes, declared, RoleHint::Wtmp) {
        Detected::Utmp(d) => assert_eq!(d.endian, Endian::Be),
        other => panic!("expected a utmp-family detection, got {other:?}"),
    }
}

#[test]
fn a_musl_wtmp_is_detected_at_the_four_hundred_byte_stride() {
    let specs = [
        Spec::login("alice", "pts/1", 1_377_694_800),
        Spec::logout("pts/1", 1_377_698_400),
        Spec::login("bob", "tty1", 1_377_700_000),
        Spec::logout("tty1", 1_377_710_000),
    ];
    let bytes = file_of(&specs, &MUSL_UTMPX_400, Endian::Le);
    let declared = bytes.len() as u64;
    assert_ne!(declared % 384, 0, "the fixture must not also divide by 384");
    match detect(&bytes, declared, RoleHint::Wtmp) {
        Detected::Utmp(d) => {
            assert_eq!(d.layout.record_size, 400);
            assert_eq!(d.layout.name, "musl-utmpx-400");
        }
        other => panic!("expected a utmp-family detection, got {other:?}"),
    }
}

#[test]
fn random_bytes_that_happen_to_be_a_record_multiple_are_refused() {
    // A deterministic pseudo-random fill: an unrelated binary that is exactly
    // 384*8 bytes long must not be claimed as login accounting.
    let mut bytes = vec![0u8; 384 * 8];
    let mut state = 0x12345678u32;
    for byte in bytes.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = (state >> 16) as u8;
    }
    let declared = bytes.len() as u64;
    assert_eq!(
        detect(&bytes, declared, RoleHint::Unknown),
        Detected::NotRecognized(DetectFailure::FailedSanity)
    );
}

#[test]
fn an_elf_binary_padded_to_a_record_multiple_is_refused() {
    let mut bytes = vec![0u8; 384 * 4];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    for (i, byte) in bytes.iter_mut().enumerate().skip(64) {
        *byte = (i % 251) as u8;
    }
    let declared = bytes.len() as u64;
    assert!(matches!(
        detect(&bytes, declared, RoleHint::Unknown),
        Detected::NotRecognized(_)
    ));
}

#[test]
fn a_file_that_is_not_a_whole_number_of_records_of_any_layout_is_refused() {
    let mut bytes = glibc_file(&[Spec::login("alice", "pts/1", 1_377_694_800)]);
    bytes.extend_from_slice(&[0xab; 100]);
    let declared = bytes.len() as u64;
    assert_eq!(declared % 384, 100);
    assert_ne!(declared % 400, 0);
    assert_eq!(
        detect(&bytes, declared, RoleHint::Wtmp),
        Detected::NotRecognized(DetectFailure::NotAWholeNumberOfRecords),
        "a stride we cannot confirm must be refused, never approximated"
    );
}

#[test]
fn a_truncated_wtmp_with_many_intact_records_is_parsed_and_flagged_as_truncated() {
    let mut bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_377_694_800),
        Spec::logout("pts/1", 1_377_698_400),
        Spec::login("bob", "tty1", 1_377_700_000),
        Spec::logout("tty1", 1_377_703_600),
        Spec::login("carol", "pts/2", 1_377_707_200),
    ]);
    bytes.extend_from_slice(&[0x11; 120]);
    let out = run("wtmp", bytes);
    let st = status(&out);
    assert_eq!(text(st, "source_file"), Some("wtmp"));
    assert_eq!(
        st.get("source_file_truncated").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(num(st, "trailing_partial_bytes"), Some(120));
    assert_eq!(num(st, "records_decoded"), Some(5));
}

#[test]
fn an_empty_file_named_wtmp_is_reported_as_not_parsed_with_its_reason() {
    let out = run("wtmp", Vec::new());
    let st = status(&out);
    assert_eq!(st.get("detected").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(text(st, "failure_reason"), Some("empty_file"));
    assert!(
        text(st, "message")
            .unwrap_or_default()
            .contains("NOT evidence"),
        "the record must say that silence here is not proof of no logins"
    );
}

#[test]
fn a_zeroed_wtmp_is_reported_as_all_records_zero_rather_than_as_no_logins() {
    let out = run("wtmp", vec![0u8; 384 * 6]);
    let st = status(&out);
    assert_eq!(st.get("detected").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(text(st, "failure_reason"), Some("all_sampled_records_zero"));
    assert!(of_type(&out, "LoginSession").is_empty());
}

#[test]
fn an_unrelated_file_produces_nothing_at_all() {
    let out = run("photo.jpg", vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
    assert!(
        out.is_empty(),
        "files that never claimed to be login accounting stay silent"
    );
}

#[test]
fn role_hint_recognises_the_family_including_rotated_names() {
    assert_eq!(role_hint("wtmp", "/var/log/wtmp"), RoleHint::Wtmp);
    assert_eq!(role_hint("wtmp.1", ""), RoleHint::Wtmp);
    assert_eq!(role_hint("btmp-20260101", ""), RoleHint::Btmp);
    assert_eq!(role_hint("", "/run/utmp"), RoleHint::Utmp);
    assert_eq!(role_hint("lastlog", "/var/log/lastlog"), RoleHint::Lastlog);
    assert_eq!(
        role_hint("notes.txt", "/home/x/notes.txt"),
        RoleHint::Unknown
    );
}

#[test]
fn a_name_mentioning_btmp_is_never_downgraded_to_session_history() {
    // "btmp" also matches the loose "tmp" family; failed-login semantics must
    // win, because reporting a failed attempt as a successful session is the
    // worst error this parser could make.
    assert_eq!(role_hint("btmp", "/var/log/btmp"), RoleHint::Btmp);
    assert_eq!(
        role_hint("btmp.2", "/var/log/wtmp.d/btmp.2"),
        RoleHint::Btmp
    );
}

#[test]
fn a_structurally_valid_file_with_an_unknown_name_is_read_as_history_not_as_failures() {
    let bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_377_694_800),
        Spec::logout("pts/1", 1_377_698_400),
    ]);
    let out = run("carved_00012.bin", bytes);
    let st = status(&out);
    assert_eq!(text(st, "source_file"), Some("wtmp"));
    assert_eq!(
        st.get("source_role_from_filename")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(
        text(st, "role_note").is_some(),
        "the guessed role must be stated, not hidden"
    );
    assert!(
        of_type(&out, "FailedLogin").is_empty(),
        "a failure claim must never be invented from content alone"
    );
    assert_eq!(of_type(&out, "LoginSession").len(), 1);
}

// --- module wiring -----------------------------------------------------------

#[test]
fn the_module_identifies_itself_and_subscribes_to_the_file_pipeline() {
    let parser = UtmpParser;
    assert_eq!(parser.id(), "plugin.linux.utmp");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));
    let subs = parser.subscribes_to();
    assert!(subs.contains(&ArtifactType::FileEntry));
    assert!(subs.contains(&ArtifactType::FileContent));
    assert!(subs.contains(&ArtifactType::SystemArtifact));
    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn an_artifact_named_wtmp_with_no_content_reports_that_it_could_not_be_read() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "wtmp", "path": "/var/log/wtmp"}),
    );
    let out = UtmpParser.process(&artifact).expect("never errors");
    let st = status(&out);
    assert_eq!(text(st, "failure_reason"), Some("unreadable"));
}

#[test]
fn an_artifact_with_no_content_and_an_unrelated_name_produces_nothing() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "readme.md"}),
    );
    assert!(UtmpParser
        .process(&artifact)
        .expect("never errors")
        .is_empty());
}

#[test]
fn a_source_that_declares_a_size_but_returns_no_bytes_is_reported_unreadable() {
    let source = Arc::new(MockSource::claiming(Vec::new(), 384 * 4096));
    let artifact = artifact_named("wtmp", source);
    let out = UtmpParser.process(&artifact).expect("never errors");
    let st = status(&out);
    assert_eq!(st.get("detected").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(text(st, "failure_reason"), Some("unreadable"));
}

#[test]
fn a_short_read_marks_every_emitted_record_incomplete() {
    let bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_377_694_800),
        Spec::logout("pts/1", 1_377_698_400),
        Spec::login("bob", "tty1", 1_377_700_000),
    ]);
    // The source claims a thousand records and delivers three.
    let source = Arc::new(MockSource::claiming(bytes, 384 * 1000));
    let artifact = artifact_named("wtmp", source);
    let out = UtmpParser.process(&artifact).expect("never errors");

    assert!(!out.is_empty());
    for produced in &out {
        assert_eq!(
            produced
                .metadata
                .get("content_incomplete")
                .and_then(|v| v.as_bool()),
            Some(true),
            "a prefix of the evidence must never be presented as the whole of it"
        );
        assert_eq!(
            produced
                .metadata
                .get("content_incomplete_reason")
                .and_then(|v| v.as_str()),
            Some("short_read")
        );
    }
}

// --- sessions ----------------------------------------------------------------

#[test]
fn a_session_closed_by_a_logout_carries_an_observed_duration() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_970_000).from_ipv4([10, 0, 4, 22], "workstation"),
            Spec::logout("pts/1", 1_751_973_600),
        ]),
    );
    let sessions = of_type(&out, "LoginSession");
    assert_eq!(sessions.len(), 1);
    let s = sessions[0];
    assert_eq!(text(s, "user"), Some("alice"));
    assert_eq!(text(s, "tty"), Some("pts/1"));
    assert_eq!(text(s, "host"), Some("workstation"));
    assert_eq!(text(s, "ip"), Some("10.0.4.22"));
    assert_eq!(num(s, "login_time"), Some(1_751_970_000));
    assert_eq!(num(s, "logout_time"), Some(1_751_973_600));
    assert_eq!(num(s, "duration_seconds"), Some(3600));
    assert_eq!(text(s, "status"), Some("logged_out"));
    assert_eq!(text(s, "closed_by"), Some("logout_record"));
    assert_eq!(
        text(s, "short_desc").map(|d| d.contains("1h00m")),
        Some(true)
    );
}

#[test]
fn a_session_still_open_at_the_end_of_the_file_has_no_logout_and_no_duration() {
    let out = run(
        "utmp",
        glibc_file(&[
            Spec::login("bob", "tty1", 1_751_970_000),
            Spec::login("carol", "pts/7", 1_751_970_500),
        ]),
    );
    let sessions = of_type(&out, "LoginSession");
    assert_eq!(sessions.len(), 2);
    let s = sessions
        .iter()
        .find(|s| text(s, "user") == Some("bob"))
        .expect("bob's open session is reported");
    assert_eq!(text(s, "status"), Some("still_logged_in"));
    assert_eq!(text(s, "closed_by"), Some("end_of_file"));
    assert!(
        s.get("logout_time").is_none(),
        "an unwritten logout must not be materialised"
    );
    assert!(
        s.get("duration_seconds").is_none(),
        "an open session has no duration, not a duration of zero"
    );
    assert_eq!(text(s, "source_file"), Some("utmp"));
}

#[test]
fn a_session_interrupted_by_a_boot_is_bounded_but_never_given_a_logout_time() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("root", "pts/3", 1_751_960_000),
            Spec::boot(1_751_963_600, "5.15.0-92-generic"),
        ]),
    );
    let sessions = of_type(&out, "LoginSession");
    assert_eq!(sessions.len(), 1);
    let s = sessions[0];
    assert_eq!(text(s, "status"), Some("gone_no_logout"));
    assert_eq!(text(s, "closed_by"), Some("boot"));
    assert!(
        s.get("logout_time").is_none(),
        "a reboot is not a logout record and must not be reported as one"
    );
    assert!(s.get("duration_seconds").is_none());
    assert_eq!(num(s, "bounded_before_time"), Some(1_751_963_600));
    assert_eq!(num(s, "max_duration_seconds"), Some(3600));
}

#[test]
fn a_session_running_when_the_machine_was_shut_down_is_closed_by_the_shutdown() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_960_000),
            Spec::shutdown(1_751_961_000),
        ]),
    );
    let s = of_type(&out, "LoginSession");
    assert_eq!(text(s[0], "closed_by"), Some("shutdown"));
    assert_eq!(text(s[0], "status"), Some("gone_no_logout"));
    assert_eq!(num(s[0], "bounded_before_time"), Some(1_751_961_000));
}

#[test]
fn a_second_login_on_the_same_terminal_closes_the_first_as_superseded() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_960_000),
            Spec::login("bob", "pts/1", 1_751_961_000),
            Spec::logout("pts/1", 1_751_962_000),
        ]),
    );
    let sessions = of_type(&out, "LoginSession");
    assert_eq!(sessions.len(), 2);
    let alice = sessions
        .iter()
        .find(|s| text(s, "user") == Some("alice"))
        .expect("alice's session survives");
    assert_eq!(text(alice, "closed_by"), Some("superseded_by_new_login"));
    assert_eq!(text(alice, "status"), Some("gone_no_logout"));
    let bob = sessions
        .iter()
        .find(|s| text(s, "user") == Some("bob"))
        .expect("bob's session is present");
    assert_eq!(num(bob, "duration_seconds"), Some(1000));
}

#[test]
fn a_logout_that_precedes_its_login_yields_no_duration_at_all() {
    // A clock that moved backwards must not produce a negative or fabricated
    // session length.
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_970_000),
            Spec::logout("pts/1", 1_751_960_000),
        ]),
    );
    let s = of_type(&out, "LoginSession");
    assert_eq!(num(s[0], "logout_time"), Some(1_751_960_000));
    assert!(s[0].get("duration_seconds").is_none());
}

#[test]
fn a_login_with_an_unusable_timestamp_is_reported_without_a_date_and_without_a_timeline_row() {
    let undated = Spec::login("rick", "long", 0);
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_960_000),
            Spec::logout("pts/1", 1_751_961_000),
            Spec::login("bob", "tty1", 1_751_962_000),
            Spec::logout("tty1", 1_751_963_000),
            undated,
        ]),
    );
    let sessions = of_type(&out, "LoginSession");
    let rick = sessions
        .iter()
        .find(|s| text(s, "user") == Some("rick"))
        .expect("a session with an unusable time is still reported");
    assert!(rick.get("login_time").is_none());
    assert!(rick.get("date").is_none());
    assert_eq!(
        rick.get("login_time_unusable").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(num(rick, "login_time_raw"), Some(0));
    assert_eq!(
        timeline(&out).len(),
        4,
        "an undated record must never be pinned to the epoch on the timeline"
    );
    assert_eq!(num(status(&out), "records_without_usable_time"), Some(1));
}

#[test]
fn an_unpaired_logout_is_counted_rather_than_turned_into_a_session() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::logout("pts/9", 1_751_960_000),
            Spec::login("alice", "pts/1", 1_751_961_000),
        ]),
    );
    assert_eq!(num(status(&out), "unpaired_logouts"), Some(1));
    assert_eq!(of_type(&out, "LoginSession").len(), 1);
}

#[test]
fn the_session_cap_is_reported_when_it_bites() {
    let records: Vec<UtmpRecord> = (0..4)
        .map(|i| {
            let spec = Spec::login(&format!("user{i}"), &format!("pts/{i}"), 1_751_960_000 + i);
            let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
            decode_utmp(&bytes, 0, i as usize, &GLIBC_UTMP_384, Endian::Le).expect("decodes")
        })
        .collect();
    let built = reconstruct(&records, 2);
    assert_eq!(built.sessions.len(), 2);
    assert!(
        built.session_cap_reached,
        "a truncated reconstruction must announce itself"
    );
}

#[test]
fn the_session_cap_marks_every_emitted_artifact_incomplete_not_just_the_status_row() {
    // Four logins on four terminals, reconstructed under a two-session ceiling.
    // The two sessions that survive are real, but the inventory is a prefix: a
    // reader who took it for the whole file would conclude that user2 and user3
    // never logged in.
    let bytes = glibc_file(&[
        Spec::login("user0", "pts/0", 1_751_960_000),
        Spec::login("user1", "pts/1", 1_751_960_100),
        Spec::login("user2", "pts/2", 1_751_960_200),
        Spec::login("user3", "pts/3", 1_751_960_300),
    ]);
    let artifact = artifact_named("wtmp", Arc::new(MockSource::new(bytes)));
    let out = parse_with_limits(&artifact, Limits::testing(MAX_UTMP_RECORDS, 2));

    let st = status(&out);
    assert_eq!(num(st, "session_cap_reached"), Some(2));
    assert_eq!(num(st, "sessions"), Some(2));

    assert!(!out.is_empty());
    for produced in &out {
        assert_eq!(
            produced
                .metadata
                .get("content_incomplete")
                .and_then(|v| v.as_bool()),
            Some(true),
            "a capped session inventory must never read as the whole of the file"
        );
        assert_eq!(
            produced
                .metadata
                .get("content_incomplete_reason")
                .and_then(|v| v.as_str()),
            Some("cap_reached")
        );
    }
}

#[test]
fn the_record_cap_marks_every_emitted_artifact_incomplete() {
    let bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_751_960_000),
        Spec::logout("pts/1", 1_751_963_600),
        Spec::login("bob", "tty1", 1_751_964_000),
    ]);
    let artifact = artifact_named("wtmp", Arc::new(MockSource::new(bytes)));
    let out = parse_with_limits(&artifact, Limits::testing(1, MAX_SESSIONS));

    let st = status(&out);
    assert_eq!(num(st, "record_cap_reached"), Some(1));
    assert_eq!(num(st, "records_decoded"), Some(1));

    for produced in &out {
        assert_eq!(
            produced
                .metadata
                .get("content_incomplete_reason")
                .and_then(|v| v.as_str()),
            Some("cap_reached"),
            "records past the ceiling were not read, and every artifact must say so"
        );
    }
}

#[test]
fn a_reconstruction_that_stayed_inside_its_caps_is_not_flagged_incomplete() {
    // The counterpart to the two tests above: crying wolf on a complete parse
    // would make the incompleteness flag worthless.
    let bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_751_960_000),
        Spec::logout("pts/1", 1_751_963_600),
    ]);
    let artifact = artifact_named("wtmp", Arc::new(MockSource::new(bytes)));
    let out = parse_with_limits(&artifact, Limits::testing(MAX_UTMP_RECORDS, MAX_SESSIONS));

    let st = status(&out);
    assert!(st.get("session_cap_reached").is_none());
    assert!(st.get("record_cap_reached").is_none());
    for produced in &out {
        assert!(
            produced.metadata.get("content_incomplete").is_none(),
            "a complete parse must not be stamped incomplete"
        );
    }
}

// --- classification ----------------------------------------------------------

#[test]
fn a_boot_record_is_recognised_from_its_pseudo_user_and_tilde_terminal() {
    let bytes = Spec::boot(1_751_960_000, "5.15.0-92-generic").build(&GLIBC_UTMP_384, Endian::Le);
    let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(classify(&rec), RecordKind::Boot);
}

#[test]
fn a_runlevel_record_entering_level_zero_is_treated_as_a_shutdown() {
    let spec = Spec {
        ut_type: record::UT_RUN_LVL,
        user: "runlevel".into(),
        line: "~".into(),
        // The new run-level is packed into the low byte of ut_pid.
        pid: i32::from(b'0'),
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(classify(&rec), RecordKind::Shutdown);
}

#[test]
fn a_runlevel_record_entering_level_five_is_a_run_level_change() {
    let spec = Spec {
        ut_type: record::UT_RUN_LVL,
        user: "runlevel".into(),
        line: "~".into(),
        pid: i32::from(b'5') | (i32::from(b'3') << 8),
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(classify(&rec), RecordKind::Runlevel);

    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::boot(1_751_950_000, "5.15.0-92-generic"),
            spec,
            Spec::login("alice", "pts/1", 1_751_960_000),
        ]),
    );
    let boots = of_type(&out, "BootEvent");
    let runlevel = boots
        .iter()
        .find(|b| text(b, "kind") == Some("runlevel"))
        .expect("the run-level change is reported");
    assert_eq!(text(runlevel, "runlevel"), Some("5"));
    assert_eq!(text(runlevel, "previous_runlevel"), Some("3"));
}

#[test]
fn a_clock_change_pair_is_recognised_by_the_date_pseudo_user() {
    for (line, expected) in [
        ("{", RecordKind::ClockSetNew),
        ("|", RecordKind::ClockSetOld),
    ] {
        let spec = Spec {
            ut_type: record::UT_INIT_PROCESS,
            user: "date".into(),
            line: line.into(),
            ..Spec::default()
        };
        let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
        let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
        assert_eq!(classify(&rec), expected);
    }
}

#[test]
fn a_login_written_without_the_user_process_type_is_still_a_login() {
    // Real login programs have written history with ut_type left at
    // INIT_PROCESS; last(1) treats those as logins and so must we, or the
    // sessions simply disappear.
    let spec = Spec {
        ut_type: record::UT_INIT_PROCESS,
        user: "frank".into(),
        line: "pts/4".into(),
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(classify(&rec), RecordKind::Login);
}

#[test]
fn an_idle_getty_placeholder_is_bookkeeping_rather_than_a_session() {
    let spec = Spec {
        ut_type: record::UT_LOGIN_PROCESS,
        user: "LOGIN".into(),
        line: "tty3".into(),
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(classify(&rec), RecordKind::Bookkeeping);

    let out = run(
        "wtmp",
        glibc_file(&[
            spec,
            Spec::boot(1_751_950_000, "5.15.0-92-generic"),
            Spec::shutdown(1_751_955_000),
        ]),
    );
    assert!(of_type(&out, "LoginSession").is_empty());
    assert_eq!(num(status(&out), "bookkeeping_records"), Some(1));
}

#[test]
fn a_user_process_record_with_an_empty_user_is_a_logout() {
    let spec = Spec {
        ut_type: record::UT_USER_PROCESS,
        user: String::new(),
        line: "pts/1".into(),
        ..Spec::default()
    };
    let bytes = spec.build(&GLIBC_UTMP_384, Endian::Le);
    let rec = decode_utmp(&bytes, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert_eq!(classify(&rec), RecordKind::Logout);
}

// --- btmp --------------------------------------------------------------------

#[test]
fn btmp_records_become_failed_logins_that_carry_the_source_host_and_ip() {
    let out = run(
        "btmp",
        glibc_file(&[
            Spec::login("root", "ssh:notty", 1_751_969_000)
                .from_ipv4([203, 0, 113, 9], "203.0.113.9"),
            Spec::login("root", "ssh:notty", 1_751_969_060)
                .from_ipv4([203, 0, 113, 9], "203.0.113.9"),
            Spec::login("admin", "ssh:notty", 1_751_969_120)
                .from_ipv4([198, 51, 100, 7], "198.51.100.7"),
        ]),
    );
    let failed = of_type(&out, "FailedLogin");
    assert_eq!(failed.len(), 3);
    assert_eq!(text(failed[0], "user"), Some("root"));
    assert_eq!(text(failed[0], "ip"), Some("203.0.113.9"));
    assert_eq!(text(failed[0], "host"), Some("203.0.113.9"));
    assert_eq!(text(failed[0], "source_file"), Some("btmp"));
    assert_eq!(num(failed[0], "time"), Some(1_751_969_000));
    assert_eq!(
        text(failed[2], "short_desc"),
        Some("Failed login: admin from 198.51.100.7")
    );
}

#[test]
fn btmp_never_produces_a_login_session() {
    let out = run(
        "btmp",
        glibc_file(&[
            Spec::login("root", "ssh:notty", 1_751_969_000),
            Spec::logout("ssh:notty", 1_751_969_100),
        ]),
    );
    assert!(
        of_type(&out, "LoginSession").is_empty(),
        "a rejected attempt must never be reconstructed into a session"
    );
    assert_eq!(of_type(&out, "FailedLogin").len(), 1);
}

#[test]
fn a_failed_login_timeline_row_is_labelled_as_a_failure() {
    let out = run(
        "btmp",
        glibc_file(&[
            Spec::login("root", "ssh:notty", 1_751_969_000).from_ipv4([203, 0, 113, 9], ""),
            Spec::login("root", "ssh:notty", 1_751_969_060).from_ipv4([203, 0, 113, 9], ""),
        ]),
    );
    let events = timeline(&out);
    assert_eq!(events.len(), 2);
    assert_eq!(text(events[0], "timestamp_desc"), Some("Failed login"));
    assert_eq!(
        text(events[0], "short_desc"),
        Some("Failed login: root from 203.0.113.9")
    );
}

// --- timeline contract -------------------------------------------------------

#[test]
fn a_wtmp_produces_a_timeline_row_for_every_dated_record() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::boot(1_751_960_000, "5.15.0-92-generic"),
            Spec::login("alice", "pts/1", 1_751_970_000).from_ipv4([10, 0, 4, 22], "workstation"),
            Spec::logout("pts/1", 1_751_973_600),
            Spec::shutdown(1_751_980_000),
        ]),
    );
    let descs: Vec<&str> = timeline(&out)
        .iter()
        .filter_map(|e| text(e, "timestamp_desc"))
        .collect();
    assert_eq!(
        descs,
        vec![
            "System boot (BOOT_TIME)",
            "Login (USER_PROCESS)",
            "Logout (DEAD_PROCESS)",
            "Shutdown (RUN_LVL)",
        ]
    );
}

#[test]
fn every_timeline_row_carries_the_module_id_a_bare_second_timestamp_and_valid_full_details() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_970_000).from_ipv4([10, 0, 4, 22], "workstation"),
            Spec::logout("pts/1", 1_751_973_600),
        ]),
    );
    let events = timeline(&out);
    assert_eq!(events.len(), 2);
    for event in events {
        assert_eq!(text(event, "source_module"), Some("plugin.linux.utmp"));
        assert!(
            event.get("timestamp").and_then(|t| t.as_i64()).is_some(),
            "the timeline contract is a bare i64 of UTC unix seconds"
        );
        let details = text(event, "full_details").expect("full_details is present");
        let parsed: Value = serde_json::from_str(details).expect("full_details is valid JSON");
        assert!(parsed.is_object());
        assert!(
            event.get("timezone").is_none(),
            "utmp times are already UTC; tagging them local would shift the timeline"
        );
    }
}

#[test]
fn the_sub_second_part_of_a_login_survives_in_the_timeline_details() {
    let spec = Spec {
        usec: 123_456,
        ..Spec::login("alice", "pts/1", 1_751_970_000)
    };
    let out = run(
        "wtmp",
        glibc_file(&[spec, Spec::logout("pts/1", 1_751_973_600)]),
    );
    let events = timeline(&out);
    let details: Value =
        serde_json::from_str(text(events[0], "full_details").expect("present")).expect("json");
    assert_eq!(
        details.get("tv_usec").and_then(|v| v.as_i64()),
        Some(123_456)
    );
}

#[test]
fn an_anomalous_record_is_still_emitted_and_is_flagged_as_anomalous() {
    // One corrupt record inside an otherwise healthy file is evidence, not a
    // reason to drop the record or the file.
    let mut bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_751_970_000),
        Spec::logout("pts/1", 1_751_973_600),
        Spec::login("bob", "tty1", 1_751_974_000),
        Spec::login("carol", "tty2", 1_751_975_000),
    ]);
    // Corrupt the reserved trailer of the third record.
    bytes[2 * 384 + 370] = 0xff;
    let out = run("wtmp", bytes);
    assert_eq!(num(status(&out), "records_anomalous"), Some(1));
    assert_eq!(of_type(&out, "LoginSession").len(), 3);
}

#[test]
fn the_status_record_reports_the_layout_the_byte_order_and_the_counts() {
    let out = run(
        "wtmp",
        glibc_file(&[
            Spec::boot(1_751_960_000, "5.15.0-92-generic"),
            Spec::login("alice", "pts/1", 1_751_970_000),
            Spec::logout("pts/1", 1_751_973_600),
        ]),
    );
    let st = status(&out);
    assert_eq!(text(st, "record_layout"), Some("glibc-utmp-384"));
    assert_eq!(text(st, "byte_order"), Some("little-endian"));
    assert_eq!(num(st, "record_size"), Some(384));
    assert_eq!(num(st, "records_decoded"), Some(3));
    assert_eq!(num(st, "sessions"), Some(1));
    assert_eq!(num(st, "boot_events"), Some(1));
    assert_eq!(num(st, "timeline_events"), Some(3));
    assert_eq!(num(st, "declared_size"), Some(384 * 3));
    assert!(st.get("content_incomplete").is_none());
}

#[test]
fn empty_padding_records_are_skipped_without_being_counted_as_evidence() {
    let mut bytes = glibc_file(&[
        Spec::login("alice", "pts/1", 1_751_970_000),
        Spec::logout("pts/1", 1_751_973_600),
    ]);
    bytes.extend_from_slice(&vec![0u8; 384 * 2]);
    let out = run("wtmp", bytes);
    let st = status(&out);
    assert_eq!(num(st, "records_decoded"), Some(2));
    assert_eq!(num(st, "records_empty"), Some(2));
}

#[test]
fn every_produced_artifact_is_parented_to_the_file_it_came_from() {
    let artifact = artifact_named(
        "wtmp",
        Arc::new(MockSource::new(glibc_file(&[
            Spec::login("alice", "pts/1", 1_751_970_000),
            Spec::logout("pts/1", 1_751_973_600),
        ]))),
    );
    let out = UtmpParser.process(&artifact).expect("never errors");
    assert!(!out.is_empty());
    for produced in &out {
        assert_eq!(produced.parent_id, Some(artifact.id));
        assert_eq!(produced.case_id, artifact.case_id);
        assert!(
            produced.data.is_none(),
            "records are metadata-only; they carry no second copy of the evidence"
        );
    }
}

// --- lastlog -----------------------------------------------------------------

#[test]
fn a_lastlog_emits_one_record_per_populated_uid_and_none_for_never_logged_in() {
    let mut bytes = vec![0u8; LASTLOG_292.record_size * 3];
    // UID 0 and UID 1 never logged in; UID 2 did.
    let populated = lastlog_bytes(1_751_000_000, "pts/0", "10.0.4.22");
    let start = LASTLOG_292.record_size * 2;
    bytes[start..start + LASTLOG_292.record_size].copy_from_slice(&populated);

    let out = run("lastlog", bytes);
    let records = of_type(&out, "LastLogin");
    assert_eq!(records.len(), 1, "a never-used UID must produce no row");
    assert_eq!(num(records[0], "uid"), Some(2));
    assert_eq!(num(records[0], "last_login_time"), Some(1_751_000_000));
    assert_eq!(text(records[0], "tty"), Some("pts/0"));
    assert_eq!(text(records[0], "host"), Some("10.0.4.22"));
    assert_eq!(
        text(records[0], "ip"),
        Some("10.0.4.22"),
        "a host field that is an IP literal is exposed as one"
    );
    assert!(
        records[0].get("user").map(|v| v.is_null()).unwrap_or(false),
        "lastlog stores no username and one must never be guessed"
    );
}

#[test]
fn a_lastlog_host_that_is_a_name_yields_no_ip() {
    let mut bytes = vec![0u8; LASTLOG_292.record_size * 2];
    bytes[LASTLOG_292.record_size..].copy_from_slice(&lastlog_bytes(
        1_751_000_000,
        "pts/0",
        "workstation.corp.example",
    ));
    let out = run("lastlog", bytes);
    let records = of_type(&out, "LastLogin");
    assert_eq!(text(records[0], "host"), Some("workstation.corp.example"));
    assert!(records[0].get("ip").is_none());
}

#[test]
fn an_entirely_zero_lastlog_emits_no_records_but_still_reports_what_was_examined() {
    let out = run("lastlog", vec![0u8; LASTLOG_292.record_size * 10]);
    assert!(of_type(&out, "LastLogin").is_empty());
    let st = status(&out);
    assert_eq!(num(st, "uid_slots_walked"), Some(10));
    assert_eq!(num(st, "records_populated"), Some(0));
    assert_eq!(
        st.get("layout_unconfirmed").and_then(|v| v.as_bool()),
        Some(true),
        "with no populated record the stride was never confirmed against data"
    );
}

#[test]
fn a_lastlog_record_whose_time_is_zero_is_reported_but_never_dated() {
    let size = LASTLOG_292.record_size;
    let mut bytes = vec![0u8; size * 4];
    bytes[..size].copy_from_slice(&lastlog_bytes(1_751_000_000, "tty1", "console"));
    bytes[size..size * 2].copy_from_slice(&lastlog_bytes(1_751_000_100, "pts/0", "10.0.0.1"));
    bytes[size * 2..size * 3].copy_from_slice(&lastlog_bytes(1_751_000_200, "pts/1", "10.0.0.2"));
    // A record with a terminal but a zero timestamp: present, but undatable.
    bytes[size * 3..].copy_from_slice(&lastlog_bytes(0, "pts/9", "somewhere"));

    let out = run("lastlog", bytes);
    let records = of_type(&out, "LastLogin");
    assert_eq!(records.len(), 4);
    let undated = records
        .iter()
        .find(|r| num(r, "uid") == Some(3))
        .expect("the undatable record is still reported");
    assert!(undated.get("last_login_time").is_none());
    assert_eq!(
        undated
            .get("last_login_time_unusable")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        timeline(&out).len(),
        3,
        "only the three datable records reach the timeline"
    );
    assert_eq!(num(status(&out), "records_without_usable_time"), Some(1));
}

#[test]
fn a_file_named_lastlog_that_is_not_a_record_multiple_is_refused() {
    let mut bytes = vec![0u8; LASTLOG_292.record_size * 2];
    bytes.extend_from_slice(&[7u8; 5]);
    let out = run("lastlog", bytes);
    let st = status(&out);
    assert_eq!(st.get("detected").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        text(st, "failure_reason"),
        Some("size_not_a_record_multiple")
    );
    assert!(of_type(&out, "LastLogin").is_empty());
}

#[test]
fn a_sparse_lastlog_is_streamed_in_blocks_rather_than_read_whole() {
    let record_size = LASTLOG_292.record_size as u64;
    let mut populated = HashMap::new();
    populated.insert(0u32, lastlog_bytes(1_751_000_000, "tty1", "console"));
    populated.insert(4_999u32, lastlog_bytes(1_751_100_000, "pts/5", "10.1.1.1"));
    let source = Arc::new(SparseLastlog {
        populated,
        record_size,
        declared: record_size * 5_000,
        largest_read: AtomicUsize::new(0),
    });
    let artifact = artifact_named("lastlog", source.clone());
    let out = UtmpParser.process(&artifact).expect("never errors");

    let records = of_type(&out, "LastLogin");
    assert_eq!(records.len(), 2);
    let uids: Vec<i64> = records.iter().filter_map(|r| num(r, "uid")).collect();
    assert!(uids.contains(&0) && uids.contains(&4_999));
    assert!(
        source.largest_read.load(Ordering::SeqCst) as u64 <= 512 * record_size,
        "a sparse lastlog must never be pulled into memory whole"
    );
    assert_eq!(num(status(&out), "uid_slots_total"), Some(5_000));
}

#[test]
fn a_lastlog_uid_is_recovered_from_the_records_position_in_the_file() {
    let rec = lastlog_bytes(1_751_000_000, "pts/0", "host");
    let decoded = decode_lastlog(&rec, 4242, &LASTLOG_292, Endian::Le).expect("decodes");
    assert_eq!(
        decoded.uid, 4242,
        "the UID is the index, not a stored field"
    );
    assert_eq!(decoded.ll_time, Some(1_751_000_000));
}

#[test]
fn an_all_zero_lastlog_record_is_reported_as_never_logged_in() {
    let rec = vec![0u8; LASTLOG_292.record_size];
    assert_eq!(
        decode_lastlog(&rec, 0, &LASTLOG_292, Endian::Le),
        Err(RecordReject::Empty)
    );
}

// --- formatting --------------------------------------------------------------

#[test]
fn durations_are_rendered_the_way_an_examiner_reads_them() {
    assert_eq!(humanize_duration(45), "45s");
    assert_eq!(humanize_duration(725), "12m05s");
    assert_eq!(humanize_duration(3600), "1h00m");
    assert_eq!(humanize_duration(273_600), "3d04h");
    assert_eq!(humanize_duration(0), "0s");
}

// ---------------------------------------------------------------------------
// Files that only share the name
// ---------------------------------------------------------------------------

fn at_path(name: &str, path: &str, bytes: Vec<u8>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(MockSource::new(bytes))),
        json!({"name": name, "path": path}),
    )
}

/// UI-030 / the `HUNT-084` shape. `/etc/logrotate.d/wtmp` and
/// `/etc/logrotate.d/btmp` are *logrotate configuration* — plain text, a few
/// lines each — and the reader claimed them by basename and filed two refusal
/// records saying Linux login accounting could not be read. On the Magnet 2022
/// Linux image that put two false findings in a case on the screen an examiner
/// reads to answer "who logged in".
#[test]
fn a_logrotate_config_named_wtmp_is_not_login_accounting() {
    let config = b"/var/log/wtmp {\n missingok\n monthly\n create 0664 root utmp\n rotate 1\n}\n";
    let out = parse(&at_path("wtmp", "/etc/logrotate.d/wtmp", config.to_vec()));
    assert!(
        out.is_empty(),
        "a text file is not a truncated utmp: {:?}",
        out.first().map(|a| a.metadata.clone())
    );
}

/// An empty `wtmp` in the place a real one lives stays notable: a zeroed login
/// log is a classic anti-forensic artefact, and silence about it would be the
/// opposite of what this reader is for.
#[test]
fn an_empty_wtmp_is_still_reported() {
    let out = parse(&at_path("wtmp", "/var/log/wtmp", Vec::new()));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "UtmpParseStatus");
    assert_eq!(out[0].metadata["failure_reason"], "empty_file");
}

/// And a genuinely binary file of the wrong size is still reported: that is a
/// truncated or damaged log, which is a finding.
#[test]
fn a_binary_file_of_the_wrong_size_is_still_reported() {
    let out = parse(&at_path("wtmp", "/var/log/wtmp", vec![0x81u8; 300]));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "UtmpParseStatus");
}

// --- macOS `utmpx` (documentation/MACOS_DESIGN.md, macOS login accounting) ---

/// A Darwin record parsed at glibc's offsets reads its type out of the middle
/// of a username, which is the whole reason a fourth layout exists rather than
/// a tolerance on the three.
///
/// `ut_type` is at 296 on Darwin and at 0 on glibc, and `ut_user` occupies
/// 0..256 — so glibc's type field lands inside the name. This asserts the two
/// layouts are not interchangeable rather than asserting a decode.
#[test]
fn a_darwin_record_and_a_glibc_record_are_not_the_same_shape() {
    assert_eq!(DARWIN_UTMPX_628.record_size, 628);
    assert_eq!(DARWIN_UTMPX_628.ut_type, 296);
    assert_eq!(GLIBC_UTMP_384.ut_type, 0);
    assert_eq!(DARWIN_UTMPX_628.ut_user, (0, 256));
    let (user_off, user_len) = DARWIN_UTMPX_628.ut_user;
    assert!(
        (user_off..user_off + user_len).contains(&GLIBC_UTMP_384.ut_type),
        "glibc's ut_type offset falls inside Darwin's ut_user, so a Darwin file read at glibc's \
         offsets takes its record type from a username"
    );
    // And every byte of the Darwin record is accounted for: 308 + 256 + 64.
    let (host_off, host_len) = DARWIN_UTMPX_628.ut_host;
    let (res_off, res_len) = DARWIN_UTMPX_628.reserved;
    assert_eq!(host_off + host_len, res_off);
    assert_eq!(res_off + res_len, DARWIN_UTMPX_628.record_size);
}

/// Darwin records no remote address, so none is invented.
///
/// The bytes where glibc keeps `ut_addr_v6` are `ut_pad[16]` here — sixty-four
/// zeroes. Reading them as an address would be invisible on the common case,
/// because all-zero decodes to "no address", and would produce one confident
/// fictional remote host on the first record whose pad was not zero.
#[test]
fn the_darwin_layout_records_no_address_rather_than_a_zero_one() {
    assert_eq!(DARWIN_UTMPX_628.ut_addr, None);
    assert!(GLIBC_UTMP_384.ut_addr.is_some());
    // A record with a non-zero pad still yields no address.
    let mut rec = vec![0u8; 628];
    rec[0..8].copy_from_slice(b"analyst\0");
    rec[260..267].copy_from_slice(b"console");
    put_u32(&mut rec, 292, 501, Endian::Le);
    put_u16(&mut rec, 296, UT_USER_PROCESS, Endian::Le);
    put_u32(&mut rec, 300, 1_617_653_227, Endian::Le);
    // Something in the pad that glibc would have read as 203.0.113.9.
    rec[564..568].copy_from_slice(&[203, 0, 113, 9]);
    let decoded =
        decode_utmp(&rec, 0, 0, &DARWIN_UTMPX_628, Endian::Le).expect("the record decodes");
    assert_eq!(
        decoded.addr, None,
        "the pad is not an address field, and a layout that read it would publish 203.0.113.9 \
         as the origin of a local console login"
    );
    assert_eq!(decoded.user, "analyst");
    assert_eq!(decoded.line, "console");
}

/// Darwin has no level-0 `RUN_LVL`: a clean stop is its own record type, and it
/// must close the sessions it ended.
///
/// The bound is reported as a bound. A session the machine went down under has
/// no recorded logout, so `logout_time` stays absent and the shutdown time is
/// carried as `bounded_before` — the same rule the Linux path follows.
#[test]
fn a_macos_shutdown_record_closes_the_sessions_it_ended() {
    let out = darwin_run(&[
        darwin_signature(),
        darwin_event(record::UT_BOOT_TIME, 1, 1_617_653_088),
        Spec {
            ut_type: UT_USER_PROCESS,
            pid: 562,
            line: "ttys000".into(),
            id: "s00".into(),
            user: "eliflatt".into(),
            host: String::new(),
            sec: 1_617_653_306,
            ..Spec::default()
        },
        darwin_event(UT_DARWIN_SHUTDOWN_TIME, 0, 1_617_660_000),
    ]);

    let sessions = of_type(&out, "LoginSession");
    assert_eq!(sessions.len(), 1);
    assert_eq!(text(sessions[0], "status"), Some("gone_no_logout"));
    assert_eq!(text(sessions[0], "closed_by"), Some("shutdown"));
    assert_eq!(num(sessions[0], "bounded_before_time"), Some(1_617_660_000));
    assert_eq!(
        num(sessions[0], "max_duration_seconds"),
        Some(1_617_660_000 - 1_617_653_306)
    );
    assert!(
        sessions[0].get("logout_time").is_none(),
        "no logout was written, so none may be reported"
    );

    let boots = of_type(&out, "BootEvent");
    let shutdown = boots
        .iter()
        .find(|b| text(b, "kind") == Some("shutdown"))
        .expect("the shutdown is reported as an event in its own right");
    assert_eq!(
        text(shutdown, "ut_type"),
        Some("SHUTDOWN_TIME"),
        "the raw type is named from the Darwin enumeration, not as a RUN_LVL"
    );
    assert_eq!(num(shutdown, "date"), Some(1_617_660_000));
    assert_eq!(num(status(&out), "records_anomalous"), Some(0));
}

/// The signature record states the file's format version. It is not an event:
/// it has no timestamp, and it must be reported as provenance rather than
/// counted as a record with an unreadable time.
#[test]
fn the_format_signature_is_reported_as_a_version_and_not_as_an_event() {
    let out = darwin_run(&[
        darwin_signature(),
        Spec {
            ut_type: UT_USER_PROCESS,
            pid: 121,
            line: "console".into(),
            id: "c0".into(),
            user: "eliflatt".into(),
            host: String::new(),
            sec: 1_617_653_227,
            ..Spec::default()
        },
    ]);
    let st = status(&out);
    assert_eq!(text(st, "format_version"), Some("utmpx-1.00"));
    assert_eq!(num(st, "records_decoded"), Some(2));
    assert_eq!(num(st, "bookkeeping_records"), Some(1));
    assert_eq!(
        num(st, "records_anomalous"),
        Some(0),
        "a zero timestamp is this record type's own convention, not an anomaly"
    );
    assert_eq!(
        num(st, "records_without_usable_time"),
        Some(0),
        "the signature produces no timeline row because it describes no event"
    );
    assert_eq!(timeline(&out).len(), 1, "one dated record, one row");
}

/// A zero timestamp is excused for the signature record **only**. Any other
/// record type with no readable time is still an anomaly, because that is what
/// a wiped or fabricated record looks like.
#[test]
fn a_zero_timestamp_is_excused_for_the_signature_record_alone() {
    for (ut_type, expect_sane) in [
        (UT_DARWIN_SIGNATURE, true),
        (UT_USER_PROCESS, false),
        (record::UT_BOOT_TIME, false),
        (UT_DARWIN_SHUTDOWN_TIME, false),
    ] {
        let spec = Spec {
            ut_type,
            user: "someone".into(),
            line: "ttys000".into(),
            sec: 0,
            ..Spec::default()
        };
        let bytes = spec.build(&DARWIN_UTMPX_628, Endian::Le);
        let rec = decode_utmp(&bytes, 0, 0, &DARWIN_UTMPX_628, Endian::Le).expect("decodes");
        assert_eq!(
            rec.is_sane(),
            expect_sane,
            "type {ut_type} with a zero timestamp"
        );
    }
}

/// Darwin's `ut_id` is opaque bytes, not a string. The `console` record in the
/// corpus holds `2f 00 01 01`: as text that is the single character `/`, and
/// the bytes after the NUL make the field fail the text-cleanliness check —
/// which would flag the login record an examiner most wants as anomalous.
#[test]
fn an_opaque_darwin_ut_id_is_rendered_as_the_bytes_it_holds() {
    let mut rec =
        darwin_event(UT_USER_PROCESS, 121, 1_617_653_227).build(&DARWIN_UTMPX_628, Endian::Le);
    rec[0..8].copy_from_slice(b"eliflatt");
    rec[260..267].copy_from_slice(b"console");
    rec[256..260].copy_from_slice(&[0x2f, 0x00, 0x01, 0x01]);
    let decoded = decode_utmp(&rec, 0, 0, &DARWIN_UTMPX_628, Endian::Le).expect("decodes");
    assert_eq!(decoded.id, "0x2f000101");
    assert!(decoded.id_is_hex);
    assert!(
        decoded.is_sane(),
        "an opaque id is what the format holds; flagging it would make every macOS \
         console login look anomalous"
    );

    // A textual id still reads as text, so the common case is not hexified.
    // Written as raw bytes because the real field is full width with no room
    // for a NUL — `s000` is four characters in four bytes.
    let mut text_id =
        darwin_event(UT_USER_PROCESS, 562, 1_617_653_306).build(&DARWIN_UTMPX_628, Endian::Le);
    text_id[0..8].copy_from_slice(b"eliflatt");
    text_id[260..267].copy_from_slice(b"ttys000");
    text_id[256..260].copy_from_slice(b"s000");
    let decoded = decode_utmp(&text_id, 0, 0, &DARWIN_UTMPX_628, Endian::Le).expect("decodes");
    assert_eq!(decoded.id, "s000");
    assert!(!decoded.id_is_hex);

    // On a Linux layout the same broken field is still a fault: glibc's ut_id
    // really is a string, so bytes after the NUL mean the offsets are wrong.
    let mut rec = Spec::login("alice", "pts/0", 1_751_960_000).build(&GLIBC_UTMP_384, Endian::Le);
    rec[40..44].copy_from_slice(&[0x2f, 0x00, 0x01, 0x01]);
    let decoded = decode_utmp(&rec, 0, 0, &GLIBC_UTMP_384, Endian::Le).expect("decodes");
    assert!(!decoded.id_is_hex);
    assert!(!decoded.is_sane());
}

/// The detector must reach the Darwin layout from the bytes alone: nothing in
/// the file says `utmpx`, and the name is only a hint.
#[test]
fn a_macos_utmpx_is_detected_as_the_darwin_layout_from_its_contents() {
    let bytes = darwin_file(&[
        darwin_signature(),
        darwin_event(record::UT_BOOT_TIME, 1, 1_617_653_088),
        Spec {
            ut_type: UT_USER_PROCESS,
            pid: 121,
            line: "console".into(),
            id: "c0".into(),
            user: "eliflatt".into(),
            host: String::new(),
            sec: 1_617_653_227,
            ..Spec::default()
        },
    ]);
    let Detected::Utmp(detection) = detect(&bytes, bytes.len() as u64, RoleHint::Utmp) else {
        panic!("a real Darwin utmpx must be recognised");
    };
    assert_eq!(detection.layout.name, "darwin-utmpx-628");
    assert_eq!(detection.layout.type_dialect, TypeDialect::Darwin);
    assert_eq!(detection.endian, Endian::Le);
}

/// **The real macOS `utmpx` from the Magnet 2021 image** — the file the layout
/// was derived from, read back through the production path.
///
/// Ground truth is the file's own internal agreement, which is what makes this
/// a known answer rather than a round trip: 2,512 bytes is exactly four
/// records; the first is `SIGNATURE` carrying the format's own version string
/// `utmpx-1.00`; and the remaining three read as a coherent session — boot with
/// `ut_pid` 1, then a `console` login, then `ttys000` for the same user, in
/// ascending time order on the day the file was last written.
#[test]
fn the_real_macos_utmpx_reads_as_the_session_it_recorded() {
    let path = home("ctf-evidence/macos2021/tree/private/var/run/utmpx");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!(
            "skipping: {} not present (gitignored corpus)",
            path.display()
        );
        return;
    };
    assert_eq!(bytes.len(), 2512, "four 628-byte records");

    let out = parse(&at_path("utmpx", "/private/var/run/utmpx", bytes));

    // The layout the reader chose is named on everything it produced, so a
    // future edit that moves a field cannot pass by picking another layout.
    for a in &out {
        assert_eq!(
            text(&a.metadata, "record_layout"),
            Some("darwin-utmpx-628"),
            "every artifact names the layout it was read under"
        );
        assert_eq!(
            text(&a.metadata, "record_type_dialect"),
            Some("darwin-utmpx")
        );
    }

    let st = status(&out);
    assert_eq!(num(st, "records_decoded"), Some(4));
    assert_eq!(
        num(st, "records_anomalous"),
        Some(0),
        "every record in this file is sane under the Darwin layout; a fault here \
         means a field moved"
    );
    assert_eq!(
        text(st, "format_version"),
        Some("utmpx-1.00"),
        "the file states its own format version, which is what corroborates the layout"
    );

    let sessions = of_type(&out, "LoginSession");
    assert_eq!(
        sessions.len(),
        2,
        "a console login and a terminal login, both still open when the image was taken"
    );
    let by_tty = |tty: &str| {
        *sessions
            .iter()
            .find(|a| text(a, "tty") == Some(tty))
            .unwrap_or_else(|| panic!("no session on {tty}; got {sessions:#?}"))
    };

    let console = by_tty("console");
    assert_eq!(text(console, "user"), Some("eliflatt"));
    assert_eq!(num(console, "pid"), Some(121));
    assert_eq!(num(console, "login_time"), Some(1_617_653_227));
    assert_eq!(text(console, "ut_type"), Some("USER_PROCESS"));
    assert_eq!(
        text(console, "status"),
        Some("still_logged_in"),
        "utmp holds the sessions open at acquisition time"
    );
    assert_eq!(
        text(console, "ut_id"),
        Some("0x2f000101"),
        "Darwin's ut_id is opaque bytes; rendered as text this record's id is the \
         single character '/', which is not what the file holds"
    );

    let term = by_tty("ttys000");
    assert_eq!(text(term, "user"), Some("eliflatt"));
    assert_eq!(num(term, "pid"), Some(562));
    assert_eq!(num(term, "login_time"), Some(1_617_653_306));
    assert_eq!(
        text(term, "ut_id"),
        Some("s000"),
        "this one is text, and a text id must still read as text"
    );
    assert!(
        num(term, "login_time").unwrap() > num(console, "login_time").unwrap(),
        "the GUI login came first and the terminal second"
    );

    // No login here came from anywhere: Darwin records no address and this
    // file's ut_host is empty on every record.
    for a in &sessions {
        assert!(
            a.get("ip").is_none(),
            "no record in this file names a remote address, and none may be invented"
        );
        assert!(
            a.get("host").is_none(),
            "ut_host is empty on every record in this file"
        );
    }

    let boots = of_type(&out, "BootEvent");
    assert_eq!(boots.len(), 1, "one BOOT_TIME record");
    assert_eq!(text(boots[0], "kind"), Some("boot"));
    assert_eq!(num(boots[0], "date"), Some(1_617_653_088));
    assert_eq!(text(boots[0], "ut_type"), Some("BOOT_TIME"));
    assert!(
        boots[0].get("kernel").is_none(),
        "Darwin's boot record carries no kernel release, and one must not be invented"
    );

    // The signature record is not an event: it has no timestamp and must not
    // reach the timeline. Three dated records, three rows.
    assert_eq!(
        timeline(&out).len(),
        3,
        "boot plus two logins; the format signature is not a dated event"
    );
    assert_eq!(num(st, "bookkeeping_records"), Some(1));
    assert_eq!(
        num(st, "records_without_usable_time"),
        Some(0),
        "the signature record produces no timeline row because it describes no \
         event, not because its time could not be read"
    );
}
