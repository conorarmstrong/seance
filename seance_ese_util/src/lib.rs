#![forbid(unsafe_code)]
//! Shared machinery for reading Microsoft ESE (Extensible Storage Engine)
//! databases.
//!
//! Windows keeps several forensically important stores in ESE — SRUM's
//! `SRUDB.dat`, User Access Logging's `SUM\*.mdb`, `Windows.edb`,
//! `WebCacheV01.dat` — and every reader of one needs the same three things:
//! a way to find a column by name, a way to coerce a cell into a number or a
//! timestamp without inventing one, and a record of what the walk could not
//! read.
//!
//! This crate exists because the second reader was about to copy the first.
//! The SRUM parser had all of it; the SUM parser needed all of it; and the
//! consolidation note in `ROADMAP.md` is explicit that a drifting copy of an
//! honesty contract is how a court document ends up with counts that read as
//! exact when they are not. Extracting it was cheaper than reconciling two
//! versions later.
//!
//! # The honesty contract
//!
//! [`WalkStatus`] is the important type here, not the conversions. Every walk
//! over an ESE table can fail in four ways that all look identical in the
//! output — rows the engine refuses to decode, a column this build expects and
//! the table does not have, a cell that will not decode, and a table that could
//! not be opened at all. Each of those turns into a *smaller number* in a
//! report, and a smaller number is an affirmative claim: "this application
//! never ran", "this account never connected". The walk has to carry what it
//! could not read, or the count it publishes cannot be trusted as a count.

use chrono::{DateTime, Utc};
use libesedb::{Record, Table, Value};
use std::io;

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
pub const FILETIME_EPOCH_DIFF: u64 = 11_644_473_600;

/// What one table walk could NOT read.
///
/// Every walk skips rows the ESE layer will not hand over, and returns an empty
/// result when the column list or the record iterator cannot be opened at all.
/// Both are invisible in the output unless carried: a table from which 4 of
/// 40,000 rows were recovered otherwise publishes those 4 as the machine's
/// complete history, and a table that could not be opened publishes nothing at
/// all — exactly like a table with no rows.
///
/// What an examiner learns from this: how many rows were lost, and whether the
/// walk started. What a wrong answer looks like without it: "this application
/// never ran", drawn from a partial recovery carrying no sign of being partial.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WalkStatus {
    /// Rows the ESE layer refused to decode. They are absent from the results.
    pub rows_skipped: usize,
    /// Set when the walk could not begin: the column list ("columns") or the
    /// record iterator ("records") would not open. An empty result then says
    /// nothing about the table's contents.
    pub unreadable: Option<&'static str>,
    /// Columns this build expects that the table does not carry. Every row then
    /// reports 0 for them, which reads as "this application sent no bytes" when
    /// the truth is that the figure was never recorded here.
    pub missing_columns: Vec<&'static str>,
    /// Individual cell values that could not be decoded and were published as 0.
    pub values_defaulted: usize,
}

impl WalkStatus {
    /// True when everything the table holds was decoded.
    pub fn is_complete(&self) -> bool {
        self.rows_skipped == 0
            && self.unreadable.is_none()
            && self.missing_columns.is_empty()
            && self.values_defaulted == 0
    }

    /// The stable `content_incomplete_reason` for this walk, or `None` when the
    /// walk was complete.
    pub fn reason(&self) -> Option<&'static str> {
        if self.is_complete() {
            None
        } else {
            Some("unresolved_structure")
        }
    }

    /// A walk that could not begin. `what` is "columns" or "records".
    pub fn unreadable(what: &'static str) -> Self {
        Self {
            unreadable: Some(what),
            ..Self::default()
        }
    }
}

/// Convert a FILETIME (100-ns intervals since 1601-01-01) to `DateTime<Utc>`.
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < FILETIME_EPOCH_DIFF {
        return None;
    }
    let unix_seconds = seconds - FILETIME_EPOCH_DIFF;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(unix_seconds as i64, nanos)
}

/// Convert a `Value` to a `DateTime` if it is a FILETIME/DateTime type.
///
/// A FILETIME counts 100 ns ticks since 1601 and is unsigned. A negative value
/// in a signed column is corrupt, and casting its bits to `u64` turns it into a
/// timestamp thousands of years in the future that passes every epoch check — a
/// row dated 30828 AD reported as a real moment of activity. Negative ticks are
/// refused so the row carries no timestamp at all.
pub fn value_to_datetime(val: &Value) -> Option<DateTime<Utc>> {
    let ticks = match val {
        Value::DateTime(ft) => return filetime_to_datetime(*ft),
        Value::I64(v) => *v,
        Value::Currency(v) => *v,
        _ => return None,
    };
    if ticks < 0 {
        return None;
    }
    filetime_to_datetime(ticks as u64)
}

/// Extract an unsigned integer from a `Value`.
///
/// A negative signed value is NOT reinterpreted: casting -1 to `u64` publishes
/// 18446744073709551615 bytes of network traffic as though the database said
/// so. A counter that cannot be read as a non-negative number is unknown, and
/// the caller omits the field rather than state a figure the evidence does not
/// support (B7-032).
pub fn value_to_u64(val: &Value) -> Option<u64> {
    if let Some(v) = val.to_u64() {
        return Some(v);
    }
    if let Some(v) = val.to_u32() {
        return Some(v as u64);
    }
    if let Some(v) = val.to_i64() {
        return u64::try_from(v).ok();
    }
    if let Some(v) = val.to_i32() {
        return u64::try_from(v).ok();
    }
    None
}

/// Column names by index.
pub fn get_column_names(table: &Table) -> io::Result<Vec<String>> {
    let count = table.count_columns()?;
    let mut names = Vec::with_capacity(count as usize);
    for i in 0..count {
        let col = table.column(i)?;
        names.push(col.name()?);
    }
    Ok(names)
}

/// Index of a column by name, case-insensitively.
pub fn find_column(columns: &[String], name: &str) -> Option<usize> {
    columns.iter().position(|c| c.eq_ignore_ascii_case(name))
}

/// Find a column and record its absence on the walk status.
///
/// A column this build expects that the table does not carry makes every row
/// report zero for it. Zero bytes sent, zero accesses by an account, are
/// affirmative claims about the machine; the walk has to say when it is
/// publishing them because the figure was never there to read.
pub fn column(columns: &[String], name: &'static str, status: &mut WalkStatus) -> Option<usize> {
    let idx = find_column(columns, name);
    if idx.is_none() {
        status.missing_columns.push(name);
    }
    idx
}

/// Read a single value from a record at the given column index.
pub fn read_value(record: &Record, index: usize) -> Option<Value> {
    record.value(index as i32).ok()
}

/// Read a counter column, substituting 0 only when the cell will not decode,
/// and counting every substitution.
///
/// A column the table does not carry at all is NOT counted here: [`column`]
/// already recorded it once as a fact about the table. Counting it again per row
/// turns one missing column into one "value defaulted" for every row in the
/// database, which buries the rows where a cell really did fail to decode.
pub fn counter(record: &Record, idx: Option<usize>, status: &mut WalkStatus) -> u64 {
    let Some(i) = idx else {
        return 0;
    };
    match read_value(record, i).as_ref().and_then(value_to_u64) {
        Some(v) => v,
        None => {
            status.values_defaulted += 1;
            0
        }
    }
}

/// Read a 32-bit identifier column, counting the same way as [`counter`].
pub fn id32(record: &Record, idx: Option<usize>, status: &mut WalkStatus) -> u32 {
    let Some(i) = idx else {
        return 0;
    };
    match read_value(record, i).and_then(|v| v.to_u32()) {
        Some(v) => v,
        None => {
            status.values_defaulted += 1;
            0
        }
    }
}

/// Read a text column, or `None` when the column is absent or will not decode.
///
/// Returns `None` rather than an empty string: an account name that could not
/// be read is not an account with a blank name, and a report that renders the
/// two identically has lost the difference between "nobody" and "unknown".
/// Absence is not counted as a defaulted value — the caller omits the field,
/// which states nothing, rather than substituting one.
pub fn text(record: &Record, idx: Option<usize>) -> Option<String> {
    let value = read_value(record, idx?)?;
    let decoded = match &value {
        Value::Text(s) | Value::LargeText(s) => s.clone(),
        Value::Binary(b) | Value::LargeBinary(b) => try_decode_utf16le(b)?,
        _ => return None,
    };
    let trimmed = decoded.trim_end_matches('\0').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Decode bytes as a UTF-16LE string, or `None` if they do not look like one.
pub fn try_decode_utf16le(data: &[u8]) -> Option<String> {
    if data.len() < 2 || !data.len().is_multiple_of(2) {
        return None;
    }
    let u16_data: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0)
        .collect();
    if u16_data.is_empty() {
        return None;
    }
    let s = String::from_utf16_lossy(&u16_data);
    // Heuristic: if the string is mostly printable, it is likely valid.
    if s.chars().all(|c| {
        c.is_ascii_graphic()
            || c == ' '
            || c == '\\'
            || c == '/'
            || c == '.'
            || c == '-'
            || c == '_'
            || c == ':'
            || c == '{'
            || c == '}'
    }) {
        Some(s)
    } else {
        None
    }
}

/// Format a Windows SID from its binary form.
pub fn format_sid(data: &[u8]) -> String {
    if data.len() < 8 {
        return hex::encode(data);
    }
    let revision = data[0];
    let sub_authority_count = data[1] as usize;
    let authority =
        u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);

    let mut sid = format!("S-{}-{}", revision, authority);
    for i in 0..sub_authority_count {
        let offset = 8 + i * 4;
        if offset + 4 > data.len() {
            break;
        }
        let sub = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        sid.push_str(&format!("-{}", sub));
    }
    sid
}

/// Format a Windows GUID from its binary form (mixed-endian, as stored).
///
/// UAL keys almost everything on a role GUID, and a role GUID rendered as raw
/// hex is not something an examiner can match against Microsoft's published
/// list of server roles.
pub fn format_guid(data: &[u8]) -> Option<String> {
    if data.len() < 16 {
        return None;
    }
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        u16::from_le_bytes([data[4], data[5]]),
        u16::from_le_bytes([data[6], data[7]]),
        data[8],
        data[9],
        data[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_filetime_is_not_a_timestamp() {
        // 1601-01-01 is the epoch, not a moment anything happened.
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn a_filetime_before_the_unix_epoch_is_refused() {
        assert!(filetime_to_datetime(1).is_none());
    }

    #[test]
    fn a_known_filetime_decodes() {
        // 2020-01-01T00:00:00Z
        let ft = (1_577_836_800u64 + FILETIME_EPOCH_DIFF) * 10_000_000;
        let dt = filetime_to_datetime(ft).expect("decodes");
        assert_eq!(dt.timestamp(), 1_577_836_800);
    }

    #[test]
    fn a_negative_tick_count_is_refused_rather_than_reinterpreted() {
        // The bug this guards: -1 as u64 is a timestamp in 30828 AD that passes
        // every epoch check and reads as a real moment of activity.
        assert!(value_to_datetime(&Value::I64(-1)).is_none());
        assert!(value_to_u64(&Value::I64(-1)).is_none());
    }

    #[test]
    fn a_walk_that_read_everything_has_nothing_to_disclose() {
        let clean = WalkStatus::default();
        assert!(clean.is_complete());
        assert!(clean.reason().is_none());
    }

    #[test]
    fn each_way_a_walk_can_fall_short_marks_it_incomplete() {
        for status in [
            WalkStatus {
                rows_skipped: 1,
                ..Default::default()
            },
            WalkStatus {
                values_defaulted: 1,
                ..Default::default()
            },
            WalkStatus {
                missing_columns: vec!["X"],
                ..Default::default()
            },
            WalkStatus::unreadable("columns"),
        ] {
            assert!(
                !status.is_complete(),
                "{status:?} must not read as complete"
            );
            assert!(status.reason().is_some());
        }
    }

    #[test]
    fn a_sid_formats_to_its_canonical_string() {
        // S-1-5-18, the LocalSystem account.
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(format_sid(&sid), "S-1-5-18");
    }

    #[test]
    fn a_guid_formats_mixed_endian() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
            0x33, 0x44,
        ];
        assert_eq!(
            format_guid(&bytes).expect("16 bytes"),
            "12345678-1234-5678-9abc-def011223344"
        );
    }

    #[test]
    fn a_short_guid_is_refused_rather_than_padded() {
        assert!(format_guid(&[0u8; 8]).is_none());
    }

    // ─── Relocated with the code they cover ──────────────────────────────────
    // These came from `seance_plugin_srum::tables` when this crate was
    // extracted. They stayed with the functions rather than with the plugin,
    // so the SUM reader inherits their coverage instead of re-earning it.

    #[test]
    fn a_walk_that_never_started_is_not_an_empty_table() {
        // Zero rows skipped, zero rows returned -- indistinguishable from a
        // table with no rows unless `unreadable` says the walk never began.
        let s = WalkStatus::unreadable("records");
        assert_eq!(s.rows_skipped, 0);
        assert!(!s.is_complete());
        assert_eq!(s.unreadable, Some("records"));
    }

    #[test]
    fn test_filetime_to_datetime() {
        // 2021-01-01 00:00:00 UTC
        let dt = filetime_to_datetime(132_539_328_000_000_000u64).unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2021-01-01");
    }

    #[test]
    fn test_format_sid() {
        let sid_bytes: Vec<u8> = vec![
            1, 5, // revision=1, sub_authority_count=5
            0, 0, 0, 0, 0, 5, // authority=5 (NT Authority)
            21, 0, 0, 0, // sub-auth 1 = 21
            0x39, 0x05, 0x00, 0x00, // sub-auth 2 = 1337
            0xe8, 0x03, 0x00, 0x00, // sub-auth 3 = 1000
            0x01, 0x00, 0x00, 0x00, // sub-auth 4 = 1
            0xe9, 0x03, 0x00, 0x00, // sub-auth 5 = 1001
        ];
        assert_eq!(format_sid(&sid_bytes), "S-1-5-21-1337-1000-1-1001");
    }

    #[test]
    fn test_try_decode_utf16le() {
        let data = vec![0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        assert_eq!(try_decode_utf16le(&data), Some("test".to_string()));
    }

    #[test]
    fn test_try_decode_utf16le_with_null() {
        let data = vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00, 0x43, 0x00];
        assert_eq!(try_decode_utf16le(&data), Some("AB".to_string()));
    }

    /// B7-032: a negative counter is unknown, not a ~2^64 figure. Casting it
    /// published 18 quintillion bytes of network traffic as if the database had
    /// said so.
    #[test]
    fn a_negative_counter_is_unknown_not_a_huge_unsigned() {
        assert_eq!(value_to_u64(&Value::I32(-1)), None);
        assert_eq!(value_to_u64(&Value::I64(-4096)), None);
        // Zero and positives are unaffected.
        assert_eq!(value_to_u64(&Value::I64(0)), Some(0));
        assert_eq!(value_to_u64(&Value::I64(i64::MAX)), Some(i64::MAX as u64));
        assert_eq!(value_to_u64(&Value::I32(42)), Some(42));
        assert_eq!(value_to_u64(&Value::U32(100)), Some(100));
        assert_eq!(value_to_u64(&Value::I64(999)), Some(999));
    }

    #[test]
    fn a_negative_signed_timestamp_yields_no_date_rather_than_a_far_future_one() {
        // -1 reinterpreted as an unsigned FILETIME is year 30828: it clears the
        // epoch check and would be reported as a real moment of activity.
        assert!(value_to_datetime(&Value::I64(-1)).is_none());
        assert!(value_to_datetime(&Value::Currency(-1)).is_none());

        // A genuine FILETIME in a signed column still decodes.
        let dt = value_to_datetime(&Value::I64(132_539_328_000_000_000))
            .expect("a valid FILETIME must still decode");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2021-01-01");
    }
}
