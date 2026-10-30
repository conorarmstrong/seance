//! SQLite record decoding: varints, serial types, record header parsing.
//!
//! Ported from the vendored Go reference `internal/parser/parser.go`
//! (`readVarint`, `parseRecord`, `parseSerialType`) with bounds checks so the
//! decoder never panics on malformed input.

/// A decoded SQLite value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Reads a SQLite variable-length integer at `offset`.
///
/// Returns `(value, bytes_consumed)`. SQLite varints are 1..=9 bytes; the first
/// eight bytes contribute 7 bits each and the ninth byte contributes 8 bits.
/// Never reads past `data.len()`; a truncated varint returns what was read.
pub fn read_varint(data: &[u8], offset: usize) -> (i64, usize) {
    let mut result: u64 = 0;
    let mut i = 0;
    while i < 9 {
        let idx = offset + i;
        if idx >= data.len() {
            return (result as i64, i);
        }
        let b = data[idx];
        if i == 8 {
            result = (result << 8) | b as u64;
            return (result as i64, 9);
        }
        result = (result << 7) | (b & 0x7f) as u64;
        if b < 0x80 {
            return (result as i64, i + 1);
        }
        i += 1;
    }
    (result as i64, 9)
}

fn int24(data: &[u8]) -> i64 {
    if data.len() < 3 {
        return 0;
    }
    let mut v = (data[0] as i64) << 16 | (data[1] as i64) << 8 | (data[2] as i64);
    if v & 0x0080_0000 != 0 {
        v |= !0x00FF_FFFFi64;
    }
    v
}

fn int48(data: &[u8]) -> i64 {
    if data.len() < 6 {
        return 0;
    }
    let mut v = (data[0] as i64) << 40
        | (data[1] as i64) << 32
        | (data[2] as i64) << 24
        | (data[3] as i64) << 16
        | (data[4] as i64) << 8
        | (data[5] as i64);
    if v & 0x0000_8000_0000_0000 != 0 {
        v |= !0x0000_FFFF_FFFF_FFFFi64;
    }
    v
}

/// Decodes a single value given its serial type. Returns `(value, byte_length)`.
///
/// Serial types (per the SQLite file format):
/// 0=NULL, 1..=6 signed ints (1/2/3/4/6/8 bytes), 7=float64, 8=const 0, 9=const 1,
/// N>=12 even = BLOB of `(N-12)/2` bytes, N>=13 odd = TEXT of `(N-13)/2` bytes.
pub fn parse_serial_type(data: &[u8], offset: usize, serial: i64) -> (Value, usize) {
    if offset > data.len() {
        return (Value::Null, 0);
    }
    let avail = data.len() - offset;
    match serial {
        s if s >= 12 && s % 2 == 0 => {
            let length = ((s - 12) / 2) as usize;
            let take = length.min(avail);
            (Value::Blob(data[offset..offset + take].to_vec()), take)
        }
        s if s >= 13 && s % 2 == 1 => {
            let length = ((s - 13) / 2) as usize;
            let take = length.min(avail);
            let bytes = &data[offset..offset + take];
            if let Some(txt) = detect_and_decode_utf16(bytes) {
                return (Value::Text(txt), take);
            }
            (
                Value::Text(String::from_utf8_lossy(bytes).into_owned()),
                take,
            )
        }
        0 => (Value::Null, 0),
        1 => {
            if avail < 1 {
                return (Value::Int(0), 0);
            }
            (Value::Int(data[offset] as i8 as i64), 1)
        }
        2 => {
            if avail < 2 {
                return (Value::Int(0), 0);
            }
            let v = i16::from_be_bytes([data[offset], data[offset + 1]]);
            (Value::Int(v as i64), 2)
        }
        3 => {
            if avail < 3 {
                return (Value::Int(0), 0);
            }
            (Value::Int(int24(&data[offset..offset + 3])), 3)
        }
        4 => {
            if avail < 4 {
                return (Value::Int(0), 0);
            }
            let v = i32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            (Value::Int(v as i64), 4)
        }
        5 => {
            if avail < 6 {
                return (Value::Int(0), 0);
            }
            (Value::Int(int48(&data[offset..offset + 6])), 6)
        }
        6 => {
            if avail < 8 {
                return (Value::Int(0), 0);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[offset..offset + 8]);
            (Value::Int(i64::from_be_bytes(b)), 8)
        }
        7 => {
            if avail < 8 {
                return (Value::Float(0.0), 0);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[offset..offset + 8]);
            (Value::Float(f64::from_be_bytes(b)), 8)
        }
        8 => (Value::Int(0), 0),
        9 => (Value::Int(1), 0),
        _ => (Value::Null, 0),
    }
}

/// Maximum plausible column count for a real record. Records claiming more are
/// treated as corrupt garbage (matches the reference's 200-column guard).
const MAX_COLUMNS: usize = 200;

/// Body byte length a serial type consumes (0 for NULL/const, N for ints/blobs/
/// text). Reserved serial types 10/11 and negatives return `None` (not a valid
/// column), which the freeblock reconstructor uses to reject a bad alignment.
pub fn serial_body_len(serial: i64) -> Option<usize> {
    match serial {
        0 | 8 | 9 => Some(0),
        1 => Some(1),
        2 => Some(2),
        3 => Some(3),
        4 => Some(4),
        5 => Some(6),
        6 | 7 => Some(8),
        10 | 11 => None,
        s if s >= 12 && s % 2 == 0 => Some(((s - 12) / 2) as usize),
        s if s >= 13 => Some(((s - 13) / 2) as usize),
        _ => None, // negative
    }
}

/// Decodes a record payload into a list of [`Value`]s plus any corruption notes.
///
/// Resilient to a header length that overruns the payload, a header truncated
/// mid serial-type, and values that extend past the payload end. Ported from the
/// Go reference `parseRecord`.
pub fn parse_record(payload: &[u8], payload_length: usize) -> (Vec<Value>, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    if payload.is_empty() {
        return (Vec::new(), vec!["empty payload".to_string()]);
    }
    let (header_len_raw, consumed) = read_varint(payload, 0);
    let mut header_len = header_len_raw as usize;
    if header_len > payload_length {
        notes.push("header length exceeds payload length".to_string());
        header_len = payload_length;
    }
    if header_len > payload.len() {
        notes.push("header length exceeds available data".to_string());
        header_len = payload.len();
    }

    let mut header_offset = consumed;
    let mut bytes_read = consumed;
    let mut serial_types: Vec<i64> = Vec::new();

    while bytes_read < header_len && header_offset < payload.len() {
        if serial_types.len() >= MAX_COLUMNS {
            return (
                Vec::new(),
                vec!["record exceeds maximum column count (likely corrupt)".to_string()],
            );
        }
        let (serial, used) = read_varint(payload, header_offset);
        if used == 0 {
            break;
        }
        serial_types.push(serial);
        header_offset += used;
        bytes_read += used;
    }
    if bytes_read < header_len {
        notes.push("header truncated before all serial types read".to_string());
    }

    // NOTE: the reference `parseRecord` applies an "off-by-one header length"
    // heuristic that drops the last serial type when it looks like printable
    // ASCII. That heuristic misfires on perfectly valid records whose final
    // column is medium-length TEXT (its serial byte lands in the printable
    // range), corrupting e.g. sqlite_master rows. It is deliberately omitted
    // here; genuine corruption is handled by bounds checks and the carver.

    let mut values: Vec<Value> = Vec::with_capacity(serial_types.len());
    let mut value_offset = header_offset;
    for (idx, serial) in serial_types.iter().enumerate() {
        if value_offset > payload.len() {
            notes.push("value data truncated".to_string());
            for _ in idx..serial_types.len() {
                values.push(Value::Null);
            }
            break;
        }
        let (value, length) = parse_serial_type(payload, value_offset, *serial);
        if value_offset + length > payload.len() {
            notes.push("value extends beyond payload".to_string());
        }
        values.push(value);
        value_offset += length;
    }
    (values, notes)
}

// ---------------------------------------------------------------------------
// UTF-16 salvage (ported from carving.go DetectAndDecodeUTF16).
// ---------------------------------------------------------------------------

/// Attempts to detect and decode UTF-16 (LE or BE) text. Returns `None` when the
/// bytes are not convincingly UTF-16.
pub fn detect_and_decode_utf16(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    if is_valid_utf16le(data) {
        let decoded = decode_utf16(data, true);
        if is_likely_text(&decoded) {
            return Some(decoded);
        }
    }
    if is_valid_utf16be(data) {
        let decoded = decode_utf16(data, false);
        if is_likely_text(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn is_valid_utf16le(data: &[u8]) -> bool {
    if !data.len().is_multiple_of(2) {
        return false;
    }
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        return true;
    }
    let mut null_count = 0;
    let mut i = 1;
    while i < data.len() && i < 100 {
        if data[i] == 0 {
            null_count += 1;
        }
        i += 2;
    }
    null_count > data.len() / 4
}

fn is_valid_utf16be(data: &[u8]) -> bool {
    if !data.len().is_multiple_of(2) {
        return false;
    }
    if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF {
        return true;
    }
    let mut null_count = 0;
    let mut i = 0;
    while i < data.len() && i < 100 {
        if data[i] == 0 {
            null_count += 1;
        }
        i += 2;
    }
    null_count > data.len() / 4
}

fn decode_utf16(data: &[u8], little_endian: bool) -> String {
    let mut d = data;
    if !d.len().is_multiple_of(2) {
        d = &d[..d.len() - 1];
    }
    let mut start = 0;
    if d.len() >= 2
        && ((little_endian && d[0] == 0xFF && d[1] == 0xFE)
            || (!little_endian && d[0] == 0xFE && d[1] == 0xFF))
    {
        start = 2;
    }
    let mut units: Vec<u16> = Vec::with_capacity((d.len() - start) / 2);
    let mut i = start;
    while i + 1 < d.len() + 1 && i < d.len() {
        if i + 2 > d.len() {
            break;
        }
        let u = if little_endian {
            u16::from_le_bytes([d[i], d[i + 1]])
        } else {
            u16::from_be_bytes([d[i], d[i + 1]])
        };
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Returns true when `s` is >80% printable, i.e. plausibly human-readable text.
pub fn is_likely_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut printable = 0usize;
    let mut total = 0usize;
    for c in s.chars() {
        total += 1;
        let cp = c as u32;
        if (32..=126).contains(&cp) || cp >= 160 || c == '\n' || c == '\r' || c == '\t' {
            printable += 1;
        }
    }
    if total == 0 {
        return false;
    }
    (printable as f64) / (total as f64) > 0.8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_single_byte() {
        assert_eq!(read_varint(&[0x00], 0), (0, 1));
        assert_eq!(read_varint(&[0x7f], 0), (127, 1));
    }

    #[test]
    fn varint_two_byte() {
        // 0x81 0x00 -> 128
        assert_eq!(read_varint(&[0x81, 0x00], 0), (128, 2));
    }

    #[test]
    fn varint_nine_byte_uses_full_last_byte() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let (v, n) = read_varint(&data, 0);
        assert_eq!(n, 9);
        assert_eq!(v, -1);
    }

    #[test]
    fn varint_truncated_does_not_panic() {
        // Continuation bit set but no more bytes.
        let (_v, n) = read_varint(&[0x81], 0);
        assert_eq!(n, 1);
    }

    #[test]
    fn serial_types_cover_all_variants() {
        assert_eq!(parse_serial_type(&[], 0, 0), (Value::Null, 0));
        assert_eq!(parse_serial_type(&[0x2a], 0, 1), (Value::Int(42), 1));
        assert_eq!(parse_serial_type(&[0xff], 0, 1), (Value::Int(-1), 1));
        assert_eq!(parse_serial_type(&[], 0, 8), (Value::Int(0), 0));
        assert_eq!(parse_serial_type(&[], 0, 9), (Value::Int(1), 0));
        // text serial 13 + 2*3 = 19 -> 3 chars "abc"
        assert_eq!(
            parse_serial_type(b"abc", 0, 19),
            (Value::Text("abc".to_string()), 3)
        );
        // blob serial 12 + 2*2 = 16 -> 2 bytes
        assert_eq!(
            parse_serial_type(&[1, 2, 3], 0, 16),
            (Value::Blob(vec![1, 2]), 2)
        );
    }

    #[test]
    fn record_roundtrip_simple() {
        // header_len=4, serials: null(0), text 3 chars (19), int8 (1)
        // payload: [04][00][13][01]['a']['b']['c'][0x2a]
        let payload = [0x04, 0x00, 0x13, 0x01, b'a', b'b', b'c', 0x2a];
        let (vals, notes) = parse_record(&payload, payload.len());
        assert!(notes.is_empty(), "unexpected notes: {:?}", notes);
        assert_eq!(vals.len(), 3);
        assert_eq!(vals[0], Value::Null);
        assert_eq!(vals[1], Value::Text("abc".to_string()));
        assert_eq!(vals[2], Value::Int(42));
    }

    #[test]
    fn record_truncated_header_is_noted_not_panicked() {
        let payload = [0x09, 0x13]; // claims 9-byte header, only 2 bytes present
        let (_vals, notes) = parse_record(&payload, payload.len());
        assert!(!notes.is_empty());
    }
}
