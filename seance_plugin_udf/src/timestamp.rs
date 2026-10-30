//! ECMA-167 1/7.3 timestamps (12 bytes): type-and-timezone, year, month, day,
//! hour, minute, second, centiseconds, hundreds of microseconds, microseconds.

/// A decoded timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// RFC 3339. With an offset when the disc recorded one; without one (a
    /// local wall-clock time) when it did not.
    pub text: String,
    /// False when the timestamp says its timezone is unspecified (-2047):
    /// the time is then not placed on an absolute timeline.
    pub timezone_specified: bool,
}

/// Decode a 12-byte timestamp. `None` for an all-zero or out-of-range one.
pub fn decode(ts: &[u8]) -> Option<Decoded> {
    let ts = ts.get(..12)?;
    let tt = u16::from_le_bytes([ts[0], ts[1]]);
    let kind = tt >> 12;
    // The offset is a 12-bit two's-complement count of minutes.
    let raw = (tt & 0x0FFF) as i16;
    let offset_minutes = if raw & 0x0800 != 0 { raw - 0x1000 } else { raw };
    let year = i16::from_le_bytes([ts[2], ts[3]]) as i32;
    let date = chrono::NaiveDate::from_ymd_opt(year, ts[4] as u32, ts[5] as u32)?;
    let micros = ts[9] as u32 * 10_000 + ts[10] as u32 * 100 + ts[11] as u32;
    let time =
        chrono::NaiveTime::from_hms_micro_opt(ts[6] as u32, ts[7] as u32, ts[8] as u32, micros)?;
    let naive = chrono::NaiveDateTime::new(date, time);
    let fmt = if micros == 0 {
        "%Y-%m-%dT%H:%M:%S"
    } else {
        "%Y-%m-%dT%H:%M:%S%.6f"
    };
    // Type 1 carries a local offset; -2047 means "not specified". Type 0 is
    // UTC. Type 2 ("by agreement") has no defined zone.
    let offset = match kind {
        0 => Some(0),
        1 if offset_minutes != -2047 && offset_minutes.abs() <= 1440 => Some(offset_minutes),
        _ => None,
    };
    match offset {
        Some(m) => {
            let tz = chrono::FixedOffset::east_opt(m as i32 * 60)?;
            let dt = chrono::TimeZone::from_local_datetime(&tz, &naive).single()?;
            let text = if micros == 0 {
                dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
            } else {
                dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
            };
            Some(Decoded {
                text,
                timezone_specified: true,
            })
        }
        None => Some(Decoded {
            text: naive.format(fmt).to_string(),
            timezone_specified: false,
        }),
    }
}

#[cfg(test)]
pub(crate) fn encode(
    year: i16,
    mon: u8,
    day: u8,
    h: u8,
    m: u8,
    s: u8,
    tz_minutes: i16,
) -> [u8; 12] {
    let tz = (tz_minutes as u16) & 0x0FFF;
    let tt = (1u16 << 12) | tz;
    let mut b = [0u8; 12];
    b[0..2].copy_from_slice(&tt.to_le_bytes());
    b[2..4].copy_from_slice(&year.to_le_bytes());
    b[4] = mon;
    b[5] = day;
    b[6] = h;
    b[7] = m;
    b[8] = s;
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_with_offset() {
        let d = decode(&encode(2024, 5, 6, 7, 8, 9, 60)).unwrap();
        assert_eq!(d.text, "2024-05-06T07:08:09+01:00");
        assert!(d.timezone_specified);
    }

    #[test]
    fn negative_offset_and_fraction() {
        let mut b = encode(2001, 12, 31, 23, 59, 58, -300);
        b[9] = 12; // centiseconds
        b[10] = 3; // hundreds of microseconds
        b[11] = 4; // microseconds
        let d = decode(&b).unwrap();
        assert_eq!(d.text, "2001-12-31T23:59:58.120304-05:00");
    }

    #[test]
    fn unspecified_timezone_is_not_invented() {
        let d = decode(&encode(2010, 1, 2, 3, 4, 5, -2047)).unwrap();
        assert_eq!(d.text, "2010-01-02T03:04:05");
        assert!(!d.timezone_specified);
    }

    #[test]
    fn zero_timestamp_is_none() {
        assert!(decode(&[0u8; 12]).is_none());
    }
}
