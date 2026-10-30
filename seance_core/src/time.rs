//! Shared forensic time-base conversions.
//!
//! Windows FILETIME and Apple Cocoa/Core-Data timestamps were each reimplemented
//! in ~9 and ~4 plugins respectively, with divergent zero/pre-epoch handling.
//! This module is the single canonical implementation. Every converter returns
//! `Option` and rejects the "unset" sentinel (0, and negative/pre-epoch values),
//! so an unset field is honestly omitted rather than surfaced as a fabricated
//! 1601/1970/2001 wall-clock — a forensic correctness invariant.

use chrono::{DateTime, Utc};

/// Seconds between the Windows FILETIME epoch (1601-01-01) and Unix (1970-01-01).
const FILETIME_EPOCH_DIFF: u64 = 11_644_473_600;

/// Unix seconds for 2001-01-01 — the Apple / Cocoa / Core Data reference epoch.
pub const COCOA_EPOCH: i64 = 978_307_200;

/// Cocoa integer values larger than this are nanoseconds since 2001 (iOS 11+
/// message stores), not whole seconds.
const COCOA_NS_THRESHOLD: i64 = 1_000_000_000_000;

/// Seconds between the Unix epoch and 10000-01-01, the first instant RFC 3339
/// cannot express: it mandates a four-digit year.
///
/// Windows uses a far-future FILETIME as a "never" sentinel -- `0x7FFF…FF` is
/// what it stores for an account that never expires, and it is on the `Guest`
/// account of the real `SAM` hive in this repository. Converted
/// unconditionally that gave `+30828-09-14T02:48:05.477580700+00:00` out of a
/// function named `filetime_to_rfc3339`, which is not RFC 3339 and is not a
/// date anything recorded. So a value past this bound is treated as the
/// sentinel it is, and the caller omits the field.
const UNIX_SECONDS_AT_YEAR_10000: i64 = 253_402_300_800;

/// Windows FILETIME (100 ns ticks since 1601-01-01) → `DateTime<Utc>`, preserving
/// sub-second precision. `None` for the 0/unset sentinel, a pre-1970 value, or a
/// far-future "never" sentinel.
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < FILETIME_EPOCH_DIFF {
        return None;
    }
    if seconds - FILETIME_EPOCH_DIFF >= UNIX_SECONDS_AT_YEAR_10000 as u64 {
        return None;
    }
    let unix_seconds = (seconds - FILETIME_EPOCH_DIFF) as i64;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(unix_seconds, nanos)
}

/// Windows FILETIME → Unix seconds. `None` for the unset/pre-epoch sentinel.
pub fn filetime_to_unix_secs(filetime: u64) -> Option<i64> {
    filetime_to_datetime(filetime).map(|dt| dt.timestamp())
}

/// Windows FILETIME → RFC 3339 string. `None` for the unset/invalid sentinel —
/// callers omit the field rather than storing an empty string.
pub fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    filetime_to_datetime(filetime).map(|dt| dt.to_rfc3339())
}

/// Microseconds between the 1601 epoch and the Unix epoch. Chrome/WebKit store
/// timestamps as microseconds since 1601-01-01 (the FILETIME epoch, but in µs
/// rather than 100 ns ticks).
const WEBKIT_EPOCH_DIFF_US: i64 = 11_644_473_600_000_000;

/// Chrome / WebKit timestamp (microseconds since 1601-01-01) → Unix seconds.
/// `None` for the 0/unset sentinel or a pre-1970 value.
///
/// Chrome's `visits.visit_time`, `urls.last_visit_time`, `downloads.start_time`
/// and the Chrome cache all use this base. It was previously reimplemented
/// per-plugin (`webkit_to_unix`, `chrome_time_to_unix`) with divergent guards —
/// one rejected only exactly 0, the other rejected anything below the epoch
/// difference, so the same input could convert in one plugin and be dropped in
/// another. This is the single implementation.
pub fn webkit_us_to_unix_secs(webkit_us: i64) -> Option<i64> {
    webkit_us_to_unix_us(webkit_us).map(|us| us.div_euclid(1_000_000))
}

/// Chrome / WebKit timestamp → Unix **microseconds**, preserving sub-second
/// precision. `None` for the 0/unset sentinel or a pre-1970 value.
pub fn webkit_us_to_unix_us(webkit_us: i64) -> Option<i64> {
    if webkit_us <= 0 || webkit_us < WEBKIT_EPOCH_DIFF_US {
        return None;
    }
    Some(webkit_us - WEBKIT_EPOCH_DIFF_US)
}

/// Firefox **PRTime** (microseconds since the *Unix* epoch — note the different
/// base to WebKit) → Unix seconds. `None` for the 0/negative unset sentinel.
pub fn prtime_to_unix_secs(prtime_us: i64) -> Option<i64> {
    if prtime_us <= 0 {
        return None;
    }
    Some(prtime_us.div_euclid(1_000_000))
}

/// Cocoa / Core Data timestamp in **seconds** since 2001-01-01, as stored in a
/// SQLite REAL column → (Unix seconds, sub-second nanos). `None` for the
/// 0/negative "unset" sentinel, for a non-finite value, and for a magnitude
/// that cannot be shifted onto the Unix epoch.
///
/// The float stores (WhatsApp `ZMESSAGEDATE`, Safari `visit_time`, call
/// history, iOS calendar/notes/reminders, macOS CFAbsoluteTime) genuinely carry
/// a fraction, and two records inside the same second are ordered only by it.
/// Truncating to whole seconds destroys that ordering, which is why this is the
/// **only** entry point for a Cocoa float — the same sub-second contract
/// [`cocoa_to_unix_nanos`] already gives integer stores.
///
/// A whole-seconds `cocoa_secs_to_unix` used to sit beside it and was what every
/// call site reached for, so the fraction was decoded correctly here and thrown
/// away one line later. It is gone rather than deprecated: a caller that wants
/// seconds takes `.0` from this pair, which keeps the discarding visible at the
/// call site instead of hiding it behind a name.
pub fn cocoa_secs_to_unix_nanos(v: f64) -> Option<(i64, u32)> {
    let (secs, nanos) = unix_secs_f64_to_nanos(v)?;
    // A float too large for i64 is already rejected by the split; the checked
    // add rejects the epoch shift overflowing instead of wrapping into a
    // plausible-looking date.
    Some((secs.checked_add(COCOA_EPOCH)?, nanos))
}

/// A REAL column of **Unix** seconds → (Unix seconds, sub-second nanos). `None`
/// for the 0/negative "unset" sentinel, a non-finite value, and a magnitude that
/// does not fit an `i64`.
///
/// This is the fraction-preserving split [`cocoa_secs_to_unix_nanos`] is built
/// on, exposed because several Apple stores hold one REAL column that is Cocoa
/// seconds on one generation and Unix seconds on another (the iOS PowerLog).
/// Both branches of such a decode must round the fraction identically, or the
/// same event lands on two different instants depending on which generation
/// wrote it.
pub fn unix_secs_f64_to_nanos(v: f64) -> Option<(i64, u32)> {
    // NaN fails both comparisons, so `is_finite` is what rejects it (and the
    // infinities) rather than letting a fabricated 1970/2001 wall-clock through.
    if v <= 0.0 || !v.is_finite() {
        return None;
    }
    let mut secs = v.floor();
    let mut nanos = ((v - secs) * 1_000_000_000.0).round() as i64;
    // The rounding can land exactly on the next second; carry it rather than
    // emitting an out-of-range nanos field.
    if nanos >= 1_000_000_000 {
        secs += 1.0;
        nanos -= 1_000_000_000;
    }
    // Outside i64 the float-to-int cast saturates, which would report a date at
    // the end of time as fact. A value that far out is a misread column.
    if secs >= i64::MAX as f64 {
        return None;
    }
    Some((secs as i64, nanos as u32))
}

/// Cocoa / Core Data integer timestamp that may be **seconds or nanoseconds**
/// since 2001 (iOS 11+ message stores use nanoseconds) → (Unix seconds,
/// sub-second nanos). `None` for the 0/negative sentinel. This is the richer
/// iMessage-style semantics; use it when a store mixes the two encodings.
pub fn cocoa_to_unix_nanos(cocoa_ts: i64) -> Option<(i64, u32)> {
    if cocoa_ts <= 0 {
        return None;
    }
    let (secs, nanos) = if cocoa_ts > COCOA_NS_THRESHOLD {
        (
            cocoa_ts.div_euclid(1_000_000_000),
            cocoa_ts.rem_euclid(1_000_000_000) as u32,
        )
    } else {
        (cocoa_ts, 0)
    };
    Some((secs + COCOA_EPOCH, nanos))
}

/// Cocoa / Core Data integer timestamp (seconds or nanoseconds) → Unix seconds.
/// `None` for the 0/negative sentinel.
pub fn cocoa_to_unix_secs(cocoa_ts: i64) -> Option<i64> {
    cocoa_to_unix_nanos(cocoa_ts).map(|(secs, _)| secs)
}

/// Full-precision Unix **nanoseconds** for a decoded `(seconds, nanos)` pair, or
/// `None` when there is no sub-second part to carry — the whole-seconds field
/// already says it all — or when the product does not fit in an `i64`.
///
/// This is the second half of the sub-second contract: decoding to
/// `(secs, nanos)` only preserves the fraction inside the parser, and a record
/// that publishes the seconds alone has still thrown it away. Parsers therefore
/// emit this beside the whole-second field as `<field>_ns`, which is the key
/// `seance_db` reads to fill `timeline_events.timestamp_subsec_nanos` — it is
/// how the fraction reaches the unified timeline and orders two events inside
/// the same second instead of stopping at the plugin boundary.
pub fn unix_ns(secs: i64, nanos: u32) -> Option<i64> {
    if nanos == 0 {
        return None;
    }
    secs.checked_mul(1_000_000_000)?
        .checked_add(i64::from(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_zero_and_pre_epoch_are_none() {
        assert_eq!(filetime_to_unix_secs(0), None);
        // A FILETIME smaller than the 1601→1970 gap is before the Unix epoch.
        assert_eq!(filetime_to_unix_secs(1), None);
        assert_eq!(filetime_to_datetime(0), None);
        assert_eq!(filetime_to_rfc3339(0), None);
    }

    /// The two documented "never" sentinels must not render as dates.
    ///
    /// `0x7FFFFFFFFFFFFFFF` is what Windows stores for "this account never
    /// expires" -- it is on the `Guest` account of the real SAM hive in this
    /// repository -- and `0xFFFFFFFFFFFFFFFF` is the all-ones form. Converted
    /// unconditionally they gave `+30828-09-14T02:48:05.477580700+00:00` and
    /// `+60056-05-28T05:36:10.955161500+00:00`: strings a function named
    /// `filetime_to_rfc3339` must not return at all, because RFC 3339 mandates
    /// a four-digit year. A field carrying one of these is not recorded, and
    /// the caller must be able to say so.
    #[test]
    fn a_far_future_filetime_is_a_sentinel_and_not_a_date() {
        for ft in [
            0x7FFF_FFFF_FFFF_FFFFu64,
            0xFFFF_FFFF_FFFF_FFFF,
            // The first tick past the last year RFC 3339 can express.
            253_402_300_800 * 10_000_000 + 11_644_473_600 * 10_000_000,
        ] {
            assert_eq!(filetime_to_datetime(ft), None, "{ft:#018x}");
            assert_eq!(filetime_to_rfc3339(ft), None, "{ft:#018x}");
            assert_eq!(filetime_to_unix_secs(ft), None, "{ft:#018x}");
        }
    }

    /// And the year before that boundary still converts, so the guard has not
    /// swallowed a range of real dates.
    #[test]
    fn the_last_four_digit_year_still_converts() {
        // 9999-12-31T23:59:59Z
        let ft = (253_402_300_799 + 11_644_473_600) * 10_000_000;
        assert!(
            filetime_to_rfc3339(ft)
                .expect("9999 is a renderable year")
                .starts_with("9999-12-31T23:59:59"),
            "got {:?}",
            filetime_to_rfc3339(ft)
        );
    }

    #[test]
    fn filetime_known_value() {
        // 2010-01-01T00:00:00Z == FILETIME 129_067_776_000_000_000.
        let ft = 129_067_776_000_000_000u64;
        assert_eq!(filetime_to_unix_secs(ft), Some(1_262_304_000));
        assert!(filetime_to_rfc3339(ft)
            .unwrap()
            .starts_with("2010-01-01T00:00:00"));
    }

    #[test]
    fn filetime_sub_second_precision() {
        // One extra 100 ns tick over a whole second must land in the nanos.
        let ft = 129_067_776_000_000_001u64;
        let dt = filetime_to_datetime(ft).unwrap();
        assert_eq!(dt.timestamp_subsec_nanos(), 100);
    }

    #[test]
    fn cocoa_secs_zero_negative_are_none() {
        assert_eq!(cocoa_secs_to_unix_nanos(0.0), None);
        assert_eq!(cocoa_secs_to_unix_nanos(-5.0), None);
        assert_eq!(cocoa_to_unix_secs(0), None);
        assert_eq!(cocoa_to_unix_secs(-1), None);
    }

    #[test]
    fn cocoa_seconds_and_nanoseconds() {
        // Whole seconds since 2001.
        assert_eq!(
            cocoa_secs_to_unix_nanos(700_000_000.0),
            Some((700_000_000 + COCOA_EPOCH, 0))
        );
        assert_eq!(
            cocoa_to_unix_secs(700_000_000),
            Some(700_000_000 + COCOA_EPOCH)
        );
        // iOS 11+ nanoseconds since 2001: 700_000_000 s expressed in ns.
        let ns = 700_000_000i64 * 1_000_000_000 + 123;
        let (secs, nanos) = cocoa_to_unix_nanos(ns).unwrap();
        assert_eq!(secs, 700_000_000 + COCOA_EPOCH);
        assert_eq!(nanos, 123);
    }

    #[test]
    fn cocoa_float_sub_second_ordering_is_preserved() {
        // Two records 250 ms and 750 ms into the same second — the fraction is
        // the only thing that orders them. Truncating the float made both land
        // on the same whole second and the ordering was lost (BUG-020).
        let (first_secs, first_nanos) = cocoa_secs_to_unix_nanos(700_000_000.25).unwrap();
        let (second_secs, second_nanos) = cocoa_secs_to_unix_nanos(700_000_000.75).unwrap();
        assert_eq!(first_secs, 700_000_000 + COCOA_EPOCH);
        assert_eq!(second_secs, first_secs);
        assert_eq!(first_nanos, 250_000_000);
        assert_eq!(second_nanos, 750_000_000);
        assert!(
            (first_secs, first_nanos) < (second_secs, second_nanos),
            "sub-second Cocoa ordering must survive the conversion"
        );
    }

    #[test]
    fn cocoa_float_sentinels_and_out_of_range_are_none() {
        assert_eq!(cocoa_secs_to_unix_nanos(0.0), None);
        assert_eq!(cocoa_secs_to_unix_nanos(-1.5), None);
        // A non-finite or absurd value must be omitted, never wrapped into a
        // plausible-looking date.
        assert_eq!(cocoa_secs_to_unix_nanos(f64::NAN), None);
        assert_eq!(cocoa_secs_to_unix_nanos(f64::INFINITY), None);
        assert_eq!(cocoa_secs_to_unix_nanos(f64::MAX), None);
    }

    #[test]
    fn unix_float_seconds_split_matches_the_cocoa_one_modulo_the_epoch() {
        // The PowerLog pair: the same instant written in either base must land
        // on the same nanosecond, or one generation of the store reads late.
        let cocoa = 700_000_000.125_f64;
        let unix = cocoa + COCOA_EPOCH as f64;
        assert_eq!(
            unix_secs_f64_to_nanos(unix),
            cocoa_secs_to_unix_nanos(cocoa)
        );
        assert_eq!(unix_secs_f64_to_nanos(0.0), None);
        assert_eq!(unix_secs_f64_to_nanos(-1.0), None);
        assert_eq!(unix_secs_f64_to_nanos(f64::NAN), None);
        assert_eq!(unix_secs_f64_to_nanos(f64::MAX), None);
    }

    #[test]
    fn unix_ns_carries_the_fraction_and_stays_absent_without_one() {
        let (secs, nanos) = cocoa_secs_to_unix_nanos(700_000_000.25).unwrap();
        assert_eq!(
            unix_ns(secs, nanos),
            Some((700_000_000 + COCOA_EPOCH) * 1_000_000_000 + 250_000_000)
        );
        // A whole second has nothing the seconds field does not already carry,
        // so no `_ns` is published rather than a redundant one.
        assert_eq!(unix_ns(700_000_000 + COCOA_EPOCH, 0), None);
        // Out of i64 range stays absent instead of wrapping to a plausible date.
        assert_eq!(unix_ns(i64::MAX, 1), None);
    }

    #[test]
    fn webkit_known_value_and_sentinels() {
        // 2019-01-01T00:00:00Z == 1546300800 unix == that + 11644473600 seconds
        // since 1601, expressed in microseconds.
        let webkit = (1_546_300_800i64 + 11_644_473_600) * 1_000_000;
        assert_eq!(webkit_us_to_unix_secs(webkit), Some(1_546_300_800));
        // Sub-second precision is preserved by the _us variant.
        assert_eq!(
            webkit_us_to_unix_us(webkit + 250_000),
            Some(1_546_300_800_250_000)
        );
        // Unset / pre-epoch sentinels are rejected rather than surfaced as 1601.
        assert_eq!(webkit_us_to_unix_secs(0), None);
        assert_eq!(webkit_us_to_unix_secs(-1), None);
        assert_eq!(webkit_us_to_unix_secs(1_000), None);
    }

    #[test]
    fn prtime_is_unix_based_not_1601_based() {
        // PRTime is microseconds since 1970, unlike WebKit's 1601 base: the same
        // integer must convert differently under the two functions.
        let prtime = 1_546_300_800i64 * 1_000_000;
        assert_eq!(prtime_to_unix_secs(prtime), Some(1_546_300_800));
        assert_eq!(prtime_to_unix_secs(0), None);
        assert_ne!(
            prtime_to_unix_secs(prtime),
            webkit_us_to_unix_secs(prtime),
            "the two epochs must not be conflated"
        );
    }
}
