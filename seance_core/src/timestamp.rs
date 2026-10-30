//! The one decision procedure for "given a metadata timestamp, what instant is
//! this?" — and, where no instant can be justified, the stated reason why.
//!
//! An instant is a claim about when something happened, and this crate's output
//! is quoted into statements handed to courts. So the procedure answers with
//! three kinds of thing, never with a fourth kind that guesses:
//!
//!   * an instant read **as written** — in the unit the record's contract states
//!     (`seance_sqlite_util::chat` documents `date` as whole Unix seconds), or
//!     parsed from a written date-time that carries its own UTC offset;
//!   * an instant placed **by rescue** — reachable only by assuming which unit
//!     the parser used (milliseconds, microseconds, Windows FILETIME ticks).
//!     That is a weaker fact than a value read to contract, and every consumer
//!     must be able to say so, which is why the confidence travels with the
//!     instant instead of being flattened away;
//!   * **unplaceable**, split into `value` (the key was there and no reading of
//!     it is admissible) and `absent` (no key, or JSON null). A value that
//!     cannot be read is absent, never zero and never a guess.
//!
//! The browser reader `frontend/src/lib/epoch.ts` is the incumbent expression of
//! this rule: it already decides what four shipping views render, so it — not a
//! fresh idea about what the rule ought to be — is what this module reproduces,
//! magnitude bands and all. A server-side aggregation that answered differently
//! would put two different instants for one record in front of one examiner.
//! The two are pinned to each other by a shared corpus of `{name, keys, input,
//! expect}` rows at [`CORPUS_PATH`], read by both test suites.
//!
//! ## Where this deliberately differs from the browser
//!
//! `Date.parse` reads a zone-less date-time (`"2024-03-05T12:00:00"`) in the
//! *viewer's* local zone, so the same evidence is a different instant on two
//! examiners' machines. A server cannot know that zone and must not invent one,
//! so [`place_value`] refuses the shape as `unplaceable_value`. It is the one
//! known divergence, it is tested, and no corpus row depends on it.
//!
//! `Date.parse` also accepts implementation-defined text shapes beyond those
//! below (V8's legacy parser takes `"2024-3-5"`, for instance). This module
//! shape-checks text before parsing it and accepts exactly three written forms:
//! RFC 3339, RFC 2822, and a bare `YYYY-MM-DD` date read as UTC midnight.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Repo-relative path of the corpus that pins every expression of this rule.
/// Stated here so a later expression (the histogram SQL) reads the same bytes
/// rather than a retyped copy of them, which would pin the copy.
pub const CORPUS_PATH: &str = "frontend/src/test/fixtures/epoch-corpus.json";

/// 100 ns ticks between the FILETIME epoch (1601) and the Unix epoch (1970).
const FILETIME_UNIX_OFFSET: i128 = 116_444_736_000_000_000;

/// JavaScript `Date`'s representable range, ±100,000,000 days in milliseconds.
/// The browser reader rejects anything beyond it rather than let `toISOString()`
/// throw downstream, so this expression must reject the same values — and
/// because the bound sits below 2^53, every accepted millisecond count is an
/// exact integer in both a double and an `i64`.
const MAX_JS_DATE_MS: f64 = 8.64e15;

/// How the record's own unit was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Read in the unit the record's contract states, or parsed from a written
    /// date-time that carries its own offset. The strongest footing available.
    AsWritten,
    /// Placed only by assuming which unit the parser used. The evidence
    /// supports this instant *under that assumption*, and a report that shows
    /// it must say so.
    ByRescue,
}

/// Why no instant could be produced. The two are kept apart because they are
/// different findings: one says the record holds something unreadable, the
/// other says the record never claimed a time at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// A listed key was present with a non-null value, and no reading of it is
    /// admissible.
    Value,
    /// Every listed key was absent or JSON null.
    Absent,
}

/// The three-valued answer. Its serialised shape *is* the `expect` shape of a
/// corpus row, so a test compares a computed [`Placement`] with a deserialised
/// one and needs no translation layer in between to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Placement {
    /// An instant, in whole Unix seconds, with the footing it stands on.
    Placed {
        placed_secs: i64,
        confidence: Confidence,
    },
    /// No instant, with the reason stated.
    Unplaceable { unplaceable: Reason },
}

impl Placement {
    /// The instant, if there is one. Deliberately not a `Default`-shaped
    /// accessor: there is no sensible zero for "when did this happen".
    pub fn epoch_secs(&self) -> Option<i64> {
        match self {
            Self::Placed { placed_secs, .. } => Some(*placed_secs),
            Self::Unplaceable { .. } => None,
        }
    }

    /// The footing the instant stands on, if there is an instant.
    pub fn confidence(&self) -> Option<Confidence> {
        match self {
            Self::Placed { confidence, .. } => Some(*confidence),
            Self::Unplaceable { .. } => None,
        }
    }

    /// True where an instant was reachable only by assuming a unit. A view that
    /// counts these is stating the size of its own assumption.
    pub fn is_rescued(&self) -> bool {
        self.confidence() == Some(Confidence::ByRescue)
    }

    /// The census class name, spelled exactly as the histogram's ordered census
    /// spells it, so the two cannot drift apart in a report's wording.
    pub fn census_class(&self) -> &'static str {
        match self {
            Self::Placed {
                confidence: Confidence::AsWritten,
                ..
            } => "placed_as_written",
            Self::Placed {
                confidence: Confidence::ByRescue,
                ..
            } => "placed_by_rescue",
            Self::Unplaceable {
                unplaceable: Reason::Value,
            } => "unplaceable_value",
            Self::Unplaceable {
                unplaceable: Reason::Absent,
            } => "unplaceable_absent",
        }
    }
}

/// Place a record by reading `keys` in order.
///
/// The first key that *yields an instant* wins — not the first key that is
/// non-null. The distinction is the whole ballgame for `{"date": 0,
/// "timestamp": 1600000000}`, a live shape: reading it as "first non-null" puts
/// the record in 1970 and reading it as the browser does puts it in 2020, fifty
/// years apart from the same bytes.
///
/// When no key yields an instant, a key that was present but unreadable
/// outranks an absent one in the stated reason: the record did claim a time,
/// and the report must not say it was silent.
pub fn place_from_metadata<K: AsRef<str>>(meta: &Map<String, Value>, keys: &[K]) -> Placement {
    let mut saw_present_value = false;
    for key in keys {
        match place_value(meta.get(key.as_ref())) {
            placed @ Placement::Placed { .. } => return placed,
            Placement::Unplaceable {
                unplaceable: Reason::Value,
            } => saw_present_value = true,
            Placement::Unplaceable {
                unplaceable: Reason::Absent,
            } => {}
        }
    }
    Placement::Unplaceable {
        unplaceable: if saw_present_value {
            Reason::Value
        } else {
            Reason::Absent
        },
    }
}

/// Place a single metadata value. `None` is an absent key; `Some(Value::Null)`
/// is a key written as JSON null, which the comms parsers use to mean "this
/// record carries no time" and which must therefore read as absent too, never
/// as 1970-01-01.
pub fn place_value(value: Option<&Value>) -> Placement {
    let reading = match value {
        None | Some(Value::Null) => Reading::Unplaceable(Reason::Absent),
        Some(Value::Number(n)) => match n.as_f64() {
            // JSON numbers reach the browser as doubles, so the magnitude bands
            // are judged on a double here as well; judging a 17-digit integer
            // on its exact value could pick a different band than the browser.
            Some(v) => read_number(v),
            None => Reading::Unplaceable(Reason::Value),
        },
        Some(Value::String(s)) => read_string(s),
        // A bool, array or object is a present value with no reading.
        Some(_) => Reading::Unplaceable(Reason::Value),
    };
    match reading {
        Reading::Ms { ms, confidence } => Placement::Placed {
            placed_secs: floor_ms_to_secs(ms),
            confidence,
        },
        Reading::Unplaceable(reason) => Placement::Unplaceable {
            unplaceable: reason,
        },
    }
}

/// The intermediate answer, in milliseconds, before it is floored to the second
/// the record is reported at. Milliseconds are carried this far because the
/// browser reader hands milliseconds to its views and the two must agree about
/// which second a sub-second value lands in.
enum Reading {
    Ms { ms: f64, confidence: Confidence },
    Unplaceable(Reason),
}

/// Whole seconds containing the instant `ms`, rounding towards the past.
fn floor_ms_to_secs(ms: f64) -> i64 {
    // Towards the past on both sides of the epoch, which is why this is neither
    // `as i64` nor `/` on integers: both truncate towards zero, so an instant
    // half a second before 1970 would be reported in the second *after* the one
    // that contains it. Measured, the double division `(ms / 1000.0).floor()`
    // agrees everywhere inside the accepted range — a double step only grows
    // coarser than the 0.001 that a quotient of N.999 needs above 1.7e16 ms,
    // which the range check has already excluded — but the millisecond count is
    // exact as an `i64` here, so the division is done where no rounding
    // argument is needed at all.
    (ms.floor() as i64).div_euclid(1000)
}

/// Read a number by magnitude, in the browser reader's bands.
///
/// The bands are not a theory of what the data ought to be: they are what four
/// shipping views already render. A microsecond value lands in the FILETIME
/// band and is placed in the 17th century — wrong, reproduced faithfully here
/// because the two expressions disagreeing about it would be worse, and fixed
/// where it is caused (the plugins that write the wrong unit) rather than
/// papered over here.
fn read_number(v: f64) -> Reading {
    if !v.is_finite() {
        return Reading::Unplaceable(Reason::Value);
    }
    let (ms, confidence) = if v > 1e15 {
        // Windows FILETIME: 100 ns ticks since 1601.
        (
            (v - FILETIME_UNIX_OFFSET as f64) / 10_000.0,
            Confidence::ByRescue,
        )
    } else if v > 1e12 {
        (v, Confidence::ByRescue) // Unix milliseconds
    } else if v > 1e8 {
        (v * 1000.0, Confidence::AsWritten) // Unix seconds, the contract
    } else {
        // Below the seconds band. This refuses genuine pre-1973 instants, which
        // is a real loss and is why the corpus states it outright rather than
        // leaving it to be discovered in a case.
        return Reading::Unplaceable(Reason::Value);
    };
    if ms.is_finite() && ms.abs() <= MAX_JS_DATE_MS {
        Reading::Ms { ms, confidence }
    } else {
        Reading::Unplaceable(Reason::Value)
    }
}

/// Read a string: a numeric shape by magnitude, anything else as written text.
fn read_string(s: &str) -> Reading {
    if s.is_empty() {
        return Reading::Unplaceable(Reason::Value);
    }
    let n = js_number(s);
    // A `-`, `:` or `T` marks the value as written text rather than a tick
    // count, which is also what keeps a negative numeric string out of the
    // magnitude bands.
    let numeric_shape = !s.trim().is_empty() && !n.is_nan() && !s.contains(['-', ':', 'T']);
    if numeric_shape {
        if let Some(exact) = integer_literal_reading(s.trim()) {
            return exact;
        }
        return read_number(n);
    }
    match parse_written_date_time(s) {
        Some(ms) => Reading::Ms {
            ms,
            confidence: Confidence::AsWritten,
        },
        None => Reading::Unplaceable(Reason::Value),
    }
}

/// Integer literal — the form a tick count arrives in as a string.
fn is_integer_literal(s: &str) -> bool {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Exact [`read_number`] for an integer-literal string, in the same bands.
/// `None` means "not my shape", which the caller must tell apart from "this is
/// not a usable timestamp".
///
/// A FILETIME (~1.3e17) or WebKit microsecond value (~1.3e16) is past the exact
/// integer range of a double, so reading it as a double first would snap the
/// tick count to a neighbouring value and could move the result into the next
/// second. The string still holds the exact ticks, so the conversion is done in
/// integers — mirroring the browser reader's BigInt path, including its
/// truncation towards zero.
fn integer_literal_reading(s: &str) -> Option<Reading> {
    if !is_integer_literal(s) {
        return None;
    }
    let Ok(v) = s.parse::<i128>() else {
        // BigInt is arbitrary precision where `i128` is not, but a literal too
        // long for an `i128` is many orders of magnitude outside any
        // representable date, so both expressions refuse it.
        return Some(Reading::Unplaceable(Reason::Value));
    };
    let (ms, confidence) = if v > 1_000_000_000_000_000 {
        ((v - FILETIME_UNIX_OFFSET) / 10_000, Confidence::ByRescue)
    } else if v > 1_000_000_000_000 {
        (v, Confidence::ByRescue)
    } else if v > 100_000_000 {
        (v * 1000, Confidence::AsWritten)
    } else {
        return Some(Reading::Unplaceable(Reason::Value));
    };
    let as_f64 = ms as f64;
    Some(if as_f64.is_finite() && as_f64.abs() <= MAX_JS_DATE_MS {
        Reading::Ms {
            ms: as_f64,
            confidence,
        }
    } else {
        Reading::Unplaceable(Reason::Value)
    })
}

/// JavaScript's `Number(s)` for the shapes that can reach it here.
///
/// This is a coercion, not a parse: `Number("")` is 0, `Number("0x10")` is 16,
/// `Number("Infinity")` is infinite. Rust's own `f64` parser accepts `"inf"`
/// and `"nan"`, which JavaScript's does not, so the character set is checked
/// before it is handed over. The result only ever decides whether the string
/// takes the numeric branch and, for a non-integer literal, what number it
/// denotes.
fn js_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16u32),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = t.strip_prefix(prefix) {
            return match i128::from_str_radix(digits, radix) {
                Ok(v) => v as f64,
                Err(_) => f64::NAN,
            };
        }
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E'))
    {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// Parse the written date-time shapes this rule accepts, to epoch milliseconds.
///
/// Only shapes that carry their own zone, plus a bare date read as UTC
/// midnight, which is what ECMA-262 does with a date-only form. Anything else —
/// including a zone-less date-time, and including SQLite's magic words `now`
/// and `10:00:00` — is refused, because placing it would require assuming a
/// zone or a date that no evidence supplies.
fn parse_written_date_time(s: &str) -> Option<f64> {
    let t = s.trim();
    let utc: DateTime<Utc> = if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        dt.into()
    } else if let Ok(dt) = DateTime::parse_from_rfc2822(t) {
        dt.into()
    } else if is_bare_iso_date(t) {
        let date = NaiveDate::parse_from_str(t, "%Y-%m-%d").ok()?;
        Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?)
    } else {
        return None;
    };
    // `timestamp_subsec_millis` truncates rather than rounds, and `timestamp`
    // floors, so a sub-second value lands in the second that contains it on
    // both sides of the epoch.
    let ms = utc.timestamp() as f64 * 1000.0 + f64::from(utc.timestamp_subsec_millis());
    // The browser rejects a date outside `Date`'s range by returning NaN from
    // `Date.parse`; the same values are refused here so the two agree.
    (ms.is_finite() && ms.abs() <= MAX_JS_DATE_MS).then_some(ms)
}

/// Exactly `YYYY-MM-DD`, checked by shape before `chrono` sees it.
///
/// `chrono`'s `%m` and `%d` accept one digit as happily as two, so without this
/// check `"2024-3-5"` would parse here. The browser's legacy parser also takes
/// that shape but reads it in the viewer's *local* zone, so accepting it would
/// invent a disagreement of up to a day.
fn is_bare_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

/// One row of the shared corpus at [`CORPUS_PATH`].
#[derive(Debug, Clone, Deserialize)]
pub struct CorpusRow {
    /// What the row pins, in a sentence, so a failure names the finding rather
    /// than an index.
    pub name: String,
    /// The ordered key list the procedure is given.
    pub keys: Vec<String>,
    /// The metadata object, as a parser would have written it.
    pub input: Map<String, Value>,
    /// The one admissible answer.
    pub expect: Placement,
}

/// The shared corpus. Every expression of this rule is checked against these
/// rows, which is what makes "the browser and the server agree" a test result
/// rather than an intention.
#[derive(Debug, Clone, Deserialize)]
pub struct Corpus {
    /// What the corpus is for, carried in the file so it travels with it.
    pub description: String,
    pub rows: Vec<CorpusRow>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn place_one(v: Value) -> Placement {
        place_value(Some(&v))
    }

    #[test]
    fn an_absent_key_and_a_null_key_are_both_absent_but_a_zero_is_not() {
        assert_eq!(
            place_value(None),
            Placement::Unplaceable {
                unplaceable: Reason::Absent
            }
        );
        assert_eq!(
            place_one(Value::Null),
            Placement::Unplaceable {
                unplaceable: Reason::Absent
            }
        );
        assert_eq!(
            place_one(json!(0)),
            Placement::Unplaceable {
                unplaceable: Reason::Value
            }
        );
    }

    #[test]
    fn the_seconds_band_is_as_written_and_the_rescue_bands_say_so() {
        assert_eq!(
            place_one(json!(1_709_640_000)).confidence(),
            Some(Confidence::AsWritten)
        );
        assert!(place_one(json!(1_709_640_000_000_i64)).is_rescued());
        assert!(place_one(json!(133_500_000_000_000_000_i64)).is_rescued());
        assert!(!place_one(json!(1_709_640_000)).is_rescued());
    }

    #[test]
    fn a_zone_less_date_time_is_refused_because_the_zone_is_the_viewers_not_the_records() {
        assert_eq!(
            place_one(json!("2024-03-05T12:00:00")),
            Placement::Unplaceable {
                unplaceable: Reason::Value
            }
        );
        // A one-digit month would be read locally by the browser's legacy
        // parser, so it is refused rather than silently read as UTC.
        assert_eq!(
            place_one(json!("2024-3-5")),
            Placement::Unplaceable {
                unplaceable: Reason::Value
            }
        );
    }

    #[test]
    fn a_sub_second_value_lands_in_the_second_that_contains_it_on_both_sides_of_the_epoch() {
        // Floor, not truncation towards zero: a pre-epoch instant 0.5 s before
        // 1970 is inside the second that starts at -1, not the one at 0.
        assert_eq!(floor_ms_to_secs(-500.0), -1);
        assert_eq!(floor_ms_to_secs(-1.0), -1);
        assert_eq!(floor_ms_to_secs(0.0), 0);
        assert_eq!(floor_ms_to_secs(999.9), 0);
        assert_eq!(floor_ms_to_secs(1000.0), 1);
    }

    #[test]
    fn flooring_is_exact_at_both_ends_of_the_accepted_range() {
        // The extremes of what the reader will accept at all, one millisecond
        // inside the bound on each side. These are the values where a rounding
        // error would be largest, and the browser's `Math.floor(ms / 1000)`
        // was measured to give the same two answers.
        assert_eq!(floor_ms_to_secs(8_639_999_999_999_999.0), 8_639_999_999_999);
        assert_eq!(
            floor_ms_to_secs(-8_639_999_999_999_999.0),
            -8_640_000_000_000
        );
    }

    #[test]
    fn a_filetime_string_converts_through_integers_rather_than_a_double() {
        // One 100 ns tick below a second boundary. Through a double the tick
        // count rounds up to the boundary and the instant reads a whole second
        // later than the evidence.
        assert_eq!(
            place_one(json!("133699999999999999")).epoch_secs(),
            Some(1_725_526_399)
        );
    }

    #[test]
    fn js_number_coerces_the_way_javascript_does() {
        assert_eq!(js_number(""), 0.0);
        assert_eq!(js_number("   "), 0.0);
        assert_eq!(js_number("0x1000"), 4096.0);
        assert_eq!(js_number("1e9"), 1e9);
        assert_eq!(js_number(" 1709640000 "), 1_709_640_000.0);
        assert!(js_number("Infinity").is_infinite());
        // Rust would parse these; JavaScript would not.
        assert!(js_number("inf").is_nan());
        assert!(js_number("nan").is_nan());
        assert!(js_number("nope").is_nan());
    }

    #[test]
    fn the_written_forms_all_parse_and_carry_their_own_offset() {
        assert_eq!(
            place_one(json!("Mon, 3 Jun 2024 14:22:01 +0100")).epoch_secs(),
            Some(1_717_420_921)
        );
        assert_eq!(
            place_one(json!("2024-03-05T12:00:00+05:30")).epoch_secs(),
            Some(1_709_620_200)
        );
        assert_eq!(
            place_one(json!("2024-03-05")).epoch_secs(),
            Some(1_709_596_800)
        );
    }

    #[test]
    fn key_precedence_is_first_key_that_yields_an_instant_not_first_non_null() {
        let meta = json!({"date": 0, "timestamp": 1600000000});
        assert_eq!(
            place_from_metadata(meta.as_object().unwrap(), &["date", "timestamp"]).epoch_secs(),
            Some(1_600_000_000)
        );
    }

    #[test]
    fn census_class_names_match_the_ordered_census() {
        assert_eq!(
            place_one(json!(1_709_640_000)).census_class(),
            "placed_as_written"
        );
        assert_eq!(
            place_one(json!(1_709_640_000_000_i64)).census_class(),
            "placed_by_rescue"
        );
        assert_eq!(place_one(json!("nope")).census_class(), "unplaceable_value");
        assert_eq!(place_value(None).census_class(), "unplaceable_absent");
    }
}
