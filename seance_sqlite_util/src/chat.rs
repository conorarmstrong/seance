//! The chat-message record shell, in one place.
//!
//! Every messaging parser in this tree emits the same artifact shape: a
//! `ParsedRecord` whose `subtype` is `chat_message`, carrying `type`, `service`,
//! `platform`, `text`, `date`, `is_from_me` / `direction`, a conversation key
//! and a one-line `name`. That shape is a *contract* with two consumers that
//! cannot type-check it:
//!
//! - `seance_db::chat_timeline_row` projects it onto the unified timeline and
//!   groups conversations by `json_extract(metadata_json, '$.chat_identifier')`
//!   and `'$.type'`;
//! - the frontend `MessagingViewer` / `comms/normalize.ts` render it.
//!
//! It was hand-built as a fresh `serde_json::Map` (or a fresh `json!` literal)
//! in a dozen crates, and the copies had already drifted on the one axis that
//! matters most in a court document — **how an unknown is written down**:
//!
//! - seven crates omitted an unknown `direction` / `is_from_me`, with a comment
//!   saying "absent, not false: an unknown direction must not read as
//!   received";
//! - three (`instagram`, `snapchat`, `twitter`) wrote JSON `null` into the same
//!   keys, because a `json!` literal has no way to leave a field out;
//! - `direction` and `is_from_me` were two independent expressions in every
//!   copy, so nothing but repetition stopped them disagreeing.
//!
//! [`ChatMessage`] removes all three possibilities structurally. There is one
//! way to say "unknown" (`None`, which omits the key), `direction` is *derived*
//! from `is_from_me` and cannot be set independently, and `subtype` is written
//! by this module rather than by the caller.
//!
//! # What deliberately stays per-crate
//!
//! [`ChatMessage::record_type`] — the metadata `type` — is a required argument
//! with no default. `seance_db` groups conversations by `metadata.$.type`, so
//! it names the app whose store was parsed (`"Viber"`, `"TelegramMessage"`),
//! and the incompleteness markers that qualify those records must use a
//! *different* type (`"ViberIncomplete"`) or they join the grouping as phantom
//! one-message threads. See [`crate::dropped_rows_marker`].
//!
//! Schema-specific SQL, column discovery and row decoding stay in their own
//! crates. This module is the shell the rows are poured into, nothing else.

use seance_core::artifact::{Artifact, ArtifactType};
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

/// The `subtype` every chat record carries, in metadata and on the artifact.
///
/// `seance_db::chat_timeline_row` returns `None` for anything else, so a record
/// that misses it is silently absent from the unified timeline.
pub const CHAT_MESSAGE_SUBTYPE: &str = "chat_message";

/// How many characters of the body go into the one-line `name`.
const PREVIEW_CHARS: usize = 80;

/// Written in the `name` when the row had no body at all — a media message, a
/// call record, an undecoded blob. Distinct from an empty body, which
/// [`ChatMessage::text`] also treats as absent.
const NO_TEXT: &str = "(no text)";

/// Written in the `name` when the direction was never recorded. Deliberately
/// not "received": the whole point of [`ChatMessage::from_me`] taking an
/// `Option` is that an unattributed message must not be attributed.
const NO_DIRECTION: &str = "message";

/// The direction string for a message the device owner sent.
pub const DIRECTION_SENT: &str = "sent";

/// The direction string for a message the device owner received.
pub const DIRECTION_RECEIVED: &str = "received";

/// `is_from_me` rendered as the `direction` string the timeline and the
/// frontend read.
///
/// The only place the mapping exists. It was written out at a dozen call sites
/// as `is_from_me.map(|m| if m { "sent" } else { "received" })`, next to a
/// separate insert of `is_from_me` itself, which is two chances to disagree
/// about who sent a message — the most consequential error this tool can make
/// (B2-083).
pub fn direction_of(is_from_me: Option<bool>) -> Option<&'static str> {
    is_from_me.map(|m| {
        if m {
            DIRECTION_SENT
        } else {
            DIRECTION_RECEIVED
        }
    })
}

/// One chat message, ready to become an [`Artifact`].
///
/// Build it with [`ChatMessage::new`] and the setters, then call
/// [`ChatMessage::into_artifact`]. Every optional field follows one rule:
/// **`None` omits the key**. Nothing writes `null`, `false`, `0` or an empty
/// string in place of a fact that was not established, because a report cannot
/// distinguish those from findings.
#[derive(Debug, Clone)]
pub struct ChatMessage<'a> {
    record_type: &'a str,
    service: &'a str,
    platform: &'a str,
    text: Option<String>,
    date: Option<i64>,
    is_from_me: Option<bool>,
    chat_identifier: Option<String>,
    contact: Option<String>,
    display: Option<String>,
    extra: Vec<(&'a str, JsonValue)>,
}

impl<'a> ChatMessage<'a> {
    /// A message from `service` on `platform`, filed under `record_type`.
    ///
    /// `record_type` becomes metadata `type` and is what `seance_db` groups
    /// conversations by, so it must be the per-app record type and must never
    /// be shared with an incompleteness marker.
    pub fn new(record_type: &'a str, service: &'a str, platform: &'a str) -> Self {
        Self {
            record_type,
            service,
            platform,
            text: None,
            date: None,
            is_from_me: None,
            chat_identifier: None,
            contact: None,
            display: None,
            extra: Vec::new(),
        }
    }

    /// The message body. An empty string is treated as no body: the app wrote a
    /// blank where a media or system message has no text, and an empty `text`
    /// key in a report reads as a recovered message that happened to say
    /// nothing.
    pub fn text(mut self, text: Option<String>) -> Self {
        self.text = text.filter(|s| !s.is_empty());
        self
    }

    /// The message timestamp in **whole Unix seconds**.
    ///
    /// `seance_db::chat_timeline_row` reads `date` as seconds; a store that
    /// keeps milliseconds or microseconds must normalise before calling this
    /// (see [`crate::unix_seconds_from_magnitude`]). `None` keeps the message
    /// off the timeline rather than pinning it to 1970.
    pub fn date_secs(mut self, date: Option<i64>) -> Self {
        self.date = date;
        self
    }

    /// Whether the device owner sent this message, when the store recorded it.
    ///
    /// `None` leaves both `is_from_me` and `direction` off the record. There is
    /// no way to set `direction` independently, so the two cannot disagree.
    pub fn from_me(mut self, is_from_me: Option<bool>) -> Self {
        self.is_from_me = is_from_me;
        self
    }

    /// The conversation key: the value `seance_db` groups a thread by. An empty
    /// string is treated as absent.
    pub fn chat_identifier(mut self, id: Option<String>) -> Self {
        self.chat_identifier = id.filter(|s| !s.is_empty());
        self
    }

    /// The other party, as the store named them. An empty string is treated as
    /// absent.
    pub fn contact(mut self, contact: Option<String>) -> Self {
        self.contact = contact.filter(|s| !s.is_empty());
        self
    }

    /// Override the one-line `name`.
    ///
    /// Most parsers should not: the derived label
    /// ([`ChatMessage::derived_name`]) is the shape the record list shows for
    /// the whole messaging family, and a bespoke one makes two rows from two
    /// apps look like different kinds of evidence. Use it where the app's label
    /// genuinely carries something else — Telegram's dialog id, Snapchat's
    /// content type, a media URL standing in for an absent body.
    pub fn display(mut self, display: String) -> Self {
        self.display = Some(display);
        self
    }

    /// An app-specific field. `JsonValue::Null` is dropped rather than written,
    /// so a `json!` value built from an `Option` follows the same
    /// absent-means-omitted rule as the fields above.
    ///
    /// Extras cannot overwrite the shared fields; see
    /// [`ChatMessage::into_artifact`].
    pub fn extra(mut self, key: &'a str, value: JsonValue) -> Self {
        self.extra.push((key, value));
        self
    }

    /// [`ChatMessage::extra`] for several fields at once.
    pub fn extras(mut self, fields: impl IntoIterator<Item = (&'a str, JsonValue)>) -> Self {
        self.extra.extend(fields);
        self
    }

    /// The direction this record will carry, derived from `is_from_me`.
    pub fn direction(&self) -> Option<&'static str> {
        direction_of(self.is_from_me)
    }

    /// The derived one-line label.
    ///
    /// `"{direction}: {contact} — {preview}"`, dropping the contact segment
    /// when the record has no contact, so a parser with no contact concept
    /// (Viber's `messages` table has none) does not print `(unknown)` and imply
    /// there was a name it failed to read.
    pub fn derived_name(&self) -> String {
        let preview: String = self
            .text
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(PREVIEW_CHARS)
            .collect();
        let body = if preview.is_empty() {
            NO_TEXT
        } else {
            &preview
        };
        let direction = self.direction().unwrap_or(NO_DIRECTION);
        match self.contact.as_deref() {
            Some(contact) => format!("{direction}: {contact} — {body}"),
            None => format!("{direction}: {body}"),
        }
    }

    /// Render the record.
    ///
    /// Field order is fixed here so every messaging plugin produces the same
    /// document, and the shared keys are written *before* the extras and are
    /// not overwritten by them: an app-specific field cannot quietly redefine
    /// `type`, `subtype`, `direction` or `date` and change how the record is
    /// grouped or placed on the timeline.
    pub fn into_artifact(self, case_id: Uuid, parent_id: Uuid) -> Artifact {
        let name = match &self.display {
            Some(d) => d.clone(),
            None => self.derived_name(),
        };
        let direction = self.direction();

        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!(self.record_type));
        m.insert("subtype".into(), json!(CHAT_MESSAGE_SUBTYPE));
        m.insert("platform".into(), json!(self.platform));
        m.insert("service".into(), json!(self.service));
        // Absent, not false: an unknown direction must not read as "received".
        if let Some(from_me) = self.is_from_me {
            m.insert("is_from_me".into(), json!(from_me));
        }
        if let Some(d) = direction {
            m.insert("direction".into(), json!(d));
        }
        if let Some(t) = self.text {
            m.insert("text".into(), json!(t));
        }
        if let Some(d) = self.date {
            m.insert("date".into(), json!(d));
        }
        if let Some(c) = self.chat_identifier {
            m.insert("chat_identifier".into(), json!(c));
        }
        if let Some(c) = self.contact {
            m.insert("contact".into(), json!(c));
        }
        for (key, value) in self.extra {
            // A null extra is an absent fact, and absent facts are omitted.
            if value.is_null() {
                continue;
            }
            m.entry(key.to_string()).or_insert(value);
        }
        m.insert("name".into(), json!(name));

        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::Value::Object(m),
        )
        .with_parent(parent_id)
        .with_subtype(CHAT_MESSAGE_SUBTYPE)
    }
}

/// Magnitude-based unit normaliser: microseconds / milliseconds / seconds since
/// the Unix epoch → whole Unix seconds.
///
/// App stores drift between units across versions and between tables in the
/// same file (Instagram Direct writes 16-digit microseconds; Twitter's DM
/// tables mix milliseconds and seconds), so the unit is judged from the
/// magnitude rather than assumed. This is **not** an epoch conversion: every
/// branch is already relative to 1970, so it does not belong in
/// `seance_core::time`, which converts *foreign epochs* (FILETIME 1601, WebKit
/// 1601 µs, Cocoa 2001).
///
/// An unset (`0`) or negative value yields `None`. An absent timestamp must
/// stay absent rather than surface as 1970-01-01 and anchor a false timeline
/// entry.
pub fn unix_seconds_from_magnitude(raw: i64) -> Option<i64> {
    unix_parts_from_magnitude(raw).map(|(secs, _)| secs)
}

/// [`unix_seconds_from_magnitude`], keeping the sub-second remainder instead of
/// dividing it away: microseconds / milliseconds / seconds since the Unix epoch
/// → `(whole Unix seconds, sub-second nanoseconds)`.
///
/// The three bands live here and nowhere else, and
/// [`unix_seconds_from_magnitude`] is the seconds-only view of this function, so
/// a parser that needs the fraction cannot end up judging the unit by a
/// different rule than a parser that does not. That divergence is exactly the
/// defect this pair replaces: three call-log and messaging parsers each carried
/// their own two-branch `raw < 10^11 ? raw : raw / 1000`, which reads a 16-digit
/// microsecond store as milliseconds — `1_700_000_000_123_456` becomes
/// `1_700_000_000_123`, which is a date in the year 55840.
///
/// The fraction is evidence, not noise: two calls placed inside the same second
/// are ordered only by it. A microsecond value therefore keeps all six of its
/// sub-second digits (as nanoseconds), and a millisecond value all three.
///
/// An unset (`0`) or negative value yields `None`, for the reason given on
/// [`unix_seconds_from_magnitude`].
pub fn unix_parts_from_magnitude(raw: i64) -> Option<(i64, u32)> {
    if raw <= 0 {
        return None;
    }
    Some(if raw >= 1_000_000_000_000_000 {
        // Microseconds.
        (raw / 1_000_000, (raw % 1_000_000) as u32 * 1_000)
    } else if raw >= 1_000_000_000_000 {
        // Milliseconds.
        (raw / 1_000, (raw % 1_000) as u32 * 1_000_000)
    } else {
        // Already seconds; the store recorded no fraction to keep.
        (raw, 0)
    })
}

/// Earliest instant a communications record is allowed to claim: 1990-01-01Z.
///
/// The first SMS was sent in 1992 and the first iPhone call log in 2007, so a
/// messaging or call timestamp before 1990 is not an old message — it is a unit
/// misread, an unset column, or a corrupt row. The bound is deliberately looser
/// than the evidence requires so that it fails only on values no reading of the
/// store could justify.
pub const PLAUSIBLE_INSTANT_MIN_SECS: i64 = 631_152_000;

/// Latest instant a communications record is allowed to claim: 2100-01-01Z.
///
/// Nothing seized today can carry a timestamp a lifetime in the future, so a
/// value past this bound is likewise a misread rather than a date.
pub const PLAUSIBLE_INSTANT_MAX_SECS: i64 = 4_102_444_800;

/// Whether a whole-Unix-seconds value falls in the window a communications
/// record may plausibly claim.
///
/// This is the assertion the parser contract tests share. It is not a filter:
/// no parser silently drops a record because its timestamp failed this check,
/// because a value outside the window is a fact about the store that an
/// examiner must be able to see. It exists so that a future parser cannot
/// quietly reintroduce a two-branch magnitude normaliser and place messages
/// tens of thousands of years in the future without a test saying so.
pub fn is_plausible_instant_secs(secs: i64) -> bool {
    (PLAUSIBLE_INSTANT_MIN_SECS..=PLAUSIBLE_INSTANT_MAX_SECS).contains(&secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn an_unknown_direction_is_omitted_rather_than_written_as_null_or_false() {
        let (case, parent) = ids();
        let a = ChatMessage::new("Viber", "Viber", "Android")
            .text(Some("hi".into()))
            .from_me(None)
            .into_artifact(case, parent);
        // Not `false`, and not `null`: three plugins used to write JSON null
        // here because a `json!` literal cannot omit a field, and a consumer
        // reading `is_from_me` with a boolean default turns that into
        // "received" — a claim about who sent a message that no evidence
        // supports.
        assert!(a.metadata.get("is_from_me").is_none());
        assert!(a.metadata.get("direction").is_none());
    }

    #[test]
    fn direction_always_agrees_with_is_from_me() {
        let (case, parent) = ids();
        for (from_me, expected) in [(true, "sent"), (false, "received")] {
            let a = ChatMessage::new("Kik", "Kik", "Android")
                .from_me(Some(from_me))
                .into_artifact(case, parent);
            assert_eq!(a.metadata["is_from_me"], from_me);
            assert_eq!(a.metadata["direction"], expected);
        }
    }

    #[test]
    fn every_record_carries_the_chat_message_subtype_in_both_places() {
        let (case, parent) = ids();
        let a = ChatMessage::new("Skype", "Skype", "Desktop").into_artifact(case, parent);
        // `seance_db::chat_timeline_row` reads the metadata copy; the artifact
        // accessor reads the same key, so both must be set by construction
        // rather than by each caller remembering.
        assert_eq!(a.metadata["subtype"], CHAT_MESSAGE_SUBTYPE);
        assert_eq!(a.subtype(), Some(CHAT_MESSAGE_SUBTYPE));
        assert_eq!(a.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(a.parent_id, Some(parent));
        assert_eq!(a.case_id, case);
    }

    #[test]
    fn the_record_type_is_the_callers_and_is_never_the_service_name() {
        let (case, parent) = ids();
        // Telegram's records are typed `TelegramMessage`, not `Telegram`, and
        // its incompleteness marker is typed `TelegramMessageIncomplete`.
        // `seance_db` groups conversations on this key, so the shell must not
        // substitute the service label for it.
        let a =
            ChatMessage::new("TelegramMessage", "Telegram", "Android").into_artifact(case, parent);
        assert_eq!(a.metadata["type"], "TelegramMessage");
        assert_eq!(a.metadata["service"], "Telegram");
    }

    #[test]
    fn an_empty_body_is_absent_not_an_empty_string() {
        let (case, parent) = ids();
        let a = ChatMessage::new("WeChat", "WeChat", "Android")
            .text(Some(String::new()))
            .into_artifact(case, parent);
        assert!(a.metadata.get("text").is_none());
        assert!(a.metadata["name"].as_str().unwrap().contains(NO_TEXT));
    }

    #[test]
    fn an_empty_conversation_key_or_contact_is_absent() {
        let (case, parent) = ids();
        let a = ChatMessage::new("LINE", "LINE", "Android")
            .chat_identifier(Some(String::new()))
            .contact(Some(String::new()))
            .into_artifact(case, parent);
        // An empty `chat_identifier` would group every keyless message of every
        // app into one phantom conversation.
        assert!(a.metadata.get("chat_identifier").is_none());
        assert!(a.metadata.get("contact").is_none());
    }

    #[test]
    fn a_null_extra_is_dropped_so_json_built_options_follow_the_same_rule() {
        let (case, parent) = ids();
        let a = ChatMessage::new("TwitterDM", "Twitter/X DM", "Android")
            .extra("sender_screen_name", json!(None::<String>))
            .extra("entry_type", json!("message"))
            // A real `false` is a finding and must survive.
            .extra("text_recovered", json!(false))
            .into_artifact(case, parent);
        assert!(a.metadata.get("sender_screen_name").is_none());
        assert_eq!(a.metadata["entry_type"], "message");
        assert_eq!(a.metadata["text_recovered"], false);
    }

    #[test]
    fn an_extra_cannot_overwrite_a_shared_field() {
        let (case, parent) = ids();
        let a = ChatMessage::new("Instagram", "Instagram Direct", "Android")
            .from_me(Some(true))
            .date_secs(Some(1_700_000_000))
            .extra("direction", json!("received"))
            .extra("type", json!("InstagramIncomplete"))
            .extra("date", json!(0))
            .into_artifact(case, parent);
        // An app-specific field that shadowed `type` would move the record into
        // another conversation grouping; one that shadowed `date` would move it
        // on the timeline.
        assert_eq!(a.metadata["direction"], "sent");
        assert_eq!(a.metadata["type"], "Instagram");
        assert_eq!(a.metadata["date"], 1_700_000_000);
    }

    #[test]
    fn the_derived_name_drops_the_contact_segment_when_there_is_no_contact() {
        let (case, parent) = ids();
        let with_contact = ChatMessage::new("Kik", "Kik", "Android")
            .from_me(Some(false))
            .contact(Some("Alice".into()))
            .text(Some("hello".into()))
            .into_artifact(case, parent);
        assert_eq!(with_contact.metadata["name"], "received: Alice — hello");

        // Viber's `messages` table has no contact column at all. Printing
        // "(unknown)" there asserts a name existed and was not read.
        let without = ChatMessage::new("Viber", "Viber", "Android")
            .from_me(Some(true))
            .text(Some("hello".into()))
            .into_artifact(case, parent);
        assert_eq!(without.metadata["name"], "sent: hello");
    }

    #[test]
    fn the_derived_name_says_message_when_the_direction_is_unknown() {
        let (case, parent) = ids();
        let a = ChatMessage::new("Viber", "Viber", "Android")
            .text(Some("hello".into()))
            .into_artifact(case, parent);
        assert_eq!(a.metadata["name"], "message: hello");
    }

    #[test]
    fn the_preview_in_the_name_is_bounded_by_characters_not_bytes() {
        let (case, parent) = ids();
        // Slicing by byte index would panic mid-codepoint on a non-ASCII body.
        let body: String = "é".repeat(200);
        let a = ChatMessage::new("WeChat", "WeChat", "Android")
            .text(Some(body))
            .into_artifact(case, parent);
        let name = a.metadata["name"].as_str().unwrap().to_string();
        assert_eq!(name.chars().filter(|c| *c == 'é').count(), PREVIEW_CHARS);
    }

    #[test]
    fn a_display_override_replaces_the_derived_name_only() {
        let (case, parent) = ids();
        let a = ChatMessage::new("Snapchat", "Snapchat", "Android")
            .from_me(Some(true))
            .display("snap text: yo".into())
            .into_artifact(case, parent);
        assert_eq!(a.metadata["name"], "snap text: yo");
        assert_eq!(a.metadata["direction"], "sent");
    }

    #[test]
    fn magnitude_normaliser_covers_micro_milli_and_whole_seconds() {
        assert_eq!(
            unix_seconds_from_magnitude(1_700_000_000),
            Some(1_700_000_000)
        );
        assert_eq!(
            unix_seconds_from_magnitude(1_700_000_000_000),
            Some(1_700_000_000)
        );
        assert_eq!(
            unix_seconds_from_magnitude(1_700_000_000_000_000),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn an_unset_timestamp_is_none_rather_than_the_epoch() {
        assert_eq!(unix_seconds_from_magnitude(0), None);
        assert_eq!(unix_seconds_from_magnitude(-1), None);
        assert_eq!(unix_parts_from_magnitude(0), None);
        assert_eq!(unix_parts_from_magnitude(-1), None);
    }

    #[test]
    fn the_parts_view_keeps_the_fraction_the_seconds_view_divides_away() {
        // Seconds: the store recorded no fraction, so none is invented.
        assert_eq!(
            unix_parts_from_magnitude(1_700_000_000),
            Some((1_700_000_000, 0))
        );
        // Milliseconds: three digits of fraction, which is what orders two
        // records inside the same second.
        assert_eq!(
            unix_parts_from_magnitude(1_700_000_000_750),
            Some((1_700_000_000, 750_000_000))
        );
        // Microseconds: all six digits survive, rather than the value being
        // read as milliseconds and multiplied a thousandfold.
        assert_eq!(
            unix_parts_from_magnitude(1_700_000_000_123_456),
            Some((1_700_000_000, 123_456_000))
        );
    }

    #[test]
    fn the_seconds_view_is_exactly_the_parts_view_with_the_fraction_dropped() {
        // The bands must be judged once. If these two ever disagree, a parser
        // that wants the fraction and a parser that does not would place the
        // same stored value in different years.
        for raw in [
            -1,
            0,
            1,
            1_700_000_000,
            999_999_999_999,
            1_000_000_000_000,
            1_700_000_000_750,
            999_999_999_999_999,
            1_000_000_000_000_000,
            1_700_000_000_123_456,
            i64::MAX,
        ] {
            assert_eq!(
                unix_seconds_from_magnitude(raw),
                unix_parts_from_magnitude(raw).map(|(secs, _)| secs),
                "the two views disagree on {raw}"
            );
        }
    }

    #[test]
    fn every_band_of_one_instant_lands_in_the_plausible_window() {
        // 2023-11-14T22:13:20Z, as a store might have written it in any of the
        // three units this corpus contains.
        for raw in [1_700_000_000, 1_700_000_000_000, 1_700_000_000_000_000] {
            let secs = unix_seconds_from_magnitude(raw).expect("a positive value places");
            assert_eq!(secs, 1_700_000_000);
            assert!(
                is_plausible_instant_secs(secs),
                "{raw} placed at {secs}, outside the window a message may claim"
            );
        }
        // The window has to actually reject the failure it was written for: a
        // microsecond value read as milliseconds.
        assert!(!is_plausible_instant_secs(1_700_000_000_000));
        assert!(!is_plausible_instant_secs(0));
    }

    /// The other class this module exists to eliminate: a comms parser
    /// deciding for itself whether a stored number is seconds or milliseconds.
    ///
    /// A local `SECONDS_MILLIS_THRESHOLD` of 10^11 — "below this, seconds;
    /// at or above it, milliseconds" — is right about the two units its author
    /// had in front of them and silently wrong about the third. It reads a
    /// 16-digit microsecond store as milliseconds, so a message sent in 2023
    /// is filed under the year 55840, and every viewer downstream then needs a
    /// magnitude rescue to undo it. Three parsers carried a copy of that rule;
    /// the fix was to delete all three and route them through
    /// [`unix_seconds_from_magnitude`] / [`unix_parts_from_magnitude`], which
    /// judge three bands rather than two.
    ///
    /// This test is what stops a fourth copy appearing. The fingerprint is the
    /// threshold itself, in either the named or the bare-literal form — a
    /// parser that needs a unit judgement has a shared function to call, so
    /// there is no legitimate reason for one of these to be written out again.
    ///
    /// The list is explicit rather than a glob for the reason given on
    /// [`no_migrated_plugin_hand_builds_the_chat_record_shell`]: a scan that
    /// silently finds nothing would pass forever if the layout changed.
    #[test]
    fn no_comms_plugin_carries_its_own_seconds_versus_milliseconds_threshold() {
        const COMMS_PLUGINS: &[&str] = &[
            "seance_plugin_android_sms",
            "seance_plugin_call_history",
            "seance_plugin_signal",
            "seance_plugin_imessage",
            "seance_plugin_whatsapp",
            "seance_plugin_viber",
            "seance_plugin_kik",
            "seance_plugin_line",
            "seance_plugin_skype",
            "seance_plugin_telegram",
            "seance_plugin_instagram",
            "seance_plugin_snapchat",
            "seance_plugin_twitter",
            "seance_plugin_wechat",
            "seance_plugin_fbmessenger",
        ];
        // Both spellings of the same 10^11 boundary: the named constant the
        // three offenders used, and the bare literal a re-inlining would leave.
        const FINGERPRINTS: &[&str] = &[
            "SECONDS_MILLIS_THRESHOLD",
            "100_000_000_000",
            "100000000000",
        ];
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("seance_sqlite_util has a parent directory")
            .to_path_buf();

        let mut offenders = Vec::new();
        for crate_name in COMMS_PLUGINS {
            let src = workspace.join(crate_name).join("src");
            let entries = std::fs::read_dir(&src)
                .unwrap_or_else(|e| panic!("cannot scan {}: {e}", src.display()));
            let mut scanned = 0usize;
            for entry in entries {
                let path = entry.expect("readable directory entry").path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                scanned += 1;
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                for fingerprint in FINGERPRINTS {
                    if text.contains(fingerprint) {
                        offenders.push(format!("{}: {fingerprint}", path.display()));
                    }
                }
            }
            assert!(scanned > 0, "no .rs sources found under {}", src.display());
        }
        assert!(
            offenders.is_empty(),
            "these parsers judge seconds-vs-milliseconds with a local two-branch \
             threshold instead of the shared three-band normaliser, which is how a \
             microsecond store came to be dated to the year 55840: {offenders:?}"
        );
    }

    /// The class this module exists to eliminate: a plugin hand-building the
    /// chat-record map again, with its own answer to what an unknown looks
    /// like.
    ///
    /// `with_subtype("chat_message")` is the unambiguous fingerprint of a
    /// hand-built record — it appears in record construction and nowhere else,
    /// never in a test assertion. After the extraction the only occurrence in
    /// the crates listed here is this module's.
    ///
    /// The list is explicit rather than a glob so the test fails when a crate
    /// is missing: a scan that silently finds nothing would pass forever if the
    /// layout changed, which is the same silent-empty-result failure the rest
    /// of this crate exists to prevent. `imessage`, `whatsapp`, `signal` and
    /// `android_sms` are not listed yet — they build the same shell by hand and
    /// are the next crates to migrate; add each one here as it moves.
    #[test]
    fn no_migrated_plugin_hand_builds_the_chat_record_shell() {
        const MIGRATED: &[&str] = &[
            "seance_plugin_viber",
            "seance_plugin_kik",
            "seance_plugin_line",
            "seance_plugin_skype",
            "seance_plugin_telegram",
            "seance_plugin_instagram",
            "seance_plugin_snapchat",
            "seance_plugin_twitter",
            "seance_plugin_wechat",
            "seance_plugin_fbmessenger",
        ];
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("seance_sqlite_util has a parent directory")
            .to_path_buf();

        let mut offenders = Vec::new();
        for crate_name in MIGRATED {
            let src = workspace.join(crate_name).join("src");
            let entries = std::fs::read_dir(&src)
                .unwrap_or_else(|e| panic!("cannot scan {}: {e}", src.display()));
            let mut scanned = 0usize;
            for entry in entries {
                let path = entry.expect("readable directory entry").path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                scanned += 1;
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                if text.contains("with_subtype(\"chat_message\")") {
                    offenders.push(path.display().to_string());
                }
            }
            assert!(scanned > 0, "no .rs sources found under {}", src.display());
        }
        assert!(
            offenders.is_empty(),
            "these crates build the chat record by hand instead of using \
             ChatMessage, which is how the honesty contract drifted before: {offenders:?}"
        );
    }
}
