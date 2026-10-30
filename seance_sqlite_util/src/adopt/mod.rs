//! The per-parser side of the schema-drift defence, shared (ROADMAP §5.11).
//!
//! [`crate::stale`] holds the mechanism — [`crate::SupportedRange`],
//! [`crate::StaleWarning`], [`crate::FieldMap`]. This module holds what an
//! adopting parser used to keep as its own `schema_support.rs`: the declared
//! bound, where the store's version is read from, and the record a parse owes.
//! Fifteen crates carried six near-identical copies of it until 2026-09-26; each
//! now declares its bound and calls one of the two record shapes here:
//!
//! * [`app_marker`] — the record filed under the parser's own `<App>Incomplete`
//!   type (WhatsApp, Telegram, Viber, Kik, Signal);
//! * [`note_marker`] — the per-store notes filed under the parser's own
//!   `<App>Incomplete` type, a disclosure and a claim kept apart (Snapchat,
//!   Skype, LINE, WeChat, Instagram);
//! * [`stale_marker`] — the record filed as a shared `ParserStaleWarning`
//!   (contacts, browser history, installed apps, Android apps, mobile device).
//! * [`inline_marker`] — the same `ParserStaleWarning` records for a parser
//!   that keeps its field maps inline with no `SchemaSupport` bound (Android
//!   SMS, call history, iMessage, Twitter, Facebook Messenger), lifted from
//!   five copies later the same day.

/// The subtype of every schema record, in every shape here and in [`crate::stale`]
/// (ROADMAP §5.11, decided 2026-09-26). Until then the app and note shapes
/// carried `parse_incomplete` (and the note shape `schema_support` for a
/// disclosure); whether a record claims incompleteness is its
/// `content_incomplete` flag, not its subtype.
pub const SCHEMA_SUBTYPE: &str = "parser_stale";

/// The `warning_class` every schema record carries, whatever its `type`, so a
/// filter finds a parser's schema records without knowing its record types.
pub const WARNING_CLASS: &str = "ParserStaleWarning";

pub mod app_marker;
pub mod inline_marker;
pub mod note_marker;
pub mod stale_marker;

#[cfg(test)]
mod golden_tests;
