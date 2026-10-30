//! This parser's schema-drift record (`ROADMAP.md` §1.4a): the shared
//! [`seance_sqlite_util::adopt::app_marker`] shape, filed under the parser's own
//! `*Incomplete` type. Until 2026-09-26 this file was one of five byte-identical
//! copies of that code (ROADMAP §5.11); the crate now declares its bound where it
//! reads the store and takes the record from the shared module, so the copies
//! cannot drift apart.
//!
//! For this parser the record is one per message TABLE walked, not one per
//! store: a modern store (`message`) carries one, a legacy store split into
//! `sms` and `mms` carries two, and a table whose `PRAGMA table_info` returned
//! no columns carries none — its walk has already recorded that it could not be
//! read, and a "no column recognised" record over it would say the wrong thing.

#[allow(unused_imports)]
pub(crate) use seance_sqlite_util::adopt::app_marker::{
    field_expr, user_version, SchemaBound, SchemaCheck, SchemaSupport, SchemaVersion,
};
