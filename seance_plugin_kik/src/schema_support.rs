//! This parser's schema-drift record (`ROADMAP.md` §1.4a): the shared
//! [`seance_sqlite_util::adopt::app_marker`] shape, filed under the parser's own
//! `*Incomplete` type. Until 2026-09-26 this file was one of five byte-identical
//! copies of that code (ROADMAP §5.11); the crate now declares its bound where it
//! reads the store and takes the record from the shared module, so the copies
//! cannot drift apart.

#[allow(unused_imports)]
pub(crate) use seance_sqlite_util::adopt::app_marker::{
    field_expr, user_version, SchemaBound, SchemaCheck, SchemaSupport, SchemaVersion,
};
