//! This crate's adoption of the schema-drift defence (`ROADMAP.md` §1.4a): the
//! shared [`seance_sqlite_util::adopt::stale_marker`] shape, filed as a
//! `ParserStaleWarning`. Until 2026-09-26 this file was one of five
//! near-identical copies of that code (ROADMAP §5.11); the crate now declares
//! each store's validated range where it reads the store and takes the version
//! locators and the records from the shared module, so the copies cannot drift
//! apart. Every range endpoint an adopter declares was read out of a real
//! database, and the `evidence` string on each `SchemaSupport` names the file.

#[allow(unused_imports)]
pub(crate) use seance_sqlite_util::adopt::stale_marker::{
    assess_version, keyed_version, plan_columns, single_row_version, unresolved_fields_marker,
    user_version, ColumnPlan, SchemaSupport, SchemaVersion,
};
