//! This parser's schema-drift notes (ROADMAP §1.4a): the shared
//! [`seance_sqlite_util::adopt::note_marker`] shape, filed under the parser's
//! own `<App>Incomplete` type. Until 2026-09-26 this file was one of five
//! byte-identical copies of that code (ROADMAP §5.11); the crate now declares
//! its bound where it reads the store and takes the notes from the shared
//! module, so the copies cannot drift apart.

#[allow(unused_imports)]
pub use seance_sqlite_util::adopt::note_marker::{
    assess, read_user_version, Observation, SchemaSupport, SchemaVersion, SupportBound,
    DISCLOSURE_SUBTYPE, INCOMPLETE_SUBTYPE, USER_VERSION_LOCATOR, WARNING_CLASS,
};
