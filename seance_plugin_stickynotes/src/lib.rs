#![forbid(unsafe_code)]

//! Windows Sticky Notes (`ROADMAP` §2.6).
//!
//! Two formats, a decade apart:
//!
//! * `StickyNotes.snt` — an OLE2 compound file, one storage per note, written
//!   by the desktop gadget up to Windows 10's Anniversary update.
//! * `plum.sqlite` — the UWP app's store, under
//!   `…\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState`.
//!
//! # Every record says how far it has been validated
//!
//! When this crate was written no Sticky Notes evidence of either format existed
//! on the machine, so it was built from the formats' documented structure and
//! from the OLE2 reader this repository already uses for Outlook messages, and
//! designed so that **no stream-naming guess is load-bearing**: it enumerates
//! what is there and reports what it read.
//!
//! On 2026-09-24 the `.snt` reader was graded against one real Windows 7 file,
//! the NIST CFReDS Data Leakage case's (`SNT-1` in
//! `documentation/VALIDATION.md`), so `.snt` records carry a stamp saying that
//! and bounding it to one file and one plain-text note. On 2026-09-27 the
//! `plum.sqlite` reader was graded against one **lab-made** database written by
//! the real Sticky Notes app 6.1.4.0 on the project's Windows 11 lab VM
//! (`PLUM-1`), so records from a store at `user_version` 13 carry a stamp
//! bounded to that; any other schema version keeps the never-validated stamp.
//! See [`unvalidated`].

pub mod module;
pub mod plum;
pub mod rtf;
pub mod snt;
pub mod unvalidated;

#[cfg(test)]
mod plum_real_tests;
#[cfg(test)]
mod plum_tests;
#[cfg(test)]
mod rtf_tests;
#[cfg(test)]
mod snt_real_tests;
#[cfg(test)]
mod snt_tests;

pub use module::StickyNotesParser;
