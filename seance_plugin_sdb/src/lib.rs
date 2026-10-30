#![forbid(unsafe_code)]
//! Windows application-compatibility shim databases (`.sdb`).
//!
//! `ROADMAP` §1.7. `sysmain.sdb` ships with Windows and holds the
//! compatibility fixes for thousands of programs; a **custom** database
//! installed with `sdbinst.exe` is a documented persistence and
//! defence-evasion technique, because a shim can inject a DLL into a process
//! the shimmed program starts.
//!
//! # What it reads
//!
//! Both container forms (`sdbf`, and the zlib-compressed `zdbf`), the tag
//! stream, and the string table. Measured against seven real Microsoft
//! databases from a Windows 11 ARM64 ISO, all of which consume exactly.
//!
//! # What it does not do
//!
//! It does not name tags it cannot name. 97 distinct tag ids occur across the
//! seven, and this build's table covers the documented ones; the rest are
//! carried by **numeric id** and counted on a census record, because a guessed
//! name is read as a fact.

pub mod container;
pub mod entities;
pub mod format;
mod module;
pub mod strings;

pub use module::SdbParser;

#[cfg(test)]
mod tests;
