//! Well-known SIDs, rights and flag names.
//!
//! Moved to [`seance_core::secdesc::wellknown`] on 2026-09-15 (`ROADMAP` §2.5),
//! because a registry key's ACL needs the same tables and the registry rights
//! had to live beside the file rights they are so easily confused with — `0x1`
//! is `FILE_READ_DATA` on a file and `KEY_QUERY_VALUE` on a key.
//!
//! Re-exported here so `crate::wellknown::…` still resolves for this crate and
//! its tests.

pub use seance_core::secdesc::wellknown::*;
