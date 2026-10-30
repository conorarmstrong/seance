#![forbid(unsafe_code)]
//! # Seance Core
//!
//! Core forensics framework providing artifacts, data sources, modules, and orchestration.
//!
//! ## Example: Creating an Artifact
//!
//! ```rust
//! use seance_core::artifact::{Artifact, ArtifactType};
//! use uuid::Uuid;
//! use serde_json::json;
//!
//! let case_id = Uuid::new_v4();
//! let artifact = Artifact::new(
//!     case_id,
//!     ArtifactType::FileEntry,
//!     None,
//!     json!({"name": "example.txt"}),
//! );
//!
//! assert_eq!(artifact.case_id, case_id);
//! ```
//!
//! ## Example: Using DataSource
//!
//! ```rust
//! use seance_core::data_source::{DataSource, FileDataSource};
//! # use std::io::Write;
//! # let mut temp = tempfile::NamedTempFile::new().unwrap();
//! # temp.write_all(b"Test data").unwrap();
//! # temp.flush().unwrap();
//!
//! let source = FileDataSource::new(temp.path().to_path_buf()).unwrap();
//! let mut buffer = vec![0u8; 9];
//! let bytes = source.read_at(0, &mut buffer).unwrap();
//! assert_eq!(bytes, 9);
//! ```

#![allow(clippy::type_complexity, clippy::too_many_arguments)]
pub mod artifact;
pub mod blob_text;
pub mod codepage;
pub mod compression;
pub mod credential;
pub mod data_source;
pub mod db;
pub mod evidence_loss;
pub mod file_detection;
pub mod filter;
pub mod finding;
/// Free clusters as regions a carver and a scanner can be pointed at.
pub mod free_space;
pub mod guid;
pub mod hashing;
pub mod ingestion;
pub mod io;
pub mod memory_guard;
pub mod models;
pub mod module;
pub mod ntfs_timestamps;
pub mod orchestrator;
pub mod profile;
pub mod search;
pub mod secdesc;
pub mod shadow_copy;
/// File slack as regions (HUNT-124).
pub mod slack;
pub mod spilled_source;
pub mod task_queue;
pub mod temp_spill;
pub mod time;
pub mod timestamp;
pub mod typedstream;
pub mod virtual_columns;

/// Shared `DataSource` test doubles proving the short-read contract in
/// [`crate::io`].
///
/// Available to this crate's own tests, and to a downstream crate that opts in
/// with `seance_core = { path = "../seance_core", features = ["test-support"] }`
/// under `[dev-dependencies]`. Resolver 2 keeps that feature out of a normal
/// build, so no dependency edge compiles this module; `--all-features` still
/// does, which is why nothing in it has side effects.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod data_source_tests;
