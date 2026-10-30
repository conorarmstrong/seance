//! Module trait and error types for forensic analysis plugins.
//!
//! This module defines the [`ForensicsModule`] trait that all analysis plugins must
//! implement to participate in the Seance processing pipeline.
//!
//! # Plugin Architecture
//!
//! Seance uses a publish-subscribe model where modules declare which artifact types
//! they can process. When an artifact is produced, the orchestrator routes it to all
//! subscribed modules for processing.
//!
//! # Example Plugin
//!
//! ```rust,ignore
//! use seance_core::artifact::{Artifact, ArtifactType};
//! use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
//!
//! pub struct MyParser;
//!
//! impl ForensicsModule for MyParser {
//!     fn id(&self) -> &str { "plugin.custom.myparser" }
//!     fn version(&self) -> &str { "1.0.0" }
//!
//!     fn subscribes_to(&self) -> Vec<ArtifactType> {
//!         vec![ArtifactType::FileEntry]
//!     }
//!
//!     fn input_capability(&self) -> InputCapability {
//!         InputCapability::Stream
//!     }
//!
//!     fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
//!         // Parse the artifact and return any discovered artifacts
//!         Ok(vec![])
//!     }
//! }
//! ```

use crate::artifact::{Artifact, ArtifactType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Information about a registered forensic analysis module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: String,
    pub version: String,
    pub subscribes_to: Vec<String>,
    pub execution_mode: String,
}

/// Errors that can occur during module processing.
///
/// Modules should return appropriate error variants to allow the orchestrator
/// to handle failures gracefully (skip the artifact, retry, or abort).
#[derive(Error, Debug)]
pub enum ModuleError {
    /// The input artifact is not in an expected format.
    /// Used when content detection fails or required metadata is missing.
    #[error("Invalid input format: {0}")]
    InvalidInputFormat(String),

    /// An I/O error occurred while reading artifact data.
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    /// The artifact data could not be parsed.
    /// Include details about the parse failure location when possible.
    #[error("Parsing Error: {0}")]
    ParsingError(String),

    /// An unrecoverable error that should halt processing.
    /// Use sparingly - prefer returning empty results for corrupt data.
    #[error("Fatal Error: {0}")]
    FatalError(String),
}

/// Controls when a module executes in the processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Runs automatically when matching artifacts enter the pipeline.
    Automatic,
    /// Only runs when explicitly triggered via ad-hoc execution.
    OptIn,
}

/// How a module intends to read its artifact's data.
///
/// # Advisory, not dispatch
///
/// **The orchestrator does not read this value, and does not prepare anything
/// on a module's behalf.** Every module receives the artifact's
/// [`DataSource`](crate::data_source::DataSource) as it is and arranges its own
/// access. This declaration documents intent — it is worth having for that, and
/// tests assert it — but nothing branches on it.
///
/// That is stated here because the doc comments used to promise otherwise, and
/// a promise a framework does not keep is worse than no promise: a plugin author
/// who read "the framework automatically registers a VFS" would write a parser
/// that waits for something that never arrives.
///
/// # If you are adding capability dispatch
///
/// Two things would have to be true, and neither is today: the orchestrator
/// would have to match on this before calling `process`, and the shared
/// machinery (a VFS shim, a spill-to-temp) would have to exist for it to hand
/// over. Until then the honest reading of every variant below is "this module
/// says it will do this itself".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputCapability {
    /// Sequential read with seeking via [`SourceCursor`](crate::data_source::SourceCursor).
    ///
    /// Best for: Archive formats (ZIP, TAR), Registry hives, document formats,
    /// and most file parsers that read data sequentially with occasional seeks.
    Stream,

    /// Direct random access to the underlying [`DataSource`](crate::data_source::DataSource).
    ///
    /// Best for: File system parsers that need efficient random access to
    /// different regions of a disk image.
    RandomAccess,

    /// SQLite database access via a custom VFS shim.
    ///
    /// **No such shim exists and no module declares this.** It described a
    /// capability that was designed and never built. Retained rather than
    /// deleted so that the enum's serialised form does not shift under anything
    /// that stored it, and so this note stays where the next reader looks.
    ///
    /// SQLite-backed plugins spill to a temporary file instead — see
    /// `seance_sqlite_util::TempDb`, which handles the staging, the `-wal`
    /// sibling, and cleanup on every exit path.
    ///
    /// Deprecated rather than deleted: removing it would shift the enum under
    /// anything that stored it, while leaving it un-flagged means a third-party
    /// plugin author can declare it, receive nothing, and have no way to find
    /// out except by reading this file. A compiler warning is the only channel
    /// that reaches them.
    #[deprecated(
        since = "0.9.0",
        note = "no VFS shim exists and the orchestrator does not dispatch on this; use InputCapability::Stream and spill with seance_sqlite_util::TempDb"
    )]
    SqliteVfs,

    /// The module needs a real path on the local filesystem — because it hands
    /// the data to a library or external tool that will only open a file.
    ///
    /// **The framework does not spill for you.** A module declaring this
    /// either requires a `path` in the artifact's metadata and refuses without
    /// one — `seance_container_e01` and `seance_container_aff4` both do, and
    /// neither spills anything — or writes the temporary file itself and
    /// removes it on every exit path, including the error ones.
    /// `seance_plugin_ios_backup` is the spill exemplar; copy that one rather
    /// than expecting the orchestrator to act.
    ///
    /// Spilling puts evidence-derived bytes in `$TMPDIR`, which may be less
    /// protected than the case workspace — see the evidence-handling section of
    /// `README.md`.
    FilePath,
}

/// The core trait that all forensic analysis modules must implement.
///
/// This trait defines the contract between the Seance orchestrator and analysis
/// plugins. Modules are discovered at startup and receive artifacts matching their
/// subscription list.
///
/// # Thread Safety
///
/// Modules must be `Send + Sync` as they may be invoked concurrently by the
/// orchestrator's worker threads. Avoid shared mutable state or use appropriate
/// synchronization primitives.
///
/// # Error Handling
///
/// Modules should handle corrupt or malformed input gracefully:
/// - Return `Ok(vec![])` to skip artifacts that don't match expected format
/// - Return `Err(ModuleError::ParsingError(...))` for parse failures
/// - Only use `FatalError` for truly unrecoverable situations
///
/// # Example
///
/// ```rust,ignore
/// impl ForensicsModule for EvtxParser {
///     fn id(&self) -> &str { "plugin.windows.evtx" }
///     fn version(&self) -> &str { "1.0.0" }
///
///     fn subscribes_to(&self) -> Vec<ArtifactType> {
///         vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
///     }
///
///     fn input_capability(&self) -> InputCapability {
///         InputCapability::Stream
///     }
///
///     fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
///         // Check if this is an EVTX file
///         if !self.is_evtx(artifact) {
///             return Ok(vec![]); // Skip non-EVTX files
///         }
///
///         // Parse and return event artifacts
///         let events = self.parse_events(artifact)?;
///         Ok(events)
///     }
/// }
/// ```
pub trait ForensicsModule: Send + Sync {
    /// Returns the unique identifier for this module.
    ///
    /// Convention: `plugin.<category>.<name>` (e.g., "plugin.windows.evtx").
    fn id(&self) -> &str;

    /// Returns the semantic version of this module.
    ///
    /// Format: `MAJOR.MINOR.PATCH` (e.g., "1.0.0").
    fn version(&self) -> &str;

    /// Returns the artifact types this module can process.
    ///
    /// The orchestrator only routes artifacts matching these types to this module.
    /// Modules may still filter further based on content detection.
    fn subscribes_to(&self) -> Vec<ArtifactType>;

    /// Returns how this module wants to access artifact data.
    ///
    /// See [`InputCapability`] for details on each access mode.
    fn input_capability(&self) -> InputCapability;

    /// Processes an artifact and returns any discovered child artifacts.
    ///
    /// # Arguments
    ///
    /// * `artifact` - The artifact to process
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Artifact>)` - List of discovered artifacts (may be empty)
    /// * `Err(ModuleError)` - Processing failed
    ///
    /// # Implementation Notes
    ///
    /// - Always set `parent_id` on produced artifacts using `with_parent()`
    /// - Use content-based detection rather than relying solely on filenames
    /// - Handle corrupt input gracefully by returning empty results
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError>;

    /// Processes an artifact, handing finished batches to `sink` as it goes
    /// instead of holding every product until the end (HUNT-125).
    ///
    /// `process` returns one `Vec` for the whole artifact, so a module that
    /// walks a whole volume holds everything it found, in memory, until the
    /// walk ends. That is memory proportional to the evidence. A module whose
    /// output is large and independent of the rest of its own output overrides
    /// this, passes each full batch to `sink` and drops it, and returns only
    /// what it had to keep back.
    ///
    /// Contract for what goes to `sink`:
    ///
    /// * It is dispatched exactly as if it had been returned: persisted, and
    ///   re-queued to the modules that subscribe to its type.
    /// * It must not need any later step of the module's own post-processing
    ///   (nothing that looks across the whole returned set), and must not
    ///   contain `file_hash` records.
    /// * A batch is final. If the module goes on to fail, the batches already
    ///   sunk stay recorded, and the run's history says it failed.
    ///
    /// The default sinks nothing and calls [`process`](Self::process), so a
    /// module that does not override it behaves exactly as before.
    fn process_streaming(
        &self,
        artifact: &Artifact,
        sink: &mut dyn FnMut(Vec<Artifact>),
    ) -> Result<Vec<Artifact>, ModuleError> {
        let _ = sink;
        self.process(artifact)
    }

    /// Returns the execution mode for this module.
    ///
    /// Defaults to [`ExecutionMode::Automatic`], meaning the module runs whenever
    /// matching artifacts enter the pipeline. Override to return [`ExecutionMode::OptIn`]
    /// for expensive modules that should only run when explicitly triggered.
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
}
