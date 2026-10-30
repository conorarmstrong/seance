//! The seam every OS-specific memory analysis plugs into.
//!
//! Séance is built on [`ForensicsModule`]: a module declares which artifact
//! types it subscribes to, and the orchestrator hands it matching artifacts.
//! Memory analysis is no different, but it has one wrinkle that invites a
//! mistake — the analysis crates (Windows, Linux, macOS) are large, and the
//! interesting work is all in walking kernel structures, so it is easy to write
//! a crate full of correct analysis that the orchestrator never calls because
//! nobody implemented the trait.
//!
//! That is what this module prevents. An OS crate implements [`MemoryAnalysis`]
//! — a small trait about *analysis*, with no orchestrator concepts in it — and
//! wraps it in [`MemoryAnalysisModule`], which is the `ForensicsModule`. The
//! subscription filter, the "is this actually a memory image" check, the layer
//! reconstruction and the artifact bookkeeping are written once here and shared,
//! so an OS crate cannot be wired up wrongly and cannot forget to be wired up at
//! all.
//!
//! ## Where this sits in the pipeline
//!
//! ```text
//! RawEvidence / FileEntry
//!         │
//!         ▼
//! container.memory_image        (crate::module::MemoryImageModule)
//!    emits ParsedRecord { type: "MemoryImage", analysis_stage: "physical_only" }
//!         │
//!         ▼
//! plugin.memory.<os>            (MemoryAnalysisModule<A>)
//!    emits ParsedRecord (and RawEvidence / FileEntry for recovered
//!    content), superseding analysis_stage. It emits no TimelineEvent:
//!    memory times stay inside the records and do not reach the case
//!    timeline (ROADMAP "Memory events on the timeline").
//! ```
//!
//! The `analysis_stage` marker on the phase-1 record exists precisely so this
//! stage can supersede it: an examiner reading a case must be able to tell
//! "the image loaded" from "the image was analysed".
//!
//! ## Second evidence items
//!
//! An analysis sometimes needs a *second* file to answer a question about the
//! first: a Windows pagefile holds the pages the kernel swapped out, and without
//! it those pages are holes. [`CaseEvidence`] is how such a file is reached, and
//! it is here rather than in an OS crate because the problem is the same for
//! every tier and the mistake is the same too — a resolver held by a module that
//! serves every case at once must never resolve one case's reference against
//! another case's evidence. Resolution therefore takes the image record, which
//! carries the case, rather than being fixed when the module is constructed.
//!
//! [`EvidenceBesideImage`] is the resolver that needs no case database: it opens
//! evidence sitting beside the memory image, inside the same directory of the
//! case's evidence tree, and refuses anything outside it. A deployment that
//! stores evidence in a database supplies its own implementation instead.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, warn};

use crate::format::MemoryImageFormat;
use crate::layer::MemoryLayer;
use crate::meta::LayerMeta;
use crate::module::refused;
use crate::physical::PhysicalLayer;

/// The record type the container stage emits and this stage consumes.
pub const MEMORY_IMAGE_RECORD: &str = "MemoryImage";

/// Split one of the memory tier's environment lists into its entries.
///
/// A list is separated by `:` or `;`, and a colon that opens a Windows drive
/// path is **not** a separator. `SEANCE_PAGEFILES=0=C:\evidence\pagefile.sys`
/// split on every colon yields `0=C` — an index naming the relative path `C`,
/// which opens something else or nothing — and the orphaned
/// `\evidence\pagefile.sys`, which has no `=` and is dropped with a warning. So
/// the examiner who set it correctly gets no pagefile attached, and a
/// `SEANCE_SYMBOL_DIRS` written the same way loses both halves silently to the
/// `is_dir` filter that follows it.
///
/// One parser for every OS tier, here rather than in each of them, because the
/// defect was the same line copied three times and fixing one copy leaves the
/// other two breaking the same examiner's configuration.
///
/// A drive colon is recognised structurally rather than by platform: the entry
/// travels with the case notes, and a list an examiner wrote on Windows has to
/// mean the same thing on the Linux machine that re-runs the analysis.
/// `std::env::split_paths` would give the opposite — the same string parsed two
/// ways — which is how a re-run silently examines different evidence.
///
/// Entries are trimmed, and empty ones dropped: a trailing separator is a typo,
/// not a request to open the current directory.
pub fn split_env_list(list: &str) -> Vec<&str> {
    let bytes = list.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    for (at, byte) in bytes.iter().enumerate() {
        let separates = match byte {
            b';' => true,
            b':' => !is_drive_colon(bytes, start, at),
            _ => false,
        };
        if separates {
            out.push(&list[start..at]);
            start = at + 1;
        }
    }
    out.push(&list[start..]);
    out.into_iter()
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Where an examiner may put a symbol file so a run finds it, in the order the
/// resolvers read them.
///
/// Stated on every discovery failure, on every OS tier. `symbol_dirs_searched`
/// only ever names directories that already exist, so on a machine with none of
/// them the list is empty or holds a single repository-relative developer path —
/// which reads as a broken build rather than as a missing ISF. What was tried
/// and what is accepted are different facts and both belong on the record.
///
/// Shared here rather than restated per tier: the resolution order is the same
/// for Windows, Linux and macOS, and a copy that drifts is worse than no copy.
pub const SYMBOL_DIR_GUIDANCE: &[&str] = &[
    "SEANCE_SYMBOL_DIRS (separated list; takes precedence)",
    "<directory containing the seance executable>/symbols",
    "./symbols (relative to the working directory)",
];

/// Whether the colon at `at` is the drive colon of the entry that began at
/// `start`, rather than the separator before the next entry.
///
/// The only shape a colon takes inside a Windows path is `X:\` or `X:/` at the
/// very front of it, so the letter must open the entry — allowing for leading
/// spaces, and for the `index=` prefix a pagefile entry carries — and a
/// separator must follow. Anything else is a separator, which is what keeps
/// every list an examiner has ever written on Unix parsing exactly as before.
fn is_drive_colon(bytes: &[u8], start: usize, at: usize) -> bool {
    if at == 0 || !bytes[at - 1].is_ascii_alphabetic() {
        return false;
    }
    let letter = at - 1;
    let before = &bytes[start..letter];
    let opens_path = before.iter().all(u8::is_ascii_whitespace) || before.last() == Some(&b'=');
    opens_path && matches!(bytes.get(at + 1), Some(b'\\') | Some(b'/'))
}

/// A second evidence item the case already holds, opened by the name an
/// examiner writes.
///
/// The gap this closes: an analysis is handed the memory image and nothing
/// else, so the only way to attach a pagefile was an absolute host path. A
/// pagefile that lives inside the ingested case — beside the capture in the
/// evidence tree, or extracted from a disk image into the case's own storage —
/// could not be named at all.
///
/// Resolution takes the image record rather than being fixed when the resolver
/// is built. One module instance serves every case in the process, and a
/// resolver that had bound itself to a case at construction would answer case
/// A's reference with case B's bytes — the exact failure that makes swapped
/// pages worse than useless, because a wrong pagefile does not fail, it returns
/// another machine's memory.
///
/// An implementation must **refuse** rather than fall back. A reference that
/// cannot be resolved inside the case must not quietly become a host path: the
/// examiner asked for one file and would be given another, with nothing in the
/// case saying so.
pub trait CaseEvidence: Send + Sync + std::fmt::Debug {
    /// Open the item `reference` names, for the case the image record belongs
    /// to.
    ///
    /// `Err` carries what an examiner has to read to fix it — which reference,
    /// looked for where, and why it was refused.
    fn open(&self, image_record: &Artifact, reference: &str) -> EvidenceResult;

    /// Where this resolver looks, for the record that says where a second
    /// evidence item's bytes came from.
    fn describes(&self) -> String;
}

/// What resolving a [`CaseEvidence`] reference produces: the item's bytes, or
/// the sentence an examiner needs in order to fix the reference.
///
/// The error is prose rather than a variant because there is nothing to branch
/// on — every failure ends the same way, with the pagefile not attached — and
/// the whole value of it is the sentence that names which reference was looked
/// for, where, and why it was refused.
pub type EvidenceResult = Result<Arc<dyn DataSource>, String>;

/// The resolver that needs no case database: evidence sitting beside the memory
/// image, in the same directory of the case's evidence tree.
///
/// This is the ordinary memory-forensics layout — a capture and the machine's
/// `pagefile.sys` acquired together into one evidence folder — and it is
/// reachable with nothing wired up but the environment variable that names the
/// file.
///
/// Confinement is deliberate and narrow. A reference is a relative path with no
/// `..` in it, resolved against the image's own directory, and the resolved
/// path is re-checked against that directory after canonicalisation so a
/// symlink cannot walk out of it. A reference the examiner meant to be anywhere
/// else on the host is what `SEANCE_PAGEFILES` is for, and the two must not be
/// the same variable: one names evidence, the other names a path.
///
/// An image with no file of its own — a capture read out of a disk image, an
/// archive or a container — is refused by name. That refusal is what a
/// database-backed [`CaseEvidence`] closes; guessing a host path for it would
/// be the fabrication this crate exists to prevent.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvidenceBesideImage;

impl CaseEvidence for EvidenceBesideImage {
    fn open(&self, image_record: &Artifact, reference: &str) -> EvidenceResult {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err("an empty reference names no evidence".to_string());
        }
        let relative = Path::new(reference);
        if relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(format!(
                "{reference:?} is not a reference to evidence inside the case: it is absolute or \
                 climbs out of the memory image's own directory. Name a path under that \
                 directory, or use SEANCE_PAGEFILES for a file elsewhere on this host"
            ));
        }

        let image_path = image_record
            .data
            .as_ref()
            .and_then(|source| source.get_underlying_path())
            .ok_or_else(|| {
                format!(
                    "{reference:?} could not be resolved: this memory image has no file of its \
                     own in the case — it was read out of a disk image, an archive or another \
                     container — so there is no evidence directory to resolve against. Reaching \
                     it needs a case-database resolver, and a host path guessed for it would be \
                     a different file"
                )
            })?;
        let root = image_path.parent().ok_or_else(|| {
            format!(
                "{reference:?} could not be resolved: the memory image's own path ({}) has no \
                 directory to resolve against",
                image_path.display()
            )
        })?;

        let root = canonical(root)?;
        let candidate = canonical(&root.join(relative))?;
        if !candidate.starts_with(&root) {
            return Err(format!(
                "{reference:?} resolves to {}, which is outside the memory image's own directory \
                 ({}); it is not evidence this case holds beside the image",
                candidate.display(),
                root.display()
            ));
        }

        let source = FileDataSource::new(candidate.clone()).map_err(|err| {
            format!(
                "{reference:?} resolves to {}, which could not be opened: {err}",
                candidate.display()
            )
        })?;
        Ok(Arc::new(source) as Arc<dyn DataSource>)
    }

    fn describes(&self) -> String {
        "evidence held beside the memory image, in the same directory of the case's evidence tree"
            .to_string()
    }
}

/// Canonicalise a path, reporting the failure in the examiner's terms.
///
/// Canonicalisation is what makes the confinement check meaningful — it is the
/// step that resolves a symlink pointing out of the evidence directory — so a
/// path that will not canonicalise is refused rather than used as written.
fn canonical(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|err| format!("{} could not be read: {err}", path.display()))
}

/// What an OS-specific memory analysis has to provide.
///
/// Deliberately small and free of orchestrator concepts: an implementor thinks
/// about kernel structures, not about artifact subscriptions. Everything to do
/// with being a module is handled by [`MemoryAnalysisModule`].
pub trait MemoryAnalysis: Send + Sync + 'static {
    /// Module id, following the tree's convention: `plugin.memory.windows`.
    fn id(&self) -> &str;

    /// Semantic version of this analysis.
    fn version(&self) -> &str;

    /// The operating system this analysis understands, for logging and for the
    /// `analysed_os` field on emitted records.
    fn os(&self) -> &str;

    /// Analyse a decoded physical address space.
    ///
    /// `physical` is the image's physical memory. `image_record` is the
    /// `MemoryImage` artifact from the container stage, whose metadata carries
    /// the format, the addressable size and any incompleteness discovered while
    /// decoding — all of which an analysis should respect rather than rediscover.
    ///
    /// Returning `Ok(vec![])` means "this analysis does not apply to this image"
    /// — a Linux analysis handed a Windows crash dump, say. Returning `Err`
    /// means the analysis *should* have applied and could not complete, which is
    /// a finding in its own right and must not be silently swallowed.
    fn analyse(
        &self,
        physical: Arc<dyn MemoryLayer>,
        image_record: &Artifact,
    ) -> Result<Vec<Artifact>, ModuleError>;
}

/// Adapts a [`MemoryAnalysis`] into a [`ForensicsModule`].
///
/// Registering one of these is the only way an OS analysis reaches the
/// orchestrator, which is the point: the wiring is written once, here, rather
/// than re-derived (and forgotten) in each OS crate.
#[derive(Debug)]
pub struct MemoryAnalysisModule<A: MemoryAnalysis> {
    analysis: A,
}

impl<A: MemoryAnalysis> MemoryAnalysisModule<A> {
    /// Wrap an analysis so the orchestrator can drive it.
    pub fn new(analysis: A) -> Self {
        Self { analysis }
    }

    /// The wrapped analysis.
    pub fn analysis(&self) -> &A {
        &self.analysis
    }
}

/// Whether this artifact is the memory-image record the container stage emits.
///
/// Checked on `type` rather than on a name or an extension: the container stage
/// is the only thing that produces this record, and it always sets the field.
pub fn is_memory_image_record(artifact: &Artifact) -> bool {
    artifact
        .metadata
        .get("type")
        .and_then(|v| v.as_str())
        .is_some_and(|t| t == MEMORY_IMAGE_RECORD)
}

/// Whether the container stage decoded the image successfully.
///
/// A failure record carries the same `type` so an examiner sees it, but there is
/// no address space behind it to analyse.
fn decoded_successfully(artifact: &Artifact) -> bool {
    artifact
        .metadata
        .get("decode_failed")
        .and_then(|v| v.as_bool())
        != Some(true)
}

impl<A: MemoryAnalysis> ForensicsModule for MemoryAnalysisModule<A> {
    fn id(&self) -> &str {
        self.analysis.id()
    }

    fn version(&self) -> &str {
        self.analysis.version()
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // The container stage emits the decoded image as a ParsedRecord. This
        // stage consumes that, never raw evidence: re-detecting the format here
        // would duplicate the container stage and could disagree with it.
        vec![ArtifactType::ParsedRecord]
    }

    fn input_capability(&self) -> InputCapability {
        // Page-table walks and pool scans seek constantly; a stream would make
        // every translation a re-read from the start.
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if !is_memory_image_record(artifact) {
            return Ok(Vec::new());
        }
        if !decoded_successfully(artifact) {
            debug!(
                "{}: image record reports a decode failure; nothing to analyse",
                self.analysis.id()
            );
            return Ok(Vec::new());
        }
        let Some(source) = artifact.data.as_ref() else {
            // The container stage always attaches the decoded layer. An image
            // record without one is a pipeline defect, not an empty image, and
            // saying so beats reporting "no processes found".
            warn!(
                "{}: memory image record carries no address space",
                self.analysis.id()
            );
            return Err(refused(
                "memory image record carries no decoded address space".into(),
            ));
        };

        let physical = physical_layer_for(source, artifact)?;
        debug!(
            "{}: analysing {} bytes of {} memory",
            self.analysis.id(),
            physical.size(),
            self.analysis.os()
        );
        self.analysis.analyse(physical, artifact)
    }
}

/// Rebuild a [`MemoryLayer`] view over the decoded address space carried by the
/// image record.
///
/// The container stage hands the decoded layer down as a `DataSource`, which is
/// what artifacts carry. Wrapping it in a [`PhysicalLayer`] restores the layer
/// interface — `mapping`, `min_address`, `max_address` — that translation and
/// scanning need.
///
/// Holes survive this round trip: the decoded layer already answers a read into
/// an unacquired region with an error carrying the hole, and `PhysicalLayer`
/// forwards rather than reinterprets it. What does *not* survive is the segment
/// map, so `mapping()` here describes the address space as contiguous. A caller
/// that needs the true segment geometry should read `incomplete` from the image
/// record's metadata, which the container stage populated from the format
/// reader and which travels with the artifact.
pub(crate) fn physical_layer_for(
    source: &Arc<dyn DataSource>,
    image_record: &Artifact,
) -> Result<Arc<dyn MemoryLayer>, ModuleError> {
    // Restore what the container stage knew, rather than starting from a blank
    // `LayerMeta`. `PhysicalLayer::raw` would build one declaring the format
    // `Raw` with no notes and no incompleteness, and discovery would then never
    // see the directory table base a crash dump states in its own header.
    let meta = image_record
        .metadata
        .get("layer_meta")
        .map(LayerMeta::from_json)
        .unwrap_or_else(|| LayerMeta::new(MemoryImageFormat::Raw));

    // The geometry, when the container recorded one. Its absence is not a claim
    // of full coverage — a flat image records nothing here because the identity
    // mapping is already correct for it — but its PRESENCE means the image is
    // sparse, and a layer that answered "all backed" for it would hand every
    // coverage figure downstream a range that was never acquired.
    //
    // Every entry must parse. Dropping the ones that do not would widen the
    // declared coverage silently — an unreadable range would become a range
    // nobody said was missing — so a geometry that cannot be read in full is a
    // refusal, not a shorter geometry.
    let backed: Option<Vec<(u64, u64)>> = match image_record.metadata.get("backed_ranges") {
        None => None,
        Some(value) => {
            let items = value.as_array().ok_or_else(|| {
                refused("the image record's backed_ranges is not a list of ranges".to_string())
            })?;
            let mut ranges = Vec::with_capacity(items.len());
            for item in items {
                let parsed = item
                    .get("start")
                    .and_then(|v| v.as_u64())
                    .zip(item.get("length").and_then(|v| v.as_u64()));
                match parsed {
                    Some(range) => ranges.push(range),
                    None => {
                        return Err(refused(format!(
                            "the image record states a backed range this tool cannot read \
                             ({item}), so the acquisition's coverage cannot be established"
                        )))
                    }
                }
            }
            Some(ranges)
        }
    };

    let layer = PhysicalLayer::new(Arc::clone(source), meta).map_err(|e| {
        refused(format!(
            "the decoded address space could not be re-opened for analysis: {e}"
        ))
    })?;
    let layer = match backed {
        // A declared geometry with nothing in it says "no address in this image
        // was acquired". Whatever produced it was wrong, and the one reading it
        // must not resolve that by falling back to "all of it was acquired".
        Some(ranges) if ranges.is_empty() => {
            return Err(refused(
                "the image record declares a geometry that lists no acquired ranges; \
                 its coverage cannot be established"
                    .to_string(),
            ))
        }
        Some(ranges) => layer.with_backed(ranges),
        None => layer,
    };
    Ok(Arc::new(layer) as Arc<dyn MemoryLayer>)
}

/// Metadata every analysis stage should stamp on the records it emits.
///
/// Supersedes the container stage's `analysis_stage: "physical_only"`, so a case
/// shows what was actually done rather than only what was loaded.
pub fn analysed_stamp(os: &str, module_id: &str, module_version: &str) -> serde_json::Value {
    json!({
        "analysis_stage": "analysed",
        "analysed_os": os,
        "analysed_by": module_id,
        "analysed_by_version": module_version,
    })
}

/// The stamp for the profile record of an analysis that succeeded, which also
/// **supersedes** the failure record an earlier pass left behind.
///
/// A memory image whose symbols were missing records a `MemoryProfile` saying
/// the profile was not established, naming the PDB to fetch. Fetching it and
/// re-running is the action the product asks for — and the case then held both
/// records, "not established" and "analysed", with nothing saying which was
/// current (`HUNT-090`'s "a symbol pack that arrives after the first memory
/// pass"). The state lives in `analysis_stage` rather than `status`, so the
/// record names the field as well as the value.
pub fn analysed_profile_stamp(
    os: &str,
    module_id: &str,
    module_version: &str,
) -> serde_json::Value {
    let mut stamp = analysed_stamp(os, module_id, module_version);
    let obj = stamp.as_object_mut().expect("stamp is an object");
    obj.insert("supersedes_status".into(), json!("discovery_failed"));
    obj.insert("supersedes_field".into(), json!("analysis_stage"));
    stamp
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::Artifact;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingAnalysis {
        calls: AtomicUsize,
    }

    impl MemoryAnalysis for CountingAnalysis {
        fn id(&self) -> &str {
            "plugin.memory.test"
        }
        fn version(&self) -> &str {
            env!("CARGO_PKG_VERSION")
        }
        fn os(&self) -> &str {
            "test"
        }
        fn analyse(
            &self,
            _physical: Arc<dyn MemoryLayer>,
            _image_record: &Artifact,
        ) -> Result<Vec<Artifact>, ModuleError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    fn module() -> MemoryAnalysisModule<CountingAnalysis> {
        MemoryAnalysisModule::new(CountingAnalysis {
            calls: AtomicUsize::new(0),
        })
    }

    fn image_artifact(data: Option<Arc<dyn DataSource>>) -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            data,
            json!({"type": "MemoryImage", "image_format": "raw"}),
        )
    }

    #[test]
    fn an_analysis_subscribes_to_the_record_the_container_stage_emits() {
        // Subscribing to RawEvidence here would mean re-detecting the format and
        // possibly disagreeing with the stage that already decoded it.
        assert_eq!(module().subscribes_to(), vec![ArtifactType::ParsedRecord]);
    }

    #[test]
    fn an_artifact_that_is_not_a_memory_image_is_left_alone() {
        let m = module();
        let other = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "BrowserHistory"}),
        );
        assert!(m.process(&other).unwrap().is_empty());
        assert_eq!(m.analysis().calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_image_record_with_no_address_space_is_an_error_not_an_empty_result() {
        // "No processes found" and "there was nothing to look at" must never be
        // the same answer.
        let m = module();
        let err = m.process(&image_artifact(None)).unwrap_err();
        assert!(
            err.to_string().contains("no decoded address space"),
            "{err}"
        );
        assert_eq!(m.analysis().calls.load(Ordering::SeqCst), 0);
    }

    /// And the error has to survive the orchestrator, which is decided by the
    /// variant and not by the sentence.
    ///
    /// `ModuleError::InvalidInputFormat` is its *skip* signal: both arms that
    /// match it (`seance_core/src/orchestrator.rs`, automatic and ad-hoc) log at
    /// `debug!`, broadcast `ModuleCompleted` with zero artifacts, and write a
    /// processing-log row with `status: "skipped"` and **`error_message: None`**.
    /// Every refusal here is a statement that a coverage or an address space
    /// could not be established, and that statement is the whole deliverable —
    /// routed through that variant it is dropped, and the case dashboard shows
    /// a memory stage that ran and found nothing.
    #[test]
    fn a_refusal_does_not_use_the_variant_the_orchestrator_swallows() {
        let m = module();
        let no_space = m.process(&image_artifact(None)).unwrap_err();

        let bad_geometry = record_with_geometry(0x4000, json!([{"start": "nope", "length": 1}]));
        let data = bad_geometry.data.clone().unwrap();
        let unreadable_geometry = physical_layer_for(&data, &bad_geometry)
            .expect_err("a range that cannot be read is not a shorter geometry");

        let no_ranges = record_with_geometry(0x4000, json!([]));
        let data = no_ranges.data.clone().unwrap();
        let empty_geometry =
            physical_layer_for(&data, &no_ranges).expect_err("no ranges is not full coverage");

        for err in [no_space, unreadable_geometry, empty_geometry] {
            assert!(
                !matches!(err, ModuleError::InvalidInputFormat(_)),
                "refused as InvalidInputFormat, which the orchestrator records as \
                 status=\"skipped\" with error_message=None: {err}"
            );
        }
    }

    #[test]
    fn a_record_reporting_a_decode_failure_is_not_analysed() {
        let m = module();
        let mut art = image_artifact(None);
        art.metadata
            .as_object_mut()
            .unwrap()
            .insert("decode_failed".into(), json!(true));
        assert!(m.process(&art).unwrap().is_empty());
        assert_eq!(m.analysis().calls.load(Ordering::SeqCst), 0);
    }

    /// An image record carrying `data` and whatever geometry `ranges` states.
    fn record_with_geometry(bytes: usize, ranges: serde_json::Value) -> Artifact {
        let data: Arc<dyn DataSource> = Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(vec![0u8; bytes]),
        );
        let mut art = image_artifact(Some(data));
        art.metadata
            .as_object_mut()
            .unwrap()
            .insert("backed_ranges".into(), ranges);
        art
    }

    #[test]
    fn a_declared_geometry_that_cannot_be_read_is_refused_rather_than_shortened() {
        // The defect this guards: unreadable entries were dropped one by one.
        // A range that fell out of the list was not reported missing — it became
        // a range nobody had said was acquired, which reads downstream as an
        // acquisition that never covered it, or, if every entry fell out, as an
        // image with no gaps at all.
        let art = record_with_geometry(
            0x4000,
            json!([{"start": 0x1000, "length": 0x1000}, {"start": "0x3000", "length": 0x1000}]),
        );
        let data = art.data.clone().unwrap();
        let err = physical_layer_for(&data, &art).expect_err("half a geometry is not a geometry");
        assert!(err.to_string().contains("coverage"), "{err}");

        // A geometry listing nothing is not "everything".
        let empty = record_with_geometry(0x4000, json!([]));
        let data = empty.data.clone().unwrap();
        let err = physical_layer_for(&data, &empty).expect_err("no ranges is not full coverage");
        assert!(err.to_string().contains("no acquired ranges"), "{err}");

        // And a geometry that reads cleanly still produces the sparse layer.
        let good = record_with_geometry(0x4000, json!([{"start": 0x1000, "length": 0x1000}]));
        let data = good.data.clone().unwrap();
        let layer = physical_layer_for(&data, &good).expect("a readable geometry");
        assert!(layer.is_valid(0x1000, 0x1000));
        assert!(!layer.is_valid(0, 0x1000));
    }

    #[test]
    fn a_crash_dumps_published_dtb_survives_the_artifact_boundary() {
        // The defect this guards: the container stage decodes a crash dump and
        // records the directory table base the dump header publishes, then the
        // analysis stage reopened the carried `DataSource` and got a blank
        // `LayerMeta`. Discovery reads that note, so losing it did not fail —
        // it quietly demoted a dump that STATES its DTB to one that has to be
        // scanned for one, which is slower and can settle on a different answer.
        let original = LayerMeta::new(MemoryImageFormat::WindowsCrashDump64)
            .with_architecture(crate::meta::Architecture::X64)
            .with_declared_size(0x8000_0000)
            .with_note("directory_table_base", 0x1ae000u64)
            .with_note("kd_debugger_data_block", 0xfffff8002a41bea0u64)
            .with_incomplete(
                seance_core::io::IncompleteReason::ShortRead,
                "the last segment was truncated",
            );

        // The round trip the artifact actually performs.
        let restored = LayerMeta::from_json(&original.to_json());

        assert_eq!(
            restored.format(),
            Some(MemoryImageFormat::WindowsCrashDump64)
        );
        assert_eq!(
            restored.architecture(),
            Some(crate::meta::Architecture::X64)
        );
        assert_eq!(restored.declared_size(), Some(0x8000_0000));
        assert_eq!(
            restored
                .note("directory_table_base")
                .and_then(|v| v.as_u64()),
            Some(0x1ae000),
            "the DTB the dump header published must reach discovery"
        );
        assert_eq!(
            restored
                .note("kd_debugger_data_block")
                .and_then(|v| v.as_u64()),
            Some(0xfffff8002a41bea0)
        );

        // And the acquisition's own statement of its incompleteness, which is
        // the difference between "this image is whole" and "this image is short
        // and here is why".
        let incomplete = restored.incomplete_chain();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(
            incomplete[0].reason,
            seance_core::io::IncompleteReason::ShortRead
        );
        assert!(incomplete[0].detail.contains("truncated"));
    }

    #[test]
    fn a_record_with_no_layer_meta_still_opens_rather_than_failing() {
        // Records written before the meta was carried, and any future producer
        // that omits it, must still analyse — degraded, not refused.
        let restored = LayerMeta::from_json(&serde_json::json!({}));
        assert_eq!(restored.format(), None);
        assert!(restored.incomplete_chain().is_empty());
    }

    /// A throwaway directory that removes itself, so a test can lay out an
    /// evidence folder without leaving one behind.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("seance-analysis-{label}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("a writable temporary directory");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// An image record whose address space is the file at `path`, which is what
    /// the container stage produces for a capture ingested as a loose file.
    fn image_backed_by(path: &Path) -> Artifact {
        let source =
            FileDataSource::new(path.to_path_buf()).expect("the image file was just written");
        image_artifact(Some(Arc::new(source) as Arc<dyn DataSource>))
    }

    #[test]
    fn a_pagefile_that_lives_beside_the_image_in_the_case_can_be_opened() {
        // The gap this closes. `MemoryAnalysis::analyse` handed an analysis the
        // layer and the image record and nothing else, so the only way to name
        // a pagefile was an absolute host path — and a pagefile acquired into
        // the case beside the capture, which is how memory evidence is
        // ordinarily collected, could not be named at all. Every page the
        // kernel had swapped out then stayed a hole while the examiner had the
        // file sitting next to the image.
        let dir = TempDir::new("beside");
        let image = dir.path.join("memdump.raw");
        std::fs::write(&image, vec![0u8; 4096]).expect("a writable temporary file");
        std::fs::write(dir.path.join("pagefile.sys"), b"swapped-out bytes")
            .expect("a writable temporary file");

        let record = image_backed_by(&image);
        let source = EvidenceBesideImage
            .open(&record, "pagefile.sys")
            .expect("a file beside the image is evidence this case holds");
        let mut buf = vec![0u8; b"swapped-out bytes".len()];
        source.read_at(0, &mut buf).expect("the pagefile reads");
        assert_eq!(&buf[..], b"swapped-out bytes");
    }

    #[test]
    fn a_case_reference_cannot_climb_out_of_the_images_own_directory() {
        // The confinement that makes the reference a piece of evidence rather
        // than a second way of writing a host path. `SEANCE_PAGEFILES` names a
        // path and always has; this names something the case holds, and the two
        // must not silently become the same thing.
        let dir = TempDir::new("confined");
        let evidence = dir.path.join("evidence");
        std::fs::create_dir_all(&evidence).expect("a writable temporary directory");
        let image = evidence.join("memdump.raw");
        std::fs::write(&image, vec![0u8; 4096]).expect("a writable temporary file");
        std::fs::write(dir.path.join("elsewhere.sys"), b"not this case's")
            .expect("a writable temporary file");
        let record = image_backed_by(&image);

        let err = EvidenceBesideImage
            .open(&record, "../elsewhere.sys")
            .expect_err("a reference that climbs out is not evidence beside the image");
        assert!(err.contains("climbs out"), "{err}");

        let err = EvidenceBesideImage
            .open(&record, "/etc/hosts")
            .expect_err("an absolute path is not a reference to case evidence");
        assert!(err.contains("absolute"), "{err}");

        // And a name that simply is not there refuses by name rather than
        // resolving to something else.
        let err = EvidenceBesideImage
            .open(&record, "pagefile.sys")
            .expect_err("there is no pagefile beside this image");
        assert!(err.contains("pagefile.sys"), "{err}");
    }

    #[test]
    fn an_image_with_no_file_of_its_own_refuses_rather_than_guessing_a_path() {
        // A capture read out of a disk image or an archive has no directory in
        // the evidence tree to resolve against. Refusing by name is what tells
        // an examiner that a case-database resolver is the missing piece;
        // falling back to the working directory would open whatever happened to
        // be named there and report it as this machine's swapped memory.
        let record = image_artifact(Some(Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(vec![0u8; 4096]),
        )));
        let err = EvidenceBesideImage
            .open(&record, "pagefile.sys")
            .expect_err("there is no evidence directory behind this image");
        assert!(err.contains("no file of its own"), "{err}");
        assert!(err.contains("case-database resolver"), "{err}");
    }

    #[test]
    fn a_windows_path_in_an_environment_list_is_not_cut_at_its_drive_colon() {
        // `0=C:\evidence\pagefile.sys` split on every colon yields `0=C` — an
        // index naming the relative path `C` — and an orphan with no `=` at
        // all. Both are dropped with a warning, so an examiner who set the
        // variable correctly on Windows got no pagefile attached and a report
        // whose swapped pages all stayed holes. The same list written for
        // `SEANCE_SYMBOL_DIRS` lost both halves silently to the `is_dir`
        // filter that follows it.
        assert_eq!(
            split_env_list(r"0=C:\evidence\pagefile.sys"),
            vec![r"0=C:\evidence\pagefile.sys"]
        );
        assert_eq!(
            split_env_list(r"C:\symbols;D:\packs"),
            vec![r"C:\symbols", r"D:\packs"]
        );
        assert_eq!(
            split_env_list("0=C:/evidence/pagefile.sys"),
            vec!["0=C:/evidence/pagefile.sys"]
        );

        // And the separator every list in the field already uses keeps working,
        // including a drive path standing beside a Unix one.
        assert_eq!(
            split_env_list("0=/evidence/pagefile.sys:1=/evidence/pagefile2.sys"),
            vec!["0=/evidence/pagefile.sys", "1=/evidence/pagefile2.sys"]
        );
        assert_eq!(
            split_env_list(r"C:\symbols:/opt/symbols"),
            vec![r"C:\symbols", "/opt/symbols"]
        );
        assert_eq!(split_env_list(""), Vec::<&str>::new());
        assert_eq!(split_env_list("::"), Vec::<&str>::new());
        assert_eq!(split_env_list(" /opt/symbols : "), vec!["/opt/symbols"]);
    }

    #[test]
    fn the_stamp_supersedes_the_physical_only_marker() {
        let stamp = analysed_stamp("windows", "plugin.memory.windows", "0.1.0");
        assert_eq!(stamp["analysis_stage"], "analysed");
        assert_eq!(stamp["analysed_os"], "windows");
    }
}

#[cfg(test)]
mod profile_stamp_tests {
    use super::*;

    /// HUNT-090's own example: a symbol pack that arrives after the first
    /// memory pass. The failed profile record names the PDB to fetch; fetching
    /// it and re-running left the case holding "profile not established" and
    /// "profile analysed" side by side, with nothing saying which was current.
    #[test]
    fn an_analysed_profile_supersedes_the_failure_it_replaces() {
        let stamp = analysed_profile_stamp("windows", "plugin.memory.windows", "1.0.1");
        assert_eq!(stamp["analysis_stage"], "analysed");
        assert_eq!(stamp["supersedes_status"], "discovery_failed");
        // The memory stages keep their state in `analysis_stage`, so the record
        // names the field as well as the value.
        assert_eq!(stamp["supersedes_field"], "analysis_stage");
    }

    /// Only the profile record supersedes. Every other record an analysis emits
    /// carries the plain stamp, so a process list does not issue a supersession
    /// query per stage for records that cannot exist.
    #[test]
    fn the_plain_stamp_supersedes_nothing() {
        let stamp = analysed_stamp("windows", "plugin.memory.windows", "1.0.1");
        assert!(stamp.get("supersedes_status").is_none());
    }
}
