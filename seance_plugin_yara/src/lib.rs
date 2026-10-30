// The `Err` arm carries an `Artifact`, because a scan that could not run is a
// finding an examiner must see rather than an error string to log. Boxing it
// to save stack would obscure that; the value is produced once per scan.
#![allow(clippy::result_large_err)]
#![forbid(unsafe_code)]
//! YARA content scanning as a [`ForensicsModule`].
//!
//! Runs an examiner-supplied YARA rule set over an artifact's bytes and emits
//! one `YaraMatch` record per matching rule. Séance ships **no rules of its
//! own**: a YARA result is only ever as good as the rules behind it, and a
//! forensic tool has no business asserting maliciousness on an examiner's
//! behalf. A match is a flagged aid, not a verdict.
//!
//! Backed by `yara-x`, VirusTotal's pure-Rust YARA engine (BSD-3-Clause) — no
//! C-YARA FFI and no GPL.
//!
//! # Where rules come from
//!
//! [`YaraScanner::from_rule_path`] is the **only** constructor. It takes a
//! filesystem path — a single rule file, or a directory searched recursively
//! for `*.yar` / `*.yara` — supplied by the examiner (the `--yara-rules` flag
//! at the registration site). There is deliberately no default rule directory
//! and no bundled rule set.
//!
//! # Why there is no "unconfigured" scanner
//!
//! The obvious shape — a scanner that holds `Option<Rules>` and returns no
//! matches when it holds `None` — is the exact defect this project keeps
//! finding: a module that is listed in the registry, reports success, and
//! produces nothing, which an examiner reads as "scanned, nothing found". It
//! is unconstructible here. No rules means no scanner, which means the module
//! is never registered and `plugin.detection.yara` is absent from the module
//! list entirely. Absence of the module is visible; a silent no-op is not.
//!
//! # Every exit from `process` is accounted for
//!
//! A YARA result set is read as "these rules did or did not fire on this
//! object". That reading is only sound if "no records" can mean exactly one
//! thing. So every path out of [`YaraScanner::process`] either scanned the
//! whole object or emitted a record saying why it did not:
//!
//! | Situation                            | Emitted                        |
//! |--------------------------------------|--------------------------------|
//! | no data source attached              | `YaraNotScanned`               |
//! | declared bytes, read returned none    | `YaraNotScanned`               |
//! | engine error or scan timeout          | `YaraScanError`                |
//! | only a leading prefix was readable    | matches + `YaraPartialScan`    |
//! | whole live file scanned               | matches (empty means no match) |
//! | any other surface scanned whole       | matches + `YaraRegionScanned`  |
//! | a registry hive record                | matches + `YaraRegistryCoverage` |
//! | an artifact type with no surface      | `YaraNotScanned`, no `surface` |
//!
//! # Surfaces (`ROADMAP` §2.3)
//!
//! Every record about scanned bytes carries a `surface` — one of
//! [`Surface::ALL`]: `file`, `ads`, `registry_value`, `unallocated`,
//! `carved`, `deleted_file`, `volume`, `slack` — because the same rule firing on the
//! same bytes means something different in each place, and a hit in free
//! space presented like a hit in a live file is the misreading this field
//! exists to prevent. `file` is the narrow case, not the default: it is
//! stamped only on a `FileEntry`, `FileContent` or `SystemArtifact` whose
//! producer marked it neither `carved` nor `deleted` nor `is_ads`. Each
//! surface arrives as what its producer already publishes; this module adds
//! no parser of its own:
//!
//! * **`carved`** — anything the carver marked `carved: true`. No file
//!   system served it and its bounds are the carver's inference; the hit
//!   carries `carving_signature`, `carving_offset`, `carving_validated` and
//!   `carving_source` where the carver wrote them, and is placed as
//!   `offset_in_parent` only when `carving_offset` is into the parent (it is
//!   not for slack carving, and the hit then carries no such field).
//! * **`deleted_file`** — a `FileEntry` its producer marked `deleted: true`
//!   that is not a stream. The clusters may have been reallocated since; the
//!   hit carries `entry_deleted`, `deleted_recovery_source` and
//!   `deleted_content_caveat` as the producer wrote them.
//! * **`volume`** — a `Partition`, `FileSystem`, `RawEvidence` or
//!   `Container` scanned end to end, named by `volume_type`. A hit is a byte
//!   offset in that image and is attributed to no file; on a `Partition` it
//!   is also placed as `offset_in_parent` from the partition's
//!   `offset_bytes`, and on a `FileSystem` it is not, because that
//!   `offset_bytes` is copied from the partition and is not the parent's
//!   coordinate space.
//! * **`ads`** — a `FileEntry` the $MFT parser marked `is_ads`, with its
//!   `stream_name`; the hit names the stream, its `base_file` and `path`,
//!   and carries the entry's `deleted` flag as `entry_deleted` where the
//!   producer set one.
//! * **`unallocated`** — an `UnallocatedSpace` artifact: a run the file
//!   system's bitmap proves free (`seance_core::free_space`) or a gap the
//!   partition table leaves. The hit carries the region's `offset_bytes`,
//!   `size_bytes` and — where the producer states one — `offset_basis`,
//!   because a volume-relative offset read as evidence-absolute is the wrong
//!   place on the disk; each pattern hit is placed as `offset_in_parent`.
//! * **`registry_value`** — the registry parser's `RegistryHive` record,
//!   whose `all_values` inventory is scanned value by value. Since
//!   `HUNT-159` the parser publishes each value's stored bytes as
//!   `value_data_b64` beside its rendering, except a large value past the
//!   hive's per-hive cap; a record from an older build carries the rendering
//!   alone. So each hit states its `value_bytes_basis`: `exact` (the stored
//!   bytes), `rebuilt_from_rendering` (hex, or a little-endian DWORD/QWORD at
//!   its own width, rebuilt by this scanner) or `reencoded_utf16le` (a
//!   string's text re-encoded — an inference, labelled as one, with
//!   `raw_data_size` beside `bytes_scanned`) or `reencoded_utf16le_elements`
//!   (a capped multi-string's `value_data_list` elements re-encoded as the
//!   stored list, `HUNT-217`). A value whose
//!   rendering cannot reproduce its bytes is not scanned and is counted by
//!   reason on the `YaraRegistryCoverage` record; the hive record's own
//!   incompleteness travels onto every record.
//!
//! * **`slack`** — a `SlackSpace` region the NTFS, FAT or exFAT parser
//!   published for a live file (`seance_core::slack`, `HUNT-124`): the bytes
//!   from the file's logical end to the end of the cluster holding its last
//!   byte. A `FileEntry`'s own data source is trimmed to the logical size, so
//!   this is the only way those bytes are reached. The hit names the file as
//!   `base_file` and `path`, carries `owner_artifact_id`, `logical_size`,
//!   `cluster_size`, `region_source` (`file_slack`), the region's
//!   `offset_bytes`, `size_bytes`, `offset_basis` and `filesystem`, and each pattern hit is placed as
//!   `offset_in_parent` in the file system's coordinate space. The producer
//!   publishes no region for an all-zero tail, a resident, compressed,
//!   encrypted or deleted file, or clusters allocated past the one holding
//!   the last byte, so those bytes are not scanned as slack. Each region is
//!   scanned on its own, so a string that begins in the file's content and
//!   ends in its slack, or runs from the slack into the next cluster, is not
//!   matched whole here (DFTT #2's `1slack1` and `2slack2`); a `volume` scan
//!   of the whole image is what finds it.
//!
//! A `ParsedRecord` that is not a registry hive, or a `TimelineEvent`, has
//! no surface here and is refused with a `YaraNotScanned` that names the
//! type (`refused_artifact_type`) and carries **no** `surface`, because the
//! only truthful sentence would be that the provenance is unknown.
//!
//! Every match names **where** and **how often** its strings fired
//! (`pattern_matches`, capped at `MAX_PATTERN_MATCHES_RECORDED` with the
//! total beside it), and carries the Shannon entropy of the bytes it was
//! found in as `entropy_bits_per_byte` with `entropy_bytes`, the population
//! it was computed over.
//!
//! # Composed with the §2.1 substrate
//!
//! `seance_bulk::decode` lifts base64 spans and gzip members out of a
//! buffer. Every region scanned here is also handed to those decoders, and
//! each decoded buffer is scanned as a child of the region: a rule written
//! for a payload fires on the payload rather than on its encoding. A hit on
//! decoded bytes says so (`bytes_are_decoded`, `decoded_via`, the span's
//! offset, `offset_in_decoded` rather than `offset_in_region`), the decoding
//! is one level deep and stamped `decoded_depth: 1`, and the ceilings —
//! `MAX_DECODED_SPANS_PER_REGION`, `MAX_DECODED_BYTES_PER_REGION` — are
//! reported with the counts they stopped at.
//!
//! # Registration
//!
//! ```rust,ignore
//! if let Some(path) = args.yara_rules.as_deref() {
//!     let scanner = seance_plugin_yara::YaraScanner::from_rule_path(path)?;
//!     orchestrator.register_module(std::sync::Arc::new(scanner));
//! }
//! ```
//!
//! It registers as [`ExecutionMode::OptIn`], like `plugin.recovery.file_carver`
//! and `plugin.media.ocr`: running a JIT-compiled rule set over every byte of
//! every artifact in a large case costs more than a baseline ingest should, and
//! YARA hunting is an examiner-directed act, not an extraction step. The
//! orchestrator keeps opt-in modules dispatchable ad hoc by module id.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use seance_bulk::decode::{decode_base64_spans, decode_gzip_members, Decoded};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

/// Module id, as it appears in the orchestrator registry and in the ad-hoc
/// execution API.
pub const MODULE_ID: &str = "plugin.detection.yara";

// The product version, as every other module reports it. This said `"0.1.0"`
// — a per-crate label from before the workspace had one version — and reached
// the report's module table beside forty modules saying `1.0.0`, which reads as
// a component that was never updated rather than one whose author forgot the
// string. `check-version.sh` holds the workspace to one number for exactly this.
const MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Most bytes of a single artifact scanned. YARA scans the whole buffer at
/// once, so this bounds per-artifact time and memory on very large files.
const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

/// Wall-clock ceiling on a single artifact's scan. A pathological rule (a
/// catastrophically backtracking regex, say) must not wedge a worker forever.
/// A timeout surfaces as [`yara_x::ScanError::Timeout`] and becomes an explicit
/// `YaraScanError` record — never a silent "no matches".
const SCAN_TIMEOUT: Duration = Duration::from_secs(60);

/// Most pattern hits listed on one match record. A rule matching a byte that
/// recurs every few bytes across a 256 MiB region would otherwise carry
/// millions of offsets; the total is always published beside the list, and
/// `pattern_matches_truncated` says when the list is a prefix of it.
const MAX_PATTERN_MATCHES_RECORDED: usize = 64;

/// Most decoded spans scanned out of one region — a stream, a free region, a
/// file, or one registry value. Free space full of base64 text would
/// otherwise turn one region into an unbounded number of scans; the count
/// found is published beside the count scanned wherever the ceiling bites.
pub(crate) const MAX_DECODED_SPANS_PER_REGION: usize = 256;

/// Most decoded bytes scanned out of one region, for the same reason.
pub(crate) const MAX_DECODED_BYTES_PER_REGION: u64 = 64 * 1024 * 1024;

/// Shortest base64 run lifted out of a region — the figure
/// `seance_plugin_bulk` uses, so the two find the same spans.
const MIN_BASE64_SPAN: usize = 24;

/// Extensions recognised when a rule *directory* is scanned. A path pointing
/// straight at a file is loaded whatever it is called.
const RULE_FILE_EXTENSIONS: [&str; 2] = ["yar", "yara"];

/// Why a rule set could not be loaded.
///
/// Every variant is fatal by design. A rule set that half-loaded would leave an
/// examiner believing a detection ran when part of it never compiled.
#[derive(Debug)]
pub enum RuleLoadError {
    /// The rule path or one of the files under it could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A directory was given but holds no `.yar` / `.yara` files.
    NoRuleFiles { path: PathBuf },
    /// One or more rule files failed to compile. Each string is the engine's
    /// full diagnostic, which names the originating file and line.
    Compile { errors: Vec<String> },
    /// The files compiled but declare no rules at all.
    EmptyRuleSet { path: PathBuf },
}

impl fmt::Display for RuleLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleLoadError::Io { path, source } => {
                write!(
                    f,
                    "cannot read YARA rules at {}: {}",
                    path.display(),
                    source
                )
            }
            RuleLoadError::NoRuleFiles { path } => write!(
                f,
                "no .yar or .yara files under {}: YARA scanning was requested but \
                 there are no rules to scan with",
                path.display()
            ),
            RuleLoadError::Compile { errors } => {
                write!(
                    f,
                    "{} YARA rule error(s); no scanning was performed:",
                    errors.len()
                )?;
                for e in errors {
                    write!(f, "\n{e}")?;
                }
                Ok(())
            }
            RuleLoadError::EmptyRuleSet { path } => write!(
                f,
                "the YARA source under {} compiled but declares no rules",
                path.display()
            ),
        }
    }
}

impl std::error::Error for RuleLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RuleLoadError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A YARA scanner over a compiled, non-empty rule set.
pub struct YaraScanner {
    rules: yara_x::Rules,
    rule_count: usize,
}

// `yara_x::Rules` is not `Debug` (it is a compiled WASM module and several
// interned pools), so derive is not available; the rule count is the part worth
// printing anyway.
impl fmt::Debug for YaraScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YaraScanner")
            .field("rule_count", &self.rule_count)
            .finish()
    }
}

impl YaraScanner {
    /// Compile the rule set at `path` — a single rule file, or a directory
    /// searched recursively for `*.yar` / `*.yara`.
    ///
    /// Fails closed, in all four senses that matter:
    ///
    /// * an unreadable path or file is an error, not an empty rule set;
    /// * a directory with no rule files is an error, not a scanner that
    ///   matches nothing;
    /// * **any** rule that fails to compile fails the whole load, and the
    ///   returned error carries the engine's diagnostic for *every* bad file,
    ///   not just the first. A broken rule that was quietly dropped would let
    ///   an examiner believe a detection ran that never did;
    /// * a set that compiles to zero rules is an error.
    ///
    /// Compiler *warnings* do not fail the load — they are valid rules the
    /// engine has an opinion about — but each one is logged at WARN so it is
    /// on the record.
    pub fn from_rule_path(path: &Path) -> Result<Self, RuleLoadError> {
        let files = collect_rule_files(path)?;
        if files.is_empty() {
            return Err(RuleLoadError::NoRuleFiles {
                path: path.to_path_buf(),
            });
        }

        let mut sources = Vec::with_capacity(files.len());
        for file in &files {
            let text = fs::read_to_string(file).map_err(|e| RuleLoadError::Io {
                path: file.clone(),
                source: e,
            })?;
            sources.push(text);
        }

        let mut compiler = yara_x::Compiler::new();
        for (file, text) in files.iter().zip(sources.iter()) {
            let src =
                yara_x::SourceCode::from(text.as_str()).with_origin(file.display().to_string());
            // The result is deliberately discarded: `add_source` reports only
            // the first error it added, while `Compiler::errors()` accumulates
            // all of them. Carrying on means a rule set with three broken files
            // reports three diagnostics instead of sending the examiner round
            // the loop three times.
            let _ = compiler.add_source(src);
        }

        let errors: Vec<String> = compiler.errors().iter().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return Err(RuleLoadError::Compile { errors });
        }
        for warning in compiler.warnings() {
            warn!("YARA rule warning: {warning}");
        }

        let rules = compiler.build();
        let rule_count = rules.iter().len();
        if rule_count == 0 {
            return Err(RuleLoadError::EmptyRuleSet {
                path: path.to_path_buf(),
            });
        }

        info!(
            "YARA rule set loaded: {} rule(s) from {} file(s) under {}",
            rule_count,
            files.len(),
            path.display()
        );
        for file in &files {
            info!("  YARA rule file: {}", file.display());
        }

        Ok(Self { rules, rule_count })
    }

    /// Number of rules in the compiled set. Always non-zero: a scanner with no
    /// rules cannot be constructed.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// The compiled rules, for a caller driving the engine itself.
    ///
    /// Exposed for [`memory::MemoryYaraScanner`], which scans an address space
    /// chunk by chunk through `seance_memory::scan` rather than handing a file
    /// to [`Self::process`]. One compiled set, two drivers: a second compilation
    /// would be a second rule set, and a rule that failed to compile in one of
    /// them would make the two disagree about what was looked for.
    pub fn rules(&self) -> &yara_x::Rules {
        &self.rules
    }

    /// Every rule identifier in set order.
    ///
    /// The order is the set's own, which is what makes a numeric pattern id
    /// meaningful to a caller that has to name the rule behind a hit.
    pub fn rule_identifiers(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|rule| rule.identifier().to_string())
            .collect()
    }

    /// Scan `bytes` as one region, returning one record per matching rule.
    ///
    /// An engine failure comes back as `Err(record)` — a separate channel, not
    /// another entry in the same vector — so that a caller counting the vector
    /// cannot count a fault as a match. Returning both through one `Vec` is
    /// exactly how the partial-coverage record came to report "1 match in the
    /// scanned prefix" for a scan that matched nothing and never finished.
    ///
    /// `scanner` is the caller's, so a hive of thousands of values builds the
    /// engine once rather than once per value (about 0.4 ms each, measured in
    /// `memory.rs`).
    fn scan_region(
        &self,
        scanner: &mut yara_x::Scanner<'_>,
        case_id: Uuid,
        parent: Uuid,
        bytes: &[u8],
        declared_size: u64,
        region: &Region,
    ) -> Result<Vec<Artifact>, Artifact> {
        let results = match scanner.scan(bytes) {
            Ok(results) => results,
            Err(e) => {
                // An engine failure (timeout, module error, ...) is NOT a clean
                // "no match". An empty match set here would let a fault
                // masquerade as the object being clean.
                warn!(
                    "YARA scan failed on {} bytes of {}: {e}",
                    bytes.len(),
                    region.surface.as_str()
                );
                let mut meta = json!({
                    "type": "YaraScanError",
                    "subtype": "yara_scan_error",
                    "name": "yara_scan_error",
                    "source_module": MODULE_ID,
                    "rules_in_set": self.rule_count(),
                    "error": e.to_string(),
                    "bytes_offered": bytes.len(),
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    "message": "The YARA engine did not complete this scan; \
                                no conclusion about this object can be drawn from it",
                });
                region.stamp(&mut meta);
                return Err(
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta)
                        .with_parent(parent),
                );
            }
        };
        let (entropy, entropy_bytes) = entropy_fields(bytes);
        Ok(results
            .matching_rules()
            .map(|rule| {
                let tags: Vec<&str> = rule.tags().map(|t| t.identifier()).collect();
                let mut hits: Vec<serde_json::Value> = Vec::new();
                let mut hit_count: u64 = 0;
                for pattern in rule.patterns() {
                    for m in pattern.matches() {
                        hit_count += 1;
                        if hits.len() >= MAX_PATTERN_MATCHES_RECORDED {
                            continue;
                        }
                        let range = m.range();
                        let offset = range.start as u64;
                        let mut hit = json!({
                            "pattern": pattern.identifier(),
                            region.hit_offset_key: offset,
                            "length": range.len() as u64,
                        });
                        if let (Some(base), Some(map)) = (region.parent_offset, hit.as_object_mut())
                        {
                            // `checked_add`: a corrupt region offset near the
                            // top of u64 must not wrap into a plausible small
                            // address. Absent means "could not be placed", not
                            // "at zero".
                            if let Some(in_parent) = base.checked_add(offset) {
                                map.insert("offset_in_parent".into(), json!(in_parent));
                            }
                        }
                        hits.push(hit);
                    }
                }
                let mut meta = json!({
                    "type": "YaraMatch",
                    "subtype": "yara_match",
                    "name": rule.identifier(),
                    "source_module": MODULE_ID,
                    "rules_in_set": self.rule_count(),
                    "rule": rule.identifier(),
                    "namespace": rule.namespace(),
                    "tags": tags,
                    "bytes_scanned": bytes.len() as u64,
                    "declared_size": declared_size,
                    "entropy_bits_per_byte": entropy,
                    "entropy_bytes": entropy_bytes,
                    "pattern_match_count": hit_count,
                    "pattern_matches_recorded": hits.len() as u64,
                    "pattern_matches_truncated": hit_count > hits.len() as u64,
                    // A rule can be true with none of its strings found
                    // (`condition: true`, a `filesize` test). Such a hit has
                    // no offset, and says so rather than listing none.
                    "matched_without_pattern": hit_count == 0,
                    "pattern_matches": hits,
                });
                region.stamp(&mut meta);
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta).with_parent(parent)
            })
            .collect())
    }

    /// A record stating that this artifact was **not** scanned, and why.
    ///
    /// Emitting nothing here would be indistinguishable from a completed scan
    /// that found nothing.
    fn not_scanned_record(
        &self,
        artifact: &Artifact,
        region: &Region,
        reason: IncompleteReason,
        detail: &str,
        declared_size: u64,
    ) -> Artifact {
        let mut meta = json!({
            "type": "YaraNotScanned",
            "subtype": "yara_not_scanned",
            "name": "yara_not_scanned",
            "source_module": MODULE_ID,
            "rules_in_set": self.rule_count(),
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            "declared_size": declared_size,
            "content_incomplete_detail": detail,
            "detail": detail,
            "message": "This object was not scanned; the absence of matches says \
                        nothing about it",
        });
        region.stamp(&mut meta);
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id)
    }

    /// A record stating that an artifact of a type this module has no
    /// surface for was not scanned.
    ///
    /// It carries no `surface` and no `surface_means`: the only sentence
    /// this module could truthfully put there is that it does not know
    /// where these bytes came from, and a stamped surface would be the
    /// claim the field exists to prevent.
    fn refused_record(&self, artifact: &Artifact, ty: ArtifactType) -> Artifact {
        let detail = format!(
            "this module has no surface for a {ty} artifact: it scans files, alternate data \
             streams, carved objects, deleted files, whole volumes, unallocated space, file \
             slack and registry hive records, and will not stamp bytes of unknown provenance as any of \
             those"
        );
        let meta = json!({
            "type": "YaraNotScanned",
            "subtype": "yara_not_scanned",
            "name": "yara_not_scanned",
            "source_module": MODULE_ID,
            "rules_in_set": self.rule_count(),
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "declared_size": artifact.data.as_ref().map(|d| d.size()).unwrap_or(0),
            "content_incomplete_detail": detail,
            "detail": detail,
            "refused_artifact_type": ty.to_string(),
            "message": "This object was not scanned; the absence of matches says \
                        nothing about it",
        });
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id)
    }

    /// A record stating that only a prefix of the artifact was scanned.
    ///
    /// A rule whose strings live past `bytes_scanned` cannot fire, so an empty
    /// result set is not evidence of a clean object. Without this record the
    /// two are indistinguishable.
    fn partial_scan_record(
        &self,
        artifact: &Artifact,
        region: &Region,
        bytes_scanned: u64,
        declared_size: u64,
        matches: usize,
    ) -> Artifact {
        let reason = if declared_size > MAX_SCAN_BYTES {
            IncompleteReason::CapReached
        } else {
            IncompleteReason::ShortRead
        };
        let mut meta = json!({
            "type": "YaraPartialScan",
            "subtype": "yara_partial_scan",
            "name": "yara_partial_scan",
            "source_module": MODULE_ID,
            "rules_in_set": self.rule_count(),
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            "bytes_scanned": bytes_scanned,
            "declared_size": declared_size,
            "max_scan_bytes": MAX_SCAN_BYTES,
            "matches_in_scanned_prefix": matches,
            "message": "Only the leading bytes of this object were scanned; rules \
                        matching later content could not fire",
        });
        region.stamp(&mut meta);
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id)
    }

    /// The record that says a stream, free region, carved object, deleted
    /// file or whole volume **was looked at**, with the entropy of what was
    /// there.
    ///
    /// Emitted for every surface but a live file, whose contract — a full
    /// scan that matched nothing produces nothing — predates the others. On
    /// the other surfaces the region itself is the finding: a high-entropy
    /// run of free clusters is a lead whether or not a rule fired, and "no
    /// match" over a stream or a recovered file means nothing unless the
    /// record says the bytes were read.
    fn region_record(
        &self,
        artifact: &Artifact,
        region: &Region,
        bytes: &[u8],
        declared_size: u64,
        matches: usize,
        decoded: &DecodeOutcome,
    ) -> Artifact {
        let (entropy, entropy_bytes) = entropy_fields(bytes);
        let complete = bytes.len() as u64 >= declared_size;
        let mut meta = json!({
            "type": "YaraRegionScanned",
            "subtype": "yara_region_scanned",
            "name": "yara_region_scanned",
            "source_module": MODULE_ID,
            "rules_in_set": self.rule_count(),
            "bytes_scanned": bytes.len() as u64,
            "declared_size": declared_size,
            "scan_complete": complete,
            "entropy_bits_per_byte": entropy,
            "entropy_bytes": entropy_bytes,
            "matches": matches,
        });
        let mut shortfalls: Vec<String> = Vec::new();
        let mut reason: Option<IncompleteReason> = None;
        if !complete {
            reason = Some(if declared_size > MAX_SCAN_BYTES {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::ShortRead
            });
            shortfalls.push(format!(
                "{} of {} declared bytes were read; the entropy is over the bytes read and \
                 the scan could not reach the rest",
                bytes.len(),
                declared_size
            ));
        }
        if let Some(detail) = decoded.shortfall() {
            reason.get_or_insert(IncompleteReason::CapReached);
            shortfalls.push(detail);
        }
        if let Some(map) = meta.as_object_mut() {
            decoded.stamp(map);
            if let Some(reason) = reason {
                map.insert("content_incomplete".into(), json!(true));
                map.insert("content_incomplete_reason".into(), json!(reason.as_str()));
                map.insert(
                    "content_incomplete_detail".into(),
                    json!(shortfalls.join(". ")),
                );
            }
        }
        region.stamp(&mut meta);
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id)
    }

    /// For a plain file, which has no region record: the decode step's
    /// ceiling or engine failure, emitted only when there was one. A file
    /// whose spans were all scanned keeps the file contract of no extra
    /// record.
    fn decode_coverage_record(
        &self,
        artifact: &Artifact,
        region: &Region,
        decoded: &DecodeOutcome,
    ) -> Artifact {
        let mut meta = json!({
            "type": "YaraDecodeCoverage",
            "subtype": "yara_decode_coverage",
            "name": "yara_decode_coverage",
            "source_module": MODULE_ID,
            "rules_in_set": self.rule_count(),
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::CapReached.as_str(),
            "content_incomplete_detail": decoded.shortfall(),
            "message": "Not every encoded span lifted out of this object was scanned; a rule \
                        written for a decoded payload may have had no chance to fire",
        });
        if let Some(map) = meta.as_object_mut() {
            decoded.stamp(map);
        }
        region.stamp(&mut meta);
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
            .with_parent(artifact.id)
    }

    /// The §2.1 composition: lift every base64 span and gzip member out of
    /// `source`, scan each decoded buffer as a child of `region`, and label
    /// every hit as a hit on decoded bytes.
    ///
    /// One level deep, by design. The bulk plugin's own re-scan carries a
    /// generation counter because the orchestrator does not; this module
    /// never re-queues, so a span inside a decoded span is not decoded, and
    /// `decoded_depth: 1` on the records says so.
    ///
    /// `from` names what the decoders were run over. For most regions that
    /// is the region's bytes. For a registry string value it is the value's
    /// published text: the hive holds the string as UTF-16, whose
    /// interleaved zero bytes break every base64 run, and the encoding an
    /// examiner is hunting lives in the text.
    fn scan_decoded_spans(
        &self,
        scanner: &mut yara_x::Scanner<'_>,
        case_id: Uuid,
        parent: Uuid,
        source: &[u8],
        region: &Region,
        from: DecodeSource,
    ) -> (Vec<Artifact>, DecodeOutcome) {
        let mut outcome = DecodeOutcome::default();
        let mut out: Vec<Artifact> = Vec::new();
        let base64 = decode_base64_spans(source, MIN_BASE64_SPAN);
        // Spans the decoder's own ceilings left undecoded were found and not
        // scanned; they count toward the shortfall the coverage record states.
        outcome.spans_found += base64.spans_not_decoded as u64;
        outcome.cap_reached |= base64.cap_reached;
        let spans = base64
            .decoded
            .into_iter()
            .chain(decode_gzip_members(source));
        for span in spans {
            outcome.spans_found += 1;
            let len = span.data.len() as u64;
            if outcome.spans_scanned >= MAX_DECODED_SPANS_PER_REGION as u64
                || outcome.bytes_scanned.saturating_add(len) > MAX_DECODED_BYTES_PER_REGION
            {
                outcome.cap_reached = true;
                continue;
            }
            let child = region.decoded_child(&span, from);
            match self.scan_region(scanner, case_id, parent, &span.data, len, &child) {
                Ok(found) => {
                    outcome.spans_scanned += 1;
                    outcome.bytes_scanned += len;
                    outcome.matches += found.len() as u64;
                    out.extend(found);
                }
                Err(scan_error) => {
                    outcome.engine_errors += 1;
                    out.push(scan_error);
                }
            }
        }
        (out, outcome)
    }

    /// Scan one artifact's attached bytes as one region.
    fn process_region(&self, artifact: &Artifact, region: Region) -> Vec<Artifact> {
        let Some(data) = artifact.data.as_ref() else {
            // Ad-hoc dispatch will hand this module whatever artifact the
            // examiner targeted, resolved content or not. "Nothing to read" is
            // a result about the request, not about the object's contents.
            let declared = artifact
                .metadata
                .get("size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let why = if artifact
                .metadata
                .get("volume_not_in_evidence")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                "no content is attached to this artifact: the volume its clusters are on was \
                 not supplied"
            } else {
                "no content is attached to this artifact"
            };
            return vec![self.not_scanned_record(
                artifact,
                &region,
                IncompleteReason::UnresolvedStructure,
                why,
                declared,
            )];
        };

        let declared = data.size();
        let bytes = read_capped(data.as_ref(), MAX_SCAN_BYTES);

        if bytes.is_empty() && declared > 0 {
            return vec![self.not_scanned_record(
                artifact,
                &region,
                IncompleteReason::ShortRead,
                "the content source returned no bytes",
                declared,
            )];
        }

        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        let mut out = match self.scan_region(
            &mut scanner,
            artifact.case_id,
            artifact.id,
            &bytes,
            declared,
            &region,
        ) {
            Ok(matches) => matches,
            // The engine did not finish. The scan-error record already says no
            // conclusion can be drawn about this object; adding a coverage
            // record beside it would only invite someone to count the fault as
            // a match.
            Err(scan_error) => return vec![scan_error],
        };
        // `out` holds match records and nothing else here — the engine
        // failure returned above — so this count cannot be inflated by a
        // fault record.
        let mut matches = out.len();
        let (decoded_out, decoded) = self.scan_decoded_spans(
            &mut scanner,
            artifact.case_id,
            artifact.id,
            &bytes,
            &region,
            DecodeSource::RegionBytes,
        );
        matches += decoded.matches as usize;
        out.extend(decoded_out);
        if region.surface.reports_region() {
            out.push(self.region_record(artifact, &region, &bytes, declared, matches, &decoded));
        } else if decoded.shortfall().is_some() {
            out.push(self.decode_coverage_record(artifact, &region, &decoded));
        }
        if (bytes.len() as u64) < declared {
            out.push(self.partial_scan_record(
                artifact,
                &region,
                bytes.len() as u64,
                declared,
                matches,
            ));
        }
        out
    }

    /// Scan a registry hive record's values, within `byte_budget` bytes.
    ///
    /// The registry parser publishes a hive as one record carrying every value
    /// it walked, each with a *rendering* and — since `HUNT-159` — its stored
    /// bytes as `value_data_b64`, unless the value is over 64 bytes and the
    /// hive's per-hive cap was reached (`value_data_b64_omitted`). A record
    /// from an older build carries the rendering alone. Each value's record
    /// says on what basis its bytes were scanned: `exact` (the stored bytes),
    /// `rebuilt_from_rendering` (a lossless hex or DWORD/QWORD rendering,
    /// rebuilt here), or `reencoded_utf16le` where a string's text was
    /// re-encoded and the stored bytes are inferred from it. A value whose
    /// rendering cannot reproduce its bytes is **not scanned and is counted**,
    /// by reason, on the
    /// coverage record — never silently passed over.
    ///
    /// `byte_budget` is the ceiling on bytes scanned across the hive. A hive
    /// past it stops, and every value past the stop is counted against the
    /// budget on the coverage record with the budget itself beside them.
    pub(crate) fn scan_hive_values(
        &self,
        hive: &Artifact,
        values: &[serde_json::Value],
        byte_budget: u64,
    ) -> Vec<Artifact> {
        let hive_context = hive_context(&hive.metadata);
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);

        let mut out: Vec<Artifact> = Vec::new();
        let mut scanned = 0u64;
        let mut scanned_exact = 0u64;
        let mut scanned_rebuilt = 0u64;
        let mut scanned_reencoded = 0u64;
        let mut engine_errors = 0u64;
        let mut matches = 0u64;
        let mut bytes_scanned = 0u64;
        let mut budget_reached = false;
        let mut not_scanned: BTreeMap<&'static str, u64> = BTreeMap::new();
        let mut decoded_total = DecodeOutcome::default();

        for value in values {
            if budget_reached {
                *not_scanned.entry(REASON_BYTE_BUDGET).or_default() += 1;
                continue;
            }
            let (bytes, basis) = match registry_value_bytes(value) {
                Ok(reproduced) => reproduced,
                Err(reason) => {
                    *not_scanned.entry(reason).or_default() += 1;
                    continue;
                }
            };
            let len = bytes.len() as u64;
            if bytes_scanned.saturating_add(len) > byte_budget {
                budget_reached = true;
                *not_scanned.entry(REASON_BYTE_BUDGET).or_default() += 1;
                continue;
            }

            let mut context = hive_context.clone();
            for key in ["key_path", "value_name", "value_type", "raw_data_size"] {
                if let Some(v) = value.get(key) {
                    context.insert(key.to_string(), v.clone());
                }
            }
            context.insert("value_bytes_basis".into(), json!(basis.as_str()));
            context.insert("value_bytes_basis_means".into(), json!(basis.statement()));
            let region = Region::new(Surface::RegistryValue, context, None);
            match self.scan_region(&mut scanner, hive.case_id, hive.id, &bytes, len, &region) {
                Ok(found) => {
                    scanned += 1;
                    match basis {
                        ValueBytesBasis::Exact => scanned_exact += 1,
                        ValueBytesBasis::RebuiltFromRendering => scanned_rebuilt += 1,
                        ValueBytesBasis::ReencodedUtf16le
                        | ValueBytesBasis::ReencodedUtf16leElements => scanned_reencoded += 1,
                    }
                    bytes_scanned += len;
                    matches += found.len() as u64;
                    out.extend(found);
                }
                Err(scan_error) => {
                    engine_errors += 1;
                    out.push(scan_error);
                }
            }
            // The encoding an examiner hunts in a string value lives in its
            // text, not in the UTF-16 that stores it.
            let (decode_source, from) = match basis {
                ValueBytesBasis::Exact
                | ValueBytesBasis::RebuiltFromRendering
                | ValueBytesBasis::ReencodedUtf16leElements => {
                    (bytes.as_slice(), DecodeSource::ValueBytes)
                }
                ValueBytesBasis::ReencodedUtf16le => (
                    value
                        .get("value_data")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .as_bytes(),
                    DecodeSource::ValueText,
                ),
            };
            let (decoded_out, decoded) = self.scan_decoded_spans(
                &mut scanner,
                hive.case_id,
                hive.id,
                decode_source,
                &region,
                from,
            );
            matches += decoded.matches;
            decoded_total.add(&decoded);
            out.extend(decoded_out);
        }

        let values_not_scanned: u64 = not_scanned.values().sum();
        let mut meta = json!({
            "type": "YaraRegistryCoverage",
            "subtype": "yara_registry_coverage",
            "name": "yara_registry_coverage",
            "source_module": MODULE_ID,
            "rules_in_set": self.rule_count(),
            "surface": Surface::RegistryValue.as_str(),
            "values_total": values.len() as u64,
            "values_scanned": scanned,
            "values_scanned_exact": scanned_exact,
            "values_scanned_rebuilt": scanned_rebuilt,
            "values_scanned_reencoded": scanned_reencoded,
            "values_not_scanned": values_not_scanned,
            "not_scanned_reasons": not_scanned,
            "values_engine_error": engine_errors,
            "bytes_scanned": bytes_scanned,
            "byte_budget": byte_budget,
            "byte_budget_reached": budget_reached,
            "matches": matches,
            "value_bytes_means": "the registry parser publishes each value's stored bytes \
                (`value_data_b64`) beside its rendering, except a large value past the hive's \
                per-hive cap; a record from an older build carries the rendering alone. A value \
                with stored bytes is scanned on them (`exact`); one without is rebuilt from its \
                rendering (`rebuilt_from_rendering`) or its text re-encoded \
                (`reencoded_utf16le`; a multi-string's elements, from `value_data_list`, as \
                `reencoded_utf16le_elements`, counted with the re-encoded), and every value that could not be reproduced is counted \
                above by reason",
        });
        if let Some(map) = meta.as_object_mut() {
            for (k, v) in &hive_context {
                map.insert(k.clone(), v.clone());
            }
            decoded_total.stamp(map);
            let mut shortfalls: Vec<String> = Vec::new();
            let mut reason: Option<IncompleteReason> = None;
            if values_not_scanned > 0 || engine_errors > 0 {
                reason = Some(if budget_reached {
                    IncompleteReason::CapReached
                } else {
                    IncompleteReason::UnresolvedStructure
                });
                shortfalls.push(format!(
                    "{values_not_scanned} of {} values were not scanned and {engine_errors} \
                     failed in the engine; no match set over this hive covers them",
                    values.len()
                ));
            }
            if let Some(detail) = decoded_total.shortfall() {
                reason.get_or_insert(IncompleteReason::CapReached);
                shortfalls.push(detail);
            }
            if let Some(reason) = reason {
                map.insert("content_incomplete".into(), json!(true));
                map.insert("content_incomplete_reason".into(), json!(reason.as_str()));
                map.insert(
                    "content_incomplete_detail".into(),
                    json!(shortfalls.join(". ")),
                );
            }
        }
        out.push(
            Artifact::new(hive.case_id, ArtifactType::ParsedRecord, None, meta)
                .with_parent(hive.id),
        );
        out
    }
}

impl ForensicsModule for YaraScanner {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        MODULE_VERSION
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // Opt-in, so this list is not a dispatch rule: it is what the API
        // offers the module against. An alternate data stream arrives as a
        // `FileEntry`, free space as `UnallocatedSpace`, a file's slack as
        // `SlackSpace`, and a registry hive's values on its `ParsedRecord`.
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            ArtifactType::UnallocatedSpace,
            ArtifactType::SlackSpace,
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn execution_mode(&self) -> ExecutionMode {
        // Opt-in, matching `plugin.recovery.file_carver` and `plugin.media.ocr`:
        // a JIT-compiled rule set over every byte of every artifact is far too
        // expensive for a baseline ingest, and YARA hunting is examiner-directed.
        ExecutionMode::OptIn
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        match classify(artifact) {
            Kind::Hive => {
                let Some(values) = artifact
                    .metadata
                    .get("all_values")
                    .and_then(|v| v.as_array())
                else {
                    let region = Region::new(
                        Surface::RegistryValue,
                        hive_context(&artifact.metadata),
                        None,
                    );
                    return Ok(vec![self.not_scanned_record(
                        artifact,
                        &region,
                        IncompleteReason::UnresolvedStructure,
                        "the hive record carries no value inventory (`all_values`), so there \
                         are no value bytes to reproduce",
                        0,
                    )]);
                };
                Ok(self.scan_hive_values(artifact, values, MAX_SCAN_BYTES))
            }
            Kind::Bytes(region) => Ok(self.process_region(artifact, region)),
            Kind::Unsupported(ty) => Ok(vec![self.refused_record(artifact, ty)]),
        }
    }
}

/// Where scanned bytes came from.
///
/// Stamped on every record this module emits as `surface`, because the same
/// rule firing on the same sixteen bytes means something different in each
/// place: in a live file it is content the file system serves; in a stream
/// it is content hidden beside a file; in a registry value it is
/// configuration; in a carved object it is bytes a signature cut out of a
/// region with bounds nobody recorded; in a deleted file it is whatever now
/// occupies clusters the file system gave up; in a whole volume it is a byte
/// offset attributed to no file at all; in free space it is residue of
/// something that may no longer exist. A reader who cannot tell those apart
/// has been told a hit in unallocated space is a hit in a live file, and
/// this is the field that stops that.
///
/// `File` is the narrow case, not the default: it is stamped only on an
/// artifact whose producer marked it neither carved nor deleted nor a
/// stream, and whose type is one the file system or the ingest path serves
/// as a file. Everything else has its own surface or is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// A live file's own content — the unnamed `$DATA` stream of an in-use
    /// record, or a `FileContent` / `SystemArtifact` the ingest path serves.
    File,
    /// An NTFS alternate data stream: a `FileEntry` the $MFT parser marked
    /// `is_ads`, with its `stream_name`.
    Ads,
    /// One value in a registry hive, reproduced from the hive record's value
    /// inventory.
    RegistryValue,
    /// A run the file system's bitmap marks free, or a gap between
    /// partitions — an `UnallocatedSpace` artifact.
    Unallocated,
    /// An object the carver cut out of a scanned region by signature
    /// (`carved: true`). No file system served it; its bounds are the
    /// carver's inference.
    Carved,
    /// A file whose record the file system no longer lists as in use
    /// (`deleted: true`). Its runs say where the file was; the clusters may
    /// since have been reallocated.
    DeletedFile,
    /// A `Partition`, `FileSystem`, `RawEvidence` or `Container` scanned end
    /// to end. A hit is a byte offset in that image and is attributed to no
    /// file.
    Volume,
    /// The slack of a live file (`ROADMAP` §2.3): a `SlackSpace` region the
    /// NTFS, FAT or exFAT parser published from the file's allocation — the
    /// bytes from its logical end to the end of the cluster holding its last
    /// byte. Allocated to that file, and not its content.
    Slack,
}

impl Surface {
    /// Every surface, in the order the vocabulary is stated.
    pub const ALL: [Surface; 8] = [
        Surface::File,
        Surface::Ads,
        Surface::RegistryValue,
        Surface::Unallocated,
        Surface::Carved,
        Surface::DeletedFile,
        Surface::Volume,
        Surface::Slack,
    ];

    /// The value the `surface` field carries.
    pub fn as_str(&self) -> &'static str {
        match self {
            Surface::File => "file",
            Surface::Ads => "ads",
            Surface::RegistryValue => "registry_value",
            Surface::Unallocated => "unallocated",
            Surface::Carved => "carved",
            Surface::DeletedFile => "deleted_file",
            Surface::Volume => "volume",
            Surface::Slack => "slack",
        }
    }

    /// Whether a fully scanned, unmatched region of this surface still yields
    /// a `YaraRegionScanned` record. See [`YaraScanner::region_record`].
    ///
    /// Every surface but a live file: on each of the others the region is
    /// itself the finding, and "no match" means nothing unless the record
    /// says the bytes were read. A registry hive has its own coverage record.
    fn reports_region(&self) -> bool {
        !matches!(self, Surface::File | Surface::RegistryValue)
    }

    /// One sentence on what a hit here is and is not.
    fn statement(&self) -> &'static str {
        match self {
            Surface::File => "the bytes are the file's own content as the file system serves it",
            Surface::Ads => {
                "the bytes are an alternate data stream: content stored beside the \
                named file, not the file's own content, and not shown by a directory listing"
            }
            Surface::RegistryValue => {
                "the bytes are one registry value's data, reproduced from \
                the hive record's inventory on the basis `value_bytes_basis` states"
            }
            Surface::Unallocated => {
                "the bytes are in space the file system or partition table \
                marks as not in use; a match here is not a match in any live file, and the \
                region may hold fragments of more than one former object"
            }
            Surface::Carved => {
                "the bytes are an object the carver cut out of a scanned region by \
                signature; no file system served them, the object's start and size are the \
                carver's inference from the signature and may be wrong, and nothing shows \
                these bytes ever existed as a file with these bounds"
            }
            Surface::DeletedFile => {
                "the bytes are what a deleted file's record still points at; the file \
                system no longer lists the file, its clusters may have been reallocated since, \
                and the content read may belong to whatever was written there later"
            }
            Surface::Volume => {
                "the bytes are a partition, file system or evidence image scanned end \
                to end; a match is at a byte offset in that image and is not attributed to any \
                file — it may lie in a live file, a deleted file, slack or free space"
            }
            Surface::Slack => {
                "the bytes are the slack of the live file named here: from its logical end to \
                the end of the cluster that holds its last byte. They are allocated to that file \
                but are not the file's content, and may be what the cluster held before this \
                file was written into it (part of an earlier file) or padding; a string split \
                across the file's logical end, or past the end of the cluster, is not matched \
                whole here"
            }
        }
    }
}

/// How a registry value's bytes were arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueBytesBasis {
    /// The record's `value_data_b64`: the value's stored bytes, as published.
    Exact,
    /// Rebuilt by this scanner from a lossless rendering — hex, or a `DWORD`
    /// or `QWORD` at its own width. Reproduces the stored bytes, but they are
    /// a reconstruction, not bytes the parser published (`HUNT-207`).
    RebuiltFromRendering,
    /// A string's decoded text, re-encoded as UTF-16LE. Reproduces the stored
    /// bytes only for a well-formed string with a single terminator.
    ReencodedUtf16le,
    /// A `REG_MULTI_SZ`'s elements from the record's `value_data_list`, each
    /// re-encoded as UTF-16LE with its terminator, then the list terminator
    /// (`HUNT-217`). Reproduces the stored bytes only for a well-formed list:
    /// the parser drops empty elements and decodes lossily.
    ReencodedUtf16leElements,
}

impl ValueBytesBasis {
    fn as_str(&self) -> &'static str {
        match self {
            ValueBytesBasis::Exact => "exact",
            ValueBytesBasis::RebuiltFromRendering => "rebuilt_from_rendering",
            ValueBytesBasis::ReencodedUtf16le => "reencoded_utf16le",
            ValueBytesBasis::ReencodedUtf16leElements => "reencoded_utf16le_elements",
        }
    }

    fn statement(&self) -> &'static str {
        match self {
            ValueBytesBasis::Exact => {
                "the bytes scanned are the value's stored bytes, as the registry parser \
                published them in `value_data_b64`"
            }
            ValueBytesBasis::RebuiltFromRendering => {
                "the record carries no stored bytes for this value (it was written by a \
                build older than HUNT-159), so the bytes scanned were rebuilt from a lossless \
                rendering — hex, or a little-endian DWORD/QWORD at its own width; they \
                reproduce the stored bytes but are a reconstruction"
            }
            ValueBytesBasis::ReencodedUtf16le => {
                "the record carries no stored bytes for this string value (it was written \
                by a build older than HUNT-159, or its bytes passed the hive's per-hive cap), \
                so the bytes scanned are its decoded text re-encoded as UTF-16LE without its \
                terminator; that reproduces the stored bytes only for a well-formed string with \
                one terminator, and `raw_data_size` beside `bytes_scanned` shows the difference \
                where there is one"
            }
            ValueBytesBasis::ReencodedUtf16leElements => {
                "the record carries no stored bytes for this multi-string value (its bytes \
                passed the hive's per-hive cap), so the bytes scanned are the elements of its \
                `value_data_list` re-encoded as UTF-16LE, each with its terminator, then the \
                list terminator; that reproduces the stored bytes only for a well-formed list \
                (the registry parser drops empty elements and replaces unpaired UTF-16 \
                surrogates), and `raw_data_size` beside `bytes_scanned` shows the difference \
                where there is one"
            }
        }
    }
}

/// Reasons a registry value was not scanned, as the coverage record counts them.
const REASON_MULTI_SZ: &str = "multi_sz_rendering_is_lossy";
const REASON_PARSER_ERROR: &str = "parser_could_not_read_value";
const REASON_NOT_REPRODUCED: &str = "rendering_does_not_reproduce_bytes";
const REASON_BYTE_BUDGET: &str = "byte_budget_reached";
/// A `REG_DWORD_BIG_ENDIAN` with no stored bytes: builds before `HUNT-158`
/// rendered it as the little-endian number and later ones as the big-endian
/// one, and the record does not say which wrote it (`HUNT-207`).
const REASON_BIG_ENDIAN_ORDER: &str = "big_endian_dword_rendering_order_unknown";

/// Reproduce a registry value's bytes from what the hive record publishes.
///
/// Since `HUNT-159` the registry parser publishes every value's stored bytes
/// as `value_data_b64`, except a value over 64 bytes past the hive's per-hive
/// cap (marked `value_data_b64_omitted`); those bytes win wherever present.
/// Without them — a record from an older build, or a capped value — this
/// mirrors the parser's rendering rules, branch for branch, with the type
/// names matched exactly: string types are re-encoded; a `DWORD` or `QWORD`
/// is rebuilt from its `0x…` rendering only at its own width; a
/// `REG_DWORD_BIG_ENDIAN` is refused, because the byte order its rendering
/// was decoded in changed with `HUNT-158`; a multi-string is re-encoded
/// from its `value_data_list` elements where the record carries them
/// (`HUNT-217`), and otherwise refused, because its rendering joins its parts
/// with a separator that cannot be told from content; everything else is the hex rendering of a value of at most 64
/// bytes. Any rendering that does not account for exactly `raw_data_size`
/// bytes is refused rather than scanned as an approximation.
fn registry_value_bytes(
    value: &serde_json::Value,
) -> Result<(Vec<u8>, ValueBytesBasis), &'static str> {
    let value_type = value
        .get("value_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let rendering = value
        .get("value_data")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let raw_size = value
        .get("raw_data_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    if let Some(b64) = value.get("value_data_b64").and_then(|v| v.as_str()) {
        let bytes = BASE64.decode(b64).map_err(|_| REASON_NOT_REPRODUCED)?;
        if bytes.len() != raw_size {
            return Err(REASON_NOT_REPRODUCED);
        }
        return Ok((bytes, ValueBytesBasis::Exact));
    }
    // The parser renders a value it could not read as "(error …)" with a size
    // of zero; a real zero-length value never renders that way.
    if raw_size == 0 && rendering.starts_with("(error ") {
        return Err(REASON_PARSER_ERROR);
    }

    if value_type == "RegSZ" || value_type == "RegExpandSZ" {
        if rendering == "(empty string)" && raw_size < 2 {
            return if raw_size == 0 {
                Ok((Vec::new(), ValueBytesBasis::RebuiltFromRendering))
            } else {
                Err(REASON_NOT_REPRODUCED)
            };
        }
        let bytes: Vec<u8> = rendering
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        Ok((bytes, ValueBytesBasis::ReencodedUtf16le))
    } else if value_type == "RegDWord" {
        fixed_width_bytes(rendering, raw_size, 4)
    } else if value_type == "RegDWordBigEndian" {
        Err(REASON_BIG_ENDIAN_ORDER)
    } else if value_type == "RegQWord" {
        fixed_width_bytes(rendering, raw_size, 8)
    } else if value_type == "RegMultiSZ" {
        let Some(elements) = value.get("value_data_list").and_then(|v| v.as_array()) else {
            return Err(REASON_MULTI_SZ);
        };
        let mut bytes = Vec::with_capacity(raw_size);
        for element in elements {
            let text = element.as_str().ok_or(REASON_NOT_REPRODUCED)?;
            bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
            bytes.extend([0, 0]);
        }
        bytes.extend([0, 0]);
        Ok((bytes, ValueBytesBasis::ReencodedUtf16leElements))
    } else {
        hex_rendering_bytes(rendering, raw_size)
    }
}

/// A DWORD or QWORD from its `0x{value:0width$x} ({value})` rendering.
///
/// Only when the stored size is the width: the parser reads the first four or
/// eight bytes of whatever was there and renders that number, so a longer
/// value's tail is not in the rendering and cannot be rebuilt.
fn fixed_width_bytes(
    rendering: &str,
    raw_size: usize,
    width: usize,
) -> Result<(Vec<u8>, ValueBytesBasis), &'static str> {
    if raw_size != width {
        return Err(REASON_NOT_REPRODUCED);
    }
    let hex = rendering
        .strip_prefix("0x")
        .and_then(|rest| rest.get(..width * 2))
        .ok_or(REASON_NOT_REPRODUCED)?;
    let number = u64::from_str_radix(hex, 16).map_err(|_| REASON_NOT_REPRODUCED)?;
    Ok((
        number.to_le_bytes()[..width].to_vec(),
        ValueBytesBasis::RebuiltFromRendering,
    ))
}

/// A binary value from the parser's space-separated two-digit hex rendering.
fn hex_rendering_bytes(
    rendering: &str,
    raw_size: usize,
) -> Result<(Vec<u8>, ValueBytesBasis), &'static str> {
    if rendering.is_empty() {
        return if raw_size == 0 {
            Ok((Vec::new(), ValueBytesBasis::RebuiltFromRendering))
        } else {
            Err(REASON_NOT_REPRODUCED)
        };
    }
    let mut bytes = Vec::with_capacity(raw_size);
    for pair in rendering.split(' ') {
        if pair.len() != 2 {
            return Err(REASON_NOT_REPRODUCED);
        }
        bytes.push(u8::from_str_radix(pair, 16).map_err(|_| REASON_NOT_REPRODUCED)?);
    }
    if bytes.len() != raw_size {
        return Err(REASON_NOT_REPRODUCED);
    }
    Ok((bytes, ValueBytesBasis::RebuiltFromRendering))
}

/// The hive-level fields every record about a hive's values carries: which
/// hive, and whether the hive record is itself the whole hive. A match set
/// over a capped or short hive must not read as the whole hive's.
fn hive_context(metadata: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    let mut context = serde_json::Map::new();
    if let Some(hive_type) = metadata.get("hive_type") {
        context.insert("hive_type".into(), hive_type.clone());
    }
    if let Some(complete) = metadata.get("key_inventory_complete") {
        context.insert("hive_key_inventory_complete".into(), complete.clone());
    }
    if let Some(incomplete) = metadata.get("content_incomplete") {
        context.insert("hive_content_incomplete".into(), incomplete.clone());
        if let Some(reason) = metadata.get("content_incomplete_reason") {
            context.insert("hive_content_incomplete_reason".into(), reason.clone());
        }
    }
    context
}

/// One region of bytes to scan, and what every record about it must carry.
struct Region {
    surface: Surface,
    /// Copied onto every record emitted for the region — the stream name, the
    /// key path, the region's offset — so each record names its own
    /// provenance without a walk back to the source artifact.
    context: serde_json::Map<String, serde_json::Value>,
    /// The region's first byte in its parent's coordinate space, where the
    /// region has one. Pattern hits are then also published against it.
    parent_offset: Option<u64>,
    /// The field a pattern hit's offset is published under: into the region,
    /// or into a decoded buffer lifted out of it. Two names, because the two
    /// are not the same coordinate space and a reader must not add one to a
    /// region offset.
    hit_offset_key: &'static str,
}

impl Region {
    fn new(
        surface: Surface,
        context: serde_json::Map<String, serde_json::Value>,
        parent_offset: Option<u64>,
    ) -> Self {
        Self {
            surface,
            context,
            parent_offset,
            hit_offset_key: "offset_in_region",
        }
    }

    /// The region a decoded span is scanned as: the same surface and
    /// provenance, plus what was decoded, from where, and how.
    fn decoded_child(&self, span: &Decoded, from: DecodeSource) -> Region {
        let mut context = self.context.clone();
        context.insert("bytes_are_decoded".into(), json!(true));
        context.insert("decoded_via".into(), json!(span.method));
        context.insert("decoded_from".into(), json!(from.as_str()));
        context.insert(from.offset_key().into(), json!(span.offset as u64));
        if let (Some(base), DecodeSource::RegionBytes) = (self.parent_offset, from) {
            if let Some(in_parent) = base.checked_add(span.offset as u64) {
                context.insert("decoded_span_offset_in_parent".into(), json!(in_parent));
            }
        }
        context.insert("decoded_bytes".into(), json!(span.data.len() as u64));
        context.insert("decoded_truncated".into(), json!(span.truncated));
        context.insert("decoded_depth".into(), json!(1));
        context.insert(
            "decoded_means".into(),
            json!(
                "the bytes scanned were decoded out of an encoded span found in this region; \
                 they were never stored in this form, a hit's `offset_in_decoded` is into the \
                 decoded buffer and not into the region, and the decoding is one level deep"
            ),
        );
        Region {
            surface: self.surface,
            context,
            parent_offset: None,
            hit_offset_key: "offset_in_decoded",
        }
    }

    fn stamp(&self, meta: &mut serde_json::Value) {
        if let Some(map) = meta.as_object_mut() {
            map.insert("surface".into(), json!(self.surface.as_str()));
            map.insert("surface_means".into(), json!(self.surface.statement()));
            for (k, v) in &self.context {
                map.insert(k.clone(), v.clone());
            }
        }
    }
}

/// What the decoders were run over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeSource {
    /// The region's own bytes.
    RegionBytes,
    /// A registry value's reproduced bytes.
    ValueBytes,
    /// A registry string value's published text.
    ValueText,
}

impl DecodeSource {
    fn as_str(&self) -> &'static str {
        match self {
            DecodeSource::RegionBytes => "region_bytes",
            DecodeSource::ValueBytes => "value_bytes",
            DecodeSource::ValueText => "value_text",
        }
    }

    /// Where the span's offset is measured from, named so a text offset is
    /// never added to a byte offset.
    fn offset_key(&self) -> &'static str {
        match self {
            DecodeSource::RegionBytes | DecodeSource::ValueBytes => "decoded_span_offset_in_region",
            DecodeSource::ValueText => "decoded_span_offset_in_text",
        }
    }
}

/// What the decode-and-rescan step found and did, for the record that
/// reports it — always with the ceilings beside the counts.
#[derive(Debug, Default, Clone, Copy)]
struct DecodeOutcome {
    spans_found: u64,
    spans_scanned: u64,
    bytes_scanned: u64,
    cap_reached: bool,
    engine_errors: u64,
    matches: u64,
}

impl DecodeOutcome {
    fn add(&mut self, other: &DecodeOutcome) {
        self.spans_found += other.spans_found;
        self.spans_scanned += other.spans_scanned;
        self.bytes_scanned += other.bytes_scanned;
        self.cap_reached |= other.cap_reached;
        self.engine_errors += other.engine_errors;
        self.matches += other.matches;
    }

    fn stamp(&self, map: &mut serde_json::Map<String, serde_json::Value>) {
        map.insert("decoded_spans_found".into(), json!(self.spans_found));
        map.insert("decoded_spans_scanned".into(), json!(self.spans_scanned));
        map.insert("decoded_bytes_scanned".into(), json!(self.bytes_scanned));
        map.insert("decoded_cap_reached".into(), json!(self.cap_reached));
        map.insert(
            "decoded_span_cap".into(),
            json!(MAX_DECODED_SPANS_PER_REGION),
        );
        map.insert(
            "decoded_byte_cap".into(),
            json!(MAX_DECODED_BYTES_PER_REGION),
        );
        map.insert("decoded_engine_errors".into(), json!(self.engine_errors));
        map.insert("decoded_matches".into(), json!(self.matches));
        map.insert("decoded_depth".into(), json!(1));
    }

    /// The sentence a record carries when not every span was scanned.
    fn shortfall(&self) -> Option<String> {
        if !self.cap_reached && self.engine_errors == 0 {
            return None;
        }
        let mut parts = Vec::new();
        if self.cap_reached {
            parts.push(format!(
                "{} decoded spans past the ceiling ({} spans or {} bytes per region) were \
                 found and not scanned",
                self.spans_found.saturating_sub(self.spans_scanned),
                MAX_DECODED_SPANS_PER_REGION,
                MAX_DECODED_BYTES_PER_REGION
            ));
        }
        if self.engine_errors > 0 {
            parts.push(format!(
                "the engine failed on {} decoded span(s)",
                self.engine_errors
            ));
        }
        Some(parts.join("; "))
    }
}

/// What an artifact is to this module.
enum Kind {
    /// A registry hive record: its values are scanned one by one.
    Hive,
    /// Anything with attached bytes, scanned as one region.
    Bytes(Region),
    /// An artifact type this module has no surface for. It is refused, not
    /// scanned under a surface it cannot vouch for.
    Unsupported(ArtifactType),
}

/// Read an artifact's shape off what its producer published.
///
/// The registry hive record is recognised by its `type`, whatever artifact
/// type carries it. Then the producer's provenance flags, strongest first: `carved` outranks everything, a stream
/// (`is_ads`) outranks `deleted` because `entry_deleted` already carries the
/// record's state onto the stream, and a deleted file is its own surface.
/// Only then does the artifact type decide: a file the file system or the
/// ingest path serves is `file`; free space is `unallocated`; a partition,
/// file system, evidence image or container scanned whole is `volume`;
/// anything else is refused.
fn classify(artifact: &Artifact) -> Kind {
    let meta = &artifact.metadata;
    if meta.get("type").and_then(|v| v.as_str()) == Some("RegistryHive") {
        return Kind::Hive;
    }
    let mut context = serde_json::Map::new();
    let copy = |context: &mut serde_json::Map<String, serde_json::Value>, from: &str, to: &str| {
        if let Some(v) = meta.get(from) {
            context.insert(to.to_string(), v.clone());
        }
    };
    if meta.get("carved").and_then(|v| v.as_bool()) == Some(true) {
        for key in [
            "carving_signature",
            "carving_offset",
            "carving_offset_absolute",
            "carving_validated",
            "carving_source",
        ] {
            copy(&mut context, key, key);
        }
        copy(&mut context, "parent_file", "base_file");
        // The carver's `carving_offset` is into the artifact it scanned —
        // the carved object's parent — except when it carved slack, where
        // it is into the slack window and the parent is the file. Only the
        // first can place a hit in the parent's coordinate space.
        let parent_offset = if meta.get("carving_source").is_none() {
            meta.get("carving_offset").and_then(|v| v.as_u64())
        } else {
            None
        };
        return Kind::Bytes(Region::new(Surface::Carved, context, parent_offset));
    }
    // Only a boolean the producer wrote is carried: a match must not invent
    // a `false` for an entry whose producer never said.
    let deleted = meta.get("deleted").and_then(|v| v.as_bool());
    if let Some(deleted) = deleted {
        context.insert("entry_deleted".into(), json!(deleted));
    }
    let is_ads = artifact.artifact_type == ArtifactType::FileEntry
        && meta.get("is_ads").and_then(|v| v.as_bool()) == Some(true);
    if is_ads {
        copy(&mut context, "stream_name", "stream_name");
        copy(&mut context, "parent_file", "base_file");
        copy(&mut context, "path", "path");
        return Kind::Bytes(Region::new(Surface::Ads, context, None));
    }
    if deleted == Some(true) {
        copy(&mut context, "path", "path");
        copy(
            &mut context,
            "deleted_recovery_source",
            "deleted_recovery_source",
        );
        copy(
            &mut context,
            "deleted_content_caveat",
            "deleted_content_caveat",
        );
        return Kind::Bytes(Region::new(Surface::DeletedFile, context, None));
    }
    match artifact.artifact_type {
        ArtifactType::FileEntry | ArtifactType::FileContent | ArtifactType::SystemArtifact => {
            Kind::Bytes(Region::new(Surface::File, context, None))
        }
        ArtifactType::Partition
        | ArtifactType::FileSystem
        | ArtifactType::RawEvidence
        | ArtifactType::Container => {
            context.insert(
                "volume_type".into(),
                json!(artifact.artifact_type.to_string()),
            );
            copy(&mut context, "offset_bytes", "offset_bytes");
            copy(&mut context, "size_bytes", "size_bytes");
            copy(&mut context, "offset_basis", "offset_basis");
            // A partition's `offset_bytes` is into the evidence it was found
            // in — its parent. A file system's is copied from its partition,
            // so it is the grandparent's coordinate space and cannot place a
            // hit "in parent"; an evidence image or container has no parent.
            let parent_offset = if artifact.artifact_type == ArtifactType::Partition {
                meta.get("offset_bytes").and_then(|v| v.as_u64())
            } else {
                None
            };
            Kind::Bytes(Region::new(Surface::Volume, context, parent_offset))
        }
        ArtifactType::UnallocatedSpace => {
            copy(&mut context, "offset_bytes", "offset_bytes");
            copy(&mut context, "size_bytes", "size_bytes");
            copy(&mut context, "offset_basis", "offset_basis");
            copy(&mut context, "filesystem", "filesystem");
            if let Some(source) = meta.get("source") {
                context.insert("region_source".into(), source.clone());
            } else if meta.get("partition_scheme").is_some() {
                context.insert("region_source".into(), json!("partition_gap"));
            }
            let parent_offset = meta.get("offset_bytes").and_then(|v| v.as_u64());
            Kind::Bytes(Region::new(Surface::Unallocated, context, parent_offset))
        }
        ArtifactType::SlackSpace => {
            // The region's `offset_bytes` is into the file system it hangs off
            // (`seance_core::slack`), so it places a hit in the parent.
            copy(&mut context, "offset_bytes", "offset_bytes");
            copy(&mut context, "size_bytes", "size_bytes");
            copy(&mut context, "offset_basis", "offset_basis");
            copy(&mut context, "filesystem", "filesystem");
            copy(&mut context, "parent_file", "base_file");
            copy(&mut context, "parent_path", "path");
            copy(&mut context, "owner_artifact_id", "owner_artifact_id");
            copy(&mut context, "logical_size", "logical_size");
            copy(&mut context, "cluster_size", "cluster_size");
            copy(&mut context, "source", "region_source");
            let parent_offset = meta.get("offset_bytes").and_then(|v| v.as_u64());
            Kind::Bytes(Region::new(Surface::Slack, context, parent_offset))
        }
        ArtifactType::ParsedRecord | ArtifactType::TimelineEvent => {
            Kind::Unsupported(artifact.artifact_type.clone())
        }
    }
}

/// Shannon entropy of `bytes`, in bits per byte: 0 for one repeated value,
/// 8 for every value equally often. Zero over no bytes, which is "no
/// information" rather than a claim about content — the byte count travels
/// beside it wherever it is published.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// The entropy fields a record carries: the figure to four decimals, and the
/// population it was computed over.
fn entropy_fields(bytes: &[u8]) -> (f64, u64) {
    let entropy = (shannon_entropy(bytes) * 10_000.0).round() / 10_000.0;
    (entropy, bytes.len() as u64)
}

/// Collect the rule files under `path`, sorted, so a rule set compiles in the
/// same order on every run and on every machine.
///
/// Symlinks are **followed**, both to files and to directories. `DirEntry`'s
/// own `file_type()` describes the link rather than its target, so testing it
/// directly would drop a symlinked rule file with no diagnostic — and a rule
/// set that quietly lost half its rules is the failure this module exists to
/// prevent (`rules/apt -> /opt/yara-rules/apt` is an ordinary way to assemble
/// one). Cycles are bounded instead by remembering each directory's
/// canonicalised path, so `rules/all -> rules` is visited once rather than
/// forever.
///
/// A dangling link is fatal only when it was going to be a rule: `apt.yar`
/// pointing at nothing is a rule the examiner believes is loaded, while a
/// broken `notes.txt` is not this module's business.
fn collect_rule_files(path: &Path) -> Result<Vec<PathBuf>, RuleLoadError> {
    // `fs::metadata` follows links, so a rule tree reached entirely through one
    // is walked like any other.
    let meta = fs::metadata(path).map_err(|e| RuleLoadError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if meta.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let canonical = fs::canonicalize(&dir).map_err(|e| RuleLoadError::Io {
            path: dir.clone(),
            source: e,
        })?;
        if !visited.insert(canonical) {
            continue;
        }

        let entries = fs::read_dir(&dir).map_err(|e| RuleLoadError::Io {
            path: dir.clone(),
            source: e,
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| RuleLoadError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let entry_path = entry.path();
            let target = match fs::metadata(&entry_path) {
                Ok(target) => target,
                Err(e) => {
                    if has_rule_extension(&entry_path) {
                        return Err(RuleLoadError::Io {
                            path: entry_path,
                            source: e,
                        });
                    }
                    continue;
                }
            };
            if target.is_dir() {
                stack.push(entry_path);
            } else if target.is_file() && has_rule_extension(&entry_path) {
                out.push(entry_path);
            }
        }
    }
    out.sort();
    // The same file can be reached twice through two different links; compiling
    // it twice would be a duplicate-rule error, not a bigger rule set.
    out.dedup();
    Ok(out)
}

fn has_rule_extension(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => RULE_FILE_EXTENSIONS
            .iter()
            .any(|known| ext.eq_ignore_ascii_case(known)),
        None => false,
    }
}

/// YARA over an address space rather than a file: the `Scanner` the memory
/// tier drives through `seance_memory::scan`.
pub mod memory;

#[cfg(test)]
mod memory_tests;
#[cfg(test)]
mod surfaces_real_tests;
#[cfg(test)]
mod surfaces_tests;
#[cfg(test)]
mod tests;
