//! The `ForensicsModule` that turns a memory image into ordinary Séance evidence.
//!
//! # What this phase delivers
//!
//! Phase 1 of the memory-forensics programme (plan 07) does **not** analyse memory
//! — there is no address translation and no symbol handling yet. What it does is
//! make a memory capture a first-class evidence type: the image is identified,
//! its physical address space is decoded, and that decoded view is attached to
//! the artifact as a [`DataSource`].
//!
//! That single move is the whole payoff. Every existing Séance capability that
//! consumes a `DataSource` — the carver with its whole signature set, the hasher, the
//! string search and entity extraction, the hex viewer — starts working on memory
//! content immediately, with no symbol table and no profile. An examiner can
//! carve documents and images out of RAM, hash the capture for continuity, and
//! grep it for an address or a filename on the day this lands.
//!
//! Phases 2+ add page-table translation, symbols/ISF, and the process/network/
//! module views proper.
//!
//! # Detection is deliberately conservative
//!
//! A raw memory dump has **no magic**. It is bytes. The Windows XP reference
//! image in the parity corpus begins `7e af 00 f0` — an interrupt-vector entry,
//! indistinguishable from any other headerless file.
//!
//! So this module claims an artifact only when one of two things is true:
//!
//! 1. A format reader positively identifies it (`PAGEDU64`, `EMiL`, `AVML`,
//!    `\x7fELF` + core, `hibr`, a QEMU/VMware structure), or
//! 2. the artifact's metadata **declares** it — `memory_image: true`, or a
//!    `memory_image_format` naming one of
//!    [`crate::format::DECLARABLE_FORMAT_NAMES`].
//!
//! Guessing would be far worse than missing a bare `.raw`: every unrecognised
//! file in every case would be claimed as a memory image, and each would emit a
//! record asserting an image that is not there. A missed raw dump is recoverable
//! by the examiner declaring it; a false claim is silent misinformation.
//!
//! # A declaration is never discarded in silence
//!
//! The other half of that rule. A declaration this build cannot act on — a
//! format name it does not know, a flag that is not a boolean — is an error, not
//! an absence. Returning `Ok(vec![])` for one made an examiner's assertion
//! vanish: no record, no failure, and every downstream memory stage reporting
//! `did_not_run`, which is exactly what an ordinary undeclared disk image
//! produces. "Nobody said this was memory" and "someone said so and we did not
//! understand them" must never render alike.

use std::sync::Arc;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::{
    detect,
    format::{parse_format_name, MemoryImageFormat, DECLARABLE_FORMAT_NAMES},
    formats::{self, FormatError},
    layer::{LayerError, MappedRange, MemoryLayer},
    meta::LayerMeta,
    physical::PhysicalLayer,
};

/// Metadata key by which a case can declare a headerless image to be memory.
const DECLARE_FLAG: &str = "memory_image";
/// Metadata key naming the format explicitly, for a declared raw image.
const DECLARE_FORMAT: &str = "memory_image_format";

/// Name endings that are a headerless *memory* capture and very little else.
///
/// Deliberately short, and deliberately without `.raw`, `.dd`, `.bin` or
/// `.img`: those are the extensions of every second disk image in every case,
/// and attaching [`undeclared_memory_hint`] to them would put the sentence in
/// front of examiners doing work that has nothing to do with memory. A hint
/// that fires on everything is one nobody reads.
const HEADERLESS_MEMORY_SUFFIXES: &[&str] = &[".mem", ".vmem", ".ram"];

/// Identifies a memory capture, decodes its physical address space, and attaches
/// it so the rest of Séance can read it.
pub struct MemoryImageModule;

/// A decoded image: the addressable layer, what the format said about it, and
/// the acquired physical extents when the format records them.
///
/// Named because the triple is otherwise three anonymous halves at the one
/// place a reader most needs to know which is which.
type DecodedImage = (Arc<dyn DataSource>, LayerMeta, Option<Vec<(u64, u64)>>);

impl ForensicsModule for MemoryImageModule {
    fn id(&self) -> &str {
        "container.memory_image"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // A memory capture arrives either as the ingested evidence itself, or as
        // a file extracted from a container (a `.vmem` inside a VM directory, a
        // dump inside a zip).
        vec![ArtifactType::RawEvidence, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unnamed)");

        // 1. Identify. `detect` returns `Raw` for "no magic found", which is the
        //    absence of a detection and never a positive one, so a raw image is
        //    accepted only when the case declared it.
        let detected = detect(source.as_ref());
        // What the case named, as opposed to what it merely flagged. Only a
        // name is a claim the evidence can contradict, so only a name is
        // reported for and against on the record below. A name this build
        // cannot read is an error, never an absence: see `named_format`.
        let named = named_format(artifact)?;
        let declared = declared_format(artifact, named)?;

        let format = match (detected, declared) {
            // A positive magic always wins: it is evidence, the declaration is a
            // human assertion. Disagreement is surfaced rather than silently
            // resolved, because it usually means the wrong file was declared.
            (MemoryImageFormat::Raw, None) => {
                // Claiming nothing is right — no evidence says this is memory —
                // but for a name that is almost always a capture, saying why
                // nothing happened costs nothing and is the only thing that
                // tells an examiner a declaration was what was missing. It is a
                // log line and not a record: see `undeclared_memory_hint`.
                if let Some(hint) = undeclared_memory_hint(name) {
                    warn!("{}", hint);
                }
                return Ok(Vec::new());
            }
            (MemoryImageFormat::Raw, Some(d)) => d,
            (found, None) => found,
            (found, Some(d)) if found == d => found,
            (found, Some(d)) => {
                // The log line is for whoever is watching the run. The record
                // below is what an examiner reads, and it is where the
                // disagreement actually has to land: a declaration that the
                // evidence contradicts usually means the wrong file was
                // declared, and a report that shows only the winner has quietly
                // dropped the fact that there was a contest.
                warn!(
                    "{}: declared as {:?} but its header identifies {:?}; \
                     using the header and recording the disagreement on the record",
                    name, d, found
                );
                found
            }
        };

        info!("Memory image detected: {} ({:?})", name, format);

        // 2. Decode the physical address space.
        let (layer, meta, backed): DecodedImage = match open_layer(format, source) {
            Ok(v) => v,
            Err(e) => {
                // A file that announced itself as a memory image and then failed
                // to parse is reported, not skipped: the examiner declared it or
                // its header claimed it, so silence would be the wrong answer.
                warn!("{}: memory image failed to decode: {}", name, e);
                return Ok(vec![failure_record(artifact, format, named, &e, source)]);
            }
        };

        debug!(
            "{}: decoded {:?}, {} addressable bytes",
            name,
            format,
            layer.size()
        );

        // 3. Emit the image record and hand the decoded view to the pipeline.
        Ok(vec![image_record(
            artifact, format, named, &meta, &layer, source, backed,
        )])
    }
}

/// The format a case declared for this artifact, if any, given the format it
/// [named](named_format).
///
/// Accepts either `memory_image_format: "<name>"` or the boolean
/// `memory_image: true` (which means "raw, trust me"). A name that was given
/// takes precedence and never falls through to the flag: "raw, trust me" is not
/// what an examiner who typed a format name said. Since an unreadable name is
/// already an error by the time this is called, there is no path on which a
/// typo becomes "raw".
///
/// # Errors
///
/// [`refused`] if `memory_image` is present but is not a boolean. A declaration
/// written as the string `"true"`, or as `1`, is an assertion this build cannot
/// act on, and dropping it would make an examiner who declared a capture
/// indistinguishable from one who declared nothing.
fn declared_format(
    artifact: &Artifact,
    named: Option<MemoryImageFormat>,
) -> Result<Option<MemoryImageFormat>, ModuleError> {
    if let Some(named) = named {
        return Ok(Some(named));
    }
    match artifact.metadata.get(DECLARE_FLAG) {
        None => Ok(None),
        Some(value) => match value.as_bool() {
            Some(true) => Ok(Some(MemoryImageFormat::Raw)),
            Some(false) => Ok(None),
            None => Err(refused(format!(
                "{DECLARE_FLAG} must be a boolean; it is {value}. A declaration that this \
                 source is a capture of physical memory is an assertion on the record, and \
                 one written in a form this build cannot read is refused rather than ignored"
            ))),
        },
    }
}

/// The error a refused declaration becomes, and the one variant it must not be.
///
/// # What an examiner learns
///
/// That a declaration was made and could not be honoured — on the case
/// dashboard, as a processing-log row with `status: "error"` carrying this
/// sentence, and on the status bus as an
/// `OrchestratorEvent::ModuleError`.
///
/// # What a wrong answer would look like
///
/// [`ModuleError::InvalidInputFormat`], which reads like the right variant and
/// is the one variant the orchestrator is written to swallow: both of its match
/// arms on it (`seance_core/src/orchestrator.rs`, the automatic path and the
/// ad-hoc path) log at `debug!`, broadcast `ModuleCompleted` with zero
/// artifacts, and write a processing-log row with `status: "skipped"` and
/// **`error_message: None`** — the message is discarded, and
/// `test_skipping_module_emits_completed_with_zero_artifacts` pins that
/// behaviour. Returning it here would have reproduced the very defect this
/// refusal exists to close: an examiner's declaration dropped without a word,
/// rendering identically to a disk image nobody declared.
///
/// [`ModuleError::ParsingError`] is what the orchestrator surfaces. The text is
/// what carries the meaning, so it names the key, the offending value and the
/// set the value could have been drawn from.
///
/// Shared with [`crate::analysis`] so the choice is made once. Every refusal in
/// this crate exists because something could not be established, and the
/// sentence saying what is the entire deliverable — routing any of them through
/// the skip variant deletes it.
pub(crate) fn refused(detail: String) -> ModuleError {
    ModuleError::ParsingError(detail)
}

/// The format a case named explicitly, as distinct from the `memory_image: true`
/// flag.
///
/// The two are different assertions and only this one is about the format. The
/// flag says "this file is memory", which a headerless dump needs and which no
/// header can contradict; the name says "this file is a LiME capture", which a
/// header can and does contradict. Stamping a mismatch for the flag would put
/// "declared raw, header says LiME" on every ordinary flagged capture and train
/// examiners to ignore the field.
///
/// # Errors
///
/// [`refused`] if `memory_image_format` is present but is not a string, or names
/// no format in [`DECLARABLE_FORMAT_NAMES`].
///
/// # What an examiner learns
///
/// That a declaration was made and could not be honoured. This used to return
/// `None` for an unreadable name, which then met `(Raw, None)` in `process` and
/// returned `Ok(vec![])`: the module claimed nothing, no memory record was
/// written, and every downstream memory stage reported `did_not_run` — the same
/// output as an ordinary disk image nobody declared. An examiner who picked
/// "hibernation" in the ingest form got precisely that. The error here becomes a
/// failed processing-log row and a `ModuleError` event naming the evidence and
/// the word that was not understood — see [`refused`] for why the variant
/// matters as much as the sentence.
fn named_format(artifact: &Artifact) -> Result<Option<MemoryImageFormat>, ModuleError> {
    let Some(value) = artifact.metadata.get(DECLARE_FORMAT) else {
        return Ok(None);
    };
    let Some(name) = value.as_str() else {
        return Err(refused(format!(
            "{DECLARE_FORMAT} must be a string naming an acquisition format; it is {value}. \
             Accepted names: {}",
            accepted_format_names()
        )));
    };
    parse_format_name(name).map(Some).ok_or_else(|| {
        refused(format!(
            "{DECLARE_FORMAT} is {name:?}, which names no acquisition format this build can \
             read, so the declaration cannot be honoured and is not discarded in silence. \
             Accepted names: {}",
            accepted_format_names()
        ))
    })
}

/// What to tell an operator whose headerless capture reached this module
/// without a declaration, or `None` when the name is not memory-shaped.
///
/// # Why this is a hint and not a claim
///
/// A file name is not evidence. `detect` answering [`MemoryImageFormat::Raw`]
/// is the *absence* of a detection, and promoting a file to "memory" because of
/// its extension is exactly the guess this module refuses to make — every
/// unrecognised file in every case would then carry a record asserting an image
/// that is not there.
///
/// But the honest refusal has a cost that was being paid in silence. An
/// examiner who ingested `physmem.mem` gets no memory record, no warning and no
/// processing-log row, and every downstream memory stage reports `did_not_run`
/// — output identical to a case where no capture was ever supplied. The usual
/// conclusion is "Séance cannot do memory", when the missing piece was one
/// metadata key. This is that sentence, and it names the keys rather than
/// describing the problem.
///
/// # Where it belongs
///
/// It is returned rather than emitted so the ingest surfaces can put it in
/// front of an operator at the moment of ingest, which is where it is actually
/// read; [`MemoryImageModule::process`] logs it for whoever is watching the run.
pub fn undeclared_memory_hint(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if !HEADERLESS_MEMORY_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return None;
    }
    Some(format!(
        "{name} was not claimed as a memory image: it carries no acquisition-format magic, and \
         a name is not evidence that a file is a capture of physical memory. If it is one, \
         re-ingest it with {DECLARE_FLAG}: true for a headerless capture, or with \
         {DECLARE_FORMAT} naming its acquisition format. Accepted names: {}",
        accepted_format_names()
    ))
}

/// Every name a declaration may use, for the message that refuses one that is
/// not among them. Built from the exported table so it cannot drift from what
/// [`parse_format_name`] actually accepts.
fn accepted_format_names() -> String {
    DECLARABLE_FORMAT_NAMES
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Decode `source` as `format` and return its physical address space as a
/// layer that still knows where its holes are.
///
/// The container stage decodes an image once, at ingest, and hands the result
/// on as an opaque `DataSource`. A later reader of the *bytes* — the layer
/// export ([`crate::export`]) above all — needs the decoded space again with
/// its geometry, and this is the one way to get it: the same decoder the
/// ingest ran ([`open_layer`]), wrapped in a [`PhysicalLayer`] that is told the
/// backed ranges rather than left to answer "all of it is backed".
pub fn open_physical_layer(
    format: MemoryImageFormat,
    source: &Arc<dyn DataSource>,
) -> Result<Arc<dyn MemoryLayer>, FormatError> {
    let (decoded, meta, backed) = open_layer(format, source)?;
    let physical =
        PhysicalLayer::new(decoded, meta).map_err(|source| FormatError::layer(format, source))?;
    Ok(Arc::new(match backed {
        Some(ranges) => physical.with_backed(ranges),
        None => physical,
    }) as Arc<dyn MemoryLayer>)
}

/// Decode `source` according to `format`, returning the physical view and the
/// metadata describing how it was obtained.
#[allow(clippy::type_complexity)]
fn open_layer(
    format: MemoryImageFormat,
    source: &Arc<dyn DataSource>,
) -> Result<(Arc<dyn DataSource>, LayerMeta, Option<Vec<(u64, u64)>>), FormatError> {
    /// Every layer type reaches its metadata through the `MemoryLayer` trait, so
    /// the six arms differ only in which reader produced the layer.
    /// Erase the concrete layer type, keeping what only it could tell us.
    ///
    /// The geometry has to be read here, because one line later the layer is an
    /// `Arc<dyn DataSource>` and its holes are no longer visible to anyone. A
    /// flat image reports `None` — the absence of a claim, not a claim of
    /// emptiness — so the analysis side falls back to the identity mapping that
    /// is correct for it.
    ///
    /// `None` is therefore reserved for a layer that really is one unbroken run
    /// from address zero. A layer that could not state its geometry is an
    /// error, never a `None`: see [`backed_ranges`].
    fn finish<L: MemoryLayer + 'static>(
        format: MemoryImageFormat,
        l: L,
    ) -> Result<(Arc<dyn DataSource>, LayerMeta, Option<Vec<(u64, u64)>>), FormatError> {
        let m = l.layer_meta().clone();
        let size = l.size();
        let ranges = backed_ranges(&l).map_err(|source| FormatError::layer(format, source))?;
        if ranges.is_empty() {
            // Unreachable for every reader here — each one refuses an image with
            // no segments — and a refusal keeps it that way, because an empty
            // geometry is read downstream as "flat", i.e. as full coverage.
            return Err(FormatError::malformed(
                format,
                "the decoded address space reports no acquired bytes at all, so its \
                 coverage cannot be stated",
            ));
        }
        let backed = match ranges.as_slice() {
            [(0, len)] if *len == size => None,
            _ => Some(ranges),
        };
        Ok((Arc::new(l) as Arc<dyn DataSource>, m, backed))
    }

    let src = Arc::clone(source);
    Ok(match format {
        // `raw` rather than `new`: it is the constructor reserved for a source an
        // examiner has DECLARED to be memory, which is the only way a headerless
        // image gets here at all.
        MemoryImageFormat::Raw => finish(
            format,
            PhysicalLayer::raw(src).map_err(|source| FormatError::Layer {
                format: "raw",
                source,
            })?,
        )?,
        // A hibernation file is a memory image the machine took of itself. Its
        // pages are Xpress-compressed; the reader walks the restore sets,
        // decompresses them, and returns the physical address space. A file that
        // is a hibernation image but uses a construct this reader does not
        // implement (an older layout, or the Xpress-Huffman codec throughout)
        // fails with a reason naming what is missing rather than a blanket
        // refusal — so "found a memory image, could not read this part of it"
        // still reaches the examiner.
        //
        // The default reader targets the validated Windows 10/11 x64 layout. An
        // older layout (Windows 7 / NT6.1 x64) can be selected explicitly with
        // `SEANCE_HIBER_LEGACY=nt61-x64` — a structure-only path whose output no
        // corpus has validated, so it is never the default and every page it
        // produces is stamped `unvalidated` (that stamp travels onto the record).
        MemoryImageFormat::WindowsHibernation => {
            let layer = match std::env::var("SEANCE_HIBER_LEGACY").ok().as_deref() {
                Some("nt61-x64") => formats::hibernation::open_legacy_nt61_x64_unvalidated(src)?,
                _ => formats::hibernation::open(src)?,
            };
            finish(format, layer)?
        }
        MemoryImageFormat::WindowsCrashDump32 | MemoryImageFormat::WindowsCrashDump64 => {
            finish(format, formats::crash::open(src)?)?
        }
        MemoryImageFormat::Lime => finish(format, formats::lime::open(src)?)?,
        MemoryImageFormat::Avml => finish(format, formats::avml::open(src)?)?,
        MemoryImageFormat::ElfCore => finish(format, formats::elf::open(src)?)?,
        MemoryImageFormat::QemuSaveVm => finish(format, formats::qemu::open(src)?)?,
        // A `.vmss`/`.vmsn` carries the metadata; the memory lives in the paired
        // `.vmem`. The reader reaches it through the sibling mechanism and
        // degrades honestly (flat read, incomplete flag) when it cannot.
        MemoryImageFormat::VmwareSnapshot => finish(format, formats::vmware::open(src)?)?,
    })
}

/// Which parts of a decoded address space are really backed by acquired bytes,
/// ascending and merged where they touch.
///
/// # What an examiner learns
///
/// Whether "the tool read nothing there" means the suspect's machine held
/// nothing there, or means the acquisition never covered that address. The
/// answer only exists at this moment: one line later the layer is an
/// `Arc<dyn DataSource>`, its segment list is gone, and
/// [`crate::physical::PhysicalLayer`] rebuilt over it answers "every address is
/// backed" unless it is handed this geometry.
///
/// # What a wrong answer would look like
///
/// Silence. Asking a segmented layer to map its whole space does **not** return
/// the mapped parts: [`MemoryLayer::mapping`] refuses at the *first* hole, so
/// the one call that used to be made here returned `Err` for precisely the
/// sparse images the geometry exists for — a LiME capture that starts at
/// `0x1000`, any crash dump that skips the first page, anything with an MMIO
/// window in the middle. Discarding that error left every such image declared
/// flat, and unacquired ranges then counted as captured in every coverage
/// figure downstream. So the walk steps hole by hole, and an error it cannot
/// account for is returned rather than flattened into "all backed".
///
/// A layer that reports short runs instead of refusing (a
/// [`crate::physical::PhysicalLayer`] that already knows its geometry) is
/// handled by the same walk: what it does not report is not backed.
fn backed_ranges(layer: &dyn MemoryLayer) -> Result<Vec<(u64, u64)>, LayerError> {
    let size = layer.size();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut pos = layer.min_address();
    while pos < size {
        match layer.mapping(pos, size - pos) {
            Ok(runs) => {
                extend_ranges(&mut ranges, &runs);
                break;
            }
            Err(LayerError::Hole(hole)) => {
                if hole.address > pos {
                    let mapped = layer.mapping(pos, hole.address - pos)?;
                    extend_ranges(&mut ranges, &mapped);
                }
                // A hole that does not advance past `pos` would loop forever.
                // It is a fault in the layer beneath, not a geometry, and is
                // reported rather than skipped.
                let next = hole.address.saturating_add(hole.length);
                if next <= pos {
                    return Err(LayerError::Hole(hole));
                }
                pos = next;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(ranges)
}

/// Append `runs` to `ranges`, merging a run that begins exactly where the last
/// range ends.
///
/// Merging is about *backedness*, which does not care how the bytes are laid
/// out in the file: a QEMU snapshot maps every guest page as its own run, and
/// without this a 4 GiB guest would carry a million-entry geometry into the
/// artifact's metadata to say "all of it is backed".
fn extend_ranges(ranges: &mut Vec<(u64, u64)>, runs: &[MappedRange]) {
    for run in runs {
        if run.length == 0 {
            continue;
        }
        match ranges.last_mut() {
            Some((start, len)) if start.saturating_add(*len) == run.offset => {
                *len = len.saturating_add(run.length);
            }
            _ => ranges.push((run.offset, run.length)),
        }
    }
}

/// The record an examiner sees first: what the image is, how much of it is
/// really addressable, and anything that makes it less than whole.
fn image_record(
    parent: &Artifact,
    format: MemoryImageFormat,
    named: Option<MemoryImageFormat>,
    meta: &LayerMeta,
    layer: &Arc<dyn DataSource>,
    raw: &Arc<dyn DataSource>,
    backed: Option<Vec<(u64, u64)>>,
) -> Artifact {
    let addressable = layer.size();
    let on_disk = raw.size();

    let mut m = json!({
        "type": "MemoryImage",
        "subtype": "memory_image",
        "image_format": format.as_str(),
        "addressable_bytes": addressable,
        "file_bytes": on_disk,
        "name": format!("Memory image ({})", format.as_str()),
    });

    let obj = m.as_object_mut().expect("object literal");

    declare_format_agreement(obj, format, named);

    // A hibernation file that decoded is still a hibernation file: the state and
    // the moment the machine was suspended are timeline facts available from no
    // other artifact, so they ride on the successful image record too, not only
    // on the failure record they used to be confined to.
    if format == MemoryImageFormat::WindowsHibernation {
        obj.insert("hibernation".into(), hibernation_facts(raw));
    }

    // The bugcheck is a fact about the crash, not about whether the file
    // decoded, so it rides the successful record too. Were it attached only
    // where decoding failed, a stop code on screen would read as a symptom of
    // an unreadable file.
    if is_crash_dump(format) {
        obj.insert("crash_dump".into(), crash_dump_facts(raw));
    }

    // Name the operating system when it is one no tier here analyses. Without
    // this the case shows a Windows discovery failure and silence from
    // everything else, which reads as "not a Windows image" -- an invitation to
    // try again -- rather than "this is a Mac, and no setting will help".
    let recognised = PhysicalLayer::raw(Arc::clone(layer))
        .ok()
        .and_then(|view| crate::recognise::unsupported_os(&view));
    if let Some(found) = recognised {
        warn!(
            "memory image is a {} capture, which this build does not analyse",
            found.os
        );
        if let Some(fields) = found.to_json().as_object() {
            for (key, value) in fields {
                obj.insert(key.clone(), value.clone());
            }
        }
    }

    // Only state what is known. A declared size that disagrees with what is
    // actually addressable is exactly the kind of thing an examiner must see,
    // so both are recorded rather than reconciled.
    if let Some(declared) = meta.declared_size() {
        obj.insert("declared_size".into(), json!(declared));
        if declared != addressable {
            obj.insert("size_mismatch".into(), json!(true));
        }
    }
    if let Some(arch) = meta.architecture() {
        obj.insert("architecture".into(), json!(arch.as_str()));
    }

    // The layer's own account of itself, serialised so it survives the artifact
    // boundary. Without this the analysis side reopens the carried `DataSource`
    // and gets a blank `LayerMeta`, losing the format, the incompleteness the
    // acquisition itself reported, and every note — including the directory
    // table base and `KdDebuggerDataBlock` that a Windows crash dump publishes
    // in its header and that discovery reads. Losing those does not fail
    // loudly; it quietly demotes a dump that states its DTB to one that has to
    // be scanned for it.
    obj.insert("layer_meta".into(), meta.to_json());

    // The geometry, so the analysis side can tell a sparse acquisition from a
    // flat one. Without it a decoded LiME or crash dump — which reaches
    // analysis as an opaque `DataSource` already translated into memory space —
    // is wrapped in a layer that answers "all of it is backed", and every
    // coverage figure downstream is then computed over ranges that were never
    // acquired.
    if let Some(runs) = backed {
        obj.insert(
            "backed_ranges".into(),
            json!(runs
                .iter()
                .map(|(start, length)| json!({"start": start, "length": length}))
                .collect::<Vec<_>>()),
        );
    }

    // Incompleteness travels up the whole layer chain: a truncated segment deep
    // in a format reader must still reach the record.
    let incomplete = meta.incomplete_chain();
    if !incomplete.is_empty() {
        obj.insert(
            "incomplete".into(),
            json!(incomplete.iter().map(|i| i.to_json()).collect::<Vec<_>>()),
        );
        obj.insert("content_complete".into(), json!(false));
    } else {
        obj.insert("content_complete".into(), json!(true));
    }

    // Phase 1 is honest about its own limits: this record exists so nobody
    // mistakes "the image is loaded" for "the image has been analysed".
    obj.insert("analysis_stage".into(), json!("physical_only"));
    obj.insert(
        "analysis_note".into(),
        json!(
            "Physical address space decoded. Content is searchable, carvable and \
             hashable. Process, module and network analysis require address \
             translation and symbols, which are not part of this stage."
        ),
    );

    Artifact::new(
        parent.case_id,
        ArtifactType::ParsedRecord,
        Some(Arc::clone(layer)),
        m,
    )
    .with_parent(parent.id)
}

/// Record what the case declared this file to be, and whether the evidence
/// agreed.
///
/// # What an examiner learns
///
/// That there was a disagreement at all. The header wins — it is evidence and
/// the declaration is a human assertion — but "this was booked in as a LiME
/// capture and its header says QEMU" is usually the wrong file, and it is not a
/// fact that can be recovered later: the declaration lives on the parent
/// artifact and the record shows only the winner.
///
/// # Why the agreeing case is stamped too
///
/// So that `format_declaration_mismatch: false` and "nobody declared anything"
/// are different states in the JSON rather than the same absence. A declaration
/// that was made and upheld is corroboration; no key at all means no-one said.
/// A file nobody declared gets neither key, because there is nothing to report.
fn declare_format_agreement(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    format: MemoryImageFormat,
    named: Option<MemoryImageFormat>,
) {
    let Some(named) = named else {
        return;
    };
    obj.insert("declared_image_format".into(), json!(named.as_str()));
    obj.insert("format_declaration_mismatch".into(), json!(named != format));
}

/// Emitted when something that announced itself as a memory image would not
/// decode. Failing loudly beats returning nothing for a file the examiner
/// explicitly declared.
///
/// # `decode_failed` is the key everything downstream reads
///
/// Not `subtype`, and not the absent `data`. Three consumers key off it and all
/// three were being told the opposite of the truth while it was missing:
///
/// - [`crate::analysis::MemoryAnalysisModule`] skips a record that failed to
///   decode. Without the key it read this record as a decoded image, found no
///   address space behind it, and returned an error — so every analysis stage
///   in the case reported a fault instead of "there is nothing here to analyse".
/// - `GET /api/v1/cases/:id/memory/images` reads
///   `decode_failed`, defaulting to `false`, and the image page renders a
///   `decode failed` badge from it. A hibernation file — the one format that
///   *always* reaches this record, because its pages are Xpress-compressed —
///   was therefore listed as an image with no failure shown, next to an
///   `addressable_bytes` it never had.
/// - Any report built from that list would say the same.
///
/// The record's whole purpose is to assert "a capture was found and could not be
/// read". Omitting the field an examiner's screen is driven by turned that into
/// "a capture was found", which is the claim it exists to prevent.
fn failure_record(
    parent: &Artifact,
    format: MemoryImageFormat,
    named: Option<MemoryImageFormat>,
    err: &FormatError,
    source: &Arc<dyn DataSource>,
) -> Artifact {
    let mut m = json!({
        "type": "MemoryImage",
        "subtype": "memory_image_error",
        "image_format": format.as_str(),
        "decode_failed": true,
        "content_complete": false,
        "error": err.to_string(),
        "name": format!("Memory image (unreadable {})", format.as_str()),
    });
    let obj = m.as_object_mut().expect("object literal");
    // A file that was declared as one format, detected as another and then
    // failed to parse is the case this matters most in: the decode failure is
    // the expected consequence of the wrong file having been declared, and the
    // record has to carry both halves for anyone to see that.
    declare_format_agreement(obj, format, named);
    if format == MemoryImageFormat::WindowsHibernation {
        obj.insert("hibernation".into(), hibernation_facts(source));
    }
    if is_crash_dump(format) {
        obj.insert("crash_dump".into(), crash_dump_facts(source));
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent.id)
}

/// Whether this format is one of the two `_DUMP_HEADER` layouts.
fn is_crash_dump(format: MemoryImageFormat) -> bool {
    matches!(
        format,
        MemoryImageFormat::WindowsCrashDump32 | MemoryImageFormat::WindowsCrashDump64
    )
}

/// What the crash-dump header states, for the record — including the record
/// that says the file could not be mapped.
///
/// # What an examiner learns
///
/// A triage/small dump (`DumpType 0x3`, or a `0x2`/`0x4` with no
/// `_SUMMARY_DUMP`) is refused, correctly: it holds bugcheck structures rather
/// than a physical address space, so there is no memory in it to search. But
/// its header is a full `_DUMP_HEADER` all the same, and it states **which
/// bugcheck stopped the machine, at what moment, on which build, with how many
/// processors** — facts that were being parsed only on the path that succeeds
/// and thrown away on the path that refuses. The examiner was told "decode
/// failed" about a file that plainly says why the machine stopped.
///
/// # What a wrong answer would look like
///
/// A missing key, which reads as "this dump states no bugcheck" rather than
/// "these bytes are not a dump header". So both outcomes are stated, exactly as
/// [`hibernation_facts`] does, and the facts carry
/// `maps_an_address_space` so that a stop code on the record can never be
/// mistaken for a decoded image.
fn crash_dump_facts(source: &Arc<dyn DataSource>) -> serde_json::Value {
    match formats::crash::header_facts(source.as_ref()) {
        Some(facts) => {
            let mut value = facts.to_json();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("header_recognised".into(), json!(true));
            }
            value
        }
        None => json!({
            "header_recognised": false,
            "detail": "the first bytes are not a readable _DUMP_HEADER: no PAGEDUMP or PAGEDU64 \
                       signature, or too little of the header present to read it. Nothing about \
                       the crash can be stated from this file.",
        }),
    }
}

/// What the hibernation header states, for the record that says its pages could
/// not be decompressed.
///
/// # What an examiner learns
///
/// The facts the header holds even though the image behind it cannot be
/// reconstructed: whether the file still holds a capture (`hibr`/`wake`/`RSTR`
/// all do — Windows marks the file on resume rather than clearing it), the page
/// size, the number of pages stored, and **the moment the machine was
/// suspended**. That timestamp is a timeline fact available from no other
/// artifact, and it was being parsed and thrown away: the failure record named
/// Xpress and said nothing about the file's state or its time.
///
/// # What a wrong answer would look like
///
/// A missing key, which would read as "the file has no state" rather than "the
/// header could not be recognised". So both outcomes are stated, and
/// [`formats::hibernation::identify_named`] is the right entry point here
/// precisely because the file is already either detected by signature or
/// declared by the examiner — the only circumstance in which an all-zero header
/// may honestly be reported as an inactive hibernation file.
fn hibernation_facts(source: &Arc<dyn DataSource>) -> serde_json::Value {
    let mut head = vec![0u8; formats::hibernation::HEADER_BYTES];
    let read = seance_core::io::read_full(source.as_ref(), 0, &mut head);
    match formats::hibernation::identify_named(&head[..read]) {
        Some(header) => {
            let mut facts = header.to_json();
            if let Some(obj) = facts.as_object_mut() {
                obj.insert("header_recognised".into(), json!(true));
            }
            facts
        }
        None => json!({
            "header_recognised": false,
            "bytes_read": read,
            "detail": "the first bytes are not a hibernation header: no hibr, wake or RSTR \
                       signature, and not the all-zero header of a file that has never been \
                       hibernated to. The declaration is not borne out by the file.",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use uuid::Uuid;

    fn artifact_with(name: &str, bytes: Vec<u8>, extra: serde_json::Value) -> Artifact {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let mut md = json!({ "name": name });
        if let (Some(o), Some(e)) = (md.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        Artifact::new(Uuid::new_v4(), ArtifactType::RawEvidence, Some(ds), md)
    }

    /// The central safety property: an ordinary file is NOT claimed. A raw dump
    /// has no magic, so if this module guessed, every unrecognised artifact in
    /// every case would be reported as a memory image.
    #[test]
    fn an_undeclared_headerless_file_is_not_claimed() {
        let art = artifact_with(
            "notes.bin",
            std::iter::repeat_n([0x7e, 0xaf, 0x00, 0xf0], 4)
                .flatten()
                .collect::<Vec<u8>>(),
            json!({}),
        );
        assert!(
            MemoryImageModule.process(&art).unwrap().is_empty(),
            "a headerless file must never be guessed to be memory"
        );
    }

    /// The other half of refusing to guess: an examiner who supplied a capture
    /// and got total silence has to be able to find out why.
    ///
    /// Before this, an undeclared `.mem` produced no record, no warning and no
    /// processing-log row — the same output as a case with no capture in it at
    /// all — and the usual conclusion was that the tool cannot read memory.
    #[test]
    fn an_undeclared_headerless_capture_names_the_keys_that_would_have_declared_it() {
        let hint = undeclared_memory_hint("physmem.mem").expect("a memory-shaped name");
        assert!(hint.contains("physmem.mem"));
        assert!(hint.contains(DECLARE_FLAG));
        assert!(hint.contains(DECLARE_FORMAT));
        // Naming the keys is no use without the vocabulary they accept.
        assert!(hint.contains("avml"));
        // Case is not part of the assertion an extension makes.
        assert!(undeclared_memory_hint("GUEST.VMEM").is_some());

        // And it stays rare. A disk image's extension is not memory-shaped,
        // whatever the file turns out to hold, and an ordinary file is not
        // either: a hint that fires on everything is one nobody reads.
        assert!(undeclared_memory_hint("disk0.raw").is_none());
        assert!(undeclared_memory_hint("evidence.dd").is_none());
        assert!(undeclared_memory_hint("setupapi.dev.log").is_none());

        // The hint changes nothing about what is claimed: still no record.
        let art = artifact_with("physmem.mem", vec![0u8; 8192], json!({}));
        assert!(
            MemoryImageModule.process(&art).unwrap().is_empty(),
            "a name must never promote a file to being memory"
        );
    }

    #[test]
    fn a_declared_raw_image_is_accepted() {
        // Same bytes as above, but the case says it is memory.
        let art = artifact_with(
            "physmem.raw",
            vec![0u8; 8192],
            json!({ DECLARE_FLAG: true }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["type"], "MemoryImage");
        assert_eq!(out[0].metadata["image_format"], "raw");
        assert_eq!(out[0].metadata["analysis_stage"], "physical_only");
        assert!(
            out[0].data.is_some(),
            "the decoded view must be attached so the carver and hasher can read it"
        );
    }

    #[test]
    fn a_declared_format_name_that_is_unknown_is_refused_rather_than_dropped() {
        let art = artifact_with(
            "thing.bin",
            vec![0u8; 4096],
            json!({ DECLARE_FORMAT: "not-a-format" }),
        );
        let err = MemoryImageModule
            .process(&art)
            .expect_err("a declaration this build cannot honour must not read as no declaration");
        let rendered = err.to_string();
        assert!(
            rendered.contains("not-a-format"),
            "the refusal must quote the word that was not understood: {rendered}"
        );
        assert!(
            rendered.contains("hibernation"),
            "and name the set it could have been drawn from: {rendered}"
        );
        // And it must certainly not have become "raw, trust me": the same file
        // with the flag instead of the typo is the accepted case, so the two
        // cannot be allowed to converge.
        let flagged = artifact_with("thing.bin", vec![0u8; 4096], json!({ DECLARE_FLAG: true }));
        assert_eq!(
            MemoryImageModule.process(&flagged).unwrap()[0].metadata["image_format"],
            "raw"
        );
    }

    /// The LIVE-002 regression. An examiner picks "hibernation" in the ingest
    /// form; the ingest writes `memory_image_format: "hibernation"`.
    ///
    /// Before the fix `parse_format_name` had no hibernation name at all, so
    /// this yielded `None`, met `(Raw, None)` and returned `Ok(vec![])`: no
    /// record, no error, and every memory stage reporting `did_not_run`. Now
    /// the declaration is honoured. This case uses an **all-zero** file — an
    /// *inactive* hibernation file, allocated but never written — so there is no
    /// image to reconstruct, and the record must say that (state `inactive`,
    /// holds no image) rather than fall silent. (A `HIBR` file whose pages *can*
    /// be decompressed is exercised by the real-image integration test.)
    #[test]
    fn a_declared_hibernation_file_produces_a_record_that_names_the_limitation() {
        for name in ["hibernation", "hiberfil.sys", "windows_hibernation"] {
            let art = artifact_with(
                "hiberfil.sys",
                vec![0u8; 8192],
                json!({ DECLARE_FORMAT: name }),
            );
            let out = MemoryImageModule
                .process(&art)
                .unwrap_or_else(|e| panic!("declaring {name:?} must be honoured: {e}"));
            assert_eq!(out.len(), 1, "declaring {name:?} produced no record");
            let md = &out[0].metadata;
            assert_eq!(md["subtype"], "memory_image_error");
            assert_eq!(md["image_format"], "windows_hibernation");
            assert_eq!(md["declared_image_format"], "windows_hibernation");
            let reason = md["error"].as_str().expect("a stated reason");
            assert!(
                reason.to_ascii_lowercase().contains("hibernation image"),
                "the record must name why nothing could be read: {reason}"
            );
            // An all-zero header on a file the examiner declared: "allocated
            // but holds no image", which is a finding, not an absence.
            assert_eq!(md["hibernation"]["header_recognised"], true);
            assert_eq!(md["hibernation"]["state"], "inactive");
            assert_eq!(md["hibernation"]["may_hold_an_image"], false);
        }
    }

    /// A real `hiberfil.sys` carries its own signature, so the same record is
    /// produced with no declaration at all — the declaration path and the
    /// detection path must not disagree about what the file is.
    ///
    /// It also carries the facts the header states, which were being parsed and
    /// discarded: `HibernationHeader::to_json` had no caller, so the record said
    /// nothing about the state of the file or **when the machine was
    /// suspended** — a timeline fact available from no other artifact in the
    /// case. (This fixture is a header with no restore sets behind it, so it
    /// takes the failure route. A real hibernation file decodes; see
    /// `formats::hibernation`.)
    #[test]
    fn a_detected_hibernation_file_carries_the_facts_its_header_states() {
        let mut bytes = vec![0u8; 8192];
        bytes[..4].copy_from_slice(b"hibr");
        bytes[0x18..0x1C].copy_from_slice(&4096u32.to_le_bytes());
        // 2024-06-01 12:00:00 UTC in FILETIME.
        bytes[0x20..0x28].copy_from_slice(&133_614_720_000_000_000u64.to_le_bytes());
        bytes[0x58..0x5C].copy_from_slice(&262_144u32.to_le_bytes());

        let art = artifact_with("hiberfil.sys", bytes, json!({}));
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        let md = &out[0].metadata;
        assert_eq!(md["image_format"], "windows_hibernation");
        assert_eq!(md["subtype"], "memory_image_error");

        let hib = &md["hibernation"];
        assert_eq!(hib["header_recognised"], true);
        assert_eq!(hib["state"], "hibernated");
        assert_eq!(
            hib["may_hold_an_image"], true,
            "the file still holds a capture, which is the point of reporting it"
        );
        assert_eq!(hib["page_size"], 4096);
        assert_eq!(hib["pages_stored"], 262_144);
        assert_eq!(
            hib["system_time_filetime"], 133_614_720_000_000_000u64,
            "the moment the machine was suspended must reach the record"
        );
    }

    /// Every failure record must state `decode_failed`, because that is the key
    /// the rest of the product is driven by — not `subtype`, and not the absent
    /// `data`.
    ///
    /// Unfixed, the key was simply missing. `MemoryAnalysisModule` then took the
    /// decoded-image path (`decoded_successfully` is
    /// `metadata["decode_failed"] != Some(true)`, and an absent key is not
    /// `Some(true)`), found no address space, and returned an error from every
    /// analysis stage in the case. `GET .../memory/images` reads the same key
    /// with `unwrap_or(false)`, so the image page showed no failure badge for a
    /// capture that could not be read at all. (When this was written a
    /// hibernation file reached this record every time, because decompression
    /// was unimplemented; it now decodes, and the fixtures that take this route
    /// are headers with nothing behind them.)
    #[test]
    fn a_failure_record_states_that_the_decode_failed() {
        // Two routes to the same record: the examiner's declaration, and a
        // header that identified itself. Neither may omit the key.
        let declared = artifact_with(
            "hiberfil.sys",
            vec![0u8; 8192],
            json!({ DECLARE_FORMAT: "hibernation" }),
        );
        let mut detected_bytes = vec![0u8; 8192];
        detected_bytes[..4].copy_from_slice(b"hibr");
        let detected = artifact_with("hiberfil.sys", detected_bytes, json!({}));

        for art in [declared, detected] {
            let out = MemoryImageModule.process(&art).unwrap();
            let md = &out[0].metadata;
            assert_eq!(md["subtype"], "memory_image_error");
            assert_eq!(
                md["decode_failed"], true,
                "an image listing built from this record would show a capture that was \
                 never readable as one that decoded: {md}"
            );
            assert!(
                out[0].data.is_none(),
                "there is no address space behind a failure record, which is exactly why \
                 decode_failed has to be stated rather than inferred"
            );
        }
    }

    /// A file declared as a hibernation image whose header is not one: the
    /// record must say the declaration is not borne out, rather than omitting
    /// the key and reading as "this file has no state".
    #[test]
    fn a_declared_hibernation_file_with_no_header_says_so() {
        let art = artifact_with(
            "not_really.sys",
            vec![0x5Au8; 8192],
            json!({ DECLARE_FORMAT: "hiberfil.sys" }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        let hib = &out[0].metadata["hibernation"];
        assert_eq!(hib["header_recognised"], false);
        assert!(hib["detail"]
            .as_str()
            .expect("a stated reason")
            .contains("not borne out"));
    }

    /// The refusal has to survive the orchestrator, and the variant decides
    /// whether it does.
    ///
    /// `ModuleError::InvalidInputFormat` is the orchestrator's *skip* signal:
    /// both arms that match it (`seance_core/src/orchestrator.rs`, automatic and
    /// ad-hoc) log at `debug!`, broadcast `ModuleCompleted` with zero artifacts,
    /// and write a processing-log row with `status: "skipped"` and
    /// `error_message: None`. The sentence naming the word that was not
    /// understood is thrown away there, so an examiner reading the case
    /// dashboard sees nothing at all — the same silence this refusal exists to
    /// end. Only the other variants reach `ModuleError` on the status bus and a
    /// row with `error_message: Some(..)`.
    #[test]
    fn a_refused_declaration_does_not_use_the_variant_the_orchestrator_swallows() {
        for metadata in [
            json!({ DECLARE_FORMAT: "not-a-format" }),
            json!({ DECLARE_FORMAT: 7 }),
            json!({ DECLARE_FLAG: "true" }),
        ] {
            let art = artifact_with("thing.bin", vec![0u8; 4096], metadata.clone());
            let err = MemoryImageModule
                .process(&art)
                .expect_err("the declaration cannot be honoured");
            assert!(
                !matches!(err, ModuleError::InvalidInputFormat(_)),
                "{metadata} was refused as InvalidInputFormat, which the orchestrator \
                 records as status=\"skipped\" with error_message=None: the refusal never \
                 reaches the examiner"
            );
            assert!(
                !err.to_string().is_empty(),
                "the row on the dashboard is the message; it cannot be blank"
            );
        }
    }

    /// The same class one key over: a declaration written in a shape this build
    /// cannot read must be refused, not treated as no declaration.
    #[test]
    fn a_declaration_in_the_wrong_shape_is_refused() {
        // `memory_image: "true"` — a string, as a JSON-typing slip easily
        // produces. `as_bool()` returned `None`, `unwrap_or(false)` made it a
        // non-declaration, and the capture was never analysed.
        let art = artifact_with(
            "physmem.raw",
            vec![0u8; 4096],
            json!({ DECLARE_FLAG: "true" }),
        );
        let err = MemoryImageModule
            .process(&art)
            .expect_err("a non-boolean declaration flag must be refused");
        assert!(err.to_string().contains(DECLARE_FLAG), "{err}");

        // And a format name that is not a string at all.
        let art = artifact_with("physmem.raw", vec![0u8; 4096], json!({ DECLARE_FORMAT: 7 }));
        let err = MemoryImageModule
            .process(&art)
            .expect_err("a non-string format declaration must be refused");
        assert!(err.to_string().contains(DECLARE_FORMAT), "{err}");

        // `memory_image: false` is a declaration that this is NOT memory, and
        // is honoured as such: no record, no error.
        let art = artifact_with("notes.bin", vec![0u8; 4096], json!({ DECLARE_FLAG: false }));
        assert!(MemoryImageModule.process(&art).unwrap().is_empty());
    }

    #[test]
    fn a_declaration_the_header_contradicts_reaches_the_record() {
        // The defect this guards: the disagreement was written to a `warn!`
        // line that said it was "recording the disagreement", and nothing put
        // it on the artifact. The header wins — it is evidence and the
        // declaration is an assertion — but a report that shows only the winner
        // has dropped the fact that the file was booked in as something else,
        // which is usually how a mislabelled exhibit is caught.
        let art = artifact_with(
            "booked_in_as.avml",
            lime_with_gaps(),
            json!({ DECLARE_FORMAT: "avml" }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out[0].metadata["image_format"], "lime", "the header wins");
        assert_eq!(out[0].metadata["declared_image_format"], "avml");
        assert_eq!(out[0].metadata["format_declaration_mismatch"], true);

        // A declaration the evidence upholds is stamped too, as false: "the
        // case said LiME and the header agrees" is corroboration, and it must
        // not render like a file nobody declared.
        let art = artifact_with(
            "linux.lime",
            lime_with_gaps(),
            json!({ DECLARE_FORMAT: "lime" }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out[0].metadata["declared_image_format"], "lime");
        assert_eq!(out[0].metadata["format_declaration_mismatch"], false);

        // And a file nobody named carries neither key: there is no declaration
        // to report on.
        let art = artifact_with("linux.lime", lime_with_gaps(), json!({}));
        let out = MemoryImageModule.process(&art).unwrap();
        let md = &out[0].metadata;
        assert!(md.get("declared_image_format").is_none());
        assert!(md.get("format_declaration_mismatch").is_none());

        // The `memory_image: true` flag is not a format claim — it says the
        // file is memory, which no header contradicts — so flagging a LiME
        // capture must not manufacture a mismatch against "raw".
        let art = artifact_with(
            "linux.lime",
            lime_with_gaps(),
            json!({ DECLARE_FLAG: true }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        let md = &out[0].metadata;
        assert_eq!(md["image_format"], "lime");
        assert!(md.get("format_declaration_mismatch").is_none());
    }

    #[test]
    fn a_contradicted_declaration_survives_onto_the_failure_record() {
        // The case that matters most: the file was declared as one format, its
        // header says another, and the decode then fails. The failure is the
        // expected consequence of the wrong exhibit having been declared, and
        // only the record carrying both halves lets anyone see that.
        // A LiME file whose second header re-declares the first segment's
        // addresses: the magic is unmistakable, and the reader refuses it
        // because two payloads cannot hold one physical address.
        let mut bytes = Vec::new();
        for _ in 0..2 {
            bytes.extend_from_slice(&0x4C69_4D45u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&0x1000u64.to_le_bytes());
            bytes.extend_from_slice(&0x1FFFu64.to_le_bytes());
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&vec![0xABu8; 0x1000]);
        }
        let art = artifact_with(
            "booked_in_as.avml",
            bytes,
            json!({ DECLARE_FORMAT: "avml" }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["subtype"], "memory_image_error");
        assert_eq!(out[0].metadata["image_format"], "lime");
        assert_eq!(out[0].metadata["declared_image_format"], "avml");
        assert_eq!(out[0].metadata["format_declaration_mismatch"], true);
    }

    #[test]
    fn declared_format_names_map_to_the_enum() {
        assert_eq!(
            parse_format_name("PAGEDU64"),
            Some(MemoryImageFormat::WindowsCrashDump64)
        );
        assert_eq!(parse_format_name(" LiME "), Some(MemoryImageFormat::Lime));
        assert_eq!(parse_format_name("avml"), Some(MemoryImageFormat::Avml));
        assert_eq!(parse_format_name("wat"), None);
    }

    #[test]
    fn the_attached_view_reads_the_image_bytes() {
        let mut bytes = vec![0u8; 4096];
        bytes[0x100..0x108].copy_from_slice(b"FINDTHIS");
        let art = artifact_with("mem.raw", bytes, json!({ DECLARE_FLAG: true }));

        let out = MemoryImageModule.process(&art).unwrap();
        let view = out[0].data.as_ref().expect("decoded view attached");

        let mut buf = [0u8; 8];
        view.read_at(0x100, &mut buf).unwrap();
        assert_eq!(&buf, b"FINDTHIS", "the carver/search must see real content");
    }

    #[test]
    fn an_artifact_with_no_data_source_is_skipped() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            None,
            json!({ "name": "x", DECLARE_FLAG: true }),
        );
        assert!(MemoryImageModule.process(&art).unwrap().is_empty());
    }

    /// A LiME acquisition with a leading gap and an interior gap: physical
    /// memory really does start above zero and really is interrupted by MMIO
    /// windows, so this is the ordinary shape of a Linux capture, not a corner
    /// case.
    fn lime_with_gaps() -> Vec<u8> {
        let mut bytes = Vec::new();
        for (start, end) in [(0x1000u64, 0x1FFFu64), (0x3000, 0x3FFF)] {
            bytes.extend_from_slice(&0x4C69_4D45u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&start.to_le_bytes());
            bytes.extend_from_slice(&end.to_le_bytes());
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&vec![0xABu8; (end - start + 1) as usize]);
        }
        bytes
    }

    #[test]
    fn a_sparse_image_carries_its_geometry_into_the_record() {
        // The defect this guards: the geometry was read with a single
        // `mapping(0, size)`, which a segmented layer REFUSES at the first
        // hole. Every image whose first page is unmapped — this one, any crash
        // dump that skips page zero — therefore took the `Err(_) => None` arm,
        // and `None` means "flat, all of it backed". The analysis side then
        // rebuilt a layer that answered "backed" for addresses the acquisition
        // never contained, which is the one claim a coverage figure must never
        // make.
        let art = artifact_with("linux.lime", lime_with_gaps(), json!({}));
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["image_format"], "lime");

        let ranges = out[0].metadata["backed_ranges"]
            .as_array()
            .expect("a sparse image must state which ranges it actually holds");
        let got: Vec<(u64, u64)> = ranges
            .iter()
            .map(|r| (r["start"].as_u64().unwrap(), r["length"].as_u64().unwrap()))
            .collect();
        assert_eq!(got, vec![(0x1000, 0x1000), (0x3000, 0x1000)]);

        // And the geometry round-trips through the real analysis-side rebuild
        // into a layer that keeps the gaps.
        let decoded = out[0].data.as_ref().expect("the decoded view is attached");
        let layer = crate::analysis::physical_layer_for(decoded, &out[0])
            .expect("the recorded geometry rebuilds");
        assert!(layer.is_valid(0x1000, 0x1000));
        assert!(
            !layer.is_valid(0, 0x1000),
            "the leading gap was never acquired"
        );
        assert!(!layer.is_valid(0x2000, 0x1000), "nor the MMIO window");
    }

    #[test]
    fn a_flat_image_claims_no_geometry_at_all() {
        // The other direction: `None` must stay reserved for an image that
        // really is one unbroken run, or every flat dump would acquire a
        // pointless — and eventually wrong — coverage claim.
        let art = artifact_with(
            "physmem.raw",
            vec![7u8; 8192],
            json!({ DECLARE_FLAG: true }),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        assert!(
            out[0].metadata.get("backed_ranges").is_none(),
            "a flat image needs no geometry: the identity mapping is correct for it"
        );
    }

    #[test]
    fn a_layer_that_reports_short_runs_is_walked_the_same_way() {
        // `PhysicalLayer` answers a gap with a short run list rather than an
        // error, so both conventions have to produce the same geometry.
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 0x4000]));
        let layer = PhysicalLayer::raw(inner)
            .unwrap()
            .with_backed(vec![(0x1000, 0x1000), (0x2000, 0x1000)]);
        assert_eq!(
            backed_ranges(&layer).unwrap(),
            // Touching ranges merge: adjacency in memory is all backedness means.
            vec![(0x1000, 0x2000)]
        );
    }

    /// VOL-MEM-007. A triage/small dump is refused as an address space — there
    /// is no memory in it to map — and until now that refusal was the entire
    /// record: `decode_failed`, an error string, and silence about a file whose
    /// header states which bugcheck stopped the machine, when, on what build
    /// and with how many processors. Those bytes were parsed for every dump
    /// that mapped and for none that did not.
    ///
    /// The precedent is one branch away: a hibernation file that cannot be
    /// decompressed still publishes its state and the moment of suspend.
    #[test]
    fn a_refused_triage_dump_still_reports_its_bugcheck_on_the_failure_record() {
        let bytes = formats::crash::tests::triage_dump_64(0x3);
        let art = artifact_with("MEMORY.DMP", bytes, json!({}));
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        let md = &out[0].metadata;

        assert_eq!(md["subtype"], "memory_image_error");
        assert_eq!(
            md["decode_failed"], true,
            "the refusal itself must not weaken: the dump is still not an address space"
        );

        let crash = &md["crash_dump"];
        assert_eq!(crash["header_recognised"], true);
        assert_eq!(crash["maps_an_address_space"], false);
        assert_eq!(crash["bug_check_code"], 0xD1);
        assert_eq!(crash["bug_check_parameters"][0], 0x1000);
        assert_eq!(crash["minor_version"], 19041);
        assert_eq!(crash["number_processors"], 8);
        assert_eq!(crash["system_time_filetime"], 0x01D9_0000_0000_0000u64);
        assert!(
            crash["triage_detail"].is_string(),
            "the record must say why no memory was mapped: {crash}"
        );
    }

    /// The same block, on the record of a dump that did decode. A panel that
    /// appears only when decoding failed would teach an examiner that a
    /// bugcheck code is a symptom of a broken file rather than a fact about the
    /// crash — and the hibernation facts already ride both records for exactly
    /// that reason.
    #[test]
    fn a_decoded_crash_dump_carries_the_same_crash_dump_block() {
        let art = artifact_with(
            "MEMORY.DMP",
            formats::crash::tests::full_dump_64(),
            json!({}),
        );
        let out = MemoryImageModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        let md = &out[0].metadata;

        assert_eq!(md["subtype"], "memory_image");
        assert_eq!(md["image_format"], "windows_crashdump_64");

        let crash = &md["crash_dump"];
        assert_eq!(crash["header_recognised"], true);
        assert_eq!(crash["maps_an_address_space"], true);
        assert_eq!(crash["dump_kind"], "full");
        assert_eq!(crash["bug_check_code"], 0xD1);
        assert!(
            crash["triage_detail"].is_null(),
            "a decoded image is not a triage dump: {crash}"
        );
    }

    /// A capture that is not a crash dump carries no crash block at all.
    /// Attaching one full of nulls would render as a bugcheck panel that states
    /// nothing, which reads as "this crash has no stop code" rather than "this
    /// is not a crash dump".
    #[test]
    fn a_capture_that_is_not_a_crash_dump_carries_no_crash_block() {
        let mut bytes = vec![0u8; 8192];
        bytes[..4].copy_from_slice(b"hibr");
        let art = artifact_with("hiberfil.sys", bytes, json!({}));
        let out = MemoryImageModule.process(&art).unwrap();
        assert!(
            out[0].metadata.get("crash_dump").is_none(),
            "only a crash dump gets a crash-dump block"
        );
    }

    #[test]
    fn module_identity() {
        assert_eq!(MemoryImageModule.id(), "container.memory_image");
        assert!(MemoryImageModule
            .subscribes_to()
            .contains(&ArtifactType::RawEvidence));
    }
}
