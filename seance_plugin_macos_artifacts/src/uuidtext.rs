//! The unified log's format-string catalogue — `/var/db/uuidtext`.
//!
//! A unified-log message on disk is not text. The `.tracev3` firehose records
//! a *reference* — a binary image and an offset into it — plus the arguments,
//! and the words come from a **format string** held in this tree. Two kinds of
//! file hold them:
//!
//! * a **per-image entry**, at `uuidtext/<first two hex digits of the image's
//!   UUID>/<the other thirty>`, opening with the magic `0x66778899`. It holds
//!   the format strings of one binary and, at the end, that binary's path.
//! * a **shared cache**, `uuidtext/dsc/<32 hex digits>`, opening with `hcsd`.
//!   One of these covers the whole dyld shared cache: on the corpus, 527
//!   images and 651,026 format strings in 31 MB.
//!
//! # Why read a catalogue at all
//!
//! Two answers, and the second is the one an examiner cares about.
//!
//! It is what a `.tracev3` is decoded *against*, so a reader that cannot read
//! it cannot produce a single line of log text however well it walks the
//! firehose.
//!
//! And on its own it is an **inventory of the code on the machine that logs**:
//! every binary here is one the operating system had a logging catalogue for,
//! with its path, its UUID and its load address. That survives the log files.
//! On the corpus image the `diagnostics` tree holds **no `.tracev3` at all**
//! while this tree is intact — 274 entry files and two shared caches — so the
//! only thing left saying what was running is the catalogue.
//!
//! **A catalogue is not a log, and this reader never presents it as one.** It
//! holds the sentences the OS *would* have substituted arguments into. Nothing
//! here says any of them was ever written.
//!
//! # The formats, and the check each one passes
//!
//! An **entry file** is a 16-byte header (`magic`, `major`, `minor`,
//! `range_count`), then `range_count` pairs of `u32 offset, u32 size`, then
//! each range's bytes in order, then the image's path as one NUL-terminated
//! string. **It tiles exactly**: on all 274 corpus files, 16 + 8×n + Σsizes
//! lands on a tail holding exactly one NUL — the path — and nothing else.
//!
//! A **shared cache** is a 16-byte header (`hcsd`, `major`, `range_count`,
//! `image_count`), then `range_count` 16-byte range entries (`image index`,
//! `range start`, `data offset`, `range size`), then `image_count` 28-byte
//! image entries (`load address`, `size`, 16-byte UUID, `path offset`), then
//! the strings and the paths. Its check is the same shape: **the image table
//! ends at exactly the byte the first range's data begins at** — 27,300 in
//! both corpus caches — every one of the 783 range data offsets lands in the
//! string area, and all 527 path offsets resolve to a NUL-terminated path.
//!
//! # An entry file's UUID is its file name, not its content
//!
//! The 32 hex digits a `.tracev3` reference resolves through are the
//! directory name plus the file name. **They are nowhere in the file.** So a
//! file copied out of the tree under another name cannot be matched to a log
//! reference, and this reader says where the UUID came from rather than
//! presenting a path-derived identifier as something the file stated.
//!
//! # 274 catalogue files are not 274 binaries
//!
//! Twelve of the corpus's paths appear **twice, under two different UUIDs** —
//! two builds of the same binary, each with its own catalogue. Nine of the
//! twelve are Bluetooth and power components (`bluetoothd`,
//! `IOBluetoothFamily` and its four plug-ins, `BluetoothReporter`, `powerd`,
//! `pmset`) and two are `templateMigrator` and `recoveryos_agent`, which is
//! the shape of an OS update or a recovery variant sitting beside the
//! installed one. So the tree names **262** distinct binaries in 274 files,
//! and a reader that counted files would overstate the inventory.
//!
//! # The format strings are counted, not emitted
//!
//! 848,768 of them across the corpus tree. They are the operating system's own
//! source text — `"%s: connection from pid_t: %d"` — not observations about
//! this machine, and one record each would bury a case under Apple's strings.
//! Each image's count and a bounded sample are reported; the strings are read
//! in full so that a `.tracev3` decode can use them.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use tracing::info;

use crate::{stamp_incomplete, Staged};

/// `0x66778899`, little-endian, at the start of a per-image entry file.
const ENTRY_MAGIC: u32 = 0x6677_8899;
/// `hcsd` at the start of a shared cache.
const SHARED_MAGIC: &[u8; 4] = b"hcsd";

/// Fixed part of either file before its tables.
const HEADER_BYTES: usize = 16;
/// One entry file's range: `u32 offset, u32 size`.
const ENTRY_RANGE_BYTES: usize = 8;
/// One version-1 shared cache's range: image index, range start, data
/// offset, size.
const SHARED_RANGE_BYTES: usize = 16;
/// One version-1 shared cache's image: load address, size, 16-byte UUID,
/// path offset.
const SHARED_IMAGE_BYTES: usize = 28;
/// Version 2 (Monterey and later): a 64-bit range start first and a 64-bit
/// image index last.
const SHARED_RANGE_BYTES_V2: usize = 24;
/// Version 2: a 64-bit load address.
const SHARED_IMAGE_BYTES_V2: usize = 32;

/// Largest catalogue file staged. The corpus's shared caches are 31 MB each;
/// the cap is what stops a corrupt count from staging a disk.
const MAX_CATALOGUE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest number of ranges walked in one file.
const MAX_RANGES: usize = 1_000_000;
/// Largest number of images read from one shared cache.
const MAX_IMAGES: usize = 200_000;
/// Longest path read.
const MAX_PATH_BYTES: usize = 4096;
/// How many format strings are sampled onto a record. A count plus a sample:
/// the whole set is Apple's source text, not evidence.
const MAX_SAMPLED_STRINGS: usize = 8;
/// Longest sampled string kept, so one enormous format string cannot dominate
/// a record.
const MAX_SAMPLE_BYTES: usize = 240;

/// The sentence every record from this tree carries.
const CATALOGUE_NOTE: &str =
    "This is the unified log's format-string CATALOGUE, not a log. It holds the sentences the \
     operating system would have substituted arguments into; the messages themselves are in \
     `.tracev3` files under /var/db/diagnostics. Nothing here is evidence that any particular \
     message was ever written. What it does establish is that the machine held a logging \
     catalogue for this binary.";

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    let s = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A NUL-terminated string at `at`, bounded.
fn c_string(d: &[u8], at: usize) -> Option<String> {
    let rest = d.get(at..)?;
    let len = rest.iter().take(MAX_PATH_BYTES).position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&rest[..len]).into_owned())
}

/// The format strings in one range's bytes: NUL-separated, empties dropped.
fn strings_in(bytes: &[u8]) -> (usize, Vec<String>) {
    let mut count = 0usize;
    let mut sample = Vec::new();
    for part in bytes.split(|&b| b == 0) {
        if part.is_empty() {
            continue;
        }
        count += 1;
        if sample.len() < MAX_SAMPLED_STRINGS {
            let cut = part.len().min(MAX_SAMPLE_BYTES);
            sample.push(String::from_utf8_lossy(&part[..cut]).into_owned());
        }
    }
    (count, sample)
}

/// The 32-hex UUID an entry file's own path carries.
///
/// `uuidtext/51/A230C8287F307CA652F723CC388382` is UUID
/// `51A230C8287F307CA652F723CC388382`. Returns `None` when the path is not
/// that shape — which is not a parse failure, it is a file that cannot be
/// matched to a log reference, and the record says so.
fn uuid_from_path(path: &str) -> Option<String> {
    let normalised = path.replace('\\', "/");
    let mut parts = normalised.rsplit('/');
    let name = parts.next()?;
    let dir = parts.next()?;
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes().all(|b| b.is_ascii_hexdigit())
            && !s.bytes().any(|b| b.is_ascii_lowercase())
    };
    if hex(dir, 2) && hex(name, 30) {
        Some(format!("{dir}{name}"))
    } else {
        None
    }
}

/// One binary the catalogue holds format strings for.
#[derive(Debug, Clone)]
struct Image {
    /// Where the image is loaded in the shared cache. Absent for an entry
    /// file, which describes one binary and states no address.
    load_address: Option<u64>,
    size: Option<u32>,
    uuid: Option<String>,
    /// Where the UUID came from. An entry file's is its own file name; a
    /// shared cache states each image's outright.
    uuid_from_file_name: bool,
    path: Option<String>,
    ranges: usize,
    strings: usize,
    sample: Vec<String>,
}

/// Whichever kind of catalogue file this is, and what it held.
#[derive(Debug)]
struct Catalogue {
    kind: &'static str,
    major: u32,
    minor: Option<u32>,
    ranges: usize,
    strings: usize,
    images: Vec<Image>,
    /// Images the cache names that no range points at: they are in the shared
    /// cache and have no format strings here.
    images_with_no_ranges: usize,
    /// True when the file's own arithmetic came out — see the module docs for
    /// which check each kind passes.
    tiled: bool,
    /// What went wrong, in words, when it did not.
    flaw: Option<String>,
    /// A table ran past what was staged.
    truncated: bool,
    capped: Vec<&'static str>,
}

/// Read a per-image entry file.
fn read_entry(data: &[u8], file_path: &str) -> Option<Catalogue> {
    if le_u32(data, 0)? != ENTRY_MAGIC {
        return None;
    }
    let major = le_u32(data, 4)?;
    let minor = le_u32(data, 8)?;
    let declared = le_u32(data, 12)? as usize;
    let mut capped = Vec::new();
    let count = if declared > MAX_RANGES {
        capped.push("the range table");
        MAX_RANGES
    } else {
        declared
    };

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut truncated = false;
    for i in 0..count {
        let at = HEADER_BYTES + i * ENTRY_RANGE_BYTES;
        let (Some(offset), Some(size)) = (le_u32(data, at), le_u32(data, at + 4)) else {
            truncated = true;
            break;
        };
        ranges.push((offset as usize, size as usize));
    }

    // The ranges' bytes follow the table, in order.
    let mut p = HEADER_BYTES + ranges.len() * ENTRY_RANGE_BYTES;
    let mut strings = 0usize;
    let mut sample: Vec<String> = Vec::new();
    for (_, size) in &ranges {
        let Some(bytes) = data.get(p..p + size) else {
            truncated = true;
            break;
        };
        let (n, mut s) = strings_in(bytes);
        strings += n;
        if sample.len() < MAX_SAMPLED_STRINGS {
            s.truncate(MAX_SAMPLED_STRINGS - sample.len());
            sample.extend(s);
        }
        p += size;
    }

    // Then the image's path, as the only thing left in the file.
    let tail = data.get(p..).unwrap_or_default();
    let path = c_string(data, p);
    // The check this format passes: the tail is exactly one NUL-terminated
    // string. A tail holding more is a file this reader has not understood,
    // and one holding none is truncated.
    let tiled = tail.iter().filter(|b| **b == 0).count() == 1 && tail.last() == Some(&0);
    let flaw = if tiled {
        None
    } else {
        Some(format!(
            "after the header, the {} range table entr(ies) and {} byte(s) of range data, {} \
             byte(s) remain, holding {} NUL(s) — the format puts exactly one NUL-terminated \
             image path there, so this file's own arithmetic does not come out and the strings \
             counted above may not be all of them",
            ranges.len(),
            ranges.iter().map(|(_, s)| s).sum::<usize>(),
            tail.len(),
            tail.iter().filter(|b| **b == 0).count()
        ))
    };

    let uuid = uuid_from_path(file_path);
    Some(Catalogue {
        kind: "per_image_entry",
        major,
        minor: Some(minor),
        ranges: ranges.len(),
        strings,
        images: vec![Image {
            load_address: None,
            size: None,
            uuid_from_file_name: uuid.is_some(),
            uuid,
            path,
            ranges: ranges.len(),
            strings,
            sample,
        }],
        images_with_no_ranges: 0,
        tiled,
        flaw,
        truncated,
        capped,
    })
}

/// Read a `dsc` shared cache.
fn read_shared(data: &[u8]) -> Option<Catalogue> {
    if data.get(0..4)? != &SHARED_MAGIC[..] {
        return None;
    }
    // A u16 major and a u16 minor. Version 2 widened both tables; reading one
    // with the other's widths misaligns every entry.
    let major = u32::from(u16::from_le_bytes([*data.get(4)?, *data.get(5)?]));
    let v2 = major == 2;
    let (range_bytes, image_bytes) = if v2 {
        (SHARED_RANGE_BYTES_V2, SHARED_IMAGE_BYTES_V2)
    } else {
        (SHARED_RANGE_BYTES, SHARED_IMAGE_BYTES)
    };
    let declared_ranges = le_u32(data, 8)? as usize;
    let declared_images = le_u32(data, 12)? as usize;
    let mut capped = Vec::new();
    let range_count = if declared_ranges > MAX_RANGES {
        capped.push("the range table");
        MAX_RANGES
    } else {
        declared_ranges
    };
    let image_count = if declared_images > MAX_IMAGES {
        capped.push("the image table");
        MAX_IMAGES
    } else {
        declared_images
    };

    let range_table = HEADER_BYTES;
    let image_table = range_table + range_count * range_bytes;
    let strings_begin = image_table + image_count * image_bytes;

    let mut truncated = false;
    let mut per_image: Vec<(usize, usize, Vec<String>)> = vec![(0, 0, Vec::new()); image_count];
    let mut ranges = 0usize;
    let mut strings = 0usize;
    let mut data_offsets_outside = 0usize;
    for i in 0..range_count {
        let at = range_table + i * range_bytes;
        let index_at = if v2 { at + 16 } else { at };
        let (Some(image_index), Some(data_offset), Some(size)) = (
            le_u32(data, index_at),
            le_u32(data, at + 8),
            le_u32(data, at + 12),
        ) else {
            truncated = true;
            break;
        };
        ranges += 1;
        let from = data_offset as usize;
        if from < strings_begin || from >= data.len() {
            // A range whose data is not in the string area is one this reader
            // will not read: the bytes it points at are some other structure.
            data_offsets_outside += 1;
            continue;
        }
        let Some(bytes) = data.get(from..(from + size as usize).min(data.len())) else {
            truncated = true;
            continue;
        };
        let (n, s) = strings_in(bytes);
        strings += n;
        if let Some(slot) = per_image.get_mut(image_index as usize) {
            slot.0 += 1;
            slot.1 += n;
            if slot.2.len() < MAX_SAMPLED_STRINGS {
                let room = MAX_SAMPLED_STRINGS - slot.2.len();
                slot.2.extend(s.into_iter().take(room));
            }
        }
    }

    let mut images = Vec::with_capacity(image_count);
    let mut images_with_no_ranges = 0usize;
    for i in 0..image_count {
        let at = image_table + i * image_bytes;
        // Version 2 widens the load address to 64 bits and shifts the rest.
        let w = if v2 { 4 } else { 0 };
        let load_address = if v2 {
            le_u32(data, at)
                .zip(le_u32(data, at + 4))
                .map(|(lo, hi)| u64::from(lo) | (u64::from(hi) << 32))
        } else {
            le_u32(data, at).map(u64::from)
        };
        let (Some(load_address), Some(size), Some(path_offset)) = (
            load_address,
            le_u32(data, at + 4 + w),
            le_u32(data, at + 24 + w),
        ) else {
            truncated = true;
            break;
        };
        let uuid = data
            .get(at + 8 + w..at + 24 + w)
            .map(|u| u.iter().map(|b| format!("{b:02X}")).collect::<String>());
        let path = c_string(data, path_offset as usize);
        let (ranges_here, strings_here, sample) =
            per_image.get(i).cloned().unwrap_or((0, 0, Vec::new()));
        if ranges_here == 0 {
            images_with_no_ranges += 1;
        }
        images.push(Image {
            load_address: Some(load_address),
            size: Some(size),
            uuid,
            uuid_from_file_name: false,
            path,
            ranges: ranges_here,
            strings: strings_here,
            sample,
        });
    }

    // The check this format passes: the image table ends at exactly the byte
    // the first range's data begins at. Both tables' widths and both counts
    // have to be right for that to hold.
    let first_data = le_u32(data, range_table + 8).map(|v| v as usize);
    let tiled = first_data == Some(strings_begin) && data_offsets_outside == 0;
    let flaw = if tiled {
        None
    } else {
        Some(format!(
            "the image table ends at byte {strings_begin} and the first range's data begins at \
             {}, and {data_offsets_outside} of {ranges} range(s) point outside the string area \
             — the format puts the strings immediately after the image table, so this file's \
             own arithmetic does not come out and the strings counted above may not be all of \
             them",
            first_data
                .map(|v| v.to_string())
                .unwrap_or_else(|| "nowhere readable".into())
        ))
    };

    Some(Catalogue {
        kind: "shared_cache",
        major,
        minor: None,
        ranges,
        strings,
        images,
        images_with_no_ranges,
        tiled,
        flaw,
        truncated,
        capped,
    })
}

pub struct UnifiedLogCatalogueParser;

fn provenance(meta: &mut Map<String, Value>, file_name: &str, kind: &str) {
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert("source_format".into(), json!(format!("uuidtext_{kind}")));
}

fn catalogue_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    catalogue: &Catalogue,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("UnifiedLogCatalogue"));
    meta.insert("subtype".into(), json!(catalogue.kind));
    provenance(&mut meta, file_name, catalogue.kind);
    meta.insert("catalogue_kind".into(), json!(catalogue.kind));
    meta.insert("format_version_major".into(), json!(catalogue.major));
    if let Some(minor) = catalogue.minor {
        meta.insert("format_version_minor".into(), json!(minor));
    }
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("ranges".into(), json!(catalogue.ranges));
    meta.insert("images".into(), json!(catalogue.images.len()));
    meta.insert("format_strings".into(), json!(catalogue.strings));
    if catalogue.images_with_no_ranges > 0 {
        meta.insert(
            "images_with_no_format_strings".into(),
            json!(catalogue.images_with_no_ranges),
        );
        meta.insert(
            "images_with_no_format_strings_note".into(),
            json!(
                "These binaries are named by the cache and no range points at them, so this \
                   file holds no format strings for them. They are reported because a log \
                   reference into one of them will not resolve here, and an examiner owed that \
                   answer should not have to infer it from an absence."
            ),
        );
    }
    // The file's own arithmetic, published either way so a reader can see that
    // it was checked rather than take the counts on trust.
    meta.insert("layout_self_consistent".into(), json!(catalogue.tiled));
    meta.insert("note".into(), json!(CATALOGUE_NOTE));

    let mut reasons: Vec<(IncompleteReason, String)> = Vec::new();
    if let Some(flaw) = &catalogue.flaw {
        reasons.push((IncompleteReason::UnresolvedStructure, flaw.clone()));
    }
    if catalogue.truncated {
        reasons.push((
            IncompleteReason::ShortRead,
            "a table or a range ran past the bytes staged, so the walk stopped there rather \
             than reading the rest against whatever followed"
                .to_string(),
        ));
    }
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(file_name)));
    }
    if !catalogue.capped.is_empty() {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "a reader cap was reached in: {}",
                catalogue.capped.join(", ")
            ),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    let label = match catalogue.kind {
        "shared_cache" => format!(
            "Unified log shared catalogue: {} image(s), {} format string(s)",
            catalogue.images.len(),
            catalogue.strings
        ),
        _ => format!(
            "Unified log catalogue for {}",
            catalogue
                .images
                .first()
                .and_then(|i| i.path.clone())
                .unwrap_or_else(|| file_name.to_string())
        ),
    };
    meta.insert("name".into(), json!(label.clone()));
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "{label} — the format strings a .tracev3 is decoded against, not log messages"
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype(catalogue.kind)
}

fn image_artifact(
    artifact: &Artifact,
    file_name: &str,
    kind: &'static str,
    image: &Image,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("UnifiedLogImage"));
    meta.insert("subtype".into(), json!("unifiedlog_image"));
    provenance(&mut meta, file_name, kind);
    if let Some(path) = &image.path {
        meta.insert("image_path".into(), json!(path));
    } else {
        meta.insert("image_path_recorded".into(), json!(false));
    }
    match &image.uuid {
        Some(uuid) => {
            meta.insert("image_uuid".into(), json!(uuid));
            // Where an identifier came from is part of the identifier. An
            // entry file states its UUID nowhere: it is the file's own name,
            // so a file renamed on the way out of the tree loses it.
            meta.insert(
                "image_uuid_source".into(),
                json!(if image.uuid_from_file_name {
                    "this file's own name, which is where the format puts it — the UUID is not \
                     in the file's content, so a copy under another name cannot be matched to a \
                     log reference"
                } else {
                    "the shared cache's image table"
                }),
            );
        }
        None => {
            meta.insert("image_uuid_recorded".into(), json!(false));
            meta.insert(
                "image_uuid_note".into(),
                json!(
                    "A per-image catalogue's UUID is its file name — two hex digits of \
                       directory and thirty of file name — and this file's path is not that \
                       shape, so it cannot be matched to a log reference."
                ),
            );
        }
    }
    if let Some(load_address) = image.load_address {
        meta.insert("load_address".into(), json!(load_address));
    }
    if let Some(size) = image.size {
        meta.insert("image_size".into(), json!(size));
    }
    meta.insert("ranges".into(), json!(image.ranges));
    meta.insert("format_strings".into(), json!(image.strings));
    if !image.sample.is_empty() {
        // Bounded, and labelled as a sample: the whole set is Apple's source
        // text and one record each would bury a case under it.
        meta.insert("format_string_sample".into(), json!(image.sample));
    }
    meta.insert("note".into(), json!(CATALOGUE_NOTE));
    let label = image
        .path
        .clone()
        .or_else(|| image.uuid.clone())
        .unwrap_or_else(|| file_name.to_string());
    meta.insert("name".into(), json!(label.clone()));
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "The machine held a logging catalogue for {label}: {} format string(s)",
            image.strings
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("unifiedlog_image")
}

impl ForensicsModule for UnifiedLogCatalogueParser {
    fn id(&self) -> &str {
        "macos.unifiedlog_catalogue"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Selection is by magic alone. Every file in this tree is named in hex
        // — `51/A230C8287F307CA652F723CC388382` — so there is no name to
        // select on, and a hex name is not a claim about content.
        let staged = Staged::read(ds.as_ref(), MAX_CATALOGUE_BYTES);
        let Some(catalogue) =
            read_entry(&staged.bytes, name).or_else(|| read_shared(&staged.bytes))
        else {
            return Ok(Vec::new());
        };

        let mut out = Vec::with_capacity(catalogue.images.len() + 1);
        out.push(catalogue_artifact(artifact, name, &staged, &catalogue));
        for image in &catalogue.images {
            out.push(image_artifact(artifact, name, catalogue.kind, image));
        }
        info!(
            "UnifiedLogCatalogueParser: {name} — {} ({} image(s), {} format string(s))",
            catalogue.kind,
            catalogue.images.len(),
            catalogue.strings
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;
    use uuid::Uuid;

    // --- fixture construction -------------------------------------------------
    //
    // Both files are written from literal offsets rather than through the
    // reader's own constants, so a mistake in those cannot make a test agree
    // with itself.

    /// One per-image entry file: header, range table, range bytes, path.
    fn entry_file(major: u32, minor: u32, ranges: &[(u32, &[&str])], path: &str) -> Vec<u8> {
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        for (_, strings) in ranges {
            let mut blob = Vec::new();
            for s in *strings {
                blob.extend_from_slice(s.as_bytes());
                blob.push(0);
            }
            blobs.push(blob);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&0x6677_8899u32.to_le_bytes());
        out.extend_from_slice(&major.to_le_bytes());
        out.extend_from_slice(&minor.to_le_bytes());
        out.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
        for ((offset, _), blob) in ranges.iter().zip(&blobs) {
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        }
        for blob in &blobs {
            out.extend_from_slice(blob);
        }
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out
    }

    struct SharedImage {
        load_address: u32,
        size: u32,
        uuid: [u8; 16],
        path: &'static str,
        /// Format strings, as one range.
        strings: &'static [&'static str],
    }

    /// One `dsc` shared cache: header, range table, image table, then the
    /// strings and the paths.
    fn shared_cache(major: u32, images: &[SharedImage]) -> Vec<u8> {
        // A range only for an image that has strings, as the real caches do:
        // 33 of the corpus cache's 527 images have none.
        let with_strings: Vec<usize> = images
            .iter()
            .enumerate()
            .filter(|(_, i)| !i.strings.is_empty())
            .map(|(n, _)| n)
            .collect();
        let strings_begin = 16 + with_strings.len() * 16 + images.len() * 28;
        // Lay the string blobs out first so the range table can name them.
        let mut blobs: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut at = strings_begin;
        for &i in &with_strings {
            let mut blob = Vec::new();
            for s in images[i].strings {
                blob.extend_from_slice(s.as_bytes());
                blob.push(0);
            }
            blobs.push((at, blob.clone()));
            at += blob.len();
        }
        // Then the paths, after the strings.
        let mut paths: Vec<usize> = Vec::new();
        let mut path_bytes = Vec::new();
        for image in images {
            paths.push(at + path_bytes.len());
            path_bytes.extend_from_slice(image.path.as_bytes());
            path_bytes.push(0);
        }

        let mut out = Vec::new();
        out.extend_from_slice(SHARED_MAGIC);
        out.extend_from_slice(&major.to_le_bytes());
        out.extend_from_slice(&(with_strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&(images.len() as u32).to_le_bytes());
        for (slot, &i) in with_strings.iter().enumerate() {
            out.extend_from_slice(&(i as u32).to_le_bytes());
            out.extend_from_slice(&images[i].load_address.to_le_bytes());
            out.extend_from_slice(&(blobs[slot].0 as u32).to_le_bytes());
            out.extend_from_slice(&(blobs[slot].1.len() as u32).to_le_bytes());
        }
        for (i, image) in images.iter().enumerate() {
            out.extend_from_slice(&image.load_address.to_le_bytes());
            out.extend_from_slice(&image.size.to_le_bytes());
            out.extend_from_slice(&image.uuid);
            out.extend_from_slice(&(paths[i] as u32).to_le_bytes());
        }
        assert_eq!(out.len(), strings_begin, "the fixture's own arithmetic");
        for (_, blob) in &blobs {
            out.extend_from_slice(blob);
        }
        out.extend_from_slice(&path_bytes);
        out
    }

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let case = Uuid::new_v4();
        let mut file = Artifact::new(
            case,
            ArtifactType::FileEntry,
            None,
            json!({ "name": name, "size": bytes.len() }),
        );
        file.data = Some(Arc::new(ByteSliceDataSource::new(bytes)));
        UnifiedLogCatalogueParser
            .process(&file)
            .expect("the parser must not error")
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    fn one<'a>(out: &'a [Artifact], wanted: &str) -> &'a Value {
        of_type(out, wanted)
            .first()
            .copied()
            .unwrap_or_else(|| panic!("a {wanted} record"))
    }

    fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|x| x.as_str())
    }
    fn n(v: &Value, key: &str) -> Option<i64> {
        v.get(key).and_then(|x| x.as_i64())
    }

    const UUID_PATH: &str = "private/var/db/uuidtext/51/A230C8287F307CA652F723CC388382";

    // --- the per-image entry file --------------------------------------------

    #[test]
    fn a_per_image_entry_yields_its_binary_and_its_format_string_count() {
        let bytes = entry_file(
            2,
            1,
            &[
                (
                    38496,
                    &[
                        "com.apple.textinputmethod-services",
                        "IMKLaunchAgent -listener: got IMKClient service from pid_t: %d",
                    ],
                ),
                (46192, &["%s:  %s\n", "%s\n"]),
            ],
            "/System/Library/Frameworks/InputMethodKit.framework/Versions/A/Resources/imklaunchagent",
        );
        let out = run(bytes, UUID_PATH);

        let catalogue = one(&out, "UnifiedLogCatalogue");
        assert_eq!(s(catalogue, "catalogue_kind"), Some("per_image_entry"));
        assert_eq!(n(catalogue, "format_version_major"), Some(2));
        assert_eq!(n(catalogue, "format_version_minor"), Some(1));
        assert_eq!(n(catalogue, "ranges"), Some(2));
        assert_eq!(n(catalogue, "format_strings"), Some(4));
        // The file's own arithmetic, published either way.
        assert_eq!(catalogue["layout_self_consistent"], json!(true));
        assert!(catalogue.get("content_incomplete").is_none());

        let image = one(&out, "UnifiedLogImage");
        assert_eq!(
            s(image, "image_path"),
            Some("/System/Library/Frameworks/InputMethodKit.framework/Versions/A/Resources/imklaunchagent")
        );
        assert_eq!(n(image, "format_strings"), Some(4));
        assert!(image["format_string_sample"]
            .as_array()
            .expect("a sample")
            .iter()
            .any(|v| v.as_str() == Some("%s\n")));
    }

    #[test]
    fn an_entry_files_uuid_comes_from_its_name_and_the_record_says_so() {
        // The UUID a `.tracev3` reference resolves through is nowhere in the
        // file. Presenting a path-derived identifier as something the file
        // stated would be the error here.
        let bytes = entry_file(2, 1, &[(0, &["%s"])], "/usr/bin/true");
        let image = {
            let out = run(bytes, UUID_PATH);
            one(&out, "UnifiedLogImage").clone()
        };
        assert_eq!(
            s(&image, "image_uuid"),
            Some("51A230C8287F307CA652F723CC388382")
        );
        assert!(s(&image, "image_uuid_source")
            .expect("a source")
            .contains("this file's own name"));
        assert!(s(&image, "image_uuid_source")
            .expect("a source")
            .contains("not in the file's content"));
    }

    #[test]
    fn a_catalogue_under_a_name_that_is_not_a_uuid_says_it_cannot_be_matched() {
        // A file carved out of unallocated space, or copied to a desktop, is
        // still read — but it can no longer be tied to a log reference, and
        // silently omitting the UUID would read as a file that had none.
        let bytes = entry_file(2, 1, &[(0, &["%s"])], "/usr/bin/true");
        for name in [
            "carved_000123.bin",
            "uuidtext/51/not-thirty-hex-digits",
            "A230C8287F307CA652F723CC388382",
        ] {
            let out = run(bytes.clone(), name);
            let image = one(&out, "UnifiedLogImage");
            assert_eq!(
                image["image_uuid_recorded"],
                json!(false),
                "{name} gives no UUID"
            );
            assert!(s(image, "image_uuid_note")
                .expect("a note")
                .contains("cannot be matched to a log reference"));
            // And the strings are still read.
            assert_eq!(
                n(one(&out, "UnifiedLogCatalogue"), "format_strings"),
                Some(1)
            );
        }
    }

    #[test]
    fn a_lower_case_hex_name_is_not_read_as_a_uuid() {
        // The tree's own names are upper case. Accepting either case would
        // manufacture a UUID for a file somebody had lower-cased on the way
        // out, and a UUID that does not match the tree's is worse than none.
        assert_eq!(
            uuid_from_path("uuidtext/51/A230C8287F307CA652F723CC388382").as_deref(),
            Some("51A230C8287F307CA652F723CC388382")
        );
        assert_eq!(
            uuid_from_path("uuidtext/51/a230c8287f307ca652f723cc388382"),
            None
        );
        assert_eq!(
            uuid_from_path("uuidtext/5g/A230C8287F307CA652F723CC388382"),
            None
        );
        assert_eq!(uuid_from_path("A230C8287F307CA652F723CC388382"), None);
        // A Windows-walked image hands paths back with backslashes.
        assert_eq!(
            uuid_from_path("uuidtext\\51\\A230C8287F307CA652F723CC388382").as_deref(),
            Some("51A230C8287F307CA652F723CC388382")
        );
    }

    #[test]
    fn an_entry_file_whose_arithmetic_does_not_come_out_says_so_and_keeps_what_it_read() {
        // The check this format passes is that the bytes left after the
        // ranges hold exactly one NUL-terminated path. A file where they hold
        // more is one this reader has not understood, and reporting its
        // counts without that caveat would present a partial read as a whole
        // one.
        let mut bytes = entry_file(2, 1, &[(0, &["%s", "%d"])], "/usr/bin/true");
        bytes.extend_from_slice(b"trailing\0junk\0");
        let out = run(bytes, UUID_PATH);
        let catalogue = one(&out, "UnifiedLogCatalogue");
        assert_eq!(catalogue["layout_self_consistent"], json!(false));
        assert_eq!(
            s(catalogue, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
        let detail = s(catalogue, "content_incomplete_detail").expect("a sentence");
        assert!(
            detail.contains("exactly one NUL-terminated image path"),
            "{detail}"
        );
        // And the two strings it did read are still reported.
        assert_eq!(n(catalogue, "format_strings"), Some(2));
    }

    #[test]
    fn a_range_running_past_the_file_stops_the_walk_rather_than_reading_past_it() {
        let mut bytes = entry_file(2, 1, &[(0, &["%s"])], "/usr/bin/true");
        // Claim a range far larger than the file holds.
        bytes[20..24].copy_from_slice(&100_000u32.to_le_bytes());
        let out = run(bytes, UUID_PATH);
        let catalogue = one(&out, "UnifiedLogCatalogue");
        assert_eq!(catalogue["layout_self_consistent"], json!(false));
        let detail = s(catalogue, "content_incomplete_detail").expect("a sentence");
        assert!(detail.contains("ran past the bytes staged"), "{detail}");
    }

    // --- the shared cache -----------------------------------------------------

    #[test]
    fn a_shared_cache_yields_every_binary_it_covers() {
        let bytes = shared_cache(
            1,
            &[
                SharedImage {
                    load_address: 0x12000,
                    size: 0x2000,
                    uuid: [
                        0xE6, 0x44, 0xCA, 0xA0, 0x65, 0xB7, 0x36, 0xE4, 0x80, 0x41, 0x52, 0x0F,
                        0x33, 0x01, 0xF3, 0xDB,
                    ],
                    path: "/usr/lib/system/libsystem_blocks.dylib",
                    strings: &[],
                },
                SharedImage {
                    load_address: 0x14000,
                    size: 0x36000,
                    uuid: [
                        0x70, 0xF2, 0x62, 0x62, 0x01, 0xAA, 0x3C, 0xEC, 0x9F, 0xAD, 0x27, 0x01,
                        0xD2, 0x40, 0x96, 0xF0,
                    ],
                    path: "/usr/lib/system/libxpc.dylib",
                    strings: &["xpc_connection_send_message: %s", "%{public}s"],
                },
            ],
        );
        let out = run(
            bytes,
            "private/var/db/uuidtext/dsc/4FC4D24FF9353B97BB605B2545EF5F41",
        );

        let catalogue = one(&out, "UnifiedLogCatalogue");
        assert_eq!(s(catalogue, "catalogue_kind"), Some("shared_cache"));
        assert_eq!(n(catalogue, "format_version_major"), Some(1));
        assert_eq!(n(catalogue, "images"), Some(2));
        assert_eq!(n(catalogue, "format_strings"), Some(2));
        assert_eq!(catalogue["layout_self_consistent"], json!(true));

        let images = of_type(&out, "UnifiedLogImage");
        assert_eq!(images.len(), 2);
        assert_eq!(
            s(images[0], "image_uuid"),
            Some("E644CAA065B736E48041520F3301F3DB"),
            "the cache states each image's UUID outright, unlike an entry file"
        );
        assert_eq!(
            s(images[0], "image_uuid_source"),
            Some("the shared cache's image table")
        );
        assert_eq!(
            s(images[1], "image_path"),
            Some("/usr/lib/system/libxpc.dylib")
        );
        assert_eq!(n(images[1], "load_address"), Some(0x14000));
        assert_eq!(n(images[1], "format_strings"), Some(2));
    }

    #[test]
    fn an_image_the_cache_holds_no_strings_for_is_counted_and_named() {
        // A log reference into such an image will not resolve here, and an
        // examiner owed that answer should not have to infer it from silence.
        let bytes = shared_cache(
            1,
            &[SharedImage {
                load_address: 0x12000,
                size: 0x2000,
                uuid: [0; 16],
                path: "/usr/lib/system/libsystem_blocks.dylib",
                strings: &[],
            }],
        );
        let out = run(bytes, "dsc/ABCDEF0123456789ABCDEF0123456789");
        let catalogue = one(&out, "UnifiedLogCatalogue");
        assert_eq!(n(catalogue, "images_with_no_format_strings"), Some(1));
        assert!(s(catalogue, "images_with_no_format_strings_note")
            .expect("a note")
            .contains("will not resolve here"));
        let image = one(&out, "UnifiedLogImage");
        assert_eq!(n(image, "format_strings"), Some(0));
        assert!(image.get("format_string_sample").is_none());
    }

    #[test]
    fn a_shared_cache_whose_tables_do_not_meet_its_strings_says_so() {
        // The check this format passes: the image table ends at exactly the
        // byte the first range's data begins at. Both counts and both table
        // widths have to be right for that, so it catches the whole class of
        // off-by-one layout errors at once.
        let mut bytes = shared_cache(
            1,
            &[SharedImage {
                load_address: 0x12000,
                size: 0x2000,
                uuid: [1; 16],
                path: "/usr/bin/true",
                strings: &["%s"],
            }],
        );
        // Move the first range's data offset off the string area.
        let at = 16 + 8;
        bytes[at..at + 4].copy_from_slice(&9_000_000u32.to_le_bytes());
        let out = run(bytes, "dsc/ABCDEF0123456789ABCDEF0123456789");
        let catalogue = one(&out, "UnifiedLogCatalogue");
        assert_eq!(catalogue["layout_self_consistent"], json!(false));
        let detail = s(catalogue, "content_incomplete_detail").expect("a sentence");
        assert!(detail.contains("point outside the string area"), "{detail}");
    }

    // --- selection and the claim every record carries -------------------------

    #[test]
    fn a_file_that_is_neither_kind_is_passed_over_in_silence() {
        for bytes in [
            b"not a catalogue".to_vec(),
            vec![0u8; 64],
            b"SQLite format 3\0".to_vec(),
        ] {
            assert!(run(bytes, UUID_PATH).is_empty());
        }
    }

    /// Monterey and later write version-2 shared caches: 24-byte ranges with
    /// a 64-bit start and the image index at the end, and 32-byte images with
    /// a 64-bit load address. Read with the version-1 widths, every table is
    /// misaligned and the file reports that its arithmetic does not come out.
    #[test]
    fn a_version_2_shared_cache_is_read_with_its_own_widths() {
        let path = home(
            "forensic_corpora/mandiant_unifiedlogs/test_data/\
             system_logs_monterey.logarchive/dsc/227156B475DD3CD6863DDD54A1D8C096",
        );
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            2,
            "a version-2 cache"
        );
        let out = run(bytes, "dsc/227156B475DD3CD6863DDD54A1D8C096");
        let cat = one(&out, "UnifiedLogCatalogue");
        assert_eq!(cat["layout_self_consistent"], json!(true), "{cat:#}");
        assert_eq!(cat["format_version_major"], json!(2));
        // 0x03a6 ranges and 0x026a images, as the header declares.
        assert_eq!(n(cat, "images"), Some(0x026a));
        assert_eq!(n(cat, "ranges"), Some(0x03a6));
        let images = of_type(&out, "UnifiedLogImage");
        assert!(images
            .iter()
            .all(|i| s(i, "image_path").is_some_and(|p| p.starts_with('/'))));

        // Every shared cache in the six archives, version 1 and 2, tiles.
        let root = home("forensic_corpora/mandiant_unifiedlogs/test_data");
        let mut caches = 0;
        for a in std::fs::read_dir(root).unwrap().flatten() {
            for f in std::fs::read_dir(a.path().join("dsc"))
                .into_iter()
                .flatten()
                .flatten()
            {
                let name = format!("dsc/{}", f.file_name().to_string_lossy());
                let out = run(std::fs::read(f.path()).unwrap(), &name);
                let cat = one(&out, "UnifiedLogCatalogue");
                assert_eq!(cat["layout_self_consistent"], json!(true), "{name}");
                caches += 1;
            }
        }
        assert_eq!(caches, 10);
    }

    #[test]
    fn selection_is_by_magic_because_every_name_in_this_tree_is_hex() {
        // The tree's names carry no extension and no word, so there is nothing
        // to select on but the first four bytes.
        let bytes = entry_file(2, 1, &[(0, &["%s"])], "/usr/bin/true");
        assert!(!run(bytes.clone(), "somewhere/else/entirely.bin").is_empty());
        assert!(!run(bytes, "").is_empty());
    }

    #[test]
    fn every_record_says_a_catalogue_is_not_a_log() {
        // The inference this whole module must refuse: a format string is a
        // sentence the OS would have written, not one it did.
        let bytes = entry_file(2, 1, &[(0, &["user %s logged in"])], "/usr/bin/login");
        let out = run(bytes, UUID_PATH);
        assert_eq!(out.len(), 2);
        for record in &out {
            let note = record.metadata["note"].as_str().expect("a note");
            assert!(note.contains("not a log"), "{note}");
            assert!(
                note.contains(
                    "Nothing here is evidence that any particular message was ever \
                               written"
                ),
                "{note}"
            );
            assert_eq!(
                record.metadata["source_format"].as_str(),
                Some("uuidtext_per_image_entry")
            );
        }
    }

    // --- the real catalogue ---------------------------------------------------

    /// The corpus's `uuidtext` tree, in full.
    ///
    /// The image's `diagnostics` tree holds **no `.tracev3` file at all**, so
    /// this is the only thing on it that still says what code the machine was
    /// running and logging. Every figure below is pinned.
    #[test]
    fn the_real_uuidtext_tree_yields_the_machines_logging_inventory() {
        let root = home(
            "ctf-evidence/macos2021/tree/System/Volumes/Preboot/\
             943CAEE3-8306-426A-A65E-4E0F4B52EBDB/PreLoginData/uuidtext",
        );
        let Ok(entries) = std::fs::read_dir(root) else {
            eprintln!("skipping: the macOS uuidtext corpus is not present (gitignored)");
            return;
        };

        let mut entry_files = 0usize;
        let mut entry_strings = 0usize;
        let mut entry_ranges = 0usize;
        let mut inconsistent = 0usize;
        let mut no_uuid = 0usize;
        let mut paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut shared: Vec<(usize, usize, usize)> = Vec::new();

        for dir in entries.flatten() {
            let Ok(files) = std::fs::read_dir(dir.path()) else {
                continue;
            };
            for file in files.flatten() {
                let Ok(bytes) = std::fs::read(file.path()) else {
                    continue;
                };
                // The reader is given the path the tree gives it, because the
                // UUID of an entry file is that path.
                let name = format!(
                    "{}/{}",
                    dir.file_name().to_string_lossy(),
                    file.file_name().to_string_lossy()
                );
                let out = run(bytes, &name);
                if out.is_empty() {
                    continue;
                }
                let catalogue = one(&out, "UnifiedLogCatalogue");
                if catalogue["layout_self_consistent"] != json!(true) {
                    inconsistent += 1;
                }
                match s(catalogue, "catalogue_kind") {
                    Some("per_image_entry") => {
                        entry_files += 1;
                        entry_strings += n(catalogue, "format_strings").unwrap_or(0) as usize;
                        entry_ranges += n(catalogue, "ranges").unwrap_or(0) as usize;
                        let image = one(&out, "UnifiedLogImage");
                        if image.get("image_uuid").is_none() {
                            no_uuid += 1;
                        }
                        if let Some(path) = s(image, "image_path") {
                            paths.insert(path.to_string());
                        }
                    }
                    Some("shared_cache") => shared.push((
                        n(catalogue, "images").unwrap_or(0) as usize,
                        n(catalogue, "ranges").unwrap_or(0) as usize,
                        n(catalogue, "format_strings").unwrap_or(0) as usize,
                    )),
                    other => panic!("unexpected catalogue kind {other:?}"),
                }
            }
        }

        assert_eq!(entry_files, 274, "per-image entry files");
        assert_eq!(entry_ranges, 504);
        assert_eq!(entry_strings, 197_742);
        assert_eq!(
            inconsistent, 0,
            "every one of the 276 files' own arithmetic comes out: the entry files' ranges land \
             on a tail holding exactly one path, and both shared caches' image tables end at the \
             byte their first range's data begins at"
        );
        assert_eq!(
            no_uuid, 0,
            "every entry file's path is the two-plus-thirty hex digits the format puts the UUID in"
        );
        // The inventory itself: which binaries this machine had a logging
        // catalogue for — and **twelve of them appear twice, under two
        // different UUIDs**, which means the machine held catalogues for two
        // BUILDS of the same binary. Nine of the twelve are Bluetooth and
        // power components and two are the installer and recovery agents, so
        // the shape of it is an OS update or a recovery variant sitting
        // beside the installed one. A count of files is not a count of
        // binaries, and reporting 274 binaries would be wrong.
        assert_eq!(
            paths.len(),
            262,
            "274 catalogue files name 262 distinct binaries: twelve paths have two UUIDs each"
        );
        for expected in [
            "/System/Library/Frameworks/InputMethodKit.framework/Versions/A/Resources/imklaunchagent",
            "/usr/libexec/opendirectoryd",
            // One of the twelve held under two UUIDs.
            "/usr/sbin/bluetoothd",
        ] {
            assert!(
                paths.iter().any(|p| p == expected),
                "{expected} is one of the binaries this machine logged from"
            );
        }

        // Two shared caches, identical in shape — which is what a machine
        // that has updated its shared cache once looks like.
        assert_eq!(shared.len(), 2);
        for (images, ranges, strings) in &shared {
            assert_eq!((*images, *ranges, *strings), (527, 783, 651_026));
        }
    }

    /// And the finding this tree carries on its own, stated as the absence it
    /// is.
    #[test]
    fn the_corpus_holds_a_catalogue_and_no_logs_at_all() {
        let diagnostics = home(
            "ctf-evidence/macos2021/tree/System/Volumes/Preboot/\
             943CAEE3-8306-426A-A65E-4E0F4B52EBDB/PreLoginData/diagnostics",
        );
        if !diagnostics.is_dir() {
            eprintln!("skipping: the macOS diagnostics corpus is not present (gitignored)");
            return;
        }
        // Walk it for anything a unified-log reader could decode.
        let mut tracev3 = 0usize;
        let mut stack = vec![diagnostics.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("tracev3"))
                {
                    tracev3 += 1;
                }
            }
        }
        assert_eq!(
            tracev3, 0,
            "this is why the catalogue is worth reading on its own: the image's diagnostics tree \
             holds no .tracev3 at all, so the 274 entry files and two shared caches are the only \
             thing left on it saying what code was running and logging. It is also why the \
             per-message decode in ROADMAP §1.6 cannot be graded here"
        );
    }
}
