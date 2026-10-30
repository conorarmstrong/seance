#![forbid(unsafe_code)]
//! AFF4 (Advanced Forensic Format 4) Container Module
//!
//! Reads forensic disk images in the AFF4 standard (Evimetry / c-aff4). AFF4
//! stores evidence in a ZIP container described by RDF/Turtle metadata:
//!
//! - `information.turtle` describes the objects: a top-level `aff4:Image`
//!   whose `aff4:dataStream` is either an `aff4:Map` or an `aff4:ImageStream`.
//! - An `aff4:ImageStream` holds the bytes as fixed-size chunks (default 32 KiB)
//!   grouped into bevies. Each bevy is two ZIP segments: `<urn>/<bevy:08d>`
//!   (concatenated, per-chunk compressed data) and `<urn>/<bevy:08d>.index`
//!   (one `u64 offset + u32 length` entry per chunk). A chunk stored at its full
//!   uncompressed length is raw; otherwise it is snappy- or deflate-compressed.
//! - An `aff4:Map` remaps logical offsets onto one or more target streams via
//!   `<urn>/map` (28-byte entries: `u64 mapOffset, u64 length, u64 targetOffset,
//!   u32 targetId`) and `<urn>/idx` (newline-separated target URNs). Regions not
//!   covered by any entry read as the `aff4:mapGapDefaultStream` (normally
//!   `aff4:Zero`). Targets can be image streams or symbolic constant-byte
//!   streams (`aff4:Zero`, `aff4:SymbolicStream<HH>`).
//!
//! The reader reconstructs the logical image behind a [`DataSource`], reading and
//! decompressing chunks on demand, so an AFF4 image ingests like any raw image.
//!
//! ## References
//! - AFF4 Standard: <https://github.com/aff4/Standard>
//! - Reference images: <https://github.com/aff4/ReferenceImages>

use anyhow::{anyhow, Result};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Mutex;
use tracing::{info, warn};
use zip::ZipArchive;

pub struct Aff4ContainerModule;

/// Hard cap on how many bytes a single ZIP segment may materialise into memory.
/// A hostile/corrupt AFF4 can claim an enormous uncompressed size or ship a
/// zip-bomb segment; the reader fails closed at this ceiling instead of letting
/// a claimed size drive an unbounded allocation. Mirrors the ZIP container's
/// `MAX_ENTRY_SIZE`.
const MAX_ZIP_ENTRY: u64 = 4 * 1024 * 1024 * 1024;

/// Upper bound on `aff4:chunkSize`. The AFF4 default is 32 KiB; no real image
/// uses a chunk anywhere near this. Bounding it caps the per-chunk decompress
/// buffer so hostile metadata cannot drive a multi-GiB allocation, and (with the
/// zero check) removes the divide-by-zero on `chunk_size`.
const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;

// --- Turtle metadata (lightweight, line-oriented) --------------------------

/// A minimal view of the turtle graph: subject URN -> predicate -> values.
/// Enough for AFF4's regular, tool-produced metadata; not a general RDF parser.
struct TurtleGraph {
    subjects: HashMap<String, HashMap<String, Vec<String>>>,
    /// The `^^datatype` suffix of each literal value, indexed exactly like
    /// `subjects` and aligned by position with the cleaned value in that
    /// predicate's Vec. `clean_value` throws the suffix away because most
    /// callers (`aff4:size`, `aff4:chunkSize`, ...) never care about it, but
    /// AFF4's generic `aff4:hash "<hex>"^^aff4:SHA256` predicate names its
    /// digest algorithm this way (HUNT-141), so it needs to be recoverable.
    datatypes: HashMap<String, HashMap<String, Vec<Option<String>>>>,
}

impl TurtleGraph {
    /// Parse turtle by tracking the current subject and reading
    /// `predicate value[ , value]* [;|.]` statements. Prefixed names are kept
    /// verbatim (e.g. `aff4:size`); URNs are unwrapped from `<...>`; the base
    /// subject `:` is expanded to `base`.
    fn parse(text: &str, base: &str) -> Self {
        let mut subjects: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let mut datatypes: HashMap<String, HashMap<String, Vec<Option<String>>>> = HashMap::new();
        let mut current: Option<String> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('@') || line.starts_with('#') {
                continue;
            }
            // A subject starts a block: `<urn>` or `:` optionally followed by
            // predicates on the same line.
            let (subject_tok, rest) = if let Some(r) = line.strip_prefix('<') {
                // `<urn> ...`
                if let Some(end) = r.find('>') {
                    (Some(unwrap_urn(&line[..end + 2])), r[end + 1..].trim())
                } else {
                    (None, line)
                }
            } else if line == ":" || line.starts_with(": ") || line.starts_with(":\t") {
                (Some(base.to_string()), line[1..].trim())
            } else {
                (None, line)
            };

            if let Some(subj) = subject_tok {
                current = Some(subj.clone());
                subjects.entry(subj.clone()).or_default();
                parse_predicates(
                    rest,
                    current.as_ref().unwrap(),
                    &mut subjects,
                    &mut datatypes,
                    base,
                );
            } else if let Some(subj) = current.clone() {
                parse_predicates(line, &subj, &mut subjects, &mut datatypes, base);
            }
        }
        TurtleGraph {
            subjects,
            datatypes,
        }
    }

    fn get(&self, subject: &str, predicate: &str) -> Option<&str> {
        self.subjects
            .get(subject)?
            .get(predicate)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// The `^^datatype` suffix of the first value on `subject`/`predicate`
    /// (e.g. `aff4:hash "<hex>"^^aff4:SHA256` -> `Some("aff4:SHA256")`), or
    /// `None` when that value has no datatype suffix at all.
    fn get_datatype(&self, subject: &str, predicate: &str) -> Option<&str> {
        self.datatypes
            .get(subject)?
            .get(predicate)?
            .first()
            .and_then(|d| d.as_deref())
    }

    fn get_all(&self, subject: &str, predicate: &str) -> Vec<String> {
        self.subjects
            .get(subject)
            .and_then(|m| m.get(predicate))
            .cloned()
            .unwrap_or_default()
    }

    /// First subject whose `a` (rdf:type) values include `type_name`.
    fn subject_of_type(&self, type_name: &str) -> Option<String> {
        self.subjects
            .iter()
            .find(|(_, preds)| {
                preds
                    .get("a")
                    .map(|types| types.iter().any(|t| t == type_name))
                    .unwrap_or(false)
            })
            .map(|(s, _)| s.clone())
    }
}

/// Append `pred value` statements from one turtle line into the graph. Values
/// may be `<urn>`, prefixed names, or `"literal"^^type`; the trailing `;`/`.`
/// and datatype suffix are stripped.
fn parse_predicates(
    line: &str,
    subject: &str,
    subjects: &mut HashMap<String, HashMap<String, Vec<String>>>,
    datatypes: &mut HashMap<String, HashMap<String, Vec<Option<String>>>>,
    _base: &str,
) {
    let line = line.trim_end_matches([';', '.']).trim();
    if line.is_empty() {
        return;
    }
    let mut it = line.split_whitespace();
    let predicate = match it.next() {
        Some(p) => p.to_string(),
        None => return,
    };
    let remainder: String = it.collect::<Vec<_>>().join(" ");
    let entry = subjects
        .entry(subject.to_string())
        .or_default()
        .entry(predicate.clone())
        .or_default();
    let dt_entry = datatypes
        .entry(subject.to_string())
        .or_default()
        .entry(predicate)
        .or_default();
    for value in remainder.split(',') {
        let raw = value.trim();
        let v = clean_value(raw);
        if !v.is_empty() {
            entry.push(v);
            dt_entry.push(extract_datatype(raw));
        }
    }
}

/// Normalise a turtle object: unwrap `<urn>`, drop the `^^type` suffix, and
/// strip surrounding quotes.
fn clean_value(v: &str) -> String {
    let v = v.trim().trim_end_matches([';', '.']).trim();
    if let Some(inner) = v.strip_prefix('<') {
        if let Some(end) = inner.find('>') {
            return inner[..end].to_string();
        }
    }
    let v = v.split("^^").next().unwrap_or(v).trim();
    v.trim_matches('"').to_string()
}

/// The `^^datatype` suffix `clean_value` strips (e.g. `"<hex>"^^aff4:SHA256`
/// -> `Some("aff4:SHA256")`). `None` for a URN, a bare prefixed name, or a
/// literal with no datatype.
fn extract_datatype(v: &str) -> Option<String> {
    let v = v.trim().trim_end_matches([';', '.']).trim();
    if v.starts_with('<') {
        return None; // a URN object, not a literal
    }
    let mut parts = v.splitn(2, "^^");
    parts.next();
    parts.next().map(|d| d.trim().trim_matches('"').to_string())
}

fn unwrap_urn(tok: &str) -> String {
    tok.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

// --- Compression -----------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Compression {
    Snappy,
    Deflate,
    Stored,
}

impl Compression {
    fn from_urn(urn: &str) -> Compression {
        let u = urn.to_lowercase();
        if u.contains("snappy") {
            Compression::Snappy
        } else if u.contains("deflate") || u.contains("1951") || u.contains("zlib") {
            Compression::Deflate
        } else {
            Compression::Stored
        }
    }
}

/// Decompress one chunk. A chunk stored at its full uncompressed length is raw
/// (the writer keeps incompressible chunks verbatim), regardless of the stream's
/// nominal method.
fn decompress_chunk(comp: &[u8], expected: usize, method: Compression) -> Result<Vec<u8>> {
    if comp.len() == expected {
        return Ok(comp.to_vec());
    }
    let out = match method {
        Compression::Stored => comp.to_vec(),
        Compression::Snappy => {
            // Reject a frame that declares more than the expected chunk length
            // *before* decompress_vec allocates it (zip-bomb class): a valid
            // chunk always declares exactly `expected` uncompressed bytes.
            let declared = snap::raw::decompress_len(comp)
                .map_err(|e| anyhow!("snappy chunk header decode failed: {}", e))?;
            if declared != expected {
                return Err(anyhow!(
                    "snappy chunk declares {} bytes but {} were expected",
                    declared,
                    expected
                ));
            }
            snap::raw::Decoder::new()
                .decompress_vec(comp)
                .map_err(|e| anyhow!("snappy chunk decode failed: {}", e))?
        }
        Compression::Deflate => {
            // Bound the decompressed output at `expected + 1` so a deflate bomb
            // cannot grow the buffer without limit; the exact-length check below
            // then rejects any chunk that is not precisely `expected` bytes.
            let limit = expected as u64 + 1;
            let mut out = Vec::with_capacity(expected);
            let mut d = flate2::read::DeflateDecoder::new(comp).take(limit);
            if d.read_to_end(&mut out).is_err() {
                // Some writers use zlib-wrapped deflate.
                let mut z = flate2::read::ZlibDecoder::new(comp).take(limit);
                out.clear();
                z.read_to_end(&mut out)
                    .map_err(|e| anyhow!("deflate chunk decode failed: {}", e))?;
            }
            out
        }
    };
    // The decompressed chunk must be exactly the expected length. A short chunk
    // would be zero-padded to the chunk size downstream and read back as real
    // evidence; fail closed instead of fabricating the missing bytes.
    if out.len() != expected {
        return Err(anyhow!(
            "AFF4 chunk decompressed to {} bytes but {} were expected",
            out.len(),
            expected
        ));
    }
    Ok(out)
}

// --- ImageStream reader -----------------------------------------------------

struct Bevy {
    data: Vec<u8>,
    index: Vec<(u64, u32)>, // (offset into data, compressed length) per chunk
}

/// Reads and decompresses the chunks of one `aff4:ImageStream`.
struct ImageStreamReader {
    zip_path: String,
    zip_prefix: String, // URL-encoded URN prefix used for ZIP entry names
    chunk_size: u64,
    chunks_in_segment: u64,
    stream_size: u64,
    compression: Compression,
    bevies: Mutex<HashMap<u32, std::sync::Arc<Bevy>>>,
    // Single-entry cache of the last decompressed chunk (global index).
    last_chunk: Mutex<Option<(u64, std::sync::Arc<Vec<u8>>)>>,
}

impl std::fmt::Debug for ImageStreamReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageStreamReader")
            .field("stream_size", &self.stream_size)
            .field("chunk_size", &self.chunk_size)
            .finish()
    }
}

impl ImageStreamReader {
    fn bevy(&self, bevy_id: u32) -> Result<std::sync::Arc<Bevy>> {
        if let Some(b) = self
            .bevies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&bevy_id)
        {
            return Ok(b.clone());
        }
        let data = read_zip_entry(
            &self.zip_path,
            &format!("{}/{:08}", self.zip_prefix, bevy_id),
        )?;
        let index_name = format!("{}/{:08}.index", self.zip_prefix, bevy_id);
        let idx_raw = read_zip_entry(&self.zip_path, &index_name)?;
        let index = parse_bevy_index(&idx_raw, &index_name)?;
        let bevy = std::sync::Arc::new(Bevy { data, index });
        self.bevies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(bevy_id, bevy.clone());
        Ok(bevy)
    }

    /// Decompressed bytes of global chunk `chunk`.
    fn chunk(&self, chunk: u64) -> Result<std::sync::Arc<Vec<u8>>> {
        if let Some((c, data)) = self
            .last_chunk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            if *c == chunk {
                return Ok(data.clone());
            }
        }
        let bevy_id = (chunk / self.chunks_in_segment) as u32;
        let in_bevy = (chunk % self.chunks_in_segment) as usize;
        let bevy = self.bevy(bevy_id)?;
        let (off, len) = *bevy
            .index
            .get(in_bevy)
            .ok_or_else(|| anyhow!("chunk {} missing from bevy {}", chunk, bevy_id))?;
        let comp = bevy
            .data
            .get(off as usize..off as usize + len as usize)
            .ok_or_else(|| anyhow!("chunk {} data out of range", chunk))?;
        let base = chunk * self.chunk_size;
        let expected = self.chunk_size.min(self.stream_size.saturating_sub(base)) as usize;
        let out = std::sync::Arc::new(decompress_chunk(comp, expected, self.compression)?);
        *self.last_chunk.lock().unwrap_or_else(|e| e.into_inner()) = Some((chunk, out.clone()));
        Ok(out)
    }

    /// Read into `buf` starting at logical offset `off` within this stream.
    fn read_into(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let p = off + done as u64;
            if p >= self.stream_size {
                // A read landing past the ImageStream end can only come from a
                // corrupt/hostile map entry. Zero-filling here would surface
                // fabricated bytes as imaged zeros; fail closed instead.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "AFF4 map reads past ImageStream end: offset {} >= stream size {}",
                        p, self.stream_size
                    ),
                ));
            }
            let chunk = p / self.chunk_size;
            let coff = (p % self.chunk_size) as usize;
            let data = self
                .chunk(chunk)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            if coff >= data.len() {
                // The decompressed chunk is shorter than the in-chunk offset the
                // map points at (structurally impossible for a sound image, since
                // decompress_chunk guarantees the exact expected length). Never
                // pad with zeros; fail closed.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "AFF4 chunk {} is {} bytes but map needs in-chunk offset {}",
                        chunk,
                        data.len(),
                        coff
                    ),
                ));
            }
            let n = (data.len() - coff).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&data[coff..coff + n]);
            done += n;
        }
        Ok(())
    }
}

// --- Map + symbolic targets -------------------------------------------------

/// Repeating marker served for `aff4:UnreadableData` regions — bytes the imager
/// asked the device for and did not get back. It is deliberately not zeros: a
/// zero-filled bad sector is byte-for-byte identical to a sector that genuinely
/// held zeros, and once it reaches a file hash, an export or a preview there is
/// nothing left to tell them apart. pyaff4 serves a repeating textual pattern
/// for exactly this reason; this matches that intent.
const UNREADABLE_PATTERN: &[u8] = b"UNREADABLEDATA";

/// Repeating marker served for `aff4:UnknownData` regions — ranges the image
/// never covered at all. Same reasoning as [`UNREADABLE_PATTERN`].
const UNKNOWN_PATTERN: &[u8] = b"UNKNOWNDATA";

/// How bytes are produced for a region that is not imaged evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    /// A constant byte: `aff4:Zero`, `aff4:SymbolicStream<HH>`. These are
    /// deliberate, spec-defined constant streams and mean what they say.
    Byte(u8),
    /// A repeating pattern marking bytes that are NOT evidence.
    Pattern(&'static [u8]),
}

impl Fill {
    /// Write this fill into `buf`, phase-aligned to the logical image offset
    /// `pos` so a given offset always yields the same byte no matter how the
    /// read was split up (hashing and re-reads must agree).
    fn write(self, pos: u64, buf: &mut [u8]) {
        match self {
            Fill::Byte(b) => buf.fill(b),
            Fill::Pattern(p) => {
                debug_assert!(!p.is_empty());
                for (i, x) in buf.iter_mut().enumerate() {
                    *x = p[((pos + i as u64) % p.len() as u64) as usize];
                }
            }
        }
    }
}

#[derive(Debug)]
enum Target {
    Image(std::sync::Arc<ImageStreamReader>),
    Symbolic(u8),
    /// `aff4:UnreadableData` — the imager tried to read this range and the
    /// device refused. Served as [`UNREADABLE_PATTERN`], never as zeros, and
    /// counted into the source's coverage so the container artifact can say so.
    Unreadable,
    /// `aff4:UnknownData` — this range was never imaged. Served as
    /// [`UNKNOWN_PATTERN`], never as zeros, and counted into coverage.
    UnknownData,
    /// A target URN we could not resolve to a stream or symbolic constant. A
    /// read that lands on it fails closed rather than fabricating zeros.
    Unknown(String),
}

impl Target {
    /// Resolve a target URN to either an image-stream reader or a constant-byte
    /// symbolic stream. An unrecognised URN becomes [`Target::Unknown`] so a
    /// read covering it fails closed instead of silently returning zeros.
    fn resolve(urn: &str, streams: &HashMap<String, std::sync::Arc<ImageStreamReader>>) -> Target {
        if let Some(s) = streams.get(urn) {
            return Target::Image(s.clone());
        }
        let lower = urn.to_lowercase();
        // The Zero symbolic stream is referenced by several URN spellings:
        // `http://aff4.org/Schema#Zero`, the prefixed `aff4:Zero`, and the URN
        // form `aff4://Zero`. Match the local name after any `#`, `/` or `:`.
        if lower.ends_with("#zero")
            || lower.ends_with("/zero")
            || lower.ends_with(":zero")
            || lower.ends_with("symbolicstream00")
        {
            return Target::Symbolic(0x00);
        }
        if lower.ends_with("symbolicstreamff") {
            return Target::Symbolic(0xFF);
        }
        // Regions the imager could not read, and regions never imaged at all.
        // These are NOT constant streams and must not be served as zeros: an
        // all-zero bad sector is indistinguishable from a sector that really
        // held zeros once it has flowed into a hash or an export.
        if lower.ends_with("unreadabledata") {
            return Target::Unreadable;
        }
        if lower.ends_with("unknowndata") {
            return Target::UnknownData;
        }
        // aff4://.../SymbolicStream<HH> -> repeating byte 0xHH.
        if let Some(idx) = lower.rfind("symbolicstream") {
            let hh = &urn[idx + "symbolicstream".len()..];
            if hh.len() == 2 {
                if let Ok(b) = u8::from_str_radix(hh, 16) {
                    return Target::Symbolic(b);
                }
            }
        }
        warn!(
            "AFF4 map target {} is unknown; a read covering it will fail closed",
            urn
        );
        Target::Unknown(urn.to_string())
    }

    /// The fill this target serves, for the targets that are not real bytes.
    fn fill(&self) -> Option<Fill> {
        match self {
            Target::Symbolic(b) => Some(Fill::Byte(*b)),
            Target::Unreadable => Some(Fill::Pattern(UNREADABLE_PATTERN)),
            Target::UnknownData => Some(Fill::Pattern(UNKNOWN_PATTERN)),
            Target::Image(_) | Target::Unknown(_) => None,
        }
    }
}

#[derive(Debug)]
struct MapEntry {
    map_off: u64,
    length: u64,
    target_off: u64,
    target_id: u32,
}

/// How much of the logical image is something other than imaged evidence.
///
/// Every counter here is a range an examiner must not read as "the device held
/// these bytes". They are measured from the map at open time so the container
/// artifact can carry the standard incompleteness pair, rather than the fact
/// living only in the bytes a preview happens to render.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aff4Coverage {
    /// Bytes the imager attempted and could not read (`aff4:UnreadableData`).
    pub unreadable_bytes: u64,
    /// Bytes that were never imaged (`aff4:UnknownData`).
    pub unknown_bytes: u64,
    /// Bytes covered by no map entry at all: served as the declared
    /// `aff4:mapGapDefaultStream`, which is not evidence either.
    pub unmapped_bytes: u64,
    /// Bytes whose map target URN could not be bound to any stream. Reads over
    /// these fail closed, so the image cannot be served in full.
    pub unresolved_bytes: u64,
    /// Streams / sibling containers that could not be opened while binding the
    /// map's targets. A spanned set missing a container under-maps silently
    /// without this.
    pub stream_bind_failures: Vec<String>,
}

impl Aff4Coverage {
    /// True when some part of the logical image is not imaged evidence.
    pub fn has_non_evidence_regions(&self) -> bool {
        self.unreadable_bytes > 0
            || self.unknown_bytes > 0
            || self.unmapped_bytes > 0
            || self.unresolved_bytes > 0
    }

    /// Total bytes of the logical image that are not imaged evidence.
    pub fn non_evidence_bytes(&self) -> u64 {
        self.unreadable_bytes
            .saturating_add(self.unknown_bytes)
            .saturating_add(self.unmapped_bytes)
            .saturating_add(self.unresolved_bytes)
    }
}

/// Measure how much of `size` is covered by real stream bytes and how much is
/// unreadable / unknown / unmapped / unresolved.
///
/// `entries` must be sorted by `map_off`. Overlapping entries are attributed to
/// whichever entry claims the range first, so the totals never exceed `size`.
///
/// `gap` is the declared `aff4:mapGapDefaultStream`, which decides what the
/// ranges no entry covers actually are. A constant/marker gap stream means those
/// ranges were never imaged; a gap stream that is a real `aff4:ImageStream` —
/// the differential-image case, where uncovered ranges come from a base image —
/// means they are evidence and must not be counted against the image.
fn measure_coverage(
    size: u64,
    entries: &[MapEntry],
    targets: &[Target],
    gap: &Target,
) -> Aff4Coverage {
    let mut cov = Aff4Coverage::default();
    let mut gap_bytes = 0u64;
    let mut cursor = 0u64; // first logical offset not yet accounted for
    for e in entries {
        let start = e.map_off.min(size);
        let end = e.map_off.saturating_add(e.length).min(size);
        if start > cursor {
            gap_bytes += start - cursor;
            cursor = start;
        }
        if end > cursor {
            let n = end - cursor;
            match targets.get(e.target_id as usize) {
                Some(Target::Unreadable) => cov.unreadable_bytes += n,
                Some(Target::UnknownData) => cov.unknown_bytes += n,
                // A dangling target id and an unbindable URN both mean the same
                // thing to an examiner: these bytes cannot be produced.
                Some(Target::Unknown(_)) | None => cov.unresolved_bytes += n,
                Some(Target::Image(_)) | Some(Target::Symbolic(_)) => {}
            }
            cursor = end;
        }
    }
    if cursor < size {
        gap_bytes += size - cursor;
    }
    match gap {
        // The gap default is a real stream: those ranges carry imaged bytes.
        Target::Image(_) => {}
        // The gap default could not be bound at all, so the ranges it covers
        // cannot be produced — a read over one fails closed.
        Target::Unknown(_) => cov.unresolved_bytes = cov.unresolved_bytes.saturating_add(gap_bytes),
        Target::Symbolic(_) | Target::Unreadable | Target::UnknownData => {
            cov.unmapped_bytes = cov.unmapped_bytes.saturating_add(gap_bytes)
        }
    }
    cov
}

// --- Hash predicates (HUNT-141) ---------------------------------------------

/// Digest predicates this reader recognises on an AFF4 subject: an
/// algorithm-named predicate (`aff4:sha256`/`aff4:sha1`/`aff4:md5`, matched
/// case-insensitively on the predicate's local name — the part after the last
/// `:`) or the standard's generic `aff4:hash`, whose literal names the
/// algorithm through its `^^datatype` (e.g. `"<hex>"^^aff4:SHA256`).
///
/// Nothing in this repository's AFF4 reference material (`reference/`,
/// `documentation/`) pins one authoritative predicate spelling — c-aff4,
/// pyaff4 and Evimetry are not consistent with each other — so this supports
/// the plausible set (`aff4:hash`, `aff4:sha256`, `aff4:sha1`, `aff4:md5`)
/// rather than asserting a single true spelling. That is a guess and stays
/// labelled as one in the module documentation, not asserted as certain.
///
/// Returns every distinct algorithm found (a container may record more than
/// one), never fabricating one algorithm's digest from another's.
fn find_hashes(graph: &TurtleGraph, subject: &str) -> Vec<(&'static str, String)> {
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Some(preds) = graph.subjects.get(subject) else {
        return found;
    };
    for predicate in preds.keys() {
        let local = predicate
            .rsplit(':')
            .next()
            .unwrap_or(predicate)
            .to_lowercase();
        let algo = if local.ends_with("sha256") {
            Some("sha256")
        } else if local.ends_with("sha1") {
            Some("sha1")
        } else if local.ends_with("md5") {
            Some("md5")
        } else if local.ends_with("hash") {
            graph
                .get_datatype(subject, predicate)
                .and_then(algorithm_from_datatype)
        } else {
            None
        };
        let Some(algo) = algo else { continue };
        let Some(value) = graph.get(subject, predicate) else {
            continue;
        };
        let hex = value.trim().to_lowercase();
        if !hex.is_empty() && seen.insert(algo) {
            found.push((algo, hex));
        }
    }
    found
}

/// The digest algorithm named by a turtle datatype suffix, e.g.
/// `aff4:SHA256` or `http://aff4.org/Schema#SHA256` -> `"sha256"`.
fn algorithm_from_datatype(datatype: &str) -> Option<&'static str> {
    let d = datatype.to_lowercase();
    if d.ends_with("sha256") {
        Some("sha256")
    } else if d.ends_with("sha1") {
        Some("sha1")
    } else if d.ends_with("md5") {
        Some("md5")
    } else {
        None
    }
}

/// The logical AFF4 image behind a [`DataSource`]: a sorted map of ranges onto
/// image streams and symbolic streams.
#[derive(Debug)]
pub struct Aff4DataSource {
    size: u64,
    entries: Vec<MapEntry>, // sorted by map_off
    targets: Vec<Target>,   // indexed by target_id
    /// The declared `aff4:mapGapDefaultStream` (typically `aff4:Zero`), served
    /// for logical ranges no map entry covers. Held as a resolved [`Target`]
    /// rather than a fill byte so a gap default that names a real stream (a
    /// differential image over a base) is read from, and one that cannot be
    /// resolved at all fails the read closed instead of degrading to zeros.
    gap_target: Target,
    coverage: Aff4Coverage,
    /// Digest(s) the container's turtle graph recorded for this image/stream
    /// (HUNT-141): `(algorithm, lowercase hex)` pairs this reader recognised.
    /// Empty means the graph carried no hash predicate this reader
    /// recognised at all — `process()` must say so explicitly rather than
    /// leave the absence silent.
    hashes: Vec<(&'static str, String)>,
}

impl Aff4DataSource {
    pub fn open(path: &str) -> Result<Aff4DataSource> {
        let base = read_zip_entry(path, "container.description")
            .ok()
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_default();
        let turtle_bytes = read_zip_entry(path, "information.turtle")
            .map_err(|e| anyhow!("AFF4 information.turtle unreadable: {}", e))?;
        let turtle = String::from_utf8_lossy(&turtle_bytes);
        let graph = TurtleGraph::parse(&turtle, &base);

        // Top-level image: an aff4:Image / aff4:DiskImage / aff4:ContiguousImage.
        let image = graph
            .subject_of_type("aff4:Image")
            .or_else(|| graph.subject_of_type("aff4:DiskImage"))
            .or_else(|| graph.subject_of_type("aff4:ContiguousImage"))
            .ok_or_else(|| anyhow!("no aff4:Image in turtle metadata"))?;
        let size: u64 = graph
            .get(&image, "aff4:size")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("aff4:Image has no size"))?;
        let data_stream = graph
            .get(&image, "aff4:dataStream")
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("aff4:Image has no dataStream"))?;

        // HUNT-141: the acquisition-recorded digest(s), if the container's
        // turtle graph carries any at all — checked on the image subject
        // first (where AFF4 tools conventionally record it), falling back to
        // the data-stream subject. An empty result is itself meaningful:
        // `process()` reports "not recorded in container" rather than
        // silently omitting stored_md5/stored_sha1.
        let mut hashes = find_hashes(&graph, &image);
        if hashes.is_empty() {
            hashes = find_hashes(&graph, &data_stream);
        }

        // Collect every image stream so map targets can bind to them. For
        // striped / spanned images the streams are split across sibling
        // containers, so scan every .aff4 file in the same directory and bind
        // each stream to the container that actually stores its first bevy.
        let mut streams: HashMap<String, std::sync::Arc<ImageStreamReader>> = HashMap::new();
        // Every stream we could NOT bind is recorded rather than skipped. A
        // spanned set whose second container will not open otherwise under-maps
        // in silence: the map still resolves, the missing ranges just stop being
        // servable, and nothing anywhere says a container was missing (B7-029).
        let mut bind_failures: Vec<String> = Vec::new();
        for file in sibling_aff4_files(path) {
            let names = match zip_entry_names(&file) {
                Ok(n) => n,
                Err(e) => {
                    bind_failures.push(format!("{file}: ZIP directory unreadable: {e}"));
                    continue;
                }
            };
            let file_graph = if file == path {
                None // reuse the already-parsed primary graph below
            } else {
                match read_zip_entry(&file, "information.turtle") {
                    Ok(b) => Some(TurtleGraph::parse(&String::from_utf8_lossy(&b), "")),
                    Err(e) => {
                        bind_failures.push(format!("{file}: information.turtle unreadable: {e}"));
                        continue;
                    }
                }
            };
            let g = file_graph.as_ref().unwrap_or(&graph);
            for (urn, preds) in g.subjects.iter() {
                let is_stream = preds
                    .get("a")
                    .map(|t| t.iter().any(|x| x == "aff4:ImageStream"))
                    .unwrap_or(false);
                if !is_stream || streams.contains_key(urn) {
                    continue;
                }
                // Bind only to the container that holds this stream's bevy data.
                let bevy0 = format!("{}/00000000", urn_to_zip_prefix(urn));
                if names.contains(&bevy0) {
                    match build_image_stream(&file, urn, g) {
                        Ok(reader) => {
                            streams.insert(urn.clone(), std::sync::Arc::new(reader));
                        }
                        Err(e) => {
                            bind_failures.push(format!("{urn} in {file}: {e}"));
                        }
                    }
                }
            }
        }
        if !bind_failures.is_empty() {
            warn!(
                "AFF4 {}: {} image stream(s)/container(s) could not be bound",
                path,
                bind_failures.len()
            );
        }

        // The data stream is either a Map or an ImageStream.
        let is_map = graph
            .get_all(&data_stream, "a")
            .iter()
            .any(|t| t == "aff4:Map");

        if is_map {
            let gap_urn = graph
                .get(&data_stream, "aff4:mapGapDefaultStream")
                .unwrap_or("aff4:Zero");
            // What an unmapped range reads as is declared by the container, and
            // that declaration is honoured as written: a symbolic constant is
            // filled, a real `aff4:ImageStream` (a differential image over a
            // base) is read from, and a URN that resolves to nothing fails the
            // covering read closed rather than degrading to 0x00 — 0x00 is
            // itself a legal thing for a container to declare, so guessing it
            // would make an unmet declaration indistinguishable from a met one.
            //
            // The failure is deferred to the read that actually lands in a gap.
            // Refusing to open would throw away an image whose map covers every
            // byte, where the declaration is never consulted at all.
            let gap_target = Target::resolve(gap_urn, &streams);
            let (entries, targets) = load_map(path, &data_stream, &streams)?;
            let mut coverage = measure_coverage(size, &entries, &targets, &gap_target);
            coverage.stream_bind_failures = bind_failures;
            if coverage.unresolved_bytes > 0 && matches!(gap_target, Target::Unknown(_)) {
                warn!(
                    "AFF4 {}: mapGapDefaultStream {} could not be resolved and the map leaves \
                     gaps; reads over them will fail closed",
                    path, gap_urn
                );
            }
            Ok(Aff4DataSource {
                size,
                entries,
                targets,
                gap_target,
                coverage,
                hashes,
            })
        } else {
            // Direct image stream: one identity map entry over the whole image.
            let reader = streams.get(&data_stream).cloned().ok_or_else(|| {
                anyhow!("dataStream {} is neither Map nor ImageStream", data_stream)
            })?;
            Ok(Aff4DataSource {
                size,
                entries: vec![MapEntry {
                    map_off: 0,
                    length: size,
                    target_off: 0,
                    target_id: 0,
                }],
                targets: vec![Target::Image(reader)],
                gap_target: Target::Symbolic(0),
                coverage: Aff4Coverage {
                    stream_bind_failures: bind_failures,
                    ..Aff4Coverage::default()
                },
                hashes,
            })
        }
    }

    /// Digest(s) the AFF4 container's turtle graph recorded for this
    /// image/stream (HUNT-141): `(algorithm, lowercase hex)` pairs, e.g.
    /// `[("md5", "d41d8cd9...")]`. Empty means the graph carried no hash
    /// predicate this reader recognised — see [`find_hashes`] for exactly
    /// which spellings that covers.
    pub fn hash_baseline(&self) -> &[(&'static str, String)] {
        &self.hashes
    }

    /// How much of the logical image is not imaged evidence. The container
    /// module stamps this onto the emitted artifact.
    pub fn coverage(&self) -> &Aff4Coverage {
        &self.coverage
    }

    /// Assemble a source straight from a map, for tests that exercise `read_at`
    /// without building a whole container. Gaps fill with zero, matching the
    /// default `aff4:Zero` gap stream.
    #[cfg(test)]
    fn for_test(size: u64, entries: Vec<MapEntry>, targets: Vec<Target>) -> Aff4DataSource {
        Self::for_test_with_gap(size, entries, targets, Target::Symbolic(0))
    }

    /// As [`Aff4DataSource::for_test`] but with an explicit
    /// `aff4:mapGapDefaultStream` target, for the gap-handling tests.
    #[cfg(test)]
    fn for_test_with_gap(
        size: u64,
        entries: Vec<MapEntry>,
        targets: Vec<Target>,
        gap_target: Target,
    ) -> Aff4DataSource {
        let coverage = measure_coverage(size, &entries, &targets, &gap_target);
        Aff4DataSource {
            size,
            entries,
            targets,
            gap_target,
            coverage,
            hashes: Vec::new(),
        }
    }

    /// Index of the entry whose range covers `pos`, if any (binary search).
    fn entry_covering(&self, pos: u64) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entries.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.entries[mid].map_off <= pos {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let e = &self.entries[lo - 1];
        // `saturating_add` so a corrupt entry whose map_off + length wraps u64 is
        // treated as covering `pos`; `read_at` then fails closed on the overflow
        // rather than this misclassifying it as an uncovered gap (zero-fill).
        if pos < e.map_off.saturating_add(e.length) {
            Some(lo - 1)
        } else {
            None
        }
    }

    /// Start offset of the first entry beginning after `pos` (gap end).
    fn next_entry_after(&self, pos: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.map_off > pos)
            .map(|e| e.map_off)
    }
}

/// Produce the bytes a resolved [`Target`] serves for one contiguous run.
///
/// `logical_pos` is the offset in the logical image (it phases the marker fills
/// so a given offset always yields the same byte however a read is split);
/// `target_off` is the offset within the target stream. `what` names the
/// declaration being honoured, so an error says which one could not be met.
fn serve_target(
    target: &Target,
    logical_pos: u64,
    target_off: u64,
    buf: &mut [u8],
    what: &str,
) -> std::io::Result<()> {
    match target {
        Target::Image(reader) => reader.read_into(target_off, buf),
        Target::Symbolic(_) | Target::Unreadable | Target::UnknownData => {
            // Symbolic constants are real declarations; the unreadable/unknown
            // fills are recognisable markers so an examiner can see the bytes
            // are not evidence.
            let fill = target.fill().expect("non-image target has a fill");
            fill.write(logical_pos, buf);
            Ok(())
        }
        Target::Unknown(urn) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "AFF4 {} references unresolved target {}; refusing to fabricate zeros",
                what, urn
            ),
        )),
    }
}

impl DataSource for Aff4DataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = (self.size - offset).min(buf.len() as u64) as usize;
        let mut filled = 0usize;
        while filled < want {
            let pos = offset + filled as u64;
            match self.entry_covering(pos) {
                Some(i) => {
                    let e = &self.entries[i];
                    // A corrupt/hostile map entry can carry offsets/lengths near
                    // u64::MAX. Unchecked adds would wrap and serve wrong image
                    // bytes (or a huge `n`); compute the range with checked
                    // arithmetic and fail closed on overflow instead.
                    let seg_end = e.map_off.checked_add(e.length).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "AFF4 map entry range overflows: map_off {} + length {}",
                                e.map_off, e.length
                            ),
                        )
                    })?;
                    let seg_left = (seg_end - pos) as usize;
                    let n = seg_left.min(want - filled);
                    let toff = e.target_off.checked_add(pos - e.map_off).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "AFF4 map entry target offset overflows: target_off {} + {}",
                                e.target_off,
                                pos - e.map_off
                            ),
                        )
                    })?;
                    // A corrupt/hostile map entry can reference a target index
                    // past the idx table. Bounds-check instead of indexing (which
                    // would panic inside a DataSource read); a dangling target is
                    // a structural error, not something to paper over with zeros.
                    let target = self.targets.get(e.target_id as usize).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "AFF4 map entry references target {} but only {} targets exist",
                                e.target_id,
                                self.targets.len()
                            ),
                        )
                    })?;
                    serve_target(target, pos, toff, &mut buf[filled..filled + n], "map entry")?;
                    filled += n;
                }
                None => {
                    let gap_end = self.next_entry_after(pos).unwrap_or(self.size);
                    let n = ((gap_end - pos) as usize).min(want - filled);
                    // A range no entry covers reads as the container's declared
                    // `aff4:mapGapDefaultStream`, at the same logical offset.
                    serve_target(
                        &self.gap_target,
                        pos,
                        pos,
                        &mut buf[filled..filled + n],
                        "mapGapDefaultStream",
                    )?;
                    filled += n;
                }
            }
        }
        Ok(filled)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

fn build_image_stream(zip_path: &str, urn: &str, graph: &TurtleGraph) -> Result<ImageStreamReader> {
    let chunk_size: u64 = graph
        .get(urn, "aff4:chunkSize")
        .and_then(|s| s.parse().ok())
        .unwrap_or(32768);
    // An explicit `aff4:chunkSize` of 0 parses to Some(0) and bypasses the
    // default above; it would divide-by-zero in `chunk`/`read_into`. Reject 0
    // and absurd sizes (allocation bound) — fail closed rather than panic.
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(anyhow!(
            "AFF4 ImageStream {} has invalid chunkSize {} (must be 1..={})",
            urn,
            chunk_size,
            MAX_CHUNK_SIZE
        ));
    }
    let chunks_in_segment: u64 = graph
        .get(urn, "aff4:chunksInSegment")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2048);
    // Zero would divide-by-zero when mapping a chunk to its bevy.
    if chunks_in_segment == 0 {
        return Err(anyhow!(
            "AFF4 ImageStream {} has invalid chunksInSegment 0",
            urn
        ));
    }
    let stream_size: u64 = graph
        .get(urn, "aff4:size")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("ImageStream {} has no size", urn))?;
    let compression = graph
        .get(urn, "aff4:compressionMethod")
        .map(Compression::from_urn)
        .unwrap_or(Compression::Stored);
    Ok(ImageStreamReader {
        zip_path: zip_path.to_string(),
        zip_prefix: urn_to_zip_prefix(urn),
        chunk_size,
        chunks_in_segment,
        stream_size,
        compression,
        bevies: Mutex::new(HashMap::new()),
        last_chunk: Mutex::new(None),
    })
}

fn load_map(
    zip_path: &str,
    map_urn: &str,
    streams: &HashMap<String, std::sync::Arc<ImageStreamReader>>,
) -> Result<(Vec<MapEntry>, Vec<Target>)> {
    let prefix = urn_to_zip_prefix(map_urn);
    let idx_raw = read_zip_entry(zip_path, &format!("{}/idx", prefix))?;
    let targets: Vec<Target> = String::from_utf8_lossy(&idx_raw)
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|urn| Target::resolve(urn, streams))
        .collect();

    let map_raw = read_zip_entry(zip_path, &format!("{}/map", prefix))?;
    let mut entries = parse_map_records(&map_raw, map_urn)?;
    entries.sort_by_key(|e| e.map_off);
    Ok((entries, targets))
}

/// Bytes per AFF4 map record: `u64 mapOffset, u64 length, u64 targetOffset,
/// u32 targetId`.
const MAP_RECORD_LEN: usize = 28;

/// Bytes per AFF4 bevy index record: `u64 offset, u32 length`.
const BEVY_INDEX_RECORD_LEN: usize = 12;

/// Parse the `<map>` segment into its records.
///
/// A map segment is a whole number of 28-byte records by construction. Trailing
/// bytes mean the segment was truncated, and the records that did not survive
/// are ranges of the image: dropping them silently would leave those offsets
/// uncovered, and uncovered offsets read as `mapGapDefaultStream` fill. The
/// examiner would then be shown a run of zero (or constant) bytes as if that
/// were what the evidence contained. Fail closed instead — a container that
/// cannot describe its own layout must not be served as an image.
fn parse_map_records(map_raw: &[u8], map_urn: &str) -> Result<Vec<MapEntry>> {
    let remainder = map_raw.len() % MAP_RECORD_LEN;
    if remainder != 0 {
        return Err(anyhow!(
            "AFF4 map for {} is {} bytes: {} trailing byte(s) past the last whole {}-byte record. \
             The map is truncated; the ranges it omits would be served as gap fill rather than \
             evidence",
            map_urn,
            map_raw.len(),
            remainder,
            MAP_RECORD_LEN
        ));
    }
    let mut entries = Vec::with_capacity(map_raw.len() / MAP_RECORD_LEN);
    for rec in map_raw.as_chunks::<MAP_RECORD_LEN>().0 {
        entries.push(MapEntry {
            map_off: u64::from_le_bytes(rec[0..8].try_into().unwrap()),
            length: u64::from_le_bytes(rec[8..16].try_into().unwrap()),
            target_off: u64::from_le_bytes(rec[16..24].try_into().unwrap()),
            target_id: u32::from_le_bytes(rec[24..28].try_into().unwrap()),
        });
    }
    Ok(entries)
}

/// Parse a bevy `.index` segment into `(offset, length)` per chunk.
///
/// Same contract as [`parse_map_records`]: a partial trailing record means the
/// index is truncated, and a chunk whose index entry is missing cannot be
/// located at all. Silently dropping it would make the tail of the bevy
/// unreadable while the image still claimed its full size.
fn parse_bevy_index(idx_raw: &[u8], segment_name: &str) -> Result<Vec<(u64, u32)>> {
    let remainder = idx_raw.len() % BEVY_INDEX_RECORD_LEN;
    if remainder != 0 {
        return Err(anyhow!(
            "AFF4 bevy index {} is {} bytes: {} trailing byte(s) past the last whole {}-byte \
             record. The index is truncated and the chunks it omits cannot be located",
            segment_name,
            idx_raw.len(),
            remainder,
            BEVY_INDEX_RECORD_LEN
        ));
    }
    let mut index = Vec::with_capacity(idx_raw.len() / BEVY_INDEX_RECORD_LEN);
    for rec in idx_raw.as_chunks::<BEVY_INDEX_RECORD_LEN>().0 {
        index.push((
            u64::from_le_bytes(rec[0..8].try_into().unwrap()),
            u32::from_le_bytes(rec[8..12].try_into().unwrap()),
        ));
    }
    Ok(index)
}

/// AFF4 stores segments under the URL-encoded stream URN. Only `:` and `/`
/// differ from the raw URN.
fn urn_to_zip_prefix(urn: &str) -> String {
    urn.replace(':', "%3A").replace('/', "%2F")
}

/// The container `path` plus any other `.aff4` files in the same directory
/// (for striped / spanned image sets). The primary is returned first.
fn sibling_aff4_files(path: &str) -> Vec<String> {
    let mut files = vec![path.to_string()];
    if let Some(dir) = std::path::Path::new(path).parent() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let is_aff4 = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("aff4"))
                    .unwrap_or(false);
                if is_aff4 {
                    let s = p.to_string_lossy().to_string();
                    if s != path {
                        files.push(s);
                    }
                }
            }
        }
    }
    files
}

/// Names of every entry in a ZIP container.
/// An entry's name. `zip` 9 reports a name it cannot decode as an error; the entry is still listed,
/// under the lossy reading of its raw bytes, rather than dropped from the container's inventory.
fn entry_name<R: std::io::Read>(f: &zip::read::ZipFile<'_, R>) -> String {
    f.name()
        .map(|n| n.into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(f.name_raw()).into_owned())
}

fn zip_entry_names(zip_path: &str) -> Result<std::collections::HashSet<String>> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut names = std::collections::HashSet::with_capacity(archive.len());
    for i in 0..archive.len() {
        if let Ok(f) = archive.by_index(i) {
            names.insert(entry_name(&f));
        }
    }
    Ok(names)
}

/// Read a single ZIP entry fully into memory, hard-capped at [`MAX_ZIP_ENTRY`].
fn read_zip_entry(zip_path: &str, entry: &str) -> Result<Vec<u8>> {
    read_zip_entry_capped(zip_path, entry, MAX_ZIP_ENTRY)
}

/// Read a single ZIP entry, capping the in-memory materialisation at `cap`
/// bytes. The pre-allocation is bounded regardless of the entry's claimed
/// uncompressed size, and one byte past `cap` is read so an over-cap (zip-bomb)
/// entry fails closed instead of being silently truncated. (`cap` is a parameter
/// only so the cap behaviour is testable without allocating gigabytes.)
fn read_zip_entry_capped(zip_path: &str, entry: &str, cap: u64) -> Result<Vec<u8>> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;
    let f = archive
        .by_name(entry)
        .map_err(|_| anyhow!("AFF4 segment {} not found", entry))?;
    let mut buf = Vec::with_capacity(f.size().min(64 * 1024 * 1024) as usize);
    f.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(anyhow!("AFF4 segment {} exceeds {}-byte cap", entry, cap));
    }
    Ok(buf)
}

// --- Module -----------------------------------------------------------------

impl Aff4ContainerModule {
    fn is_aff4_file(&self, name: &str) -> bool {
        name.to_lowercase().ends_with(".aff4")
    }

    /// Surface-level container metadata (file list, turtle presence, version).
    fn extract_aff4_metadata(&self, path: &str) -> Result<serde_json::Value> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        let mut metadata = json!({
            "container_type": "AFF4",
            "files_in_container": archive.len(),
        });

        if let Ok(mut info_file) = archive.by_name("information.turtle") {
            let mut contents = String::new();
            info_file.read_to_string(&mut contents)?;
            metadata["turtle_metadata_size"] = json!(contents.len());
            if contents.contains("aff4:ImageStream") {
                metadata["contains_image_stream"] = json!(true);
            }
            if contents.contains("aff4:Map") {
                metadata["contains_map"] = json!(true);
            }
        }

        if let Ok(mut version_file) = archive.by_name("version.txt") {
            let mut version = String::new();
            version_file.read_to_string(&mut version)?;
            metadata["aff4_version"] = json!(version.trim());
        }

        let mut file_list = Vec::new();
        for i in 0..archive.len() {
            if let Ok(file) = archive.by_index(i) {
                file_list.push(entry_name(&file));
            }
        }
        metadata["container_files"] = json!(file_list);
        Ok(metadata)
    }
}

impl ForensicsModule for Aff4ContainerModule {
    fn id(&self) -> &str {
        "container.aff4_reader"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::FilePath
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if let Some(subtype) = artifact.subtype() {
            if subtype != "aff4" {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if artifact.subtype().is_none() && !self.is_aff4_file(name) {
            return Ok(Vec::new());
        }

        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ModuleError::InvalidInputFormat("AFF4 module requires file path".to_string())
            })?;

        info!("AFF4ContainerModule processing: {}", name);

        let aff4_metadata = self.extract_aff4_metadata(path).map_err(|e| {
            ModuleError::ParsingError(format!("Failed to extract AFF4 metadata: {}", e))
        })?;

        let source = Aff4DataSource::open(path)
            .map_err(|e| ModuleError::ParsingError(format!("Failed to open AFF4 image: {}", e)))?;
        let size = source.size();
        let coverage = source.coverage().clone();
        let hashes = source.hash_baseline().to_vec();

        let mut metadata = json!({
            "name": format!("{}_extracted", name),
            "size": size,
            "subtype": "raw",
            "container": "aff4",
            "container_path": path,
            "path": path,
            "aff4_metadata": aff4_metadata,
        });

        // Ranges the imager could not read, never imaged, or could not bind are
        // served as recognisable markers rather than zeros — but a marker inside
        // the bytes is not a disclosure. State it in the artifact metadata, with
        // the standard pair, so hashing, export and the completeness census all
        // see that this image is not wholly imaged evidence (B4-017/B7-029).
        if coverage.has_non_evidence_regions() {
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str());
            metadata["aff4_unreadable_bytes"] = json!(coverage.unreadable_bytes);
            metadata["aff4_unknown_bytes"] = json!(coverage.unknown_bytes);
            metadata["aff4_unmapped_bytes"] = json!(coverage.unmapped_bytes);
            metadata["aff4_unresolved_bytes"] = json!(coverage.unresolved_bytes);
            metadata["aff4_non_evidence_bytes"] = json!(coverage.non_evidence_bytes());
            metadata["message"] = json!(
                "Part of this AFF4 image is not imaged evidence: ranges the imager could not \
                 read, ranges never imaged, or ranges no map target could be bound to. Those \
                 bytes are served as recognisable markers, not as device content"
            );
        }
        if !coverage.stream_bind_failures.is_empty() {
            metadata["inventory_incomplete"] = json!(true);
            // A flag with no reason beside it renders as "no reason was
            // recorded" and is skipped by every reason-keyed consumer.
            metadata["inventory_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str());
            metadata["stream_bind_failures"] = json!(coverage.stream_bind_failures);
        }

        // HUNT-141: publish whatever acquisition digest the turtle graph
        // recorded, matching seance_container_e01's stored_md5/stored_sha1
        // precedent exactly so seance_core's decoded-media verification pass
        // picks it up unmodified. An algorithm this reader has no stored_*
        // baseline for (e.g. SHA256) is still surfaced under its own key
        // rather than fabricated into stored_md5/stored_sha1 or dropped. When
        // the graph carried no hash predicate at all, say so on the record —
        // silence here would read as "nobody checked" rather than "checked,
        // and there is nothing to compare against" (forensic honesty).
        if hashes.is_empty() {
            metadata["aff4_hash_baseline"] = json!("not recorded in container");
        } else {
            for (algorithm, hex) in &hashes {
                match *algorithm {
                    "md5" => metadata["stored_md5"] = json!(hex),
                    "sha1" => metadata["stored_sha1"] = json!(hex),
                    other => metadata[format!("aff4_hash_{other}")] = json!(hex),
                }
            }
        }

        let evidence_artifact = Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(std::sync::Arc::new(source) as std::sync::Arc<dyn DataSource>),
            metadata,
        )
        .with_parent(artifact.id);

        info!("AFF4 image reconstructed: {} bytes logical image", size);
        Ok(vec![evidence_artifact])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use uuid::Uuid;
    use zip::write::SimpleFileOptions as FileOptions;
    use zip::ZipWriter;

    fn make_artifact(name: &str, subtype: Option<&str>, path: Option<&str>) -> Artifact {
        let mut meta = json!({ "name": name });
        if let Some(s) = subtype {
            meta["subtype"] = json!(s);
        }
        if let Some(p) = path {
            meta["path"] = json!(p);
        }
        Artifact::new(Uuid::new_v4(), ArtifactType::Container, None, meta)
    }

    /// Build a minimal but spec-conformant AFF4: a Map over an ImageStream
    /// (one snappy chunk of 'A'*chunk) followed by a Zero gap. Returns the path
    /// and the expected logical bytes.
    fn write_minimal_aff4() -> (PathBuf, Vec<u8>) {
        let path = write_aff4_with("aff4:Zero", "aff4://Zero");
        let mut expected = vec![b'A'; 512];
        expected.extend_from_slice(&vec![0u8; 512]);
        (path, expected)
    }

    /// A 1024-byte AFF4 whose map is `[0,512) -> ImageStream('A'*512)` and
    /// `[512,1024) -> second_target_urn`, with `gap_urn` as the declared
    /// `aff4:mapGapDefaultStream`.
    fn write_aff4_with(gap_urn: &str, second_target_urn: &str) -> PathBuf {
        let chunk_size = 512u64;
        let stream_urn = "aff4://11111111-1111-1111-1111-111111111111";
        let map_urn = "aff4://22222222-2222-2222-2222-222222222222";
        let image_urn = "aff4://33333333-3333-3333-3333-333333333333";
        let base = "aff4://00000000-0000-0000-0000-000000000000";

        // ImageStream data: one chunk of 512 'A's, snappy-compressed.
        let chunk_plain = vec![b'A'; chunk_size as usize];
        let comp = snap::raw::Encoder::new()
            .compress_vec(&chunk_plain)
            .unwrap();
        // index entry: offset 0, length = comp.len()
        let mut index = Vec::new();
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&(comp.len() as u32).to_le_bytes());

        // Logical layout: [0,512) -> ImageStream chunk 0 ('A'); [512,1024) ->
        // whatever `second_target_urn` names.
        let logical_size = 1024u64;

        // Map: idx targets (0=ImageStream, 1=second target); two entries.
        let idx = format!("{}\n{}\n", stream_urn, second_target_urn);
        let mut map = Vec::new();
        // entry 0: [0,512) -> target 0 offset 0
        map.extend_from_slice(&0u64.to_le_bytes());
        map.extend_from_slice(&512u64.to_le_bytes());
        map.extend_from_slice(&0u64.to_le_bytes());
        map.extend_from_slice(&0u32.to_le_bytes());
        // entry 1: [512,1024) -> target 1 (Zero)
        map.extend_from_slice(&512u64.to_le_bytes());
        map.extend_from_slice(&512u64.to_le_bytes());
        map.extend_from_slice(&0u64.to_le_bytes());
        map.extend_from_slice(&1u32.to_le_bytes());

        let turtle = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <{image}> a aff4:Image, aff4:DiskImage ;\n\
                 aff4:size \"{size}\"^^xsd:long ;\n\
                 aff4:dataStream <{map}> .\n\
             <{map}> a aff4:Map ;\n\
                 aff4:mapGapDefaultStream {gap} ;\n\
                 aff4:dependentStream <{stream}> ;\n\
                 aff4:size \"{size}\"^^xsd:long .\n\
             <{stream}> a aff4:ImageStream ;\n\
                 aff4:chunkSize \"{cs}\"^^xsd:int ;\n\
                 aff4:chunksInSegment \"2048\"^^xsd:int ;\n\
                 aff4:compressionMethod <http://code.google.com/p/snappy/> ;\n\
                 aff4:size \"512\"^^xsd:long .\n",
            image = image_urn,
            map = map_urn,
            stream = stream_urn,
            gap = gap_urn,
            size = logical_size,
            cs = chunk_size
        );

        // Each container gets its own directory: `sibling_aff4_files` scans the
        // containing directory for spanned sets, so writing them all into the
        // shared temp root would make concurrent tests each other's siblings.
        let dir = std::env::temp_dir().join(format!("seance_aff4_min_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image.aff4");
        let f = File::create(&path).unwrap();
        let mut zw = ZipWriter::new(f);
        let opts: FileOptions =
            FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        let sp = urn_to_zip_prefix(stream_urn);
        let mp = urn_to_zip_prefix(map_urn);
        zw.start_file("container.description", opts).unwrap();
        zw.write_all(base.as_bytes()).unwrap();
        zw.start_file("version.txt", opts).unwrap();
        zw.write_all(b"major=1\nminor=0\n").unwrap();
        zw.start_file("information.turtle", opts).unwrap();
        zw.write_all(turtle.as_bytes()).unwrap();
        zw.start_file(format!("{}/00000000", sp), opts).unwrap();
        zw.write_all(&comp).unwrap();
        zw.start_file(format!("{}/00000000.index", sp), opts)
            .unwrap();
        zw.write_all(&index).unwrap();
        zw.start_file(format!("{}/map", mp), opts).unwrap();
        zw.write_all(&map).unwrap();
        zw.start_file(format!("{}/idx", mp), opts).unwrap();
        zw.write_all(idx.as_bytes()).unwrap();
        zw.finish().unwrap();

        path
    }

    /// Write a container `filename` in `dir` from a turtle body and a set of
    /// (entry-name, bytes) segments (plus the standard description/version).
    fn write_container(
        dir: &std::path::Path,
        filename: &str,
        base: &str,
        turtle: &str,
        segments: &[(String, Vec<u8>)],
    ) {
        let f = File::create(dir.join(filename)).unwrap();
        let mut zw = ZipWriter::new(f);
        let opts: FileOptions =
            FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file("container.description", opts).unwrap();
        zw.write_all(base.as_bytes()).unwrap();
        zw.start_file("version.txt", opts).unwrap();
        zw.write_all(b"major=1\nminor=0\n").unwrap();
        zw.start_file("information.turtle", opts).unwrap();
        zw.write_all(turtle.as_bytes()).unwrap();
        for (name, bytes) in segments {
            zw.start_file(name.clone(), opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap();
    }

    /// One snappy chunk + its 1-entry index, as ZIP segments under `stream_urn`.
    fn stream_segments(stream_urn: &str, plain: &[u8]) -> Vec<(String, Vec<u8>)> {
        let comp = snap::raw::Encoder::new().compress_vec(plain).unwrap();
        let mut index = Vec::new();
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        let sp = urn_to_zip_prefix(stream_urn);
        vec![
            (format!("{}/00000000", sp), comp),
            (format!("{}/00000000.index", sp), index),
        ]
    }

    /// A minimal single-container AFF4 (one 512-byte snappy ImageStream chunk,
    /// mapped whole with an `aff4:Zero` gap default) whose `<image>` subject
    /// carries `extra_image_turtle` verbatim — for HUNT-141's hash-predicate
    /// tests, which need control over exactly what the image subject
    /// declares. Reuses `write_container`/`stream_segments`, the same
    /// synthetic-AFF4 builder `reads_striped_image_across_two_containers` uses.
    fn write_minimal_aff4_with_image_extra(extra_image_turtle: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("seance_aff4_hash_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = "aff4://00000000-0000-0000-0000-000000000000";
        let image = "aff4://33333333-3333-3333-3333-333333333333";
        let map = "aff4://22222222-2222-2222-2222-222222222222";
        let stream = "aff4://11111111-1111-1111-1111-111111111111";

        let idx = format!("{}\n", stream);
        let mut mapb = Vec::new();
        mapb.extend_from_slice(&0u64.to_le_bytes());
        mapb.extend_from_slice(&512u64.to_le_bytes());
        mapb.extend_from_slice(&0u64.to_le_bytes());
        mapb.extend_from_slice(&0u32.to_le_bytes());
        let mp = urn_to_zip_prefix(map);

        let turtle = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <{image}> a aff4:Image, aff4:DiskImage ;\n\
                 aff4:size \"512\"^^xsd:long ;\n\
                 {extra}\n\
                 aff4:dataStream <{map}> .\n\
             <{map}> a aff4:Map ;\n\
                 aff4:mapGapDefaultStream aff4:Zero ;\n\
                 aff4:dependentStream <{stream}> ;\n\
                 aff4:size \"512\"^^xsd:long .\n\
             <{stream}> a aff4:ImageStream ;\n\
                 aff4:chunkSize \"512\"^^xsd:int ;\n\
                 aff4:chunksInSegment \"2048\"^^xsd:int ;\n\
                 aff4:compressionMethod <http://code.google.com/p/snappy/> ;\n\
                 aff4:size \"512\"^^xsd:long .\n",
            extra = extra_image_turtle,
        );

        let mut segs = stream_segments(stream, &vec![b'A'; 512]);
        segs.push((format!("{}/map", mp), mapb));
        segs.push((format!("{}/idx", mp), idx.into_bytes()));
        write_container(&dir, "image.aff4", base, &turtle, &segs);
        dir.join("image.aff4")
    }

    /// HUNT-141: an algorithm-named predicate (`aff4:md5`) and the generic
    /// `aff4:hash` predicate with an algorithm-naming `^^datatype` must both
    /// land on the emitted artifact's top-level metadata as stored_md5 /
    /// stored_sha1 — matching seance_container_e01's precedent exactly, so
    /// seance_core's decoded-media verification pass picks either up
    /// unmodified.
    #[test]
    fn image_hash_predicates_land_as_stored_md5_and_sha1() {
        let md5_hex = "d41d8cd98f00b204e9800998ecf8427e";
        let sha1_hex = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let path = write_minimal_aff4_with_image_extra(&format!(
            "aff4:md5 \"{md5}\" ;\n aff4:hash \"{sha1}\"^^aff4:SHA1 ;",
            md5 = md5_hex,
            sha1 = sha1_hex,
        ));
        let art = make_artifact("hashed.aff4", Some("aff4"), Some(&path.to_string_lossy()));
        let out = Aff4ContainerModule.process(&art).expect("process");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m.get("stored_md5"), Some(&json!(md5_hex)));
        assert_eq!(m.get("stored_sha1"), Some(&json!(sha1_hex)));
        assert_eq!(m.get("aff4_hash_baseline"), None);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// HUNT-141: an AFF4 whose turtle graph carries no hash predicate this
    /// reader recognises must say so explicitly on the artifact's own
    /// metadata rather than leave stored_md5/stored_sha1 silently absent, so
    /// nothing downstream reads that silence as "nobody checked".
    #[test]
    fn missing_hash_predicate_is_recorded_not_silent() {
        let path = write_minimal_aff4_with_image_extra("");
        let art = make_artifact("unhashed.aff4", Some("aff4"), Some(&path.to_string_lossy()));
        let out = Aff4ContainerModule.process(&art).expect("process");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(
            m.get("aff4_hash_baseline"),
            Some(&json!("not recorded in container"))
        );
        assert_eq!(m.get("stored_md5"), None);
        assert_eq!(m.get("stored_sha1"), None);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// HUNT-141: a digest algorithm this reader recognises but for which
    /// seance_core has no `stored_*` verification baseline (SHA256) must
    /// still be surfaced under its own key — never fabricated into
    /// stored_md5/stored_sha1, and never dropped as if it were absent.
    #[test]
    fn sha256_only_hash_is_surfaced_not_fabricated() {
        let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let path = write_minimal_aff4_with_image_extra(&format!(
            "aff4:sha256 \"{sha256}\" ;",
            sha256 = sha256_hex,
        ));
        let art = make_artifact("sha256.aff4", Some("aff4"), Some(&path.to_string_lossy()));
        let out = Aff4ContainerModule.process(&art).expect("process");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m.get("aff4_hash_sha256"), Some(&json!(sha256_hex)));
        assert_eq!(m.get("stored_md5"), None);
        assert_eq!(m.get("stored_sha1"), None);
        assert_eq!(m.get("aff4_hash_baseline"), None);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn reads_striped_image_across_two_containers() {
        // Map (container A) references stream A (in A) and stream B (in B).
        let dir = std::env::temp_dir().join(format!("seance_aff4_striped_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = "aff4://00000000-0000-0000-0000-000000000000";
        let image = "aff4://33333333-3333-3333-3333-333333333333";
        let map = "aff4://22222222-2222-2222-2222-222222222222";
        let stream_a = "aff4://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let stream_b = "aff4://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

        // idx: 0=stream_a, 1=stream_b. map: [0,512)->A, [512,1024)->B.
        let idx = format!("{}\n{}\n", stream_a, stream_b);
        let mut mapb = Vec::new();
        for (moff, tid) in [(0u64, 0u32), (512u64, 1u32)] {
            mapb.extend_from_slice(&moff.to_le_bytes());
            mapb.extend_from_slice(&512u64.to_le_bytes());
            mapb.extend_from_slice(&0u64.to_le_bytes());
            mapb.extend_from_slice(&tid.to_le_bytes());
        }
        let mp = urn_to_zip_prefix(map);
        let stream_decl = |urn: &str| {
            format!(
                "<{urn}> a aff4:ImageStream ;\n\
                 aff4:chunkSize \"512\"^^xsd:int ;\n\
                 aff4:chunksInSegment \"2048\"^^xsd:int ;\n\
                 aff4:compressionMethod <http://code.google.com/p/snappy/> ;\n\
                 aff4:size \"512\"^^xsd:long .\n"
            )
        };
        let turtle_a = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <{image}> a aff4:Image, aff4:DiskImage ;\n\
                 aff4:size \"1024\"^^xsd:long ;\n\
                 aff4:dataStream <{map}> .\n\
             <{map}> a aff4:Map ;\n\
                 aff4:mapGapDefaultStream aff4:Zero ;\n\
                 aff4:dependentStream <{stream_a}> , <{stream_b}> ;\n\
                 aff4:size \"1024\"^^xsd:long .\n{a}",
            a = stream_decl(stream_a),
        );
        let mut segs_a = stream_segments(stream_a, &[b'A'; 512]);
        segs_a.push((format!("{}/map", mp), mapb));
        segs_a.push((format!("{}/idx", mp), idx.into_bytes()));
        write_container(&dir, "striped_1.aff4", base, &turtle_a, &segs_a);

        // Container B holds stream B's data and describes it.
        let turtle_b = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n{}",
            stream_decl(stream_b)
        );
        write_container(
            &dir,
            "striped_2.aff4",
            base,
            &turtle_b,
            &stream_segments(stream_b, &[b'B'; 512]),
        );

        let ds = Aff4DataSource::open(&dir.join("striped_1.aff4").to_string_lossy())
            .expect("open striped");
        assert_eq!(ds.size(), 1024);
        let mut got = vec![0u8; 1024];
        ds.read_at(0, &mut got).unwrap();
        let mut expected = vec![b'A'; 512];
        expected.extend_from_slice(&[b'B'; 512]);
        assert_eq!(
            got, expected,
            "striped image must interleave both containers' streams"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_identity() {
        let m = Aff4ContainerModule;
        assert_eq!(m.id(), "container.aff4_reader");
        assert!(!m.version().is_empty());
        assert_eq!(m.subscribes_to(), vec![ArtifactType::Container]);
        assert_eq!(m.input_capability(), InputCapability::FilePath);
    }

    #[test]
    fn is_aff4_file_extension_detection() {
        let m = Aff4ContainerModule;
        assert!(m.is_aff4_file("image.aff4"));
        assert!(m.is_aff4_file("IMAGE.AFF4"));
        assert!(!m.is_aff4_file("image.e01"));
    }

    #[test]
    fn non_aff4_subtype_short_circuits() {
        let art = make_artifact("evidence.e01", Some("e01"), Some("/tmp/nope.e01"));
        assert!(Aff4ContainerModule.process(&art).unwrap().is_empty());
    }

    #[test]
    fn missing_path_for_aff4_is_invalid_input() {
        let art = make_artifact("evidence.aff4", Some("aff4"), None);
        matches!(
            Aff4ContainerModule.process(&art),
            Err(ModuleError::InvalidInputFormat(_))
        );
    }

    #[test]
    fn bad_path_surfaces_parsing_error() {
        let art = make_artifact("e.aff4", Some("aff4"), Some("/tmp/seance_no_such_xyz.aff4"));
        matches!(
            Aff4ContainerModule.process(&art),
            Err(ModuleError::ParsingError(_))
        );
    }

    #[test]
    fn reads_map_over_snappy_imagestream_with_zero_gap() {
        let (path, expected) = write_minimal_aff4();
        let ds = Aff4DataSource::open(&path.to_string_lossy()).expect("open aff4");
        assert_eq!(ds.size(), expected.len() as u64);

        let mut got = vec![0u8; expected.len()];
        let n = ds.read_at(0, &mut got).unwrap();
        assert_eq!(n, expected.len());
        assert_eq!(got, expected, "reconstructed logical image mismatch");

        // Cross-boundary read (last 'A' + first zeros).
        let mut mid = [0u8; 8];
        ds.read_at(508, &mut mid).unwrap();
        assert_eq!(&mid, &[b'A', b'A', b'A', b'A', 0, 0, 0, 0]);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn process_emits_raw_evidence_with_datasource() {
        let (path, expected) = write_minimal_aff4();
        let art = make_artifact("min.aff4", Some("aff4"), Some(&path.to_string_lossy()));
        let out = Aff4ContainerModule.process(&art).expect("process");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].artifact_type, ArtifactType::RawEvidence);
        assert_eq!(
            out[0].metadata.get("container").and_then(|v| v.as_str()),
            Some("aff4")
        );
        let ds = out[0].data.as_ref().expect("datasource attached");
        assert_eq!(ds.size(), expected.len() as u64);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn symbolic_stream_hex_byte_resolves() {
        let empty = HashMap::new();
        match Target::resolve("aff4://foo/SymbolicStream61", &empty) {
            Target::Symbolic(b) => assert_eq!(b, 0x61),
            _ => panic!("expected symbolic"),
        }
        match Target::resolve("http://aff4.org/Schema#Zero", &empty) {
            Target::Symbolic(b) => assert_eq!(b, 0x00),
            _ => panic!("expected zero"),
        }
    }

    #[test]
    fn decompress_chunk_rejects_short_output() {
        // BUG-010: a chunk that decompresses to fewer than `expected` bytes must
        // error, not be accepted and zero-padded downstream as if it were full.
        let short = vec![b'x'; 10];
        let err = decompress_chunk(&short, 512, Compression::Stored).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("expected") && msg.contains("512"),
            "unexpected error: {msg}"
        );
    }

    /// B3-032: a map segment with a partial trailing record must fail closed.
    ///
    /// What an examiner learns: this container's layout is truncated and cannot
    /// be trusted. The wrong answer this guards against is the dropped record's
    /// range reading as gap fill — bytes the image never contained,
    /// presented as evidence with no error anywhere.
    #[test]
    fn truncated_map_segment_fails_closed() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0u64.to_le_bytes()); // map_off
        raw.extend_from_slice(&512u64.to_le_bytes()); // length
        raw.extend_from_slice(&0u64.to_le_bytes()); // target_off
        raw.extend_from_slice(&0u32.to_le_bytes()); // target_id
        assert_eq!(raw.len(), MAP_RECORD_LEN);

        // One whole record parses.
        let entries = parse_map_records(&raw, "aff4://map").expect("whole records parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].length, 512);

        // A second, half-written record is a truncated map, not one entry.
        raw.extend_from_slice(&4096u64.to_le_bytes());
        let err = parse_map_records(&raw, "aff4://map").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("truncated") && msg.contains("aff4://map"),
            "the error must name the truncated map: {msg}"
        );
    }

    /// B3-032: a bevy index with a partial trailing record must fail closed —
    /// a chunk whose index entry was cut off cannot be located, and its bytes
    /// must not be quietly omitted from the image.
    #[test]
    fn truncated_bevy_index_fails_closed() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0u64.to_le_bytes()); // offset
        raw.extend_from_slice(&32u32.to_le_bytes()); // length
        assert_eq!(raw.len(), BEVY_INDEX_RECORD_LEN);

        let index = parse_bevy_index(&raw, "stream/00000000.index").expect("whole records parse");
        assert_eq!(index, vec![(0u64, 32u32)]);

        raw.push(0x01); // one stray byte
        let err = parse_bevy_index(&raw, "stream/00000000.index").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("truncated") && msg.contains("00000000.index"),
            "the error must name the truncated index: {msg}"
        );
    }

    #[test]
    fn unknown_map_target_errors_instead_of_zero_filling() {
        // BUG-037: a map entry pointing at an unresolvable target URN must fail
        // closed on a read covering it, not silently return zeros.
        let ds = Aff4DataSource::for_test(
            512,
            vec![MapEntry {
                map_off: 0,
                length: 512,
                target_off: 0,
                target_id: 0,
            }],
            vec![Target::resolve(
                "aff4://unresolvable-target",
                &HashMap::new(),
            )],
        );
        assert!(
            matches!(ds.targets[0], Target::Unknown(_)),
            "an unrecognised URN must resolve to Target::Unknown, not a silent zero"
        );
        let mut buf = [0u8; 16];
        let err = ds.read_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn map_range_length_overflow_fails_closed() {
        // BUG-055: a map entry whose map_off + length wraps u64 must fail closed
        // on a covering read, not wrap around and serve wrong/fabricated bytes.
        let ds = Aff4DataSource::for_test(
            100,
            vec![MapEntry {
                map_off: 10,
                length: u64::MAX,
                target_off: 0,
                target_id: 0,
            }],
            vec![Target::Symbolic(0)],
        );
        let mut buf = [0u8; 16];
        let err = ds.read_at(20, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn map_target_offset_overflow_fails_closed() {
        // BUG-055: target_off + (pos - map_off) must not wrap. A near-u64::MAX
        // target offset on a mid-entry read fails closed instead of wrapping.
        let ds = Aff4DataSource::for_test(
            1024,
            vec![MapEntry {
                map_off: 0,
                length: 1024,
                target_off: u64::MAX,
                target_id: 0,
            }],
            vec![Target::Symbolic(0)],
        );
        let mut buf = [0u8; 16];
        // pos = 100 makes (pos - map_off) push target_off past u64::MAX.
        let err = ds.read_at(100, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn out_of_range_target_id_errors_instead_of_panicking() {
        // A corrupt map entry references target 5 while only one target exists.
        // read_at must surface an InvalidData error, not panic on an OOB index.
        let ds = Aff4DataSource::for_test(
            512,
            vec![MapEntry {
                map_off: 0,
                length: 512,
                target_off: 0,
                target_id: 5,
            }],
            vec![Target::Symbolic(0)],
        );
        let mut buf = [0u8; 16];
        let err = ds.read_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Build a minimal ImageStream turtle graph with the given geometry strings.
    fn stream_graph(chunk_size: &str, chunks_in_segment: &str) -> (TurtleGraph, String) {
        let urn = "aff4://s".to_string();
        let turtle = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <{urn}> a aff4:ImageStream ;\n\
                 aff4:chunkSize \"{cs}\"^^xsd:int ;\n\
                 aff4:chunksInSegment \"{cis}\"^^xsd:int ;\n\
                 aff4:size \"512\"^^xsd:long .\n",
            urn = urn,
            cs = chunk_size,
            cis = chunks_in_segment
        );
        (TurtleGraph::parse(&turtle, ""), urn)
    }

    #[test]
    fn zero_chunk_size_rejected() {
        // BUG-087: an explicit chunkSize of 0 must be rejected at construction so
        // `chunk`/`read_into` never divide by zero.
        let (g, urn) = stream_graph("0", "2048");
        let err = build_image_stream("/nonexistent.aff4", &urn, &g).unwrap_err();
        assert!(format!("{err}").contains("chunkSize"), "got: {err}");
    }

    #[test]
    fn zero_chunks_in_segment_rejected() {
        // BUG-087: an explicit chunksInSegment of 0 must be rejected so mapping a
        // chunk to its bevy never divides by zero.
        let (g, urn) = stream_graph("512", "0");
        let err = build_image_stream("/nonexistent.aff4", &urn, &g).unwrap_err();
        assert!(format!("{err}").contains("chunksInSegment"), "got: {err}");
    }

    #[test]
    fn oversized_chunk_size_rejected() {
        // BUG-088: an absurd chunkSize would drive a multi-GiB per-chunk buffer;
        // fail closed above the sane ceiling instead of allocating from it.
        let (g, urn) = stream_graph("9999999999", "2048");
        assert!(build_image_stream("/nonexistent.aff4", &urn, &g).is_err());
    }

    #[test]
    fn snappy_declared_length_over_expected_fails_before_allocating() {
        // BUG-088: a snappy chunk whose declared uncompressed length exceeds the
        // expected chunk length must fail closed before decompress_vec allocates
        // it (zip-bomb class).
        let big = vec![b'Z'; 100_000];
        let comp = snap::raw::Encoder::new().compress_vec(&big).unwrap();
        let err = decompress_chunk(&comp, 512, Compression::Snappy).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("declares") && msg.contains("100000"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn zip_entry_over_cap_fails_closed() {
        // BUG-088: a ZIP segment larger than the cap must fail closed, not be
        // truncated at the cap and served as a complete segment.
        let path = std::env::temp_dir().join(format!("seance_aff4_cap_{}.zip", Uuid::new_v4()));
        let f = File::create(&path).unwrap();
        let mut zw = ZipWriter::new(f);
        let opts: FileOptions =
            FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file("blob", opts).unwrap();
        zw.write_all(&vec![0xAAu8; 2000]).unwrap();
        zw.finish().unwrap();
        let p = path.to_string_lossy().to_string();

        // Under a generous cap the entry reads back in full.
        assert_eq!(read_zip_entry_capped(&p, "blob", 4096).unwrap().len(), 2000);
        // Under a tiny cap the same entry exceeds it and must error, not truncate.
        let err = read_zip_entry_capped(&p, "blob", 1024).unwrap_err();
        assert!(format!("{err}").contains("cap"), "got: {err}");

        let _ = std::fs::remove_file(&path);
    }

    /// B4-017: `aff4:UnreadableData` is a range the imager asked the device for
    /// and did not get. Served as zeros it is byte-identical to a range that
    /// genuinely held zeros, and by the time it reaches a file hash, an export
    /// or a preview there is nothing left to tell the two apart.
    #[test]
    fn unreadable_data_serves_a_marker_not_zeros() {
        let t = Target::resolve("http://aff4.org/Schema#UnreadableData", &HashMap::new());
        assert!(
            matches!(t, Target::Unreadable),
            "UnreadableData must not resolve to a constant-zero symbolic stream"
        );

        let ds = Aff4DataSource::for_test(
            512,
            vec![MapEntry {
                map_off: 0,
                length: 512,
                target_off: 0,
                target_id: 0,
            }],
            vec![t],
        );
        let mut buf = [0u8; 32];
        assert_eq!(ds.read_at(0, &mut buf).unwrap(), 32);
        assert!(
            buf.iter().any(|&b| b != 0),
            "unreadable bytes must not read back as zeros"
        );
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, UNREADABLE_PATTERN[i % UNREADABLE_PATTERN.len()]);
        }
        assert_eq!(ds.coverage().unreadable_bytes, 512);
        assert!(ds.coverage().has_non_evidence_regions());
    }

    /// B4-017: `aff4:UnknownData` — never imaged at all — gets the same
    /// treatment and its own counter.
    #[test]
    fn unknown_data_serves_a_marker_not_zeros() {
        let t = Target::resolve("http://aff4.org/Schema#UnknownData", &HashMap::new());
        assert!(matches!(t, Target::UnknownData));
        let ds = Aff4DataSource::for_test(
            256,
            vec![MapEntry {
                map_off: 0,
                length: 256,
                target_off: 0,
                target_id: 0,
            }],
            vec![t],
        );
        let mut buf = [0u8; 16];
        ds.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
        assert_eq!(&buf[..UNKNOWN_PATTERN.len()], UNKNOWN_PATTERN);
        assert_eq!(ds.coverage().unknown_bytes, 256);
    }

    /// A marker fill must be phase-stable on the logical offset: the same offset
    /// has to yield the same byte however a read is split, or a hash of the
    /// image would depend on the buffer size used to compute it.
    #[test]
    fn marker_fill_is_stable_across_split_reads() {
        let ds = Aff4DataSource::for_test(
            512,
            vec![MapEntry {
                map_off: 0,
                length: 512,
                target_off: 0,
                target_id: 0,
            }],
            vec![Target::Unreadable],
        );
        let mut whole = [0u8; 64];
        ds.read_at(0, &mut whole).unwrap();
        let mut tail = [0u8; 32];
        ds.read_at(17, &mut tail).unwrap();
        assert_eq!(&whole[17..49], &tail[..]);
    }

    /// B4-017: a range no map entry covers was never imaged either. It is still
    /// filled (with the container's declared gap stream), so the only place the
    /// fact can be recorded is the coverage the module stamps on the artifact.
    #[test]
    fn unmapped_gap_is_counted_as_non_evidence() {
        let ds = Aff4DataSource::for_test(
            1024,
            vec![MapEntry {
                map_off: 0,
                length: 512,
                target_off: 0,
                target_id: 0,
            }],
            vec![Target::Symbolic(0)],
        );
        assert_eq!(ds.coverage().unmapped_bytes, 512);
        assert_eq!(ds.coverage().unreadable_bytes, 0);
        assert!(ds.coverage().has_non_evidence_regions());
    }

    /// A fully mapped image of real stream bytes must NOT be flagged: the flag
    /// only means something if a clean image does not carry it.
    #[test]
    fn fully_mapped_image_reports_no_non_evidence_regions() {
        let path = write_minimal_aff4().0;
        let ds = Aff4DataSource::open(&path.to_string_lossy()).expect("open aff4");
        // [512,1024) is an explicit aff4:Zero target — a deliberate constant
        // stream, not a hole — so nothing is flagged.
        assert!(!ds.coverage().has_non_evidence_regions());
        assert!(ds.coverage().stream_bind_failures.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// B4-017: an `aff4:mapGapDefaultStream` that cannot be resolved used to
    /// silently degrade to 0x00 — which is itself a legal value for that
    /// declaration, so an unmet declaration became indistinguishable from a met
    /// one. A read landing in the gap must fail closed and name the URN.
    #[test]
    fn unresolvable_gap_default_stream_fails_the_gap_read_closed() {
        let gap = Target::resolve("aff4://no-such-gap-stream", &HashMap::new());
        assert!(matches!(gap, Target::Unknown(_)));
        // [0,512) is mapped; [512,1024) is a gap served by the unresolvable
        // default stream.
        let ds = Aff4DataSource::for_test_with_gap(
            1024,
            vec![MapEntry {
                map_off: 0,
                length: 512,
                target_off: 0,
                target_id: 0,
            }],
            vec![Target::Symbolic(0)],
            gap,
        );
        // The mapped half still reads.
        let mut ok = [0xFFu8; 16];
        ds.read_at(0, &mut ok)
            .expect("the mapped range still reads");
        assert_eq!(ok, [0u8; 16]);

        let mut buf = [0u8; 16];
        let err = ds
            .read_at(600, &mut buf)
            .expect_err("an unservable gap default must not fall back to zeros");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = format!("{err}");
        assert!(
            msg.contains("mapGapDefaultStream") && msg.contains("no-such-gap-stream"),
            "the error must name the gap stream it could not honour: {msg}"
        );
        // And the gap is counted as bytes that cannot be produced.
        assert_eq!(ds.coverage().unresolved_bytes, 512);
    }

    /// The counterweight to the above: an image whose map covers every byte
    /// never consults the gap default, so an odd declaration must not cost the
    /// examiner the whole exhibit. Refusing to open here would turn a readable
    /// image into no evidence at all.
    #[test]
    fn a_fully_mapped_image_opens_despite_an_odd_gap_declaration() {
        let path = write_aff4_with("<aff4://no-such-gap-stream>", "aff4://Zero");
        let ds = Aff4DataSource::open(&path.to_string_lossy())
            .expect("a fully mapped image must still open");
        let mut buf = [0u8; 8];
        ds.read_at(0, &mut buf).expect("mapped bytes read");
        assert_eq!(&buf, b"AAAAAAAA");
        assert!(!ds.coverage().has_non_evidence_regions());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// B4-017: the container artifact — not just the bytes — must say the image
    /// is not wholly imaged evidence, using the standard pair every consumer
    /// reads.
    #[test]
    fn process_stamps_incompleteness_for_unreadable_regions() {
        let path = write_aff4_with("aff4:Zero", "http://aff4.org/Schema#UnreadableData");
        let art = make_artifact("bad.aff4", Some("aff4"), Some(&path.to_string_lossy()));
        let out = Aff4ContainerModule.process(&art).expect("process");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m.get("content_incomplete"), Some(&json!(true)));
        assert_eq!(
            m.get("content_incomplete_reason"),
            Some(&json!("unresolved_structure"))
        );
        assert_eq!(m.get("aff4_unreadable_bytes"), Some(&json!(512)));
        assert_eq!(m.get("aff4_non_evidence_bytes"), Some(&json!(512)));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// B7-029: a spanned set whose sibling container will not open used to bind
    /// nothing and say nothing. The unbindable target already fails reads closed;
    /// the container artifact must also carry the inventory signal.
    #[test]
    fn unbindable_sibling_container_is_reported() {
        let dir = std::env::temp_dir().join(format!("seance_aff4_bind_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = "aff4://00000000-0000-0000-0000-000000000000";
        let image = "aff4://33333333-3333-3333-3333-333333333333";
        let map = "aff4://22222222-2222-2222-2222-222222222222";
        let stream_a = "aff4://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let stream_b = "aff4://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

        let idx = format!("{}\n{}\n", stream_a, stream_b);
        let mut mapb = Vec::new();
        for (moff, tid) in [(0u64, 0u32), (512u64, 1u32)] {
            mapb.extend_from_slice(&moff.to_le_bytes());
            mapb.extend_from_slice(&512u64.to_le_bytes());
            mapb.extend_from_slice(&0u64.to_le_bytes());
            mapb.extend_from_slice(&tid.to_le_bytes());
        }
        let mp = urn_to_zip_prefix(map);
        let turtle_a = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <{image}> a aff4:Image, aff4:DiskImage ;\n\
                 aff4:size \"1024\"^^xsd:long ;\n\
                 aff4:dataStream <{map}> .\n\
             <{map}> a aff4:Map ;\n\
                 aff4:mapGapDefaultStream aff4:Zero ;\n\
                 aff4:size \"1024\"^^xsd:long .\n\
             <{stream_a}> a aff4:ImageStream ;\n\
                 aff4:chunkSize \"512\"^^xsd:int ;\n\
                 aff4:chunksInSegment \"2048\"^^xsd:int ;\n\
                 aff4:compressionMethod <http://code.google.com/p/snappy/> ;\n\
                 aff4:size \"512\"^^xsd:long .\n"
        );
        let mut segs_a = stream_segments(stream_a, &[b'A'; 512]);
        segs_a.push((format!("{}/map", mp), mapb));
        segs_a.push((format!("{}/idx", mp), idx.into_bytes()));
        write_container(&dir, "set_1.aff4", base, &turtle_a, &segs_a);

        // The sibling that would hold stream B is present but is not a ZIP.
        std::fs::write(dir.join("set_2.aff4"), b"this is not a zip container").unwrap();

        let path = dir.join("set_1.aff4").to_string_lossy().to_string();
        let ds = Aff4DataSource::open(&path).expect("primary opens");
        assert!(
            !ds.coverage().stream_bind_failures.is_empty(),
            "an unreadable sibling container must be recorded, not skipped"
        );
        // Stream B never bound, so its half of the image is unservable.
        assert_eq!(ds.coverage().unresolved_bytes, 512);

        let art = make_artifact("set_1.aff4", Some("aff4"), Some(&path));
        let out = Aff4ContainerModule.process(&art).expect("process");
        let m = &out[0].metadata;
        assert_eq!(m.get("inventory_incomplete"), Some(&json!(true)));
        assert_eq!(
            m.get("inventory_incomplete_reason"),
            Some(&json!("unresolved_structure"))
        );
        assert_eq!(m.get("content_incomplete"), Some(&json!(true)));
        assert!(m.get("stream_bind_failures").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn map_read_past_imagestream_end_fails_closed() {
        // BUG-089: a map entry pointing past the ImageStream end must fail closed,
        // not zero-fill fabricated bytes as if they were imaged zeros.
        let reader = std::sync::Arc::new(ImageStreamReader {
            zip_path: "/nonexistent.aff4".to_string(),
            zip_prefix: "x".to_string(),
            chunk_size: 512,
            chunks_in_segment: 2048,
            stream_size: 512,
            compression: Compression::Stored,
            bevies: Mutex::new(HashMap::new()),
            last_chunk: Mutex::new(None),
        });
        let ds = Aff4DataSource::for_test(
            16,
            vec![MapEntry {
                map_off: 0,
                length: 16,
                // target_off 1000 pushes the ImageStream read past stream_size 512
                target_off: 1000,
                target_id: 0,
            }],
            vec![Target::Image(reader)],
        );
        let mut buf = [0u8; 16];
        let err = ds.read_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
