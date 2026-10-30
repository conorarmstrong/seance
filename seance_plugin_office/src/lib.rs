#![forbid(unsafe_code)]
//! Office-document text extraction.
//!
//! [`OfficeParser`] self-selects modern office files and extracts their readable
//! text into a single `OfficeDocument`
//! [`ParsedRecord`](ArtifactType::ParsedRecord), so the content is full-text
//! searchable (the search indexer serialises artifact metadata into its content
//! field) and viewable in the artifact's text tab.
//!
//! # Supported inputs
//!
//! Both families are ZIP containers of XML parts, read entirely in pure Rust:
//!
//! - **OOXML** — Word (`.docx`/`.docm`), Excel (`.xlsx`/`.xlsm`) and PowerPoint
//!   (`.pptx`/`.pptm`). Word text comes from `word/document.xml`; Excel from
//!   `xl/sharedStrings.xml` resolved against each `xl/worksheets/sheet*.xml`;
//!   PowerPoint from every `ppt/slides/slide*.xml`.
//! - **ODF** — OpenDocument text/spreadsheet/presentation (`.odt`/`.ods`/`.odp`),
//!   whose body text lives in `content.xml`.
//!
//! Document properties (title, author, created/modified) are read from
//! `docProps/core.xml` (OOXML) or `meta.xml` (ODF) when present.
//!
//! # Scope
//!
//! Legacy OLE2/CFB binaries (`.doc`/`.xls`/`.ppt`, pre-2007) use a different
//! container and are out of scope here.
//!
//! # Honesty & robustness
//!
//! A corrupt archive, a missing part, or non-UTF-8 XML never panics and never
//! fails the pipeline: whatever text was recovered is emitted, otherwise an empty
//! result. Absent properties are omitted, never emitted as null.
//!
//! Incompleteness is reported at both levels. The outer archive read has the
//! [`MAX_CONTENT_BYTES`] cap and can be short; individual ZIP members have the
//! [`MAX_ENTRY_BYTES`] decompression cap and can fail to inflate. A part that is
//! *present but unreadable* is recorded in `skipped_parts` and sets
//! `content_incomplete`, because the alternative — `.unwrap_or_default()` on a
//! skipped `word/document.xml` — publishes a document whose text is empty and
//! whose record says nothing went wrong. A part that is genuinely absent is not
//! an error and is not recorded.

use quick_xml::events::Event;
use quick_xml::Reader;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_xml_util::XmlGuard;
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::io::{Cursor, Read};
use tracing::{debug, warn};
use uuid::Uuid;
use zip::ZipArchive;

/// Cap on the raw file bytes read from a source (256 MiB).
const MAX_CONTENT_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on the extracted text stored on the record (4 MiB of UTF-8).
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
/// Cap on a single *decompressed* ZIP member (128 MiB). OOXML/ODF parts are
/// normally kilobytes to a few megabytes; a member that inflates past this is a
/// decompression bomb and is skipped rather than buffered unbounded.
const MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;

/// The office family an input belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Word,
    Excel,
    PowerPoint,
}

impl Format {
    fn label(self) -> &'static str {
        match self {
            Format::Word => "Word",
            Format::Excel => "Excel",
            Format::PowerPoint => "PowerPoint",
        }
    }
}

/// Whether the input is OOXML or ODF, and which family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ooxml(Format),
    Odf(Format),
}

pub struct OfficeParser;

impl ForensicsModule for OfficeParser {
    fn id(&self) -> &str {
        "plugin.documents.office"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Directories and content-less artifacts have nothing to parse.
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        // Cheap pre-filter on extension; anything without an office extension is
        // confirmed against the container's own content types before we commit to
        // reading it, so a plain ZIP is never mistaken for a document.
        let ext_kind = detect_by_name(name);
        if ext_kind.is_none() && !name.is_empty() {
            // Named file with a non-office extension: skip without reading.
            if has_extension(name) {
                return Ok(Vec::new());
            }
        }

        let declared = data.size();
        let content = read_capped(data.as_ref(), MAX_CONTENT_BYTES);
        if content.len() < 4 || &content[..2] != b"PK" {
            return Ok(Vec::new()); // not a ZIP container
        }
        // A partial ZIP still yields *some* parts, so text and properties come
        // out looking like a full parse. Record that the archive was cut short
        // (B2-049): missing parts are then a known gap, not an absent section.
        let content_incomplete = (content.len() as u64) < declared;

        let mut archive = match ZipArchive::new(Cursor::new(content.as_slice())) {
            Ok(a) => a,
            Err(e) => {
                // The PK magic already matched. A container we cannot open is not
                // a file that is not an office document: returning nothing makes
                // a corrupt `.docx` indistinguishable from a `.txt` (B6-011).
                warn!("OfficeParser: {} could not be opened as a ZIP: {}", name, e);
                return Ok(vec![unreadable_container_record(
                    artifact.case_id,
                    artifact.id,
                    name,
                    ext_kind,
                    content.len() as u64,
                    declared,
                    &e.to_string(),
                )]);
            }
        };
        let mut skipped = SkippedParts::default();
        let kind = match ext_kind {
            Some(k) => k,
            None => match sniff_kind(&mut archive, &mut skipped) {
                Some(k) => k,
                None => return Ok(Vec::new()),
            },
        };

        debug!("OfficeParser parsing {} as {:?}", name, kind);
        let (text, props) = match kind {
            Kind::Ooxml(fmt) => extract_ooxml(&mut archive, fmt, &mut skipped),
            Kind::Odf(fmt) => extract_odf(&mut archive, fmt, &mut skipped),
        };

        let fmt = match kind {
            Kind::Ooxml(f) | Kind::Odf(f) => f,
        };
        Ok(vec![build_record(
            artifact.case_id,
            artifact.id,
            name,
            fmt,
            matches!(kind, Kind::Odf(_)),
            text,
            props,
            ContentRead {
                incomplete: content_incomplete,
                bytes_read: content.len() as u64,
                declared_size: declared,
                skipped_parts: skipped,
            },
        )])
    }
}

/// Map a filename extension to a document kind, or `None` if not an office file.
fn detect_by_name(name: &str) -> Option<Kind> {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "docx" | "docm" | "dotx" | "dotm" => Some(Kind::Ooxml(Format::Word)),
        "xlsx" | "xlsm" | "xltx" | "xltm" => Some(Kind::Ooxml(Format::Excel)),
        "pptx" | "pptm" | "potx" | "potm" | "ppsx" => Some(Kind::Ooxml(Format::PowerPoint)),
        "odt" | "ott" => Some(Kind::Odf(Format::Word)),
        "ods" | "ots" => Some(Kind::Odf(Format::Excel)),
        "odp" | "otp" => Some(Kind::Odf(Format::PowerPoint)),
        _ => None,
    }
}

/// True if the name has a file extension at all (a `.` with following chars).
fn has_extension(name: &str) -> bool {
    name.rsplit('/')
        .next()
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| !e.is_empty())
        .unwrap_or(false)
}

/// Identify an extension-less container by its declared content: OOXML names the
/// family in `[Content_Types].xml`; ODF states it in `mimetype`.
fn sniff_kind(archive: &mut ZipArchive<Cursor<&[u8]>>, skipped: &mut SkippedParts) -> Option<Kind> {
    if let Some(ct) = read_entry(archive, "[Content_Types].xml", skipped) {
        if ct.contains("wordprocessingml") {
            return Some(Kind::Ooxml(Format::Word));
        }
        if ct.contains("spreadsheetml") {
            return Some(Kind::Ooxml(Format::Excel));
        }
        if ct.contains("presentationml") {
            return Some(Kind::Ooxml(Format::PowerPoint));
        }
    }
    if let Some(m) = read_entry(archive, "mimetype", skipped) {
        if m.contains("opendocument.text") {
            return Some(Kind::Odf(Format::Word));
        }
        if m.contains("opendocument.spreadsheet") {
            return Some(Kind::Odf(Format::Excel));
        }
        if m.contains("opendocument.presentation") {
            return Some(Kind::Odf(Format::PowerPoint));
        }
    }
    None
}

/// Document parts that were present in the archive but could not be read.
///
/// A part that is simply absent is NOT recorded here — an `.xlsx` with no
/// `sharedStrings.xml` is ordinary. What is recorded is a part the archive
/// declares and the parser refused or failed to inflate, because the caller
/// then substitutes empty text and the resulting document looks blank rather
/// than unreadable (B2-164).
#[derive(Debug, Default)]
struct SkippedParts {
    /// Parts present in the archive that could not be read at all.
    parts: Vec<(String, IncompleteReason)>,
    /// Parts whose XML stopped on a parse error part-way through. The text
    /// extracted from them is a PREFIX of what they held, and a truncated but
    /// successfully-inflated `document.xml` otherwise reads as a short document
    /// rather than a document we stopped reading (B6-013).
    xml_truncated: Vec<(String, String)>,
    /// Parts whose XML parsed to EOF but tripped a bound of the reader, or
    /// carried malformed attributes. Distinct from `xml_truncated`: the walk
    /// finished, so what was extracted is not a prefix -- but an element's
    /// attributes may have been refused, and a document built to be expensive
    /// to parse is itself worth reporting.
    xml_anomalies: Vec<(String, String)>,
}

impl SkippedParts {
    fn record(&mut self, name: &str, reason: IncompleteReason) {
        self.parts.push((name.to_string(), reason));
    }

    /// Note that `name`'s XML walk ended on an error rather than at EOF.
    fn record_xml_stop(&mut self, name: &str, error: &str) {
        warn!(
            "OfficeParser: XML in {} ended on a parse error: {}",
            name, error
        );
        self.xml_truncated
            .push((name.to_string(), error.to_string()));
    }

    /// Note that `name`'s XML parsed to EOF but tripped a reader bound.
    fn record_xml_anomaly(&mut self, name: &str, detail: &str) {
        warn!(
            "OfficeParser: XML in {} tripped a reader bound: {}",
            name, detail
        );
        self.xml_anomalies
            .push((name.to_string(), detail.to_string()));
    }

    /// True when any part is missing or short.
    fn has_issues(&self) -> bool {
        !self.parts.is_empty() || !self.xml_truncated.is_empty() || !self.xml_anomalies.is_empty()
    }
}

/// The result of walking one XML part: what was extracted, and whether the walk
/// reached the end of the document or stopped on a parse error.
struct XmlWalk<T> {
    value: T,
    /// `Some(error)` when quick-xml errored before `Eof`.
    stopped: Option<String>,
    /// Bounds the reader applied, or malformed attributes it found, while the
    /// walk still ran to `Eof`. Empty for an ordinary document.
    anomalies: Vec<String>,
}

impl<T> XmlWalk<T> {
    /// A walk that completed with nothing to disclose beyond `stopped`.
    ///
    /// Most parts read no attributes at all, so they cannot trip the bounded
    /// reader and have no anomalies to carry.
    fn plain(value: T, stopped: Option<String>) -> Self {
        Self {
            value,
            stopped,
            anomalies: Vec::new(),
        }
    }

    /// Take the value, recording any early stop against `part` in `skipped`.
    fn take(self, part: &str, skipped: &mut SkippedParts) -> T {
        if let Some(err) = self.stopped {
            skipped.record_xml_stop(part, &err);
        }
        for anomaly in &self.anomalies {
            skipped.record_xml_anomaly(part, anomaly);
        }
        self.value
    }
}

/// Read a ZIP entry to a lossy-UTF-8 string, or `None` if absent/unreadable.
/// The decompressed size is bounded so a zip-bomb member cannot OOM the worker.
/// A member that exists but could not be read is recorded in `skipped`.
fn read_entry(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    skipped: &mut SkippedParts,
) -> Option<String> {
    read_entry_capped(archive, name, MAX_ENTRY_BYTES, skipped)
}

/// Read a ZIP entry to a lossy-UTF-8 string, reading at most `cap` decompressed
/// bytes. Returns `None` if the member is absent, unreadable, or its
/// decompressed size exceeds `cap` (a decompression bomb — no partial content is
/// returned, so an over-cap part is never mistaken for the whole part).
///
/// The three `None` cases are not equivalent and are not reported as though they
/// were: an absent member returns `None` silently, while an over-cap or
/// unreadable member is pushed onto `skipped` so the record can say the document
/// was not parsed in full.
fn read_entry_capped(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    cap: u64,
    skipped: &mut SkippedParts,
) -> Option<String> {
    let mut f = match archive.by_name(name) {
        Ok(f) => f,
        // Genuinely not in the archive: nothing was lost.
        Err(zip::result::ZipError::FileNotFound) => return None,
        Err(e) => {
            warn!(
                "OfficeParser: ZIP member {} could not be opened: {}",
                name, e
            );
            skipped.record(name, IncompleteReason::UnresolvedStructure);
            return None;
        }
    };
    let mut bytes = Vec::new();
    // Read one byte past the cap: if we actually get it, the member is too big.
    if let Err(e) = (&mut f).take(cap.saturating_add(1)).read_to_end(&mut bytes) {
        warn!("OfficeParser: ZIP member {} failed to inflate: {}", name, e);
        skipped.record(name, IncompleteReason::UnresolvedStructure);
        return None;
    }
    if bytes.len() as u64 > cap {
        warn!(
            "OfficeParser: ZIP member {} exceeds {} decompressed bytes; skipping (possible zip bomb)",
            name, cap
        );
        skipped.record(name, IncompleteReason::CapReached);
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Sorted list of entry names matching `prefix` and `suffix` (e.g. slides).
fn entries_matching(
    archive: &ZipArchive<Cursor<&[u8]>>,
    prefix: &str,
    suffix: &str,
) -> Vec<String> {
    let mut names: Vec<String> = archive
        .file_names()
        // A name `zip` cannot decode is an error; it cannot be an OOXML part name either.
        .filter_map(Result::ok)
        .filter(|n| n.starts_with(prefix) && n.ends_with(suffix))
        .map(Cow::into_owned)
        .collect();
    // Natural order, not lexicographic. `names.sort()` put `slide10.xml`
    // before `slide2.xml`, so a deck of ten or more slides was extracted as
    // 1, 10, 11, …, 2, 20 — text in an order no one presented it in, and the
    // same for a workbook's sheets.
    names.sort_by_key(|n| natural_key(n));
    names
}

/// A sort key that orders `slide2.xml` before `slide10.xml`.
///
/// The name split at its trailing run of digits: everything before them, then
/// the digits as a number, then the rest — so equal stems order by number and
/// a name with no number keeps its place among its peers by text.
fn natural_key(name: &str) -> (String, u64, String) {
    let stem_end = name.rfind(|c: char| c.is_ascii_digit()).map(|i| i + 1);
    let Some(digits_end) = stem_end else {
        return (name.to_string(), 0, String::new());
    };
    let digits_start = name[..digits_end]
        .rfind(|c: char| !c.is_ascii_digit())
        .map(|i| i + 1)
        .unwrap_or(0);
    let number = name[digits_start..digits_end].parse::<u64>().unwrap_or(0);
    (
        name[..digits_start].to_string(),
        number,
        name[digits_end..].to_string(),
    )
}

fn extract_ooxml(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    fmt: Format,
    skipped: &mut SkippedParts,
) -> (String, Map<String, Value>) {
    // Each part is read into a local first, so the read's borrow of `skipped` is
    // done before the walk records an early stop against the same part.
    let text = match fmt {
        Format::Word => {
            const PART: &str = "word/document.xml";
            let xml = read_entry(archive, PART, skipped);
            match xml {
                Some(x) => collect_tagged_text(&x, b"t", b"p").take(PART, skipped),
                None => String::new(),
            }
        }
        Format::PowerPoint => {
            let slides = entries_matching(archive, "ppt/slides/slide", ".xml");
            let mut out = String::new();
            for (i, slide) in slides.iter().enumerate() {
                let xml = read_entry(archive, slide, skipped);
                if let Some(x) = xml {
                    if i > 0 {
                        out.push('\n');
                    }
                    let walk = collect_tagged_text(&x, b"t", b"p");
                    out.push_str(&walk.take(slide, skipped));
                }
            }
            out
        }
        Format::Excel => {
            const SHARED: &str = "xl/sharedStrings.xml";
            let shared_xml = read_entry(archive, SHARED, skipped);
            let shared = match shared_xml {
                Some(x) => parse_shared_strings(&x).take(SHARED, skipped),
                None => Vec::new(),
            };
            let sheets = entries_matching(archive, "xl/worksheets/sheet", ".xml");
            let mut out = String::new();
            for sheet in &sheets {
                let xml = read_entry(archive, sheet, skipped);
                if let Some(x) = xml {
                    let walk = extract_worksheet(&x, &shared);
                    out.push_str(&walk.take(sheet, skipped));
                }
            }
            out
        }
    };
    const CORE: &str = "docProps/core.xml";
    let core_xml = read_entry(archive, CORE, skipped);
    let props = match core_xml {
        Some(x) => collect_named_text(&x, CORE_PROP_FIELDS).take(CORE, skipped),
        None => Map::new(),
    };
    (text, props)
}

fn extract_odf(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    _fmt: Format,
    skipped: &mut SkippedParts,
) -> (String, Map<String, Value>) {
    const CONTENT: &str = "content.xml";
    const META: &str = "meta.xml";
    let content_xml = read_entry(archive, CONTENT, skipped);
    let text = match content_xml {
        Some(x) => collect_body_text(&x).take(CONTENT, skipped),
        None => String::new(),
    };
    let meta_xml = read_entry(archive, META, skipped);
    let props = match meta_xml {
        Some(x) => collect_named_text(&x, ODF_META_FIELDS).take(META, skipped),
        None => Map::new(),
    };
    (text, props)
}

/// (local element name, output key) pairs read from OOXML `core.xml`.
const CORE_PROP_FIELDS: &[(&[u8], &str)] = &[
    (b"title", "title"),
    (b"subject", "subject"),
    (b"creator", "author"),
    (b"lastModifiedBy", "last_modified_by"),
    (b"created", "created"),
    (b"modified", "modified"),
    (b"keywords", "keywords"),
];

/// (local element name, output key) pairs read from ODF `meta.xml`.
const ODF_META_FIELDS: &[(&[u8], &str)] = &[
    (b"title", "title"),
    (b"subject", "subject"),
    (b"creator", "author"),
    (b"initial-creator", "initial_creator"),
    (b"creation-date", "created"),
    (b"date", "modified"),
];

/// Concatenate the text of every element whose local name is `text_tag`,
/// inserting a newline whenever an element named `break_tag` closes. Used for
/// Word (`w:t` runs, `w:p` paragraphs) and PowerPoint (`a:t`, `a:p`).
fn collect_tagged_text(xml: &str, text_tag: &[u8], break_tag: &[u8]) -> XmlWalk<String> {
    let mut reader = Reader::from_str(xml);
    let mut out = String::new();
    let mut in_text = 0usize;
    let mut stopped = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if e.local_name().as_ref() == text_tag {
                    in_text += 1;
                }
            }
            Ok(Event::End(e)) => {
                let ln = e.local_name();
                if ln.as_ref() == text_tag && in_text > 0 {
                    in_text -= 1;
                }
                if ln.as_ref() == break_tag {
                    out.push('\n');
                }
            }
            Ok(Event::Text(t)) if in_text > 0 => {
                if let Ok(s) = t.unescape() {
                    out.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                stopped = Some(e.to_string());
                break;
            }
            _ => {}
        }
    }
    XmlWalk::plain(out, stopped)
}

/// Parse `xl/sharedStrings.xml` into the shared-string table: one entry per
/// `<si>`, being the concatenation of its `<t>` runs.
fn parse_shared_strings(xml: &str) -> XmlWalk<Vec<String>> {
    let mut reader = Reader::from_str(xml);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_si = false;
    let mut in_t = false;
    let mut stopped = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                b"si" => {
                    in_si = true;
                    cur.clear();
                }
                b"t" => in_t = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                b"si" if in_si => {
                    out.push(std::mem::take(&mut cur));
                    in_si = false;
                }
                b"t" => in_t = false,
                _ => {}
            },
            Ok(Event::Text(t)) if in_si && in_t => {
                if let Ok(s) = t.unescape() {
                    cur.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                stopped = Some(e.to_string());
                break;
            }
            _ => {}
        }
    }
    XmlWalk::plain(out, stopped)
}

/// Extract a worksheet's readable cells: shared-string cells (`t="s"`, `<v>` is
/// an index), inline strings (`<is><t>`) and literal values, tab-joined per row.
fn extract_worksheet(xml: &str, shared: &[String]) -> XmlWalk<String> {
    // The only part of an office document whose attributes this parser reads,
    // and therefore the only one that can reach quick-xml's quadratic
    // duplicate-name check. A `.xlsx` is an ordinary email attachment, so the
    // sheet XML inside one is attacker-chosen input.
    let mut guard = XmlGuard::default();
    let mut reader = Reader::from_str(xml);
    let mut out = String::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell_shared = false;
    let mut in_v = false;
    let mut in_t = false;
    let mut v = String::new();
    let mut inline = String::new();
    let mut stopped = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                b"c" => {
                    cell_shared = guard
                        .attributes(&e)
                        .into_iter()
                        .any(|a| a.key.local_name().as_ref() == b"t" && a.value.as_ref() == b"s");
                    v.clear();
                    inline.clear();
                }
                b"v" => in_v = true,
                b"t" => in_t = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                b"v" => in_v = false,
                b"t" => in_t = false,
                b"c" => {
                    let text = if !inline.is_empty() {
                        std::mem::take(&mut inline)
                    } else if cell_shared {
                        v.trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| shared.get(i).cloned())
                            .unwrap_or_default()
                    } else {
                        std::mem::take(&mut v)
                    };
                    if !text.is_empty() {
                        row.push(text);
                    }
                }
                b"row" if !row.is_empty() => {
                    out.push_str(&row.join("\t"));
                    out.push('\n');
                    row.clear();
                }
                _ => {}
            },
            Ok(Event::Text(t)) => {
                if in_v {
                    if let Ok(s) = t.unescape() {
                        v.push_str(&s);
                    }
                } else if in_t {
                    if let Ok(s) = t.unescape() {
                        inline.push_str(&s);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                stopped = Some(e.to_string());
                break;
            }
            _ => {}
        }
    }
    XmlWalk {
        value: out,
        stopped,
        anomalies: guard.describe(),
    }
}

/// Collect all text inside an ODF `<office:body>`, breaking lines on paragraph,
/// heading and table-row ends.
fn collect_body_text(xml: &str) -> XmlWalk<String> {
    let mut reader = Reader::from_str(xml);
    let mut out = String::new();
    let mut in_body = 0usize;
    let mut stopped = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if e.local_name().as_ref() == b"body" => in_body += 1,
            Ok(Event::End(e)) => {
                let ln = e.local_name();
                match ln.as_ref() {
                    b"body" if in_body > 0 => in_body -= 1,
                    b"p" | b"h" | b"table-row" if in_body > 0 => out.push('\n'),
                    _ => {}
                }
            }
            Ok(Event::Text(t)) if in_body > 0 => {
                if let Ok(s) = t.unescape() {
                    out.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                stopped = Some(e.to_string());
                break;
            }
            _ => {}
        }
    }
    XmlWalk::plain(out, stopped)
}

/// Read the first text value for each requested local element name into a map,
/// keyed by the paired output name. Absent fields are simply omitted.
fn collect_named_text(xml: &str, fields: &[(&[u8], &str)]) -> XmlWalk<Map<String, Value>> {
    let mut reader = Reader::from_str(xml);
    let mut map = Map::new();
    let mut active: Option<String> = None;
    let mut cur = String::new();
    let mut stopped = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let ln = e.local_name();
                if let Some((_, key)) = fields.iter().find(|(tag, _)| *tag == ln.as_ref()) {
                    active = Some((*key).to_string());
                    cur.clear();
                }
            }
            Ok(Event::End(e)) => {
                let ln = e.local_name();
                if fields.iter().any(|(tag, _)| *tag == ln.as_ref()) {
                    if let Some(key) = active.take() {
                        let val = cur.trim();
                        if !val.is_empty() && !map.contains_key(&key) {
                            map.insert(key, json!(val));
                        }
                    }
                }
            }
            Ok(Event::Text(t)) if active.is_some() => {
                if let Ok(s) = t.unescape() {
                    cur.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                stopped = Some(e.to_string());
                break;
            }
            _ => {}
        }
    }
    XmlWalk::plain(map, stopped)
}

/// The record emitted when a file that begins with the ZIP magic (and, usually,
/// carries an office extension) will not open as an archive at all.
///
/// Nothing can be extracted from it, but "nothing extracted" and "not an office
/// document" must not look the same: the first is a damaged exhibit that an
/// examiner may need to recover by other means, the second is a file no one
/// needs to look at again.
fn unreadable_container_record(
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    ext_kind: Option<Kind>,
    bytes_read: u64,
    declared_size: u64,
    error: &str,
) -> Artifact {
    let mut metadata = Map::new();
    metadata.insert("type".into(), json!("OfficeDocument"));
    metadata.insert("status".into(), json!("container_unreadable"));
    metadata.insert(
        "name".into(),
        json!(format!("Office document (unreadable): {file_name}")),
    );
    metadata.insert("file_name".into(), json!(file_name));
    if let Some(k) = ext_kind {
        let (fmt, is_odf) = match k {
            Kind::Ooxml(f) => (f, false),
            Kind::Odf(f) => (f, true),
        };
        metadata.insert("format".into(), json!(fmt.label()));
        metadata.insert(
            "container".into(),
            json!(if is_odf { "OpenDocument" } else { "OOXML" }),
        );
    }
    metadata.insert("content_incomplete".into(), json!(true));
    metadata.insert(
        "content_incomplete_reason".into(),
        json!(if bytes_read < declared_size {
            IncompleteReason::ShortRead.as_str()
        } else {
            IncompleteReason::UnresolvedStructure.as_str()
        }),
    );
    metadata.insert("inventory_incomplete".into(), json!(true));
    metadata.insert(
        "inventory_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    metadata.insert("bytes_read".into(), json!(bytes_read));
    metadata.insert("declared_size".into(), json!(declared_size));
    metadata.insert("open_error".into(), json!(error));
    metadata.insert("text".into(), json!(""));
    metadata.insert(
        "message".into(),
        json!(
            "This file starts with the ZIP magic but its archive directory could not be \
               read, so no text or properties could be extracted. That is not evidence the \
               document was empty or that it is not an office document"
        ),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(metadata),
    )
    .with_parent(parent_id)
    .with_subtype("office_document")
}

/// How much of the document's bytes the parse actually saw.
struct ContentRead {
    incomplete: bool,
    bytes_read: u64,
    declared_size: u64,
    /// Members the archive declared but the parser could not read.
    skipped_parts: SkippedParts,
}

/// Assemble the single `OfficeDocument` record.
#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    fmt: Format,
    is_odf: bool,
    mut text: String,
    props: Map<String, Value>,
    read: ContentRead,
) -> Artifact {
    let char_count = text.chars().count();
    let word_count = text.split_whitespace().count();
    let truncated = text.len() > MAX_TEXT_BYTES;
    if truncated {
        // Cut on a char boundary at or below the cap.
        let mut end = MAX_TEXT_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    let stored_text_bytes = text.len();

    let title = props
        .get("title")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(file_name);
    let container = if is_odf { "OpenDocument" } else { "OOXML" };

    let mut metadata = Map::new();
    metadata.insert("type".into(), json!("OfficeDocument"));
    metadata.insert("format".into(), json!(fmt.label()));
    metadata.insert("container".into(), json!(container));
    metadata.insert(
        "name".into(),
        json!(format!("{} document: {}", fmt.label(), title)),
    );
    metadata.insert("file_name".into(), json!(file_name));
    metadata.insert("text".into(), json!(text));
    metadata.insert("char_count".into(), json!(char_count));
    metadata.insert("word_count".into(), json!(word_count));
    metadata.insert("text_truncated".into(), json!(truncated));
    // B6-012: the text above was clipped at the storage cap. `text_truncated`
    // alone is a key no consumer reads, so a clipped body reaches the artifact
    // viewer, the search index and the completeness census looking whole. The
    // standard pair goes on first; a more fundamental shortfall below overwrites
    // the reason.
    if truncated {
        metadata.insert("content_incomplete".into(), json!(true));
        metadata.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::CapReached.as_str()),
        );
        metadata.insert("text_bytes_stored".into(), json!(stored_text_bytes));
        metadata.insert("max_text_bytes".into(), json!(MAX_TEXT_BYTES));
        metadata.insert(
            "message".into(),
            json!(
                "The document's extracted text is longer than the stored limit; the text \
                   below is the leading portion of it"
            ),
        );
    }
    if read.incomplete {
        metadata.insert("content_incomplete".into(), json!(true));
        metadata.insert(
            "content_incomplete_reason".into(),
            json!(if read.declared_size > MAX_CONTENT_BYTES {
                IncompleteReason::CapReached.as_str()
            } else {
                IncompleteReason::ShortRead.as_str()
            }),
        );
        metadata.insert("bytes_read".into(), json!(read.bytes_read));
        metadata.insert("declared_size".into(), json!(read.declared_size));
        metadata.insert("max_content_bytes".into(), json!(MAX_CONTENT_BYTES));
        metadata.insert(
            "message".into(),
            json!("Only part of the document archive was read; parts beyond it were not parsed"),
        );
    }
    // A part the archive declared but the parser could not inflate. The text
    // above is missing whatever that part held, and callers substituted an empty
    // string for it — so without this the document reads as genuinely blank.
    if read.skipped_parts.has_issues() {
        metadata.insert("content_incomplete".into(), json!(true));
        metadata.insert("parts_incomplete".into(), json!(true));
        // Only set the reason when the outer read did not already explain the
        // shortfall; that one is the more fundamental cause.
        if !read.incomplete {
            let reason = read
                .skipped_parts
                .parts
                .iter()
                .map(|(_, r)| *r)
                .max_by_key(|r| u8::from(*r == IncompleteReason::CapReached))
                .unwrap_or(IncompleteReason::UnresolvedStructure);
            metadata.insert("content_incomplete_reason".into(), json!(reason.as_str()));
            metadata.insert("max_entry_bytes".into(), json!(MAX_ENTRY_BYTES));
            metadata.insert(
                "message".into(),
                json!(
                    "One or more document parts were present but could not be read in full; \
                     the text and properties below omit whatever they held"
                ),
            );
        }
        if !read.skipped_parts.parts.is_empty() {
            metadata.insert(
                "skipped_parts".into(),
                json!(read
                    .skipped_parts
                    .parts
                    .iter()
                    .map(|(part, reason)| json!({ "part": part, "reason": reason.as_str() }))
                    .collect::<Vec<_>>()),
            );
        }
        // B6-013: a part that inflated fine but whose XML stopped on a parse
        // error part-way through. The extracted text is a prefix; unflagged, a
        // truncated-but-inflated `document.xml` reads as a short document.
        if !read.skipped_parts.xml_truncated.is_empty() {
            metadata.insert(
                "xml_truncated_parts".into(),
                json!(read
                    .skipped_parts
                    .xml_truncated
                    .iter()
                    .map(|(part, err)| json!({ "part": part, "error": err }))
                    .collect::<Vec<_>>()),
            );
        }
        // A part that parsed to EOF but tripped a bound of the reader, or
        // carried malformed attributes. Recorded separately from
        // `xml_truncated_parts` because the text here is NOT a prefix -- the
        // walk finished -- but the document was still not read in full, and a
        // document built to be expensive to parse is a finding in itself.
        if !read.skipped_parts.xml_anomalies.is_empty() {
            metadata.insert(
                "xml_anomalies".into(),
                json!(read
                    .skipped_parts
                    .xml_anomalies
                    .iter()
                    .map(|(part, detail)| json!({ "part": part, "detail": detail }))
                    .collect::<Vec<_>>()),
            );
        }
    }
    for (k, v) in props {
        metadata.entry(k).or_insert(v);
    }

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(metadata),
    )
    .with_parent(parent_id)
    .with_subtype("office_document")
}

#[cfg(test)]
mod tests;
