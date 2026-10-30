//! Resolving a firehose tracepoint's format string and rendering its message.
//!
//! A tracepoint names its format string by **reference** — an offset into the
//! `uuidtext` entry of the process's main executable, into the `dsc` shared
//! cache the process's catalog entry names, into an image found by address in
//! the catalog's per-process UUID table, or into a `uuidtext` entry named in
//! the tracepoint itself. This module holds those string tables, follows the
//! reference, and renders the message with the tracepoint's arguments.
//!
//! # The same machine's tree, or nothing
//!
//! A reference is only meaningful against the catalogue of the machine that
//! wrote the log: the same UUID names the same binary everywhere, but a tree
//! from another machine may hold a different build's strings under it, or
//! none. A [`CatalogueSet`] is therefore loaded from one tree — one
//! `.logarchive`, or one `/var/db/uuidtext` — and a reference it cannot
//! follow is reported as **unresolved, with the reason**, never rendered as an
//! empty message.
//!
//! # Rendering
//!
//! [`render`] is a printf-style formatter over Apple's format strings,
//! including the `%{public}`/`%{private}` annotations. A withheld argument
//! renders as `<private>`, as Apple's own tools render it. Arguments this
//! module does not decode — `%{…}P` objects other than `uuid_t`, and the
//! value-type annotations (`%{time_t}d`, `%{errno}d`, …) other than `bool` and
//! `BOOL` — render as their raw value, and the count of such renderings is
//! reported beside the text, so a rendering that is less than Apple's says so.
//!
//! The table layouts and the lookup rules follow the community reading in
//! Mandiant's `macos-UnifiedLogs` (Apache-2.0) and libyal's dtformats notes;
//! the reading is checked against the corpus, not taken as the answer.

use std::collections::HashMap;
use std::sync::Arc;

use crate::firehose::{FormatLocation, Item, ItemValue, Tracepoint, ACTIVITY, LOSS, SIGNPOST};
use crate::unifiedlog_chunks::Catalog;

/// A dynamic format: the high bit of the offset says the message is one
/// `%s` argument rather than a string in any table.
const DYNAMIC_BIT: u32 = 0x8000_0000;

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at.checked_add(8)?).map(|s| {
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        u64::from_le_bytes(b)
    })
}
fn c_string(d: &[u8], at: usize) -> Option<String> {
    let rest = d.get(at..)?;
    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// A per-image `uuidtext` entry's string table.
#[derive(Debug, Clone)]
pub(crate) struct UuidText {
    /// `(range start, size)`, in file order; each range's bytes follow the
    /// table in the same order.
    ranges: Vec<(u32, u32)>,
    /// Everything after the range table: the ranges' bytes, then the path.
    footer: Vec<u8>,
    pub(crate) path: Option<String>,
}

/// Parse a per-image `uuidtext` entry (magic `0x66778899`).
pub(crate) fn parse_uuidtext(d: &[u8]) -> Option<UuidText> {
    if le_u32(d, 0)? != 0x6677_8899 {
        return None;
    }
    let count = le_u32(d, 12)? as usize;
    if count > MAX_RANGES {
        return None;
    }
    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        ranges.push((le_u32(d, 16 + i * 8)?, le_u32(d, 20 + i * 8)?));
    }
    let footer = d.get(16 + count * 8..)?.to_vec();
    let strings: usize = ranges.iter().map(|(_, size)| *size as usize).sum();
    let path = if strings < footer.len() {
        c_string(&footer, strings)
    } else {
        None
    };
    Some(UuidText {
        ranges,
        footer,
        path,
    })
}

/// Ranges or images read from one table; past this a file is not believed.
const MAX_RANGES: usize = 1_000_000;

impl UuidText {
    /// The format string at a reference offset.
    pub(crate) fn format_at(&self, offset: u32) -> Option<String> {
        // Each range's bytes follow the previous range's, so a range's
        // position in the footer is the sum of the sizes before it.
        let mut at = 0usize;
        for &(start, size) in &self.ranges {
            if offset >= start && offset - start < size {
                let bytes = self.footer.get(at..at + size as usize)?;
                return c_string(bytes, (offset - start) as usize);
            }
            at += size as usize;
        }
        None
    }
}

/// One range of a shared cache.
#[derive(Debug, Clone)]
struct DscRange {
    start: u64,
    size: u32,
    data_offset: u32,
    image_index: u64,
}

/// One image a shared cache covers.
#[derive(Debug, Clone)]
pub(crate) struct DscImage {
    pub(crate) uuid: String,
    pub(crate) path: Option<String>,
}

/// A `dsc` shared cache's string table.
#[derive(Debug, Clone)]
pub(crate) struct Dsc {
    /// The format version, 1 or 2.
    #[allow(dead_code)]
    pub(crate) major: u16,
    ranges: Vec<DscRange>,
    images: Vec<DscImage>,
    data: Vec<u8>,
}

/// Parse a `dsc` shared cache (magic `hcsd`), version 1 or 2.
pub(crate) fn parse_dsc(d: &[u8]) -> Option<Dsc> {
    if d.get(0..4)? != b"hcsd" {
        return None;
    }
    let major = le_u16(d, 4)?;
    // Version 2 (Monterey and later) widens the range start and the image
    // load address to 64 bits and moves the range's image index to its end.
    let (range_bytes, image_bytes) = match major {
        1 => (16usize, 28usize),
        2 => (24, 32),
        _ => return None,
    };
    let range_count = le_u32(d, 8)? as usize;
    let image_count = le_u32(d, 12)? as usize;
    if range_count > MAX_RANGES || image_count > MAX_RANGES {
        return None;
    }
    let mut ranges = Vec::with_capacity(range_count);
    for i in 0..range_count {
        let at = 16 + i * range_bytes;
        ranges.push(if major == 2 {
            DscRange {
                start: le_u64(d, at)?,
                data_offset: le_u32(d, at + 8)?,
                size: le_u32(d, at + 12)?,
                image_index: le_u64(d, at + 16)?,
            }
        } else {
            DscRange {
                image_index: u64::from(le_u32(d, at)?),
                start: u64::from(le_u32(d, at + 4)?),
                data_offset: le_u32(d, at + 8)?,
                size: le_u32(d, at + 12)?,
            }
        });
    }
    let images_at = 16 + range_count * range_bytes;
    let mut images = Vec::with_capacity(image_count);
    for i in 0..image_count {
        let at = images_at + i * image_bytes;
        let (uuid_at, path_at) = if major == 2 {
            (at + 12, at + 28)
        } else {
            (at + 8, at + 24)
        };
        images.push(DscImage {
            uuid: hex(d.get(uuid_at..uuid_at + 16)?),
            path: c_string(d, le_u32(d, path_at)? as usize),
        });
    }
    ranges.sort_by_key(|r| r.start);
    Some(Dsc {
        major,
        ranges,
        images,
        data: d.to_vec(),
    })
}

impl Dsc {
    /// The format string and the image it belongs to, at a reference offset.
    pub(crate) fn format_at(&self, offset: u64) -> Option<(String, &DscImage)> {
        let read = |r: &DscRange| -> Option<(String, &DscImage)> {
            let within = offset.checked_sub(r.start)?;
            if within >= u64::from(r.size) {
                return None;
            }
            let from = r.data_offset as usize;
            let bytes = self.data.get(from..from + r.size as usize)?;
            let text = c_string(bytes, within as usize)?;
            let image = self.images.get(usize::try_from(r.image_index).ok()?)?;
            Some((text, image))
        };
        // The ranges are sorted by start: the candidate is the last one
        // starting at or before the offset. Ranges may abut or overlap, so a
        // miss there falls back to every range in order.
        let idx = self.ranges.partition_point(|r| r.start <= offset);
        idx.checked_sub(1)
            .and_then(|i| read(&self.ranges[i]))
            .or_else(|| self.ranges.iter().find_map(read))
    }

    /// The image a dynamic (`%s`) reference into the cache is attributed to:
    /// the first range's, as the community reading does.
    fn first_image(&self) -> Option<&DscImage> {
        let r = self.ranges.first()?;
        self.images.get(usize::try_from(r.image_index).ok()?)
    }
}

/// One machine's format-string catalogue: its `uuidtext` entries and shared
/// caches, keyed by 32 upper-case hex digits.
#[derive(Debug, Default)]
pub(crate) struct CatalogueSet {
    pub(crate) uuidtext: HashMap<String, Arc<UuidText>>,
    pub(crate) dsc: HashMap<String, Arc<Dsc>>,
}

impl CatalogueSet {
    /// Load one tree: a `.logarchive` root or a `uuidtext` directory, whose
    /// `<XX>/<30 hex>` files are entries and whose `dsc/<32 hex>` files are
    /// shared caches. Files that do not parse are skipped and counted.
    ///
    /// Test-only: the module reaches its tree file by file through
    /// `DataSource::open_from_ancestor` (see `unifiedlog_decode`); this whole
    /// directory walk is how the tests read a tree independently of that.
    #[cfg(test)]
    pub(crate) fn load_tree(root: &std::path::Path) -> (Self, usize) {
        let mut set = Self::default();
        let mut skipped = 0usize;
        let Ok(dirs) = std::fs::read_dir(root) else {
            return (set, skipped);
        };
        for dir in dirs.flatten() {
            let name = dir.file_name().to_string_lossy().into_owned();
            let is_hex = |s: &str| {
                s.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
            };
            if name == "dsc" {
                for f in std::fs::read_dir(dir.path())
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    let fname = f.file_name().to_string_lossy().into_owned();
                    if fname.len() != 32 || !is_hex(&fname) {
                        continue;
                    }
                    match std::fs::read(f.path()).ok().as_deref().and_then(parse_dsc) {
                        Some(d) => {
                            set.dsc.insert(fname, Arc::new(d));
                        }
                        None => skipped += 1,
                    }
                }
            } else if name.len() == 2 && is_hex(&name) {
                for f in std::fs::read_dir(dir.path())
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    let fname = f.file_name().to_string_lossy().into_owned();
                    if fname.len() != 30 || !is_hex(&fname) {
                        continue;
                    }
                    match std::fs::read(f.path())
                        .ok()
                        .as_deref()
                        .and_then(parse_uuidtext)
                    {
                        Some(u) => {
                            set.uuidtext.insert(format!("{name}{fname}"), Arc::new(u));
                        }
                        None => skipped += 1,
                    }
                }
            }
        }
        (set, skipped)
    }
}

/// What following a tracepoint's reference produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Resolution {
    /// The format string, when the reference was followed.
    pub(crate) format: Option<String>,
    /// Why it was not, in words.
    pub(crate) unresolved: Option<String>,
    /// The reference was a dynamic `%s`, not a string in any table.
    pub(crate) dynamic: bool,
    pub(crate) image_uuid: Option<String>,
    pub(crate) image_path: Option<String>,
    pub(crate) process_uuid: Option<String>,
    pub(crate) process_path: Option<String>,
    pub(crate) pid: Option<u32>,
    pub(crate) euid: Option<u32>,
    pub(crate) subsystem: Option<String>,
    pub(crate) category: Option<String>,
}

/// Follow a tracepoint's format-string reference through the catalog that
/// precedes it in its file and the machine's catalogue set.
pub(crate) fn resolve(
    t: &Tracepoint,
    first_proc_id: u64,
    second_proc_id: u32,
    catalog: &Catalog,
    set: &CatalogueSet,
) -> Resolution {
    let mut r = Resolution::default();
    if t.activity_type == LOSS {
        r.unresolved = Some("a loss record carries no format string".into());
        return r;
    }
    let Some(p) = catalog.process(first_proc_id, second_proc_id) else {
        r.unresolved = Some(format!(
            "the catalog before this entry names no process {first_proc_id}/{second_proc_id}, \
             so there is no binary to look the format string up in"
        ));
        return r;
    };
    r.pid = Some(p.pid);
    r.euid = Some(p.euid);
    let main_uuid = catalog.uuid(p.main_uuid_index).map(str::to_string);
    r.process_path = main_uuid
        .as_deref()
        .and_then(|u| set.uuidtext.get(u))
        .and_then(|u| u.path.clone());
    r.process_uuid = main_uuid.clone();
    if let Some(id) = t.subsystem_id {
        if let Some(sub) = p.subsystems.iter().find(|s| s.id == id) {
            r.subsystem = sub.subsystem.clone();
            r.category = sub.category.clone();
        }
    }
    let offset = t.format_offset;
    let dynamic = offset & DYNAMIC_BIT != 0;

    match &t.location {
        FormatLocation::SharedCache {
            large_offset,
            large_shared_cache,
            large_form,
        } => {
            // The community reading: an activity or signpost using the 0xc
            // formatter without a large offset takes its string from the main
            // executable, not the cache.
            let supports_large = matches!(t.activity_type, ACTIVITY | SIGNPOST);
            if !*large_form || !supports_large || *large_offset != 0 {
                from_dsc(
                    &mut r,
                    catalog.uuid(p.dsc_uuid_index),
                    offset,
                    *large_offset,
                    *large_shared_cache,
                    set,
                );
            } else {
                from_uuidtext(&mut r, main_uuid.as_deref(), offset, dynamic, set);
            }
        }
        FormatLocation::MainExe => {
            from_uuidtext(&mut r, main_uuid.as_deref(), offset, dynamic, set)
        }
        FormatLocation::UuidRelative(uuid) => {
            from_uuidtext(&mut r, Some(uuid.as_str()), offset, dynamic, set)
        }
        FormatLocation::Absolute { alt_index } => {
            let address = (u64::from(*alt_index) << 32) + u64::from(t.pc_id.unwrap_or_default());
            let image = p.uuids.iter().find(|u| {
                address >= u.load_address && address <= u.load_address + u64::from(u.size)
            });
            match image.and_then(|u| catalog.uuid(u.uuid_index)) {
                Some(uuid) => {
                    let dynamic = dynamic || u64::from(offset) == address;
                    from_uuidtext(&mut r, Some(uuid), offset, dynamic, set);
                }
                None => {
                    r.unresolved = Some(format!(
                        "no image in the process's catalog UUID table covers address \
                         {address:#x}, so the binary holding the format string is unknown"
                    ));
                }
            }
        }
        FormatLocation::Unknown(bits) => {
            r.unresolved = Some(format!(
                "the formatter bits {bits:#06x} name no location this reader knows"
            ));
        }
        FormatLocation::NotApplicable => {
            r.unresolved = Some("this entry kind carries no format string".into());
        }
    }
    r
}

/// Look a reference up in a `uuidtext` entry.
fn from_uuidtext(
    r: &mut Resolution,
    uuid: Option<&str>,
    offset: u32,
    dynamic: bool,
    set: &CatalogueSet,
) {
    let Some(uuid) = uuid else {
        r.unresolved = Some("the catalog names no UUID for this binary".into());
        return;
    };
    r.image_uuid = Some(uuid.to_string());
    let Some(entry) = set.uuidtext.get(uuid) else {
        r.unresolved = Some(format!(
            "the uuidtext entry {uuid} is not in this machine's catalogue tree"
        ));
        return;
    };
    r.image_path = entry.path.clone();
    if dynamic {
        r.dynamic = true;
        r.format = Some("%s".into());
        return;
    }
    match entry.format_at(offset) {
        Some(f) => r.format = Some(f),
        None => {
            r.unresolved = Some(format!(
                "offset {offset:#x} is in no range of uuidtext entry {uuid}"
            ))
        }
    }
}

/// Look a reference up in a `dsc` shared cache.
fn from_dsc(
    r: &mut Resolution,
    uuid: Option<&str>,
    offset: u32,
    large_offset: u16,
    large_shared_cache: u16,
    set: &CatalogueSet,
) {
    let Some(uuid) = uuid else {
        r.unresolved = Some("the catalog names no shared cache for this process".into());
        return;
    };
    let Some(dsc) = set.dsc.get(uuid) else {
        r.unresolved = Some(format!(
            "the shared cache {uuid} is not in this machine's catalogue tree"
        ));
        return;
    };
    if offset & DYNAMIC_BIT != 0 {
        r.dynamic = true;
        r.format = Some("%s".into());
        if let Some(image) = dsc.first_image() {
            r.image_uuid = Some(image.uuid.clone());
            r.image_path = image.path.clone();
        }
        return;
    }
    // A large offset widens the 32-bit reference: by 0x80000000 per unit
    // when it is 1 or 2 and exceeds the large-shared-cache field, otherwise
    // by 4 GiB per unit of half that field, or of itself.
    let widen = if large_offset == 0 {
        0
    } else if matches!(large_offset, 1 | 2) && large_offset > large_shared_cache {
        0x8000_0000 * u64::from(large_offset)
    } else if large_shared_cache != 0 {
        0x1_0000_0000 * u64::from(large_shared_cache / 2)
    } else {
        0x1_0000_0000 * u64::from(large_offset)
    };
    let at = widen + u64::from(offset);
    match dsc.format_at(at) {
        Some((f, image)) => {
            r.format = Some(f);
            r.image_uuid = Some(image.uuid.clone());
            r.image_path = image.path.clone();
        }
        None => {
            r.unresolved = Some(format!(
                "offset {at:#x} is in no range of shared cache {uuid}"
            ))
        }
    }
}

/// A rendered message, and how much of it is less than Apple's rendering.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Rendered {
    pub(crate) text: String,
    /// Arguments rendered as their raw value because this module does not
    /// decode their annotation or object type.
    pub(crate) rendered_raw: usize,
    /// Specifiers with no argument left to fill them.
    pub(crate) missing_arguments: usize,
}

/// Render a format string with a tracepoint's arguments.
pub(crate) fn render(format: &str, items: &[Item]) -> Rendered {
    let mut r = Rendered::default();
    let b = format.as_bytes();
    let mut next = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'%' {
            let j = format[i..].find('%').map_or(b.len(), |k| i + k);
            r.text.push_str(&format[i..j]);
            i = j;
            continue;
        }
        if b.get(i + 1) == Some(&b'%') {
            r.text.push('%');
            i += 2;
            continue;
        }
        let start = i;
        match parse_spec(format, i + 1) {
            Some((spec, end)) => {
                i = end;
                render_one(&spec, items, &mut next, &mut r);
            }
            None => {
                // Not a conversion this formatter knows: kept as written.
                r.text.push('%');
                i = start + 1;
            }
        }
    }
    r
}

/// One conversion specifier.
#[derive(Debug, Default)]
struct Spec {
    annotation: Option<String>,
    left: bool,
    plus: bool,
    alt: bool,
    zero: bool,
    width: Option<usize>,
    width_arg: bool,
    precision: Option<usize>,
    precision_arg: bool,
    long: bool,
    conv: char,
}

/// Parse the specifier after a `%` at byte `at`. `None` when it is not one.
fn parse_spec(f: &str, mut at: usize) -> Option<(Spec, usize)> {
    let b = f.as_bytes();
    let mut s = Spec::default();
    if b.get(at) == Some(&b'{') {
        let end = f[at..].find('}')?;
        s.annotation = Some(f[at + 1..at + end].to_string());
        at += end + 1;
    }
    while let Some(c) = b.get(at) {
        match c {
            b'-' => s.left = true,
            b'+' => s.plus = true,
            b'#' => s.alt = true,
            b'0' => s.zero = true,
            b' ' => {}
            _ => break,
        }
        at += 1;
    }
    if b.get(at) == Some(&b'*') {
        s.width_arg = true;
        at += 1;
    } else {
        let d = digits(b, &mut at);
        s.width = d;
    }
    if b.get(at) == Some(&b'.') {
        at += 1;
        if b.get(at) == Some(&b'*') {
            s.precision_arg = true;
            at += 1;
        } else {
            s.precision = Some(digits(b, &mut at).unwrap_or(0));
        }
    }
    while let Some(c) = b.get(at) {
        match c {
            b'h' => {}
            b'l' | b'q' | b'j' | b'z' | b't' | b'L' => s.long = true,
            _ => break,
        }
        at += 1;
    }
    let c = *b.get(at)? as char;
    if !"diouxXcsSpPaAeEfFgG@mC".contains(c) {
        return None;
    }
    s.conv = c;
    Some((s, at + 1))
}

fn digits(b: &[u8], at: &mut usize) -> Option<usize> {
    let from = *at;
    while b.get(*at).is_some_and(u8::is_ascii_digit) {
        *at += 1;
    }
    std::str::from_utf8(&b[from..*at]).ok()?.parse().ok()
}

/// The next argument, as a count (for `*` width or precision).
fn take_count(items: &[Item], next: &mut usize) -> Option<usize> {
    let item = items.get(*next)?;
    *next += 1;
    match item.value {
        ItemValue::Precision(v) => usize::try_from(v).ok(),
        ItemValue::Number(v) => usize::try_from(v).ok(),
        _ => None,
    }
}

/// The widest field a width or precision may ask for. Both come from the
/// catalogue's format string or from an argument — evidence, not code — and
/// an unbounded one is gigabytes of padding or a formatter panic.
pub(crate) const MAX_FIELD_WIDTH: usize = 4096;

fn render_one(spec: &Spec, items: &[Item], next: &mut usize, r: &mut Rendered) {
    let mut width = spec.width;
    let mut precision = spec.precision;
    if spec.width_arg {
        width = take_count(items, next);
    }
    if spec.precision_arg {
        precision = take_count(items, next);
    } else if items
        .get(*next)
        .is_some_and(|i| matches!(i.value, ItemValue::Precision(_)))
    {
        // A length the OS recorded for an argument whose format states none.
        let _ = take_count(items, next);
    }
    let width = width.map(|w| w.min(MAX_FIELD_WIDTH));
    let precision = precision.map(|p| p.min(MAX_FIELD_WIDTH));
    let Some(item) = items.get(*next) else {
        r.missing_arguments += 1;
        r.text.push_str("<missing argument>");
        return;
    };
    *next += 1;

    // The annotation: privacy words, and at most one value type.
    let mut value_type: Option<String> = None;
    if let Some(a) = &spec.annotation {
        for word in a.split(',').map(str::trim) {
            match word {
                "public" | "private" | "sensitive" | "" => {}
                w if w.starts_with("mask.") || w.starts_with("name=") => {}
                w => value_type = Some(w.to_string()),
            }
        }
    }

    let body = match &item.value {
        ItemValue::Private => "<private>".to_string(),
        ItemValue::Missing => "<missing data>".to_string(),
        ItemValue::Null => "(null)".to_string(),
        ItemValue::Precision(v) => v.to_string(),
        ItemValue::Number(v) => match value_type.as_deref() {
            Some("bool") => (if *v != 0 { "true" } else { "false" }).to_string(),
            Some("BOOL") => (if *v != 0 { "YES" } else { "NO" }).to_string(),
            Some(_) => {
                r.rendered_raw += 1;
                number(*v, spec, precision)
            }
            // A %c whose value is not a Unicode scalar value cannot be shown
            // as a character: it is rendered as its number and counted.
            None if matches!(spec.conv, 'c' | 'C') && char::from_u32(*v as u32).is_none() => {
                r.rendered_raw += 1;
                format!("<invalid character {:#x}>", *v as u32)
            }
            None => number(*v, spec, precision),
        },
        ItemValue::Text(t) => match precision {
            Some(p) if matches!(spec.conv, 's' | 'S' | '@') => t.chars().take(p).collect(),
            _ => t.clone(),
        },
        ItemValue::Bytes(bytes) => match value_type.as_deref() {
            Some("uuid_t") if bytes.len() == 16 => {
                let h = hex(bytes);
                format!(
                    "{}-{}-{}-{}-{}",
                    &h[0..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..32]
                )
            }
            _ => {
                r.rendered_raw += 1;
                format!("<{} bytes: {}>", bytes.len(), hex(bytes))
            }
        },
    };
    let numeric = matches!(item.value, ItemValue::Number(_))
        && "diouxXp".contains(spec.conv)
        && value_type.is_none();
    r.text
        .push_str(&pad(body, width, spec.left, spec.zero && numeric));
}

/// A number, per its conversion.
fn number(v: i64, spec: &Spec, precision: Option<usize>) -> String {
    // An argument's recorded width is lost by here; a negative value under
    // an unsigned conversion is read at the width the format states.
    let unsigned = |v: i64| -> u64 {
        if spec.long || v >= 0 {
            v as u64
        } else {
            u64::from(v as i32 as u32)
        }
    };
    let digits = match spec.conv {
        'd' | 'i' => {
            let s = v.unsigned_abs().to_string();
            let s = zero_extend(s, precision);
            if v < 0 {
                format!("-{s}")
            } else if spec.plus {
                format!("+{s}")
            } else {
                s
            }
        }
        'u' => zero_extend(unsigned(v).to_string(), precision),
        'x' => {
            let s = zero_extend(format!("{:x}", unsigned(v)), precision);
            if spec.alt && v != 0 {
                format!("0x{s}")
            } else {
                s
            }
        }
        'X' => {
            let s = zero_extend(format!("{:X}", unsigned(v)), precision);
            if spec.alt && v != 0 {
                format!("0X{s}")
            } else {
                s
            }
        }
        'o' => zero_extend(format!("{:o}", unsigned(v)), precision),
        'p' => format!("0x{:x}", v as u64),
        // render_one has already caught a value that is not a scalar value.
        'c' | 'C' => char::from_u32(v as u32)
            .map(String::from)
            .unwrap_or_else(|| format!("<invalid character {:#x}>", v as u32)),
        'e' | 'E' | 'f' | 'F' | 'g' | 'G' | 'a' | 'A' => {
            let f = f64::from_bits(v as u64);
            format!("{:.*}", precision.unwrap_or(6), f)
        }
        _ => v.to_string(),
    };
    digits
}

fn zero_extend(s: String, precision: Option<usize>) -> String {
    match precision {
        Some(p) if p > s.len() => format!("{}{s}", "0".repeat(p - s.len())),
        _ => s,
    }
}

fn pad(s: String, width: Option<usize>, left: bool, zero: bool) -> String {
    let Some(w) = width else {
        return s;
    };
    let len = s.chars().count();
    if len >= w {
        return s;
    }
    let fill = w - len;
    if left {
        format!("{s}{}", " ".repeat(fill))
    } else if zero {
        let (sign, rest) = match s.strip_prefix('-') {
            Some(rest) => ("-", rest.to_string()),
            None => ("", s.clone()),
        };
        format!("{sign}{}{rest}", "0".repeat(fill))
    } else {
        format!("{}{s}", " ".repeat(fill))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::unifiedlog_chunks::{ProcessInfo, ProcessUuid, Subsystem};

    // --- fixture construction, from literal offsets ---------------------------

    fn entry_file(ranges: &[(u32, &[&str])], path: &str) -> Vec<u8> {
        let blobs: Vec<Vec<u8>> = ranges
            .iter()
            .map(|(_, strings)| {
                let mut b = Vec::new();
                for s in *strings {
                    b.extend_from_slice(s.as_bytes());
                    b.push(0);
                }
                b
            })
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(&0x6677_8899u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
        for ((start, _), blob) in ranges.iter().zip(&blobs) {
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        }
        for blob in &blobs {
            out.extend_from_slice(blob);
        }
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out
    }

    /// A shared cache holding one image and one range of strings starting at
    /// range offset `start`, in version `major`'s layout.
    fn shared_cache(
        major: u16,
        start: u64,
        strings: &[&str],
        uuid: [u8; 16],
        path: &str,
    ) -> Vec<u8> {
        let (range_bytes, image_bytes) = if major == 2 { (24, 32) } else { (16, 28) };
        let strings_at = 16 + range_bytes + image_bytes;
        let mut blob = Vec::new();
        for s in strings {
            blob.extend_from_slice(s.as_bytes());
            blob.push(0);
        }
        let path_at = strings_at + blob.len();
        let mut out = b"hcsd".to_vec();
        out.extend_from_slice(&major.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        if major == 2 {
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&(strings_at as u32).to_le_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&start.to_le_bytes());
        } else {
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(start as u32).to_le_bytes());
            out.extend_from_slice(&(strings_at as u32).to_le_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            out.extend_from_slice(&(start as u32).to_le_bytes());
        }
        out.extend_from_slice(&0x1000u32.to_le_bytes());
        out.extend_from_slice(&uuid);
        out.extend_from_slice(&(path_at as u32).to_le_bytes());
        assert_eq!(out.len(), strings_at, "the fixture's own arithmetic");
        out.extend_from_slice(&blob);
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out
    }

    const MAIN: &str = "11111111111111111111111111111111";
    const DSC: &str = "22222222222222222222222222222222";

    fn catalog() -> Catalog {
        Catalog {
            uuids: vec![MAIN.into(), DSC.into()],
            processes: vec![ProcessInfo {
                index: 0,
                main_uuid_index: 0,
                dsc_uuid_index: 1,
                first_proc_id: 5,
                second_proc_id: 6,
                pid: 321,
                euid: 501,
                uuids: vec![ProcessUuid {
                    size: 0x1000,
                    uuid_index: 0,
                    load_address: 0x5000,
                }],
                subsystems: vec![Subsystem {
                    id: 3,
                    subsystem: Some("com.example.sub".into()),
                    category: Some("cat".into()),
                }],
            }],
            ..Default::default()
        }
    }

    fn tracepoint(location: FormatLocation, offset: u32, items: Vec<Item>) -> Tracepoint {
        Tracepoint {
            activity_type: 4,
            log_type: 0,
            flags: 0,
            format_offset: offset,
            thread_id: 1,
            continuous_time: 0,
            pc_id: Some(0),
            location,
            subsystem_id: Some(3),
            activity_id: None,
            unique_pid: None,
            signpost_id: None,
            signpost_name: None,
            oversize_ref: None,
            items,
            backtrace_frames: 0,
            loss: None,
            flaw: None,
        }
    }

    /// A %c argument that is not a Unicode scalar value is rendered as its
    /// raw number and counted, not dropped as an empty string.
    #[test]
    fn an_invalid_character_argument_is_rendered_raw_and_counted() {
        let r = render("[%c]", &[item(0x00, ItemValue::Number(0xD800))]);
        assert_eq!(r.text, "[<invalid character 0xd800>]");
        assert_eq!(r.rendered_raw, 1);
        let r = render("[%c]", &[item(0x00, ItemValue::Number(0x41))]);
        assert_eq!(r.text, "[A]");
        assert_eq!(r.rendered_raw, 0);
    }

    fn item(item_type: u8, value: ItemValue) -> Item {
        Item {
            item_type,
            value,
            from_private_data: false,
            declared_size: 0,
        }
    }

    fn set_with_main(bytes: Vec<u8>) -> CatalogueSet {
        let mut set = CatalogueSet::default();
        set.uuidtext.insert(
            MAIN.into(),
            Arc::new(parse_uuidtext(&bytes).expect("an entry file")),
        );
        set
    }

    #[test]
    fn a_main_exe_reference_resolves_to_the_entry_files_string() {
        let bytes = entry_file(
            &[(0x100, &["first %d", "second %s"]), (0x900, &["third"])],
            "/usr/libexec/demo",
        );
        let set = set_with_main(bytes);
        // "second %s" is 9 bytes into the first range; "third" starts the
        // second range, whose bytes follow the first's.
        let r = resolve(
            &tracepoint(FormatLocation::MainExe, 0x109, vec![]),
            5,
            6,
            &catalog(),
            &set,
        );
        assert_eq!(r.format.as_deref(), Some("second %s"));
        assert_eq!(r.image_path.as_deref(), Some("/usr/libexec/demo"));
        assert_eq!(r.process_path.as_deref(), Some("/usr/libexec/demo"));
        assert_eq!((r.pid, r.euid), (Some(321), Some(501)));
        assert_eq!(r.subsystem.as_deref(), Some("com.example.sub"));
        assert_eq!(r.category.as_deref(), Some("cat"));
        let r = resolve(
            &tracepoint(FormatLocation::MainExe, 0x900, vec![]),
            5,
            6,
            &catalog(),
            &set,
        );
        assert_eq!(r.format.as_deref(), Some("third"));
        // The high bit makes it a dynamic "%s", not a table lookup.
        let r = resolve(
            &tracepoint(FormatLocation::MainExe, 0x8000_0000, vec![]),
            5,
            6,
            &catalog(),
            &set,
        );
        assert!(r.dynamic);
        assert_eq!(r.format.as_deref(), Some("%s"));
    }

    #[test]
    fn a_shared_cache_reference_resolves_through_the_dsc_range_table() {
        for major in [1u16, 2] {
            let bytes = shared_cache(
                major,
                0x4000,
                &["cache says %s", "and %d"],
                [0x33; 16],
                "/System/Library/Frameworks/Demo.framework/Demo",
            );
            let mut set = set_with_main(entry_file(&[(0, &["x"])], "/usr/libexec/demo"));
            set.dsc.insert(
                DSC.into(),
                Arc::new(parse_dsc(&bytes).expect("a shared cache")),
            );
            let loc = FormatLocation::SharedCache {
                large_offset: 0,
                large_shared_cache: 0,
                large_form: false,
            };
            let r = resolve(&tracepoint(loc, 0x400e, vec![]), 5, 6, &catalog(), &set);
            assert_eq!(r.format.as_deref(), Some("and %d"), "version {major}");
            assert_eq!(
                r.image_uuid.as_deref(),
                Some("33333333333333333333333333333333")
            );
            assert_eq!(
                r.image_path.as_deref(),
                Some("/System/Library/Frameworks/Demo.framework/Demo")
            );
        }
    }

    #[test]
    fn a_reference_into_a_catalogue_that_is_absent_says_unresolved_not_empty() {
        let set = CatalogueSet::default();
        let r = resolve(
            &tracepoint(FormatLocation::MainExe, 0x10, vec![]),
            5,
            6,
            &catalog(),
            &set,
        );
        assert_eq!(r.format, None);
        assert!(r.unresolved.as_deref().unwrap().contains(MAIN), "{r:?}");
        // A process the catalog does not name.
        let r = resolve(
            &tracepoint(FormatLocation::MainExe, 0x10, vec![]),
            9,
            9,
            &catalog(),
            &set,
        );
        assert!(r.unresolved.as_deref().unwrap().contains("catalog"));
        // An offset the entry file does not cover.
        let set = set_with_main(entry_file(&[(0, &["x"])], "/usr/libexec/demo"));
        let r = resolve(
            &tracepoint(FormatLocation::MainExe, 0x7777, vec![]),
            5,
            6,
            &catalog(),
            &set,
        );
        assert_eq!(r.format, None);
        assert!(r.unresolved.as_deref().unwrap().contains("offset"));
        // The rendering of an unresolved message is not an empty string.
        assert_eq!(r.image_path.as_deref(), Some("/usr/libexec/demo"));
    }

    #[test]
    fn format_items_render_with_private_marked() {
        let items = vec![
            item(0x00, ItemValue::Number(42)),
            item(0x21, ItemValue::Private),
            item(0x22, ItemValue::Text("world".into())),
            item(0x00, ItemValue::Number(255)),
            item(0x42, ItemValue::Null),
        ];
        let r = render(
            "n=%d who=%{private}s hi %{public}s hex=%#x obj=%@ 100%%",
            &items,
        );
        assert_eq!(
            r.text,
            "n=42 who=<private> hi world hex=0xff obj=(null) 100%"
        );
        assert_eq!(r.missing_arguments, 0);
        // A specifier with nothing left to fill it says so.
        let r = render("a %d b %s", &[item(0x00, ItemValue::Number(1))]);
        assert_eq!(r.text, "a 1 b <missing argument>");
        assert_eq!(r.missing_arguments, 1);
        // Width, precision, and a dynamic precision argument.
        let r = render(
            "[%5d|%-4s|%.*s|%03u]",
            &[
                item(0x00, ItemValue::Number(7)),
                item(0x22, ItemValue::Text("ab".into())),
                item(0x10, ItemValue::Precision(3)),
                item(0x22, ItemValue::Text("abcdef".into())),
                item(0x00, ItemValue::Number(9)),
            ],
        );
        assert_eq!(r.text, "[    7|ab  |abc|009]");
        // A width or precision a format string (or an argument) states is
        // clamped, so a hostile catalogue cannot demand gigabytes of padding
        // (found by the unifiedlog_tracev3 fuzz target).
        for f in ["%50000000d", "%.50000000d", "%.50000000f", "%*d"] {
            let r = render(
                f,
                &[
                    item(0x00, ItemValue::Number(50_000_000)),
                    item(0x00, ItemValue::Number(1)),
                ],
            );
            assert!(
                r.text.len() <= MAX_FIELD_WIDTH + 64,
                "{f}: {}",
                r.text.len()
            );
        }
        // bool / BOOL are decoded; an undecoded annotation is raw and counted.
        let r = render(
            "%{bool}d %{BOOL}d %{time_t}d",
            &[
                item(0x00, ItemValue::Number(1)),
                item(0x00, ItemValue::Number(0)),
                item(0x00, ItemValue::Number(1_600_000_000)),
            ],
        );
        assert_eq!(r.text, "true NO 1600000000");
        assert_eq!(r.rendered_raw, 1);
        // A uuid_t object renders as a UUID.
        let r = render(
            "%{public,uuid_t}.16P",
            &[item(0x32, ItemValue::Bytes((0u8..16).collect()))],
        );
        assert_eq!(r.text, "00010203-0405-0607-0809-0A0B0C0D0E0F");
    }

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    /// Resolve every firehose tracepoint in one Big Sur Persist file against
    /// the tree it came from, and render it.
    #[test]
    fn the_big_sur_persist_file_resolves_against_its_own_tree() {
        use crate::firehose::parse_firehose;
        use crate::unifiedlog_chunks::{
            decompress_chunkset, parse_catalog, walk_entries, TAG_FIREHOSE,
        };
        let root = corpus().join("system_logs_big_sur.logarchive");
        let Ok(file) = std::fs::read(root.join("Persist/0000000000000004.tracev3")) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let (set, skipped) = CatalogueSet::load_tree(&root);
        assert_eq!(skipped, 0, "every catalogue file in the tree parses");

        let mut catalog = Catalog::default();
        let (mut resolved, mut dynamic, mut unresolved, mut raw) = (0usize, 0usize, 0usize, 0usize);
        let mut first: Option<(String, String, Resolution)> = None;
        let mut reasons: Vec<String> = Vec::new();
        let mut losses = 0usize;
        let mut off = 0usize;
        while off + 16 <= file.len() {
            let tag = u32::from_le_bytes(file[off..off + 4].try_into().unwrap());
            let size = u64::from_le_bytes(file[off + 8..off + 16].try_into().unwrap()) as usize;
            let body = &file[off + 16..off + 16 + size];
            if tag == 0x600b {
                catalog = parse_catalog(body).unwrap();
            } else if tag == 0x600d {
                let bytes = decompress_chunkset(body).unwrap();
                for e in walk_entries(&bytes).entries {
                    if e.tag != TAG_FIREHOSE {
                        continue;
                    }
                    let chunk = parse_firehose(e.payload).unwrap();
                    for t in &chunk.tracepoints {
                        if t.activity_type == LOSS {
                            losses += 1;
                            continue;
                        }
                        let r =
                            resolve(t, chunk.first_proc_id, chunk.second_proc_id, &catalog, &set);
                        match &r.format {
                            Some(f) => {
                                if r.dynamic {
                                    dynamic += 1;
                                } else {
                                    resolved += 1;
                                }
                                let text = render(f, &t.items);
                                raw += text.rendered_raw;
                                if first.is_none() {
                                    first = Some((f.clone(), text.text, r.clone()));
                                }
                            }
                            None => {
                                unresolved += 1;
                                reasons.push(r.unresolved.clone().unwrap_or_default());
                            }
                        }
                    }
                }
            }
            off += 16 + size;
            off += (8 - off % 8) % 8;
        }
        let (format, text, r) = first.expect("a resolved message");
        // Mandiant's reading of this file's first entry, as a comparison.
        assert_eq!(format, "opendirectoryd (build %{public}s) launched...");
        assert_eq!(text, "opendirectoryd (build 796.100) launched...");
        assert_eq!(
            r.process_path.as_deref(),
            Some("/usr/libexec/opendirectoryd")
        );
        assert_eq!(r.subsystem.as_deref(), Some("com.apple.opendirectoryd"));
        assert_eq!(r.pid, Some(105));
        // 110,836 resolved, 108 dynamic `%s`, 8 unresolved and 1 loss record:
        // 110,953 entries, which is Mandiant's count for this file. The 8 are
        // one offset the entry file's ranges do not cover, said as such.
        assert_eq!((resolved, dynamic, unresolved, losses), PERSIST_4_COUNTS);
        assert!(reasons.iter().all(|r| {
            r == "offset 0x422304 is in no range of uuidtext entry E502E11E518F38A79F0BE129168338E7"
        }));
        eprintln!("{raw} argument(s) rendered raw");
    }

    /// Every tracepoint in each of the six corpus archives, resolved against
    /// that archive's own tree: `(resolved, dynamic, unresolved, loss)`.
    #[test]
    fn every_corpus_archive_resolves_against_its_own_tree() {
        use crate::firehose::parse_firehose;
        use crate::unifiedlog_chunks::{
            decompress_chunkset, parse_catalog, walk_entries, TAG_FIREHOSE,
        };
        let Ok(archives) = std::fs::read_dir(corpus()) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let mut got = std::collections::BTreeMap::new();
        for a in archives.flatten() {
            let name = a.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".logarchive") {
                continue;
            }
            let (set, skipped) = CatalogueSet::load_tree(&a.path());
            assert_eq!(skipped, 0, "{name}");
            let mut counts = (0usize, 0usize, 0usize, 0usize);
            let mut reasons: std::collections::BTreeMap<String, usize> = Default::default();
            let mut stack = vec![a.path()];
            while let Some(dir) = stack.pop() {
                for e in std::fs::read_dir(&dir).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                        continue;
                    }
                    if p.extension().is_none_or(|x| x != "tracev3") {
                        continue;
                    }
                    let file = std::fs::read(&p).unwrap();
                    let mut catalog = Catalog::default();
                    let mut off = 0usize;
                    while off + 16 <= file.len() {
                        let tag = u32::from_le_bytes(file[off..off + 4].try_into().unwrap());
                        let size = u64::from_le_bytes(file[off + 8..off + 16].try_into().unwrap())
                            as usize;
                        let Some(body) = file.get(off + 16..off + 16 + size) else {
                            break;
                        };
                        if tag == 0x600b {
                            catalog = parse_catalog(body).unwrap();
                        } else if tag == 0x600d {
                            let bytes = decompress_chunkset(body).unwrap();
                            for e in walk_entries(&bytes).entries {
                                if e.tag != TAG_FIREHOSE {
                                    continue;
                                }
                                let chunk = parse_firehose(e.payload).unwrap();
                                for t in &chunk.tracepoints {
                                    if t.activity_type == LOSS {
                                        counts.3 += 1;
                                        continue;
                                    }
                                    let r = resolve(
                                        t,
                                        chunk.first_proc_id,
                                        chunk.second_proc_id,
                                        &catalog,
                                        &set,
                                    );
                                    match (&r.format, r.dynamic) {
                                        (Some(_), true) => counts.1 += 1,
                                        (Some(_), false) => counts.0 += 1,
                                        (None, _) => {
                                            counts.2 += 1;
                                            let why = r.unresolved.unwrap_or_default();
                                            let class = why
                                                .split_whitespace()
                                                .filter(|w| !w.chars().any(|c| c.is_ascii_digit()))
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            *reasons.entry(class).or_default() += 1;
                                        }
                                    }
                                }
                            }
                        }
                        off += 16 + size;
                        off += (8 - off % 8) % 8;
                    }
                }
            }
            let unresolved_by_reason: usize = reasons.values().sum();
            assert_eq!(unresolved_by_reason, counts.2, "{name}: {reasons:#?}");
            got.insert(name, counts);
        }
        let want: std::collections::BTreeMap<String, (usize, usize, usize, usize)> =
            CORPUS_RESOLUTION
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
        assert_eq!(got, want);
    }

    /// As a comparison, not an answer key: the unresolved counts by reason
    /// equal the categories Mandiant's tests pin for the same archives — High
    /// Sierra 3 bad offsets; Big Sur 54; Monterey 531 absent entries, 60 bad
    /// offsets and 309 bad shared-cache offsets; Tahoe 2, 268 and 647, which
    /// their tests say were checked against Apple's own `log raw-dump`.
    pub(crate) type Census = (usize, usize, usize, usize);
    pub(crate) const CORPUS_RESOLUTION: [(&str, Census); 6] = [
        ("system_logs_high_sierra.logarchive", (569_400, 180, 3, 0)),
        ("system_logs_big_sur.logarchive", (746_682, 553, 54, 5)),
        (
            "system_logs_big_sur_private_enabled.logarchive",
            (886_662, 678, 60, 6),
        ),
        (
            "system_logs_big_sur_public_private_data_mix.logarchive",
            (1_286_876, 484, 22, 3),
        ),
        (
            "system_logs_monterey.logarchive",
            (2_231_582, 1_400, 900, 23),
        ),
        ("system_logs_tahoe.logarchive", (4_173_949, 196, 917, 9)),
    ];

    const PERSIST_4_COUNTS: (usize, usize, usize, usize) = (110_836, 108, 8, 1);
}
