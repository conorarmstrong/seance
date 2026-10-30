//! Version resources of loaded images (`ROADMAP` §5.3, upstream's `verinfo`).
//!
//! # What an examiner learns
//!
//! What each loaded driver and DLL says it is: the file and product version
//! its linker stamped into it, the company, the original file name. It is
//! read from the image **in memory**, so it is the version of the code that
//! was running — not the version of a file on disk that may since have been
//! replaced — and a module whose in-memory version disagrees with its name,
//! or whose company is not who signed the file it claims to be, is a lead.
//!
//! # Where it comes from
//!
//! A PE's resource directory (data directory entry 2) is a three-level tree:
//! type, name, language. The `RT_VERSION` type (16) leads to a data entry
//! whose bytes are a `VS_VERSIONINFO` block: a `VS_FIXEDFILEINFO` (signature
//! `0xFEEF04BD`, the four-part versions as two double-words each) followed by
//! `StringFileInfo` tables of key/value strings and a `VarFileInfo`
//! translation list. The layout is Microsoft's published one; every field is
//! read at the offset the format prescribes and the block's own length
//! fields bound every read.
//!
//! # Seven ways an image has no version, told apart
//!
//! Headers that will not read (a paged-out DLL — the ordinary case, and not
//! evidence about the image); bytes at the loader's address that are not a
//! PE; no resource directory at all; a resource tree with no `RT_VERSION`
//! entry; a tree or data entry that will not read; a block that does not
//! decode; and a resource section marked **discardable**, which is not read.
//! Each is its own
//! [`VersionOutcome`], because "this DLL's version could not be read" and
//! "this DLL carries no version" are different facts and the second is a
//! finding.
//!
//! The last is the kernel's own case, measured on the Windows 11 26200
//! capture: `ntoskrnl.exe`'s `.rsrc` section carries
//! `IMAGE_SCN_MEM_DISCARDABLE`, the memory manager frees discardable sections
//! of a driver once boot completes, and the bytes at the resource directory's
//! address were code from something else — reading them as a directory
//! produced "65,535 entries". So a resource directory that falls in a
//! discardable section is reported as discarded and **not read at all**,
//! which upstream's `verinfo` meets the same way. The test is the section
//! flag alone: the reader does not look at the bytes, so the record says the
//! section is marked discardable and was not read, not that the bytes there
//! were checked. That is right for a driver, whose discardable sections the
//! kernel does free; a user-mode image is mapped by a loader that does not
//! act on the flag, so a DLL with a discardable resource section may still
//! hold its version in RAM and would be reported here unread rather than
//! misread. On the measured capture no user-mode image has one (all 150
//! discarded images are kernel modules).

use std::collections::BTreeMap;

use seance_core::io::{read_exact_or_fail, IncompleteReason};
use seance_memory::object::ListStop;
use seance_memory::{Incomplete, MemoryLayer};
use serde_json::{json, Value};

use crate::dump::{read_pe_headers, PeHeaders};
use crate::modules::{
    list_dlls, KernelModules, LoadedModule, ModuleSymbols, ModuleWalkConfig, ProcessSpace,
};
use crate::process::ProcessList;
use crate::profile::WindowsProfile;

/// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
pub const DIRECTORY_ENTRY_RESOURCE: usize = 2;
/// `IMAGE_SCN_MEM_DISCARDABLE`: the loader may free the section after load.
pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// The resource type of a version block.
pub const RT_VERSION: u32 = 16;
/// `VS_FIXEDFILEINFO.dwSignature`.
pub const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;
/// Largest version block this reader will decode. Real ones are a few
/// kilobytes; a declared size above this is not a version block.
pub const MAX_VERSION_BLOCK_BYTES: u32 = 1 << 16;
/// Entries one resource directory level may declare before the walk refuses.
const MAX_DIRECTORY_ENTRIES: u16 = 4096;

/// Caps on one survey.
#[derive(Debug, Clone)]
pub struct VersionInfoConfig {
    /// Images read across the kernel and every process. Reaching it is stated.
    pub max_images: usize,
    /// Strings kept per string table.
    pub max_strings_per_table: usize,
    /// Whether each process's loaded DLLs are read as well as the kernel's
    /// modules.
    pub process_modules: bool,
}

impl Default for VersionInfoConfig {
    fn default() -> Self {
        Self {
            max_images: 32_768,
            max_strings_per_table: 64,
            process_modules: true,
        }
    }
}

/// `VS_FIXEDFILEINFO`, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedFileInfo {
    pub struct_version: u32,
    pub file_version: [u16; 4],
    pub product_version: [u16; 4],
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    /// The two date double-words (`dwFileDateMS`, `dwFileDateLS`), published
    /// as read: Microsoft's linker leaves them zero, and a non-zero value is
    /// reported, not interpreted.
    pub file_date: u64,
}

impl FixedFileInfo {
    pub fn file_version_text(&self) -> String {
        dotted(self.file_version)
    }

    pub fn product_version_text(&self) -> String {
        dotted(self.product_version)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "struct_version": self.struct_version,
            "file_version": self.file_version_text(),
            "file_version_parts": self.file_version,
            "product_version": self.product_version_text(),
            "product_version_parts": self.product_version,
            "file_flags_mask": self.file_flags_mask,
            "file_flags": self.file_flags,
            "file_os": self.file_os,
            "file_type": self.file_type,
            "file_subtype": self.file_subtype,
            "file_date": self.file_date,
        })
    }
}

fn dotted(parts: [u16; 4]) -> String {
    format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3])
}

/// One `StringTable` of a `StringFileInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTable {
    /// The table's key: language and code page as eight hex digits.
    pub language_codepage: String,
    pub entries: Vec<(String, String)>,
    /// Strings beyond the per-table cap were not kept.
    pub truncated: bool,
}

impl StringTable {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "language_codepage": self.language_codepage,
            "entries": self.entries.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
            "truncated": self.truncated,
        })
    }
}

/// How the read of one image ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionOutcome {
    /// The fixed block was read; string tables may or may not be present.
    Read,
    /// The PE headers were not acquired. Not a fact about the image.
    HeadersUnreadable(String),
    /// The image is not a PE at the address the loader gave.
    NotPe(String),
    /// The optional header names no resource directory.
    NoResourceDirectory,
    /// The resource tree holds no `RT_VERSION` entry.
    NoVersionResource,
    /// The tree or the data entry would not read.
    ResourceUnreadable(String),
    /// The section holding the resource directory is marked
    /// `IMAGE_SCN_MEM_DISCARDABLE`, so it was not read: the kernel frees such
    /// sections of a driver after boot (on the measured capture the kernel's
    /// own held code, not a resource tree). Only the section flag is
    /// examined; the bytes at the directory's address are not checked.
    ResourceDiscarded(String),
    /// The version block was read and does not decode.
    Malformed(String),
}

impl VersionOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::HeadersUnreadable(_) => "headers_unreadable",
            Self::NotPe(_) => "not_pe",
            Self::NoResourceDirectory => "no_resource_directory",
            Self::NoVersionResource => "no_version_resource",
            Self::ResourceUnreadable(_) => "resource_unreadable",
            Self::ResourceDiscarded(_) => "resource_discarded",
            Self::Malformed(_) => "malformed",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::HeadersUnreadable(d)
            | Self::NotPe(d)
            | Self::ResourceUnreadable(d)
            | Self::ResourceDiscarded(d)
            | Self::Malformed(d) => Some(d),
            _ => None,
        }
    }

    /// The resource section is marked discardable and was not read, which is
    /// neither an absence in the image nor a gap in the capture: for a driver
    /// the version is not in RAM by design; for a user-mode image it was
    /// not looked for.
    pub fn is_discarded(&self) -> bool {
        matches!(self, Self::ResourceDiscarded(_))
    }

    /// The image was examined and carries no version, which is a fact about
    /// the image rather than about the capture.
    pub fn is_absence(&self) -> bool {
        matches!(self, Self::NoResourceDirectory | Self::NoVersionResource)
    }

    /// The question could not be put to the image.
    pub fn is_unreadable(&self) -> bool {
        matches!(
            self,
            Self::HeadersUnreadable(_) | Self::ResourceUnreadable(_)
        )
    }
}

/// One image's version resource.
#[derive(Debug, Clone)]
pub struct ImageVersion {
    pub base: u64,
    /// `SizeOfImage` from the headers, when they read.
    pub size_of_image: Option<u32>,
    /// `IMAGE_FILE_HEADER.Machine`, when the headers read.
    pub machine: Option<u16>,
    pub fixed: Option<FixedFileInfo>,
    pub strings: Vec<StringTable>,
    /// `VarFileInfo\Translation` pairs: language, code page.
    pub translations: Vec<(u16, u16)>,
    pub outcome: VersionOutcome,
}

impl ImageVersion {
    fn ended(base: u64, outcome: VersionOutcome) -> Self {
        Self {
            base,
            size_of_image: None,
            machine: None,
            fixed: None,
            strings: Vec::new(),
            translations: Vec::new(),
            outcome,
        }
    }

    /// The first string table's value for a key.
    pub fn string(&self, key: &str) -> Option<&str> {
        self.strings.iter().find_map(|t| t.get(key))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "base": format!("{:#018x}", self.base),
            "size_of_image": self.size_of_image,
            "machine": self.machine,
            "outcome": self.outcome.as_str(),
            "outcome_detail": self.outcome.detail(),
            "fixed": self.fixed.as_ref().map(FixedFileInfo::to_json),
            "strings": self.strings.iter().map(StringTable::to_json).collect::<Vec<_>>(),
            "translations": self.translations.iter().map(|(l, c)| format!("{l:04X}{c:04X}")).collect::<Vec<_>>(),
        })
    }
}

/// Read one image's version resource from the address it is loaded at.
pub fn read_image_version(
    layer: &dyn MemoryLayer,
    base: u64,
    config: &VersionInfoConfig,
) -> ImageVersion {
    let headers = match read_pe_headers(layer, base) {
        Ok(headers) => headers,
        Err(crate::dump::DumpError::NotPe { detail, .. }) => {
            return ImageVersion::ended(base, VersionOutcome::NotPe(detail));
        }
        Err(err) => {
            return ImageVersion::ended(base, VersionOutcome::HeadersUnreadable(err.to_string()));
        }
    };
    let mut out = ImageVersion {
        base,
        size_of_image: Some(headers.size_of_image),
        machine: Some(headers.machine),
        fixed: None,
        strings: Vec::new(),
        translations: Vec::new(),
        outcome: VersionOutcome::Read,
    };
    let directory = headers.directory(DIRECTORY_ENTRY_RESOURCE);
    if !directory.is_present() {
        out.outcome = VersionOutcome::NoResourceDirectory;
        return out;
    }
    if let Some(section) = headers.section_at(directory.virtual_address) {
        if section.characteristics & SCN_MEM_DISCARDABLE != 0 {
            out.outcome = VersionOutcome::ResourceDiscarded(format!(
                "the resource directory lies in section '{}', which is marked \
                 IMAGE_SCN_MEM_DISCARDABLE, and was not read: the kernel frees such a section \
                 of a driver after boot, so its bytes are not expected to be the resource; \
                 the bytes at its address were not checked",
                section.name
            ));
            return out;
        }
    }
    let (data_rva, size) = match locate_version_data(layer, &headers, directory.virtual_address) {
        Ok(Some(found)) => found,
        Ok(None) => {
            out.outcome = VersionOutcome::NoVersionResource;
            return out;
        }
        Err(err) => {
            out.outcome = VersionOutcome::ResourceUnreadable(err);
            return out;
        }
    };
    if size == 0 || size > MAX_VERSION_BLOCK_BYTES {
        out.outcome = VersionOutcome::Malformed(format!(
            "the version data entry declares {size} byte(s), outside 1..={MAX_VERSION_BLOCK_BYTES}"
        ));
        return out;
    }
    let Some(address) = headers.address_of(data_rva) else {
        out.outcome =
            VersionOutcome::Malformed("the version data's address leaves the space".into());
        return out;
    };
    let block = match read(layer, address, u64::from(size), "the version block") {
        Ok(block) => block,
        Err(err) => {
            out.outcome = VersionOutcome::ResourceUnreadable(err);
            return out;
        }
    };
    match decode_version_block(&block, config) {
        Ok((fixed, strings, translations)) => {
            out.fixed = Some(fixed);
            out.strings = strings;
            out.translations = translations;
        }
        Err(err) => out.outcome = VersionOutcome::Malformed(err),
    }
    out
}

fn read(layer: &dyn MemoryLayer, address: u64, len: u64, what: &str) -> Result<Vec<u8>, String> {
    let size = usize::try_from(len).map_err(|_| format!("{what}: {len} bytes does not fit"))?;
    let mut buf = vec![0u8; size];
    read_exact_or_fail(layer.as_data_source(), address, &mut buf, what)
        .map_err(|err| format!("{what} at {address:#x} would not read: {err}"))?;
    Ok(buf)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Walk type → name → language to the `RT_VERSION` data entry.
///
/// `Ok(None)` when the tree holds no version; `Err` when it would not read.
fn locate_version_data(
    layer: &dyn MemoryLayer,
    headers: &PeHeaders,
    root_rva: u32,
) -> Result<Option<(u32, u32)>, String> {
    let root = headers
        .address_of(root_rva)
        .ok_or_else(|| "the resource directory's address leaves the space".to_string())?;

    // Level 1: the type directory, searched for RT_VERSION among id entries.
    let Some(level2) = directory_entry(layer, root, 0, |id, named| !named && id == RT_VERSION)?
    else {
        return Ok(None);
    };
    let Some((level2_offset, is_dir)) = level2 else {
        return Ok(None);
    };
    if !is_dir {
        return Err("the RT_VERSION entry points at data rather than a name directory".into());
    }
    // Level 2: the first name. Level 3: the first language.
    let Some(Some((level3_offset, is_dir))) =
        directory_entry(layer, root, level2_offset, |_, _| true)?
    else {
        return Ok(None);
    };
    if !is_dir {
        return Err(
            "the version's name entry points at data rather than a language directory".into(),
        );
    }
    let Some(Some((data_offset, is_dir))) =
        directory_entry(layer, root, level3_offset, |_, _| true)?
    else {
        return Ok(None);
    };
    if is_dir {
        return Err("the version's language entry points at a fourth directory level".into());
    }
    let entry = read(
        layer,
        root + u64::from(data_offset),
        16,
        "the version data entry",
    )?;
    let rva = u32_at(&entry, 0).unwrap_or(0);
    let size = u32_at(&entry, 4).unwrap_or(0);
    Ok(Some((rva, size)))
}

/// The first entry of the directory at `root + offset` that `select` accepts,
/// as `(offset of what it points at, is a subdirectory)`. `Ok(None)` when no
/// entry is accepted.
fn directory_entry(
    layer: &dyn MemoryLayer,
    root: u64,
    offset: u32,
    select: impl Fn(u32, bool) -> bool,
) -> Result<Option<Option<(u32, bool)>>, String> {
    let at = root + u64::from(offset);
    let header = read(layer, at, 16, "a resource directory")?;
    let named = u16_at(&header, 12).unwrap_or(0);
    let ids = u16_at(&header, 14).unwrap_or(0);
    let total = named.saturating_add(ids);
    if total > MAX_DIRECTORY_ENTRIES {
        return Err(format!(
            "a resource directory declares {total} entries, above the {MAX_DIRECTORY_ENTRIES} \
             this reader will walk"
        ));
    }
    if total == 0 {
        return Ok(None);
    }
    let entries = read(
        layer,
        at + 16,
        u64::from(total) * 8,
        "resource directory entries",
    )?;
    for index in 0..usize::from(total) {
        let name = u32_at(&entries, index * 8).unwrap_or(0);
        let target = u32_at(&entries, index * 8 + 4).unwrap_or(0);
        let is_named = name & 0x8000_0000 != 0 || index < usize::from(named);
        if select(name & 0x7FFF_FFFF, is_named) {
            return Ok(Some(Some((
                target & 0x7FFF_FFFF,
                target & 0x8000_0000 != 0,
            ))));
        }
    }
    Ok(Some(None))
}

/// One block of the version resource: `wLength`, `wValueLength`, `wType`, a
/// NUL-terminated UTF-16 key, padding, then the value and the children.
struct Block {
    end: usize,
    value_length: usize,
    kind: u16,
    key: String,
    value_at: usize,
}

fn pad4(at: usize) -> usize {
    (at + 3) & !3
}

fn parse_block(buf: &[u8], at: usize) -> Result<Block, String> {
    let length = usize::from(u16_at(buf, at).ok_or("a block header runs past the data")?);
    let value_length = usize::from(u16_at(buf, at + 2).unwrap_or(0));
    let kind = u16_at(buf, at + 4).unwrap_or(0);
    if length < 6 {
        return Err(format!(
            "a block at {at} declares {length} byte(s), fewer than its header"
        ));
    }
    let end = (at + length).min(buf.len());
    let mut key_units = Vec::new();
    let mut cursor = at + 6;
    loop {
        let unit = u16_at(buf, cursor).ok_or("a block's key runs past the data")?;
        cursor += 2;
        if unit == 0 {
            break;
        }
        key_units.push(unit);
        if cursor > end {
            return Err(format!("a block's key at {at} runs past the block"));
        }
    }
    Ok(Block {
        end,
        value_length,
        kind,
        key: String::from_utf16_lossy(&key_units),
        value_at: pad4(cursor),
    })
}

/// Decode a `VS_VERSIONINFO` block.
#[allow(clippy::type_complexity)]
fn decode_version_block(
    buf: &[u8],
    config: &VersionInfoConfig,
) -> Result<(FixedFileInfo, Vec<StringTable>, Vec<(u16, u16)>), String> {
    let root = parse_block(buf, 0)?;
    if root.key != "VS_VERSION_INFO" {
        return Err(format!(
            "the root key is '{}', not 'VS_VERSION_INFO'",
            root.key
        ));
    }
    if root.value_length < 52 {
        return Err(format!(
            "the root block declares {} byte(s) of fixed info, fewer than the 52 of \
             VS_FIXEDFILEINFO",
            root.value_length
        ));
    }
    let fixed_at = root.value_at;
    let word = |index: usize| u32_at(buf, fixed_at + index * 4);
    let signature = word(0).ok_or("the fixed info runs past the data")?;
    if signature != FIXED_FILE_INFO_SIGNATURE {
        return Err(format!(
            "the fixed info signature is {signature:#010x}, not {FIXED_FILE_INFO_SIGNATURE:#010x}"
        ));
    }
    let hi = |v: u32| (v >> 16) as u16;
    let lo = |v: u32| (v & 0xFFFF) as u16;
    let fv_ms = word(2).unwrap_or(0);
    let fv_ls = word(3).unwrap_or(0);
    let pv_ms = word(4).unwrap_or(0);
    let pv_ls = word(5).unwrap_or(0);
    let fixed = FixedFileInfo {
        struct_version: word(1).unwrap_or(0),
        file_version: [hi(fv_ms), lo(fv_ms), hi(fv_ls), lo(fv_ls)],
        product_version: [hi(pv_ms), lo(pv_ms), hi(pv_ls), lo(pv_ls)],
        file_flags_mask: word(6).unwrap_or(0),
        file_flags: word(7).unwrap_or(0),
        file_os: word(8).unwrap_or(0),
        file_type: word(9).unwrap_or(0),
        file_subtype: word(10).unwrap_or(0),
        file_date: (u64::from(word(11).unwrap_or(0)) << 32) | u64::from(word(12).unwrap_or(0)),
    };

    let mut strings = Vec::new();
    let mut translations = Vec::new();
    let mut cursor = pad4(fixed_at + root.value_length);
    while cursor + 6 <= root.end {
        let child = parse_block(buf, cursor)?;
        if child.end <= cursor {
            break;
        }
        match child.key.as_str() {
            "StringFileInfo" => {
                let mut table_at = child.value_at;
                while table_at + 6 <= child.end {
                    let table = parse_block(buf, table_at)?;
                    if table.end <= table_at {
                        break;
                    }
                    strings.push(decode_string_table(buf, &table, config)?);
                    table_at = pad4(table.end);
                }
            }
            "VarFileInfo" => {
                let mut var_at = child.value_at;
                while var_at + 6 <= child.end {
                    let var = parse_block(buf, var_at)?;
                    if var.end <= var_at {
                        break;
                    }
                    if var.key == "Translation" {
                        let mut at = var.value_at;
                        while at + 4 <= var.value_at + var.value_length && at + 4 <= var.end {
                            translations.push((
                                u16_at(buf, at).unwrap_or(0),
                                u16_at(buf, at + 2).unwrap_or(0),
                            ));
                            at += 4;
                        }
                    }
                    var_at = pad4(var.end);
                }
            }
            _ => {}
        }
        cursor = pad4(child.end);
    }
    Ok((fixed, strings, translations))
}

fn decode_string_table(
    buf: &[u8],
    table: &Block,
    config: &VersionInfoConfig,
) -> Result<StringTable, String> {
    let mut out = StringTable {
        language_codepage: table.key.clone(),
        entries: Vec::new(),
        truncated: false,
    };
    let mut at = table.value_at;
    while at + 6 <= table.end {
        let entry = parse_block(buf, at)?;
        if entry.end <= at {
            break;
        }
        if out.entries.len() >= config.max_strings_per_table {
            out.truncated = true;
            break;
        }
        // For a text value (`wType == 1`) the length is in 16-bit units and
        // includes the terminator; for a binary one it is in bytes.
        let units = if entry.kind == 1 {
            entry.value_length
        } else {
            entry.value_length / 2
        };
        let mut text = Vec::new();
        for index in 0..units {
            let Some(unit) = u16_at(buf, entry.value_at + index * 2) else {
                break;
            };
            if unit == 0 || entry.value_at + index * 2 >= entry.end {
                break;
            }
            text.push(unit);
        }
        out.entries
            .push((entry.key, String::from_utf16_lossy(&text)));
        at = pad4(entry.end);
    }
    Ok(out)
}

// ── The survey over a profile ───────────────────────────────────────────────

/// One image, with where it was found.
#[derive(Debug, Clone)]
pub struct ImageRecord {
    pub name: Option<String>,
    pub path: Option<String>,
    /// `SizeOfImage` as the loader entry recorded it.
    pub loader_size: Option<u64>,
    pub version: ImageVersion,
}

impl ImageRecord {
    fn from_module(module: &LoadedModule, version: ImageVersion) -> Self {
        Self {
            name: module.base_name.name().map(str::to_string),
            path: module.full_path.name().map(str::to_string),
            loader_size: module.size_of_image,
            version,
        }
    }

    /// The key a distinct-image table groups on: path (case-folded) and
    /// file version.
    pub fn identity(&self) -> (String, String) {
        (
            self.path
                .clone()
                .or_else(|| self.name.clone())
                .unwrap_or_else(|| format!("{:#018x}", self.version.base))
                .to_lowercase(),
            self.version
                .fixed
                .as_ref()
                .map(FixedFileInfo::file_version_text)
                .unwrap_or_else(|| format!("({})", self.version.outcome.as_str())),
        )
    }

    pub fn to_json(&self) -> Value {
        let mut value = self.version.to_json();
        if let Some(object) = value.as_object_mut() {
            object.insert("name".into(), json!(self.name));
            object.insert("path".into(), json!(self.path));
            object.insert("loader_size".into(), json!(self.loader_size));
            object.insert("company".into(), json!(self.version.string("CompanyName")));
            object.insert(
                "original_filename".into(),
                json!(self.version.string("OriginalFilename")),
            );
            object.insert(
                "file_description".into(),
                json!(self.version.string("FileDescription")),
            );
            object.insert(
                "product_name".into(),
                json!(self.version.string("ProductName")),
            );
        }
        value
    }
}

/// One process's images.
#[derive(Debug, Clone)]
pub struct ProcessVersions {
    pub process: u64,
    pub pid: Option<u64>,
    pub name: Option<String>,
    pub images: Vec<ImageRecord>,
    /// Whether the DLL list was walked end to end.
    pub list_complete: bool,
    /// Why nothing was read for this process, when nothing was.
    pub unavailable: Option<String>,
}

impl ProcessVersions {
    pub fn to_json(&self) -> Value {
        json!({
            "process": format!("{:#018x}", self.process),
            "pid": self.pid,
            "name": self.name,
            "images": self.images.iter().map(ImageRecord::to_json).collect::<Vec<_>>(),
            "images_total": self.images.len(),
            "list_complete": self.list_complete,
            "unavailable": self.unavailable,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct VersionSurvey {
    pub kernel: Vec<ImageRecord>,
    /// Why the kernel module list was not read, when it was not.
    pub kernel_unavailable: Option<String>,
    pub kernel_list_complete: bool,
    pub processes: Vec<ProcessVersions>,
    pub process_list_complete: bool,
    /// Images across kernel and processes at which the cap fired.
    pub images_capped: bool,
    pub images_examined: u64,
}

impl VersionSurvey {
    fn all_images(&self) -> impl Iterator<Item = &ImageRecord> {
        self.kernel
            .iter()
            .chain(self.processes.iter().flat_map(|p| p.images.iter()))
    }

    pub fn images_with_a_version(&self) -> u64 {
        self.all_images()
            .filter(|i| i.version.fixed.is_some())
            .count() as u64
    }

    pub fn images_without_a_version(&self) -> u64 {
        self.all_images()
            .filter(|i| i.version.outcome.is_absence())
            .count() as u64
    }

    pub fn images_unreadable(&self) -> u64 {
        self.all_images()
            .filter(|i| i.version.outcome.is_unreadable())
            .count() as u64
    }

    pub fn images_discarded(&self) -> u64 {
        self.all_images()
            .filter(|i| i.version.outcome.is_discarded())
            .count() as u64
    }

    pub fn images_malformed(&self) -> u64 {
        self.all_images()
            .filter(|i| {
                matches!(
                    i.version.outcome,
                    VersionOutcome::Malformed(_) | VersionOutcome::NotPe(_)
                )
            })
            .count() as u64
    }

    /// Distinct (path, version) pairs and how many images carry each.
    pub fn distinct(&self) -> BTreeMap<(String, String), u64> {
        let mut out = BTreeMap::new();
        for image in self.all_images() {
            *out.entry(image.identity()).or_insert(0) += 1;
        }
        out
    }

    pub fn is_complete(&self) -> bool {
        self.kernel_unavailable.is_none()
            && self.kernel_list_complete
            && self.process_list_complete
            && !self.images_capped
            && self
                .processes
                .iter()
                .all(|p| p.unavailable.is_none() && p.list_complete)
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(why) = &self.kernel_unavailable {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the kernel's module list was not read: {why}"),
            ));
        }
        if !self.kernel_list_complete {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                "the kernel's module list did not walk end to end, so a driver past the break \
                 was not read"
                    .to_string(),
            ));
        }
        if !self.process_list_complete {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                "the process list did not walk end to end, so a process past the break had no \
                 DLLs read"
                    .to_string(),
            ));
        }
        if self.images_capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the image cap fired after {} image(s); later ones were not read",
                    self.images_examined
                ),
            ));
        }
        let skipped = self
            .processes
            .iter()
            .filter(|p| p.unavailable.is_some())
            .count();
        if skipped > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{skipped} process(es) had no readable DLL list, so their images were not \
                     examined; that is not a process with no images"
                ),
            ));
        }
        let partial = self
            .processes
            .iter()
            .filter(|p| p.unavailable.is_none() && !p.list_complete)
            .count();
        if partial > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!("{partial} process(es) had a DLL list that did not walk end to end"),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        format!(
            "{} image(s) examined: {} kernel module(s) and the DLLs of {} process(es). {} carry \
             a version resource, {} carry none, {} have a resource section marked discardable \
             that was not read, {} could not be read and {} did not decode.",
            self.images_examined,
            self.kernel.len(),
            self.processes.len(),
            self.images_with_a_version(),
            self.images_without_a_version(),
            self.images_discarded(),
            self.images_unreadable(),
            self.images_malformed()
        )
    }

    pub fn to_json(&self) -> Value {
        let distinct: Vec<Value> = self
            .distinct()
            .into_iter()
            .map(|((path, version), count)| json!({"path": path, "version": version, "images": count}))
            .collect();
        json!({
            "kernel_modules": self.kernel.iter().map(ImageRecord::to_json).collect::<Vec<_>>(),
            "kernel_modules_total": self.kernel.len(),
            "kernel_unavailable": self.kernel_unavailable,
            "kernel_list_complete": self.kernel_list_complete,
            "processes": self.processes.iter().map(ProcessVersions::to_json).collect::<Vec<_>>(),
            "processes_total": self.processes.len(),
            "process_list_complete": self.process_list_complete,
            "images_examined": self.images_examined,
            "images_with_a_version": self.images_with_a_version(),
            "images_without_a_version": self.images_without_a_version(),
            "images_unreadable": self.images_unreadable(),
            "images_resource_discarded": self.images_discarded(),
            "images_malformed": self.images_malformed(),
            "images_capped": self.images_capped,
            "distinct_images": distinct,
            "distinct_images_total": self.distinct().len(),
            "outcome_basis":
                "Each image's outcome is one of: read; headers unreadable (a paged-out image -- \
                 not a fact about the image); not a PE at the loader's address; no resource \
                 directory; a resource tree with no RT_VERSION entry; the resource section \
                 marked IMAGE_SCN_MEM_DISCARDABLE and not read (the kernel frees such a section \
                 of a driver after boot, as the kernel's own on Windows 11 26200; the bytes \
                 there are not checked); the resource unreadable; or a version block that does \
                 not decode. 'No version' is claimed \
                 only for the two absences, never for an image that could not be read.",
            "source_basis":
                "Versions are read from the image bytes in memory through the PE resource tree \
                 (data directory 2, type 16, first name, first language), so they describe the \
                 code that was loaded rather than a file on disk.",
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Read the version resource of every kernel module and, when asked, of every
/// DLL of every process.
pub fn survey_version_info(
    profile: &WindowsProfile,
    kernel_modules: Result<&KernelModules, String>,
    processes: Option<&ProcessList>,
    config: &VersionInfoConfig,
) -> VersionSurvey {
    let mut survey = VersionSurvey {
        kernel: Vec::new(),
        kernel_unavailable: None,
        kernel_list_complete: true,
        processes: Vec::new(),
        process_list_complete: processes.is_some_and(|p| p.forward_stop.is_complete()),
        images_capped: false,
        images_examined: 0,
    };
    match kernel_modules {
        Ok(list) => {
            survey.kernel_list_complete = list.is_complete();
            for module in &list.modules {
                if survey.images_examined as usize >= config.max_images {
                    survey.images_capped = true;
                    break;
                }
                let Some(base) = module.base else { continue };
                survey.images_examined += 1;
                let version = read_image_version(profile.kernel_space.as_ref(), base, config);
                survey
                    .kernel
                    .push(ImageRecord::from_module(module, version));
            }
        }
        Err(why) => survey.kernel_unavailable = Some(why),
    }

    let Some(processes) = processes.filter(|_| config.process_modules) else {
        return survey;
    };
    let symbols = match ModuleSymbols::from_profile(profile) {
        Ok(symbols) => symbols,
        Err(err) => {
            for process in &processes.processes {
                survey.processes.push(ProcessVersions {
                    process: process.address,
                    pid: process.pid.known().copied(),
                    name: process.image_file_name.known().cloned(),
                    images: Vec::new(),
                    list_complete: false,
                    unavailable: Some(format!(
                        "this build's loader structures could not be described: {err}"
                    )),
                });
            }
            return survey;
        }
    };
    let walk = ModuleWalkConfig::default();
    for process in &processes.processes {
        let mut record = ProcessVersions {
            process: process.address,
            pid: process.pid.known().copied(),
            name: process.image_file_name.known().cloned(),
            images: Vec::new(),
            list_complete: false,
            unavailable: None,
        };
        if survey.images_capped {
            record.unavailable = Some("the image cap fired before this process was reached".into());
            survey.processes.push(record);
            continue;
        }
        let space = match ProcessSpace::build(profile, &symbols, process.address, &walk) {
            Ok(space) => space,
            Err(err) => {
                record.unavailable = Some(format!("its address space could not be built: {err}"));
                survey.processes.push(record);
                continue;
            }
        };
        let dlls = match list_dlls(profile, &symbols, process.address, &space, &walk) {
            Ok(dlls) => dlls,
            Err(err) => {
                record.unavailable = Some(format!("its DLL list could not be walked: {err}"));
                survey.processes.push(record);
                continue;
            }
        };
        record.list_complete = dlls.loader.empty_is_a_fact()
            || (dlls.is_complete() && matches!(dlls.stop, Some(ListStop::Wrapped)));
        if !dlls.loader.is_available() && !dlls.loader.empty_is_a_fact() {
            record.unavailable = Some(format!(
                "its loader data was not available ({}), so its images were not examined",
                dlls.loader.as_str()
            ));
        }
        for module in dlls.all_modules() {
            if survey.images_examined as usize >= config.max_images {
                survey.images_capped = true;
                break;
            }
            let Some(base) = module.base else { continue };
            survey.images_examined += 1;
            let version = read_image_version(space.layer().as_ref(), base, config);
            record
                .images
                .push(ImageRecord::from_module(module, version));
        }
        survey.processes.push(record);
    }
    survey
}
