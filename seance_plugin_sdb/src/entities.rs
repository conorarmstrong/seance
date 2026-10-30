//! What a shim database says, as records.
//!
//! # The structure, read off the real files
//!
//! The three top-level tags are the **index** table (`0x7802`), the **database**
//! (`0x7001`) and the **string table** (`0x7801`). The entities are under the
//! second — which is worth saying because the conventional reading of the
//! numbers puts the database at `0x7802`, and dumping `0x7802` gives ten index
//! descriptors and no entities at all.
//!
//! Under the database: a FILETIME, a version string, the database's name, a
//! GUID, and one `0x7007` list per shimmed executable. Each of those carries a
//! name pattern, an application name, a vendor, a GUID, and lists of matching
//! criteria.
//!
//! # Which tags this build names, and on what basis
//!
//! Only the ones whose meaning is **evident from the data**. `0x6006` holds
//! `"Visual Basic"` beside `0x6001`'s `"MSVBVM??.DLL"` and `0x6005`'s
//! `"Microsoft Corporation"`, so it is the application name and the vendor is
//! the vendor — that is a reading of the bytes, and the records say so once.
//!
//! Every other tag is carried by **numeric id** and counted. A guessed name is
//! read as a fact, and there is no authoritative offline name list to check one
//! against.

use serde_json::{json, Value};

use crate::format::{Tag, TagType};
use crate::strings::StringTable;

/// The database list — where the entities are.
pub const TAG_DATABASE: u16 = 0x7001;
/// The index descriptors.
pub const TAG_INDEXES: u16 = 0x7802;
/// One shimmed executable.
pub const TAG_EXE: u16 = 0x7007;
/// A criterion the executable must match.
pub const TAG_MATCHING_FILE: u16 = 0x7008;
/// A library entry.
pub const TAG_LIBRARY: u16 = 0x7002;

// Tags whose meaning is evident from the data. See the module comment.
const TAG_NAME: u16 = 0x6001;
const TAG_VENDOR: u16 = 0x6005;
const TAG_APP_NAME: u16 = 0x6006;
const TAG_WILDCARD_NAME: u16 = 0x600B;
const TAG_DB_VERSION: u16 = 0x6022;
const TAG_TIME: u16 = 0x5001;
const TAG_DB_GUID: u16 = 0x9007;
const TAG_EXE_GUID: u16 = 0x9004;

/// The basis every record carries for the names this build gives its fields.
const NAMING_BASIS: &str =
    "Microsoft publishes no tag dictionary for this format. The fields named here are the ones \
     whose meaning is evident from the data itself -- the tag holding \"Visual Basic\" beside a \
     name of \"MSVBVM??.DLL\" and a vendor of \"Microsoft Corporation\" is the application \
     name. Every other tag is carried by numeric id and counted, because a guessed name is \
     read as a fact.";

fn read_u32(body: &[u8], at: usize) -> Option<u32> {
    body.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64(body: &[u8], at: usize) -> Option<u64> {
    body.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

fn hex(body: &[u8], at: usize, len: usize) -> Option<String> {
    body.get(at..at + len)
        .map(|s| s.iter().map(|b| format!("{b:02x}")).collect())
}

/// A tag's direct children.
///
/// # Why this takes an index rather than scanning
///
/// The walk emits tags in stream order, so a parent's descendants are the
/// contiguous run immediately after it, and the run ends at the first tag at or
/// above the parent's own depth. Scanning the whole list per parent instead is
/// quadratic — and not theoretically: on `sysmain.sdb`, 13,871 executables
/// against 339,377 tags, with several lookups each, is tens of billions of
/// comparisons, and the test suite hung on it. Walk order is a property of the
/// walk, so this is not a trick; it is the shape the data already has.
fn children(tags: &[Tag], parent_index: usize) -> impl Iterator<Item = &Tag> {
    let parent = &tags[parent_index];
    let depth = parent.depth;
    let child_depth = depth + 1;
    tags[parent_index + 1..]
        .iter()
        .take_while(move |t| t.depth > depth)
        .filter(move |t| t.depth == child_depth)
}

/// A child's resolved string, by parent index.
fn child_string_at(
    body: &[u8],
    tags: &[Tag],
    parent_index: usize,
    want: u16,
    table: &StringTable,
) -> Option<String> {
    children(tags, parent_index)
        .find(|t| t.tag == want && t.value_readable())
        .and_then(|t| read_u32(body, t.payload_at))
        .and_then(|r| table.resolve(r))
        .map(str::to_string)
}

/// The database itself.
#[derive(Clone, Debug)]
pub struct ShimDatabase {
    pub name: Option<String>,
    pub version: Option<String>,
    pub database_guid: Option<String>,
    pub created_filetime: Option<u64>,
    pub executables: usize,
    pub libraries: usize,
    pub matching_criteria: usize,
}

impl ShimDatabase {
    pub fn to_json(&self) -> Value {
        json!({
            "type": "ShimDatabase",
            "name": self.name.clone().unwrap_or_else(|| "(unnamed shim database)".into()),
            "database_name": self.name,
            "database_version": self.version,
            "database_guid": self.database_guid,
            "created": self.created_filetime.and_then(seance_core::time::filetime_to_rfc3339),
            "created_filetime_raw": self.created_filetime,
            "shimmed_executables": self.executables,
            "libraries": self.libraries,
            "matching_criteria": self.matching_criteria,
            "naming_basis": NAMING_BASIS,
            // What the presence of a database does and does not establish.
            "installed": false,
            "installed_basis": "This is the contents of a shim database FILE. Whether it is \
                                registered with the operating system is a separate fact, \
                                recorded under the registry's InstalledSDB key, and is not \
                                established by the file existing on disk.",
        })
    }
}

/// One shimmed executable.
#[derive(Clone, Debug)]
pub struct ShimExe {
    pub name: Option<String>,
    pub wildcard_name: Option<String>,
    pub app_name: Option<String>,
    pub vendor: Option<String>,
    pub exe_guid: Option<String>,
    pub matching_files: Vec<String>,
    /// Tags under this executable that this build does not name, by id.
    pub unnamed_tags: Vec<u16>,
}

impl ShimExe {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("ShimExe"));
        m.insert(
            "name".into(),
            json!(self
                .app_name
                .clone()
                .or_else(|| self.name.clone())
                .unwrap_or_else(|| "(unnamed)".into())),
        );
        m.insert("executable_name".into(), json!(self.name));
        m.insert("wildcard_name".into(), json!(self.wildcard_name));
        m.insert("application_name".into(), json!(self.app_name));
        m.insert("vendor".into(), json!(self.vendor));
        m.insert("exe_guid".into(), json!(self.exe_guid));
        m.insert("matching_files".into(), json!(self.matching_files));
        m.insert("naming_basis".into(), json!(NAMING_BASIS));
        if !self.unnamed_tags.is_empty() {
            let ids: Vec<String> = self
                .unnamed_tags
                .iter()
                .map(|t| format!("0x{t:04X}"))
                .collect();
            m.insert("unnamed_tags".into(), json!(ids));
            m.insert(
                "unnamed_tags_note".into(),
                json!(
                    "These tags are present on this entry and this build does not name \
                       them. They are listed by id rather than omitted, so the record does \
                       not read as everything the database holds about this executable."
                ),
            );
        }
        // A shim entry is not by itself a record of the program running.
        m.insert("execution_evidence".into(), json!(false));
        m.insert(
            "basis".into(),
            json!(
                "A shim entry says the operating system would apply a compatibility fix to \
                   a program matching this pattern. It is not a record that such a program \
                   was ever present or ever ran."
            ),
        );
        Value::Object(m)
    }
}

/// The census: what was walked, and what this build could not name.
#[derive(Clone, Debug)]
pub struct ShimCoverage {
    pub container: &'static str,
    pub major_version: u32,
    pub minor_version: u32,
    pub tags_walked: usize,
    pub distinct_tag_ids: usize,
    pub unnamed_tag_ids: usize,
    pub string_table_entries: usize,
    pub string_refs: usize,
    pub unresolved_string_refs: usize,
    pub tags_without_a_readable_value: usize,
    pub walk_complete: bool,
    pub walk_limit: Option<String>,
    pub container_incomplete: Option<String>,
}

impl ShimCoverage {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("ShimDatabaseCoverage"));
        m.insert("name".into(), json!("Shim database coverage"));
        m.insert("container".into(), json!(self.container));
        m.insert(
            "format_version".into(),
            json!(format!("{}.{}", self.major_version, self.minor_version)),
        );
        if self.major_version != crate::format::KNOWN_MAJOR_VERSION {
            m.insert("content_incomplete".into(), json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                json!(seance_core::io::IncompleteReason::Unvalidated.as_str()),
            );
            m.insert(
                "format_version_note".into(),
                json!(format!(
                    "This build has been measured against major version {}. This database \
                     declares {}, so what was read from it is not validated against a known \
                     layout -- it is what the tag stream yielded.",
                    crate::format::KNOWN_MAJOR_VERSION,
                    self.major_version
                )),
            );
        }
        m.insert("tags_walked".into(), json!(self.tags_walked));
        m.insert("distinct_tag_ids".into(), json!(self.distinct_tag_ids));
        m.insert("unnamed_tag_ids".into(), json!(self.unnamed_tag_ids));
        // The honest framing: a fact about this build's table, not a claim
        // about what Microsoft has published.
        m.insert(
            "unnamed_tag_ids_note".into(),
            json!(format!(
                "{} of the {} distinct tag ids in this database are not named by this build \
                 and are carried by numeric id. That is a statement about this reader's \
                 table, not about what is documented: Microsoft publishes no tag dictionary \
                 for this format.",
                self.unnamed_tag_ids, self.distinct_tag_ids
            )),
        );
        m.insert(
            "string_table_entries".into(),
            json!(self.string_table_entries),
        );
        m.insert("string_refs".into(), json!(self.string_refs));
        m.insert(
            "unresolved_string_refs".into(),
            json!(self.unresolved_string_refs),
        );
        m.insert(
            "tags_without_a_readable_value".into(),
            json!(self.tags_without_a_readable_value),
        );
        if self.tags_without_a_readable_value > 0 {
            m.insert(
                "unreadable_value_note".into(),
                json!(
                    "Some tags' payloads end past their parent list's declared size. Their \
                       values are absent from these records rather than read: clamping to the \
                       parent would yield a wrong number and reading past it would trust a \
                       length the parent contradicts. This shape occurs in Microsoft's own \
                       shipped databases."
                ),
            );
        }
        m.insert("walk_complete".into(), json!(self.walk_complete));
        if !self.walk_complete {
            m.insert("content_incomplete".into(), json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
            );
            m.insert(
                "walk_limit".into(),
                json!(self.walk_limit.clone().unwrap_or_default()),
            );
        }
        if let Some(why) = &self.container_incomplete {
            m.insert("container_incomplete".into(), json!(why));
        }
        Value::Object(m)
    }
}

/// Every tag id this build names.
fn is_named(tag: u16) -> bool {
    matches!(
        tag,
        TAG_DATABASE
            | TAG_INDEXES
            | TAG_EXE
            | TAG_MATCHING_FILE
            | TAG_LIBRARY
            | TAG_NAME
            | TAG_VENDOR
            | TAG_APP_NAME
            | TAG_WILDCARD_NAME
            | TAG_DB_VERSION
            | TAG_TIME
            | TAG_DB_GUID
            | TAG_EXE_GUID
            | crate::strings::TAG_STRINGTABLE
            | crate::strings::TAG_STRINGTABLE_ITEM
    )
}

/// Read the database and its executables out of a walked stream.
pub fn read(
    body: &[u8],
    tags: &[Tag],
    table: &StringTable,
) -> (Option<ShimDatabase>, Vec<ShimExe>) {
    let Some(db_index) = tags
        .iter()
        .position(|t| t.tag == TAG_DATABASE && t.depth == 0)
    else {
        return (None, Vec::new());
    };
    let exe_indices: Vec<usize> = tags
        .iter()
        .enumerate()
        .filter(|(_, t)| t.tag == TAG_EXE)
        .map(|(i, _)| i)
        .collect();
    let criteria = tags.iter().filter(|t| t.tag == TAG_MATCHING_FILE).count();
    let libraries = tags.iter().filter(|t| t.tag == TAG_LIBRARY).count();

    let db = ShimDatabase {
        name: child_string_at(body, tags, db_index, TAG_NAME, table),
        version: child_string_at(body, tags, db_index, TAG_DB_VERSION, table),
        database_guid: children(tags, db_index)
            .find(|t| t.tag == TAG_DB_GUID && t.value_readable())
            .and_then(|t| hex(body, t.payload_at, t.payload_len)),
        created_filetime: children(tags, db_index)
            .find(|t| t.tag == TAG_TIME && t.value_readable())
            .and_then(|t| read_u64(body, t.payload_at)),
        executables: exe_indices.len(),
        libraries,
        matching_criteria: criteria,
    };

    let out = exe_indices
        .into_iter()
        .map(|exe| {
            // The matching-file children, each by its own index so its name can
            // be read without another scan.
            let matching_files: Vec<String> = tags[exe + 1..]
                .iter()
                .enumerate()
                .take_while(|(_, t)| t.depth > tags[exe].depth)
                .filter(|(_, t)| t.tag == TAG_MATCHING_FILE && t.depth == tags[exe].depth + 1)
                .filter_map(|(i, _)| child_string_at(body, tags, exe + 1 + i, TAG_NAME, table))
                .collect();
            let unnamed_tags = {
                let mut ids: Vec<u16> = children(tags, exe)
                    .filter(|t| !is_named(t.tag))
                    .map(|t| t.tag)
                    .collect();
                ids.sort_unstable();
                ids.dedup();
                ids
            };
            ShimExe {
                name: child_string_at(body, tags, exe, TAG_NAME, table),
                wildcard_name: child_string_at(body, tags, exe, TAG_WILDCARD_NAME, table),
                app_name: child_string_at(body, tags, exe, TAG_APP_NAME, table),
                vendor: child_string_at(body, tags, exe, TAG_VENDOR, table),
                exe_guid: children(tags, exe)
                    .find(|t| t.tag == TAG_EXE_GUID && t.value_readable())
                    .and_then(|t| hex(body, t.payload_at, t.payload_len)),
                matching_files,
                unnamed_tags,
            }
        })
        .collect();
    (Some(db), out)
}

/// Build the census.
pub fn coverage(
    body: &[u8],
    opened: &crate::container::Opened,
    walk: &crate::format::Walk,
    table: &StringTable,
) -> ShimCoverage {
    let distinct: std::collections::BTreeSet<u16> = walk.tags.iter().map(|t| t.id()).collect();
    let unnamed = walk
        .tags
        .iter()
        .filter(|t| !is_named(t.tag))
        .map(|t| t.id())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let refs: Vec<&Tag> = walk
        .tags
        .iter()
        .filter(|t| t.tag_type == TagType::StringRef)
        .collect();
    let unresolved = refs
        .iter()
        .filter(|t| {
            !t.value_readable()
                || read_u32(body, t.payload_at)
                    .map(|r| table.resolve(r).is_none())
                    .unwrap_or(true)
        })
        .count();
    ShimCoverage {
        container: opened.container.as_str(),
        major_version: opened.major_version,
        minor_version: opened.minor_version,
        tags_walked: walk.tags.len(),
        distinct_tag_ids: distinct.len(),
        unnamed_tag_ids: unnamed,
        string_table_entries: table.len(),
        string_refs: refs.len(),
        unresolved_string_refs: unresolved,
        tags_without_a_readable_value: walk.tags.iter().filter(|t| !t.value_readable()).count(),
        walk_complete: walk.complete(body.len()),
        walk_limit: walk.limit.as_ref().map(ToString::to_string),
        container_incomplete: opened.incomplete.clone(),
    }
}
