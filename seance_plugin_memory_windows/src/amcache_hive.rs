//! The Amcache hive, located in kernel memory and decoded key by key.
//!
//! `Amcache.hve` is an ordinary registry hive that the Application Experience
//! service keeps under `C:\Windows\AppCompat\Programs`. When the service has
//! run, the hive is loaded, and a loaded hive is on `CmpHiveListHead` like any
//! other — so finding it is a hive-list walk and a name match, and reading it is
//! [`crate::registry`]'s job. Nothing here re-implements hive parsing; this
//! module is a decoder over registry values, which is exactly the layer at
//! which the Amcache format lives.
//!
//! # The two generations of the format
//!
//! | Windows | Key | Entry is |
//! |---|---|---|
//! | 8, 8.1 | `Root\File\<volume GUID>\<file id>` | one executable |
//! | 8, 8.1 | `Root\Programs\<program id>` | one installed program |
//! | 10, 11 | `Root\InventoryApplicationFile\<name>` | one executable |
//! | 10, 11 | `Root\InventoryApplication\<program id>` | one installed program |
//! | 10, 11 | `Root\InventoryDriverBinary\<name or hash>` | one driver |
//!
//! Both generations are read: a machine upgraded in place keeps the Windows 8
//! keys, and an examiner who is told "there are no Amcache entries" because
//! only the Windows 10 keys were looked at has been told something false.
//!
//! # The value names are the format
//!
//! The Windows 8 keys name their values with single hex digits — `15` is the
//! path, `101` is the SHA-1, `f` is the PE compile time — and there is nothing
//! in the hive that says so. Those mappings are the format, they are written
//! down in [`WIN8_FILE_VALUES`] and [`WIN8_PROGRAM_VALUES`] with a note beside
//! each of what it means, and a value name this module does not recognise is
//! ignored rather than guessed at.
//!
//! # What a wrong answer looks like
//!
//! The `FileId` value is a SHA-1 with four zeroes stuck on the front. Stripping
//! "leading zeroes" rather than exactly that four-character prefix corrupts
//! every hash that genuinely begins with a zero digit — about one in sixteen —
//! and a corrupted hash does not match the binary it identifies, so a real
//! match is reported as no match. [`normalise_file_id`] strips exactly the
//! prefix, only when what remains is forty hex digits, and records a note when
//! the value is not that shape at all.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::Incomplete;

use crate::amcache::{
    push_note, text_field_json, time_field_json, wallclock_field_json, AmcacheConfig, Field,
    WallClock, WinTime, TYPE_CMHIVE, TYPE_CM_KEY_NODE,
};
use crate::profile::WindowsProfile;
use crate::registry::hivelist::{HiveListing, HIVE_LIST_HEAD};
use crate::registry::key::{CellReader, KeyNode, RegistryData, Subkeys, ValueData, Values};
use crate::registry::space::HiveSpace;
use crate::registry::RegistryError;

/// The file name the Amcache hive is loaded from.
pub const AMCACHE_FILE_NAME: &str = "amcache.hve";

/// The key every Amcache entry hangs beneath, relative to the hive root.
pub const AMCACHE_ROOT: &str = "Root";

/// Windows 8 `Root\File` value names, and what each one holds.
///
/// The names are single hex digits with no self-description anywhere in the
/// hive, so this table *is* the format. A wrong entry here silently relabels a
/// field: reading `12` as the last-modified time rather than the creation time
/// swaps two timestamps that a report presents side by side.
pub const WIN8_FILE_VALUES: [(&str, &str); 8] = [
    ("100", "program id, correlating with Root\\Programs"),
    ("101", "SHA-1 of the file, with a four-zero prefix"),
    ("0", "product name from the PE version resource"),
    ("1", "company name from the PE version resource"),
    ("15", "full path the file was seen at"),
    ("d", "product version from the PE version resource"),
    ("11", "file last-modified time, as a FILETIME"),
    ("12", "file creation time, as a FILETIME"),
];

/// Windows 8 `Root\Programs` value names.
pub const WIN8_PROGRAM_VALUES: [(&str, &str); 4] = [
    ("0", "product name"),
    ("1", "product version"),
    ("2", "publisher"),
    ("a", "install time, as seconds since the Unix epoch"),
];

// ── Layout ──────────────────────────────────────────────────────────────────

/// What reaching the Amcache hive needs from this build's symbols.
///
/// Resolved once, so a build whose symbol table cannot describe a hive fails
/// before a hive list is walked rather than at the first key node.
#[derive(Debug, Clone)]
pub struct HiveLayout {
    /// Address of `CmpHiveListHead` in the kernel address space.
    pub hive_list_head: u64,
}

impl HiveLayout {
    /// Resolve the hive list head, or say why the hive cannot be reached.
    ///
    /// `Err` carries a sentence for the examiner rather than an error type,
    /// because the caller records it beside the other source's reason instead
    /// of raising it: a build with no `CmpHiveListHead` may still have a
    /// readable Shimcache.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, String> {
        if !profile.symbols.has_type(TYPE_CMHIVE) {
            return Err(format!(
                "the symbol table has no '{TYPE_CMHIVE}', so a loaded registry hive cannot be \
                 described"
            ));
        }
        if !profile.symbols.has_type(TYPE_CM_KEY_NODE) {
            return Err(format!(
                "the symbol table has no '{TYPE_CM_KEY_NODE}', so a registry key cannot be decoded"
            ));
        }
        let rva = profile
            .symbols
            .symbol_address(HIVE_LIST_HEAD)
            .map_err(|err| format!("the symbol table does not name '{HIVE_LIST_HEAD}': {err}"))?;
        let hive_list_head = profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
            format!(
                "the kernel base {:#x} plus '{HIVE_LIST_HEAD}' at {rva:#x} does not fit in 64 bits",
                profile.kernel_base.value
            )
        })?;
        Ok(Self { hive_list_head })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"hive_list_head": self.hive_list_head})
    }
}

// ── Entries ─────────────────────────────────────────────────────────────────

/// Which Amcache key an entry came out of.
///
/// Carried on every entry because the same field means different things under
/// different keys: a `Root\Programs` entry's install time is when the *program*
/// was installed, and a `Root\File` entry's creation time is when the *file*
/// appeared, and a report that merged the two would be wrong about both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmcacheSource {
    /// Windows 8 `Root\File`: one executable.
    Win8File,
    /// Windows 8 `Root\Programs`: one installed program.
    Win8Program,
    /// Windows 10 `Root\InventoryApplicationFile`: one executable.
    InventoryApplicationFile,
    /// Windows 10 `Root\InventoryApplication`: one installed program.
    InventoryApplication,
    /// Windows 10 `Root\InventoryDriverBinary`: one driver.
    InventoryDriverBinary,
}

impl AmcacheSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            AmcacheSource::Win8File => "win8_file",
            AmcacheSource::Win8Program => "win8_program",
            AmcacheSource::InventoryApplicationFile => "inventory_application_file",
            AmcacheSource::InventoryApplication => "inventory_application",
            AmcacheSource::InventoryDriverBinary => "inventory_driver_binary",
        }
    }

    /// Whether entries from this key describe a file rather than a program.
    pub fn is_file(self) -> bool {
        matches!(
            self,
            AmcacheSource::Win8File
                | AmcacheSource::InventoryApplicationFile
                | AmcacheSource::InventoryDriverBinary
        )
    }

    /// The key name under `Root` that this source lives at.
    pub fn key_name(self) -> &'static str {
        match self {
            AmcacheSource::Win8File => "File",
            AmcacheSource::Win8Program => "Programs",
            AmcacheSource::InventoryApplicationFile => "InventoryApplicationFile",
            AmcacheSource::InventoryApplication => "InventoryApplication",
            AmcacheSource::InventoryDriverBinary => "InventoryDriverBinary",
        }
    }

    /// Whether entries hang one level below the key or two.
    ///
    /// `Root\File` groups its entries by volume GUID, so an entry is two levels
    /// down. Enumerating only one level there returns the volume keys and no
    /// files at all, which renders as "this machine ran nothing".
    pub fn entries_are_nested(self) -> bool {
        matches!(self, AmcacheSource::Win8File)
    }
}

/// One Amcache entry: a program, an executable or a driver.
///
/// Every field is a [`Field`], so a report can always say which of the five
/// kinds of nothing it is looking at.
#[derive(Debug, Clone)]
pub struct AmcacheEntry {
    /// Which key it came out of.
    pub source: AmcacheSource,
    /// The key's path below the hive root, for provenance.
    pub key_path: String,
    /// The key's own name, which for several sources is itself the evidence:
    /// a `Root\Programs` key is named with the program id, and an
    /// `InventoryDriverBinary` key with either the driver's path or its hash.
    pub key_name: String,
    /// When the key was last written. The most reliable time in the record,
    /// because the kernel writes it and no application controls it.
    pub key_last_write: Field<WinTime>,
    /// The program id, correlating a file entry with its program entry.
    pub program_id: Field<String>,
    /// Product, program or driver name.
    pub name: Field<String>,
    /// Publisher or company.
    pub publisher: Field<String>,
    /// Full path the file was seen at, or the program's root directory.
    pub path: Field<String>,
    /// Product or driver version.
    pub version: Field<String>,
    /// SHA-1 of the file, with Amcache's four-zero prefix removed.
    pub sha1: Field<String>,
    /// Service the driver is registered under.
    pub service: Field<String>,
    /// File size in bytes, where the entry records one.
    pub file_size: Field<u64>,
    /// The file's last-modified time as Amcache recorded it.
    pub last_modified: Field<WinTime>,
    /// A second last-modified time some Windows 8 entries carry, taken from the
    /// file's `$STANDARD_INFORMATION` rather than from `$FILE_NAME`.
    pub last_modified_2: Field<WinTime>,
    /// The file's creation time.
    pub created: Field<WinTime>,
    /// When the program was installed, where the entry records it as an
    /// absolute instant.
    pub installed: Field<WinTime>,
    /// When the program was installed, where the entry records it as local wall
    /// clock text with no time zone.
    pub install_date_local: Field<WallClock>,
    /// The PE `TimeDateStamp`: when the binary was linked.
    pub compiled: Field<WinTime>,
    /// The PE link date where the entry records it as local wall clock text.
    pub link_date_local: Field<WallClock>,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl AmcacheEntry {
    /// An entry from `source` at `key_path`, with every field marked as one
    /// this source does not record.
    ///
    /// Starting from [`Field::NotApplicable`] rather than from an empty string
    /// is what makes a field the decoder forgets to fill in visible as "this
    /// source does not record it" rather than as "the machine recorded
    /// nothing".
    pub fn new(source: AmcacheSource, key_path: String, key_name: String) -> Self {
        Self {
            source,
            key_path,
            key_name,
            key_last_write: Field::NotApplicable,
            program_id: Field::NotApplicable,
            name: Field::NotApplicable,
            publisher: Field::NotApplicable,
            path: Field::NotApplicable,
            version: Field::NotApplicable,
            sha1: Field::NotApplicable,
            service: Field::NotApplicable,
            file_size: Field::NotApplicable,
            last_modified: Field::NotApplicable,
            last_modified_2: Field::NotApplicable,
            created: Field::NotApplicable,
            installed: Field::NotApplicable,
            install_date_local: Field::NotApplicable,
            compiled: Field::NotApplicable,
            link_date_local: Field::NotApplicable,
            notes: Vec::new(),
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source": self.source.as_str(),
            "describes": if self.source.is_file() { "file" } else { "program" },
            "key_path": self.key_path,
            "key_name": self.key_name,
            "key_last_write": time_field_json(&self.key_last_write),
            "program_id": text_field_json(&self.program_id),
            "name": text_field_json(&self.name),
            "publisher": text_field_json(&self.publisher),
            "path": text_field_json(&self.path),
            "version": text_field_json(&self.version),
            "sha1": text_field_json(&self.sha1),
            "service": text_field_json(&self.service),
            "file_size": crate::amcache::number_field_json(&self.file_size),
            "last_modified": time_field_json(&self.last_modified),
            "last_modified_2": time_field_json(&self.last_modified_2),
            "created": time_field_json(&self.created),
            "installed": time_field_json(&self.installed),
            "install_date_local": wallclock_field_json(&self.install_date_local),
            "compiled": time_field_json(&self.compiled),
            "link_date_local": wallclock_field_json(&self.link_date_local),
            "notes": self.notes,
        })
    }
}

// ── Sections ────────────────────────────────────────────────────────────────

/// Whether one Amcache key was there, and whether that answer is reliable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    /// The key was found and its subkeys enumerated.
    Read,
    /// The key is not under `Root`.
    Absent {
        /// Whether the enumeration that established that was itself
        /// exhaustive. `false` means the key may have been there and its index
        /// cell was not acquired, which is not the same finding at all.
        search_complete: bool,
    },
    /// The key could not be reached, and here is why.
    Unreachable(String),
}

impl KeyStatus {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyStatus::Read => "read",
            KeyStatus::Absent { .. } => "absent",
            KeyStatus::Unreachable(_) => "unreachable",
        }
    }

    /// Whether this status supports a claim about what the machine did.
    pub fn is_conclusive(&self) -> bool {
        match self {
            KeyStatus::Read => true,
            KeyStatus::Absent { search_complete } => *search_complete,
            KeyStatus::Unreachable(_) => false,
        }
    }
}

/// One Amcache key's entries, and everything the enumeration could not do.
#[derive(Debug, Clone)]
pub struct AmcacheKeySection {
    /// Which key this is.
    pub source: AmcacheSource,
    /// Whether the key was there.
    pub status: KeyStatus,
    /// The entries, capped by [`AmcacheConfig::max_entries_per_key`].
    pub entries: Vec<AmcacheEntry>,
    /// How many entries the key held in total, exact even when the list above
    /// was capped.
    pub entries_total: usize,
    /// Whether the entry cap fired. The enumeration stopped; the key did not
    /// end.
    pub truncated: bool,
    /// Everything that stopped the enumeration being exhaustive.
    pub incomplete: Vec<Incomplete>,
}

impl AmcacheKeySection {
    /// A section for a key that could not be reached.
    pub fn unreachable(source: AmcacheSource, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            source,
            status: KeyStatus::Unreachable(detail.clone()),
            entries: Vec::new(),
            entries_total: 0,
            truncated: false,
            incomplete: vec![Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "Amcache's Root\\{} could not be read: {detail}",
                    source.key_name()
                ),
            )],
        }
    }

    /// Whether every entry under this key was recovered.
    pub fn is_complete(&self) -> bool {
        self.status.is_conclusive() && !self.truncated && self.incomplete.is_empty()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source": self.source.as_str(),
            "key": format!("{AMCACHE_ROOT}\\{}", self.source.key_name()),
            "status": self.status.as_str(),
            "status_detail": match &self.status {
                KeyStatus::Unreachable(detail) => Some(detail.clone()),
                _ => None,
            },
            "conclusive": self.status.is_conclusive(),
            "entries": self.entries.iter().map(AmcacheEntry::to_json).collect::<Vec<_>>(),
            "entries_total": self.entries_total,
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "incomplete": self.incomplete.iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Whether the Amcache hive was in memory at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiveStatus {
    /// The hive was found on the kernel's hive list.
    Loaded {
        /// Address of its `_CMHIVE`, which is the provenance of every entry.
        cmhive: u64,
        /// The path it was loaded from.
        name: String,
    },
    /// The hive list was walked and no Amcache hive was on it.
    NotLoaded {
        /// Whether the walk that established that was itself exhaustive.
        search_complete: bool,
    },
    /// The hive list could not be walked, or the hive could not be opened.
    Unreachable(String),
}

impl HiveStatus {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            HiveStatus::Loaded { .. } => "loaded",
            HiveStatus::NotLoaded { .. } => "not_loaded",
            HiveStatus::Unreachable(_) => "unreachable",
        }
    }
}

/// Everything the Amcache hive said, and everything it could not.
#[derive(Debug, Clone)]
pub struct AmcacheHive {
    /// Whether the hive was there.
    pub status: HiveStatus,
    /// One section per key this module knows about, always all five, so a
    /// report can show that the Windows 8 keys were looked for and were not
    /// there rather than leaving the question open.
    pub sections: Vec<AmcacheKeySection>,
    /// Notes, capped by [`AmcacheConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total.
    pub notes_total: usize,
}

impl AmcacheHive {
    /// A result for an image whose Amcache hive could not be reached at all.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            status: HiveStatus::Unreachable(detail.into()),
            sections: Vec::new(),
            notes: Vec::new(),
            notes_total: 0,
        }
    }

    /// How many entries were recovered across every key.
    pub fn entry_count(&self) -> usize {
        self.sections.iter().map(|s| s.entries.len()).sum()
    }

    /// Whether the hive was read in full.
    ///
    /// A hive that is not loaded is **not** complete, even though the walk that
    /// established it was exhaustive. The flag answers "may a report say this
    /// machine has no Amcache record of that program?", and the answer when the
    /// hive was never loaded is no: the hive on disk may hold the entry.
    pub fn is_complete(&self) -> bool {
        matches!(self.status, HiveStatus::Loaded { .. })
            && self.sections.iter().all(AmcacheKeySection::is_complete)
    }

    /// Everything a report must declare about this hive.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        match &self.status {
            HiveStatus::Loaded { .. } => {}
            HiveStatus::NotLoaded { search_complete } => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                if *search_complete {
                    "no Amcache hive was loaded when this image was taken, so the machine's \
                     Amcache record could not be read from memory"
                        .to_string()
                } else {
                    "no Amcache hive was found, and the hive list could not be walked in full, so \
                     one may have been loaded and missed"
                        .to_string()
                },
            )),
            HiveStatus::Unreachable(detail) => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the Amcache hive could not be reached: {detail}"),
            )),
        }
        for section in &self.sections {
            out.extend(section.incomplete.iter().cloned());
            if section.truncated {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "Amcache's Root\\{} held {} entries and the enumeration stopped at its \
                         cap; the key continues",
                        section.source.key_name(),
                        section.entries_total
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status.as_str(),
            "cmhive": match &self.status {
                HiveStatus::Loaded { cmhive, .. } => Some(*cmhive),
                _ => None,
            },
            "hive_name": match &self.status {
                HiveStatus::Loaded { name, .. } => Some(name.clone()),
                _ => None,
            },
            "status_detail": match &self.status {
                HiveStatus::Unreachable(detail) => Some(detail.clone()),
                _ => None,
            },
            "sections": self.sections.iter().map(AmcacheKeySection::to_json).collect::<Vec<_>>(),
            "entry_count": self.entry_count(),
            "complete": self.is_complete(),
            "notes": self.notes,
            "notes_total": self.notes_total,
        })
    }
}

// ── The walk ────────────────────────────────────────────────────────────────

/// The sources this module reads, oldest format first.
pub const ALL_SOURCES: [AmcacheSource; 5] = [
    AmcacheSource::Win8File,
    AmcacheSource::Win8Program,
    AmcacheSource::InventoryApplicationFile,
    AmcacheSource::InventoryApplication,
    AmcacheSource::InventoryDriverBinary,
];

/// Find the Amcache hive in memory and decode every entry it holds.
///
/// Never returns an error: a hive list that will not walk, a hive that is not
/// loaded and a key that is not present are all findings about the image, and
/// each lands on [`AmcacheHive::status`] or on a section's
/// [`AmcacheKeySection::status`] with the evidence for it.
pub fn read_amcache_hive(
    profile: &WindowsProfile,
    layout: &HiveLayout,
    config: &AmcacheConfig,
) -> AmcacheHive {
    let listing = match crate::registry::hivelist::list_hives_from(profile, layout.hive_list_head) {
        Ok(listing) => listing,
        Err(err) => {
            return AmcacheHive::unavailable(format!("the hive list could not be walked: {err}"))
        }
    };
    read_amcache_from_listing(profile, &listing, config)
}

/// Decode the Amcache hive out of an already-walked hive list.
///
/// Split out so a caller that has walked `CmpHiveListHead` for its own reasons
/// — and an examiner who recovered the head by other means — does not walk it
/// twice and risk two walks disagreeing.
pub fn read_amcache_from_listing(
    profile: &WindowsProfile,
    listing: &HiveListing,
    config: &AmcacheConfig,
) -> AmcacheHive {
    let mut notes = Vec::new();
    let mut notes_total = 0usize;

    let Some(record) = select_amcache_hive(listing) else {
        return AmcacheHive {
            status: HiveStatus::NotLoaded {
                search_complete: listing.is_complete(),
            },
            sections: Vec::new(),
            notes,
            notes_total,
        };
    };
    let hive_name = record
        .name
        .path()
        .map(str::to_string)
        .unwrap_or_else(|| "<no backing file>".to_string());

    let reader = match open_reader(profile, record.address) {
        Ok(reader) => reader,
        Err(err) => {
            return AmcacheHive::unavailable(format!(
                "the Amcache hive at {:#x} could not be opened: {err}",
                record.address
            ))
        }
    };

    // The `Root` key is the whole format's anchor. Without it there is nothing
    // to enumerate, and saying so is a different finding from saying the five
    // keys below it were all absent.
    let root = match crate::registry::printkey::print_key(&reader, Some(AMCACHE_ROOT)) {
        Ok(root_listing) => root_listing,
        Err(err) => {
            // Every section is unreachable rather than absent. An empty section
            // list would make `is_complete` vacuously true — "no entries, and
            // you may rely on that" — which is the opposite of what happened.
            let detail = format!("the hive has no readable '{AMCACHE_ROOT}' key: {err}");
            return AmcacheHive {
                status: HiveStatus::Loaded {
                    cmhive: record.address,
                    name: hive_name,
                },
                sections: ALL_SOURCES
                    .iter()
                    .map(|source| AmcacheKeySection::unreachable(*source, detail.clone()))
                    .collect(),
                notes: vec![detail],
                notes_total: 1,
            };
        }
    };
    if !root.subkeys.is_complete() {
        push_note(
            &mut notes,
            &mut notes_total,
            config.max_recorded_notes,
            format!(
                "the subkey index of '{AMCACHE_ROOT}' could not be read in full, so a key \
                 reported absent below may have been present"
            ),
        );
    }

    let sections = ALL_SOURCES
        .iter()
        .map(|source| read_section(&reader, &root.subkeys, *source, config))
        .collect();

    AmcacheHive {
        status: HiveStatus::Loaded {
            cmhive: record.address,
            name: hive_name,
        },
        sections,
        notes,
        notes_total,
    }
}

/// The hive on `listing` that is an Amcache hive, if one is loaded.
///
/// Matched on the file name rather than on a substring of the whole path,
/// because a user profile directory called `amcache` would otherwise select an
/// `NTUSER.DAT`, and every entry decoded out of it would be attributed to
/// Amcache.
pub fn select_amcache_hive(
    listing: &HiveListing,
) -> Option<&crate::registry::hivelist::HiveRecord> {
    listing.hives.iter().find(|hive| {
        hive.name
            .file_name()
            .is_some_and(|file| file.eq_ignore_ascii_case(AMCACHE_FILE_NAME))
    })
}

/// Open a cell reader over one hive.
///
/// Opened from wherever this image keeps its bins: from Windows 10 build 17063
/// the kernel maps them through the Registry process, and reading them in
/// kernel space instead returns holes where every Amcache entry is.
fn open_reader(profile: &WindowsProfile, cmhive: u64) -> Result<CellReader, RegistryError> {
    let hive = HiveSpace::open_for_image(profile, cmhive)?;
    CellReader::new(Arc::clone(&hive))
}

/// Enumerate one Amcache key.
fn read_section(
    reader: &CellReader,
    root_subkeys: &Subkeys,
    source: AmcacheSource,
    config: &AmcacheConfig,
) -> AmcacheKeySection {
    let wanted = source.key_name();
    let Some(key) = root_subkeys
        .keys
        .iter()
        .find(|key| key.name.text.eq_ignore_ascii_case(wanted))
    else {
        return AmcacheKeySection {
            source,
            status: KeyStatus::Absent {
                search_complete: root_subkeys.is_complete(),
            },
            entries: Vec::new(),
            entries_total: 0,
            truncated: false,
            incomplete: if root_subkeys.is_complete() {
                Vec::new()
            } else {
                vec![Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "'{AMCACHE_ROOT}\\{wanted}' was not found, and the subkey index that was \
                         searched could not be read in full, so it may have been present"
                    ),
                )]
            },
        };
    };

    let mut section = AmcacheKeySection {
        source,
        status: KeyStatus::Read,
        entries: Vec::new(),
        entries_total: 0,
        truncated: false,
        incomplete: Vec::new(),
    };

    let first = reader.subkeys(key);
    section.incomplete.extend(first.incomplete.iter().cloned());

    if source.entries_are_nested() {
        for volume in &first.keys {
            let second = reader.subkeys(volume);
            section.incomplete.extend(second.incomplete.iter().cloned());
            for entry_key in &second.keys {
                let path = format!(
                    "{AMCACHE_ROOT}\\{wanted}\\{}\\{}",
                    volume.name.text, entry_key.name.text
                );
                collect_entry(reader, &mut section, source, entry_key, path, config);
            }
        }
    } else {
        for entry_key in &first.keys {
            let path = format!("{AMCACHE_ROOT}\\{wanted}\\{}", entry_key.name.text);
            collect_entry(reader, &mut section, source, entry_key, path, config);
        }
    }
    section
}

/// Decode one entry key and push it, respecting the entry cap.
fn collect_entry(
    reader: &CellReader,
    section: &mut AmcacheKeySection,
    source: AmcacheSource,
    key: &KeyNode,
    key_path: String,
    config: &AmcacheConfig,
) {
    section.entries_total = section.entries_total.saturating_add(1);
    if section.entries.len() >= config.max_entries_per_key {
        section.truncated = true;
        return;
    }
    let values = reader.values(key);
    section
        .entries
        .push(decode_entry(source, key, &values, key_path));
}

// ── Decoding ────────────────────────────────────────────────────────────────

/// Decode one entry from its key and its values.
///
/// Public so the decoding can be exercised directly against hand-built values,
/// which is the only way to test the failure paths — a value whose data page
/// was not acquired, a SHA-1 of the wrong shape, an install date that is not a
/// date — without building a synthetic hive for each of them.
pub fn decode_entry(
    source: AmcacheSource,
    key: &KeyNode,
    values: &Values,
    key_path: String,
) -> AmcacheEntry {
    let mut entry = AmcacheEntry::new(source, key_path, key.name.text.clone());
    entry.key_last_write = key_write_time(key);

    match source {
        AmcacheSource::InventoryApplicationFile => {
            entry.program_id = string_value(values, "ProgramId");
            entry.path = string_value(values, "LowerCaseLongPath");
            entry.publisher = string_value(values, "Publisher");
            entry.name = string_value(values, "ProductName");
            entry.version = string_value(values, "ProductVersion");
            entry.link_date_local = wallclock_value(values, "LinkDate");
            entry.file_size = number_value(values, "Size");
            entry.sha1 = file_id_value(values, "FileId", &mut entry.notes);
        }
        AmcacheSource::InventoryApplication => {
            // The key is named with the program id, so a file entry can be
            // correlated with the program that installed it.
            entry.program_id = name_field(&key.name.text);
            entry.name = string_value(values, "Name");
            entry.version = string_value(values, "Version");
            entry.publisher = string_value(values, "Publisher");
            entry.path = string_value(values, "RootDirPath");
            entry.install_date_local = wallclock_value(values, "InstallDate");
        }
        AmcacheSource::InventoryDriverBinary => {
            // Depending on the Windows version the key is named either with the
            // driver's path or with its hash; the one that is not the key name
            // is the value. Deciding by whether the key name looks like a path
            // is what upstream does and is the only signal available.
            let key_name_is_path = key.name.text.contains('\\') || key.name.text.contains('/');
            if key_name_is_path {
                entry.path = name_field(&key.name.text);
                entry.sha1 = file_id_value(values, "DriverId", &mut entry.notes);
                entry.name = string_value(values, "DriverName");
            } else {
                entry.sha1 =
                    normalise_field(name_field(&key.name.text), &mut entry.notes, "the key name");
                entry.name = string_value(values, "DriverName");
                entry.path = string_value(values, "DriverName");
            }
            entry.publisher = string_value(values, "DriverCompany");
            entry.version = string_value(values, "Product");
            entry.service = string_value(values, "Service");
            entry.compiled = unix_epoch_value(values, "DriverTimeStamp");
        }
        AmcacheSource::Win8File => {
            entry.program_id = string_value(values, "100");
            entry.sha1 = file_id_value(values, "101", &mut entry.notes);
            entry.name = string_value(values, "0");
            entry.publisher = string_value(values, "1");
            entry.path = string_value(values, "15");
            entry.version = string_value(values, "d");
            entry.file_size = number_value(values, "6");
            entry.last_modified = filetime_value(values, "11");
            entry.created = filetime_value(values, "12");
            entry.last_modified_2 = filetime_value(values, "17");
            entry.compiled = unix_epoch_value(values, "f");
        }
        AmcacheSource::Win8Program => {
            entry.program_id = name_field(&key.name.text);
            entry.name = string_value(values, "0");
            entry.version = string_value(values, "1");
            entry.publisher = string_value(values, "2");
            entry.installed = unix_epoch_value(values, "a");
        }
    }
    entry
}

/// A key's `LastWriteTime` as a rendered instant.
fn key_write_time(key: &KeyNode) -> Field<WinTime> {
    let Ok(filetime) = u64::try_from(key.last_write_time) else {
        return Field::Unparsable(format!(
            "the key's LastWriteTime is {}, which is not a FILETIME",
            key.last_write_time
        ));
    };
    match WinTime::from_filetime(filetime) {
        Some(time) => Field::Present(time),
        None => Field::Unset,
    }
}

/// The value named `name`, compared case-insensitively as the registry does.
pub fn find_value<'a>(
    values: &'a Values,
    name: &str,
) -> Option<&'a crate::registry::key::KeyValue> {
    values
        .values
        .iter()
        .find(|value| value.name.text.eq_ignore_ascii_case(name))
}

/// Trailing NUL code points, which registry strings routinely carry, removed.
///
/// Left in, they turn every comparison against a path into a mismatch and every
/// rendered path into one with an invisible character on the end.
pub fn trim_nuls(text: &str) -> String {
    text.trim_end_matches('\u{0}').to_string()
}

/// A key name used as evidence, or [`Field::Unset`] when the name is empty.
///
/// Several Amcache keys carry their most important field in the key's *name* —
/// the program id, the driver's hash. A key with no name recorded nothing, and
/// an empty string presented as a program id would correlate with every other
/// entry that also failed to record one.
fn name_field(name: &str) -> Field<String> {
    let text = trim_nuls(name);
    if text.is_empty() {
        Field::Unset
    } else {
        Field::Present(text)
    }
}

/// Read a value as text.
///
/// A `REG_SZ` is decoded as text by the registry reader already. A `REG_BINARY`
/// holding UTF-16 — which is how several Windows 8 Amcache values are stored —
/// is decoded here from the raw bytes, and a note is not warranted because that
/// is the format. A value that is a number, or whose byte count is odd, is
/// [`Field::Unparsable`] naming the type, never an empty string.
pub fn string_value(values: &Values, name: &str) -> Field<String> {
    let Some(value) = find_value(values, name) else {
        return Field::Absent;
    };
    let (raw, decoded) = match &value.data {
        ValueData::Unavailable(incomplete) => {
            return Field::Unreadable(format!(
                "the data of '{name}' could not be read: {}",
                incomplete.detail
            ))
        }
        ValueData::Available { raw, decoded } => (raw, decoded),
    };
    match decoded {
        RegistryData::Text(text) => {
            let trimmed = trim_nuls(&text.text);
            if trimmed.is_empty() {
                Field::Unset
            } else {
                Field::Present(trimmed)
            }
        }
        RegistryData::MultiText(_) => Field::Unparsable(format!(
            "'{name}' is a {}, and this field holds a single string",
            value.value_type.as_str()
        )),
        RegistryData::Empty => Field::Unset,
        RegistryData::Dword(_) | RegistryData::Qword(_) => Field::Unparsable(format!(
            "'{name}' is a {}, and this field holds text",
            value.value_type.as_str()
        )),
        RegistryData::Binary | RegistryData::Malformed { .. } => {
            if raw.is_empty() {
                return Field::Unset;
            }
            if raw.len() % 2 != 0 {
                return Field::Unparsable(format!(
                    "'{name}' holds {} byte(s), which is not a whole number of UTF-16 units",
                    raw.len()
                ));
            }
            let text = trim_nuls(&crate::poolscan::decode_utf16le(raw));
            if text.is_empty() {
                Field::Unset
            } else {
                Field::Present(text)
            }
        }
    }
}

/// Read a value as an unsigned number.
pub fn number_value(values: &Values, name: &str) -> Field<u64> {
    let Some(value) = find_value(values, name) else {
        return Field::Absent;
    };
    let (raw, decoded) = match &value.data {
        ValueData::Unavailable(incomplete) => {
            return Field::Unreadable(format!(
                "the data of '{name}' could not be read: {}",
                incomplete.detail
            ))
        }
        ValueData::Available { raw, decoded } => (raw, decoded),
    };
    match decoded {
        RegistryData::Dword(number) => Field::Present(u64::from(*number)),
        RegistryData::Qword(number) => Field::Present(*number),
        RegistryData::Text(text) => match trim_nuls(&text.text).trim().parse::<u64>() {
            Ok(number) => Field::Present(number),
            Err(_) => Field::Unparsable(format!(
                "'{name}' holds the text '{}', which is not a number",
                text.text
            )),
        },
        RegistryData::Empty => Field::Unset,
        _ => Field::Unparsable(format!(
            "'{name}' holds {} byte(s) of {}, which is not a number this field can read",
            raw.len(),
            value.value_type.as_str()
        )),
    }
}

/// Read a value as a FILETIME.
///
/// Amcache stores these as `REG_QWORD`, and older writers store them as eight
/// raw bytes under `REG_BINARY`; both are accepted, and anything else is
/// refused rather than reinterpreted. A four-byte value is refused explicitly,
/// because reading one as the low half of a FILETIME produces a date in 1601
/// that renders exactly like a real one.
pub fn filetime_value(values: &Values, name: &str) -> Field<WinTime> {
    let Some(value) = find_value(values, name) else {
        return Field::Absent;
    };
    let (raw, decoded) = match &value.data {
        ValueData::Unavailable(incomplete) => {
            return Field::Unreadable(format!(
                "the data of '{name}' could not be read: {}",
                incomplete.detail
            ))
        }
        ValueData::Available { raw, decoded } => (raw, decoded),
    };
    let filetime = match decoded {
        RegistryData::Qword(number) => *number,
        RegistryData::Empty => return Field::Unset,
        _ => {
            if raw.len() != 8 {
                return Field::Unparsable(format!(
                    "'{name}' holds {} byte(s), and a FILETIME is 8",
                    raw.len()
                ));
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(raw);
            u64::from_le_bytes(bytes)
        }
    };
    match WinTime::from_filetime(filetime) {
        Some(time) => Field::Present(time),
        None if filetime == 0 => Field::Unset,
        None => Field::Unparsable(format!(
            "'{name}' holds the FILETIME {filetime}, which is before 1970 and so is not a time \
             this machine recorded"
        )),
    }
}

/// Read a value as seconds since the Unix epoch.
///
/// Amcache stores the PE `TimeDateStamp` and the Windows 8 install time this
/// way — a different base from every other time in the same hive, which is
/// exactly the kind of detail that produces a 1970 date in a report when it is
/// missed.
pub fn unix_epoch_value(values: &Values, name: &str) -> Field<WinTime> {
    let Some(value) = find_value(values, name) else {
        return Field::Absent;
    };
    let decoded = match &value.data {
        ValueData::Unavailable(incomplete) => {
            return Field::Unreadable(format!(
                "the data of '{name}' could not be read: {}",
                incomplete.detail
            ))
        }
        ValueData::Available { decoded, .. } => decoded,
    };
    let seconds = match decoded {
        RegistryData::Dword(number) => i64::from(*number),
        RegistryData::Qword(number) => match i64::try_from(*number) {
            Ok(seconds) => seconds,
            Err(_) => {
                return Field::Unparsable(format!(
                    "'{name}' holds {number}, which is not a number of seconds any machine \
                     recorded"
                ))
            }
        },
        RegistryData::Empty => return Field::Unset,
        RegistryData::Text(text) => match trim_nuls(&text.text).trim().parse::<i64>() {
            Ok(seconds) => seconds,
            Err(_) => {
                return Field::Unparsable(format!(
                    "'{name}' holds the text '{}', which is not a number of seconds",
                    text.text
                ))
            }
        },
        _ => {
            return Field::Unparsable(format!(
                "'{name}' is a {}, which is not a number of seconds",
                value.value_type.as_str()
            ))
        }
    };
    if seconds == 0 {
        return Field::Unset;
    }
    match WinTime::from_unix_seconds(seconds) {
        Some(time) => Field::Present(time),
        None => Field::Unparsable(format!(
            "'{name}' holds {seconds} second(s) since 1970, which is not a time any machine \
             recorded"
        )),
    }
}

/// Read a value as Amcache's local wall-clock text.
pub fn wallclock_value(values: &Values, name: &str) -> Field<WallClock> {
    match string_value(values, name) {
        Field::Present(text) => match parse_wallclock(&text) {
            Some(local_iso8601) => Field::Present(WallClock {
                raw: text,
                local_iso8601,
            }),
            None => Field::Unparsable(format!(
                "'{name}' holds '{text}', which is not the MM/DD/YYYY HH:MM:SS form Amcache \
                 writes"
            )),
        },
        Field::NotApplicable => Field::NotApplicable,
        Field::Absent => Field::Absent,
        Field::Unset => Field::Unset,
        Field::Unreadable(detail) => Field::Unreadable(detail),
        Field::Unparsable(detail) => Field::Unparsable(detail),
    }
}

/// Read a value as an Amcache file id and normalise it to a SHA-1.
fn file_id_value(values: &Values, name: &str, notes: &mut Vec<String>) -> Field<String> {
    normalise_field(string_value(values, name), notes, &format!("'{name}'"))
}

/// Normalise whatever a file-id field holds, recording a note when it is not
/// the shape Amcache writes.
fn normalise_field(field: Field<String>, notes: &mut Vec<String>, what: &str) -> Field<String> {
    match field {
        Field::Present(raw) => {
            let (value, note) = normalise_file_id(&raw);
            if let Some(note) = note {
                notes.push(format!("{what}: {note}"));
            }
            Field::Present(value)
        }
        other => other,
    }
}

/// Strip Amcache's four-zero prefix from a file id, and say when it is not one.
///
/// Amcache stores a file's SHA-1 as forty hex digits with `0000` on the front.
/// The prefix is stripped only when what remains is exactly forty hex digits;
/// anything else is returned unchanged with a note, because a value that is not
/// a SHA-1 must not be presented as one, and a SHA-1 that genuinely begins with
/// a zero digit must not lose it.
///
/// Returns the normalised value and, when the input was not the expected shape,
/// a note for the entry.
pub fn normalise_file_id(raw: &str) -> (String, Option<String>) {
    let trimmed = trim_nuls(raw).trim().to_string();
    let is_hex = |text: &str| text.chars().all(|c| c.is_ascii_hexdigit());

    if trimmed.len() == 44 && trimmed.starts_with("0000") && is_hex(&trimmed) {
        return (trimmed[4..].to_ascii_lowercase(), None);
    }
    if trimmed.len() == 40 && is_hex(&trimmed) {
        return (trimmed.to_ascii_lowercase(), None);
    }
    let note = format!(
        "the file id '{trimmed}' is {} character(s) long and is not the four-zero prefix plus a \
         40-character SHA-1 that Amcache writes, so it is reported exactly as stored",
        trimmed.chars().count()
    );
    (trimmed, Some(note))
}

/// Days in `month` of `year`, or `None` for a month number that is not one.
fn days_in_month(year: u32, month: u32) -> Option<u32> {
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    })
}

/// Parse Amcache's `MM/DD/YYYY HH:MM:SS` local wall-clock text.
///
/// Returns the same reading as `YYYY-MM-DDTHH:MM:SS`, with **no** zone
/// designator, because the hive records none. Every component is range-checked
/// against the calendar, so `13/32/2019` is refused rather than reformatted
/// into a date that does not exist.
pub fn parse_wallclock(text: &str) -> Option<String> {
    let text = trim_nuls(text);
    let mut parts = text.split_whitespace();
    let date = parts.next()?;
    let time = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let mut date_parts = date.split('/');
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    let year: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    let mut time_parts = time.split(':');
    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;
    let second: u32 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() {
        return None;
    }

    // A year outside this range is not a date the Application Experience
    // service wrote; accepting one would put an entry at the far end of a
    // timeline where it dominates the view.
    if !(1601..=9999).contains(&year) {
        return None;
    }
    if day == 0 || day > days_in_month(year, month)? {
        return None;
    }
    // 23:59:60 exists in the leap-second table and Windows never writes it, but
    // refusing a second of 60 would drop a real reading for no benefit.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amcache::test_support::{
        binary_value, empty_values, key_node, qword_value, sz_value, unavailable_value, values_of,
    };
    use crate::registry::hivelist::list_hives;
    use crate::registry::test_support::{xp_profile, XP_CMHIVE};

    /// A SHA-1 whose first digit is genuinely zero, which is the case a
    /// "strip leading zeroes" implementation corrupts.
    const SHA1_STARTING_WITH_ZERO: &str = "0abcdef0123456789abcdef0123456789abcdef1";

    #[test]
    fn the_four_zero_prefix_is_stripped_and_a_real_leading_zero_is_kept() {
        let stored = format!("0000{SHA1_STARTING_WITH_ZERO}");
        let (value, note) = normalise_file_id(&stored);
        assert_eq!(value, SHA1_STARTING_WITH_ZERO);
        assert!(note.is_none(), "a well-formed file id needs no note");
        assert_eq!(
            value.len(),
            40,
            "stripping more than the prefix would corrupt the hash"
        );
    }

    #[test]
    fn a_file_id_that_is_not_a_sha1_is_reported_as_stored_with_a_note() {
        let (value, note) = normalise_file_id("00001234");
        assert_eq!(value, "00001234");
        let note = note.expect("an unexpected shape must be stated");
        assert!(note.contains("8 character(s)"), "{note}");

        // Non-hex characters inside an otherwise 44-character value: not a hash.
        let odd = format!("0000{}", "z".repeat(40));
        let (value, note) = normalise_file_id(&odd);
        assert_eq!(value, odd);
        assert!(note.is_some());
    }

    #[test]
    fn a_file_id_already_forty_hex_digits_is_kept_and_lower_cased() {
        let (value, note) = normalise_file_id(&"AB".repeat(20));
        assert_eq!(value, "ab".repeat(20));
        assert!(note.is_none());
    }

    #[test]
    fn a_value_whose_data_page_was_never_acquired_is_not_an_empty_string() {
        let values = values_of(vec![unavailable_value("Publisher")]);
        let field = string_value(&values, "Publisher");
        assert_eq!(field.status(), "unreadable");
        assert!(!field.absence_is_a_fact());
        assert!(field
            .detail()
            .expect("a reason travels with the refusal")
            .contains("Publisher"));
    }

    #[test]
    fn a_value_that_is_not_in_the_key_is_absent_rather_than_unreadable() {
        let values = empty_values();
        assert_eq!(string_value(&values, "Publisher").status(), "absent");
        assert_eq!(filetime_value(&values, "11").status(), "absent");
        assert_eq!(unix_epoch_value(&values, "f").status(), "absent");
        assert_eq!(number_value(&values, "6").status(), "absent");
        assert_eq!(wallclock_value(&values, "InstallDate").status(), "absent");
    }

    #[test]
    fn a_utf16_string_stored_under_reg_binary_is_still_read_as_text() {
        // The Windows 8 Amcache writes several of its values this way.
        let mut bytes = Vec::new();
        for unit in "C:\\evil.exe".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let values = values_of(vec![binary_value("15", bytes)]);
        assert_eq!(
            string_value(&values, "15"),
            Field::Present("C:\\evil.exe".to_string())
        );
    }

    #[test]
    fn an_odd_byte_count_is_refused_rather_than_half_decoded() {
        let values = values_of(vec![binary_value("15", vec![0x41, 0x00, 0x42])]);
        let field = string_value(&values, "15");
        assert_eq!(field.status(), "unparsable");
        assert!(field.detail().expect("a reason").contains("3 byte(s)"));
    }

    #[test]
    fn a_four_byte_value_is_refused_as_a_filetime_rather_than_read_as_its_low_half() {
        let values = values_of(vec![binary_value("11", vec![0x00, 0x01, 0x02, 0x03])]);
        let field = filetime_value(&values, "11");
        assert_eq!(field.status(), "unparsable");
        assert!(field
            .detail()
            .expect("a reason")
            .contains("and a FILETIME is 8"));
    }

    #[test]
    fn a_zero_filetime_is_unset_rather_than_a_1601_date() {
        let values = values_of(vec![qword_value("11", 0)]);
        assert_eq!(filetime_value(&values, "11"), Field::Unset);
        assert!(filetime_value(&values, "11").absence_is_a_fact());
    }

    #[test]
    fn a_filetime_and_a_unix_compile_time_in_the_same_key_land_on_the_same_base() {
        // 2010-01-01T00:00:00Z under both encodings.
        let values = values_of(vec![
            qword_value("11", 129_067_776_000_000_000),
            qword_value("f", 1_262_304_000),
        ]);
        let modified = filetime_value(&values, "11");
        let compiled = unix_epoch_value(&values, "f");
        assert_eq!(
            modified.value().map(|t| t.rfc3339.clone()),
            compiled.value().map(|t| t.rfc3339.clone())
        );
        assert!(modified
            .value()
            .expect("a real time")
            .rfc3339
            .starts_with("2010-01-01T00:00:00"));
    }

    #[test]
    fn a_local_install_date_is_normalised_without_inventing_a_time_zone() {
        assert_eq!(
            parse_wallclock("03/09/2019 14:05:06").as_deref(),
            Some("2019-03-09T14:05:06")
        );
        // Single-digit components, which the service also writes.
        assert_eq!(
            parse_wallclock("3/9/2019 4:05:06").as_deref(),
            Some("2019-03-09T04:05:06")
        );
        let values = values_of(vec![sz_value("InstallDate", "03/09/2019 14:05:06")]);
        let field = wallclock_value(&values, "InstallDate");
        let value = field.value().expect("a real install date");
        assert_eq!(value.local_iso8601, "2019-03-09T14:05:06");
        assert_eq!(value.raw, "03/09/2019 14:05:06");
        // The rendering must not claim UTC, because nothing recorded the zone.
        assert!(!value.local_iso8601.ends_with('Z'));
        assert_eq!(
            value.to_json()["zone"],
            serde_json::json!("unknown_machine_local")
        );
    }

    #[test]
    fn a_date_that_is_not_on_the_calendar_is_refused_rather_than_reformatted() {
        for bad in [
            "13/01/2019 00:00:00", // no thirteenth month
            "02/30/2019 00:00:00", // February never has thirty days
            "02/29/2019 00:00:00", // 2019 is not a leap year
            "01/00/2019 00:00:00", // there is no day zero
            "01/01/2019 24:00:00", // hours run 0..23
            "01/01/2019 00:60:00", // minutes run 0..59
            "01/01/1500 00:00:00", // before the FILETIME epoch entirely
            "01/01/2019",          // no time at all
            "01/01/2019 00:00:00 PM",
            "not a date at all",
            "",
        ] {
            assert_eq!(parse_wallclock(bad), None, "'{bad}' must be refused");
        }
        // 2020 is a leap year, so the same day is a real one.
        assert!(parse_wallclock("02/29/2020 00:00:00").is_some());
    }

    #[test]
    fn an_unparsable_install_date_says_so_rather_than_vanishing() {
        let values = values_of(vec![sz_value("InstallDate", "sometime last year")]);
        let field = wallclock_value(&values, "InstallDate");
        assert_eq!(field.status(), "unparsable");
        assert!(field.detail().expect("a reason").contains("MM/DD/YYYY"));
    }

    #[test]
    fn an_inventory_application_file_entry_decodes_every_field_it_records() {
        let values = values_of(vec![
            sz_value("ProgramId", "0006e1b2fc1234567890"),
            sz_value("LowerCaseLongPath", "c:\\users\\sarah\\evil.exe"),
            sz_value("Publisher", "Contoso Ltd"),
            sz_value("ProductName", "Evil"),
            sz_value("ProductVersion", "1.2.3.4"),
            sz_value("LinkDate", "03/09/2019 14:05:06"),
            sz_value("FileId", &format!("0000{SHA1_STARTING_WITH_ZERO}")),
        ]);
        let key = key_node("evil.exe|0006e1b2", 132_669_792_000_000_000);
        let entry = decode_entry(
            AmcacheSource::InventoryApplicationFile,
            &key,
            &values,
            "Root\\InventoryApplicationFile\\evil.exe|0006e1b2".to_string(),
        );

        assert_eq!(entry.sha1, Field::Present(SHA1_STARTING_WITH_ZERO.into()));
        assert_eq!(
            entry.path,
            Field::Present("c:\\users\\sarah\\evil.exe".into())
        );
        assert_eq!(entry.publisher, Field::Present("Contoso Ltd".into()));
        assert_eq!(entry.version, Field::Present("1.2.3.4".into()));
        assert_eq!(
            entry
                .link_date_local
                .value()
                .map(|w| w.local_iso8601.clone()),
            Some("2019-03-09T14:05:06".to_string())
        );
        assert!(entry.key_last_write.is_present());
        // This key records no install time at all, and that must not read as
        // "the program was never installed".
        assert_eq!(entry.installed, Field::NotApplicable);
        assert_eq!(entry.service, Field::NotApplicable);
        assert!(entry.notes.is_empty(), "{:?}", entry.notes);
    }

    #[test]
    fn a_windows_eight_file_entry_reads_the_hex_digit_value_names() {
        let values = values_of(vec![
            sz_value("100", "0006e1b2fc1234567890"),
            sz_value("101", &format!("0000{}", "ab".repeat(20))),
            sz_value("0", "Evil"),
            sz_value("1", "Contoso Ltd"),
            sz_value("15", "c:\\windows\\temp\\evil.exe"),
            sz_value("d", "1.2.3.4"),
            qword_value("11", 129_067_776_000_000_000),
            qword_value("12", 129_067_776_000_000_000),
            qword_value("f", 1_262_304_000),
        ]);
        let key = key_node("0006e1b2fc", 132_669_792_000_000_000);
        let entry = decode_entry(
            AmcacheSource::Win8File,
            &key,
            &values,
            "Root\\File\\{volume}\\0006e1b2fc".to_string(),
        );
        assert_eq!(entry.sha1, Field::Present("ab".repeat(20)));
        assert_eq!(
            entry.path,
            Field::Present("c:\\windows\\temp\\evil.exe".into())
        );
        assert_eq!(entry.name, Field::Present("Evil".into()));
        assert_eq!(entry.publisher, Field::Present("Contoso Ltd".into()));
        assert!(entry.last_modified.is_present());
        assert!(entry.created.is_present());
        assert!(entry.compiled.is_present());
        // `17` was not in this key, and absent is not the same as never
        // recorded by the format.
        assert_eq!(entry.last_modified_2, Field::Absent);
    }

    #[test]
    fn a_driver_binary_key_named_with_a_path_takes_its_hash_from_the_value() {
        let values = values_of(vec![
            sz_value("DriverId", &format!("0000{}", "cd".repeat(20))),
            sz_value("DriverCompany", "Contoso Ltd"),
            sz_value("Service", "evildrv"),
            qword_value("DriverTimeStamp", 1_262_304_000),
        ]);
        let key = key_node("c:/windows/system32/drivers/evil.sys", 0);
        let entry = decode_entry(
            AmcacheSource::InventoryDriverBinary,
            &key,
            &values,
            "Root\\InventoryDriverBinary\\evil.sys".to_string(),
        );
        assert_eq!(
            entry.path,
            Field::Present("c:/windows/system32/drivers/evil.sys".into())
        );
        assert_eq!(entry.sha1, Field::Present("cd".repeat(20)));
        assert_eq!(entry.service, Field::Present("evildrv".into()));
        assert!(entry.compiled.is_present());
        // The key's LastWriteTime was zero, which is the never-set sentinel.
        assert_eq!(entry.key_last_write, Field::Unset);
    }

    #[test]
    fn a_driver_binary_key_named_with_a_hash_takes_its_name_from_the_value() {
        let values = values_of(vec![sz_value("DriverName", "evil.sys")]);
        let key = key_node(&format!("0000{}", "ef".repeat(20)), 0);
        let entry = decode_entry(
            AmcacheSource::InventoryDriverBinary,
            &key,
            &values,
            "Root\\InventoryDriverBinary\\hash".to_string(),
        );
        assert_eq!(entry.sha1, Field::Present("ef".repeat(20)));
        assert_eq!(entry.name, Field::Present("evil.sys".into()));
    }

    #[test]
    fn an_inventory_application_key_is_named_with_the_program_id() {
        let values = values_of(vec![
            sz_value("Name", "Evil Suite"),
            sz_value("Publisher", "Contoso Ltd"),
            sz_value("RootDirPath", "c:\\program files\\evil"),
            sz_value("Version", "9.9"),
            sz_value("InstallDate", "03/09/2019 14:05:06"),
        ]);
        let key = key_node("0006e1b2fc1234567890", 132_669_792_000_000_000);
        let entry = decode_entry(
            AmcacheSource::InventoryApplication,
            &key,
            &values,
            "Root\\InventoryApplication\\0006e1b2fc1234567890".to_string(),
        );
        assert_eq!(
            entry.program_id,
            Field::Present("0006e1b2fc1234567890".into())
        );
        assert_eq!(entry.name, Field::Present("Evil Suite".into()));
        assert!(entry.install_date_local.is_present());
        // A program entry has no hash: the format records none, and reporting
        // an empty one would look like a file whose hash was not computed.
        assert_eq!(entry.sha1, Field::NotApplicable);
    }

    #[test]
    fn a_hive_that_is_not_an_amcache_hive_is_never_selected() {
        // The registry fixture's only named hive is an NTUSER.DAT.
        let profile = xp_profile();
        let listing = list_hives(&profile).expect("the fixture hive list walks");
        assert!(select_amcache_hive(&listing).is_none());
    }

    #[test]
    fn an_image_with_no_amcache_hive_says_so_and_is_not_reported_as_complete() {
        let profile = xp_profile();
        let layout = HiveLayout::from_profile(&profile).expect("the fixture names CmpHiveListHead");
        let hive = read_amcache_hive(&profile, &layout, &AmcacheConfig::default());

        assert!(matches!(hive.status, HiveStatus::NotLoaded { .. }));
        assert_eq!(hive.entry_count(), 0);
        assert!(
            !hive.is_complete(),
            "a hive that was never loaded cannot support 'this program never ran'"
        );
        let reasons = hive.incomplete();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].detail.contains("no Amcache hive"), "{reasons:?}");
    }

    #[test]
    fn a_hive_without_a_root_key_is_reported_as_loaded_and_empty_with_a_reason() {
        // The fixture hive is a real hive with no `Root` key, which is exactly
        // the shape of a hive that is not an Amcache hive at all.
        let profile = xp_profile();
        let listing = list_hives(&profile).expect("the fixture hive list walks");
        let reader = open_reader(&profile, XP_CMHIVE).expect("the fixture hive opens");
        let root = crate::registry::printkey::print_key(&reader, Some(AMCACHE_ROOT));
        assert!(root.is_err(), "the fixture hive has no Root key");
        // And the hive-list selection agrees that this is not the Amcache hive.
        assert!(select_amcache_hive(&listing).is_none());
    }

    #[test]
    fn every_source_reports_a_key_of_its_own_and_they_are_all_distinct() {
        let mut names: Vec<&str> = ALL_SOURCES.iter().map(|s| s.key_name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        // Only `Root\File` nests its entries under volume keys.
        assert_eq!(
            ALL_SOURCES
                .iter()
                .filter(|s| s.entries_are_nested())
                .count(),
            1
        );
    }

    #[test]
    fn a_capped_section_keeps_its_total_exact_and_says_it_stopped() {
        let mut section = AmcacheKeySection {
            source: AmcacheSource::InventoryApplicationFile,
            status: KeyStatus::Read,
            entries: Vec::new(),
            entries_total: 0,
            truncated: false,
            incomplete: Vec::new(),
        };
        let config = AmcacheConfig {
            max_entries_per_key: 2,
            ..AmcacheConfig::default()
        };
        for step in 0..5 {
            section.entries_total = section.entries_total.saturating_add(1);
            if section.entries.len() >= config.max_entries_per_key {
                section.truncated = true;
                continue;
            }
            section.entries.push(AmcacheEntry::new(
                AmcacheSource::InventoryApplicationFile,
                format!("Root\\InventoryApplicationFile\\{step}"),
                format!("{step}"),
            ));
        }
        assert_eq!(section.entries.len(), 2);
        assert_eq!(section.entries_total, 5);
        assert!(section.truncated);
        assert!(!section.is_complete());
    }

    #[test]
    fn a_key_reported_absent_from_an_unreadable_index_is_not_a_conclusive_absence() {
        assert!(KeyStatus::Read.is_conclusive());
        assert!(KeyStatus::Absent {
            search_complete: true
        }
        .is_conclusive());
        assert!(!KeyStatus::Absent {
            search_complete: false
        }
        .is_conclusive());
        assert!(!KeyStatus::Unreachable("paged out".into()).is_conclusive());
    }
}
