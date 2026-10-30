//! The CIM repository's page mapping: `MAPPING1/2/3.MAP` from Vista onward,
//! `OBJECTS.MAP` on Windows XP (HUNT-195).
//!
//! `OBJECTS.DATA` is addressed in *logical* pages; the mapping file says which
//! physical 8192-byte page of the file holds each logical page, and which
//! physical pages are free. A record whose descriptor runs past the end of its
//! page continues at the start of the *next logical* page, which is wherever
//! the mapping puts it — not the physically next page. A physical page that
//! no logical page maps to holds no current data: whatever records it carries
//! are superseded or free-page copies.
//!
//! # Layout (as read off the real files in `tests/fixtures/wmi/`)
//!
//! A mapping section is a header, one entry per logical page, a free-page
//! list and a footer:
//!
//! | Form | Header (u32 each) | Entry |
//! |------|-------------------|-------|
//! | Vista onward (`MAPPINGn.MAP`) | `0xABCD`, sequence number, two values whose meaning is not documented, physical page count, logical page count | 24 bytes; the first u32 is the physical page |
//! | XP (`OBJECTS.MAP`) | `0xABCD`, sequence number, physical page count, logical page count | 4 bytes: the physical page |
//! | Server 2003 (`MAPPINGn.MAP`) | the XP header | 4 bytes, as XP |
//!
//! then a u32 free-page count, that many u32 physical page numbers, and the
//! footer `0xDCBA`. A Vista-onward file holds two sections — `OBJECTS.DATA`'s
//! then `INDEX.BTR`'s — carrying the same sequence number; XP keeps
//! `INDEX.BTR`'s in a separate `INDEX.MAP` (one XP-form section, read by [`parse_xp_index_map`], `VALIDATION.md` `WMI-9`); **Windows Server 2003 R2 SP2 x64** (2026-10-22,
//! `VALIDATION.md` `WMI-8`) is a third shape: numbered files like Vista's holding both sections
//! like Vista's, with XP's header and four-byte entries ([`MappingForm::XpNumbered`]). On every
//! real file here the mapped and the free pages partition the physical pages exactly.
//!
//! The 24-byte entry's second u32 looks like a page checksum, but it is not
//! CRC-32 (with or without the usual init and final XOR) or CRC-32C of the
//! page, so it is not checked. What the other fields mean is not documented
//! publicly and they are not read.
//!
//! # Which file is current
//!
//! Windows keeps three `MAPPINGn.MAP` files and rewrites them in turn. The one
//! used is the well-formed file (every section's signature, counts and footer
//! valid) with the highest sequence number. `MAPPING.VER`, which some
//! references give as the XP-era pointer to the current file, is not held in
//! any repository here and is not read.
//!
//! References: Joachim Metz, *WMI repository file format* (libyal/dtformats);
//! Ballenthin, Graeber, Teodorescu, *WMI Offense, Defense, and Forensics*
//! (FireEye, 2015) and its `flare-wmi` reader. Where they and the bytes
//! disagree, the bytes won.

/// The signature every mapping section starts with.
pub const MAPPING_SIGNATURE: u32 = 0xABCD;
/// The value that ends every mapping section.
pub const MAPPING_FOOTER: u32 = 0xDCBA;
/// A logical page that maps to no physical page.
pub const UNMAPPED: u32 = 0xFFFF_FFFF;

/// Which form of mapping file this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingForm {
    /// `MAPPING1/2/3.MAP`: 24-byte entries, `OBJECTS.DATA` then `INDEX.BTR`.
    Vista,
    /// `OBJECTS.MAP` (or `INDEX.MAP`): 4-byte entries, one section.
    Xp,
    /// `MAPPINGn.MAP` holding two sections of 4-byte entries, `OBJECTS.DATA`'s then `INDEX.BTR`'s
    /// (Windows Server 2003 R2 SP2). The index's root is the root page its logical page 0 names.
    XpNumbered,
}

/// One mapping section: logical page -> physical page, plus the free list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageMap {
    pub sequence: u32,
    /// Physical pages the section accounts for.
    pub physical_pages: u32,
    /// Indexed by logical page; [`UNMAPPED`] for a logical page with none.
    pub logical: Vec<u32>,
    /// Physical pages the section lists as free.
    pub free: Vec<u32>,
    /// The fourth u32 of the first entry of a Vista-onward section; zero in
    /// the XP form, which has no such field. In `INDEX.BTR`'s section it is
    /// the logical page of the index's root (60 or 61 on every repository
    /// held; HUNT-195). In `OBJECTS.DATA`'s section it reads zero.
    pub first_entry_aux: u32,
    /// The index section of an [`MappingForm::XpNumbered`] file: its root is not in the mapping but in
    /// the header of the index's logical page 0 (the fourth u32), where a Vista-onward page holds zero.
    pub root_in_page_zero: bool,
}

impl PageMap {
    /// The physical page holding `logical`, when it is mapped.
    pub fn physical(&self, logical: usize) -> Option<usize> {
        self.logical
            .get(logical)
            .copied()
            .filter(|&p| p != UNMAPPED)
            .map(|p| p as usize)
    }

    /// For each physical page below `pages`, the logical page mapped to it.
    pub fn inverse(&self, pages: usize) -> Vec<Option<usize>> {
        let mut out = vec![None; pages];
        for (l, &p) in self.logical.iter().enumerate() {
            if let Some(slot) = out.get_mut(p as usize) {
                if p != UNMAPPED {
                    *slot = Some(l);
                }
            }
        }
        out
    }
}

/// A parsed mapping file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub form: MappingForm,
    pub sequence: u32,
    /// `OBJECTS.DATA`'s section.
    pub objects: PageMap,
    /// `INDEX.BTR`'s section, in a Vista-onward file.
    pub index: Option<PageMap>,
}

/// Parse a mapping file, or say why it is refused.
///
/// Every count is checked against the bytes left before anything is
/// allocated, every mapped page must lie below the section's physical page
/// count and be mapped once, and every section must end in the footer. Bytes
/// past the last section are ignored: the Data Leakage copies carry stale
/// bytes there from an earlier, longer write.
pub fn parse_mapping(bytes: &[u8], form: MappingForm) -> Result<Mapping, String> {
    let (objects, end) = parse_section(bytes, 0, form, "OBJECTS.DATA")?;
    let index = match form {
        MappingForm::Xp => None,
        MappingForm::Vista | MappingForm::XpNumbered => {
            let (mut index, _) = parse_section(bytes, end, form, "INDEX.BTR")?;
            index.root_in_page_zero = form == MappingForm::XpNumbered;
            if index.sequence != objects.sequence {
                return Err(format!(
                    "the INDEX.BTR section's sequence number {} differs from the \
                     OBJECTS.DATA section's {}",
                    index.sequence, objects.sequence
                ));
            }
            Some(index)
        }
    };
    Ok(Mapping {
        form,
        sequence: objects.sequence,
        objects,
        index,
    })
}

fn u32_at(bytes: &[u8], at: usize, what: &str) -> Result<u32, String> {
    at.checked_add(4)
        .and_then(|end| bytes.get(at..end))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("the file ends before the {what} at byte {at}"))
}

/// Parse a Windows XP `INDEX.MAP`: one XP-form section, the mapping of `INDEX.BTR`, whose root is named by the header of
/// logical page 0 (`HUNT-195`, `VALIDATION.md` `WMI-8`). Its sequence number must equal `OBJECTS.MAP`'s, which the caller checks.
pub fn parse_xp_index_map(bytes: &[u8]) -> Result<PageMap, String> {
    let (mut index, _) = parse_section(bytes, 0, MappingForm::Xp, "INDEX.BTR")?;
    index.root_in_page_zero = true;
    Ok(index)
}

/// Parse one section starting at `at`; returns it and the offset past its footer.
fn parse_section(
    bytes: &[u8],
    at: usize,
    form: MappingForm,
    section: &str,
) -> Result<(PageMap, usize), String> {
    let sig = u32_at(bytes, at, "signature")?;
    if sig != MAPPING_SIGNATURE {
        return Err(format!(
            "the {section} section at byte {at} has signature {sig:#x}, not {MAPPING_SIGNATURE:#x}"
        ));
    }
    let sequence = u32_at(bytes, at + 4, "sequence number")?;
    let (header, entry_size, phys_at, count_at) = match form {
        MappingForm::Vista => (24usize, 24usize, at + 16, at + 20),
        MappingForm::Xp | MappingForm::XpNumbered => (16, 4, at + 8, at + 12),
    };
    let physical_pages = u32_at(bytes, phys_at, "physical page count")?;
    let count = u32_at(bytes, count_at, "logical page count")? as usize;
    let entries_at = at + header;
    let room = bytes.len().saturating_sub(entries_at) / entry_size;
    if count > room {
        return Err(format!(
            "the {section} section declares {count} logical pages but the file has room for {room}"
        ));
    }
    let first_entry_aux = match form {
        MappingForm::Vista if count > 0 => u32_at(bytes, entries_at + 12, "first mapping entry")?,
        _ => 0,
    };
    let mut logical = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::with_capacity(count);
    for k in 0..count {
        let p = u32_at(bytes, entries_at + k * entry_size, "mapping entry")?;
        if p != UNMAPPED {
            if p >= physical_pages {
                return Err(format!(
                    "logical page {k} of the {section} section names physical page {p}, \
                     past the section's {physical_pages} physical pages"
                ));
            }
            if !seen.insert(p) {
                return Err(format!(
                    "physical page {p} is mapped twice in the {section} section"
                ));
            }
        }
        logical.push(p);
    }
    let free_at = entries_at + count * entry_size;
    let free_count = u32_at(bytes, free_at, "free-page count")? as usize;
    let free_room = bytes.len().saturating_sub(free_at + 4) / 4;
    if free_count > free_room {
        return Err(format!(
            "the {section} section declares {free_count} free pages but the file has room for {free_room}"
        ));
    }
    let mut free = Vec::with_capacity(free_count);
    for k in 0..free_count {
        let p = u32_at(bytes, free_at + 4 + 4 * k, "free-page entry")?;
        if p >= physical_pages {
            return Err(format!(
                "free page {p} of the {section} section is past its {physical_pages} physical pages"
            ));
        }
        free.push(p);
    }
    let footer_at = free_at + 4 + 4 * free_count;
    let footer = u32_at(bytes, footer_at, "footer")?;
    if footer != MAPPING_FOOTER {
        return Err(format!(
            "the {section} section's footer at byte {footer_at} is {footer:#x}, not {MAPPING_FOOTER:#x}"
        ));
    }
    Ok((
        PageMap {
            sequence,
            physical_pages,
            logical,
            free,
            first_entry_aux,
            root_in_page_zero: false,
        },
        footer_at + 4,
    ))
}

/// The index of the mapping to use among `candidates`: the well-formed one
/// with the highest sequence number. A tie goes to the first listed.
pub fn choose_active(candidates: &[Result<Mapping, String>]) -> Option<usize> {
    let mut best: Option<(usize, u32)> = None;
    for (i, c) in candidates.iter().enumerate() {
        if let Ok(m) = c {
            if best.is_none_or(|(_, s)| m.sequence > s) {
                best = Some((i, m.sequence));
            }
        }
    }
    best.map(|(i, _)| i)
}

/// Ceiling on one mapping file read. The real ones are 2.7 KB to 79 KB; four
/// bytes per logical page on a 512 MB `OBJECTS.DATA` is 256 KB.
pub const MAX_MAPPING_BYTES: u64 = 16 * 1024 * 1024;

/// The mapping files looked for beside `OBJECTS.DATA`, in order. The numbered
/// files are the only form read when any is present; `OBJECTS.MAP` (the XP
/// form) is looked for only when none is.
pub const NUMBERED_MAPPING_FILES: &[&str] = &["MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"];
pub const XP_MAPPING_FILE: &str = "OBJECTS.MAP";

/// What looking beside `OBJECTS.DATA` for its mapping found.
#[derive(Debug, Clone, Default)]
pub struct MappingRead {
    /// Whether the file's source can look beside itself at all. When it
    /// cannot, nothing below is "not there": it is "could not look".
    pub could_look: bool,
    /// The mapping used: its file name and contents.
    pub used: Option<(String, Mapping)>,
    /// Well-formed mapping files with a lower sequence number than the one used.
    pub older: Vec<(String, u32)>,
    /// Mapping files found but refused, with the reason.
    pub refused: Vec<(String, String)>,
    /// Mapping files looked for and not found.
    pub not_found: Vec<String>,
    /// Mapping files present beside the file but withheld by the neighbour
    /// bundle, because the directory holds the name more than once and one
    /// copy is not chosen over the other. Never counted as not found.
    pub withheld: Vec<String>,
    /// What `INDEX.BTR` beside the file came to (HUNT-195).
    pub index: crate::wmi_index::IndexRead,
}

/// Whether the neighbour bundle withheld `name` (present more than once).
fn withheld_named(ds: &dyn seance_core::data_source::DataSource, name: &str) -> bool {
    ds.relative_withheld(name) || ds.relative_withheld(&name.to_ascii_lowercase())
}

fn open_named(
    ds: &dyn seance_core::data_source::DataSource,
    name: &str,
) -> Option<std::sync::Arc<dyn seance_core::data_source::DataSource>> {
    ds.open_relative(name)
        .or_else(|| ds.open_relative(&name.to_ascii_lowercase()))
}

/// Look beside `OBJECTS.DATA` (`ds`) for its page mapping and choose the one
/// to use. `file_pages` is the number of whole pages of `OBJECTS.DATA` that
/// were read: a mapping that accounts for a different number of physical
/// pages does not describe this file and is refused rather than trusted.
pub fn read_beside(
    ds: &dyn seance_core::data_source::DataSource,
    file_pages: usize,
) -> MappingRead {
    let mut out = MappingRead {
        could_look: ds.supports_siblings(),
        ..MappingRead::default()
    };
    let mut candidates: Vec<(String, Result<Mapping, String>)> = Vec::new();
    for name in NUMBERED_MAPPING_FILES {
        match open_named(ds, name) {
            Some(src) => candidates.push((name.to_string(), read_numbered(src.as_ref()))),
            None if withheld_named(ds, name) => out.withheld.push(name.to_string()),
            None => out.not_found.push(name.to_string()),
        }
    }
    // A withheld numbered file is the numbered form present, so the XP form
    // is not looked for in its place.
    if candidates.is_empty() && out.withheld.is_empty() {
        match open_named(ds, XP_MAPPING_FILE) {
            Some(src) => {
                let mut mapping = read_one(src.as_ref(), MappingForm::Xp);
                if let Ok(m) = mapping.as_mut() {
                    attach_xp_index_map(ds, m, &mut out);
                }
                candidates.push((XP_MAPPING_FILE.to_string(), mapping));
            }
            None if withheld_named(ds, XP_MAPPING_FILE) => {
                out.withheld.push(XP_MAPPING_FILE.to_string())
            }
            None => out.not_found.push(XP_MAPPING_FILE.to_string()),
        }
    }
    if !out.could_look {
        // Nothing was found, and nothing may be said to be absent.
        out.not_found.clear();
    }
    let results: Vec<Result<Mapping, String>> = candidates
        .iter()
        .map(|(name, r)| match r {
            Ok(m) if m.objects.physical_pages as usize != file_pages => Err(format!(
                "{name} accounts for {} physical pages of OBJECTS.DATA but {file_pages} whole \
                 pages of OBJECTS.DATA were read, so it does not describe this file",
                m.objects.physical_pages
            )),
            other => other.clone(),
        })
        .collect();
    let active = choose_active(&results);
    for (i, ((name, _), r)) in candidates.into_iter().zip(results).enumerate() {
        match r {
            Ok(m) if Some(i) == active => out.used = Some((name, m)),
            Ok(m) => out.older.push((name, m.sequence)),
            Err(reason) => out.refused.push((name, reason)),
        }
    }
    out.index = match &out.used {
        Some((_, m)) => read_index_beside(ds, m, out.could_look),
        None => crate::wmi_index::IndexRead::default(),
    };
    out
}

/// Read `INDEX.MAP` beside `OBJECTS.MAP` and give the data mapping its index section, when the file is there, parses and
/// carries the same sequence number. Anything else is recorded as not found or refused, with the reason, and leaves the
/// mapping without an index (`read_index_beside` then says why).
fn attach_xp_index_map(
    ds: &dyn seance_core::data_source::DataSource,
    mapping: &mut Mapping,
    out: &mut MappingRead,
) {
    const NAME: &str = "INDEX.MAP";
    let Some(src) = open_named(ds, NAME) else {
        if withheld_named(ds, NAME) {
            out.withheld.push(NAME.to_string());
        } else if out.could_look {
            out.not_found.push(NAME.to_string());
        }
        return;
    };
    let parsed = if src.size() > MAX_MAPPING_BYTES {
        Err(format!(
            "the file is {} bytes, past the {MAX_MAPPING_BYTES}-byte ceiling for a mapping file",
            src.size()
        ))
    } else {
        let bytes = seance_core::io::read_capped(src.as_ref(), MAX_MAPPING_BYTES);
        if (bytes.len() as u64) < src.size() {
            Err(format!(
                "only {} of the file's {} bytes could be read",
                bytes.len(),
                src.size()
            ))
        } else {
            parse_xp_index_map(&bytes)
        }
    };
    match parsed {
        Ok(index) if index.sequence == mapping.sequence => mapping.index = Some(index),
        Ok(index) => out.refused.push((
            NAME.to_string(),
            format!(
                "its sequence number {} differs from OBJECTS.MAP's {}, so it does not belong with it",
                index.sequence, mapping.sequence
            ),
        )),
        Err(reason) => out.refused.push((NAME.to_string(), reason)),
    }
}

fn read_index_beside(
    ds: &dyn seance_core::data_source::DataSource,
    mapping: &Mapping,
    could_look: bool,
) -> crate::wmi_index::IndexRead {
    use crate::wmi_index::{indexed_records, IndexRead, MAX_INDEX_BYTES};
    const NAME: &str = "INDEX.BTR";
    let Some(map) = mapping.index.as_ref() else {
        return IndexRead::Unread(
            "the repository is the Windows XP form, and its INDEX.MAP beside OBJECTS.MAP was not \
             found or was refused, so INDEX.BTR has no mapping to be read through"
                .to_string(),
        );
    };
    if !could_look {
        return IndexRead::Unread(
            "the file's source cannot look beside it, so INDEX.BTR could not be looked for"
                .to_string(),
        );
    }
    let Some(src) = open_named(ds, NAME) else {
        return IndexRead::Unread(if withheld_named(ds, NAME) {
            "INDEX.BTR is present beside the file more than once and was withheld, not chosen \
             between"
                .to_string()
        } else {
            "INDEX.BTR was not found beside the file".to_string()
        });
    };
    if src.size() > MAX_INDEX_BYTES {
        return IndexRead::Unread(format!(
            "INDEX.BTR is {} bytes, past the {MAX_INDEX_BYTES}-byte ceiling",
            src.size()
        ));
    }
    let bytes = seance_core::io::read_capped(src.as_ref(), MAX_INDEX_BYTES);
    if (bytes.len() as u64) < src.size() {
        return IndexRead::Unread(format!(
            "only {} of INDEX.BTR's {} bytes could be read",
            bytes.len(),
            src.size()
        ));
    }
    match indexed_records(&bytes, map) {
        Ok(set) => IndexRead::Read(set),
        Err(why) => IndexRead::Unread(format!("INDEX.BTR was refused: {why}")),
    }
}

/// A numbered mapping file is Vista's form or, on Windows Server 2003, XP's two-section one: the first that
/// parses, and when neither does, both reasons.
fn read_numbered(src: &dyn seance_core::data_source::DataSource) -> Result<Mapping, String> {
    match read_one(src, MappingForm::Vista) {
        Ok(m) => Ok(m),
        Err(vista) => read_one(src, MappingForm::XpNumbered)
            .map_err(|xp| format!("as the Vista form: {vista}; as the Server 2003 form: {xp}")),
    }
}

fn read_one(
    src: &dyn seance_core::data_source::DataSource,
    form: MappingForm,
) -> Result<Mapping, String> {
    if src.size() > MAX_MAPPING_BYTES {
        return Err(format!(
            "the file is {} bytes, past the {MAX_MAPPING_BYTES}-byte ceiling for a mapping file",
            src.size()
        ));
    }
    let bytes = seance_core::io::read_capped(src, MAX_MAPPING_BYTES);
    if (bytes.len() as u64) < src.size() {
        return Err(format!(
            "only {} of the file's {} bytes could be read",
            bytes.len(),
            src.size()
        ));
    }
    parse_mapping(&bytes, form)
}
