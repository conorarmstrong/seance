//! The big-page pool tracker (`ROADMAP` §5.3, upstream's `bigpools`).
//!
//! # What an examiner learns
//!
//! Every allocation the kernel's pool made that was too large for a lookaside
//! block — a page or more — with its tag, its size and where it is. It is the
//! table a leaking or a hidden driver shows up in: a tag nothing loaded should
//! own, or a tag whose allocations outnumber everything else.
//!
//! # The table is walked whole and three kinds of slot are told apart
//!
//! `PoolBigPageTable` points at an array of `_POOL_TRACKER_BIG_PAGES` and
//! `PoolBigPageTableSize` is its length. A slot whose `Va` has its low bit set
//! was **freed**: the kernel marks the slot rather than clearing it, so the
//! tag and the size of an allocation that is gone stay readable. A slot that
//! is all zero was never used. Both are counted, and only the first is an
//! allocation the record lists — a freed allocation is evidence of what *was*
//! there, and is published as such, distinguished by type.
//!
//! # The kernel's own counter is read beside the walk
//!
//! `ExpPoolBigEntriesInUse` is the kernel's count of live slots. It is a
//! different fact from the number of live slots the walk found, and both are
//! reported; a disagreement is either a table mid-update at capture or a slot
//! the walk could not read, and preferring one number would hide it. The ISF
//! gives the symbol no type; it is read as a 32-bit value, the width the
//! kernel keeps that counter at, and the record states the width, because a
//! read at pointer width would fold whatever follows the counter into it.
//!
//! # Widths follow the build's pointer
//!
//! `Va`, `NumberOfBytes` and `ProcessBilled` are pointer-width fields, read at
//! the width the ISF's `pointer` base type declares: eight bytes on x64, four
//! on x86, where the slot is sixteen bytes and an eight-byte read would take
//! the neighbouring member with it.
//!
//! # Pool type against pool flags
//!
//! Older builds declare `PoolType` on the tracker entry, an `_POOL_TYPE` the
//! symbol table can name. Windows 11 build 26200 declares **no** `PoolType`:
//! the slot carries a 12-bit `PoolFlags` bitfield instead, whose encoding no
//! public symbol names. It is published raw and no pool type is inferred from
//! it; the record says which of the two this build had.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::StructReader;
use seance_memory::Incomplete;
use seance_symbols::TypeKind;
use serde_json::{json, Value};

use crate::profile::WindowsProfile;

/// Slots this walk will read. Reaching it is reported as a cap.
///
/// A table of four million 32-byte slots is 128 MiB; a declared size above it
/// is a corrupt or hostile value, not a machine with more allocations.
pub const MAX_TABLE_ENTRIES: u64 = 1 << 22;

/// Slots read in one contiguous read before falling back to one at a time.
const READ_BATCH: u64 = 256;

/// What stops the whole survey.
#[derive(Debug, Clone)]
pub enum BigPoolError {
    Unsupported { detail: String },
}

impl BigPoolError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn class(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported_build",
        }
    }
}

impl std::fmt::Display for BigPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { detail } => write!(f, "{detail}"),
        }
    }
}

/// How the table is described on this build.
#[derive(Debug, Clone)]
pub struct BigPoolSymbols {
    /// `PoolBigPageTable`, the global holding the table's address.
    pub table_pointer: u64,
    /// `PoolBigPageTableSize`, the global holding the slot count.
    pub table_size: u64,
    /// `ExpPoolBigEntriesInUse`, when declared.
    pub in_use_counter: Option<u64>,
    /// Width of a pointer on this build, from the ISF's `pointer` base type:
    /// the width `Va`, `NumberOfBytes` and `ProcessBilled` are read at.
    pub pointer_bytes: u64,
    /// Size of one `_POOL_TRACKER_BIG_PAGES`.
    pub entry_size: u64,
    pub va_offset: u64,
    pub key_offset: u64,
    /// Byte offset of `NumberOfBytes`, when declared.
    pub number_of_bytes: Option<u64>,
    /// Byte offset of `ProcessBilled`, when declared.
    pub process_billed: Option<u64>,
    /// Byte offset of `PoolType`, on builds that declare it.
    pub pool_type: Option<u64>,
    /// `PoolFlags`, on builds that declare that instead: the storage unit's
    /// byte offset, the field's bit position and its width, from the symbols.
    pub pool_flags: Option<BitfieldSpec>,
}

/// Where a bitfield lies, as the symbol table declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitfieldSpec {
    pub offset: u64,
    pub bit_position: u64,
    pub bit_length: u64,
}

impl BitfieldSpec {
    /// Extract the field from its 32-bit storage unit.
    pub fn extract(self, unit: u32) -> u64 {
        let mask = if self.bit_length >= 32 {
            u32::MAX
        } else {
            (1u32 << self.bit_length) - 1
        };
        u64::from((unit >> self.bit_position.min(31)) & mask)
    }
}

impl BigPoolSymbols {
    /// Resolve what this build declares.
    ///
    /// # Errors
    ///
    /// [`BigPoolError::Unsupported`] naming what is missing: the two globals,
    /// the entry type, or its `Va` and `Key` members.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, BigPoolError> {
        let symbol = |name: &str| -> Result<u64, BigPoolError> {
            let rva = profile.symbols.symbol_address(name).map_err(|_| {
                BigPoolError::unsupported(format!(
                    "this build's symbol table has no '{name}', so the big-page pool table \
                     cannot be located and nothing can be said about what it held"
                ))
            })?;
            profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
                BigPoolError::unsupported(format!(
                    "the address of '{name}' does not fit in 64 bits"
                ))
            })
        };
        let table_pointer = symbol("PoolBigPageTable")?;
        let table_size = symbol("PoolBigPageTableSize")?;
        let in_use_counter = symbol("ExpPoolBigEntriesInUse").ok();

        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let pointer_bytes = u64::from(reader.pointer_size().map_err(|err| {
            BigPoolError::unsupported(format!(
                "this build's symbol table does not size a pointer, so no slot field can be \
                 read at its width: {err}"
            ))
        })?);
        if pointer_bytes != 4 && pointer_bytes != 8 {
            return Err(BigPoolError::unsupported(format!(
                "this build declares a {pointer_bytes}-byte pointer, a width this reader does \
                 not read slot fields at"
            )));
        }
        let entry = "_POOL_TRACKER_BIG_PAGES";
        let entry_size = reader.size_of(entry).map_err(|err| {
            BigPoolError::unsupported(format!(
                "this build's symbol table does not size '{entry}': {err}"
            ))
        })?;
        let offset = |member: &str| -> Result<u64, BigPoolError> {
            reader
                .member_offset(entry, member)
                .map(|o| o.bytes())
                .map_err(|err| {
                    BigPoolError::unsupported(format!(
                        "this build declares no '{entry}.{member}', so a slot cannot be read: {err}"
                    ))
                })
        };
        let optional = |member: &str| -> Option<u64> {
            reader.member_offset(entry, member).ok().map(|o| o.bytes())
        };
        let pool_flags = profile
            .symbols
            .member(entry, "PoolFlags")
            .ok()
            .and_then(|member| match profile.symbols.entry(member.ty).ok()?.kind {
                TypeKind::Bitfield {
                    bit_position,
                    bit_length,
                    ..
                } => Some(BitfieldSpec {
                    offset: member.offset,
                    bit_position,
                    bit_length,
                }),
                _ => None,
            });
        Ok(Self {
            table_pointer,
            table_size,
            in_use_counter,
            pointer_bytes,
            entry_size: entry_size.bytes(),
            va_offset: offset("Va")?,
            key_offset: offset("Key")?,
            number_of_bytes: optional("NumberOfBytes"),
            process_billed: optional("ProcessBilled"),
            pool_type: optional("PoolType"),
            pool_flags,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "table_pointer_symbol": format!("{:#018x}", self.table_pointer),
            "table_size_symbol": format!("{:#018x}", self.table_size),
            "in_use_counter_symbol": self.in_use_counter.map(|a| format!("{a:#018x}")),
            "pointer_bytes": self.pointer_bytes,
            "entry_size": self.entry_size,
            "va_offset": self.va_offset,
            "key_offset": self.key_offset,
            "number_of_bytes_offset": self.number_of_bytes,
            "process_billed_offset": self.process_billed,
            "pool_type_offset": self.pool_type,
            "pool_flags": self.pool_flags.map(|f| json!({
                "offset": f.offset, "bit_position": f.bit_position, "bit_length": f.bit_length
            })),
        })
    }
}

/// Publication caps. The walk itself is bounded by [`MAX_TABLE_ENTRIES`].
#[derive(Debug, Clone)]
pub struct BigPoolConfig {
    /// Rows published on the record. The per-tag totals are always exact.
    pub max_published_entries: usize,
}

impl Default for BigPoolConfig {
    fn default() -> Self {
        Self {
            max_published_entries: 50_000,
        }
    }
}

/// A pool type as the symbol table names it.
#[derive(Debug, Clone)]
pub struct PoolTypeValue {
    pub raw: u64,
    /// The `_POOL_TYPE` constant, when the enumeration defines the value.
    pub name: Option<String>,
}

/// One slot that held an allocation.
#[derive(Debug, Clone)]
pub struct BigPoolEntry {
    pub index: u64,
    /// The allocation's address, with the free marker bit stripped.
    pub va: u64,
    /// The slot was freed: the kernel set the low bit of `Va` and left the
    /// rest of the slot in place.
    pub free: bool,
    /// The four-byte tag as text where every byte is printable ASCII, else as
    /// the hex of all four bytes.
    pub tag: String,
    /// The tag exactly as stored, little-endian.
    pub tag_raw: u32,
    pub number_of_bytes: Option<u64>,
    pub pool_type: Option<PoolTypeValue>,
    pub pool_flags: Option<u64>,
    pub process_billed: Option<u64>,
}

impl BigPoolEntry {
    pub fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "va": format!("{:#018x}", self.va),
            "free": self.free,
            "tag": self.tag,
            "tag_raw": self.tag_raw,
            "number_of_bytes": self.number_of_bytes,
            "pool_type": self.pool_type.as_ref().map(|t| json!({"raw": t.raw, "name": t.name})),
            "pool_flags": self.pool_flags,
            "process_billed": self.process_billed.map(|p| format!("{p:#018x}")),
        })
    }
}

/// The totals for one tag.
#[derive(Debug, Clone, Default)]
pub struct TagTotals {
    pub in_use: u64,
    pub free: u64,
    pub bytes_in_use: u64,
    pub bytes_free: u64,
}

impl TagTotals {
    pub fn to_json(&self) -> Value {
        json!({
            "in_use": self.in_use,
            "free": self.free,
            "bytes_in_use": self.bytes_in_use,
            "bytes_free": self.bytes_free,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct BigPoolSurvey {
    pub symbols: BigPoolSymbols,
    /// Where the table is.
    pub table: u64,
    /// `PoolBigPageTableSize`, as read.
    pub entries_declared: u64,
    /// Slots the walk read, including empty ones.
    pub entries_read: u64,
    /// Slots the walk could not read.
    pub entries_unreadable: u64,
    pub entries_in_use: u64,
    pub entries_free: u64,
    pub entries_empty: u64,
    /// `ExpPoolBigEntriesInUse`, as read.
    pub in_use_claimed: Option<u64>,
    /// Per-tag totals, exact over every slot read.
    pub tags: BTreeMap<String, TagTotals>,
    /// In-use and free allocations, in table order, capped for publication.
    pub entries: Vec<BigPoolEntry>,
    /// The publication cap fired.
    pub entries_truncated: bool,
    /// The walk stopped at [`MAX_TABLE_ENTRIES`].
    pub capped: bool,
    pub notes: Vec<String>,
}

impl BigPoolSurvey {
    /// Whether the kernel's counter equals the live slots walked. `None`
    /// without a counter, which is not agreement.
    pub fn counter_agrees(&self) -> Option<bool> {
        self.in_use_claimed.map(|c| c == self.entries_in_use)
    }

    /// Every slot read and none capped. A publication cap does not make the
    /// walk incomplete: the totals are exact.
    pub fn is_complete(&self) -> bool {
        !self.capped && self.entries_unreadable == 0
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the table declares {} slot(s) and the walk stopped at {MAX_TABLE_ENTRIES}, so \
                     every total here is a floor",
                    self.entries_declared
                ),
            ));
        }
        if self.entries_unreadable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} slot(s) could not be read, so an allocation among them would not be \
                     listed and the per-tag totals are floors",
                    self.entries_unreadable
                ),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        format!(
            "The big-page pool table at {:#018x} declares {} slot(s); {} were read, of which {} \
             hold a live allocation, {} a freed one and {} were never used. {} distinct tag(s).{}",
            self.table,
            self.entries_declared,
            self.entries_read,
            self.entries_in_use,
            self.entries_free,
            self.entries_empty,
            self.tags.len(),
            match self.counter_agrees() {
                Some(true) => format!(
                    " The kernel's own in-use counter reads {} and agrees.",
                    self.entries_in_use
                ),
                Some(false) => format!(
                    " The kernel's own in-use counter reads {} against the {} live slot(s) \
                     walked; both are reported.",
                    self.in_use_claimed.unwrap_or(0),
                    self.entries_in_use
                ),
                None => " This build declares no in-use counter to compare against.".to_string(),
            }
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "table": format!("{:#018x}", self.table),
            "entries_declared": self.entries_declared,
            "entries_read": self.entries_read,
            "entries_unreadable": self.entries_unreadable,
            "entries_in_use": self.entries_in_use,
            "entries_free": self.entries_free,
            "entries_empty": self.entries_empty,
            "in_use_counter_claimed": self.in_use_claimed,
            "in_use_counter_agrees": self.counter_agrees(),
            "counter_basis":
                "`ExpPoolBigEntriesInUse` carries no declared type in the ISF and is read as a \
                 32-bit value, the width the kernel keeps the counter at; a read at pointer \
                 width would fold the bytes after it into the count. It is compared with the \
                 walk and never preferred to it.",
            "width_basis": format!(
                "`Va`, `NumberOfBytes` and `ProcessBilled` are read at this build's pointer \
                 width of {} byte(s), from the ISF's `pointer` base type.",
                self.symbols.pointer_bytes
            ),
            "tags": self.tags.iter().map(|(tag, totals)| (tag.clone(), totals.to_json())).collect::<serde_json::Map<_, _>>(),
            "tags_total": self.tags.len(),
            "entries": self.entries.iter().map(BigPoolEntry::to_json).collect::<Vec<_>>(),
            "entries_published": self.entries.len(),
            "entries_truncated": self.entries_truncated,
            "entries_publication_cap_note": self.entries_truncated.then(|| format!(
                "only the first {} of {} allocation slot(s) are listed; the per-tag totals \
                 cover every slot read",
                self.entries.len(),
                self.entries_in_use + self.entries_free
            )),
            "free_basis":
                "A slot whose `Va` has its low bit set was freed: the kernel marks the slot and \
                 leaves the tag and size in place, so a freed allocation's tag is evidence of \
                 what was there. It is listed with `free: true`, never as a live allocation. A \
                 slot that is all zero was never used and is counted, not listed.",
            "classification_basis": match (&self.symbols.pool_type, &self.symbols.pool_flags) {
                (Some(_), _) => "`PoolType` is declared on this build's tracker entry and is named \
                                 from the `_POOL_TYPE` enumeration; a value the enumeration does \
                                 not define is published as its number.".to_string(),
                (None, Some(_)) => "This build declares no `PoolType` on the tracker entry, only a \
                                    `PoolFlags` bitfield whose encoding no public symbol names. \
                                    The flags are published raw and no pool type is inferred \
                                    from them.".to_string(),
                (None, None) => "This build declares neither `PoolType` nor `PoolFlags` on the \
                                 tracker entry, so no allocation is classified.".to_string(),
            },
            "statement": self.describe(),
            "notes": self.notes,
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Render a pool tag: text when every byte is printable ASCII, else hex.
pub fn render_tag(raw: [u8; 4]) -> String {
    if raw.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        raw.iter().map(|b| *b as char).collect()
    } else {
        format!("0x{:02x}{:02x}{:02x}{:02x}", raw[0], raw[1], raw[2], raw[3])
    }
}

/// Walk the big-page pool table.
///
/// Never fails once the symbols resolved: a table whose address or size would
/// not read is a survey with that note and no slots, and a slot that would
/// not read is counted rather than skipped.
pub fn survey_big_pool(
    profile: &WindowsProfile,
    symbols: &BigPoolSymbols,
    config: &BigPoolConfig,
) -> BigPoolSurvey {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut survey = BigPoolSurvey {
        symbols: symbols.clone(),
        table: 0,
        entries_declared: 0,
        entries_read: 0,
        entries_unreadable: 0,
        entries_in_use: 0,
        entries_free: 0,
        entries_empty: 0,
        in_use_claimed: None,
        tags: BTreeMap::new(),
        entries: Vec::new(),
        entries_truncated: false,
        capped: false,
        notes: Vec::new(),
    };

    let table = match reader.read_pointer_at(symbols.table_pointer) {
        Ok(t) => t,
        Err(err) => {
            survey
                .notes
                .push(format!("`PoolBigPageTable` would not read: {err}"));
            return survey;
        }
    };
    survey.table = table;
    // `SIZE_T`: pointer-width, and untyped in the ISF.
    let declared = match reader.read_pointer_at(symbols.table_size) {
        Ok(n) => n,
        Err(err) => {
            survey
                .notes
                .push(format!("`PoolBigPageTableSize` would not read: {err}"));
            return survey;
        }
    };
    survey.entries_declared = declared;
    // A 32-bit counter, whatever the pointer width: see the module doc.
    survey.in_use_claimed = symbols.in_use_counter.and_then(|at| {
        reader
            .read_bytes(at, 4)
            .ok()
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    });
    if table == 0 || declared == 0 {
        survey.notes.push(
            "the table is null or declares no slots, so there is nothing to walk".to_string(),
        );
        return survey;
    }

    let to_walk = declared.min(MAX_TABLE_ENTRIES);
    survey.capped = declared > MAX_TABLE_ENTRIES;
    let entry_size = symbols.entry_size;
    let enum_names = pool_type_enum(profile);

    let mut index = 0u64;
    while index < to_walk {
        let batch = READ_BATCH.min(to_walk - index);
        let Some(at) = table.checked_add(index * entry_size) else {
            survey.notes.push(format!(
                "slot {index} lies past the end of the address space; the walk stopped there"
            ));
            survey.capped = true;
            break;
        };
        let bytes = reader.read_bytes(at, batch * entry_size).ok();
        for slot in 0..batch {
            let slot_bytes: Option<Vec<u8>> = match &bytes {
                Some(all) => {
                    let start = (slot * entry_size) as usize;
                    Some(all[start..start + entry_size as usize].to_vec())
                }
                None => reader.read_bytes(at + slot * entry_size, entry_size).ok(),
            };
            match slot_bytes {
                Some(raw) => {
                    survey.entries_read += 1;
                    record_slot(
                        &mut survey,
                        symbols,
                        config,
                        &enum_names,
                        index + slot,
                        &raw,
                    );
                }
                None => survey.entries_unreadable += 1,
            }
        }
        index += batch;
    }
    survey
}

/// Read one slot's fields out of its bytes.
fn record_slot(
    survey: &mut BigPoolSurvey,
    symbols: &BigPoolSymbols,
    config: &BigPoolConfig,
    enum_names: &Option<seance_symbols::EnumInfo>,
    index: u64,
    raw: &[u8],
) {
    let u32_at = |at: u64| -> Option<u32> {
        let at = at as usize;
        raw.get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
    };
    // A pointer-width field, at the width this build's ISF declares.
    let pointer_at = |at: u64| -> Option<u64> {
        let at = at as usize;
        match symbols.pointer_bytes {
            4 => u32_at(at as u64).map(u64::from),
            8 => raw
                .get(at..at + 8)
                .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes"))),
            // `from_profile` refuses any other width.
            _ => None,
        }
    };
    let Some(va_raw) = pointer_at(symbols.va_offset) else {
        survey.entries_unreadable += 1;
        return;
    };
    let Some(tag_raw) = u32_at(symbols.key_offset) else {
        survey.entries_unreadable += 1;
        return;
    };
    if va_raw == 0 && raw.iter().all(|b| *b == 0) {
        survey.entries_empty += 1;
        return;
    }
    let free = va_raw & 1 == 1;
    let va = va_raw & !1;
    let tag = render_tag(tag_raw.to_le_bytes());

    let number_of_bytes = symbols.number_of_bytes.and_then(pointer_at);
    let process_billed = symbols.process_billed.and_then(pointer_at);
    let pool_type = symbols.pool_type.and_then(u32_at).map(|raw| PoolTypeValue {
        raw: u64::from(raw),
        name: enum_names
            .as_ref()
            .and_then(|e| e.name_of(i128::from(raw)))
            .map(str::to_string),
    });
    let pool_flags = symbols
        .pool_flags
        .and_then(|spec| u32_at(spec.offset).map(|unit| spec.extract(unit)));

    let totals = survey.tags.entry(tag.clone()).or_default();
    if free {
        survey.entries_free += 1;
        totals.free += 1;
        totals.bytes_free = totals
            .bytes_free
            .saturating_add(number_of_bytes.unwrap_or(0));
    } else {
        survey.entries_in_use += 1;
        totals.in_use += 1;
        totals.bytes_in_use = totals
            .bytes_in_use
            .saturating_add(number_of_bytes.unwrap_or(0));
    }
    if survey.entries.len() < config.max_published_entries {
        survey.entries.push(BigPoolEntry {
            index,
            va,
            free,
            tag,
            tag_raw,
            number_of_bytes,
            pool_type,
            pool_flags,
            process_billed,
        });
    } else {
        survey.entries_truncated = true;
    }
}

/// The `_POOL_TYPE` enumeration, when this build declares it.
fn pool_type_enum(profile: &WindowsProfile) -> Option<seance_symbols::EnumInfo> {
    let id = profile.symbols.type_id("_POOL_TYPE").ok()?;
    match &profile.symbols.entry(id).ok()?.kind {
        TypeKind::Enum(info) => Some(info.clone()),
        _ => None,
    }
}
