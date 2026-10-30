//! The Windows **shell item** (PIDL), read once for every parser that meets one.
//!
//! A shell item is the binary structure Explorer uses to name a thing — a
//! folder, a file, a volume, a control-panel applet — and it turns up in four
//! places this product reads:
//!
//! * **shellbags** (`BagMRU` in `UsrClass.dat` / `NTUSER.DAT`), a tree of them;
//! * a **shortcut**'s `LinkTargetIDList`;
//! * a **jump list**'s embedded shortcuts, through the same;
//! * the **registry MRUs** — `RecentDocs` and `LastVisitedPidlMRU`, which
//!   store a display name and then a shell item ID list, and
//!   `OpenSavePidlMRU`, which stores the ID list alone.
//!
//! Before this crate existed each of those read what it needed in its own way,
//! and the MRUs read a `.lnk` name by **scanning for NUL-delimited printable
//! runs** rather than by walking the format — which is what `HUNT-127`
//! complains about and why every such name shipped with a `link_name_basis`
//! saying its boundaries came from delimiters. `ROADMAP` §5.16.
//!
//! # What is established, and what is not
//!
//! The item's **type byte** and the name inside a file-entry item are read, as
//! is the `BEEF0004` extension block — its long name, its two FAT
//! timestamps, and (version >= 7) the NTFS **MFT file reference** — for the
//! block versions libfwsi documents (3, 7, 8, 9). Some other item classes
//! (GUID folders, drive/volume items, network locations, URIs, delegate
//! folders) have their own fixed-offset fields read too. What is **not**
//! read yet is disclosed per item through [`ParsedShellItem::parsed`] rather
//! than folded into one crate-wide claim: a control-panel item, a root
//! folder, or a type this reader does not know at all always reports
//! `parsed: false` alongside its raw bytes, and a type whose read fell back
//! to a heuristic (rather than a documented fixed offset) reports `false`
//! too. A type this reader does not know yields `UnknownType_0x<hex>` rather
//! than a guess.
//!
//! # Every time here is local wall-clock with no zone
//!
//! A shell item's timestamps are FAT date/time pairs at two-second resolution.
//! They are returned as `DateTime<Utc>` because that is the one type a caller
//! can order and render, and **they are not UTC**: a caller must say so on
//! whatever it emits. `FAT_TIME_NOTE` is the sentence for that.

#![forbid(unsafe_code)]

use chrono::{DateTime, TimeZone, Utc};

/// Largest number of items walked in one ID list, so a corrupt size field
/// cannot spin the walk. A real PIDL is a path: tens of items, not thousands.
pub const MAX_ID_LIST_ITEMS: usize = 256;

/// Split a shell item **ID list** into its items.
///
/// An ID list is what the registry MRUs and a shortcut's `LinkTargetIDList`
/// hold: a sequence of `u16` little-endian sizes, each counting itself, ended
/// by a size of zero. Shellbags store one item per `BagMRU` slot and do not
/// need this.
///
/// The returned slices are the whole items, size field included, which is what
/// [`parse_shell_item`] and [`shell_item_times`] expect. A size that does not
/// advance, or that runs past the buffer, ends the walk — the items already
/// found are real, and reading past a bad length would read one item's name out
/// of the next item's bytes.
pub fn walk_id_list(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while out.len() < MAX_ID_LIST_ITEMS {
        let Some(head) = bytes.get(at..at + 2) else {
            break;
        };
        let size = u16::from_le_bytes([head[0], head[1]]) as usize;
        // Zero is the list terminator; anything under 3 cannot hold a size and
        // a type byte, so it is not an item either.
        if size < 3 {
            break;
        }
        let Some(item) = bytes.get(at..at + size) else {
            break;
        };
        out.push(item);
        at += size;
    }
    out
}

/// [`walk_id_list`], with every item decoded through [`parse_shell_item_detail`]
/// instead of left as raw bytes.
///
/// Added so a consuming crate reads one shared, per-item `parsed`/`mft_reference`
/// pair rather than each writing its own "call `walk_id_list`, then map each
/// item through `parse_shell_item`" loop — which is exactly how
/// `seance_plugin_lnk` and `seance_plugin_registry`'s MRU reader came to
/// publish `shell_item_path` from the richer decoder in this crate while
/// neither surfaced `parsed` or the MFT reference the same decoder already
/// extracts: both were written against [`parse_shell_item`] (name only)
/// before [`parse_shell_item_detail`] existed, and neither was updated when it
/// landed. A code-review pass on 2026-09-18 caught the gap; this is the fix
/// that keeps a third consumer from repeating it.
pub fn walk_id_list_detail(bytes: &[u8]) -> Vec<ParsedShellItem> {
    walk_id_list(bytes)
        .into_iter()
        .map(parse_shell_item_detail)
        .collect()
}

/// Extract the FAT/DOS last-modified time embedded in a file-entry shell item
/// (types 0x30-0x3F). Fully bounds-checked; never panics on short or hostile
/// input, and returns `None` for item classes that carry no timestamp.
pub fn shell_item_mtime(data: &[u8]) -> Option<DateTime<Utc>> {
    // Layout: 0=size(2) 2=type(1) 3=unk(1) 4=filesize(4) 8=dosdate(2) 10=dostime(2)
    if data.len() < 12 {
        return None;
    }
    // Only file-entry shell items carry a DOS date/time at this offset — the
    // same `0x30..=0x3F` test `parse_shell_item_detail` classifies by, so a
    // time is never read from an item whose name was not.
    if !matches!(data[2], 0x30..=0x3F) {
        return None;
    }
    let dos_date = u16::from_le_bytes([data[8], data[9]]);
    let dos_time = u16::from_le_bytes([data[10], data[11]]);
    dos_datetime_to_utc(dos_date, dos_time)
}

/// Convert a FAT DOS date/time pair to a UTC datetime. Returns `None` for a
/// zero or out-of-range value. DOS timestamps carry no timezone, so they are
/// surfaced as UTC.
pub fn dos_datetime_to_utc(dos_date: u16, dos_time: u16) -> Option<DateTime<Utc>> {
    if dos_date == 0 {
        return None;
    }
    let day = (dos_date & 0x1F) as u32;
    let month = ((dos_date >> 5) & 0x0F) as u32;
    let year = 1980 + ((dos_date >> 9) & 0x7F) as i32;
    let second = ((dos_time & 0x1F) as u32) * 2;
    let minute = ((dos_time >> 5) & 0x3F) as u32;
    let hour = ((dos_time >> 11) & 0x1F) as u32;
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
}

pub fn parse_shell_item(data: &[u8]) -> String {
    parse_shell_item_detail(data).name
}

/// Parse file entry shell item (type 0x30-0x3F).
/// These contain a short name at a fixed offset, and optionally a Unicode long name
/// inside a BEEF0004 extension block.
pub fn parse_file_entry_item(data: &[u8]) -> String {
    parse_file_entry_item_detail(data).0
}

/// [`parse_file_entry_item`], with a flag for whether the name it returns
/// came from a real, documented field (the `BEEF0004` long name or the fixed
/// short-name offset) rather than the heuristic last resort.
fn parse_file_entry_item_detail(data: &[u8]) -> (String, bool) {
    // Try to find the BEEF0004 extension block (contains Unicode long filename)
    if let Some(unicode_name) = find_beef0004_unicode_name(data) {
        if !unicode_name.is_empty() {
            return (unicode_name, true);
        }
    }

    // Fall back to short name at offset 14 (after size + type + filesize + date + time + attrs)
    // Offset: 0=size(2), 2=type(1), 3=unknown(1), 4=filesize(4), 8=date(2), 10=time(2), 12=attrs(2), 14=name
    if data.len() > 14 {
        if let Some(name) = extract_null_terminated(&data[14..], 255) {
            if !name.is_empty() {
                return (name, true);
            }
        }
    }

    // Last resort: heuristic string extraction — not a documented field, so
    // never reported as parsed.
    if data.len() > 14 {
        (extract_string_heuristic(&data[3..]), false)
    } else {
        ("Unparsed".to_string(), false)
    }
}

/// What a shellbag's times are, and are not.
pub const FAT_TIME_NOTE: &str = concat!(
    "These are FAT date/time pairs as Explorer wrote them: local wall-clock on the machine ",
    "at the time, with NO recorded zone and a two-second resolution. They are rendered ",
    "RFC 3339 so every date in this case has one shape, but they are NOT UTC — shifting one ",
    "by a zero offset is wrong by whatever the machine's offset was. They are also what ",
    "Explorer recorded when it last wrote this bag, which is not necessarily the folder's ",
    "current state on disk."
);

/// The three FAT date/time pairs a file-entry shell item can carry.
///
/// All three are **local wall-clock with no recorded zone** — that is what the
/// FAT encoding is — so every one of them is emitted beside a `timezone:
/// "local"` marker and never as a UTC instant (`BUG-107`). Reading one as UTC
/// shifts it by the machine's offset, which on a British summer evening is an
/// hour and across a date line is a day.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShellItemTimes {
    /// From the shell item itself, at item offset 8.
    pub modified: Option<DateTime<Utc>>,
    /// From the `BEEF0004` extension block, at block offset 8.
    pub created: Option<DateTime<Utc>>,
    /// From the same block, at block offset 12.
    pub accessed: Option<DateTime<Utc>>,
}

/// Read every time a file-entry shell item carries.
///
/// The modification time was already read; the creation and access times sit
/// in the `BEEF0004` extension block and were not (`ROADMAP` §5.16). They are
/// what makes a shellbag say *when* a folder was browsed rather than only
/// *that* it was.
pub fn shell_item_times(data: &[u8]) -> ShellItemTimes {
    let mut times = ShellItemTimes {
        modified: shell_item_mtime(data),
        ..ShellItemTimes::default()
    };
    // The block's own signature is what locates it; its offset is not fixed.
    if let Some(sig_at) = find_beef0004(data) {
        // The block starts four bytes before the signature, so block offsets
        // 8 and 12 are `sig_at + 4` and `sig_at + 8`.
        let pair = |at: usize| -> Option<DateTime<Utc>> {
            let b = data.get(at..at + 4)?;
            dos_datetime_to_utc(
                u16::from_le_bytes([b[0], b[1]]),
                u16::from_le_bytes([b[2], b[3]]),
            )
        };
        times.created = pair(sig_at + 4);
        times.accessed = pair(sig_at + 8);
    }
    times
}

/// Offset of the `0xBEEF0004` signature within a shell item, if it carries a
/// block whose version this reader knows the layout of.
///
/// Shared by the name and the time readers so the two can never disagree about
/// which block they are reading.
pub fn find_beef0004(data: &[u8]) -> Option<usize> {
    let sig: [u8; 4] = [0x04, 0x00, 0xEF, 0xBE];
    // `i` is the signature offset, i.e. block offset 4; the block starts at
    // i-4, so i must be at least 4 to read the preceding size/version fields.
    for i in 4..data.len().saturating_sub(4) {
        if data[i..i + 4] != sig {
            continue;
        }
        let version = u16::from_le_bytes([data[i - 2], data[i - 1]]);
        // libfwsi only defines the layout for these versions, and the two
        // timestamps sit at the same block offsets in all of them.
        if matches!(version, 3 | 7 | 8 | 9) {
            return Some(i);
        }
    }
    None
}

/// Search for the BEEF0004 extension block and extract the Unicode long name.
///
/// Offsets follow libfwsi (`libfwsi_file_entry_extension_values.c`). The block
/// starts 4 bytes before the 0xBEEF0004 signature: `size(2) version(2)
/// signature(4)`. The long name is not at a single fixed offset; its position
/// depends on the block version, because version >= 7 inserts an 18-byte file
/// reference block and versions 8/9 add extra fields.
pub fn find_beef0004_unicode_name(data: &[u8]) -> Option<String> {
    // Little-endian bytes of signature 0xBEEF0004.
    let sig: [u8; 4] = [0x04, 0x00, 0xEF, 0xBE];
    // `i` is the signature offset, i.e. block offset 4; the block starts at i-4,
    // so i must be at least 4 to read the preceding size/version fields.
    for i in 4..data.len().saturating_sub(4) {
        if data[i..i + 4] != sig {
            continue;
        }

        // Version is at block offset 2 == i - 2 (before the signature).
        let version = u16::from_le_bytes([data[i - 2], data[i - 1]]);
        // libfwsi only defines the long-name layout for these versions.
        if !matches!(version, 3 | 7 | 8 | 9) {
            continue;
        }

        // The "long name offset" field (block offset 16 == i + 12) is used as a
        // presence flag: zero means the block carries no long name.
        match data.get(i + 12..i + 14) {
            Some(b) if u16::from_le_bytes([b[0], b[1]]) != 0 => {}
            Some(_) => continue,
            None => continue,
        }

        // Block-relative offset of the long name, mirroring libfwsi's field walk:
        //   18 base
        //   +18 file-reference block (unknown 2 + file ref 8 + unknown 8)  [v >= 7]
        //   +2  localized-name-offset field  [all versions]
        //   +4  [v >= 9]
        //   +4  [v >= 8]
        let mut rel = 18usize;
        if version >= 7 {
            rel += 18;
        }
        rel += 2;
        if version >= 9 {
            rel += 4;
        }
        if version >= 8 {
            rel += 4;
        }

        // Block starts at i - 4; translate the block-relative offset to a file
        // offset. Yields i+16 (v3), i+34 (v7), i+38 (v8), i+42 (v9).
        let name_off = (i - 4) + rel;
        if name_off < data.len() {
            if let Some(name) = extract_utf16_le(&data[name_off..], 260) {
                return Some(name);
            }
        }
    }
    None
}

/// Block-relative offset of the NTFS file reference within a `BEEF0004`
/// extension block that has one: 18 (the fixed head every version shares,
/// see [`find_beef0004_unicode_name`]) + 2 (an "unknown" field libfwsi
/// documents ahead of the reference). Only versions >= 7 have this block at
/// all — a v3 block's layout ends before this offset means anything.
const MFT_FILE_REFERENCE_REL_OFFSET: usize = 20;

/// The 8-byte NTFS file reference libfwsi documents inside a file-entry shell
/// item's `BEEF0004` extension block, for block versions >= 7: a 48-bit MFT
/// entry (record) index and a 16-bit sequence number, packed little-endian
/// with the sequence in the high 16 bits (MS-FSCC 2.1.5.1 /
/// `libfwsi_file_entry_extension_values.c`'s `file_reference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MftFileReference {
    /// The MFT record (entry) index. Masked to 48 bits on read, so a
    /// corrupt or hostile top half of the packed `u64` cannot leak into the
    /// entry index.
    pub entry: u64,
    /// Incremented each time the MFT slot is reused. Pairing it with `entry`
    /// is what tells "this file" from "whatever now occupies the same slot".
    pub sequence: u16,
}

/// The low 48 bits of the packed reference are the MFT entry index; the top
/// 16 are the sequence number.
const MFT_ENTRY_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// What a `BEEF0004` block's file-reference field held, kept as three cases
/// because a consumer has to say three different things about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MftReferenceField {
    /// No block this reader knows the layout of, a version-3 block (which
    /// predates the field), or a block too short to hold it.
    Absent,
    /// The field is there and every byte of it is zero. Windows writes that
    /// when it has no reference — every one of the 38 `RecentDocs` `.lnk`
    /// items in plaso's `NTUSER-WIN7.DAT` carries a version-8 block with a
    /// zeroed field. It is **not** a reference to MFT entry 0 (that is
    /// `$MFT` itself) with sequence 0 (a sequence number NTFS never issues).
    Zero,
    /// A reference.
    Present(MftFileReference),
}

/// Read the file-reference field of a file-entry shell item's `BEEF0004`
/// extension block, distinguishing "not there" from "there and zero" from a
/// reference — never one fabricated from whatever bytes happen to be there.
pub fn beef0004_mft_reference_field(data: &[u8]) -> MftReferenceField {
    let Some(sig_at) = find_beef0004(data) else {
        return MftReferenceField::Absent;
    };
    // Version is at block offset 2 == sig_at - 2 (see `find_beef0004`).
    let version = u16::from_le_bytes([data[sig_at - 2], data[sig_at - 1]]);
    if version < 7 {
        return MftReferenceField::Absent;
    }
    // The block starts 4 bytes before the signature (size(2) version(2)).
    let block_start = sig_at - 4;
    let at = block_start + MFT_FILE_REFERENCE_REL_OFFSET;
    let Some(bytes) = data.get(at..at + 8) else {
        return MftReferenceField::Absent;
    };
    let Ok(bytes) = <[u8; 8]>::try_from(bytes) else {
        return MftReferenceField::Absent;
    };
    let raw = u64::from_le_bytes(bytes);
    if raw == 0 {
        return MftReferenceField::Zero;
    }
    MftReferenceField::Present(MftFileReference {
        entry: raw & MFT_ENTRY_MASK,
        sequence: (raw >> 48) as u16,
    })
}

/// The MFT file reference from a file-entry shell item's `BEEF0004`
/// extension block, for the versions that carry one.
///
/// `None` when the field is absent ([`MftReferenceField::Absent`]) **or all
/// zero** ([`MftReferenceField::Zero`]): publishing a zero field as entry 0
/// would name `$MFT`. A consumer that wants to say the field was there and
/// zero reads [`beef0004_mft_reference_field`] or
/// [`ParsedShellItem::mft_reference_zero`].
pub fn beef0004_mft_reference(data: &[u8]) -> Option<MftFileReference> {
    match beef0004_mft_reference_field(data) {
        MftReferenceField::Present(reference) => Some(reference),
        MftReferenceField::Absent | MftReferenceField::Zero => None,
    }
}

/// The sentence a consumer publishes beside a deepest item whose
/// file-reference field was there and zero, so the two readers that publish
/// it (`seance_plugin_lnk`, `seance_plugin_registry`) say the same thing.
pub const MFT_REFERENCE_ZERO_NOTE: &str = "the deepest item's BEEF0004 block carries a \
    file-reference field and it is zero. Zero is not a file reference — entry 0 is $MFT and \
    no sequence number is 0 — so none is claimed.";

/// A shell item together with a **per-item** signal for whether its own
/// type-specific structure was actually decoded.
///
/// `parsed` is not a crate-wide claim: one item in an ID list can report
/// `true` while its neighbour reports `false`, because whether a given
/// item's fields were read depends on that item's own type and length, not
/// on what this crate knows in general. `false` covers both "this build
/// does not know this item type" and "the type is known but this instance
/// was too short, or otherwise fell back to a placeholder/heuristic" —
/// either way `raw` is the authority for that item, not `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedShellItem {
    /// The same string [`parse_shell_item`] returns.
    pub name: String,
    /// True only when this item's fields were read from their real,
    /// documented offsets, not a placeholder or a heuristic guess.
    pub parsed: bool,
    /// The MFT file reference, for a file-entry (or compressed-folder) item
    /// carrying a `BEEF0004` block of version >= 7 whose field is not zero.
    pub mft_reference: Option<MftFileReference>,
    /// True when that field is there and all zero
    /// ([`MftReferenceField::Zero`]): a fact worth stating, and not a
    /// reference. Never true together with a `Some` `mft_reference`.
    pub mft_reference_zero: bool,
    /// The whole item, size field included. Always kept, whether or not
    /// `parsed` is true, so nothing this reader cannot interpret is ever
    /// silently dropped.
    pub raw: Vec<u8>,
}

/// [`parse_shell_item`], but with the per-item `parsed` signal and the MFT
/// file reference alongside the name. The two functions read exactly the
/// same fields for the same reason a shellbag's name and its times must
/// never disagree about which block they read: `parse_shell_item` is this
/// function's `name` field, so the two can never drift apart.
pub fn parse_shell_item_detail(data: &[u8]) -> ParsedShellItem {
    let raw = data.to_vec();
    if data.len() < 3 {
        return ParsedShellItem {
            name: "INVALID".to_string(),
            parsed: false,
            mft_reference: None,
            mft_reference_zero: false,
            raw,
        };
    }

    let type_indicator = data[2];
    // File entries are `0x30..=0x3F` and nothing else. The earlier
    // `type_indicator & 0x70 == 0x30` test also admitted `0xB0..=0xBF`, for
    // which this build cites no layout; a misaligned walk on plaso's
    // `NTUSER-WIN7.DAT` met a `0xBB` and read the byte at offset 14 as a
    // one-letter file name with `parsed: true`.
    let is_file_entry = matches!(type_indicator, 0x30..=0x3F);

    let (name, parsed) = match type_indicator {
        // A class-0x00 item with the users-property-view signature at
        // offset 6. Its property stores (`1SPS`) are not decoded, so the
        // class is named and nothing is claimed read.
        0x00 if is_users_property_view(data) => ("UsersPropertyView".to_string(), false),

        // Root folder (Desktop, My Computer, etc.). No field of this item is
        // read yet — the name is a fixed placeholder, not something taken
        // out of the bytes.
        0x00 => ("ROOT".to_string(), false),

        // GUID folder items (Control Panel, My Computer, Recycle Bin, etc.)
        0x1E | 0x1F => {
            if data.len() >= 20 {
                // GUID is at offset 4..20 (16 bytes, LE format) — a real,
                // fixed-offset field, so this is genuine structure.
                (format_known_guid(&data[4..20]), true)
            } else {
                ("SystemFolder".to_string(), false)
            }
        }

        // Drive / volume items
        0x20..=0x2F => {
            if data.len() > 3 {
                match extract_null_terminated(&data[3..], 25) {
                    Some(name) => (name, true),
                    None => ("Volume".to_string(), false),
                }
            } else {
                ("Volume".to_string(), false)
            }
        }

        // File entry items (most common — folders and files)
        _ if is_file_entry => parse_file_entry_item_detail(data),

        // Network share / location items
        0x41 | 0x42 | 0x43 | 0x46 | 0x47 | 0xC3 => {
            if data.len() > 5 {
                match extract_null_terminated(&data[5..], 260) {
                    Some(name) => (name, true),
                    None => ("NetworkLocation".to_string(), false),
                }
            } else {
                ("NetworkLocation".to_string(), false)
            }
        }

        // Compressed folder / ZIP items reuse the file-entry layout.
        0x52 => parse_file_entry_item_detail(data),

        // URI / FTP items
        0x61 => {
            if data.len() > 6 {
                match extract_null_terminated(&data[6..], 260) {
                    Some(name) => (name, true),
                    None => ("URI".to_string(), false),
                }
            } else {
                ("URI".to_string(), false)
            }
        }

        // Control panel items — no field read yet.
        0x71 => ("ControlPanel".to_string(), false),

        // Delegate folder items (Libraries, Searches)
        0x74 => {
            if data.len() >= 30 {
                // Inner shell item signature GUID at offset 14..30.
                (format_known_guid(&data[14..30]), true)
            } else {
                ("DelegateFolder".to_string(), false)
            }
        }

        _ => (format!("UnknownType_0x{:02X}", type_indicator), false),
    };

    // The MFT reference lives in the same BEEF0004 block as the long name,
    // so it is worth asking for on any item that could carry that block.
    let field = if is_file_entry || type_indicator == 0x52 {
        beef0004_mft_reference_field(data)
    } else {
        MftReferenceField::Absent
    };
    let (mft_reference, mft_reference_zero) = match field {
        MftReferenceField::Present(reference) => (Some(reference), false),
        MftReferenceField::Zero => (None, true),
        MftReferenceField::Absent => (None, false),
    };

    ParsedShellItem {
        name,
        parsed,
        mft_reference,
        mft_reference_zero,
        raw,
    }
}

/// The signatures at offset 6 of a class-`0x00` "users property view" item,
/// little-endian: `0x3B93AFBB`, `0x23FEBBEE`, `0x10141981`. All three occur
/// in plaso's `NTUSER-WIN7.DAT` `ComDlg32` MRUs, and plaso's known answers
/// for that hive (`tests/parsers/winreg_plugins/mrulistex.py`) render each
/// as `<Users property view>`: for instance `LastVisitedPidlMRU` value 1 as
/// `<Users Libraries> <Users property view> <Users property view> <Users
/// property view>`, whose three class-`0x00` items carry `0x23FEBBEE`,
/// `0x10141981`, `0x10141981`. Nothing past the signature is decoded here.
const USERS_PROPERTY_VIEW_SIGNATURES: [[u8; 4]; 3] = [
    [0xBB, 0xAF, 0x93, 0x3B],
    [0xEE, 0xBB, 0xFE, 0x23],
    [0x81, 0x19, 0x14, 0x10],
];

fn is_users_property_view(data: &[u8]) -> bool {
    data.len() >= 10 && USERS_PROPERTY_VIEW_SIGNATURES.contains(&data[6..10].try_into().unwrap())
}

/// Extract a null-terminated ASCII string from data, up to max_len bytes.
pub fn extract_null_terminated(data: &[u8], max_len: usize) -> Option<String> {
    let limit = std::cmp::min(data.len(), max_len);
    let mut end = 0;
    while end < limit && data[end] != 0 {
        end += 1;
    }
    if end > 0 {
        Some(String::from_utf8_lossy(&data[..end]).to_string())
    } else {
        None
    }
}

/// Extract a null-terminated UTF-16LE string from data.
pub fn extract_utf16_le(data: &[u8], max_chars: usize) -> Option<String> {
    let mut chars = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() && chars.len() < max_chars {
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
        i += 2;
    }
    if chars.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&chars))
    }
}

/// Map well-known GUIDs to human-readable names.
pub fn format_known_guid(guid_bytes: &[u8]) -> String {
    if guid_bytes.len() < 16 {
        return "SystemFolder".to_string();
    }

    // Format as standard GUID string for lookup
    let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
    let d3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
    let guid = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1,
        d2,
        d3,
        guid_bytes[8],
        guid_bytes[9],
        guid_bytes[10],
        guid_bytes[11],
        guid_bytes[12],
        guid_bytes[13],
        guid_bytes[14],
        guid_bytes[15]
    );

    match guid.as_str() {
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" => "MyComputer".to_string(),
        "{450D8FBA-AD25-11D0-98A8-0800361B1103}" => "MyDocuments".to_string(),
        "{645FF040-5081-101B-9F08-00AA002F954E}" => "RecycleBin".to_string(),
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" => "NetworkPlaces".to_string(),
        "{871C5380-42A0-1069-A2EA-08002B30309D}" => "Internet".to_string(),
        "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" => "UsersFiles".to_string(),
        "{031E4825-7B94-4DC3-B131-E946B44C8DD5}" => "Libraries".to_string(),
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" => "Desktop".to_string(),
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" => "Documents".to_string(),
        "{374DE290-123F-4565-9164-39C4925E467B}" => "Downloads".to_string(),
        "{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" => "Music".to_string(),
        "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}" => "Pictures".to_string(),
        "{A0953C92-50DC-43BF-BE83-3742FED03C9C}" => "Videos".to_string(),
        _ => format!("GUID:{}", guid),
    }
}

pub fn extract_string_heuristic(data: &[u8]) -> String {
    if data.len() > 12 && data.len() > 11 {
        let slice = &data[11..];
        let mut end = 0;
        while end < slice.len() && slice[end] != 0 {
            end += 1;
        }
        if end > 0 {
            return String::from_utf8_lossy(&slice[..end]).to_string();
        }
    }

    "Unparsed".to_string()
}

/// Fixtures for building shell items in tests, here so that every consumer
/// builds one the same way and none has to re-derive the offsets.
///
/// The same reason `seance_xml_util::abx::fixture` exists: a fixture built by
/// inverting the reader agrees with the reader whether or not either is right,
/// and a fixture each consumer writes for itself drifts.
pub mod fixture {

    /// Build a 0xBEEF0004 extension block for `version` carrying `long` as its
    /// UTF-16 long name, placed at the version-correct block offset.
    pub fn build_beef0004(version: u16, long: &str) -> Vec<u8> {
        let mut rel = 18usize;
        if version >= 7 {
            rel += 18;
        }
        rel += 2;
        if version >= 9 {
            rel += 4;
        }
        if version >= 8 {
            rel += 4;
        }
        let mut block = vec![0u8; rel];
        block[2..4].copy_from_slice(&version.to_le_bytes());
        block[4..8].copy_from_slice(&[0x04, 0x00, 0xEF, 0xBE]);
        // Non-zero "long name offset" field acts as the presence flag.
        block[16..18].copy_from_slice(&(rel as u16).to_le_bytes());
        for ch in long.encode_utf16() {
            block.extend_from_slice(&ch.to_le_bytes());
        }
        block.extend_from_slice(&[0, 0]); // UTF-16 NUL terminator
        block.extend_from_slice(&[0, 0]); // first-extension-block offset trailer
        let size = block.len() as u16;
        block[0..2].copy_from_slice(&size.to_le_bytes());
        block
    }

    /// Stamp an NTFS file reference onto a `BEEF0004` block already built by
    /// [`build_beef0004`], for `version >= 7` (the versions that carry the
    /// field at all). `entry` is truncated to 48 bits, matching what
    /// [`super::beef0004_mft_reference`] masks on read.
    ///
    /// Panics on a version below 7 or a block too short to hold the field —
    /// both mean the caller built the wrong fixture for what it is testing,
    /// not a case this helper should paper over.
    pub fn set_mft_reference(block: &mut [u8], entry: u64, sequence: u16) {
        let version = u16::from_le_bytes([block[2], block[3]]);
        assert!(
            version >= 7,
            "no file-reference field exists in a version {version} block"
        );
        const FILE_REF_REL_OFFSET: usize = 20;
        assert!(
            block.len() >= FILE_REF_REL_OFFSET + 8,
            "block too short to hold a file reference"
        );
        let packed = (entry & 0x0000_FFFF_FFFF_FFFF) | ((sequence as u64) << 48);
        block[FILE_REF_REL_OFFSET..FILE_REF_REL_OFFSET + 8].copy_from_slice(&packed.to_le_bytes());
    }

    /// A DOS date/time pair, built the way FAT encodes one.
    pub fn dos_pair(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> [u8; 4] {
        let date: u16 = (((year - 1980) as u16) << 9) | ((month as u16) << 5) | (day as u16);
        let time: u16 = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second / 2) as u16);
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&date.to_le_bytes());
        out[2..4].copy_from_slice(&time.to_le_bytes());
        out
    }

    /// A whole file-entry shell item: the fixed head with its modification
    /// time, then a `BEEF0004` block with its creation and access times.
    pub fn file_entry_with_times(version: u16, long: &str) -> Vec<u8> {
        let mut item = vec![0u8; 14];
        item[2] = 0x31; // file-entry type
                        // Item offset 8: the modification date/time.
        item[8..12].copy_from_slice(&dos_pair(2021, 6, 15, 14, 30, 44));
        let mut block = build_beef0004(version, long);
        // Block offsets 8 and 12: creation and last access.
        block[8..12].copy_from_slice(&dos_pair(2019, 1, 2, 3, 4, 6));
        block[12..16].copy_from_slice(&dos_pair(2021, 12, 31, 23, 59, 58));
        item.extend_from_slice(&block);
        // The item's own size, at its first two bytes. A shellbag slot holds
        // one item and never reads this; an ID list is walked by it, so a
        // fixture without it terminates the walk immediately.
        let size = item.len() as u16;
        item[0..2].copy_from_slice(&size.to_le_bytes());
        item
    }
}

#[cfg(test)]
mod id_list_tests {
    use super::*;

    /// An ID list is a path: each item names one level.
    #[test]
    fn an_id_list_splits_into_its_items() {
        let mut list = Vec::new();
        for name in ["Users", "bob", "report.docx"] {
            let mut item = vec![0u8; 14];
            item[2] = 0x31; // file-entry type
            item.extend_from_slice(name.as_bytes());
            item.push(0);
            let size = item.len() as u16;
            item[0..2].copy_from_slice(&size.to_le_bytes());
            list.extend_from_slice(&item);
        }
        list.extend_from_slice(&0u16.to_le_bytes()); // terminator

        let items = walk_id_list(&list);
        assert_eq!(items.len(), 3);
        assert_eq!(parse_shell_item(items[0]), "Users");
        assert_eq!(parse_shell_item(items[1]), "bob");
        assert_eq!(parse_shell_item(items[2]), "report.docx");
    }

    #[test]
    fn a_size_that_does_not_advance_or_runs_past_the_buffer_ends_the_walk() {
        // A size of zero is the terminator; one under three cannot hold a size
        // and a type byte. Either way the walk stops rather than looping.
        assert!(walk_id_list(&[0, 0]).is_empty());
        assert!(walk_id_list(&[1, 0, 0, 0]).is_empty());
        assert!(walk_id_list(&[2, 0, 0, 0]).is_empty());
        // A size past the end keeps the items already found and stops. Reading
        // on would take one item's name out of the next item's bytes.
        let mut list = vec![0u8; 14];
        list[0..2].copy_from_slice(&14u16.to_le_bytes());
        list[2] = 0x31;
        list.extend_from_slice(&[0xFF, 0xFF]); // a 65,535-byte item that is not there
        assert_eq!(walk_id_list(&list).len(), 1);
    }

    #[test]
    fn a_hostile_list_is_bounded() {
        // Every item the smallest a walk will accept, so the cap is what stops
        // it and not the buffer.
        let mut list = Vec::new();
        for _ in 0..(MAX_ID_LIST_ITEMS + 50) {
            list.extend_from_slice(&3u16.to_le_bytes());
            list.push(0x31);
        }
        assert_eq!(walk_id_list(&list).len(), MAX_ID_LIST_ITEMS);
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    #[test]
    fn beef0004_long_name_decodes_for_each_version() {
        // Regression: previously `version` was read from the wrong offset and the
        // long-name position was miscomputed for every version (empty/garbage).
        for &ver in &[3u16, 7, 8, 9] {
            let block = build_beef0004(ver, "LongFileName.txt");
            // Prefix with a non-signature short-name region so the block starts
            // well past offset 4 (as in a real file-entry shell item).
            let mut item = vec![0x11u8; 20];
            item.extend_from_slice(&block);

            let name = find_beef0004_unicode_name(&item)
                .unwrap_or_else(|| panic!("v{ver}: long name not found"));
            assert_eq!(name, "LongFileName.txt", "version {ver}");

            // parse_file_entry_item must prefer the long name too.
            let mut shell_item = vec![0u8; 14];
            shell_item[2] = 0x31; // file-entry type
            shell_item.extend_from_slice(&block);
            assert_eq!(parse_file_entry_item(&shell_item), "LongFileName.txt");
        }
    }

    #[test]
    fn beef0004_zero_long_name_offset_is_skipped() {
        let mut block = build_beef0004(8, "Ignored.txt");
        block[16..18].copy_from_slice(&0u16.to_le_bytes()); // clear presence flag
        let mut item = vec![0x11u8; 20];
        item.extend_from_slice(&block);
        assert!(find_beef0004_unicode_name(&item).is_none());
    }

    /// `ROADMAP` §5.16. A shellbag says a folder was browsed; these two times
    /// are what let it say *when*, and they were never read — the record
    /// carried no time at all and only the timeline event had the third.
    #[test]
    fn a_file_entry_yields_all_three_of_its_fat_times() {
        for &ver in &[3u16, 7, 8, 9] {
            let item = file_entry_with_times(ver, "Quarterly.xlsx");
            let times = shell_item_times(&item);
            assert_eq!(
                times.modified.map(|t| t.to_rfc3339()),
                Some("2021-06-15T14:30:44+00:00".to_string()),
                "version {ver}"
            );
            assert_eq!(
                times.created.map(|t| t.to_rfc3339()),
                Some("2019-01-02T03:04:06+00:00".to_string()),
                "version {ver}: the BEEF0004 block's creation time"
            );
            assert_eq!(
                times.accessed.map(|t| t.to_rfc3339()),
                Some("2021-12-31T23:59:58+00:00".to_string()),
                "version {ver}: the BEEF0004 block's last-access time"
            );
            // And the two readers agree about which block they read.
            assert_eq!(
                find_beef0004_unicode_name(&item).as_deref(),
                Some("Quarterly.xlsx")
            );
        }
    }

    #[test]
    fn a_shell_item_with_no_extension_block_yields_only_its_own_time() {
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        item[8..12].copy_from_slice(&dos_pair(2020, 3, 4, 5, 6, 8));
        let times = shell_item_times(&item);
        assert!(times.modified.is_some());
        // Absent, not zero: nothing here knows when the folder was made.
        assert_eq!(times.created, None);
        assert_eq!(times.accessed, None);
    }

    #[test]
    fn a_zero_fat_pair_is_absent_rather_than_1980() {
        // FAT writes all-zero for "not recorded", and 1980-00-00 is not a date.
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        let mut block = build_beef0004(8, "x");
        block[8..12].copy_from_slice(&[0, 0, 0, 0]);
        block[12..16].copy_from_slice(&dos_pair(2021, 5, 5, 5, 5, 5));
        item.extend_from_slice(&block);
        let times = shell_item_times(&item);
        assert_eq!(times.created, None, "a zero pair is not 1980-01-00");
        assert!(times.accessed.is_some());
    }

    /// The block whose version this reader does not know the layout of is not
    /// read for times either, because the two timestamps' offsets are only
    /// established for the versions libfwsi documents.
    #[test]
    fn an_unknown_extension_block_version_yields_no_times() {
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        let mut block = build_beef0004(8, "x");
        block[2..4].copy_from_slice(&99u16.to_le_bytes());
        block[8..12].copy_from_slice(&dos_pair(2021, 5, 5, 5, 5, 5));
        item.extend_from_slice(&block);
        let times = shell_item_times(&item);
        assert_eq!(times.created, None);
        assert_eq!(times.accessed, None);
    }
}

#[cfg(test)]
mod mft_reference_tests {
    use super::fixture::*;
    use super::*;

    /// `ROADMAP` §5.16. The MFT file reference is what ties a shell item back
    /// to the exact MFT record it named — the 48-bit entry index and the
    /// 16-bit sequence number packed into one little-endian `u64`
    /// (libfwsi's `ntfs_file_reference`, MS-FSCC 2.1.5.1). This is a
    /// known-answer test: the bytes are assembled by hand, not through
    /// `set_mft_reference`, so a bug in both the reader and the fixture
    /// helper cannot cancel out.
    #[test]
    fn the_48_bit_entry_and_16_bit_sequence_split_correctly() {
        for &ver in &[7u16, 8, 9] {
            let mut block = build_beef0004(ver, "x.txt");
            // Entry index near the top of the 48-bit range, sequence with
            // its own top bit set — chosen so a truncated shift or a wrong
            // mask would move a bit across the 48/16 boundary and get caught.
            let entry: u64 = 0x0000_FEDC_BA98_7654 & 0x0000_FFFF_FFFF_FFFF;
            let sequence: u16 = 0x8001;
            let packed = entry | ((sequence as u64) << 48);
            const FILE_REF_REL_OFFSET: usize = 20;
            block[FILE_REF_REL_OFFSET..FILE_REF_REL_OFFSET + 8]
                .copy_from_slice(&packed.to_le_bytes());

            let mut item = vec![0u8; 14];
            item[2] = 0x31; // file-entry type
            item.extend_from_slice(&block);

            let mft = beef0004_mft_reference(&item)
                .unwrap_or_else(|| panic!("v{ver}: no file reference read"));
            assert_eq!(mft.entry, entry, "version {ver}: entry index");
            assert_eq!(mft.sequence, sequence, "version {ver}: sequence number");
        }
    }

    /// Version 3 predates the file-reference field entirely (libfwsi); the
    /// bytes at the version-7-and-up offset are just whatever else that
    /// layout puts there, and reading them as a reference would fabricate one.
    #[test]
    fn a_version_3_block_has_no_file_reference() {
        let block = build_beef0004(3, "x.txt");
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        item.extend_from_slice(&block);
        assert_eq!(beef0004_mft_reference(&item), None);
    }

    /// The fixture helper a real test will actually reach for: build a block
    /// then stamp a reference onto it, rather than hand-packing bytes.
    #[test]
    fn the_fixture_helper_round_trips_a_reference() {
        for &ver in &[7u16, 8, 9] {
            let mut block = build_beef0004(ver, "y.txt");
            set_mft_reference(&mut block, 0x1234_5678_9ABC, 42);
            let mut item = vec![0u8; 14];
            item[2] = 0x31;
            item.extend_from_slice(&block);
            let mft = beef0004_mft_reference(&item).expect("a reference");
            assert_eq!(mft.entry, 0x1234_5678_9ABC, "version {ver}");
            assert_eq!(mft.sequence, 42, "version {ver}");
        }
    }

    #[test]
    fn a_shell_item_with_no_extension_block_has_no_file_reference() {
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        assert_eq!(beef0004_mft_reference(&item), None);
    }
}

#[cfg(test)]
mod parsed_shell_item_tests {
    use super::fixture::*;
    use super::*;

    /// A well-formed GUID folder item's GUID is read from its real,
    /// documented offset — that is genuine structure, not a placeholder —
    /// so it reports parsed.
    #[test]
    fn a_guid_folder_item_with_its_guid_present_reports_parsed_true() {
        let mut item = vec![0u8; 20];
        item[2] = 0x1F;
        // {B4BFCC3A-DB2C-424C-B029-7FE99A87C641} = Desktop, a known GUID.
        item[4..20].copy_from_slice(&[
            0x3A, 0xCC, 0xBF, 0xB4, 0x2C, 0xDB, 0x4C, 0x42, 0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87,
            0xC6, 0x41,
        ]);
        let detail = parse_shell_item_detail(&item);
        assert!(detail.parsed, "a full GUID folder item is real structure");
        assert_eq!(detail.name, "Desktop");
        assert_eq!(detail.raw, item, "raw bytes are always kept");
    }

    /// The same item type, truncated before the GUID field exists at all,
    /// falls back to a placeholder name — that is not a read of anything,
    /// so it must not claim to be parsed.
    #[test]
    fn a_truncated_guid_folder_item_reports_parsed_false() {
        let item = vec![0u8, 0, 0x1F]; // too short to hold the GUID
        let detail = parse_shell_item_detail(&item);
        assert!(!detail.parsed);
        assert_eq!(detail.name, "SystemFolder");
        assert_eq!(detail.raw, item, "bytes preserved even though unparsed");
    }

    /// A control-panel item has no field this reader decodes at all today —
    /// the name is a fixed word, not something read from the bytes — so it
    /// must keep reporting false, with the raw bytes still there for a later
    /// build to decode.
    #[test]
    fn a_control_panel_item_reports_parsed_false_with_bytes_preserved() {
        let item = vec![0xAAu8, 0xBB, 0x71, 0xCC, 0xDD, 0xEE];
        let detail = parse_shell_item_detail(&item);
        assert!(!detail.parsed);
        assert_eq!(detail.name, "ControlPanel");
        assert_eq!(
            detail.raw, item,
            "bytes this reader cannot interpret are never dropped"
        );
    }

    /// A type byte outside every known class is the clearest "cannot
    /// interpret this" case, and must say so per item, not as a blanket flag.
    #[test]
    fn an_unknown_type_byte_reports_parsed_false() {
        let item = vec![0u8, 0, 0xD9, 1, 2, 3];
        let detail = parse_shell_item_detail(&item);
        assert!(!detail.parsed);
        assert_eq!(detail.name, "UnknownType_0xD9");
        assert_eq!(detail.raw, item);
    }

    /// A file-entry item whose long name came from the `BEEF0004` block is
    /// real structure, and — being version 8 — also carries an MFT
    /// reference that the same call must surface.
    #[test]
    fn a_file_entry_item_with_a_long_name_reports_parsed_true_and_its_mft_reference() {
        let mut block = build_beef0004(8, "Quarterly.xlsx");
        set_mft_reference(&mut block, 0x0000_ABCD_EF01, 7);
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        item.extend_from_slice(&block);

        let detail = parse_shell_item_detail(&item);
        assert!(detail.parsed);
        assert_eq!(detail.name, "Quarterly.xlsx");
        let mft = detail.mft_reference.expect("a v8 block carries one");
        assert_eq!(mft.entry, 0x0000_ABCD_EF01);
        assert_eq!(mft.sequence, 7);
    }

    /// One ID list, items of differing classes: `shell_item_parsed` is a
    /// property of the ITEM, not of the list or the crate, so two items at
    /// different depths of the same walk must be able to disagree.
    #[test]
    fn shell_item_parsed_is_per_item_not_a_blanket_flag() {
        let mut list = Vec::new();

        let mut guid_item = vec![0u8; 20];
        guid_item[2] = 0x1F;
        guid_item[4..20].copy_from_slice(&[
            0x3A, 0xCC, 0xBF, 0xB4, 0x2C, 0xDB, 0x4C, 0x42, 0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87,
            0xC6, 0x41,
        ]);
        let guid_size = guid_item.len() as u16;
        guid_item[0..2].copy_from_slice(&guid_size.to_le_bytes());
        list.extend_from_slice(&guid_item);

        let mut control_panel_item = vec![0u8; 6];
        control_panel_item[2] = 0x71;
        let cp_size = control_panel_item.len() as u16;
        control_panel_item[0..2].copy_from_slice(&cp_size.to_le_bytes());
        list.extend_from_slice(&control_panel_item);

        list.extend_from_slice(&0u16.to_le_bytes()); // terminator

        let items = walk_id_list(&list);
        assert_eq!(items.len(), 2);
        let parsed: Vec<bool> = items
            .iter()
            .map(|i| parse_shell_item_detail(i).parsed)
            .collect();
        assert_eq!(
            parsed,
            vec![true, false],
            "the GUID folder item is read structurally, the control-panel item is not"
        );
    }

    /// `walk_id_list_detail` is `walk_id_list` plus `parse_shell_item_detail`
    /// per item — the shape a consumer needs to publish `shell_item_parsed`
    /// and the MFT reference alongside the path, in one call instead of
    /// writing the walk-then-map loop itself.
    #[test]
    fn walk_id_list_detail_decodes_every_item_and_keeps_the_mft_reference() {
        use fixture::{build_beef0004, set_mft_reference};

        let mut block = build_beef0004(7, "report.docx");
        set_mft_reference(&mut block, 0x1234, 7);
        let mut item = vec![0u8; 14];
        item[2] = 0x31; // file-entry type
        item.extend_from_slice(&block);
        let size = item.len() as u16;
        item[0..2].copy_from_slice(&size.to_le_bytes());

        let mut list = Vec::new();
        list.extend_from_slice(&item);
        list.extend_from_slice(&0u16.to_le_bytes()); // terminator

        let detail = walk_id_list_detail(&list);
        assert_eq!(detail.len(), 1);
        assert_eq!(detail[0].name, "report.docx");
        assert!(detail[0].parsed);
        let mft = detail[0]
            .mft_reference
            .expect("a version-7 BEEF0004 block carries an MFT reference");
        assert_eq!(mft.entry, 0x1234);
        assert_eq!(mft.sequence, 7);
    }
}

#[cfg(test)]
mod zero_file_reference_tests {
    use super::fixture::*;
    use super::*;

    /// A version-7+ block whose file-reference field is all zero is not a
    /// reference to MFT entry 0 (that is `$MFT` itself, sequence 0 is never
    /// issued): Windows writes zero when it has none. Every one of the 38
    /// `RecentDocs` `.lnk` items in plaso's `NTUSER-WIN7.DAT` carries such a
    /// field. Reading it as `Some(0, 0)` fabricated a reference two consumers
    /// then had to withhold or, in `seance_plugin_lnk`, published.
    #[test]
    fn an_all_zero_file_reference_field_is_reported_as_zero_not_as_a_reference() {
        for &ver in &[7u16, 8, 9] {
            let block = build_beef0004(ver, "z.txt");
            let mut item = vec![0u8; 14];
            item[2] = 0x31;
            item.extend_from_slice(&block);

            assert_eq!(beef0004_mft_reference(&item), None, "version {ver}");
            assert_eq!(
                beef0004_mft_reference_field(&item),
                MftReferenceField::Zero,
                "version {ver}"
            );
            let detail = parse_shell_item_detail(&item);
            assert_eq!(detail.mft_reference, None, "version {ver}");
            assert!(detail.mft_reference_zero, "version {ver}");
        }
    }

    /// The field being absent (no block, or a version-3 block) is a different
    /// fact from it being present and zero, and the two must not be confused:
    /// only the latter earns a "the field is zero" note.
    #[test]
    fn an_absent_field_is_absent_and_not_zero() {
        let block = build_beef0004(3, "z.txt");
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        item.extend_from_slice(&block);
        assert_eq!(
            beef0004_mft_reference_field(&item),
            MftReferenceField::Absent
        );
        assert!(!parse_shell_item_detail(&item).mft_reference_zero);

        let mut bare = vec![0u8; 14];
        bare[2] = 0x31;
        assert_eq!(
            beef0004_mft_reference_field(&bare),
            MftReferenceField::Absent
        );
        assert!(!parse_shell_item_detail(&bare).mft_reference_zero);
    }

    /// A real reference still comes through the same field reader.
    #[test]
    fn a_real_reference_is_present() {
        let mut block = build_beef0004(8, "z.txt");
        set_mft_reference(&mut block, 44518, 33);
        let mut item = vec![0u8; 14];
        item[2] = 0x31;
        item.extend_from_slice(&block);
        assert_eq!(
            beef0004_mft_reference_field(&item),
            MftReferenceField::Present(MftFileReference {
                entry: 44518,
                sequence: 33
            })
        );
        let detail = parse_shell_item_detail(&item);
        assert_eq!(
            detail.mft_reference,
            Some(MftFileReference {
                entry: 44518,
                sequence: 33
            })
        );
        assert!(!detail.mft_reference_zero);
    }
}

/// Items taken byte for byte out of plaso's
/// `reference/plaso/test_data/NTUSER-WIN7.DAT`, hand-decoded before the
/// assertions were written. Public for the same reason [`fixture`] is: the
/// consumers' tests pin the same bytes, and a copy each would drift.
pub mod real_items {
    fn hex(parts: &[&str]) -> Vec<u8> {
        let s: String = parts.concat();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `…\ComDlg32\OpenSavePidlMRU\exe` value `0` (byte-identical to `\*`
    /// value `0`): a 390-byte `REG_BINARY` at hive file offset 0x8a80c whose
    /// `vk` declares 0x186 bytes. Four items and a two-byte terminator:
    ///
    /// * 20 bytes, type `0x1F`, GUID `{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}`;
    /// * 183 bytes, type `0x00`, data size 177 (= 183 − 6) at offset 4,
    ///   signature `0x3B93AFBB` at offset 6, then property-store size 163 at
    ///   offset 10 holding three `1SPS` stores (69 + 45 + 45 + a 4-byte
    ///   terminator = 163) — the "users property view" item;
    /// * 51 bytes, type `0xC3`, `\\controller\WebDavShare` at offset 5;
    /// * 134 bytes, type `0x32`, `Firefox Setup 3.6.12.exe` at offset 14 and
    ///   a version-8 `BEEF0004` block (long-name offset 42, the file-reference
    ///   field at block offset 20 all zero, the long name at 42).
    ///
    /// plaso reads the same value as `<Computers and Devices> <Users property
    /// view>\\controller\WebDavShare\Firefox Setup 3.6.12.exe`
    /// (`tests/parsers/winreg_plugins/mrulistex.py`).
    pub fn open_save_pidl_mru_exe_0() -> Vec<u8> {
        let bytes = hex(&[
            "14001f580d1a2cf021be504388b07367fc96ef3cb7000000b100bbaf933ba3000400000000004500",
            "00003153505330f125b7ef471a10a5f102608c9eebac290000000a000000001f0000000b00000063",
            "006f006e00740072006f006c006c006500720000000000000000002d000000315350533aa4bddeb3",
            "37834391e74498da2995ab1100000003000000001300000000000000000000002d00000031535053",
            "7343e50abe43ad4f85e469dc8633986e110000000b000000000b000000ffff000000000000000000",
            "0000003300c301c15c5c636f6e74726f6c6c65725c5765624461765368617265004d6963726f736f",
            "6674204e6574776f726b00000200860032000000000000000000800046697265666f782053657475",
            "7020332e362e31322e65786500005e0008000400efbe00000000000000002a000000000000000000",
            "00000000000000000000000000000000460069007200650066006f00780020005300650074007500",
            "7000200033002e0036002e00310032002e00650078006500000028000000",
        ]);
        assert_eq!(bytes.len(), 390);
        bytes
    }

    /// The 183-byte users-property-view item on its own (bytes 20..203).
    pub fn users_property_view_item() -> Vec<u8> {
        open_save_pidl_mru_exe_0()[20..203].to_vec()
    }

    /// The ID list of `…\ComDlg32\LastVisitedPidlMRU` value `7` (152 bytes
    /// after the UTF-16 name `{48E1ED6B-CF49-4609-B1C1-C082BFC3D0B4}`, at
    /// hive file offset 0xe1392). Three items and a terminator:
    ///
    /// * 20 bytes, type `0x1F`, GUID `{59031A47-3F72-44A7-89C5-5595FE6B30EE}`;
    /// * 32 bytes, type `0x00`, signature `0x23FEBBEE` at offset 6 — a users
    ///   property view;
    /// * 98 bytes, type `0x31`, short name `ALLOYR~1` at offset 14, a
    ///   version-8 `BEEF0004` block with long name `Alloy Research` and the
    ///   file-reference bytes `e6 ad 00 00 00 00 21 00`: entry 0xADE6 =
    ///   44518, sequence 0x21 = 33.
    ///
    /// plaso reads it as `<Shared Documents Folder> <Users property
    /// view>\Alloy Research` with `file_reference: '44518-33'`.
    pub fn last_visited_pidl_mru_7() -> Vec<u8> {
        let bytes = hex(&[
            "14001f44471a0359723fa74489c55595fe6b30ee200000001a00eebbfe2300001000d09ad3fd8f23",
            "af46adb46c85480369c7000062003100000000006c4040a61000414c4c4f59527e3100004a000800",
            "0400efbe684001b26c4040a62a000000e6ad00000000210000000000000000000000000000004100",
            "6c006c006f007900200052006500730065006100720063006800000018000000",
        ]);
        assert_eq!(bytes.len(), 152);
        bytes
    }

    /// A 974-byte class-`0x00` item with signature `0x10141981` at offset 6
    /// (the third item of `LastVisitedPidlMRU` value `6`, hive file offset
    /// 0xd9b2a): a users property view carrying `1SPS` property stores.
    pub fn users_property_view_10141981_item() -> Vec<u8> {
        let bytes = hex(&[
            "ce0300009e0381191410740320000000006000000000000000000000000000000000000000000000",
            "0000000100008c0000003153505330f125b7ef471a10a5f102608c9eebac250000000a000000001f",
            "0000000900000053007400610072004600750072007900000000002900000004000000001f000000",
            "0c000000460069006c006500200066006f006c0064006500720000000d0000000c00000000010000",
            "00150000000e0000000040000000004090b59100cd01000000003100000031535053b1166d44ad8d",
            "7048a748402ea43d788c15000000640000000015000000e504624b09789a1e000000001401000031",
            "535053a66a63283d95d211b5d600c04fd918d0110000001900000000130000007f0180709d000000",
            "2000000000111000008c00000014001f44471a0359723fa74489c55595fe6b30ee200000001a00ee",
            "bbfe2300001000d09ad3fd8f23af46adb46c85480369c7000056003100000000006c4044a6100053",
            "7461724675727900003e0008000400efbe6c4044a66c4044a62a0000004e3b01000000bb00000000",
            "00000000000000000000005300740061007200460075007200790000001800000025000000180000",
            "00001f000000090000005300740061007200460075007200790000000000250000000b000000001f",
            "0000000a0000004400690072006500630074006f00720079000000000000002d0000003153505390",
            "1c6949177e1a10a91c08002b2ecda91100000003000000000300000000000000000000001c010000",
            "3153505340e83e1e2bbc6c4782372acd1a839b225500000008000000001f0000002200000043003a",
            "005c00550073006500720073005c006e0066007500720079005c0044006f00630075006d0065006e",
            "00740073005c005300740061007200460075007200790000002500000003000000001f1000000100",
            "00000700000066006f006c0064006500720000000000110000001400000000030000000100000075",
            "00000011000000001f000000310000007b00310036003800350044003400410042002d0041003500",
            "310042002d0034004100460031002d0041003400450035002d004300450045003800370030003000",
            "320034003300310044007d002e004d006500720067006500200041006e0079000000000000000000",
            "2900000031535053fcb3b4b9512b424ab5d8324146afcf250d000000080000000001000000000000",
            "002d00000031535053c0e85bcf6c23d34abacecd608a2748d71100000064000000000b000000ffff",
            "0000000000000000000000002a0000001900efbe40a7983f9c83f74a8c365badfb33d5fd8207ba82",
            "7a5b6945b5d7ec83085f08cca403",
        ]);
        assert_eq!(bytes.len(), 974);
        bytes
    }

    /// What the MRU reader used to walk: the same value with its first 24
    /// bytes taken as a UTF-16 "display name" (there is none — the value is a
    /// bare ID list), so the walk began 4 bytes into the second item, at
    /// `b1 00 bb af 93 3b …`, and read a 177-byte item of type `0xBB`.
    pub fn misaligned_tail() -> Vec<u8> {
        open_save_pidl_mru_exe_0()[24..].to_vec()
    }
}

#[cfg(test)]
mod real_item_tests {
    use super::real_items::*;
    use super::*;

    /// The value walks into its four items, each named from its own fields
    /// where this reader has them and by class where it does not.
    #[test]
    fn the_real_open_save_pidl_mru_value_walks_into_its_four_items() {
        let items = walk_id_list_detail(&open_save_pidl_mru_exe_0());
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "NetworkPlaces",
                "UsersPropertyView",
                "\\\\controller\\WebDavShare",
                "Firefox Setup 3.6.12.exe",
            ]
        );
        let parsed: Vec<bool> = items.iter().map(|i| i.parsed).collect();
        assert_eq!(parsed, [true, false, true, true]);
        let last = items.last().unwrap();
        assert_eq!(last.mft_reference, None);
        assert!(
            last.mft_reference_zero,
            "the v8 block's field is there and zero"
        );
    }

    /// A class-`0x00` item carrying one of the users-property-view
    /// signatures at offset 6 is not a root folder: named by class, its
    /// property stores not decoded, so `parsed` is false and the bytes stay.
    #[test]
    fn a_users_property_view_item_is_named_by_its_signature_and_not_decoded() {
        let sig_3b93afbb = users_property_view_item();
        let sig_23febbee = last_visited_pidl_mru_7()[20..52].to_vec();
        let sig_10141981 = users_property_view_10141981_item();
        for (item, sig) in [
            (sig_3b93afbb, [0xbb, 0xaf, 0x93, 0x3b]),
            (sig_23febbee, [0xee, 0xbb, 0xfe, 0x23]),
            (sig_10141981, [0x81, 0x19, 0x14, 0x10]),
        ] {
            assert_eq!(item[2], 0x00);
            assert_eq!(&item[6..10], &sig);
            let detail = parse_shell_item_detail(&item);
            assert_eq!(detail.name, "UsersPropertyView", "{sig:02x?}");
            assert!(!detail.parsed);
            assert_eq!(detail.mft_reference, None);
            assert!(!detail.mft_reference_zero);
            assert_eq!(detail.raw, item);
            assert_eq!(parse_shell_item(&item), "UsersPropertyView");
        }

        // A class-0x00 item with no such signature is still the root-folder
        // placeholder it always was.
        let mut root = vec![0u8; 12];
        root[0] = 12;
        assert_eq!(parse_shell_item_detail(&root).name, "ROOT");
    }

    /// `LastVisitedPidlMRU` value 7: the deepest item's file reference is
    /// the one plaso reads (`44518-33`), through the same walk.
    #[test]
    fn the_real_last_visited_value_7_walks_to_alloy_research_and_its_mft_reference() {
        let items = walk_id_list_detail(&last_visited_pidl_mru_7());
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["UsersFiles", "UsersPropertyView", "Alloy Research"]);
        let parsed: Vec<bool> = items.iter().map(|i| i.parsed).collect();
        assert_eq!(parsed, [true, false, true]);
        let last = items.last().unwrap();
        assert_eq!(
            last.mft_reference,
            Some(MftFileReference {
                entry: 44518,
                sequence: 33
            })
        );
        assert!(!last.mft_reference_zero);
    }

    /// A type byte in `0xB0..=0xBF` is not a file entry. The old
    /// `type & 0x70 == 0x30` class test said it was, and on this misaligned
    /// tail it read offset 14 (`45 00`) as the name `E` with `parsed: true`.
    /// No layout for that range is cited in this build, so it is reported
    /// unread, with no name, no time and no file reference taken from it.
    #[test]
    fn a_0xb0_to_0xbf_type_byte_is_not_read_as_a_file_entry() {
        let tail = misaligned_tail();
        assert_eq!(tail[2], 0xBB);
        let items = walk_id_list_detail(&tail);
        assert!(!items.is_empty());
        let first = &items[0];
        assert_eq!(first.name, "UnknownType_0xBB");
        assert!(!first.parsed);
        assert_eq!(first.mft_reference, None);
        assert!(!first.mft_reference_zero);
        assert_eq!(shell_item_mtime(&first.raw), None);
        assert_eq!(shell_item_times(&first.raw), ShellItemTimes::default());

        for t in 0xB0u8..=0xBF {
            let mut item = vec![0u8; 40];
            item[0] = 40;
            item[2] = t;
            item[14..17].copy_from_slice(b"E\0\0");
            let detail = parse_shell_item_detail(&item);
            assert!(!detail.parsed, "type 0x{t:02X}");
            assert_eq!(detail.name, format!("UnknownType_0x{t:02X}"));
        }
    }
}
