//! Startup folders: anything sitting in one runs at logon.
//!
//! Windows executes every item in the per-user and all-users Startup folders
//! when a user logs on. Usually those items are `.lnk` shortcuts, so the thing
//! that actually runs is the shortcut's *target*, not the shortcut — a report
//! that named the `.lnk` would point the examiner at a 1 KB stub instead of the
//! program. The shortcut is therefore resolved here, from its own bytes, with
//! every field read through bounds-checked accessors.
//!
//! Items that are not shortcuts are reported too. A batch file or an executable
//! dropped straight into a Startup folder runs exactly the same way, and
//! filtering on `.lnk` would omit it.
//!
//! A shortcut that will not parse still produces an entry, marked unread. The
//! fact that *something* in the Startup folder runs at logon is established by
//! the file's location alone; only the target is in doubt.

use crate::normalize::basename;
use crate::record::{AsepEntry, InstalledTime, LocationKind, ReadStatus};
use serde_json::json;
use thiserror::Error;

/// The path fragment every Startup folder shares.
const STARTUP_FRAGMENT: &str = "/start menu/programs/startup/";

/// Ceiling on a shortcut read into memory. Real shortcuts are kilobytes.
pub const MAX_LNK_BYTES: u64 = 4 * 1024 * 1024;

/// Which Startup folder a file sits in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupLocation {
    /// The profile whose Startup folder this is, when the path names one.
    pub user: Option<String>,
    /// True for the all-users (`ProgramData` / `All Users`) Startup folder.
    pub all_users: bool,
}

/// Classify a path as a Startup-folder item. `normalized` must already have
/// been through [`crate::normalize::normalize_evidence_path`].
///
/// Returns `None` for anything not under a Startup folder. The match is on the
/// canonical English path fragment; a machine with localised shell folder names
/// or a redirected Startup folder will not match here, which is why the
/// `startup_folder_redirect` registry category reports the folder Windows was
/// actually told to read — a localised or moved Startup folder is visible there
/// even when this check cannot see its contents.
pub fn classify_startup_path(normalized: &str) -> Option<StartupLocation> {
    if !normalized.contains(STARTUP_FRAGMENT) {
        return None;
    }
    let all_users = normalized.contains("/programdata/")
        || normalized.contains("/all users/")
        || normalized.contains("/documents and settings/all users/");
    let user = if all_users {
        None
    } else {
        segment_after(normalized, "/users/")
            .or_else(|| segment_after(normalized, "/documents and settings/"))
    };
    Some(StartupLocation { user, all_users })
}

fn segment_after(path: &str, marker: &str) -> Option<String> {
    let pos = path.find(marker)?;
    let start = pos.checked_add(marker.len())?;
    let rest = path.get(start..)?;
    let seg = match rest.find('/') {
        Some(end) => rest.get(..end)?,
        None => rest,
    };
    if seg.is_empty() {
        None
    } else {
        Some(seg.to_string())
    }
}

/// Why a shortcut could not be resolved.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LnkError {
    /// Fewer bytes than a shell link header.
    #[error("shortcut is shorter than the 76-byte shell link header")]
    TooShort,
    /// The header size or link CLSID is not a shell link's.
    #[error("shortcut header did not validate (header size {size}, signature 0x{signature:08X})")]
    BadHeader {
        /// The header size the file claims.
        size: u32,
        /// The first four bytes of the link CLSID.
        signature: u32,
    },
    /// A structure ran past the end of the file.
    #[error("shortcut structure ran past the end of the file while reading {0}")]
    Truncated(&'static str),
    /// The shortcut's bytes were not available to read.
    #[error("the shortcut's content was not available to this module")]
    ContentUnavailable,
}

/// What a shortcut points at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LnkTarget {
    /// The resolved local target path, when the shortcut carries one.
    pub target: Option<String>,
    /// Command-line arguments passed to the target.
    pub arguments: Option<String>,
    /// The working directory the shortcut sets.
    pub working_dir: Option<String>,
    /// The relative path, kept as a fallback when there is no local base path.
    pub relative_path: Option<String>,
}

/// Read the target out of a shell link.
///
/// Every field is read through `get`, so a truncated or hostile shortcut
/// produces an error rather than a panic or a value read from the wrong offset.
pub fn parse_lnk(buf: &[u8]) -> Result<LnkTarget, LnkError> {
    if buf.len() < 76 {
        return Err(LnkError::TooShort);
    }
    let header_size = read_u32(buf, 0).ok_or(LnkError::Truncated("the header size"))?;
    let signature = read_u32(buf, 4).ok_or(LnkError::Truncated("the link CLSID"))?;
    if header_size != 76 || signature != 0x0002_1401 {
        return Err(LnkError::BadHeader {
            size: header_size,
            signature,
        });
    }
    let flags = read_u32(buf, 20).ok_or(LnkError::Truncated("the link flags"))?;
    let has_id_list = flags & 0x01 != 0;
    let has_link_info = flags & 0x02 != 0;
    let has_name = flags & 0x04 != 0;
    let has_relative = flags & 0x08 != 0;
    let has_working_dir = flags & 0x10 != 0;
    let has_arguments = flags & 0x20 != 0;
    let has_icon = flags & 0x40 != 0;
    let is_unicode = flags & 0x80 != 0;

    let mut out = LnkTarget::default();
    let mut cursor: usize = 76;

    if has_id_list {
        let size = read_u16(buf, cursor).ok_or(LnkError::Truncated("the target ID list size"))?;
        cursor = cursor
            .checked_add(2)
            .and_then(|c| c.checked_add(size as usize))
            .ok_or(LnkError::Truncated("the target ID list"))?;
        if cursor > buf.len() {
            return Err(LnkError::Truncated("the target ID list"));
        }
    }

    if has_link_info {
        let info_start = cursor;
        let info_size =
            read_u32(buf, info_start).ok_or(LnkError::Truncated("the link info size"))? as usize;
        let info_header_size = read_u32(buf, info_start.saturating_add(4))
            .ok_or(LnkError::Truncated("the link info header size"))?
            as usize;
        let info_flags = read_u32(buf, info_start.saturating_add(8))
            .ok_or(LnkError::Truncated("the link info flags"))?;

        if info_flags & 0x01 != 0 {
            let (base_field, suffix_field) = if info_header_size >= 0x24 {
                (0x1Cusize, 0x20usize)
            } else {
                (0x10usize, 0x18usize)
            };
            let unicode = info_header_size >= 0x24;
            let base_offset = read_u32(buf, info_start.saturating_add(base_field));
            let suffix_offset = read_u32(buf, info_start.saturating_add(suffix_field));
            let base = base_offset.and_then(|off| {
                read_string_at(buf, info_start.checked_add(off as usize)?, unicode)
            });
            let suffix = suffix_offset.and_then(|off| {
                read_string_at(buf, info_start.checked_add(off as usize)?, unicode)
            });
            let combined = match (base, suffix) {
                (Some(b), Some(s)) if !s.is_empty() => Some(format!("{b}{s}")),
                (Some(b), _) => Some(b),
                (None, _) => None,
            };
            out.target = combined.filter(|s| !s.is_empty());
        }

        cursor = info_start
            .checked_add(info_size.max(1))
            .ok_or(LnkError::Truncated("the link info block"))?;
        if cursor > buf.len() {
            return Err(LnkError::Truncated("the link info block"));
        }
    }

    // String data, in the fixed order the shell link format defines. Each is
    // skipped even when its value is not wanted, or every later string would be
    // read from the wrong offset.
    for (present, slot) in [
        (has_name, 0u8),
        (has_relative, 1),
        (has_working_dir, 2),
        (has_arguments, 3),
        (has_icon, 4),
    ] {
        if !present {
            continue;
        }
        let count =
            read_u16(buf, cursor).ok_or(LnkError::Truncated("a string data length"))? as usize;
        let bytes = if is_unicode {
            count.checked_mul(2)
        } else {
            Some(count)
        }
        .ok_or(LnkError::Truncated("a string data length"))?;
        let start = cursor
            .checked_add(2)
            .ok_or(LnkError::Truncated("a string data block"))?;
        let end = start
            .checked_add(bytes)
            .ok_or(LnkError::Truncated("a string data block"))?;
        let slice = buf
            .get(start..end)
            .ok_or(LnkError::Truncated("a string data block"))?;
        let text = if is_unicode {
            seance_core::codepage::decode_utf16le(slice)
        } else {
            decode_ansi(slice)
        };
        match slot {
            1 => out.relative_path = non_empty(text),
            2 => out.working_dir = non_empty(text),
            3 => out.arguments = non_empty(text),
            _ => {}
        }
        cursor = end;
    }

    Ok(out)
}

fn non_empty(s: String) -> Option<String> {
    let t = s.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let slice = buf.get(at..end)?;
    Some(u16::from_le_bytes([*slice.first()?, *slice.get(1)?]))
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let slice = buf.get(at..end)?;
    Some(u32::from_le_bytes([
        *slice.first()?,
        *slice.get(1)?,
        *slice.get(2)?,
        *slice.get(3)?,
    ]))
}

/// Read a NUL-terminated string at `at`, in the encoding the link info header
/// implies. Returns `None` when the offset is past the end of the file.
fn read_string_at(buf: &[u8], at: usize, unicode: bool) -> Option<String> {
    let rest = buf.get(at..)?;
    if unicode {
        let mut units = Vec::new();
        for chunk in rest.as_chunks::<2>().0.iter() {
            let unit = u16::from_le_bytes([*chunk.first()?, *chunk.get(1)?]);
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        Some(String::from_utf16_lossy(&units))
    } else {
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        Some(decode_ansi(rest.get(..end)?))
    }
}

/// Decode a single-byte string. Bytes above 0x7F are mapped through Latin-1
/// rather than dropped, so a path with accented characters is still legible and
/// is never silently shortened.
fn decode_ansi(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect()
}

/// Build the entry for a Startup-folder item.
///
/// `created` is the file's own creation time as recorded on the file entry,
/// which is when the item was placed in the Startup folder — the closest thing
/// to an install time this ASEP has. It is passed through only when the file
/// entry actually carried one.
pub fn startup_entry(
    path: &str,
    file_name: &str,
    location: &StartupLocation,
    shortcut: Option<Result<LnkTarget, LnkError>>,
    created: Option<String>,
) -> AsepEntry {
    let mut entry = AsepEntry::new(
        "startup_folder",
        if file_name.is_empty() {
            basename(path)
        } else {
            file_name
        },
        path,
        LocationKind::File,
    );
    entry.scope = "filesystem".to_string();
    entry.user = location.user.clone();
    entry.enabled = Some(true);
    entry.enabled_basis =
        "The file is present in a Startup folder; Windows runs everything in that folder \
         at logon."
            .to_string();
    entry.put("startup_all_users", json!(location.all_users));

    let who = if location.all_users {
        "when any user logs on".to_string()
    } else {
        match location.user.as_deref() {
            Some(user) => format!("when {user} logs on"),
            None => "when the owner of this profile logs on".to_string(),
        }
    };

    match shortcut {
        Some(Ok(target)) => {
            entry.put("startup_item_kind", json!("shortcut"));
            let resolved = target
                .target
                .clone()
                .or_else(|| target.relative_path.clone());
            entry.image = resolved.clone();
            entry.arguments = target.arguments.clone();
            entry.working_dir = target.working_dir.clone();
            entry.command = match (resolved.as_deref(), target.arguments.as_deref()) {
                (Some(t), Some(a)) => Some(format!("{t} {a}")),
                (Some(t), None) => Some(t.to_string()),
                _ => None,
            };
            entry.put("shortcut_relative_path", json!(target.relative_path));
            entry.runs_when = match resolved.as_deref() {
                Some(t) => format!("Runs {t} {who}, from a shortcut in the Startup folder."),
                None => format!(
                    "Runs {who}: this shortcut is in the Startup folder, but it records no \
                     target path, so what it launches could not be established."
                ),
            };
            if resolved.is_none() {
                entry.read_status = ReadStatus::Unread(
                    "The shortcut parsed but carries neither a local base path nor a \
                     relative path, so its target is not recorded in the file."
                        .to_string(),
                );
                entry.observe(
                    "shortcut_target_absent",
                    "The shortcut resolves its target through a shell item ID list this \
                     build does not decode, so the target path is not stated here.",
                );
            }
        }
        Some(Err(err)) => {
            entry.put("startup_item_kind", json!("shortcut"));
            entry.runs_when = format!(
                "Runs {who}: a shortcut in the Startup folder that could not be read, so \
                 what it launches is unknown."
            );
            entry.read_status = ReadStatus::Unread(format!(
                "The shortcut could not be parsed: {err}. The item is still in the Startup \
                 folder and still runs at logon; only its target is unknown."
            ));
        }
        None => {
            entry.put("startup_item_kind", json!("file"));
            entry.image = Some(path.to_string());
            entry.command = Some(path.to_string());
            entry.runs_when = format!(
                "Runs {who}: this file is in the Startup folder, and Windows launches every \
                 item in that folder at logon."
            );
        }
    }

    match created {
        Some(ts) => {
            entry.installed_time = Some(InstalledTime {
                value: ts,
                source: "startup_item_file_created",
                timezone: None,
            });
        }
        None => {
            entry.installed_time_unavailable_reason = Some(
                "The file entry for this Startup item carries no creation time, so when it \
                 was placed in the Startup folder is not recorded here.",
            );
        }
    }

    entry
}
