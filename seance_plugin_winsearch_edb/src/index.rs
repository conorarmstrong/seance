//! Walking the Search index's property table.
//!
//! Two layouts are read, both measured on real files:
//!
//! - **Windows 7, `SystemIndex_0A`** (NIST CFReDS Data Leakage): one column
//!   per property, named for it (`System_ItemPathDisplay`), the row key
//!   `DocID`. Times and sizes are 8-byte binary values in **big-endian** order.
//! - **Windows 10, `SystemIndex_PropertyStore`** (LoneWolf, 1709): the same
//!   properties, each column name prefixed with a number and a dash
//!   (`4428-System_ItemPathDisplay`, `15F-System_DateModified`), the row key
//!   `WorkID`. Times and sizes are 8-byte values in **little-endian** order.
//!
//! The byte order is taken from the layout, not guessed per value; a value
//! that does not land between 1980 and 2100 is reported raw with that said.
//! On both files, eight bytes of `0x2A` stand where a size is not set (every
//! folder), and a 32-bit `0x2A2A2A2A` where attributes are not; both are
//! reported as not set, never as a number.

use crate::compression::{decode_text, Decoded};
use libesedb::{EseDb, Record, Table, Value};
use seance_ese_util::{get_column_names, WalkStatus};
use serde_json::{json, Map, Value as Json};
use std::path::Path;

/// Rows read per index; more are reported as a cut, never silently dropped.
pub const MAX_ROWS: usize = 2_000_000;

/// Which property-table layout a database carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Windows7SystemIndex0A,
    Windows10PropertyStore,
}

impl Layout {
    pub fn name(self) -> &'static str {
        match self {
            Layout::Windows7SystemIndex0A => "windows7_systemindex_0a",
            Layout::Windows10PropertyStore => "windows10_propertystore",
        }
    }
    fn table(self) -> &'static str {
        match self {
            Layout::Windows7SystemIndex0A => "SystemIndex_0A",
            Layout::Windows10PropertyStore => "SystemIndex_PropertyStore",
        }
    }
    fn big_endian(self) -> bool {
        self == Layout::Windows7SystemIndex0A
    }
}

/// How a property's value is read.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Time,
    Size,
    Attributes,
    Plain,
}

/// The properties read, and how. Anything else in the table is not read.
const PROPERTIES: &[(&str, Kind)] = &[
    ("System_ItemPathDisplay", Kind::Text),
    ("System_ItemUrl", Kind::Text),
    ("System_ItemName", Kind::Text),
    ("System_ItemNameDisplay", Kind::Text),
    ("System_ItemFolderPathDisplay", Kind::Text),
    ("System_FileName", Kind::Text),
    ("System_FileExtension", Kind::Text),
    ("System_ItemType", Kind::Text),
    ("System_ItemTypeText", Kind::Text),
    ("System_KindText", Kind::Text),
    ("System_MIMEType", Kind::Text),
    ("System_Size", Kind::Size),
    ("System_FileAttributes", Kind::Attributes),
    ("System_DateModified", Kind::Time),
    ("System_DateCreated", Kind::Time),
    ("System_DateAccessed", Kind::Time),
    ("System_DateImported", Kind::Time),
    ("System_ItemDate", Kind::Time),
    ("System_Search_GatherTime", Kind::Time),
    ("System_FileOwner", Kind::Text),
    ("System_ComputerName", Kind::Text),
    ("System_IsFolder", Kind::Plain),
    ("System_IsDeleted", Kind::Plain),
    ("System_IsAttachment", Kind::Plain),
    ("System_Search_Store", Kind::Text),
    ("System_Link_TargetParsingPath", Kind::Text),
    ("System_Link_TargetUrl", Kind::Text),
    ("Microsoft_IE_TargetUrl", Kind::Text),
    ("Microsoft_IE_Title", Kind::Text),
    ("Microsoft_IE_VisitCount", Kind::Plain),
    ("System_Title", Kind::Text),
    ("System_Subject", Kind::Text),
    ("System_Author", Kind::Text),
    ("System_Communication_AccountName", Kind::Text),
    ("System_Message_FromName", Kind::Text),
    ("System_Message_FromAddress", Kind::Text),
    ("System_Message_ToName", Kind::Text),
    ("System_Message_ToAddress", Kind::Text),
    ("System_Message_SenderName", Kind::Text),
    ("System_Message_SenderAddress", Kind::Text),
    ("System_Message_DateSent", Kind::Time),
    ("System_Message_DateReceived", Kind::Time),
    ("System_Message_HasAttachments", Kind::Plain),
    ("System_Message_AttachmentNames", Kind::Text),
    ("System_IsRead", Kind::Plain),
    ("System_Search_AutoSummary", Kind::Text),
];

/// A column name with any `NNNN-` / `NNF-` prefix removed.
pub fn property_name(column: &str) -> &str {
    match column.split_once('-') {
        Some((prefix, rest))
            if !prefix.is_empty()
                && prefix
                    .trim_end_matches('F')
                    .bytes()
                    .all(|b| b.is_ascii_digit()) =>
        {
            rest
        }
        _ => column,
    }
}

/// One indexed item.
#[derive(Debug, Clone, Default)]
pub struct Item {
    pub id: Option<u64>,
    pub properties: Map<String, Json>,
    /// Properties present on the row that were not decoded, with why.
    pub not_decoded: Vec<(String, String)>,
}

/// The walk's result.
#[derive(Debug, Clone)]
pub struct Index {
    pub layout: Layout,
    pub db_state: Option<u32>,
    pub items: Vec<Item>,
    pub walk: WalkStatus,
    pub cut_at_cap: bool,
    /// The error libesedb gave when it first failed to count the table's
    /// rows; the walk then used the count of what it could reach, a floor.
    pub tree_error: Option<String>,
}

/// A FILETIME as RFC 3339, when it lands between 1980 and 2100.
pub fn filetime_rfc3339(ft: u64) -> Option<String> {
    const LO: u64 = 0x01A8_E79F_E1D5_8000; // 1980-01-01
    const HI: u64 = 0x0245_0000_0000_0000; // after 2100
    if !(LO..HI).contains(&ft) {
        return None;
    }
    let since = ft - 116_444_736_000_000_000;
    let secs = (since / 10_000_000) as i64;
    let nanos = ((since % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
}

fn u64_of(b: &[u8], big: bool) -> Option<u64> {
    let a: [u8; 8] = b.try_into().ok()?;
    Some(if big {
        u64::from_be_bytes(a)
    } else {
        u64::from_le_bytes(a)
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn utf16le(b: &[u8]) -> Option<String> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units)
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
}

/// Scalar values as JSON; `None` for binary and text forms.
fn plain(v: &Value) -> Option<Json> {
    Some(match v {
        Value::Bool(b) => json!(b),
        Value::U8(n) => json!(n),
        Value::I16(n) => json!(n),
        Value::U16(n) => json!(n),
        Value::I32(n) => json!(n),
        Value::U32(n) => json!(n),
        Value::I64(n) => json!(n),
        Value::Currency(n) => json!(n),
        Value::F32(n) => json!(n),
        Value::F64(n) => json!(n),
        _ => return None,
    })
}

/// One property's value: `Ok(Some)` decoded, `Ok(None)` absent/not set,
/// `Err(reason)` present but not decoded.
fn read_property(
    record: &Record,
    col: i32,
    kind: Kind,
    layout: Layout,
) -> Result<Option<Json>, String> {
    let value = match record.value(col) {
        Ok(v) => v,
        Err(_) => return Err("libesedb could not read the value".into()),
    };
    let big = layout.big_endian();
    match (&value, kind) {
        (Value::Null(()), _) => Ok(None),
        (Value::Multi, _) => {
            let mv = record
                .multi(col)
                .map_err(|_| "a multi-valued value libesedb could not open".to_string())?;
            let vals = mv
                .iter_values()
                .map_err(|_| "a multi-valued value libesedb could not walk".to_string())?;
            let mut parts = Vec::new();
            for v in vals {
                match v {
                    Ok(Value::Text(s)) | Ok(Value::LargeText(s)) => parts.push(json!(s)),
                    Ok(other) => match plain(&other) {
                        Some(j) => parts.push(j),
                        None => {
                            return Err(
                                "a multi-valued value with a binary member, not decoded".into()
                            )
                        }
                    },
                    Err(_) => return Err("a multi-valued member libesedb could not read".into()),
                }
            }
            Ok(Some(Json::Array(parts)))
        }
        (Value::Long, _) => {
            let lv = record
                .long(col)
                .map_err(|_| "a long value libesedb could not open".to_string())?;
            let bytes = lv
                .vec()
                .map_err(|_| "a long value libesedb could not read".to_string())?;
            match kind {
                Kind::Text => utf16le(&bytes)
                    .map(|s| Some(json!(s)))
                    .ok_or_else(|| "a long value that is not UTF-16 text, not decoded".into()),
                _ => Err("a long value where a scalar was expected, not decoded".into()),
            }
        }
        (Value::Text(s) | Value::LargeText(s), _) => Ok(Some(json!(s))),
        (Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b), Kind::Time) => {
            let Some(ft) = u64_of(b, big) else {
                return Err(format!("a {}-byte time value, not decoded", b.len()));
            };
            if ft == 0 {
                return Ok(None);
            }
            match filetime_rfc3339(ft) {
                Some(t) => Ok(Some(json!(t))),
                None => Err(format!(
                    "0x{} does not read as a time between 1980 and 2100 in this layout's byte order",
                    hex(b)
                )),
            }
        }
        (Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b), Kind::Size) => {
            if b.iter().all(|&x| x == 0x2A) {
                return Ok(None);
            }
            u64_of(b, big)
                .map(|n| Some(json!(n)))
                .ok_or_else(|| format!("a {}-byte size value, not decoded", b.len()))
        }
        (Value::U32(0x2A2A_2A2A), Kind::Attributes) => Ok(None),
        (Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b), Kind::Text) => {
            if layout == Layout::Windows7SystemIndex0A {
                match decode_text(b) {
                    Decoded::Text(t) => Ok(Some(json!(t))),
                    Decoded::NotDecoded { type_byte, reason } => {
                        Err(format!("encoding type {type_byte}: {reason}"))
                    }
                }
            } else {
                utf16le(b)
                    .filter(|s| {
                        !s.chars()
                            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
                    })
                    .map(|s| Some(json!(s)))
                    .ok_or_else(|| "a binary value that is not UTF-16 text, not decoded".into())
            }
        }
        (Value::DateTime(ft), Kind::Time) => Ok(filetime_rfc3339(*ft).map(|t| json!(t))),
        (Value::Guid(b), _) => Ok(Some(json!(hex(b)))),
        (other, _) => match plain(other) {
            Some(j) => Ok(Some(j)),
            None => Err("a value of an unexpected type, not decoded".into()),
        },
    }
}

fn row_id(record: &Record, col: Option<i32>) -> Option<u64> {
    let v = record.value(col?).ok()?;
    match v {
        Value::I32(n) => u64::try_from(n).ok(),
        Value::U32(n) => Some(n as u64),
        Value::I64(n) => u64::try_from(n).ok(),
        _ => None,
    }
}

fn walk_table(table: &Table, layout: Layout) -> (Vec<Item>, WalkStatus, bool, Option<String>) {
    let mut status = WalkStatus::default();
    let Ok(cols) = get_column_names(table) else {
        return (Vec::new(), WalkStatus::unreadable("columns"), false, None);
    };
    let id_col = cols
        .iter()
        .position(|c| c == "DocID" || c == "WorkID")
        .map(|i| i as i32);
    let wanted: Vec<(i32, &'static str, Kind)> = PROPERTIES
        .iter()
        .filter_map(|&(name, kind)| {
            cols.iter()
                .position(|c| property_name(c) == name)
                .map(|i| (i as i32, name, kind))
        })
        .collect();
    // libesedb counts leaf values by walking the table's page tree. On a
    // dirty or sparse database that walk can meet a page that is not a leaf
    // and fail; a second call then succeeds with the count of what it could
    // reach. That second count is a floor, and the failure is kept to say so.
    let (count, tree_error) = match table.count_records() {
        Ok(n) => (n, None),
        Err(first) => match table.count_records() {
            Ok(n) => (n, Some(first.to_string())),
            Err(_) => return (Vec::new(), WalkStatus::unreadable("records"), false, None),
        },
    };
    let mut items = Vec::new();
    let mut cut = false;
    for i in 0..count.max(0) {
        if items.len() >= MAX_ROWS {
            cut = true;
            break;
        }
        let Ok(rec) = table.record(i) else {
            status.rows_skipped += 1;
            continue;
        };
        let mut item = Item {
            id: row_id(&rec, id_col),
            ..Default::default()
        };
        for &(col, name, kind) in &wanted {
            match read_property(&rec, col, kind, layout) {
                Ok(Some(v)) => {
                    item.properties.insert(name.to_string(), v);
                }
                Ok(None) => {}
                Err(why) => item.not_decoded.push((name.to_string(), why)),
            }
        }
        items.push(item);
    }
    (items, status, cut, tree_error)
}

/// Read `db_path` when it carries a Search property table; `Ok(None)` for any
/// other ESE database.
pub fn read_index(db_path: &Path, bytes: &[u8]) -> Result<Option<Index>, String> {
    let db = EseDb::open(db_path).map_err(|e| format!("the ESE database would not open: {e}"))?;
    for layout in [
        Layout::Windows10PropertyStore,
        Layout::Windows7SystemIndex0A,
    ] {
        let Ok(table) = db.table_by_name(layout.table()) else {
            continue;
        };
        let Ok(cols) = get_column_names(&table) else {
            continue;
        };
        // The table must carry the path property to be the index's.
        if !cols
            .iter()
            .any(|c| property_name(c) == "System_ItemPathDisplay")
        {
            continue;
        }
        let (items, walk, cut_at_cap, tree_error) = walk_table(&table, layout);
        let db_state = bytes
            .get(52..56)
            .map(|s| u32::from_le_bytes(s.try_into().expect("4 bytes")));
        return Ok(Some(Index {
            layout,
            db_state,
            items,
            walk,
            cut_at_cap,
            tree_error,
        }));
    }
    Ok(None)
}
