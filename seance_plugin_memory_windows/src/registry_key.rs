//! Registry cells: key nodes, subkey indexes and values, decoded out of a
//! [`HiveSpace`].
//!
//! Every structure here is a *cell*: a length-prefixed allocation inside a hive
//! bin, identified by a cell index rather than by an address. What this module
//! adds on top of [`crate::registry::space`] is the meaning of the bytes at
//! that index — which two ASCII letters say what kind of cell it is, how a key
//! reaches its subkeys through as many as four different index formats, and how
//! a value's data is stored in one of three completely different ways depending
//! on how big it is.
//!
//! # The three places a value's data can be
//!
//! Getting this wrong is the single easiest way to publish a confident wrong
//! answer about a registry value:
//!
//! | Condition | Where the bytes are |
//! |---|---|
//! | High bit of `DataLength` set | **Inside the cell**, in the four bytes of `Data` itself |
//! | Length over 16 KiB and the target cell is a `db` record | Split across **big-data blocks** |
//! | Otherwise | In the cell `Data` names |
//!
//! The inline case is the dangerous one. `Data` there is not a cell index at
//! all — it is the data — and reading it as an index sends the translator after
//! an arbitrary 32-bit number. Upstream checks the bit; so does this, and it
//! refuses an inline length above four rather than truncating it.
//!
//! # Names are not always the same encoding
//!
//! A key or value name is UTF-16LE *unless* the compressed-name flag is set, in
//! which case it is one byte per character. `NameLength` is a count of **bytes**
//! either way. Upstream decodes every name as Latin-1 regardless, which renders
//! a non-compressed name as `T\0e\0s\0t\0`; this branches on the flag, because a
//! key name is often the whole finding.

// These test modules assert relationships between *compile-time constants* --
// MAX_SUBKEYS > MAX_INDEX_CELLS, MIN_CREATE_FILETIME < MAX_CREATE_FILETIME, a
// stage's declared record type. Clippy sees both sides are const and calls the
// assertion constant; that is exactly the point. They exist so that changing
// one bound in isolation fails, and deleting them would remove the guard rather
// than satisfy it.
#![allow(clippy::assertions_on_constants)]

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::meta::Incomplete;
use seance_memory::object::{Obj, StructReader};

use crate::registry::error::{render_signature, RegistryError};
use crate::registry::space::{
    array_shape, member_type, unsigned_member, CellIndex, HiveSpace, Store, MAX_CELL_READ,
};

/// `_CM_KEY_NODE.Flags`: the key exists only in volatile storage.
pub const KEY_IS_VOLATILE: u64 = 0x0001;
/// `_CM_KEY_NODE.Flags`: the key is the mount point of another hive.
pub const KEY_HIVE_EXIT: u64 = 0x0002;
/// `_CM_KEY_NODE.Flags`: the key is this hive's root.
pub const KEY_HIVE_ENTRY: u64 = 0x0004;
/// `_CM_KEY_NODE.Flags`: the key cannot be deleted.
pub const KEY_NO_DELETE: u64 = 0x0008;
/// `_CM_KEY_NODE.Flags`: the key is a symbolic link to another key.
pub const KEY_SYM_LINK: u64 = 0x0010;
/// `_CM_KEY_NODE.Flags`: the name is one byte per character, not UTF-16.
pub const KEY_COMP_NAME: u64 = 0x0020;
/// `_CM_KEY_VALUE.Flags`: the name is one byte per character, not UTF-16.
pub const VALUE_COMP_NAME: u64 = 0x0001;

/// The bit of `_CM_KEY_VALUE.DataLength` that means "the data is in `Data`".
pub const VALUE_DATA_INLINE: u64 = 0x8000_0000;

/// Largest number of bytes one big-data block holds.
///
/// A property of the format: a block is one cell in a bin, and the format
/// reserves the rest of the 16 KiB page for the cell header and alignment.
pub const BIG_DATA_BLOCK: u64 = 0x3FD8;

/// The declared data length above which a value may be a big-data record.
pub const BIG_DATA_THRESHOLD: u64 = 0x4000;

/// Ceiling on the subkeys one key will report.
///
/// Far above any real key — the largest keys on a Windows system have a few
/// tens of thousands of subkeys — so reaching it means the index cells are
/// corrupt rather than that the key is big. Reported as a cap, never as the end.
pub const MAX_SUBKEYS: usize = 65_536;

/// Ceiling on the index cells one subkey enumeration will visit.
///
/// Counted over `lf`/`lh`/`li`/`ri` cells **only**. Key nodes are not index
/// cells and are bounded by [`MAX_SUBKEYS`] instead: counting them here would
/// stop a perfectly ordinary `Software\Classes` — which routinely holds several
/// thousand subkeys — a few thousand keys short of its real contents.
pub const MAX_INDEX_CELLS: usize = 4_096;

/// Ceiling on the list entries one subkey enumeration will read, across every
/// index cell it visits.
///
/// `_CM_KEY_INDEX.Count` is a sixteen-bit field read out of the image, so a
/// corrupt index cell can declare 65,535 entries; without a budget spanning the
/// whole walk, [`MAX_INDEX_CELLS`] corrupt cells would mean a quarter of a
/// billion hive reads and a queue of the same size. Twice [`MAX_SUBKEYS`] is far
/// above any real key and bounds both.
pub const MAX_INDEX_ENTRIES: usize = 131_072;

/// Ceiling on how deeply subkey indexes may nest.
///
/// The format nests at most twice: an `ri` root of `lf`/`lh` leaves. Anything
/// deeper is a chain that does not terminate.
pub const MAX_INDEX_DEPTH: u32 = 8;

/// Ceiling on the values one key will report.
pub const MAX_VALUES: usize = 65_536;

/// Ceiling on the blocks one big-data value is assembled from.
pub const MAX_BIG_DATA_BLOCKS: u64 = 4_096;

/// The two-byte signature at the start of a registry cell.
///
/// The format's own tag for what a cell is. Dispatching on it rather than on
/// what the referring structure claimed is what keeps a corrupt subkey list
/// from being read as a list of key nodes that are really something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellKind {
    /// `nk` — a key.
    KeyNode,
    /// `vk` — a value.
    KeyValue,
    /// `sk` — a security descriptor.
    KeySecurity,
    /// `db` — a big-data record: a list of blocks holding one large value.
    BigData,
    /// `lf` — a fast leaf: pairs of (subkey cell index, first four name bytes).
    FastLeaf,
    /// `lh` — a hash leaf: pairs of (subkey cell index, name hash).
    HashLeaf,
    /// `li` — an index leaf: bare subkey cell indices, with no hint alongside.
    IndexLeaf,
    /// `ri` — an index root: cell indices of *further index cells*, not of keys.
    IndexRoot,
}

impl CellKind {
    /// The kind a signature names, or `None` for a signature the format does
    /// not define.
    pub fn from_signature(signature: [u8; 2]) -> Option<CellKind> {
        match &signature {
            b"nk" => Some(CellKind::KeyNode),
            b"vk" => Some(CellKind::KeyValue),
            b"sk" => Some(CellKind::KeySecurity),
            b"db" => Some(CellKind::BigData),
            b"lf" => Some(CellKind::FastLeaf),
            b"lh" => Some(CellKind::HashLeaf),
            b"li" => Some(CellKind::IndexLeaf),
            b"ri" => Some(CellKind::IndexRoot),
            _ => None,
        }
    }

    /// The signature bytes.
    pub fn signature(self) -> [u8; 2] {
        match self {
            CellKind::KeyNode => *b"nk",
            CellKind::KeyValue => *b"vk",
            CellKind::KeySecurity => *b"sk",
            CellKind::BigData => *b"db",
            CellKind::FastLeaf => *b"lf",
            CellKind::HashLeaf => *b"lh",
            CellKind::IndexLeaf => *b"li",
            CellKind::IndexRoot => *b"ri",
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            CellKind::KeyNode => "nk",
            CellKind::KeyValue => "vk",
            CellKind::KeySecurity => "sk",
            CellKind::BigData => "db",
            CellKind::FastLeaf => "lf",
            CellKind::HashLeaf => "lh",
            CellKind::IndexLeaf => "li",
            CellKind::IndexRoot => "ri",
        }
    }

    /// How many list slots one entry of this index occupies.
    ///
    /// `lf` and `lh` store a hint beside every cell index, so their lists are
    /// twice as long as their entry count. Walking one with a stride of one
    /// yields alternating real subkeys and name hashes read as cell indices,
    /// half of which translate to somewhere plausible.
    fn list_stride(self) -> Option<u64> {
        match self {
            CellKind::FastLeaf | CellKind::HashLeaf => Some(2),
            CellKind::IndexLeaf | CellKind::IndexRoot => Some(1),
            _ => None,
        }
    }
}

/// A key or value name, decoded and with the bytes it was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegName {
    /// The decoded name.
    pub text: String,
    /// Whether the name was stored one byte per character.
    pub compressed: bool,
    /// Whether every code unit decoded cleanly.
    ///
    /// `false` means the text contains replacement characters standing in for
    /// units that are not valid UTF-16 — which is a fact about the evidence,
    /// not a rendering detail, because unpaired surrogates in a key name are
    /// one of the ways a name is made hard to see.
    pub well_formed: bool,
    /// The bytes exactly as they were acquired.
    pub raw: Vec<u8>,
}

impl RegName {
    /// Decode `bytes` as a name.
    ///
    /// `compressed` comes from the key's or value's own flag word, never from
    /// what the bytes look like: a UTF-16 name of ASCII characters and a
    /// compressed name are trivially distinguishable by guessing and the guess
    /// is wrong often enough to matter.
    pub fn decode(bytes: Vec<u8>, compressed: bool) -> RegName {
        if compressed {
            // One byte per character, in the system's ANSI code page. Latin-1 is
            // the only total mapping available without knowing that code page,
            // and it round-trips the ASCII that names are made of in practice.
            let text: String = bytes.iter().map(|byte| char::from(*byte)).collect();
            return RegName {
                text,
                compressed,
                well_formed: true,
                raw: bytes,
            };
        }
        let (text, well_formed) = decode_utf16le(&bytes);
        RegName {
            text,
            compressed,
            well_formed,
            raw: bytes,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "text": self.text,
            "compressed": self.compressed,
            "well_formed": self.well_formed,
        })
    }
}

/// One registry key, as it exists in memory.
#[derive(Debug, Clone)]
pub struct KeyNode {
    /// The key's own cell index, store bit included.
    pub cell: CellIndex,
    /// `_CM_KEY_NODE.Flags`.
    pub flags: u64,
    /// `_CM_KEY_NODE.LastWriteTime` as a raw Windows FILETIME.
    ///
    /// Kept raw rather than converted here: the conversion belongs with the
    /// timestamp contract, and a key whose FILETIME is nonsense must still be
    /// reportable as the nonsense it holds.
    pub last_write_time: i64,
    /// The parent key's cell index.
    pub parent: CellIndex,
    /// The key's name.
    pub name: RegName,
    /// Stable and volatile subkey counts, as the key declares them.
    pub subkey_counts: [u64; 2],
    /// Stable and volatile subkey index cells.
    pub subkey_lists: [CellIndex; 2],
    /// How many values the key declares.
    pub value_count: u64,
    /// The cell holding the key's list of value cells.
    pub value_list: CellIndex,
}

impl KeyNode {
    /// Whether this key exists only in volatile storage.
    ///
    /// Decided by which store the key's own cell index selects, which is the
    /// fact; the `KEY_IS_VOLATILE` flag is the key's opinion and is reported
    /// separately.
    pub fn is_volatile(&self) -> bool {
        self.cell.store() == Store::Volatile
    }

    /// Whether the key claims to be this hive's root.
    pub fn is_hive_root(&self) -> bool {
        self.flags & KEY_HIVE_ENTRY != 0
    }

    /// Whether the key is a symbolic link to another key.
    pub fn is_symlink(&self) -> bool {
        self.flags & KEY_SYM_LINK != 0
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cell": self.cell.raw(),
            "store": self.cell.store().as_str(),
            "name": self.name.to_json(),
            "flags": self.flags,
            "last_write_time": self.last_write_time,
            "parent": self.parent.raw(),
            "subkey_counts": self.subkey_counts,
            "value_count": self.value_count,
            "volatile": self.is_volatile(),
            "symlink": self.is_symlink(),
        })
    }
}

/// The registry value types Windows defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegValueType {
    /// `REG_NONE`.
    None,
    /// `REG_SZ`: a UTF-16LE string.
    Sz,
    /// `REG_EXPAND_SZ`: a UTF-16LE string with unexpanded `%VARIABLES%`.
    ExpandSz,
    /// `REG_BINARY`: opaque bytes.
    Binary,
    /// `REG_DWORD`: a little-endian 32-bit integer.
    Dword,
    /// `REG_DWORD_BIG_ENDIAN`: a big-endian 32-bit integer.
    DwordBigEndian,
    /// `REG_LINK`: a UTF-16LE symbolic-link target.
    Link,
    /// `REG_MULTI_SZ`: NUL-separated UTF-16LE strings, ended by an empty one.
    MultiSz,
    /// `REG_RESOURCE_LIST`.
    ResourceList,
    /// `REG_FULL_RESOURCE_DESCRIPTOR`.
    FullResourceDescriptor,
    /// `REG_RESOURCE_REQUIREMENTS_LIST`.
    ResourceRequirementsList,
    /// `REG_QWORD`: a little-endian 64-bit integer.
    Qword,
    /// A type number Windows does not define.
    ///
    /// Kept as the number rather than folded into `REG_BINARY`: a value whose
    /// type is 0x1F4 is evidence of something, and reporting it as binary hides
    /// the only unusual thing about it.
    Unknown(u32),
}

impl RegValueType {
    /// The type a `_CM_KEY_VALUE.Type` number names.
    pub fn from_raw(raw: u32) -> RegValueType {
        match raw {
            0 => RegValueType::None,
            1 => RegValueType::Sz,
            2 => RegValueType::ExpandSz,
            3 => RegValueType::Binary,
            4 => RegValueType::Dword,
            5 => RegValueType::DwordBigEndian,
            6 => RegValueType::Link,
            7 => RegValueType::MultiSz,
            8 => RegValueType::ResourceList,
            9 => RegValueType::FullResourceDescriptor,
            10 => RegValueType::ResourceRequirementsList,
            11 => RegValueType::Qword,
            other => RegValueType::Unknown(other),
        }
    }

    /// The Windows name of the type.
    pub fn as_str(self) -> &'static str {
        match self {
            RegValueType::None => "REG_NONE",
            RegValueType::Sz => "REG_SZ",
            RegValueType::ExpandSz => "REG_EXPAND_SZ",
            RegValueType::Binary => "REG_BINARY",
            RegValueType::Dword => "REG_DWORD",
            RegValueType::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            RegValueType::Link => "REG_LINK",
            RegValueType::MultiSz => "REG_MULTI_SZ",
            RegValueType::ResourceList => "REG_RESOURCE_LIST",
            RegValueType::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            RegValueType::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            RegValueType::Qword => "REG_QWORD",
            RegValueType::Unknown(_) => "REG_UNKNOWN",
        }
    }
}

/// One decoded string out of a registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegText {
    /// The text.
    pub text: String,
    /// Whether every code unit decoded cleanly.
    pub well_formed: bool,
}

/// A registry value's data, decoded according to its declared type.
///
/// The raw bytes travel alongside in [`ValueData::Available`], so a decode that
/// is wrong for the data can always be re-examined against what was actually
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryData {
    /// `REG_NONE`, or a value with no data.
    Empty,
    /// One string.
    Text(RegText),
    /// A `REG_MULTI_SZ` list, with the terminating empty string removed.
    MultiText(Vec<RegText>),
    /// A 32-bit integer.
    Dword(u32),
    /// A 64-bit integer.
    Qword(u64),
    /// Opaque bytes; see the raw data beside it.
    Binary,
    /// The declared type and the data disagree — a `REG_DWORD` of six bytes,
    /// for instance.
    ///
    /// Reported rather than coerced: a `REG_DWORD` whose data is not four bytes
    /// long was written by something that was not the registry API, and that is
    /// the finding.
    Malformed {
        /// What is inconsistent.
        detail: String,
    },
}

/// Whether a value's data could be read, and what it decoded to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueData {
    /// The bytes were read.
    Available {
        /// The data exactly as acquired.
        raw: Vec<u8>,
        /// The decode of those bytes under the value's declared type.
        decoded: RegistryData,
    },
    /// The bytes could not be read, and here is why.
    ///
    /// The distinction this whole module is built around: a value whose data
    /// cell was paged out is **not** an empty value, and must never render as
    /// one.
    Unavailable(Incomplete),
}

impl ValueData {
    /// Whether the data was readable.
    pub fn is_available(&self) -> bool {
        matches!(self, ValueData::Available { .. })
    }
}

/// One registry value.
#[derive(Debug, Clone)]
pub struct KeyValue {
    /// The value's own cell index.
    pub cell: CellIndex,
    /// The value's name. Empty for the key's default value.
    pub name: RegName,
    /// The declared type.
    pub value_type: RegValueType,
    /// The type number exactly as stored.
    pub raw_type: u32,
    /// Declared data length, with the inline bit removed.
    pub declared_len: u64,
    /// Whether the data is stored inside the cell rather than in another one.
    pub inline: bool,
    /// The data.
    pub data: ValueData,
}

impl KeyValue {
    /// Whether this is the key's unnamed default value.
    pub fn is_default(&self) -> bool {
        self.name.raw.is_empty()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let data = match &self.data {
            ValueData::Available { raw, decoded } => serde_json::json!({
                "available": true,
                "length": raw.len(),
                "decoded": decoded_to_json(decoded),
            }),
            ValueData::Unavailable(incomplete) => serde_json::json!({
                "available": false,
                "incomplete": incomplete.to_json(),
            }),
        };
        serde_json::json!({
            "cell": self.cell.raw(),
            "name": self.name.to_json(),
            "type": self.value_type.as_str(),
            "raw_type": self.raw_type,
            "declared_length": self.declared_len,
            "inline": self.inline,
            "data": data,
        })
    }
}

/// Serializable form of a decoded value.
fn decoded_to_json(decoded: &RegistryData) -> serde_json::Value {
    match decoded {
        RegistryData::Empty => serde_json::json!({"kind": "empty"}),
        RegistryData::Text(text) => serde_json::json!({
            "kind": "text", "text": text.text, "well_formed": text.well_formed
        }),
        RegistryData::MultiText(parts) => serde_json::json!({
            "kind": "multi_text",
            "text": parts.iter().map(|part| part.text.clone()).collect::<Vec<_>>(),
            "well_formed": parts.iter().all(|part| part.well_formed),
        }),
        RegistryData::Dword(value) => serde_json::json!({"kind": "dword", "value": value}),
        RegistryData::Qword(value) => serde_json::json!({"kind": "qword", "value": value}),
        RegistryData::Binary => serde_json::json!({"kind": "binary"}),
        RegistryData::Malformed { detail } => {
            serde_json::json!({"kind": "malformed", "detail": detail})
        }
    }
}

/// The subkeys of one key, and everything that stopped the enumeration being
/// complete.
#[derive(Debug, Clone)]
pub struct Subkeys {
    /// The keys found, in the order the index cells list them.
    pub keys: Vec<KeyNode>,
    /// How many the key declares, stable plus volatile.
    ///
    /// Compared against `keys.len()` because a mismatch is a finding: a subkey
    /// list edited to hide a key leaves the count behind.
    pub declared: u64,
    /// Everything that could not be enumerated, and why.
    pub incomplete: Vec<Incomplete>,
}

impl Subkeys {
    /// Whether every subkey the key declares was enumerated with no failures.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty()
    }
}

/// The values of one key, and everything that stopped the enumeration being
/// complete.
#[derive(Debug, Clone)]
pub struct Values {
    /// The values found, in list order.
    pub values: Vec<KeyValue>,
    /// How many the key declares.
    pub declared: u64,
    /// Everything that could not be enumerated, and why.
    pub incomplete: Vec<Incomplete>,
}

impl Values {
    /// Whether every value the key declares was enumerated with no failures.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty()
    }
}

/// Reads registry cells out of one hive.
///
/// Holds the hive space and a struct reader over it, so a `_CM_KEY_NODE` is
/// read at symbol-table offsets from an address that is a cell index. Cheap to
/// clone; bound to exactly one hive, because cell indices mean nothing outside
/// the hive that issued them.
#[derive(Debug, Clone)]
pub struct CellReader {
    hive: Arc<HiveSpace>,
    reader: StructReader,
    cell_header: u64,
    index_width: u64,
}

impl CellReader {
    /// A reader over `hive`.
    ///
    /// # Errors
    ///
    /// If the symbol table does not describe `_CM_KEY_INDEX.List`, which is
    /// where the width of a cell index is taken from. Every list in the format
    /// — subkey lists, value lists, big-data block lists — is an array of that
    /// same type, so one wrong stride would misread all three.
    pub fn new(hive: Arc<HiveSpace>) -> Result<CellReader, RegistryError> {
        let reader = HiveSpace::cell_reader(&hive);
        let cell_header = hive.cell_header_len();
        let (index_width, _) = array_shape(hive.symbols(), "_CM_KEY_INDEX", "List")?;
        if index_width != 4 {
            return Err(RegistryError::Malformed(format!(
                "this symbol table declares a cell index of {index_width} byte(s); the hive file \
                 format defines it as four on every architecture"
            )));
        }
        Ok(CellReader {
            hive,
            reader,
            cell_header,
            index_width,
        })
    }

    /// The hive these cells belong to.
    pub fn hive(&self) -> &Arc<HiveSpace> {
        &self.hive
    }

    /// The cell index of a cell's *contents*, past its allocation header.
    pub fn contents_of(&self, cell: CellIndex) -> Result<CellIndex, RegistryError> {
        cell.offset_by(self.cell_header)
    }

    /// The two signature bytes at the start of a cell's contents.
    pub fn signature(&self, cell: CellIndex) -> Result<[u8; 2], RegistryError> {
        let contents = self.contents_of(cell)?;
        let bytes = self.hive.read_cell(contents, 2)?;
        Ok([bytes[0], bytes[1]])
    }

    /// What kind of cell this is, refusing a signature the format does not
    /// define.
    pub fn kind(&self, cell: CellIndex) -> Result<CellKind, RegistryError> {
        let signature = self.signature(cell)?;
        CellKind::from_signature(signature).ok_or_else(|| RegistryError::UnknownCell {
            index: cell.raw(),
            signature: render_signature(signature),
        })
    }

    /// An object of a named type at a cell's contents.
    fn object(&self, cell: CellIndex, type_name: &str) -> Result<Obj, RegistryError> {
        let contents = self.contents_of(cell)?;
        Ok(self.reader.object(u64::from(contents.raw()), type_name)?)
    }

    /// Read `len` bytes at a hive-space address produced by
    /// [`Obj::member_address`].
    fn bytes_at(&self, address: u64, len: u64) -> Result<Vec<u8>, RegistryError> {
        let raw = u32::try_from(address).map_err(|_| {
            RegistryError::Overflow(format!(
                "the hive-space address {address:#x} is not a 32-bit cell index"
            ))
        })?;
        self.hive.read_cell(CellIndex::new(raw), len)
    }

    /// One 32-bit cell index out of a list, at `slot` entries into it.
    ///
    /// The list is little-endian because the hive *file format* is, on every
    /// architecture Windows has ever run on; the *width* comes from the symbol
    /// table, because a stride is the thing that silently halves a subkey list.
    fn list_entry(&self, list_address: u64, slot: u64) -> Result<CellIndex, RegistryError> {
        let offset = slot.checked_mul(self.index_width).ok_or_else(|| {
            RegistryError::Overflow(format!("slot {slot} of a cell-index list overflows"))
        })?;
        let address = list_address.checked_add(offset).ok_or_else(|| {
            RegistryError::Overflow(format!(
                "the list at {list_address:#x} plus slot {slot} overflows"
            ))
        })?;
        let bytes = self.bytes_at(address, self.index_width)?;
        Ok(CellIndex::new(u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ])))
    }

    /// Read the key at a cell index.
    ///
    /// # Errors
    ///
    /// [`RegistryError::WrongCell`] if the cell is a valid registry cell of
    /// another kind, and [`RegistryError::UnknownCell`] if its signature is not
    /// one the format defines. Neither is skipped: a subkey list that points at
    /// a value cell is corrupt, and reporting the key it "contains" would be
    /// inventing one.
    pub fn key_node(&self, cell: CellIndex) -> Result<KeyNode, RegistryError> {
        let kind = self.kind(cell)?;
        if kind != CellKind::KeyNode {
            return Err(RegistryError::WrongCell {
                index: cell.raw(),
                found: render_signature(kind.signature()),
                expected: "a key node ('nk')",
            });
        }
        let node = self.object(cell, "_CM_KEY_NODE")?;
        let flags = unsigned_member(&node, "Flags")?;
        let last_write_time = node
            .int("LastWriteTime.QuadPart")?
            .as_i64()
            .ok_or_else(|| {
                RegistryError::Malformed(
                    "_CM_KEY_NODE.LastWriteTime does not fit a 64-bit FILETIME".to_string(),
                )
            })?;
        let name_length = unsigned_member(&node, "NameLength")?;
        let name_address = node.member_address("Name")?;
        let name = RegName::decode(
            self.bytes_at(name_address, name_length)?,
            flags & KEY_COMP_NAME != 0,
        );

        let mut subkey_counts = [0u64; 2];
        let mut subkey_lists = [CellIndex::new(0); 2];
        for slot in 0..2u64 {
            subkey_counts[slot as usize] = node
                .element_int("SubKeyCounts", slot)?
                .as_u64()
                .ok_or_else(|| {
                    RegistryError::Malformed(format!(
                        "_CM_KEY_NODE.SubKeyCounts[{slot}] is negative"
                    ))
                })?;
            let list = node
                .element_int("SubKeyLists", slot)?
                .as_u64()
                .ok_or_else(|| {
                    RegistryError::Malformed(format!(
                        "_CM_KEY_NODE.SubKeyLists[{slot}] is negative"
                    ))
                })?;
            subkey_lists[slot as usize] = as_cell_index(list, "_CM_KEY_NODE.SubKeyLists")?;
        }

        let value_count = unsigned_member(&node, "ValueList.Count")?;
        let value_list = as_cell_index(
            unsigned_member(&node, "ValueList.List")?,
            "_CM_KEY_NODE.ValueList.List",
        )?;
        let parent = as_cell_index(unsigned_member(&node, "Parent")?, "_CM_KEY_NODE.Parent")?;

        Ok(KeyNode {
            cell,
            flags,
            last_write_time,
            parent,
            name,
            subkey_counts,
            subkey_lists,
            value_count,
            value_list,
        })
    }

    /// The key's class data, when it declares one.
    ///
    /// `_CM_KEY_NODE.Class` names a cell holding `ClassLength` bytes — text most
    /// keys do not have. The ones that matter for credential recovery are
    /// `SYSTEM\...\Control\Lsa\{JD,Skew1,GBG,Data}`, whose class strings are the
    /// scrambled quarters of the machine's boot key. Returns the raw bytes (the
    /// caller decodes them); `None` when the key declares no class.
    pub fn key_class(&self, cell: CellIndex) -> Result<Option<Vec<u8>>, RegistryError> {
        let node = self.object(cell, "_CM_KEY_NODE")?;
        let class_length = unsigned_member(&node, "ClassLength")?;
        if class_length == 0 {
            return Ok(None);
        }
        let class_index = unsigned_member(&node, "Class")?;
        // HCELL_NIL — the key declares a length but no cell.
        if class_index == u64::from(u32::MAX) {
            return Ok(None);
        }
        let class_cell = as_cell_index(class_index, "_CM_KEY_NODE.Class")?;
        let contents = self.contents_of(class_cell)?;
        Ok(Some(self.hive.read_cell(contents, class_length)?))
    }

    /// Every subkey of `node`, from both stores.
    ///
    /// Walks the subkey indexes breadth-first, dispatching on each cell's own
    /// signature rather than on what the parent list claimed it would be. That
    /// is what makes all four index formats work through one path, `ri` roots
    /// of `lf`/`lh` leaves included, and it is what stops a corrupt list from
    /// being read as the format it is not.
    ///
    /// Bounded three ways — entry count, index-cell count and nesting depth —
    /// and cycle-safe on the index cells, because a subkey index that points
    /// back at itself otherwise produces an endless supply of real-looking keys.
    /// Every bound that fires and every cell that could not be read is recorded
    /// in [`Subkeys::incomplete`]; nothing is dropped in silence.
    pub fn subkeys(&self, node: &KeyNode) -> Subkeys {
        let declared = node.subkey_counts[0].saturating_add(node.subkey_counts[1]);
        let mut keys = Vec::new();
        let mut incomplete = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<(CellIndex, u32)> = VecDeque::new();
        // Index cells and key nodes are bounded separately: a key with more
        // subkeys than there are index cells in the bound is an ordinary key,
        // not a corrupt one.
        let mut index_cells = 0usize;
        let mut index_cap_noted = false;
        let mut entries_examined = 0usize;

        // A store with no subkeys leaves its list at the "no cell" marker, and
        // translating that marker would be a lookup two gigabytes into the hive.
        for (count, list) in node.subkey_counts.iter().zip(node.subkey_lists.iter()) {
            if *count == 0 || list.is_nil() {
                continue;
            }
            queue.push_back((*list, 0));
        }

        while let Some((cell, depth)) = queue.pop_front() {
            if keys.len() >= MAX_SUBKEYS {
                incomplete.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "the subkey walk stopped at its cap of {MAX_SUBKEYS} keys; this key has \
                         more"
                    ),
                ));
                break;
            }
            if depth > MAX_INDEX_DEPTH {
                incomplete.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the subkey index nests more than {MAX_INDEX_DEPTH} deep at cell {cell}, \
                         which the format does not permit"
                    ),
                ));
                continue;
            }
            if !visited.insert(cell.raw()) {
                incomplete.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("the subkey index returns to cell {cell}, so it does not terminate"),
                ));
                continue;
            }

            let kind = match self.kind(cell) {
                Ok(kind) => kind,
                Err(err) => {
                    incomplete.push(err.to_incomplete());
                    continue;
                }
            };
            match kind {
                CellKind::KeyNode => match self.key_node(cell) {
                    Ok(key) => keys.push(key),
                    Err(err) => incomplete.push(err.to_incomplete()),
                },
                CellKind::FastLeaf
                | CellKind::HashLeaf
                | CellKind::IndexLeaf
                | CellKind::IndexRoot => {
                    if index_cells >= MAX_INDEX_CELLS {
                        if !index_cap_noted {
                            index_cap_noted = true;
                            incomplete.push(Incomplete::new(
                                IncompleteReason::CapReached,
                                format!(
                                    "the subkey walk stopped after {MAX_INDEX_CELLS} index cells; \
                                     the index continues"
                                ),
                            ));
                        }
                        continue;
                    }
                    index_cells = index_cells.saturating_add(1);
                    if let Err(err) = self.push_index_children(
                        cell,
                        kind,
                        depth,
                        &mut queue,
                        &mut entries_examined,
                    ) {
                        incomplete.push(err.to_incomplete());
                    }
                }
                other => incomplete.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "cell {cell} in a subkey index is a '{}' cell, which cannot hold subkeys",
                        other.as_str()
                    ),
                )),
            }
        }

        if incomplete.is_empty() && keys.len() as u64 != declared {
            // Not an error and not a failure to read: the key's own count and
            // its own index disagree, which is what an unlinked key looks like.
            incomplete.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the key declares {declared} subkey(s) and its subkey index lists {}; the two \
                     disagree",
                    keys.len()
                ),
            ));
        }

        Subkeys {
            keys,
            declared,
            incomplete,
        }
    }

    /// Queue the children an index cell names.
    ///
    /// `budget` is the whole walk's remaining allowance of list entries, not
    /// this cell's: `Count` comes out of the image, so a cell that declares
    /// 65,535 children has to be stopped by something that spans the walk rather
    /// than by a per-cell bound that every corrupt cell renews.
    fn push_index_children(
        &self,
        cell: CellIndex,
        kind: CellKind,
        depth: u32,
        queue: &mut VecDeque<(CellIndex, u32)>,
        budget: &mut usize,
    ) -> Result<(), RegistryError> {
        let Some(stride) = kind.list_stride() else {
            return Err(RegistryError::WrongCell {
                index: cell.raw(),
                found: render_signature(kind.signature()),
                expected: "a subkey index",
            });
        };
        let index = self.object(cell, "_CM_KEY_INDEX")?;
        let count = unsigned_member(&index, "Count")?;
        let list_address = index.member_address("List")?;
        for entry in 0..count {
            if *budget >= MAX_INDEX_ENTRIES {
                return Err(RegistryError::Cap {
                    what: "entries read from one key's subkey index",
                    cap: MAX_INDEX_ENTRIES as u64,
                });
            }
            *budget = budget.saturating_add(1);
            let slot = entry.checked_mul(stride).ok_or_else(|| {
                RegistryError::Overflow(format!("entry {entry} of the index at {cell} overflows"))
            })?;
            let child = self.list_entry(list_address, slot)?;
            if child.is_nil() {
                continue;
            }
            queue.push_back((child, depth.saturating_add(1)));
        }
        Ok(())
    }

    /// Every value of `node`.
    ///
    /// The value list is a cell holding `ValueList.Count` cell indices. A zero
    /// entry is a hole the registry left behind and is skipped; anything else
    /// that cannot be read is recorded rather than dropped.
    pub fn values(&self, node: &KeyNode) -> Values {
        let declared = node.value_count;
        let mut values = Vec::new();
        let mut incomplete = Vec::new();

        if declared == 0 || node.value_list.is_nil() {
            return Values {
                values,
                declared,
                incomplete,
            };
        }
        if declared > MAX_VALUES as u64 {
            incomplete.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the key declares {declared} values, beyond the cap of {MAX_VALUES}; the list \
                     was not walked"
                ),
            ));
            return Values {
                values,
                declared,
                incomplete,
            };
        }

        let list_address = match self.contents_of(node.value_list) {
            Ok(contents) => u64::from(contents.raw()),
            Err(err) => {
                incomplete.push(err.to_incomplete());
                return Values {
                    values,
                    declared,
                    incomplete,
                };
            }
        };

        for slot in 0..declared {
            let cell = match self.list_entry(list_address, slot) {
                Ok(cell) => cell,
                Err(err) => {
                    incomplete.push(err.to_incomplete());
                    continue;
                }
            };
            if cell.raw() == 0 || cell.is_nil() {
                continue;
            }
            match self.key_value(cell) {
                Ok(value) => values.push(value),
                Err(err) => incomplete.push(err.to_incomplete()),
            }
        }

        if incomplete.is_empty() && values.len() as u64 != declared {
            // Symmetrically with the subkey walk: the key's own count and its own
            // value list disagree, which is what an unlinked value leaves behind.
            // Without this a listing two values short would report itself
            // complete, and a value removed from the list would be invisible.
            incomplete.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the key declares {declared} value(s) and its value list names {}; the two \
                     disagree",
                    values.len()
                ),
            ));
        }

        Values {
            values,
            declared,
            incomplete,
        }
    }

    /// Read the value at a cell index, data included.
    pub fn key_value(&self, cell: CellIndex) -> Result<KeyValue, RegistryError> {
        let kind = self.kind(cell)?;
        if kind != CellKind::KeyValue {
            return Err(RegistryError::WrongCell {
                index: cell.raw(),
                found: render_signature(kind.signature()),
                expected: "a value ('vk')",
            });
        }
        let value = self.object(cell, "_CM_KEY_VALUE")?;
        let flags = unsigned_member(&value, "Flags")?;
        let name_length = unsigned_member(&value, "NameLength")?;
        let name_address = value.member_address("Name")?;
        let name = RegName::decode(
            self.bytes_at(name_address, name_length)?,
            flags & VALUE_COMP_NAME != 0,
        );

        let raw_type = unsigned_member(&value, "Type")?;
        let value_type = RegValueType::from_raw(raw_type as u32);
        let raw_length = unsigned_member(&value, "DataLength")?;
        let inline = raw_length & VALUE_DATA_INLINE != 0;
        let declared_len = raw_length & !VALUE_DATA_INLINE;

        let data = match self.read_value_data(&value, inline, declared_len) {
            Ok(raw) => {
                let decoded = decode_data(value_type, &raw);
                ValueData::Available { raw, decoded }
            }
            Err(err) => ValueData::Unavailable(err.to_incomplete()),
        };

        Ok(KeyValue {
            cell,
            name,
            value_type,
            raw_type: raw_type as u32,
            declared_len,
            inline,
            data,
        })
    }

    /// The bytes of one value, from wherever the format put them.
    fn read_value_data(
        &self,
        value: &Obj,
        inline: bool,
        declared_len: u64,
    ) -> Result<Vec<u8>, RegistryError> {
        if declared_len == 0 {
            return Ok(Vec::new());
        }
        if inline {
            // `Data` is not a cell index here: it *is* the data. Following it
            // as an index would send the translator after an arbitrary number.
            let (width, _) = array_shape_or_scalar(self, "_CM_KEY_VALUE", "Data")?;
            if declared_len > width {
                return Err(RegistryError::InlineTooLong {
                    length: declared_len,
                });
            }
            let address = value.member_address("Data")?;
            return self.bytes_at(address, declared_len);
        }

        let data_cell = as_cell_index(unsigned_member(value, "Data")?, "_CM_KEY_VALUE.Data")?;
        if declared_len > BIG_DATA_THRESHOLD {
            // Decided by the target cell's own signature rather than by the
            // hive's version number: upstream gates on version 5 alone, which
            // misreads a version-4 hive that does have big data, and turns a
            // version field that could not be read into sixteen kilobytes of
            // the wrong bytes.
            if self.signature(data_cell).ok() == Some(*b"db") {
                return self.read_big_data(data_cell, declared_len);
            }
        }
        let contents = self.contents_of(data_cell)?;
        self.hive.read_cell(contents, declared_len)
    }

    /// Assemble a value from its big-data blocks.
    ///
    /// A `db` cell holds a count and the cell index of a *list* of cell
    /// indices, each of which names a block of up to [`BIG_DATA_BLOCK`] bytes.
    /// The blocks are concatenated in list order, and the last one is truncated
    /// to what the value's declared length still needs.
    fn read_big_data(&self, cell: CellIndex, declared_len: u64) -> Result<Vec<u8>, RegistryError> {
        let record = self.object(cell, "_CM_BIG_DATA")?;
        let count = unsigned_member(&record, "Count")?;
        if count > MAX_BIG_DATA_BLOCKS {
            return Err(RegistryError::Cap {
                what: "big-data blocks in one value",
                cap: MAX_BIG_DATA_BLOCKS,
            });
        }
        if declared_len > MAX_CELL_READ {
            return Err(RegistryError::Cap {
                what: "the assembled length of one big-data value",
                cap: MAX_CELL_READ,
            });
        }
        let list_cell = as_cell_index(unsigned_member(&record, "List")?, "_CM_BIG_DATA.List")?;
        let list_address = u64::from(self.contents_of(list_cell)?.raw());

        let mut data = Vec::with_capacity(declared_len as usize);
        let mut remaining = declared_len;
        for slot in 0..count {
            if remaining == 0 {
                break;
            }
            let block = self.list_entry(list_address, slot)?;
            let contents = self.contents_of(block)?;
            let amount = remaining.min(BIG_DATA_BLOCK);
            data.extend_from_slice(&self.hive.read_cell(contents, amount)?);
            remaining -= amount;
        }
        if remaining != 0 {
            return Err(RegistryError::Malformed(format!(
                "the big-data record at {cell} declares {count} block(s), which is {remaining} \
                 byte(s) short of the value's declared length"
            )));
        }
        Ok(data)
    }
}

/// The width of a member that may be declared as an array or as a scalar.
///
/// `_CM_KEY_VALUE.Data` is a four-byte cell index on every build, but some
/// symbol tables declare it as an array of bytes. Either way what an inline
/// value needs is how many bytes of it there are, and that comes from the
/// table.
fn array_shape_or_scalar(
    reader: &CellReader,
    type_name: &str,
    path: &str,
) -> Result<(u64, u64), RegistryError> {
    match array_shape(reader.hive.symbols(), type_name, path) {
        Ok((width, count)) => Ok((width.saturating_mul(count), count)),
        Err(_) => {
            let id = member_type(reader.hive.symbols(), type_name, path)?;
            Ok((reader.hive.symbols().size_of_id(id)?, 1))
        }
    }
}

/// A number read out of a cell that is being used as a cell index.
///
/// A cell index is 32 bits wide by the format's definition, so a member holding
/// something wider is a member this reader has misidentified, and truncating it
/// would produce an index that translates to a real cell somewhere else.
fn as_cell_index(value: u64, what: &str) -> Result<CellIndex, RegistryError> {
    u32::try_from(value).map(CellIndex::new).map_err(|_| {
        RegistryError::Malformed(format!(
            "'{what}' holds {value:#x}, which is not a 32-bit cell index"
        ))
    })
}

/// Decode a value's bytes under its declared type.
///
/// A type whose data is the wrong length yields [`RegistryData::Malformed`]
/// rather than a coerced number: `REG_DWORD` with six bytes of data was not
/// written through the registry API, and that is worth saying.
pub fn decode_data(value_type: RegValueType, raw: &[u8]) -> RegistryData {
    match value_type {
        RegValueType::None => RegistryData::Empty,
        RegValueType::Sz | RegValueType::ExpandSz | RegValueType::Link => {
            let (text, well_formed) = decode_utf16le(trim_trailing_nul_units(raw));
            RegistryData::Text(RegText { text, well_formed })
        }
        RegValueType::MultiSz => {
            let mut parts = Vec::new();
            for chunk in split_utf16_nul(raw) {
                let (text, well_formed) = decode_utf16le(chunk);
                parts.push(RegText { text, well_formed });
            }
            while parts.last().is_some_and(|part| part.text.is_empty()) {
                parts.pop();
            }
            RegistryData::MultiText(parts)
        }
        RegValueType::Dword => match raw.len() {
            4 => RegistryData::Dword(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
            other => RegistryData::Malformed {
                detail: format!("REG_DWORD with {other} byte(s) of data, not 4"),
            },
        },
        RegValueType::DwordBigEndian => match raw.len() {
            4 => RegistryData::Dword(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])),
            other => RegistryData::Malformed {
                detail: format!("REG_DWORD_BIG_ENDIAN with {other} byte(s) of data, not 4"),
            },
        },
        RegValueType::Qword => {
            if raw.len() == 8 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(raw);
                RegistryData::Qword(u64::from_le_bytes(bytes))
            } else {
                RegistryData::Malformed {
                    detail: format!("REG_QWORD with {} byte(s) of data, not 8", raw.len()),
                }
            }
        }
        RegValueType::Binary
        | RegValueType::ResourceList
        | RegValueType::FullResourceDescriptor
        | RegValueType::ResourceRequirementsList
        | RegValueType::Unknown(_) => RegistryData::Binary,
    }
}

/// Decode UTF-16LE, reporting whether every code unit was valid.
///
/// An odd byte count or an unpaired surrogate yields replacement characters and
/// `false`, never an error: the bytes are real evidence and must be renderable,
/// but a reader has to be able to tell a name that decoded cleanly from one
/// that did not.
pub fn decode_utf16le(bytes: &[u8]) -> (String, bool) {
    let mut well_formed = bytes.len().is_multiple_of(2);
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let mut text = String::new();
    for unit in char::decode_utf16(units) {
        match unit {
            Ok(character) => text.push(character),
            Err(_) => {
                well_formed = false;
                text.push(char::REPLACEMENT_CHARACTER);
            }
        }
    }
    (text, well_formed)
}

/// Drop trailing UTF-16 NUL units from a string's bytes.
fn trim_trailing_nul_units(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len() - (bytes.len() % 2);
    while end >= 2 && bytes[end - 2] == 0 && bytes[end - 1] == 0 {
        end -= 2;
    }
    &bytes[..end]
}

/// Split `REG_MULTI_SZ` bytes on UTF-16 NUL units.
fn split_utf16_nul(bytes: &[u8]) -> Vec<&[u8]> {
    let usable = bytes.len() - (bytes.len() % 2);
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut at = 0usize;
    while at + 2 <= usable {
        if bytes[at] == 0 && bytes[at + 1] == 0 {
            parts.push(&bytes[start..at]);
            start = at + 2;
        }
        at += 2;
    }
    if start < usable {
        parts.push(&bytes[start..usable]);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::space::HiveSpace;
    use crate::registry::test_support::{xp_profile, ROOT_CELL, XP_CMHIVE};

    fn reader() -> CellReader {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).expect("the fixture hive opens");
        CellReader::new(hive).expect("the fixture symbols describe the registry types")
    }

    fn root(reader: &CellReader) -> KeyNode {
        reader
            .key_node(CellIndex::new(ROOT_CELL))
            .expect("the root key is resident")
    }

    #[test]
    fn every_cell_signature_the_format_defines_round_trips() {
        for kind in [
            CellKind::KeyNode,
            CellKind::KeyValue,
            CellKind::KeySecurity,
            CellKind::BigData,
            CellKind::FastLeaf,
            CellKind::HashLeaf,
            CellKind::IndexLeaf,
            CellKind::IndexRoot,
        ] {
            assert_eq!(CellKind::from_signature(kind.signature()), Some(kind));
            assert_eq!(kind.as_str().as_bytes(), kind.signature().as_slice());
        }
        assert_eq!(CellKind::from_signature(*b"zz"), None);
    }

    #[test]
    fn the_two_leaf_formats_that_store_a_hint_have_a_stride_of_two() {
        // A stride of one over an `lf` list reads the four-byte name hints as
        // cell indices, and roughly half of them translate to a real cell.
        assert_eq!(CellKind::FastLeaf.list_stride(), Some(2));
        assert_eq!(CellKind::HashLeaf.list_stride(), Some(2));
        assert_eq!(CellKind::IndexLeaf.list_stride(), Some(1));
        assert_eq!(CellKind::IndexRoot.list_stride(), Some(1));
        assert_eq!(CellKind::KeyNode.list_stride(), None);
    }

    #[test]
    fn the_root_key_reads_its_name_flags_and_lists_from_symbol_declared_offsets() {
        let reader = reader();
        let root = root(&reader);
        assert_eq!(root.name.text, "ROOT");
        assert!(root.name.compressed);
        assert!(root.is_hive_root());
        assert!(!root.is_volatile());
        assert_eq!(root.subkey_counts, [3, 1]);
        assert_eq!(root.last_write_time, 0x01C0_0000_0000_0001);
    }

    #[test]
    fn a_subkey_walk_covers_all_four_index_formats_through_one_path() {
        // The fixture roots the stable subkeys on an `ri` naming an `lf` and an
        // `lh`, and puts the volatile subkey behind an `li`. All four have to
        // work, and only the cells' own signatures say which is which.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let mut names: Vec<&str> = subkeys
            .keys
            .iter()
            .map(|key| key.name.text.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["Hashed", "Sarah", "Test", "Volatile"]);
        assert!(
            subkeys.is_complete(),
            "nothing should be missing: {:?}",
            subkeys.incomplete
        );
        assert_eq!(subkeys.declared, 4);
    }

    #[test]
    fn a_subkey_that_lives_only_in_the_volatile_store_is_labelled_as_such() {
        // The evidence a disk image cannot show. If this were read out of the
        // stable map it would either fail or return an unrelated key.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let volatile = subkeys
            .keys
            .iter()
            .find(|key| key.name.text == "Volatile")
            .expect("the volatile subkey is enumerated");
        assert!(volatile.is_volatile());
        assert_eq!(volatile.cell.store(), Store::Volatile);
    }

    #[test]
    fn a_name_that_is_not_compressed_is_decoded_as_utf16_not_as_latin1() {
        // Upstream reads every name as Latin-1, which renders this one as
        // "T\0e\0s\0t\0". The flag says which encoding it is, so the flag is
        // what decides.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let test = subkeys
            .keys
            .iter()
            .find(|key| key.name.text == "Test")
            .expect("the UTF-16-named subkey is enumerated");
        assert!(!test.name.compressed);
        assert_eq!(test.name.raw.len(), 8, "four characters, two bytes each");
        assert!(test.name.well_formed);
    }

    #[test]
    fn a_key_whose_declared_count_disagrees_with_its_index_says_so() {
        // The shape an unlinked key leaves behind: the subkey count survives
        // and the list that reached the key does not. Silence here is how a
        // hidden key stays hidden.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let test = subkeys
            .keys
            .iter()
            .find(|key| key.name.text == "Test")
            .expect("Test is enumerated");
        let under_test = reader.subkeys(test);
        assert!(under_test.keys.is_empty());
        assert_eq!(under_test.declared, 1, "the key still claims one subkey");
        assert!(!under_test.is_complete());
        assert!(
            under_test.incomplete[0].detail.contains("disagree"),
            "{:?}",
            under_test.incomplete
        );
    }

    #[test]
    fn a_subkey_index_stops_reading_entries_once_the_walks_budget_is_spent() {
        // `_CM_KEY_INDEX.Count` is a sixteen-bit number out of the image, so the
        // budget has to span the whole walk: a per-cell bound is renewed by every
        // corrupt cell, and four thousand of them is a quarter of a billion reads.
        let reader = reader();
        let mut queue: VecDeque<(CellIndex, u32)> = VecDeque::new();

        let mut spent = MAX_INDEX_ENTRIES;
        let err = reader
            .push_index_children(
                CellIndex::new(0x0300),
                CellKind::FastLeaf,
                0,
                &mut queue,
                &mut spent,
            )
            .expect_err("a spent budget must refuse rather than read");
        assert_eq!(err.class(), "cap");
        assert_eq!(
            err.incomplete_reason(),
            IncompleteReason::CapReached,
            "a bound that fired must never read as the end of the index"
        );
        assert!(queue.is_empty(), "nothing may be queued past the budget");

        // With budget in hand the same cell queues both its children and spends
        // exactly one unit per declared entry, not per list slot: an `lf` leaf
        // stores a name hint beside every index, so the two differ by a factor
        // of two and the wrong one halves the budget.
        let mut budget = 0usize;
        reader
            .push_index_children(
                CellIndex::new(0x0300),
                CellKind::FastLeaf,
                0,
                &mut queue,
                &mut budget,
            )
            .expect("the fixture's fast leaf reads");
        assert_eq!(queue.len(), 2);
        assert_eq!(budget, 2);
    }

    #[test]
    fn key_nodes_are_not_charged_against_the_cap_on_index_cells() {
        // A key with more subkeys than there are index cells in the bound is an
        // ordinary key: `Software\Classes` holds several thousand. Charging key
        // nodes to the index-cell cap would truncate that listing at the bound
        // and label a normal registry as one whose index does not terminate.
        assert!(
            MAX_SUBKEYS > MAX_INDEX_CELLS,
            "the two bounds count different things and must not be conflated"
        );
        assert!(
            MAX_INDEX_ENTRIES >= MAX_SUBKEYS,
            "the entry budget must not bite before the subkey cap does"
        );

        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        assert_eq!(subkeys.keys.len(), 4);
        assert!(
            subkeys.is_complete(),
            "four keys reached through three index cells is not near any bound: {:?}",
            subkeys.incomplete
        );
    }

    #[test]
    fn a_key_with_no_subkeys_at_all_reports_none_and_declares_no_gap() {
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|key| key.name.text == "Sarah")
            .expect("Sarah is enumerated");
        let under_sarah = reader.subkeys(sarah);
        assert!(under_sarah.keys.is_empty());
        assert_eq!(under_sarah.declared, 0);
        assert!(under_sarah.is_complete());
    }

    #[test]
    fn a_value_stored_inline_is_read_out_of_the_cell_not_followed_as_an_index() {
        // The high bit of DataLength means Data holds the bytes. Following it
        // as a cell index sends the translator after 0x2A.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let values = reader.values(sarah);
        let count = values
            .values
            .iter()
            .find(|value| value.name.text == "Count")
            .expect("the inline value is enumerated");
        assert!(count.inline);
        assert_eq!(count.declared_len, 4);
        match &count.data {
            ValueData::Available { raw, decoded } => {
                assert_eq!(raw, &vec![0x2A, 0, 0, 0]);
                assert_eq!(decoded, &RegistryData::Dword(0x2A));
            }
            other => panic!("expected available data, got {other:?}"),
        }
    }

    #[test]
    fn a_string_value_is_decoded_as_utf16_with_its_terminator_removed() {
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let values = reader.values(sarah);
        let path = values
            .values
            .iter()
            .find(|value| value.name.text == "Path")
            .expect("the string value is enumerated");
        assert_eq!(path.value_type, RegValueType::Sz);
        match &path.data {
            ValueData::Available { raw, decoded } => {
                assert_eq!(raw.len(), 8, "three characters and a terminator");
                assert_eq!(
                    decoded,
                    &RegistryData::Text(RegText {
                        text: "abc".to_string(),
                        well_formed: true
                    })
                );
            }
            other => panic!("expected available data, got {other:?}"),
        }
    }

    #[test]
    fn a_multi_string_value_splits_on_nul_units_and_drops_the_terminator() {
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let values = reader.values(sarah);
        let list = values
            .values
            .iter()
            .find(|value| value.name.text == "List")
            .expect("the multi-string value is enumerated");
        assert_eq!(list.value_type, RegValueType::MultiSz);
        match &list.data {
            ValueData::Available { decoded, .. } => match decoded {
                RegistryData::MultiText(parts) => {
                    let texts: Vec<&str> = parts.iter().map(|part| part.text.as_str()).collect();
                    assert_eq!(texts, vec!["a", "b"]);
                }
                other => panic!("expected multi-text, got {other:?}"),
            },
            other => panic!("expected available data, got {other:?}"),
        }
    }

    #[test]
    fn a_value_whose_data_was_paged_out_is_unavailable_and_never_an_empty_value() {
        // The single most important behaviour in the module. Upstream pads with
        // NUL bytes, which renders identically to a value the suspect cleared.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let values = reader.values(sarah);
        let missing = values
            .values
            .iter()
            .find(|value| value.is_default())
            .expect("the default value is enumerated");
        match &missing.data {
            ValueData::Unavailable(incomplete) => {
                assert_eq!(incomplete.reason, IncompleteReason::ShortRead);
                assert!(!incomplete.detail.is_empty());
            }
            other => panic!("paged-out data must not be reported as bytes: {other:?}"),
        }
        assert!(!missing.data.is_available());
        // The value itself is still reported: its name and type are evidence.
        assert_eq!(missing.value_type, RegValueType::Binary);
    }

    #[test]
    fn a_value_list_is_walked_to_the_count_the_key_declares() {
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let values = reader.values(sarah);
        assert_eq!(values.declared, 4);
        assert_eq!(values.values.len(), 4);
        assert!(values.is_complete(), "{:?}", values.incomplete);
    }

    #[test]
    fn a_value_list_shorter_than_the_count_the_key_declares_says_so() {
        // A zero slot in a value list is a value the registry unlinked, and
        // skipping it quietly means a listing two values short reports itself
        // complete. That is the same shape as a hidden subkey and gets the same
        // treatment.
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let hashed = subkeys
            .keys
            .iter()
            .find(|key| key.name.text == "Hashed")
            .expect("Hashed is enumerated");

        let mut gappy = hashed.clone();
        gappy.value_count = 2; // its list names one value and then a zero slot.
        let values = reader.values(&gappy);

        assert_eq!(values.values.len(), 1, "the real value is still reported");
        assert_eq!(values.declared, 2);
        assert!(!values.is_complete());
        assert!(
            values.incomplete[0].detail.contains("disagree"),
            "{:?}",
            values.incomplete
        );
        assert_eq!(
            values.incomplete[0].reason,
            IncompleteReason::UnresolvedStructure
        );
    }

    #[test]
    fn a_key_with_no_values_yields_none_without_following_the_no_cell_marker() {
        let reader = reader();
        let root = root(&reader);
        let values = reader.values(&root);
        assert!(values.values.is_empty());
        assert_eq!(values.declared, 0);
        assert!(values.is_complete());
    }

    #[test]
    fn reading_a_value_cell_as_a_key_is_refused_rather_than_decoded() {
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let value_cell = reader.values(sarah).values[0].cell;
        let err = reader
            .key_node(value_cell)
            .expect_err("a 'vk' cell is not a key");
        assert_eq!(err.class(), "wrong_cell");
        assert!(err.to_string().contains("'vk'"), "{err}");
    }

    #[test]
    fn a_cell_with_a_signature_the_format_does_not_define_is_named_not_skipped() {
        let reader = reader();
        let err = reader
            .kind(CellIndex::new(crate::registry::test_support::JUNK_CELL))
            .expect_err("a junk signature must not decode");
        assert_eq!(err.class(), "unknown_cell");
    }

    #[test]
    fn a_big_data_value_is_assembled_from_its_blocks_in_list_order() {
        let reader = reader();
        let subkeys = reader.subkeys(&root(&reader));
        let hashed = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Hashed")
            .expect("the big-data key is enumerated");
        let values = reader.values(hashed);
        let big = values
            .values
            .iter()
            .find(|value| value.name.text == "Big")
            .expect("the big-data value is enumerated");
        let first_block = crate::registry::test_support::BIG_BLOCK_LEN as usize;
        match &big.data {
            ValueData::Available { raw, .. } => {
                assert_eq!(
                    raw.len(),
                    crate::registry::test_support::BIG_VALUE_LEN as usize,
                    "the assembled value is as long as the value declared"
                );
                assert!(
                    raw[..first_block].iter().all(|byte| *byte == 0x11),
                    "the first block, which itself spans four bin pages"
                );
                assert!(
                    raw[first_block..].iter().all(|byte| *byte == 0x22),
                    "and the remainder, from a block somewhere else entirely"
                );
            }
            other => panic!("expected available data, got {other:?}"),
        }
    }

    #[test]
    fn every_value_type_number_windows_defines_has_a_name() {
        for raw in 0..=11u32 {
            let kind = RegValueType::from_raw(raw);
            assert_ne!(kind, RegValueType::Unknown(raw));
            assert!(kind.as_str().starts_with("REG_"));
        }
        assert_eq!(RegValueType::from_raw(500), RegValueType::Unknown(500));
        assert_eq!(RegValueType::from_raw(500).as_str(), "REG_UNKNOWN");
    }

    #[test]
    fn a_dword_whose_data_is_the_wrong_length_is_malformed_rather_than_coerced() {
        assert_eq!(
            decode_data(RegValueType::Dword, &[1, 2, 3]),
            RegistryData::Malformed {
                detail: "REG_DWORD with 3 byte(s) of data, not 4".to_string()
            }
        );
        assert_eq!(
            decode_data(RegValueType::Qword, &[1, 2, 3, 4]),
            RegistryData::Malformed {
                detail: "REG_QWORD with 4 byte(s) of data, not 8".to_string()
            }
        );
        assert_eq!(
            decode_data(RegValueType::Dword, &[0x2A, 0, 0, 0]),
            RegistryData::Dword(0x2A)
        );
        assert_eq!(
            decode_data(RegValueType::DwordBigEndian, &[0, 0, 0, 0x2A]),
            RegistryData::Dword(0x2A)
        );
        assert_eq!(
            decode_data(RegValueType::Qword, &[1, 0, 0, 0, 0, 0, 0, 0]),
            RegistryData::Qword(1)
        );
    }

    #[test]
    fn an_unknown_value_type_keeps_its_number_and_its_bytes() {
        let decoded = decode_data(RegValueType::Unknown(0x1F4), &[1, 2, 3]);
        assert_eq!(decoded, RegistryData::Binary);
    }

    #[test]
    fn utf16_that_does_not_decode_cleanly_is_reported_as_such_rather_than_refused() {
        // An unpaired high surrogate: real evidence, and not valid UTF-16.
        let (text, well_formed) = decode_utf16le(&[0x00, 0xD8]);
        assert_eq!(text, "\u{FFFD}");
        assert!(!well_formed);

        // An odd byte count is also a fact about the evidence.
        let (text, well_formed) = decode_utf16le(&[0x41, 0x00, 0x42]);
        assert_eq!(text, "A");
        assert!(!well_formed);

        let (text, well_formed) = decode_utf16le(&[0x41, 0x00]);
        assert_eq!(text, "A");
        assert!(well_formed);
    }

    #[test]
    fn a_compressed_name_is_one_byte_per_character_and_a_wide_one_is_two() {
        let compressed = RegName::decode(b"Sarah".to_vec(), true);
        assert_eq!(compressed.text, "Sarah");
        assert!(compressed.well_formed);

        let wide = RegName::decode(vec![b'S', 0, b'a', 0, b'r', 0, b'a', 0, b'h', 0], false);
        assert_eq!(wide.text, "Sarah");
        assert_eq!(wide.raw.len(), 10);

        // And the same bytes read the other way are visibly different, which is
        // why the flag decides rather than the bytes.
        let misread = RegName::decode(vec![b'S', 0, b'a', 0], true);
        assert_eq!(misread.text, "S\u{0}a\u{0}");
    }

    #[test]
    fn multi_sz_splitting_handles_empty_and_unterminated_lists() {
        assert_eq!(split_utf16_nul(&[]).len(), 0);
        // "a\0b\0\0" with an odd trailing byte the split must ignore.
        let bytes = [b'a', 0, 0, 0, b'b', 0, 0, 0, 0x41];
        let parts = split_utf16_nul(&bytes);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], &[b'a', 0]);
        assert_eq!(parts[1], &[b'b', 0]);
    }

    #[test]
    fn trailing_string_terminators_are_trimmed_and_interior_nuls_are_not() {
        assert_eq!(trim_trailing_nul_units(&[b'a', 0, 0, 0]), &[b'a', 0]);
        assert_eq!(trim_trailing_nul_units(&[b'a', 0, 0, 0, 0, 0]), &[b'a', 0]);
        assert_eq!(trim_trailing_nul_units(&[]), &[] as &[u8]);
        assert_eq!(trim_trailing_nul_units(&[0, 0]), &[] as &[u8]);
    }

    #[test]
    fn a_key_and_a_value_both_serialise_everything_a_report_needs() {
        let reader = reader();
        let root = root(&reader);
        let json = root.to_json();
        assert_eq!(json["name"]["text"], "ROOT");
        assert_eq!(json["store"], "stable");
        assert_eq!(json["volatile"], false);

        let subkeys = reader.subkeys(&root);
        let sarah = subkeys
            .keys
            .iter()
            .find(|k| k.name.text == "Sarah")
            .unwrap();
        let values = reader.values(sarah);
        let count = values
            .values
            .iter()
            .find(|v| v.name.text == "Count")
            .unwrap();
        let json = count.to_json();
        assert_eq!(json["type"], "REG_DWORD");
        assert_eq!(json["inline"], true);
        assert_eq!(json["data"]["available"], true);
        assert_eq!(json["data"]["decoded"]["value"], 0x2A);

        let missing = values.values.iter().find(|v| v.is_default()).unwrap();
        let json = missing.to_json();
        assert_eq!(json["data"]["available"], false);
        assert_eq!(json["data"]["incomplete"]["reason"], "short_read");
    }
}
