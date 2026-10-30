//! Hand-built registry fixtures: two synthetic kernels, two synthetic hives,
//! and a deliberate unacquired window in the middle of the evidence.
//!
//! Nothing here is captured. Every structure is written at an address chosen by
//! hand, so a test asserting that a hive's stable store starts at
//! `0x8040B000` is asserting against bytes that were put there for that reason,
//! and a test asserting that a paged-out value is reported as unavailable is
//! asserting against a page that genuinely was never written.
//!
//! Two fixtures, because the two things most likely to be got wrong are
//! architecture-shaped:
//!
//! - [`xp_profile`] is 32-bit, with the pre-Windows-8 `_HMAP_ENTRY` that holds
//!   a bin address outright, a stable store and a volatile store, all four
//!   subkey-index formats, inline, ordinary and big-data values, and a bin that
//!   was never acquired.
//! - [`win8_profile`] is 64-bit, with the Windows 8 `_HMAP_ENTRY` that holds a
//!   flagged bin address plus a block offset. Read the pre-Windows-8 way it
//!   would land on the start of the bin — a real cell, at the wrong place —
//!   which is exactly the failure the fixture exists to catch.
//!
//! The 32-bit fixture is the important one: a reader that assumed eight-byte
//! pointers would follow `_DUAL.Map` to an address made of half a pointer and
//! half the field after it, and that address is not obviously wrong.

use std::sync::{Arc, OnceLock};

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::layer::MemoryLayer;
use seance_memory::meta::{Architecture, LayerMeta};
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::MemoryImageFormat;
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use crate::profile::{Evidence, Found, KernelBuild, WindowsProfile};

// ---------------------------------------------------------------------------
// The 32-bit fixture's address map
// ---------------------------------------------------------------------------

/// Load address of the synthetic 32-bit kernel.
pub const XP_KERNEL_BASE: u64 = 0x8040_0000;
/// Length of the acquired region below the unacquired window.
pub const XP_LOW_LEN: u64 = 0x1_F000;
/// First address with nothing behind it.
pub const XP_HOLE_START: u64 = XP_KERNEL_BASE + XP_LOW_LEN;
/// First address of the second acquired region, past the window.
pub const XP_HIGH_START: u64 = XP_KERNEL_BASE + 0x2_0000;
/// Length of the second acquired region.
pub const XP_HIGH_LEN: u64 = 0x1000;

/// `CmpHiveListHead`, and the RVA the fixture ISF declares for it.
pub const XP_HIVE_LIST_HEAD: u64 = XP_KERNEL_BASE + 0x1000;

/// The named hive's `_CMHIVE`.
pub const XP_CMHIVE: u64 = XP_KERNEL_BASE + 0x2000;
/// A hive with no backing file, whose base block is in the unacquired window.
pub const XP_UNNAMED_CMHIVE: u64 = XP_KERNEL_BASE + 0x2100;
/// A structure on the hive list carrying the wrong signature.
pub const XP_JUNK_CMHIVE: u64 = XP_CMHIVE + 0x400;

/// Where the named hive's file path is stored.
const XP_NAME_BUFFER: u64 = XP_KERNEL_BASE + 0x3000;
/// The named hive's `_HBASE_BLOCK`.
const XP_BASE_BLOCK: u64 = XP_KERNEL_BASE + 0x4000;
/// The named hive's stable `_HMAP_DIRECTORY`.
const XP_STABLE_DIR: u64 = XP_KERNEL_BASE + 0x5000;
/// The named hive's stable `_HMAP_TABLE`.
const XP_STABLE_TABLE: u64 = XP_KERNEL_BASE + 0x6000;
/// The named hive's volatile `_HMAP_DIRECTORY`.
const XP_VOLATILE_DIR: u64 = XP_KERNEL_BASE + 0x8000;
/// The named hive's volatile `_HMAP_TABLE`.
const XP_VOLATILE_TABLE: u64 = XP_KERNEL_BASE + 0x9000;

/// Where the named hive's first stable bin page lives.
pub const XP_STABLE_BIN_VA: u64 = XP_KERNEL_BASE + 0xB000;
/// Where its second stable bin page lives — deliberately not next to the first.
pub const XP_STABLE_BIN_VA_1: u64 = XP_KERNEL_BASE + 0xC000;
/// Where its volatile bin page lives.
pub const VOLATILE_BIN_VA: u64 = XP_KERNEL_BASE + 0xD000;

/// The second hive's only bin page.
const XP_SECOND_BIN_VA: u64 = XP_KERNEL_BASE + 0xE000;
/// The second hive's stable `_HMAP_DIRECTORY`.
const XP_SECOND_DIR: u64 = XP_KERNEL_BASE + 0xF000;
/// The second hive's stable `_HMAP_TABLE`.
const XP_SECOND_TABLE: u64 = XP_KERNEL_BASE + 0x1_0000;

/// First of the five bin pages the big-data value is spread over.
const XP_BIG_BIN_VA: u64 = XP_KERNEL_BASE + 0x1_2000;

/// Declared length of the named hive's stable store.
pub const STABLE_LENGTH: u64 = 0x8000;
/// Declared length of the named hive's volatile store.
pub const VOLATILE_LENGTH: u64 = 0x1000;
/// Declared length of the second hive's stable store.
pub const SECOND_STABLE_LENGTH: u64 = 0x2000;

/// The named hive's root cell index.
pub const ROOT_CELL: u32 = 0x20;
/// A cell whose bin is mapped and whose bytes were never acquired.
pub const PAGED_OUT_CELL: u32 = 0x2000;
/// A cell whose signature is not one the format defines.
pub const JUNK_CELL: u32 = 0x1800;

/// Total length of the big-data value.
pub const BIG_VALUE_LEN: u64 = 0x4008;
/// How much of it the first block holds.
pub const BIG_BLOCK_LEN: u64 = 0x3FD8;

/// The path the named hive reports.
pub const XP_HIVE_PATH: &str =
    "\\Device\\HarddiskVolume1\\Documents and Settings\\Sarah\\NTUSER.DAT";

// ---------------------------------------------------------------------------
// The 64-bit fixture's address map
// ---------------------------------------------------------------------------

/// Load address of the synthetic 64-bit kernel.
pub const WIN8_KERNEL_BASE: u64 = 0xFFFF_F800_0010_0000;
/// The 64-bit fixture's `_CMHIVE`.
pub const WIN8_CMHIVE: u64 = WIN8_KERNEL_BASE + 0x2000;
/// The bin address its `_HMAP_ENTRY` names, before the block offset is added.
pub const WIN8_BIN_VA: u64 = WIN8_KERNEL_BASE + 0x8000;
/// The 64-bit fixture's root cell index.
pub const WIN8_ROOT_CELL: u32 = 0x20;

const WIN8_BASE_BLOCK: u64 = WIN8_KERNEL_BASE + 0x1000;
const WIN8_DIR: u64 = WIN8_KERNEL_BASE + 0x3000;
const WIN8_TABLE: u64 = WIN8_KERNEL_BASE + 0x5000;
const WIN8_LEN: u64 = 0x1_0000;

// ---------------------------------------------------------------------------
// Symbol tables
// ---------------------------------------------------------------------------

/// A 32-bit Windows-shaped ISF covering everything the registry tier reads.
const XP_ISF: &str = r#"{
  "metadata": {"format": "6.2.0", "producer": {"name": "seance-registry-fixture", "version": "1.0.0"},
               "windows": {}},
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "char", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "wchar": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
  },
  "user_types": {
    "_LIST_ENTRY": {"size": 8, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 4, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_UNICODE_STRING": {"size": 8, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 4, "type": {"kind": "pointer", "subtype": {"kind": "base", "name": "wchar"}}}
    }},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_HMAP_ENTRY": {"size": 16, "kind": "struct", "fields": {
      "BlockAddress": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "BinAddress": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}},
      "CmView": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},
      "MemAlloc": {"offset": 12, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_HMAP_TABLE": {"size": 8192, "kind": "struct", "fields": {
      "Table": {"offset": 0, "type": {"kind": "array", "count": 512,
                "subtype": {"kind": "struct", "name": "_HMAP_ENTRY"}}}
    }},
    "_HMAP_DIRECTORY": {"size": 4096, "kind": "struct", "fields": {
      "Directory": {"offset": 0, "type": {"kind": "array", "count": 1024,
                    "subtype": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HMAP_TABLE"}}}}
    }},
    "_DUAL": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "Map": {"offset": 4, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HMAP_DIRECTORY"}}},
      "SmallDir": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HMAP_DIRECTORY"}}},
      "Guard": {"offset": 12, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_HBASE_BLOCK": {"size": 64, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "Sequence1": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}},
      "Major": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},
      "Minor": {"offset": 12, "type": {"kind": "base", "name": "unsigned long"}},
      "Type": {"offset": 16, "type": {"kind": "base", "name": "unsigned long"}},
      "Format": {"offset": 20, "type": {"kind": "base", "name": "unsigned long"}},
      "RootCell": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}},
      "Length": {"offset": 28, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_HHIVE": {"size": 48, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "BaseBlock": {"offset": 4, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HBASE_BLOCK"}}},
      "Version": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},
      "Storage": {"offset": 12, "type": {"kind": "array", "count": 2,
                  "subtype": {"kind": "struct", "name": "_DUAL"}}}
    }},
    "_CMHIVE": {"size": 80, "kind": "struct", "fields": {
      "Hive": {"offset": 0, "type": {"kind": "struct", "name": "_HHIVE"}},
      "FileFullPath": {"offset": 48, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "FileUserName": {"offset": 56, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "HiveRootPath": {"offset": 64, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "HiveList": {"offset": 72, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
    }},
    "_CHILD_LIST": {"size": 8, "kind": "struct", "fields": {
      "Count": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "List": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_CM_KEY_NODE": {"size": 80, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "Flags": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "LastWriteTime": {"offset": 4, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "Parent": {"offset": 12, "type": {"kind": "base", "name": "unsigned long"}},
      "SubKeyCounts": {"offset": 16, "type": {"kind": "array", "count": 2,
                       "subtype": {"kind": "base", "name": "unsigned long"}}},
      "SubKeyLists": {"offset": 24, "type": {"kind": "array", "count": 2,
                      "subtype": {"kind": "base", "name": "unsigned long"}}},
      "ValueList": {"offset": 32, "type": {"kind": "struct", "name": "_CHILD_LIST"}},
      "Security": {"offset": 40, "type": {"kind": "base", "name": "unsigned long"}},
      "Class": {"offset": 44, "type": {"kind": "base", "name": "unsigned long"}},
      "MaxNameLen": {"offset": 48, "type": {"kind": "base", "name": "unsigned long"}},
      "MaxClassLen": {"offset": 52, "type": {"kind": "base", "name": "unsigned long"}},
      "MaxValueNameLen": {"offset": 56, "type": {"kind": "base", "name": "unsigned long"}},
      "MaxValueDataLen": {"offset": 60, "type": {"kind": "base", "name": "unsigned long"}},
      "WorkVar": {"offset": 64, "type": {"kind": "base", "name": "unsigned long"}},
      "NameLength": {"offset": 68, "type": {"kind": "base", "name": "unsigned short"}},
      "ClassLength": {"offset": 70, "type": {"kind": "base", "name": "unsigned short"}},
      "Name": {"offset": 72, "type": {"kind": "array", "count": 1,
               "subtype": {"kind": "base", "name": "wchar"}}}
    }},
    "_CM_KEY_INDEX": {"size": 8, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "Count": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "List": {"offset": 4, "type": {"kind": "array", "count": 1,
               "subtype": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_CM_KEY_VALUE": {"size": 24, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "NameLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "DataLength": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}},
      "Data": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},
      "Type": {"offset": 12, "type": {"kind": "base", "name": "unsigned long"}},
      "Flags": {"offset": 16, "type": {"kind": "base", "name": "unsigned short"}},
      "Spare": {"offset": 18, "type": {"kind": "base", "name": "unsigned short"}},
      "Name": {"offset": 20, "type": {"kind": "array", "count": 1,
               "subtype": {"kind": "base", "name": "wchar"}}}
    }},
    "_CM_BIG_DATA": {"size": 8, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "Count": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "List": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }}
  },
  "enums": {},
  "symbols": {
    "CmpHiveListHead": {"address": 4096, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
  }
}"#;

/// A 64-bit ISF with the Windows 8 `_HMAP_ENTRY` and no hive-list symbol.
const WIN8_ISF: &str = r#"{
  "metadata": {"format": "6.2.0", "producer": {"name": "seance-registry-fixture", "version": "1.0.0"},
               "windows": {}},
  "base_types": {
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "char", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "wchar": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
  },
  "user_types": {
    "_LIST_ENTRY": {"size": 16, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "base", "name": "wchar"}}}
    }},
    "_HMAP_ENTRY": {"size": 16, "kind": "struct", "fields": {
      "PermanentBinAddress": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}},
      "BlockOffset": {"offset": 8, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_HMAP_TABLE": {"size": 8192, "kind": "struct", "fields": {
      "Table": {"offset": 0, "type": {"kind": "array", "count": 512,
                "subtype": {"kind": "struct", "name": "_HMAP_ENTRY"}}}
    }},
    "_HMAP_DIRECTORY": {"size": 8192, "kind": "struct", "fields": {
      "Directory": {"offset": 0, "type": {"kind": "array", "count": 1024,
                    "subtype": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HMAP_TABLE"}}}}
    }},
    "_DUAL": {"size": 24, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "Map": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HMAP_DIRECTORY"}}},
      "SmallDir": {"offset": 16, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HMAP_DIRECTORY"}}}
    }},
    "_HBASE_BLOCK": {"size": 64, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "RootCell": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_HHIVE": {"size": 72, "kind": "struct", "fields": {
      "Signature": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "BaseBlock": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HBASE_BLOCK"}}},
      "Version": {"offset": 16, "type": {"kind": "base", "name": "unsigned long"}},
      "Storage": {"offset": 24, "type": {"kind": "array", "count": 2,
                  "subtype": {"kind": "struct", "name": "_DUAL"}}}
    }},
    "_CMHIVE": {"size": 136, "kind": "struct", "fields": {
      "Hive": {"offset": 0, "type": {"kind": "struct", "name": "_HHIVE"}},
      "FileFullPath": {"offset": 72, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "FileUserName": {"offset": 88, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "HiveRootPath": {"offset": 104, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "HiveList": {"offset": 120, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#;

/// A minimal ISF declaring `_HCELL` the way the hive file format does.
const HCELL_AGREEING_ISF: &str = r#"{
  "metadata": {"format": "6.2.0", "windows": {}},
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_HCELL": {"size": 12, "kind": "struct", "fields": {
      "Size": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "u": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#;

/// The same, with the cell's contents declared somewhere the format never puts
/// them.
const HCELL_DISAGREEING_ISF: &str = r#"{
  "metadata": {"format": "6.2.0", "windows": {}},
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_HCELL": {"size": 16, "kind": "struct", "fields": {
      "Size": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "u": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#;

/// An `_HCELL` that declares no `u` member at all.
///
/// The build-variant case: the type is there and the member this module would
/// cross-check against is not, so the cross-check cannot be made. Nothing about
/// the hive format changes, and the stage must run.
const HCELL_WITHOUT_CONTENTS_ISF: &str = r#"{
  "metadata": {"format": "6.2.0", "windows": {}},
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_HCELL": {"size": 4, "kind": "struct", "fields": {
      "Size": {"offset": 0, "type": {"kind": "base", "name": "long"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#;

/// A table declaring `_HCELL` without the member the cross-check reads.
pub fn hcell_table_without_contents() -> Arc<SymbolTable> {
    compile(HCELL_WITHOUT_CONTENTS_ISF)
}

/// Compile one of the fixture ISFs.
fn compile(isf: &str) -> Arc<SymbolTable> {
    let source = seance_symbols::load_slice(isf.as_bytes(), &DecompressLimits::default())
        .expect("the fixture ISF must load");
    Arc::new(
        SymbolTable::compile_source(source, &CompileOptions::default())
            .unwrap_or_else(|err| panic!("the fixture ISF must compile: {err}")),
    )
}

/// The compiled 32-bit fixture symbols.
pub fn xp_symbols() -> Arc<SymbolTable> {
    static TABLE: OnceLock<Arc<SymbolTable>> = OnceLock::new();
    Arc::clone(TABLE.get_or_init(|| compile(XP_ISF)))
}

/// The compiled 64-bit fixture symbols.
pub fn win8_symbols() -> Arc<SymbolTable> {
    static TABLE: OnceLock<Arc<SymbolTable>> = OnceLock::new();
    Arc::clone(TABLE.get_or_init(|| compile(WIN8_ISF)))
}

/// Two tables declaring `_HCELL`: one that agrees with the format and one that
/// does not.
pub fn hcell_tables() -> (Arc<SymbolTable>, Arc<SymbolTable>) {
    (compile(HCELL_AGREEING_ISF), compile(HCELL_DISAGREEING_ISF))
}

// ---------------------------------------------------------------------------
// Image building
// ---------------------------------------------------------------------------

/// The fixture image: two acquired regions with an unacquired window between.
struct Image {
    bytes: Vec<u8>,
    base: u64,
    low_len: u64,
    high_start: u64,
    high_len: u64,
}

impl Image {
    fn new(base: u64, low_len: u64, high_start: u64, high_len: u64) -> Self {
        Image {
            bytes: vec![0u8; (low_len + high_len) as usize],
            base,
            low_len,
            high_start,
            high_len,
        }
    }

    /// Where an address lives in the backing buffer, or `None` for the window.
    fn offset_of(&self, address: u64) -> Option<usize> {
        if (self.base..self.base + self.low_len).contains(&address) {
            return Some((address - self.base) as usize);
        }
        if (self.high_start..self.high_start + self.high_len).contains(&address) {
            return Some((address - self.high_start + self.low_len) as usize);
        }
        None
    }

    fn put(&mut self, address: u64, data: &[u8]) {
        for (step, byte) in data.iter().enumerate() {
            let at = address + step as u64;
            match self.offset_of(at) {
                Some(offset) => self.bytes[offset] = *byte,
                None => panic!("fixture address {at:#x} is inside the unacquired window"),
            }
        }
    }

    fn put_u16(&mut self, address: u64, value: u16) {
        self.put(address, &value.to_le_bytes());
    }

    fn put_u32(&mut self, address: u64, value: u32) {
        self.put(address, &value.to_le_bytes());
    }

    fn put_u64(&mut self, address: u64, value: u64) {
        self.put(address, &value.to_le_bytes());
    }

    fn put_utf16(&mut self, address: u64, text: &str) -> u16 {
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(units.len() * 2);
        for unit in &units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self.put(address, &bytes);
        bytes.len() as u16
    }

    fn build(self, architecture: Architecture) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(self.bytes));
        let segments = vec![
            Segment::new(0, self.base, self.low_len),
            Segment::new(self.low_len, self.high_start, self.high_len),
        ];
        Arc::new(
            SegmentedLayer::new(
                source,
                segments,
                LayerMeta::new(MemoryImageFormat::Lime).with_architecture(architecture),
            )
            .expect("a well-formed fixture segment list"),
        )
    }
}

/// Where a cell index of the named 32-bit hive lands in the image.
///
/// `None` for the page the fixture deliberately never acquired.
fn xp_hive_page(page: u64, volatile: bool) -> Option<u64> {
    if volatile {
        return if page == 0 {
            Some(VOLATILE_BIN_VA)
        } else {
            None
        };
    }
    match page {
        0 => Some(XP_STABLE_BIN_VA),
        1 => Some(XP_STABLE_BIN_VA_1),
        // Mapped by the storage map, never acquired: this is the paged-out bin.
        2 => Some(XP_HOLE_START),
        3..=7 => Some(XP_BIG_BIN_VA + (page - 3) * 0x1000),
        _ => None,
    }
}

/// Write bytes at a hive-space cell index, splitting across bin pages.
fn put_cell(image: &mut Image, index: u32, data: &[u8]) {
    let volatile = index & 0x8000_0000 != 0;
    let mut within = u64::from(index & 0x7FFF_FFFF);
    let mut written = 0usize;
    while written < data.len() {
        let page = within >> 12;
        let offset = within & 0xFFF;
        let va = xp_hive_page(page, volatile)
            .unwrap_or_else(|| panic!("fixture cell index {index:#x} has no bin page {page}"));
        let room = (0x1000 - offset) as usize;
        let take = room.min(data.len() - written);
        image.put(va + offset, &data[written..written + take]);
        written += take;
        within += take as u64;
    }
}

fn put_cell_u16(image: &mut Image, index: u32, value: u16) {
    put_cell(image, index, &value.to_le_bytes());
}

fn put_cell_u32(image: &mut Image, index: u32, value: u32) {
    put_cell(image, index, &value.to_le_bytes());
}

/// Write a `_CM_KEY_NODE` at the contents of `cell`, at the offsets the fixture
/// ISF declares.
#[allow(clippy::too_many_arguments)]
fn put_key_node(
    image: &mut Image,
    cell: u32,
    name: &str,
    compressed: bool,
    flags: u16,
    parent: u32,
    subkey_counts: [u32; 2],
    subkey_lists: [u32; 2],
    value_count: u32,
    value_list: u32,
) {
    let at = cell + 4;
    put_cell(image, at, b"nk");
    put_cell_u16(image, at + 2, flags);
    put_cell(image, at + 4, &0x01C0_0000_0000_0001i64.to_le_bytes());
    put_cell_u32(image, at + 12, parent);
    put_cell_u32(image, at + 16, subkey_counts[0]);
    put_cell_u32(image, at + 20, subkey_counts[1]);
    put_cell_u32(image, at + 24, subkey_lists[0]);
    put_cell_u32(image, at + 28, subkey_lists[1]);
    put_cell_u32(image, at + 32, value_count);
    put_cell_u32(image, at + 36, value_list);

    let name_bytes = encode_name(name, compressed);
    put_cell_u16(image, at + 68, name_bytes.len() as u16);
    put_cell(image, at + 72, &name_bytes);
}

/// Write a `_CM_KEY_VALUE` at the contents of `cell`.
#[allow(clippy::too_many_arguments)]
fn put_key_value(
    image: &mut Image,
    cell: u32,
    name: &str,
    data_length: u32,
    data: u32,
    value_type: u32,
) {
    let at = cell + 4;
    put_cell(image, at, b"vk");
    let name_bytes = encode_name(name, true);
    put_cell_u16(image, at + 2, name_bytes.len() as u16);
    put_cell_u32(image, at + 4, data_length);
    put_cell_u32(image, at + 8, data);
    put_cell_u32(image, at + 12, value_type);
    put_cell_u16(image, at + 16, 1); // VALUE_COMP_NAME
    put_cell(image, at + 20, &name_bytes);
}

/// Write a `_CM_KEY_INDEX` at the contents of `cell`.
fn put_key_index(image: &mut Image, cell: u32, signature: &[u8; 2], entries: &[u32], stride: u64) {
    let at = cell + 4;
    put_cell(image, at, signature);
    put_cell_u16(image, at + 2, entries.len() as u16);
    for (slot, entry) in entries.iter().enumerate() {
        let offset = (slot as u64 * stride * 4) as u32;
        put_cell_u32(image, at + 4 + offset, *entry);
        if stride == 2 {
            // The hint the format stores beside every entry in an lf/lh leaf.
            put_cell_u32(image, at + 8 + offset, 0xDEAD_BEEF);
        }
    }
}

/// Write a bare list of cell indices at the contents of `cell`.
fn put_index_list(image: &mut Image, cell: u32, entries: &[u32]) {
    let at = cell + 4;
    for (slot, entry) in entries.iter().enumerate() {
        put_cell_u32(image, at + (slot as u32 * 4), *entry);
    }
}

/// Encode a key or value name the way the flag says it is stored.
fn encode_name(name: &str, compressed: bool) -> Vec<u8> {
    if compressed {
        name.bytes().collect()
    } else {
        let mut bytes = Vec::new();
        for unit in name.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }
}

/// Write a `_CMHIVE` header: the `_HHIVE` and its two stores.
fn put_cmhive(
    image: &mut Image,
    at: u64,
    signature: u32,
    base_block: u64,
    stable: (u64, u64),
    volatile: (u64, u64),
) {
    image.put_u32(at, signature);
    image.put_u32(at + 4, base_block as u32);
    image.put_u32(at + 8, 5); // Version
    image.put_u32(at + 12, stable.0 as u32); // Storage[0].Length
    image.put_u32(at + 16, stable.1 as u32); // Storage[0].Map
    image.put_u32(at + 28, volatile.0 as u32); // Storage[1].Length
    image.put_u32(at + 32, volatile.1 as u32); // Storage[1].Map
}

/// Point `_HMAP_DIRECTORY.Directory[slot]` at a table.
fn put_directory_slot(image: &mut Image, directory: u64, slot: u64, table: u64) {
    image.put_u32(directory + slot * 4, table as u32);
}

/// Fill in one pre-Windows-8 `_HMAP_ENTRY`.
fn put_map_entry(image: &mut Image, table: u64, slot: u64, block: u64) {
    image.put_u32(table + slot * 16, block as u32);
}

/// The 32-bit fixture image.
///
/// `broken_forward` rewires the hive list so that following `Flink` runs into
/// the unacquired window, which is what an unreadable `_CMHIVE` does to a real
/// walk.
fn xp_image(broken_forward: bool) -> Arc<dyn MemoryLayer> {
    let mut image = Image::new(XP_KERNEL_BASE, XP_LOW_LEN, XP_HIGH_START, XP_HIGH_LEN);

    // --- the hive list -----------------------------------------------------
    let link = |cmhive: u64| cmhive + 72;
    let broken_link = XP_HOLE_START + 72;
    if broken_forward {
        image.put_u32(XP_HIVE_LIST_HEAD, link(XP_CMHIVE) as u32);
        image.put_u32(XP_HIVE_LIST_HEAD + 4, link(XP_UNNAMED_CMHIVE) as u32);
        image.put_u32(link(XP_CMHIVE), broken_link as u32);
        image.put_u32(link(XP_CMHIVE) + 4, XP_HIVE_LIST_HEAD as u32);
        image.put_u32(link(XP_UNNAMED_CMHIVE), XP_HIVE_LIST_HEAD as u32);
        image.put_u32(link(XP_UNNAMED_CMHIVE) + 4, broken_link as u32);
    } else {
        image.put_u32(XP_HIVE_LIST_HEAD, link(XP_CMHIVE) as u32);
        image.put_u32(XP_HIVE_LIST_HEAD + 4, link(XP_JUNK_CMHIVE) as u32);
        image.put_u32(link(XP_CMHIVE), link(XP_UNNAMED_CMHIVE) as u32);
        image.put_u32(link(XP_CMHIVE) + 4, XP_HIVE_LIST_HEAD as u32);
        image.put_u32(link(XP_UNNAMED_CMHIVE), link(XP_JUNK_CMHIVE) as u32);
        image.put_u32(link(XP_UNNAMED_CMHIVE) + 4, link(XP_CMHIVE) as u32);
        image.put_u32(link(XP_JUNK_CMHIVE), XP_HIVE_LIST_HEAD as u32);
        image.put_u32(link(XP_JUNK_CMHIVE) + 4, link(XP_UNNAMED_CMHIVE) as u32);
    }

    // --- the named hive ----------------------------------------------------
    put_cmhive(
        &mut image,
        XP_CMHIVE,
        0xBEE0_BEE0,
        XP_BASE_BLOCK,
        (STABLE_LENGTH, XP_STABLE_DIR),
        (VOLATILE_LENGTH, XP_VOLATILE_DIR),
    );
    let name_len = image.put_utf16(XP_NAME_BUFFER, XP_HIVE_PATH);
    image.put_u16(XP_CMHIVE + 48, name_len); // FileFullPath.Length
    image.put_u16(XP_CMHIVE + 50, name_len);
    image.put_u32(XP_CMHIVE + 52, XP_NAME_BUFFER as u32);

    image.put_u32(XP_BASE_BLOCK, 0x6667_6572); // "regf"
    image.put_u32(XP_BASE_BLOCK + 24, ROOT_CELL);

    put_directory_slot(&mut image, XP_STABLE_DIR, 0, XP_STABLE_TABLE);
    for page in 0..8u64 {
        if let Some(va) = xp_hive_page(page, false) {
            put_map_entry(&mut image, XP_STABLE_TABLE, page, va);
        }
    }
    put_directory_slot(&mut image, XP_VOLATILE_DIR, 0, XP_VOLATILE_TABLE);
    put_map_entry(&mut image, XP_VOLATILE_TABLE, 0, VOLATILE_BIN_VA);

    // --- the second hive ---------------------------------------------------
    // Its base block is in the unacquired window, so its root has to be probed
    // rather than read, and its only subkey index is in there too.
    put_cmhive(
        &mut image,
        XP_UNNAMED_CMHIVE,
        0xBEE0_BEE0,
        XP_HOLE_START + 0x800,
        (SECOND_STABLE_LENGTH, XP_SECOND_DIR),
        (0, 0),
    );
    put_directory_slot(&mut image, XP_SECOND_DIR, 0, XP_SECOND_TABLE);
    put_map_entry(&mut image, XP_SECOND_TABLE, 0, XP_SECOND_BIN_VA);
    put_map_entry(&mut image, XP_SECOND_TABLE, 1, XP_HOLE_START);
    // Its root key, written directly because it lives in a different hive's
    // address space from everything `put_cell` knows about.
    image.put(XP_SECOND_BIN_VA + 0x24, b"nk");
    image.put_u16(XP_SECOND_BIN_VA + 0x26, 0x24); // KEY_HIVE_ENTRY | KEY_COMP_NAME
    image.put_u32(XP_SECOND_BIN_VA + 0x30, 0xFFFF_FFFF); // Parent
    image.put_u32(XP_SECOND_BIN_VA + 0x34, 1); // SubKeyCounts[0]
    image.put_u32(XP_SECOND_BIN_VA + 0x3C, 0x1000); // SubKeyLists[0] -> the window
    image.put_u32(XP_SECOND_BIN_VA + 0x40, 0xFFFF_FFFF); // SubKeyLists[1]
    image.put_u32(XP_SECOND_BIN_VA + 0x44, 0); // ValueList.Count
    image.put_u32(XP_SECOND_BIN_VA + 0x48, 0xFFFF_FFFF); // ValueList.List
    image.put_u16(XP_SECOND_BIN_VA + 0x68, 6); // NameLength
    image.put(XP_SECOND_BIN_VA + 0x6C, b"SECOND");

    // --- the structure on the list that is not a hive ----------------------
    put_cmhive(
        &mut image,
        XP_JUNK_CMHIVE,
        0x1234_5678,
        XP_BASE_BLOCK,
        (STABLE_LENGTH, XP_STABLE_DIR),
        (VOLATILE_LENGTH, XP_VOLATILE_DIR),
    );

    // --- the named hive's cells -------------------------------------------
    put_key_node(
        &mut image,
        ROOT_CELL,
        "ROOT",
        true,
        0x0024, // KEY_HIVE_ENTRY | KEY_COMP_NAME
        0xFFFF_FFFF,
        [3, 1],
        [0x1010, 0x8000_0020],
        0,
        0xFFFF_FFFF,
    );
    put_key_node(
        &mut image,
        0x0100,
        "Sarah",
        true,
        0x0020,
        ROOT_CELL,
        [0, 0],
        [0xFFFF_FFFF, 0xFFFF_FFFF],
        4,
        0x0400,
    );
    // A key whose subkey count outlives the index that used to reach its child.
    put_key_node(
        &mut image,
        0x0200,
        "Test",
        false,
        0x0000,
        ROOT_CELL,
        [1, 0],
        [0xFFFF_FFFF, 0xFFFF_FFFF],
        0,
        0xFFFF_FFFF,
    );
    put_key_index(&mut image, 0x0300, b"lf", &[0x0100, 0x0200], 2);

    put_index_list(&mut image, 0x0400, &[0x0500, 0x0600, 0x0700, 0x0800]);
    put_key_value(&mut image, 0x0500, "Path", 8, 0x0900, 1); // REG_SZ
    put_key_value(&mut image, 0x0600, "Count", 0x8000_0004, 0x2A, 4); // inline REG_DWORD
    put_key_value(&mut image, 0x0700, "", 16, PAGED_OUT_CELL, 3); // REG_BINARY, paged out
    put_key_value(&mut image, 0x0800, "List", 8, 0x0A00, 7); // REG_MULTI_SZ
    put_cell(&mut image, 0x0904, &utf16(&["abc"]));
    put_cell(&mut image, 0x0A04, &utf16(&["a", "b"]));

    // The page boundary: two bytes at the end of page 0 and two at the start of
    // page 1, which are nowhere near each other in memory.
    put_cell(&mut image, 0x0FFE, &[0xAA, 0xAA]);
    put_cell(&mut image, 0x1000, &[0xBB, 0xBB]);

    put_key_index(&mut image, 0x1010, b"ri", &[0x0300, 0x1100], 1);
    put_key_index(&mut image, 0x1100, b"lh", &[0x1200], 2);
    put_key_node(
        &mut image,
        0x1200,
        "Hashed",
        true,
        0x0020,
        ROOT_CELL,
        [0, 0],
        [0xFFFF_FFFF, 0xFFFF_FFFF],
        1,
        0x1300,
    );
    put_index_list(&mut image, 0x1300, &[0x1400]);
    put_key_value(
        &mut image,
        0x1400,
        "Big",
        BIG_VALUE_LEN as u32,
        0x1500,
        3, // REG_BINARY
    );
    // The big-data record and its two blocks.
    put_cell(&mut image, 0x1504, b"db");
    put_cell_u16(&mut image, 0x1506, 2);
    put_cell_u32(&mut image, 0x1508, 0x1600);
    put_index_list(&mut image, 0x1600, &[0x3000, 0x7000]);
    put_cell(&mut image, 0x3004, &vec![0x11u8; BIG_BLOCK_LEN as usize]);
    put_cell(
        &mut image,
        0x7004,
        &vec![0x22u8; (BIG_VALUE_LEN - BIG_BLOCK_LEN) as usize],
    );

    // A cell whose signature the format does not define.
    put_cell(&mut image, JUNK_CELL + 4, &[0xFF, 0xFF]);

    // --- the volatile store ------------------------------------------------
    put_key_index(&mut image, 0x8000_0020, b"li", &[0x8000_0100], 1);
    put_key_node(
        &mut image,
        0x8000_0100,
        "Volatile",
        true,
        0x0021, // KEY_IS_VOLATILE | KEY_COMP_NAME
        ROOT_CELL,
        [0, 0],
        [0xFFFF_FFFF, 0xFFFF_FFFF],
        0,
        0xFFFF_FFFF,
    );

    image.build(Architecture::X86)
}

/// UTF-16LE bytes for a list of strings, each terminated with a NUL unit.
///
/// One string gives `REG_SZ`'s single terminated string; several give
/// `REG_MULTI_SZ`'s NUL-separated run.
fn utf16(parts: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        for unit in part.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes
}

/// The 64-bit fixture image.
fn win8_image() -> Arc<dyn MemoryLayer> {
    let mut image = Image::new(
        WIN8_KERNEL_BASE,
        WIN8_LEN,
        WIN8_KERNEL_BASE + WIN8_LEN + 0x1000,
        0x1000,
    );

    // _HHIVE
    image.put_u32(WIN8_CMHIVE, 0xBEE0_BEE0);
    image.put_u64(WIN8_CMHIVE + 8, WIN8_BASE_BLOCK);
    image.put_u32(WIN8_CMHIVE + 16, 5);
    // Storage[0]
    image.put_u32(WIN8_CMHIVE + 24, 0x2000);
    image.put_u64(WIN8_CMHIVE + 32, WIN8_DIR);
    // Storage[1] stays zero: no volatile store at all.

    image.put_u32(WIN8_BASE_BLOCK, 0x6667_6572);
    image.put_u32(WIN8_BASE_BLOCK + 24, WIN8_ROOT_CELL);

    image.put_u64(WIN8_DIR, WIN8_TABLE);
    // The Windows 8 shape: a bin address with flag bits in the bottom nibble,
    // and the block's offset inside that bin held separately.
    image.put_u64(WIN8_TABLE, WIN8_BIN_VA | 0xB);
    image.put_u64(WIN8_TABLE + 8, 0x1000);

    image.put(WIN8_BIN_VA + 0x1000 + 0x24, b"nk");

    image.build(Architecture::X64)
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

fn profile_for(
    layer: Arc<dyn MemoryLayer>,
    symbols: Arc<SymbolTable>,
    kernel_base: u64,
    architecture: Architecture,
) -> WindowsProfile {
    WindowsProfile {
        kernel_space: Arc::clone(&layer),
        physical: layer,
        symbols,
        pagefiles: Vec::new(),
        dtb: Found::new(0x39000, Evidence::Confirmed),
        kernel_base: Found::new(kernel_base, Evidence::Confirmed),
        kdbg: None,
        build: KernelBuild {
            pdb: "ntoskrnl.pdb".to_string(),
            guid: "0".repeat(32),
            age: 1,
            build_lab: None,
            major: 5,
            minor: 1,
            build: Some(2600),
            build_source: None,
        },
        architecture,
    }
}

/// The 32-bit fixture: two hives, a rejected structure, a volatile store, all
/// four subkey-index formats, and an unacquired bin.
pub fn xp_profile() -> WindowsProfile {
    static LAYER: OnceLock<Arc<dyn MemoryLayer>> = OnceLock::new();
    let layer = Arc::clone(LAYER.get_or_init(|| xp_image(false)));
    profile_for(layer, xp_symbols(), XP_KERNEL_BASE, Architecture::X86)
}

/// The same kernel with the hive list rewired so that walking it forwards runs
/// into the unacquired window.
pub fn broken_forward_profile() -> WindowsProfile {
    static LAYER: OnceLock<Arc<dyn MemoryLayer>> = OnceLock::new();
    let layer = Arc::clone(LAYER.get_or_init(|| xp_image(true)));
    profile_for(layer, xp_symbols(), XP_KERNEL_BASE, Architecture::X86)
}

/// The 64-bit fixture, with the Windows 8 `_HMAP_ENTRY` shape.
pub fn win8_profile() -> WindowsProfile {
    static LAYER: OnceLock<Arc<dyn MemoryLayer>> = OnceLock::new();
    let layer = Arc::clone(LAYER.get_or_init(win8_image));
    profile_for(layer, win8_symbols(), WIN8_KERNEL_BASE, Architecture::X64)
}
