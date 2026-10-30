//! Hand-built fixtures for the execution-history stage.
//!
//! Two kinds, because the stage has two halves that fail in different ways:
//!
//! * **Registry values.** The Amcache decoder's job is to turn a key's values
//!   into fields, and every interesting case — a value whose data page was
//!   never acquired, a `REG_BINARY` holding UTF-16, a four-byte value where a
//!   FILETIME belongs — is a property of one value. Building those directly is
//!   the only way to test each one in isolation; building a synthetic hive per
//!   case would test the hive reader instead.
//! * **A synthetic Windows 10 x64 kernel.** The Shimcache half is a sweep, and
//!   a sweep can only be tested against bytes laid out at known addresses. The
//!   fixture puts a loaded `ahcache.sys` with real PE section headers, two
//!   `SHIM_CACHE_HANDLE` structures in its `.data` — because a real image has
//!   two and picking the wrong one is the failure this stage exists to avoid —
//!   an `_ERESOURCE` and an `_RTL_AVL_TABLE` behind each, and a three-entry LRU
//!   list behind the second.
//!
//! Nothing here is captured. Every structure is written at an address chosen by
//! hand, so a test asserting that the third entry's execution flag is
//! *unreadable* is asserting against a blob pointer that deliberately addresses
//! memory outside the image.

use seance_memory::Architecture;

use crate::amcache::shim::SectionRange;
use crate::poolscan::test_support::{profile, table, Image};
use crate::profile::WindowsProfile;
use crate::registry::key::{
    KeyNode, KeyValue, RegName, RegText, RegValueType, RegistryData, ValueData, Values,
};
use crate::registry::space::CellIndex;

// ---------------------------------------------------------------------------
// Registry values
// ---------------------------------------------------------------------------

/// A key node with a name and a `LastWriteTime`, and nothing else set.
///
/// Every other member is the format's "no cell" marker, so a decoder that
/// reached for one would fail rather than read a plausible-looking zero.
pub(crate) fn key_node(name: &str, last_write_time: i64) -> KeyNode {
    KeyNode {
        cell: CellIndex::new(0x20),
        flags: 0x0020,
        last_write_time,
        parent: CellIndex::new(0xFFFF_FFFF),
        name: RegName::decode(name.as_bytes().to_vec(), true),
        subkey_counts: [0, 0],
        subkey_lists: [CellIndex::new(0xFFFF_FFFF), CellIndex::new(0xFFFF_FFFF)],
        value_count: 0,
        value_list: CellIndex::new(0xFFFF_FFFF),
    }
}

/// A complete, readable value list.
pub(crate) fn values_of(values: Vec<KeyValue>) -> Values {
    Values {
        declared: values.len() as u64,
        values,
        incomplete: Vec::new(),
    }
}

/// A key that carries no values at all.
pub(crate) fn empty_values() -> Values {
    values_of(Vec::new())
}

/// One `REG_SZ` value.
pub(crate) fn sz_value(name: &str, text: &str) -> KeyValue {
    let mut raw = Vec::new();
    for unit in text.encode_utf16() {
        raw.extend_from_slice(&unit.to_le_bytes());
    }
    raw.extend_from_slice(&[0, 0]);
    KeyValue {
        cell: CellIndex::new(0x100),
        name: RegName::decode(name.as_bytes().to_vec(), true),
        value_type: RegValueType::Sz,
        raw_type: 1,
        declared_len: raw.len() as u64,
        inline: false,
        data: ValueData::Available {
            raw,
            decoded: RegistryData::Text(RegText {
                text: text.to_string(),
                well_formed: true,
            }),
        },
    }
}

/// One `REG_QWORD` value.
pub(crate) fn qword_value(name: &str, value: u64) -> KeyValue {
    KeyValue {
        cell: CellIndex::new(0x100),
        name: RegName::decode(name.as_bytes().to_vec(), true),
        value_type: RegValueType::Qword,
        raw_type: 11,
        declared_len: 8,
        inline: false,
        data: ValueData::Available {
            raw: value.to_le_bytes().to_vec(),
            decoded: RegistryData::Qword(value),
        },
    }
}

/// One `REG_BINARY` value holding exactly `raw`.
pub(crate) fn binary_value(name: &str, raw: Vec<u8>) -> KeyValue {
    KeyValue {
        cell: CellIndex::new(0x100),
        name: RegName::decode(name.as_bytes().to_vec(), true),
        value_type: RegValueType::Binary,
        raw_type: 3,
        declared_len: raw.len() as u64,
        inline: false,
        data: ValueData::Available {
            raw,
            decoded: RegistryData::Binary,
        },
    }
}

/// A value that is present in the key and whose data page was never acquired.
///
/// The case that must never render like an empty value: the machine recorded
/// something and the acquisition did not capture it.
pub(crate) fn unavailable_value(name: &str) -> KeyValue {
    KeyValue {
        cell: CellIndex::new(0x100),
        name: RegName::decode(name.as_bytes().to_vec(), true),
        value_type: RegValueType::Sz,
        raw_type: 1,
        declared_len: 32,
        inline: false,
        data: ValueData::Unavailable(seance_memory::Incomplete::new(
            seance_core::io::IncompleteReason::ShortRead,
            "the data cell's page was never acquired",
        )),
    }
}

// ---------------------------------------------------------------------------
// The synthetic Windows 10 x64 kernel
// ---------------------------------------------------------------------------

/// Where the loaded-module list head is.
const MODULE_LIST_HEAD: u64 = 0x0100;
/// The `_LDR_DATA_TABLE_ENTRY` for `ahcache.sys`.
const LDR_ENTRY: u64 = 0x0200;
/// Its `FullDllName` buffer.
const FULL_NAME: u64 = 0x0300;
/// Its `BaseDllName` buffer.
const BASE_NAME: u64 = 0x0380;

/// Where `ahcache.sys` is loaded.
const MODULE_BASE: u64 = 0x1000;
/// Offset of the NT headers inside the image.
const LFANEW: u64 = 0x80;
/// Declared size of the optional header, which the section table follows.
const OPTIONAL_HEADER_SIZE: u64 = 0xF0;

/// The `.data` section, as a relative virtual address and size.
const DATA_RVA: u64 = 0x2000;
const DATA_SIZE: u64 = 0x200;
/// The `PAGE` section, which the AVL routines must point into.
const PAGE_RVA: u64 = 0x4000;
const PAGE_SIZE: u64 = 0x400;

/// The two `SHIM_CACHE_HANDLE` structures.
const HANDLE_A: u64 = 0x6000;
const HANDLE_B: u64 = 0x7000;
/// Where the pointers to them sit inside `.data`.
const HANDLE_A_SLOT: u64 = MODULE_BASE + DATA_RVA + 0x40;
const HANDLE_B_SLOT: u64 = MODULE_BASE + DATA_RVA + 0x80;

/// The two `_ERESOURCE`s.
const ERESOURCE_A: u64 = 0x8000;
const ERESOURCE_B: u64 = 0x8200;
/// The two `_RTL_AVL_TABLE`s.
const AVL_A: u64 = 0x9000;
const AVL_B: u64 = 0xA000;
/// `sizeof(_RTL_AVL_TABLE)` in the fixture ISF, which is the real x64 size.
const AVL_SIZE: u64 = 104;

/// The three cache entries.
const ENTRY_1: u64 = 0xB000;
const ENTRY_2: u64 = 0xB100;
const ENTRY_3: u64 = 0xB200;
/// Their detail records.
const DETAIL_1: u64 = 0xC000;
const DETAIL_2: u64 = 0xC100;
const DETAIL_3: u64 = 0xC200;
/// Their shim blobs. The third addresses memory outside the image on purpose,
/// so that "the flag could not be read" can be told from "it did not execute".
const BLOB_1: u64 = 0xD000;
const BLOB_2: u64 = 0xD100;
const BLOB_UNREADABLE: u64 = 0x0003_0000;
/// Their path buffers.
const PATH_1: u64 = 0xE000;
const PATH_2: u64 = 0xE100;
const PATH_3: u64 = 0xE200;

/// The `LastModified` FILETIME on the first entry: 2021-06-01T00:00:00Z.
const MODIFIED_1: u64 = 132_669_792_000_000_000;

/// A synthetic 64-bit kernel with the types the Shimcache sweep measures
/// against, all at their real x64 offsets.
fn shim_isf() -> &'static str {
    r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-shim-fixture", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "CC1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": {
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"},
    "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
  },
  "user_types": {
    "_LIST_ENTRY": {"size": 16, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 8, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_RTL_BALANCED_LINKS": {"size": 32, "kind": "struct", "fields": {
      "Parent": {"offset": 0, "type": {"kind": "pointer",
                 "subtype": {"kind": "struct", "name": "_RTL_BALANCED_LINKS"}}},
      "LeftChild": {"offset": 8, "type": {"kind": "pointer",
                    "subtype": {"kind": "struct", "name": "_RTL_BALANCED_LINKS"}}},
      "RightChild": {"offset": 16, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_RTL_BALANCED_LINKS"}}},
      "Balance": {"offset": 24, "type": {"kind": "base", "name": "unsigned char"}}
    }},
    "_RTL_AVL_TABLE": {"size": 104, "kind": "struct", "fields": {
      "BalancedRoot": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_BALANCED_LINKS"}},
      "OrderedPointer": {"offset": 32, "type": {"kind": "pointer",
                         "subtype": {"kind": "base", "name": "void"}}},
      "NumberGenericTableElements": {"offset": 44,
                                     "type": {"kind": "base", "name": "unsigned long"}},
      "DepthOfTree": {"offset": 48, "type": {"kind": "base", "name": "unsigned long"}},
      "CompareRoutine": {"offset": 72, "type": {"kind": "pointer",
                         "subtype": {"kind": "base", "name": "void"}}},
      "AllocateRoutine": {"offset": 80, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "void"}}},
      "FreeRoutine": {"offset": 88, "type": {"kind": "pointer",
                      "subtype": {"kind": "base", "name": "void"}}},
      "TableContext": {"offset": 96, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "void"}}}
    }},
    "_KSEMAPHORE": {"size": 32, "kind": "struct", "fields": {
      "Limit": {"offset": 24, "type": {"kind": "base", "name": "long"}}
    }},
    "_ERESOURCE": {"size": 104, "kind": "struct", "fields": {
      "SystemResourcesList": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "OwnerTable": {"offset": 16, "type": {"kind": "pointer",
                     "subtype": {"kind": "base", "name": "void"}}},
      "ActiveCount": {"offset": 24, "type": {"kind": "base", "name": "unsigned short"}},
      "Flag": {"offset": 26, "type": {"kind": "base", "name": "unsigned short"}},
      "SharedWaiters": {"offset": 40, "type": {"kind": "pointer",
                        "subtype": {"kind": "struct", "name": "_KSEMAPHORE"}}},
      "ExclusiveWaiters": {"offset": 48, "type": {"kind": "pointer",
                           "subtype": {"kind": "base", "name": "void"}}},
      "NumberOfSharedWaiters": {"offset": 72, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_LDR_DATA_TABLE_ENTRY": {"size": 128, "kind": "struct", "fields": {
      "InLoadOrderLinks": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DllBase": {"offset": 48, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "void"}}},
      "SizeOfImage": {"offset": 64, "type": {"kind": "base", "name": "unsigned long"}},
      "FullDllName": {"offset": 72, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "BaseDllName": {"offset": 88, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }}
  },
  "enums": {},
  "symbols": {
    "PsLoadedModuleList": {"address": 256}
  }
}"#
}

/// Everything a Shimcache test needs to know about the fixture.
pub(crate) struct ShimFixture {
    /// The profile the stage runs against.
    pub(crate) profile: WindowsProfile,
    /// Where the host module is loaded.
    pub(crate) module_base: u64,
    /// Its `.data` section.
    pub(crate) data_section: SectionRange,
    /// Its `PAGE` section.
    pub(crate) page_section: SectionRange,
    /// The paths the three entries hold, in list order.
    pub(crate) expected_paths: Vec<String>,
    /// The first entry's `LastModified` FILETIME.
    pub(crate) expected_modified: u64,
}

/// Build the synthetic Windows 10 x64 image.
pub(crate) fn shim_fixture() -> ShimFixture {
    let mut image = Image::new();
    let paths = [
        "\\??\\C:\\Windows\\System32\\evil.exe",
        "\\??\\C:\\Users\\Sarah\\Downloads\\dropper.exe",
        "\\??\\C:\\Temp\\third.exe",
    ];

    // --- the loaded-module list --------------------------------------------
    image.put_u64(MODULE_LIST_HEAD, LDR_ENTRY);
    image.put_u64(MODULE_LIST_HEAD + 8, LDR_ENTRY);
    image.put_u64(LDR_ENTRY, MODULE_LIST_HEAD);
    image.put_u64(LDR_ENTRY + 8, MODULE_LIST_HEAD);
    image.put_u64(LDR_ENTRY + 48, MODULE_BASE);
    image.put_u32(LDR_ENTRY + 64, 0x6000);
    put_unicode(
        &mut image,
        LDR_ENTRY + 72,
        FULL_NAME,
        "\\SystemRoot\\System32\\drivers\\ahcache.sys",
    );
    put_unicode(&mut image, LDR_ENTRY + 88, BASE_NAME, "ahcache.sys");

    // --- the PE headers ----------------------------------------------------
    let nt = MODULE_BASE + LFANEW;
    image.write(MODULE_BASE, b"MZ");
    image.put_u32(MODULE_BASE + 0x3C, LFANEW as u32);
    image.write(nt, b"PE\0\0");
    image.put_u16(nt + 4, 0x8664); // Machine
    image.put_u16(nt + 6, 2); // NumberOfSections
    image.put_u16(nt + 0x14, OPTIONAL_HEADER_SIZE as u16);
    let table = nt + 0x18 + OPTIONAL_HEADER_SIZE;
    put_section(&mut image, table, ".data", DATA_RVA, DATA_SIZE);
    put_section(&mut image, table + 0x28, "PAGE", PAGE_RVA, PAGE_SIZE);

    // --- the two anchors ---------------------------------------------------
    image.put_u64(HANDLE_A_SLOT, HANDLE_A);
    image.put_u64(HANDLE_B_SLOT, HANDLE_B);
    image.put_u64(HANDLE_A, ERESOURCE_A);
    image.put_u64(HANDLE_A + 8, AVL_A);
    image.put_u64(HANDLE_B, ERESOURCE_B);
    image.put_u64(HANDLE_B + 8, AVL_B);

    put_eresource(
        &mut image,
        ERESOURCE_A,
        ERESOURCE_A + 0x100,
        ERESOURCE_A + 0x180,
    );
    put_eresource(
        &mut image,
        ERESOURCE_B,
        ERESOURCE_B + 0x100,
        ERESOURCE_B + 0x180,
    );

    let page_base = MODULE_BASE + PAGE_RVA;
    put_avl_table(&mut image, AVL_A, page_base);
    put_avl_table(&mut image, AVL_B, page_base);

    // Anchor A's list is empty: a valid head that yields no entries, which is
    // what the compatibility-database cache looks like on a fresh boot.
    let head_a = AVL_A + AVL_SIZE;
    image.put_u64(head_a, head_a);
    image.put_u64(head_a + 8, head_a);

    // Anchor B holds the Shimcache: three entries, most recent first.
    let head_b = AVL_B + AVL_SIZE;
    let entries = [ENTRY_1, ENTRY_2, ENTRY_3];
    image.put_u64(head_b, ENTRY_1);
    image.put_u64(head_b + 8, ENTRY_3);
    for (index, entry) in entries.iter().enumerate() {
        let next = entries.get(index + 1).copied().unwrap_or(head_b);
        let previous = if index == 0 {
            head_b
        } else {
            entries[index - 1]
        };
        image.put_u64(*entry, next);
        image.put_u64(*entry + 8, previous);
    }

    let details = [DETAIL_1, DETAIL_2, DETAIL_3];
    let buffers = [PATH_1, PATH_2, PATH_3];
    for index in 0..3 {
        // `SHIM_CACHE_ENTRY` on Windows 10 x64: the path at 0x18 and the
        // pointer to the detail record at 0x28.
        put_unicode(
            &mut image,
            entries[index] + 0x18,
            buffers[index],
            paths[index],
        );
        image.put_u64(entries[index] + 0x28, details[index]);
    }

    // `SHIM_CACHE_ENTRY_DETAIL`: LastModified at 8, BlobSize at 0x10 and
    // BlobBuffer at 0x18. Windows 10 x64 carries no InsertFlags, so the
    // execution flag is the first four bytes of the blob.
    image.put_u64(DETAIL_1 + 8, MODIFIED_1);
    image.put_u32(DETAIL_1 + 0x10, 4);
    image.put_u64(DETAIL_1 + 0x18, BLOB_1);
    image.put_u32(BLOB_1, 1);

    image.put_u64(DETAIL_2 + 8, MODIFIED_1 + 10_000_000);
    image.put_u32(DETAIL_2 + 0x10, 4);
    image.put_u64(DETAIL_2 + 0x18, BLOB_2);
    image.put_u32(BLOB_2, 0);

    image.put_u64(DETAIL_3 + 8, MODIFIED_1 + 20_000_000);
    image.put_u32(DETAIL_3 + 0x10, 4);
    image.put_u64(DETAIL_3 + 0x18, BLOB_UNREADABLE);

    ShimFixture {
        profile: profile(
            image.layer(),
            table_for_shim(),
            Architecture::X64,
            10,
            0,
            // Windows 10 20H1, which selects the `windows-10-x64` layout and
            // `ahcache.sys` as the host module.
            Some(19_041),
        ),
        module_base: MODULE_BASE,
        data_section: SectionRange {
            start: MODULE_BASE + DATA_RVA,
            end: MODULE_BASE + DATA_RVA + DATA_SIZE,
        },
        page_section: SectionRange {
            start: page_base,
            end: page_base + PAGE_SIZE,
        },
        expected_paths: paths.iter().map(|path| (*path).to_string()).collect(),
        expected_modified: MODIFIED_1,
    }
}

/// Build a synthetic Windows 7 x64 image, whose Shimcache is anchored the other
/// way: an `_RTL_AVL_TABLE` embedded in the kernel's own `.data` with the lock
/// in front of it at an offset that has to be *computed*, not searched for.
///
/// The second discovery strategy is a different piece of code from the Windows
/// 8-and-later one, and an image that only exercised the newer one would leave
/// every pre-Windows-8 machine covered by code nothing had ever run.
pub(crate) fn inline_shim_fixture() -> ShimFixture {
    // The lock's address is `table - (sizeof(_ERESOURCE) + ((table -
    // sizeof(_ERESOURCE)) % 0x20))`. With a 104-byte `_ERESOURCE` and a table
    // at 0x3100 that is 0x3100 - 0x80, so the fixture puts it exactly there:
    // a lock anywhere else must not validate this table.
    const ERESOURCE: u64 = 0x3080;
    const AVL: u64 = 0x3100;
    const RING_A: u64 = 0x3F00;
    const RING_B: u64 = 0x3F80;
    const ENTRY_A: u64 = 0x6000;
    const ENTRY_B: u64 = 0x6100;
    const PATH_A: u64 = 0x7000;
    const PATH_B: u64 = 0x7100;
    /// `.data` has to reach past the list head at `AVL + 104`.
    const DATA_LEN: u64 = 0x400;

    let mut image = Image::new();
    let paths = [
        "\\??\\C:\\Windows\\System32\\net.exe",
        "\\??\\C:\\Users\\Sarah\\AppData\\Local\\Temp\\stage2.exe",
    ];

    // The kernel on the loaded-module list.
    image.put_u64(MODULE_LIST_HEAD, LDR_ENTRY);
    image.put_u64(MODULE_LIST_HEAD + 8, LDR_ENTRY);
    image.put_u64(LDR_ENTRY, MODULE_LIST_HEAD);
    image.put_u64(LDR_ENTRY + 8, MODULE_LIST_HEAD);
    image.put_u64(LDR_ENTRY + 48, MODULE_BASE);
    image.put_u32(LDR_ENTRY + 64, 0x6000);
    put_unicode(
        &mut image,
        LDR_ENTRY + 72,
        FULL_NAME,
        "\\SystemRoot\\system32\\ntoskrnl.exe",
    );
    put_unicode(&mut image, LDR_ENTRY + 88, BASE_NAME, "ntoskrnl.exe");

    let nt = MODULE_BASE + LFANEW;
    image.write(MODULE_BASE, b"MZ");
    image.put_u32(MODULE_BASE + 0x3C, LFANEW as u32);
    image.write(nt, b"PE\0\0");
    image.put_u16(nt + 4, 0x8664);
    image.put_u16(nt + 6, 2);
    image.put_u16(nt + 0x14, OPTIONAL_HEADER_SIZE as u16);
    let table = nt + 0x18 + OPTIONAL_HEADER_SIZE;
    put_section(&mut image, table, ".data", DATA_RVA, DATA_LEN);
    put_section(&mut image, table + 0x28, "PAGE", PAGE_RVA, PAGE_SIZE);

    let page_base = MODULE_BASE + PAGE_RVA;
    put_eresource(&mut image, ERESOURCE, RING_A, RING_B);
    put_avl_table(&mut image, AVL, page_base);

    // `SHIM_CACHE_ENTRY` on Windows 7 x64: the path at 0x10, the timestamp at
    // 0x20 and the insert flags at 0x28, all inline — no detail record.
    let head = AVL + AVL_SIZE;
    image.put_u64(head, ENTRY_A);
    image.put_u64(head + 8, ENTRY_B);
    image.put_u64(ENTRY_A, ENTRY_B);
    image.put_u64(ENTRY_A + 8, head);
    image.put_u64(ENTRY_B, head);
    image.put_u64(ENTRY_B + 8, ENTRY_A);
    put_unicode(&mut image, ENTRY_A + 0x10, PATH_A, paths[0]);
    put_unicode(&mut image, ENTRY_B + 0x10, PATH_B, paths[1]);
    image.put_u64(ENTRY_A + 0x20, MODIFIED_1);
    image.put_u64(ENTRY_B + 0x20, MODIFIED_1 + 10_000_000);
    // Bit 1 of InsertFlags is the shim engine saying it watched the file run.
    image.put_u32(ENTRY_A + 0x28, 0x2);
    image.put_u32(ENTRY_B + 0x28, 0x0);

    ShimFixture {
        profile: profile(
            image.layer(),
            table_for_shim(),
            Architecture::X64,
            6,
            1,
            // Windows 7 SP1, which selects the `windows-7-x64` layout, the
            // inline anchor and the kernel as the host module.
            Some(7_601),
        ),
        module_base: MODULE_BASE,
        data_section: SectionRange {
            start: MODULE_BASE + DATA_RVA,
            end: MODULE_BASE + DATA_RVA + DATA_LEN,
        },
        page_section: SectionRange {
            start: page_base,
            end: page_base + PAGE_SIZE,
        },
        expected_paths: paths.iter().map(|path| (*path).to_string()).collect(),
        expected_modified: MODIFIED_1,
    }
}

/// The compiled fixture symbol table, shared by both Shimcache fixtures.
fn table_for_shim() -> std::sync::Arc<seance_symbols::SymbolTable> {
    table(shim_isf())
}

/// A Windows 7 x64 profile whose symbol table declares one type under a name
/// nothing looks for.
///
/// For the refusal tests. The image is empty because layout resolution reads no
/// memory: it is a symbol-table question, and answering it is the whole of what
/// is under test.
pub(crate) fn shim_profile_with_type_renamed(type_name: &str) -> WindowsProfile {
    let isf = shim_isf().replace(
        &format!("\"{type_name}\":"),
        &format!("\"{type_name}_UNDER_ANOTHER_NAME\":"),
    );
    profile(
        Image::new().layer(),
        table(&isf),
        Architecture::X64,
        6,
        1,
        Some(7_601),
    )
}

/// Write a `_UNICODE_STRING` at `at` whose buffer is at `buffer`.
fn put_unicode(image: &mut Image, at: u64, buffer: u64, text: &str) {
    let length = text.encode_utf16().count() * 2;
    image.put_u16(at, length as u16);
    image.put_u16(at + 2, length as u16);
    image.put_u64(at + 8, buffer);
    image.put_utf16(buffer, text);
}

/// Write one `IMAGE_SECTION_HEADER`.
fn put_section(image: &mut Image, at: u64, name: &str, rva: u64, size: u64) {
    let mut padded = [0u8; 8];
    let bytes = name.as_bytes();
    padded[..bytes.len()].copy_from_slice(bytes);
    image.write(at, &padded);
    image.put_u32(at + 8, size as u32);
    image.put_u32(at + 12, rva as u32);
}

/// Write an `_ERESOURCE` whose system-resource list is a three-node ring.
///
/// A ring rather than a self-link, because the validity check requires `Flink`
/// and `Blink` to differ: a resource linked only to itself is the shape of an
/// initialised-but-unused lock, and accepting it would let a zeroed page pass.
fn put_eresource(image: &mut Image, at: u64, next: u64, previous: u64) {
    image.put_u64(at, next);
    image.put_u64(at + 8, previous);
    image.put_u64(next, previous);
    image.put_u64(next + 8, at);
    image.put_u64(previous, at);
    image.put_u64(previous + 8, next);
    // No shared waiters, and no semaphore to validate.
    image.put_u64(at + 40, 0);
    image.put_u32(at + 72, 0);
}

/// Write an `_RTL_AVL_TABLE` whose parent points at itself and whose three
/// routines are three distinct addresses inside `PAGE`.
fn put_avl_table(image: &mut Image, at: u64, page_base: u64) {
    image.put_u64(at, at);
    image.put_u64(at + 72, page_base + 0x100);
    image.put_u64(at + 80, page_base + 0x200);
    image.put_u64(at + 88, page_base + 0x300);
}
