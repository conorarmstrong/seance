//! Synthetic images for the handle, token, privilege and SID tests.
//!
//! Two fixtures, because the four stages in this module tree have two
//! completely different shapes to get right and a test that only exercises one
//! of them proves nothing about the other:
//!
//! * [`win10_image`] — 64-bit, a **two-level** handle table whose first
//!   mid-level slot is empty, entries that hold the object address as a shifted
//!   44-bit field, object headers whose type index is XORed with a cookie and
//!   their own address, `ObpInfoMaskToOffset` for name lookups, and a token
//!   whose privileges are three bitmaps.
//! * [`xp_image`] — 32-bit, a **single-level** table, entries holding an
//!   `_EX_FAST_REF`, object headers pointing straight at their `_OBJECT_TYPE`,
//!   `NameInfoOffset` in the header, and a token whose privileges are a counted
//!   array.
//!
//! Everything is written by address rather than by a generator, so a failing
//! test points at one line here rather than at a builder.
#![allow(dead_code)]

use std::sync::Arc;

use seance_memory::{Architecture, MemoryLayer};
use seance_symbols::SymbolTable;

use crate::poolscan::test_support::{profile, table, Image};
use crate::poolscan::ObjectTypeMap;
use crate::profile::WindowsProfile;

// ── The 64-bit fixture ──────────────────────────────────────────────────────

/// The process whose handles, privileges and SIDs the tests read.
pub(crate) const WIN10_EPROCESS: u64 = 0x1000;

/// Its `_HANDLE_TABLE`.
pub(crate) const WIN10_HANDLE_TABLE: u64 = 0x2000;

/// The mid-level page of pointers.
pub(crate) const WIN10_LEVEL1_PAGE: u64 = 0x3000;

/// The one level-0 page, hanging off mid-level **slot 1**, so that handle
/// values start at 1024 rather than 0.
pub(crate) const WIN10_LEAF_PAGE: u64 = 0x4000;

/// Object header of the named mutant.
pub(crate) const WIN10_MUTANT_HEADER: u64 = 0x5030;

/// Object header of the file.
pub(crate) const WIN10_FILE_HEADER: u64 = 0x5130;

/// Object header of the open registry key.
pub(crate) const WIN10_KEY_HEADER: u64 = 0x5230;

/// Object header of the handle to another process.
pub(crate) const WIN10_PROCESS_HEADER: u64 = 0x5330;

/// Object header of the handle to a thread.
pub(crate) const WIN10_THREAD_HEADER: u64 = 0x5430;

/// Object header whose type index is not in the kernel's table.
pub(crate) const WIN10_UNKNOWN_HEADER: u64 = 0x5530;

/// An object header past the top of the fixture's address space.
pub(crate) const WIN10_MISSING_HEADER: u64 = 0x0003_0000;

/// The device object the file's path is relative to.
pub(crate) const WIN10_DEVICE_OBJECT: u64 = 0x6000;

/// That device object's own object header, `body_offset` in front of it.
pub(crate) const WIN10_DEVICE_HEADER: u64 = WIN10_DEVICE_OBJECT - 48;

/// The `_TOKEN`.
pub(crate) const WIN10_TOKEN: u64 = 0x8000;

/// A `_SID` claiming more sub-authorities than a SID can have.
pub(crate) const WIN10_BAD_SID: u64 = 0x8240;

/// `ObHeaderCookie`'s value in the fixture.
pub(crate) const WIN10_COOKIE: u64 = 0x5A;

/// Where `ObTypeIndexTable` lives.
const WIN10_TYPE_TABLE: u64 = 0x9000;

/// Where `ObHeaderCookie` lives.
const WIN10_COOKIE_AT: u64 = 0x8FF0;

/// The driver that owns the fixture's devices, and the two further devices of
/// its tree: a second device of its own, and a filter's device attached above
/// the first.
pub(crate) const WIN10_DRIVER_OBJECT: u64 = 0xA000;
pub(crate) const WIN10_SECOND_DEVICE: u64 = 0xA200;
pub(crate) const WIN10_ATTACHED_DEVICE: u64 = 0xA400;
pub(crate) const WIN10_FILTER_DRIVER: u64 = 0xA600;

/// Where `ObpInfoMaskToOffset` lives.
const WIN10_INFO_MASK_TABLE: u64 = 0x9800;

/// Distance from an object header to its `_OBJECT_HEADER_NAME_INFO`, which is
/// what the fixture's `ObpInfoMaskToOffset[2]` holds.
const WIN10_NAME_INFO_DISTANCE: u64 = 0x20;

/// The 64-bit synthetic ISF.
///
/// Deliberately laid out like a real Windows 10 table where it matters: a
/// 16-byte handle table entry so a page holds 256 of them, `ObjectPointerBits`
/// as a 44-bit field at bit 20, an `_OBJECT_HEADER` whose `Body` is 48 bytes
/// in, and a `_SID` whose `SubAuthority` array is declared with one element.
pub(crate) fn win10_isf() -> String {
    r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "EE1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": {
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "short": {"size": 2, "signed": true, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"},
    "char": {"size": 1, "signed": true, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_OBJECT_TYPE": {"size": 32, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_OBJECT_HEADER": {"size": 56, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long long"}},
      "TypeIndex": {"offset": 24, "type": {"kind": "base", "name": "unsigned char"}},
      "InfoMask": {"offset": 26, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 48, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_OBJECT_HEADER_NAME_INFO": {"size": 32, "kind": "struct", "fields": {
      "Directory": {"offset": 0, "type": {"kind": "pointer",
                    "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Name": {"offset": 8, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_HANDLE_TABLE": {"size": 128, "kind": "struct", "fields": {
      "TableCode": {"offset": 8, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_HANDLE_TABLE_ENTRY": {"size": 16, "kind": "union", "fields": {
      "LowValue": {"offset": 0, "type": {"kind": "base", "name": "long long"}},
      "InfoTable": {"offset": 0, "type": {"kind": "pointer",
                    "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ObjectPointerBits": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 20,
                            "bit_length": 44,
                            "type": {"kind": "base", "name": "unsigned long long"}}},
      "GrantedAccessBits": {"offset": 8, "type": {"kind": "bitfield", "bit_position": 0,
                            "bit_length": 25,
                            "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_EX_FAST_REF": {"size": 8, "kind": "union", "fields": {
      "Object": {"offset": 0, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Value": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}},
      "RefCnt": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0, "bit_length": 4,
                 "type": {"kind": "base", "name": "unsigned long long"}}}
    }},
    "_EPROCESS": {"size": 128, "kind": "struct", "fields": {
      "ObjectTable": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_HANDLE_TABLE"}}},
      "Token": {"offset": 8, "type": {"kind": "union", "name": "_EX_FAST_REF"}},
      "UniqueProcessId": {"offset": 16, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 24, "type": {"kind": "array", "count": 15,
                        "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_DEVICE_OBJECT": {"size": 88, "kind": "struct", "fields": {
      "Type": {"offset": 0, "type": {"kind": "base", "name": "short"}},
      "DriverObject": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "struct", "name": "_DRIVER_OBJECT"}}},
      "NextDevice": {"offset": 16, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_DEVICE_OBJECT"}}},
      "AttachedDevice": {"offset": 24, "type": {"kind": "pointer",
                         "subtype": {"kind": "struct", "name": "_DEVICE_OBJECT"}}},
      "DeviceType": {"offset": 72, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_DRIVER_OBJECT": {"size": 80, "kind": "struct", "fields": {
      "DeviceObject": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "struct", "name": "_DEVICE_OBJECT"}}},
      "DriverName": {"offset": 56, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_FILE_OBJECT": {"size": 32, "kind": "struct", "fields": {
      "DeviceObject": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "struct", "name": "_DEVICE_OBJECT"}}},
      "FileName": {"offset": 16, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_CLIENT_ID": {"size": 16, "kind": "struct", "fields": {
      "UniqueProcess": {"offset": 0, "type": {"kind": "pointer",
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "UniqueThread": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_ETHREAD": {"size": 32, "kind": "struct", "fields": {
      "Cid": {"offset": 0, "type": {"kind": "struct", "name": "_CLIENT_ID"}}
    }},
    "_CM_NAME_CONTROL_BLOCK": {"size": 32, "kind": "struct", "fields": {
      "Compressed": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0,
                     "bit_length": 1, "type": {"kind": "base", "name": "unsigned long"}}},
      "NameLength": {"offset": 4, "type": {"kind": "base", "name": "unsigned short"}},
      "Name": {"offset": 8, "type": {"kind": "array", "count": 1,
               "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_CM_KEY_CONTROL_BLOCK": {"size": 32, "kind": "struct", "fields": {
      "ParentKcb": {"offset": 8, "type": {"kind": "pointer",
                    "subtype": {"kind": "struct", "name": "_CM_KEY_CONTROL_BLOCK"}}},
      "NameBlock": {"offset": 16, "type": {"kind": "pointer",
                    "subtype": {"kind": "struct", "name": "_CM_NAME_CONTROL_BLOCK"}}},
      "Flags": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_CM_KEY_BODY": {"size": 64, "kind": "struct", "fields": {
      "Type": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "KeyControlBlock": {"offset": 8, "type": {"kind": "pointer",
                          "subtype": {"kind": "struct", "name": "_CM_KEY_CONTROL_BLOCK"}}},
      "Trans": {"offset": 56, "type": {"kind": "pointer",
                "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_SEP_TOKEN_PRIVILEGES": {"size": 24, "kind": "struct", "fields": {
      "Present": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}},
      "Enabled": {"offset": 8, "type": {"kind": "base", "name": "unsigned long long"}},
      "EnabledByDefault": {"offset": 16, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_SID_IDENTIFIER_AUTHORITY": {"size": 6, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "array", "count": 6,
                "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_SID": {"size": 12, "kind": "struct", "fields": {
      "Revision": {"offset": 0, "type": {"kind": "base", "name": "unsigned char"}},
      "SubAuthorityCount": {"offset": 1, "type": {"kind": "base", "name": "unsigned char"}},
      "IdentifierAuthority": {"offset": 2, "type": {"kind": "struct",
                              "name": "_SID_IDENTIFIER_AUTHORITY"}},
      "SubAuthority": {"offset": 8, "type": {"kind": "array", "count": 1,
                       "subtype": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_SID_AND_ATTRIBUTES": {"size": 16, "kind": "struct", "fields": {
      "Sid": {"offset": 0, "type": {"kind": "pointer",
              "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Attributes": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_TOKEN": {"size": 64, "kind": "struct", "fields": {
      "Privileges": {"offset": 0, "type": {"kind": "struct", "name": "_SEP_TOKEN_PRIVILEGES"}},
      "UserAndGroupCount": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}},
      "UserAndGroups": {"offset": 32, "type": {"kind": "pointer",
                        "subtype": {"kind": "struct", "name": "_SID_AND_ATTRIBUTES"}}}
    }}
  },
  "enums": {},
  "symbols": {
    "ObHeaderCookie": {"address": 36848},
    "ObTypeIndexTable": {"address": 36864},
    "ObpInfoMaskToOffset": {"address": 38912}
  }
}"#
    .to_string()
}

/// Write a `_UNICODE_STRING` and the buffer it points at.
fn unicode(image: &mut Image, at: u64, buffer: u64, text: &str) {
    let bytes = text.encode_utf16().count() as u64 * 2;
    image.put_u16(at, bytes as u16);
    image.put_u16(at + 2, (bytes + 2) as u16);
    image.put_u64(at + 8, buffer);
    image.put_utf16(buffer, text);
}

/// Write the obfuscated type index and the info mask of one object header.
///
/// The stored index is `real ^ (header >> 8) ^ cookie`, truncated to a byte,
/// which is exactly what Windows 10 does and what
/// [`ObjectTypeMap::name_for`](crate::poolscan::ObjectTypeMap::name_for) undoes.
fn win10_header(image: &mut Image, at: u64, real_index: u64, info_mask: u8) {
    let stored = (real_index ^ ((at >> 8) & 0xFF) ^ WIN10_COOKIE) & 0xFF;
    image.put_u8(at + 24, stored as u8);
    image.put_u8(at + 26, info_mask);
}

/// Write one handle table entry: the shifted object pointer and the access mask.
fn win10_entry(image: &mut Image, index: u64, object_header: u64, granted_access: u32) {
    let at = WIN10_LEAF_PAGE + index * 16;
    // The inverse of the decode: an address becomes a 44-bit field by losing
    // its low four bits, and the field sits at bit 20 of `LowValue`.
    image.put_u64(at, (object_header >> 4) << 20);
    image.put_u32(at + 8, granted_access);
}

/// The 64-bit fixture image.
pub(crate) fn win10_image() -> Image {
    let mut image = Image::new();

    // The process, its handle table and its token.
    image.put_u64(WIN10_EPROCESS, WIN10_HANDLE_TABLE);
    image.put_u64(WIN10_EPROCESS + 8, WIN10_TOKEN | 3);
    image.put_u64(WIN10_EPROCESS + 16, 420);
    image.write(WIN10_EPROCESS + 24, b"notepad.exe");

    // A two-level table. Mid-level slot 0 is empty, which is what makes the
    // first real handle 1024 rather than 0.
    image.put_u64(WIN10_HANDLE_TABLE + 8, WIN10_LEVEL1_PAGE | 1);
    image.put_u64(WIN10_LEVEL1_PAGE + 8, WIN10_LEAF_PAGE);

    win10_entry(&mut image, 0, WIN10_MUTANT_HEADER, 0x001F_0001);
    // Entry 1 is left zero: a slot that holds no object.
    win10_entry(&mut image, 2, WIN10_FILE_HEADER, 0x0010_0081);
    win10_entry(&mut image, 3, WIN10_KEY_HEADER, 0x0002_0019);
    win10_entry(&mut image, 4, WIN10_PROCESS_HEADER, 0x001F_FFFF);
    win10_entry(&mut image, 5, WIN10_THREAD_HEADER, 0x001F_03FF);
    win10_entry(&mut image, 6, WIN10_UNKNOWN_HEADER, 0x001F_0001);
    win10_entry(&mut image, 7, WIN10_MISSING_HEADER, 0x001F_0001);

    // Object headers. Index 2 is Mutant, 3 File, 4 Key, 1 Process, 5 Thread.
    win10_header(&mut image, WIN10_MUTANT_HEADER, 2, 2);
    win10_header(&mut image, WIN10_FILE_HEADER, 3, 0);
    win10_header(&mut image, WIN10_KEY_HEADER, 4, 0);
    win10_header(&mut image, WIN10_PROCESS_HEADER, 1, 0);
    win10_header(&mut image, WIN10_THREAD_HEADER, 5, 0);
    win10_header(&mut image, WIN10_UNKNOWN_HEADER, 200, 0);
    win10_header(&mut image, WIN10_DEVICE_HEADER, 1, 2);

    // The mutant's name, in the name info in front of its header.
    unicode(
        &mut image,
        WIN10_MUTANT_HEADER - WIN10_NAME_INFO_DISTANCE + 8,
        0x6300,
        "\\BaseNamedObjects\\Mutex1",
    );

    // The file object, its device and the two halves of its name.
    let file_object = WIN10_FILE_HEADER + 48;
    image.put_u64(file_object + 8, WIN10_DEVICE_OBJECT);
    unicode(
        &mut image,
        file_object + 16,
        0x6200,
        "\\Windows\\notepad.exe",
    );
    unicode(
        &mut image,
        WIN10_DEVICE_HEADER - WIN10_NAME_INFO_DISTANCE + 8,
        0x6100,
        "HarddiskVolume2",
    );

    // The device tree (`device_tree`): one driver owning two devices, with a
    // second driver's device attached above the first -- which is what a filter
    // driver looks like in memory. The first device is the one the file object
    // above names, so it is already header-ed and named `HarddiskVolume2`.
    image.put_u64(WIN10_DRIVER_OBJECT + 8, WIN10_DEVICE_OBJECT);
    unicode(
        &mut image,
        WIN10_DRIVER_OBJECT + 56,
        0x6400,
        "\\Driver\\disk",
    );
    image.put_u64(WIN10_DEVICE_OBJECT + 8, WIN10_DRIVER_OBJECT);
    image.put_u64(WIN10_DEVICE_OBJECT + 16, WIN10_SECOND_DEVICE);
    image.put_u64(WIN10_DEVICE_OBJECT + 24, WIN10_ATTACHED_DEVICE);
    // FILE_DEVICE_DISK, which `wdm.h` defines.
    image.put_u32(WIN10_DEVICE_OBJECT + 72, 0x7);

    win10_header(&mut image, WIN10_SECOND_DEVICE - 48, 1, 0);
    image.put_u64(WIN10_SECOND_DEVICE + 8, WIN10_DRIVER_OBJECT);
    // A device type `wdm.h` does not define, so the record must report the
    // number rather than a word.
    image.put_u32(WIN10_SECOND_DEVICE + 72, 0x0000_7FFF);

    win10_header(&mut image, WIN10_ATTACHED_DEVICE - 48, 1, 2);
    unicode(
        &mut image,
        WIN10_ATTACHED_DEVICE - 48 - WIN10_NAME_INFO_DISTANCE + 8,
        0x6500,
        "FilterDevice",
    );
    image.put_u64(WIN10_ATTACHED_DEVICE + 8, WIN10_FILTER_DRIVER);
    image.put_u32(WIN10_ATTACHED_DEVICE + 72, 0x7);
    unicode(
        &mut image,
        WIN10_FILTER_DRIVER + 56,
        0x6600,
        "\\Driver\\volsnap",
    );

    // The open registry key: three control blocks, of which the root has no
    // parent and contributes no path component.
    image.put_u64(WIN10_KEY_HEADER + 48 + 8, 0x7000);
    image.put_u64(0x7000 + 8, 0x7100);
    image.put_u64(0x7000 + 16, 0x7200);
    image.put_u64(0x7100 + 8, 0x7180);
    image.put_u64(0x7100 + 16, 0x7220);
    // 0x7180 is the hive root: its ParentKcb stays zero.
    image.put_u32(0x7200, 1);
    image.put_u16(0x7204, 3);
    image.write(0x7208, b"Run");
    image.put_u32(0x7220, 1);
    image.put_u16(0x7224, 8);
    image.write(0x7228, b"Software");

    // The process and thread the other handles refer to.
    image.put_u64(WIN10_PROCESS_HEADER + 48 + 16, 1234);
    image.write(WIN10_PROCESS_HEADER + 48 + 24, b"explorer.exe");
    image.put_u64(WIN10_THREAD_HEADER + 48, 4);
    image.put_u64(WIN10_THREAD_HEADER + 48 + 8, 8);

    // The object-type table. Slot 0 is always null and the first null after it
    // ends the table, so slot 6 is left zero.
    image.put_u64(WIN10_TYPE_TABLE + 8, 0x9100);
    image.put_u64(WIN10_TYPE_TABLE + 16, 0x9140);
    image.put_u64(WIN10_TYPE_TABLE + 24, 0x9180);
    image.put_u64(WIN10_TYPE_TABLE + 32, 0x91C0);
    image.put_u64(WIN10_TYPE_TABLE + 40, 0x9200);
    unicode(&mut image, 0x9100, 0x9400, "Process");
    unicode(&mut image, 0x9140, 0x9420, "Mutant");
    unicode(&mut image, 0x9180, 0x9440, "File");
    unicode(&mut image, 0x91C0, 0x9460, "Key");
    unicode(&mut image, 0x9200, 0x9480, "Thread");
    image.put_u8(WIN10_COOKIE_AT, WIN10_COOKIE as u8);

    // `ObpInfoMaskToOffset`, indexed by `InfoMask & 3`. Index 2 is the one the
    // fixture's named objects use.
    image.write(WIN10_INFO_MASK_TABLE, &[0x00, 0x10, 0x20, 0x30]);

    // The token: two privileges present, one enabled and one on by default.
    image.put_u64(WIN10_TOKEN, (1 << 20) | (1 << 23));
    image.put_u64(WIN10_TOKEN + 8, 1 << 20);
    image.put_u64(WIN10_TOKEN + 16, 1 << 23);
    image.put_u32(WIN10_TOKEN + 24, 2);
    image.put_u64(WIN10_TOKEN + 32, 0x8100);

    image.put_u64(0x8100, 0x8200);
    image.put_u32(0x8108, 7);
    image.put_u64(0x8110, 0x8220);
    image.put_u32(0x8118, 0xE);

    // S-1-5-18, the Local System account.
    image.put_u8(0x8200, 1);
    image.put_u8(0x8201, 1);
    image.write(0x8202, &[0, 0, 0, 0, 0, 5]);
    image.put_u32(0x8208, 18);

    // S-1-5-21-111-222-333-500: five sub-authorities in an array the symbol
    // table declares with one element.
    image.put_u8(0x8220, 1);
    image.put_u8(0x8221, 5);
    image.write(0x8222, &[0, 0, 0, 0, 0, 5]);
    image.put_u32(0x8228, 21);
    image.put_u32(0x822C, 111);
    image.put_u32(0x8230, 222);
    image.put_u32(0x8234, 333);
    image.put_u32(0x8238, 500);

    // A structure that is not a SID: twenty sub-authorities.
    image.put_u8(WIN10_BAD_SID, 1);
    image.put_u8(WIN10_BAD_SID + 1, 20);

    image
}

/// The compiled 64-bit symbol table.
pub(crate) fn win10_symbols() -> Arc<SymbolTable> {
    table(&win10_isf())
}

/// A profile over the 64-bit fixture.
pub(crate) fn win10_profile() -> WindowsProfile {
    let layer: Arc<dyn MemoryLayer> = win10_image().layer();
    profile(
        layer,
        win10_symbols(),
        Architecture::X64,
        10,
        0,
        Some(22000),
    )
}

/// A profile over the 64-bit fixture with named types removed from its symbol
/// table.
///
/// For the refusal tests: a build whose symbols cannot describe something must
/// fail naming it, and the only way to prove that is to take it away.
pub(crate) fn win10_profile_without(dropped: &[&str]) -> WindowsProfile {
    let layer: Arc<dyn MemoryLayer> = win10_image().layer();
    profile(
        layer,
        table(&without_types(&win10_isf(), dropped)),
        Architecture::X64,
        10,
        0,
        Some(22000),
    )
}

/// One fixture ISF with named types removed from it.
fn without_types(isf: &str, dropped: &[&str]) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(isf).expect("the fixture ISF is valid JSON");
    if let Some(types) = value
        .get_mut("user_types")
        .and_then(serde_json::Value::as_object_mut)
    {
        for name in dropped {
            types.remove(*name);
        }
        // A struct embedded **by value** carries its size into the containing
        // type, so a member left pointing at a type that is no longer there is
        // an ISF that will not compile at all — and the refusal under test is
        // then never reached. Behind a pointer the reference is a name only, so
        // those members stay and the build genuinely has the member without the
        // type, which is its own refusal case.
        let remaining: Vec<String> = types.keys().cloned().collect();
        for name in remaining {
            let Some(fields) = types
                .get_mut(&name)
                .and_then(|ty| ty.get_mut("fields"))
                .and_then(serde_json::Value::as_object_mut)
            else {
                continue;
            };
            fields.retain(|_, field| !embeds_any(field.get("type"), dropped));
        }
    }
    value.to_string()
}

/// Whether an ISF type reference embeds one of `dropped` by value.
///
/// Walks arrays, which embed their element type, and stops at pointers, which
/// do not.
fn embeds_any(ty: Option<&serde_json::Value>, dropped: &[&str]) -> bool {
    let Some(ty) = ty else {
        return false;
    };
    match ty.get("kind").and_then(serde_json::Value::as_str) {
        Some("struct") | Some("union") | Some("enum") => ty
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| dropped.contains(&name)),
        Some("array") => embeds_any(ty.get("subtype"), dropped),
        _ => false,
    }
}

/// The object-type map of the 64-bit fixture.
pub(crate) fn win10_type_map() -> ObjectTypeMap {
    ObjectTypeMap::from_profile(&win10_profile())
        .expect("the fixture declares an object-type table")
}

// ── The 32-bit fixture ──────────────────────────────────────────────────────

/// The process whose handles and token the XP tests read.
pub(crate) const XP_EPROCESS: u64 = 0x1000;

/// Its `_HANDLE_TABLE`.
pub(crate) const XP_HANDLE_TABLE: u64 = 0x2000;

/// Its single level-0 page.
pub(crate) const XP_LEAF_PAGE: u64 = 0x3000;

/// The object header of the one open handle, deliberately not eight-byte
/// aligned in the entry: the entry stores it with attribute bits set.
pub(crate) const XP_MUTANT_HEADER: u64 = 0x5018;

/// The `_OBJECT_TYPE` that header points at.
pub(crate) const XP_OBJECT_TYPE: u64 = 0x6000;

/// The `_TOKEN`.
pub(crate) const XP_TOKEN: u64 = 0x8000;

/// The 32-bit synthetic ISF.
pub(crate) fn xp_isf() -> String {
    r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "FF1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 2,
                        "database": "ntoskrnl.pdb", "machine_type": 332}}
  },
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_UNICODE_STRING": {"size": 8, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 4, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_OBJECT_TYPE": {"size": 64, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_OBJECT_HEADER": {"size": 32, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "Type": {"offset": 8, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "_OBJECT_TYPE"}}},
      "NameInfoOffset": {"offset": 12, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 24, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_OBJECT_HEADER_NAME_INFO": {"size": 16, "kind": "struct", "fields": {
      "Directory": {"offset": 0, "type": {"kind": "pointer",
                    "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Name": {"offset": 4, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_HANDLE_TABLE": {"size": 68, "kind": "struct", "fields": {
      "TableCode": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_HANDLE_TABLE_ENTRY": {"size": 8, "kind": "union", "fields": {
      "Object": {"offset": 0, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned char"}}},
      "InfoTable": {"offset": 0, "type": {"kind": "pointer",
                    "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Value": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "GrantedAccess": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_EX_FAST_REF": {"size": 4, "kind": "union", "fields": {
      "Object": {"offset": 0, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Value": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "RefCnt": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0, "bit_length": 3,
                 "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_EPROCESS": {"size": 256, "kind": "struct", "fields": {
      "ObjectTable": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_HANDLE_TABLE"}}},
      "Token": {"offset": 4, "type": {"kind": "union", "name": "_EX_FAST_REF"}},
      "UniqueProcessId": {"offset": 8, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 12, "type": {"kind": "array", "count": 16,
                        "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_LUID": {"size": 8, "kind": "struct", "fields": {
      "LowPart": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "HighPart": {"offset": 4, "type": {"kind": "base", "name": "long"}}
    }},
    "_LUID_AND_ATTRIBUTES": {"size": 12, "kind": "struct", "fields": {
      "Luid": {"offset": 0, "type": {"kind": "struct", "name": "_LUID"}},
      "Attributes": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_SID_IDENTIFIER_AUTHORITY": {"size": 6, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "array", "count": 6,
                "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_SID": {"size": 12, "kind": "struct", "fields": {
      "Revision": {"offset": 0, "type": {"kind": "base", "name": "unsigned char"}},
      "SubAuthorityCount": {"offset": 1, "type": {"kind": "base", "name": "unsigned char"}},
      "IdentifierAuthority": {"offset": 2, "type": {"kind": "struct",
                              "name": "_SID_IDENTIFIER_AUTHORITY"}},
      "SubAuthority": {"offset": 8, "type": {"kind": "array", "count": 1,
                       "subtype": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_SID_AND_ATTRIBUTES": {"size": 8, "kind": "struct", "fields": {
      "Sid": {"offset": 0, "type": {"kind": "pointer",
              "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Attributes": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_TOKEN": {"size": 64, "kind": "struct", "fields": {
      "PrivilegeCount": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "Privileges": {"offset": 4, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_LUID_AND_ATTRIBUTES"}}},
      "UserAndGroupCount": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},
      "UserAndGroups": {"offset": 12, "type": {"kind": "pointer",
                        "subtype": {"kind": "struct", "name": "_SID_AND_ATTRIBUTES"}}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#
    .to_string()
}

/// Write a 32-bit `_UNICODE_STRING` and the buffer it points at.
fn unicode32(image: &mut Image, at: u64, buffer: u64, text: &str) {
    let bytes = text.encode_utf16().count() as u64 * 2;
    image.put_u16(at, bytes as u16);
    image.put_u16(at + 2, (bytes + 2) as u16);
    image.put_u32(at + 4, buffer as u32);
    image.put_utf16(buffer, text);
}

/// The 32-bit fixture image.
pub(crate) fn xp_image() -> Image {
    let mut image = Image::new();

    image.put_u32(XP_EPROCESS, XP_HANDLE_TABLE as u32);
    image.put_u32(XP_EPROCESS + 4, (XP_TOKEN | 3) as u32);
    image.put_u32(XP_EPROCESS + 8, 4);
    image.write(XP_EPROCESS + 12, b"System");

    // A single-level table: `TableCode` with no level bits set.
    image.put_u32(XP_HANDLE_TABLE, XP_LEAF_PAGE as u32);
    // The entry stores the header with attribute bits set in the space below
    // the pointer's alignment, which is what the mask exists to strip.
    image.put_u32(XP_LEAF_PAGE, (XP_MUTANT_HEADER | 3) as u32);
    image.put_u32(XP_LEAF_PAGE + 4, 0x001F_0003);

    // The object header points straight at its type, and carries the distance
    // back to its name info as a byte.
    image.put_u32(XP_MUTANT_HEADER + 8, XP_OBJECT_TYPE as u32);
    image.put_u8(XP_MUTANT_HEADER + 12, 0x10);
    unicode32(
        &mut image,
        XP_MUTANT_HEADER - 0x10 + 4,
        0x5100,
        "\\Sessions\\1\\Windows",
    );
    unicode32(&mut image, XP_OBJECT_TYPE, 0x6100, "Mutant");

    // A token whose privileges are a counted array rather than bitmaps.
    image.put_u32(XP_TOKEN, 2);
    image.put_u32(XP_TOKEN + 4, 0x8100);
    image.put_u32(XP_TOKEN + 8, 1);
    image.put_u32(XP_TOKEN + 12, 0x8200);
    image.put_u32(0x8100, 20);
    image.put_u32(0x8108, 2);
    image.put_u32(0x810C, 23);
    image.put_u32(0x8114, 3);

    image.put_u32(0x8200, 0x8300);
    image.put_u32(0x8204, 7);
    image.put_u8(0x8300, 1);
    image.put_u8(0x8301, 1);
    image.write(0x8302, &[0, 0, 0, 0, 0, 5]);
    image.put_u32(0x8308, 18);

    image
}

/// A profile over the 32-bit fixture.
pub(crate) fn xp_profile() -> WindowsProfile {
    let layer: Arc<dyn MemoryLayer> = xp_image().layer();
    profile(layer, table(&xp_isf()), Architecture::X86, 5, 1, Some(2600))
}

/// A profile over the 32-bit fixture with named types removed.
///
/// The 64-bit sibling cannot stand in for it: the XP-shaped layouts — a token's
/// privileges as a counted array rather than as bitmaps — are only reached on a
/// build with no Vista members, so a refusal on that path can only be proved
/// here.
pub(crate) fn xp_profile_without(dropped: &[&str]) -> WindowsProfile {
    let layer: Arc<dyn MemoryLayer> = xp_image().layer();
    profile(
        layer,
        table(&without_types(&xp_isf(), dropped)),
        Architecture::X86,
        5,
        1,
        Some(2600),
    )
}
