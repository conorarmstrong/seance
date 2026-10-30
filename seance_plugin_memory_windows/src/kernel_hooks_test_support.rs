//! One synthetic 64-bit Windows 10 image that every kernel-hooks test reads.
//!
//! Written by address rather than generated, so a failing test points at one
//! line of this file instead of at a builder. The image deliberately contains
//! both an ordinary case and a suspicious one for each capability, because a
//! fixture in which everything is a finding cannot distinguish a stage that
//! works from one that flags everything.
//!
//! # The address map
//!
//! | Range | What is there |
//! |---|---|
//! | `0x0000`–`0x7fff` | the kernel image, `ntoskrnl.exe`, and all its data |
//! | `0x8000`–`0x8fff` | `fltmgr.sys`, a driver the loaded-module list holds |
//! | `0x9000`–`0x9fff` | `hidden.sys`, which the list does **not** hold |
//! | `0x1000`–`0x1fff` | callback blocks, list records and strings |
//! | `0x3000`–`0x3fff` | pool allocations: two driver objects, three loader entries |
//!
//! The profile's kernel base is zero, which is what
//! [`crate::poolscan::test_support::profile`] records, so a symbol's declared
//! address is also its address in the image.

use seance_memory::Architecture;

use crate::poolscan::test_support::{profile, table, Image};
use crate::profile::WindowsProfile;

// ── Where the kernel's data lives ───────────────────────────────────────────

/// `PsLoadedModuleList`, the head of the kernel's own module list.
pub(crate) const PS_LOADED_MODULE_LIST: u64 = 0x0100;

/// `PspCreateProcessNotifyRoutine`, 64 slots on this build.
pub(crate) const PROCESS_NOTIFY_ARRAY: u64 = 0x0200;

/// `PspCreateThreadNotifyRoutine`, 64 slots on this build.
pub(crate) const THREAD_NOTIFY_ARRAY: u64 = 0x0400;

/// `PspLoadImageNotifyRoutine`, always 8 slots.
pub(crate) const IMAGE_NOTIFY_ARRAY: u64 = 0x0600;

/// `CallbackListHead`, the Windows 7 and later registry callback list.
pub(crate) const REGISTRY_LIST_HEAD: u64 = 0x0700;

/// `CmpCallBackCount`.
pub(crate) const REGISTRY_COUNT_AT: u64 = 0x0710;

/// `KeBugCheckCallbackListHead`.
pub(crate) const BUGCHECK_LIST_HEAD: u64 = 0x0720;

/// `KeBugCheckReasonCallbackListHead`.
pub(crate) const BUGCHECK_REASON_LIST_HEAD: u64 = 0x0730;

/// `KiServiceTable`.
pub(crate) const SERVICE_TABLE: u64 = 0x0740;

/// `KiServiceLimit`.
pub(crate) const SERVICE_LIMIT_AT: u64 = 0x0750;

/// `ObTypeIndexTable`.
pub(crate) const TYPE_INDEX_TABLE: u64 = 0x0760;

/// `CmpCallBackVector`, present in the image always and named by a symbol only
/// in the legacy-shape variant of the ISF.
pub(crate) const REGISTRY_VECTOR: u64 = 0x0790;

// ── The three module images ─────────────────────────────────────────────────

/// Base of `ntoskrnl.exe`, which is also the profile's kernel base.
pub(crate) const NT_BASE: u64 = 0x0000;

/// Size of `ntoskrnl.exe`, so it covers `0x0000`–`0x7fff`.
pub(crate) const NT_SIZE: u64 = 0x8000;

/// Base of `fltmgr.sys`, a driver the loaded-module list holds.
pub(crate) const FLT_BASE: u64 = 0x8000;

/// Size of `fltmgr.sys`.
pub(crate) const FLT_SIZE: u64 = 0x1000;

/// Base of `hidden.sys`, which the loaded-module list does **not** hold.
pub(crate) const HIDDEN_BASE: u64 = 0x9000;

/// Size of `hidden.sys`.
pub(crate) const HIDDEN_SIZE: u64 = 0x1000;

// ── Callback records ────────────────────────────────────────────────────────

/// A callback block whose routine is inside the kernel: the ordinary case.
pub(crate) const NOTIFY_BLOCK_NT: u64 = 0x1000;

/// A callback block whose routine is inside `hidden.sys`: the finding.
pub(crate) const NOTIFY_BLOCK_HIDDEN: u64 = 0x1020;

/// The registry filter entry.
pub(crate) const REGISTRY_ENTRY: u64 = 0x1040;

/// The bugcheck callback record.
pub(crate) const BUGCHECK_RECORD: u64 = 0x1100;

/// The bugcheck-reason callback record.
pub(crate) const BUGCHECK_REASON_RECORD: u64 = 0x1140;

/// The routine `NOTIFY_BLOCK_NT` registers, inside the kernel.
pub(crate) const NT_ROUTINE: u64 = 0x1500;

/// The routine `NOTIFY_BLOCK_HIDDEN` registers, inside `hidden.sys` and so
/// inside no module the loaded-module list holds.
pub(crate) const HIDDEN_ROUTINE: u64 = 0x9100;

/// The routine the registry filter registers, inside `fltmgr.sys`.
pub(crate) const FLT_ROUTINE: u64 = 0x8100;

/// The routine the bugcheck callback registers, inside the kernel.
pub(crate) const BUGCHECK_ROUTINE: u64 = 0x1600;

/// The routine the bugcheck-reason callback registers, inside `hidden.sys`.
pub(crate) const BUGCHECK_REASON_ROUTINE: u64 = 0x9200;

/// The system call target inside `hidden.sys`.
pub(crate) const SERVICE_HIDDEN_TARGET: u64 = 0x9300;

/// The system call target inside `fltmgr.sys`.
pub(crate) const SERVICE_FLT_TARGET: u64 = 0x8200;

/// The system call target below the service table, which only an arithmetic
/// shift of a negative entry reaches.
pub(crate) const SERVICE_LOW_TARGET: u64 = 0x0100;

// ── Pool allocations ────────────────────────────────────────────────────────

/// Allocation holding the `fltmgr.sys` driver object.
pub(crate) const DRIVER_FLT_ALLOC: u64 = 0x3000;

/// The `_DRIVER_EXTENSION` that driver object points at.
pub(crate) const DRIVER_FLT_EXTENSION: u64 = 0x3200;

/// Allocation holding a driver object with a zeroed `DriverStart`.
pub(crate) const DRIVER_BLANK_ALLOC: u64 = 0x3400;

/// Allocation holding the `ntoskrnl.exe` loader entry.
pub(crate) const LDR_NT_ALLOC: u64 = 0x3800;

/// Allocation holding the `fltmgr.sys` loader entry.
pub(crate) const LDR_FLT_ALLOC: u64 = 0x3900;

/// Allocation holding the `hidden.sys` loader entry, which the kernel's list
/// does not hold.
pub(crate) const LDR_HIDDEN_ALLOC: u64 = 0x3A00;

/// The dispatch routine `fltmgr.sys` publishes for every IRP but one.
pub(crate) const FLT_DISPATCH: u64 = 0x8100;

/// The dispatch routine `fltmgr.sys` publishes for `IRP_MJ_READ`, which is
/// inside neither `fltmgr.sys` nor any module the list holds.
pub(crate) const FLT_HOOKED_DISPATCH: u64 = 0x9400;

/// The IRP major function index the fixture hooks.
pub(crate) const HOOKED_IRP_INDEX: u64 = 3;

/// The dispatch routine the zeroed-start driver publishes.
pub(crate) const BLANK_DISPATCH: u64 = 0x9500;

// ── Offsets the fixture ISF declares ────────────────────────────────────────

/// Offsets in the synthetic 64-bit ISF below.
pub(crate) mod off {
    /// `sizeof(_POOL_HEADER)`.
    pub(crate) const POOL_HEADER_SIZE: u64 = 16;
    /// `_POOL_HEADER.BlockSize`.
    pub(crate) const POOL_BLOCK_SIZE: u64 = 0;
    /// `_POOL_HEADER.PoolType`.
    pub(crate) const POOL_TYPE: u64 = 2;
    /// `_POOL_HEADER.PoolTag`.
    pub(crate) const POOL_TAG: u64 = 4;

    /// `_OBJECT_HEADER.PointerCount`.
    pub(crate) const OH_POINTER_COUNT: u64 = 0;
    /// `_OBJECT_HEADER.TypeIndex`.
    pub(crate) const OH_TYPE_INDEX: u64 = 24;
    /// `_OBJECT_HEADER.InfoMask`.
    pub(crate) const OH_INFO_MASK: u64 = 26;
    /// `_OBJECT_HEADER.Body`.
    pub(crate) const OH_BODY: u64 = 48;

    /// `_UNICODE_STRING.Length`.
    pub(crate) const UNICODE_LENGTH: u64 = 0;
    /// `_UNICODE_STRING.MaximumLength`.
    pub(crate) const UNICODE_MAX_LENGTH: u64 = 2;
    /// `_UNICODE_STRING.Buffer`.
    pub(crate) const UNICODE_BUFFER: u64 = 8;

    /// `_LIST_ENTRY.Flink`.
    pub(crate) const LIST_FLINK: u64 = 0;

    /// `_EX_CALLBACK_ROUTINE_BLOCK.Function`.
    pub(crate) const BLOCK_FUNCTION: u64 = 8;

    /// `_CM_CALLBACK_ENTRY.Function`.
    pub(crate) const CM_FUNCTION: u64 = 40;
    /// `_CM_CALLBACK_ENTRY.Altitude`.
    pub(crate) const CM_ALTITUDE: u64 = 48;

    /// `_KBUGCHECK_CALLBACK_RECORD.CallbackRoutine`.
    pub(crate) const BUGCHECK_ROUTINE: u64 = 16;
    /// `_KBUGCHECK_CALLBACK_RECORD.Component`.
    pub(crate) const BUGCHECK_COMPONENT: u64 = 40;

    /// `_DRIVER_OBJECT.DriverStart`.
    pub(crate) const DRIVER_START: u64 = 16;
    /// `_DRIVER_OBJECT.DriverSize`.
    pub(crate) const DRIVER_SIZE: u64 = 24;
    /// `_DRIVER_OBJECT.DriverExtension`.
    pub(crate) const DRIVER_EXTENSION: u64 = 32;
    /// `_DRIVER_OBJECT.DriverName`.
    pub(crate) const DRIVER_NAME: u64 = 40;
    /// `_DRIVER_OBJECT.DriverInit`.
    pub(crate) const DRIVER_INIT: u64 = 56;
    /// `_DRIVER_OBJECT.DriverUnload`.
    pub(crate) const DRIVER_UNLOAD: u64 = 64;
    /// `_DRIVER_OBJECT.MajorFunction`.
    pub(crate) const DRIVER_MAJOR_FUNCTION: u64 = 72;

    /// `_DRIVER_EXTENSION.ServiceKeyName`.
    pub(crate) const EXTENSION_SERVICE_KEY: u64 = 0;

    /// `_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks`.
    pub(crate) const LDR_LOAD_LINKS: u64 = 0;
    /// `_LDR_DATA_TABLE_ENTRY.DllBase`.
    pub(crate) const LDR_DLL_BASE: u64 = 48;
    /// `_LDR_DATA_TABLE_ENTRY.SizeOfImage`.
    pub(crate) const LDR_SIZE_OF_IMAGE: u64 = 64;
    /// `_LDR_DATA_TABLE_ENTRY.FullDllName`.
    pub(crate) const LDR_FULL_NAME: u64 = 72;
    /// `_LDR_DATA_TABLE_ENTRY.BaseDllName`.
    pub(crate) const LDR_BASE_NAME: u64 = 88;

    /// `_OBJECT_TYPE.Name`.
    pub(crate) const OBJECT_TYPE_NAME: u64 = 0;
}

/// The `_OBJECT_TYPE` the object manager's slot 1 points at.
pub(crate) const OBJECT_TYPE_DRIVER: u64 = 0x1D00;

/// Where each fixture string's characters live.
mod strings {
    pub(super) const DRIVER_TYPE_NAME: u64 = 0x1D40;
    pub(super) const ALTITUDE: u64 = 0x1E00;
    pub(super) const COMPONENT: u64 = 0x1E40;
    pub(super) const FLT_DRIVER_NAME: u64 = 0x1E80;
    pub(super) const FLT_SERVICE_KEY: u64 = 0x1EC0;
    pub(super) const BLANK_DRIVER_NAME: u64 = 0x1F00;
    // A full path runs to about eighty bytes of UTF-16, so the buffers are
    // spaced 0x80 apart.
    pub(super) const NT_FULL: u64 = 0x2000;
    pub(super) const NT_BASE_NAME: u64 = 0x2080;
    pub(super) const FLT_FULL: u64 = 0x2100;
    pub(super) const FLT_BASE_NAME: u64 = 0x2180;
    pub(super) const HIDDEN_FULL: u64 = 0x2200;
    pub(super) const HIDDEN_BASE_NAME: u64 = 0x2280;
}

/// Where the unlisted driver's `BaseDllName` characters live.
///
/// Exported so a test can overwrite those characters in place — the same
/// `Length`, the same `MaximumLength`, different bytes — which is what a loader
/// entry whose pool has been handed to something else looks like.
pub(crate) const HIDDEN_BASE_NAME_BUFFER: u64 = strings::HIDDEN_BASE_NAME;

/// The image's file name for each of the three modules, as the fixture writes
/// them.
pub(crate) const NT_NAME: &str = "ntoskrnl.exe";

/// The listed driver's file name.
pub(crate) const FLT_NAME: &str = "fltmgr.sys";

/// The unlisted driver's file name.
pub(crate) const HIDDEN_NAME: &str = "hidden.sys";

/// The object-manager path of the fixture's `fltmgr.sys` driver object.
pub(crate) const FLT_DRIVER_PATH: &str = "\\Driver\\Fltmgr";

/// The service key that driver object was started from.
pub(crate) const FLT_SERVICE_KEY: &str = "Fltmgr";

/// The altitude the fixture's registry filter declares.
pub(crate) const REGISTRY_ALTITUDE: &str = "360000";

/// The component the fixture's bugcheck record claims.
pub(crate) const BUGCHECK_COMPONENT: &str = "Ntfs";

// ── The ISF ─────────────────────────────────────────────────────────────────

/// A synthetic 64-bit Windows 10 ISF covering every type and symbol this stage
/// reads.
///
/// The optional object headers are all declared, because the *set* a build
/// declares decides what each `InfoMask` bit means and how far the top-down
/// search for an object header inside an allocation is allowed to look.
pub(crate) fn hook_isf() -> String {
    [
        r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "3A4B5C6D7E8F90A1B2C3D4E5F6071829", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": "#,
        crate::image_fixture::BASE_TYPES_X64,
        r#",
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
    "_POOL_HEADER": {"size": 16, "kind": "struct", "fields": {
      "BlockSize": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolType": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_OBJECT_HEADER": {"size": 56, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "HandleCount": {"offset": 8, "type": {"kind": "base", "name": "long"}},
      "TypeIndex": {"offset": 24, "type": {"kind": "base", "name": "unsigned char"}},
      "InfoMask": {"offset": 26, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 48, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_OBJECT_HEADER_CREATOR_INFO": {"size": 32, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_NAME_INFO": {"size": 32, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_OBJECT_HEADER_HANDLE_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_QUOTA_INFO": {"size": 32, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_PROCESS_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_AUDIT_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_EXTENDED_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_PADDING_INFO": {"size": 8, "kind": "struct", "fields": {
      "PaddingAmount": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_OBJECT_TYPE": {"size": 32, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_EX_RUNDOWN_REF": {"size": 8, "kind": "struct", "fields": {
      "Count": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_EX_CALLBACK_ROUTINE_BLOCK": {"size": 24, "kind": "struct", "fields": {
      "RundownProtect": {"offset": 0, "type": {"kind": "struct", "name": "_EX_RUNDOWN_REF"}},
      "Function": {"offset": 8, "type": {"kind": "pointer",
                   "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Context": {"offset": 16, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_CM_CALLBACK_ENTRY": {"size": 64, "kind": "struct", "fields": {
      "Link": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "Cookie": {"offset": 24, "type": {"kind": "base", "name": "unsigned long long"}},
      "Function": {"offset": 40, "type": {"kind": "pointer",
                   "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Altitude": {"offset": 48, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_KBUGCHECK_CALLBACK_RECORD": {"size": 64, "kind": "struct", "fields": {
      "Entry": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "CallbackRoutine": {"offset": 16, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Component": {"offset": 40, "type": {"kind": "pointer",
                    "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_KBUGCHECK_REASON_CALLBACK_RECORD": {"size": 64, "kind": "struct", "fields": {
      "Entry": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "CallbackRoutine": {"offset": 16, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Component": {"offset": 40, "type": {"kind": "pointer",
                    "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "_DRIVER_EXTENSION": {"size": 32, "kind": "struct", "fields": {
      "ServiceKeyName": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_DRIVER_OBJECT": {"size": 304, "kind": "struct", "fields": {
      "Type": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "Size": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "DriverStart": {"offset": 16, "type": {"kind": "pointer",
                      "subtype": {"kind": "base", "name": "unsigned char"}}},
      "DriverSize": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}},
      "DriverExtension": {"offset": 32, "type": {"kind": "pointer",
                          "subtype": {"kind": "struct", "name": "_DRIVER_EXTENSION"}}},
      "DriverName": {"offset": 40, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "DriverInit": {"offset": 56, "type": {"kind": "pointer",
                     "subtype": {"kind": "base", "name": "unsigned char"}}},
      "DriverUnload": {"offset": 64, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}},
      "MajorFunction": {"offset": 72, "type": {"kind": "array", "count": 28,
                        "subtype": {"kind": "pointer",
                                    "subtype": {"kind": "base", "name": "unsigned char"}}}}
    }},
    "_LDR_DATA_TABLE_ENTRY": {"size": 112, "kind": "struct", "fields": {
      "InLoadOrderLinks": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InMemoryOrderLinks": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InInitializationOrderLinks": {"offset": 32,
                                     "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DllBase": {"offset": 48, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "unsigned char"}}},
      "EntryPoint": {"offset": 56, "type": {"kind": "pointer",
                     "subtype": {"kind": "base", "name": "unsigned char"}}},
      "SizeOfImage": {"offset": 64, "type": {"kind": "base", "name": "unsigned long"}},
      "FullDllName": {"offset": 72, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "BaseDllName": {"offset": 88, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }}
  },
  "enums": {},
  "symbols": {
    "PsLoadedModuleList": {"address": 256},
    "PspCreateProcessNotifyRoutine": {"address": 512},
    "PspCreateThreadNotifyRoutine": {"address": 1024},
    "PspLoadImageNotifyRoutine": {"address": 1536},
    "CallbackListHead": {"address": 1792},
    "CmpCallBackCount": {"address": 1808},
    "KeBugCheckCallbackListHead": {"address": 1824},
    "KeBugCheckReasonCallbackListHead": {"address": 1840},
    "KiServiceTable": {"address": 1856},
    "KiServiceLimit": {"address": 1872},
    "ObTypeIndexTable": {"address": 1888}
  }
}"#,
    ]
    .concat()
}

/// The same ISF with `CmpCallBackVector` named, which makes the registry group
/// take the pre-Windows-7 vector shape instead of the list shape.
pub(crate) fn isf_with_registry_vector() -> String {
    hook_isf().replace(
        r#""ObTypeIndexTable": {"address": 1888}"#,
        r#""ObTypeIndexTable": {"address": 1888},
    "CmpCallBackVector": {"address": 1936}"#,
    )
}

// ── Building the image ──────────────────────────────────────────────────────

/// A `_UNICODE_STRING` at `at`, with its characters at `buffer`.
fn put_unicode(image: &mut Image, at: u64, buffer: u64, text: &str) {
    let bytes = u16::try_from(text.encode_utf16().count() * 2).expect("a short fixture string");
    image.put_u16(at + off::UNICODE_LENGTH, bytes);
    image.put_u16(at + off::UNICODE_MAX_LENGTH, bytes);
    image.put_u64(at + off::UNICODE_BUFFER, buffer);
    image.put_utf16(buffer, text);
}

/// A NUL-terminated ASCII string, as a bugcheck record's component is.
fn put_ascii(image: &mut Image, at: u64, text: &str) {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    image.write(at, &bytes);
}

/// A pool allocation holding an executive object with no optional headers, so
/// its `_OBJECT_HEADER` sits at the very start of the allocation.
///
/// Returns the address of the object body.
fn put_executive(
    image: &mut Image,
    pool_base: u64,
    tag: &[u8; 4],
    pool_type: u16,
    block_size: u16,
    type_index: u8,
) -> u64 {
    image.put_u16(pool_base + off::POOL_BLOCK_SIZE, block_size);
    image.put_u16(pool_base + off::POOL_TYPE, pool_type);
    image.write(pool_base + off::POOL_TAG, tag);
    let header = pool_base + off::POOL_HEADER_SIZE;
    image.put_u32(header + off::OH_POINTER_COUNT, 4);
    image.put_u8(header + off::OH_TYPE_INDEX, type_index);
    image.put_u8(header + off::OH_INFO_MASK, 0);
    header + off::OH_BODY
}

/// A pool allocation holding a structure that is not an executive object, so it
/// follows the pool header directly.
///
/// Returns the address of the structure.
fn put_plain(
    image: &mut Image,
    pool_base: u64,
    tag: &[u8; 4],
    pool_type: u16,
    block_size: u16,
) -> u64 {
    image.put_u16(pool_base + off::POOL_BLOCK_SIZE, block_size);
    image.put_u16(pool_base + off::POOL_TYPE, pool_type);
    image.write(pool_base + off::POOL_TAG, tag);
    pool_base + off::POOL_HEADER_SIZE
}

/// The object manager's type table: slot 1 is `Driver`, and the null at slot 2
/// ends it as a real table's first null does.
fn put_type_table(image: &mut Image) {
    image.put_u64(TYPE_INDEX_TABLE, 0);
    image.put_u64(TYPE_INDEX_TABLE + 8, OBJECT_TYPE_DRIVER);
    image.put_u64(TYPE_INDEX_TABLE + 16, 0);
    put_unicode(
        image,
        OBJECT_TYPE_DRIVER + off::OBJECT_TYPE_NAME,
        strings::DRIVER_TYPE_NAME,
        "Driver",
    );
}

/// One loader entry, written into a pool allocation so that the sweep and the
/// list walk see the same object — which is what makes the comparison between
/// them meaningful.
///
/// Returns the entry's address.
fn put_loader_entry(
    image: &mut Image,
    pool_base: u64,
    base: u64,
    size: u64,
    full_at: u64,
    name_at: u64,
    name: &str,
) -> u64 {
    let entry = put_plain(image, pool_base, b"MmLd", 2, 8);
    image.put_u64(entry + off::LDR_DLL_BASE, base);
    image.put_u32(
        entry + off::LDR_SIZE_OF_IMAGE,
        u32::try_from(size).expect("a fixture image size"),
    );
    put_unicode(
        image,
        entry + off::LDR_FULL_NAME,
        full_at,
        &format!("\\SystemRoot\\System32\\drivers\\{name}"),
    );
    put_unicode(image, entry + off::LDR_BASE_NAME, name_at, name);
    entry
}

/// The complete fixture image.
pub(crate) fn populated_image() -> Image {
    let mut image = Image::new();
    put_type_table(&mut image);

    // ── The kernel's loaded-module list ─────────────────────────────────────
    //
    // Three loader entries live in `MmLd` allocations; two of them are linked
    // into `PsLoadedModuleList` and the third is not, which is the unlinked
    // driver a pool sweep exists to find.
    let nt_entry = put_loader_entry(
        &mut image,
        LDR_NT_ALLOC,
        NT_BASE,
        NT_SIZE,
        strings::NT_FULL,
        strings::NT_BASE_NAME,
        NT_NAME,
    );
    let flt_entry = put_loader_entry(
        &mut image,
        LDR_FLT_ALLOC,
        FLT_BASE,
        FLT_SIZE,
        strings::FLT_FULL,
        strings::FLT_BASE_NAME,
        FLT_NAME,
    );
    let hidden_entry = put_loader_entry(
        &mut image,
        LDR_HIDDEN_ALLOC,
        HIDDEN_BASE,
        HIDDEN_SIZE,
        strings::HIDDEN_FULL,
        strings::HIDDEN_BASE_NAME,
        HIDDEN_NAME,
    );
    image.put_u64(PS_LOADED_MODULE_LIST + off::LIST_FLINK, nt_entry);
    image.put_u64(nt_entry + off::LDR_LOAD_LINKS + off::LIST_FLINK, flt_entry);
    image.put_u64(
        flt_entry + off::LDR_LOAD_LINKS + off::LIST_FLINK,
        PS_LOADED_MODULE_LIST,
    );
    // The hidden entry's own link points at itself, so a walk that reached it
    // would stop at once rather than wander. It is not in the list.
    image.put_u64(
        hidden_entry + off::LDR_LOAD_LINKS + off::LIST_FLINK,
        hidden_entry,
    );

    // ── Notification callbacks ──────────────────────────────────────────────
    image.put_u64(NOTIFY_BLOCK_NT + off::BLOCK_FUNCTION, NT_ROUTINE);
    image.put_u64(NOTIFY_BLOCK_HIDDEN + off::BLOCK_FUNCTION, HIDDEN_ROUTINE);
    // Slot values carry an `_EX_FAST_REF` reference count in their low bits. A
    // stage that fails to mask it reads the block fifteen bytes early.
    image.put_u64(PROCESS_NOTIFY_ARRAY, NOTIFY_BLOCK_NT | 1);
    image.put_u64(THREAD_NOTIFY_ARRAY, NOTIFY_BLOCK_HIDDEN | 3);
    // The image-load array is deliberately left empty: an array with no
    // registration is ordinary and must not read as a failure. Written
    // explicitly so the fixture states it rather than leaving it to be inferred
    // from the absence of a line.
    image.put_u64(IMAGE_NOTIFY_ARRAY, 0);

    // ── Registry callbacks ──────────────────────────────────────────────────
    image.put_u64(REGISTRY_LIST_HEAD + off::LIST_FLINK, REGISTRY_ENTRY);
    image.put_u64(REGISTRY_ENTRY + off::LIST_FLINK, REGISTRY_LIST_HEAD);
    image.put_u64(REGISTRY_ENTRY + off::CM_FUNCTION, FLT_ROUTINE);
    put_unicode(
        &mut image,
        REGISTRY_ENTRY + off::CM_ALTITUDE,
        strings::ALTITUDE,
        REGISTRY_ALTITUDE,
    );
    image.put_u32(REGISTRY_COUNT_AT, 1);
    // The legacy vector, read only by the ISF variant that names it.
    image.put_u64(REGISTRY_VECTOR, NOTIFY_BLOCK_NT | 1);

    // ── Bugcheck callbacks ──────────────────────────────────────────────────
    image.put_u64(BUGCHECK_LIST_HEAD + off::LIST_FLINK, BUGCHECK_RECORD);
    image.put_u64(BUGCHECK_RECORD + off::LIST_FLINK, BUGCHECK_LIST_HEAD);
    image.put_u64(BUGCHECK_RECORD + off::BUGCHECK_ROUTINE, BUGCHECK_ROUTINE);
    image.put_u64(
        BUGCHECK_RECORD + off::BUGCHECK_COMPONENT,
        strings::COMPONENT,
    );
    put_ascii(&mut image, strings::COMPONENT, BUGCHECK_COMPONENT);

    image.put_u64(
        BUGCHECK_REASON_LIST_HEAD + off::LIST_FLINK,
        BUGCHECK_REASON_RECORD,
    );
    image.put_u64(
        BUGCHECK_REASON_RECORD + off::LIST_FLINK,
        BUGCHECK_REASON_LIST_HEAD,
    );
    image.put_u64(
        BUGCHECK_REASON_RECORD + off::BUGCHECK_ROUTINE,
        BUGCHECK_REASON_ROUTINE,
    );

    // ── The service table ───────────────────────────────────────────────────
    //
    // Four entries, each a signed 32-bit offset from the table shifted left by
    // four. Entry 2 is negative on purpose: only an arithmetic shift recovers
    // an address below the table, and a logical shift turns it into a
    // four-gigabyte forward jump that would land outside every module.
    image.put_u32(SERVICE_LIMIT_AT, 4);
    let entry_for = |target: u64| -> u32 {
        let offset = i64::try_from(target).expect("a fixture address")
            - i64::try_from(SERVICE_TABLE).expect("a fixture address");
        (offset << 4) as u32
    };
    image.put_u32(SERVICE_TABLE, entry_for(NT_ROUTINE));
    image.put_u32(SERVICE_TABLE + 4, entry_for(SERVICE_HIDDEN_TARGET));
    image.put_u32(SERVICE_TABLE + 8, entry_for(SERVICE_LOW_TARGET));
    image.put_u32(SERVICE_TABLE + 12, entry_for(SERVICE_FLT_TARGET));

    // ── Driver objects ──────────────────────────────────────────────────────
    let flt_driver = put_executive(&mut image, DRIVER_FLT_ALLOC, b"Driv", 2, 32, 1);
    image.put_u64(flt_driver + off::DRIVER_START, FLT_BASE);
    image.put_u32(
        flt_driver + off::DRIVER_SIZE,
        u32::try_from(FLT_SIZE).expect("a fixture image size"),
    );
    image.put_u64(flt_driver + off::DRIVER_EXTENSION, DRIVER_FLT_EXTENSION);
    image.put_u64(flt_driver + off::DRIVER_INIT, FLT_BASE + 0x10);
    image.put_u64(flt_driver + off::DRIVER_UNLOAD, FLT_BASE + 0x20);
    put_unicode(
        &mut image,
        flt_driver + off::DRIVER_NAME,
        strings::FLT_DRIVER_NAME,
        FLT_DRIVER_PATH,
    );
    put_unicode(
        &mut image,
        DRIVER_FLT_EXTENSION + off::EXTENSION_SERVICE_KEY,
        strings::FLT_SERVICE_KEY,
        FLT_SERVICE_KEY,
    );
    for index in 0..28u64 {
        let handler = if index == HOOKED_IRP_INDEX {
            FLT_HOOKED_DISPATCH
        } else {
            FLT_DISPATCH
        };
        image.put_u64(flt_driver + off::DRIVER_MAJOR_FUNCTION + index * 8, handler);
    }

    // A driver object whose `DriverStart` has been zeroed, which is what a
    // rootkit does to make its image range unanswerable.
    let blank_driver = put_executive(&mut image, DRIVER_BLANK_ALLOC, b"Driv", 2, 32, 1);
    put_unicode(
        &mut image,
        blank_driver + off::DRIVER_NAME,
        strings::BLANK_DRIVER_NAME,
        "\\Driver\\hidden",
    );
    for index in 0..28u64 {
        image.put_u64(
            blank_driver + off::DRIVER_MAJOR_FUNCTION + index * 8,
            BLANK_DISPATCH,
        );
    }

    image
}

/// A profile over one fixture image and one ISF.
pub(crate) fn hook_profile(image: Image, isf: &str) -> WindowsProfile {
    profile(
        image.layer(),
        table(isf),
        Architecture::X64,
        10,
        0,
        Some(22000),
    )
}
