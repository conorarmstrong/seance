//! Naming the object behind a handle.
//!
//! A handle row that says only "the process at 0x…8080 held a File handle with
//! access 0x100081" is close to useless. The finding is *which* file: whether
//! the process had the victim's mailbox open, whether it held the SAM hive,
//! whether the mutex it owned is the one a particular malware family uses to
//! avoid running twice. Getting from an `_OBJECT_HEADER` to that string is what
//! this module does, and it is five different jobs depending on what kind of
//! object it is.
//!
//! # The generic name lives in a header that may not be there
//!
//! Most named kernel objects — mutants, events, sections, symbolic links —
//! carry their name in an `_OBJECT_HEADER_NAME_INFO` placed *in front of* the
//! object header. Whether it is there at all, and how far in front, is
//! build-specific:
//!
//! | Build | How far back |
//! |---|---|
//! | XP, 2003 | `_OBJECT_HEADER.NameInfoOffset`, a byte in the header itself |
//! | Vista and later | `ObpInfoMaskToOffset[InfoMask & 3]`, a kernel table |
//!
//! An offset of zero means the object has no name info, which is a fact about
//! the object. Not being able to *find out* is a different thing entirely, and
//! [`NameInfoLocation::Unavailable`] keeps them apart so a nameless-looking
//! table is never quietly produced on a build whose lookup this module cannot
//! do.
//!
//! # Four kinds of object do not use it
//!
//! * **File** — the name is `_FILE_OBJECT.FileName`, and it is a path *relative
//!   to a device*. `\Windows\notepad.exe` on its own is ambiguous across
//!   volumes, so the device object's own name is resolved and prefixed, giving
//!   `\Device\HarddiskVolume2\Windows\notepad.exe`. When the device cannot be
//!   named the bare path is reported and the row says the device was not
//!   resolved, rather than implying a volume.
//! * **Process** and **Thread** — the object is an `_EPROCESS` or `_ETHREAD`,
//!   and the useful identity is the image name and PID, or the thread and
//!   process ids. A handle from one process to another is how one process reads
//!   or writes another's memory, so the target's identity is the finding.
//! * **Key** — the object is a `_CM_KEY_BODY`, and the path is assembled by
//!   walking key control blocks up to the hive root. The walk is bounded and
//!   cycle-safe: these are pointers out of an image.

use std::collections::HashSet;
use std::sync::Arc;

use seance_memory::object::{Obj, ObjError, StructReader};

use crate::handles::token::{first_member, TokenError};
use crate::poolscan::{decode_utf16le, image_file_name, unicode_string};
use crate::profile::WindowsProfile;

/// The header in front of every executive object.
pub const TYPE_OBJECT_HEADER: &str = "_OBJECT_HEADER";

/// The optional header that carries an object's name.
pub const TYPE_OBJECT_HEADER_NAME_INFO: &str = "_OBJECT_HEADER_NAME_INFO";

/// The kernel table mapping an `InfoMask` to the distance back to the name
/// info, on Vista and later.
pub const SYMBOL_INFO_MASK_TO_OFFSET: &str = "ObpInfoMaskToOffset";

/// The bit of `InfoMask` that announces an `_OBJECT_HEADER_NAME_INFO`.
pub const NAME_INFO_BIT: u64 = 0x2;

/// The mask applied to `InfoMask` before indexing `ObpInfoMaskToOffset`.
///
/// `NAME_INFO_BIT | (NAME_INFO_BIT - 1)`: the table is indexed by the bits at
/// and below the one being looked for, because the headers below it are what
/// decide how far back this one sits.
pub const NAME_INFO_MASK: u64 = NAME_INFO_BIT | (NAME_INFO_BIT - 1);

/// How many entries `ObpInfoMaskToOffset` has, so the index is bounded before
/// it is used.
pub const INFO_MASK_TABLE_LEN: u64 = 256;

/// A file object.
pub const TYPE_FILE_OBJECT: &str = "_FILE_OBJECT";

/// A device object, which a file's path is relative to.
pub const TYPE_DEVICE_OBJECT: &str = "_DEVICE_OBJECT";

/// The process structure a Process handle points at.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// The thread structure a Thread handle points at.
pub const TYPE_ETHREAD: &str = "_ETHREAD";

/// The open-registry-key structure a Key handle points at.
pub const TYPE_CM_KEY_BODY: &str = "_CM_KEY_BODY";

/// The key control block a `_CM_KEY_BODY` names its path through.
pub const TYPE_CM_KEY_CONTROL_BLOCK: &str = "_CM_KEY_CONTROL_BLOCK";

/// The name control block one path component lives in.
pub const TYPE_CM_NAME_CONTROL_BLOCK: &str = "_CM_NAME_CONTROL_BLOCK";

/// `KEY_HIVE_ENTRY`, in `_CM_KEY_CONTROL_BLOCK.Flags`.
///
/// From Windows 10 14393 the key control block chain carries one extra element
/// standing for the hive itself, which is not part of the key's path.
pub const KEY_HIVE_ENTRY: u64 = 0x04;

/// Ceiling on components in one registry key path.
///
/// The deepest path Windows itself creates is about twenty. Reaching this means
/// the control-block chain is not a path.
pub const MAX_KEY_DEPTH: usize = 128;

/// Ceiling on the byte length of one key-path component.
pub const MAX_KEY_COMPONENT_BYTES: u64 = 1024;

/// The object type names this module gives special treatment.
pub const TYPE_NAME_FILE: &str = "File";
/// The object-manager name of a process object.
pub const TYPE_NAME_PROCESS: &str = "Process";
/// The object-manager name of a thread object.
pub const TYPE_NAME_THREAD: &str = "Thread";
/// The object-manager name of an open registry key.
pub const TYPE_NAME_KEY: &str = "Key";

// ── Layout ──────────────────────────────────────────────────────────────────

/// How an object's generic name is reached on this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameInfoLocation {
    /// XP and 2003: a byte in the object header says how far back the name info
    /// is.
    HeaderMember(String),
    /// Vista and later: `ObpInfoMaskToOffset`, indexed by the low bits of
    /// `InfoMask`.
    InfoMaskTable {
        /// Path to `InfoMask` inside `_OBJECT_HEADER`.
        info_mask: String,
        /// Address of the table in the kernel address space.
        table: u64,
    },
    /// Neither is available, so a generic name cannot be produced at all. The
    /// string says why, and every object that would have used it reports
    /// [`HandleName::Unavailable`] rather than looking nameless.
    Unavailable(String),
}

impl NameInfoLocation {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            NameInfoLocation::HeaderMember(_) => "header_member",
            NameInfoLocation::InfoMaskTable { .. } => "info_mask_table",
            NameInfoLocation::Unavailable(_) => "unavailable",
        }
    }
}

/// The members a file handle's name is read through.
#[derive(Debug, Clone)]
pub struct FileNameSymbols {
    /// Path to the `_UNICODE_STRING` holding the path within the device.
    pub file_name: String,
    /// Path to the device object pointer, when this build has one.
    pub device_object: Option<String>,
}

/// The members a process handle's name is read through.
#[derive(Debug, Clone)]
pub struct ProcessNameSymbols {
    /// Path to the fixed-width image name.
    pub image_file_name: String,
    /// Path to the process id.
    pub unique_process_id: String,
}

/// The members a thread handle's name is read through.
#[derive(Debug, Clone)]
pub struct ThreadNameSymbols {
    /// Path to the thread id.
    pub unique_thread: String,
    /// Path to the owning process id.
    pub unique_process: String,
}

/// The members a registry-key handle's path is walked through.
#[derive(Debug, Clone)]
pub struct KeyNameSymbols {
    /// Path to the key control block pointer on `_CM_KEY_BODY`.
    pub key_control_block: String,
    /// Path to the parent control block pointer.
    pub parent: String,
    /// Path to the name control block pointer.
    pub name_block: String,
    /// Path to the name characters inside a name control block.
    pub name: String,
    /// Path to the name's length in bytes.
    pub name_length: String,
    /// Path to the flag saying the name is stored one byte per character.
    pub compressed: Option<String>,
    /// Path to the control block's flags, which mark the extra hive element.
    pub flags: Option<String>,
    /// Whether this build has the extra hive element to skip at all.
    pub has_hive_entry: bool,
}

/// Everything one image's handle names are resolved through.
#[derive(Debug, Clone)]
pub struct NameSymbols {
    /// Distance from an `_OBJECT_HEADER` to the object it heads.
    pub body_offset: u64,
    /// How the generic name is reached.
    pub name_info: NameInfoLocation,
    /// Path to the `_UNICODE_STRING` inside `_OBJECT_HEADER_NAME_INFO`.
    pub name_info_name: Option<String>,
    /// File handles, when this build declares `_FILE_OBJECT`.
    pub file: Option<FileNameSymbols>,
    /// Process handles, when this build declares `_EPROCESS`.
    pub process: Option<ProcessNameSymbols>,
    /// Thread handles, when this build declares `_ETHREAD`.
    pub thread: Option<ThreadNameSymbols>,
    /// Key handles, when this build declares the registry control blocks.
    pub key: Option<KeyNameSymbols>,
}

impl NameSymbols {
    /// Resolve everything needed to name the object behind a handle.
    ///
    /// # Errors
    ///
    /// [`TokenError::Unsupported`] only when `_OBJECT_HEADER` has no `Body`,
    /// which means no object can be located inside its allocation at all.
    /// Everything else is optional and becomes a stated `Unavailable` on the
    /// rows it would have applied to: a build without `_CM_KEY_BODY` still
    /// produces a handle table, with its registry rows saying why they have no
    /// path.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, TokenError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type(TYPE_OBJECT_HEADER) {
            return Err(TokenError::unsupported(format!(
                "the symbol table has no '{TYPE_OBJECT_HEADER}', so the object behind a handle \
                 cannot be located"
            )));
        }
        let body_offset = reader
            .member_offset(TYPE_OBJECT_HEADER, "Body")
            .map_err(|err| {
                TokenError::unsupported(format!(
                    "'{TYPE_OBJECT_HEADER}.Body' could not be located, so the distance from an \
                     object header to its object is unknown: {err}"
                ))
            })?
            .bytes();

        let name_info = resolve_name_info(profile, &reader);
        let name_info_name = if profile.symbols.has_type(TYPE_OBJECT_HEADER_NAME_INFO) {
            first_member(&reader, TYPE_OBJECT_HEADER_NAME_INFO, &["Name"])?.map(str::to_string)
        } else {
            None
        };

        let file = match first_member(&reader, TYPE_FILE_OBJECT, &["FileName"])? {
            Some(file_name) => Some(FileNameSymbols {
                file_name: file_name.to_string(),
                device_object: first_member(&reader, TYPE_FILE_OBJECT, &["DeviceObject"])?
                    .map(str::to_string),
            }),
            None => None,
        };

        let process = match (
            first_member(&reader, TYPE_EPROCESS, &["ImageFileName"])?,
            first_member(&reader, TYPE_EPROCESS, &["UniqueProcessId"])?,
        ) {
            (Some(image_file_name), Some(unique_process_id)) => Some(ProcessNameSymbols {
                image_file_name: image_file_name.to_string(),
                unique_process_id: unique_process_id.to_string(),
            }),
            _ => None,
        };

        let thread = match (
            first_member(&reader, TYPE_ETHREAD, &["Cid.UniqueThread"])?,
            first_member(&reader, TYPE_ETHREAD, &["Cid.UniqueProcess"])?,
        ) {
            (Some(unique_thread), Some(unique_process)) => Some(ThreadNameSymbols {
                unique_thread: unique_thread.to_string(),
                unique_process: unique_process.to_string(),
            }),
            _ => None,
        };

        let key = resolve_key_symbols(profile, &reader)?;

        Ok(Self {
            body_offset,
            name_info,
            name_info_name,
            file,
            process,
            thread,
            key,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "body_offset": self.body_offset,
            "name_info": self.name_info.as_str(),
            "name_info_name": self.name_info_name,
            "has_file": self.file.is_some(),
            "has_process": self.process.is_some(),
            "has_thread": self.thread.is_some(),
            "has_key": self.key.is_some(),
        })
    }
}

/// Where this build keeps the distance back to an object's name info.
fn resolve_name_info(profile: &WindowsProfile, reader: &StructReader) -> NameInfoLocation {
    if !profile.symbols.has_type(TYPE_OBJECT_HEADER_NAME_INFO) {
        return NameInfoLocation::Unavailable(format!(
            "the symbol table has no '{TYPE_OBJECT_HEADER_NAME_INFO}', so a named object's name \
             cannot be read"
        ));
    }
    // XP first: a build that has the byte in the header uses it, and reading
    // `ObpInfoMaskToOffset` there would index a table that does not exist.
    //
    // The three outcomes are kept apart deliberately. "This build declares no
    // `NameInfoOffset`" is XP saying nothing was missed; "the symbol table could
    // not answer" is damage, and reporting it as the first would be a fabricated
    // claim about the suspect's machine.
    match first_member(reader, TYPE_OBJECT_HEADER, &["NameInfoOffset"]) {
        Ok(Some(member)) => return NameInfoLocation::HeaderMember(member.to_string()),
        Ok(None) => {}
        Err(err) => {
            return NameInfoLocation::Unavailable(format!(
                "the symbol table could not say whether '{TYPE_OBJECT_HEADER}' declares \
                 NameInfoOffset, so how a named object's name is reached is unknown: {err}"
            ))
        }
    }
    let info_mask = match first_member(reader, TYPE_OBJECT_HEADER, &["InfoMask"]) {
        Ok(Some(member)) => member.to_string(),
        Ok(None) => {
            return NameInfoLocation::Unavailable(format!(
                "'{TYPE_OBJECT_HEADER}' has neither NameInfoOffset nor InfoMask, so how far in \
                 front of an object header its name info sits cannot be worked out"
            ))
        }
        Err(err) => {
            return NameInfoLocation::Unavailable(format!(
                "the symbol table could not say whether '{TYPE_OBJECT_HEADER}' declares InfoMask, \
                 so how far in front of an object header its name info sits is unknown: {err}"
            ))
        }
    };
    let rva = match profile.symbols.symbol_address(SYMBOL_INFO_MASK_TO_OFFSET) {
        Ok(rva) => rva,
        Err(_) => {
            return NameInfoLocation::Unavailable(format!(
                "the symbol table has no '{SYMBOL_INFO_MASK_TO_OFFSET}', so an InfoMask cannot be \
                 turned into the distance back to a name"
            ))
        }
    };
    match profile.kernel_base.value.checked_add(rva) {
        Some(table) => NameInfoLocation::InfoMaskTable { info_mask, table },
        None => NameInfoLocation::Unavailable(format!(
            "the address of '{SYMBOL_INFO_MASK_TO_OFFSET}' does not fit in the 64-bit address space"
        )),
    }
}

/// The registry control-block members, when this build has all of them.
///
/// `Ok(None)` means this build does not describe registry key paths, so the key
/// rows of the handle table say why they have no path rather than looking as
/// though the keys had none. `Err` means the symbol table could not answer,
/// which is a different claim and is not silently turned into the first.
fn resolve_key_symbols(
    profile: &WindowsProfile,
    reader: &StructReader,
) -> Result<Option<KeyNameSymbols>, ObjError> {
    for type_name in [
        TYPE_CM_KEY_BODY,
        TYPE_CM_KEY_CONTROL_BLOCK,
        TYPE_CM_NAME_CONTROL_BLOCK,
    ] {
        if !profile.symbols.has_type(type_name) {
            return Ok(None);
        }
    }
    let (Some(key_control_block), Some(parent), Some(name_block), Some(name), Some(name_length)) = (
        first_member(reader, TYPE_CM_KEY_BODY, &["KeyControlBlock"])?,
        first_member(reader, TYPE_CM_KEY_CONTROL_BLOCK, &["ParentKcb"])?,
        first_member(reader, TYPE_CM_KEY_CONTROL_BLOCK, &["NameBlock"])?,
        first_member(reader, TYPE_CM_NAME_CONTROL_BLOCK, &["Name"])?,
        first_member(reader, TYPE_CM_NAME_CONTROL_BLOCK, &["NameLength"])?,
    ) else {
        return Ok(None);
    };
    Ok(Some(KeyNameSymbols {
        key_control_block: key_control_block.to_string(),
        parent: parent.to_string(),
        name_block: name_block.to_string(),
        name: name.to_string(),
        name_length: name_length.to_string(),
        compressed: first_member(reader, TYPE_CM_NAME_CONTROL_BLOCK, &["Compressed"])?
            .map(str::to_string),
        flags: first_member(reader, TYPE_CM_KEY_CONTROL_BLOCK, &["Flags"])?.map(str::to_string),
        // The extra hive element arrived with the same build that added
        // `_CM_KEY_BODY.Trans`, which is how its presence is detected without
        // pinning a build number.
        has_hive_entry: reader.has_member(TYPE_CM_KEY_BODY, "Trans"),
    }))
}

// ── Result ──────────────────────────────────────────────────────────────────

/// The name of the object behind a handle, or why there is not one.
///
/// [`HandleName::Unnamed`] and [`HandleName::Unavailable`] are kept apart
/// because an unnamed object is ordinary — most events and sections have no
/// name — while an unavailable one means the bytes were not captured or the
/// build's layout is unknown, and rendering the second as the first hides a gap
/// in the evidence in the most common column of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleName {
    /// The object genuinely has no name.
    Unnamed,
    /// The name.
    Name(String),
    /// A name exists or might, and it could not be read. The string says why.
    Unavailable(String),
}

impl HandleName {
    /// The name, when there is one.
    pub fn text(&self) -> Option<&str> {
        match self {
            HandleName::Name(name) => Some(name),
            _ => None,
        }
    }

    /// Whether the name exists and could not be read.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, HandleName::Unavailable(_))
    }

    /// Stable identifier for artifact metadata.
    pub fn kind(&self) -> &'static str {
        match self {
            HandleName::Unnamed => "unnamed",
            HandleName::Name(_) => "name",
            HandleName::Unavailable(_) => "unavailable",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            HandleName::Unnamed => serde_json::json!({"kind": "unnamed"}),
            HandleName::Name(name) => serde_json::json!({"kind": "name", "name": name}),
            HandleName::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

// ── Naming ──────────────────────────────────────────────────────────────────

/// Name the object an `_OBJECT_HEADER` heads.
///
/// `header` is the object header's address and `object_type` is the
/// object-manager type name already resolved for it. Never returns an error:
/// every way of failing to name an object is a [`HandleName`] variant, because
/// a handle whose target could not be named is still a handle the process held.
pub fn object_name(
    reader: &StructReader,
    symbols: &NameSymbols,
    header: u64,
    object_type: &str,
) -> HandleName {
    let Some(body) = header.checked_add(symbols.body_offset) else {
        return HandleName::Unavailable(
            "the object's body would lie past the end of the address space".to_string(),
        );
    };
    match object_type {
        TYPE_NAME_FILE => file_name(reader, symbols, body),
        TYPE_NAME_PROCESS => process_name(reader, symbols, body),
        TYPE_NAME_THREAD => thread_name(reader, symbols, body),
        TYPE_NAME_KEY => key_name(reader, symbols, body),
        _ => generic_name(reader, symbols, header),
    }
}

/// The name an object's `_OBJECT_HEADER_NAME_INFO` carries.
///
/// `Ok(None)` means the object has no name info, which is ordinary.
pub fn generic_name(reader: &StructReader, symbols: &NameSymbols, header: u64) -> HandleName {
    match name_info_name(reader, symbols, header) {
        Ok(Some(name)) => HandleName::Name(name),
        Ok(None) => HandleName::Unnamed,
        Err(detail) => HandleName::Unavailable(detail),
    }
}

/// The `_OBJECT_HEADER_NAME_INFO` name of an object, as a plain result.
///
/// Split out because a file's device is named the same way, from a different
/// object header.
fn name_info_name(
    reader: &StructReader,
    symbols: &NameSymbols,
    header: u64,
) -> Result<Option<String>, String> {
    let Some(name_path) = symbols.name_info_name.as_deref() else {
        return Err(format!(
            "'{TYPE_OBJECT_HEADER_NAME_INFO}' has no Name on this build"
        ));
    };
    let object_header = reader
        .object(header, TYPE_OBJECT_HEADER)
        .map_err(|err| err.to_string())?;

    let distance = match &symbols.name_info {
        NameInfoLocation::Unavailable(detail) => return Err(detail.clone()),
        NameInfoLocation::HeaderMember(member) => object_header
            .int(member)
            .map_err(|err| format!("'{member}' could not be read: {err}"))?
            .as_u64()
            .ok_or_else(|| format!("'{member}' is negative, which is not a distance"))?,
        NameInfoLocation::InfoMaskTable { info_mask, table } => {
            let mask = object_header
                .int(info_mask)
                .map_err(|err| format!("'{info_mask}' could not be read: {err}"))?
                .as_u64()
                .ok_or_else(|| format!("'{info_mask}' is negative, which is not a mask"))?;
            let index = mask & NAME_INFO_MASK;
            if index >= INFO_MASK_TABLE_LEN {
                return Err(format!(
                    "an InfoMask index of {index} is past the end of \
                     '{SYMBOL_INFO_MASK_TO_OFFSET}'"
                ));
            }
            let at = table
                .checked_add(index)
                .ok_or_else(|| format!("'{SYMBOL_INFO_MASK_TO_OFFSET}' wraps the address space"))?;
            let byte = reader
                .read_bytes(at, 1)
                .map_err(|err| format!("'{SYMBOL_INFO_MASK_TO_OFFSET}[{index}]': {err}"))?;
            u64::from(byte[0])
        }
    };
    // Zero means the object has no name info at all, which most objects do not.
    if distance == 0 {
        return Ok(None);
    }
    let name_info = header
        .checked_sub(distance)
        .ok_or_else(|| "the name info would sit below address zero".to_string())?;
    let object = reader
        .object(name_info, TYPE_OBJECT_HEADER_NAME_INFO)
        .map_err(|err| err.to_string())?;
    unicode_string(&object, name_path).map_err(|err| err.to_string())
}

/// The device-qualified path a file handle names.
fn file_name(reader: &StructReader, symbols: &NameSymbols, body: u64) -> HandleName {
    let Some(file) = symbols.file.as_ref() else {
        return HandleName::Unavailable(format!(
            "the symbol table has no '{TYPE_FILE_OBJECT}.FileName', so a file handle cannot be \
             named"
        ));
    };
    let object = match reader.object(body, TYPE_FILE_OBJECT) {
        Ok(object) => object,
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };
    let path = match unicode_string(&object, &file.file_name) {
        Ok(path) => path,
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };

    // The device prefix, when it can be had. A path without it is still the
    // truth about the handle; a path *with the wrong one* would name a file on
    // a volume the process never touched, so a device that cannot be named is
    // omitted and said.
    let device = file
        .device_object
        .as_deref()
        .and_then(|member| device_name(reader, symbols, &object, member));

    match (device, path) {
        (Some(device), Some(path)) => HandleName::Name(format!("{device}{path}")),
        (Some(device), None) => HandleName::Name(device),
        (None, Some(path)) => HandleName::Name(path),
        (None, None) => HandleName::Unnamed,
    }
}

/// `\Device\<name>` for the device a file object sits on.
fn device_name(
    reader: &StructReader,
    symbols: &NameSymbols,
    file: &Obj,
    member: &str,
) -> Option<String> {
    let device = file.pointer(member).ok()?;
    if device == 0 {
        return None;
    }
    // A device object is an executive object like any other, so its name is in
    // the name info in front of *its* header, which sits `body_offset` in front
    // of the device object itself.
    let header = device.checked_sub(symbols.body_offset)?;
    let name = name_info_name(reader, symbols, header).ok().flatten()?;
    Some(format!("\\Device\\{name}"))
}

/// `<image> Pid <n>` for a handle to another process.
fn process_name(reader: &StructReader, symbols: &NameSymbols, body: u64) -> HandleName {
    let Some(process) = symbols.process.as_ref() else {
        return HandleName::Unavailable(format!(
            "the symbol table cannot describe '{TYPE_EPROCESS}', so a process handle cannot be \
             named"
        ));
    };
    let object = match reader.object(body, TYPE_EPROCESS) {
        Ok(object) => object,
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };
    let image = match object.bytes(&process.image_file_name) {
        Ok(bytes) => image_file_name(&bytes),
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };
    let pid = match object.int(&process.unique_process_id) {
        Ok(value) => value.as_u64(),
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };
    match pid {
        Some(pid) => HandleName::Name(format!("{image} Pid {pid}")),
        None => HandleName::Unavailable(format!(
            "'{}' is negative, which is not a process id",
            process.unique_process_id
        )),
    }
}

/// `Tid <n> Pid <n>` for a handle to a thread.
fn thread_name(reader: &StructReader, symbols: &NameSymbols, body: u64) -> HandleName {
    let Some(thread) = symbols.thread.as_ref() else {
        return HandleName::Unavailable(format!(
            "the symbol table cannot describe '{TYPE_ETHREAD}', so a thread handle cannot be named"
        ));
    };
    let object = match reader.object(body, TYPE_ETHREAD) {
        Ok(object) => object,
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };
    let tid = object
        .int(&thread.unique_thread)
        .ok()
        .and_then(|v| v.as_u64());
    let pid = object
        .int(&thread.unique_process)
        .ok()
        .and_then(|v| v.as_u64());
    match (tid, pid) {
        (Some(tid), Some(pid)) => HandleName::Name(format!("Tid {tid} Pid {pid}")),
        _ => HandleName::Unavailable(format!(
            "'{}' and '{}' could not both be read",
            thread.unique_thread, thread.unique_process
        )),
    }
}

/// The full registry path a key handle names.
///
/// Walks key control blocks from the open key up towards the hive root,
/// collecting one path component per block. The root's own control block has no
/// parent and is not part of the path, which is why the walk stops at it rather
/// than at a null name.
fn key_name(reader: &StructReader, symbols: &NameSymbols, body: u64) -> HandleName {
    let Some(key) = symbols.key.as_ref() else {
        return HandleName::Unavailable(format!(
            "the symbol table cannot describe '{TYPE_CM_KEY_BODY}' and its control blocks, so a \
             registry handle cannot be named"
        ));
    };
    let object = match reader.object(body, TYPE_CM_KEY_BODY) {
        Ok(object) => object,
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };
    let mut current = match object.pointer(&key.key_control_block) {
        Ok(0) => return HandleName::Unnamed,
        Ok(value) => value,
        Err(err) => return HandleName::Unavailable(err.to_string()),
    };

    let mut components: Vec<String> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    while current != 0 {
        if components.len() >= MAX_KEY_DEPTH {
            return HandleName::Unavailable(format!(
                "the key control blocks are more than {MAX_KEY_DEPTH} deep, which is a chain \
                 rather than a registry path"
            ));
        }
        // Cycle safety: these are pointers out of an image, and a loop here
        // would build a path forever.
        if !seen.insert(current) {
            return HandleName::Unavailable(
                "the key control blocks form a cycle, so no path can be built from them"
                    .to_string(),
            );
        }
        let block = match reader.object(current, TYPE_CM_KEY_CONTROL_BLOCK) {
            Ok(block) => block,
            Err(err) => return HandleName::Unavailable(err.to_string()),
        };
        let parent = match block.pointer(&key.parent) {
            Ok(value) => value,
            Err(err) => return HandleName::Unavailable(err.to_string()),
        };
        // The block with no parent is the hive's own root. Its name is the
        // hive, not a component of the key's path.
        if parent == 0 {
            break;
        }

        // From Windows 10 14393 one element of the chain stands for the hive
        // entry rather than for a path component. Including it inserts a
        // spurious element into every registry path in the report.
        let skip = key.has_hive_entry
            && key
                .flags
                .as_deref()
                .and_then(|path| block.int(path).ok())
                .and_then(|value| value.as_u64())
                .is_some_and(|flags| flags & KEY_HIVE_ENTRY != 0);
        if !skip {
            let name_block = match block.pointer(&key.name_block) {
                Ok(0) => break,
                Ok(value) => value,
                Err(err) => return HandleName::Unavailable(err.to_string()),
            };
            match key_component(reader, key, name_block) {
                Ok(component) => components.push(component),
                Err(detail) => return HandleName::Unavailable(detail),
            }
        }
        current = parent;
    }

    if components.is_empty() {
        return HandleName::Unnamed;
    }
    components.reverse();
    HandleName::Name(components.join("\\"))
}

/// One component of a registry path, out of a `_CM_NAME_CONTROL_BLOCK`.
///
/// The kernel stores a component either as UTF-16 or, when every character fits
/// in a byte, one byte per character with `Compressed` set. Decoding the second
/// as the first produces a name with a NUL between every letter, and decoding
/// the first as the second produces every other letter.
fn key_component(
    reader: &StructReader,
    key: &KeyNameSymbols,
    name_block: u64,
) -> Result<String, String> {
    let block = reader
        .object(name_block, TYPE_CM_NAME_CONTROL_BLOCK)
        .map_err(|err| err.to_string())?;
    let length = block
        .int(&key.name_length)
        .map_err(|err| format!("'{}' could not be read: {err}", key.name_length))?
        .as_u64()
        .ok_or_else(|| format!("'{}' is negative", key.name_length))?;
    if length == 0 {
        return Ok(String::new());
    }
    if length > MAX_KEY_COMPONENT_BYTES {
        return Err(format!(
            "a key path component of {length} byte(s) is not a name"
        ));
    }
    let compressed = key
        .compressed
        .as_deref()
        .and_then(|path| block.int(path).ok())
        .and_then(|value| value.as_u64())
        .is_some_and(|value| value != 0);

    let at = block
        .member_address(&key.name)
        .map_err(|err| format!("'{}' could not be located: {err}", key.name))?;
    let bytes = reader
        .read_bytes(at, length)
        .map_err(|err| format!("a key path component at {at:#x} could not be read: {err}"))?;
    let (text, damage) = if compressed {
        // One byte per character, in the OEM code page. Rendering the bytes as
        // Latin-1 keeps every one of them visible rather than dropping the ones
        // above 0x7F.
        //
        // The damage test is made on the **bytes**, not on that rendering. Every
        // byte from 0x80 to 0x9F lands on a C1 code point, which Unicode calls a
        // control character and this code page does not: in Windows-1252 those
        // sixteen bytes are ‚ƒ„…†‡ˆ‰Š‹Œ and in Windows-1251 they are Cyrillic
        // letters. Running the Unicode rule over a byte-preserving rendering
        // would refuse to name any key on a non-English system, which is the
        // ordinary evidence this check must not touch.
        let text: String = bytes.iter().map(|byte| char::from(*byte)).collect();
        let damage = bytes
            .iter()
            .find(|byte| **byte < 0x20)
            .map(|byte| match *byte {
                0 => "the name contains an embedded NUL",
                _ => "the name contains a control character",
            });
        (text, damage)
    } else {
        let text = decode_utf16le(&bytes);
        let damage = crate::poolscan::name_damage(&text);
        (text, damage)
    };
    // The same rule the `_UNICODE_STRING` reader applies: a component that
    // decodes to something no registry key is named is a torn or reused name
    // block, and a path built from it is a path the examiner will go looking
    // for. Unavailable says what happened; the damage says something false.
    if let Some(damage) = damage {
        return Err(format!(
            "a key path component at {at:#x} is {length} byte(s) in which {damage}, so it is not \
             the name it was read as"
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::test_support::{
        win10_profile, xp_profile, WIN10_FILE_HEADER, WIN10_KEY_HEADER, WIN10_MUTANT_HEADER,
        WIN10_PROCESS_HEADER, WIN10_THREAD_HEADER, XP_MUTANT_HEADER,
    };

    fn win10() -> (StructReader, NameSymbols) {
        let profile = win10_profile();
        let symbols = NameSymbols::from_profile(&profile).expect("the layout resolves");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        (reader, symbols)
    }

    #[test]
    fn a_named_object_is_read_through_the_info_mask_table_on_a_modern_build() {
        let (reader, symbols) = win10();
        assert!(matches!(
            symbols.name_info,
            NameInfoLocation::InfoMaskTable { .. }
        ));
        assert_eq!(
            object_name(&reader, &symbols, WIN10_MUTANT_HEADER, "Mutant"),
            HandleName::Name("\\BaseNamedObjects\\Mutex1".to_string())
        );
    }

    #[test]
    fn a_named_object_is_read_through_the_header_byte_on_windows_xp() {
        let profile = xp_profile();
        let symbols = NameSymbols::from_profile(&profile).expect("the layout resolves");
        assert!(matches!(
            symbols.name_info,
            NameInfoLocation::HeaderMember(_)
        ));
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        assert_eq!(
            object_name(&reader, &symbols, XP_MUTANT_HEADER, "Mutant"),
            HandleName::Name("\\Sessions\\1\\Windows".to_string())
        );
    }

    #[test]
    fn an_object_whose_name_info_offset_is_zero_is_unnamed_rather_than_unavailable() {
        // The distinction the whole enum exists for: most events and sections
        // really have no name, and that must not read as a failed read.
        let (reader, symbols) = win10();
        assert_eq!(
            object_name(&reader, &symbols, WIN10_FILE_HEADER, "Mutant"),
            HandleName::Unnamed
        );
    }

    #[test]
    fn a_file_handle_is_named_with_the_device_its_path_is_relative_to() {
        let (reader, symbols) = win10();
        assert_eq!(
            object_name(&reader, &symbols, WIN10_FILE_HEADER, "File"),
            HandleName::Name("\\Device\\HarddiskVolume2\\Windows\\notepad.exe".to_string())
        );
    }

    #[test]
    fn a_process_handle_names_the_process_it_could_have_opened() {
        let (reader, symbols) = win10();
        assert_eq!(
            object_name(&reader, &symbols, WIN10_PROCESS_HEADER, "Process"),
            HandleName::Name("explorer.exe Pid 1234".to_string())
        );
    }

    #[test]
    fn a_thread_handle_names_the_thread_and_its_owning_process() {
        let (reader, symbols) = win10();
        assert_eq!(
            object_name(&reader, &symbols, WIN10_THREAD_HEADER, "Thread"),
            HandleName::Name("Tid 8 Pid 4".to_string())
        );
    }

    #[test]
    fn a_key_handle_names_the_full_path_and_stops_at_the_hive_root() {
        let (reader, symbols) = win10();
        assert_eq!(
            object_name(&reader, &symbols, WIN10_KEY_HEADER, "Key"),
            HandleName::Name("Software\\Run".to_string())
        );
    }

    #[test]
    fn an_object_header_whose_bytes_were_never_captured_is_unavailable_not_unnamed() {
        let (reader, symbols) = win10();
        let name = object_name(&reader, &symbols, 0x00FF_0000, "Mutant");
        assert!(name.is_unavailable(), "{name:?}");
        assert_eq!(name.text(), None);
    }

    #[test]
    fn a_build_without_the_name_info_table_says_so_instead_of_reporting_no_names() {
        let profile =
            crate::handles::test_support::win10_profile_without(&["_OBJECT_HEADER_NAME_INFO"]);
        let symbols = NameSymbols::from_profile(&profile).expect("the body offset still resolves");
        assert!(matches!(
            symbols.name_info,
            NameInfoLocation::Unavailable(_)
        ));
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let name = object_name(&reader, &symbols, WIN10_MUTANT_HEADER, "Mutant");
        assert!(
            name.is_unavailable(),
            "a build whose names cannot be read must not report objects as unnamed: {name:?}"
        );
    }
}
