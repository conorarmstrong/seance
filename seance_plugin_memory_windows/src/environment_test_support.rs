//! A synthetic Windows image the whole environment stage can be walked over.
//!
//! The fixtures elsewhere in this crate hand every stage a raw physical layer
//! as its kernel address space, which is enough for a stage that only reads
//! kernel structures. It is not enough here: reading a process's environment
//! means building that process's *own* address space, and a raw physical layer
//! publishes no paging mode to build one from.
//!
//! So this image carries real x86-64 page tables, and they map the part of the
//! image the fixture puts data in twice: once at the offset itself, and once at
//! [`KERNEL`] plus the offset. Every address below is therefore its own physical
//! offset with at most a kernel base added, which keeps the fixture readable
//! while still exercising the page-table walk, the process directory table base
//! and the per-process layer — the three things that stand between a
//! `_RTL_USER_PROCESS_PARAMETERS.Environment` pointer and the variables an
//! examiner reads.
//!
//! The split between the two halves is not decoration. A pool allocation is
//! kernel memory by definition, so a sweep of the kernel address space begins at
//! the kernel half and never looks below it — see
//! [`crate::poolscan::kernel_half_sweep`]. A fixture that put the `Wind`-tagged
//! window station at a *user* address was modelling an image that cannot exist,
//! and the desktop walk it fed found the station only because the sweep started
//! at zero. Kernel structures therefore live above [`KERNEL`] here, and the
//! `_PEB`, parameter block and environment — which really are user addresses in
//! the process's own space — live below it.

use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::translate::{PagingMode, PagingSpec, PteSemantics, VirtualLayer};
use seance_memory::{Architecture, MemoryLayer, PhysicalLayer};
use seance_symbols::SymbolTable;

use crate::profile::{Evidence, Found, KernelBuild, WindowsProfile};

/// Size of the synthetic image.
pub(crate) const IMAGE_SIZE: usize = 0x3_0000;

/// Lowest address of the kernel half of an x86-64 address space.
///
/// The same number [`crate::poolscan::kernel_half_start`] derives from a
/// declared pointer width of eight. Every kernel structure in this fixture sits
/// at `KERNEL` plus its own physical offset, because that is where a kernel
/// structure is, and because a sweep of the kernel space starts here.
pub(crate) const KERNEL: u64 = 0xFFFF_8000_0000_0000;

/// Top-level page table. Also the directory table base of every process here.
pub(crate) const PML4: u64 = 0x1000;
const PDPT: u64 = 0x2000;
const PD: u64 = 0x3000;
const PT: u64 = 0x4000;

/// Present bit of a page-table entry.
const PRESENT: u64 = 1;

/// `PML4` slot covering [`KERNEL`]: bits 47:39 of `0xFFFF_8000_0000_0000`.
const KERNEL_PML4_INDEX: u64 = 256;

/// Lowest mapped offset. Everything the fixture writes lives above it, so the
/// page tables themselves are never reachable virtually.
pub(crate) const MAPPED_FROM: u64 = 0x5000;

/// `PsActiveProcessHead`.
pub(crate) const HEAD: u64 = KERNEL + 0x5000;

/// The System process: no PEB, no session.
pub(crate) const SYSTEM: u64 = KERNEL + 0x6000;

/// An interactive process in session 1, with a full environment.
pub(crate) const EXPLORER: u64 = KERNEL + 0x7000;

/// A service in session 0.
pub(crate) const SVCHOST: u64 = KERNEL + 0x8000;

/// Session 0's `_MM_SESSION_SPACE`.
pub(crate) const SESSION0: u64 = KERNEL + 0x9000;

/// Session 1's `_MM_SESSION_SPACE`.
pub(crate) const SESSION1: u64 = KERNEL + 0x9200;

/// A process on session 1's own process list and *not* on the active process
/// list: the unlinked-process finding the session cross-check exists for.
pub(crate) const HIDDEN: u64 = KERNEL + 0xB000;

/// `explorer.exe`'s PEB.
pub(crate) const PEB_EXPLORER: u64 = 0xC000;
/// `explorer.exe`'s `_RTL_USER_PROCESS_PARAMETERS`.
pub(crate) const PARAMS_EXPLORER: u64 = 0xC100;

/// `svchost.exe`'s PEB.
pub(crate) const PEB_SVCHOST: u64 = 0xC800;
const PARAMS_SVCHOST: u64 = 0xC900;

/// `explorer.exe`'s environment block.
pub(crate) const ENV_EXPLORER: u64 = 0xD000;

/// `svchost.exe`'s environment block.
pub(crate) const ENV_SVCHOST: u64 = 0xE000;

/// The desktop `explorer.exe`'s thread is attached to.
pub(crate) const DESKTOP_A: u64 = KERNEL + 0x11000;

/// A second desktop on the same station, which is the thing worth finding.
pub(crate) const DESKTOP_B: u64 = KERNEL + 0x11200;

const THREAD_A: u64 = KERNEL + 0x12000;
const THREAD_B: u64 = KERNEL + 0x12100;
const PROCINFO_A: u64 = KERNEL + 0x12300;
const PROCINFO_B: u64 = KERNEL + 0x12380;

/// The `Wind`-tagged pool allocation holding the window station.
pub(crate) const POOL_STATION: u64 = KERNEL + 0x14000;
const STATION_NAME_INFO: u64 = KERNEL + 0x14010;
const STATION_HEADER: u64 = KERNEL + 0x14030;

/// The `tagWINDOWSTATION` itself, `Body` bytes past its object header.
pub(crate) const STATION: u64 = KERNEL + 0x14060;

const STATION_NAME_TEXT: u64 = KERNEL + 0x15000;
const DESKTOP_A_NAME_TEXT: u64 = KERNEL + 0x15100;
const DESKTOP_B_NAME_TEXT: u64 = KERNEL + 0x15200;

const TYPE_TABLE: u64 = KERNEL + 0x16000;
const OBJECT_TYPE_AT: u64 = KERNEL + 0x17000;
const OBJECT_TYPE_NAME_TEXT: u64 = KERNEL + 0x17100;
const HEADER_COOKIE_AT: u64 = KERNEL + 0x17200;

/// The per-boot object-header cookie the fixture uses.
const HEADER_COOKIE: u64 = 0x2B;

/// Distance from an `_OBJECT_HEADER` to the object it heads, as the fixture's
/// ISF declares it.
const BODY_OFFSET: u64 = 48;

/// Distance from an `_OBJECT_HEADER` back to its `_OBJECT_HEADER_NAME_INFO`.
const NAME_INFO_DISTANCE: u64 = 32;

/// Offsets the fixture's `_EPROCESS` declares.
pub(crate) mod off {
    pub(crate) const DTB: u64 = 0;
    pub(crate) const CREATE_TIME: u64 = 32;
    pub(crate) const PID: u64 = 48;
    pub(crate) const LINKS_FLINK: u64 = 56;
    pub(crate) const LINKS_BLINK: u64 = 64;
    pub(crate) const PPID: u64 = 72;
    pub(crate) const SESSION: u64 = 88;
    pub(crate) const PEB: u64 = 96;
    pub(crate) const THREADS: u64 = 112;
    pub(crate) const SESSION_LINKS_FLINK: u64 = 120;
    pub(crate) const SESSION_LINKS_BLINK: u64 = 128;
    pub(crate) const NAME: u64 = 136;
}

/// 2021-06-01T00:00:00Z as a Windows FILETIME.
pub(crate) const CREATE_TIME: u64 = 132_669_792_000_000_000;

/// The physical offset a fixture address is written at.
///
/// Both halves of the address space are mapped onto the same bytes, so an
/// address is either its own offset or [`KERNEL`] plus it. Written as one
/// function so a kernel structure can be *declared* at the address it really
/// occupies without every call site restating the arithmetic.
fn offset_of(address: u64) -> u64 {
    address.checked_sub(KERNEL).unwrap_or(address)
}

/// A hand-built image, written by address so a failing test points at one place
/// rather than at a generator.
pub(crate) struct Image {
    pub(crate) bytes: Vec<u8>,
}

impl Image {
    pub(crate) fn new() -> Self {
        Self {
            bytes: vec![0u8; IMAGE_SIZE],
        }
    }

    pub(crate) fn write(&mut self, address: u64, data: &[u8]) {
        let at = offset_of(address) as usize;
        assert!(
            at + data.len() <= IMAGE_SIZE,
            "the fixture writes {} byte(s) at {address:#x}, which lands at offset {at:#x} in a \
             {IMAGE_SIZE:#x} byte image; raise IMAGE_SIZE rather than moving the structure",
            data.len()
        );
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }

    pub(crate) fn put_u64(&mut self, address: u64, value: u64) {
        self.write(address, &value.to_le_bytes());
    }

    pub(crate) fn put_u32(&mut self, address: u64, value: u32) {
        self.write(address, &value.to_le_bytes());
    }

    pub(crate) fn put_u16(&mut self, address: u64, value: u16) {
        self.write(address, &value.to_le_bytes());
    }

    pub(crate) fn put_u8(&mut self, address: u64, value: u8) {
        self.write(address, &[value]);
    }

    /// A UTF-16LE string at an address, with no terminator.
    pub(crate) fn put_utf16(&mut self, address: u64, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self.write(address, &bytes);
    }

    /// An environment block: NUL-separated UTF-16LE entries, double-NUL ended.
    ///
    /// Returns the block's length in bytes, which is what a real
    /// `EnvironmentSize` holds.
    pub(crate) fn put_environment(&mut self, address: u64, entries: &[&str]) -> u64 {
        let mut bytes = Vec::new();
        for entry in entries {
            for unit in entry.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&[0, 0]);
        }
        bytes.extend_from_slice(&[0, 0]);
        let length = bytes.len() as u64;
        self.write(address, &bytes);
        length
    }

    /// The raw physical layer over these bytes.
    pub(crate) fn physical(&self) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(self.bytes.clone()));
        Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"))
    }
}

/// Write an x86-64 hierarchy that maps [`MAPPED_FROM`] upwards into both halves
/// of the address space.
///
/// Mapping the low half identity is what lets the fixture use one number for
/// both the physical offset it writes at and the user virtual address the
/// analysis reads at. The kernel half is mapped by pointing a second `PML4`
/// slot at the *same* page-directory-pointer table: everything the fixture
/// writes is under 2 MiB, so the `PDPT`, `PD` and page-table indices of
/// `KERNEL + n` and of `n` are identical, and only the top-level index differs.
/// One kernel structure therefore appears at exactly one kernel address.
///
/// The walk itself is entirely real: four levels, present bits, and a directory
/// table base a process's `_EPROCESS` has to publish before its address space
/// can be built.
fn put_page_tables(image: &mut Image) {
    image.put_u64(PML4, PDPT | PRESENT);
    image.put_u64(PML4 + KERNEL_PML4_INDEX * 8, PDPT | PRESENT);
    image.put_u64(PDPT, PD | PRESENT);
    image.put_u64(PD, PT | PRESENT);
    let mut page = MAPPED_FROM;
    while page < IMAGE_SIZE as u64 {
        // Under 2 MiB the page-table index is just the page number, because the
        // page directory index is zero throughout.
        let index = page >> 12;
        image.put_u64(PT + index * 8, page | PRESENT);
        page += 0x1000;
    }
}

/// Link one `_EPROCESS` into the active process list.
fn link_active(image: &mut Image, at: u64, next: u64, previous: u64) {
    image.put_u64(at + off::LINKS_FLINK, next);
    image.put_u64(at + off::LINKS_BLINK, previous);
}

/// Write one `_EPROCESS`.
fn put_process(
    image: &mut Image,
    at: u64,
    pid: u64,
    ppid: u64,
    name: &str,
    session: u64,
    peb: u64,
) {
    image.put_u64(at + off::DTB, PML4);
    image.put_u64(at + off::CREATE_TIME, CREATE_TIME);
    image.put_u64(at + off::PID, pid);
    image.put_u64(at + off::PPID, ppid);
    image.put_u64(at + off::SESSION, session);
    image.put_u64(at + off::PEB, peb);
    image.put_u64(at + off::THREADS, 4);
    image.write(at + off::NAME, name.as_bytes());
}

/// Write a `_PEB`, its `_RTL_USER_PROCESS_PARAMETERS` and its environment.
fn put_environment_chain(image: &mut Image, peb: u64, params: u64, block: u64, entries: &[&str]) {
    image.put_u64(peb + 32, params);
    let length = image.put_environment(block, entries);
    // `Length` is the size of the whole parameter-block allocation, which on
    // Windows XP contains the environment too and so serves as an upper bound;
    // `EnvironmentSize` is the environment's own length. A build that has only
    // the first still stops decoding at the double NUL.
    image.put_u32(params + 4, 0x1000);
    image.put_u64(params + 128, block);
    image.put_u64(params + 136, length);
}

/// Write an object header and the name info in front of it.
fn put_named_object(image: &mut Image, header: u64, name_text: u64, name: &str) {
    image.put_u32(header, 7); // PointerCount
    image.put_u8(header + 25, NAME_INFO_DISTANCE as u8); // NameInfoOffset
    let info = header - NAME_INFO_DISTANCE;
    let bytes = (name.encode_utf16().count() * 2) as u16;
    image.put_u16(info + 16, bytes); // Name.Length
    image.put_u16(info + 18, bytes + 2); // Name.MaximumLength
    image.put_u64(info + 24, name_text); // Name.Buffer
    image.put_utf16(name_text, name);
}

/// The image every test in this stage walks.
pub(crate) fn image_with_environment() -> Image {
    let mut image = Image::new();
    put_page_tables(&mut image);

    // ── The active process list ────────────────────────────────────────────
    image.put_u64(HEAD, SYSTEM + off::LINKS_FLINK);
    image.put_u64(HEAD + 8, SVCHOST + off::LINKS_FLINK);
    link_active(&mut image, SYSTEM, EXPLORER + off::LINKS_FLINK, HEAD);
    link_active(
        &mut image,
        EXPLORER,
        SVCHOST + off::LINKS_FLINK,
        SYSTEM + off::LINKS_FLINK,
    );
    link_active(&mut image, SVCHOST, HEAD, EXPLORER + off::LINKS_FLINK);

    put_process(&mut image, SYSTEM, 4, 0, "System", 0, 0);
    put_process(
        &mut image,
        EXPLORER,
        1400,
        1200,
        "explorer.exe",
        SESSION1,
        PEB_EXPLORER,
    );
    put_process(
        &mut image,
        SVCHOST,
        900,
        600,
        "svchost.exe",
        SESSION0,
        PEB_SVCHOST,
    );
    put_process(&mut image, HIDDEN, 666, 1400, "evil.exe", SESSION1, 0);

    // ── Sessions ───────────────────────────────────────────────────────────
    image.put_u32(SESSION0 + 8, 0);
    image.put_u32(SESSION1 + 8, 1);

    // Session 0 holds only svchost.exe.
    image.put_u64(SESSION0 + 16, SVCHOST + off::SESSION_LINKS_FLINK);
    image.put_u64(SESSION0 + 24, SVCHOST + off::SESSION_LINKS_FLINK);
    image.put_u64(SVCHOST + off::SESSION_LINKS_FLINK, SESSION0 + 16);
    image.put_u64(SVCHOST + off::SESSION_LINKS_BLINK, SESSION0 + 16);

    // Session 1 holds explorer.exe and a process the active list does not.
    image.put_u64(SESSION1 + 16, EXPLORER + off::SESSION_LINKS_FLINK);
    image.put_u64(SESSION1 + 24, HIDDEN + off::SESSION_LINKS_FLINK);
    image.put_u64(
        EXPLORER + off::SESSION_LINKS_FLINK,
        HIDDEN + off::SESSION_LINKS_FLINK,
    );
    image.put_u64(EXPLORER + off::SESSION_LINKS_BLINK, SESSION1 + 16);
    image.put_u64(HIDDEN + off::SESSION_LINKS_FLINK, SESSION1 + 16);
    image.put_u64(
        HIDDEN + off::SESSION_LINKS_BLINK,
        EXPLORER + off::SESSION_LINKS_FLINK,
    );

    // ── Environments ───────────────────────────────────────────────────────
    put_environment_chain(
        &mut image,
        PEB_EXPLORER,
        PARAMS_EXPLORER,
        ENV_EXPLORER,
        &[
            "USERNAME=sarah",
            "USERDOMAIN=CORP",
            "SESSIONNAME=Console",
            "PATH=C:\\Windows",
            "COR_PROFILER_PATH=C:\\Users\\sarah\\evil.dll",
            "=C:=C:\\Users\\sarah",
        ],
    );
    put_environment_chain(
        &mut image,
        PEB_SVCHOST,
        PARAMS_SVCHOST,
        ENV_SVCHOST,
        &[
            "USERNAME=SYSTEM",
            "USERDOMAIN=NT AUTHORITY",
            "SESSIONNAME=Services",
            "PATH=C:\\Windows",
        ],
    );

    // ── The window station, in a Wind-tagged pool allocation ───────────────
    // Sixteen granules of sixteen bytes: a 256-byte allocation, comfortably
    // above the declared size of a tagWINDOWSTATION.
    image.put_u16(POOL_STATION, 16); // BlockSize
    image.put_u16(POOL_STATION + 2, 2); // PoolType: non-paged, Vista encoding
    image.write(POOL_STATION + 4, b"Wind");
    put_named_object(&mut image, STATION_HEADER, STATION_NAME_TEXT, "WinSta0");
    // One optional header — the name info, bit 1 — sits between the pool header
    // and the object header, which is what the InfoMask below announces.
    image.put_u8(STATION_HEADER + 26, 0b10);
    assert_eq!(STATION_HEADER - NAME_INFO_DISTANCE, STATION_NAME_INFO);
    assert_eq!(STATION_HEADER + BODY_OFFSET, STATION);
    let stored_index = ((1u64 ^ (STATION_HEADER >> 8) ^ HEADER_COOKIE) & 0xFF) as u8;
    image.put_u8(STATION_HEADER + 24, stored_index);

    image.put_u32(STATION, 1); // dwSessionId
    image.put_u64(STATION + 8, 0); // rpwinstaNext
    image.put_u64(STATION + 16, DESKTOP_A); // rpdeskList

    // ── Two desktops, the second of which nobody switched to ───────────────
    put_named_object(
        &mut image,
        DESKTOP_A - BODY_OFFSET,
        DESKTOP_A_NAME_TEXT,
        "Default",
    );
    put_named_object(
        &mut image,
        DESKTOP_B - BODY_OFFSET,
        DESKTOP_B_NAME_TEXT,
        "hidden",
    );
    image.put_u64(DESKTOP_A, DESKTOP_B); // rpdeskNext
    image.put_u64(DESKTOP_A + 8, STATION); // rpwinstaParent
    image.put_u64(DESKTOP_B, 0);
    image.put_u64(DESKTOP_B + 8, STATION);

    // Each desktop's thread list holds one thread.
    image.put_u64(DESKTOP_A + 16, THREAD_A);
    image.put_u64(DESKTOP_A + 24, THREAD_A);
    image.put_u64(THREAD_A, DESKTOP_A + 16);
    image.put_u64(THREAD_A + 8, DESKTOP_A + 16);
    image.put_u64(THREAD_A + 16, PROCINFO_A);
    image.put_u64(PROCINFO_A, EXPLORER);

    image.put_u64(DESKTOP_B + 16, THREAD_B);
    image.put_u64(DESKTOP_B + 24, THREAD_B);
    image.put_u64(THREAD_B, DESKTOP_B + 16);
    image.put_u64(THREAD_B + 8, DESKTOP_B + 16);
    image.put_u64(THREAD_B + 16, PROCINFO_B);
    image.put_u64(PROCINFO_B, HIDDEN);

    // ── The object-type table, so the sweep's type test can actually run ───
    image.put_u64(TYPE_TABLE, 0); // slot zero is always null
    image.put_u64(TYPE_TABLE + 8, OBJECT_TYPE_AT);
    let name = "WindowStation";
    let bytes = (name.encode_utf16().count() * 2) as u16;
    image.put_u16(OBJECT_TYPE_AT, bytes);
    image.put_u16(OBJECT_TYPE_AT + 2, bytes + 2);
    image.put_u64(OBJECT_TYPE_AT + 8, OBJECT_TYPE_NAME_TEXT);
    image.put_utf16(OBJECT_TYPE_NAME_TEXT, name);
    image.put_u8(HEADER_COOKIE_AT, HEADER_COOKIE as u8);

    image
}

/// A profile whose kernel address space is a real page-table walk over `image`.
pub(crate) fn virtual_profile(image: &Image, symbols: Arc<SymbolTable>) -> WindowsProfile {
    let physical = image.physical();
    let kernel_space: Arc<dyn MemoryLayer> = Arc::new(
        VirtualLayer::new(
            Arc::clone(&physical),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows),
        )
        .expect("a usable directory table base"),
    );
    WindowsProfile {
        kernel_space,
        physical,
        symbols,
        pagefiles: Vec::new(),
        dtb: Found::new(PML4, Evidence::Confirmed),
        kernel_base: Found::new(0, Evidence::Confirmed),
        kdbg: None,
        build: KernelBuild {
            pdb: "ntkrnlmp.pdb".into(),
            guid: "0".repeat(32),
            age: 1,
            build_lab: None,
            major: 10,
            minor: 0,
            build: Some(19041),
            build_source: Some("kuser_shared_data"),
        },
        architecture: Architecture::X64,
    }
}

/// The kernel-only symbol table: everything but win32k.
///
/// The ordinary case for a real image, and the one where the desktop survey has
/// to report itself unsupported rather than empty.
pub(crate) fn plain_isf() -> String {
    isf_with_gui(false)
}

/// A symbol table that additionally describes the win32k GUI structures.
///
/// Volatility ships these as hand-written files, one per build. Supplying one
/// is what makes the desktop walk runnable, and this is what it looks like when
/// somebody has.
pub(crate) fn gui_isf() -> String {
    isf_with_gui(true)
}

fn isf_with_gui(gui: bool) -> String {
    let gui_types = if gui {
        r#"
    "tagWINDOWSTATION": {"size": 64, "kind": "struct", "fields": {
      "dwSessionId": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "rpwinstaNext": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned char"}}},
      "rpdeskList": {"offset": 16, "type": {"kind": "pointer",
                     "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "tagDESKTOP": {"size": 64, "kind": "struct", "fields": {
      "rpdeskNext": {"offset": 0, "type": {"kind": "pointer",
                     "subtype": {"kind": "base", "name": "unsigned char"}}},
      "rpwinstaParent": {"offset": 8, "type": {"kind": "pointer",
                         "subtype": {"kind": "base", "name": "unsigned char"}}},
      "PtiList": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
    }},
    "tagTHREADINFO": {"size": 64, "kind": "struct", "fields": {
      "PtiLink": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "ppi": {"offset": 16, "type": {"kind": "pointer",
              "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},
    "tagPROCESSINFO": {"size": 32, "kind": "struct", "fields": {
      "Process": {"offset": 0, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "unsigned char"}}}
    }},"#
    } else {
        ""
    };

    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "CC1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                         "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base_types},
  "user_types": {{
    "_LIST_ENTRY": {{"size": 16, "kind": "struct", "fields": {{
      "Flink": {{"offset": 0, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}},
      "Blink": {{"offset": 8, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_LARGE_INTEGER": {{"size": 8, "kind": "union", "fields": {{
      "QuadPart": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_UNICODE_STRING": {{"size": 16, "kind": "struct", "fields": {{
      "Length": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "MaximumLength": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "Buffer": {{"offset": 8, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "base", "name": "unsigned short"}}}}}}
    }}}},
    "_QUAD": {{"size": 8, "kind": "struct", "fields": {{
      "Value": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_POOL_HEADER": {{"size": 16, "kind": "struct", "fields": {{
      "BlockSize": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolType": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolTag": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_OBJECT_HEADER": {{"size": 56, "kind": "struct", "fields": {{
      "PointerCount": {{"offset": 0, "type": {{"kind": "base", "name": "long"}}}},
      "HandleCount": {{"offset": 8, "type": {{"kind": "base", "name": "long"}}}},
      "TypeIndex": {{"offset": 24, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "NameInfoOffset": {{"offset": 25, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "InfoMask": {{"offset": 26, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "Body": {{"offset": 48, "type": {{"kind": "struct", "name": "_QUAD"}}}}
    }}}},
    "_OBJECT_HEADER_CREATOR_INFO": {{"size": 32, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_NAME_INFO": {{"size": 32, "kind": "struct", "fields": {{
      "Name": {{"offset": 16, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    "_OBJECT_HEADER_HANDLE_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_QUOTA_INFO": {{"size": 32, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_PROCESS_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_AUDIT_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_EXTENDED_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_PADDING_INFO": {{"size": 8, "kind": "struct", "fields": {{
      "PaddingAmount": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_OBJECT_TYPE": {{"size": 32, "kind": "struct", "fields": {{
      "Name": {{"offset": 0, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    "_MM_SESSION_SPACE": {{"size": 64, "kind": "struct", "fields": {{
      "SessionId": {{"offset": 8, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "ProcessList": {{"offset": 16, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}
    }}}},
    "_PEB": {{"size": 64, "kind": "struct", "fields": {{
      "ProcessParameters": {{"offset": 32, "type": {{"kind": "pointer",
                             "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_RTL_USER_PROCESS_PARAMETERS": {{"size": 160, "kind": "struct", "fields": {{
      "Length": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "CommandLine": {{"offset": 96, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}},
      "Environment": {{"offset": 128, "type": {{"kind": "pointer",
                       "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "EnvironmentSize": {{"offset": 136, "type": {{"kind": "base",
                           "name": "unsigned long long"}}}}
    }}}},{gui_types}
    "_EPROCESS": {{"size": 640, "kind": "struct", "fields": {{
      "DirectoryTableBase": {{"offset": 0, "type": {{"kind": "base",
                              "name": "unsigned long long"}}}},
      "CreateTime": {{"offset": 32, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "ExitTime": {{"offset": 40, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "UniqueProcessId": {{"offset": 48, "type": {{"kind": "pointer",
                           "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ActiveProcessLinks": {{"offset": 56, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "InheritedFromUniqueProcessId": {{"offset": 72, "type": {{"kind": "pointer",
                                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ObjectTable": {{"offset": 80, "type": {{"kind": "pointer",
                       "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "Session": {{"offset": 88, "type": {{"kind": "pointer",
                   "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "Peb": {{"offset": 96, "type": {{"kind": "pointer",
               "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "WoW64Process": {{"offset": 104, "type": {{"kind": "pointer",
                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ActiveThreads": {{"offset": 112, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "SessionProcessLinks": {{"offset": 120, "type": {{"kind": "struct",
                               "name": "_LIST_ENTRY"}}}},
      "ImageFileName": {{"offset": 136, "type": {{"kind": "array", "count": 15,
                         "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "PsActiveProcessHead": {{"address": {head}}},
    "ObTypeIndexTable": {{"address": {type_table}}},
    "ObHeaderCookie": {{"address": {cookie}}}
  }}
}}"#,
        base_types = crate::image_fixture::BASE_TYPES_X64,
        head = HEAD,
        type_table = TYPE_TABLE,
        cookie = HEADER_COOKIE_AT,
    )
}
