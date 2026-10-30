//! Acquisition-format detection.
//!
//! Every constant here was read out of the Volatility 3 layer sources
//! (`framework/layers/{crash,lime,avml,elf,qemu,vmware}.py`), which are used as
//! the format specification. The detection *policy* is Séance's own and is
//! stricter than upstream's in two places, both noted on the relevant check.

use seance_core::data_source::DataSource;
use seance_core::io::read_full;
use tracing::debug;

use crate::meta::Architecture;

/// Bytes of header pulled for detection. Sixty-four covers the longest
/// structure any check needs (the ELF64 file header).
const HEADER_PROBE_BYTES: usize = 64;

/// `PAGE`, the first word of every Windows crash dump header.
const CRASH_SIGNATURE: &[u8; 4] = b"PAGE";
/// `DUMP`, the second word of a 32-bit crash dump (`_DUMP_HEADER`).
const CRASH_VALID_32: &[u8; 4] = b"DUMP";
/// `DU64`, the second word of a 64-bit crash dump (`_DUMP_HEADER64`).
const CRASH_VALID_64: &[u8; 4] = b"DU64";

/// LiME's magic, `0x4C694D45` as a little-endian `u32`, i.e. the bytes `EMiL`.
const LIME_MAGIC: u32 = 0x4C69_4D45;
/// The only LiME header version upstream accepts, and the only one ever shipped.
const LIME_VERSION: u32 = 1;

/// AVML's magic, `0x4C4D5641` as a little-endian `u32`, i.e. the bytes `AVML`.
const AVML_MAGIC: u32 = 0x4C4D_5641;
/// The only AVML version upstream accepts.
const AVML_VERSION: u32 = 2;

/// QEMU savevm magic `QEVM` followed by a big-endian version word of 3.
const QEMU_MAGIC: &[u8; 8] = b"QEVM\x00\x00\x00\x03";

/// The four VMware snapshot-metadata magics. The low nibble of the first byte
/// is the metadata version (0 through 3).
const VMWARE_MAGICS: [&[u8; 4]; 4] = [
    b"\xd0\xbe\xd2\xbe",
    b"\xd1\xba\xd1\xba",
    b"\xd2\xbe\xd2\xbe",
    b"\xd3\xbe\xd3\xbe",
];
/// Size of one entry in a VMware metadata group table (`64s` name + two `u64`).
const VMWARE_GROUP_ENTRY_BYTES: u64 = 80;
/// Offset of the group table: 4-byte magic + two `u32`.
const VMWARE_GROUP_TABLE_OFFSET: u64 = 12;
/// Sanity bound on the declared group count. Real snapshots hold a handful.
const VMWARE_MAX_GROUPS: u32 = 4096;

/// `\x7fELF`.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
/// `EI_CLASS == ELFCLASS64`.
const ELF_CLASS_64: u8 = 2;
/// `ET_CORE`.
const ELF_TYPE_CORE: u16 = 4;

/// An acquisition format a memory image can arrive in.
///
/// # `Raw` is not a detection
///
/// Eight of the nine formats Volatility supports carry a magic. Raw memory does
/// not: a `.raw`/`.mem`/`.dd` dump is a headerless copy of physical memory, and
/// **no sequence of bytes can prove that a file is one**. Worse, a memory image
/// contains cached copies of MBR sectors, GPT headers and filesystem
/// superblocks, so guessing would make the partition and filesystem modules
/// "find" structure inside RAM and emit fabricated evidence.
///
/// So [`detect`] returning `Raw` means exactly one thing: *no memory-image
/// magic was present*. It is not a claim that the source is memory. Treating a
/// source as raw physical memory requires an examiner declaration; see
/// [`MemoryImageFormat::is_content_detected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryImageFormat {
    /// No memory-image magic found. See the type-level note: this is the
    /// absence of a detection, never a positive one.
    Raw,
    /// Windows crash dump with a 32-bit `_DUMP_HEADER` (`PAGEDUMP`).
    WindowsCrashDump32,
    /// Windows crash dump with a 64-bit `_DUMP_HEADER64` (`PAGEDU64`).
    WindowsCrashDump64,
    /// LiME, the Linux Memory Extractor's segment format.
    Lime,
    /// Microsoft AVML, snappy-framed blocks.
    Avml,
    /// An ELF64 core file, as written by `virsh dump`, VirtualBox and QEMU's
    /// `dump-guest-memory`.
    ElfCore,
    /// A QEMU `savevm` suspend-to-disk file.
    QemuSaveVm,
    /// VMware snapshot metadata (`.vmss` / `.vmsn`). The magic lives in the
    /// metadata file, not in the paired `.vmem` that actually holds the memory;
    /// see [`detect`] for what that means.
    VmwareSnapshot,
    /// A Windows hibernation file (`hiberfil.sys`).
    ///
    /// A capture of physical memory that the machine took of itself, sitting on
    /// the disk image an examiner already has. Its header is read, its state
    /// reported, and **its pages are decompressed into an address space**: both
    /// Xpress codecs decode, and this comment said "decompression is not
    /// implemented, so no address space is produced from it yet" for a while
    /// after that stopped being true. How *much* of a file is reconstructed is
    /// a separate question with its own answer — 1.6% of the one corpus file
    /// measured, `MEM-026` — and the layer states it rather than presenting a
    /// partial reconstruction as whole. See [`crate::formats::hibernation`].
    WindowsHibernation,
}

impl MemoryImageFormat {
    /// Every variant, so the tests can enumerate them.
    ///
    /// Hand-maintained, and honestly so: nothing makes the compiler notice a
    /// variant left out of this array. What the compiler does force is an arm in
    /// [`as_str`](MemoryImageFormat::as_str), which is where a new format is
    /// first felt — add it here in the same edit. Everything downstream is then
    /// checked: `every_format_variant_has_a_declarable_name` walks this array
    /// and fails if a format cannot be spelled by
    /// [`DECLARABLE_FORMAT_NAMES`], and a format the enum has but a declaration
    /// cannot name is an option an examiner can pick that the analysis silently
    /// drops.
    pub const ALL: [MemoryImageFormat; 9] = [
        MemoryImageFormat::Raw,
        MemoryImageFormat::WindowsCrashDump32,
        MemoryImageFormat::WindowsCrashDump64,
        MemoryImageFormat::Lime,
        MemoryImageFormat::Avml,
        MemoryImageFormat::ElfCore,
        MemoryImageFormat::QemuSaveVm,
        MemoryImageFormat::VmwareSnapshot,
        MemoryImageFormat::WindowsHibernation,
    ];

    /// Stable identifier for artifact metadata, logs and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryImageFormat::Raw => "raw",
            MemoryImageFormat::WindowsCrashDump32 => "windows_crashdump_32",
            MemoryImageFormat::WindowsCrashDump64 => "windows_crashdump_64",
            MemoryImageFormat::Lime => "lime",
            MemoryImageFormat::Avml => "avml",
            MemoryImageFormat::ElfCore => "elf_core",
            MemoryImageFormat::QemuSaveVm => "qemu_savevm",
            MemoryImageFormat::VmwareSnapshot => "vmware_snapshot",
            MemoryImageFormat::WindowsHibernation => "windows_hibernation",
        }
    }

    /// The inverse of [`MemoryImageFormat::as_str`].
    ///
    /// Needed because a layer's metadata crosses the artifact boundary as JSON:
    /// the format has to survive that round trip or the analysis side cannot
    /// tell a crash dump from a raw image.
    ///
    /// This is [`parse_format_name`] under another name, deliberately: two
    /// tables mapping strings to this enum drifted once already — a name the
    /// metadata round trip understood that an examiner's declaration did not —
    /// and the only way that cannot happen again is for there to be one table.
    // Inherent rather than `FromStr`: this answers `Option`, and the trait
    // demands an associated error type that would have to be invented for a
    // name that simply is not one of the variants.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(name: &str) -> Option<Self> {
        parse_format_name(name)
    }

    /// Whether this format was established from the bytes themselves.
    ///
    /// `false` only for [`MemoryImageFormat::Raw`], which can never be
    /// content-detected and must be declared by the examiner.
    pub fn is_content_detected(self) -> bool {
        self != MemoryImageFormat::Raw
    }

    /// Whether this is one of the two Windows crash dump layouts.
    pub fn is_windows_crash_dump(self) -> bool {
        matches!(
            self,
            MemoryImageFormat::WindowsCrashDump32 | MemoryImageFormat::WindowsCrashDump64
        )
    }

    /// The architecture the *format alone* proves, if any.
    ///
    /// Only the two crash-dump layouts qualify: the header structure itself is
    /// per-bitness. Every other format either carries the architecture in a
    /// field a reader must parse (ELF `e_machine`, QEMU's configuration
    /// section) or does not carry it at all. Those readers set
    /// [`crate::meta::LayerMeta::architecture`] themselves; nothing here
    /// guesses.
    pub fn architecture_hint(self) -> Option<Architecture> {
        match self {
            MemoryImageFormat::WindowsCrashDump32 => Some(Architecture::X86),
            MemoryImageFormat::WindowsCrashDump64 => Some(Architecture::X64),
            _ => None,
        }
    }
}

/// Every name an examiner may declare a memory image as, and what each means.
///
/// # What an examiner learns
///
/// Which words the product will actually act on. A raw dump has no magic, so a
/// declaration is the *only* way it can be analysed at all
/// ([`crate::module::MemoryImageModule`] claims a headerless image on no other
/// basis), and a name outside this table is not a small mistake — it makes the
/// module emit nothing and every downstream memory stage report `did_not_run`
/// with nothing on the record.
///
/// # What a wrong answer would look like
///
/// Exactly that silence. `"hibernation"` was offered by the ingest form and was
/// absent here, so choosing it produced a run indistinguishable from one where
/// no declaration had been made: an examiner's assertion, accepted by the UI,
/// discarded without a word. Absence of evidence rendered as evidence of
/// absence.
///
/// # Why it is exported
///
/// So `seance_api` can reject an unrecognised `memory_image_format` with a 400
/// naming the accepted set, instead of keeping a second copy of this list that
/// will drift from it. Adding a variant to [`MemoryImageFormat`] without adding
/// a name here fails `every_format_variant_has_a_declarable_name`.
///
/// The first name for each format is its canonical [`MemoryImageFormat::as_str`]
/// spelling; the rest are the shorthands examiners actually type. Matching is
/// case-insensitive and ignores surrounding whitespace, so only lower-case
/// entries belong here.
pub const DECLARABLE_FORMAT_NAMES: &[(&str, MemoryImageFormat)] = &[
    ("raw", MemoryImageFormat::Raw),
    ("dd", MemoryImageFormat::Raw),
    // LiME can be asked to write a padded image, which is raw memory with the
    // gaps filled rather than a LiME segment file.
    ("lime-raw", MemoryImageFormat::Raw),
    ("padded", MemoryImageFormat::Raw),
    (
        "windows_crashdump_32",
        MemoryImageFormat::WindowsCrashDump32,
    ),
    (
        "windows_crash_dump32",
        MemoryImageFormat::WindowsCrashDump32,
    ),
    ("crash32", MemoryImageFormat::WindowsCrashDump32),
    ("pagedump", MemoryImageFormat::WindowsCrashDump32),
    (
        "windows_crashdump_64",
        MemoryImageFormat::WindowsCrashDump64,
    ),
    (
        "windows_crash_dump64",
        MemoryImageFormat::WindowsCrashDump64,
    ),
    ("crash64", MemoryImageFormat::WindowsCrashDump64),
    // Unqualified "crash" resolves to the 64-bit layout: every Windows build
    // that still writes a 32-bit `_DUMP_HEADER` is out of support, and the
    // header word is checked by the reader either way.
    ("crash", MemoryImageFormat::WindowsCrashDump64),
    ("pagedu64", MemoryImageFormat::WindowsCrashDump64),
    ("dmp", MemoryImageFormat::WindowsCrashDump64),
    ("lime", MemoryImageFormat::Lime),
    ("avml", MemoryImageFormat::Avml),
    ("elf_core", MemoryImageFormat::ElfCore),
    ("elf", MemoryImageFormat::ElfCore),
    ("elfcore", MemoryImageFormat::ElfCore),
    ("core", MemoryImageFormat::ElfCore),
    ("qemu_savevm", MemoryImageFormat::QemuSaveVm),
    ("qemu", MemoryImageFormat::QemuSaveVm),
    ("savevm", MemoryImageFormat::QemuSaveVm),
    ("vmware_snapshot", MemoryImageFormat::VmwareSnapshot),
    ("vmware", MemoryImageFormat::VmwareSnapshot),
    ("vmss", MemoryImageFormat::VmwareSnapshot),
    ("vmsn", MemoryImageFormat::VmwareSnapshot),
    // The `.vmem` is headerless raw memory, but naming it as such would lose
    // the fact that it came from a snapshot; the reader pairs it with its
    // metadata sibling and degrades honestly when it cannot find one.
    ("vmem", MemoryImageFormat::VmwareSnapshot),
    ("windows_hibernation", MemoryImageFormat::WindowsHibernation),
    ("hibernation", MemoryImageFormat::WindowsHibernation),
    ("hiberfil", MemoryImageFormat::WindowsHibernation),
    ("hiberfil.sys", MemoryImageFormat::WindowsHibernation),
    ("hiber", MemoryImageFormat::WindowsHibernation),
];

/// Map a declared or round-tripped format name onto the enum.
///
/// Unknown names yield `None` rather than a default, so a typo can never
/// silently become "raw" — the caller must treat `None` as a refusal and say so.
/// [`crate::module::MemoryImageModule`] does not fall back to the
/// `memory_image: true` flag on an unreadable name for the same reason: "raw,
/// trust me" is not what an examiner who typed a format name said.
pub fn parse_format_name(name: &str) -> Option<MemoryImageFormat> {
    let name = name.trim().to_ascii_lowercase();
    DECLARABLE_FORMAT_NAMES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, format)| *format)
}

/// Identify the acquisition format of `ds` from its contents.
///
/// Checks run in a fixed order so the result is deterministic; the magics are
/// mutually exclusive, so the order does not change any answer. Every check is
/// guarded by the number of bytes actually read, so a source shorter than a
/// given header simply fails that check instead of reading past the end.
///
/// Two deliberate departures from upstream:
///
/// - **ELF requires `e_type == ET_CORE`.** Volatility's `Elf64Stacker` claims
///   any little-endian ELF64 file. Séance ingests ordinary ELF executables and
///   shared objects constantly, and claiming them as memory images would route
///   them into the memory pipeline. A core file says it is a core file.
/// - **VMware requires a structurally valid group table**, not just the 4-byte
///   magic, which is otherwise weak enough to fire on unrelated binary data.
///
/// Note on VMware: the file that carries the magic is the *metadata*
/// (`.vmss` / `.vmsn`). The memory itself lives in the paired `.vmem`, which is
/// headerless raw memory and therefore falls under the same rule as any other
/// raw dump — it cannot be detected, only declared or reached from its
/// metadata. Pairing the two is the format reader's job.
pub fn detect(ds: &dyn DataSource) -> MemoryImageFormat {
    let mut header = [0u8; HEADER_PROBE_BYTES];
    let n = read_full(ds, 0, &mut header);
    let head = &header[..n];

    if let Some(fmt) = detect_crash_dump(head) {
        return fmt;
    }
    if detect_lime(head) {
        return MemoryImageFormat::Lime;
    }
    if detect_avml(head) {
        return MemoryImageFormat::Avml;
    }
    if detect_qemu(head) {
        return MemoryImageFormat::QemuSaveVm;
    }
    if detect_vmware(head, ds.size()) {
        return MemoryImageFormat::VmwareSnapshot;
    }
    if detect_elf_core(head) {
        return MemoryImageFormat::ElfCore;
    }
    // Last of the positive detections: a hibernation file's signature is four
    // bytes, so it is tried only after every format with a stronger magic.
    if crate::formats::hibernation::identify(head).is_some() {
        return MemoryImageFormat::WindowsHibernation;
    }
    MemoryImageFormat::Raw
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn be_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

/// `PAGE` + (`DUMP` | `DU64`). An eight-byte magic needs no further structure.
fn detect_crash_dump(head: &[u8]) -> Option<MemoryImageFormat> {
    if head.len() < 8 || &head[0..4] != CRASH_SIGNATURE {
        return None;
    }
    match &head[4..8] {
        v if v == CRASH_VALID_32 => Some(MemoryImageFormat::WindowsCrashDump32),
        v if v == CRASH_VALID_64 => Some(MemoryImageFormat::WindowsCrashDump64),
        other => {
            debug!(
                valid_dump = ?other,
                "PAGE signature with an unrecognised dump word; not claiming as a crash dump"
            );
            None
        }
    }
}

/// `<IIQQQ`: magic, version, start, end, reserved. `end` is the last address of
/// the first segment and is inclusive, so `end >= start` must hold.
fn detect_lime(head: &[u8]) -> bool {
    if head.len() < 32 || le_u32(head, 0) != LIME_MAGIC {
        return false;
    }
    let version = le_u32(head, 4);
    if version != LIME_VERSION {
        debug!(version, "LiME magic with an unsupported version");
        return false;
    }
    let (start, end) = (le_u64(head, 8), le_u64(head, 16));
    if end < start {
        debug!(start, end, "LiME header declares an inverted segment range");
        return false;
    }
    true
}

/// `<IIQQQ`: magic, version, start, end, padding. Same shape as LiME, different
/// magic, and `end` is exclusive here — either way the range cannot invert.
fn detect_avml(head: &[u8]) -> bool {
    if head.len() < 32 || le_u32(head, 0) != AVML_MAGIC {
        return false;
    }
    let version = le_u32(head, 4);
    if version != AVML_VERSION {
        debug!(version, "AVML magic with an unsupported version");
        return false;
    }
    let (start, end) = (le_u64(head, 8), le_u64(head, 16));
    if end < start {
        debug!(start, end, "AVML header declares an inverted block range");
        return false;
    }
    true
}

fn detect_qemu(head: &[u8]) -> bool {
    head.len() >= 8 && &head[0..8] == QEMU_MAGIC
}

/// `<4sII`: magic, unknown, groupCount — then `groupCount` entries of
/// `64s` name + two `u64`. The declared table has to fit inside the file.
fn detect_vmware(head: &[u8], source_size: u64) -> bool {
    if head.len() < 12 {
        return false;
    }
    let magic: &[u8] = &head[0..4];
    if !VMWARE_MAGICS.iter().any(|m| m.as_slice() == magic) {
        return false;
    }
    let group_count = le_u32(head, 8);
    if group_count == 0 || group_count > VMWARE_MAX_GROUPS {
        debug!(
            group_count,
            "VMware metadata magic with an implausible group count"
        );
        return false;
    }
    let table_bytes = u64::from(group_count).saturating_mul(VMWARE_GROUP_ENTRY_BYTES);
    let needed = VMWARE_GROUP_TABLE_OFFSET.saturating_add(table_bytes);
    if needed > source_size {
        debug!(
            needed,
            source_size, "VMware group table does not fit inside the source"
        );
        return false;
    }
    true
}

/// ELF64 with `e_type == ET_CORE` and at least one program header. `EI_DATA`
/// selects the width decoding for `e_type`/`e_phnum`; a big-endian core is
/// still a core, and saying so lets the reader fail closed with a named reason
/// rather than being silently mistaken for raw memory.
fn detect_elf_core(head: &[u8]) -> bool {
    if head.len() < 64 || &head[0..4] != ELF_MAGIC {
        return false;
    }
    if head[4] != ELF_CLASS_64 {
        debug!(ei_class = head[4], "ELF is not 64-bit; not a memory image");
        return false;
    }
    let little_endian = match head[5] {
        1 => true,
        2 => false,
        other => {
            debug!(ei_data = other, "ELF has an invalid data encoding");
            return false;
        }
    };
    let (e_type, e_phnum) = if little_endian {
        (le_u16(head, 16), le_u16(head, 56))
    } else {
        (be_u16(head, 16), be_u16(head, 56))
    };
    if e_type != ELF_TYPE_CORE {
        // Not a departure worth logging loudly: ordinary executables and shared
        // objects hit this path on every ingest.
        return false;
    }
    if e_phnum == 0 {
        debug!("ELF core declares no program headers; it describes no memory");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    fn src(bytes: Vec<u8>) -> ByteSliceDataSource {
        ByteSliceDataSource::new(bytes)
    }

    /// Pad a header out so short-source guards do not mask what is under test.
    fn padded(mut bytes: Vec<u8>, to: usize) -> Vec<u8> {
        bytes.resize(bytes.len().max(to), 0);
        bytes
    }

    // ── Declared format names ───────────────────────────────────────────────

    /// The structural close of the class LIVE-002 is about: a format the enum
    /// has but the name table cannot spell is a picker option that yields
    /// `Ok(vec![])` and a run of `did_not_run` stages.
    ///
    /// Before the fix this failed on `WindowsHibernation` (no name at all) and
    /// on five formats whose canonical `as_str()` spelling — the very string
    /// `layer_meta` round-trips through JSON — was not accepted by the
    /// declaration parser.
    #[test]
    fn every_format_variant_has_a_declarable_name() {
        for format in MemoryImageFormat::ALL {
            assert_eq!(
                parse_format_name(format.as_str()),
                Some(format),
                "{} has no declarable name; declaring it would be dropped in silence",
                format.as_str()
            );
            assert_eq!(
                MemoryImageFormat::from_str(format.as_str()),
                Some(format),
                "{} does not survive the artifact-metadata round trip",
                format.as_str()
            );
            assert!(
                DECLARABLE_FORMAT_NAMES
                    .iter()
                    .any(|(_, candidate)| *candidate == format),
                "{} is absent from the exported name table the API validates against",
                format.as_str()
            );
        }
    }

    /// A hibernation file is a complete capture of physical memory sitting on a
    /// disk image. Declaring one must reach [`MemoryImageFormat::WindowsHibernation`]
    /// so the module emits the record that says a capture was found and why its
    /// pages cannot be read yet — the opposite claim to emitting nothing.
    #[test]
    fn hibernation_can_be_declared_by_every_name_the_form_may_send() {
        for name in [
            "windows_hibernation",
            "hibernation",
            "hiberfil",
            "hiberfil.sys",
            "hiber",
            "  Hibernation  ",
            "HIBERFIL.SYS",
        ] {
            assert_eq!(
                parse_format_name(name),
                Some(MemoryImageFormat::WindowsHibernation),
                "{name:?}"
            );
        }
    }

    #[test]
    fn the_exported_table_is_unambiguous_and_matchable() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, format) in DECLARABLE_FORMAT_NAMES {
            assert!(
                seen.insert(*name),
                "{name:?} appears twice; one of the two mappings is unreachable"
            );
            assert_eq!(
                *name,
                name.trim().to_ascii_lowercase(),
                "{name:?} can never match: lookup lower-cases and trims first"
            );
            assert_eq!(
                parse_format_name(name),
                Some(*format),
                "{name:?} does not resolve to the format it is listed against"
            );
        }
    }

    #[test]
    fn an_unrecognised_name_is_refused_rather_than_defaulted() {
        // The API rejects with 400 on `None`. Anything that turned this into
        // `Some(Raw)` would treat a typo as "raw, trust me" and analyse an
        // arbitrary file as physical memory.
        for name in ["wat", "", "   ", "hibernating", "raw-ish", "vmdk"] {
            assert_eq!(parse_format_name(name), None, "{name:?}");
        }
    }

    // ── LiME ────────────────────────────────────────────────────────────────

    fn lime_header(magic: u32, version: u32, start: u64, end: u64) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&magic.to_le_bytes());
        h.extend_from_slice(&version.to_le_bytes());
        h.extend_from_slice(&start.to_le_bytes());
        h.extend_from_slice(&end.to_le_bytes());
        h.extend_from_slice(&0u64.to_le_bytes()); // reserved
        h
    }

    #[test]
    fn detects_a_valid_lime_image() {
        let mut image = lime_header(LIME_MAGIC, 1, 0x1000, 0x1FFF);
        image.resize(image.len() + 0x1000, 0xAA);
        assert_eq!(detect(&src(image)), MemoryImageFormat::Lime);
        // The magic really is the ASCII "EMiL" on disk.
        assert_eq!(&LIME_MAGIC.to_le_bytes(), b"EMiL");
    }

    #[test]
    fn truncated_lime_header_is_not_claimed() {
        // Magic present, header cut off mid-way: fail closed rather than parse
        // a header whose tail would be read as zeros.
        let short = lime_header(LIME_MAGIC, 1, 0, 0xFFF)[..20].to_vec();
        assert_eq!(detect(&src(short)), MemoryImageFormat::Raw);
        // Even a 4-byte file that happens to be the magic is not enough.
        assert_eq!(
            detect(&src(LIME_MAGIC.to_le_bytes().to_vec())),
            MemoryImageFormat::Raw
        );
    }

    #[test]
    fn malformed_lime_headers_do_not_panic_and_are_not_claimed() {
        // Wrong version.
        assert_eq!(
            detect(&src(lime_header(LIME_MAGIC, 7, 0, 0xFFF))),
            MemoryImageFormat::Raw
        );
        // Inverted range.
        assert_eq!(
            detect(&src(lime_header(LIME_MAGIC, 1, 0xFFFF, 0x10))),
            MemoryImageFormat::Raw
        );
        // Extremes that would overflow a naive `end - start + 1`.
        assert_eq!(
            detect(&src(lime_header(LIME_MAGIC, 1, 0, u64::MAX))),
            MemoryImageFormat::Lime
        );
        assert_eq!(
            detect(&src(lime_header(LIME_MAGIC, 1, u64::MAX, u64::MAX))),
            MemoryImageFormat::Lime
        );
    }

    // ── AVML ────────────────────────────────────────────────────────────────

    fn avml_header(magic: u32, version: u32, start: u64, end: u64) -> Vec<u8> {
        lime_header(magic, version, start, end)
    }

    #[test]
    fn detects_a_valid_avml_image() {
        let image = padded(avml_header(AVML_MAGIC, 2, 0, 0x10_0000), 0x200);
        assert_eq!(detect(&src(image)), MemoryImageFormat::Avml);
        assert_eq!(&AVML_MAGIC.to_le_bytes(), b"AVML");
    }

    #[test]
    fn truncated_avml_header_is_not_claimed() {
        let short = avml_header(AVML_MAGIC, 2, 0, 0x1000)[..16].to_vec();
        assert_eq!(detect(&src(short)), MemoryImageFormat::Raw);
    }

    #[test]
    fn malformed_avml_headers_do_not_panic_and_are_not_claimed() {
        // AVML version 1 exists in the wild but is not the supported layout.
        assert_eq!(
            detect(&src(avml_header(AVML_MAGIC, 1, 0, 0x1000))),
            MemoryImageFormat::Raw
        );
        assert_eq!(
            detect(&src(avml_header(AVML_MAGIC, 2, 0x9000, 0x10))),
            MemoryImageFormat::Raw
        );
    }

    // ── Windows crash dump ──────────────────────────────────────────────────

    fn crash_header(valid: &[u8; 4]) -> Vec<u8> {
        let mut h = CRASH_SIGNATURE.to_vec();
        h.extend_from_slice(valid);
        padded(h, 0x2000)
    }

    #[test]
    fn detects_both_crash_dump_layouts() {
        assert_eq!(
            detect(&src(crash_header(CRASH_VALID_32))),
            MemoryImageFormat::WindowsCrashDump32
        );
        assert_eq!(
            detect(&src(crash_header(CRASH_VALID_64))),
            MemoryImageFormat::WindowsCrashDump64
        );
    }

    #[test]
    fn truncated_crash_header_is_not_claimed() {
        // "PAGE" alone is four bytes of a filename, a chunk tag, anything.
        assert_eq!(detect(&src(b"PAGE".to_vec())), MemoryImageFormat::Raw);
        assert_eq!(detect(&src(b"PAGEDU".to_vec())), MemoryImageFormat::Raw);
    }

    #[test]
    fn malformed_crash_header_does_not_panic_and_is_not_claimed() {
        // Right signature, unknown dump word: a format we cannot read, and we
        // must not pretend otherwise.
        assert_eq!(
            detect(&src(padded(b"PAGEXXXX".to_vec(), 0x100))),
            MemoryImageFormat::Raw
        );
    }

    #[test]
    fn crash_dump_bitness_is_the_only_format_derived_architecture() {
        assert_eq!(
            MemoryImageFormat::WindowsCrashDump32.architecture_hint(),
            Some(Architecture::X86)
        );
        assert_eq!(
            MemoryImageFormat::WindowsCrashDump64.architecture_hint(),
            Some(Architecture::X64)
        );
        for fmt in [
            MemoryImageFormat::Raw,
            MemoryImageFormat::Lime,
            MemoryImageFormat::Avml,
            MemoryImageFormat::ElfCore,
            MemoryImageFormat::QemuSaveVm,
            MemoryImageFormat::VmwareSnapshot,
        ] {
            assert_eq!(
                fmt.architecture_hint(),
                None,
                "{} must not guess an architecture",
                fmt.as_str()
            );
        }
    }

    // ── QEMU savevm ─────────────────────────────────────────────────────────

    #[test]
    fn detects_a_valid_qemu_savevm() {
        let image = padded(QEMU_MAGIC.to_vec(), 0x400);
        assert_eq!(detect(&src(image)), MemoryImageFormat::QemuSaveVm);
    }

    #[test]
    fn truncated_qemu_header_is_not_claimed() {
        assert_eq!(detect(&src(b"QEVM".to_vec())), MemoryImageFormat::Raw);
    }

    #[test]
    fn malformed_qemu_version_is_not_claimed() {
        // Version word 2: a savevm stream we do not support.
        let mut h = b"QEVM".to_vec();
        h.extend_from_slice(&[0, 0, 0, 2]);
        assert_eq!(detect(&src(padded(h, 0x100))), MemoryImageFormat::Raw);
    }

    // ── VMware snapshot metadata ────────────────────────────────────────────

    fn vmware_meta(magic: &[u8; 4], group_count: u32, total_size: usize) -> Vec<u8> {
        let mut h = magic.to_vec();
        h.extend_from_slice(&0u32.to_le_bytes()); // unknown
        h.extend_from_slice(&group_count.to_le_bytes());
        padded(h, total_size)
    }

    #[test]
    fn detects_valid_vmware_metadata_for_every_magic() {
        for magic in VMWARE_MAGICS {
            let meta = vmware_meta(magic, 3, 12 + 3 * 80);
            assert_eq!(
                detect(&src(meta)),
                MemoryImageFormat::VmwareSnapshot,
                "magic {magic:02x?} must be recognised"
            );
        }
    }

    #[test]
    fn truncated_vmware_metadata_is_not_claimed() {
        // Magic only, no group count.
        assert_eq!(
            detect(&src(VMWARE_MAGICS[0].to_vec())),
            MemoryImageFormat::Raw
        );
        // Group count declared but the table does not fit in the file: the
        // structural check is what keeps a 4-byte magic from firing on noise.
        assert_eq!(
            detect(&src(vmware_meta(VMWARE_MAGICS[0], 64, 200))),
            MemoryImageFormat::Raw
        );
    }

    #[test]
    fn malformed_vmware_group_counts_do_not_panic_and_are_not_claimed() {
        assert_eq!(
            detect(&src(vmware_meta(VMWARE_MAGICS[2], 0, 4096))),
            MemoryImageFormat::Raw
        );
        assert_eq!(
            detect(&src(vmware_meta(VMWARE_MAGICS[2], u32::MAX, 4096))),
            MemoryImageFormat::Raw
        );
    }

    // ── ELF core ────────────────────────────────────────────────────────────

    fn elf64_header(e_type: u16, e_phnum: u16, little_endian: bool, class: u8) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(ELF_MAGIC);
        h[4] = class;
        h[5] = if little_endian { 1 } else { 2 };
        h[6] = 1; // EI_VERSION
        if little_endian {
            h[16..18].copy_from_slice(&e_type.to_le_bytes());
            h[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
            h[56..58].copy_from_slice(&e_phnum.to_le_bytes());
        } else {
            h[16..18].copy_from_slice(&e_type.to_be_bytes());
            h[18..20].copy_from_slice(&183u16.to_be_bytes()); // EM_AARCH64
            h[56..58].copy_from_slice(&e_phnum.to_be_bytes());
        }
        h
    }

    #[test]
    fn detects_a_valid_elf64_core() {
        let image = padded(elf64_header(ELF_TYPE_CORE, 12, true, ELF_CLASS_64), 0x1000);
        assert_eq!(detect(&src(image)), MemoryImageFormat::ElfCore);
    }

    #[test]
    fn detects_a_big_endian_elf64_core() {
        // A core we cannot yet read is still a core; saying "raw memory" would
        // be a lie that routes it into the wrong pipeline.
        let image = padded(elf64_header(ELF_TYPE_CORE, 4, false, ELF_CLASS_64), 0x1000);
        assert_eq!(detect(&src(image)), MemoryImageFormat::ElfCore);
    }

    #[test]
    fn truncated_elf_header_is_not_claimed() {
        let full = elf64_header(ELF_TYPE_CORE, 4, true, ELF_CLASS_64);
        assert_eq!(detect(&src(full[..48].to_vec())), MemoryImageFormat::Raw);
        assert_eq!(detect(&src(ELF_MAGIC.to_vec())), MemoryImageFormat::Raw);
    }

    #[test]
    fn ordinary_elf_binaries_are_never_claimed_as_memory_images() {
        // ET_EXEC and ET_DYN are what a disk image is full of. Volatility's
        // stacker claims these; Séance must not.
        for e_type in [1u16 /* REL */, 2 /* EXEC */, 3 /* DYN */] {
            let image = padded(elf64_header(e_type, 8, true, ELF_CLASS_64), 0x1000);
            assert_eq!(
                detect(&src(image)),
                MemoryImageFormat::Raw,
                "ELF e_type {e_type} must not be claimed"
            );
        }
    }

    #[test]
    fn malformed_elf_headers_do_not_panic_and_are_not_claimed() {
        // 32-bit ELF.
        assert_eq!(
            detect(&src(elf64_header(ELF_TYPE_CORE, 4, true, 1))),
            MemoryImageFormat::Raw
        );
        // Invalid EI_DATA.
        let mut bad = elf64_header(ELF_TYPE_CORE, 4, true, ELF_CLASS_64);
        bad[5] = 9;
        assert_eq!(detect(&src(bad)), MemoryImageFormat::Raw);
        // A core with no program headers describes no memory.
        assert_eq!(
            detect(&src(elf64_header(ELF_TYPE_CORE, 0, true, ELF_CLASS_64))),
            MemoryImageFormat::Raw
        );
    }

    // ── Raw and the absence of detection ────────────────────────────────────

    #[test]
    fn headerless_data_is_reported_as_raw_and_flagged_as_undetected() {
        let image = src(vec![0x5A; 0x4000]);
        let fmt = detect(&image);
        assert_eq!(fmt, MemoryImageFormat::Raw);
        assert!(
            !fmt.is_content_detected(),
            "Raw must never claim to have been detected from content"
        );
        for detected in [
            MemoryImageFormat::Lime,
            MemoryImageFormat::Avml,
            MemoryImageFormat::ElfCore,
            MemoryImageFormat::QemuSaveVm,
            MemoryImageFormat::VmwareSnapshot,
            MemoryImageFormat::WindowsCrashDump32,
            MemoryImageFormat::WindowsCrashDump64,
        ] {
            assert!(detected.is_content_detected());
        }
    }

    #[test]
    fn an_empty_source_does_not_panic() {
        assert_eq!(detect(&src(Vec::new())), MemoryImageFormat::Raw);
    }

    #[test]
    fn a_source_that_dribbles_bytes_is_still_detected() {
        // Windowed / container-backed sources legitimately return fewer bytes
        // than requested; detection must loop rather than give up.
        let image = padded(lime_header(LIME_MAGIC, 1, 0, 0xFFF), 0x100);
        assert_eq!(
            detect(&seance_core::test_support::DribbleSource::new(image, 3)),
            MemoryImageFormat::Lime
        );
    }

    #[test]
    fn format_identifiers_are_stable_and_distinct() {
        let all = [
            MemoryImageFormat::Raw,
            MemoryImageFormat::WindowsCrashDump32,
            MemoryImageFormat::WindowsCrashDump64,
            MemoryImageFormat::Lime,
            MemoryImageFormat::Avml,
            MemoryImageFormat::ElfCore,
            MemoryImageFormat::QemuSaveVm,
            MemoryImageFormat::VmwareSnapshot,
        ];
        let mut seen = std::collections::HashSet::new();
        for fmt in all {
            assert!(seen.insert(fmt.as_str()), "duplicate id {}", fmt.as_str());
        }
        assert_eq!(MemoryImageFormat::Lime.as_str(), "lime");
        assert!(MemoryImageFormat::WindowsCrashDump64.is_windows_crash_dump());
        assert!(!MemoryImageFormat::Lime.is_windows_crash_dump());
    }
}
