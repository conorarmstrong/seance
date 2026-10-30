//! The ISF document exactly as it appears on disk.
//!
//! ISF (Intermediate Symbol Format) is Volatility 3's JSON symbol format: one
//! object with five top-level keys — `metadata`, `base_types`, `user_types`,
//! `enums` and `symbols`. Everything an examiner can learn about a kernel's
//! layout comes from here: where `_EPROCESS.UniqueProcessId` sits, how wide it
//! is, what `PsActiveProcessHead` resolves to.
//!
//! # Fidelity note
//!
//! No copy of the Volatility 3 source tree was present in this repository when
//! this module was written (`reference/volatility3/` does not exist), so the
//! model below follows the documented shape of
//! `volatility3/schemas/schema-6.3.0.json` and
//! `volatility3/framework/symbols/intermed.py`. Where those two disagree with a
//! producer in the wild, the documented shape wins and the divergence is a
//! validation failure rather than a silent accommodation.
//!
//! # Two deliberate departures from a naive model
//!
//! - **Maps are kept as ordered lists, not maps.** A JSON object with a
//!   repeated key deserialises into a `BTreeMap` by silently keeping the last
//!   value. For a struct's `fields` that means one member's offset quietly
//!   overwrites another's, which is exactly the class of error this crate
//!   exists to catch, so [`NamedList`] preserves duplicates for the admission
//!   gate to reject.
//! - **Numbers are kept as tokens.** `symbols[].address` is `"type": "number"`
//!   in the schema, not `"integer"`. Kernel virtual addresses exceed 2^53, so
//!   any consumer routing the token through an IEEE-754 double corrupts them
//!   without saying so. The raw [`serde_json::Number`] is retained and rejected
//!   unless it is an exact unsigned integer.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::base64;
use crate::error::{Result, SymbolError};

/// Lowest ISF format version this reader implements.
///
/// The floor is **4.0.0 and not 4.1.0**: `poolheader-x64.json`,
/// `poolheader-x86.json`, `poolheader-x64-win7.json`, `pdb.json`,
/// `registry.json` and `callbacks-x64.json` all declare `"format": "4.0.0"`, so
/// a 4.1.0 floor rejects the pool-header fragments and pool scanning cannot run
/// at all. Below 4.0.0, upstream *guesses* x86 versus x64 from base-type sizes,
/// which is precisely the heuristic Séance refuses to ship.
pub const MIN_SUPPORTED_FORMAT: Version = Version::new(4, 0, 0);

/// Highest ISF format version this reader implements.
///
/// Upstream's own reader stops at 6.2.0 and raises on a 6.3.0 file even though
/// its schema exists, so an ISF at 6.3.0 is accepted here but cannot be used
/// for a like-for-like comparison run against Volatility.
pub const MAX_SUPPORTED_FORMAT: Version = Version::new(6, 3, 0);

/// First format version in which `constant_data` is defined, which is what
/// makes banner-based Linux and macOS identification possible.
pub const CONSTANT_DATA_MIN_FORMAT: Version = Version::new(4, 1, 0);

/// First format version in which an `"anonymous": true` field's own fields are
/// lifted into its parent with accumulated offsets.
///
/// Skip the lift and every field after an anonymous member sits at the wrong
/// offset. Modern Linux ISFs are full of them.
pub const ANONYMOUS_FLATTEN_MIN_FORMAT: Version = Version::new(6, 2, 0);

/// The base type whose *name* (not kind) declares the guest pointer width.
///
/// The schema's `element_base_type.kind` is `^(void|int|float|char|bool)$`:
/// there is no `pointer` kind. Upstream special-cases the base type literally
/// named `pointer` and promotes it. An ISF with no such entry is therefore
/// silently pointer-less rather than architecture-mismatched, so its absence is
/// a structural failure here.
pub const POINTER_BASE_TYPE: &str = "pointer";

/// Symbol carrying the Linux kernel banner as `constant_data`.
pub const LINUX_BANNER_SYMBOL: &str = "linux_banner";

/// Symbol carrying the macOS kernel version string as `constant_data`.
pub const MAC_BANNER_SYMBOL: &str = "version";

/// A three-part ISF format version.
///
/// Version negotiation is not cosmetic: the reader's major must equal the
/// file's major and the reader's minor must be at least the file's, because a
/// higher minor adds semantics (base64 `constant_data` at 4.1.0, anonymous-field
/// flattening at 6.2.0) that a lower reader would not apply, producing offsets
/// that are wrong rather than missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major component. Must match a reader major exactly.
    pub major: u16,
    /// Minor component. The reader's must be greater than or equal to this.
    pub minor: u16,
    /// Patch component. Carried for the record; it selects no behaviour.
    pub patch: u16,
}

impl Version {
    /// A version from its three components.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse `"6.2.0"`.
    ///
    /// Strict by design: exactly three non-empty decimal components, nothing
    /// else. A version string this reader cannot understand exactly is a
    /// version whose semantics it cannot claim to implement.
    pub fn parse(text: &str) -> Result<Version> {
        let mut components = [0u16; 3];
        let mut seen = 0usize;
        for raw in text.split('.') {
            if seen == 3 {
                return Err(SymbolError::malformed(format!(
                    "metadata.format '{text}' has more than three components"
                )));
            }
            if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(SymbolError::malformed(format!(
                    "metadata.format '{text}' has the non-numeric component '{raw}'"
                )));
            }
            components[seen] = raw.parse::<u16>().map_err(|_| {
                SymbolError::malformed(format!(
                    "metadata.format '{text}' has the component '{raw}', \
                     which does not fit in 16 bits"
                ))
            })?;
            seen += 1;
        }
        if seen != 3 {
            return Err(SymbolError::malformed(format!(
                "metadata.format '{text}' is not three dot-separated numbers"
            )));
        }
        Ok(Version::new(components[0], components[1], components[2]))
    }

    /// Whether this reader implements the file's version.
    ///
    /// The patch component is ignored: no ISF behaviour has ever hung off it.
    pub fn is_supported(self) -> bool {
        let file = (self.major, self.minor);
        let floor = (MIN_SUPPORTED_FORMAT.major, MIN_SUPPORTED_FORMAT.minor);
        let ceiling = (MAX_SUPPORTED_FORMAT.major, MAX_SUPPORTED_FORMAT.minor);
        file >= floor && file <= ceiling
    }

    /// Whether `constant_data` is defined at this version.
    pub fn has_constant_data(self) -> bool {
        (self.major, self.minor)
            >= (
                CONSTANT_DATA_MIN_FORMAT.major,
                CONSTANT_DATA_MIN_FORMAT.minor,
            )
    }

    /// Whether anonymous fields must be lifted into their parent at this
    /// version.
    pub fn flattens_anonymous_fields(self) -> bool {
        (self.major, self.minor)
            >= (
                ANONYMOUS_FLATTEN_MIN_FORMAT.major,
                ANONYMOUS_FLATTEN_MIN_FORMAT.minor,
            )
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The processor architecture a symbol table describes.
///
/// Deliberately duplicated rather than imported: this crate answers "given
/// these bytes, is this type database sound?" and has no dependency on the
/// layer stack, so it cannot reach for `seance_memory::meta::Architecture`. The
/// two are kept identical in meaning: the width of a guest pointer, and nothing
/// inferred from "it looks like a 64-bit value".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// 32-bit x86 (IA-32).
    X86,
    /// 64-bit x86 (AMD64 / Intel 64).
    X64,
    /// 64-bit ARM (AArch64).
    Arm64,
}

impl Architecture {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::Arm64 => "arm64",
        }
    }

    /// Width of a guest pointer, in bytes.
    pub fn pointer_size(self) -> u8 {
        match self {
            Architecture::X86 => 4,
            Architecture::X64 | Architecture::Arm64 => 8,
        }
    }
}

/// Pointer width implied by a PE `IMAGE_FILE_MACHINE_*` value, if it is one
/// this crate recognises.
///
/// Returned as a width rather than an [`Architecture`] on purpose: 32-bit ARM
/// is a four-byte pointer but is not x86, and claiming otherwise in a report
/// would be a small lie with no upside.
pub fn machine_type_pointer_size(machine_type: u64) -> Option<u8> {
    match machine_type {
        0x014c => Some(4),          // IMAGE_FILE_MACHINE_I386
        0x01c0 | 0x01c4 => Some(4), // ARM, ARMNT (Thumb-2)
        0x8664 => Some(8),          // AMD64
        0xaa64 => Some(8),          // ARM64
        0x0200 => Some(8),          // IA64
        _ => None,
    }
}

/// An ordered list of `(name, value)` pairs read from a JSON object, keeping
/// duplicate keys instead of collapsing them.
///
/// A `BTreeMap` would silently keep the last value for a repeated key. In a
/// struct's `fields` that means one member's offset overwrites another's and
/// the resulting table is wrong in a way nothing downstream can see, so
/// duplicates are preserved here and rejected by the admission gate with both
/// names quoted.
#[derive(Debug, Clone)]
pub struct NamedList<V> {
    entries: Vec<(String, V)>,
}

impl<V> Default for NamedList<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<V> NamedList<V> {
    /// Every entry in document order, duplicates included.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> + '_ {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// How many entries the document declared, duplicates included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the block was empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// First entry with this name. Linear; callers on a hot path build their
    /// own index (the compiled table does).
    pub fn get(&self, name: &str) -> Option<&V> {
        self.entries.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// Names that appear more than once, each reported once, in document order.
    pub fn duplicates(&self) -> Vec<&str> {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut reported: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut out = Vec::new();
        for (name, _) in &self.entries {
            if !seen.insert(name.as_str()) && reported.insert(name.as_str()) {
                out.push(name.as_str());
            }
        }
        out
    }
}

impl<'de, V> Deserialize<'de> for NamedList<V>
where
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ListVisitor<V>(PhantomData<V>);

        impl<'de, V> Visitor<'de> for ListVisitor<V>
        where
            V: Deserialize<'de>,
        {
            type Value = NamedList<V>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<NamedList<V>, A::Error>
            where
                A: MapAccess<'de>,
            {
                // The size hint comes from the document; cap the pre-allocation
                // so a hostile hint cannot ask for an arbitrary reservation.
                let hint = map.size_hint().unwrap_or(0).min(4096);
                let mut entries = Vec::with_capacity(hint);
                while let Some((key, value)) = map.next_entry::<String, V>()? {
                    entries.push((key, value));
                }
                Ok(NamedList { entries })
            }
        }

        deserializer.deserialize_map(ListVisitor(PhantomData))
    }
}

/// The width class of a base type, as the schema defines it.
///
/// Note there is no `pointer` kind in the schema; the pointer base type is
/// identified by *name*. [`BaseKind::Pointer`] is accepted only because some
/// producers emit it, and is treated exactly as an unsigned integer of the
/// declared size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaseKind {
    /// No value: the `void` entry, which exists so `void *` has a subtype.
    Void,
    /// Integer.
    Int,
    /// IEEE floating point.
    Float,
    /// Character.
    Char,
    /// Boolean.
    Bool,
    /// Not in the schema; tolerated as an unsigned integer of the declared size.
    Pointer,
}

impl BaseKind {
    /// Stable identifier for artifact metadata and rejection messages.
    pub fn as_str(self) -> &'static str {
        match self {
            BaseKind::Void => "void",
            BaseKind::Int => "int",
            BaseKind::Float => "float",
            BaseKind::Char => "char",
            BaseKind::Bool => "bool",
            BaseKind::Pointer => "pointer",
        }
    }
}

/// Byte order of a base type's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

/// Which aggregate a user type is.
///
/// Three kinds, not two: the schema's `element_user_type.kind` is
/// `^(struct|union|class)$`, and it is precisely `class` that carries the
/// `_Class__member` name-mangling workaround. Folding `class` into `struct`
/// makes "the definition's aggregate kind is authoritative" ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggKind {
    /// C struct: members at distinct offsets.
    Struct,
    /// C union: members overlaid. Kept as a union so a reader can enumerate the
    /// alternatives instead of silently picking one.
    Union,
    /// C++ class.
    Class,
}

impl AggKind {
    /// Stable identifier for artifact metadata and rejection messages.
    pub fn as_str(self) -> &'static str {
        match self {
            AggKind::Struct => "struct",
            AggKind::Union => "union",
            AggKind::Class => "class",
        }
    }
}

/// A primitive type: the leaf every layout eventually bottoms out in.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseTypeDef {
    /// Width in bytes. Zero only for `void`.
    pub size: u64,
    /// Whether the type is signed.
    pub signed: bool,
    /// Width class.
    pub kind: BaseKind,
    /// Byte order of the storage.
    pub endian: Endian,
}

/// One member of a struct, union or class.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldDef {
    /// Byte offset from the start of the enclosing type.
    pub offset: u64,
    /// The member's type.
    #[serde(rename = "type")]
    pub ty: TypeDescriptor,
    /// Whether this member is an anonymous struct or union whose own members
    /// are lifted into the parent (format 6.2.0 and above).
    #[serde(default)]
    pub anonymous: bool,
}

/// A struct, union or class definition.
#[derive(Debug, Clone, Deserialize)]
pub struct UserTypeDef {
    /// Size of the whole aggregate in bytes, as the producer computed it.
    pub size: u64,
    /// Which aggregate this is. The definition's kind is authoritative: a
    /// descriptor saying `struct` that points at a `union` definition is legal
    /// and the union wins.
    pub kind: AggKind,
    /// Members, in document order, duplicates preserved for the gate.
    #[serde(default)]
    pub fields: NamedList<FieldDef>,
}

/// An enumeration definition.
#[derive(Debug, Clone, Deserialize)]
pub struct EnumDef {
    /// Width the producer recorded. Advisory only: the base type defines the
    /// width, and a mismatch is a signal the producer is broken.
    pub size: u64,
    /// Name of the base type that gives this enum its real width and sign.
    pub base: String,
    /// Constants, in document order, duplicates preserved for the gate.
    #[serde(default)]
    pub constants: NamedList<serde_json::Number>,
}

/// A symbol: a name bound to an address, optionally with a type and with the
/// bytes of its value.
#[derive(Debug, Clone, Deserialize)]
pub struct SymbolDef {
    /// The symbol's address, kept as the raw JSON token. Kernel virtual
    /// addresses exceed 2^53; routing one through a double corrupts it
    /// silently, so it is validated as an exact unsigned integer and never
    /// rounded.
    pub address: serde_json::Number,
    /// The symbol's type, when the producer recorded one.
    #[serde(rename = "type", default)]
    pub ty: Option<TypeDescriptor>,
    /// Base64 of the symbol's constant value, present from format 4.1.0. This
    /// is what carries `linux_banner`.
    #[serde(default)]
    pub constant_data: Option<String>,
    /// The mangled or linker-visible name, when it differs.
    #[serde(default)]
    pub linkage_name: Option<String>,
}

impl SymbolDef {
    /// The address as an exact `u64`.
    ///
    /// # Errors
    ///
    /// [`SymbolError::Malformed`] if the token is not an exact unsigned
    /// integer, naming the symbol. A float token is refused rather than
    /// rounded: a kernel address that is one bit wrong points at the wrong
    /// structure and yields confident nonsense.
    pub fn address_u64(&self, symbol_name: &str) -> Result<u64> {
        self.address.as_u64().ok_or_else(|| {
            SymbolError::malformed(format!(
                "symbol '{symbol_name}' has address {} which is not an exact unsigned integer; \
                 Séance never rounds a kernel address",
                self.address
            ))
        })
    }

    /// The decoded bytes of `constant_data`, if the producer recorded any.
    ///
    /// # Errors
    ///
    /// [`SymbolError::Malformed`] if the field is not strict base64.
    pub fn constant_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.constant_data {
            None => Ok(None),
            Some(encoded) => base64::decode(encoded).map(Some),
        }
    }
}

/// A type reference. The seven-shape tagged union the schema calls
/// `type_descriptor`, plus `class`.
///
/// Descriptors nest: a member can be a pointer to an array of pointers to a
/// struct. Named shapes refer to an entry in `base_types`, `user_types` or
/// `enums`; the rest describe their subject inline.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TypeDescriptor {
    /// A primitive named in `base_types`.
    Base {
        /// Entry name in `base_types`.
        name: String,
    },
    /// A struct named in `user_types`.
    Struct {
        /// Entry name in `user_types`.
        name: String,
    },
    /// A union named in `user_types`.
    Union {
        /// Entry name in `user_types`.
        name: String,
    },
    /// A class named in `user_types`.
    Class {
        /// Entry name in `user_types`.
        name: String,
    },
    /// An enumeration named in `enums`.
    Enum {
        /// Entry name in `enums`.
        name: String,
    },
    /// A pointer. Its width comes from the `pointer` base type, never from an
    /// assumption about the host.
    Pointer {
        /// What is pointed at.
        subtype: Box<TypeDescriptor>,
    },
    /// A fixed-length array.
    Array {
        /// Declared element count. A corrupt count is the classic
        /// out-of-memory vector, so iteration is capped by an explicit caller
        /// bound rather than by trusting this number.
        count: u64,
        /// Element type.
        subtype: Box<TypeDescriptor>,
    },
    /// A function. Opaque by construction: the schema gives it no subtype, no
    /// return type and no argument list, so pointer-to-function carries no
    /// signature and nothing may pretend otherwise.
    Function,
    /// A bitfield inside an integer or enumeration storage unit.
    Bitfield {
        /// Index of the least significant bit of the field within the unit.
        ///
        /// Signed because producers emit negative values and refusing to
        /// *parse* one costs the whole document. Apple's shipped 10.12.3 KDK
        /// has `IONVRAMDescriptor.bridgeDevices` at bit position -8, and typing
        /// this `u64` meant serde rejected 4,839 types and 43,548 symbols over
        /// one IOKit descriptor no analysis stage reads. A value out of range
        /// is judged by gate 1, where it costs that member and nothing else.
        bit_position: i64,
        /// Width of the field in bits. Signed for the same reason.
        bit_length: i64,
        /// The storage unit. `oneOf[type_base, type_enum]` in the schema, so
        /// endianness may have to be resolved through an enum to reach a base
        /// type.
        #[serde(rename = "type")]
        ty: Box<TypeDescriptor>,
    },
}

impl TypeDescriptor {
    /// The shape name, for diagnostics.
    pub fn kind_str(&self) -> &'static str {
        match self {
            TypeDescriptor::Base { .. } => "base",
            TypeDescriptor::Struct { .. } => "struct",
            TypeDescriptor::Union { .. } => "union",
            TypeDescriptor::Class { .. } => "class",
            TypeDescriptor::Enum { .. } => "enum",
            TypeDescriptor::Pointer { .. } => "pointer",
            TypeDescriptor::Array { .. } => "array",
            TypeDescriptor::Function => "function",
            TypeDescriptor::Bitfield { .. } => "bitfield",
        }
    }

    /// The referenced name, for the named shapes.
    pub fn referenced_name(&self) -> Option<&str> {
        match self {
            TypeDescriptor::Base { name }
            | TypeDescriptor::Struct { name }
            | TypeDescriptor::Union { name }
            | TypeDescriptor::Class { name }
            | TypeDescriptor::Enum { name } => Some(name.as_str()),
            _ => None,
        }
    }
}

/// Who produced this ISF, and when.
///
/// Load-bearing for admission: a producer with a known type-confusion defect is
/// refused outright rather than warned about, because its offsets are wrong in
/// a way that reads as ordinary data.
#[derive(Debug, Clone, Deserialize)]
pub struct Producer {
    /// Tool name, e.g. `dwarf2json`.
    #[serde(default)]
    pub name: Option<String>,
    /// Tool version.
    #[serde(default)]
    pub version: Option<String>,
    /// Production timestamp as the producer wrote it.
    #[serde(default)]
    pub datetime: Option<String>,
}

/// The CodeView identity of the Windows kernel this ISF describes.
#[derive(Debug, Clone, Deserialize)]
pub struct PdbInfo {
    /// PDB GUID as uppercase hex, already in the order the symbol server uses.
    /// The mixed-endian reorder of the 16 raw bytes happens where the RSDS
    /// record is read out of the image, not here.
    #[serde(rename = "GUID")]
    pub guid: String,
    /// PDB age.
    pub age: u64,
    /// PDB file name, e.g. `ntkrnlmp.pdb`.
    pub database: String,
    /// `IMAGE_FILE_MACHINE_*` value, when the producer recorded one.
    #[serde(default)]
    pub machine_type: Option<u64>,
}

/// PE version fields, when the producer had the PE to read them from.
///
/// Absent from every ISF produced by a PDB-only converter in an air-gapped lab,
/// which is why nothing in this crate requires it.
#[derive(Debug, Clone, Deserialize)]
pub struct PeInfo {
    /// Major version.
    #[serde(default)]
    pub major: Option<u64>,
    /// Minor version.
    #[serde(default)]
    pub minor: Option<u64>,
    /// Revision.
    #[serde(default)]
    pub revision: Option<u64>,
    /// Build.
    #[serde(default)]
    pub build: Option<u64>,
}

/// Windows-specific metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct WindowsMetadata {
    /// The CodeView identity, which is the whole of Windows symbol identity.
    #[serde(default)]
    pub pdb: Option<PdbInfo>,
    /// PE version fields, when available.
    #[serde(default)]
    pub pe: Option<PeInfo>,
}

/// One input the producer consumed, with its hash where it recorded one.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceRef {
    /// `dwarf`, `symtab`, `system-map`, and so on.
    #[serde(default)]
    pub kind: Option<String>,
    /// File name of the input.
    #[serde(default)]
    pub name: Option<String>,
    /// Hash algorithm.
    #[serde(default)]
    pub hash_type: Option<String>,
    /// Hash value.
    #[serde(default)]
    pub hash_value: Option<String>,
}

/// Linux and macOS metadata: the inputs the converter was run against.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UnixMetadata {
    /// Symbol sources, e.g. the `System.map` or the ELF symtab.
    #[serde(default)]
    pub symbols: Vec<SourceRef>,
    /// Type sources, e.g. the DWARF in a `vmlinux`.
    #[serde(default)]
    pub types: Vec<SourceRef>,
}

/// Which operating system an ISF declares itself to be for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsfOs {
    /// `metadata.windows` present.
    Windows,
    /// `metadata.linux` present.
    Linux,
    /// `metadata.mac` present.
    Mac,
    /// No OS key at all. Legal, and the normal case for the hand-written,
    /// version-independent fragments that describe file formats and pool
    /// headers rather than a kernel build.
    None,
}

impl IsfOs {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            IsfOs::Windows => "windows",
            IsfOs::Linux => "linux",
            IsfOs::Mac => "mac",
            IsfOs::None => "none",
        }
    }

    /// The symbol whose `constant_data` carries this OS's banner, if any.
    pub fn banner_symbol(self) -> Option<&'static str> {
        match self {
            IsfOs::Linux => Some(LINUX_BANNER_SYMBOL),
            IsfOs::Mac => Some(MAC_BANNER_SYMBOL),
            IsfOs::Windows | IsfOs::None => None,
        }
    }
}

/// The `metadata` block: the part that says *which build* this file describes.
///
/// Small, and always parsed on its own during identification, because a
/// tens-of-megabyte ISF must be able to answer "is this the right symbol file?"
/// without being fully parsed.
#[derive(Debug, Clone, Deserialize)]
pub struct IsfMetadata {
    /// Declared ISF format version, as written.
    pub format: String,
    /// Who produced the file.
    #[serde(default)]
    pub producer: Option<Producer>,
    /// Windows identity, if this is a Windows ISF.
    #[serde(default)]
    pub windows: Option<WindowsMetadata>,
    /// Linux inputs, if this is a Linux ISF.
    #[serde(default)]
    pub linux: Option<UnixMetadata>,
    /// macOS inputs, if this is a macOS ISF.
    #[serde(default)]
    pub mac: Option<UnixMetadata>,
}

impl IsfMetadata {
    /// The declared format version.
    pub fn version(&self) -> Result<Version> {
        Version::parse(&self.format)
    }

    /// Which OS keys are present. More than one is a schema violation (the
    /// metadata is a `oneOf`), reported here as a count so the gate can name it.
    pub fn os_key_count(&self) -> usize {
        usize::from(self.windows.is_some())
            + usize::from(self.linux.is_some())
            + usize::from(self.mac.is_some())
    }

    /// The single OS this ISF declares, or [`IsfOs::None`].
    ///
    /// When more than one key is present the answer is ambiguous, so the first
    /// in a fixed order is returned only for reporting; the admission gate
    /// rejects the document regardless.
    pub fn os(&self) -> IsfOs {
        if self.windows.is_some() {
            IsfOs::Windows
        } else if self.linux.is_some() {
            IsfOs::Linux
        } else if self.mac.is_some() {
            IsfOs::Mac
        } else {
            IsfOs::None
        }
    }

    /// The Windows identity string `{database}|{GUID}|{age}`.
    ///
    /// This exact triple is compared byte-for-byte against the one recovered
    /// from the kernel's own CodeView record in the image. There is no
    /// near-match tier.
    pub fn windows_identifier(&self) -> Option<String> {
        let pdb = self.windows.as_ref()?.pdb.as_ref()?;
        Some(format!(
            "{}|{}|{}",
            pdb.database,
            pdb.guid.to_uppercase(),
            pdb.age
        ))
    }

    /// Pointer width implied by the declared machine type, if declared.
    pub fn declared_pointer_size(&self) -> Option<u8> {
        let machine = self.windows.as_ref()?.pdb.as_ref()?.machine_type?;
        machine_type_pointer_size(machine)
    }
}

/// A whole ISF document, parsed.
///
/// Compiling this into a queryable table is Stage B of the pipeline and happens
/// at most once per distinct file, keyed by content hash. Identification (Stage
/// A) never builds one of these.
#[derive(Debug, Clone, Deserialize)]
pub struct IsfDocument {
    /// Which build this file describes.
    pub metadata: IsfMetadata,
    /// Primitive types.
    #[serde(default)]
    pub base_types: NamedList<BaseTypeDef>,
    /// Structs, unions and classes.
    #[serde(default)]
    pub user_types: NamedList<UserTypeDef>,
    /// Enumerations.
    #[serde(default)]
    pub enums: NamedList<EnumDef>,
    /// Symbols.
    #[serde(default)]
    pub symbols: NamedList<SymbolDef>,
}

impl IsfDocument {
    /// Parse a whole ISF document from decompressed JSON bytes.
    ///
    /// # Errors
    ///
    /// [`SymbolError::Json`] with the failing line and column. Nothing is
    /// recovered or defaulted: a document that does not fit the model is not a
    /// document this crate will draw conclusions from.
    pub fn parse(json: &[u8]) -> Result<IsfDocument> {
        serde_json::from_slice(json).map_err(|e| SymbolError::json("the ISF document", e))
    }

    /// The declared format version.
    pub fn version(&self) -> Result<Version> {
        self.metadata.version()
    }

    /// The size the `pointer` base type declares, if the entry exists.
    pub fn pointer_size(&self) -> Option<u64> {
        self.base_types.get(POINTER_BASE_TYPE).map(|b| b.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_parses_only_when_it_is_exactly_three_numbers() {
        assert_eq!(Version::parse("6.2.0").unwrap(), Version::new(6, 2, 0));
        assert!(Version::parse("6.2").is_err());
        assert!(Version::parse("6.2.0.1").is_err());
        assert!(Version::parse("6.2.x").is_err());
        assert!(Version::parse("").is_err());
        assert!(Version::parse("6..0").is_err());
        assert!(Version::parse("99999999.0.0").is_err());
    }

    #[test]
    fn the_supported_range_is_four_zero_zero_to_six_three_zero() {
        assert!(!Version::new(3, 9, 9).is_supported());
        assert!(
            Version::new(4, 0, 0).is_supported(),
            "the pool-header fragments live here"
        );
        assert!(Version::new(6, 2, 0).is_supported());
        assert!(Version::new(6, 3, 0).is_supported());
        assert!(!Version::new(6, 4, 0).is_supported());
        assert!(!Version::new(7, 0, 0).is_supported());
    }

    #[test]
    fn version_gated_behaviour_switches_at_the_documented_versions() {
        assert!(!Version::new(4, 0, 0).has_constant_data());
        assert!(Version::new(4, 1, 0).has_constant_data());
        assert!(!Version::new(6, 1, 0).flattens_anonymous_fields());
        assert!(Version::new(6, 2, 0).flattens_anonymous_fields());
        assert_eq!(Version::new(6, 2, 0).to_string(), "6.2.0");
    }

    #[test]
    fn a_repeated_member_name_survives_parsing_instead_of_overwriting() {
        // Serialised into a map this would silently become one field at offset
        // 16 and the table would be wrong with nothing to show for it.
        let json = r#"{
            "size": 32, "kind": "struct",
            "fields": {
                "pid": {"offset": 8, "type": {"kind": "base", "name": "int"}},
                "pid": {"offset": 16, "type": {"kind": "base", "name": "int"}}
            }
        }"#;
        let user: UserTypeDef = serde_json::from_str(json).expect("parses");
        assert_eq!(user.fields.len(), 2);
        assert_eq!(user.fields.duplicates(), vec!["pid"]);
    }

    #[test]
    fn every_descriptor_shape_round_trips_from_json() {
        let cases = [
            (r#"{"kind":"base","name":"int"}"#, "base"),
            (r#"{"kind":"struct","name":"_EPROCESS"}"#, "struct"),
            (r#"{"kind":"union","name":"_LARGE_INTEGER"}"#, "union"),
            (r#"{"kind":"class","name":"Widget"}"#, "class"),
            (r#"{"kind":"enum","name":"pid_type"}"#, "enum"),
            (
                r#"{"kind":"pointer","subtype":{"kind":"base","name":"void"}}"#,
                "pointer",
            ),
            (
                r#"{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}"#,
                "array",
            ),
            (r#"{"kind":"function"}"#, "function"),
            (
                r#"{"kind":"bitfield","bit_position":3,"bit_length":1,
                    "type":{"kind":"base","name":"unsigned int"}}"#,
                "bitfield",
            ),
        ];
        for (json, expected) in cases {
            let desc: TypeDescriptor =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(desc.kind_str(), expected);
        }
    }

    #[test]
    fn a_descriptor_with_an_unknown_kind_is_refused() {
        let err = serde_json::from_str::<TypeDescriptor>(r#"{"kind":"quantum","name":"x"}"#)
            .expect_err("an unknown descriptor shape must not parse");
        assert!(err.to_string().contains("quantum"), "{err}");
    }

    #[test]
    fn a_kernel_address_above_two_to_the_fifty_three_survives_exactly() {
        let symbol: SymbolDef =
            serde_json::from_str(r#"{"address": 18446744071578845184}"#).expect("parses");
        assert_eq!(
            symbol.address_u64("PsActiveProcessHead").unwrap(),
            0xFFFF_FFFF_8100_0000
        );
    }

    #[test]
    fn a_floating_point_address_is_refused_rather_than_rounded() {
        let symbol: SymbolDef =
            serde_json::from_str(r#"{"address": 1.8446744e19}"#).expect("parses as a number");
        let err = symbol
            .address_u64("PsActiveProcessHead")
            .expect_err("a float address must not be accepted");
        assert!(err.to_string().contains("PsActiveProcessHead"), "{err}");
        assert!(err.to_string().contains("never rounds"), "{err}");
    }

    #[test]
    fn a_negative_address_is_refused() {
        let symbol: SymbolDef = serde_json::from_str(r#"{"address": -8}"#).expect("parses");
        assert!(symbol.address_u64("bogus").is_err());
    }

    #[test]
    fn the_windows_identity_is_the_pdb_triple_with_an_uppercase_guid() {
        let metadata: IsfMetadata = serde_json::from_str(
            r#"{"format":"6.2.0","windows":{"pdb":{
                 "GUID":"aa1b2c3d4e5f60718293a4b5c6d7e8f9","age":1,
                 "database":"ntkrnlmp.pdb","machine_type":34404}}}"#,
        )
        .expect("parses");
        assert_eq!(
            metadata.windows_identifier().unwrap(),
            "ntkrnlmp.pdb|AA1B2C3D4E5F60718293A4B5C6D7E8F9|1"
        );
        assert_eq!(metadata.os(), IsfOs::Windows);
        assert_eq!(metadata.declared_pointer_size(), Some(8));
        assert_eq!(metadata.os_key_count(), 1);
    }

    #[test]
    fn a_metadata_block_with_two_operating_systems_is_countable_as_such() {
        let metadata: IsfMetadata = serde_json::from_str(
            r#"{"format":"6.2.0","windows":{},"linux":{"symbols":[],"types":[]}}"#,
        )
        .expect("parses");
        assert_eq!(metadata.os_key_count(), 2);
    }

    #[test]
    fn a_machine_type_maps_only_to_widths_we_actually_know() {
        assert_eq!(machine_type_pointer_size(0x8664), Some(8));
        assert_eq!(machine_type_pointer_size(0x014c), Some(4));
        assert_eq!(machine_type_pointer_size(0xaa64), Some(8));
        assert_eq!(machine_type_pointer_size(0x1234), None);
        assert_eq!(Architecture::X86.pointer_size(), 4);
        assert_eq!(Architecture::Arm64.as_str(), "arm64");
    }

    #[test]
    fn a_symbol_carrying_constant_data_yields_its_bytes() {
        let symbol: SymbolDef = serde_json::from_str(
            r#"{"address": 4096, "constant_data": "TGludXggdmVyc2lvbiA2LjEuMAoA"}"#,
        )
        .expect("parses");
        assert_eq!(
            symbol.constant_bytes().unwrap().unwrap(),
            b"Linux version 6.1.0\n\0"
        );
    }
}
