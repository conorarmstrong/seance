//! BTF — the type information a modern Linux kernel carries about itself.
//!
//! # Why this removes the symbol problem
//!
//! Analysing a Linux memory capture means reading kernel structures, and doing
//! that needs to know where each field sits. Traditionally that comes from an
//! ISF file generated from the kernel's debug symbols, matched to the capture
//! by its `linux_banner` — which means an examiner needs the exact ISF for the
//! exact build, out of the combinatorial space of every distribution, version,
//! patch level and configuration.
//!
//! Since roughly 5.2, and on by default across mainstream distributions since
//! about 2020 (`CONFIG_DEBUG_INFO_BTF=y`), the kernel is built with a compact
//! description of **its own data structures** and keeps it in memory. It exists
//! so eBPF programs can be compiled once and run against any kernel; it happens
//! to be exactly what a memory forensics tool needs.
//!
//! So for such a capture the layout is not looked up, matched or inferred. It
//! is *read out of the evidence*, and it cannot be the layout of a different
//! build, because it came from this one.
//!
//! # Why not simply use a close-enough profile
//!
//! Because struct layout is not a function of kernel version. Configuration
//! moves fields (`CONFIG_SMP`, cgroups, scheduler and hardening options all
//! change `task_struct`), distributions patch heavily, and `randstruct` builds
//! deliberately randomise member order. A wrong offset does not fail: it reads
//! the neighbouring field and returns a plausible number, which is the failure
//! mode this codebase spends most of its effort refusing.
//!
//! # Status: wired into Linux discovery
//!
//! Two consumers, both in `seance_plugin_memory_linux::discovery`:
//!
//! - **A corroboration gate.** An ISF is matched to an image by its
//!   `linux_banner`, and a banner is not unique to a build — two kernels from
//!   one distribution and version can share a banner and differ in layout. The
//!   gate compares the matched symbol file against this, the kernel's own
//!   account of itself, and fails when they disagree. It is the only check that
//!   can tell a correct match from a merely plausible one, because it is the
//!   only one whose reference came out of the evidence.
//! - **A better dead end.** When no ISF is found at all, the failure now says
//!   whether the kernel describes itself, how much of it compiled cleanly, and
//!   what is still missing.
//!
//! What this cannot yet do is *replace* an ISF, because discovery must resolve
//! `linux_banner` and `init_task` to addresses and BTF carries none. That waits
//! on `kallsyms`.
//!
//! # What this module does and does not give you
//!
//! BTF describes **types**: struct layouts, member offsets, sizes. It does not
//! carry symbol *addresses* — `init_task`, `swapper_pg_dir` and the rest come
//! from `kallsyms`, which is a separate structure and essentially universal.
//! Together the two are a complete substitute for an ISF; separately, each is
//! half of one.
//!
//! # Format
//!
//! From the kernel's `include/uapi/linux/btf.h`. A 24-byte header, then a type
//! section and a string section, both at offsets relative to the end of the
//! header:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 2 | magic, `0xEB9F` little-endian |
//! | 2 | 1 | version, 1 |
//! | 3 | 1 | flags |
//! | 4 | 4 | `hdr_len`, 24 |
//! | 8 | 4 | `type_off` |
//! | 12 | 4 | `type_len` |
//! | 16 | 4 | `str_off` |
//! | 20 | 4 | `str_len` |
//!
//! Each type entry is a 12-byte `btf_type` — `name_off`, `info`, and a union of
//! `size` or `type` — followed by a variable tail whose shape depends on the
//! kind encoded in `info`. Walking the section requires decoding every kind's
//! tail length correctly, including the ones this module has no use for:
//! mis-sizing one entry desynchronises every entry after it.

use std::collections::HashMap;
use std::fmt;

/// `0xEB9F`, stored little-endian as `9f eb`.
pub const BTF_MAGIC: u16 = 0xEB9F;
/// The only BTF version in existence.
const BTF_VERSION: u8 = 1;
/// Size of `struct btf_header`.
const HEADER_LEN: usize = 24;
/// Size of `struct btf_type`.
const TYPE_LEN: usize = 12;

// Kinds, from `enum btf_kind`. All of them are listed, including those this
// module does not interpret, because the walk has to skip their tails.
const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

/// Why a byte range was not accepted as BTF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfError {
    /// Fewer bytes than a header.
    TooShort { have: usize, need: usize },
    /// No `0xEB9F` at the start.
    NotBtf,
    /// A version this module does not implement.
    UnsupportedVersion(u8),
    /// The header's declared sections do not fit the data.
    ///
    /// Named separately from [`BtfError::NotBtf`] because it is the error a
    /// *scan* produces on a coincidental magic, and distinguishing "these two
    /// bytes happened to match" from "this is BTF and it is damaged" is the
    /// difference between moving on and reporting corruption.
    InconsistentHeader(&'static str),
    /// A type entry's tail runs past the end of the type section.
    TruncatedType { index: usize },
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BtfError::TooShort { have, need } => {
                write!(f, "{have} byte(s) is short of the {need}-byte BTF header")
            }
            BtfError::NotBtf => write!(f, "no BTF magic (0xEB9F) at the start of this range"),
            BtfError::UnsupportedVersion(v) => {
                write!(f, "BTF version {v} is not version {BTF_VERSION}")
            }
            BtfError::InconsistentHeader(what) => {
                write!(f, "the BTF header is not self-consistent: {what}")
            }
            BtfError::TruncatedType { index } => {
                write!(
                    f,
                    "type entry {index} runs past the end of the type section"
                )
            }
        }
    }
}

impl std::error::Error for BtfError {}

/// What a BTF type entry is.
///
/// Only the kinds a consumer needs to distinguish are named; everything else is
/// [`TypeKind::Other`], which callers render opaque rather than guess at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    Int,
    Float,
    Pointer,
    Array,
    Struct,
    Union,
    Enum,
    Typedef,
    Const,
    Volatile,
    Restrict,
    TypeTag,
    Func,
    FuncProto,
    Other,
}

/// One entry in the kernel's type table, as a consumer needs to see it.
///
/// Kept for every entry rather than only the named composites, because a
/// member's declared type is a chain — pointer to const to typedef to struct —
/// and resolving it means walking entries that have no name of their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEntry {
    pub kind: TypeKind,
    /// The entry's own name, empty for anonymous and for most qualifiers.
    pub name: String,
    /// What this entry points at, wraps or elements — 0 when it refers to
    /// nothing.
    pub referent: u32,
    /// Element count, for [`TypeKind::Array`] only.
    pub array_len: u32,
    /// Declared byte size, for [`TypeKind::Struct`], [`TypeKind::Union`] and
    /// [`TypeKind::Enum`] only (0 for every other kind). Kept so an ANONYMOUS aggregate — which
    /// has no name to look up in the composite table — can still report whether
    /// it occupies any bytes: an empty `struct { }` (e.g. `local_lock_t` on a
    /// non-lockdep kernel) has size 0 and must not be rendered as a 1-byte
    /// placeholder.
    pub size: u32,
}

/// An enumeration the kernel declares (`BTF_KIND_ENUM` or `BTF_KIND_ENUM64`).
///
/// Kept for every enumeration, named or anonymous, by type id: a member's
/// declared type reaches one by id, and two distinct enumerations may share a
/// name (Ubuntu's 6.8 BTF declares `energy_perf_value_index` twice, once with
/// the `EPP_*` constants and once with `EPB_*`), so a name is not a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumType {
    /// The enumeration's name, empty for an anonymous one.
    pub name: String,
    /// Width in bytes, as BTF records it (1, 2, 4 or 8 on a real kernel).
    pub size: u32,
    /// Whether the constants are signed. BTF says so with the entry's
    /// `kind_flag`; a blob whose producer predates that flag records every
    /// enumeration as unsigned, and the raw values are read that way —
    /// consistently, so a member read through the same width names the same
    /// constant.
    pub signed: bool,
    /// Constants in declaration order, values widened so both a signed and
    /// an unsigned 64-bit constant are exact.
    pub constants: Vec<(String, i128)>,
}

/// One member of a struct or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    /// Index of the member's type in the type table.
    pub type_id: u32,
    /// Offset from the start of the containing type, in **bits**.
    ///
    /// Kept in bits rather than bytes because a bitfield member does not begin
    /// on a byte boundary, and rounding here would quietly relocate it. Use
    /// [`Member::byte_offset`] when a byte offset is what is wanted, which is
    /// `None` for a member that does not start on one.
    pub bit_offset: u32,
    /// Width in bits for a bitfield member, `None` otherwise.
    pub bitfield_size: Option<u32>,
}

impl Member {
    /// Byte offset, or `None` when this member does not start on a byte
    /// boundary.
    pub fn byte_offset(&self) -> Option<u64> {
        self.bit_offset
            .is_multiple_of(8)
            .then_some((self.bit_offset / 8) as u64)
    }
}

/// A struct or union declared by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composite {
    pub name: String,
    /// Size in bytes.
    pub size: u32,
    pub is_union: bool,
    pub members: Vec<Member>,
}

impl Composite {
    /// A member by name.
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }
}

/// The kernel's own type table, parsed.
#[derive(Debug, Clone, Default)]
pub struct Btf {
    /// Structs and unions by name.
    ///
    /// Anonymous types are not indexed here — they have no name to look up by
    /// and are reachable only through the member that declares them.
    composites: HashMap<String, Composite>,
    /// Total type entries walked, named or not. Reported so a caller can tell
    /// a complete parse from one that stopped early.
    type_count: usize,
    /// `typedef` name → the name it resolves to, where that target is itself
    /// named. Lets `task_struct` be found through `struct task_struct` and vice
    /// versa without the caller knowing which spelling this kernel used.
    typedefs: HashMap<String, String>,
    /// Every entry, indexed by BTF type id. Index 0 is the void type and holds
    /// a placeholder so the vector and the ids line up.
    entries: Vec<TypeEntry>,
    /// **Anonymous** structs and unions, by BTF type id.
    ///
    /// An anonymous aggregate — `struct { ... }` embedded without a member name,
    /// as `mm_struct` and `task_struct` use pervasively — has no name to index in
    /// [`Self::composites`], but its members still have to cross into the ISF so
    /// that a lookup of a field nested inside one resolves. This is the only
    /// place they are reachable: the member that declares the anonymous
    /// aggregate carries its type id, and this maps that id to its members. Named
    /// composites are deliberately not indexed here — they are reachable by name
    /// through [`Self::composites`], and duplicating them would hold two copies
    /// of every named struct's member list.
    anon_composites: HashMap<u32, Composite>,
    /// Every enumeration, by BTF type id.
    enums: HashMap<u32, EnumType>,
}

impl Btf {
    /// Parse a complete BTF blob.
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        if data.len() < HEADER_LEN {
            return Err(BtfError::TooShort {
                have: data.len(),
                need: HEADER_LEN,
            });
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            return Err(BtfError::NotBtf);
        }
        if data[2] != BTF_VERSION {
            return Err(BtfError::UnsupportedVersion(data[2]));
        }

        let word =
            |at: usize| u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        let hdr_len = word(4) as usize;
        if hdr_len < HEADER_LEN {
            return Err(BtfError::InconsistentHeader("header shorter than 24 bytes"));
        }
        let type_off = word(8) as usize;
        let type_len = word(12) as usize;
        let str_off = word(16) as usize;
        let str_len = word(20) as usize;

        // Section offsets are relative to the END of the header.
        let base = hdr_len;
        let type_start = base
            .checked_add(type_off)
            .ok_or(BtfError::InconsistentHeader(
                "type section offset overflows",
            ))?;
        let type_end = type_start
            .checked_add(type_len)
            .ok_or(BtfError::InconsistentHeader(
                "type section length overflows",
            ))?;
        let str_start = base
            .checked_add(str_off)
            .ok_or(BtfError::InconsistentHeader(
                "string section offset overflows",
            ))?;
        let str_end = str_start
            .checked_add(str_len)
            .ok_or(BtfError::InconsistentHeader(
                "string section length overflows",
            ))?;

        if type_end > data.len() || str_end > data.len() {
            return Err(BtfError::InconsistentHeader(
                "a declared section runs past the end of the data",
            ));
        }
        if type_len == 0 {
            return Err(BtfError::InconsistentHeader("the type section is empty"));
        }

        let types = &data[type_start..type_end];
        let strings = &data[str_start..str_end];

        let name_at = |offset: u32| -> String {
            let start = offset as usize;
            if start >= strings.len() {
                return String::new();
            }
            let end = strings[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|n| start + n)
                .unwrap_or(strings.len());
            String::from_utf8_lossy(&strings[start..end]).into_owned()
        };

        let mut composites = HashMap::new();
        let mut anon_composites: HashMap<u32, Composite> = HashMap::new();
        let mut enums: HashMap<u32, EnumType> = HashMap::new();
        let mut typedefs = HashMap::new();
        // Id 0 is void and has no entry on the wire; a placeholder keeps the
        // vector indexable by id.
        let mut entries = vec![TypeEntry {
            kind: TypeKind::Other,
            name: String::new(),
            referent: 0,
            array_len: 0,
            size: 0,
        }];
        let mut cursor = 0usize;
        let mut index = 0usize;
        // Type IDs are 1-based; id 0 is the void type and has no entry.
        let mut pending_names: Vec<String> = vec![String::new()];

        while cursor + TYPE_LEN <= types.len() {
            let t = &types[cursor..cursor + TYPE_LEN];
            let name_off = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
            let info = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
            let size_or_type = u32::from_le_bytes([t[8], t[9], t[10], t[11]]);

            let vlen = (info & 0xFFFF) as usize;
            let kind = ((info >> 24) & 0x1F) as u8;
            let kind_flag = (info >> 31) & 1 == 1;
            let name = name_at(name_off);
            pending_names.push(name.clone());

            // Bytes following the fixed 12, by kind. Getting any of these wrong
            // desynchronises every subsequent entry, which is why the kinds this
            // module never interprets are still sized exactly.
            let tail = match kind {
                KIND_INT => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION => vlen * 12,
                KIND_ENUM => vlen * 8,
                KIND_ENUM64 => vlen * 12,
                KIND_FUNC_PROTO => vlen * 8,
                KIND_VAR => 4,
                KIND_DATASEC => vlen * 12,
                KIND_DECL_TAG => 4,
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                // An unknown kind cannot be skipped safely: its tail length is
                // unknown, so everything after it would be misread. Stop, and
                // report what was walked rather than inventing the rest.
                _ => break,
            };

            let body_start = cursor + TYPE_LEN;
            let body_end = body_start
                .checked_add(tail)
                .ok_or(BtfError::TruncatedType { index })?;
            if body_end > types.len() {
                return Err(BtfError::TruncatedType { index });
            }

            // Every entry is recorded, named or not: resolving a member's
            // declared type means walking a chain of pointers, qualifiers and
            // typedefs that mostly have no names of their own.
            let (entry_kind, referent, array_len) = match kind {
                KIND_INT => (TypeKind::Int, 0, 0),
                KIND_FLOAT => (TypeKind::Float, 0, 0),
                KIND_PTR => (TypeKind::Pointer, size_or_type, 0),
                KIND_ARRAY => {
                    // `struct btf_array { type, index_type, nelems }` follows
                    // the fixed header.
                    let a = &types[body_start..body_start + 12];
                    let elem = u32::from_le_bytes([a[0], a[1], a[2], a[3]]);
                    let nelems = u32::from_le_bytes([a[8], a[9], a[10], a[11]]);
                    (TypeKind::Array, elem, nelems)
                }
                KIND_STRUCT => (TypeKind::Struct, 0, 0),
                KIND_UNION => (TypeKind::Union, 0, 0),
                KIND_ENUM | KIND_ENUM64 => (TypeKind::Enum, 0, 0),
                KIND_TYPEDEF => (TypeKind::Typedef, size_or_type, 0),
                KIND_CONST => (TypeKind::Const, size_or_type, 0),
                KIND_VOLATILE => (TypeKind::Volatile, size_or_type, 0),
                KIND_RESTRICT => (TypeKind::Restrict, size_or_type, 0),
                KIND_TYPE_TAG => (TypeKind::TypeTag, size_or_type, 0),
                KIND_FUNC => (TypeKind::Func, size_or_type, 0),
                KIND_FUNC_PROTO => (TypeKind::FuncProto, 0, 0),
                _ => (TypeKind::Other, 0, 0),
            };
            entries.push(TypeEntry {
                kind: entry_kind,
                name: name.clone(),
                referent,
                array_len,
                // For a struct or union, BTF stores the byte size in the
                // size_or_type field; for every other kind that field is a type
                // reference and there is no size to keep.
                size: match entry_kind {
                    TypeKind::Struct | TypeKind::Union | TypeKind::Enum => size_or_type,
                    _ => 0,
                },
            });

            // The type id of the entry just pushed. Ids are 1-based; the void
            // placeholder took index 0, so the entry at `entries.len() - 1` is
            // this iteration's, and its id is that index.
            let type_id = (entries.len() - 1) as u32;

            match kind {
                KIND_STRUCT | KIND_UNION => {
                    let mut members = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let m = &types[body_start + i * 12..body_start + (i + 1) * 12];
                        let m_name = name_at(u32::from_le_bytes([m[0], m[1], m[2], m[3]]));
                        let m_type = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
                        let raw = u32::from_le_bytes([m[8], m[9], m[10], m[11]]);
                        // With kind_flag set, the offset word packs a bitfield
                        // width into its top 8 bits; without it, the whole word
                        // is a bit offset.
                        let (bit_offset, bitfield_size) = if kind_flag {
                            let width = raw >> 24;
                            (raw & 0x00FF_FFFF, (width != 0).then_some(width))
                        } else {
                            (raw, None)
                        };
                        members.push(Member {
                            name: m_name,
                            type_id: m_type,
                            bit_offset,
                            bitfield_size,
                        });
                    }
                    let composite = Composite {
                        name: name.clone(),
                        size: size_or_type,
                        is_union: kind == KIND_UNION,
                        members,
                    };
                    // A named aggregate is indexed by name for the ordinary
                    // lookup. An ANONYMOUS one has no name, so it is indexed by
                    // type id instead — the only way its members stay reachable
                    // from the member that declares it. Storing the named ones by
                    // id too would double every named composite's member storage
                    // for a table nothing consults them through, so it is not
                    // done: `composite_by_id` is the anonymous-aggregate path.
                    if name.is_empty() {
                        anon_composites.insert(type_id, composite);
                    } else {
                        composites.insert(name.clone(), composite);
                    }
                }
                KIND_ENUM | KIND_ENUM64 => {
                    // `struct btf_enum { name_off, val }` (8 bytes) or
                    // `struct btf_enum64 { name_off, val_lo32, val_hi32 }`
                    // (12 bytes). `kind_flag` set means the values are signed.
                    let stride = if kind == KIND_ENUM { 8 } else { 12 };
                    let mut constants = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let e = &types[body_start + i * stride..body_start + (i + 1) * stride];
                        let c_name = name_at(u32::from_le_bytes([e[0], e[1], e[2], e[3]]));
                        let lo = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
                        let value: i128 = if kind == KIND_ENUM {
                            if kind_flag {
                                i128::from(lo as i32)
                            } else {
                                i128::from(lo)
                            }
                        } else {
                            let hi = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
                            let raw = (u64::from(hi) << 32) | u64::from(lo);
                            if kind_flag {
                                i128::from(raw as i64)
                            } else {
                                i128::from(raw)
                            }
                        };
                        constants.push((c_name, value));
                    }
                    enums.insert(
                        type_id,
                        EnumType {
                            name: name.clone(),
                            size: size_or_type,
                            signed: kind_flag,
                            constants,
                        },
                    );
                }
                KIND_TYPEDEF if !name.is_empty() => {
                    if let Some(target) = pending_names.get(size_or_type as usize) {
                        if !target.is_empty() {
                            typedefs.insert(name.clone(), target.clone());
                        }
                    }
                }
                _ => {}
            }

            cursor = body_end;
            index += 1;
        }

        Ok(Self {
            composites,
            type_count: index,
            typedefs,
            entries,
            anon_composites,
            enums,
        })
    }

    /// Find and parse the BTF blob inside a block of kernel memory.
    ///
    /// Scans for the magic and accepts the first candidate whose header is
    /// self-consistent and whose type section parses. The magic is only two
    /// bytes, so it occurs by chance roughly every 64 KiB of arbitrary data —
    /// the header validation is what does the actual identification, and a
    /// coincidence fails it immediately.
    ///
    /// `min_types` rejects a small well-formed blob that is not the kernel's
    /// own: modules carry their own BTF, and a kernel's `vmlinux` BTF describes
    /// hundreds of thousands of types where a module's describes a handful.
    /// # Cost
    ///
    /// Linear in the bytes searched, which for a whole capture means decoding
    /// it. Measured at roughly a minute over a 15.65 GiB AVML image, most of it
    /// snappy decompression rather than the scan.
    ///
    /// A production path should narrow the search rather than sweep: the kernel
    /// exports `__start_BTF` and `__stop_BTF` through `kallsyms`, so resolving
    /// those first turns this into a direct read. Sweeping is the fallback for
    /// when `kallsyms` has not been located yet — which includes the case where
    /// BTF is wanted precisely *because* nothing else about the kernel is known.
    pub fn find_in(haystack: &[u8], min_types: usize) -> Option<(usize, Self)> {
        let magic = BTF_MAGIC.to_le_bytes();
        let mut at = 0usize;
        while at + HEADER_LEN <= haystack.len() {
            let found = haystack[at..]
                .windows(2)
                .position(|w| w == magic)
                .map(|p| at + p)?;
            // Version and header length are checked before attempting a parse,
            // so a chance magic costs two comparisons rather than a walk.
            if haystack.len() - found >= HEADER_LEN
                && haystack[found + 2] == BTF_VERSION
                && u32::from_le_bytes([
                    haystack[found + 4],
                    haystack[found + 5],
                    haystack[found + 6],
                    haystack[found + 7],
                ]) as usize
                    == HEADER_LEN
            {
                if let Ok(btf) = Btf::parse(&haystack[found..]) {
                    if btf.type_count >= min_types {
                        return Some((found, btf));
                    }
                }
            }
            at = found + 2;
        }
        None
    }

    /// A struct or union by name.
    ///
    /// Accepts the bare name (`task_struct`) and follows a typedef when the
    /// kernel spells it that way, so a caller does not have to know which.
    pub fn composite(&self, name: &str) -> Option<&Composite> {
        if let Some(found) = self.composites.get(name) {
            return Some(found);
        }
        let target = self.typedefs.get(name)?;
        self.composites.get(target)
    }

    /// An **anonymous** struct or union by BTF type id.
    ///
    /// This is how an anonymous aggregate's members are reached: it has no name
    /// for [`Self::composite`], but the member that embeds it carries its type
    /// id. Named composites are looked up by name through [`Self::composite`] and
    /// are not indexed here, so this returns `None` for a named id as well as for
    /// an id that is not a struct or union.
    pub fn composite_by_id(&self, type_id: u32) -> Option<&Composite> {
        self.anon_composites.get(&type_id)
    }

    /// An enumeration by BTF type id, named or anonymous.
    pub fn enum_by_id(&self, type_id: u32) -> Option<&EnumType> {
        self.enums.get(&type_id)
    }

    /// Every enumeration's type id, in ascending order (so a caller that
    /// renders them produces the same bytes from the same blob).
    pub fn enum_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.enums.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Byte offset of `member` within `type_name`.
    ///
    /// `None` when either is absent, or when the member is a bitfield that does
    /// not begin on a byte boundary — for which a byte offset would be a lie.
    pub fn member_offset(&self, type_name: &str, member: &str) -> Option<u64> {
        self.composite(type_name)?.member(member)?.byte_offset()
    }

    /// Size in bytes of a named struct or union.
    pub fn type_size(&self, type_name: &str) -> Option<u64> {
        self.composite(type_name).map(|c| c.size as u64)
    }

    /// One entry by BTF type id, or `None` for an id past the table.
    ///
    /// Id 0 is void and resolves to a placeholder rather than to nothing, so a
    /// caller walking a chain that ends in void terminates rather than
    /// treating the end as an error.
    pub fn type_entry(&self, id: u32) -> Option<&TypeEntry> {
        self.entries.get(id as usize)
    }

    /// How many type entries were walked.
    pub fn type_count(&self) -> usize {
        self.type_count
    }

    /// How many named structs and unions were indexed.
    pub fn composite_count(&self) -> usize {
        self.composites.len()
    }

    /// Every named composite, for callers enumerating what a kernel declares.
    pub fn composite_names(&self) -> impl Iterator<Item = &str> {
        self.composites.keys().map(String::as_str)
    }
}

/// Blob assembly shared with `crate::btf_isf`'s tests.
///
/// `cfg(test)`-only: it exists so two test modules build the same shape of
/// input the same way, not as API. The authoritative check for both remains
/// `tests/btf_real_capture_test.rs`, against a blob the kernel wrote.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{BTF_MAGIC, BTF_VERSION, HEADER_LEN, KIND_STRUCT};

    /// A BTF blob declaring one struct with the given `(name, type_id, bit_offset)`
    /// members.
    pub fn blob(struct_name: &str, members: &[(&str, u32, u32)], size: u32) -> Vec<u8> {
        let mut strings = vec![0u8];
        let offset_of = |s: &str, strings: &mut Vec<u8>| -> u32 {
            if s.is_empty() {
                return 0;
            }
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let name_off = offset_of(struct_name, &mut strings);
        let member_offs: Vec<u32> = members
            .iter()
            .map(|(n, _, _)| offset_of(n, &mut strings))
            .collect();

        let mut types = Vec::new();
        let info = (members.len() as u32) | ((KIND_STRUCT as u32) << 24);
        types.extend_from_slice(&name_off.to_le_bytes());
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&size.to_le_bytes());
        for (i, (_, type_id, bit_off)) in members.iter().enumerate() {
            types.extend_from_slice(&member_offs[i].to_le_bytes());
            types.extend_from_slice(&type_id.to_le_bytes());
            types.extend_from_slice(&bit_off.to_le_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0);
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    /// One struct for [`blob_with_structs`]: name, members, byte size.
    ///
    /// Named rather than written inline because the tuple-of-slice-of-tuples is
    /// unreadable at a call site and clippy is right to say so.
    pub type StructSpec<'a> = (&'a str, &'a [(&'a str, u32, u32)], u32);

    /// A BTF blob declaring SEVERAL named structs, in the order given.
    ///
    /// [`blob`] declares one, which is enough to test a conversion and not
    /// enough to test an *ordering*: with a single composite there is only one
    /// order. This exists for the determinism check in `crate::btf_isf`, where
    /// what matters is that the generated document's byte order does not depend
    /// on how a `HashMap` happened to seed itself.
    pub fn blob_with_structs(structs: &[StructSpec<'_>]) -> Vec<u8> {
        let mut strings = vec![0u8];
        let offset_of = |s: &str, strings: &mut Vec<u8>| -> u32 {
            if s.is_empty() {
                return 0;
            }
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };

        let mut types = Vec::new();
        for (struct_name, members, size) in structs {
            let name_off = offset_of(struct_name, &mut strings);
            let member_offs: Vec<u32> = members
                .iter()
                .map(|(n, _, _)| offset_of(n, &mut strings))
                .collect();
            let info = (members.len() as u32) | ((KIND_STRUCT as u32) << 24);
            types.extend_from_slice(&name_off.to_le_bytes());
            types.extend_from_slice(&info.to_le_bytes());
            types.extend_from_slice(&size.to_le_bytes());
            for (i, (_, type_id, bit_off)) in members.iter().enumerate() {
                types.extend_from_slice(&member_offs[i].to_le_bytes());
                types.extend_from_slice(&type_id.to_le_bytes());
                types.extend_from_slice(&bit_off.to_le_bytes());
            }
        }

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0);
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    /// A BTF blob declaring an ANONYMOUS empty struct (type id 1) and a named
    /// `outer` struct (type id 2) with one member `member` of that empty type at
    /// offset 0. Models `struct pagesets { local_lock_t lock; }` where
    /// `local_lock_t` is `struct { }`.
    pub fn blob_with_anon_empty_member(outer: &str, member: &str, outer_size: u32) -> Vec<u8> {
        let mut strings = vec![0u8];
        let off = |s: &str, strings: &mut Vec<u8>| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let outer_name = off(outer, &mut strings);
        let member_name = off(member, &mut strings);

        let mut types = Vec::new();
        // Type 1: anonymous empty struct — name 0, vlen 0, size 0.
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT as u32) << 24).to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // Type 2: `outer` with one member of type 1 at bit offset 0.
        types.extend_from_slice(&outer_name.to_le_bytes());
        types.extend_from_slice(&(1u32 | ((KIND_STRUCT as u32) << 24)).to_le_bytes());
        types.extend_from_slice(&outer_size.to_le_bytes());
        types.extend_from_slice(&member_name.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes()); // member type = id 1
        types.extend_from_slice(&0u32.to_le_bytes()); // bit offset 0

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0);
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    /// A BTF blob modelling the `mm_struct.mmap` shape: a named `outer` struct
    /// whose member is an ANONYMOUS, non-empty struct that itself carries a named
    /// `inner` field. The inner field sits at byte `inner_off` inside the
    /// anonymous struct, which sits at byte `anon_off` inside `outer`, so a
    /// lookup of `outer.inner` must resolve to `anon_off + inner_off` once the
    /// anonymous member is lifted.
    pub fn blob_with_anon_field(
        outer: &str,
        inner: &str,
        anon_off: u32,
        inner_off: u32,
    ) -> Vec<u8> {
        const KIND_INT: u32 = 1;
        let mut strings = vec![0u8];
        let off = |s: &str, strings: &mut Vec<u8>| -> u32 {
            if s.is_empty() {
                return 0;
            }
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let int_name = off("int", &mut strings);
        let inner_name = off(inner, &mut strings);
        let outer_name = off(outer, &mut strings);

        let mut types = Vec::new();
        // Type 1: base int (4 bytes). Tail is one u32 of int metadata (32 bits).
        types.extend_from_slice(&int_name.to_le_bytes());
        types.extend_from_slice(&(KIND_INT << 24).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes()); // encoding: 32 bits
                                                       // Type 2: anonymous struct { inner: int } of 8 bytes.
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&(1u32 | ((KIND_STRUCT as u32) << 24)).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&inner_name.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes()); // inner type = id 1 (int)
        types.extend_from_slice(&(inner_off * 8).to_le_bytes()); // bit offset
                                                                 // Type 3: `outer` with one ANONYMOUS member of type 2 at `anon_off`.
        types.extend_from_slice(&outer_name.to_le_bytes());
        types.extend_from_slice(&(1u32 | ((KIND_STRUCT as u32) << 24)).to_le_bytes());
        types.extend_from_slice(&(anon_off + 16).to_le_bytes()); // outer size
        types.extend_from_slice(&0u32.to_le_bytes()); // member name 0 = anonymous
        types.extend_from_slice(&2u32.to_le_bytes()); // member type = id 2
        types.extend_from_slice(&(anon_off * 8).to_le_bytes()); // bit offset

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0);
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid BTF blob declaring one struct.
    ///
    /// Deliberately hand-assembled rather than captured, so the boundary cases
    /// below can be constructed. The *real* check is
    /// `tests/btf_real_capture_test.rs`, which parses a blob the kernel wrote —
    /// this crate has been caught twice by fixtures that agreed with a reader
    /// because both were written from the same misreading.
    fn blob(struct_name: &str, members: &[(&str, u32, u32)], size: u32) -> Vec<u8> {
        let mut strings = vec![0u8]; // index 0 is the empty string
        let offset_of = |s: &str, strings: &mut Vec<u8>| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let name_off = offset_of(struct_name, &mut strings);
        let member_offs: Vec<u32> = members
            .iter()
            .map(|(n, _, _)| offset_of(n, &mut strings))
            .collect();

        let mut types = Vec::new();
        let info = (members.len() as u32) | ((KIND_STRUCT as u32) << 24);
        types.extend_from_slice(&name_off.to_le_bytes());
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&size.to_le_bytes());
        for (i, (_, type_id, bit_off)) in members.iter().enumerate() {
            types.extend_from_slice(&member_offs[i].to_le_bytes());
            types.extend_from_slice(&type_id.to_le_bytes());
            types.extend_from_slice(&bit_off.to_le_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0);
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn a_struct_and_its_member_offsets_are_read() {
        let data = blob(
            "task_struct",
            &[("pid", 1, 8 * 8), ("comm", 1, 64 * 8)],
            4096,
        );
        let btf = Btf::parse(&data).expect("parses");
        assert_eq!(btf.type_size("task_struct"), Some(4096));
        assert_eq!(btf.member_offset("task_struct", "pid"), Some(8));
        assert_eq!(btf.member_offset("task_struct", "comm"), Some(64));
        assert_eq!(btf.member_offset("task_struct", "nonexistent"), None);
        assert_eq!(btf.member_offset("no_such_struct", "pid"), None);
    }

    #[test]
    fn a_bitfield_that_does_not_start_on_a_byte_has_no_byte_offset() {
        // Rounding 12 bits down to byte 1 would relocate the field, and the
        // value read there would be a real number from the wrong bits.
        let data = blob("flags_holder", &[("bit", 1, 12)], 8);
        let btf = Btf::parse(&data).expect("parses");
        assert_eq!(btf.member_offset("flags_holder", "bit"), None);
        let member = btf
            .composite("flags_holder")
            .and_then(|c| c.member("bit"))
            .expect("the member is still described");
        assert_eq!(member.bit_offset, 12, "the bit offset itself is exact");
    }

    #[test]
    fn a_range_without_the_magic_is_not_btf() {
        assert_eq!(Btf::parse(&[0u8; 64]).unwrap_err(), BtfError::NotBtf);
    }

    #[test]
    fn a_short_range_says_how_short() {
        assert_eq!(
            Btf::parse(&[0x9f, 0xeb]).unwrap_err(),
            BtfError::TooShort { have: 2, need: 24 }
        );
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        let mut data = blob("t", &[], 8);
        data[2] = 9;
        assert_eq!(
            Btf::parse(&data).unwrap_err(),
            BtfError::UnsupportedVersion(9)
        );
    }

    #[test]
    fn a_header_declaring_sections_past_the_data_is_refused() {
        let mut data = blob("t", &[("a", 1, 0)], 8);
        // Claim a type section far larger than the blob.
        data[12..16].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert!(matches!(
            Btf::parse(&data).unwrap_err(),
            BtfError::InconsistentHeader(_)
        ));
    }

    #[test]
    fn the_scanner_finds_a_blob_embedded_in_surrounding_noise() {
        let data = blob("task_struct", &[("pid", 1, 0)], 16);
        let mut haystack = vec![0xAAu8; 8192];
        // A decoy magic that is not BTF, before the real one, so the scan has
        // to reject a candidate rather than take the first two bytes it sees.
        haystack[100..102].copy_from_slice(&BTF_MAGIC.to_le_bytes());
        let at = 4096;
        haystack[at..at + data.len()].copy_from_slice(&data);

        let (found, btf) = Btf::find_in(&haystack, 1).expect("the real blob is found");
        assert_eq!(found, at, "the decoy must not be accepted");
        assert_eq!(btf.member_offset("task_struct", "pid"), Some(0));
    }

    #[test]
    fn the_scanner_rejects_a_blob_smaller_than_the_caller_requires() {
        // A module's BTF describes a handful of types; a kernel's describes
        // hundreds of thousands. A caller asking for the kernel's must not be
        // handed a module's.
        let data = blob("small", &[("a", 1, 0)], 8);
        let mut haystack = vec![0u8; 4096];
        haystack[..data.len()].copy_from_slice(&data);
        assert!(Btf::find_in(&haystack, 1000).is_none());
    }

    #[test]
    fn an_empty_type_section_is_refused() {
        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0);
        out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_len = 0
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Btf::parse(&out).unwrap_err(),
            BtfError::InconsistentHeader(_)
        ));
    }
}
