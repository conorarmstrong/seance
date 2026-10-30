//! Turning a kernel's own BTF into an ISF document.
//!
//! [`crate::btf`] reads the type description a modern Linux kernel carries
//! about itself. This module renders that description as an **ISF document**,
//! which is the form the rest of the platform already consumes.
//!
//! # Why go through ISF rather than around it
//!
//! `seance_symbols::SymbolTable` is not merely a lookup table. Compiling a
//! document runs the admission gates — duplicate member names, out-of-range
//! bitfields, members that overrun their aggregate, unresolvable type
//! references — and produces the `BuildBinding` provenance that lets a record
//! say which layout produced its figures. A second, parallel symbol source
//! that bypassed all that would be a second place for those checks to be
//! missing.
//!
//! So BTF is rendered to ISF JSON and handed to the existing parser. Nothing
//! downstream changes, the gates apply unchanged, and a BTF-derived table is
//! subject to exactly the scrutiny an ISF file from disk gets.
//!
//! # What is and is not carried across
//!
//! BTF describes **types**. It carries no symbol addresses, so the `symbols`
//! section of the generated document is **empty**, and a table compiled from it
//! can answer "where is `task_struct.comm`" but not "where is `init_task`".
//! Addresses come from `kallsyms`, which is a separate structure and separate
//! work; until that exists, a BTF-derived table complements an ISF rather than
//! replacing one outright.
//!
//! That limitation is deliberate rather than hidden. Emitting fabricated or
//! zero addresses to make the document look complete would produce a table that
//! resolves a symbol to address zero and reads whatever is mapped there.
//!
//! # Fidelity
//!
//! Member offsets, aggregate sizes, bitfield positions and widths, and the
//! struct/union distinction all cross over exactly. Type *references* are
//! rendered structurally — pointer, array, base, struct, union, enum — by
//! walking BTF's own type graph, so a member's declared type resolves the same
//! way it would from DWARF-derived ISF.
//!
//! Anonymous members are emitted with the `anonymous` flag the ISF schema
//! defines for them, under a generated placeholder name: the schema keys
//! members by name and BTF's are genuinely nameless, so a name has to be
//! invented to express one. The flag is what tells a consumer the name is not
//! the kernel's — and, for an anonymous *aggregate* member, is what makes the
//! symbol reader lift its fields into the parent. Such a member's type is a
//! synthesized named `user_type` (`__anon_<id>`) carrying the aggregate's real
//! fields, so a field nested inside one — `mm_struct.mmap`, which lives in an
//! anonymous `__randomize_layout` struct — resolves through the parent exactly
//! as it does from a dwarf2json-produced document.
//!
//! Enumerations (`BTF_KIND_ENUM` and `ENUM64`) cross into the `enums`
//! section under their own names, with the base type their width and sign call
//! for, so `module_state`, `mod_mem_type` and `bpf_prog_type` values can be
//! named. Three kinds are not emitted, and a member typed by one is described
//! by its storage (the right width and sign, no names): an anonymous
//! enumeration, one with no constants (a forward declaration), and a name that
//! two *different* enumerations share — Ubuntu's 6.8 BTF declares
//! `energy_perf_value_index` twice — because the ISF keys enumerations by name
//! and a lookup by that name could not say which was meant.

use crate::btf::{Btf, Composite};
use crate::kallsyms::Kallsyms;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// ISF format version the generated document declares.
///
/// 6.2.0 rather than the newest the reader accepts: it is the version that
/// defines the `anonymous` member flag, which BTF needs, and claiming a later
/// version would assert support for fields this producer does not emit.
const ISF_FORMAT: &str = "6.2.0";

/// What this producer calls itself in the document's metadata.
///
/// Recorded so a report can say the layout came from BTF in the image rather
/// than from a symbol file matched by banner. Those are different evidential
/// claims and the document is where the difference is preserved.
pub const PRODUCER_NAME: &str = "seance-btf";

/// Why a BTF blob could not be rendered as ISF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertError {
    /// The BTF described no named composites, so the document would declare no
    /// types. A table compiled from it could answer nothing.
    NoTypes,
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertError::NoTypes => write!(
                f,
                "the BTF describes no named structs or unions, so an ISF built \
                 from it would declare no types"
            ),
        }
    }
}

impl std::error::Error for ConvertError {}

/// Render `btf` as an ISF document.
///
/// `banner` is the kernel's `linux_banner`, when it is known; it goes into the
/// document's identity so a compiled table can be matched against the image it
/// came from. `None` is legitimate — BTF alone does not carry it.
pub fn to_isf_json(btf: &Btf, banner: Option<&str>) -> Result<Value, ConvertError> {
    to_isf_json_with_symbols(btf, banner, None)
}

/// Render `btf` as an ISF document, with symbol addresses from `kallsyms`.
///
/// This is the complete article: BTF supplies the types, `kallsyms` supplies the
/// addresses, and together they are what an ISF file contains — recovered
/// entirely from the capture, matched to nothing, downloaded from nowhere. A
/// table compiled from this can answer both "where is `task_struct.comm`" and
/// "where is `init_task`".
///
/// Passing `None` for the symbols yields a types-only document, which is what
/// [`to_isf_json`] does; that form is still useful for corroborating a symbol
/// file, but cannot drive a discovery on its own.
pub fn to_isf_json_with_symbols(
    btf: &Btf,
    banner: Option<&str>,
    kallsyms: Option<&Kallsyms>,
) -> Result<Value, ConvertError> {
    if btf.composite_count() == 0 {
        return Err(ConvertError::NoTypes);
    }

    let mut user_types = Map::new();
    let mut base_types = base_type_table();
    let mut referenced: HashSet<String> = HashSet::new();
    // Named types synthesized for anonymous aggregates, so their fields cross
    // into the ISF and the symbol reader can lift them into the parent.
    let mut synthetic: Map<String, Value> = Map::new();

    // # Why this is sorted, and why it matters more here than it looks
    //
    // This document has no file path. It was generated in memory from the
    // capture, so what the report cites to say *which* document produced a
    // figure is its SHA-256 — and `profile.rs` tells the reader it "is
    // reproducible from [the image]". That sentence is only true if the same
    // image yields the same bytes.
    //
    // `serde_json` is compiled with `preserve_order` in this workspace (`evtx`
    // and `yara-x` both ask for it, and Cargo unifies features across the
    // graph), so `Map` is an `IndexMap` and **insertion order is part of the
    // output**. `Btf::composite_names()` iterates a `HashMap`, whose order
    // depends on a per-instance random seed: two parses of the same blob in one
    // process iterate differently. That put a different SHA-256 on the same
    // image from one run to the next, so the hash identified nothing.
    //
    // Sorting is applied where the source is unordered — here, and over
    // `referenced` below. The other sections are left in the order their source
    // gives them, because those sources are already ordered: `base_type_table`
    // is a fixed sequence of inserts, and the symbols come from a slice in the
    // kernel's own table order.
    // Enumerations first: a member typed by one refers to it by the name
    // decided here.
    let (enums, enum_names) = enum_section(btf, &mut referenced);

    let mut composite_names: Vec<&str> = btf.composite_names().collect();
    composite_names.sort_unstable();

    for name in composite_names {
        let Some(composite) = btf.composite(name) else {
            continue;
        };
        user_types.insert(
            name.to_string(),
            user_type(
                btf,
                composite,
                &enum_names,
                &mut referenced,
                &mut synthetic,
                0,
            ),
        );
    }
    // Fold in the synthesized anonymous aggregates. A real kernel type is never
    // spelled `__anon_<id>`, so these cannot collide with one; `or_insert`
    // leaves any (impossible) pre-existing entry untouched.
    for (name, value) in synthetic {
        user_types.entry(name).or_insert(value);
    }

    // Any base type a member referred to that the standard table does not
    // define is added as an opaque byte-sized entry rather than omitted. A
    // dangling type reference fails the admission gate and costs the whole
    // member; an honest placeholder costs only the ability to interpret it.
    // Sorted for the reason above: `referenced` is a `HashSet`, so its
    // iteration order is a property of this process rather than of the image.
    let mut referenced: Vec<&String> = referenced.iter().collect();
    referenced.sort_unstable();
    for name in referenced {
        base_types.entry(name.clone()).or_insert_with(
            || json!({ "size": 0, "signed": false, "kind": "void", "endian": "little" }),
        );
    }

    let mut metadata = json!({
        "format": ISF_FORMAT,
        "producer": {
            "name": PRODUCER_NAME,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "linux": {
            // The types came from BTF resident in the image itself. Named so a
            // reader of the document can tell that from a `vmlinux` on disk.
            "types": [{ "kind": "btf", "name": "kernel BTF (embedded)" }],
            "symbols": symbol_sources(kallsyms),
        },
    });
    if let Some(banner) = banner {
        metadata["linux"]["banner"] = json!(banner);
    }

    Ok(json!({
        "metadata": metadata,
        "base_types": Value::Object(base_types),
        "user_types": Value::Object(user_types),
        "enums": Value::Object(enums),
        "symbols": symbols_section(kallsyms),
    }))
}

/// Render `btf` as an [`IsfSource`](seance_symbols::IsfSource), ready to compile.
///
/// Preferred over calling [`to_isf_json`] and assembling the source by hand,
/// because the provenance hashes are computed here once. Those hashes are what
/// a report cites to say *which* document produced a figure — a caller that
/// derived them separately could derive them from different bytes than the ones
/// compiled.
///
/// The compression field says `None`: the document was generated in memory and
/// was never a file, so there is no stored form to describe.
pub fn to_isf_source(
    btf: &Btf,
    banner: Option<&str>,
) -> Result<seance_symbols::IsfSource, ConvertError> {
    to_isf_source_with_symbols(btf, banner, None)
}

/// [`to_isf_source`] with symbol addresses from `kallsyms`.
pub fn to_isf_source_with_symbols(
    btf: &Btf,
    banner: Option<&str>,
    kallsyms: Option<&Kallsyms>,
) -> Result<seance_symbols::IsfSource, ConvertError> {
    let json = to_isf_json_with_symbols(btf, banner, kallsyms)?
        .to_string()
        .into_bytes();
    let digest = seance_symbols::sha256_hex(&json);
    let len = json.len() as u64;
    Ok(seance_symbols::IsfSource {
        provenance: seance_symbols::IsfProvenance {
            // Generated rather than read, so both forms are the same bytes.
            source_sha256: digest.clone(),
            source_len: len,
            json_sha256: digest,
            json_len: len,
            compression: seance_symbols::Compression::None,
        },
        json,
    })
}

/// The `symbols` section.
///
/// Empty without a `kallsyms` table, and it must stay that way: BTF carries no
/// addresses, and a fabricated one resolves to whatever happens to be mapped
/// there rather than failing.
///
/// A name that the kernel declares more than once — static functions of the
/// same name in different translation units are ordinary — is emitted once, at
/// its first address. The ISF schema keys symbols by name and has nowhere to
/// put the second.
fn symbols_section(kallsyms: Option<&Kallsyms>) -> Value {
    let Some(kallsyms) = kallsyms else {
        return json!({});
    };
    let mut out = Map::new();
    for symbol in kallsyms.symbols() {
        out.entry(symbol.name.clone())
            .or_insert_with(|| json!({ "address": symbol.address }));
    }
    Value::Object(out)
}

/// What the document records about where its symbols came from.
fn symbol_sources(kallsyms: Option<&Kallsyms>) -> Value {
    match kallsyms {
        Some(k) => json!([{
            "kind": "kallsyms",
            "name": format!("kernel kallsyms (embedded), {} symbols", k.len()),
        }]),
        None => json!([]),
    }
}

/// BTF type id → the name its enumeration is emitted under.
type EnumNames = HashMap<u32, String>;

/// The base type an enumeration of `size` bytes and this signedness is stored
/// as, from the fixed table [`base_type_table`] declares. `None` for a width
/// no C integer type has, which a real kernel never declares.
fn storage_base(size: u32, signed: bool) -> Option<&'static str> {
    Some(match (size, signed) {
        (1, false) => "unsigned char",
        (1, true) => "signed char",
        (2, false) => "unsigned short",
        (2, true) => "short",
        (4, false) => "unsigned int",
        (4, true) => "int",
        (8, false) => "unsigned long",
        (8, true) => "long",
        _ => return None,
    })
}

/// The `enums` section, and which BTF type ids it names.
///
/// Every **named** enumeration that has at least one constant and a width the
/// base table can express is emitted under its own name, with the base type
/// its width and sign call for — so the constants always fit their base and the
/// admission gate's range check cannot refuse the document over one.
///
/// A name that two *different* enumerations share is emitted for neither: the
/// ISF keys enumerations by name, and a lookup by that name could not say which
/// was meant. (Identical definitions under one name — the same enumeration
/// seen twice — are one enumeration and are emitted once.) Members typed by an
/// omitted enumeration keep their width and sign through [`storage_base`] and
/// lose only the names.
///
/// Anonymous enumerations are not emitted: nothing can look one up by name,
/// and a member typed by one is read through its storage.
fn enum_section(btf: &Btf, referenced: &mut HashSet<String>) -> (Map<String, Value>, EnumNames) {
    // name → the ids declaring it, in ascending id order.
    let mut by_name: std::collections::BTreeMap<&str, Vec<u32>> = Default::default();
    for id in btf.enum_ids() {
        let Some(e) = btf.enum_by_id(id) else {
            continue;
        };
        if e.name.is_empty() || e.constants.is_empty() || storage_base(e.size, e.signed).is_none() {
            continue;
        }
        by_name.entry(e.name.as_str()).or_default().push(id);
    }

    let mut section = Map::new();
    let mut names = EnumNames::new();
    for (name, ids) in by_name {
        let first = btf.enum_by_id(ids[0]).expect("collected above");
        let same = ids.iter().all(|id| {
            btf.enum_by_id(*id).is_some_and(|e| {
                e.size == first.size && e.signed == first.signed && e.constants == first.constants
            })
        });
        if !same {
            continue;
        }
        let base = storage_base(first.size, first.signed).expect("filtered above");
        referenced.insert(base.to_string());
        let mut constants = Map::new();
        for (constant, value) in &first.constants {
            // A duplicate constant name within one enumeration cannot come from
            // a C compiler; from a damaged blob, the first is kept, as for
            // members.
            constants.entry(constant.clone()).or_insert_with(|| {
                if *value < 0 {
                    json!(*value as i64)
                } else {
                    json!(*value as u64)
                }
            });
        }
        section.insert(
            name.to_string(),
            json!({ "size": first.size, "base": base, "constants": constants }),
        );
        for id in ids {
            names.insert(id, name.to_string());
        }
    }
    (section, names)
}

/// How deep the type-reference walk, and the synthesis of nested anonymous
/// aggregates, may recurse before a member is rendered opaque instead.
///
/// This bounds a walk over a BTF blob *recovered from evidence*, which a corrupt
/// or hostile image could otherwise make recurse without limit — a self-
/// referential type chain, or a long chain of distinct nested anonymous
/// aggregates. It is threaded through both [`type_descriptor`] and [`user_type`]
/// precisely so synthesizing an anonymous aggregate cannot restart it at zero.
const MAX_DEPTH: usize = 16;

/// One `user_types` entry.
///
/// `depth` is the recursion depth this type is being emitted at — zero for a
/// named top-level type, and one deeper than its parent for a synthesized
/// anonymous aggregate — so the [`MAX_DEPTH`] bound spans the whole nested walk
/// rather than resetting each time an anonymous aggregate is synthesized.
fn user_type(
    btf: &Btf,
    composite: &Composite,
    enum_names: &EnumNames,
    referenced: &mut HashSet<String>,
    synthetic: &mut Map<String, Value>,
    depth: usize,
) -> Value {
    let mut fields = Map::new();
    for (index, member) in composite.members.iter().enumerate() {
        let descriptor = type_descriptor(
            btf,
            member.type_id,
            enum_names,
            referenced,
            synthetic,
            depth,
        );

        // A bitfield is expressed by wrapping the storage unit, which is how
        // the ISF schema says it and how every consumer reads it.
        let (offset, descriptor) = match member.bitfield_size {
            Some(width) => {
                let unit_offset = (member.bit_offset / 8) as u64;
                let bit_position = (member.bit_offset % 8) as i64;
                (
                    unit_offset,
                    json!({
                        "kind": "bitfield",
                        "bit_position": bit_position,
                        "bit_length": width as i64,
                        "type": descriptor,
                    }),
                )
            }
            // A member whose bit offset is not a whole byte but which BTF did
            // not mark as a bitfield is still expressed as one, because the
            // byte offset alone would relocate it.
            None if !member.bit_offset.is_multiple_of(8) => {
                let unit_offset = (member.bit_offset / 8) as u64;
                let bit_position = (member.bit_offset % 8) as i64;
                (
                    unit_offset,
                    json!({
                        "kind": "bitfield",
                        "bit_position": bit_position,
                        "bit_length": 0,
                        "type": descriptor,
                    }),
                )
            }
            None => ((member.bit_offset / 8) as u64, descriptor),
        };

        let anonymous = member.name.is_empty();
        // The schema keys members by name and BTF's anonymous members have
        // none, so one is generated. The `anonymous` flag is what says the name
        // is this producer's invention and not the kernel's.
        let key = if anonymous {
            format!("__anonymous_{index}")
        } else {
            member.name.clone()
        };

        let mut field = json!({ "offset": offset, "type": descriptor });
        if anonymous {
            field["anonymous"] = json!(true);
        }
        // A struct may legitimately declare the same member name twice through
        // macro expansion; the first wins here and the gate sees one entry.
        fields.entry(key).or_insert(field);
    }

    json!({
        "size": composite.size as u64,
        "kind": if composite.is_union { "union" } else { "struct" },
        "fields": Value::Object(fields),
    })
}

/// Render a BTF type id as an ISF type descriptor.
///
/// `depth` bounds the walk. BTF's graph is a graph, not a tree — a struct may
/// contain a pointer to itself — and while the kernel's own BTF is well formed,
/// this reads a blob recovered from evidence and must not be made to recurse
/// without limit by a corrupt one.
fn type_descriptor(
    btf: &Btf,
    type_id: u32,
    enum_names: &EnumNames,
    referenced: &mut HashSet<String>,
    synthetic: &mut Map<String, Value>,
    depth: usize,
) -> Value {
    if depth >= MAX_DEPTH {
        return opaque(referenced);
    }

    let Some(entry) = btf.type_entry(type_id) else {
        return opaque(referenced);
    };

    use crate::btf::TypeKind as K;
    match entry.kind {
        K::Int | K::Float => {
            let name = if entry.name.is_empty() {
                "unsigned char".to_string()
            } else {
                entry.name.clone()
            };
            referenced.insert(name.clone());
            json!({ "kind": "base", "name": name })
        }
        K::Pointer => json!({
            "kind": "pointer",
            "subtype": type_descriptor(btf, entry.referent, enum_names, referenced, synthetic, depth + 1),
        }),
        K::Array => json!({
            "kind": "array",
            "count": entry.array_len as u64,
            "subtype": type_descriptor(btf, entry.referent, enum_names, referenced, synthetic, depth + 1),
        }),
        K::Struct | K::Union if !entry.name.is_empty() => json!({
            "kind": if entry.kind == K::Union { "union" } else { "struct" },
            "name": entry.name,
        }),
        // A zero-size anonymous aggregate is rendered as the zero-byte type
        // (`unsigned char[0]`), not the one-byte opaque placeholder: an empty
        // `struct { }` — the shape of `local_lock_t` on a kernel built without
        // CONFIG_DEBUG_LOCK_ALLOC, embedded in `struct pagesets`
        // (mm/page_alloc.c) — occupies no bytes, and a one-byte placeholder made
        // its zero-sized wrapper look incoherent (a "1-byte member in a 0-byte
        // struct"), which the admission gate refused, rejecting the ENTIRE
        // image-derived symbol table of a stock Ubuntu/Debian capture over a
        // per-cpu type no analysis reads. An empty aggregate has no fields to
        // recover, so there is nothing to synthesize.
        K::Struct | K::Union if entry.size == 0 => {
            referenced.insert("unsigned char".to_string());
            json!({
                "kind": "array",
                "count": 0,
                "subtype": { "kind": "base", "name": "unsigned char" },
            })
        }
        // A non-empty anonymous aggregate — `struct { ... }` embedded without a
        // member name, which `mm_struct` and `task_struct` use pervasively — is
        // synthesized as a named user_type carrying its fields, and referred to
        // by that name. Rendering it opaque instead (the earlier behaviour) threw
        // its fields away, so a lookup of anything nested inside one — e.g.
        // `mm_struct.mmap`, which lives in an anonymous `__randomize_layout`
        // struct — resolved to nothing and the whole VMA walk was unavailable on
        // an image-derived profile. The member that embeds it keeps its
        // `anonymous` flag, so the symbol reader lifts these fields into the
        // parent exactly as it does for a dwarf2json-produced document.
        K::Struct | K::Union => synthesize_anon(
            btf, type_id, entry.kind, enum_names, referenced, synthetic, depth,
        ),
        // An enumeration emitted in the `enums` section is referred to by
        // name, so a member typed by it reads at its real width and sign and
        // its value can be named. One that is not emitted — anonymous, a
        // forward declaration with no constants, a name two different
        // enumerations share, or a width the base table has no type for — is
        // described by its storage alone: the right width and sign, no names.
        K::Enum => match enum_names.get(&type_id) {
            Some(name) => json!({ "kind": "enum", "name": name }),
            None => match btf
                .enum_by_id(type_id)
                .and_then(|e| storage_base(e.size, e.signed))
            {
                Some(base) => {
                    referenced.insert(base.to_string());
                    json!({ "kind": "base", "name": base })
                }
                None => opaque(referenced),
            },
        },
        // Qualifiers and typedefs are transparent: what matters is what they
        // resolve to.
        K::Typedef | K::Const | K::Volatile | K::Restrict | K::TypeTag => type_descriptor(
            btf,
            entry.referent,
            enum_names,
            referenced,
            synthetic,
            depth + 1,
        ),
        K::Func | K::FuncProto => json!({ "kind": "function" }),
        K::Other => opaque(referenced),
    }
}

/// Synthesize a named user_type for an anonymous aggregate and return a
/// reference to it.
///
/// The name is `__anon_<type_id>` — deterministic, so the same image yields the
/// same document, and unmistakable for a real kernel type. The referenced type
/// is emitted into `synthetic` (the caller folds that into `user_types`), so its
/// fields cross into the ISF and can be lifted into whatever parent embeds it.
///
/// The name is reserved with a placeholder before the members are walked, so an
/// aggregate that reaches itself through a pointer resolves to the reference
/// rather than recursing without end. A cycle is not the only way to recurse
/// without bound, though: a chain of *distinct* nested anonymous aggregates
/// would, so `depth` carries the [`MAX_DEPTH`] budget across the synthesis and a
/// too-deep aggregate is rendered opaque rather than followed.
fn synthesize_anon(
    btf: &Btf,
    type_id: u32,
    kind: crate::btf::TypeKind,
    enum_names: &EnumNames,
    referenced: &mut HashSet<String>,
    synthetic: &mut Map<String, Value>,
    depth: usize,
) -> Value {
    use crate::btf::TypeKind as K;
    // Too deep to keep synthesizing: an evidence-recovered blob does not get to
    // drive this to a stack overflow. The member is kept as an opaque byte, the
    // same fallback every other bounded case here uses.
    if depth >= MAX_DEPTH {
        return opaque(referenced);
    }
    let name = format!("__anon_{type_id}");
    let reference = json!({
        "kind": if kind == K::Union { "union" } else { "struct" },
        "name": name.clone(),
    });
    // Already emitted, or being emitted right now (a cycle): the reference is
    // enough, and re-entering would not terminate.
    if synthetic.contains_key(&name) {
        return reference;
    }
    // No members recorded for this id — keep the member as opaque rather than
    // emit a dangling reference the gate would reject.
    let Some(composite) = btf.composite_by_id(type_id) else {
        return opaque(referenced);
    };
    synthetic.insert(name.clone(), Value::Null);
    // One level deeper: the synthesized type's own members continue the same
    // bounded walk rather than restarting it.
    let value = user_type(btf, composite, enum_names, referenced, synthetic, depth + 1);
    synthetic.insert(name.clone(), value);
    reference
}

/// A descriptor for something this converter cannot express.
///
/// A byte, not a void: the ISF gate rejects a member whose type does not
/// resolve, which would cost the member entirely. A one-byte opaque placeholder
/// keeps the member and its offset — which is what analysis reads — while
/// making no claim about how to interpret its contents.
fn opaque(referenced: &mut HashSet<String>) -> Value {
    referenced.insert("unsigned char".to_string());
    json!({ "kind": "base", "name": "unsigned char" })
}

/// The primitive types a generated document declares.
///
/// BTF names its integer types the way C does, so these are the C names. Widths
/// are the LP64 ones every Linux architecture this tool meets uses; where BTF
/// declares a type this table does not have, it is added as opaque by the
/// caller rather than guessed at.
fn base_type_table() -> Map<String, Value> {
    let mut t = Map::new();
    let mut add = |name: &str, size: u64, signed: bool, kind: &str| {
        t.insert(
            name.to_string(),
            json!({ "size": size, "signed": signed, "kind": kind, "endian": "little" }),
        );
    };
    add("void", 0, false, "void");
    add("pointer", 8, false, "int");
    add("char", 1, true, "char");
    add("signed char", 1, true, "char");
    add("unsigned char", 1, false, "char");
    add("_Bool", 1, false, "bool");
    add("bool", 1, false, "bool");
    add("short", 2, true, "int");
    add("short int", 2, true, "int");
    add("unsigned short", 2, false, "int");
    add("short unsigned int", 2, false, "int");
    add("int", 4, true, "int");
    add("unsigned int", 4, false, "int");
    add("long", 8, true, "int");
    add("long int", 8, true, "int");
    add("unsigned long", 8, false, "int");
    add("long unsigned int", 8, false, "int");
    add("long long", 8, true, "int");
    add("long long int", 8, true, "int");
    add("unsigned long long", 8, false, "int");
    add("long long unsigned int", 8, false, "int");
    add("float", 4, true, "float");
    add("double", 8, true, "float");
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::Btf;

    /// The converter's output must be a document the real parser accepts.
    fn compile(json: &Value) -> Result<(), String> {
        seance_symbols::IsfDocument::parse(json.to_string().as_bytes())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// An enumeration that is not emitted keeps its member's width and sign.
    ///
    /// The named, emitted case — and the name two enumerations share — are
    /// graded against a kernel-written blob in
    /// `tests/btf_symboltable_test.rs`. These are the shapes that blob has no
    /// clean example of: an anonymous signed 1-byte enumeration, a forward
    /// declaration with no constants, and a width no C integer has (which only
    /// a damaged blob declares).
    #[test]
    fn an_enumeration_that_is_not_emitted_is_read_through_its_storage() {
        const KIND_ENUM: u32 = 6;
        const KIND_STRUCT: u32 = 4;
        let mut strings = vec![0u8];
        let mut name = |s: &str| {
            let at = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            at
        };
        let (a, fwd, odd, x, holder, ma, mb, mc) = (
            name("A"),
            name("fwd"),
            name("odd"),
            name("X"),
            name("holder"),
            name("a"),
            name("b"),
            name("c"),
        );
        let mut types = Vec::new();
        let mut word = |w: u32| types.extend_from_slice(&w.to_le_bytes());
        // 1: anonymous, signed (kind_flag), 1 byte, { A = -1 }.
        word(0);
        word(1 | (KIND_ENUM << 24) | (1 << 31));
        word(1);
        word(a);
        word(-1i32 as u32);
        // 2: `enum fwd`, declared, no constants.
        word(fwd);
        word(KIND_ENUM << 24);
        word(4);
        // 3: `enum odd`, 3 bytes wide, { X = 0 }.
        word(odd);
        word(1 | (KIND_ENUM << 24));
        word(3);
        word(x);
        word(0);
        // 4: `struct holder { a; b; c; }`, 16 bytes.
        word(holder);
        word(3 | (KIND_STRUCT << 24));
        word(16);
        for (member, ty, bits) in [(ma, 1, 0), (mb, 2, 32), (mc, 3, 64)] {
            word(member);
            word(ty);
            word(bits);
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&0xEB9Fu16.to_le_bytes());
        blob.extend_from_slice(&[1, 0]);
        for w in [
            24u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            blob.extend_from_slice(&w.to_le_bytes());
        }
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);

        let btf = Btf::parse(&blob).expect("parses");
        assert_eq!(
            btf.enum_by_id(1).map(|e| (e.signed, e.constants.clone())),
            Some((true, vec![("A".to_string(), -1)]))
        );
        let doc = to_isf_json(&btf, None).expect("converts");
        assert_eq!(doc["enums"], json!({}), "none of the three is emitted");
        let fields = &doc["user_types"]["holder"]["fields"];
        assert_eq!(
            fields["a"]["type"],
            json!({ "kind": "base", "name": "signed char" })
        );
        assert_eq!(
            fields["b"]["type"],
            json!({ "kind": "base", "name": "unsigned int" })
        );
        assert_eq!(
            fields["c"]["type"],
            json!({ "kind": "base", "name": "unsigned char" })
        );
        compile(&doc).expect("the ISF parser accepts it");
    }

    fn tiny_btf() -> Vec<u8> {
        // Reuses the blob builder in `crate::btf`'s tests via a minimal
        // hand-assembly: one struct, two byte-aligned members.
        crate::btf::test_support::blob(
            "task_struct",
            &[("pid", 1, 8 * 8), ("comm", 1, 64 * 8)],
            4096,
        )
    }

    /// The generated document must be byte-identical for the same input.
    ///
    /// This document has no file path, so the report cites its SHA-256 instead
    /// and says it "is reproducible from" the image. `serde_json` carries
    /// `preserve_order` in this workspace — `evtx` and `yara-x` both enable it
    /// and Cargo unifies features — so `Map` is an `IndexMap` and insertion
    /// order reaches the bytes. `Btf::composite_names()` iterates a `HashMap`,
    /// whose order comes from a per-instance random seed, so two parses of the
    /// same blob produced two different documents and two different hashes.
    ///
    /// Twelve structs, because with one there is only one order and the check
    /// would pass against the defect. Twelve names ordered by chance agree with
    /// sorted order about one time in 479,001,600.
    #[test]
    fn two_parses_of_one_blob_generate_byte_identical_documents() {
        let members: &[(&str, u32, u32)] = &[("pid", 1, 0), ("comm", 1, 64)];
        let structs: Vec<crate::btf::test_support::StructSpec<'_>> = vec![
            ("task_struct", members, 4096),
            ("mm_struct", members, 512),
            ("vm_area_struct", members, 256),
            ("cred", members, 128),
            ("file", members, 256),
            ("dentry", members, 192),
            ("inode", members, 640),
            ("super_block", members, 1408),
            ("net", members, 2048),
            ("sock", members, 768),
            ("module", members, 1024),
            ("nsproxy", members, 64),
        ];
        let blob = crate::btf::test_support::blob_with_structs(&structs);

        // Two INDEPENDENT parses. One `Btf` reused would iterate its single
        // HashMap the same way twice and prove nothing.
        let first = Btf::parse(&blob).expect("parses");
        let second = Btf::parse(&blob).expect("parses");

        let a = to_isf_json(&first, Some("Linux version 6.8.0")).expect("converts");
        let b = to_isf_json(&second, Some("Linux version 6.8.0")).expect("converts");

        assert_eq!(
            a.to_string(),
            b.to_string(),
            "two parses of one blob produced different documents, so the SHA-256 the report \
             cites identifies nothing a defence expert could reproduce"
        );
    }

    /// And the ordering is the one the fix chose, not merely *an* order: the
    /// user types come out sorted. Stated separately so a future change that
    /// makes the document stable by accident — memoising it, say — does not
    /// quietly satisfy the test above while leaving the underlying order at the
    /// mercy of a hash seed.
    #[test]
    fn the_generated_user_types_are_emitted_in_sorted_order() {
        let members: &[(&str, u32, u32)] = &[("pid", 1, 0)];
        let structs: Vec<crate::btf::test_support::StructSpec<'_>> = vec![
            ("zone", members, 64),
            ("mm_struct", members, 64),
            ("task_struct", members, 64),
            ("cred", members, 64),
        ];
        let btf =
            Btf::parse(&crate::btf::test_support::blob_with_structs(&structs)).expect("parses");
        let doc = to_isf_json(&btf, None).expect("converts");

        let keys: Vec<&str> = doc["user_types"]
            .as_object()
            .expect("user_types is an object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "user_types must be emitted in sorted order");
    }

    #[test]
    fn a_generated_document_parses_as_isf() {
        let btf = Btf::parse(&tiny_btf()).expect("parses");
        let doc = to_isf_json(&btf, Some("Linux version 6.8.0")).expect("converts");
        compile(&doc).expect("the ISF parser must accept what this produces");
    }

    /// A member whose type is an anonymous EMPTY struct — the shape of
    /// `local_lock_t` (`struct { }`) embedded in `struct pagesets` on a stock
    /// non-lockdep kernel — must convert to the ZERO-byte type, not a one-byte
    /// opaque placeholder. A one-byte placeholder made its size-0 wrapper look
    /// incoherent and the admission gate rejected the whole image-derived table
    /// (the entire Linux analysis of a common capture) over it.
    #[test]
    fn an_empty_anonymous_aggregate_member_converts_to_zero_bytes() {
        let btf = Btf::parse(&crate::btf::test_support::blob_with_anon_empty_member(
            "pagesets", "lock", 0,
        ))
        .expect("parses");
        let doc = to_isf_json(&btf, Some("Linux version 5.15.0")).expect("converts");

        let lock = &doc["user_types"]["pagesets"]["fields"]["lock"]["type"];
        assert_eq!(
            lock["kind"], "array",
            "an empty anonymous struct member must be a zero-length array, got {lock}"
        );
        assert_eq!(
            lock["count"],
            json!(0),
            "the array must be zero-length (0 bytes)"
        );

        // And the whole document — a size-0 struct with a size-0 member — must be
        // ADMITTED (as the char[0] caveat), not refused.
        compile(&doc).expect("the size-0 wrapper with a size-0 member must be admissible");
    }

    /// A field nested inside an ANONYMOUS aggregate — the shape of
    /// `mm_struct.mmap`, which lives in an anonymous `__randomize_layout` struct
    /// — must be recoverable through the parent. The conversion must synthesize a
    /// named type for the anonymous aggregate and keep the member's `anonymous`
    /// flag, so the symbol reader lifts the inner field into the parent. Rendering
    /// the anonymous aggregate opaque (the earlier behaviour) discarded the field
    /// and made every image-derived VMA walk, env read, etc. impossible.
    #[test]
    fn a_field_in_an_anonymous_aggregate_is_reachable_through_the_parent() {
        // `outer` embeds an anonymous struct at byte 8; that struct holds `inner`
        // at byte 4. So `outer.inner` must resolve to byte 12 once lifted.
        let btf = Btf::parse(&crate::btf::test_support::blob_with_anon_field(
            "outer", "inner", 8, 4,
        ))
        .expect("parses");
        let doc = to_isf_json(&btf, Some("Linux version 5.15.0")).expect("converts");

        // The anonymous member references a synthesized named struct, marked
        // anonymous so the reader lifts it.
        let anon = &doc["user_types"]["outer"]["fields"]["__anonymous_0"];
        assert_eq!(anon["anonymous"], json!(true));
        assert_eq!(anon["type"]["kind"], json!("struct"));
        let synth = anon["type"]["name"].as_str().expect("a synthesized name");
        assert!(
            doc["user_types"][synth]["fields"]["inner"].is_object(),
            "the synthesized type must carry the inner field, got {}",
            doc["user_types"][synth]
        );

        // And end to end: compiling the source and looking up the nested field
        // must resolve it at the lifted offset.
        let source = to_isf_source(&btf, Some("Linux version 5.15.0")).expect("builds a source");
        let table = seance_symbols::SymbolTable::compile_source(
            source,
            &seance_symbols::CompileOptions::default(),
        )
        .expect("the document compiles");
        assert_eq!(
            table
                .member_offset("outer", "inner")
                .expect("inner resolves"),
            12,
            "the field nested in the anonymous aggregate must be lifted to its true offset"
        );
    }

    #[test]
    fn member_offsets_survive_the_conversion() {
        let btf = Btf::parse(&tiny_btf()).expect("parses");
        let doc = to_isf_json(&btf, None).expect("converts");
        let fields = &doc["user_types"]["task_struct"]["fields"];
        assert_eq!(fields["pid"]["offset"], json!(8));
        assert_eq!(fields["comm"]["offset"], json!(64));
        assert_eq!(doc["user_types"]["task_struct"]["size"], json!(4096));
        assert_eq!(doc["user_types"]["task_struct"]["kind"], json!("struct"));
    }

    /// The symbols section stays empty, and that is the point.
    #[test]
    fn no_symbol_addresses_are_invented() {
        let btf = Btf::parse(&tiny_btf()).expect("parses");
        let doc = to_isf_json(&btf, None).expect("converts");
        assert_eq!(
            doc["symbols"],
            json!({}),
            "BTF carries no addresses; emitting one would resolve a symbol to \
             whatever happens to be mapped there"
        );
    }

    #[test]
    fn a_btf_with_no_named_types_is_refused() {
        // A document declaring no types compiles to a table that can answer
        // nothing, which is worse than a failure because it looks like success.
        let empty = crate::btf::test_support::blob("", &[], 0);
        let btf = Btf::parse(&empty).expect("parses");
        assert_eq!(to_isf_json(&btf, None), Err(ConvertError::NoTypes));
    }

    #[test]
    fn the_producer_is_named_so_provenance_survives() {
        let btf = Btf::parse(&tiny_btf()).expect("parses");
        let doc = to_isf_json(&btf, None).expect("converts");
        assert_eq!(doc["metadata"]["producer"]["name"], json!(PRODUCER_NAME));
        assert_eq!(
            doc["metadata"]["linux"]["types"][0]["kind"],
            json!("btf"),
            "a report must be able to say the layout came from BTF in the image \
             rather than from a symbol file matched by banner"
        );
    }
}
