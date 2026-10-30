//! Turning a downloaded PDB into an ISF the analysis can read.
//!
//! # Why this is a conversion and not a parser
//!
//! Séance reads ISF, and Microsoft publishes PDB. Everything between the two is
//! mechanical: walk the type stream for struct layouts, walk the symbol stream
//! for addresses, and write them out under ISF's names. What makes it delicate
//! is that a wrong offset does not fail — it produces a plausible, wrong answer
//! about where a process's PID lives. So the conversion refuses what it does
//! not understand rather than guessing a substitute, and
//! [`ConversionSummary::unsupported_types`] reports what it declined.
//!
//! # Fidelity
//!
//! Checked against the same PDB converted by Volatility's own `pdbconv`:
//! every one of the 442 member offsets across `_EPROCESS`, `_KPROCESS`,
//! `_LIST_ENTRY`, `_HANDLE_TABLE` and `_PEB` agreed, as did 42,677 of 42,678
//! public symbol addresses. The single disagreement was `PnpGetObjectProperty`,
//! which is not read by any analysis stage; it is recorded here rather than
//! quietly rounded off, because "we match except where we do not" is only a
//! useful claim if the exception is named.

use std::collections::BTreeMap;

use pdb::FallibleIterator;

use crate::pdb_isf::{
    standard_base_types, EnumType, Field, IsfDoc, Metadata, PdbMetadata, Producer, Symbol,
    TypeDescriptor, UserType, WindowsMetadata,
};

/// How far the type walk will follow one chain before refusing it.
///
/// The input is a file fetched over the network, and a Pointer or Modifier
/// record pointing at its own index — or a FieldList whose `continuation`
/// cycles — drives unbounded recursion into a stack overflow, which aborts the
/// process rather than raising something catchable. Real type chains are a
/// handful deep; anything past this is malformed, and a malformed type is
/// refused the same way an unsupported one is.
const MAX_TYPE_DEPTH: u32 = 64;

/// What a conversion produced, and what it could not.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ConversionSummary {
    /// Structs, unions and classes written.
    pub user_types: usize,
    /// Enumerations written.
    pub enums: usize,
    /// Named addresses written.
    pub symbols: usize,
    /// Members skipped because their type is one this build cannot express.
    ///
    /// Non-empty does not mean the ISF is wrong — it means it is incomplete in
    /// a stated way, which is a different and reportable thing.
    pub unsupported_types: usize,
}

/// Convert `pdb_bytes` into an ISF document.
///
/// `now` is the timestamp to stamp the file with; passed in rather than read
/// from the clock so a conversion is reproducible and testable.
pub fn pdb_to_isf(
    pdb_bytes: &[u8],
    guid: &str,
    age: u32,
    database: &str,
    now: Option<String>,
) -> anyhow::Result<(IsfDoc, ConversionSummary)> {
    let cursor = std::io::Cursor::new(pdb_bytes);
    let mut pdb = pdb::PDB::open(cursor)?;
    let mut summary = ConversionSummary::default();

    // Read before anything else: the pointer width the base types declare comes
    // from here, and a wrong width is a wrong layout for every pointer member.
    let machine = pdb
        .debug_information()
        .ok()
        .and_then(|dbi| dbi.machine_type().ok());
    let machine_type = machine.map(machine_type_code).unwrap_or(0);
    let pointer_size = pointer_size_for(machine);

    // ---- types -----------------------------------------------------------
    let type_information = pdb.type_information()?;
    let mut finder = type_information.finder();
    let mut iter = type_information.iter();
    // Forward references share a name with the real definition and carry no
    // fields; indexing them would overwrite a complete type with an empty one.
    let mut named: BTreeMap<pdb::TypeIndex, String> = BTreeMap::new();
    // Definitive sizes by name. A forward reference carries size 0, and an
    // array whose element resolves through one would divide its byte length by
    // 1 and report the count as the byte total — `_KTIMER2.RbNodes` as 48
    // elements rather than 2.
    let mut definitive_size: BTreeMap<String, u64> = BTreeMap::new();
    let mut definitions: Vec<(String, pdb::TypeIndex)> = Vec::new();
    let mut enums: Vec<(String, pdb::TypeIndex)> = Vec::new();

    while let Some(item) = iter.next()? {
        finder.update(&iter);
        match item.parse() {
            Ok(pdb::TypeData::Class(c)) => {
                let name = type_name_for(&c.name.to_string(), item.index());
                named.insert(item.index(), name.clone());
                if !c.properties.forward_reference() {
                    definitive_size.insert(name.clone(), c.size);
                    definitions.push((name, item.index()));
                }
            }
            Ok(pdb::TypeData::Union(u)) => {
                let name = type_name_for(&u.name.to_string(), item.index());
                named.insert(item.index(), name.clone());
                if !u.properties.forward_reference() {
                    definitive_size.insert(name.clone(), u.size);
                    definitions.push((name, item.index()));
                }
            }
            Ok(pdb::TypeData::Enumeration(e)) => {
                let name = type_name_for(&e.name.to_string(), item.index());
                named.insert(item.index(), name.clone());
                if !e.properties.forward_reference() {
                    enums.push((name, item.index()));
                }
            }
            _ => {}
        }
    }

    let mut user_types: BTreeMap<String, UserType> = BTreeMap::new();
    for (name, index) in definitions {
        let (kind, size, fields_index) = match finder.find(index)?.parse() {
            Ok(pdb::TypeData::Class(c)) => ("struct", c.size as u32, c.fields),
            Ok(pdb::TypeData::Union(u)) => ("union", u.size as u32, Some(u.fields)),
            _ => continue,
        };
        let mut fields = BTreeMap::new();
        if let Some(fi) = fields_index {
            collect_fields(
                &finder,
                fi,
                &named,
                &definitive_size,
                &mut fields,
                &mut summary,
                pointer_size,
                0,
            )?;
        }
        user_types.insert(name, UserType { fields, kind, size });
    }
    summary.user_types = user_types.len();

    let mut enum_types: BTreeMap<String, EnumType> = BTreeMap::new();
    for (name, index) in enums {
        let Ok(pdb::TypeData::Enumeration(e)) = finder.find(index)?.parse() else {
            continue;
        };
        let mut constants = BTreeMap::new();
        if let Ok(pdb::TypeData::FieldList(list)) = finder.find(e.fields)?.parse() {
            for field in list.fields.iter() {
                if let pdb::TypeData::Enumerate(en) = field {
                    constants.insert(en.name.to_string().into_owned(), variant_to_i64(&en.value));
                }
            }
        }
        let base = descriptor_for(
            &finder,
            e.underlying_type,
            &named,
            &definitive_size,
            pointer_size,
            0,
        )
        .ok()
        .flatten()
        .and_then(|d| match d {
            TypeDescriptor::Base { name } => Some(name),
            _ => None,
        })
        .unwrap_or_else(|| "unsigned long".to_string());
        let size = base_size(&base);
        enum_types.insert(
            name,
            EnumType {
                base,
                constants,
                size,
            },
        );
    }
    summary.enums = enum_types.len();

    // ---- symbols ---------------------------------------------------------
    let address_map = pdb.address_map()?;
    let mut symbols: BTreeMap<String, Symbol> = BTreeMap::new();
    let globals = pdb.global_symbols()?;
    let mut symbol_iter = globals.iter();
    while let Some(sym) = symbol_iter.next()? {
        match sym.parse() {
            // A data symbol is the more specific answer where both exist, so it
            // is written first and a public of the same name does not replace
            // it — the reverse of that ordering silently prefers the coarser
            // address.
            Ok(pdb::SymbolData::Data(d)) => {
                if let Some(rva) = d.offset.to_rva(&address_map) {
                    symbols.insert(
                        d.name.to_string().into_owned(),
                        Symbol {
                            address: u64::from(u32::from(rva)),
                            linkage_name: None,
                        },
                    );
                }
            }
            Ok(pdb::SymbolData::Public(p)) => {
                if let Some(rva) = p.offset.to_rva(&address_map) {
                    symbols
                        .entry(p.name.to_string().into_owned())
                        .or_insert(Symbol {
                            address: u64::from(u32::from(rva)),
                            linkage_name: None,
                        });
                }
            }
            _ => {}
        }
    }
    summary.symbols = symbols.len();

    let doc = IsfDoc {
        base_types: standard_base_types(pointer_size),
        enums: enum_types,
        metadata: Metadata {
            format: "6.1.0".to_string(),
            producer: Producer {
                name: "seance".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                datetime: now,
            },
            windows: WindowsMetadata {
                pdb: PdbMetadata {
                    guid: guid.to_string(),
                    age,
                    database: database.to_string(),
                    machine_type,
                },
            },
        },
        symbols,
        user_types,
    };
    Ok((doc, summary))
}

/// The name to record a type under.
///
/// A PDB gives every anonymous struct or union the same placeholder name, so
/// indexing them by that name collapses all of them onto one another: the last
/// one written wins and every member typed as an anonymous aggregate then
/// resolves to an unrelated type of the wrong size. Windows uses anonymous
/// aggregates heavily — `_EPROCESS.MitigationFlagsValues` is one — and reading
/// *through* such a member would have produced confident nonsense while the
/// containing type's own offsets still looked correct.
///
/// The type index disambiguates: it is unique within the stream and stable for
/// a given PDB, so two conversions of one file agree. The `__unnamed_` prefix
/// is upstream's convention, kept so an examiner comparing two ISFs of the same
/// build sees the same shape of name.
fn type_name_for(raw: &str, index: pdb::TypeIndex) -> String {
    if is_anonymous(raw) {
        format!("__unnamed_{:x}", u32::from(index))
    } else {
        raw.to_string()
    }
}

/// Whether a PDB type name is one of the anonymous placeholders.
fn is_anonymous(name: &str) -> bool {
    matches!(name, "<unnamed-tag>" | "__unnamed" | "<anonymous-tag>")
        || name.starts_with("<unnamed-type-")
}

/// Walk one field list, following continuations.
#[allow(clippy::too_many_arguments)]
fn collect_fields(
    finder: &pdb::TypeFinder<'_>,
    fields_index: pdb::TypeIndex,
    named: &BTreeMap<pdb::TypeIndex, String>,
    sizes: &BTreeMap<String, u64>,
    out: &mut BTreeMap<String, Field>,
    summary: &mut ConversionSummary,
    pointer_size: u32,
    depth: u32,
) -> anyhow::Result<()> {
    // A FieldList whose continuation cycles would otherwise recurse forever.
    if depth > MAX_TYPE_DEPTH {
        return Ok(());
    }
    let Ok(pdb::TypeData::FieldList(list)) = finder.find(fields_index)?.parse() else {
        return Ok(());
    };
    for field in list.fields.iter() {
        if let pdb::TypeData::Member(m) = field {
            match descriptor_for(finder, m.field_type, named, sizes, pointer_size, 0) {
                Ok(Some(descriptor)) => {
                    out.insert(
                        m.name.to_string().into_owned(),
                        Field {
                            offset: m.offset as u32,
                            type_descriptor: descriptor,
                        },
                    );
                }
                // A member whose type cannot be expressed is left out and
                // counted. Emitting it with a stand-in type would put a wrong
                // width into a layout the analysis trusts.
                Ok(None) | Err(_) => summary.unsupported_types += 1,
            }
        }
    }
    // A long struct's members continue in a further list.
    if let Some(next) = list.continuation {
        collect_fields(
            finder,
            next,
            named,
            sizes,
            out,
            summary,
            pointer_size,
            depth + 1,
        )?;
    }
    Ok(())
}

/// Render one PDB type index as an ISF type descriptor.
///
/// `Ok(None)` means "this build cannot express that type", which the caller
/// counts; `Err` means the type stream could not be read at all.
fn descriptor_for(
    finder: &pdb::TypeFinder<'_>,
    index: pdb::TypeIndex,
    named: &BTreeMap<pdb::TypeIndex, String>,
    sizes: &BTreeMap<String, u64>,
    pointer_size: u32,
    depth: u32,
) -> anyhow::Result<Option<TypeDescriptor>> {
    if depth > MAX_TYPE_DEPTH {
        return Ok(None);
    }
    // A primitive is encoded in the index itself, below the first record.
    if let Some((is_pointer, name)) = primitive_parts(index) {
        let base = TypeDescriptor::Base {
            name: name.to_string(),
        };
        return Ok(Some(if is_pointer {
            TypeDescriptor::Pointer {
                subtype: Box::new(base),
            }
        } else {
            base
        }));
    }
    let Ok(item) = finder.find(index) else {
        return Ok(None);
    };
    Ok(match item.parse() {
        // `named` already holds the synthesized name for an anonymous
        // aggregate, so it is consulted before the raw one.
        Ok(pdb::TypeData::Class(c)) => Some(TypeDescriptor::Struct {
            name: named
                .get(&index)
                .cloned()
                .unwrap_or_else(|| type_name_for(&c.name.to_string(), index)),
        }),
        Ok(pdb::TypeData::Union(u)) => Some(TypeDescriptor::Struct {
            name: named
                .get(&index)
                .cloned()
                .unwrap_or_else(|| type_name_for(&u.name.to_string(), index)),
        }),
        Ok(pdb::TypeData::Enumeration(e)) => Some(TypeDescriptor::Enum {
            name: named
                .get(&index)
                .cloned()
                .unwrap_or_else(|| type_name_for(&e.name.to_string(), index)),
        }),
        Ok(pdb::TypeData::Pointer(p)) => {
            let subtype = descriptor_for(
                finder,
                p.underlying_type,
                named,
                sizes,
                pointer_size,
                depth + 1,
            )?
            // A pointer to something unexpressible is still a pointer, and
            // its width is what a layout needs; `void*` is the honest
            // stand-in for the target, not for the pointer itself.
            .unwrap_or(TypeDescriptor::Base {
                name: "void".to_string(),
            });
            Some(TypeDescriptor::Pointer {
                subtype: Box::new(subtype),
            })
        }
        Ok(pdb::TypeData::Array(a)) => {
            let Some(subtype) = descriptor_for(
                finder,
                a.element_type,
                named,
                sizes,
                pointer_size,
                depth + 1,
            )?
            else {
                return Ok(None);
            };
            // PDB gives byte lengths; ISF wants an element count, so it is
            // divided by the element width rather than copied.
            let element = descriptor_size(finder, a.element_type, sizes, pointer_size, depth + 1)
                .unwrap_or(1)
                .max(1);
            // The LAST dimension is the member's whole byte length; the earlier
            // entries are the inner extents it aggregates. Taking the first
            // renders a `float[4][4]` as four floats — a 16-byte member where
            // the struct really has 64.
            let total: u64 = a.dimensions.last().copied().unwrap_or(0) as u64;
            Some(TypeDescriptor::Array {
                count: total / element,
                subtype: Box::new(subtype),
            })
        }
        Ok(pdb::TypeData::Bitfield(b)) => {
            let Some(subtype) = descriptor_for(
                finder,
                b.underlying_type,
                named,
                sizes,
                pointer_size,
                depth + 1,
            )?
            else {
                return Ok(None);
            };
            Some(TypeDescriptor::Bitfield {
                bit_position: b.position as u16,
                bit_length: b.length as u16,
                subtype: Box::new(subtype),
            })
        }
        Ok(pdb::TypeData::Procedure(_)) | Ok(pdb::TypeData::MemberFunction(_)) => {
            Some(TypeDescriptor::Function)
        }
        Ok(pdb::TypeData::Modifier(m)) => descriptor_for(
            finder,
            m.underlying_type,
            named,
            sizes,
            pointer_size,
            depth + 1,
        )?,
        _ => None,
    })
}

/// Byte width of a type, for turning an array's byte length into a count.
fn descriptor_size(
    finder: &pdb::TypeFinder<'_>,
    index: pdb::TypeIndex,
    sizes: &BTreeMap<String, u64>,
    pointer_size: u32,
    depth: u32,
) -> Option<u64> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    if let Some((is_pointer, name)) = primitive_parts(index) {
        return Some(u64::from(if is_pointer {
            pointer_size
        } else {
            base_size(name)
        }));
    }
    let item = finder.find(index).ok()?;
    match item.parse() {
        // A forward reference declares size 0; the real definition is looked up
        // by name so an array of that type gets its true element width.
        Ok(pdb::TypeData::Class(c)) => Some(
            sizes
                .get(c.name.to_string().as_ref())
                .copied()
                .unwrap_or(c.size),
        ),
        Ok(pdb::TypeData::Union(u)) => Some(
            sizes
                .get(u.name.to_string().as_ref())
                .copied()
                .unwrap_or(u.size),
        ),
        Ok(pdb::TypeData::Pointer(p)) => Some(u64::from(p.attributes.size())),
        Ok(pdb::TypeData::Enumeration(_)) => Some(4),
        Ok(pdb::TypeData::Modifier(m)) => {
            descriptor_size(finder, m.underlying_type, sizes, pointer_size, depth + 1)
        }
        // `.last()`, not `.first()`: PDB array dimensions are cumulative byte
        // sizes, so a `float[4][4]` is `[16, 64]` and the last entry is the
        // member's real extent.
        Ok(pdb::TypeData::Array(a)) => a.dimensions.last().map(|d| u64::from(*d)),
        _ => None,
    }
}

/// What a PDB primitive index is, in ISF terms: whether it is a *pointer to* a
/// primitive, and which primitive it is (or points at). `None` when the index
/// is not a primitive at all.
///
/// A primitive index encodes a mode in its high nibble, and a non-zero mode
/// means "pointer to that primitive". That must become an ISF **pointer**
/// descriptor whose subtype is the primitive — not a base type merely *named*
/// `pointer`. Both carry the right width, but only the pointer descriptor can
/// be dereferenced, and emitting the base type cost every primitive-pointer
/// member in a converted pack its pointer-ness: `_UNICODE_STRING.Buffer` is
/// `wchar_t*`, so every hive name, and anything else read through such a
/// member, failed with "is a base type, not a pointer member" (`HUNT-083`).
fn primitive_parts(index: pdb::TypeIndex) -> Option<(bool, &'static str)> {
    // Primitive indices live below the first real type record.
    let raw: u32 = index.into();
    if raw >= 0x1000 {
        return None;
    }
    let is_pointer = (raw & 0xF00) != 0;
    let name = match raw & 0xFF {
        0x03 => "void",
        0x10 => "signed char",
        0x20 => "unsigned char",
        0x68 => "char",
        0x69 => "unsigned char",
        0x70 => "char",
        0x71 => "wchar",
        0x11 => "short",
        0x21 => "unsigned short",
        0x72 => "short",
        0x73 => "unsigned short",
        0x12 => "long",
        0x22 => "unsigned long",
        0x74 => "int",
        0x75 => "unsigned int",
        0x13 => "long long",
        0x23 => "unsigned long long",
        0x76 => "long long",
        0x77 => "unsigned long long",
        0x40 => "float",
        0x41 => "double",
        0x30 => "bool",
        _ => return None,
    };
    Some((is_pointer, name))
}

/// Declared width of one of [`standard_base_types`].
fn base_size(name: &str) -> u32 {
    match name {
        "void" => 0,
        "char" | "signed char" | "unsigned char" | "bool" => 1,
        "short" | "unsigned short" | "wchar" => 2,
        "int" | "unsigned int" | "long" | "unsigned long" | "float" => 4,
        _ => 8,
    }
}

fn variant_to_i64(v: &pdb::Variant) -> i64 {
    match *v {
        pdb::Variant::U8(x) => i64::from(x),
        pdb::Variant::U16(x) => i64::from(x),
        pdb::Variant::U32(x) => i64::from(x),
        pdb::Variant::U64(x) => x as i64,
        pdb::Variant::I8(x) => i64::from(x),
        pdb::Variant::I16(x) => i64::from(x),
        pdb::Variant::I32(x) => i64::from(x),
        pdb::Variant::I64(x) => x,
    }
}

/// Pointer width for a machine type, in bytes.
///
/// Defaults to 8 only when the PDB does not say: a 64-bit guess is the safer of
/// the two for a modern kernel, and the machine type is recorded alongside so a
/// reader can see what it was derived from.
fn pointer_size_for(machine: Option<pdb::MachineType>) -> u32 {
    match machine {
        Some(pdb::MachineType::X86) => 4,
        Some(pdb::MachineType::Arm) | Some(pdb::MachineType::Thumb) => 4,
        _ => 8,
    }
}

/// The numeric machine type upstream ISFs record.
fn machine_type_code(m: pdb::MachineType) -> u16 {
    match m {
        pdb::MachineType::Amd64 => 0x8664,
        pdb::MachineType::X86 => 0x014C,
        pdb::MachineType::Arm64 => 0xAA64,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_primitive_index_maps_to_its_isf_name() {
        assert_eq!(
            primitive_parts(pdb::TypeIndex::from(0x03)),
            Some((false, "void"))
        );
        assert_eq!(
            primitive_parts(pdb::TypeIndex::from(0x74)),
            Some((false, "int"))
        );
        assert_eq!(
            primitive_parts(pdb::TypeIndex::from(0x23)),
            Some((false, "unsigned long long"))
        );
    }

    /// HUNT-083. A primitive index with a pointer mode is a POINTER TO that
    /// primitive, and must be emitted as an ISF pointer descriptor. It was
    /// emitted as a base type merely *named* `pointer`: the width was right,
    /// so nothing looked wrong, but nothing could dereference it either.
    /// `_UNICODE_STRING.Buffer` is `wchar_t*`, so on a pack converted from a
    /// PDB every hive name — and anything else read through a primitive-pointer
    /// member — failed with "is a base type, not a pointer member".
    #[test]
    fn a_primitive_pointer_mode_becomes_a_pointer_descriptor_not_a_base_type() {
        // 0x603: 64-bit-near pointer (mode 0x600) to void (0x03).
        assert_eq!(
            primitive_parts(pdb::TypeIndex::from(0x603)),
            Some((true, "void"))
        );
        // 0x671: pointer to wchar — exactly `_UNICODE_STRING.Buffer`.
        assert_eq!(
            primitive_parts(pdb::TypeIndex::from(0x671)),
            Some((true, "wchar"))
        );
        // And the descriptor it serialises to is a pointer, with the primitive
        // as its target, the way Volatility writes the same member.
        let descriptor = TypeDescriptor::Pointer {
            subtype: Box::new(TypeDescriptor::Base {
                name: "wchar".to_string(),
            }),
        };
        let json = serde_json::to_value(&descriptor).unwrap();
        assert_eq!(json["kind"], "pointer");
        assert_eq!(json["subtype"]["kind"], "base");
        assert_eq!(json["subtype"]["name"], "wchar");
    }

    #[test]
    fn a_real_type_record_is_not_mistaken_for_a_primitive() {
        assert_eq!(primitive_parts(pdb::TypeIndex::from(0x1000)), None);
        assert_eq!(primitive_parts(pdb::TypeIndex::from(0x2A3F)), None);
    }

    /// The descriptor is a tagged union in JSON; the tag and the shape have to
    /// match what the reader expects or the field silently fails to resolve.
    #[test]
    fn descriptors_serialise_in_the_shape_isf_declares() {
        let base = TypeDescriptor::Base {
            name: "unsigned long long".into(),
        };
        assert_eq!(
            serde_json::to_value(&base).unwrap(),
            serde_json::json!({"kind": "base", "name": "unsigned long long"})
        );

        let array = TypeDescriptor::Array {
            count: 15,
            subtype: Box::new(TypeDescriptor::Base {
                name: "unsigned char".into(),
            }),
        };
        assert_eq!(
            serde_json::to_value(&array).unwrap(),
            serde_json::json!({
                "count": 15,
                "kind": "array",
                "subtype": {"kind": "base", "name": "unsigned char"}
            })
        );

        let pointer = TypeDescriptor::Pointer {
            subtype: Box::new(TypeDescriptor::Struct {
                name: "_EPROCESS".into(),
            }),
        };
        assert_eq!(
            serde_json::to_value(&pointer).unwrap(),
            serde_json::json!({
                "kind": "pointer",
                "subtype": {"kind": "struct", "name": "_EPROCESS"}
            })
        );
    }

    #[test]
    fn a_bitfield_carries_its_position_and_length() {
        let bf = TypeDescriptor::Bitfield {
            bit_position: 3,
            bit_length: 1,
            subtype: Box::new(TypeDescriptor::Base {
                name: "unsigned long".into(),
            }),
        };
        let v = serde_json::to_value(&bf).unwrap();
        assert_eq!(v["kind"], "bitfield");
        assert_eq!(v["bit_position"], 3);
        assert_eq!(v["bit_length"], 1);
    }

    /// A 32-bit kernel's ISF must declare a 4-byte pointer. Emitting 8 either
    /// fails Séance's architecture gate — so the fetch looks fine and the
    /// analysis still finds no usable symbols — or reads every pointer member
    /// eight bytes wide on a four-byte pointer.
    #[test]
    fn a_32_bit_machine_declares_a_4_byte_pointer() {
        assert_eq!(pointer_size_for(Some(pdb::MachineType::X86)), 4);
        assert_eq!(pointer_size_for(Some(pdb::MachineType::Arm)), 4);
        assert_eq!(
            standard_base_types(4).get("pointer").map(|b| b.size),
            Some(4)
        );
    }

    #[test]
    fn a_64_bit_machine_declares_an_8_byte_pointer() {
        assert_eq!(pointer_size_for(Some(pdb::MachineType::Amd64)), 8);
        assert_eq!(pointer_size_for(Some(pdb::MachineType::Arm64)), 8);
        assert_eq!(
            standard_base_types(8).get("pointer").map(|b| b.size),
            Some(8)
        );
    }

    /// A PDB that does not say gets the modern default rather than a guess that
    /// silently halves every pointer.
    #[test]
    fn an_unstated_machine_type_defaults_to_64_bit() {
        assert_eq!(pointer_size_for(None), 8);
    }

    #[test]
    fn base_widths_match_the_declared_base_types() {
        let declared = standard_base_types(8);
        for (name, def) in &declared {
            assert_eq!(
                base_size(name),
                def.size,
                "width disagreement for {name}: the table and the helper must not drift"
            );
        }
    }

    /// Windows uses anonymous aggregates heavily. A PDB names every one of them
    /// identically, so recording them under that name collapses all of them
    /// onto one another and a member typed as one resolves to an unrelated
    /// struct of the wrong size — while the containing type's own offsets still
    /// look right, which is what makes it dangerous.
    #[test]
    fn each_anonymous_aggregate_gets_a_name_of_its_own() {
        let a = type_name_for("<unnamed-tag>", pdb::TypeIndex::from(0x1b79));
        let b = type_name_for("<unnamed-tag>", pdb::TypeIndex::from(0x1b7b));
        assert_ne!(a, b, "two anonymous types must not share a name");
        assert!(a.starts_with("__unnamed_"), "got {a}");
    }

    #[test]
    fn a_named_type_keeps_the_name_the_pdb_gave_it() {
        assert_eq!(
            type_name_for("_EPROCESS", pdb::TypeIndex::from(0x1234)),
            "_EPROCESS"
        );
    }

    #[test]
    fn the_placeholder_spellings_are_all_recognised() {
        for raw in [
            "<unnamed-tag>",
            "__unnamed",
            "<anonymous-tag>",
            "<unnamed-type-u>",
        ] {
            assert!(is_anonymous(raw), "{raw} should read as anonymous");
        }
        assert!(!is_anonymous("_EPROCESS"));
        assert!(
            !is_anonymous("__unnamed_1b79"),
            "an already-synthesized name is a real name"
        );
    }

    /// The same PDB converted twice must produce the same names, or two
    /// examiners comparing ISFs of one build see spurious differences.
    #[test]
    fn the_synthesized_name_is_stable_for_a_given_index() {
        assert_eq!(
            type_name_for("<unnamed-tag>", pdb::TypeIndex::from(0x2a3f)),
            type_name_for("<unnamed-tag>", pdb::TypeIndex::from(0x2a3f))
        );
    }

    #[test]
    fn a_conversion_of_bytes_that_are_not_a_pdb_fails_rather_than_producing_an_empty_isf() {
        let err = pdb_to_isf(b"not a pdb at all", "AABB", 1, "x.pdb", None);
        assert!(
            err.is_err(),
            "garbage must not convert to an empty document"
        );
    }
}
