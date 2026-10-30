//! The ISF document this crate emits.
//!
//! Deliberately a separate, minimal serialisation rather than a reuse of
//! [`seance_symbols`]'s reader types: that crate's job is to read whatever a
//! symbol store holds, permissively and defensively, and its structures carry
//! the shapes needed for *that*. What is written here is one narrow, known
//! shape — the subset of ISF 6.1.0 that a PDB can actually express — and
//! keeping it separate means a change to the reader cannot silently change what
//! this produces.

use std::collections::BTreeMap;

/// A whole ISF document, in the field order upstream writes.
#[derive(Debug, Default, serde::Serialize)]
pub struct IsfDoc {
    pub base_types: BTreeMap<String, BaseType>,
    pub enums: BTreeMap<String, EnumType>,
    pub metadata: Metadata,
    pub symbols: BTreeMap<String, Symbol>,
    pub user_types: BTreeMap<String, UserType>,
}

/// What produced the file, and which build it describes.
#[derive(Debug, Default, serde::Serialize)]
pub struct Metadata {
    pub format: String,
    pub producer: Producer,
    pub windows: WindowsMetadata,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct Producer {
    pub name: String,
    pub version: String,
    /// Omitted rather than guessed when the caller does not supply a clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datetime: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct WindowsMetadata {
    pub pdb: PdbMetadata,
}

/// Which PDB this came from — the field an examiner matches against the image.
#[derive(Debug, Default, serde::Serialize)]
pub struct PdbMetadata {
    #[serde(rename = "GUID")]
    pub guid: String,
    pub age: u32,
    pub database: String,
    pub machine_type: u16,
}

/// A primitive.
#[derive(Debug, serde::Serialize)]
pub struct BaseType {
    pub endian: &'static str,
    pub kind: &'static str,
    pub signed: bool,
    pub size: u32,
}

/// An enumeration.
#[derive(Debug, serde::Serialize)]
pub struct EnumType {
    pub base: String,
    pub constants: BTreeMap<String, i64>,
    pub size: u32,
}

/// A named address.
#[derive(Debug, serde::Serialize)]
pub struct Symbol {
    pub address: u64,
    /// Only present when the PDB says what the symbol's type is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_name: Option<String>,
}

/// A struct, union or class.
#[derive(Debug, serde::Serialize)]
pub struct UserType {
    pub fields: BTreeMap<String, Field>,
    pub kind: &'static str,
    pub size: u32,
}

/// One member of a user type.
#[derive(Debug, serde::Serialize)]
pub struct Field {
    pub offset: u32,
    #[serde(rename = "type")]
    pub type_descriptor: TypeDescriptor,
}

/// How ISF names a type in a field position.
///
/// A tagged union in JSON: every variant carries `kind`, and the rest of the
/// object depends on it. Written by hand rather than derived because the shapes
/// differ per variant in a way `serde`'s tagging does not express directly.
#[derive(Debug, Clone)]
pub enum TypeDescriptor {
    /// A primitive, named in `base_types`.
    Base { name: String },
    /// A struct/union/class, named in `user_types`.
    Struct { name: String },
    /// An enumeration, named in `enums`.
    Enum { name: String },
    /// A pointer to something.
    Pointer { subtype: Box<TypeDescriptor> },
    /// A fixed-length array.
    Array {
        count: u64,
        subtype: Box<TypeDescriptor>,
    },
    /// A bitfield within an integer.
    Bitfield {
        bit_position: u16,
        bit_length: u16,
        subtype: Box<TypeDescriptor>,
    },
    /// A function; ISF carries no signature detail here.
    Function,
}

impl serde::Serialize for TypeDescriptor {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(None)?;
        match self {
            TypeDescriptor::Base { name } => {
                m.serialize_entry("kind", "base")?;
                m.serialize_entry("name", name)?;
            }
            TypeDescriptor::Struct { name } => {
                m.serialize_entry("kind", "struct")?;
                m.serialize_entry("name", name)?;
            }
            TypeDescriptor::Enum { name } => {
                m.serialize_entry("kind", "enum")?;
                m.serialize_entry("name", name)?;
            }
            TypeDescriptor::Pointer { subtype } => {
                m.serialize_entry("kind", "pointer")?;
                m.serialize_entry("subtype", subtype)?;
            }
            TypeDescriptor::Array { count, subtype } => {
                m.serialize_entry("count", count)?;
                m.serialize_entry("kind", "array")?;
                m.serialize_entry("subtype", subtype)?;
            }
            TypeDescriptor::Bitfield {
                bit_position,
                bit_length,
                subtype,
            } => {
                m.serialize_entry("bit_length", bit_length)?;
                m.serialize_entry("bit_position", bit_position)?;
                m.serialize_entry("kind", "bitfield")?;
                m.serialize_entry("type", subtype)?;
            }
            TypeDescriptor::Function => {
                m.serialize_entry("kind", "function")?;
            }
        }
        m.end()
    }
}

/// The primitives upstream ISFs declare, by the names they use.
///
/// A PDB names primitives by a numeric type index rather than a string, so the
/// mapping has to be stated somewhere; stating it here keeps it next to the
/// document that uses it.
///
/// `pointer_size` comes from the image's machine type and is not assumed. A
/// hardcoded 8 emits an ISF declaring 64-bit pointers for a 32-bit kernel,
/// which either fails Séance's architecture gate — so the fetch appears to
/// succeed while the analysis still reports no usable symbols — or, where that
/// gate does not run, reads every pointer member eight bytes wide on a
/// four-byte pointer and shifts everything after it.
pub fn standard_base_types(pointer_size: u32) -> BTreeMap<String, BaseType> {
    let mut m = BTreeMap::new();
    let mut add = |name: &str, size: u32, signed: bool, kind: &'static str| {
        m.insert(
            name.to_string(),
            BaseType {
                endian: "little",
                kind,
                signed,
                size,
            },
        );
    };
    add("void", 0, false, "void");
    add("char", 1, true, "char");
    add("signed char", 1, true, "int");
    add("unsigned char", 1, false, "int");
    add("short", 2, true, "int");
    add("unsigned short", 2, false, "int");
    add("int", 4, true, "int");
    add("unsigned int", 4, false, "int");
    add("long", 4, true, "int");
    add("unsigned long", 4, false, "int");
    add("long long", 8, true, "int");
    add("unsigned long long", 8, false, "int");
    add("float", 4, true, "float");
    add("double", 8, true, "float");
    add("bool", 1, false, "bool");
    add("wchar", 2, false, "char");
    add("pointer", pointer_size, false, "pointer");
    m
}
