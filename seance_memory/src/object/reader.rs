//! [`StructReader`] and [`Obj`]: the bridge from "a struct name plus an
//! address" to typed field reads.
//!
//! A [`StructReader`] is the pairing of an address space with the type database
//! that describes what lives in it. An [`Obj`] is one structure at one address,
//! and every member read off it resolves its offset, width, byte order and
//! signedness through the symbol table — never through a constant, and never
//! through an assumption about the machine Séance happens to be running on.

use std::sync::Arc;

use seance_core::io::read_exact_or_fail;
use seance_symbols::isf::POINTER_BASE_TYPE;
use seance_symbols::{AggInfo, Endian, SymbolError, SymbolTable, TypeId, TypeKind};

use super::error::ObjError;
use crate::layer::MemoryLayer;

/// A member's byte offset within its structure.
///
/// A newtype over `u64` for one reason, and it is not type safety in general:
/// `#[must_use]` does not fire on `reader.member_offset(t, m)?;`, because the
/// value of that statement is the integer the `?` unwrapped and an integer is
/// not `must_use`. Wrapping it moves the attribute onto a type the `?` yields,
/// so the discard is a compile error.
///
/// That discard is the shape of a real defect, not a hypothetical one. A member
/// resolved and thrown away is a pure existence proof, and proving a
/// build-variant member in a pre-flight that the reading branch never reaches
/// fails a stage on every kernel that lacks it — which is how one line failed
/// eight of nine analysis stages on a Windows XP capture, for a member only
/// Windows 8 and later ever reads.
///
/// `bytes()` is deliberately explicit rather than a `Deref` to `u64`: a silent
/// coercion would let the value slip back into arithmetic without anyone
/// deciding it should, which is most of what the newtype exists to prevent.
#[must_use = "an offset that is resolved and discarded is an existence proof; \
              declare the member in a seance_memory::binding::MemberSet instead, \
              so a build that does not have it is answered rather than failed"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberOffset(u64);

impl MemberOffset {
    /// The offset in bytes.
    #[must_use]
    pub fn bytes(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for MemberOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// The declared size of a named type, in bytes.
///
/// Exists for the same reason as [`MemberOffset`], and kept distinct from it so
/// an offset and a size cannot be added together without saying so.
#[must_use = "a size that is computed and discarded is an existence proof; \
              declare the type in a seance_memory::binding::MemberSet instead, \
              so a build that does not have it is answered rather than failed"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeSize(u64);

impl TypeSize {
    /// The size in bytes.
    #[must_use]
    pub fn bytes(self) -> u64 {
        self.0
    }
}

/// The declared shape of an array member.
///
/// Exists because a multi-dimensional array declares its dimensions **nested**,
/// and the outer count alone is not the element count. The member this was
/// written for is `_KTIMER_TABLE.TimerEntries`: `[2][256]` on Windows 11 build
/// 26200 and `[256]` on every older build in the symbol pack on the machine
/// this was measured on. A caller that read the outer dimension would walk 2 of
/// 512 timer buckets on the newer build, find real timers in both, and have
/// nothing in the result look wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayShape {
    /// Every declared dimension, outermost first.
    pub dims: Vec<u64>,
    /// Their product: the number of innermost elements.
    pub total: u64,
    /// Size of one innermost element.
    pub element_size: u64,
    /// Name of the innermost element type, for a record that says what it
    /// walked.
    pub element_type: String,
    /// Bytes the whole array occupies.
    pub bytes: u64,
    /// Byte offset of the array within the enclosing type.
    pub offset: u64,
}

impl std::fmt::Display for TypeSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How many levels of enum/bitfield indirection a member type may resolve
/// through before the table is considered self-referential.
///
/// An ISF is attacker-controlled input the moment it comes from an untrusted
/// symbol pack, and a type that resolves through itself would otherwise spin
/// forever.
pub const MAX_TYPE_DEPTH: u32 = 32;

/// Ceiling on a single buffered read, in bytes.
///
/// A corrupt or hostile ISF can declare a 2 GiB array member; allocating for it
/// is not something the examiner asked for. Refusing is honest, and the refusal
/// is a [`ObjError::Cap`] carrying [`seance_core::io::IncompleteReason::CapReached`]
/// rather than a truncated buffer.
pub const MAX_MEMBER_BYTES: u64 = 1 << 20;

/// Ceiling on the number of `.`-separated segments in a member path.
pub const MAX_PATH_SEGMENTS: usize = 16;

/// The layout of one scalar member, as the symbol table declares it.
///
/// Every field here is a fact from the ISF. None of them has a default: a
/// member whose width, byte order or signedness could not be determined is an
/// error, because guessing any of the three produces a plausible wrong value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Scalar {
    /// Storage width in bytes.
    pub(super) size: u64,
    /// Byte order.
    pub(super) endian: Endian,
    /// Whether the value is two's-complement signed.
    pub(super) signed: bool,
    /// Bit position and bit length, when the member is a bitfield.
    pub(super) bitfield: Option<(u64, u64)>,
}

/// An integer read out of memory, carrying the signedness the symbol table
/// declared for it.
///
/// Kept as a sum type rather than collapsed to `u64` because the collapse is a
/// silent lie: a four-byte signed `pid` holding `0xFFFFFFFF` is `-1`, and
/// reporting `4294967295` puts a number in the case record that the suspect's
/// machine never held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntValue {
    /// The member is declared unsigned.
    Unsigned(u64),
    /// The member is declared signed, sign-extended from its declared width.
    Signed(i64),
}

impl IntValue {
    /// Whether the symbol table declared this member signed.
    pub fn is_signed(self) -> bool {
        matches!(self, IntValue::Signed(_))
    }

    /// The value widened losslessly, for comparison and for JSON.
    pub fn as_i128(self) -> i128 {
        match self {
            IntValue::Unsigned(value) => i128::from(value),
            IntValue::Signed(value) => i128::from(value),
        }
    }

    /// The value as `u64`, or `None` if it is negative.
    ///
    /// `None` rather than a cast: a negative PID reinterpreted as a huge
    /// positive one is exactly the kind of plausible nonsense this module
    /// exists to prevent.
    pub fn as_u64(self) -> Option<u64> {
        match self {
            IntValue::Unsigned(value) => Some(value),
            IntValue::Signed(value) => u64::try_from(value).ok(),
        }
    }

    /// The value as `i64`, or `None` if it does not fit.
    pub fn as_i64(self) -> Option<i64> {
        match self {
            IntValue::Unsigned(value) => i64::try_from(value).ok(),
            IntValue::Signed(value) => Some(value),
        }
    }
}

impl std::fmt::Display for IntValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntValue::Unsigned(value) => write!(f, "{value}"),
            IntValue::Signed(value) => write!(f, "{value}"),
        }
    }
}

/// An address space paired with the type database that describes it.
///
/// # The two layers
///
/// `bytes` is where the structures live; `native` is where the pointers inside
/// those structures resolve. They are the same for ordinary work in a virtual
/// address space, and they differ for pool scanning, which reads a kernel
/// structure out of the **physical** layer while every pointer inside it is a
/// kernel **virtual** address. Both are required at construction because
/// getting them backwards does not fail loudly: each dereference simply returns
/// bytes from an unrelated address, and those bytes parse.
///
/// Cloning is three `Arc` bumps, so a reader is cheap to hand to a worker.
#[derive(Debug, Clone)]
pub struct StructReader {
    bytes: Arc<dyn MemoryLayer>,
    native: Arc<dyn MemoryLayer>,
    symbols: Arc<SymbolTable>,
}

impl StructReader {
    /// A reader whose structures and whose pointers live in the same space.
    ///
    /// The ordinary case: a kernel virtual address space, where an `_EPROCESS`
    /// and everything it points at are addressed the same way.
    pub fn new(bytes: Arc<dyn MemoryLayer>, symbols: Arc<SymbolTable>) -> Self {
        Self {
            native: Arc::clone(&bytes),
            bytes,
            symbols,
        }
    }

    /// A reader whose structures live in one space and whose pointers resolve
    /// in another.
    ///
    /// This is the pool-scanning shape: `bytes` is the physical layer the
    /// candidate was found in, `native` is the kernel virtual space its
    /// pointers belong to. [`Obj::follow`] and [`StructReader::walk_list`] both
    /// land in `native`, which is what makes the distinction survive past the
    /// first dereference.
    pub fn with_native(
        bytes: Arc<dyn MemoryLayer>,
        native: Arc<dyn MemoryLayer>,
        symbols: Arc<SymbolTable>,
    ) -> Self {
        Self {
            bytes,
            native,
            symbols,
        }
    }

    /// The same reader with the native space on both sides, for following a
    /// pointer out of a structure that was read somewhere else.
    pub fn in_native_space(&self) -> StructReader {
        StructReader {
            bytes: Arc::clone(&self.native),
            native: Arc::clone(&self.native),
            symbols: Arc::clone(&self.symbols),
        }
    }

    /// The layer these structures' bytes are read from.
    pub fn layer(&self) -> &Arc<dyn MemoryLayer> {
        &self.bytes
    }

    /// The layer the pointers inside these structures address.
    pub fn native_layer(&self) -> &Arc<dyn MemoryLayer> {
        &self.native
    }

    /// The type database.
    pub fn symbols(&self) -> &Arc<SymbolTable> {
        &self.symbols
    }

    /// Whether the structures and their pointers live in different spaces.
    pub fn spaces_differ(&self) -> bool {
        !Arc::ptr_eq(&self.bytes, &self.native)
    }

    /// Guest pointer width in bytes, from the ISF's `pointer` base type.
    ///
    /// Never the host's width, and never inferred from what the values look
    /// like. A document that declares no `pointer` base type, or one that is
    /// neither 4 nor 8 bytes, is an error rather than an assumption.
    pub fn pointer_size(&self) -> Result<u8, ObjError> {
        let scalar = self.pointer_scalar()?;
        Ok(scalar.size as u8)
    }

    /// Size of a named type in bytes, as the symbol table declares it.
    ///
    /// Returns [`TypeSize`] rather than `u64` so that discarding it is a
    /// compile error; see [`MemberOffset`] for why a bare integer could not be
    /// made to fire.
    pub fn size_of(&self, type_name: &str) -> Result<TypeSize, ObjError> {
        Ok(TypeSize(self.symbols.size_of(type_name)?))
    }

    /// Byte offset of a member, resolved through the symbol table.
    ///
    /// `path` may reach through embedded aggregates with `.`, e.g.
    /// `"Pcb.Header.Type"`. It never dereferences a pointer: a hidden read is
    /// a read an examiner cannot account for.
    ///
    /// # Prefer a declaration
    ///
    /// This is the raw form. A stage that needs a member which some kernel
    /// builds do not have must declare it in a
    /// [`crate::binding::MemberSet`], which resolves the first name this build
    /// declares and yields [`crate::binding::Field::NotDeclared`] — an answer —
    /// rather than an error, for a build that has none of them.
    ///
    /// The form to never write is the statement-position existence proof:
    ///
    /// ```text
    /// reader.member_offset(TYPE_OBJECT_HEADER, "InfoMask")?;   // the defect
    /// ```
    ///
    /// The offset is discarded, so the call's only effect is to make a member
    /// that arrived in Windows Vista fatal on Windows XP — in stages that never
    /// read it. That one line failed eight of nine analysis stages on a real XP
    /// capture.
    ///
    /// **That line is now a compile error, and it is worth recording why it
    /// took a newtype.** `#[must_use]` on this function fires on
    /// `reader.member_offset(t, m);` — the form with no `?`. It did *not* fire
    /// on `reader.member_offset(t, m)?;`, because the value of that statement
    /// is whatever the `?` unwrapped, and a `u64` is not `must_use`. So the
    /// attribute guarded the form nobody writes and missed the one that cost
    /// eight stages.
    ///
    /// Returning [`MemberOffset`] closes it: the `?` now yields a `must_use`
    /// type, so the discard is caught where it is written rather than by a
    /// grep run at review time. The two greps this used to rely on —
    /// `rg -n 'member_offset\([^)]*\)\?;'` and the same for `size_of` — are no
    /// longer the check, which matters because a grep is only run by someone
    /// who remembers to run it.
    pub fn member_offset(&self, type_name: &str, path: &str) -> Result<MemberOffset, ObjError> {
        let root = self.symbols.type_id(type_name)?;
        Ok(MemberOffset(self.resolve_path(root, type_name, path)?.0))
    }

    /// The declared shape of an array member — every dimension, and their
    /// product.
    ///
    /// See [`ArrayShape`] for why the product and not the outer count. A member
    /// that is not an array is an error rather than a shape of one element: a
    /// caller asking for a shape is about to iterate, and iterating a scalar
    /// as if it were an array of one is a wrong answer that reads correctly.
    pub fn array_shape(&self, type_name: &str, path: &str) -> Result<ArrayShape, ObjError> {
        let root = self.symbols.type_id(type_name)?;
        let (offset, mut ty) = self.resolve_path(root, type_name, path)?;
        let described = format!("{type_name}.{path}");
        let mut dims: Vec<u64> = Vec::new();
        loop {
            match &self.symbols.entry(ty)?.kind {
                TypeKind::Array { subtype, count } => {
                    dims.push(*count);
                    ty = *subtype;
                }
                other => {
                    if dims.is_empty() {
                        return Err(SymbolError::WrongTypeKind {
                            name: described,
                            actual: other.as_str(),
                            expected: "an array member",
                        }
                        .into());
                    }
                    break;
                }
            }
        }
        let element_size = self.symbols.size_of_id(ty)?;
        // A dimension of zero makes the product zero, which is an answer; an
        // overflow is not, and must not become a small number.
        let mut total: u64 = 1;
        for d in &dims {
            total = total.checked_mul(*d).ok_or_else(|| {
                ObjError::Overflow(format!(
                    "the declared dimensions of '{described}' multiply to a count that does not \
                     fit in 64 bits"
                ))
            })?;
        }
        let bytes = total.checked_mul(element_size).ok_or_else(|| {
            ObjError::Overflow(format!(
                "'{described}' declares {total} element(s) of {element_size} byte(s), which is a \
                 size that does not fit in 64 bits"
            ))
        })?;
        Ok(ArrayShape {
            dims,
            total,
            element_size,
            element_type: self.type_name_of(ty)?.to_string(),
            bytes,
            offset,
        })
    }

    /// [`Self::array_shape`], refused when the product exceeds what the caller
    /// can believe.
    ///
    /// Same rule as [`Obj::array_len_capped`], and for the same reason: the
    /// count came out of a symbol file, and the first `cap` elements of an
    /// array declaring 2^40 of them are a prefix of nonsense rather than a
    /// usable prefix of the truth.
    pub fn array_shape_capped(
        &self,
        type_name: &str,
        path: &str,
        cap: u64,
    ) -> Result<ArrayShape, ObjError> {
        let shape = self.array_shape(type_name, path)?;
        if shape.total > cap {
            return Err(ObjError::Cap {
                what: "the symbol table's declared array element count",
                cap,
            });
        }
        Ok(shape)
    }

    /// Whether this build has that member at all.
    ///
    /// The optional-field discipline: ask, then carry `Option`, never a zero.
    pub fn has_member(&self, type_name: &str, member: &str) -> bool {
        self.symbols.has_member(type_name, member)
    }

    /// Prove a member is declared, without wanting its offset.
    ///
    /// The deliberate existence proof, and the reason [`MemberOffset`] is
    /// `#[must_use]` rather than this being written as a discarded
    /// `member_offset`. Silencing that guard with `let _ =` would make a
    /// legitimate pre-flight indistinguishable from the defect it exists to
    /// catch — both would read as "an offset nobody used".
    ///
    /// **Only correct for a member the caller's own branch will certainly
    /// read.** Proving a member here that only *some* builds have, for a branch
    /// only *some* builds take, is the defect: it fails the stage on every
    /// kernel that lacks the member, including the ones that would never have
    /// read it. For that case declare it in a
    /// [`crate::binding::MemberSet`], which answers `NotDeclared` instead of
    /// failing.
    ///
    /// The error carries the symbol table's own reason, so a caller can say
    /// which member was missing and why it needed it.
    pub fn require_member(&self, type_name: &str, path: &str) -> Result<(), ObjError> {
        self.member_offset(type_name, path).map(|_| ())
    }

    /// One structure of a named type at an address.
    ///
    /// Fails here, once, if the name is not a struct, union or class, rather
    /// than at the first member read.
    pub fn object(&self, address: u64, type_name: &str) -> Result<Obj, ObjError> {
        let ty = self.symbols.type_id(type_name)?;
        self.aggregate_of(ty, type_name)?;
        Ok(Obj {
            reader: self.clone(),
            ty,
            name: Arc::from(type_name),
            address,
        })
    }

    /// An object of an already-resolved type, with no further validation.
    ///
    /// For callers that resolved and checked the type once and are now
    /// producing many objects of it — a list walk, a pool scan — so that the
    /// check happens once rather than per entry.
    pub(super) fn object_of(&self, address: u64, ty: TypeId, name: Arc<str>) -> Obj {
        Obj {
            reader: self.clone(),
            ty,
            name,
            address,
        }
    }

    /// Fill `buf` from `address` in the bytes space.
    ///
    /// # Errors
    ///
    /// [`ObjError::Hole`] carrying the unmapped range if any byte of the request
    /// has nothing behind it. `buf` is not to be read after an error: the layer
    /// contract permits it to hold part of a partial read, and part evidence
    /// plus part anything else is not evidence.
    pub fn read_into(&self, address: u64, buf: &mut [u8]) -> Result<(), ObjError> {
        self.read_into_named(address, buf, "a memory range")
    }

    /// Read `len` bytes from `address` in the bytes space.
    ///
    /// Capped at [`MAX_MEMBER_BYTES`], because the length usually came from a
    /// structure in the image.
    pub fn read_bytes(&self, address: u64, len: u64) -> Result<Vec<u8>, ObjError> {
        if len > MAX_MEMBER_BYTES {
            return Err(ObjError::Cap {
                what: "a single buffered read",
                cap: MAX_MEMBER_BYTES,
            });
        }
        let mut buf = vec![0u8; len as usize];
        self.read_into_named(address, &mut buf, "a memory range")?;
        Ok(buf)
    }

    /// Read a bare pointer at an address, at the width and byte order the ISF's
    /// `pointer` base type declares.
    ///
    /// For following a link whose containing type is not being modelled — a
    /// list link, a handle-table level, a PEB pointer chain.
    pub fn read_pointer_at(&self, address: u64) -> Result<u64, ObjError> {
        let scalar = self.pointer_scalar()?;
        let value = self.read_scalar_at(address, scalar, "a pointer")?;
        Ok(raw_bits(value))
    }

    /// Width and byte order of a guest pointer, from the `pointer` base type.
    pub(super) fn pointer_scalar(&self) -> Result<Scalar, ObjError> {
        let id = self.symbols.type_id(POINTER_BASE_TYPE)?;
        let scalar = self.scalar_of(id, POINTER_BASE_TYPE)?;
        if scalar.size != 4 && scalar.size != 8 {
            return Err(ObjError::PointerWidth {
                what: format!("the '{POINTER_BASE_TYPE}' base type"),
                size: scalar.size,
            });
        }
        Ok(scalar)
    }

    /// The aggregate behind a type id, or an error naming what it actually is.
    ///
    /// The [`TypeKind::Unresolved`] arm is not decoration. An arena entry keeps
    /// that kind when the document referenced a type it never defined, and the
    /// failure is deliberately deferred to the point of use. Folded into
    /// [`SymbolError::WrongTypeKind`] it arrives at
    /// [`crate::binding`] as *this build declares no such member* — a claim
    /// about the machine the image came from — when the truth is that the
    /// symbol table could not answer. Those are opposite statements to an
    /// examiner, so the reference that was never bound is named instead.
    pub(super) fn aggregate_of(&self, ty: TypeId, what: &str) -> Result<&AggInfo, ObjError> {
        match &self.symbols.entry(ty)?.kind {
            TypeKind::Aggregate(info) => Ok(info),
            TypeKind::Unresolved { table, name } => Err(SymbolError::UnresolvedType {
                reference: match table {
                    Some(table) => format!("{table}!{name}"),
                    None => name.to_string(),
                },
                referenced_by: what.to_string(),
            }
            .into()),
            other => Err(SymbolError::WrongTypeKind {
                name: what.to_string(),
                actual: other.as_str(),
                expected: "a struct, union or class",
            }
            .into()),
        }
    }

    /// The name the arena records for a type id, for error messages.
    pub(super) fn type_name_of(&self, ty: TypeId) -> Result<&str, ObjError> {
        Ok(self.symbols.entry(ty)?.name.as_ref())
    }

    /// Resolve a `.`-separated member path to an offset from the start of
    /// `root` and the type of the member it lands on.
    ///
    /// Reaches through embedded aggregates only. A pointer in the middle of a
    /// path is an error rather than an implicit dereference, because a read the
    /// caller did not write down is a read that cannot be accounted for when
    /// it lands in a hole.
    pub(super) fn resolve_path(
        &self,
        root: TypeId,
        root_name: &str,
        path: &str,
    ) -> Result<(u64, TypeId), ObjError> {
        if path.is_empty() {
            return Err(SymbolError::UnknownMember {
                type_name: root_name.to_string(),
                member: String::new(),
            }
            .into());
        }

        let mut offset = 0u64;
        let mut current = root;
        let mut current_name = root_name.to_string();

        for (index, segment) in path.split('.').enumerate() {
            if index >= MAX_PATH_SEGMENTS {
                return Err(ObjError::Cap {
                    what: "member path segments",
                    cap: MAX_PATH_SEGMENTS as u64,
                });
            }
            let (member_offset, member_ty) = {
                let aggregate = self.aggregate_of(current, &current_name)?;
                let member =
                    aggregate
                        .member(segment)
                        .ok_or_else(|| SymbolError::UnknownMember {
                            type_name: current_name.clone(),
                            member: segment.to_string(),
                        })?;
                (member.offset, member.ty)
            };
            offset = offset.checked_add(member_offset).ok_or_else(|| {
                ObjError::Overflow(format!(
                    "the offset of '{root_name}.{path}' does not fit in 64 bits"
                ))
            })?;
            current = member_ty;
            current_name = self.type_name_of(current)?.to_string();
        }

        Ok((offset, current))
    }

    /// Width, byte order, signedness and bitfield placement of a scalar type.
    ///
    /// Resolves through enumerations (whose base type governs, not the
    /// advisory `enums[].size`) and through bitfields (whose storage unit may
    /// itself be an enumeration, so the endianness is inherited transitively).
    pub(super) fn scalar_of(&self, ty: TypeId, what: &str) -> Result<Scalar, ObjError> {
        let mut current = ty;
        let mut bitfield = None;
        for _ in 0..MAX_TYPE_DEPTH {
            match &self.symbols.entry(current)?.kind {
                TypeKind::Base(info) => {
                    return Ok(Scalar {
                        size: info.size,
                        endian: info.endian,
                        signed: info.signed,
                        bitfield,
                    })
                }
                TypeKind::Pointer { size, endian, .. } => {
                    return Ok(Scalar {
                        size: *size,
                        endian: *endian,
                        signed: false,
                        bitfield,
                    })
                }
                TypeKind::Enum(info) => current = info.base,
                TypeKind::Bitfield {
                    base,
                    bit_position,
                    bit_length,
                } => {
                    bitfield = Some((*bit_position, *bit_length));
                    current = *base;
                }
                TypeKind::Unresolved { table, name } => {
                    let reference = match table {
                        Some(table) => format!("{table}!{name}"),
                        None => name.to_string(),
                    };
                    return Err(SymbolError::UnresolvedType {
                        reference,
                        referenced_by: what.to_string(),
                    }
                    .into());
                }
                TypeKind::Function => return Err(SymbolError::OpaqueType(what.to_string()).into()),
                other => {
                    return Err(SymbolError::WrongTypeKind {
                        name: what.to_string(),
                        actual: other.as_str(),
                        expected: "an integer, enumeration or pointer member",
                    }
                    .into())
                }
            }
        }
        Err(SymbolError::malformed(format!(
            "'{what}' resolves through more than {MAX_TYPE_DEPTH} type levels"
        ))
        .into())
    }

    /// Read one scalar at an address with a layout already resolved.
    pub(super) fn read_scalar_at(
        &self,
        address: u64,
        scalar: Scalar,
        what: &str,
    ) -> Result<IntValue, ObjError> {
        if scalar.size == 0 || scalar.size > 8 {
            return Err(SymbolError::WrongTypeKind {
                name: what.to_string(),
                actual: "a value that is not 1 to 8 bytes wide",
                expected: "an integer, enumeration or pointer member",
            }
            .into());
        }
        let width = scalar.size as usize;
        let mut buffer = [0u8; 8];
        self.read_into_named(address, &mut buffer[..width], what)?;

        let mut raw = 0u64;
        match scalar.endian {
            Endian::Little => {
                for &byte in buffer[..width].iter().rev() {
                    raw = (raw << 8) | u64::from(byte);
                }
            }
            Endian::Big => {
                for &byte in &buffer[..width] {
                    raw = (raw << 8) | u64::from(byte);
                }
            }
        }

        let mut bits = scalar.size.saturating_mul(8);
        if let Some((position, length)) = scalar.bitfield {
            if length == 0 || length > 64 || position.saturating_add(length) > bits {
                return Err(SymbolError::malformed(format!(
                    "'{what}' is a bitfield of {length} bit(s) at bit {position}, which does not \
                     fit its {}-byte storage unit",
                    scalar.size
                ))
                .into());
            }
            let mask = if length >= 64 {
                u64::MAX
            } else {
                (1u64 << length) - 1
            };
            raw = (raw >> position) & mask;
            bits = length;
        }

        Ok(if scalar.signed {
            IntValue::Signed(sign_extend(raw, bits))
        } else {
            IntValue::Unsigned(raw)
        })
    }

    /// Fill `buf` from the bytes space, naming what is being read so a failure
    /// says which field an examiner lost.
    pub(super) fn read_into_named(
        &self,
        address: u64,
        buf: &mut [u8],
        what: &str,
    ) -> Result<(), ObjError> {
        if buf.is_empty() {
            return Ok(());
        }
        let length = buf.len() as u64;
        // Guard the address arithmetic the shared helper performs internally:
        // an image-derived address near the top of the space must fail closed,
        // not wrap into a low address that happens to be mapped.
        address.checked_add(length).ok_or_else(|| {
            ObjError::Overflow(format!(
                "reading {length} byte(s) of {what} from {address:#x} runs past the end of the \
                 64-bit address space"
            ))
        })?;
        read_exact_or_fail(self.bytes.as_data_source(), address, buf, what)
            .map_err(|err| ObjError::from_read(address, length, what, err))
    }
}

/// One structure of one type at one address.
///
/// Self-contained: an `Obj` carries the reader it was made from, so an object
/// reached by following a pointer knows to read from the native space without
/// the caller having to remember. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Obj {
    reader: StructReader,
    ty: TypeId,
    name: Arc<str>,
    address: u64,
}

impl Obj {
    /// Where this structure starts, in its reader's bytes space.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The structure's type name, as the symbol table records it.
    pub fn type_name(&self) -> &str {
        &self.name
    }

    /// The structure's type id in its table's arena.
    ///
    /// Member lookups go through the id rather than the name, so an object
    /// reached through a pointer to an anonymous or synthesised type still
    /// resolves its members.
    pub fn type_id(&self) -> TypeId {
        self.ty
    }

    /// The reader this object reads through.
    pub fn reader(&self) -> &StructReader {
        &self.reader
    }

    /// Size of the structure in bytes, as the symbol table declares it.
    #[must_use = "a size that is computed and discarded is an existence proof; \
                  declare the type in a seance_memory::binding::MemberSet instead"]
    pub fn size(&self) -> Result<u64, ObjError> {
        Ok(self.reader.symbols.size_of_id(self.ty)?)
    }

    /// Byte offset of a member from the start of this structure.
    ///
    /// See [`StructReader::member_offset`] for why a discarded offset is a
    /// defect and what to declare instead.
    #[must_use = "an offset that is resolved and discarded is an existence proof; \
                  declare the member in a seance_memory::binding::MemberSet instead"]
    pub fn member_offset(&self, path: &str) -> Result<u64, ObjError> {
        Ok(self.reader.resolve_path(self.ty, &self.name, path)?.0)
    }

    /// Address of a member in the reader's bytes space.
    #[must_use = "an address that is computed and discarded is an existence proof; \
                  declare the member in a seance_memory::binding::MemberSet instead"]
    pub fn member_address(&self, path: &str) -> Result<u64, ObjError> {
        let offset = self.member_offset(path)?;
        self.address_of(offset, path)
    }

    /// Whether this build has that member.
    pub fn has_member(&self, member: &str) -> bool {
        match self.reader.aggregate_of(self.ty, &self.name) {
            Ok(aggregate) => aggregate.has_member(member),
            Err(_) => false,
        }
    }

    /// Read an integer member at the width, byte order and signedness the
    /// symbol table declares for it.
    ///
    /// The signedness travels with the value ([`IntValue`]) rather than being
    /// discarded, because a signed field rendered as unsigned is a number the
    /// suspect's machine never held.
    pub fn int(&self, path: &str) -> Result<IntValue, ObjError> {
        let (offset, ty) = self.reader.resolve_path(self.ty, &self.name, path)?;
        let what = self.describe(path);
        let scalar = self.reader.scalar_of(ty, &what)?;
        let address = self.address_of(offset, path)?;
        self.reader.read_scalar_at(address, scalar, &what)
    }

    /// Read a member the symbol table declares **unsigned**.
    ///
    /// A signed member is an error naming the field rather than a
    /// reinterpretation of its bits. Callers that do not know the signedness
    /// use [`Obj::int`], which carries it.
    pub fn unsigned(&self, path: &str) -> Result<u64, ObjError> {
        match self.int(path)? {
            IntValue::Unsigned(value) => Ok(value),
            IntValue::Signed(_) => Err(SymbolError::WrongTypeKind {
                name: self.describe(path),
                actual: "a signed member",
                expected: "an unsigned member",
            }
            .into()),
        }
    }

    /// Read a member the symbol table declares **signed**.
    ///
    /// An unsigned member is an error, symmetrically with [`Obj::unsigned`]:
    /// the caller's belief about the field and the table's declaration must
    /// agree, and if they do not, one of them is wrong about the build.
    pub fn signed(&self, path: &str) -> Result<i64, ObjError> {
        match self.int(path)? {
            IntValue::Signed(value) => Ok(value),
            IntValue::Unsigned(_) => Err(SymbolError::WrongTypeKind {
                name: self.describe(path),
                actual: "an unsigned member",
                expected: "a signed member",
            }
            .into()),
        }
    }

    /// Read a pointer member, at the width the symbol table declares for that
    /// pointer type.
    ///
    /// Null is a value, not an error: a null `Peb` means the process has no
    /// user-mode address space, which is a finding.
    pub fn pointer(&self, path: &str) -> Result<u64, ObjError> {
        Ok(self.pointer_and_target(path)?.0)
    }

    /// Read a pointer member and produce the structure it points at, in the
    /// **native** space.
    ///
    /// `Ok(None)` for a null pointer — the absence of a pointee is a fact, and
    /// a caller must be able to record it without an error path.
    ///
    /// The pointee's type comes from the pointer's own subtype in the ISF, so a
    /// `_EPROCESS*` yields an `_EPROCESS` without the caller restating it.
    /// Following a pointer to something that is not an aggregate is an error;
    /// use [`Obj::pointer`] for those.
    pub fn follow(&self, path: &str) -> Result<Option<Obj>, ObjError> {
        let (value, subtype) = self.pointer_and_target(path)?;
        if value == 0 {
            return Ok(None);
        }
        let what = self.describe(path);
        self.reader.aggregate_of(subtype, &what)?;
        let name: Arc<str> = Arc::from(self.reader.type_name_of(subtype)?);
        Ok(Some(Obj {
            reader: self.reader.in_native_space(),
            ty: subtype,
            name,
            address: value,
        }))
    }

    /// An embedded aggregate member as an object of its own, in the **same**
    /// space.
    ///
    /// Deliberately not [`Obj::follow`]: an embedded struct's bytes are inside
    /// this one, so they are read from wherever this one was read, not from the
    /// native space.
    pub fn embedded(&self, path: &str) -> Result<Obj, ObjError> {
        let (offset, ty) = self.reader.resolve_path(self.ty, &self.name, path)?;
        let what = self.describe(path);
        self.reader.aggregate_of(ty, &what)?;
        let name: Arc<str> = Arc::from(self.reader.type_name_of(ty)?);
        Ok(Obj {
            reader: self.reader.clone(),
            ty,
            name,
            address: self.address_of(offset, path)?,
        })
    }

    /// The raw bytes of a member, at the width the symbol table declares.
    ///
    /// For fixed-length character arrays (`ImageFileName`, `comm`) and for
    /// embedded blobs. The bytes are returned exactly as acquired: trimming a
    /// trailing NUL or decoding a code page is the caller's decision to record.
    pub fn bytes(&self, path: &str) -> Result<Vec<u8>, ObjError> {
        let (offset, ty) = self.reader.resolve_path(self.ty, &self.name, path)?;
        let size = self.reader.symbols.size_of_id(ty)?;
        if size > MAX_MEMBER_BYTES {
            return Err(ObjError::Cap {
                what: "a single member read",
                cap: MAX_MEMBER_BYTES,
            });
        }
        let address = self.address_of(offset, path)?;
        let mut buf = vec![0u8; size as usize];
        self.reader
            .read_into_named(address, &mut buf, &self.describe(path))?;
        Ok(buf)
    }

    /// Element count of an array member, as the symbol table declares it.
    pub fn array_len(&self, path: &str) -> Result<u64, ObjError> {
        Ok(self.array_of(path)?.1)
    }

    /// Element count of an array member, refused if the symbol table declares
    /// more elements than the caller can believe.
    ///
    /// The declared count is attacker-controlled the moment a symbol pack comes
    /// from outside the lab, and a caller iterating a count of 2^40 stops being
    /// an analysis and becomes a hang. Every caller that iterates an array
    /// states the largest count that could be real for that structure; a count
    /// above it is [`ObjError::Cap`] rather than a silently shortened loop,
    /// because such an array is *wrong*, not merely large, and the first `cap`
    /// elements of it are a prefix of nonsense.
    pub fn array_len_capped(&self, path: &str, cap: u64) -> Result<u64, ObjError> {
        let count = self.array_len(path)?;
        if count > cap {
            return Err(ObjError::Cap {
                what: "the symbol table's declared array element count",
                cap,
            });
        }
        Ok(count)
    }

    /// Address of one element of an array member.
    ///
    /// An index at or beyond the declared count is [`ObjError::IndexOutOfBounds`],
    /// never a read past the end of the array: whatever follows the array is
    /// real memory and would parse.
    pub fn element_address(&self, path: &str, index: u64) -> Result<u64, ObjError> {
        Ok(self.element_at(path, index)?.0)
    }

    /// Read one element of an array of scalars.
    pub fn element_int(&self, path: &str, index: u64) -> Result<IntValue, ObjError> {
        let (address, subtype) = self.element_at(path, index)?;
        let what = format!("{}[{index}]", self.describe(path));
        let scalar = self.reader.scalar_of(subtype, &what)?;
        self.reader.read_scalar_at(address, scalar, &what)
    }

    /// One element of an array of structures, in the **same** space.
    pub fn element_object(&self, path: &str, index: u64) -> Result<Obj, ObjError> {
        let (address, subtype) = self.element_at(path, index)?;
        let what = format!("{}[{index}]", self.describe(path));
        self.reader.aggregate_of(subtype, &what)?;
        let name: Arc<str> = Arc::from(self.reader.type_name_of(subtype)?);
        Ok(Obj {
            reader: self.reader.clone(),
            ty: subtype,
            name,
            address,
        })
    }

    /// The pointer's value and the type it points at.
    fn pointer_and_target(&self, path: &str) -> Result<(u64, TypeId), ObjError> {
        let (offset, ty) = self.reader.resolve_path(self.ty, &self.name, path)?;
        let what = self.describe(path);
        let (size, endian, subtype) = match &self.reader.symbols.entry(ty)?.kind {
            TypeKind::Pointer {
                size,
                endian,
                subtype,
            } => (*size, *endian, *subtype),
            other => {
                return Err(SymbolError::WrongTypeKind {
                    name: what,
                    actual: other.as_str(),
                    expected: "a pointer member",
                }
                .into())
            }
        };
        if size != 4 && size != 8 {
            return Err(ObjError::PointerWidth { what, size });
        }
        let scalar = Scalar {
            size,
            endian,
            signed: false,
            bitfield: None,
        };
        let address = self.address_of(offset, path)?;
        let value = self.reader.read_scalar_at(address, scalar, &what)?;
        Ok((raw_bits(value), subtype))
    }

    /// The element type and declared count of an array member.
    fn array_of(&self, path: &str) -> Result<(TypeId, u64, u64), ObjError> {
        let (offset, ty) = self.reader.resolve_path(self.ty, &self.name, path)?;
        match &self.reader.symbols.entry(ty)?.kind {
            TypeKind::Array { subtype, count } => Ok((*subtype, *count, offset)),
            other => Err(SymbolError::WrongTypeKind {
                name: self.describe(path),
                actual: other.as_str(),
                expected: "an array member",
            }
            .into()),
        }
    }

    /// Address and element type of one array element, bounds-checked.
    fn element_at(&self, path: &str, index: u64) -> Result<(u64, TypeId), ObjError> {
        let (subtype, count, offset) = self.array_of(path)?;
        if index >= count {
            return Err(ObjError::IndexOutOfBounds {
                type_name: self.name.to_string(),
                member: path.to_string(),
                index,
                count,
            });
        }
        let element = self.reader.symbols.size_of_id(subtype)?;
        let within = index.checked_mul(element).ok_or_else(|| {
            ObjError::Overflow(format!(
                "element {index} of '{}' lies at an offset that does not fit in 64 bits",
                self.describe(path)
            ))
        })?;
        let offset = offset.checked_add(within).ok_or_else(|| {
            ObjError::Overflow(format!(
                "element {index} of '{}' lies at an offset that does not fit in 64 bits",
                self.describe(path)
            ))
        })?;
        Ok((self.address_of(offset, path)?, subtype))
    }

    /// This object's address plus a member offset, refusing to wrap.
    fn address_of(&self, offset: u64, path: &str) -> Result<u64, ObjError> {
        self.address.checked_add(offset).ok_or_else(|| {
            ObjError::Overflow(format!(
                "{} at {:#x} plus {offset} does not fit in 64 bits",
                self.describe(path),
                self.address
            ))
        })
    }

    /// `Type.member.path`, for error messages an examiner can act on.
    fn describe(&self, path: &str) -> String {
        format!("{}.{path}", self.name)
    }
}

/// Sign-extend the low `bits` of `raw` to a full `i64`.
///
/// `bits` is always 1 to 64 here: a scalar is at least one byte, and a bitfield
/// is validated to be 1 to 64 bits before this is reached.
fn sign_extend(raw: u64, bits: u64) -> i64 {
    if bits >= 64 {
        return raw as i64;
    }
    let shift = 64 - bits;
    ((raw << shift) as i64) >> shift
}

/// The bits of a value that is being used as an address.
///
/// A pointer base type is unsigned in every ISF seen in the wild; this keeps a
/// document that declares otherwise from turning a high kernel address into a
/// negative number.
pub(super) fn raw_bits(value: IntValue) -> u64 {
    match value {
        IntValue::Unsigned(value) => value,
        IntValue::Signed(value) => value as u64,
    }
}

#[cfg(test)]
mod array_shape_tests {
    use crate::object::test_support::fixture;

    /// **An array of arrays declares its shape in nested dimensions, and the
    /// total is their product.**
    ///
    /// The member this exists for is `_KTIMER_TABLE.TimerEntries`, which on
    /// Windows 11 build 26200 is declared `[2][256]` and on every older build
    /// in the 1,724-ISF pack on this machine is declared `[256]`. A caller
    /// reading only the outer dimension walks 2 of 512 buckets on the newer
    /// build — and finds timers in both, so nothing about the result looks
    /// wrong.
    #[test]
    fn a_nested_array_reports_every_dimension_and_their_product() {
        let reader = fixture();
        let shape = reader.array_shape("table", "buckets").expect("declared");
        assert_eq!(shape.dims, vec![2, 4]);
        assert_eq!(shape.total, 8);
        assert_eq!(shape.element_size, 8, "`inner` is eight bytes");
        assert_eq!(shape.element_type, "inner");
        assert_eq!(shape.bytes, 64);
    }

    /// A one-dimensional array is the same answer with one dimension.
    #[test]
    fn a_flat_array_reports_one_dimension() {
        let reader = fixture();
        let shape = reader.array_shape("table", "flat").expect("declared");
        assert_eq!(shape.dims, vec![4]);
        assert_eq!(shape.total, 4);
        assert_eq!(shape.element_size, 4);
        assert_eq!(shape.bytes, 16);
    }

    /// A member that is not an array is refused rather than reported as one
    /// element.
    #[test]
    fn a_member_that_is_not_an_array_is_refused() {
        let reader = fixture();
        let err = reader
            .array_shape("proc", "pid")
            .expect_err("an int is not an array");
        assert!(err.to_string().contains("array"), "{err}");
    }

    /// **A declared count the caller cannot believe is refused, not
    /// truncated.** The count comes out of a symbol file; the first `cap`
    /// elements of an array declaring 2^40 of them are a prefix of nonsense.
    #[test]
    fn a_total_above_the_callers_bound_is_refused_rather_than_shortened() {
        let reader = fixture();
        let err = reader
            .array_shape_capped("table", "buckets", 7)
            .expect_err("8 elements against a bound of 7");
        assert_eq!(err.class(), "cap");
        // And the bound being met exactly is not a refusal.
        assert_eq!(
            reader
                .array_shape_capped("table", "buckets", 8)
                .expect("8 against 8")
                .total,
            8
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::test_support::{
        fixture, fixture32, physical_reader, ENDIAN_PROBE, HOLE_START, NODE32_A, NODE32_B, PROC_A,
        PROC_B, PROC_STRADDLE,
    };
    use seance_core::io::IncompleteReason;

    #[test]
    fn a_member_offset_comes_from_the_symbol_table_not_from_a_constant() {
        let reader = fixture();
        assert_eq!(reader.member_offset("proc", "pid").unwrap().bytes(), 0);
        assert_eq!(reader.member_offset("proc", "links").unwrap().bytes(), 8);
        assert_eq!(reader.member_offset("proc", "name").unwrap().bytes(), 40);
        assert_eq!(
            reader.member_offset("list_head", "prev").unwrap().bytes(),
            8
        );
        assert!(reader.has_member("proc", "ticks"));
    }

    #[test]
    fn a_member_this_build_does_not_have_is_an_error_not_offset_zero() {
        let reader = fixture();
        let err = reader
            .member_offset("proc", "cgroups")
            .expect_err("a member the build lacks must not resolve");
        assert_eq!(err.class(), "symbols");
        assert_eq!(
            err.incomplete_reason(),
            IncompleteReason::UnresolvedStructure
        );
        assert!(err.to_string().contains("cgroups"), "{err}");
        assert!(!reader.has_member("proc", "cgroups"));
    }

    #[test]
    fn a_type_that_is_not_a_struct_is_refused_at_the_object_not_at_the_member() {
        let reader = fixture();
        let err = reader
            .object(PROC_A, "int")
            .expect_err("a base type is not a structure");
        assert!(err.to_string().contains("base type"), "{err}");
    }

    #[test]
    fn an_unsigned_member_reads_at_its_declared_width_and_byte_order() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        assert_eq!(proc.unsigned("uid").unwrap(), 1000);
        assert_eq!(proc.unsigned("ticks").unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(proc.int("uid").unwrap(), IntValue::Unsigned(1000));
    }

    #[test]
    fn a_signed_member_is_sign_extended_from_its_declared_width() {
        // The four bytes hold 0xFFFFFFFF. As `int` that is -1; as `unsigned int`
        // it is 4294967295. Only the symbol table can say which, and reporting
        // the wrong one puts a number in the record the machine never held.
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        assert_eq!(proc.signed("pid").unwrap(), -1);
        assert_eq!(proc.int("pid").unwrap(), IntValue::Signed(-1));
        assert_eq!(proc.int("pid").unwrap().as_i128(), -1);
        assert_eq!(
            proc.int("pid").unwrap().as_u64(),
            None,
            "a negative value must not be handed back as a huge positive one"
        );
    }

    #[test]
    fn reading_a_member_at_the_wrong_signedness_is_refused_rather_than_reinterpreted() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        let err = proc
            .unsigned("pid")
            .expect_err("a signed member must not be handed back as unsigned");
        assert!(err.to_string().contains("proc.pid"), "{err}");
        let err = proc
            .signed("uid")
            .expect_err("an unsigned member must not be handed back as signed");
        assert!(err.to_string().contains("proc.uid"), "{err}");
    }

    #[test]
    fn a_bitfield_is_extracted_from_its_storage_unit_and_keeps_its_signedness() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        // `flag` is bit 3 of an unsigned int holding 0b1000.
        assert_eq!(proc.int("flag").unwrap(), IntValue::Unsigned(1));
        // `nibble` is the low four bits of a signed int holding 0b1111, which
        // is -1, not 15.
        assert_eq!(proc.int("nibble").unwrap(), IntValue::Signed(-1));
    }

    #[test]
    fn an_enumeration_member_reads_through_its_base_type() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        let state = proc.int("state").unwrap();
        assert_eq!(state, IntValue::Unsigned(2));
        // The label is the symbol table's job, and an undefined value gets none.
        let table = reader.symbols();
        assert_eq!(
            table
                .enum_constant_name("proc_state", state.as_i128())
                .unwrap(),
            Some("ZOMBIE")
        );
        assert_eq!(table.enum_constant_name("proc_state", 9).unwrap(), None);
    }

    #[test]
    fn an_embedded_struct_member_resolves_through_a_dotted_path() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        assert_eq!(proc.member_offset("inner.depth").unwrap(), 36);
        assert_eq!(proc.unsigned("inner.magic").unwrap(), 0xDEAD_BEEF);
        assert_eq!(proc.signed("inner.depth").unwrap(), -2);

        // And as an object in its own right, in the same space.
        let inner = proc.embedded("inner").unwrap();
        assert_eq!(inner.address(), PROC_A + 32);
        assert_eq!(inner.type_name(), "inner");
        assert_eq!(inner.unsigned("magic").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn a_path_through_a_pointer_is_refused_rather_than_dereferenced_silently() {
        let reader = fixture();
        let proc = reader.object(PROC_B, "proc").unwrap();
        let err = proc
            .member_offset("parent.pid")
            .expect_err("a pointer in a path must not be followed implicitly");
        assert!(err.to_string().contains("pointer"), "{err}");
    }

    #[test]
    fn a_character_array_member_comes_back_exactly_as_acquired() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        let name = proc.bytes("name").unwrap();
        assert_eq!(name.len(), 16, "the declared width, not the string length");
        assert_eq!(&name[..4], b"init");
        assert_eq!(name[4], 0);
    }

    #[test]
    fn array_elements_are_addressed_by_the_declared_element_size() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        assert_eq!(proc.array_len("slots").unwrap(), 4);
        assert_eq!(proc.element_address("slots", 0).unwrap(), PROC_A + 88);
        assert_eq!(proc.element_address("slots", 3).unwrap(), PROC_A + 100);
        assert_eq!(
            proc.element_int("slots", 0).unwrap(),
            IntValue::Unsigned(10)
        );
        assert_eq!(
            proc.element_int("slots", 3).unwrap(),
            IntValue::Unsigned(40)
        );
    }

    #[test]
    fn an_array_count_above_the_callers_bound_is_refused_rather_than_iterated() {
        // The declared count is a number from the ISF, and a caller looping
        // over one it cannot believe is a hang, not an analysis.
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        assert_eq!(proc.array_len_capped("slots", 4).unwrap(), 4);
        let err = proc
            .array_len_capped("slots", 3)
            .expect_err("a declared count above the caller's bound is not believable");
        assert_eq!(err.class(), "cap");
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
    }

    #[test]
    fn an_index_past_the_declared_count_is_refused_not_read() {
        // Whatever follows the array is real memory and would parse, which is
        // how an out-of-bounds element becomes a confident wrong answer.
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        let err = proc
            .element_int("slots", 4)
            .expect_err("element 4 of a 4-element array does not exist");
        assert_eq!(err.class(), "index_out_of_bounds");
        assert!(err.to_string().contains("4 element(s)"), "{err}");
    }

    #[test]
    fn a_pointer_is_read_at_the_width_the_table_declares() {
        let reader = fixture();
        assert_eq!(reader.pointer_size().unwrap(), 8);
        let proc = reader.object(PROC_B, "proc").unwrap();
        assert_eq!(proc.pointer("parent").unwrap(), PROC_A);
        // A bare pointer at an address, for links whose container is not modelled.
        assert_eq!(reader.read_pointer_at(PROC_B + 56).unwrap(), PROC_A);
    }

    #[test]
    fn following_a_pointer_yields_the_pointee_type_from_the_isf() {
        let reader = fixture();
        let proc = reader.object(PROC_B, "proc").unwrap();
        let parent = proc.follow("parent").unwrap().expect("proc B has a parent");
        assert_eq!(parent.type_name(), "proc");
        assert_eq!(parent.address(), PROC_A);
        assert_eq!(parent.unsigned("uid").unwrap(), 1000);
    }

    #[test]
    fn a_thirty_two_bit_table_reads_four_byte_pointers_not_the_host_width() {
        // The bytes after each pointer are 0xFFFFFFFF, so a read at the host's
        // eight bytes would yield 0xFFFFFFFF_00001140: a different address, and
        // one that would still be followed and still parse.
        let reader = fixture32();
        assert_eq!(reader.pointer_size().unwrap(), 4);

        let node = reader.object(NODE32_A, "node32").unwrap();
        assert_eq!(node.unsigned("id").unwrap(), 1);
        assert_eq!(
            node.pointer("next_node").unwrap(),
            NODE32_B,
            "the width came from the ISF, not from the machine running this"
        );
        assert_eq!(reader.read_pointer_at(NODE32_A + 12).unwrap(), NODE32_B);

        let next = node
            .follow("next_node")
            .unwrap()
            .expect("node A points at B");
        assert_eq!(next.type_name(), "node32");
        assert_eq!(next.address(), NODE32_B);
        assert_eq!(next.unsigned("id").unwrap(), 2);
        assert_eq!(next.pointer("next_node").unwrap(), 0);
    }

    #[test]
    fn byte_order_comes_from_the_symbol_table_not_from_the_host() {
        // Identical bytes, opposite declarations. Reading both the same way
        // would put a number in the record the machine never held.
        let reader = fixture();
        let probe = reader.object(ENDIAN_PROBE, "endian_probe").unwrap();
        assert_eq!(probe.unsigned("le").unwrap(), 0x0403_0201);
        assert_eq!(probe.unsigned("be").unwrap(), 0x0102_0304);
    }

    #[test]
    fn a_null_pointer_is_an_absence_not_an_error() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        assert_eq!(proc.pointer("parent").unwrap(), 0);
        assert!(proc.follow("parent").unwrap().is_none());
    }

    #[test]
    fn a_pointer_to_something_that_is_not_a_struct_cannot_be_followed() {
        let reader = fixture();
        let proc = reader.object(PROC_A, "proc").unwrap();
        // The value is readable as a pointer...
        assert_eq!(proc.pointer("handler").unwrap(), 0x1234);
        // ...but a function has no members, so there is no object to make.
        assert!(proc.follow("handler").is_err());
    }

    #[test]
    fn a_pointer_followed_out_of_a_physically_read_struct_lands_in_the_native_space() {
        // The pool-scanning invariant: the bytes came from one space, the
        // pointers inside them address another. Backwards, every dereference
        // returns unrelated bytes that still parse.
        let (reader, native) = physical_reader();
        assert!(reader.spaces_differ());
        let proc = reader.object(PROC_B, "proc").unwrap();
        let parent = proc.follow("parent").unwrap().expect("a parent pointer");
        assert!(
            Arc::ptr_eq(parent.reader().layer(), &native),
            "the pointee must be read from the native space, not the scanned one"
        );
        assert!(
            !Arc::ptr_eq(parent.reader().layer(), reader.layer()),
            "and specifically not from the layer the candidate was scanned out of"
        );
    }

    #[test]
    fn an_embedded_object_stays_in_the_space_its_bytes_came_from() {
        let (reader, _native) = physical_reader();
        let proc = reader.object(PROC_A, "proc").unwrap();
        let inner = proc.embedded("inner").unwrap();
        assert!(
            Arc::ptr_eq(inner.reader().layer(), reader.layer()),
            "an embedded struct's bytes are inside this struct's bytes"
        );
    }

    #[test]
    fn a_member_whose_bytes_are_in_a_hole_errors_with_the_hole() {
        let reader = fixture();
        let proc = reader.object(PROC_STRADDLE, "proc").unwrap();
        // The mapped part of the struct still reads.
        assert_eq!(proc.signed("pid").unwrap(), 7);
        // The part past the top of the segment does not, and says exactly which
        // bytes were never acquired.
        let err = proc
            .int("state")
            .expect_err("an unacquired member must not read as zero");
        let hole = err.hole().expect("the hole must reach the caller");
        assert_eq!(
            hole.address,
            PROC_STRADDLE + 64,
            "the hole starts where the read did"
        );
        assert!(hole.address >= HOLE_START);
        assert_eq!(err.incomplete_reason(), IncompleteReason::ShortRead);
    }

    #[test]
    fn a_member_straddling_the_edge_of_a_hole_errors_rather_than_half_reading() {
        let reader = fixture();
        let proc = reader.object(PROC_STRADDLE, "proc").unwrap();
        // `parent` starts four bytes before the hole and runs into it.
        assert_eq!(proc.member_address("parent").unwrap(), HOLE_START - 4);
        let err = proc
            .pointer("parent")
            .expect_err("half a pointer is not a pointer");
        let hole = err.hole().expect("a typed hole");
        assert_eq!(hole.address, HOLE_START);
    }

    #[test]
    fn a_read_that_would_wrap_the_address_space_fails_closed() {
        let reader = fixture();
        let mut buf = [0u8; 8];
        let err = reader
            .read_into(u64::MAX - 2, &mut buf)
            .expect_err("an address near the top must not wrap into a mapped one");
        assert_eq!(err.class(), "overflow");
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn a_read_above_the_top_of_the_space_is_truncation_not_a_hole() {
        let reader = fixture();
        let mut buf = [0u8; 8];
        let err = reader
            .read_into(0xF000_0000, &mut buf)
            .expect_err("there is no such address");
        assert_eq!(err.class(), "truncated");
        assert!(err.hole().is_none(), "past the evidence is not a hole");
    }

    #[test]
    fn an_oversized_read_is_capped_rather_than_allocated() {
        let reader = fixture();
        let err = reader
            .read_bytes(PROC_A, MAX_MEMBER_BYTES + 1)
            .expect_err("a length taken from an image must be bounded");
        assert_eq!(err.class(), "cap");
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
    }

    #[test]
    fn sign_extension_is_exact_at_every_width() {
        assert_eq!(sign_extend(0xFF, 8), -1);
        assert_eq!(sign_extend(0x7F, 8), 127);
        assert_eq!(sign_extend(0xFFFF_FFFF, 32), -1);
        assert_eq!(sign_extend(0x8000_0000, 32), i64::from(i32::MIN));
        assert_eq!(sign_extend(0xF, 4), -1);
        assert_eq!(sign_extend(0x7, 4), 7);
        assert_eq!(sign_extend(u64::MAX, 64), -1);
    }

    #[test]
    fn int_value_conversions_refuse_rather_than_wrap() {
        assert_eq!(IntValue::Unsigned(u64::MAX).as_i64(), None);
        assert_eq!(IntValue::Signed(-1).as_u64(), None);
        assert_eq!(IntValue::Signed(-1).as_i128(), -1);
        assert_eq!(IntValue::Unsigned(u64::MAX).as_i128(), i128::from(u64::MAX));
        assert!(IntValue::Signed(0).is_signed());
        assert_eq!(IntValue::Signed(-5).to_string(), "-5");
    }
}
