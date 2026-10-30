//! Stage B and C: the compiled type database and its query surface.
//!
//! # The shape, and why
//!
//! Compilation walks the document once and turns every named reference into a
//! [`TypeId`] — an index into one flat arena. Forward references, mutual
//! references and cycles are free, because a cycle is just an index that points
//! backwards. Resolution is **eager and total**: nothing is left as a lazy
//! template that detonates during a plugin run three thousand rows into a case.
//! References that cannot be bound become [`TypeKind::Unresolved`] entries,
//! collected into [`Diagnostics`] at compile time, and any query that would
//! need their layout fails with the reference named.
//!
//! # The hot path
//!
//! Member-offset lookup is the single hottest operation in memory forensics:
//! four hundred processes times thirty fields is twelve thousand lookups before
//! anything has been read. Each aggregate therefore carries its own name-to-index
//! hash map, so [`SymbolTable::member_offset`] is two hash lookups and no scan,
//! whatever the size of `_EPROCESS`.
//!
//! # What compilation refuses to do
//!
//! - It never synthesises a missing member as offset `0`.
//! - It never trusts a declared array count for an allocation; sizes are
//!   computed with checked arithmetic and overflow is an error.
//! - It never exceeds its arena budget. Failing to load is correct behaviour;
//!   being OOM-killed mid-case is not.
//! - It never admits a table the gate refused. [`SymbolTable::compile`] returns
//!   [`crate::error::SymbolError::Rejected`] carrying the whole report, so the
//!   finding written into the case record can name the failing check.

use std::collections::{HashMap, HashSet};

use crate::error::{Result, SymbolError};
use crate::identify::IsfIdentity;
use crate::isf::{
    AggKind, BaseKind, Endian, IsfDocument, TypeDescriptor, Version, POINTER_BASE_TYPE,
};
use crate::probe::ImageProbe;
use crate::source::{DecompressLimits, IsfProvenance, IsfSource};
use crate::validate::{
    self, AdmissionReport, AdmissionState, Gate, GateOutcome, GateResult, ValidationOptions,
};

/// Default ceiling on the compiled arena.
///
/// A real `ntkrnlmp` ISF compiles well inside this. The point of the ceiling is
/// not to be generous but to be *enforced*: an unbounded compile is an
/// out-of-memory kill in the middle of an examination.
pub const DEFAULT_MAX_TABLE_BYTES: u64 = 512 * 1024 * 1024;

/// Deepest chain of nested type descriptors compilation will follow.
const MAX_TYPE_DEPTH: u32 = 64;

/// Deepest chain of anonymous members that may be lifted into a parent.
const MAX_FLATTEN_DEPTH: u32 = 32;

/// Most diagnostics of each class kept as text.
const MAX_RECORDED_DIAGNOSTICS: usize = 128;

/// An index into a [`SymbolTable`]'s type arena.
///
/// Opaque and table-scoped: an id from one table means nothing in another, and
/// every accessor bounds-checks rather than trusting one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId(u32);

impl TypeId {
    /// Position in the arena.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// A primitive type's layout.
#[derive(Debug, Clone, Copy)]
pub struct BaseInfo {
    /// Width in bytes.
    pub size: u64,
    /// Whether values are signed.
    pub signed: bool,
    /// Width class.
    pub kind: BaseKind,
    /// Byte order.
    pub endian: Endian,
}

/// One member of an aggregate, after anonymous fields have been lifted.
#[derive(Debug, Clone)]
pub struct Member {
    /// Member name as the producer wrote it.
    pub name: Box<str>,
    /// Byte offset from the start of the enclosing aggregate.
    pub offset: u64,
    /// The member's type.
    pub ty: TypeId,
    /// Whether this member is itself an anonymous aggregate.
    pub anonymous: bool,
    /// The anonymous member this one was lifted out of, if it was. Kept so a
    /// rejection can say *why* a member is at the offset it claims.
    pub lifted_from: Option<Box<str>>,
}

/// A struct, union or class.
#[derive(Debug, Clone)]
pub struct AggInfo {
    /// Size of the whole aggregate in bytes.
    pub size: u64,
    /// Which aggregate this is. Unions stay unions so a reader can enumerate
    /// the alternatives instead of silently picking one.
    pub kind: AggKind,
    /// Members in declaration order, lifted anonymous members included.
    pub members: Vec<Member>,
    /// Name to member index. The hot path.
    by_name: HashMap<Box<str>, u32>,
    /// Names that lifting made resolve to more than one member, and the count
    /// for each. Held apart from `by_name` so an ambiguous name cannot silently
    /// resolve to whichever member happened to be indexed last.
    ambiguous: HashMap<Box<str>, usize>,
}

impl AggInfo {
    /// One member by name, in constant time.
    ///
    /// `None` for an ambiguous name: it addresses no single member, so there is
    /// no member to return. Callers that must tell "absent" from "cannot be
    /// addressed" ask [`AggInfo::ambiguity`].
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.by_name
            .get(name)
            .and_then(|index| self.members.get(*index as usize))
    }

    /// Whether this aggregate has a member of that name. The `has_member`
    /// discipline: an optional field is asked about, never assumed.
    pub fn has_member(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// How many members carry `name`, when more than one does.
    ///
    /// `None` means the name is not ambiguous -- either it addresses exactly
    /// one member or no member at all.
    pub fn ambiguity(&self, name: &str) -> Option<usize> {
        self.ambiguous.get(name).copied()
    }

    /// Every name lifting left unaddressable in this type, in a stable order.
    pub fn ambiguous_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.ambiguous.keys().map(|name| &**name).collect();
        names.sort_unstable();
        names
    }
}

/// One enumeration constant.
#[derive(Debug, Clone)]
pub struct EnumConstant {
    /// Constant name.
    pub name: Box<str>,
    /// Constant value, widened so both a signed and an unsigned 64-bit base fit.
    pub value: i128,
}

/// An enumeration.
#[derive(Debug, Clone)]
pub struct EnumInfo {
    /// The base type that governs width and signedness. `enums[].size` is
    /// advisory and is not used for anything.
    pub base: TypeId,
    /// The size the producer declared, kept only for the record.
    pub declared_size: u64,
    /// Constants in declaration order.
    pub constants: Vec<EnumConstant>,
    by_name: HashMap<Box<str>, u32>,
    by_value: HashMap<i128, u32>,
}

impl EnumInfo {
    /// The value of a named constant.
    pub fn value_of(&self, name: &str) -> Option<i128> {
        self.by_name
            .get(name)
            .and_then(|index| self.constants.get(*index as usize))
            .map(|constant| constant.value)
    }

    /// The name of a value.
    ///
    /// `None` for a value the enumeration does not define. Never a fabricated
    /// label: the caller reports the raw integer instead, because "3" and
    /// "probably PROCESS_EXITING" are different claims.
    pub fn name_of(&self, value: i128) -> Option<&str> {
        self.by_value
            .get(&value)
            .and_then(|index| self.constants.get(*index as usize))
            .map(|constant| constant.name.as_ref())
    }
}

/// What a type actually is.
#[derive(Debug, Clone)]
pub enum TypeKind {
    /// A primitive.
    Base(BaseInfo),
    /// A struct, union or class.
    Aggregate(AggInfo),
    /// An enumeration.
    Enum(EnumInfo),
    /// A pointer. Width comes from the `pointer` base type, never from the host.
    Pointer {
        /// What is pointed at.
        subtype: TypeId,
        /// Width in bytes.
        size: u64,
        /// Byte order, inherited from the `pointer` base type.
        endian: Endian,
    },
    /// A fixed-length array.
    Array {
        /// Element type.
        subtype: TypeId,
        /// Declared element count.
        count: u64,
    },
    /// A bitfield inside an integer or enumeration storage unit.
    Bitfield {
        /// The storage unit, which may itself be an enumeration.
        base: TypeId,
        /// Index of the least significant bit within the unit.
        bit_position: u64,
        /// Width in bits.
        bit_length: u64,
    },
    /// A function. Opaque: no size, no signature, by construction.
    Function,
    /// A reference that could not be bound. Carrying the reference rather than
    /// dropping it is the point: a query through it fails and names it.
    Unresolved {
        /// The `table` part of a `table!type` reference, if there was one.
        table: Option<Box<str>>,
        /// The referenced name.
        name: Box<str>,
    },
}

impl TypeKind {
    /// Stable identifier for messages and artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            TypeKind::Base(_) => "base type",
            TypeKind::Aggregate(info) => match info.kind {
                AggKind::Struct => "struct",
                AggKind::Union => "union",
                AggKind::Class => "class",
            },
            TypeKind::Enum(_) => "enum",
            TypeKind::Pointer { .. } => "pointer",
            TypeKind::Array { .. } => "array",
            TypeKind::Bitfield { .. } => "bitfield",
            TypeKind::Function => "function",
            TypeKind::Unresolved { .. } => "unresolved reference",
        }
    }
}

/// One entry in the arena.
#[derive(Debug, Clone)]
pub struct TypeEntry {
    /// The type's name, or a synthesised description for an anonymous shape.
    pub name: Box<str>,
    /// What it is.
    pub kind: TypeKind,
}

/// A symbol: a name bound to an address.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Symbol name.
    pub name: Box<str>,
    /// Address as the ISF declared it, before any mask is applied.
    pub address: u64,
    /// The symbol's type, if the producer recorded one.
    pub ty: Option<TypeId>,
    /// Base64 of the symbol's constant value, decoded on demand.
    pub constant_data: Option<Box<str>>,
}

impl SymbolEntry {
    /// The decoded bytes of this symbol's constant value.
    pub fn constant_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.constant_data {
            Some(encoded) => crate::base64::decode(encoded).map(Some),
            None => Ok(None),
        }
    }
}

/// What compilation could not bind, recorded rather than discovered later.
#[derive(Debug, Clone, Default)]
pub struct Diagnostics {
    /// Local references that name nothing in this document.
    pub unresolved: Vec<String>,
    /// How many there were in total, recorded or not.
    pub unresolved_total: u64,
    /// `table!type` references into another symbol table, which only a
    /// multi-table load can bind. Not a defect: this is how the hand-written
    /// pool-header fragments point at the real kernel table.
    pub external: Vec<String>,
    /// How many there were in total, recorded or not.
    pub external_total: u64,
}

impl Diagnostics {
    /// Whether anything at all went unbound.
    pub fn is_empty(&self) -> bool {
        self.unresolved_total == 0 && self.external_total == 0
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "unresolved": self.unresolved,
            "unresolved_total": self.unresolved_total,
            "external": self.external,
            "external_total": self.external_total,
        })
    }
}

/// Bounds and expectations applied while compiling.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// Ceiling on the compiled arena, in bytes.
    pub max_table_bytes: u64,
    /// What the caller knows independently, for gates 2 and 3.
    pub validation: ValidationOptions,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            max_table_bytes: DEFAULT_MAX_TABLE_BYTES,
            validation: ValidationOptions::new(),
        }
    }
}

/// The arena and its indices.
#[derive(Debug)]
struct Core {
    entries: Vec<TypeEntry>,
    base_index: HashMap<Box<str>, TypeId>,
    user_index: HashMap<Box<str>, TypeId>,
    enum_index: HashMap<Box<str>, TypeId>,
    /// Names declared in more than one of the three blocks. Almost always empty;
    /// a lookup that does not name a block refuses on these.
    shadowed: HashSet<Box<str>>,
    symbols: Vec<SymbolEntry>,
    symbol_index: HashMap<Box<str>, u32>,
    by_address: Vec<(u64, u32)>,
    diagnostics: Diagnostics,
    pointer_size: u64,
    pointer_endian: Endian,
    estimated_bytes: u64,
}

/// A compiled, validated type database.
#[derive(Debug)]
pub struct SymbolTable {
    identity: IsfIdentity,
    admission: AdmissionReport,
    symbol_mask: u64,
    core: Core,
}

/// Where a member lives and how to read it: byte offset, byte order, and the
/// `(bit_position, bit_length)` pair when it is a bitfield rather than a whole
/// number of bytes.
///
/// Named because the tuple is otherwise three anonymous halves in a signature,
/// and the third being `None` is the difference between a plain member and one
/// that occupies part of a storage unit.
type MemberLocation = (u64, Endian, Option<(u64, u64)>);

impl SymbolTable {
    /// Compile a parsed document into a queryable table.
    ///
    /// Runs the admission gate around the build: gate 1's document half first,
    /// because the build applies version-dependent semantics and must not run
    /// under a guess; then the arena; then gate 1's layout half and gates 2, 3
    /// and 5 against the arena that the queries will actually use.
    ///
    /// # Errors
    ///
    /// [`SymbolError::Rejected`] carrying the whole report if any gate failed,
    /// and the ordinary structural errors if the arena could not be built at
    /// all. A rejected table is never returned in any form: there is no "load
    /// it anyway" path, because output produced that way would enter the case
    /// record indistinguishable from verified output.
    pub fn compile(
        doc: &IsfDocument,
        provenance: IsfProvenance,
        options: &CompileOptions,
    ) -> Result<SymbolTable> {
        let mut warnings = Vec::new();
        let mut structural = validate::structural_document(doc, &options.validation, &mut warnings);
        if structural.outcome == GateOutcome::Fail {
            let mut report = AdmissionReport {
                gates: vec![structural],
                warnings,
            };
            for (gate, check) in [
                (Gate::Identity, "identity"),
                (Gate::Architecture, "architecture"),
                (Gate::ImageSanity, "image_sanity"),
                (Gate::Producer, "producer"),
            ] {
                report.record(GateResult::not_evaluated(
                    gate,
                    check,
                    "gate 1 refused the document, so no later gate ran",
                ));
            }
            return Err(SymbolError::Rejected(Box::new(report)));
        }

        let identity = IsfIdentity::from_document(doc, provenance)?;
        let version = identity.format;
        let core = Builder::new(options.max_table_bytes).build(doc, version)?;

        validate::layout(&core.entries, &mut structural);
        let mut report = AdmissionReport {
            gates: vec![structural],
            warnings,
        };
        report.record(validate::identity(&identity, &options.validation));
        report.record(validate::architecture(doc, &options.validation));
        report.record(validate::image_sanity_not_evaluated());
        report.record(validate::producer(doc));

        if report.is_rejected() {
            return Err(SymbolError::Rejected(Box::new(report)));
        }

        tracing::debug!(
            types = core.entries.len(),
            symbols = core.symbols.len(),
            unresolved = core.diagnostics.unresolved_total,
            external = core.diagnostics.external_total,
            bytes = core.estimated_bytes,
            "compiled ISF symbol table"
        );

        Ok(SymbolTable {
            identity,
            admission: report,
            symbol_mask: u64::MAX,
            core,
        })
    }

    /// Decompress, parse and compile in one step.
    pub fn compile_source(source: IsfSource, options: &CompileOptions) -> Result<SymbolTable> {
        let doc = IsfDocument::parse(&source.json)?;
        SymbolTable::compile(&doc, source.provenance, options)
    }

    /// Load an ISF file from disk and compile it.
    pub fn compile_path(
        path: &std::path::Path,
        limits: &DecompressLimits,
        options: &CompileOptions,
    ) -> Result<SymbolTable> {
        let source = crate::source::load_path(path, limits)?;
        SymbolTable::compile_source(source, options)
    }

    /// What this table is for, and which file it came from.
    pub fn identity(&self) -> &IsfIdentity {
        &self.identity
    }

    /// Hashes and lengths of the file this table was compiled from. A report
    /// that quotes an offset can quote this alongside it.
    pub fn provenance(&self) -> &IsfProvenance {
        &self.identity.provenance
    }

    /// Every check that ran, and what it concluded.
    pub fn admission(&self) -> &AdmissionReport {
        &self.admission
    }

    /// The overall admission state, which decides what plugins may do.
    pub fn state(&self) -> AdmissionState {
        self.admission.state()
    }

    /// Record a gate-4 result obtained by reading the image through this table.
    ///
    /// The first real gate-4 result clears the "no memory image was supplied"
    /// placeholder that compilation records, so a table checked against its
    /// image can reach [`AdmissionState::Verified`]. Every later result is
    /// added, because gate 4 is several named checks and each one's outcome is
    /// part of the record.
    pub fn record_gate(&mut self, result: GateResult) {
        if result.gate == Gate::ImageSanity {
            self.admission.gates.retain(|existing| {
                !(existing.gate == Gate::ImageSanity
                    && existing.check == "image_sanity"
                    && existing.outcome == GateOutcome::NotEvaluated)
            });
        }
        self.admission.record(result);
    }

    /// References compilation could not bind.
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.core.diagnostics
    }

    /// The whole type arena.
    pub fn entries(&self) -> &[TypeEntry] {
        &self.core.entries
    }

    /// Every symbol, in document order.
    pub fn symbols(&self) -> &[SymbolEntry] {
        &self.core.symbols
    }

    /// Guest pointer width in bytes, from the `pointer` base type.
    pub fn pointer_size(&self) -> u64 {
        self.core.pointer_size
    }

    /// Approximate arena footprint, in bytes.
    pub fn estimated_bytes(&self) -> u64 {
        self.core.estimated_bytes
    }

    /// The mask ANDed onto every symbol address returned by
    /// [`SymbolTable::symbol_address`].
    ///
    /// Set to the address mask of the layer the symbols address, so a 32-bit
    /// image does not yield sign-extended addresses. Legitimate arithmetic, but
    /// it changes returned values, so it is recorded rather than applied
    /// invisibly.
    pub fn symbol_mask(&self) -> u64 {
        self.symbol_mask
    }

    /// Set the symbol mask.
    ///
    /// Rebuilds the address-ordered index, because masking is not
    /// order-preserving: leaving the index sorted on unmasked addresses while
    /// [`SymbolTable::nearest_symbol`] searches it with a masked one makes that
    /// search return the wrong symbol, or the right symbol at a fabricated
    /// distance of zero. A pointer found in memory attributed to the wrong
    /// kernel symbol is a finding an examiner cannot tell from a real one.
    pub fn set_symbol_mask(&mut self, mask: u64) {
        if mask == self.symbol_mask {
            return;
        }
        self.symbol_mask = mask;
        let mut by_address: Vec<(u64, u32)> = self
            .core
            .symbols
            .iter()
            .enumerate()
            .map(|(index, symbol)| (symbol.address & mask, index as u32))
            .collect();
        by_address.sort_unstable_by_key(|(address, _)| *address);
        self.core.by_address = by_address;
    }

    /// Look up a type by name, across all three blocks.
    ///
    /// User types first, then enumerations, then base types, which is the order
    /// in which a name is most likely to have been meant. Nothing is guessed:
    /// an unknown name is an error, never the nearest match.
    ///
    /// # Errors
    ///
    /// [`SymbolError::UnknownType`] for a name this table does not declare, and
    /// [`SymbolError::Malformed`] for a name declared in **two** blocks. The
    /// three blocks are separate namespaces, so a document may legally declare a
    /// struct and a base type of the same name; a caller that has not said which
    /// it means would otherwise be handed one silently, and a struct's size read
    /// where a base type's was meant is a wrong stride applied to real bytes.
    /// Members and symbols are unaffected: their descriptors name the block, and
    /// [`SymbolTable::enumeration`] still reaches a shadowed enum directly.
    pub fn type_id(&self, name: &str) -> Result<TypeId> {
        if !self.core.shadowed.is_empty() && self.core.shadowed.contains(name) {
            return Err(SymbolError::malformed(format!(
                "'{name}' is declared in more than one of base_types, user_types and enums, \
                 so a lookup by name alone cannot say which layout was meant"
            )));
        }
        self.core
            .user_index
            .get(name)
            .or_else(|| self.core.enum_index.get(name))
            .or_else(|| self.core.base_index.get(name))
            .copied()
            .ok_or_else(|| SymbolError::UnknownType(name.to_string()))
    }

    /// Whether a type of that name exists.
    pub fn has_type(&self, name: &str) -> bool {
        self.type_id(name).is_ok()
    }

    /// One arena entry.
    pub fn entry(&self, id: TypeId) -> Result<&TypeEntry> {
        self.core.entries.get(id.index()).ok_or_else(|| {
            SymbolError::malformed(format!(
                "type id {} is outside this table's arena of {} entries",
                id.0,
                self.core.entries.len()
            ))
        })
    }

    /// One aggregate by name.
    pub fn aggregate(&self, type_name: &str) -> Result<&AggInfo> {
        let id = self.type_id(type_name)?;
        let entry = self.entry(id)?;
        match &entry.kind {
            TypeKind::Aggregate(info) => Ok(info),
            other => Err(SymbolError::WrongTypeKind {
                name: type_name.to_string(),
                actual: other.as_str(),
                expected: "a struct, union or class",
            }),
        }
    }

    /// One member of an aggregate.
    ///
    /// # Errors
    ///
    /// [`SymbolError::UnknownMember`] when this build does not have that field.
    /// The caller must treat that as "absent", never as offset zero: a
    /// synthesised member reads real bytes from the wrong place and reports
    /// them as fact.
    pub fn member(&self, type_name: &str, member: &str) -> Result<&Member> {
        let aggregate = self.aggregate(type_name)?;
        if let Some(found) = aggregate.member(member) {
            return Ok(found);
        }
        // Absent and unaddressable are different findings and a caller acts on
        // them differently, so they must not arrive as the same error.
        match aggregate.ambiguity(member) {
            Some(count) => Err(SymbolError::AmbiguousMember {
                type_name: type_name.to_string(),
                member: member.to_string(),
                count,
            }),
            None => Err(SymbolError::UnknownMember {
                type_name: type_name.to_string(),
                member: member.to_string(),
            }),
        }
    }

    /// The byte offset of a member. Two hash lookups, no scan.
    pub fn member_offset(&self, type_name: &str, member: &str) -> Result<u64> {
        Ok(self.member(type_name, member)?.offset)
    }

    /// Whether a build has a member, without erroring.
    ///
    /// The discipline for optional fields: ask, then carry `Option`, never a
    /// zero. `cap_ambient` is absent on older kernels, and "0 capabilities" is
    /// a very different claim from "this kernel does not have that set".
    pub fn has_member(&self, type_name: &str, member: &str) -> bool {
        matches!(self.aggregate(type_name), Ok(info) if info.has_member(member))
    }

    /// Size of a named type in bytes.
    pub fn size_of(&self, type_name: &str) -> Result<u64> {
        let id = self.type_id(type_name)?;
        self.size_of_id(id)
    }

    /// Whether this type's own members contradict its declared size.
    ///
    /// True when some member lies past the declared size, or ends past it. The
    /// admission gate records each such member as a caveat rather than refusing
    /// the table, because a member is read at its own offset for its own width
    /// and the declared size bounds nothing that a read consults — see
    /// [`crate::validate::GateResult::caveat`]. Volatility's hand-written
    /// netscan overlays are the corpus case: `_TCP_ENDPOINT.Owner` at 752 in a
    /// type declared 632 bytes long, and `_IN_ADDR` declared 6 bytes with a
    /// 16-byte IPv6 member, in packs whose owner attributions are nonetheless
    /// correct build after build.
    ///
    /// **This is the fail-closed hook.** A member read is safe; a *whole-type*
    /// read is not. A caller that means to fetch `size_of(type)` bytes and then
    /// slice members out of the buffer must call this first and refuse when it
    /// is true, because a member past the declared size would be truncated to
    /// nothing and a zero is indistinguishable from a real value.
    ///
    /// # Errors
    ///
    /// [`SymbolError::WrongTypeKind`] when the name is not an aggregate, and
    /// whatever [`SymbolTable::type_id`] refuses. A member whose width cannot be
    /// computed is not treated as contradicting anything: it has already failed
    /// every query that would need it.
    pub fn declared_size_is_stub(&self, type_name: &str) -> Result<bool> {
        let aggregate = self.aggregate(type_name)?;
        Ok(aggregate.members.iter().any(|member| {
            if member.offset > aggregate.size {
                return true;
            }
            match size_of_in(&self.core.entries, member.ty, 0) {
                Ok(width) => match member.offset.checked_add(width) {
                    Some(end) => end > aggregate.size,
                    None => true,
                },
                Err(_) => false,
            }
        }))
    }

    /// Size of an arena entry in bytes.
    ///
    /// # Errors
    ///
    /// [`SymbolError::OpaqueType`] for a function, [`SymbolError::UnresolvedType`]
    /// for an unbound reference, and [`SymbolError::Overflow`] for an array
    /// whose declared count times its element size does not fit. None of these
    /// answer with a plausible number.
    pub fn size_of_id(&self, id: TypeId) -> Result<u64> {
        size_of_in(&self.core.entries, id, 0)
    }

    /// One enumeration by name.
    pub fn enumeration(&self, type_name: &str) -> Result<&EnumInfo> {
        let id = self
            .core
            .enum_index
            .get(type_name)
            .copied()
            .ok_or_else(|| SymbolError::UnknownType(type_name.to_string()))?;
        match &self.entry(id)?.kind {
            TypeKind::Enum(info) => Ok(info),
            other => Err(SymbolError::WrongTypeKind {
                name: type_name.to_string(),
                actual: other.as_str(),
                expected: "an enum",
            }),
        }
    }

    /// The value of a named enumeration constant.
    pub fn enum_value(&self, type_name: &str, constant: &str) -> Result<i128> {
        self.enumeration(type_name)?
            .value_of(constant)
            .ok_or_else(|| SymbolError::UnknownMember {
                type_name: type_name.to_string(),
                member: constant.to_string(),
            })
    }

    /// The name an enumeration gives a value, if it gives it one.
    ///
    /// `Ok(None)` means the enumeration does not define that value; the caller
    /// reports the raw integer. A label is never invented.
    pub fn enum_constant_name(&self, type_name: &str, value: i128) -> Result<Option<&str>> {
        Ok(self.enumeration(type_name)?.name_of(value))
    }

    /// One symbol by name.
    pub fn symbol(&self, name: &str) -> Result<&SymbolEntry> {
        self.core
            .symbol_index
            .get(name)
            .and_then(|index| self.core.symbols.get(*index as usize))
            .ok_or_else(|| SymbolError::UnknownSymbol(name.to_string()))
    }

    /// Whether a symbol exists.
    pub fn has_symbol(&self, name: &str) -> bool {
        self.core.symbol_index.contains_key(name)
    }

    /// A symbol's address, with the symbol mask applied.
    pub fn symbol_address(&self, name: &str) -> Result<u64> {
        Ok(self.symbol(name)?.address & self.symbol_mask)
    }

    /// The symbol at or below an address, and the distance from it.
    ///
    /// Reverse symbolication for a raw pointer found in memory. Returns nothing
    /// when the address is below every symbol; the caller decides what distance
    /// is too far to be meaningful, because this crate cannot know whether the
    /// table covers the module the address belongs to.
    ///
    /// The query and the index are both under the current symbol mask, so the
    /// distance returned is a real distance between two addresses in the same
    /// space rather than between a masked one and an unmasked one.
    pub fn nearest_symbol(&self, address: u64) -> Option<(&SymbolEntry, u64)> {
        let masked = address & self.symbol_mask;
        let position = match self
            .core
            .by_address
            .binary_search_by_key(&masked, |(symbol_address, _)| *symbol_address)
        {
            Ok(exact) => exact,
            Err(0) => return None,
            Err(next) => next - 1,
        };
        let (symbol_address, index) = self.core.by_address[position];
        let symbol = self.core.symbols.get(index as usize)?;
        Some((symbol, masked.saturating_sub(symbol_address)))
    }

    /// Read one integer member of a structure out of the image, through this
    /// table.
    ///
    /// This is the primitive every gate-4 falsification check is built on:
    /// `_EPROCESS.UniqueProcessId` read at the offset *this* table declares,
    /// then tested for sanity. A wrong table fails those tests; a right one
    /// passes them.
    ///
    /// Width, byte order and any bitfield extraction come from the table, never
    /// from an assumption. A member wider than eight bytes, an aggregate, an
    /// array, a function or an unresolved reference is an error rather than a
    /// truncated read.
    ///
    /// # Errors
    ///
    /// [`SymbolError::Probe`] if the image could not supply every byte. A hole
    /// is never padded: fabricated zeros satisfy almost any sanity check, which
    /// would let a wrong table through the one gate that could have caught it.
    pub fn read_member_unsigned(
        &self,
        probe: &dyn ImageProbe,
        base_address: u64,
        type_name: &str,
        member_name: &str,
    ) -> Result<u64> {
        let member = self.member(type_name, member_name)?;
        let address = base_address.checked_add(member.offset).ok_or_else(|| {
            SymbolError::Overflow(format!(
                "address {base_address:#x} plus the offset of '{type_name}.{member_name}' \
                 does not fit in 64 bits"
            ))
        })?;
        let (size, endian, bitfield) = self.scalar_layout(member.ty, type_name, member_name)?;
        if size == 0 || size > 8 {
            return Err(SymbolError::WrongTypeKind {
                name: format!("{type_name}.{member_name}"),
                actual: "a value that is not 1 to 8 bytes wide",
                expected: "an integer member",
            });
        }

        let mut buffer = [0u8; 8];
        let width = size as usize;
        probe
            .read_exact(address, &mut buffer[..width])
            .map_err(|err| SymbolError::Probe {
                what: format!("{type_name}.{member_name} at {address:#x}"),
                detail: err.to_string(),
            })?;

        let mut value = 0u64;
        match endian {
            Endian::Little => {
                for &byte in buffer[..width].iter().rev() {
                    value = (value << 8) | u64::from(byte);
                }
            }
            Endian::Big => {
                for &byte in &buffer[..width] {
                    value = (value << 8) | u64::from(byte);
                }
            }
        }

        if let Some((bit_position, bit_length)) = bitfield {
            let bits = size.saturating_mul(8);
            if bit_length == 0 || bit_length > 64 || bit_position.saturating_add(bit_length) > bits
            {
                return Err(SymbolError::malformed(format!(
                    "'{type_name}.{member_name}' is a bitfield of {bit_length} bit(s) at bit \
                     {bit_position}, which does not fit its {size}-byte storage unit"
                )));
            }
            let mask = if bit_length >= 64 {
                u64::MAX
            } else {
                (1u64 << bit_length) - 1
            };
            value = (value >> bit_position) & mask;
        }
        Ok(value)
    }

    /// Width, byte order and bitfield placement of a scalar member.
    fn scalar_layout(
        &self,
        id: TypeId,
        type_name: &str,
        member_name: &str,
    ) -> Result<MemberLocation> {
        let mut current = id;
        let mut bitfield = None;
        for _ in 0..MAX_TYPE_DEPTH {
            match &self.entry(current)?.kind {
                TypeKind::Base(info) => return Ok((info.size, info.endian, bitfield)),
                TypeKind::Pointer { size, endian, .. } => return Ok((*size, *endian, bitfield)),
                TypeKind::Enum(info) => current = info.base,
                TypeKind::Bitfield {
                    base,
                    bit_position,
                    bit_length,
                } => {
                    // The schema gives a bitfield's storage unit as a base type
                    // or an enum, but nothing in the document stops one bitfield
                    // being declared inside another. Two bit ranges do not
                    // describe one field, and keeping the innermost would
                    // extract a different slice of genuinely-present bytes and
                    // report it as the member's value.
                    if bitfield.is_some() {
                        return Err(SymbolError::malformed(format!(
                            "'{type_name}.{member_name}' declares a bitfield inside a bitfield, \
                             so no single bit range describes it"
                        )));
                    }
                    bitfield = Some((*bit_position, *bit_length));
                    current = *base;
                }
                TypeKind::Unresolved { table, name } => {
                    return Err(SymbolError::UnresolvedType {
                        reference: qualified(table.as_deref(), name),
                        referenced_by: format!("{type_name}.{member_name}"),
                    })
                }
                TypeKind::Function => {
                    return Err(SymbolError::OpaqueType(format!(
                        "{type_name}.{member_name}"
                    )))
                }
                other => {
                    return Err(SymbolError::WrongTypeKind {
                        name: format!("{type_name}.{member_name}"),
                        actual: other.as_str(),
                        expected: "an integer member",
                    })
                }
            }
        }
        Err(SymbolError::malformed(format!(
            "'{type_name}.{member_name}' resolves through more than {MAX_TYPE_DEPTH} type levels"
        )))
    }

    /// Serializable form for artifact metadata: what this table is, where it
    /// came from, and how far it was proved.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "identity": self.identity.to_json(),
            "admission": self.admission.to_json(),
            "symbol_confidence": self.state().symbol_confidence(),
            "symbol_mask": self.symbol_mask,
            "pointer_size": self.core.pointer_size,
            "types": self.core.entries.len(),
            "symbols": self.core.symbols.len(),
            "estimated_bytes": self.core.estimated_bytes,
            "diagnostics": self.core.diagnostics.to_json(),
        })
    }
}

/// Render a possibly table-qualified reference.
fn qualified(table: Option<&str>, name: &str) -> String {
    match table {
        Some(table) => format!("{table}!{name}"),
        None => name.to_string(),
    }
}

/// Size of an arena entry, with cycle and overflow protection.
///
/// Free-standing so the admission gate can use it against a freshly built arena
/// before there is a [`SymbolTable`] to ask.
pub(crate) fn size_of_in(entries: &[TypeEntry], id: TypeId, depth: u32) -> Result<u64> {
    if depth > MAX_TYPE_DEPTH {
        return Err(SymbolError::malformed(format!(
            "type nesting deeper than {MAX_TYPE_DEPTH} levels while sizing a type"
        )));
    }
    let entry = entries
        .get(id.index())
        .ok_or_else(|| SymbolError::malformed(format!("type id {} is outside the arena", id.0)))?;
    match &entry.kind {
        TypeKind::Base(info) => Ok(info.size),
        TypeKind::Aggregate(info) => Ok(info.size),
        TypeKind::Enum(info) => size_of_in(entries, info.base, depth + 1),
        TypeKind::Pointer { size, .. } => Ok(*size),
        TypeKind::Array { subtype, count } => {
            let element = size_of_in(entries, *subtype, depth + 1)?;
            count.checked_mul(element).ok_or_else(|| {
                SymbolError::Overflow(format!(
                    "array '{}' declares {count} elements of {element} bytes, which does not fit \
                     in 64 bits",
                    entry.name
                ))
            })
        }
        TypeKind::Bitfield { base, .. } => size_of_in(entries, *base, depth + 1),
        TypeKind::Function => Err(SymbolError::OpaqueType(entry.name.to_string())),
        TypeKind::Unresolved { table, name } => Err(SymbolError::UnresolvedType {
            reference: qualified(table.as_deref(), name),
            referenced_by: entry.name.to_string(),
        }),
    }
}

/// Key under which structurally identical anonymous shapes are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AnonKey {
    Pointer(TypeId),
    Array(TypeId, u64),
    Bitfield(TypeId, u64, u64),
}

/// Which block a name is looked up in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Base,
    User,
    Enum,
}

impl Namespace {
    fn as_str(self) -> &'static str {
        match self {
            Namespace::Base => "base_types",
            Namespace::User => "user_types",
            Namespace::Enum => "enums",
        }
    }
}

/// Builds the arena.
struct Builder {
    core: Core,
    anon_index: HashMap<AnonKey, TypeId>,
    unresolved_index: HashMap<String, TypeId>,
    function_id: Option<TypeId>,
    max_bytes: u64,
}

impl Builder {
    fn new(max_bytes: u64) -> Self {
        Self {
            core: Core {
                entries: Vec::new(),
                base_index: HashMap::new(),
                user_index: HashMap::new(),
                enum_index: HashMap::new(),
                shadowed: HashSet::new(),
                symbols: Vec::new(),
                symbol_index: HashMap::new(),
                by_address: Vec::new(),
                diagnostics: Diagnostics::default(),
                pointer_size: 0,
                pointer_endian: Endian::Little,
                estimated_bytes: 0,
            },
            anon_index: HashMap::new(),
            unresolved_index: HashMap::new(),
            function_id: None,
            max_bytes,
        }
    }

    /// Charge the arena budget, failing closed when it is exhausted.
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.core.estimated_bytes = self.core.estimated_bytes.saturating_add(bytes);
        if self.core.estimated_bytes > self.max_bytes {
            return Err(SymbolError::TableTooLarge {
                needed: self.core.estimated_bytes,
                limit: self.max_bytes,
            });
        }
        Ok(())
    }

    fn push(&mut self, name: impl Into<Box<str>>, kind: TypeKind) -> Result<TypeId> {
        let name = name.into();
        self.charge(std::mem::size_of::<TypeEntry>() as u64 + name.len() as u64 + 32)?;
        if self.core.entries.len() >= u32::MAX as usize {
            return Err(SymbolError::malformed(
                "the document declares more types than one table can index",
            ));
        }
        let id = TypeId(self.core.entries.len() as u32);
        self.core.entries.push(TypeEntry { name, kind });
        Ok(id)
    }

    fn build(mut self, doc: &IsfDocument, version: Version) -> Result<Core> {
        // 1. Base types, which everything else bottoms out in.
        for (name, base) in doc.base_types.iter() {
            let id = self.push(
                name,
                TypeKind::Base(BaseInfo {
                    size: base.size,
                    signed: base.signed,
                    kind: base.kind,
                    endian: base.endian,
                }),
            )?;
            self.core.base_index.insert(name.into(), id);
            if name == POINTER_BASE_TYPE {
                self.core.pointer_size = base.size;
                self.core.pointer_endian = base.endian;
            }
        }

        // 2. Aggregate placeholders, so members may refer to types declared
        //    later, or to their own enclosing type.
        let mut user_ids = Vec::with_capacity(doc.user_types.len());
        for (name, user) in doc.user_types.iter() {
            let id = self.push(
                name,
                TypeKind::Aggregate(AggInfo {
                    size: user.size,
                    kind: user.kind,
                    members: Vec::new(),
                    by_name: HashMap::new(),
                    ambiguous: HashMap::new(),
                }),
            )?;
            self.core.user_index.insert(name.into(), id);
            user_ids.push(id);
        }

        // 3. Enumerations. The base type governs width and sign; `size` is kept
        //    only for the record.
        for (name, definition) in doc.enums.iter() {
            let base = self.named(&definition.base, Namespace::Base, name)?;
            let mut constants = Vec::with_capacity(definition.constants.len());
            let mut by_name = HashMap::with_capacity(definition.constants.len());
            let mut by_value = HashMap::new();
            for (constant_name, raw) in definition.constants.iter() {
                let value = raw
                    .as_u64()
                    .map(i128::from)
                    .or_else(|| raw.as_i64().map(i128::from))
                    .ok_or_else(|| {
                        SymbolError::malformed(format!(
                            "enum '{name}' constant '{constant_name}' has the value {raw}, \
                             which is not an exact integer"
                        ))
                    })?;
                let index = constants.len() as u32;
                by_name.insert(Box::<str>::from(constant_name), index);
                // Aliases are legal; the first name for a value wins so that
                // rendering is stable between runs.
                by_value.entry(value).or_insert(index);
                constants.push(EnumConstant {
                    name: constant_name.into(),
                    value,
                });
                self.charge(
                    std::mem::size_of::<EnumConstant>() as u64 + constant_name.len() as u64 + 64,
                )?;
            }
            let id = self.push(
                name,
                TypeKind::Enum(EnumInfo {
                    base,
                    declared_size: definition.size,
                    constants,
                    by_name,
                    by_value,
                }),
            )?;
            self.core.enum_index.insert(name.into(), id);
        }

        // 3b. Names declared in two blocks at once. Every type *descriptor*
        //     names the block it means, so resolution below is unaffected; it is
        //     the block-less query surface that cannot say which was meant, and
        //     [`SymbolTable::type_id`] refuses on exactly this set.
        let mut shadowed: HashSet<Box<str>> = HashSet::new();
        for name in self.core.user_index.keys() {
            if self.core.base_index.contains_key(name) || self.core.enum_index.contains_key(name) {
                shadowed.insert(name.clone());
            }
        }
        for name in self.core.enum_index.keys() {
            if self.core.base_index.contains_key(name) {
                shadowed.insert(name.clone());
            }
        }
        self.core.shadowed = shadowed;

        // 4. Members.
        for (index, (type_name, user)) in doc.user_types.iter().enumerate() {
            let mut members = Vec::with_capacity(user.fields.len());
            for (member_name, field) in user.fields.iter() {
                let ty = self.resolve(&field.ty, type_name, 0)?;
                self.charge(std::mem::size_of::<Member>() as u64 + member_name.len() as u64 + 64)?;
                members.push(Member {
                    name: member_name.into(),
                    offset: field.offset,
                    ty,
                    anonymous: field.anonymous,
                    lifted_from: None,
                });
            }
            let id = match user_ids.get(index) {
                Some(id) => *id,
                None => {
                    return Err(SymbolError::malformed(
                        "internal inconsistency: a user type lost its arena slot",
                    ))
                }
            };
            if let Some(TypeEntry {
                kind: TypeKind::Aggregate(aggregate),
                ..
            }) = self.core.entries.get_mut(id.index())
            {
                aggregate.members = members;
            }
        }

        // 5. Anonymous-field flattening, from format 6.2.0. Skip it and every
        //    field after an anonymous member sits at the wrong offset.
        if version.flattens_anonymous_fields() {
            self.flatten_anonymous()?;
        }

        // 6. Member indices, built after flattening so they cover lifted
        //    members too.
        self.index_members()?;

        // 7. Symbols.
        for (name, symbol) in doc.symbols.iter() {
            let address = symbol.address_u64(name)?;
            let ty = match &symbol.ty {
                Some(descriptor) => Some(self.resolve(descriptor, name, 0)?),
                None => None,
            };
            let constant_data = symbol.constant_data.as_deref().map(Box::<str>::from);
            self.charge(
                std::mem::size_of::<SymbolEntry>() as u64
                    + name.len() as u64
                    + constant_data.as_ref().map_or(0, |data| data.len() as u64)
                    + 64,
            )?;
            let index = self.core.symbols.len() as u32;
            self.core.symbol_index.insert(name.into(), index);
            self.core.by_address.push((address, index));
            self.core.symbols.push(SymbolEntry {
                name: name.into(),
                address,
                ty,
                constant_data,
            });
        }
        self.core
            .by_address
            .sort_unstable_by_key(|(address, _)| *address);

        Ok(self.core)
    }

    /// Bind a named reference, or record that it could not be bound.
    ///
    /// An unbindable reference is never quietly aliased onto some other entry:
    /// it gets its own [`TypeKind::Unresolved`] entry carrying the name, so a
    /// query through it fails and says which reference was missing.
    /// A bitfield whose declared geometry cannot describe any run of bits.
    ///
    /// Routed to the same channel as a type reference this build cannot follow,
    /// because the consequence is identical: the member exists and cannot be
    /// read. It is recorded rather than fatal -- see the call site.
    fn unresolved_bitfield(
        &mut self,
        owner: &str,
        bit_position: i64,
        bit_length: i64,
    ) -> Result<TypeId> {
        let name = format!("bitfield:{bit_length}@{bit_position}");
        let id = self.push(
            name.as_str(),
            TypeKind::Unresolved {
                table: None,
                name: Box::<str>::from(name.as_str()),
            },
        )?;
        self.core.diagnostics.unresolved_total =
            self.core.diagnostics.unresolved_total.saturating_add(1);
        if self.core.diagnostics.unresolved.len() < MAX_RECORDED_DIAGNOSTICS {
            self.core.diagnostics.unresolved.push(format!(
                "'{owner}' declares a bitfield of {bit_length} bit(s) at bit {bit_position}, \
                 which describes no run of bits, so the member cannot be read"
            ));
        }
        Ok(id)
    }

    fn named(&mut self, name: &str, namespace: Namespace, owner: &str) -> Result<TypeId> {
        // `table!type` names a type in a *different* symbol table. Binding one
        // needs a multi-table load, so it is recorded rather than treated as a
        // defect: this is exactly how the hand-written pool-header fragments
        // point at the real kernel table.
        if let Some((table, rest)) = name.split_once('!') {
            let key = format!("external:{name}");
            if let Some(id) = self.unresolved_index.get(&key) {
                return Ok(*id);
            }
            let id = self.push(
                name,
                TypeKind::Unresolved {
                    table: Some(table.into()),
                    name: rest.into(),
                },
            )?;
            self.unresolved_index.insert(key, id);
            self.core.diagnostics.external_total =
                self.core.diagnostics.external_total.saturating_add(1);
            if self.core.diagnostics.external.len() < MAX_RECORDED_DIAGNOSTICS {
                self.core
                    .diagnostics
                    .external
                    .push(format!("'{name}' referenced by '{owner}'"));
            }
            return Ok(id);
        }

        let index = match namespace {
            Namespace::Base => &self.core.base_index,
            Namespace::User => &self.core.user_index,
            Namespace::Enum => &self.core.enum_index,
        };
        if let Some(id) = index.get(name) {
            return Ok(*id);
        }

        let key = format!("{}:{name}", namespace.as_str());
        if let Some(id) = self.unresolved_index.get(&key) {
            return Ok(*id);
        }
        let id = self.push(
            name,
            TypeKind::Unresolved {
                table: None,
                name: name.into(),
            },
        )?;
        self.unresolved_index.insert(key, id);
        self.core.diagnostics.unresolved_total =
            self.core.diagnostics.unresolved_total.saturating_add(1);
        if self.core.diagnostics.unresolved.len() < MAX_RECORDED_DIAGNOSTICS {
            self.core.diagnostics.unresolved.push(format!(
                "'{name}' in {} referenced by '{owner}'",
                namespace.as_str()
            ));
        }
        Ok(id)
    }

    /// Bind an anonymous shape, sharing structurally identical ones.
    fn anonymous(&mut self, key: AnonKey, name: String, kind: TypeKind) -> Result<TypeId> {
        if let Some(id) = self.anon_index.get(&key) {
            return Ok(*id);
        }
        let id = self.push(name, kind)?;
        self.anon_index.insert(key, id);
        Ok(id)
    }

    /// Turn one descriptor into an arena entry.
    fn resolve(&mut self, descriptor: &TypeDescriptor, owner: &str, depth: u32) -> Result<TypeId> {
        if depth > MAX_TYPE_DEPTH {
            return Err(SymbolError::malformed(format!(
                "the type of '{owner}' nests more than {MAX_TYPE_DEPTH} levels deep"
            )));
        }
        match descriptor {
            TypeDescriptor::Base { name } => self.named(name, Namespace::Base, owner),
            // The *definition's* aggregate kind is authoritative: a descriptor
            // saying "struct" that points at a union definition is legal, and
            // the union wins. So all three shapes look in the same block.
            TypeDescriptor::Struct { name }
            | TypeDescriptor::Union { name }
            | TypeDescriptor::Class { name } => self.named(name, Namespace::User, owner),
            TypeDescriptor::Enum { name } => self.named(name, Namespace::Enum, owner),
            TypeDescriptor::Pointer { subtype } => {
                let target = self.resolve(subtype, owner, depth + 1)?;
                let target_name = self.name_of(target);
                let size = self.core.pointer_size;
                let endian = self.core.pointer_endian;
                self.anonymous(
                    AnonKey::Pointer(target),
                    format!("{target_name} *"),
                    TypeKind::Pointer {
                        subtype: target,
                        size,
                        endian,
                    },
                )
            }
            TypeDescriptor::Array { count, subtype } => {
                let element = self.resolve(subtype, owner, depth + 1)?;
                let element_name = self.name_of(element);
                self.anonymous(
                    AnonKey::Array(element, *count),
                    format!("{element_name}[{count}]"),
                    TypeKind::Array {
                        subtype: element,
                        count: *count,
                    },
                )
            }
            TypeDescriptor::Function => {
                // One shared entry: a function type carries no subtype, return
                // type or arguments, so every occurrence is the same opacity.
                if let Some(id) = self.function_id {
                    return Ok(id);
                }
                let id = self.push("function", TypeKind::Function)?;
                self.function_id = Some(id);
                Ok(id)
            }
            TypeDescriptor::Bitfield {
                bit_position,
                bit_length,
                ty,
            } => {
                // A producer that emits a negative bit position has described
                // no field this reader can locate. Apple's shipped 10.12.3 KDK
                // does exactly that for `IONVRAMDescriptor.bridgeDevices`
                // (position -8), and treating it as a document-level defect
                // refused 4,839 types and 43,548 symbols over one IOKit
                // descriptor no analysis stage reads.
                //
                // So it resolves to the unresolved channel, which already
                // exists for a type this build cannot describe: the member
                // stays visible in the type, no read can be taken through it,
                // and `diagnostics.unresolved` names it for the report. A wrong
                // bit position would otherwise mask real bytes into a plausible
                // small integer, which is far worse than an absence.
                if *bit_position < 0 || *bit_length < 0 {
                    return self.unresolved_bitfield(owner, *bit_position, *bit_length);
                }
                let (bit_position, bit_length) = (&(*bit_position as u64), &(*bit_length as u64));
                let base = self.resolve(ty, owner, depth + 1)?;
                let base_name = self.name_of(base);
                self.anonymous(
                    AnonKey::Bitfield(base, *bit_position, *bit_length),
                    format!("{base_name}:{bit_length}@{bit_position}"),
                    TypeKind::Bitfield {
                        base,
                        bit_position: *bit_position,
                        bit_length: *bit_length,
                    },
                )
            }
        }
    }

    fn name_of(&self, id: TypeId) -> String {
        self.core
            .entries
            .get(id.index())
            .map(|entry| entry.name.to_string())
            .unwrap_or_else(|| "?".to_string())
    }

    /// Lift the members of every anonymous aggregate member into its parent,
    /// with offsets accumulated.
    ///
    /// Every list is computed from the *unflattened* arena and applied
    /// afterwards, so a type that is lifted into two parents is not lifted
    /// twice into either.
    ///
    /// Lifting is charged against the same arena budget as everything else.
    /// Each level multiplies its parent's member count, so thirty-two levels of
    /// two anonymous members apiece — a two-kilobyte document — expand to
    /// billions of members. An uncharged expansion there is an out-of-memory
    /// kill in the middle of an examination, which is the one thing the budget
    /// exists to prevent.
    fn flatten_anonymous(&mut self) -> Result<()> {
        let aggregate_ids: Vec<TypeId> = self
            .core
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| matches!(entry.kind, TypeKind::Aggregate(_)))
            .map(|(index, _)| TypeId(index as u32))
            .collect();

        let mut memo: HashMap<TypeId, Vec<Member>> = HashMap::new();
        let mut estimated = self.core.estimated_bytes;
        let max_bytes = self.max_bytes;
        for id in &aggregate_ids {
            let mut stack = Vec::new();
            let outcome = flatten_one(
                &self.core.entries,
                *id,
                &mut memo,
                &mut stack,
                0,
                &mut estimated,
                max_bytes,
            );
            self.core.estimated_bytes = estimated;
            outcome?;
        }
        for id in aggregate_ids {
            let flattened = match memo.remove(&id) {
                Some(flattened) => flattened,
                None => continue,
            };
            if let Some(TypeEntry {
                kind: TypeKind::Aggregate(aggregate),
                ..
            }) = self.core.entries.get_mut(id.index())
            {
                aggregate.members = flattened;
            }
        }
        Ok(())
    }

    /// Build each aggregate's name-to-member index.
    fn index_members(&mut self) -> Result<()> {
        for entry in &mut self.core.entries {
            if let TypeKind::Aggregate(aggregate) = &mut entry.kind {
                let mut by_name = HashMap::with_capacity(aggregate.members.len());
                let mut ambiguous: HashMap<Box<str>, usize> = HashMap::new();
                for (index, member) in aggregate.members.iter().enumerate() {
                    if by_name.insert(member.name.clone(), index as u32).is_some() {
                        // Repeated *declared* members are refused by gate 1, so
                        // this is a collision created by lifting an anonymous
                        // member. It makes one name unaddressable in one type;
                        // it says nothing about the other 4000-odd types beside
                        // it, so it must not refuse the document. Debian 3.2's
                        // table has 20 of these and every one is a placeholder
                        // (`unnamed_field_N`, dwarf2json's filler for an
                        // anonymous member) colliding with the same placeholder
                        // in the aggregate lifted into it -- names no stage
                        // asks for. Refusing on them took the whole Linux tier
                        // out, silently, on the only kernel we have an image
                        // for.
                        *ambiguous.entry(member.name.clone()).or_insert(1) += 1;
                    }
                }
                // Drop every ambiguous name from the lookup index: leaving it
                // would resolve to whichever member was indexed last, which is
                // a real offset for the wrong field.
                for name in ambiguous.keys() {
                    by_name.remove(name);
                }
                aggregate.by_name = by_name;
                aggregate.ambiguous = ambiguous;
            }
        }
        Ok(())
    }
}

/// Charge one lifted member against the arena budget.
///
/// Free-standing because flattening reads the arena immutably while it grows
/// the accounting; the running total is written back by the caller.
fn charge_lifted(estimated: &mut u64, max_bytes: u64, name_len: usize) -> Result<()> {
    *estimated =
        estimated.saturating_add(std::mem::size_of::<Member>() as u64 + name_len as u64 + 64);
    if *estimated > max_bytes {
        return Err(SymbolError::TableTooLarge {
            needed: *estimated,
            limit: max_bytes,
        });
    }
    Ok(())
}

/// Compute one aggregate's flattened member list.
fn flatten_one(
    entries: &[TypeEntry],
    id: TypeId,
    memo: &mut HashMap<TypeId, Vec<Member>>,
    stack: &mut Vec<TypeId>,
    depth: u32,
    estimated: &mut u64,
    max_bytes: u64,
) -> Result<Vec<Member>> {
    if let Some(cached) = memo.get(&id) {
        return Ok(cached.clone());
    }
    if depth > MAX_FLATTEN_DEPTH {
        return Err(SymbolError::malformed(format!(
            "anonymous members nest more than {MAX_FLATTEN_DEPTH} levels deep"
        )));
    }
    if stack.contains(&id) {
        let name = entries
            .get(id.index())
            .map(|entry| entry.name.to_string())
            .unwrap_or_else(|| "?".to_string());
        return Err(SymbolError::malformed(format!(
            "type '{name}' contains itself as an anonymous member"
        )));
    }
    stack.push(id);

    let mut out = Vec::new();
    if let Some(TypeEntry {
        kind: TypeKind::Aggregate(aggregate),
        ..
    }) = entries.get(id.index())
    {
        for member in &aggregate.members {
            out.push(member.clone());
            if !member.anonymous {
                continue;
            }
            let child_is_aggregate = matches!(
                entries.get(member.ty.index()).map(|entry| &entry.kind),
                Some(TypeKind::Aggregate(_))
            );
            if !child_is_aggregate {
                continue;
            }
            let lifted = flatten_one(
                entries,
                member.ty,
                memo,
                stack,
                depth + 1,
                estimated,
                max_bytes,
            )?;
            for child in lifted {
                charge_lifted(estimated, max_bytes, child.name.len())?;
                let offset = member.offset.checked_add(child.offset).ok_or_else(|| {
                    SymbolError::Overflow(format!(
                        "lifting '{}' out of the anonymous member '{}' overflows a 64-bit offset",
                        child.name, member.name
                    ))
                })?;
                out.push(Member {
                    name: child.name,
                    offset,
                    ty: child.ty,
                    anonymous: child.anonymous,
                    lifted_from: Some(member.name.clone()),
                });
            }
        }
    }

    stack.pop();
    memo.insert(id, out.clone());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isf::Architecture;
    use crate::probe::test_support::FakeImage;
    use crate::source::{load_slice, test_support::gzip};

    /// A small but complete Linux-shaped ISF.
    const LINUX: &str = r#"{
      "metadata": {
        "format": "6.2.0",
        "producer": {"name": "dwarf2json", "version": "0.9.0"},
        "linux": {"symbols": [], "types": []}
      },
      "base_types": {
        "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
        "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
        "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
        "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
        "char": {"size": 1, "signed": true, "kind": "char", "endian": "little"},
        "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
      },
      "user_types": {
        "list_head": {"size": 16, "kind": "struct", "fields": {
          "next": {"offset": 0, "type": {"kind": "pointer",
                   "subtype": {"kind": "struct", "name": "list_head"}}},
          "prev": {"offset": 8, "type": {"kind": "pointer",
                   "subtype": {"kind": "struct", "name": "list_head"}}}
        }},
        "task_struct": {"size": 64, "kind": "struct", "fields": {
          "tasks": {"offset": 0, "type": {"kind": "struct", "name": "list_head"}},
          "pid": {"offset": 16, "type": {"kind": "base", "name": "int"}},
          "flags": {"offset": 20, "type": {"kind": "base", "name": "unsigned int"}},
          "state": {"offset": 24, "type": {"kind": "enum", "name": "task_state"}},
          "comm": {"offset": 32, "type": {"kind": "array", "count": 16,
                   "subtype": {"kind": "base", "name": "char"}}},
          "in_execve": {"offset": 48, "type": {"kind": "bitfield", "bit_position": 3,
                        "bit_length": 1, "type": {"kind": "base", "name": "unsigned int"}}},
          "handler": {"offset": 56, "type": {"kind": "pointer",
                      "subtype": {"kind": "function"}}}
        }}
      },
      "enums": {
        "task_state": {"size": 4, "base": "unsigned int",
                       "constants": {"TASK_RUNNING": 0, "TASK_INTERRUPTIBLE": 1,
                                     "TASK_DEAD": 128}}
      },
      "symbols": {
        "init_task": {"address": 18446744071578845184,
                      "type": {"kind": "struct", "name": "task_struct"}},
        "linux_banner": {"address": 18446744071578849280,
                         "constant_data": "TGludXggdmVyc2lvbiA2LjEuMAoA"},
        "jiffies": {"address": 18446744071578853376,
                    "type": {"kind": "base", "name": "unsigned long long"}}
      }
    }"#;

    fn compile(json: &str) -> Result<SymbolTable> {
        let source = load_slice(json.as_bytes(), &DecompressLimits::default())?;
        SymbolTable::compile_source(source, &CompileOptions::default())
    }

    fn compiled(json: &str) -> SymbolTable {
        compile(json).unwrap_or_else(|e| panic!("fixture must compile: {e}"))
    }

    /// `LINUX` with an anonymous member whose own child collides with it, the
    /// shape Debian 3.2 carries 20 times over: dwarf2json names an anonymous
    /// member `unnamed_field_0`, and the aggregate lifted into it has a member
    /// of that name too.
    fn with_lift_collision() -> String {
        LINUX.replace(
            r#""task_struct": {"size": 64, "kind": "struct", "fields": {"#,
            r#""anon_inner": {"size": 8, "kind": "struct", "fields": {
                 "unnamed_field_0": {"offset": 0, "type": {"kind": "base", "name": "int"}},
                 "real_name": {"offset": 4, "type": {"kind": "base", "name": "int"}}
               }},
               "task_struct": {"size": 64, "kind": "struct", "fields": {
                 "unnamed_field_0": {"offset": 0, "anonymous": true,
                                     "type": {"kind": "struct", "name": "anon_inner"}},"#,
        )
    }

    #[test]
    fn a_lifted_name_collision_costs_one_name_not_the_whole_table() {
        // This refused the entire document until Debian 3.2 was run against a
        // real image: 4118 types, 20 collisions, every one of them on a
        // placeholder no stage asks for, and the Linux tier emitted nothing at
        // all as a result.
        let table = compiled(&with_lift_collision());
        let aggregate = table.aggregate("task_struct").expect("the type survives");

        // The colliding name addresses nothing...
        assert_eq!(aggregate.ambiguity("unnamed_field_0"), Some(2));
        assert!(!aggregate.has_member("unnamed_field_0"));
        assert_eq!(aggregate.ambiguous_names(), vec!["unnamed_field_0"]);

        // ...and says so as a damaged reading, not an absent field.
        let err = table
            .member_offset("task_struct", "unnamed_field_0")
            .expect_err("an ambiguous name must not resolve");
        assert_eq!(err.class(), "ambiguous_member", "{err}");

        // The real members lifted alongside it are reachable, which is the
        // whole point of not refusing the table.
        assert_eq!(table.member_offset("task_struct", "real_name").unwrap(), 4);
        assert_eq!(table.member_offset("task_struct", "pid").unwrap(), 16);
    }

    #[test]
    fn a_member_offset_is_the_one_the_document_declared() {
        let table = compiled(LINUX);
        assert_eq!(table.member_offset("task_struct", "pid").unwrap(), 16);
        assert_eq!(table.member_offset("task_struct", "comm").unwrap(), 32);
        assert_eq!(table.member_offset("list_head", "prev").unwrap(), 8);
        assert!(table.has_member("task_struct", "pid"));
    }

    #[test]
    fn a_member_this_build_does_not_have_is_an_error_not_offset_zero() {
        let table = compiled(LINUX);
        let err = table
            .member_offset("task_struct", "cap_ambient")
            .expect_err("a missing member must not resolve");
        assert!(err.to_string().contains("task_struct"), "{err}");
        assert!(err.to_string().contains("cap_ambient"), "{err}");
        assert!(!table.has_member("task_struct", "cap_ambient"));

        let err = table
            .member_offset("nonexistent_struct", "pid")
            .expect_err("a missing type must not resolve");
        assert!(matches!(err, SymbolError::UnknownType(_)), "{err}");
    }

    #[test]
    fn asking_a_base_type_for_a_member_says_what_it_actually_is() {
        let table = compiled(LINUX);
        let err = table
            .member_offset("int", "pid")
            .expect_err("a base type has no members");
        assert!(matches!(err, SymbolError::WrongTypeKind { .. }), "{err}");
        assert!(err.to_string().contains("base type"), "{err}");
    }

    #[test]
    fn sizes_come_from_the_table_and_never_from_an_assumption() {
        let table = compiled(LINUX);
        assert_eq!(table.size_of("task_struct").unwrap(), 64);
        assert_eq!(table.size_of("int").unwrap(), 4);
        assert_eq!(table.pointer_size(), 8);

        // An array is its count times its element size.
        let comm = table.member("task_struct", "comm").unwrap();
        assert_eq!(table.size_of_id(comm.ty).unwrap(), 16);

        // An enum takes its width from its base type, not from `enums[].size`.
        assert_eq!(table.size_of("task_state").unwrap(), 4);

        // A pointer takes its width from the `pointer` base type.
        let next = table.member("list_head", "next").unwrap();
        assert_eq!(table.size_of_id(next.ty).unwrap(), 8);
    }

    #[test]
    fn a_function_type_has_no_size_and_says_so() {
        let table = compiled(LINUX);
        let handler = table.member("task_struct", "handler").unwrap();
        // The pointer to a function has a size; the function itself does not.
        assert_eq!(table.size_of_id(handler.ty).unwrap(), 8);
        let function = match &table.entry(handler.ty).unwrap().kind {
            TypeKind::Pointer { subtype, .. } => *subtype,
            other => panic!("expected a pointer, got {}", other.as_str()),
        };
        let err = table
            .size_of_id(function)
            .expect_err("a function type has no size");
        assert!(matches!(err, SymbolError::OpaqueType(_)), "{err}");
    }

    #[test]
    fn a_self_referential_type_compiles_because_a_cycle_is_just_an_index() {
        let table = compiled(LINUX);
        let next = table.member("list_head", "next").unwrap();
        let target = match &table.entry(next.ty).unwrap().kind {
            TypeKind::Pointer { subtype, .. } => *subtype,
            other => panic!("expected a pointer, got {}", other.as_str()),
        };
        assert_eq!(table.entry(target).unwrap().name.as_ref(), "list_head");
    }

    #[test]
    fn an_enum_maps_both_ways_and_invents_nothing() {
        let table = compiled(LINUX);
        assert_eq!(table.enum_value("task_state", "TASK_DEAD").unwrap(), 128);
        assert_eq!(
            table.enum_constant_name("task_state", 1).unwrap(),
            Some("TASK_INTERRUPTIBLE")
        );
        assert_eq!(
            table.enum_constant_name("task_state", 7).unwrap(),
            None,
            "an undefined value gets no label at all"
        );
        assert!(table.enum_value("task_state", "TASK_ZOMBIE").is_err());
    }

    #[test]
    fn a_symbol_address_survives_above_two_to_the_fifty_three() {
        let table = compiled(LINUX);
        assert_eq!(
            table.symbol_address("init_task").unwrap(),
            0xFFFF_FFFF_8100_0000
        );
        assert!(table.has_symbol("jiffies"));
        assert!(table.symbol("no_such_symbol").is_err());
    }

    #[test]
    fn the_symbol_mask_is_applied_and_recorded_rather_than_hidden() {
        let mut table = compiled(LINUX);
        assert_eq!(table.symbol_mask(), u64::MAX);
        table.set_symbol_mask(0xFFFF_FFFF);
        assert_eq!(table.symbol_address("init_task").unwrap(), 0x8100_0000);
        assert_eq!(table.to_json()["symbol_mask"], 0xFFFF_FFFFu64);
    }

    #[test]
    fn reverse_symbolication_finds_the_symbol_at_or_below_an_address() {
        let table = compiled(LINUX);
        let (symbol, distance) = table
            .nearest_symbol(0xFFFF_FFFF_8100_0040)
            .expect("an address above the first symbol resolves");
        assert_eq!(symbol.name.as_ref(), "init_task");
        assert_eq!(distance, 0x40);

        let (symbol, distance) = table
            .nearest_symbol(0xFFFF_FFFF_8100_1000)
            .expect("resolves to the next symbol down");
        assert_eq!(symbol.name.as_ref(), "linux_banner");
        assert_eq!(distance, 0);

        assert!(
            table.nearest_symbol(0x1000).is_none(),
            "an address below every symbol resolves to nothing, not to the first"
        );
    }

    #[test]
    fn a_symbols_constant_data_decodes_to_the_banner() {
        let table = compiled(LINUX);
        let banner = table
            .symbol("linux_banner")
            .unwrap()
            .constant_bytes()
            .unwrap()
            .expect("constant data is present");
        assert_eq!(banner, b"Linux version 6.1.0\n\0");
        assert_eq!(
            table.identity().identifier.as_deref(),
            Some("Linux version 6.1.0")
        );
    }

    #[test]
    fn anonymous_members_are_lifted_with_their_offsets_accumulated() {
        // Every field after an anonymous member sits at the wrong offset if the
        // lift is skipped, and modern Linux ISFs are full of them.
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"}
          },
          "user_types": {
            "__inner": {"size": 8, "kind": "union", "fields": {
              "left": {"offset": 0, "type": {"kind": "base", "name": "int"}},
              "right": {"offset": 4, "type": {"kind": "base", "name": "int"}}
            }},
            "outer": {"size": 24, "kind": "struct", "fields": {
              "head": {"offset": 0, "type": {"kind": "base", "name": "int"}},
              "__unnamed_1": {"offset": 8, "anonymous": true,
                              "type": {"kind": "union", "name": "__inner"}},
              "tail": {"offset": 16, "type": {"kind": "base", "name": "int"}}
            }}
          },
          "enums": {},
          "symbols": {}
        }"#;
        let table = compiled(json);
        assert_eq!(table.member_offset("outer", "head").unwrap(), 0);
        assert_eq!(
            table.member_offset("outer", "left").unwrap(),
            8,
            "the lifted member sits at parent offset plus its own"
        );
        assert_eq!(table.member_offset("outer", "right").unwrap(), 12);
        assert_eq!(table.member_offset("outer", "tail").unwrap(), 16);
        assert_eq!(
            table
                .member("outer", "left")
                .unwrap()
                .lifted_from
                .as_deref(),
            Some("__unnamed_1")
        );
        // The anonymous member itself is still addressable.
        assert!(table.has_member("outer", "__unnamed_1"));
    }

    #[test]
    fn anonymous_members_are_not_lifted_before_format_six_two_zero() {
        let json = r#"{
          "metadata": {"format": "6.1.0"},
          "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"}
          },
          "user_types": {
            "__inner": {"size": 8, "kind": "union", "fields": {
              "left": {"offset": 0, "type": {"kind": "base", "name": "int"}}
            }},
            "outer": {"size": 16, "kind": "struct", "fields": {
              "__unnamed_1": {"offset": 8, "anonymous": true,
                              "type": {"kind": "union", "name": "__inner"}}
            }}
          },
          "enums": {},
          "symbols": {}
        }"#;
        let table = compiled(json);
        assert!(
            !table.has_member("outer", "left"),
            "lifting is a 6.2.0 behaviour and must not be applied to older files"
        );
    }

    #[test]
    fn a_lifted_member_colliding_with_a_real_identifier_makes_that_name_unaddressable() {
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"}
          },
          "user_types": {
            "__inner": {"size": 8, "kind": "union", "fields": {
              "value": {"offset": 0, "type": {"kind": "base", "name": "int"}}
            }},
            "outer": {"size": 24, "kind": "struct", "fields": {
              "value": {"offset": 0, "type": {"kind": "base", "name": "int"}},
              "__unnamed_1": {"offset": 8, "anonymous": true,
                              "type": {"kind": "union", "name": "__inner"}}
            }}
          },
          "enums": {},
          "symbols": {}
        }"#;
        // Unlike the placeholder collisions Debian 3.2 is full of, `value` is a
        // name a stage could genuinely ask for, and two members answer to it.
        // The table still compiles -- one unaddressable name is not grounds to
        // discard every other type -- but the name itself must refuse to
        // resolve, because picking either member would report real bytes from
        // the wrong field as fact.
        let table = compile(json).expect("one ambiguous name must not refuse the document");
        let outer = table.aggregate("outer").expect("the type survives");
        assert_eq!(outer.ambiguity("value"), Some(2));
        assert!(!outer.has_member("value"));

        let err = table
            .member_offset("outer", "value")
            .expect_err("an ambiguous name must not resolve");
        assert_eq!(err.class(), "ambiguous_member", "{err}");
        let text = err.to_string();
        assert!(text.contains("outer") && text.contains("value"), "{text}");
    }

    #[test]
    fn a_type_that_contains_itself_anonymously_is_refused_rather_than_looping() {
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {"pointer": {"size": 8, "signed": false, "kind": "int",
                                     "endian": "little"}},
          "user_types": {
            "loop_a": {"size": 8, "kind": "struct", "fields": {
              "inner": {"offset": 0, "anonymous": true,
                        "type": {"kind": "struct", "name": "loop_b"}}}},
            "loop_b": {"size": 8, "kind": "struct", "fields": {
              "inner": {"offset": 0, "anonymous": true,
                        "type": {"kind": "struct", "name": "loop_a"}}}}
          },
          "enums": {},
          "symbols": {}
        }"#;
        let err = compile(json).expect_err("a cycle of anonymous members must not compile");
        assert!(err.to_string().contains("contains itself"), "{err}");
    }

    #[test]
    fn an_unresolved_local_reference_is_recorded_and_fails_only_at_use() {
        let json = LINUX.replace(r#""name": "unsigned long long""#, r#""name": "u64""#);
        let table = compiled(&json);
        assert_eq!(table.diagnostics().unresolved_total, 1);
        assert!(
            table.diagnostics().unresolved[0].contains("u64"),
            "{:?}",
            table.diagnostics()
        );

        // The symbol still exists and its address is still exact; only its
        // layout is unknown, and asking for that is an error.
        let jiffies = table.symbol("jiffies").unwrap();
        let ty = jiffies.ty.expect("the symbol has a type");
        let err = table
            .size_of_id(ty)
            .expect_err("an unbound type has no size");
        assert!(matches!(err, SymbolError::UnresolvedType { .. }), "{err}");
    }

    #[test]
    fn a_cross_table_reference_is_recorded_as_external_not_as_a_defect() {
        let json = r#"{
          "metadata": {"format": "4.0.0"},
          "base_types": {"pointer": {"size": 8, "signed": false, "kind": "int",
                                     "endian": "little"}},
          "user_types": {"_POOL_HEADER": {"size": 16, "kind": "struct", "fields": {
            "ProcessBilled": {"offset": 8, "type": {"kind": "pointer",
              "subtype": {"kind": "struct", "name": "nt_symbols!_EPROCESS"}}}}}},
          "enums": {},
          "symbols": {}
        }"#;
        let table = compiled(json);
        assert_eq!(table.diagnostics().external_total, 1);
        assert_eq!(table.diagnostics().unresolved_total, 0);
        assert!(table.diagnostics().external[0].contains("nt_symbols!_EPROCESS"));
        assert_eq!(
            table
                .member_offset("_POOL_HEADER", "ProcessBilled")
                .unwrap(),
            8
        );
    }

    #[test]
    fn an_array_whose_declared_count_overflows_is_an_error_not_a_wrapped_size() {
        let json = LINUX.replace(r#""count": 16"#, &format!(r#""count": {}"#, u64::MAX));

        // The overflow is caught at admission, not deferred to the first read:
        // a document declaring an array this size is refused outright, so no
        // caller can ever hold a table whose member sizes wrap. That is the
        // stronger guarantee, and the rejection has to name the culprit for the
        // examiner to act on it.
        let err = compile(&json).expect_err("an overflowing array count must not be admitted");
        let message = err.to_string();
        assert!(
            message.contains("task_struct") && message.contains("comm"),
            "the rejection must name the offending type and member: {message}"
        );
    }

    #[test]
    fn an_array_whose_element_width_makes_its_extent_overflow_is_refused_too() {
        // The u64::MAX-count case above is caught by the *offset addition*, so it
        // proves nothing about the multiplication that actually wraps. A
        // 2^63-element array of 4-byte ints has no representable size at all,
        // and admitting it would leave the wrap latent behind whichever plugin
        // first asked how wide `comm` is.
        let json = LINUX
            .replace(r#""count": 16"#, &format!(r#""count": {}"#, 1u64 << 63))
            .replace(r#""name": "char""#, r#""name": "int""#);
        let err = compile(&json).expect_err("an array with no computable size must not compile");
        let report = err.report().expect("a rejection carries its report");
        let failure = report.failures().next().expect("a failing gate");
        assert_eq!(failure.gate, Gate::Structural);
        assert!(
            failure
                .violations
                .iter()
                .any(|v| v.contains("comm") && v.contains("does not fit in 64 bits")),
            "{:?}",
            failure.violations
        );
    }

    #[test]
    fn lifting_anonymous_members_is_charged_against_the_arena_budget() {
        // Each level doubles its parent's member count, so twenty-four levels of
        // two anonymous members apiece describe tens of millions of members in
        // about two kilobytes of JSON. Uncharged, that is an out-of-memory kill
        // mid-examination rather than a load failure.
        const LEVELS: usize = 24;
        let mut types = String::new();
        for level in 0..LEVELS {
            types.push_str(&format!(
                r#""b{level}": {{"size": 8, "kind": "struct", "fields": {{
                     "a": {{"offset": 0, "anonymous": true,
                            "type": {{"kind": "struct", "name": "b{}"}}}},
                     "b": {{"offset": 0, "anonymous": true,
                            "type": {{"kind": "struct", "name": "b{}"}}}}
                   }}}},"#,
                level + 1,
                level + 1
            ));
        }
        types.push_str(&format!(
            r#""b{LEVELS}": {{"size": 8, "kind": "struct", "fields": {{
                 "leaf": {{"offset": 0, "type": {{"kind": "base", "name": "int"}}}}
               }}}}"#
        ));
        let json = format!(
            r#"{{
              "metadata": {{"format": "6.2.0"}},
              "base_types": {{
                "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
                "int": {{"size": 4, "signed": true, "kind": "int", "endian": "little"}}
              }},
              "user_types": {{{types}}},
              "enums": {{}},
              "symbols": {{}}
            }}"#
        );

        let options = CompileOptions {
            max_table_bytes: 1024 * 1024,
            ..CompileOptions::default()
        };
        let source = load_slice(json.as_bytes(), &DecompressLimits::default()).expect("loads");
        let err = SymbolTable::compile_source(source, &options)
            .expect_err("an anonymous-member explosion must not be built");
        assert!(
            matches!(err, SymbolError::TableTooLarge { .. }),
            "the budget must stop it, not the heap: {err}"
        );
    }

    #[test]
    fn a_type_name_declared_in_two_blocks_is_refused_rather_than_silently_picked() {
        // `int` as both a base type and a struct: the blocks are separate
        // namespaces, so this parses, and a lookup that does not name a block
        // would otherwise hand back the 128-byte struct where the 4-byte
        // integer was meant, which is a wrong stride applied to real bytes.
        let json = LINUX.replace(
            r#""list_head": {"size": 16,"#,
            r#""int": {"size": 128, "kind": "struct", "fields": {}}, "list_head": {"size": 16,"#,
        );
        let table = compiled(&json);

        let err = table
            .type_id("int")
            .expect_err("an ambiguous name must not resolve to either block");
        assert!(err.to_string().contains("more than one"), "{err}");
        assert!(table.size_of("int").is_err());
        assert!(!table.has_type("int"));
        assert!(table
            .admission()
            .warnings
            .iter()
            .any(|w| w.contains("ambiguous")));

        // Resolution through a descriptor is unaffected: it named its block, so
        // `pid` is still the four-byte integer it was declared as.
        let pid = table
            .member("task_struct", "pid")
            .expect("pid is unaffected");
        assert_eq!(pid.offset, 16);
        assert_eq!(table.size_of_id(pid.ty).unwrap(), 4);
    }

    #[test]
    fn masked_reverse_symbolication_does_not_fabricate_a_distance() {
        // The mask is applied to the query, so the address-ordered index has to
        // be under the same mask. Searching a masked address against unmasked
        // entries either finds nothing or, worse, saturates the subtraction and
        // reports an unrelated symbol at a distance of zero.
        let mut table = compiled(LINUX);
        table.set_symbol_mask(0xFFFF_FFFF);

        let (symbol, distance) = table
            .nearest_symbol(0xFFFF_FFFF_8100_0040)
            .expect("a masked address still resolves");
        assert_eq!(symbol.name.as_ref(), "init_task");
        assert_eq!(distance, 0x40);

        let (symbol, distance) = table
            .nearest_symbol(0x8100_1004)
            .expect("an already-masked address resolves the same way");
        assert_eq!(symbol.name.as_ref(), "linux_banner");
        assert_eq!(distance, 4);

        assert!(
            table.nearest_symbol(0x1000).is_none(),
            "an address below every masked symbol still resolves to nothing"
        );
    }

    #[test]
    fn a_gzipped_symbol_file_compiles_to_the_same_table() {
        let plain = compiled(LINUX);
        let compressed = gzip(LINUX.as_bytes());
        let source = load_slice(&compressed, &DecompressLimits::default()).expect("loads");
        let table =
            SymbolTable::compile_source(source, &CompileOptions::default()).expect("compiles");

        assert_eq!(
            table.member_offset("task_struct", "pid").unwrap(),
            plain.member_offset("task_struct", "pid").unwrap()
        );
        assert_eq!(
            table.provenance().json_sha256,
            plain.provenance().json_sha256,
            "the same JSON is the same evidence however it was stored"
        );
        assert_ne!(
            table.provenance().source_sha256,
            plain.provenance().source_sha256
        );
    }

    #[test]
    fn a_rejected_document_yields_the_whole_report_and_no_table() {
        // A member past the declared size no longer refuses a document -- the
        // netscan overlays proved the size is the untrustworthy half of that
        // pair -- so this exercises the rejection path through a shape that is
        // still incoherent: a type declaring no bytes whose members occupy
        // them.
        let json = LINUX.replace(
            r#""task_struct": {"size": 64"#,
            r#""task_struct": {"size": 0"#,
        );
        let err = compile(&json).expect_err("a zero-size type with real members must not compile");
        let report = err.report().expect("a rejection carries its report");
        assert_eq!(report.state(), AdmissionState::Rejected);
        let failure = report.failures().next().expect("a failing gate");
        assert_eq!(failure.gate, Gate::Structural);
        assert!(failure.violations[0].contains("task_struct"), "{failure:?}");
    }

    #[test]
    fn a_member_that_ends_past_its_struct_is_recorded_by_the_layout_check() {
        // Offset 60 is inside a 64-byte struct, but a 16-byte array at 60 is
        // not: this is the check that needs resolved sizes. It reports rather
        // than refuses, for the same reason as the offset-only check -- the
        // declared size is a producer's stub and the member is read at its own
        // offset for its own width. What must not happen is that it goes
        // unsaid, so the caveat is the assertion.
        let json = LINUX.replace(r#""comm": {"offset": 32"#, r#""comm": {"offset": 60"#);
        let table = compile(&json).expect("an overrunning member is recorded, not refused");
        let caveats: Vec<&str> = table
            .admission()
            .gates
            .iter()
            .flat_map(|gate| gate.caveats.iter().map(String::as_str))
            .collect();
        assert!(
            caveats
                .iter()
                .any(|v| v.contains("comm") && v.contains("past the type's own size")),
            "{:?}",
            caveats
        );
    }

    #[test]
    fn a_table_with_no_image_and_no_expected_identity_is_unverified_not_verified() {
        let table = compiled(LINUX);
        assert_eq!(table.state(), AdmissionState::Unverified);
        assert_eq!(table.to_json()["symbol_confidence"], "unverified");
        let unproved = table.admission().unproved_checks();
        assert!(unproved.contains(&"image_sanity"), "{unproved:?}");
        assert!(unproved.contains(&"identity"), "{unproved:?}");
    }

    #[test]
    fn a_table_proved_on_every_gate_is_verified() {
        let source = load_slice(LINUX.as_bytes(), &DecompressLimits::default()).expect("loads");
        let options = CompileOptions {
            validation: ValidationOptions::new()
                .expect_identifier("Linux version 6.1.0")
                .expect_architecture(Architecture::X64),
            ..CompileOptions::default()
        };
        let mut table = SymbolTable::compile_source(source, &options).expect("compiles");
        assert_eq!(
            table.state(),
            AdmissionState::Unverified,
            "gate 4 has not run yet, and unproved is not proved"
        );

        table.record_gate(GateResult::pass(
            Gate::ImageSanity,
            "init_task_comm",
            "init_task.comm reads 'swapper/0' and init_task.pid is 0",
        ));
        assert_eq!(table.state(), AdmissionState::Verified);
        assert_eq!(table.to_json()["symbol_confidence"], "verified");
    }

    #[test]
    fn a_failing_gate_four_check_recorded_later_rejects_an_already_built_table() {
        let source = load_slice(LINUX.as_bytes(), &DecompressLimits::default()).expect("loads");
        let mut table =
            SymbolTable::compile_source(source, &CompileOptions::default()).expect("compiles");
        table.record_gate(GateResult::fail(
            Gate::ImageSanity,
            "eprocess_pid_sane",
            "every UniqueProcessId read through this table is implausible",
        ));
        assert_eq!(table.state(), AdmissionState::Rejected);
        assert!(!table.state().permits_analysis());
    }

    #[test]
    fn an_inconclusive_gate_four_check_leaves_a_smeared_capture_analysable() {
        let source = load_slice(LINUX.as_bytes(), &DecompressLimits::default()).expect("loads");
        let mut table =
            SymbolTable::compile_source(source, &CompileOptions::default()).expect("compiles");
        table.record_gate(GateResult::inconclusive(
            Gate::ImageSanity,
            "task_list_closes",
            "the task list does not close; the capture is smeared",
        ));
        assert_eq!(table.state(), AdmissionState::Unverified);
        assert!(
            table.state().permits_analysis(),
            "damaged evidence is not a wrong symbol table"
        );
    }

    #[test]
    fn a_table_whose_identity_differs_from_the_image_does_not_compile() {
        let source = load_slice(LINUX.as_bytes(), &DecompressLimits::default()).expect("loads");
        let options = CompileOptions {
            validation: ValidationOptions::new().expect_identifier("Linux version 5.15.0"),
            ..CompileOptions::default()
        };
        let err = SymbolTable::compile_source(source, &options)
            .expect_err("a table for another build must be refused");
        let report = err.report().expect("a rejection carries its report");
        let failure = report.failures().next().expect("a failing gate");
        assert_eq!(failure.gate, Gate::Identity);
    }

    #[test]
    fn a_table_whose_pointer_width_contradicts_the_paging_mode_does_not_compile() {
        let source = load_slice(LINUX.as_bytes(), &DecompressLimits::default()).expect("loads");
        let options = CompileOptions {
            validation: ValidationOptions::new().expect_architecture(Architecture::X86),
            ..CompileOptions::default()
        };
        let err = SymbolTable::compile_source(source, &options)
            .expect_err("an x86 image must not accept an x64 table");
        let failure = err
            .report()
            .expect("a rejection carries its report")
            .failures()
            .next()
            .expect("a failing gate")
            .clone();
        assert_eq!(failure.gate, Gate::Architecture);
    }

    #[test]
    fn the_arena_budget_fails_closed_rather_than_growing_without_bound() {
        let options = CompileOptions {
            max_table_bytes: 256,
            ..CompileOptions::default()
        };
        let source = load_slice(LINUX.as_bytes(), &DecompressLimits::default()).expect("loads");
        let err = SymbolTable::compile_source(source, &options)
            .expect_err("a table beyond its budget must not be built");
        assert!(matches!(err, SymbolError::TableTooLarge { .. }), "{err}");
    }

    #[test]
    fn reading_a_member_through_the_table_uses_the_declared_offset_and_width() {
        let table = compiled(LINUX);
        let base = 0x1_0000u64;
        let mut bytes = vec![0u8; 64];
        bytes[16..20].copy_from_slice(&4u32.to_le_bytes()); // pid
        bytes[24..28].copy_from_slice(&128u32.to_le_bytes()); // state
        let image = FakeImage::new(base, bytes);

        assert_eq!(
            table
                .read_member_unsigned(&image, base, "task_struct", "pid")
                .unwrap(),
            4
        );
        assert_eq!(
            table
                .read_member_unsigned(&image, base, "task_struct", "state")
                .unwrap(),
            128,
            "an enum reads at the width of its base type"
        );
    }

    #[test]
    fn reading_a_bitfield_extracts_exactly_its_bits() {
        let table = compiled(LINUX);
        let base = 0x2_0000u64;
        let mut bytes = vec![0u8; 64];
        // in_execve is bit 3 of a 4-byte unit at offset 48.
        bytes[48..52].copy_from_slice(&0b1000u32.to_le_bytes());
        let image = FakeImage::new(base, bytes);
        assert_eq!(
            table
                .read_member_unsigned(&image, base, "task_struct", "in_execve")
                .unwrap(),
            1
        );

        let mut bytes = vec![0u8; 64];
        bytes[48..52].copy_from_slice(&0b0111u32.to_le_bytes());
        let image = FakeImage::new(base, bytes);
        assert_eq!(
            table
                .read_member_unsigned(&image, base, "task_struct", "in_execve")
                .unwrap(),
            0,
            "neighbouring bits must not leak into the value"
        );
    }

    #[test]
    fn a_bitfield_inside_a_bitfield_is_refused_rather_than_using_one_of_the_two_ranges() {
        // Nothing in the document stops one bitfield being declared inside
        // another, and the two ranges select different bits of the same real
        // bytes. Keeping the inner one would report bit 3 where bits 0 to 7
        // were asked for, which reads as an ordinary field value.
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"}
          },
          "user_types": {
            "flags": {"size": 8, "kind": "struct", "fields": {
              "nested": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0,
                         "bit_length": 8, "type": {"kind": "bitfield", "bit_position": 3,
                         "bit_length": 1, "type": {"kind": "base", "name": "unsigned int"}}}}
            }}
          },
          "enums": {},
          "symbols": {}
        }"#;
        let table = compiled(json);
        let image = FakeImage::new(0, vec![0xFF; 8]);
        let err = table
            .read_member_unsigned(&image, 0, "flags", "nested")
            .expect_err("two bit ranges do not describe one field");
        assert!(
            err.to_string().contains("bitfield inside a bitfield"),
            "{err}"
        );
    }

    #[test]
    fn reading_a_member_that_falls_in_a_hole_fails_instead_of_reading_zeros() {
        let table = compiled(LINUX);
        let base = 0x3_0000u64;
        let image = FakeImage::new(base, vec![0xAA; 64]).with_hole(base + 16, base + 32);
        let err = table
            .read_member_unsigned(&image, base, "task_struct", "pid")
            .expect_err("a member in a hole must not read as zero");
        assert!(matches!(err, SymbolError::Probe { .. }), "{err}");
        assert!(err.to_string().contains("task_struct.pid"), "{err}");
    }

    #[test]
    fn reading_an_aggregate_member_as_an_integer_is_refused() {
        let table = compiled(LINUX);
        let image = FakeImage::new(0, vec![0u8; 64]);
        let err = table
            .read_member_unsigned(&image, 0, "task_struct", "tasks")
            .expect_err("a struct is not an integer");
        assert!(matches!(err, SymbolError::WrongTypeKind { .. }), "{err}");
    }

    #[test]
    fn a_bitfield_outside_its_storage_unit_is_refused_even_when_it_lies_past_the_declared_size() {
        // The relaxation admits members declared past their type's size. It
        // must not carry the bitfield check out with it. `bit_position +
        // bit_length` is what the extraction shifts and masks by, so a range
        // outside the storage unit hands back bits that were never the field's
        // -- false evidence, not untidiness -- and that check is named in the
        // brief as one that stays fatal. It is reachable only because it now
        // runs before the offset check: while it ran after, a single `continue`
        // hid it for exactly the files the relaxation newly admits.
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"}
          },
          "user_types": {
            "endpoint": {"size": 8, "kind": "struct", "fields": {
              "state": {"offset": 4096, "type": {"kind": "bitfield", "bit_position": 30,
                        "bit_length": 8, "type": {"kind": "base", "name": "unsigned int"}}}
            }}
          },
          "enums": {},
          "symbols": {}
        }"#;
        let err = compile(json).expect_err("a bit range outside its unit must not be admitted");
        let report = err.report().expect("a rejection carries its report");
        let failure = report.failures().next().expect("a failing gate");
        assert!(
            failure
                .violations
                .iter()
                .any(|v| v.contains("state") && v.contains("storage unit")),
            "{:?}",
            failure.violations
        );
        // And the offset it also disagrees about is still recorded, so the
        // rejection says everything it found rather than the first thing.
        assert!(report.has_caveats(), "the offset reservation was dropped");
    }

    #[test]
    fn a_lifted_name_collision_reaches_the_admission_report() {
        // Costing one name instead of the whole document is the right trade
        // only if the report says the name was lost. `has_member` answers false
        // for an ambiguous name, and a caller following the "ask, then carry
        // Option" discipline reads that as "this build does not have the
        // field" -- a different claim from "this table cannot say which bytes
        // are its". Without this on the record, that difference reaches nobody.
        let table = compiled(&with_lift_collision());
        let admission = table.admission();
        assert!(
            admission.has_caveats(),
            "a name was made unaddressable in silence"
        );
        let caveats = admission.caveats();
        let caveat = caveats
            .iter()
            .find(|c| c.contains("unnamed_field_0"))
            .unwrap_or_else(|| panic!("the caveat must name the lost name: {caveats:?}"));
        assert!(
            caveat.contains("task_struct") && caveat.contains("refused"),
            "the caveat must name the type and say the lookup refuses: {caveat}"
        );
        assert_eq!(table.to_json()["admission"]["admitted_with_caveats"], true);
    }

    /// A netscan overlay pack reduced to what matters: a hand-written table
    /// whose declared type sizes are stubs the producer never measured.
    ///
    /// `_TCP_ENDPOINT.Owner` at 752 inside a declared 632 bytes is verbatim
    /// from `netscan-win10-20348-x64.json`; `_IN_ADDR` is Volatility's union of
    /// a 4-byte and a 16-byte address, declared 6 bytes long, and it appears in
    /// all 25 packs upstream ships.
    const OVERLAY: &str = r#"{
      "metadata": {"format": "6.2.0", "producer": {"name": "dgmcdona-by-hand", "version": "1"}},
      "base_types": {
        "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
        "unsigned char": {"size": 1, "signed": false, "kind": "char", "endian": "little"}
      },
      "user_types": {
        "_TCP_ENDPOINT": {"size": 632, "kind": "struct", "fields": {
          "Owner": {"offset": 752, "type": {"kind": "base", "name": "pointer"}}
        }},
        "_IN_ADDR": {"size": 6, "kind": "union", "fields": {
          "addr4": {"offset": 0, "type": {"kind": "array", "count": 4,
                    "subtype": {"kind": "base", "name": "unsigned char"}}},
          "addr6": {"offset": 0, "type": {"kind": "array", "count": 16,
                    "subtype": {"kind": "base", "name": "unsigned char"}}}
        }}
      },
      "enums": {},
      "symbols": {}
    }"#;

    #[test]
    fn an_overlay_whose_declared_sizes_are_stubs_compiles_with_its_caveats_on_the_record() {
        // Before this, gate 1 rejected all 25 of Volatility's netscan packs and
        // `windows.netscan` and `windows.netstat` produced nothing at all on
        // every modern build. Admission is only half of the fix: the report has
        // to carry why it was admitted, or a quiet wrong answer has replaced a
        // loud one.
        let table = compiled(OVERLAY);
        assert_ne!(table.state(), AdmissionState::Rejected);

        let admission = table.admission();
        assert!(admission.has_caveats(), "the pack was admitted in silence");
        let caveats = admission.caveats();
        assert!(
            caveats
                .iter()
                .any(|c| c.contains("_TCP_ENDPOINT") && c.contains("Owner") && c.contains("752")),
            "the member past the declared size must be named: {caveats:?}"
        );
        assert!(
            caveats
                .iter()
                .any(|c| c.contains("_IN_ADDR") && c.contains("addr6")),
            "the member whose tail runs past the declared size must be named: {caveats:?}"
        );

        // And it reaches artifact metadata, which is what a case record quotes.
        let json = table.to_json();
        assert_eq!(json["admission"]["admitted_with_caveats"], true);
        assert!(json["admission"]["caveats"]
            .as_array()
            .expect("an array")
            .iter()
            .any(|c| c.as_str().is_some_and(|c| c.contains("_TCP_ENDPOINT"))));
    }

    #[test]
    fn the_member_past_the_declared_size_still_reads_at_its_own_offset() {
        // Why the caveat is sound rather than merely convenient. `Owner` is
        // read at base+752 with the pointer's own width, exactly as the file
        // says, and the declared 632 never enters the arithmetic. The 101 owner
        // attributions in the Windows 11 netscan oracle agree with pslist on
        // both pid and image name because of this.
        let table = compiled(OVERLAY);
        let base = 0x5_0000u64;
        let mut bytes = vec![0u8; 1024];
        bytes[752..760].copy_from_slice(&0xFFFF_8000_1234_5678u64.to_le_bytes());
        let image = FakeImage::new(base, bytes);
        assert_eq!(
            table
                .read_member_unsigned(&image, base, "_TCP_ENDPOINT", "Owner")
                .expect("the member is read through its own offset"),
            0xFFFF_8000_1234_5678
        );
    }

    #[test]
    fn a_type_whose_members_contradict_its_declared_size_says_so_when_asked() {
        // The fail-closed hook for the one read a caveat does not make safe: a
        // caller that fetches `size_of(type)` bytes and slices members out of
        // the buffer would truncate `Owner` and `addr6` to nothing, and a zero
        // is indistinguishable from a real value.
        let table = compiled(OVERLAY);
        assert!(table.declared_size_is_stub("_TCP_ENDPOINT").unwrap());
        assert!(table.declared_size_is_stub("_IN_ADDR").unwrap());

        // A measured type answers the other way, so the hook is a real
        // discriminator rather than a constant.
        let sound = compiled(LINUX);
        assert!(!sound.declared_size_is_stub("task_struct").unwrap());
        assert!(!sound.declared_size_is_stub("list_head").unwrap());
        assert!(sound.declared_size_is_stub("no_such_type").is_err());
    }

    #[test]
    fn reading_a_member_typed_by_an_enum_of_unstated_width_fails_closed() {
        // The one relaxation that would be dangerous if it stopped at
        // admission. dwarf2json emits `base: "void"` for an enum whose
        // underlying type the compilation unit never settled -- Debian 3.2's
        // `migrate_mode` is exactly that -- so the document is admitted, but
        // the width genuinely is unknown and a read must not invent one.
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
          },
          "user_types": {
            "holder": {"size": 8, "kind": "struct", "fields": {
              "mode": {"offset": 0, "type": {"kind": "enum", "name": "migrate_mode"}}
            }}
          },
          "enums": {"migrate_mode": {"size": 0, "base": "void", "constants": {"MIGRATE_ASYNC": 0}}},
          "symbols": {}
        }"#;
        let table = compiled(json);
        assert_ne!(table.state(), AdmissionState::Rejected, "the enum is real");
        assert!(table.admission().has_caveats());

        let image = FakeImage::new(0, vec![0xFF; 64]);
        let err = table
            .read_member_unsigned(&image, 0, "holder", "mode")
            .expect_err("a width nobody stated must not be guessed at");
        assert!(matches!(err, SymbolError::WrongTypeKind { .. }), "{err}");
        assert!(err.to_string().contains("holder.mode"), "{err}");
    }

    #[test]
    fn a_big_endian_member_is_assembled_the_other_way_round() {
        let json = LINUX.replace(
            r#""int": {"size": 4, "signed": true, "kind": "int", "endian": "little"}"#,
            r#""int": {"size": 4, "signed": true, "kind": "int", "endian": "big"}"#,
        );
        let table = compiled(&json);
        let base = 0x4_0000u64;
        let mut bytes = vec![0u8; 64];
        bytes[16..20].copy_from_slice(&0x0000_0004u32.to_be_bytes());
        let image = FakeImage::new(base, bytes);
        assert_eq!(
            table
                .read_member_unsigned(&image, base, "task_struct", "pid")
                .unwrap(),
            4
        );
    }

    #[test]
    fn a_truncated_or_garbage_symbol_file_errors_rather_than_panicking() {
        for garbage in [
            "not json",
            "{}",
            r#"{"metadata": {"format": "6.2.0"}"#,
            r#"{"metadata": {"format": "nonsense"}}"#,
            r#"{"metadata": {"format": "6.2.0"}, "user_types": {"x": {"size": 8}}}"#,
        ] {
            let outcome = compile(garbage);
            assert!(outcome.is_err(), "'{garbage}' must not compile");
        }
        let half = &LINUX.as_bytes()[..LINUX.len() / 2];
        assert!(compile(std::str::from_utf8(half).unwrap()).is_err());
    }

    #[test]
    fn identical_anonymous_shapes_are_shared_rather_than_duplicated() {
        let table = compiled(LINUX);
        let next = table.member("list_head", "next").unwrap().ty;
        let prev = table.member("list_head", "prev").unwrap().ty;
        assert_eq!(next, prev, "one pointer-to-list_head entry serves both");
    }
}
