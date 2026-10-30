//! Loaded kernel modules, walked from the `modules` list head.
//!
//! ## The member that moves
//!
//! A module's code extent has been spelled three ways:
//!
//! | Kernel | Base | Size |
//! |---|---|---|
//! | up to 4.4 | `module_core` | `core_size` |
//! | 4.5 – 6.3 | `core_layout.base` | `core_layout.size` |
//! | 6.4 onward | `mem[MOD_TEXT].base` | `mem[MOD_TEXT].size` |
//!
//! The first two are ordered candidates and this stage reads either. The third
//! is an **array indexed by an enumeration**, `mod_mem_type`, and it is decoded
//! through the constants the symbol table declares for it (an image-derived
//! table carries them, from the kernel's BTF): every region is published by its
//! constant's name, the core base is `mem[MOD_TEXT].base`, the core size is the
//! sum of the regions not named `MOD_INIT_*` and the init size the sum of those
//! that are — the meaning Volatility's `linux.lsmod` gives the columns on 6.4+.
//! When the table declares no `mod_mem_type`, no index can be named and the
//! array is not decoded; that is stated on the row rather than left as a blank,
//! because a blank cell with nothing beside it would read as a module with no
//! code.
//!
//! ## Why this stage does not depend on the process list
//!
//! It walks a kernel global. A machine whose task list will not walk can still
//! have its loaded drivers enumerated, and on an intrusion case the driver list
//! is often the more important of the two — so this stage runs whether or not
//! [`crate::tasks`] succeeded.

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::{ListSpec, ListStop, Obj, StructReader};
use seance_symbols::SymbolTable;

use crate::error::{name_list, StageError};
use crate::module::STAGE_LINUX_KERNEL_MODULES;
use crate::profile::LinuxProfile;
use crate::read::{read_c_string_member, read_char_array, read_integer, signed_to_json};

/// The kernel global the module list hangs off.
pub const MODULE_LIST_SYMBOLS: [&str; 1] = ["modules"];

/// The enumeration a module's lifecycle state is declared as.
pub const MODULE_STATE_TYPE: &str = "module_state";

/// Longest module argument string this stage will follow.
pub const MAX_ARGS: usize = 4096;

/// Ceiling on modules one walk will report.
///
/// A machine with more loaded modules than this has a corrupt list, not a busy
/// one. Reaching it is [`ListStop::CapReached`] and never the end of the list.
pub const MAX_MODULES: usize = 16_384;

/// Everything the kernel-module stage needs out of the symbol table.
pub const MODULE_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_KERNEL_MODULES,
    &[
        TypeSpec::new("module", &["module"]).required(
            "no loaded kernel module can be described at all, so nothing can be said about what \
             was running in the kernel",
        ),
        TypeSpec::new("list_link", &["list_head"]).required(
            "the kernel's list links cannot be sized, so no module could be reached from the \
             modules list head",
        ),
    ],
    &[
        MemberSpec::new("list", &["module"], &["list"]).required(
            "a module structure has no link into the module list, so the list cannot be walked \
             and an empty result would read as a kernel with no modules loaded",
        ),
        MemberSpec::new("list_next", &["list_head"], &["next"]).required(
            "a list link has no forward pointer, so the module list cannot be walked at all",
        ),
        MemberSpec::new("name", &["module"], &["name"]),
        MemberSpec::new("state", &["module"], &["state"]),
        // `module_core`/`core_size` up to Linux 4.4; `core_layout` from 4.5.
        MemberSpec::new(
            "core_base",
            &["module"],
            &["module_core", "core_layout.base"],
        ),
        MemberSpec::new("core_size", &["module"], &["core_size", "core_layout.size"]),
        MemberSpec::new(
            "init_base",
            &["module"],
            &["module_init", "init_layout.base"],
        ),
        MemberSpec::new("init_size", &["module"], &["init_size", "init_layout.size"]),
        // Linux 6.4 replaced both layouts with an array indexed by an
        // enumeration. Declared so the stage can *say* the kernel uses that
        // shape rather than leave the size columns blank with no explanation.
        MemberSpec::new("module_memory", &["module"], &["mem"]),
        MemberSpec::new("taints", &["module"], &["taints"]),
        MemberSpec::new("args", &["module"], &["args"]),
        MemberSpec::new("version", &["module"], &["version"]),
        MemberSpec::new("srcversion", &["module"], &["srcversion"]),
    ],
);

/// Caps for one module-list walk.
#[derive(Debug, Clone)]
pub struct ModuleListConfig {
    /// Ceiling on modules reported.
    pub max_modules: usize,
}

/// What a module list built from one linked list can and cannot claim.
///
/// Attached to the artifact rather than left to documentation: records are read
/// individually, and this is the caveat most likely to be separated from the
/// finding it qualifies.
pub const ENUMERATION_SCOPE_NOTE: &str =
    "These modules were enumerated by walking the kernel's module list. Unlinking a `struct \
     module` from that list is the oldest and commonest way of hiding a loaded kernel module \
     on Linux, and the module continues to run. `complete` above means the walk terminated \
     normally; it does NOT mean this is every module the kernel had loaded. No second \
     enumeration method corroborates this list, so a module absent from it has not been shown \
     to be absent from the kernel.";

impl Default for ModuleListConfig {
    fn default() -> Self {
        Self {
            max_modules: MAX_MODULES,
        }
    }
}

/// One entry of a 6.4+ module's `mem[]` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMemoryRegion {
    /// The array index, which is the `mod_mem_type` value.
    pub index: u64,
    /// The `mod_mem_type` constant that names the index (`MOD_TEXT`, ...).
    pub kind: String,
    /// `mem[index].base`.
    pub base: u64,
    /// `mem[index].size`, in bytes.
    pub size: u64,
}

impl ModuleMemoryRegion {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "index": self.index,
            "kind": self.kind,
            "base_hex": format!("{:#x}", self.base),
            "size": self.size,
        })
    }
}

/// One loaded kernel module.
#[derive(Debug, Clone)]
pub struct ModuleRecord {
    /// Address of the `module` structure in the kernel address space.
    pub address: u64,
    /// `module.name`, truncated at its first NUL.
    pub name: Field<String>,
    /// Whether every byte of the name before its NUL was valid UTF-8.
    pub name_well_formed: bool,
    /// The lifecycle state word.
    pub state: Field<i64>,
    /// The enumeration constant that state names, when this build's
    /// `module_state` defines one for the value. `None` is not "unknown state":
    /// it is "this kernel's enumeration has no name for that number", which is
    /// worth seeing rather than being papered over with a made-up label.
    pub state_name: Option<String>,
    /// Base address of the module's core allocation.
    pub core_base: Field<u64>,
    /// Size of the module's core allocation.
    pub core_size: Field<i64>,
    /// Base address of the module's init allocation, freed once init returns.
    pub init_base: Field<u64>,
    /// Size of the module's init allocation.
    pub init_size: Field<i64>,
    /// Core plus init, which is the figure Volatility's `linux.lsmod` prints as
    /// "Code Size". Known only when both parts were read.
    pub code_size: Field<i64>,
    /// The taint word.
    pub taints: Field<i64>,
    /// The module's load-time argument string.
    pub args: Field<String>,
    /// The module's declared version.
    pub version: Field<String>,
    /// The module's source version hash.
    pub srcversion: Field<String>,
    /// Every `module.mem[]` region, on a 6.4+ kernel whose symbol table names
    /// the `mod_mem_type` constants; empty on an older kernel (which has no
    /// such array) and when the array could not be decoded (a note says why).
    pub memory: Vec<ModuleMemoryRegion>,
    /// Anything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl ModuleRecord {
    /// A row carrying only an address, for tests that correlate on address.
    ///
    /// The cross-view keys on the structure's address and reads no other field,
    /// so a test of it should not have to invent a dozen plausible ones.
    #[cfg(test)]
    pub(crate) fn address_only_for_test(address: u64) -> Self {
        // Each `Field<T>` needs its own value: the generic parameter differs
        // per member, so one shared constructor cannot serve them all.
        Self {
            address,
            name: Field::Unavailable("not read".into()),
            name_well_formed: true,
            state: Field::Unavailable("not read".into()),
            state_name: None,
            core_base: Field::Unavailable("not read".into()),
            core_size: Field::Unavailable("not read".into()),
            init_base: Field::Unavailable("not read".into()),
            init_size: Field::Unavailable("not read".into()),
            code_size: Field::Unavailable("not read".into()),
            taints: Field::Unavailable("not read".into()),
            args: Field::Unavailable("not read".into()),
            version: Field::Unavailable("not read".into()),
            srcversion: Field::Unavailable("not read".into()),
            memory: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// The names of the fields that exist on this build and could not be read.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, unavailable) in [
            ("name", self.name.is_unavailable()),
            ("state", self.state.is_unavailable()),
            ("core_base", self.core_base.is_unavailable()),
            ("core_size", self.core_size.is_unavailable()),
            ("init_base", self.init_base.is_unavailable()),
            ("init_size", self.init_size.is_unavailable()),
            ("taints", self.taints.is_unavailable()),
            ("args", self.args.is_unavailable()),
            ("version", self.version.is_unavailable()),
            ("srcversion", self.srcversion.is_unavailable()),
        ] {
            if unavailable {
                out.push(name);
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "name": self.name.to_json(),
            "name_well_formed": self.name_well_formed,
            "state": signed_to_json(&self.state),
            "state_name": self.state_name,
            "core_base": self.core_base.to_json_address(),
            "core_size": signed_to_json(&self.core_size),
            "init_base": self.init_base.to_json_address(),
            "init_size": signed_to_json(&self.init_size),
            "code_size": signed_to_json(&self.code_size),
            "taints": signed_to_json(&self.taints),
            "args": self.args.to_json(),
            "version": self.version.to_json(),
            "srcversion": self.srcversion.to_json(),
            "memory": self.memory.iter().map(ModuleMemoryRegion::to_json).collect::<Vec<_>>(),
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        })
    }
}

/// Every loaded kernel module, and everything the walk could not do.
#[derive(Debug, Clone)]
pub struct ModuleList {
    /// Address of the `modules` list head.
    pub head: u64,
    /// The offset subtracted from every list link to recover its `module`.
    pub links_offset: u64,
    /// The modules, in the order the list gave them.
    pub modules: Vec<ModuleRecord>,
    /// Why the walk ended.
    pub stop: ListStop,
    /// What this kernel build provided for the stage.
    pub layout: serde_json::Value,
}

impl ModuleList {
    /// Whether the list was walked end to end and every field of every row was
    /// either read or explicitly absent.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
            && self
                .modules
                .iter()
                .all(|module| module.unreadable_fields().is_empty())
    }

    /// Everything a report must declare about this list.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(incomplete) = self.stop.incomplete() {
            out.push(Incomplete::new(
                incomplete.reason,
                format!(
                    "walking the kernel module list from {:#x}: {}",
                    self.head, incomplete.detail
                ),
            ));
        }
        for module in &self.modules {
            let unreadable = module.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the module structure at {:#x} has field(s) that exist on this build and \
                         could not be read: {}",
                        module.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for the module-list artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "head": self.head,
            "head_hex": format!("{:#x}", self.head),
            "links_offset": self.links_offset,
            "count": self.modules.len(),
            "complete": self.is_complete(),
            "walk_stop": self.stop.as_str(),
            // The same qualification the process list carries, and for a
            // sharper reason: unlinking a `struct module` from this list is the
            // oldest and commonest Linux rootkit technique, and the module goes
            // on running. A listing that renders complete without saying so is
            // at its least trustworthy exactly where an examiner needs it most.
            "enumeration_method": "module_list_walk",
            "enumeration_scope_note": ENUMERATION_SCOPE_NOTE,
            "corroborated_by_second_method": false,
            "modules": self.modules.iter().map(ModuleRecord::to_json).collect::<Vec<_>>(),
            "layout": self.layout,
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

/// Bind the kernel-module stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(MODULE_LAYOUT.bind(&reader)?)
}

/// Walk the kernel's module list.
///
/// # Errors
///
/// Only when the stage could not run at all: the symbol table declares no
/// `modules` list head, or a member declared `required` is absent. A walk that
/// stopped early is a [`ModuleList`] that says so, not an error.
pub fn list_modules(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    config: &ModuleListConfig,
) -> Result<ModuleList, StageError> {
    let head = profile
        .symbols
        .symbol_address(MODULE_LIST_SYMBOLS[0])
        .map_err(|_| StageError::NoStartSymbol {
            stage: STAGE_LINUX_KERNEL_MODULES.key,
            candidates: name_list(&MODULE_LIST_SYMBOLS),
            without_it: "there is no module list head to walk, so no loaded kernel module can be \
                         enumerated and an empty listing would read as a kernel running no \
                         modules at all",
        })?;

    let module_type = layout
        .type_of("module")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let link_type = layout
        .type_of("list_link")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let links = layout
        .member("list")?
        .member()
        .expect("a required member is declared or binding refused the stage");
    let forward = layout
        .member("list_next")?
        .member()
        .expect("a required member is declared or binding refused the stage");
    let links_offset = layout
        .member("list")?
        .offset()
        .expect("a declared member has an offset");

    let reader: StructReader = crate::tasks::reader_for(profile);
    let spec = ListSpec::new(link_type, forward)
        .in_container(module_type, links)
        .with_max_entries(config.max_modules);
    let walk = reader.walk_list(head, &spec)?;
    let (entries, stop) = walk.walk_to_end();

    let modules = entries
        .iter()
        .map(|obj| read_module(layout, &profile.symbols, obj))
        .collect::<Result<Vec<_>, StageError>>()?;

    Ok(ModuleList {
        head,
        links_offset,
        modules,
        stop,
        layout: layout.to_json(),
    })
}

/// Read one `module` structure into a row.
fn read_module(
    layout: &BuildBinding,
    symbols: &SymbolTable,
    obj: &Obj,
) -> Result<ModuleRecord, StageError> {
    let (name, name_well_formed) = read_char_array(layout, obj, "name")?;
    let state = read_integer(layout, obj, "state")?;
    let state_name = state.known().and_then(|value| {
        symbols
            .enum_constant_name(MODULE_STATE_TYPE, i128::from(*value))
            .ok()
            .flatten()
            .map(str::to_string)
    });

    let mut core_base = layout.read_pointer(obj, "core_base")?;
    let mut core_size = read_integer(layout, obj, "core_size")?;
    let mut init_base = layout.read_pointer(obj, "init_base")?;
    let mut init_size = read_integer(layout, obj, "init_size")?;
    let mut memory = Vec::new();

    let mut notes = Vec::new();
    // Linux 6.4 replaced both layouts with `mem[]`, an array of
    // `struct module_memory { base, size, ... }` indexed by `mod_mem_type`.
    // Read only when neither older spelling is declared, so a build that has
    // `core_layout` is never read twice.
    let mem_member = layout
        .member("module_memory")
        .ok()
        .filter(|bound| bound.is_declared())
        .and_then(|bound| bound.member());
    if let (true, Some(mem_member)) = (core_size.is_not_declared(), mem_member) {
        match decode_module_memory(symbols, obj, mem_member) {
            Some(decoded) => {
                core_base = decoded.core_base;
                core_size = decoded.core_size;
                init_base = decoded.init_base;
                init_size = decoded.init_size;
                memory = decoded.regions;
                notes.extend(decoded.notes);
            }
            // The one case where a blank size column would be misleading
            // rather than merely empty: this kernel *does* record the extent,
            // and the symbol table does not say which index is which.
            None => notes.push(format!(
                "this kernel records a module's extent in 'module.mem[]', an array indexed by \
                 the '{MOD_MEM_TYPE}' enumeration, which the symbol table does not declare; \
                 without it no index can be named, so the array is not decoded and the size \
                 columns are absent — which is not a statement that the module has no code"
            )),
        }
    }
    let code_size = sum_sizes(&core_size, &init_size);

    Ok(ModuleRecord {
        address: obj.address(),
        name,
        name_well_formed,
        state,
        state_name,
        core_base,
        core_size,
        init_base,
        init_size,
        code_size,
        taints: read_integer(layout, obj, "taints")?,
        args: read_c_string_member(layout, obj, "args", MAX_ARGS)?,
        version: read_c_string_member(layout, obj, "version", MAX_ARGS)?,
        srcversion: read_c_string_member(layout, obj, "srcversion", MAX_ARGS)?,
        memory,
        notes,
    })
}

/// The enumeration that indexes a 6.4+ `module.mem[]`.
pub const MOD_MEM_TYPE: &str = "mod_mem_type";

/// The constant naming the text region of `module.mem[]`.
pub const MOD_TEXT: &str = "MOD_TEXT";

/// What one module's `mem[]` array decoded to.
struct DecodedMemory {
    regions: Vec<ModuleMemoryRegion>,
    core_base: Field<u64>,
    core_size: Field<i64>,
    init_base: Field<u64>,
    init_size: Field<i64>,
    notes: Vec<String>,
}

/// Decode `module.mem[]` through the `mod_mem_type` constants the symbol
/// table declares. `None` when it declares no such enumeration: the index of
/// each region is then unknown, and this stage does not assume one.
///
/// The columns take the meaning they have for the older layouts, and that
/// Volatility's `linux.lsmod` gives them on 6.4+: the core base is
/// `mem[MOD_TEXT].base`; the core size is the sum of every region whose
/// constant does not begin `MOD_INIT_` (text, data, rodata, ro-after-init on
/// 6.8); the init base is `mem[MOD_INIT_TEXT].base` and the init size the sum of
/// the `MOD_INIT_*` regions, which the kernel zeroes once the module's init
/// has returned. The regions are separate allocations, so the core base plus
/// the core size is not an extent; each region's own base and size are
/// published beside the sums.
///
/// A sum is published only when every region in it was read; one region that
/// could not be read makes the sum unavailable with the reason, and the regions
/// that were read are still listed.
fn decode_module_memory(
    symbols: &SymbolTable,
    obj: &Obj,
    mem_member: &str,
) -> Option<DecodedMemory> {
    let enumeration = symbols.enumeration(MOD_MEM_TYPE).ok()?;
    let mut notes = Vec::new();
    let length = match obj.array_len(mem_member) {
        Ok(length) => length,
        Err(err) => {
            let detail = format!("module.{mem_member}[] could not be sized: {err}");
            return Some(DecodedMemory {
                regions: Vec::new(),
                core_base: Field::Unavailable(detail.clone()),
                core_size: Field::Unavailable(detail.clone()),
                init_base: Field::Unavailable(detail.clone()),
                init_size: Field::Unavailable(detail),
                notes,
            });
        }
    };

    // Each index the array holds, named by the first constant with that value
    // (MOD_MEM_NUM_TYPES equals the length and MOD_INVALID is -1, so neither
    // names an element).
    let mut named: Vec<(u64, &str)> = Vec::new();
    for constant in &enumeration.constants {
        let Ok(index) = u64::try_from(constant.value) else {
            continue;
        };
        if index < length && !named.iter().any(|(seen, _)| *seen == index) {
            named.push((index, constant.name.as_ref()));
        }
    }
    named.sort_unstable_by_key(|(index, _)| *index);
    if (named.len() as u64) < length {
        notes.push(format!(
            "module.{mem_member}[] has {length} element(s) and '{MOD_MEM_TYPE}' names {} of \
             them; an unnamed element is not read and is in neither size",
            named.len()
        ));
    }

    let mut regions = Vec::new();
    let mut core_total: Result<i64, String> = Ok(0);
    let mut init_total: Result<i64, String> = Ok(0);
    let mut core_base: Field<u64> = Field::Unavailable(format!(
        "'{MOD_MEM_TYPE}' declares no {MOD_TEXT} constant, so no region is the text"
    ));
    let mut init_base: Field<u64> = Field::Unavailable(format!(
        "'{MOD_MEM_TYPE}' declares no MOD_INIT_TEXT constant, so no region is the init text"
    ));
    for (index, kind) in named {
        let is_init = kind.starts_with("MOD_INIT_");
        let read = obj
            .element_object(mem_member, index)
            .map_err(|e| e.to_string())
            .and_then(|entry| {
                let base = entry.pointer("base").map_err(|e| e.to_string())?;
                let size = entry.unsigned("size").map_err(|e| e.to_string())?;
                Ok((base, size))
            });
        let total = if is_init {
            &mut init_total
        } else {
            &mut core_total
        };
        match read {
            Ok((base, size)) => {
                if kind == MOD_TEXT {
                    core_base = Field::Known(base);
                } else if kind == "MOD_INIT_TEXT" {
                    init_base = Field::Known(base);
                }
                if let Ok(sum) = total {
                    *total = i64::try_from(size)
                        .ok()
                        .and_then(|size| sum.checked_add(size))
                        .ok_or_else(|| {
                            format!("module.{mem_member}[] sizes do not sum without overflowing")
                        });
                }
                regions.push(ModuleMemoryRegion {
                    index,
                    kind: kind.to_string(),
                    base,
                    size,
                });
            }
            Err(err) => {
                let detail =
                    format!("module.{mem_member}[{index}] ({kind}) could not be read: {err}");
                if kind == MOD_TEXT {
                    core_base = Field::Unavailable(detail.clone());
                } else if kind == "MOD_INIT_TEXT" {
                    init_base = Field::Unavailable(detail.clone());
                }
                if total.is_ok() {
                    *total = Err(detail);
                }
            }
        }
    }
    let field = |total: Result<i64, String>| match total {
        Ok(sum) => Field::Known(sum),
        Err(detail) => Field::Unavailable(detail),
    };
    Some(DecodedMemory {
        regions,
        core_base,
        core_size: field(core_total),
        init_base,
        init_size: field(init_total),
        notes,
    })
}

/// Core plus init, only when both were read.
///
/// A sum with a missing operand is not a smaller sum. Reporting `core_size`
/// alone as the code size would understate the module's extent by however much
/// its init section was, and reporting zero would state that a loaded module
/// occupies no memory.
fn sum_sizes(core: &Field<i64>, init: &Field<i64>) -> Field<i64> {
    match (core, init) {
        (Field::Known(core), Field::Known(init)) => match core.checked_add(*init) {
            Some(total) => Field::Known(total),
            None => Field::Unavailable(
                "the core and init sizes this kernel declares do not sum without overflowing, so \
                 at least one of them is not a size"
                    .to_string(),
            ),
        },
        (Field::Unavailable(detail), _) | (_, Field::Unavailable(detail)) => {
            Field::Unavailable(detail.clone())
        }
        (Field::NotDeclared { member }, _) | (_, Field::NotDeclared { member }) => {
            Field::NotDeclared { member }
        }
        _ => Field::NotApplicable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> ModuleRecord {
        ModuleRecord {
            address: 0xFFFF_FFFF_A042_6260,
            name: Field::Known("rfcomm".into()),
            name_well_formed: true,
            state: Field::Known(0),
            state_name: Some("MODULE_STATE_LIVE".into()),
            core_base: Field::Known(0xFFFF_FFFF_A041_D000),
            core_size: Field::Known(0x7F2C),
            init_base: Field::NotApplicable,
            init_size: Field::Known(0x478),
            code_size: Field::Known(0x83A4),
            taints: Field::Known(0),
            args: Field::Known("l2cap_mtu=1013".into()),
            version: Field::Known("1.11".into()),
            srcversion: Field::NotApplicable,
            memory: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn the_code_size_is_core_plus_init_and_only_when_both_were_read() {
        assert_eq!(
            sum_sizes(&Field::Known(0x7F2C), &Field::Known(0x478)),
            Field::Known(0x83A4)
        );

        // A sum with a missing operand is not a smaller sum. Publishing
        // core_size alone here would understate the module's extent, and
        // publishing zero would say a loaded module occupies no memory.
        let absent: Field<i64> = Field::NotDeclared {
            member: "core_size",
        };
        assert!(sum_sizes(&absent, &Field::Known(0x478)).is_not_declared());
        assert!(sum_sizes(&Field::Known(0x7F2C), &absent).is_not_declared());

        let damaged: Field<i64> = Field::Unavailable("the page was not acquired".into());
        assert!(sum_sizes(&damaged, &Field::Known(0x478)).is_unavailable());

        // Overflow means at least one operand is not a size, and saying so is
        // better than publishing a wrapped number.
        assert!(sum_sizes(&Field::Known(i64::MAX), &Field::Known(1)).is_unavailable());
    }

    #[test]
    fn a_row_with_every_field_read_declares_nothing_unreadable() {
        assert!(row().unreadable_fields().is_empty());
    }

    #[test]
    fn a_size_this_build_does_not_declare_is_not_a_gap_in_the_evidence() {
        let mut module = row();
        module.core_size = Field::NotDeclared {
            member: "core_size",
        };
        assert!(module.unreadable_fields().is_empty());
        module.core_size = Field::Unavailable("the page was not acquired".into());
        assert_eq!(module.unreadable_fields(), vec!["core_size"]);
    }

    fn list(stop: ListStop, modules: Vec<ModuleRecord>) -> ModuleList {
        ModuleList {
            head: 0xFFFF_FFFF_8161_DAC0,
            links_offset: 8,
            modules,
            stop,
            layout: serde_json::json!({"stage": "linux_kernel_modules"}),
        }
    }

    #[test]
    fn a_walk_that_stopped_early_is_not_a_complete_module_list() {
        assert!(list(ListStop::Wrapped, vec![row()]).is_complete());

        let short = list(ListStop::NullLink { at: 0x1000 }, vec![row()]);
        assert!(!short.is_complete());
        let reasons = short.incomplete();
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].detail.contains("module list"),
            "{:?}",
            reasons[0]
        );
    }

    #[test]
    fn every_key_the_stage_reads_is_a_key_the_stage_declared() {
        const READ_KEYS: &[&str] = &[
            "list",
            "list_next",
            "name",
            "state",
            "core_base",
            "core_size",
            "init_base",
            "init_size",
            "module_memory",
            "taints",
            "args",
            "version",
            "srcversion",
        ];
        for key in READ_KEYS {
            assert!(
                MODULE_LAYOUT.members.iter().any(|spec| spec.key == *key),
                "{key} is read by the stage and declared nowhere"
            );
        }
        assert_eq!(MODULE_LAYOUT.members.len(), READ_KEYS.len());
        assert_eq!(MODULE_LAYOUT.stage.key, STAGE_LINUX_KERNEL_MODULES.key);
    }

    #[test]
    fn the_extent_members_list_both_spellings_oldest_first() {
        let spec = |key: &str| {
            *MODULE_LAYOUT
                .members
                .iter()
                .find(|spec| spec.key == key)
                .expect("declared")
        };
        assert_eq!(
            spec("core_size").members,
            ["core_size", "core_layout.size"].as_slice()
        );
        assert_eq!(
            spec("core_base").members,
            ["module_core", "core_layout.base"].as_slice()
        );
        // The 6.4 shape is declared so the stage can say the kernel uses it,
        // never so it can be read as a size.
        assert_eq!(spec("module_memory").members, ["mem"].as_slice());
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    /// **A one-method module list must say what it cannot see.**
    ///
    /// Unlinking a `struct module` from the kernel's list is the oldest Linux
    /// rootkit technique and leaves the module running. A listing rendering as
    /// complete, with nothing qualifying it, is least trustworthy exactly where
    /// an examiner needs it most.
    #[test]
    fn the_module_list_states_that_an_unlinked_module_would_not_appear() {
        let list = ModuleList {
            head: 0xffff_ffff_8fc4_0000,
            links_offset: 0x08,
            modules: Vec::new(),
            stop: seance_memory::object::ListStop::Wrapped,
            layout: serde_json::json!({}),
        };
        let json = list.to_json();

        assert_eq!(json["enumeration_method"], "module_list_walk");
        assert_eq!(json["corroborated_by_second_method"], false);
        let note = json["enumeration_scope_note"].as_str().expect("a note");
        assert!(
            note.contains("Unlinking"),
            "must name the technique: {note}"
        );
        assert!(
            note.contains("does NOT mean this is every module"),
            "must say plainly what `complete` is not: {note}"
        );
    }
}
