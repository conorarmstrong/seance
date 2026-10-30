//! Where a code address lives: kernel text, a listed module, or nowhere known.
//!
//! Every hook check in this stage ends with the same question about a pointer
//! read out of kernel memory — a syscall-table entry, an ftrace callback, a
//! kprobe handler: *what code is at this address?* The answer is a
//! [`CodeMap`] lookup, and it has exactly three honest outcomes:
//!
//! * inside the kernel's own text (`_stext`..`_etext`), named by the nearest
//!   symbol and the offset into it;
//! * inside the extent of a module the module list named — the module is
//!   named, because a hook installed by a loaded module is a finding with an
//!   owner;
//! * inside neither, which is the shape of a hook whose code was placed by
//!   hand or by a module that has unlinked itself.
//!
//! The third outcome is only as strong as the map, and the map says how strong
//! it is: a module whose extent this build could not read (the 6.4 `mem[]`
//! shape, an unreadable descriptor) is listed by name under
//! [`CodeMap::modules_without_extent`], and every "unknown" verdict a caller
//! derives from this map must be read against that list. A map with no kernel
//! text bounds at all attributes by nearest symbol only and says so.

use seance_memory::binding::{BuildBinding, Field};
use seance_memory::object::StructReader;
use seance_symbols::SymbolTable;

use crate::lsmod::ModuleList;

/// The symbols that bound the kernel's own text.
pub const KERNEL_TEXT_START: [&str; 2] = ["_stext", "_text"];
pub const KERNEL_TEXT_END: [&str; 2] = ["_etext", "__etext"];

/// The 6.4+ module-memory enumeration and the entry that holds the text.
const MOD_MEM_TYPE_ENUM: &str = crate::lsmod::MOD_MEM_TYPE;
const MOD_TEXT_CONSTANT: &str = crate::lsmod::MOD_TEXT;
/// `MOD_TEXT` has been the first enumerator of `mod_mem_type` since the
/// array arrived in 6.4. Used only when the symbol table carries no such
/// enumeration — the module stage then does not decode `mem[]` itself — and
/// stated on the map when it is. An image-derived table carries the
/// enumeration since `MEM-042`, and the module stage's decoded MOD_TEXT region
/// is used instead; the real-capture tests pin the index by geometry (a
/// `struct module` lies in its module's data extent, never in the one read as
/// text).
const MOD_TEXT_ASSUMED_INDEX: u64 = 0;

/// One module's code extent, as this build could establish it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRange {
    /// `module.name`.
    pub name: String,
    /// Address of the `struct module`.
    pub module_address: u64,
    /// First byte of the extent.
    pub base: u64,
    /// Length in bytes.
    pub size: u64,
    /// Which members supplied the extent.
    pub source: &'static str,
}

impl ModuleRange {
    fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.base.saturating_add(self.size)
    }
}

/// What a code address was attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// Inside the kernel's text, at `offset` bytes into `symbol`.
    KernelText { symbol: String, offset: u64 },
    /// Inside a listed module's extent.
    Module { name: String, offset: u64 },
    /// Outside the kernel's text and every module extent the map holds. The
    /// nearest symbol below it is named so an examiner can see what it is
    /// near; the distance says how far.
    Unknown {
        nearest_symbol: Option<(String, u64)>,
    },
    /// The kernel's text bounds were not established, so the only evidence is
    /// the nearest symbol; whether the address is inside it is not known.
    NearestSymbolOnly { symbol: String, offset: u64 },
    /// A null pointer.
    Null,
}

impl Attribution {
    /// Stable machine-readable class.
    pub fn class(&self) -> &'static str {
        match self {
            Attribution::KernelText { .. } => "kernel_text",
            Attribution::Module { .. } => "module",
            Attribution::Unknown { .. } => "unknown",
            Attribution::NearestSymbolOnly { .. } => "nearest_symbol_only",
            Attribution::Null => "null",
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Attribution::KernelText { symbol, offset } => serde_json::json!({
                "class": self.class(), "symbol": symbol, "offset": offset,
            }),
            Attribution::Module { name, offset } => serde_json::json!({
                "class": self.class(), "module": name, "offset": offset,
            }),
            Attribution::Unknown { nearest_symbol } => serde_json::json!({
                "class": self.class(),
                "nearest_symbol": nearest_symbol.as_ref().map(|(name, _)| name),
                "distance_from_nearest_symbol": nearest_symbol.as_ref().map(|(_, d)| d),
            }),
            Attribution::NearestSymbolOnly { symbol, offset } => serde_json::json!({
                "class": self.class(), "symbol": symbol, "offset": offset,
            }),
            Attribution::Null => serde_json::json!({ "class": self.class() }),
        }
    }
}

/// The map every attribution is made against.
#[derive(Debug, Clone)]
pub struct CodeMap {
    /// `[start, end)` of the kernel's text, when both bounds were found.
    pub kernel_text: Option<(u64, u64)>,
    /// Which symbols supplied the bounds, or why there are none.
    pub kernel_text_source: String,
    /// Every module whose extent was established.
    pub modules: Vec<ModuleRange>,
    /// Modules the list named whose extent could not be established, each with
    /// the reason. An "unknown" attribution is weaker for every name here.
    pub modules_without_extent: Vec<(String, String)>,
    /// Whether a module list was available at all.
    pub module_list_available: bool,
    /// Assumptions the map rests on, stated once each.
    pub notes: Vec<String>,
    symbols: std::sync::Arc<SymbolTable>,
}

impl CodeMap {
    /// Build the map from the symbol table and the module list the module
    /// stage walked (or `None` when it did not).
    pub fn build(
        reader: &StructReader,
        layout: &BuildBinding,
        modules: Option<&ModuleList>,
    ) -> Self {
        let symbols = std::sync::Arc::clone(reader.symbols());
        let (kernel_text, kernel_text_source) = kernel_text_bounds(&symbols);
        let mut ranges = Vec::new();
        let mut without = Vec::new();
        let mut notes = Vec::new();
        if let Some(list) = modules {
            for module in &list.modules {
                let name = module
                    .name
                    .known()
                    .cloned()
                    .unwrap_or_else(|| format!("<module at {:#x}>", module.address));
                match module_extent(reader, layout, module) {
                    Ok((base, size, source)) => {
                        if source == MEM_TEXT_ASSUMED_SOURCE && notes.is_empty() {
                            notes.push(format!(
                                "module text extents were read from module.mem[{MOD_TEXT_ASSUMED_INDEX}] \
                                 on the assumption that MOD_TEXT is the first enumerator of \
                                 mod_mem_type, because the symbol table carries no such \
                                 enumeration; it has been the first since the array arrived in 6.4"
                            ));
                        }
                        ranges.push(ModuleRange {
                            name,
                            module_address: module.address,
                            base,
                            size,
                            source,
                        })
                    }
                    Err(reason) => without.push((name, reason)),
                }
            }
        }
        Self {
            kernel_text,
            kernel_text_source,
            modules: ranges,
            modules_without_extent: without,
            module_list_available: modules.is_some(),
            notes,
            symbols,
        }
    }

    /// Attribute one code address.
    pub fn attribute(&self, address: u64) -> Attribution {
        if address == 0 {
            return Attribution::Null;
        }
        if let Some(range) = self.modules.iter().find(|r| r.contains(address)) {
            return Attribution::Module {
                name: range.name.clone(),
                offset: address - range.base,
            };
        }
        let nearest = self
            .symbols
            .nearest_symbol(address)
            .map(|(entry, distance)| (entry.name.to_string(), distance));
        match self.kernel_text {
            Some((start, end)) if address >= start && address < end => match nearest {
                Some((symbol, offset)) => Attribution::KernelText { symbol, offset },
                None => Attribution::Unknown {
                    nearest_symbol: None,
                },
            },
            Some(_) => Attribution::Unknown {
                nearest_symbol: nearest,
            },
            None => match nearest {
                Some((symbol, offset)) => Attribution::NearestSymbolOnly { symbol, offset },
                None => Attribution::Unknown {
                    nearest_symbol: None,
                },
            },
        }
    }

    /// The sentences that qualify every "unknown" verdict made against this map.
    pub fn limitations(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.kernel_text.is_none() {
            out.push(format!(
                "the kernel's text bounds were not established ({}), so an address is \
                 attributed by its nearest symbol only and 'unknown' cannot be distinguished \
                 from 'inside the kernel'",
                self.kernel_text_source
            ));
        }
        if !self.module_list_available {
            out.push(
                "the module list was not walked, so no address can be attributed to a module \
                 and every address outside the kernel's text reads as unknown"
                    .to_string(),
            );
        }
        if !self.modules_without_extent.is_empty() {
            let names: Vec<&str> = self
                .modules_without_extent
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            out.push(format!(
                "{} listed module(s) have no readable code extent on this build ({}), so an \
                 address inside one of them reads as unknown rather than as that module: {}",
                names.len(),
                self.modules_without_extent[0].1,
                names.join(", ")
            ));
        }
        out
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kernel_text": self.kernel_text.map(|(s, e)| serde_json::json!({
                "start_hex": format!("{s:#x}"), "end_hex": format!("{e:#x}"),
            })),
            "kernel_text_source": self.kernel_text_source,
            "module_list_available": self.module_list_available,
            "module_count_with_extent": self.modules.len(),
            "modules_without_extent": self.modules_without_extent.iter().map(|(name, reason)| {
                serde_json::json!({ "name": name, "reason": reason })
            }).collect::<Vec<_>>(),
            "notes": self.notes,
            "limitations": self.limitations(),
        })
    }
}

fn kernel_text_bounds(symbols: &SymbolTable) -> (Option<(u64, u64)>, String) {
    let start = KERNEL_TEXT_START
        .iter()
        .find_map(|name| symbols.symbol_address(name).ok().map(|a| (*name, a)));
    let end = KERNEL_TEXT_END
        .iter()
        .find_map(|name| symbols.symbol_address(name).ok().map(|a| (*name, a)));
    match (start, end) {
        (Some((s_name, s)), Some((e_name, e))) if e > s => {
            (Some((s, e)), format!("{s_name}..{e_name}"))
        }
        (Some((s_name, s)), Some((e_name, e))) => (
            None,
            format!("{s_name} ({s:#x}) is not below {e_name} ({e:#x})"),
        ),
        _ => (
            None,
            format!(
                "no {} / {} symbol in the symbol table",
                KERNEL_TEXT_START.join("|"),
                KERNEL_TEXT_END.join("|")
            ),
        ),
    }
}

/// A module's text extent, from whichever members this build records it in.
fn module_extent(
    reader: &StructReader,
    layout: &BuildBinding,
    module: &crate::lsmod::ModuleRecord,
) -> Result<(u64, u64, &'static str), String> {
    // 6.4 onward, when the module stage decoded `mem[]` through the symbol
    // table's own `mod_mem_type`: its MOD_TEXT region is the text. Checked
    // first, because on such a kernel the stage's core base and core size are
    // mem[MOD_TEXT].base and the sum of every core region — separate
    // allocations, whose sum laid from the text base is not an extent.
    if let Some(text) = module
        .memory
        .iter()
        .find(|region| region.kind == MOD_TEXT_CONSTANT)
    {
        if text.base == 0 || text.size == 0 {
            return Err(format!(
                "module.mem[MOD_TEXT] records base {:#x} and size {}, which is no extent",
                text.base, text.size
            ));
        }
        return Ok((text.base, text.size, MEM_TEXT_SOURCE));
    }
    // Up to 6.3: the module stage already read core base and size.
    if let (Field::Known(base), Field::Known(size)) = (&module.core_base, &module.core_size) {
        if *base != 0 && *size > 0 {
            return Ok((*base, *size as u64, "core_layout/module_core"));
        }
    }
    // 6.4 onward: mem[MOD_TEXT].
    let mem_bound = layout.member("module_mem").map_err(|e| e.to_string())?;
    let Some(mem_member) = mem_bound.member() else {
        return Err(match (&module.core_base, &module.core_size) {
            (Field::Unavailable(detail), _) | (_, Field::Unavailable(detail)) => {
                format!("its core extent could not be read: {detail}")
            }
            _ => "this build declares neither a core extent nor module.mem[]".to_string(),
        });
    };
    let module_type = mem_bound.type_name().unwrap_or("module");
    let obj = reader
        .object(module.address, module_type)
        .map_err(|e| format!("the module structure could not be read: {e}"))?;
    let (index, source) = match reader
        .symbols()
        .enum_value(MOD_MEM_TYPE_ENUM, MOD_TEXT_CONSTANT)
    {
        Ok(value) => (
            u64::try_from(value).map_err(|_| "MOD_TEXT is negative".to_string())?,
            MEM_TEXT_SOURCE,
        ),
        Err(_) => (MOD_TEXT_ASSUMED_INDEX, MEM_TEXT_ASSUMED_SOURCE),
    };
    let entry = obj
        .element_object(mem_member, index)
        .map_err(|e| format!("module.mem[{index}] could not be read: {e}"))?;
    let base = entry
        .pointer("base")
        .map_err(|e| format!("module.mem[MOD_TEXT].base: {e}"))?;
    let size = entry
        .unsigned("size")
        .map_err(|e| format!("module.mem[MOD_TEXT].size: {e}"))?;
    if base == 0 || size == 0 {
        return Err(format!(
            "module.mem[MOD_TEXT] records base {base:#x} and size {size}, which is no extent"
        ));
    }
    Ok((base, size, source))
}

/// The extent sources a range may name.
pub const MEM_TEXT_SOURCE: &str = "mem[MOD_TEXT]";
pub const MEM_TEXT_ASSUMED_SOURCE: &str = "mem[0] (MOD_TEXT assumed)";
