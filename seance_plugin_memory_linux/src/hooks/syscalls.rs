//! The system-call tables, entry by entry, against the code map.
//!
//! Source A is the table itself: `sys_call_table`, and where the build has
//! them `ia32_sys_call_table` and `x32_sys_call_table`, read as arrays of code
//! pointers out of kernel memory. Source B is the code map: the kernel's text
//! bounds and symbols, and the module list's code extents.
//!
//! ## How many entries
//!
//! The kernel does not publish `NR_syscalls` as a symbol. The table's length is
//! taken the way Volatility's `check_syscall` takes it: the distance to the
//! next symbol above the table, divided by the pointer size. With an
//! image-derived symbol table (every kallsyms entry) that bound is tight; with
//! a sparse symbol file it can overshoot into whatever follows, so the count
//! and its source are published, a trailing run of null entries is reported
//! as padding rather than as missing system calls, and a count past
//! [`MAX_ENTRIES`] is refused as not a table.
//!
//! ## What the table is on a modern x86-64 kernel
//!
//! From Linux 6.9 — and on the stable series that took the BHI mitigation
//! back, which is why an Ubuntu 5.15 kernel has it too — the x86-64 entry path
//! dispatches through `x64_sys_call`, a compiled `switch`, and consults the
//! table only for tracing. A build that declares `x64_sys_call` is checked all
//! the same — the table is still the documented registration — but the survey
//! says the entry path does not call through it, so a clean table on such a
//! kernel does not show the dispatch was clean.

use seance_memory::object::StructReader;

use super::regions::{Attribution, CodeMap};

/// A table claiming more entries than this is not a system-call table.
pub const MAX_ENTRIES: u64 = 2048;

/// The tables, in the order they are checked.
pub const TABLE_SYMBOLS: [&str; 3] = [
    "sys_call_table",
    "ia32_sys_call_table",
    "x32_sys_call_table",
];

/// The symbol whose presence means the entry path no longer calls through the
/// table.
pub const SWITCH_DISPATCH_SYMBOL: &str = "x64_sys_call";

/// What one entry resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryVerdict {
    /// Points at the start of a kernel symbol.
    KernelSymbol,
    /// Points into the kernel's text but not at a symbol start — not how a
    /// table entry is written, and worth a look.
    InsideKernelSymbol,
    /// Points into a listed module's code: a hook with an owner.
    Module,
    /// Points outside the kernel's text and every listed module: a candidate
    /// hook.
    Unknown,
    /// The kernel's text bounds were not established; the entry resolves to a
    /// symbol start and nothing more can be said.
    SymbolStartUnbounded,
    /// A null entry.
    Null,
    /// The entry's bytes would not read.
    Unreadable,
}

impl EntryVerdict {
    fn as_str(&self) -> &'static str {
        match self {
            EntryVerdict::KernelSymbol => "kernel_symbol",
            EntryVerdict::InsideKernelSymbol => "inside_kernel_symbol",
            EntryVerdict::Module => "module",
            EntryVerdict::Unknown => "unknown",
            EntryVerdict::SymbolStartUnbounded => "symbol_start_unbounded",
            EntryVerdict::Null => "null",
            EntryVerdict::Unreadable => "unreadable",
        }
    }

    fn is_candidate(&self) -> bool {
        matches!(
            self,
            EntryVerdict::InsideKernelSymbol | EntryVerdict::Module | EntryVerdict::Unknown
        )
    }
}

/// One table entry.
#[derive(Debug, Clone)]
pub struct SyscallEntry {
    pub index: u64,
    pub target: Option<u64>,
    pub attribution: Option<Attribution>,
    pub verdict: EntryVerdict,
    pub detail: Option<String>,
}

impl SyscallEntry {
    /// The verdict's stable label.
    pub fn verdict_str(&self) -> &'static str {
        self.verdict.as_str()
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "index": self.index,
            "target_hex": self.target.map(|t| format!("{t:#x}")),
            "attribution": self.attribution.as_ref().map(Attribution::to_json),
            "verdict": self.verdict.as_str(),
            "detail": self.detail,
        })
    }
}

/// One table.
#[derive(Debug, Clone)]
pub struct SyscallTable {
    pub symbol: &'static str,
    pub address: u64,
    pub entry_count: u64,
    pub entry_count_source: String,
    /// Only the rows worth reading: every entry that is not a plain kernel
    /// symbol at a symbol start. The clean rows are counted, not listed.
    pub notable: Vec<SyscallEntry>,
    pub kernel_symbol_count: u64,
    pub trailing_null_count: u64,
    pub unreadable_count: u64,
}

impl SyscallTable {
    fn candidate_count(&self) -> usize {
        self.notable
            .iter()
            .filter(|e| e.verdict.is_candidate())
            .count()
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "symbol": self.symbol,
            "address_hex": format!("{:#x}", self.address),
            "entry_count": self.entry_count,
            "entry_count_source": self.entry_count_source,
            "kernel_symbol_count": self.kernel_symbol_count,
            "trailing_null_count": self.trailing_null_count,
            "unreadable_count": self.unreadable_count,
            "candidate_count": self.candidate_count(),
            "notable": self.notable.iter().map(SyscallEntry::to_json).collect::<Vec<_>>(),
        })
    }
}

/// The check's whole result.
#[derive(Debug, Clone)]
pub struct SyscallCheck {
    pub tables: Vec<SyscallTable>,
    /// Each table the build lacks, or could not be sized or read, by name.
    pub not_checked: Vec<String>,
    /// Whether the entry path dispatches through a compiled switch instead.
    pub switch_dispatch: bool,
}

impl SyscallCheck {
    pub fn is_complete(&self) -> bool {
        !self.tables.is_empty()
            && self.not_checked.is_empty()
            && self.tables.iter().all(|t| t.unreadable_count == 0)
    }

    pub fn candidate_count(&self) -> usize {
        self.tables.iter().map(SyscallTable::candidate_count).sum()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sources": [
                "the system-call table(s) read out of kernel memory",
                "the kernel's text bounds and symbol table, and the module list's code extents",
            ],
            "tables": self.tables.iter().map(SyscallTable::to_json).collect::<Vec<_>>(),
            "not_checked": self.not_checked,
            "switch_dispatch": self.switch_dispatch,
            "switch_dispatch_note": if self.switch_dispatch {
                Some("this kernel declares x64_sys_call: since Linux 6.9 (backported to the \
                      stable series with the BHI mitigation) the x86-64 entry path dispatches \
                      through that compiled switch and consults sys_call_table only for tracing, \
                      so a clean table here does not show the dispatch path was unmodified; \
                      patching the switch itself is a text modification this stage does not \
                      examine")
            } else {
                None
            },
            "candidate_count": self.candidate_count(),
        })
    }
}

/// Check every table the build declares.
pub fn check(reader: &StructReader, map: &CodeMap) -> SyscallCheck {
    let symbols = reader.symbols();
    let mut tables = Vec::new();
    let mut not_checked = Vec::new();

    for symbol in TABLE_SYMBOLS {
        let Ok(address) = symbols.symbol_address(symbol) else {
            // The primary table is expected; the compatibility tables exist only
            // on builds with that ABI, so their absence is a fact, not a gap.
            if symbol == TABLE_SYMBOLS[0] {
                not_checked.push(format!(
                    "the system-call table was not checked: the symbol table has no {symbol}"
                ));
            }
            continue;
        };
        match size_table(reader, address) {
            Ok((count, source)) => {
                tables.push(read_table(reader, map, symbol, address, count, source));
            }
            Err(reason) => not_checked.push(format!(
                "{symbol} at {address:#x} was not checked: {reason}"
            )),
        }
    }

    SyscallCheck {
        tables,
        not_checked,
        switch_dispatch: symbols.has_symbol(SWITCH_DISPATCH_SYMBOL),
    }
}

/// The table's length from the next symbol above it.
fn size_table(reader: &StructReader, address: u64) -> Result<(u64, String), String> {
    let symbols = reader.symbols();
    let pointer = u64::from(reader.pointer_size().map_err(|e| e.to_string())?);
    let mask = symbols.symbol_mask();
    let next = symbols
        .symbols()
        .iter()
        .map(|s| (s.address & mask, &s.name))
        .filter(|(a, _)| *a > address)
        .min_by_key(|(a, _)| *a);
    let Some((next_address, next_name)) = next else {
        return Err("no symbol lies above it, so its length could not be bounded".to_string());
    };
    let count = (next_address - address) / pointer;
    if count == 0 {
        return Err(format!(
            "the next symbol ({next_name}) is at {next_address:#x}, leaving no room for an entry"
        ));
    }
    if count > MAX_ENTRIES {
        return Err(format!(
            "the next symbol above it ({next_name}) is {} bytes away, which would make {count} \
             entries, past the {MAX_ENTRIES} this check accepts as a table",
            next_address - address
        ));
    }
    Ok((
        count,
        format!("distance to the next symbol above the table ({next_name} at {next_address:#x})"),
    ))
}

fn read_table(
    reader: &StructReader,
    map: &CodeMap,
    symbol: &'static str,
    address: u64,
    count: u64,
    source: String,
) -> SyscallTable {
    let pointer = u64::from(reader.pointer_size().unwrap_or(8));
    let mut notable = Vec::new();
    let mut kernel_symbol_count = 0u64;
    let mut unreadable_count = 0u64;
    let mut trailing_nulls = 0u64;
    for index in 0..count {
        let slot = address.wrapping_add(index * pointer);
        let target = match reader.read_pointer_at(slot) {
            Ok(target) => target,
            Err(err) => {
                unreadable_count += 1;
                trailing_nulls = 0;
                notable.push(SyscallEntry {
                    index,
                    target: None,
                    attribution: None,
                    verdict: EntryVerdict::Unreadable,
                    detail: Some(err.to_string()),
                });
                continue;
            }
        };
        let attribution = map.attribute(target);
        let verdict = match &attribution {
            Attribution::Null => EntryVerdict::Null,
            Attribution::KernelText { offset: 0, .. } => EntryVerdict::KernelSymbol,
            Attribution::KernelText { .. } => EntryVerdict::InsideKernelSymbol,
            Attribution::Module { .. } => EntryVerdict::Module,
            Attribution::Unknown { .. } => EntryVerdict::Unknown,
            Attribution::NearestSymbolOnly { offset: 0, .. } => EntryVerdict::SymbolStartUnbounded,
            Attribution::NearestSymbolOnly { .. } => EntryVerdict::Unknown,
        };
        if verdict == EntryVerdict::Null {
            trailing_nulls += 1;
        } else {
            trailing_nulls = 0;
        }
        if verdict == EntryVerdict::KernelSymbol {
            kernel_symbol_count += 1;
            continue;
        }
        notable.push(SyscallEntry {
            index,
            target: Some(target),
            attribution: Some(attribution),
            verdict,
            detail: None,
        });
    }
    // A trailing run of nulls is the gap between the table's real end and the
    // next symbol, not missing system calls; it is counted and dropped from the
    // notable rows so a padded table does not read as a hundred hooks.
    if trailing_nulls > 0 {
        let cut = notable.len() - trailing_nulls as usize;
        notable.truncate(cut);
    }
    SyscallTable {
        symbol,
        address,
        entry_count: count,
        entry_count_source: source,
        notable,
        kernel_symbol_count,
        trailing_null_count: trailing_nulls,
        unreadable_count,
    }
}
