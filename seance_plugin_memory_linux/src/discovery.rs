//! Finding the kernel, its symbols and its page tables in a Linux image.
//!
//! Windows discovery has structures to lean on: a crash dump publishes its own
//! directory table base, and a raw image carries a `KdDebuggerDataBlock` that
//! names half a dozen kernel globals. Linux has none of that. What it has is the
//! kernel banner — the `Linux version …` string in the kernel's own `.rodata` —
//! and that one string is the whole of the entry point.
//!
//! ## The chain, and why every link is checked
//!
//! ```text
//!   sweep physical memory for "Linux version "      -> banner physical address
//!   match the banner against an ISF's linux_banner  -> the symbol table
//!   ISF's linux_banner symbol address               -> banner virtual address
//!   virtual - physical                              -> kernel text mapping shift
//!   init_level4_pgt symbol address - shift          -> directory table base
//!   translate the banner back through that DTB      -> the DTB and the depth
//!                                                      are both proved
//! ```
//!
//! The last line proves two things at once, and the second is easy to miss.
//! Whether the machine was translating four levels or five is `CR4.LA57`, which
//! no capture records and no symbol holds, so the walk is attempted at each
//! depth [`PAGING_MODES`] offers and the depth that brings the banner back is
//! the one this image is read at. A depth that cannot be demonstrated is never
//! assumed: discovery ends at [`DiscoveryError::PageTablesUnproved`], which
//! names the depths it tried.
//!
//! The shift is **derived, never assumed**. `0xFFFFFFFF80000000` is the shift on
//! a kernel loaded where the linker put it, and it is wrong the moment the
//! kernel is relocated or KASLR is on. A wrong shift does not fail: it produces
//! a directory table base that points at bytes which are not a page table, and
//! the walk over them returns physical addresses that are plausible and wrong.
//! So the last line above is not a formality — it is the only thing separating a
//! derived DTB from a guessed one, and it is what makes the fact
//! [`Evidence::Validated`] rather than [`Evidence::Scanned`].
//!
//! ## Ordered candidates, in both dimensions
//!
//! The top-level page table is `init_level4_pgt` on this Debian 3.2 build,
//! `swapper_pg_dir` on many others and `init_top_pgt` from Linux 4.12. None of
//! them is *the* name, and a build that declares only one of the three is
//! completely ordinary. [`PAGE_TABLE_SYMBOLS`] is the ordered list, and the one
//! this build actually declared is recorded on the profile so a report can name
//! it.
//!
//! ## What "no banner" means, and what it must not be turned into
//!
//! A sweep that covered the whole image and found no banner means this is not a
//! Linux capture, and this tier does not apply — the Windows tier will have
//! said the same thing about a Linux image. A sweep that could *not* cover the
//! whole image and found no banner means nothing at all, and reporting it as
//! "not Linux" would be a positive claim built on a gap. The two are kept apart
//! by [`DiscoveryError::NoKernelBanner::swept_completely`], which is what
//! [`crate::module`] branches on.

use seance_core::data_source::DataSource;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use seance_memory::isf_files::collect_isf_files;
pub use seance_memory::isf_files::{is_isf_file_name, ISF_SUFFIXES};
use seance_memory::layer::MemoryLayer;
use seance_memory::meta::Architecture as LayerArch;
use seance_memory::scan::{scan_layer, ScanConfig, SingleStringScanner};
use seance_memory::translate::{
    Arm64Regime, PagingMode, PagingSpec, PteSemantics, TableCache, TranslationPolicy, Ttbr,
    VirtualLayer,
};
use seance_symbols::{
    identify_path, normalize_banner, AdmissionState, Architecture as IsfArch, CompileOptions,
    DecompressLimits, Gate, GateOutcome, GateResult, IdentifyOptions, IsfOs, SymbolError,
    SymbolTable, ValidationOptions,
};
use tracing::debug;

use crate::image_symbols::{self, ImageDerivedSymbols};
use crate::profile::{
    Evidence, Found, KernelShift, LinuxBuild, LinuxLayerProbe, LinuxProfile, SymbolOrigin,
};

/// The byte string every Linux kernel banner starts with.
pub const BANNER_NEEDLE: &[u8] = b"Linux version ";

/// The ISF symbol whose `constant_data` carries the banner.
pub const BANNER_SYMBOL: &str = "linux_banner";

/// Symbols the top-level page table can be declared under, most likely first.
///
/// - `init_level4_pgt` — x86-64 up to Linux 4.11, and what Debian 3.2 declares.
/// - `swapper_pg_dir` — the historic name, and still present on many builds.
/// - `init_top_pgt` — Linux 4.12 onward, when five-level paging support renamed
///   the four-level root.
///
/// A build declaring none of them is a genuine stop, not a silent fallback to
/// address zero: a walk rooted at physical zero reads whatever lies at the
/// bottom of the image and produces confident nonsense.
pub const PAGE_TABLE_SYMBOLS: [&str; 3] = ["init_level4_pgt", "swapper_pg_dir", "init_top_pgt"];

/// Paging depths offered to the page-table proof, most common first.
///
/// # Why the depth is proved and not read
///
/// Whether an x86-64 machine was translating four levels or five is `CR4.LA57`,
/// a control register. No raw capture, LiME image or ELF core writes it down,
/// and there is no kernel *variable* holding it that could be read out of the
/// image without first having the page tables the answer is needed for.
///
/// Nor does the kernel build settle it. A kernel compiled with
/// `CONFIG_X86_5LEVEL` boots four-level on a processor without LA57 and
/// five-level on one with it, and declares the same `init_top_pgt` either way,
/// so the symbol table describes both machines identically.
///
/// What *does* settle it is the proof this module already performs for the
/// directory table base: walk the tables and require `linux_banner` to come
/// back to the physical address the sweep found it at, with the same bytes. A
/// hierarchy walked at the wrong depth mistakes its top table for the one below
/// and indexes every level with the wrong nine bits of the address, so the
/// banner does not come back — and if no depth produces the banner, discovery
/// fails with [`DiscoveryError::PageTablesUnproved`] rather than picking one.
/// That is the fail-closed rule: a depth is never assumed, only demonstrated.
///
/// Four-level is offered first because it is overwhelmingly the common case and
/// the order decides nothing else: whichever depth is tried, it has to prove
/// itself against the same evidence before it is used.
///
/// # arm64
///
/// The arm64 kernel regimes follow ([`ARM64_PAGING_MODES`]): the granule and
/// width are `TCR_EL1` fields, register state exactly like `CR4.LA57`, and
/// are proved the same way. The shift arithmetic holds unchanged, because
/// `linux_banner` and `swapper_pg_dir` both sit in the kernel image mapping
/// (`kimage_voffset`). Not every mode is offered to every image — see
/// [`modes_for`].
pub const PAGING_MODES: [PagingMode; 9] = [
    PagingMode::Intel32e,
    PagingMode::Intel32eLa57,
    ARM64_PAGING_MODES[0],
    ARM64_PAGING_MODES[1],
    ARM64_PAGING_MODES[2],
    ARM64_PAGING_MODES[3],
    ARM64_PAGING_MODES[4],
    ARM64_PAGING_MODES[5],
    ARM64_PAGING_MODES[6],
];

/// The x86-64 depths, four-level first.
pub const INTEL_PAGING_MODES: [PagingMode; 2] = [PagingMode::Intel32e, PagingMode::Intel32eLa57];

/// The arm64 kernel (TTBR1) regimes, in the order
/// [`crate::vmcoreinfo::ARM64_KERNEL_REGIMES`] gives them.
pub const ARM64_PAGING_MODES: [PagingMode; 7] = [
    arm64_kernel_mode(0),
    arm64_kernel_mode(1),
    arm64_kernel_mode(2),
    arm64_kernel_mode(3),
    arm64_kernel_mode(4),
    arm64_kernel_mode(5),
    arm64_kernel_mode(6),
];

const fn arm64_kernel_mode(index: usize) -> PagingMode {
    let (granule, va_bits) = crate::vmcoreinfo::ARM64_KERNEL_REGIMES[index];
    match Arm64Regime::new(granule, Ttbr::Ttbr1, va_bits) {
        Ok(regime) => PagingMode::Arm64(regime),
        Err(_) => panic!("every listed arm64 regime has a width the architecture defines"),
    }
}

/// Which architecture's kernel the symbol table (or, failing it, the
/// kernel's `VMCOREINFO`) says this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchitectureHint {
    /// A symbol only x86-64 kernels define.
    X86_64,
    /// A symbol only arm64 kernels define.
    Arm64,
    /// Neither.
    Unknown,
}

/// The architecture a symbol table's own names settle, asked through
/// `has_symbol`.
///
/// `kimage_voffset` (the arm64 kernel image's virtual-to-physical offset,
/// `arch/arm64/mm/mmu.c`) exists only on arm64; `phys_base`, `init_top_pgt`
/// and `init_level4_pgt` only on x86-64. `swapper_pg_dir` is both
/// architectures' name and settles nothing. A table declaring both families'
/// symbols settles nothing either.
pub fn architecture_hint_from(has_symbol: impl Fn(&str) -> bool) -> ArchitectureHint {
    let arm64 = ARM64_ONLY_SYMBOLS.iter().any(|name| has_symbol(name));
    let x86 = X86_64_ONLY_SYMBOLS.iter().any(|name| has_symbol(name));
    match (arm64, x86) {
        (true, false) => ArchitectureHint::Arm64,
        (false, true) => ArchitectureHint::X86_64,
        _ => ArchitectureHint::Unknown,
    }
}

/// Symbols only an arm64 kernel defines.
pub const ARM64_ONLY_SYMBOLS: [&str; 1] = ["kimage_voffset"];

/// Symbols only an x86-64 kernel defines.
pub const X86_64_ONLY_SYMBOLS: [&str; 3] = ["phys_base", "init_top_pgt", "init_level4_pgt"];

/// The paging modes offered to the proof for a hint.
///
/// A hinted architecture is offered only its own modes. That is not a
/// shortcut: a simple arm64 4 KiB / 48-bit hierarchy is also a valid x86-64
/// four-level one (the same index split, bit 0 read as present), and from
/// Linux 5.4 the arm64 kernel image sits at an x86-64-canonical address, so
/// an Intel walk can "prove" an arm64 image. Unhinted, every mode is offered
/// and each family must prove alone — see [`DiscoveryError::ArchitectureUndetermined`].
pub fn modes_for(hint: ArchitectureHint) -> Vec<PagingMode> {
    match hint {
        ArchitectureHint::X86_64 => INTEL_PAGING_MODES.to_vec(),
        ArchitectureHint::Arm64 => ARM64_PAGING_MODES.to_vec(),
        ArchitectureHint::Unknown => PAGING_MODES.to_vec(),
    }
}

/// The `DiscoveryError` for "no offered mode proved", naming arm64 when the
/// image says it is arm64.
fn unproved(
    hint: ArchitectureHint,
    banner: &str,
    attempts: usize,
    banner_virtual: u64,
    offered: &[PagingMode],
) -> DiscoveryError {
    if hint == ArchitectureHint::Arm64 {
        // When the hint came from the VMCOREINFO sweep, the symbol table named
        // no architecture and the Intel depths were offered too. They are
        // named as what they are, never listed as arm64 regimes.
        let (arm64, intel): (Vec<PagingMode>, Vec<PagingMode>) =
            offered.iter().copied().partition(|mode| !mode.is_intel());
        let also = if intel.is_empty() {
            String::new()
        } else {
            format!(
                "; the x86-64 depths {} were also tried, because the symbol table named no \
                 architecture and only the image's VMCOREINFO said arm64",
                mode_list(&intel)
            )
        };
        return DiscoveryError::UnsupportedArchitecture {
            banner: banner.to_string(),
            reason: format!(
                "it is an arm64 kernel whose page tables proved under none of the arm64 \
                 regimes this build decodes ({}{also}; {attempts} attempt(s)): a 52-bit or \
                 FEAT_LPA2 regime is not offered to discovery, which proves a regime without \
                 registers and holds no capture of what an LPA2 kernel's banner chain looks like",
                mode_list(&arm64)
            ),
        };
    }
    DiscoveryError::PageTablesUnproved {
        banner: banner.to_string(),
        attempts,
        symbol: BANNER_SYMBOL,
        banner_virtual,
        modes: mode_list(offered),
    }
}

/// The `DiscoveryError` for an unhinted table whose only proof was an
/// x86-64 one, on an image whose `VMCOREINFO` names an arm64 kernel.
///
/// `vmcoreinfo` is what the check found, as [`VmcoreinfoCheck::clause`] says
/// it: an agreed note naming arm64, or a check that could not settle but saw
/// a copy naming arm64.
fn intel_proof_vetoed(
    banner: &str,
    intel: PagingMode,
    attempts: usize,
    vmcoreinfo: &str,
) -> DiscoveryError {
    DiscoveryError::UnsupportedArchitecture {
        banner: banner.to_string(),
        reason: format!(
            "{vmcoreinfo}, yet only the x86-64 mode '{intel}' proved its page tables and none of \
             the arm64 regimes this build decodes did ({}; {attempts} attempt(s)). An arm64 \
             hierarchy can also read as a valid x86-64 one, so that x86-64 proof is not taken; a \
             52-bit or FEAT_LPA2 regime is not offered to discovery",
            mode_list(&ARM64_PAGING_MODES)
        ),
    }
}

/// The `task_struct` symbol every Linux kernel's process list hangs off.
pub const INIT_TASK_SYMBOL: &str = "init_task";

/// Longest banner this reader will accept, in bytes.
///
/// A real banner is a couple of hundred bytes. The cap exists because the sweep
/// finds the needle in places that are not a banner — a saved kernel image, a
/// log page — and reading unbounded bytes after a needle hit would let the
/// evidence decide how much memory to allocate.
pub const MAX_BANNER_BYTES: u64 = 1024;

/// Caps and tuning for one discovery run.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Ceiling on banner needle hits the physical sweep reports.
    pub max_banner_hits: usize,
    /// Ceiling on *distinct* banner strings considered.
    pub max_banner_candidates: usize,
    /// Ceiling on physical addresses tried per distinct banner when deriving
    /// the kernel shift.
    pub max_shift_attempts: usize,
    /// Ceiling on files enumerated while searching for symbols.
    pub max_isf_files: usize,
    /// Directory depth the symbol search descends.
    pub max_isf_depth: usize,
    /// Ceiling on files actually opened and identified.
    pub max_isf_identified: usize,
    /// Whether to fall back to symbols read out of the image when no symbol
    /// file describes the kernel.
    ///
    /// Defaults to permitting it, because an examiner who cannot analyse an
    /// image at all is worse served than one who analyses it and is told the
    /// layouts came from the evidence rather than from a validated file. A lab
    /// whose procedure requires the latter sets
    /// [`ImageDerivedSymbols::Refuse`].
    pub image_derived_symbols: ImageDerivedSymbols,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_banner_hits: 4_096,
            max_banner_candidates: 8,
            max_shift_attempts: 64,
            max_isf_files: 65_536,
            max_isf_depth: 8,
            max_isf_identified: 4_096,
            image_derived_symbols: ImageDerivedSymbols::default(),
        }
    }
}

/// One banner string recovered from physical memory, and where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerCandidate {
    /// The normalised banner.
    pub banner: String,
    /// Physical addresses the string was found at, in ascending order. There is
    /// normally more than one: the kernel's own copy in `.rodata`, plus
    /// whatever `/proc/version` reads and the printk ring buffer have left
    /// behind. Only one of them is the address the ISF's symbol refers to, and
    /// which one is decided by whether the resulting page tables work.
    pub physical: Vec<u64>,
}

/// What the sweep for the kernel banner found.
#[derive(Debug, Clone, Default)]
pub struct BannerSweep {
    /// Distinct banners, in the order first seen.
    pub candidates: Vec<BannerCandidate>,
    /// Needle hits examined.
    pub hits: usize,
    /// Bytes of physical memory actually examined.
    pub bytes_scanned: u64,
    /// Whether every mapped byte of the image was examined and every hit
    /// returned. A sweep that found nothing and was not complete has not shown
    /// that the image holds no Linux kernel.
    pub complete: bool,
}

impl BannerSweep {
    /// Serializable form for the discovery artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "distinct_banners": self.candidates.len(),
            "hits": self.hits,
            "bytes_scanned": self.bytes_scanned,
            "complete": self.complete,
            "banners": self
                .candidates
                .iter()
                .map(|candidate| serde_json::json!({
                    "banner": candidate.banner,
                    "addresses": candidate
                        .physical
                        .iter()
                        .map(|address| format!("{address:#x}"))
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// One Linux ISF found on disk and the banner it declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsfCandidate {
    /// Where the file is.
    pub path: PathBuf,
    /// The normalised banner the file declares.
    pub banner: String,
}

/// What the symbol search found.
#[derive(Debug, Clone, Default)]
pub struct IsfSearch {
    /// Linux ISFs whose banner could be read, in path order.
    pub candidates: Vec<IsfCandidate>,
    /// Candidate files enumerated.
    pub files_seen: usize,
    /// Files opened and identified.
    pub files_identified: usize,
    /// Whether a cap stopped the search. A truncated search that found nothing
    /// has not shown that the symbols are absent.
    pub truncated: bool,
}

impl IsfSearch {
    /// Serializable form for the discovery artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "linux_symbol_files": self.candidates.len(),
            "files_seen": self.files_seen,
            "files_identified": self.files_identified,
            "truncated": self.truncated,
        })
    }
}

/// Everything discovery did, whether or not it succeeded.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryReport {
    /// The physical sweep for the kernel banner.
    pub sweep: BannerSweep,
    /// The symbol-file search, once a banner gave it something to look for.
    pub isf: Option<IsfSearch>,
    /// Attempts made before one produced a working page-table root: one per
    /// (candidate banner location, paging depth) pair, because the depth is
    /// proved rather than known — see [`PAGING_MODES`].
    pub shift_attempts: usize,
    /// Anything worth showing an examiner that is not a failure.
    pub notes: Vec<String>,
}

impl DiscoveryReport {
    /// Record something an examiner should see that did not stop discovery.
    pub fn note(&mut self, message: impl Into<String>) {
        self.notes.push(message.into());
    }

    /// Serializable form for the discovery artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "banner_sweep": self.sweep.to_json(),
            "symbol_search": self.isf.as_ref().map(IsfSearch::to_json),
            "shift_attempts": self.shift_attempts,
            "notes": self.notes,
        })
    }
}

/// Why a Linux image could not be profiled.
///
/// Every variant is a statement about the evidence or the lab's symbol store,
/// phrased so an examiner can act on it. The one that is *not* a failure is
/// [`DiscoveryError::NoKernelBanner`] with `swept_completely` true, which means
/// this is not a Linux capture at all.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// No `Linux version ` string was found in physical memory.
    #[error(
        "no Linux kernel banner was found in {bytes_scanned} byte(s) of physical memory \
         (the sweep {sweep_state})"
    )]
    NoKernelBanner {
        /// Bytes examined.
        bytes_scanned: u64,
        /// Whether the sweep covered every mapped byte. When it did, this image
        /// holds no Linux kernel and this analysis does not apply. When it did
        /// not, nothing has been established either way, and saying "not Linux"
        /// would be a claim resting on the part of the image nobody looked at.
        swept_completely: bool,
        /// The sentence the message above interpolates.
        sweep_state: &'static str,
    },

    /// A banner was found and no symbol file in the lab describes that kernel.
    #[error(
        "this image is running '{banner}', and none of the {directories} symbol directory/ies \
         holds an ISF declaring that kernel ({files_seen} candidate file(s) seen, \
         {files_identified} identified{truncation}). Without matching symbols no kernel \
         structure can be read, because every offset would come from a different build.\
         {btf_note}"
    )]
    SymbolsNotFound {
        /// The banner recovered from the image.
        banner: String,
        /// How many directories were searched.
        directories: usize,
        /// Files enumerated.
        files_seen: usize,
        /// Files opened and identified.
        files_identified: usize,
        /// A clause about a cap that fired, or the empty string.
        truncation: String,
        /// What the kernel's own BTF offers, when it carries any.
        ///
        /// A kernel from roughly 2020 onward describes its own structures in
        /// memory, so an examiner who cannot find an ISF is not necessarily
        /// stuck — the layouts are in the image. Saying so turns a dead end
        /// into a next step. Empty when the kernel carries no BTF, which is the
        /// honest answer for older builds.
        btf_note: String,
    },

    /// The matching symbol file was refused by the admission gates.
    #[error("the symbol file {path} for '{banner}' was refused: {source}")]
    SymbolsRejected {
        /// The file that was refused.
        path: String,
        /// The banner it was chosen for.
        banner: String,
        /// The admission failure.
        source: SymbolError,
    },

    /// The kernel is not one this tier can read.
    #[error(
        "this image is running '{banner}', and {reason}. Séance's Linux memory tier reads \
         64-bit x86 paging (four- and five-level) and arm64 paging (4 KiB pages at 39 and 48 bits; \
         16 and 64 KiB pages at the widths the kernel offers), so this kernel is not analysed here. \
         That is a limit of this tool, not an absence of evidence in the image"
    )]
    UnsupportedArchitecture {
        /// The banner recovered from the image.
        banner: String,
        /// Why, as a clause.
        ///
        /// A clause rather than a number because there are several ways to
        /// arrive here and only one of them has a pointer width to quote: a
        /// table that compiled and declares four-byte pointers, a table the
        /// architecture gate refused before its width could be read, and an
        /// arm64 kernel whose page tables proved under no regime this build
        /// decodes or proved under one it does not profile. Interpolating a
        /// zero width for the others would put a false statement about the
        /// kernel in the record.
        reason: String,
    },

    /// Both an x86-64 and an arm64 paging mode translate the banner back to
    /// where it was found, and nothing in the symbol table says which
    /// architecture this is.
    #[error(
        "the page tables of '{banner}' prove under both an x86-64 mode ({intel}) and an arm64 \
         regime ({arm64}); the symbol table declares no symbol only one architecture defines, \
         and {vmcoreinfo}. Reading the image under either would be a choice neither the symbol \
         table nor the VMCOREINFO check justifies, so neither is used"
    )]
    ArchitectureUndetermined {
        /// The banner recovered from the image.
        banner: String,
        /// The x86-64 mode that proved.
        intel: String,
        /// The arm64 regime that proved.
        arm64: String,
        /// What the image's own VMCOREINFO check found, as a clause: absent,
        /// naming neither architecture, or unable to settle it.
        vmcoreinfo: String,
    },

    /// The symbol table declares no top-level page table.
    #[error(
        "the symbol table for '{banner}' declares none of {candidates}, so there is no symbol \
         from which the page-table root could be derived. Without it no virtual address in this \
         image can be translated"
    )]
    NoPageTableSymbol {
        /// The banner recovered from the image.
        banner: String,
        /// The names that were looked for.
        candidates: String,
    },

    /// The symbol table declares no banner symbol, so no shift can be derived.
    #[error(
        "the symbol table for '{banner}' declares no '{symbol}' address, so the kernel's \
         virtual-to-physical shift cannot be derived and the page-table root cannot be located"
    )]
    NoBannerSymbol {
        /// The banner recovered from the image.
        banner: String,
        /// The symbol that was looked for.
        symbol: &'static str,
    },

    /// No candidate physical address for the banner, at any offered paging
    /// depth, produced a page-table root that translates the banner back to
    /// itself.
    #[error(
        "the kernel's virtual-to-physical shift could not be established for '{banner}': \
         {attempts} combination(s) of candidate banner location and paging depth ({modes}) were \
         tried and none produced a page-table root that translates {symbol} at \
         {banner_virtual:#x} back to the address it was found at. Nothing was read from this \
         image, because an unproved page-table root translates every address to a plausible \
         wrong one, and a page table walked at the wrong depth does the same"
    )]
    PageTablesUnproved {
        /// The banner recovered from the image.
        banner: String,
        /// (Candidate location, paging depth) pairs tried.
        attempts: usize,
        /// The symbol whose address anchors the shift.
        symbol: &'static str,
        /// Its virtual address, per the symbol table.
        banner_virtual: u64,
        /// The paging depths that were offered, named. An examiner reading
        /// "the page tables could not be proved" is entitled to know whether
        /// the depth their machine used was among the ones tried.
        modes: String,
    },

    /// The physical layer could not be swept at all.
    #[error("physical memory could not be swept for the kernel banner: {0}")]
    ImageUnreadable(String),
}

impl DiscoveryError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            DiscoveryError::NoKernelBanner { .. } => "no_kernel_banner",
            DiscoveryError::SymbolsNotFound { .. } => "symbols_not_found",
            DiscoveryError::SymbolsRejected { .. } => "symbols_rejected",
            DiscoveryError::UnsupportedArchitecture { .. } => "unsupported_architecture",
            DiscoveryError::ArchitectureUndetermined { .. } => "architecture_undetermined",
            DiscoveryError::NoPageTableSymbol { .. } => "no_page_table_symbol",
            DiscoveryError::NoBannerSymbol { .. } => "no_banner_symbol",
            DiscoveryError::PageTablesUnproved { .. } => "page_tables_unproved",
            DiscoveryError::ImageUnreadable(_) => "image_unreadable",
        }
    }

    /// Whether this outcome means "this is not a Linux memory image", as
    /// opposed to "this is a Linux memory image that could not be profiled".
    ///
    /// Only true when the sweep covered every mapped byte. A sweep that could
    /// not finish and found nothing establishes nothing, and a caller that
    /// treated it as "not Linux" would be making a positive claim about the
    /// part of the image nobody looked at.
    pub fn means_not_a_linux_image(&self) -> bool {
        matches!(
            self,
            DiscoveryError::NoKernelBanner {
                swept_completely: true,
                ..
            }
        )
    }
}

/// Discover a profile, keeping the report of how it was done.
///
/// The report is returned on success only; a failure carries its own account in
/// the error, which is what [`crate::module`] writes into the case.
pub fn discover_reported(
    physical: Arc<dyn MemoryLayer>,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
) -> Result<(LinuxProfile, DiscoveryReport), DiscoveryError> {
    let mut report = DiscoveryReport {
        sweep: sweep_for_banner(&*physical, options)?,
        ..DiscoveryReport::default()
    };

    let Some(first) = report.sweep.candidates.first().cloned() else {
        let sweep_state = if report.sweep.complete {
            "covered every acquired byte, so this image holds no Linux kernel"
        } else {
            "could not cover the whole image, so nothing was established either way"
        };
        return Err(DiscoveryError::NoKernelBanner {
            bytes_scanned: report.sweep.bytes_scanned,
            swept_completely: report.sweep.complete,
            sweep_state,
        });
    };
    if report.sweep.candidates.len() > 1 {
        report.note(format!(
            "physical memory holds {} distinct kernel banners; the first that produced a working \
             page-table root was used, and the others are listed in the sweep",
            report.sweep.candidates.len()
        ));
    }

    let search = find_linux_isfs(symbol_dirs, options);
    let truncation = if search.truncated {
        ", and a cap stopped the search before it finished".to_string()
    } else {
        String::new()
    };
    let matched = report.sweep.candidates.iter().find_map(|candidate| {
        search
            .candidates
            .iter()
            .find(|isf| isf.banner == candidate.banner)
            .map(|isf| (candidate.clone(), isf.clone()))
    });
    let files_seen = search.files_seen;
    let files_identified = search.files_identified;
    report.isf = Some(search);

    // No symbol file describes this kernel. A kernel from roughly 2020 onward
    // carries its own type information and its own symbol table in the image,
    // so the analysis need not stop here — but what follows is a *different
    // kind* of evidence, and every surface that reports it says so.
    let chosen = match matched {
        Some((candidate, isf)) => Chosen::File {
            candidate,
            isf: Box::new(isf),
        },
        None => {
            let recovery =
                image_symbols::recover(physical.as_data_source(), options.image_derived_symbols);
            match recovery {
                image_symbols::Recovery::Recovered(recovered) => {
                    report.note(format!(
                        "no symbol file in the {} director{} searched describes this kernel, so \
                         its layouts were recovered from the image itself: {}. These cannot \
                         describe a build other than the one captured, but they are a single \
                         source — the cross-check against the kernel's own type information was \
                         not run, because it is the same information the layouts came from",
                        symbol_dirs.len(),
                        if symbol_dirs.len() == 1 { "y" } else { "ies" },
                        recovered.summary()
                    ));
                    Chosen::Image {
                        candidate: first.clone(),
                        recovered,
                    }
                }
                unsuccessful => {
                    return Err(DiscoveryError::SymbolsNotFound {
                        banner: first.banner.clone(),
                        directories: symbol_dirs.len(),
                        files_seen,
                        files_identified,
                        truncation,
                        btf_note: unsuccessful.note(),
                    })
                }
            }
        }
    };

    let candidate = chosen.candidate().clone();
    let validation = ValidationOptions::new().expect_architecture(IsfArch::X64);
    let compile = CompileOptions {
        // The identity check compares the banner from the image against the one
        // the document declares. That is a real test of a file off disk, which
        // could describe any build at all. A document generated from this image
        // declares no identity of its own — deliberately, because stamping the
        // banner into it and then checking the banner against it would be the
        // same circularity the layout-agreement gate is barred from above. The
        // gate records "the ISF declares no identity", which is exactly true;
        // what establishes that these symbols belong to this image is the
        // page-table proof below.
        validation: match &chosen {
            Chosen::File { .. } => validation.expect_identifier(candidate.banner.clone()),
            Chosen::Image { .. } => validation,
        },
        ..CompileOptions::default()
    };
    let mut table = match &chosen {
        Chosen::File { isf, .. } => {
            SymbolTable::compile_path(&isf.path, &DecompressLimits::default(), &compile)
                .map_err(|source| architecture_or_rejection(isf, &candidate.banner, source))?
        }
        Chosen::Image { recovered, .. } => {
            SymbolTable::compile_source(recovered.source.clone(), &compile).map_err(|source| {
                DiscoveryError::SymbolsRejected {
                    path: chosen.origin_label(),
                    banner: candidate.banner.clone(),
                    source,
                }
            })?
        }
    };

    // Pointer width is structural: every paging mode offered below (the x86-64
    // depths and the arm64 regimes) walks 8-byte entries, and a table that
    // declares 4-byte pointers would translate every address through the wrong
    // number of levels.
    if table.pointer_size() != 8 {
        return Err(DiscoveryError::UnsupportedArchitecture {
            banner: candidate.banner.clone(),
            reason: format!(
                "its symbol table declares {}-byte pointers",
                table.pointer_size()
            ),
        });
    }

    let banner_virtual =
        table
            .symbol_address(BANNER_SYMBOL)
            .map_err(|_| DiscoveryError::NoBannerSymbol {
                banner: candidate.banner.clone(),
                symbol: BANNER_SYMBOL,
            })?;
    let (dtb_symbol, page_table_virtual) = first_declared_symbol(&table, &PAGE_TABLE_SYMBOLS)
        .ok_or_else(|| DiscoveryError::NoPageTableSymbol {
            banner: candidate.banner.clone(),
            candidates: name_list(&PAGE_TABLE_SYMBOLS),
        })?;

    // Which banner candidates to try the proof against.
    //
    // A symbol file names the build it describes, so the sweep candidate whose
    // banner matched it is the only one worth trying — anything else would be
    // proving this file against a different kernel's string.
    //
    // Nothing names the build for symbols read out of the image, and an image
    // holds the banner several times over: the kernel's own copy in `.rodata`,
    // plus whatever `/proc/version` reads and the printk ring buffer left
    // behind, and on this corpus a *second kernel's* banner left in freed
    // memory. Those copies do not all normalise to one string, so they arrive
    // as separate candidates and the kernel's own is not reliably the first.
    // Trying only the first is what made this fail against a capture whose
    // `.rodata` copy sat in the second candidate — the page-table proof had
    // never been given the address it would have accepted.
    //
    // So every candidate is offered, and the proof decides. That is the same
    // principle the sweep already documents: which copy the symbol refers to is
    // settled by whether the resulting page tables work, not by position.
    let to_try: Vec<BannerCandidate> = match &chosen {
        Chosen::File { candidate, .. } => vec![candidate.clone()],
        Chosen::Image { .. } => report.sweep.candidates.clone(),
    };

    // One memo across every attempt. A page-table entry is keyed by its
    // physical address and its value is the same eight bytes whichever depth is
    // walking over it, so a rejected depth's reads are still valid for the one
    // that proves — and every mode here is an 8-byte-entry mode, which is what
    // makes that true rather than merely convenient.
    let cache = Arc::new(TableCache::new());
    // Which architecture's paging to offer. The symbol table's own names
    // settle it for every table that declares a symbol only one architecture
    // has; see `modes_for` for why an unhinted image must prove in one family
    // alone.
    let hint = architecture_hint_from(|name| table.has_symbol(name));
    let offered = modes_for(hint);
    // For an unhinted table: what settled the architecture, for the note.
    let mut unhinted_clause = String::new();
    // For an unhinted table none of whose modes proved: what the image's
    // VMCOREINFO names, so an arm64 kernel is refused by name.
    let mut unproved_hint = hint;
    let attempt = match hint {
        ArchitectureHint::Unknown => {
            let intel = prove_under(
                &physical,
                &to_try,
                banner_virtual,
                page_table_virtual,
                &INTEL_PAGING_MODES,
                &cache,
                options,
                &mut report,
            );
            let arm64 = prove_under(
                &physical,
                &to_try,
                banner_virtual,
                page_table_virtual,
                &ARM64_PAGING_MODES,
                &cache,
                options,
                &mut report,
            );
            // Whatever proved, the image's own VMCOREINFO is asked what it
            // says, and whether it could say anything: an x86-64 proof alone
            // can be an arm64 hierarchy read as x86-64 (see `modes_for`), and
            // a report must not read as if the architecture was checked when
            // the check could not look.
            let vmcore = vmcoreinfo_check(&*physical);
            match settle_architecture(intel, arm64, &vmcore, report.shift_attempts, |proof| {
                (proof.1.mode(), proof.0.banner.clone())
            }) {
                Ok(Some((proof, clause))) => {
                    unhinted_clause = clause;
                    Some(proof)
                }
                Ok(None) => {
                    unproved_hint = vmcore.hint();
                    None
                }
                Err(err) => return Err(err),
            }
        }
        _ => prove_under(
            &physical,
            &to_try,
            banner_virtual,
            page_table_virtual,
            &offered,
            &cache,
            options,
            &mut report,
        ),
    };
    let Some((candidate, spec, proved)) = attempt else {
        // An unhinted image may still say what it is in its VMCOREINFO.
        return Err(unproved(
            unproved_hint,
            &candidate.banner,
            report.shift_attempts,
            banner_virtual,
            &offered,
        ));
    };
    if to_try.len() > 1 {
        report.note(format!(
            "physical memory held {} distinct banner strings and no symbol file named which \
             build to expect, so each was offered to the page-table proof; the one that proved \
             is the kernel this profile describes",
            to_try.len()
        ));
    }
    // The paging depth is control-register state that no capture records, so
    // saying which one was used is not enough — a report has to be able to say
    // it was demonstrated. See `PAGING_MODES`.
    report.note(format!(
        "the paging depth was established by proof rather than assumed: the kernel's page tables \
         were walked at each of {}, and '{}' is the one that translated '{}' back to the physical \
         address the sweep found it at{}",
        mode_list(&offered),
        spec.mode(),
        BANNER_SYMBOL,
        match hint {
            ArchitectureHint::Unknown => unhinted_clause.clone(),
            known => format!(
                "; only {} modes were offered, because the symbol table declares a symbol only \
                 that architecture defines",
                match known {
                    ArchitectureHint::Arm64 => "arm64",
                    _ => "x86-64",
                }
            ),
        }
    ));
    if !spec.mode().is_intel() {
        report.note(
            "arm64: the page tables proved. The analysis stages that follow were written \
             against x86-64 kernels; on arm64 they have been checked on one capture only, a \
             QEMU-emulated Debian 4.19 guest (4 KiB pages, 48-bit VA), where the process list \
             and its physical-sweep cross-view, the module list, the kernel log, memory maps, \
             command lines, bash history and mounts agreed with that kernel's own structures. \
             Open files, sockets, environment variables, capabilities and hooks ran there but \
             were not graded. Nothing has been checked on ARM64 hardware, on 16 or 64 KiB \
             pages, or on an arm64 kernel newer than 4.19, and swap resolution does not run on \
             arm64",
        );
    }

    let kernel_space: Arc<dyn MemoryLayer> = proved.space;
    let probe = LinuxLayerProbe::new(Arc::clone(&kernel_space), 8, Some(candidate.banner.clone()));
    for result in image_sanity_gates(&table, &probe) {
        table.record_gate(result);
    }
    // The symbol file was matched to this image by its banner, and a banner is
    // not unique to a build. This is the only check that can tell a correct
    // match from a plausible one, because it compares the symbol file against
    // the kernel's own account of itself rather than against another name.
    //
    // It runs **only** for a table that came from a file. A table built from
    // the image's own BTF would be compared against the BTF it was built from,
    // which agrees with itself by construction: the gate would pass every time
    // and record a corroboration that never happened. Recording a
    // `NotApplicable` instead states the fact — this table has no independent
    // second source — where an examiner and a report will both see it.
    match &chosen {
        Chosen::File { .. } => {
            table.record_gate(btf_corroboration_gate(&table, physical.as_data_source()));
        }
        Chosen::Image { .. } => {
            table.record_gate(GateResult::not_applicable(
                Gate::ImageSanity,
                "linux_btf_layout_agreement",
                "these layouts were read out of this image's own BTF, so checking them against \
                 that BTF would compare a source with itself; no independent description of this \
                 kernel was available to corroborate them",
            ));
        }
    }
    // Gate 4 is the only check that can falsify a table which already agreed
    // with the image on the banner, and a table it falsified must not reach a
    // single analysis stage. `AdmissionState::Rejected` is defined as "no
    // symbol-dependent analysis runs"; returning a profile holding a rejected
    // table would make that definition unenforceable.
    if table.state() == AdmissionState::Rejected {
        return Err(DiscoveryError::SymbolsRejected {
            path: chosen.origin_label(),
            banner: candidate.banner.clone(),
            source: SymbolError::Rejected(Box::new(table.admission().clone())),
        });
    }

    let build = LinuxBuild {
        release: LinuxBuild::release_from_banner(&candidate.banner),
        banner: candidate.banner.clone(),
        symbols_from: chosen.origin(),
    };
    debug!(
        "linux discovery: {} DTB {:#x} from {} (shift {:#x})",
        build.banner, proved.dtb, dtb_symbol, proved.shift.shift
    );

    let profile = LinuxProfile {
        kernel_space,
        physical,
        symbols: Arc::new(table),
        // Derived from a symbol, then proved by translating the banner back to
        // the physical address it was found at. Not `Confirmed`: nothing in the
        // image published this value, so the strongest honest grade is the one
        // that says "scanned, then independently checked".
        dtb: Found::new(proved.dtb, Evidence::Validated),
        dtb_symbol,
        kernel_shift: Found::new(proved.shift, Evidence::Validated),
        build,
        architecture: if spec.mode().is_intel() {
            LayerArch::X64
        } else {
            LayerArch::Arm64
        },
        paging: spec,
        cache,
        // Attached by the analysis layer after discovery, from the swap areas the
        // examiner supplied; discovery itself attaches none.
        swap: Vec::new(),
    };
    Ok((profile, report))
}

/// Which description of the kernel discovery settled on.
///
/// Kept as one value rather than two `Option`s so that the places downstream
/// which must behave differently — the layout-agreement gate, above all — have
/// to say which case they are handling instead of testing a flag and getting it
/// wrong.
enum Chosen {
    /// A symbol file the lab holds, matched by banner.
    File {
        candidate: BannerCandidate,
        isf: Box<IsfCandidate>,
    },
    /// The kernel's own account of itself, read out of the image.
    Image {
        candidate: BannerCandidate,
        recovered: Box<image_symbols::RecoveredSymbols>,
    },
}

impl Chosen {
    fn candidate(&self) -> &BannerCandidate {
        match self {
            Chosen::File { candidate, .. } | Chosen::Image { candidate, .. } => candidate,
        }
    }

    /// Where these symbols came from, for the profile and the report.
    fn origin(&self) -> SymbolOrigin {
        match self {
            Chosen::File { isf, .. } => SymbolOrigin::SymbolFile {
                path: isf.path.display().to_string(),
            },
            Chosen::Image { recovered, .. } => SymbolOrigin::ImageDerived {
                btf_at: recovered.btf_at,
                kallsyms_at: recovered.kallsyms_at,
                type_count: recovered.type_count,
                symbol_count: recovered.symbol_count,
                sha256: recovered.source.provenance.json_sha256.clone(),
            },
        }
    }

    /// What to name as the source in an error.
    ///
    /// A path when there is one. When there is not, a sentence rather than a
    /// path-shaped string: an examiner reading a rejection must not go looking
    /// for a file that was never on disk.
    fn origin_label(&self) -> String {
        match self {
            Chosen::File { isf, .. } => isf.path.display().to_string(),
            Chosen::Image { recovered, .. } => format!(
                "symbols recovered from the image itself ({})",
                recovered.summary()
            ),
        }
    }
}

/// Discover a profile, discarding the report.
pub fn discover(
    physical: Arc<dyn MemoryLayer>,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
) -> Result<LinuxProfile, DiscoveryError> {
    discover_reported(physical, symbol_dirs, options).map(|(profile, _)| profile)
}

/// Turn a compile failure into the most specific thing that can be said about
/// it.
///
/// A refusal whose only failing gate is the architecture one means this tier
/// cannot read that kernel, which is a different sentence from "the symbol file
/// is bad" and sends the examiner somewhere different.
fn architecture_or_rejection(
    isf: &IsfCandidate,
    banner: &str,
    source: SymbolError,
) -> DiscoveryError {
    if let SymbolError::Rejected(report) = &source {
        let failures: Vec<&GateResult> = report
            .gates
            .iter()
            .filter(|gate| gate.outcome == GateOutcome::Fail)
            .collect();
        if !failures.is_empty() && failures.iter().all(|gate| gate.gate == Gate::Architecture) {
            return DiscoveryError::UnsupportedArchitecture {
                banner: banner.to_string(),
                // The table was refused before its width could be read, so
                // there is no number to quote. The gate's own detail carries
                // what it found, and it travels in the admission report.
                reason: "its symbol table was refused by the architecture gate, which compares \
                         its declared pointer width against the 64-bit address space this tier \
                         builds"
                    .to_string(),
            };
        }
    }
    DiscoveryError::SymbolsRejected {
        path: isf.path.display().to_string(),
        banner: banner.to_string(),
        source,
    }
}

/// Offer every banner candidate to the proof under each of `modes`, in
/// order, and keep the first that proves.
#[allow(clippy::too_many_arguments)]
fn prove_under(
    physical: &Arc<dyn MemoryLayer>,
    to_try: &[BannerCandidate],
    banner_virtual: u64,
    page_table_virtual: u64,
    modes: &[PagingMode],
    cache: &Arc<TableCache>,
    options: &DiscoveryOptions,
    report: &mut DiscoveryReport,
) -> Option<(BannerCandidate, PagingSpec, ProvedPageTables)> {
    for trying in to_try {
        for mode in modes {
            let spec = PagingSpec::new(*mode, PteSemantics::Linux);
            if let Some(proved) = prove_page_tables(
                physical,
                trying,
                banner_virtual,
                page_table_virtual,
                spec,
                cache,
                options,
                report,
            ) {
                return Some((trying.clone(), spec, proved));
            }
        }
    }
    None
}

/// For an image whose symbol table names no architecture: the one family
/// that proved, or both back when both did.
fn settle_unhinted<T>(intel: Option<T>, arm64: Option<T>) -> Result<Option<T>, (T, T)> {
    match (intel, arm64) {
        (Some(intel), Some(arm64)) => Err((intel, arm64)),
        (intel, arm64) => Ok(intel.or(arm64)),
    }
}

/// What the image's own `VMCOREINFO` says about the kernel's architecture,
/// kept apart from whether the check could look at all.
///
/// [`crate::vmcoreinfo::VmcoreSweep::agreed`] distinguishes "a complete sweep
/// found no note" from "the sweep could not settle it"; collapsing both into
/// "names nothing" would let a report read as if the architecture had been
/// checked when it had not.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VmcoreinfoCheck {
    /// Every copy agrees, the sweep was complete, and the note names this
    /// architecture.
    Names(ArchitectureHint),
    /// Every copy agrees on a complete sweep, and the note carries no line
    /// only one architecture writes.
    NamesNeither,
    /// A complete sweep found no copy.
    Absent,
    /// The check could not settle the question: the sweep failed, was cut
    /// short, or found copies that disagree.
    CouldNotLook {
        /// Why, as a clause.
        reason: String,
        /// Whether any copy that was found names an arm64 kernel.
        arm64_seen: bool,
    },
}

impl VmcoreinfoCheck {
    /// The architecture it settles, if it settles one.
    fn hint(&self) -> ArchitectureHint {
        match self {
            VmcoreinfoCheck::Names(hint) => *hint,
            _ => ArchitectureHint::Unknown,
        }
    }

    /// What the check found, as a clause for a note or a refusal.
    fn clause(&self) -> String {
        match self {
            VmcoreinfoCheck::Names(ArchitectureHint::Arm64) => {
                "the image's VMCOREINFO (every copy agreeing, on a complete sweep) names an arm64 \
                 kernel"
                    .to_string()
            }
            VmcoreinfoCheck::Names(_) => "the image's VMCOREINFO (every copy agreeing, on a \
                                          complete sweep) names an x86-64 kernel"
                .to_string(),
            VmcoreinfoCheck::NamesNeither => "the image's VMCOREINFO (every copy agreeing, on a \
                                              complete sweep) carries no line only one \
                                              architecture writes"
                .to_string(),
            VmcoreinfoCheck::Absent => {
                "a complete sweep found no VMCOREINFO in the image".to_string()
            }
            VmcoreinfoCheck::CouldNotLook { reason, arm64_seen } => format!(
                "the image's VMCOREINFO could not settle it ({reason}){}",
                if *arm64_seen {
                    "; a copy that was found names an arm64 kernel"
                } else {
                    ""
                }
            ),
        }
    }
}

/// Sweep the image for `VMCOREINFO` and say what it establishes about the
/// architecture, including when it establishes nothing because it could not
/// look.
fn vmcoreinfo_check(physical: &dyn MemoryLayer) -> VmcoreinfoCheck {
    use crate::vmcoreinfo::VmcoreArchitecture;
    let sweep = match crate::vmcoreinfo::sweep(physical) {
        Ok(sweep) => sweep,
        Err(err) => {
            return VmcoreinfoCheck::CouldNotLook {
                reason: format!("the VMCOREINFO sweep failed: {err}"),
                arm64_seen: false,
            }
        }
    };
    let arm64_seen = sweep
        .found
        .iter()
        .any(|(_, info)| info.architecture() == VmcoreArchitecture::Arm64);
    match sweep.agreed() {
        Ok(Some(info)) => match info.architecture() {
            VmcoreArchitecture::Arm64 => VmcoreinfoCheck::Names(ArchitectureHint::Arm64),
            VmcoreArchitecture::X86_64 => VmcoreinfoCheck::Names(ArchitectureHint::X86_64),
            VmcoreArchitecture::Unknown => VmcoreinfoCheck::NamesNeither,
        },
        Ok(None) => VmcoreinfoCheck::Absent,
        Err(err) => VmcoreinfoCheck::CouldNotLook {
            reason: err.to_string(),
            arm64_seen,
        },
    }
}

/// Settle an unhinted table's two families of proof against what the image's
/// `VMCOREINFO` says: the proof to take with the clause the profile note
/// carries, `Ok(None)` when neither family proved, or the refusal.
///
/// `describe` gives a proof's mode and the banner it was proved for.
fn settle_architecture<T>(
    intel: Option<T>,
    arm64: Option<T>,
    vmcore: &VmcoreinfoCheck,
    attempts: usize,
    describe: impl Fn(&T) -> (PagingMode, String),
) -> Result<Option<(T, String)>, DiscoveryError> {
    match settle_unhinted(intel, arm64) {
        Ok(None) => Ok(None),
        Ok(Some(only)) => {
            let (mode, banner) = describe(&only);
            let (family, other) = if mode.is_intel() {
                ("x86-64", "arm64 regime")
            } else {
                ("arm64", "x86-64 mode")
            };
            // An x86-64 proof alone is not taken while any VMCOREINFO copy
            // the sweep found names an arm64 kernel — agreed or not, complete
            // or not: an arm64 hierarchy can read as a valid x86-64 one.
            let arm64_named = match vmcore {
                VmcoreinfoCheck::Names(hint) => *hint == ArchitectureHint::Arm64,
                VmcoreinfoCheck::CouldNotLook { arm64_seen, .. } => *arm64_seen,
                _ => false,
            };
            if mode.is_intel() && arm64_named {
                return Err(intel_proof_vetoed(
                    &banner,
                    mode,
                    attempts,
                    &vmcore.clause(),
                ));
            }
            let corroboration = match vmcore {
                VmcoreinfoCheck::Names(hint) if *hint != ArchitectureHint::Unknown => "",
                _ => {
                    "; the architecture rests on the page-table proof alone and is not \
                     corroborated by anything else in the image"
                }
            };
            Ok(Some((
                only,
                format!(
                    "; the symbol table named no architecture and no {other} proved, so it is \
                     read as {family}; {}{corroboration}",
                    vmcore.clause()
                ),
            )))
        }
        Err((intel, arm64)) => {
            let (intel_mode, banner) = describe(&intel);
            let (arm64_mode, _) = describe(&arm64);
            let taken = match vmcore {
                VmcoreinfoCheck::Names(ArchitectureHint::Arm64) => Some((arm64, arm64_mode)),
                VmcoreinfoCheck::Names(ArchitectureHint::X86_64) => Some((intel, intel_mode)),
                _ => None,
            };
            match taken {
                Some((proof, mode)) => {
                    let other = if mode.is_intel() {
                        arm64_mode
                    } else {
                        intel_mode
                    };
                    Ok(Some((
                        proof,
                        format!(
                            "; the symbol table named no architecture and both families proved \
                             ('{mode}' and '{other}'); {}, so '{mode}' was taken",
                            vmcore.clause()
                        ),
                    )))
                }
                None => Err(DiscoveryError::ArchitectureUndetermined {
                    banner,
                    intel: intel_mode.to_string(),
                    arm64: arm64_mode.to_string(),
                    vmcoreinfo: vmcore.clause(),
                }),
            }
        }
    }
}

/// A page-table root that was proved by using it.
struct ProvedPageTables {
    space: Arc<dyn MemoryLayer>,
    dtb: u64,
    shift: KernelShift,
}

/// Try each physical location the banner was found at until one yields a
/// page-table root that translates the banner back to that same location.
///
/// The banner appears in memory more than once — the kernel's own copy, the
/// printk ring buffer, a cached `/proc/version` page — and only the kernel's own
/// copy sits at the virtual address the ISF names. Trying each and keeping the
/// one that *works* is what turns a scan result into a proved fact; picking the
/// first hit would be a guess that succeeds most of the time and fails silently
/// the rest.
#[allow(clippy::too_many_arguments)]
fn prove_page_tables(
    physical: &Arc<dyn MemoryLayer>,
    candidate: &BannerCandidate,
    banner_virtual: u64,
    page_table_virtual: u64,
    spec: PagingSpec,
    cache: &Arc<TableCache>,
    options: &DiscoveryOptions,
    report: &mut DiscoveryReport,
) -> Option<ProvedPageTables> {
    for physical_address in candidate.physical.iter().take(options.max_shift_attempts) {
        report.shift_attempts = report.shift_attempts.saturating_add(1);
        let Some(shift) = banner_virtual.checked_sub(*physical_address) else {
            continue;
        };
        let Some(dtb) = page_table_virtual.checked_sub(shift) else {
            continue;
        };
        // A page-table root is page-aligned and inside the acquired image. Both
        // are cheap and both reject a shift derived from a copy of the banner
        // that is not the kernel's own.
        if dtb == 0 || dtb % 0x1000 != 0 || dtb > physical.max_address() {
            continue;
        }
        let Ok(space) = VirtualLayer::with_cache(
            Arc::clone(physical),
            dtb,
            spec,
            TranslationPolicy::default(),
            Arc::clone(cache),
        ) else {
            continue;
        };
        // The proof: walk the tables to the banner's virtual address and land
        // on the physical address the sweep found it at, then read the bytes
        // there and get the same banner back.
        let Ok(translation) = space.translate(banner_virtual) else {
            continue;
        };
        if translation.phys != *physical_address {
            continue;
        }
        let space: Arc<dyn MemoryLayer> = Arc::new(space);
        match read_banner_at(&*space, banner_virtual) {
            Some(read_back) if read_back == candidate.banner => {
                return Some(ProvedPageTables {
                    space,
                    dtb,
                    shift: KernelShift {
                        shift,
                        banner_virtual,
                        banner_physical: *physical_address,
                    },
                })
            }
            _ => continue,
        }
    }
    None
}

/// The banner at an address in a layer, or nothing when the bytes there are not
/// one.
fn read_banner_at(layer: &dyn MemoryLayer, address: u64) -> Option<String> {
    let mut buf = vec![0u8; MAX_BANNER_BYTES as usize];
    let read = seance_core::io::read_full(layer.as_data_source(), address, &mut buf);
    buf.truncate(read);
    banner_from_bytes(&buf)
}

/// The normalised banner at the start of `bytes`, or nothing.
///
/// A real banner is NUL-terminated inside the window. Bytes with no NUL are
/// rejected rather than truncated at the window's edge: the resulting string
/// would differ from the ISF's by however much was cut off, and it would then
/// fail to match a symbol file that describes exactly this kernel.
pub fn banner_from_bytes(bytes: &[u8]) -> Option<String> {
    if !bytes.starts_with(BANNER_NEEDLE) {
        return None;
    }
    let end = bytes.iter().position(|&b| b == 0)?;
    let banner = normalize_banner(&bytes[..end]).ok()?;
    // "Linux version " plus a release is the shortest thing that can be one.
    if banner.len() <= BANNER_NEEDLE.len() {
        return None;
    }
    Some(banner)
}

/// Sweep physical memory for the kernel banner.
fn sweep_for_banner(
    physical: &dyn MemoryLayer,
    options: &DiscoveryOptions,
) -> Result<BannerSweep, DiscoveryError> {
    let scanner = SingleStringScanner::new("linux_banner", BANNER_NEEDLE)
        .map_err(|err| DiscoveryError::ImageUnreadable(err.to_string()))?;
    let config = ScanConfig {
        max_hits: options.max_banner_hits,
        ..ScanConfig::default()
    };
    let outcome = scan_layer(physical, &scanner, &config)
        .map_err(|err| DiscoveryError::ImageUnreadable(err.to_string()))?;

    let mut sweep = BannerSweep {
        hits: outcome.hits.len(),
        bytes_scanned: outcome.bytes_scanned,
        complete: outcome.is_complete(),
        ..BannerSweep::default()
    };
    for hit in &outcome.hits {
        let Some(banner) = read_banner_at(physical, hit.address) else {
            continue;
        };
        // One banner, several addresses: the kernel's own copy in `.rodata`,
        // plus whatever `/proc/version` and the printk ring buffer have left
        // behind. Every address is kept, because which one the ISF's symbol
        // refers to is decided later by whether the resulting page tables work.
        let existing = sweep
            .candidates
            .iter()
            .position(|candidate| candidate.banner == banner);
        match existing {
            Some(index) => sweep.candidates[index].physical.push(hit.address),
            None => {
                if sweep.candidates.len() >= options.max_banner_candidates {
                    continue;
                }
                sweep.candidates.push(BannerCandidate {
                    banner,
                    physical: vec![hit.address],
                });
            }
        }
    }
    Ok(sweep)
}

/// The banner a Linux ISF declares, if it is a Linux ISF and declares one.
pub fn linux_banner_of(path: &Path) -> Option<String> {
    let identity = identify_path(path, &IdentifyOptions::default()).ok()?;
    if identity.os != IsfOs::Linux {
        return None;
    }
    identity.identifier
}

/// Every Linux ISF under `dirs`, with the banner each declares.
///
/// Unlike a Windows symbol store, a Linux ISF's file name carries no identity a
/// search can hint on, so every candidate is identified. Identification is a
/// single structural pass that deserialises only the metadata block and the
/// banner symbol, which is why this is affordable; it is still bounded, and a
/// bound that fires marks the search truncated so "no symbols" is never confused
/// with "we stopped looking".
fn find_linux_isfs(dirs: &[PathBuf], options: &DiscoveryOptions) -> IsfSearch {
    let (files, truncated) = collect_isf_files(dirs, options.max_isf_files, options.max_isf_depth);
    let mut search = IsfSearch {
        files_seen: files.len(),
        truncated,
        ..IsfSearch::default()
    };
    for path in files {
        if search.files_identified >= options.max_isf_identified {
            search.truncated = true;
            break;
        }
        search.files_identified += 1;
        let Some(banner) = linux_banner_of(&path) else {
            continue;
        };
        search.candidates.push(IsfCandidate { path, banner });
    }
    search
}

/// The first of `candidates` this build declares as a symbol, and its address.
///
/// The symbol-name half of the build-variant problem: `init_level4_pgt`,
/// `swapper_pg_dir` and `init_top_pgt` are three names for one thing across
/// kernel generations, and asking for the wrong one is not a broken image.
pub fn first_declared_symbol(
    table: &SymbolTable,
    candidates: &[&'static str],
) -> Option<(&'static str, u64)> {
    for name in candidates {
        if !table.has_symbol(name) {
            continue;
        }
        if let Ok(address) = table.symbol_address(name) {
            return Some((*name, address));
        }
    }
    None
}

/// `'a', 'b'` — candidate names for a message an examiner reads.
fn name_list(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The same rendering for paging modes, which name themselves (an arm64
/// regime with its VA width, since two regimes of one granule differ only in
/// it).
fn mode_list(modes: &[PagingMode]) -> String {
    modes
        .iter()
        .map(|mode| format!("'{mode}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Only the kernel's own BTF describes this many types; a module's carries a
/// handful, and accepting one would compare the symbol file against a fraction
/// of the kernel.
const KERNEL_BTF_MIN_TYPES: usize = 20_000;

/// How many struct layouts to cross-check against the kernel's own BTF.
///
/// A sample, not the whole table: the point is to catch an ISF that describes a
/// *different build*, and a wrong build disagrees on hundreds of structures, not
/// on one. Bounded so a gate cannot cost minutes on a large image.
const BTF_CORROBORATION_SAMPLE: usize = 400;

/// Cross-check the matched ISF against the type information the kernel carries
/// about itself.
///
/// # What this catches that nothing else can
///
/// An ISF is matched to an image by its `linux_banner`. Banners are not unique
/// to a build: two kernels from the same distribution and version, differing in
/// configuration, can carry byte-identical banners and *different* struct
/// layouts. A wrong-but-plausible match is then admitted, and every member
/// offset read afterwards is silently wrong — a `task_struct.comm` read at the
/// wrong offset returns bytes, and those bytes go into a report as a process
/// name.
///
/// No amount of banner matching detects this, because the banner is what
/// matched. BTF does, because it is the kernel's own account of itself, and it
/// is in the image rather than in the symbol file.
///
/// # Why disagreement is a failure and absence is not
///
/// A kernel built without `CONFIG_DEBUG_INFO_BTF` — anything much before 2020 —
/// carries none, and that says nothing about the ISF. Absence is
/// `NotApplicable`. Disagreement is a `Fail`: the two sources describe
/// different builds, and only one of them came out of the evidence.
fn btf_corroboration_gate(table: &SymbolTable, image: &dyn DataSource) -> GateResult {
    btf_corroboration_gate_with(table, image, KERNEL_BTF_MIN_TYPES)
}

/// [`btf_corroboration_gate`] with the "is this the kernel's own BTF" threshold
/// injectable, so tests can use a blob of a handful of types rather than a
/// six-megabyte one.
fn btf_corroboration_gate_with(
    table: &SymbolTable,
    image: &dyn DataSource,
    min_types: usize,
) -> GateResult {
    const CHECK: &str = "linux_btf_layout_agreement";

    let btf = match find_kernel_btf(image, min_types) {
        BtfSearch::Found(btf) => btf,
        BtfSearch::NotPresent => {
            return GateResult::not_applicable(
                Gate::ImageSanity,
                CHECK,
                "no kernel BTF was found in this image, so the symbol file's layout \
                 could not be checked against the kernel's own account of itself. \
                 Kernels built without CONFIG_DEBUG_INFO_BTF (broadly, before 2020) \
                 carry none, and its absence says nothing about the symbols"
                    .to_string(),
            );
        }
        // Said separately from an absence on purpose: this check did not run to
        // completion, so reporting it as "no BTF present" would record a
        // corroboration that never happened.
        BtfSearch::Capped { scanned, total } => {
            return GateResult::not_applicable(
                Gate::ImageSanity,
                CHECK,
                format!(
                    "the search for the kernel's BTF stopped after {scanned} of {total} \
                     byte(s), so the symbol file was NOT checked against the kernel's \
                     own layout. This is a capped search, not an absence: the kernel \
                     may well describe itself further into the image"
                ),
            );
        }
    };

    let mut agreed = 0usize;
    let mut violations: Vec<String> = Vec::new();
    let mut checked_types = 0usize;

    for name in btf.composite_names().take(BTF_CORROBORATION_SAMPLE) {
        let Some(composite) = btf.composite(name) else {
            continue;
        };
        // A type the ISF does not declare is not a disagreement: the two
        // producers cover different subsets, and DWARF prunes what nothing
        // references.
        if !table.has_type(name) {
            continue;
        }
        checked_types += 1;
        for member in &composite.members {
            if member.name.is_empty() || member.bitfield_size.is_some() {
                continue;
            }
            let Some(expected) = member.byte_offset() else {
                continue;
            };
            let Ok(actual) = table.member_offset(name, &member.name) else {
                continue;
            };
            if actual == expected {
                agreed += 1;
            } else {
                violations.push(format!(
                    "{name}.{}: the symbol file says byte {actual}, the kernel's own BTF says byte {expected}",
                    member.name
                ));
            }
        }
    }

    if checked_types == 0 {
        return GateResult::not_applicable(
            Gate::ImageSanity,
            CHECK,
            "the kernel's BTF and the symbol file declare no types in common, so there was nothing to compare"
                .to_string(),
        );
    }

    if violations.is_empty() {
        GateResult::pass(
            Gate::ImageSanity,
            CHECK,
            format!(
                "{agreed} member offset(s) across {checked_types} structure(s) agree with the type information this kernel carries about itself, so the symbol file describes this build and not merely one with the same banner"
            ),
        )
    } else {
        let mut result = GateResult::fail(
            Gate::ImageSanity,
            CHECK,
            format!(
                "the symbol file disagrees with the kernel's own BTF on {} member offset(s) across {checked_types} structure(s) ({agreed} agreed). Two kernels can share a banner and differ in layout, so this is a symbol file for a DIFFERENT BUILD. Every offset read through it is suspect, and the BTF is the source that came out of the evidence",
                violations.len()
            ),
        );
        result.violations = violations.into_iter().take(16).collect();
        result
    }
}

/// Locate the kernel's own BTF in a memory image.
///
/// Sweeps in windows with an overlap, so a blob straddling a boundary is not
/// missed. `None` when the kernel carries none, which is ordinary for anything
/// much before 2020.
/// How much of an image to sweep looking for the kernel's BTF.
///
/// The sweep is linear in bytes read and those bytes are usually compressed, so
/// it costs about a minute per 15 GiB. Unbounded, a large server capture would
/// add many minutes to every discovery for a check that is corroboration rather
/// than a prerequisite. Bounded, a capture larger than this gets the check over
/// its first 16 GiB and is told so.
const BTF_SEARCH_LIMIT: u64 = 16 * 1024 * 1024 * 1024;

/// The result of looking for the kernel's own BTF.
///
/// Three outcomes, not two. "Searched everything and found none" and "stopped
/// before the end" are different facts about the evidence, and reporting a
/// capped search as an absence would let a wrong-ISF check quietly not happen.
enum BtfSearch {
    Found(Box<seance_memory::btf::Btf>),
    /// The whole image was swept and no kernel BTF is in it.
    NotPresent,
    /// The sweep hit [`BTF_SEARCH_LIMIT`] first.
    Capped {
        scanned: u64,
        total: u64,
    },
}

/// Locate the kernel's own BTF in a memory image.
///
/// Sweeps in windows with an overlap, so a blob straddling a boundary is not
/// missed, and stops at [`BTF_SEARCH_LIMIT`].
fn find_kernel_btf(image: &dyn DataSource, min_types: usize) -> BtfSearch {
    find_kernel_btf_limited(image, min_types, BTF_SEARCH_LIMIT)
}

/// [`find_kernel_btf`] with the sweep bound injectable, so a test can exercise
/// the capped outcome without a 16 GiB fixture.
fn find_kernel_btf_limited(image: &dyn DataSource, min_types: usize, limit: u64) -> BtfSearch {
    const WINDOW: u64 = 64 * 1024 * 1024;
    const OVERLAP: u64 = 16 * 1024 * 1024;

    let total = image.size();
    let end = total.min(limit);
    let mut buffer = vec![0u8; WINDOW.min(end.max(1)) as usize];
    let mut at = 0u64;
    while at < end {
        let want = WINDOW.min(end - at) as usize;
        if want > buffer.len() {
            buffer.resize(want, 0);
        }
        if image.read_at(at, &mut buffer[..want]).is_ok() {
            if let Some((_, btf)) = seance_memory::btf::Btf::find_in(&buffer[..want], min_types) {
                return BtfSearch::Found(Box::new(btf));
            }
        }
        at = at.saturating_add(WINDOW.saturating_sub(OVERLAP));
    }
    if end < total {
        BtfSearch::Capped {
            scanned: end,
            total,
        }
    } else {
        BtfSearch::NotPresent
    }
}

/// Gate 4: read typed fields through the candidate table and see whether they
/// make sense.
///
/// The banner already proved this table is *for* this kernel and the page-table
/// proof already established the address space. What is left to falsify is the
/// table's **layout** claims, which a corrupted or hand-edited symbol pack can
/// break while leaving the metadata block intact. Each check distinguishes three
/// outcomes, and the distinction is the point:
///
/// - the field read and its value is implausible: **fail**, and the table is
///   refused;
/// - the field could not be read at all: **inconclusive**, because an unacquired
///   page says nothing about the table;
/// - the table does not declare the field: **not applicable**, which is a fact
///   about the build and must not hold the table at unverified for it.
fn image_sanity_gates(table: &SymbolTable, probe: &LinuxLayerProbe) -> Vec<GateResult> {
    use seance_symbols::ImageProbe;

    let mut results = Vec::new();
    const TASK: &str = "task_struct";

    let Ok(init_task) = table.symbol_address(INIT_TASK_SYMBOL) else {
        results.push(GateResult::not_applicable(
            Gate::ImageSanity,
            "linux_init_task_comm",
            format!(
                "this build's symbol set has no '{INIT_TASK_SYMBOL}', so there is no known \
                 structure to read a layout check out of"
            ),
        ));
        return results;
    };

    if !table.has_member(TASK, "comm") {
        results.push(GateResult::not_applicable(
            Gate::ImageSanity,
            "linux_init_task_comm",
            format!("this build's {TASK} declares no 'comm' member to read"),
        ));
    } else {
        match table.member_offset(TASK, "comm") {
            Ok(offset) => match init_task.checked_add(offset) {
                Some(address) => {
                    let mut buf = [0u8; 16];
                    match probe.read_exact(address, &mut buf) {
                        Ok(()) => results.push(comm_verdict(&buf, address)),
                        Err(err) => results.push(GateResult::inconclusive(
                            Gate::ImageSanity,
                            "linux_init_task_comm",
                            format!("{TASK}.comm at {address:#x} could not be read: {err}"),
                        )),
                    }
                }
                None => {
                    let mut result = GateResult::fail(
                        Gate::ImageSanity,
                        "linux_init_task_comm",
                        "the offset of task_struct.comm does not fit above init_task",
                    );
                    result.violate(format!(
                        "init_task at {init_task:#x} plus the declared offset {offset} overflows \
                         the address space"
                    ));
                    results.push(result);
                }
            },
            Err(err) => results.push(GateResult::not_evaluated(
                Gate::ImageSanity,
                "linux_init_task_comm",
                format!("{TASK}.comm has no resolvable offset in this table: {err}"),
            )),
        }
    }

    results.push(task_link_gate(table, probe, init_task));
    results
}

/// What `init_task.comm` says about the table's layout.
///
/// Every Linux kernel names its idle task `swapper` — `swapper/0` since the
/// per-CPU idle threads were named in 2.6.x. Reading that string at the offset
/// this table declares is a direct test of the declared layout against the
/// image.
///
/// Anything printable that is not `swapper` is **inconclusive**, not a failure:
/// the bytes read, so the evidence is sound, and this check simply cannot decide
/// for a kernel that names its idle task something else. Bytes that are not a
/// NUL-terminated printable name at all are a failure, because no kernel's
/// `comm` looks like that and the offset must therefore be wrong.
fn comm_verdict(bytes: &[u8], address: u64) -> GateResult {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let name = &bytes[..end];
    let printable = !name.is_empty() && name.iter().all(|&b| (0x20..0x7F).contains(&b));
    if !printable {
        let mut result = GateResult::fail(
            Gate::ImageSanity,
            "linux_init_task_comm",
            "the table's task_struct layout does not describe this image",
        );
        result.violate(format!(
            "task_struct.comm at {address:#x} holds {bytes:02x?}, which is not a process name"
        ));
        return result;
    }
    let name = String::from_utf8_lossy(name).to_string();
    if name.starts_with("swapper") {
        GateResult::pass(
            Gate::ImageSanity,
            "linux_init_task_comm",
            format!("task_struct.comm at init_task reads '{name}', which is the idle task"),
        )
    } else {
        GateResult::inconclusive(
            Gate::ImageSanity,
            "linux_init_task_comm",
            format!(
                "task_struct.comm at init_task reads '{name}' rather than a 'swapper' name; the \
                 bytes read cleanly, so this check cannot decide either way"
            ),
        )
    }
}

/// Whether a list link points into the kernel's half of a 48-bit address space.
///
/// x86-64 kernel addresses start at `0xffff_8000_0000_0000`, but an arm64
/// kernel with 48-bit virtual addresses starts its linear map at
/// `0xffff_0000_0000_0000` (since 5.4; a 64 KiB-page Ubuntu 6.8 kernel's slab
/// links read `0xffff_0000_087e_d468`), so the bound is the arm64 one, which
/// the x86-64 range lies inside.
fn is_kernel_link(link: u64) -> bool {
    link >= 0xFFFF_0000_0000_0000
}

/// Whether `init_task.tasks.next` holds a kernel address.
///
/// The process list's first link. A table describing a different build puts
/// `tasks` at a different offset, and the bytes there are overwhelmingly
/// unlikely to be a 64-bit kernel-half pointer.
fn task_link_gate(table: &SymbolTable, probe: &LinuxLayerProbe, init_task: u64) -> GateResult {
    use seance_symbols::ImageProbe;

    let check = "linux_task_list_link";
    if !table.has_member("task_struct", "tasks") || !table.has_member("list_head", "next") {
        return GateResult::not_applicable(
            Gate::ImageSanity,
            check,
            "this build declares no task_struct.tasks or no list_head.next, so there is no \
             process-list link to check",
        );
    }
    let (Ok(tasks), Ok(next)) = (
        table.member_offset("task_struct", "tasks"),
        table.member_offset("list_head", "next"),
    ) else {
        return GateResult::not_evaluated(
            Gate::ImageSanity,
            check,
            "task_struct.tasks or list_head.next has no resolvable offset in this table",
        );
    };
    let Some(address) = init_task
        .checked_add(tasks)
        .and_then(|base| base.checked_add(next))
    else {
        return GateResult::not_evaluated(
            Gate::ImageSanity,
            check,
            "the process-list link's address does not fit in the address space",
        );
    };
    let mut buf = [0u8; 8];
    if let Err(err) = probe.read_exact(address, &mut buf) {
        return GateResult::inconclusive(
            Gate::ImageSanity,
            check,
            format!("the process-list link at {address:#x} could not be read: {err}"),
        );
    }
    let link = u64::from_le_bytes(buf);
    // A link into user space, or a null one, means this is not a `list_head`.
    if is_kernel_link(link) {
        GateResult::pass(
            Gate::ImageSanity,
            check,
            format!("init_task.tasks.next holds the kernel address {link:#x}"),
        )
    } else {
        let mut result = GateResult::fail(
            Gate::ImageSanity,
            check,
            "the table's task_struct layout does not describe this image",
        );
        result.violate(format!(
            "init_task.tasks.next at {address:#x} reads {link:#x}, which is not a kernel address"
        ));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_48_bit_arm64_linear_map_link_is_a_kernel_address() {
        // x86-64 slab, and the image mapping.
        assert!(is_kernel_link(0xffff_8800_1f99_4740));
        assert!(is_kernel_link(0xffff_ffff_8fc0_fb98));
        // arm64 with 48-bit VAs: PAGE_OFFSET 0xffff_0000_0000_0000 since 5.4.
        assert!(is_kernel_link(0xffff_0000_087e_d468));
        assert!(is_kernel_link(0xffff_0000_0000_0000));
        // Not kernel: null, user space, the canonical hole.
        assert!(!is_kernel_link(0));
        assert!(!is_kernel_link(0x0000_7fff_ffff_f000));
        assert!(!is_kernel_link(0xfffe_ffff_ffff_ffff));
    }

    const BANNER: &str = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) \
                          (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.57-3+deb7u2";

    #[test]
    fn a_banner_is_read_up_to_its_nul_and_normalised() {
        let mut bytes = BANNER.as_bytes().to_vec();
        bytes.extend_from_slice(b"\n\0");
        bytes.extend_from_slice(b"whatever follows in the image");
        assert_eq!(banner_from_bytes(&bytes).as_deref(), Some(BANNER));
    }

    #[test]
    fn bytes_with_no_terminator_are_not_a_banner() {
        // Truncating at the window's edge would produce a string that differs
        // from the ISF's by however much was cut off, and it would then fail to
        // match the symbol file that describes exactly this kernel — reported
        // as "no symbols for this build", which is a false statement about the
        // lab's symbol store.
        let bytes = BANNER.as_bytes().to_vec();
        assert_eq!(banner_from_bytes(&bytes), None);
    }

    #[test]
    fn something_that_merely_starts_like_a_banner_is_not_one() {
        assert_eq!(banner_from_bytes(b"Linux version \0"), None);
        assert_eq!(banner_from_bytes(b"not a banner\0"), None);
        assert_eq!(banner_from_bytes(b""), None);
    }

    #[test]
    fn a_swapper_comm_passes_and_a_printable_stranger_does_not_fail() {
        // The distinction the gate exists for: a table whose layout is wrong
        // reads bytes that are not a name at all, and that is a refusal. A
        // kernel that names its idle task something else is not a refusal, and
        // treating it as one would block the analysis of a perfectly good image.
        let swapper = comm_verdict(b"swapper/0\0\0\0\0\0\0\0", 0x1000);
        assert_eq!(swapper.outcome, GateOutcome::Pass);

        let stranger = comm_verdict(b"idle_task\0\0\0\0\0\0\0", 0x1000);
        assert_eq!(stranger.outcome, GateOutcome::Inconclusive);

        let rubbish = comm_verdict(&[0xFF; 16], 0x1000);
        assert_eq!(rubbish.outcome, GateOutcome::Fail);

        // Sixteen NULs is what a fabricated read of an unacquired page would
        // look like, and it must never read as a name.
        let zeros = comm_verdict(&[0x00; 16], 0x1000);
        assert_eq!(zeros.outcome, GateOutcome::Fail);
    }

    #[test]
    fn an_incomplete_sweep_that_found_nothing_is_not_a_statement_that_this_is_not_linux() {
        let complete = DiscoveryError::NoKernelBanner {
            bytes_scanned: 1024,
            swept_completely: true,
            sweep_state: "covered every acquired byte",
        };
        let partial = DiscoveryError::NoKernelBanner {
            bytes_scanned: 1024,
            swept_completely: false,
            sweep_state: "could not cover the whole image",
        };
        assert!(complete.means_not_a_linux_image());
        assert!(
            !partial.means_not_a_linux_image(),
            "an unfinished sweep establishes nothing, and calling it 'not Linux' would be a \
             claim about the part of the image nobody looked at"
        );
    }

    #[test]
    fn isf_file_names_are_recognised_by_suffix_alone() {
        assert!(is_isf_file_name(
            "Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"
        ));
        assert!(is_isf_file_name("vmlinux.json"));
        assert!(is_isf_file_name("VMLINUX.JSON.GZ"));
        assert!(!is_isf_file_name("vmlinux"));
        assert!(!is_isf_file_name("notes.txt"));
    }

    #[test]
    fn the_page_table_symbol_candidates_are_ordered_oldest_working_name_first() {
        // The order is the contract: a kernel declaring more than one must be
        // read through the one this list prefers, or two runs of the same image
        // could derive the DTB from different symbols.
        assert_eq!(
            PAGE_TABLE_SYMBOLS,
            ["init_level4_pgt", "swapper_pg_dir", "init_top_pgt"]
        );
        assert_eq!(
            name_list(&PAGE_TABLE_SYMBOLS),
            "'init_level4_pgt', 'swapper_pg_dir', 'init_top_pgt'"
        );
    }

    /// Build a physical image whose page tables translate a kernel virtual
    /// address to the banner bytes.
    ///
    /// `chain` is the walk from the top table down, one `(table physical
    /// address, index)` per level; the last entry points at the banner page.
    /// Writing it this way is what lets one helper stand up a four-level and a
    /// five-level hierarchy and keep the two comparable.
    fn banner_image(
        chain: &[(u64, u64)],
        banner_physical: u64,
        banner: &str,
    ) -> Arc<dyn MemoryLayer> {
        use seance_core::data_source::ByteSliceDataSource;

        let mut bytes = vec![0u8; 0x40_0000];
        {
            let mut put = |table: u64, index: u64, value: u64| {
                let at = (table + index * 8) as usize;
                bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
            };
            for (position, (table, index)) in chain.iter().enumerate() {
                let target = match chain.get(position + 1) {
                    Some((next_table, _)) => *next_table,
                    None => banner_physical,
                };
                // The present bit: everything on the path has to be resident or
                // the proof has nothing to walk.
                put(*table, *index, target | 1);
            }
        }
        let at = banner_physical as usize;
        bytes[at..at + banner.len()].copy_from_slice(banner.as_bytes());
        Arc::new(
            seance_memory::PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
                .expect("a non-empty image"),
        ) as Arc<dyn MemoryLayer>
    }

    /// Offer one image to the proof at one depth, exactly as `profile_image`
    /// does inside its loop.
    fn prove_at(
        physical: &Arc<dyn MemoryLayer>,
        banner: &str,
        banner_physical: u64,
        banner_virtual: u64,
        page_table_virtual: u64,
        mode: PagingMode,
    ) -> Option<ProvedPageTables> {
        let candidate = BannerCandidate {
            banner: normalize_banner(banner.as_bytes()).expect("a normalisable banner"),
            physical: vec![banner_physical],
        };
        prove_page_tables(
            physical,
            &candidate,
            banner_virtual,
            page_table_virtual,
            PagingSpec::new(mode, PteSemantics::Linux),
            &Arc::new(TableCache::new()),
            &DiscoveryOptions::default(),
            &mut DiscoveryReport::default(),
        )
    }

    #[test]
    fn the_paging_depth_is_the_one_that_proves_and_never_the_one_assumed() {
        // The defect: `PagingMode` had four-level x86-64 and nothing else, and
        // this module hardcoded it. Every kernel virtual address on an LA57
        // machine is 57-bit canonical, which four-level rules reject outright,
        // so discovery on such a capture ended at `PageTablesUnproved` and no
        // Linux memory analysis was possible at all.
        //
        // The fix is not "also try five levels": it is that the depth, which is
        // `CR4.LA57` and appears in no capture, is settled by the same proof
        // the directory table base already had to pass. This asserts both
        // directions of that, because a change that made LA57 work by assuming
        // it would break every four-level image and pass a one-sided test.
        const DTB: u64 = 0x10_0000;
        const BANNER_PHYSICAL: u64 = 0x20_0000;

        // Five levels: PML5 256, PML4 0, PDPT 0, PD 1, PT 0.
        const LA57_SHIFT: u64 = 0xFF00_0000_0000_0000;
        let la57 = banner_image(
            &[
                (DTB, 256),
                (0x10_1000, 0),
                (0x10_2000, 0),
                (0x10_3000, 1),
                (0x10_4000, 0),
            ],
            BANNER_PHYSICAL,
            BANNER,
        );
        let la57_banner_virtual = LA57_SHIFT + BANNER_PHYSICAL;
        let la57_page_table_virtual = LA57_SHIFT + DTB;

        // Four levels: PML4 256, PDPT 0, PD 1, PT 0.
        const FOUR_SHIFT: u64 = 0xFFFF_8000_0000_0000;
        let four = banner_image(
            &[(DTB, 256), (0x10_1000, 0), (0x10_2000, 1), (0x10_3000, 0)],
            BANNER_PHYSICAL,
            BANNER,
        );
        let four_banner_virtual = FOUR_SHIFT + BANNER_PHYSICAL;
        let four_page_table_virtual = FOUR_SHIFT + DTB;

        let proved = prove_at(
            &la57,
            BANNER,
            BANNER_PHYSICAL,
            la57_banner_virtual,
            la57_page_table_virtual,
            PagingMode::Intel32eLa57,
        )
        .expect("a five-level hierarchy proves at five levels");
        assert_eq!(proved.dtb, DTB);
        assert_eq!(proved.shift.shift, LA57_SHIFT);

        // The same image at four levels proves nothing: its kernel addresses
        // are not even canonical there. This is the whole of the old behaviour.
        assert!(
            prove_at(
                &la57,
                BANNER,
                BANNER_PHYSICAL,
                la57_banner_virtual,
                la57_page_table_virtual,
                PagingMode::Intel32e,
            )
            .is_none(),
            "a 57-bit kernel address must not translate under four-level rules"
        );

        // And the common case is untouched.
        let proved = prove_at(
            &four,
            BANNER,
            BANNER_PHYSICAL,
            four_banner_virtual,
            four_page_table_virtual,
            PagingMode::Intel32e,
        )
        .expect("a four-level hierarchy proves at four levels");
        assert_eq!(proved.dtb, DTB);
        assert_eq!(proved.shift.shift, FOUR_SHIFT);

        // A four-level hierarchy walked five levels deep reads its PML4 as a
        // PML5 and indexes it with the wrong nine bits, so it does not prove
        // either. That asymmetry is what makes the loop a test rather than a
        // preference for whichever depth is tried first.
        assert!(
            prove_at(
                &four,
                BANNER,
                BANNER_PHYSICAL,
                four_banner_virtual,
                four_page_table_virtual,
                PagingMode::Intel32eLa57,
            )
            .is_none(),
            "four-level tables must not prove at a depth the machine was not using"
        );
    }

    /// [`banner_image`] for arm64: every entry on the path is a valid
    /// table descriptor (bits 1:0 = 0b11), and the last a valid page with the
    /// access flag (bit 10) set, as Linux writes it (ARM DDI 0487 D8.3).
    fn arm64_banner_image(
        chain: &[(u64, u64)],
        banner_physical: u64,
        banner: &str,
    ) -> Arc<dyn MemoryLayer> {
        use seance_core::data_source::ByteSliceDataSource;

        let mut bytes = vec![0u8; 0x40_0000];
        for (position, (table, index)) in chain.iter().enumerate() {
            let last = position + 1 == chain.len();
            let target = chain
                .get(position + 1)
                .map_or(banner_physical, |next| next.0);
            let value = target | 0b11 | if last { 1 << 10 } else { 0 };
            let at = (table + index * 8) as usize;
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let at = banner_physical as usize;
        bytes[at..at + banner.len()].copy_from_slice(banner.as_bytes());
        Arc::new(
            seance_memory::PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
                .expect("a non-empty image"),
        ) as Arc<dyn MemoryLayer>
    }

    fn arm64_mode(granule: seance_memory::translate::Arm64Granule, bits: u8) -> PagingMode {
        PagingMode::Arm64(Arm64Regime::new(granule, Ttbr::Ttbr1, bits).unwrap())
    }

    const ARM64_BANNER: &str = "Linux version 4.19.0-11-arm64 (debian-kernel@lists.debian.org) \
                                (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.146-1";

    #[test]
    fn an_arm64_4k_48_bit_kernel_is_proved_by_the_banner_walk_and_not_assumed() {
        // Synthetic tables written from ARM DDI 0487 D8.3; the proof certifies
        // itself (the banner's bytes are read back through the walk), and the
        // translation core under it agrees with an independent walker on real
        // AArch64 trees (VALIDATION.md MEM-ARM-1). Not an arm64 profile on
        // real data: no arm64 symbol table is held.
        use seance_memory::translate::Arm64Granule::Kb4;
        const DTB: u64 = 0x10_0000;
        const BANNER_PHYSICAL: u64 = 0x20_0000;

        // 48-bit: the kernel image at 0xffff_0000_0800_0000 over PA 0. The
        // banner's VA 0xffff_0000_0820_0000 takes L0 0, L1 0, L2 0x41, L3 0.
        const VOFFSET_48: u64 = 0xffff_0000_0800_0000;
        let four_48 = arm64_banner_image(
            &[(DTB, 0), (0x10_1000, 0), (0x10_2000, 0x41), (0x10_3000, 0)],
            BANNER_PHYSICAL,
            ARM64_BANNER,
        );
        // 39-bit: the same low bits under 0xffff_ff80_0000_0000 take L1 0,
        // L2 0x41, L3 0.
        const VOFFSET_39: u64 = 0xffff_ff80_0800_0000;
        let four_39 = arm64_banner_image(
            &[(DTB, 0), (0x10_1000, 0x41), (0x10_2000, 0)],
            BANNER_PHYSICAL,
            ARM64_BANNER,
        );
        let prove = |image: &Arc<dyn MemoryLayer>, voffset: u64, mode| {
            prove_at(
                image,
                ARM64_BANNER,
                BANNER_PHYSICAL,
                voffset + BANNER_PHYSICAL,
                voffset + DTB,
                mode,
            )
        };

        let proved = prove(&four_48, VOFFSET_48, arm64_mode(Kb4, 48)).expect("4K/48 proves");
        assert_eq!(proved.dtb, DTB);
        assert_eq!(proved.shift.shift, VOFFSET_48);
        assert!(prove(&four_48, VOFFSET_48, arm64_mode(Kb4, 39)).is_none());
        let proved = prove(&four_39, VOFFSET_39, arm64_mode(Kb4, 39)).expect("4K/39 proves");
        assert_eq!(proved.dtb, DTB);
        assert!(
            prove(&four_39, VOFFSET_39, arm64_mode(Kb4, 48)).is_none(),
            "a 39-bit hierarchy must not prove at 48 bits"
        );

        // Every arm64 regime but the right one fails on each image: the
        // order of the list decides nothing.
        for (image, voffset, right) in [
            (&four_48, VOFFSET_48, arm64_mode(Kb4, 48)),
            (&four_39, VOFFSET_39, arm64_mode(Kb4, 39)),
        ] {
            let proving: Vec<PagingMode> = ARM64_PAGING_MODES
                .into_iter()
                .filter(|mode| prove(image, voffset, *mode).is_some())
                .collect();
            assert_eq!(proving, vec![right]);
        }

        // The 4.19 kernel image above sits at 0xffff_0000_…, which is not
        // x86-64 canonical (bit 47 clear under bits 63:48 set), so Intel
        // paging refuses it outright.
        assert!(prove(&four_48, VOFFSET_48, PagingMode::Intel32e).is_none());
        // The hazard the architecture hint exists for. From Linux 5.4 the
        // arm64 kernel image sits at 0xffff_8000_1000_0000, which *is*
        // x86-64 canonical, and a simple 4K/48 hierarchy is also a valid
        // x86-64 four-level one (the same 9/9/9/9/12 split, bit 0 read as
        // present, bit 1 as writable). Banner VA 0xffff_8000_1020_0000 takes
        // L0 256, L1 0, L2 0x81, L3 0 under both readings, so four-level
        // Intel paging "proves" an arm64 image. An arm64-hinted table is
        // therefore never offered an Intel mode, and an x86-hinted one never
        // an arm64 mode.
        const VOFFSET_54: u64 = 0xffff_8000_1000_0000;
        let five_four = arm64_banner_image(
            &[
                (DTB, 256),
                (0x10_1000, 0),
                (0x10_2000, 0x81),
                (0x10_3000, 0),
            ],
            BANNER_PHYSICAL,
            ARM64_BANNER,
        );
        assert!(prove(&five_four, VOFFSET_54, arm64_mode(Kb4, 48)).is_some());
        assert!(
            prove(&five_four, VOFFSET_54, PagingMode::Intel32e).is_some(),
            "the ambiguity is real, which is why the hint decides what is offered"
        );
        let arm64_offer = modes_for(ArchitectureHint::Arm64);
        assert_eq!(arm64_offer, ARM64_PAGING_MODES.to_vec());
        assert!(arm64_offer.iter().all(|mode| !mode.is_intel()));
        assert_eq!(
            modes_for(ArchitectureHint::X86_64),
            INTEL_PAGING_MODES.to_vec()
        );
        assert_eq!(modes_for(ArchitectureHint::Unknown), PAGING_MODES.to_vec());
    }

    #[test]
    fn the_architecture_hint_comes_from_symbols_only_one_architecture_defines() {
        let hint = |names: &'static [&'static str]| {
            architecture_hint_from(move |name: &str| names.contains(&name))
        };
        assert_eq!(
            hint(&["kimage_voffset", "swapper_pg_dir"]),
            ArchitectureHint::Arm64
        );
        assert_eq!(
            hint(&["phys_base", "init_top_pgt"]),
            ArchitectureHint::X86_64
        );
        assert_eq!(hint(&["init_level4_pgt"]), ArchitectureHint::X86_64);
        // swapper_pg_dir is both architectures' historic name.
        assert_eq!(
            hint(&["swapper_pg_dir", "linux_banner"]),
            ArchitectureHint::Unknown
        );
        // Both families' symbols: nothing is settled.
        assert_eq!(
            hint(&["kimage_voffset", "phys_base"]),
            ArchitectureHint::Unknown
        );
    }

    #[test]
    fn an_unhinted_image_whose_tables_prove_in_both_families_is_not_read_under_either() {
        // The 5.4-layout arm64 image of the test above: both families prove.
        const DTB: u64 = 0x10_0000;
        const BANNER_PHYSICAL: u64 = 0x20_0000;
        const VOFFSET_54: u64 = 0xffff_8000_1000_0000;
        let image = arm64_banner_image(
            &[
                (DTB, 256),
                (0x10_1000, 0),
                (0x10_2000, 0x81),
                (0x10_3000, 0),
            ],
            BANNER_PHYSICAL,
            ARM64_BANNER,
        );
        let candidates = [BannerCandidate {
            banner: normalize_banner(ARM64_BANNER.as_bytes()).unwrap(),
            physical: vec![BANNER_PHYSICAL],
        }];
        let under = |modes: &[PagingMode]| {
            prove_under(
                &image,
                &candidates,
                VOFFSET_54 + BANNER_PHYSICAL,
                VOFFSET_54 + DTB,
                modes,
                &Arc::new(TableCache::new()),
                &DiscoveryOptions::default(),
                &mut DiscoveryReport::default(),
            )
            .map(|(_, spec, _)| spec.mode())
        };
        let intel = under(&INTEL_PAGING_MODES);
        let arm64 = under(&ARM64_PAGING_MODES);
        assert_eq!(intel, Some(PagingMode::Intel32e));
        assert_eq!(arm64, Some(ARM64_PAGING_MODES[0]));
        assert!(settle_unhinted(intel, arm64).is_err());
        assert_eq!(settle_unhinted(None, arm64), Ok(arm64));
        assert_eq!(settle_unhinted(intel, None), Ok(intel));
        assert_eq!(settle_unhinted::<PagingMode>(None, None), Ok(None));
    }

    #[test]
    fn an_arm64_image_no_regime_proves_is_refused_by_name_not_left_unproved() {
        let err = unproved(
            ArchitectureHint::Arm64,
            ARM64_BANNER,
            7,
            0xffff_0000_0820_0000,
            &ARM64_PAGING_MODES,
        );
        assert_eq!(err.class(), "unsupported_architecture");
        let text = err.to_string();
        for needle in [
            "arm64 kernel",
            "arm64_4k_ttbr1 (48-bit VA)",
            "arm64_16k_ttbr1 (36-bit VA)",
            "LPA2",
            "not an absence of evidence",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        // An x86 image whose proof fails is still unproved, not unsupported.
        for hint in [ArchitectureHint::X86_64, ArchitectureHint::Unknown] {
            let err = unproved(hint, BANNER, 2, 0xFFFF_FFFF_8140_0070, &INTEL_PAGING_MODES);
            assert_eq!(err.class(), "page_tables_unproved", "{hint:?}");
        }
    }

    // ---- The whole path: `discover_reported` from a synthetic image and a
    // synthetic ISF on disk. The helper-level tests above pin each decision;
    // these pin that `discover_reported` is wired to reach them.

    const E2E_DTB: u64 = 0x10_0000;
    const E2E_BANNER_PHYSICAL: u64 = 0x20_0000;
    const E2E_NOTE_PHYSICAL: u64 = 0x30_0000;
    /// The Linux 5.4+ arm64 kernel image base: x86-64 canonical, which is
    /// what lets an Intel walk read an arm64 hierarchy at all.
    const E2E_VOFFSET: u64 = 0xffff_8000_1000_0000;
    /// The path banner VA `E2E_VOFFSET + E2E_BANNER_PHYSICAL` takes under
    /// both 4K/48 arm64 and x86-64 four-level rules.
    const E2E_CHAIN: [(u64, u64); 4] = [
        (E2E_DTB, 256),
        (0x10_1000, 0),
        (0x10_2000, 0x81),
        (0x10_3000, 0),
    ];
    /// A minimal arm64 VMCOREINFO, `kimage_voffset` naming the architecture.
    const E2E_ARM64_NOTE: &str = "OSRELEASE=4.19.0-11-arm64\nPAGESIZE=4096\n\
                                  NUMBER(VA_BITS)=48\nNUMBER(kimage_voffset)=0xfffeffffc8000000\n";

    /// How each entry on [`E2E_CHAIN`] is written.
    #[derive(Clone, Copy)]
    enum Entries {
        /// Valid arm64 table descriptors (bits 1:0 = 0b11) and a page with
        /// the access flag: also valid x86-64 entries, so both families prove.
        Arm64,
        /// x86-64 entries with only the present bit: bits 1:0 = 0b01 is an
        /// invalid arm64 table descriptor, so only Intel proves.
        IntelOnly,
        /// No entries at all: nothing proves.
        None,
    }

    fn e2e_image(entries: Entries, notes: &[&str]) -> Arc<dyn MemoryLayer> {
        use seance_core::data_source::ByteSliceDataSource;
        let mut bytes = vec![0u8; 0x40_0000];
        for (position, (table, index)) in E2E_CHAIN.iter().enumerate() {
            let last = position + 1 == E2E_CHAIN.len();
            let target = E2E_CHAIN
                .get(position + 1)
                .map_or(E2E_BANNER_PHYSICAL, |next| next.0);
            let value = match entries {
                Entries::Arm64 => target | 0b11 | if last { 1 << 10 } else { 0 },
                Entries::IntelOnly => target | 1,
                Entries::None => continue,
            };
            let at = (table + index * 8) as usize;
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let banner = format!("{ARM64_BANNER}\n");
        let at = E2E_BANNER_PHYSICAL as usize;
        bytes[at..at + banner.len()].copy_from_slice(banner.as_bytes());
        for (index, note) in notes.iter().enumerate() {
            let at = E2E_NOTE_PHYSICAL as usize + index * 0x1000;
            bytes[at..at + note.len()].copy_from_slice(note.as_bytes());
        }
        Arc::new(
            seance_memory::PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
                .expect("a non-empty image"),
        ) as Arc<dyn MemoryLayer>
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// A directory holding one ISF for [`ARM64_BANNER`] that declares the
    /// banner and page-table symbols at the 5.4+ layout, plus `kimage_voffset`
    /// when `arm64_symbol`.
    fn e2e_symbol_dir(arm64_symbol: bool) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("seance-e2e-arm64-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let kimage = if arm64_symbol {
            format!(
                r#", "kimage_voffset": {{"address": {}}}"#,
                E2E_VOFFSET + 0x38_0000
            )
        } else {
            String::new()
        };
        let isf = format!(
            r#"{{
  "metadata": {{"format":"6.2.0","producer":{{"name":"seance-e2e-fixture","version":"1.0.0"}},"linux":{{"symbols":[],"types":[]}}}},
  "base_types": {{
    "pointer": {{"size":8,"signed":false,"kind":"int","endian":"little"}},
    "char": {{"size":1,"signed":true,"kind":"char","endian":"little"}}
  }},
  "user_types": {{}},
  "enums": {{}},
  "symbols": {{
    "linux_banner": {{"address": {banner}, "constant_data": "{data}"}},
    "swapper_pg_dir": {{"address": {dtb}}}{kimage}
  }}
}}"#,
            banner = E2E_VOFFSET + E2E_BANNER_PHYSICAL,
            dtb = E2E_VOFFSET + E2E_DTB,
            data = base64(format!("{ARM64_BANNER}\n\0").as_bytes()),
        );
        std::fs::write(dir.join("arm64.json"), isf).expect("the ISF is written");
        dir
    }

    fn discover_e2e(
        entries: Entries,
        note: Option<&str>,
        arm64_symbol: bool,
    ) -> Result<(LinuxProfile, DiscoveryReport), DiscoveryError> {
        discover_e2e_notes(entries, note.as_slice(), arm64_symbol)
    }

    fn discover_e2e_notes(
        entries: Entries,
        notes: &[&str],
        arm64_symbol: bool,
    ) -> Result<(LinuxProfile, DiscoveryReport), DiscoveryError> {
        let dir = e2e_symbol_dir(arm64_symbol);
        let result = discover_reported(
            e2e_image(entries, notes),
            std::slice::from_ref(&dir),
            &DiscoveryOptions::default(),
        );
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn e2e_refusal(entries: Entries, note: Option<&str>, arm64_symbol: bool) -> DiscoveryError {
        match discover_e2e(entries, note, arm64_symbol) {
            Ok(_) => panic!("discovery profiled an image it must refuse"),
            Err(err) => err,
        }
    }

    #[test]
    fn discovery_refuses_an_unhinted_image_that_proves_in_both_families() {
        let err = e2e_refusal(Entries::Arm64, None, false);
        assert_eq!(err.class(), "architecture_undetermined", "{err}");
        let text = err.to_string();
        assert!(
            text.contains("intel32e") && text.contains("arm64_4k_ttbr1"),
            "{text}"
        );
    }

    #[test]
    fn discovery_refuses_an_arm64_hinted_image_no_regime_proves_by_name() {
        let err = e2e_refusal(Entries::None, None, true);
        assert_eq!(err.class(), "unsupported_architecture", "{err}");
        let text = err.to_string();
        assert!(text.contains("arm64 kernel"), "{text}");
        assert!(
            !text.contains("x86-64 depths"),
            "a symbol-hinted table is offered arm64 regimes only: {text}"
        );
    }

    #[test]
    fn discovery_names_arm64_from_vmcoreinfo_when_the_symbols_do_not() {
        let err = e2e_refusal(Entries::None, Some(E2E_ARM64_NOTE), false);
        assert_eq!(err.class(), "unsupported_architecture", "{err}");
        let text = err.to_string();
        assert!(
            text.contains("arm64 kernel") && text.contains("only the image's VMCOREINFO"),
            "{text}"
        );
        // Without the note, the same image is unproved, not named.
        let err = e2e_refusal(Entries::None, None, false);
        assert_eq!(err.class(), "page_tables_unproved", "{err}");
    }

    #[test]
    fn an_x86_proof_alone_is_not_taken_when_the_images_vmcoreinfo_names_arm64() {
        // The hazard the reviewer named: an unhinted arm64 image whose tables
        // read as x86-64 four-level ones and not under any arm64 regime this
        // build decodes. The VMCOREINFO says arm64, so the Intel proof is
        // vetoed rather than profiled as x86-64.
        let err = e2e_refusal(Entries::IntelOnly, Some(E2E_ARM64_NOTE), false);
        assert_eq!(err.class(), "unsupported_architecture", "{err}");
        let text = err.to_string();
        for needle in ["VMCOREINFO", "arm64 kernel", "'intel32e'", "not taken"] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
    }

    #[test]
    fn an_x86_proof_alone_with_nothing_naming_arm64_is_not_refused_by_architecture() {
        // The limit, pinned so it cannot be claimed away: with no
        // architecture-exclusive symbol and no VMCOREINFO, nothing in the
        // image says arm64, and an Intel-only proof is taken as x86-64.
        match discover_e2e(Entries::IntelOnly, None, false) {
            Ok((profile, _)) => assert_eq!(profile.architecture, LayerArch::X64),
            Err(err) => assert!(
                !matches!(
                    err,
                    DiscoveryError::UnsupportedArchitecture { .. }
                        | DiscoveryError::ArchitectureUndetermined { .. }
                ),
                "{err}"
            ),
        }
    }

    /// A minimal x86-64 VMCOREINFO for the same release, `phys_base` naming
    /// the architecture: a copy that contradicts [`E2E_ARM64_NOTE`].
    const E2E_X86_NOTE: &str = "OSRELEASE=4.19.0-11-arm64\nPAGESIZE=4096\n\
                                NUMBER(phys_base)=0x0\n";

    #[test]
    fn an_x86_proof_alone_is_not_taken_when_a_cut_short_vmcoreinfo_sweep_saw_arm64() {
        // More copies than the sweep returns: the sweep is cut short, so
        // `agreed` cannot settle it — but every copy it did see says arm64.
        let notes = vec![E2E_ARM64_NOTE; crate::vmcoreinfo::MAX_VMCOREINFO_HITS + 1];
        let err = match discover_e2e_notes(Entries::IntelOnly, &notes, false) {
            Ok((profile, _)) => panic!(
                "an arm64-noted image was profiled as {:?}",
                profile.architecture
            ),
            Err(err) => err,
        };
        assert_eq!(err.class(), "unsupported_architecture", "{err}");
        let text = err.to_string();
        for needle in ["'intel32e'", "not taken", "cut short", "arm64 kernel"] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
    }

    #[test]
    fn an_x86_proof_alone_is_not_taken_when_vmcoreinfo_copies_disagree_and_one_says_arm64() {
        let notes = [E2E_ARM64_NOTE, E2E_X86_NOTE];
        let err = match discover_e2e_notes(Entries::IntelOnly, &notes, false) {
            Ok((profile, _)) => panic!(
                "an image with an arm64 VMCOREINFO copy was profiled as {:?}",
                profile.architecture
            ),
            Err(err) => err,
        };
        assert_eq!(err.class(), "unsupported_architecture", "{err}");
        let text = err.to_string();
        for needle in ["'intel32e'", "not taken", "could not settle", "disagrees"] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
    }

    #[test]
    fn a_proof_in_both_families_is_settled_by_an_agreed_vmcoreinfo() {
        // Both families prove; the image's VMCOREINFO names arm64 — the tie
        // is not "a choice nothing in the image justifies".
        match discover_e2e(Entries::Arm64, Some(E2E_ARM64_NOTE), false) {
            Ok((profile, report)) => {
                assert_eq!(profile.architecture, LayerArch::Arm64);
                let notes = report.notes.join("\n");
                assert!(notes.contains("names an arm64 kernel"), "{notes}");
            }
            Err(err) => panic!("the VMCOREINFO did not settle the tie: {err}"),
        }
    }

    fn describe_mode(mode: &PagingMode) -> (PagingMode, String) {
        (*mode, ARM64_BANNER.to_string())
    }

    #[test]
    fn an_x86_proof_alone_taken_says_what_the_vmcoreinfo_check_could_and_could_not_see() {
        let intel = Some(PagingMode::Intel32e);
        let cases = [
            (
                VmcoreinfoCheck::Absent,
                vec!["complete sweep found no VMCOREINFO"],
            ),
            (
                VmcoreinfoCheck::Names(ArchitectureHint::X86_64),
                vec!["names an x86-64 kernel"],
            ),
            (
                VmcoreinfoCheck::NamesNeither,
                vec!["no line only one architecture writes"],
            ),
            (
                VmcoreinfoCheck::CouldNotLook {
                    reason: "the VMCOREINFO sweep was cut short".into(),
                    arm64_seen: false,
                },
                vec!["could not settle", "cut short", "not corroborated"],
            ),
        ];
        for (check, needles) in cases {
            let (mode, clause) = settle_architecture(intel, None, &check, 3, describe_mode)
                .unwrap_or_else(|err| panic!("{check:?}: {err}"))
                .expect("the Intel proof");
            assert_eq!(mode, PagingMode::Intel32e);
            assert!(
                clause.contains("no arm64 regime proved"),
                "{check:?}: {clause}"
            );
            for needle in needles {
                assert!(clause.contains(needle), "{check:?} {needle}: {clause}");
            }
        }
    }

    #[test]
    fn an_x86_proof_alone_is_refused_when_any_vmcoreinfo_copy_seen_names_arm64() {
        for check in [
            VmcoreinfoCheck::Names(ArchitectureHint::Arm64),
            VmcoreinfoCheck::CouldNotLook {
                reason: "the VMCOREINFO sweep was cut short".into(),
                arm64_seen: true,
            },
        ] {
            let err =
                settle_architecture(Some(PagingMode::Intel32e), None, &check, 3, describe_mode)
                    .expect_err("vetoed");
            assert_eq!(err.class(), "unsupported_architecture", "{check:?}");
            assert!(err.to_string().contains("not taken"), "{err}");
        }
    }

    #[test]
    fn a_tie_between_families_is_broken_only_by_an_agreed_vmcoreinfo() {
        let (intel, arm64) = (Some(PagingMode::Intel32e), Some(ARM64_PAGING_MODES[0]));
        let take =
            |check: VmcoreinfoCheck| settle_architecture(intel, arm64, &check, 3, describe_mode);
        let (mode, clause) = take(VmcoreinfoCheck::Names(ArchitectureHint::Arm64))
            .expect("settled")
            .expect("a proof");
        assert_eq!(mode, ARM64_PAGING_MODES[0]);
        assert!(
            clause.contains("both") && clause.contains("names an arm64 kernel"),
            "{clause}"
        );
        let (mode, _) = take(VmcoreinfoCheck::Names(ArchitectureHint::X86_64))
            .expect("settled")
            .expect("a proof");
        assert_eq!(mode, PagingMode::Intel32e);
        for (check, needle) in [
            (
                VmcoreinfoCheck::Absent,
                "complete sweep found no VMCOREINFO",
            ),
            (
                VmcoreinfoCheck::NamesNeither,
                "no line only one architecture writes",
            ),
            (
                VmcoreinfoCheck::CouldNotLook {
                    reason: "the VMCOREINFO sweep was cut short".into(),
                    arm64_seen: true,
                },
                "could not settle",
            ),
        ] {
            let err = take(check.clone()).expect_err("undetermined");
            assert_eq!(err.class(), "architecture_undetermined", "{check:?}");
            let text = err.to_string();
            assert!(text.contains(needle), "{needle}: {text}");
            assert!(!text.contains("nothing in it justifies"), "{text}");
        }
    }

    #[test]
    fn a_vmcoreinfo_hinted_refusal_names_only_arm64_regimes_as_arm64_ones() {
        // The symbol table named no architecture, so every mode was offered;
        // the VMCOREINFO sweep then said arm64. The refusal must not list the
        // Intel depths as "arm64 regimes", and must say the Intel ones were
        // tried too, since they were.
        let err = unproved(
            ArchitectureHint::Arm64,
            ARM64_BANNER,
            9,
            0xffff_0000_0820_0000,
            &PAGING_MODES,
        );
        assert_eq!(err.class(), "unsupported_architecture");
        let text = err.to_string();
        let arm64_part = text
            .split("arm64 regimes this build decodes")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .unwrap_or_else(|| panic!("no regime list: {text}"));
        assert!(!arm64_part.contains("intel32e"), "{text}");
        assert!(arm64_part.contains("arm64_4k_ttbr1 (48-bit VA)"), "{text}");
        assert!(
            text.contains("'intel32e', 'intel32e_la57'") && text.contains("x86-64"),
            "the Intel depths that were also tried are named as x86-64 ones: {text}"
        );
    }

    #[test]
    fn the_offered_paging_depths_are_named_where_a_failure_is_read() {
        // A capture whose depth is not in this list fails closed, and the
        // sentence an examiner reads has to say which depths were tried —
        // otherwise "the page tables could not be proved" is indistinguishable
        // from "your machine's paging mode is not supported".
        assert_eq!(&PAGING_MODES[..2], &INTEL_PAGING_MODES[..]);
        assert_eq!(&PAGING_MODES[2..], &ARM64_PAGING_MODES[..]);
        assert_eq!(
            mode_list(&PAGING_MODES),
            "'intel32e', 'intel32e_la57', 'arm64_4k_ttbr1 (48-bit VA)', \
             'arm64_4k_ttbr1 (39-bit VA)', 'arm64_64k_ttbr1 (48-bit VA)', \
             'arm64_64k_ttbr1 (42-bit VA)', 'arm64_16k_ttbr1 (47-bit VA)', \
             'arm64_16k_ttbr1 (48-bit VA)', 'arm64_16k_ttbr1 (36-bit VA)'"
        );

        let err = DiscoveryError::PageTablesUnproved {
            banner: BANNER.into(),
            attempts: 6,
            symbol: BANNER_SYMBOL,
            banner_virtual: 0xFFFF_FFFF_8140_0070,
            modes: mode_list(&PAGING_MODES),
        };
        let text = err.to_string();
        assert!(text.contains("intel32e_la57"), "{text}");
        assert!(text.contains("paging depth"), "{text}");
    }

    #[test]
    fn every_failure_class_has_a_stable_name() {
        let cases: Vec<(DiscoveryError, &str)> = vec![
            (
                DiscoveryError::NoKernelBanner {
                    bytes_scanned: 0,
                    swept_completely: true,
                    sweep_state: "",
                },
                "no_kernel_banner",
            ),
            (
                DiscoveryError::SymbolsNotFound {
                    banner: BANNER.into(),
                    directories: 1,
                    files_seen: 4,
                    files_identified: 4,
                    truncation: String::new(),
                    btf_note: String::new(),
                },
                "symbols_not_found",
            ),
            (
                DiscoveryError::UnsupportedArchitecture {
                    banner: BANNER.into(),
                    reason: "its symbol table declares 4-byte pointers".to_string(),
                },
                "unsupported_architecture",
            ),
            (
                DiscoveryError::ArchitectureUndetermined {
                    banner: BANNER.into(),
                    intel: "intel32e".into(),
                    arm64: "arm64_4k_ttbr1 (48-bit VA)".into(),
                    vmcoreinfo: "a complete sweep found no VMCOREINFO in the image".into(),
                },
                "architecture_undetermined",
            ),
            (
                DiscoveryError::NoPageTableSymbol {
                    banner: BANNER.into(),
                    candidates: name_list(&PAGE_TABLE_SYMBOLS),
                },
                "no_page_table_symbol",
            ),
            (
                DiscoveryError::NoBannerSymbol {
                    banner: BANNER.into(),
                    symbol: BANNER_SYMBOL,
                },
                "no_banner_symbol",
            ),
            (
                DiscoveryError::PageTablesUnproved {
                    banner: BANNER.into(),
                    attempts: 3,
                    symbol: BANNER_SYMBOL,
                    banner_virtual: 0xFFFF_FFFF_8140_0070,
                    modes: mode_list(&PAGING_MODES),
                },
                "page_tables_unproved",
            ),
            (
                DiscoveryError::ImageUnreadable("no sections".into()),
                "image_unreadable",
            ),
        ];
        for (err, class) in cases {
            assert_eq!(err.class(), class);
            assert!(
                !err.to_string().is_empty(),
                "every failure must read as a sentence, not a code"
            );
        }
    }

    /// The sentence an examiner reads when their lab has no symbols has to say
    /// what to fetch and why it matters, not merely that something failed.
    #[test]
    fn a_missing_symbol_file_names_the_kernel_and_says_what_is_lost() {
        let err = DiscoveryError::SymbolsNotFound {
            banner: BANNER.into(),
            directories: 2,
            files_seen: 9,
            files_identified: 9,
            truncation: String::new(),
            btf_note: String::new(),
        };
        let text = err.to_string();
        assert!(text.contains("3.2.0-4-amd64"), "{text}");
        assert!(text.contains("different build"), "{text}");
    }

    #[test]
    fn the_unsupported_architecture_message_does_not_read_as_an_empty_machine() {
        let err = DiscoveryError::UnsupportedArchitecture {
            banner: BANNER.into(),
            reason: "its symbol table declares 4-byte pointers".to_string(),
        };
        let text = err.to_string();
        assert!(
            text.contains("not an absence of evidence"),
            "a tool limit must never be phrased as a finding about the image: {text}"
        );
        // The tier offers both Intel depths (`PAGING_MODES`); a message that
        // said "four-level only" understated what it implements.
        assert!(
            text.contains("four- and five-level"),
            "the message must name both paging depths the tier offers: {text}"
        );
    }
}

#[cfg(test)]
mod btf_gate_tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_memory::btf::test_support::blob;
    use seance_memory::btf_isf::to_isf_source;
    use seance_symbols::{CompileOptions, GateOutcome};

    /// A memory image containing `btf` somewhere in the middle, surrounded by
    /// noise, as it sits in a real capture.
    fn image_holding(btf: &[u8]) -> ByteSliceDataSource {
        let mut bytes = vec![0xA5u8; 1 << 20];
        let at = 4096;
        bytes[at..at + btf.len()].copy_from_slice(btf);
        ByteSliceDataSource::new(bytes)
    }

    /// Compile a symbol table from a BTF blob, as the converter does.
    fn table_from(btf_bytes: &[u8]) -> SymbolTable {
        let btf = seance_memory::btf::Btf::parse(btf_bytes).expect("parses");
        SymbolTable::compile_source(
            to_isf_source(&btf, None).expect("converts"),
            &CompileOptions::default(),
        )
        .expect("compiles")
    }

    #[test]
    fn a_symbol_file_that_matches_the_kernels_own_btf_passes() {
        let bytes = blob(
            "task_struct",
            &[("pid", 1, 8 * 8), ("comm", 1, 64 * 8)],
            4096,
        );
        let table = table_from(&bytes);
        let result = btf_corroboration_gate_with(&table, &image_holding(&bytes), 1);
        assert_eq!(
            result.outcome,
            GateOutcome::Pass,
            "a table built from this very BTF must agree with it: {}",
            result.detail
        );
    }

    /// **The case the gate exists for.** A symbol file for a different build.
    ///
    /// Two kernels from one distribution and version can carry byte-identical
    /// banners and different layouts, so banner matching admits the wrong file
    /// and every offset read afterwards is silently wrong. Here the table says
    /// `comm` is at byte 64 and the kernel's own BTF says 96.
    #[test]
    fn a_symbol_file_for_a_different_build_is_caught() {
        let symbol_file = blob(
            "task_struct",
            &[("pid", 1, 8 * 8), ("comm", 1, 64 * 8)],
            4096,
        );
        let in_the_image = blob(
            "task_struct",
            &[("pid", 1, 8 * 8), ("comm", 1, 96 * 8)],
            4096,
        );

        let table = table_from(&symbol_file);
        let result = btf_corroboration_gate_with(&table, &image_holding(&in_the_image), 1);

        assert_eq!(
            result.outcome,
            GateOutcome::Fail,
            "a layout disagreement must fail: {}",
            result.detail
        );
        assert!(
            result.detail.contains("DIFFERENT BUILD"),
            "the detail must say plainly what the disagreement means: {}",
            result.detail
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.contains("task_struct.comm") && v.contains("64") && v.contains("96")),
            "the violation must name the member and both offsets: {:?}",
            result.violations
        );
    }

    /// A kernel with no BTF is not a failure. Anything much before 2020 carries
    /// none, and its absence says nothing about the symbol file.
    #[test]
    fn an_image_without_btf_is_not_applicable_rather_than_failing() {
        let bytes = blob("task_struct", &[("pid", 1, 0)], 4096);
        let table = table_from(&bytes);
        let empty = ByteSliceDataSource::new(vec![0u8; 1 << 20]);

        let result = btf_corroboration_gate_with(&table, &empty, 1);
        assert_eq!(result.outcome, GateOutcome::NotApplicable);
        assert!(
            result.detail.contains("says nothing about the symbols"),
            "absence must not be reported as doubt about the symbols: {}",
            result.detail
        );
    }

    /// A module's BTF must not be mistaken for the kernel's.
    ///
    /// Comparing a symbol file against a handful of types would pass trivially
    /// and report agreement that was never tested.
    #[test]
    fn a_small_btf_blob_is_not_taken_for_the_kernels() {
        let bytes = blob("task_struct", &[("pid", 1, 0)], 4096);
        let table = table_from(&bytes);
        // The real threshold, against a blob describing one type.
        let result = btf_corroboration_gate_with(&table, &image_holding(&bytes), 20_000);
        assert_eq!(result.outcome, GateOutcome::NotApplicable);
    }

    /// Types the symbol file does not declare are not disagreements.
    #[test]
    fn a_type_absent_from_the_symbol_file_is_not_a_violation() {
        let symbol_file = blob("task_struct", &[("pid", 1, 0)], 4096);
        let in_the_image = blob("mm_struct", &[("pgd", 1, 0)], 512);

        let table = table_from(&symbol_file);
        let result = btf_corroboration_gate_with(&table, &image_holding(&in_the_image), 1);
        assert_eq!(
            result.outcome,
            GateOutcome::NotApplicable,
            "no types in common means nothing to compare, not a failure: {}",
            result.detail
        );
    }
}

#[cfg(test)]
mod btf_note_tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_memory::btf::test_support::blob;

    /// A kernel with no BTF cannot describe itself, and must not claim to.
    ///
    /// The note must never be speculative: telling an examiner the evidence can
    /// supply its own layouts, when it cannot, sends them after a capability
    /// that is not there.
    #[test]
    fn an_image_without_btf_recovers_nothing() {
        let empty = ByteSliceDataSource::new(vec![0u8; 1 << 20]);
        let outcome = image_symbols::recover(&empty, Default::default());
        assert!(
            matches!(outcome, image_symbols::Recovery::NoBtf),
            "an image with no BTF must report NoBtf, got {outcome:?}"
        );
    }

    /// A module-sized blob is not the kernel's, and must not be taken for it.
    ///
    /// A module's BTF describes a handful of types. Building a symbol table
    /// from one would produce layouts covering a fraction of the kernel, and
    /// every structure it did not describe would be unreadable for a reason
    /// that looked like a missing symbol rather than a wrong source.
    #[test]
    fn a_module_sized_blob_is_not_mistaken_for_the_kernels_own() {
        let bytes = blob("task_struct", &[("pid", 1, 0)], 4096);
        let mut image = vec![0u8; 1 << 20];
        image[4096..4096 + bytes.len()].copy_from_slice(&bytes);
        let outcome = image_symbols::recover(&ByteSliceDataSource::new(image), Default::default());
        assert!(
            matches!(outcome, image_symbols::Recovery::NoBtf),
            "a module-sized blob must not be accepted as the kernel's own BTF, got {outcome:?}"
        );
    }

    /// The failure message still names the banner when a note is absent.
    ///
    /// The banner is the one thing that lets an examiner go and fetch the right
    /// ISF, so no amount of extra text may displace it.
    #[test]
    fn the_failure_still_leads_with_the_banner() {
        let err = DiscoveryError::SymbolsNotFound {
            banner: "Linux version 6.8.0-1061-aws".to_string(),
            directories: 2,
            files_seen: 40,
            files_identified: 12,
            truncation: String::new(),
            btf_note: String::new(),
        };
        let text = err.to_string();
        assert!(text.contains("6.8.0-1061-aws"));
        assert!(text.contains("no kernel structure can be read"));
    }

    /// When a note is present it says what BTF gives AND what it does not.
    #[test]
    fn a_note_states_the_limitation_as_well_as_the_offer() {
        let err = DiscoveryError::SymbolsNotFound {
            banner: "Linux version 6.8.0".to_string(),
            directories: 1,
            files_seen: 0,
            files_identified: 0,
            truncation: String::new(),
            btf_note: " This kernel does, however, carry its own type information (BTF) \
                       in the image: 9000 structure(s) describing 300000 type(s), which \
                       compiled cleanly to a usable layout table. That covers member \
                       offsets and sizes. It does NOT carry symbol addresses, which is \
                       what discovery still needs, so the image cannot yet be analysed \
                       from BTF alone."
                .to_string(),
        };
        let text = err.to_string();
        assert!(text.contains("carry its own type information"));
        assert!(
            text.contains("does NOT carry symbol addresses"),
            "an offer without its limitation sends an examiner after a capability \
             that does not exist: {text}"
        );
    }
}

#[cfg(test)]
mod btf_search_bound_tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_memory::btf::test_support::blob;

    /// A search stopped by its bound is reported as capped, never as an absence.
    ///
    /// The distinction is the whole point: a capped search means the symbol file
    /// was not checked, and recording that as "no BTF present" would file a
    /// corroboration that never ran as one that found nothing to object to.
    #[test]
    fn a_capped_search_is_distinguishable_from_an_absence() {
        let image = ByteSliceDataSource::new(vec![0u8; 4 << 20]);

        // Bound below the image size: capped.
        match find_kernel_btf_limited(&image, 1, 1 << 20) {
            BtfSearch::Capped { scanned, total } => {
                assert_eq!(scanned, 1 << 20);
                assert_eq!(total, 4 << 20);
            }
            _ => panic!("a search stopped by its bound must report as capped"),
        }

        // Bound above the image size: a real absence.
        assert!(matches!(
            find_kernel_btf_limited(&image, 1, 64 << 20),
            BtfSearch::NotPresent
        ));
    }

    #[test]
    fn a_blob_within_the_bound_is_still_found() {
        let bytes = blob("task_struct", &[("pid", 1, 0)], 4096);
        let mut image = vec![0u8; 4 << 20];
        image[8192..8192 + bytes.len()].copy_from_slice(&bytes);
        assert!(matches!(
            find_kernel_btf_limited(&ByteSliceDataSource::new(image), 1, 64 << 20),
            BtfSearch::Found(_)
        ));
    }

    /// The gate says a capped search was capped, in the examiner's terms.
    #[test]
    fn the_gate_reports_a_capped_search_as_unchecked() {
        use seance_memory::btf_isf::to_isf_source;
        use seance_symbols::{CompileOptions, GateOutcome};

        let bytes = blob("task_struct", &[("pid", 1, 0)], 4096);
        let btf = seance_memory::btf::Btf::parse(&bytes).expect("parses");
        let table = SymbolTable::compile_source(
            to_isf_source(&btf, None).expect("converts"),
            &CompileOptions::default(),
        )
        .expect("compiles");

        // A large image with the real threshold: nothing found, whole image swept.
        let image = ByteSliceDataSource::new(vec![0u8; 4 << 20]);
        let result = btf_corroboration_gate_with(&table, &image, 20_000);
        assert_eq!(result.outcome, GateOutcome::NotApplicable);
        assert!(
            result.detail.contains("says nothing about the symbols"),
            "a genuine absence must read as an absence: {}",
            result.detail
        );
    }
}
