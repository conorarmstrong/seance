//! Discovery: turning a flat physical memory image into a [`WindowsProfile`].
//!
//! # Why this file exists
//!
//! A raw memory capture has no header. It does not say which processor mode it
//! was taken in, where the page tables are, where the kernel is loaded, or which
//! Windows build was running. Every one of those has to be *recovered from the
//! bytes*, and every stage in this crate is blocked until they are. Volatility
//! calls the process automagic; here it is one function, [`discover`], and it
//! returns a profile that records how each fact was established rather than
//! asserting them all with equal confidence.
//!
//! # The chain, and why each link must be proved
//!
//! ```text
//!   physical image
//!        |  self-referential page-table scan, or the acquisition's own header,
//!        |  or the x64 boot low stub's CR3
//!        v
//!   directory table base  ---->  a virtual address space
//!        |  MZ + PE header + CodeView record naming a kernel PDB
//!        v
//!   kernel load address   ---->  symbol addresses become resolvable
//!        |  CodeView GUID and age, matched exactly against a symbol file
//!        v
//!   symbol table          ---->  structure layouts for THIS build
//!        |  _KUSER_SHARED_DATA read through those layouts
//!        v
//!   version facts
//! ```
//!
//! Each arrow is a place where a wrong answer stays silent. A wrong DTB
//! translates *some* addresses, because page-table pages look alike, and
//! everything read through it is unrelated memory that parses. A kernel base out
//! by one page resolves every symbol 4 KiB away from the structure it names. A
//! symbol table for the neighbouring build reads `UniqueProcessId` at the wrong
//! offset and produces a full process list of plausible nonsense.
//!
//! So nothing here is accepted because it was found. A directory table base is
//! accepted only when a Windows kernel is proved through it; a kernel base only
//! when a complete PE header at that address carries a CodeView record naming
//! one of the four kernel PDB files; a symbol file only when its GUID *and* age
//! are byte-equal to the image's, never when its name is close.
//!
//! # What an examiner gets when it fails
//!
//! The GUID. Every other outcome of "no symbols" is useless — an examiner cannot
//! act on "symbols not found" — whereas a GUID and an age can be taken to a
//! symbol store and turned into a working case. [`DiscoveryError::SymbolsNotFound`]
//! therefore names the GUID, the age, the PDB, the directories searched and how
//! many files were opened, and there is no path anywhere in this module that
//! substitutes a near-match symbol table for the missing one.

// `report` is filled stage by stage as discovery proceeds, and each
// assignment sits beside the comment explaining what that stage
// established. Collapsing them into one initializer would put eight
// unrelated facts in one expression and separate each from its reason.
#![allow(clippy::field_reassign_with_default)]
// `scan_dtb_candidates` and its siblings take a *slice* of regions so a caller can
// sweep several disjoint windows. Handing them one is ordinary use, not the
// `vec![a..b]`-meant-`a..b` mistake this lint is looking for.
#![allow(clippy::single_range_in_vec_init)]

#[path = "automagic_dtb.rs"]
pub mod dtb;
#[path = "automagic_isf.rs"]
pub mod isf;
#[path = "automagic_kernel.rs"]
pub mod kernel;
#[path = "automagic_pe.rs"]
pub mod pe;

use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::io::read_exact_or_fail;
use seance_memory::layer::MemoryLayer;
use seance_memory::object::StructReader;
use seance_memory::scan::ScanConfig;
use seance_memory::translate::{
    PagingMode, PagingSpec, PteSemantics, SwapFile, TableCache, TranslationPolicy, VirtualLayer,
};
use seance_memory::Architecture as LayerArch;
use seance_symbols::{
    AdmissionState, Architecture as IsfArch, CompileOptions, DecompressLimits, Gate, GateOutcome,
    GateResult, SymbolError, SymbolTable, ValidationOptions,
};

use crate::profile::{Evidence, Found, KernelBuild, WindowsProfile};

pub use dtb::{DtbCandidate, DtbScanOutcome, KuserCheck};
pub use isf::{IsfMatch, IsfSearchOutcome};
pub use kernel::{
    KernelMethod, KernelSearchLimits, KernelSearchOutcome, LowStub, KERNEL_HALF_START_X64,
    KERNEL_HALF_START_X86,
};
pub use pe::{KernelImage, LayerProbe, PdbIdentity};

/// Paging modes tried, in the order they are tried.
///
/// x86-64 first because it is the overwhelmingly common case and because a
/// 64-bit page directory misread as a 32-bit one fails fast; PAE before plain
/// 32-bit because a PAE image's page directory also satisfies the plain 32-bit
/// self-reference test, and taking the plain reading of a PAE image would start
/// every translation one level too low.
///
/// LA57 (five-level) is last, and deliberately: it self-references by the *same*
/// rules as four-level x86-64 (the PML5 and PML4 differ only in the depth of the
/// walk), so it finds the same candidate pages, and only a genuine five-level
/// image validates when walked five levels deep. Trying four-level first means a
/// four-level machine — every common one — is proven without the five-level walk
/// ever being reached, and a five-level machine falls through to it. The sweep is
/// not repeated: LA57's candidates are mirrored from the x86-64 sweep (see
/// `gather_dtb_candidates`).
pub const MODE_ORDER: [PagingMode; 4] = [
    PagingMode::Intel32e,
    PagingMode::IntelPae,
    PagingMode::Intel32,
    PagingMode::Intel32eLa57,
];

/// Longest `NtBuildLab` string read out of the image.
const MAX_BUILD_LAB_BYTES: usize = 128;

/// Major versions a Windows kernel has ever reported.
///
/// Used only to falsify a candidate symbol table in gate 4: a table whose
/// `_KUSER_SHARED_DATA.NtMajorVersion` offset lands on something that is not one
/// of these is describing a different structure layout from the one in the
/// image.
const NT_MAJOR_VERSIONS: [u64; 5] = [3, 4, 5, 6, 10];

/// Plausible range for `NtBuildNumber`, from Windows NT 3.1 to well past any
/// shipped build.
const NT_BUILD_RANGE: Range<u64> = 500..200_000;

/// What discovery is allowed to assume, and how hard it is allowed to look.
///
/// Every cap here bounds work driven by values read out of the image, which is
/// not trusted input. The defaults find the kernel on every reference image in
/// `seance_memory/tests/KNOWN_ANSWERS.md`; an examiner working an unusual image
/// widens them and the report records that they were widened.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// A directory table base the examiner supplies, for an image whose scan
    /// fails. Recorded as [`Evidence::Supplied`] — it is still proved by
    /// finding the kernel through it, but it was not *discovered*, and a report
    /// must not imply that it was.
    pub dtb: Option<u64>,
    /// The paging mode to use. When absent, every mode in [`MODE_ORDER`] is
    /// tried and the one a kernel is found through wins.
    pub paging_mode: Option<PagingMode>,
    /// A kernel load address the examiner supplies. Still proved by reading a
    /// kernel PE header there; supplying it only skips the search.
    pub kernel_base: Option<u64>,
    /// Pagefiles the examiner supplies, so a swapped-out page resolves to bytes
    /// instead of a hole.
    ///
    /// **Empty by default, and deliberately not discovered.** `pagefile.sys`
    /// beside a memory image is a *second evidence item*, and its pages were
    /// written at some earlier point — possibly long before the capture.
    /// Reaching for it unasked would fold another file's bytes into what a
    /// report calls this machine's memory, without that decision appearing
    /// anywhere. Naming it is the examiner's to make and to record.
    ///
    /// The index of each file is the one Windows assigns in `PagingFiles`
    /// order; a software PTE names it. Supplying a file under the wrong index
    /// does not fail, it answers with another file's bytes, so
    /// [`seance_memory::translate::SwapFile`] carries the index explicitly
    /// rather than inferring it from position.
    pub pagefiles: Vec<SwapFile>,
    /// Physical regions the self-reference scan sweeps.
    pub dtb_scan_regions: Vec<Range<u64>>,
    /// Candidates one mode's sweep may return.
    pub max_dtb_candidates: usize,
    /// Pages one mode's sweep may examine.
    pub max_dtb_pages: u64,
    /// Directory-table-base candidates that are built into an address space and
    /// searched for a kernel. Each attempt costs a full kernel search, so this
    /// is the cap that keeps a pathological image from running for hours.
    pub max_dtb_attempts: usize,
    /// Caps on the kernel search itself.
    pub kernel_limits: KernelSearchLimits,
    /// Chunking and caps for every byte scan discovery performs.
    pub scan: ScanConfig,
    /// What the page walker may assume.
    pub translation: TranslationPolicy,
    /// Candidate symbol files enumerated.
    pub max_isf_files: usize,
    /// Directory depth the symbol search descends.
    pub max_isf_depth: usize,
    /// Symbol files opened and identified when no file name matched the GUID.
    pub max_isf_identified: usize,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            dtb: None,
            paging_mode: None,
            kernel_base: None,
            pagefiles: Vec::new(),
            dtb_scan_regions: dtb::default_scan_regions(),
            max_dtb_candidates: 64,
            max_dtb_pages: 1 << 20,
            max_dtb_attempts: 16,
            kernel_limits: KernelSearchLimits::default(),
            scan: ScanConfig::default(),
            translation: TranslationPolicy::default(),
            max_isf_files: isf::DEFAULT_MAX_FILES,
            max_isf_depth: isf::DEFAULT_MAX_DEPTH,
            max_isf_identified: isf::DEFAULT_MAX_IDENTIFIED,
        }
    }
}

impl DiscoveryOptions {
    /// Options that use an examiner-supplied directory table base.
    ///
    /// The escape hatch for an image the self-reference scan cannot crack: a
    /// hypervisor-saved state whose page directory is outside the swept regions,
    /// or a capture so smeared that the top-level table is torn. The supplied
    /// value is still proved by finding the kernel through it — supplying a
    /// wrong one produces a failure, not a wrong answer.
    pub fn with_supplied_dtb(dtb: u64, mode: PagingMode) -> Self {
        Self {
            dtb: Some(dtb),
            paging_mode: Some(mode),
            ..Self::default()
        }
    }

    /// The modes this run will try, in order.
    pub fn modes(&self) -> Vec<PagingMode> {
        match self.paging_mode {
            Some(mode) => vec![mode],
            None => MODE_ORDER.to_vec(),
        }
    }
}

/// Where one directory-table-base candidate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtbSource {
    /// The examiner supplied it.
    Supplied,
    /// The acquisition format's own header published it — a crash dump's
    /// `DirectoryTableBase`. The strongest source there is, because the machine
    /// wrote it down at capture time.
    AcquisitionHeader,
    /// `PROCESSOR_START_BLOCK->ProcessorState->SpecialRegisters->Cr3` in the
    /// x64 boot low stub.
    LowStubCr3,
    /// A page containing exactly one self-referential entry.
    SelfReference,
}

impl DtbSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            DtbSource::Supplied => "supplied",
            DtbSource::AcquisitionHeader => "acquisition_header",
            DtbSource::LowStubCr3 => "low_stub_cr3",
            DtbSource::SelfReference => "self_reference",
        }
    }

    /// The evidence grade a candidate from this source earns *once a kernel has
    /// been proved through it*.
    ///
    /// Nothing here grades a candidate that has not been proved: an unproved
    /// candidate is not reported at all.
    fn evidence(self) -> Evidence {
        match self {
            // Supplied stays supplied however well it works. An examiner reading
            // a report is entitled to know the tool was told the answer.
            DtbSource::Supplied => Evidence::Supplied,
            // Two independent statements of the same fact: the capture tool's
            // header, or the boot processor's own register, corroborated by
            // finding the kernel through it.
            DtbSource::AcquisitionHeader | DtbSource::LowStubCr3 => Evidence::Confirmed,
            // Found by scanning, then validated by using it.
            DtbSource::SelfReference => Evidence::Validated,
        }
    }
}

/// One directory-table-base candidate that was built into an address space and
/// searched.
#[derive(Debug, Clone)]
pub struct DtbAttempt {
    /// The candidate.
    pub dtb: u64,
    /// The paging mode it was read under.
    pub mode: PagingMode,
    /// Where the candidate came from.
    pub source: DtbSource,
    /// How `_KUSER_SHARED_DATA` behaved in the resulting space.
    pub kuser: Option<KuserCheck>,
    /// What happened: `None` on success, otherwise why it was abandoned.
    pub refused: Option<String>,
}

/// Everything discovery did, whether or not it succeeded.
///
/// Separate from [`WindowsProfile`] because a profile holds facts and this holds
/// the *work*: which modes were swept, how many pages were unreadable, which
/// candidates were tried and refused, how many symbol files were opened. A
/// report that says "48 processes" should be able to say, on the same page, that
/// the address space it read them out of was the ninth candidate of a scan that
/// examined 4,096 pages and could not read 61 of them.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryReport {
    /// The x64 boot low stub, if the image has one.
    pub low_stub: Option<LowStub>,
    /// One sweep outcome per paging mode swept.
    pub dtb_scans: Vec<(PagingMode, DtbScanOutcome)>,
    /// Every candidate that was built into an address space, in order.
    pub attempts: Vec<DtbAttempt>,
    /// Whether the attempt cap stopped discovery before every candidate was
    /// tried.
    pub attempts_truncated: bool,
    /// The kernel search that succeeded, or the last one that failed.
    pub kernel: Option<KernelSearchOutcome>,
    /// The symbol-file search.
    pub isf: Option<IsfSearchOutcome>,
    /// Where the version facts came from.
    pub version_source: Option<&'static str>,
    /// Anything an examiner should read that is not a failure.
    pub notes: Vec<String>,
}

impl DiscoveryReport {
    /// Serializable form for the image-profile artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "low_stub": self.low_stub.map(|s| serde_json::json!({
                "physical_offset": s.physical_offset,
                "physical_offset_hex": format!("{:#x}", s.physical_offset),
                "cr3": s.cr3,
                // Exact beside the number: a directory-table base and a long-mode
                // entry point are 64-bit values above 2^53, and JSON numbers are
                // IEEE doubles — a rounded `cr3` translates nothing.
                "cr3_hex": format!("{:#x}", s.cr3),
                "lm_target": s.lm_target,
                "lm_target_hex": format!("{:#x}", s.lm_target),
            })),
            "dtb_scans": self
                .dtb_scans
                .iter()
                .map(|(mode, outcome)| serde_json::json!({
                    "mode": mode.as_str(),
                    "scan": outcome.to_json(),
                }))
                .collect::<Vec<_>>(),
            "attempts": self
                .attempts
                .iter()
                .map(|a| serde_json::json!({
                    "dtb": a.dtb,
                    "dtb_hex": format!("{:#x}", a.dtb),
                    "mode": a.mode.as_str(),
                    "source": a.source.as_str(),
                    "kuser": a.kuser.map(|k| format!("{k:?}")),
                    "refused": a.refused,
                }))
                .collect::<Vec<_>>(),
            "attempts_truncated": self.attempts_truncated,
            "kernel": self.kernel.as_ref().map(KernelSearchOutcome::to_json),
            "isf": self.isf.as_ref().map(IsfSearchOutcome::to_json),
            "version_source": self.version_source,
            "notes": self.notes,
        })
    }

    fn note(&mut self, message: impl Into<String>) {
        self.notes.push(message.into());
    }
}

/// Every way discovery can fail.
///
/// Each variant carries what an examiner needs to act. There is no variant that
/// means "we proceeded anyway", because there is no path here that does.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The options cannot produce a correct run.
    #[error("discovery was misconfigured: {detail}")]
    Configuration {
        /// What is wrong with the options.
        detail: String,
    },

    /// No candidate directory table base could even be built into an address
    /// space.
    ///
    /// Almost always means the image is not a Windows image, is encrypted, or is
    /// an acquisition format that was decoded into the wrong physical layout.
    #[error(
        "no usable directory table base was found: {candidates} candidate(s) from \
         {pages_examined} page(s) examined, {pages_unreadable} page(s) unreadable{truncation}"
    )]
    NoDirectoryTableBase {
        /// Candidates the sweeps produced.
        candidates: usize,
        /// Pages read and examined across every sweep.
        pages_examined: u64,
        /// Pages inside the swept regions the acquisition does not hold.
        pages_unreadable: u64,
        /// Rendered suffix naming a cap, when one fired.
        truncation: String,
    },

    /// Address spaces were built, and no Windows kernel was in any of them.
    #[error(
        "no Windows kernel was found through any of {attempts} directory table base(s): {detail}"
    )]
    NoKernel {
        /// How many candidates were built and searched.
        attempts: usize,
        /// The last search's account of itself.
        detail: String,
    },

    /// The kernel was found, and no symbol file describes it.
    ///
    /// **This is the actionable failure.** The GUID and age are what an examiner
    /// takes to a symbol store; everything else in this variant explains why the
    /// search did not already find it locally. There is deliberately no
    /// "closest match" field: a near-match symbol table produces a complete,
    /// confident, wrong analysis, so none is offered even as a suggestion.
    #[error(
        "no symbol file matches the kernel: {pdb} GUID {guid} age {age}. \
         {files_identified} of {files_seen} candidate file(s) under {directories} \
         director(y|ies) were identified{truncation}"
    )]
    SymbolsNotFound {
        /// PDB file name from the image's CodeView record.
        pdb: String,
        /// PDB GUID, 32 uppercase hex characters. Fetch this.
        guid: String,
        /// PDB age. Part of the identity, not a version hint.
        age: u32,
        /// How many symbol directories were searched.
        directories: usize,
        /// Candidate files enumerated.
        files_seen: usize,
        /// Files opened and identified.
        files_identified: usize,
        /// Rendered suffix naming a cap, when one fired.
        truncation: String,
    },

    /// A symbol file with the right GUID and age was found, and the admission
    /// gate refused it.
    ///
    /// Distinct from [`DiscoveryError::SymbolsNotFound`]: the file exists and is
    /// the right identity, and something about it is wrong — a corrupt document,
    /// a producer with a known layout defect, a pointer width that contradicts
    /// the paging mode. Fetching the same file again will not help; the examiner
    /// needs to see the report.
    #[error("the symbol file {path} for GUID {guid} was refused: {source}")]
    SymbolsRejected {
        /// Where the file is.
        path: PathBuf,
        /// The GUID it declares.
        guid: String,
        /// The gate report or structural failure.
        #[source]
        source: SymbolError,
    },

    /// The acquisition's own header states an architecture this tier cannot
    /// translate, so no sweep was run (`ROADMAP` §3.8a).
    ///
    /// Refused *before* the directory-table-base sweep rather than after it,
    /// because the sweep's failure reads as "no Windows kernel in this image"
    /// and that is not what happened: the image may well hold one, and the
    /// limit is this tool's. The x64 self-reference and the low stub the
    /// sweep looks for do not exist on ARM64 at all.
    #[error(
        "the image's header states an {architecture} machine, which the Windows memory tier does \
         not support: only Intel paging (32-bit, PAE and x86-64) is translated, so no directory \
         table base was looked for. This is a limit of this tool, not an absence of a kernel in \
         the image ({detail}); every Windows stage is unsupported on it"
    )]
    UnsupportedArchitecture {
        /// The architecture as the header stated it.
        architecture: String,
        /// Which header said so.
        detail: String,
    },

    /// The kernel and its symbols were found, and the Windows version could not
    /// be established from either `_KUSER_SHARED_DATA` or the kernel's own PE
    /// header.
    ///
    /// Fatal rather than defaulted, because several kernel structures changed
    /// layout at version boundaries and a stage that picks a branch without
    /// knowing the version reads real bytes through the wrong layout.
    #[error("the Windows version could not be established: {detail}")]
    VersionUnavailable {
        /// What was tried and what it said.
        detail: String,
    },
}

/// Discover everything the Windows stages need from a physical memory image.
///
/// Returns a [`WindowsProfile`] whose every fact carries the evidence behind it.
/// See [`discover_reported`] when the work itself — candidates swept, pages
/// unreadable, files identified — has to reach the report.
///
/// # Errors
///
/// See [`DiscoveryError`]. In particular [`DiscoveryError::SymbolsNotFound`]
/// names the GUID an examiner must fetch; nothing in this function substitutes a
/// different symbol table for a missing one.
pub fn discover(
    physical: Arc<dyn MemoryLayer>,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
) -> Result<WindowsProfile, DiscoveryError> {
    discover_reported(physical, symbol_dirs, options).map(|(profile, _)| profile)
}

/// [`discover`], plus the account of how it got there.
///
/// # The second sweep
///
/// The shipped sweep window is the low tens of megabytes, which is where every
/// Windows from XP to 11 has been observed to place its top-level page table.
/// A window that finds nothing has not shown that the image holds no kernel,
/// and large-memory Windows 11 machines have been reported with the table above
/// it. So when the configured window produces no directory table base that
/// proves out, the whole acquisition is swept once more and the answer, if
/// there is one, is recorded as having come from the wider sweep.
///
/// It costs a full read of the image, so it runs **only** on the path that
/// would otherwise have returned "no directory table base" or "no kernel". A
/// run that fails for any other reason — a missing symbol file, a rejected
/// symbol table — already found and proved a base, and re-sweeping could only
/// substitute a different one. Nor does it run when the examiner supplied a
/// base of their own or asked for no sweep at all: both are instructions, and
/// answering one with a base found elsewhere would report something nobody
/// asked for.
pub fn discover_reported(
    physical: Arc<dyn MemoryLayer>,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
) -> Result<(WindowsProfile, DiscoveryReport), DiscoveryError> {
    // The gate comes before both sweeps (`ROADMAP` §3.8a). An acquisition
    // format that reads the machine from its header -- the crash dump does --
    // publishes it on the layer; a raw image publishes nothing and is swept
    // as it always was, because a raw image states nothing this could refuse.
    if let Some(architecture) = physical.layer_meta().architecture() {
        if !matches!(architecture, LayerArch::X86 | LayerArch::X64) {
            return Err(DiscoveryError::UnsupportedArchitecture {
                architecture: architecture.as_str().to_string(),
                detail: match physical.layer_meta().format() {
                    Some(format) => format!("stated by the {} header", format.as_str()),
                    None => "stated by the acquisition's own metadata".to_string(),
                },
            });
        }
    }
    let refused = match discover_in_window(Arc::clone(&physical), symbol_dirs, options) {
        Ok(found) => return Ok(found),
        Err(err) => err,
    };
    if !matches!(
        refused,
        DiscoveryError::NoDirectoryTableBase { .. } | DiscoveryError::NoKernel { .. }
    ) {
        return Err(refused);
    }
    // Two instructions this must not talk itself out of. An examiner who named
    // a directory table base is entitled to a failure naming *their* value
    // rather than a profile assembled from a base found behind their back, and
    // an empty region list says "do not sweep" rather than "sweep somewhere
    // else".
    if options.dtb.is_some() || options.dtb_scan_regions.is_empty() {
        return Err(refused);
    }
    let Some(regions) = unswept_remainder(&*physical, &options.dtb_scan_regions) else {
        return Err(refused);
    };
    let mut wider = options.clone();
    wider.dtb_scan_regions = regions;
    match discover_in_window(physical, symbol_dirs, &wider) {
        Ok((profile, mut report)) => {
            report.note(format!(
                "the configured sweep window produced no directory table base that proved out \
                 ({refused}); this profile came from a second sweep of the whole acquisition"
            ));
            Ok((profile, report))
        }
        // The second sweep read everything the first did and more, so its
        // account of pages examined and candidates refused is the fuller one.
        // The first refusal said strictly less about the image.
        Err(err) => Err(err),
    }
}

/// The physical range to sweep when the configured window has already failed.
///
/// The whole acquisition, rather than only the part the window missed: the
/// window is a rounding error against the rest of a modern image, and one
/// unbroken range is what lets the report say the whole acquisition was swept
/// instead of leaving an examiner to work out which slices were.
///
/// `None` when the configured window already covers the image, so a failure
/// stays a single failure and nothing is read twice for nothing.
fn unswept_remainder(
    physical: &dyn MemoryLayer,
    configured: &[Range<u64>],
) -> Option<Vec<Range<u64>>> {
    let top = physical.max_address().checked_add(1)?;
    let covered = configured
        .iter()
        .any(|region| region.start == 0 && region.end >= top);
    if covered {
        return None;
    }
    Some(vec![0..top])
}

/// One pass of discovery over one sweep window.
fn discover_in_window(
    physical: Arc<dyn MemoryLayer>,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
) -> Result<(WindowsProfile, DiscoveryReport), DiscoveryError> {
    options
        .scan
        .validate()
        .map_err(|err| DiscoveryError::Configuration {
            detail: err.to_string(),
        })?;
    if options.max_dtb_attempts == 0 {
        return Err(DiscoveryError::Configuration {
            detail: "max_dtb_attempts must be at least 1, or nothing can be proved".to_string(),
        });
    }

    let mut report = DiscoveryReport::default();

    // The low stub is found once, before anything else, because it publishes
    // both a directory table base and an address inside the kernel.
    report.low_stub = kernel::find_low_stub(&*physical, options.kernel_limits.low_stub_top);

    let candidates = gather_dtb_candidates(&physical, options, &mut report);
    if candidates.is_empty() {
        return Err(no_dtb_error(&report));
    }

    let cache = Arc::new(TableCache::new());
    let mut last_kernel: Option<KernelSearchOutcome> = None;

    for (index, candidate) in candidates.iter().enumerate() {
        if index >= options.max_dtb_attempts {
            report.attempts_truncated = true;
            break;
        }
        let mut attempt = DtbAttempt {
            dtb: candidate.dtb,
            mode: candidate.mode,
            source: candidate.source,
            kuser: None,
            refused: None,
        };
        // Both x86-64 depths are 64-bit; only PAE and plain 32-bit are not. A
        // five-level candidate mistaken for 32-bit here would run the 32-bit
        // kernel search and never find its 64-bit kernel.
        let is_64bit = matches!(
            candidate.mode,
            PagingMode::Intel32e | PagingMode::Intel32eLa57
        );
        let spec = PagingSpec::new(candidate.mode, PteSemantics::Windows);

        let space = match VirtualLayer::with_cache(
            Arc::clone(&physical),
            candidate.dtb,
            spec,
            options.translation,
            Arc::clone(&cache),
        ) {
            // Attached here rather than after the fact: a `VirtualLayer` is not
            // `Clone`, and every probe below reads through this same space.
            //
            // They resolve nothing yet, and cannot. Which bits of a software
            // PTE hold `PageFileLow` depends on the Windows build, and the
            // build is read *through* this space — so the spec above leaves the
            // layout unstated and every swapped page stays a hole until
            // `finish` re-states it. Attaching here anyway is what keeps the
            // profile's space and the examiner's files together in one object
            // for the rebuild.
            Ok(space) => Arc::new(space.with_swap(options.pagefiles.clone())),
            Err(err) => {
                attempt.refused = Some(err.to_string());
                report.attempts.push(attempt);
                continue;
            }
        };
        attempt.kuser = Some(dtb::kuser_shared_data_check(&space, is_64bit));

        // Deliberately not a rejection when it abstains: recent Windows has
        // begun relocating the kernel-side `_KUSER_SHARED_DATA` mapping, so an
        // `Absent` result would reject a correct DTB on a modern image. The
        // real test is whether a kernel proves out.
        let search = match options.kernel_base {
            Some(base) => {
                let mut outcome = KernelSearchOutcome {
                    methods_tried: vec![KernelMethod::Supplied],
                    ..KernelSearchOutcome::default()
                };
                match kernel::prove_kernel_at(&*space, base) {
                    Ok(image) => {
                        outcome.image = Some(image);
                        outcome.method = Some(KernelMethod::Supplied);
                    }
                    Err(why) => outcome.rejected.push((base, KernelMethod::Supplied, why)),
                }
                outcome
            }
            None => kernel::locate_kernel(
                &*physical,
                &space,
                is_64bit,
                report.low_stub.as_ref().filter(|_| is_64bit),
                &options.scan,
                &options.kernel_limits,
            ),
        };

        let Some(image) = search.image.clone() else {
            attempt.refused = Some(format!(
                "no kernel proved out here; {} candidate(s) refused",
                search.rejected.len()
            ));
            report.attempts.push(attempt);
            last_kernel = Some(search);
            continue;
        };

        // The kernel's own `IMAGE_FILE_HEADER.Machine` against the word size the
        // paging mode implies. Disagreement means one of the two is wrong, and
        // there is no way to tell which, so neither is used.
        if image.is_64bit_machine() != is_64bit {
            attempt.refused = Some(format!(
                "the kernel at {:#x} declares machine {:#06x}, which contradicts {} paging",
                image.base,
                image.machine,
                candidate.mode.as_str()
            ));
            report.attempts.push(attempt);
            last_kernel = Some(search);
            continue;
        }

        report.attempts.push(attempt);
        report.kernel = Some(search);
        return finish(
            physical,
            space,
            candidate,
            image,
            is_64bit,
            symbol_dirs,
            options,
            report,
        );
    }

    // A search stopped by the attempt cap has not shown that the image holds no
    // kernel, and an examiner reading "no kernel was found" is entitled to the
    // difference between an exhausted search and an abandoned one.
    let truncation = if report.attempts_truncated {
        format!(
            " The attempt cap of {} stopped discovery before every candidate was tried, so this \
             is not an exhaustive result; raise max_dtb_attempts to continue.",
            options.max_dtb_attempts
        )
    } else {
        String::new()
    };
    let detail = match last_kernel.as_ref() {
        Some(search) => match search.rejected.first() {
            Some((address, method, why)) => format!(
                "the last search tried {} method(s); the first refusal was {:#x} via {}: {why}",
                search.methods_tried.len(),
                address,
                method.as_str()
            ),
            None => format!(
                "the last search tried {} method(s) and produced no candidate at all",
                search.methods_tried.len()
            ),
        },
        None => "no address space could be built from any candidate".to_string(),
    };
    report.kernel = last_kernel;
    Err(DiscoveryError::NoKernel {
        attempts: report.attempts.len(),
        detail: format!("{detail}{truncation}"),
    })
}

/// A directory-table-base candidate before it has been built into anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Candidate {
    dtb: u64,
    mode: PagingMode,
    source: DtbSource,
}

/// Assemble every directory-table-base candidate, strongest source first.
///
/// Order matters twice over. It decides which candidate is tried first, and
/// therefore which evidence grade the accepted answer carries when two sources
/// name the same base; and it bounds the work, because each candidate costs a
/// full kernel search.
fn gather_dtb_candidates(
    physical: &Arc<dyn MemoryLayer>,
    options: &DiscoveryOptions,
    report: &mut DiscoveryReport,
) -> Vec<Candidate> {
    let modes = options.modes();
    let mut out: Vec<Candidate> = Vec::new();
    // Identity is the base and the mode, not the source. Two sources naming one
    // address space describe the same work, and the attempt budget bounds full
    // kernel searches: a crash dump whose header publishes the page the sweep
    // also finds would otherwise spend four of sixteen attempts proving one
    // address. The first push wins, so the candidate keeps the grade of the
    // strongest source that named it.
    let push = |candidate: Candidate, out: &mut Vec<Candidate>| {
        let already = out
            .iter()
            .any(|existing| existing.dtb == candidate.dtb && existing.mode == candidate.mode);
        if candidate.dtb != 0 && !already {
            out.push(candidate);
        }
    };

    if let Some(dtb) = options.dtb {
        for mode in &modes {
            push(
                Candidate {
                    dtb,
                    mode: *mode,
                    source: DtbSource::Supplied,
                },
                &mut out,
            );
        }
    }

    // A crash dump publishes the DTB in its header, and the format readers put
    // it in the layer's metadata. It is a claim by the capture tool rather than
    // a fact about the bytes, so it is tried early and still proved.
    if let Some(published) = physical
        .layer_meta()
        .note("directory_table_base")
        .and_then(serde_json::Value::as_u64)
    {
        if published != 0 {
            report.note(format!(
                "the acquisition header publishes a directory table base of {published:#x}"
            ));
            for mode in &modes {
                push(
                    Candidate {
                        dtb: published,
                        mode: *mode,
                        source: DtbSource::AcquisitionHeader,
                    },
                    &mut out,
                );
            }
        }
    }

    if let Some(stub) = report.low_stub {
        if modes.contains(&PagingMode::Intel32e) {
            report.note(format!(
                "the x64 low stub at {:#x} names CR3 {:#x}",
                stub.physical_offset, stub.cr3
            ));
            push(
                Candidate {
                    dtb: stub.cr3_frame(),
                    mode: PagingMode::Intel32e,
                    source: DtbSource::LowStubCr3,
                },
                &mut out,
            );
            // The low stub's CR3 is the top-table frame whether the machine runs
            // four or five levels — the stub does not carry `CR4.LA57`. Offer it
            // to the five-level walk too when that mode is in play.
            if modes.contains(&PagingMode::Intel32eLa57) {
                push(
                    Candidate {
                        dtb: stub.cr3_frame(),
                        mode: PagingMode::Intel32eLa57,
                        source: DtbSource::LowStubCr3,
                    },
                    &mut out,
                );
            }
        }
    }

    let mut x64_swept = false;
    for mode in &modes {
        // Intel32e and Intel32eLa57 self-reference by identical rules, so a
        // single sweep of the window serves both: mirror the four-level
        // candidates onto the five-level mode rather than scan the window (up to
        // `max_dtb_pages`) a second time. Validation later proves which depth the
        // image really uses. This holds only because LA57 follows Intel32e in
        // `MODE_ORDER`, so the sweep has already run when the mirror is taken.
        if *mode == PagingMode::Intel32eLa57 && x64_swept {
            let twins: Vec<u64> = out
                .iter()
                .filter(|c| c.mode == PagingMode::Intel32e && c.source == DtbSource::SelfReference)
                .map(|c| c.dtb)
                .collect();
            for dtb in twins {
                push(
                    Candidate {
                        dtb,
                        mode: PagingMode::Intel32eLa57,
                        source: DtbSource::SelfReference,
                    },
                    &mut out,
                );
            }
            continue;
        }
        let outcome = dtb::scan_dtb_candidates(
            &**physical,
            *mode,
            &options.dtb_scan_regions,
            options.max_dtb_candidates,
            options.max_dtb_pages,
        );
        for found in &outcome.candidates {
            push(
                Candidate {
                    dtb: found.dtb,
                    mode: *mode,
                    source: DtbSource::SelfReference,
                },
                &mut out,
            );
        }
        report.dtb_scans.push((*mode, outcome));
        if *mode == PagingMode::Intel32e {
            x64_swept = true;
        }
    }

    out
}

fn no_dtb_error(report: &DiscoveryReport) -> DiscoveryError {
    let mut candidates = 0usize;
    let mut pages_examined = 0u64;
    let mut pages_unreadable = 0u64;
    let mut truncated = false;
    for (_, outcome) in &report.dtb_scans {
        candidates += outcome.candidates.len();
        pages_examined = pages_examined.saturating_add(outcome.pages_examined);
        pages_unreadable = pages_unreadable.saturating_add(outcome.pages_unreadable);
        truncated |= outcome.truncated;
    }
    DiscoveryError::NoDirectoryTableBase {
        candidates,
        pages_examined,
        pages_unreadable,
        truncation: if truncated {
            ", and a cap stopped at least one sweep before it finished".to_string()
        } else {
            String::new()
        },
    }
}

/// Select symbols, prove them against the image, read the version facts, and
/// assemble the profile.
#[allow(clippy::too_many_arguments)]
fn finish(
    physical: Arc<dyn MemoryLayer>,
    space: Arc<VirtualLayer>,
    candidate: &Candidate,
    image: KernelImage,
    is_64bit: bool,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
    mut report: DiscoveryReport,
) -> Result<(WindowsProfile, DiscoveryReport), DiscoveryError> {
    let search = isf::find_matching_isf(
        symbol_dirs,
        &image.pdb,
        options.max_isf_files,
        options.max_isf_depth,
        options.max_isf_identified,
    );
    let best = search.matches.first().cloned();
    let truncation = if search.truncated {
        ", and a cap stopped the search before it finished".to_string()
    } else {
        String::new()
    };
    report.isf = Some(search);

    let Some(best) = best else {
        let search = report.isf.as_ref().expect("just recorded");
        return Err(DiscoveryError::SymbolsNotFound {
            pdb: image.pdb.pdb.clone(),
            guid: image.pdb.guid.clone(),
            age: image.pdb.age,
            directories: symbol_dirs.len(),
            files_seen: search.files_seen,
            files_identified: search.files_identified,
            truncation,
        });
    };
    if !best.database.eq_ignore_ascii_case(&image.pdb.pdb) {
        report.note(format!(
            "the symbol file names itself {} while the image's CodeView record names {}; \
             the GUID and age agree, and the admission gate decides",
            best.database, image.pdb.pdb
        ));
    }

    let arch = if is_64bit { IsfArch::X64 } else { IsfArch::X86 };
    let compile = CompileOptions {
        validation: ValidationOptions::new()
            .expect_identifier(image.pdb.identifier())
            .expect_architecture(arch),
        ..CompileOptions::default()
    };
    let mut table = SymbolTable::compile_path(&best.path, &DecompressLimits::default(), &compile)
        .map_err(|source| DiscoveryError::SymbolsRejected {
        path: best.path.clone(),
        guid: image.pdb.guid.clone(),
        source,
    })?;

    // The address space becomes the layer every stage reads through. The
    // coercion is the only thing that happens here: the same object, viewed as
    // the trait the rest of the crate speaks. `space` stays in hand because the
    // pagefile layout below has to be re-stated on a layer built the same way.
    let kernel_space: Arc<dyn MemoryLayer> = space.clone();
    let probe = LayerProbe::new(
        Arc::clone(&kernel_space),
        if is_64bit { 8 } else { 4 },
        Some(image.pdb.identifier()),
    );
    let kuser_va = if is_64bit {
        dtb::KUSER_SHARED_DATA_KERNEL_VA_X64
    } else {
        dtb::KUSER_SHARED_DATA_KERNEL_VA_X86
    };
    let gates = image_sanity_gates(&table, &probe, kuser_va, image.base, is_64bit);
    for result in gates {
        table.record_gate(result);
    }
    // Gate 4 is the only check that can falsify a table which has already
    // matched on GUID and age, and a table it falsified must not reach a single
    // analysis stage. `_KUSER_SHARED_DATA.NtMajorVersion` reading a version no
    // Windows has ever reported means this table's layouts do not describe this
    // image, so every offset it supplies is wrong, and every field read at
    // those offsets still parses, which is why nothing downstream could catch
    // it. `AdmissionState::Rejected` is defined as "no symbol-dependent
    // analysis runs"; returning a profile holding a rejected table would make
    // that definition unenforceable.
    if table.state() == AdmissionState::Rejected {
        return Err(DiscoveryError::SymbolsRejected {
            path: best.path.clone(),
            guid: image.pdb.guid.clone(),
            source: SymbolError::Rejected(Box::new(table.admission().clone())),
        });
    }
    let symbols = Arc::new(table);

    let build = read_kernel_build(&kernel_space, &symbols, &image, kuser_va, &mut report)?;
    // The build is what settles where `MMPTE_SOFTWARE.PageFileLow` sits, and it
    // could not be known when the space was built, so the layer above answers
    // every swapped page with a hole whatever the examiner attached. Re-state it
    // now, before anything else reads through the space.
    let kernel_space = with_pagefile_layout(&space, kernel_space, &build, options, &mut report);
    let kdbg = locate_kdbg(&kernel_space, &symbols, image.base, is_64bit, &mut report);

    let architecture = if is_64bit {
        LayerArch::X64
    } else {
        LayerArch::X86
    };
    let kernel_base_evidence = match report
        .kernel
        .as_ref()
        .and_then(|search| search.method)
        .unwrap_or(KernelMethod::VirtualScan)
    {
        KernelMethod::Supplied => Evidence::Supplied,
        // The machine wrote these two down; the PE header then proved them.
        KernelMethod::LowStub | KernelMethod::KdbgTag => Evidence::Confirmed,
        // Found by searching, then proved by reading a kernel header there.
        KernelMethod::FixedMapping | KernelMethod::VirtualScan => Evidence::Validated,
    };

    let profile = WindowsProfile {
        kernel_space,
        physical,
        symbols,
        pagefiles: options.pagefiles.clone(),
        dtb: Found::new(candidate.dtb, candidate.source.evidence()),
        kernel_base: Found::new(image.base, kernel_base_evidence),
        kdbg,
        build,
        architecture,
    };
    Ok((profile, report))
}

/// Rebuild the kernel address space with the `MMPTE_SOFTWARE.PageFileLow`
/// layout this build uses, so an attached pagefile resolves through it.
///
/// The ordering is forced and cannot be avoided: the space has to exist before
/// the build number can be read, because the build number is read *through* it.
/// A [`PagingSpec`] built before then leaves `swap_index_shift` unset, so a
/// software PTE is classified with `index: None`, and `VirtualLayer::swap_run`
/// keeps the page a hole rather than answering it from a file the PTE did not
/// name. Without this rebuild every pagefile the examiner attached is dead on
/// the kernel space for the whole analysis, while the discovery record says
/// they were attached. Per-process spaces never had the problem: they are built
/// after discovery, from a profile that already carries the build.
///
/// The original layer is kept when nothing would change by rebuilding — no
/// pagefile attached — and when the build never settled which Windows this is.
/// [`PagingSpec::with_win8_pagefile_layout`] takes a `bool` and there is no
/// value of it meaning "unknown": guessing reads four bits that name a
/// *different* pagefile, and an offset applied to the wrong file returns bytes
/// rather than failing.
fn with_pagefile_layout(
    space: &Arc<VirtualLayer>,
    kernel_space: Arc<dyn MemoryLayer>,
    build: &KernelBuild,
    options: &DiscoveryOptions,
    report: &mut DiscoveryReport,
) -> Arc<dyn MemoryLayer> {
    if options.pagefiles.is_empty() {
        return kernel_space;
    }
    let Some(win8) = build.is_win8_or_later() else {
        report.note(
            "the Windows build was never established, so which bits of a software PTE name the \
             pagefile is unknown; the attached pagefile(s) resolve nothing on the kernel address \
             space and swapped kernel pages stay holes",
        );
        return kernel_space;
    };
    let spec = space.spec().with_win8_pagefile_layout(win8);
    match VirtualLayer::with_cache(
        Arc::clone(space.physical()),
        space.dtb(),
        spec,
        space.policy(),
        Arc::clone(space.table_cache()),
    ) {
        Ok(layer) => Arc::new(layer.with_swap(options.pagefiles.clone())),
        // Same base, same mode, same policy as the layer that was already built
        // and read through, so nothing here can fail that did not fail then.
        // If it somehow does, the space that works is kept — losing a proved
        // profile over an attachment would cost the examiner the whole image —
        // and the report says the pagefiles are not resolving on it.
        Err(err) => {
            report.note(format!(
                "the kernel address space could not be rebuilt with this build's pagefile layout \
                 ({err}), so swapped kernel pages stay holes"
            ));
            kernel_space
        }
    }
}

/// Gate 4: read typed fields through the candidate table and see whether they
/// make sense.
///
/// The one check that can falsify a symbol table which has already matched on
/// GUID and age — which should be impossible, and is exactly the kind of
/// impossible thing a corrupted or hand-edited symbol pack makes happen. Every
/// check distinguishes three outcomes, and the distinction is the point:
///
/// - the field read and its value is implausible: **fail**, and the table is
///   refused;
/// - the field could not be read at all: **inconclusive**, because a paged-out
///   `_KUSER_SHARED_DATA` says nothing about the table, and it still blocks;
/// - the table does not declare the field at all: **not applicable**, which is
///   recorded and named but does not block, because the member's absence is a
///   fact about the operating system with nothing left to prove. It is never
///   `pass`: an examiner comparing two builds must be able to see which checks
///   each one actually supported.
fn image_sanity_gates(
    table: &SymbolTable,
    probe: &LayerProbe,
    kuser_va: u64,
    kernel_base: u64,
    is_64bit: bool,
) -> Vec<GateResult> {
    let mut results = Vec::new();

    const KUSER: &str = "_KUSER_SHARED_DATA";
    if !table.has_member(KUSER, "NtMajorVersion") {
        // Absent from the layout, so there is nothing to prove and nothing that
        // could have been proved. Recorded as inapplicable rather than unproved
        // so it does not hold the table at `Unverified`; a read that was
        // attempted and failed is `inconclusive` below, which does block.
        results.push(GateResult::not_applicable(
            Gate::ImageSanity,
            "windows_nt_version",
            format!("this build's {KUSER} has no NtMajorVersion member to read"),
        ));
    } else {
        match table.read_member_unsigned(probe, kuser_va, KUSER, "NtMajorVersion") {
            Ok(major) => {
                if NT_MAJOR_VERSIONS.contains(&major) {
                    results.push(GateResult::pass(
                        Gate::ImageSanity,
                        "windows_nt_version",
                        format!("{KUSER}.NtMajorVersion reads {major}, a version Windows has had"),
                    ));
                } else {
                    let mut result = GateResult::fail(
                        Gate::ImageSanity,
                        "windows_nt_version",
                        "the table's _KUSER_SHARED_DATA layout does not describe this image",
                    );
                    result.violate(format!(
                        "{KUSER}.NtMajorVersion at {kuser_va:#x} reads {major}, and no Windows \
                         has ever reported that"
                    ));
                    results.push(result);
                }
            }
            Err(err) => results.push(GateResult::inconclusive(
                Gate::ImageSanity,
                "windows_nt_version",
                format!("{KUSER}.NtMajorVersion could not be read: {err}"),
            )),
        }
    }

    if !table.has_member(KUSER, "NtBuildNumber") {
        // Recorded rather than skipped, so a table missing the member does not
        // read in the report exactly like one that passed — but recorded as
        // INAPPLICABLE, not unproved. Windows XP genuinely has no
        // `_KUSER_SHARED_DATA.NtBuildNumber`; the build comes from `NtBuildLab`
        // instead, which is why `build_from_lab` exists. Calling that absence
        // unproved held every XP capture at `Unverified` and stamped all its
        // analysis stages as short of the evidence, when the stages had run in
        // full and the only thing missing was a member the operating system
        // never had.
        results.push(GateResult::not_applicable(
            Gate::ImageSanity,
            "windows_build_number",
            format!(
                "this build's {KUSER} has no NtBuildNumber member; the build number is read from \
                 NtBuildLab instead"
            ),
        ));
    } else {
        match table.read_member_unsigned(probe, kuser_va, KUSER, "NtBuildNumber") {
            Ok(build) if NT_BUILD_RANGE.contains(&build) => results.push(GateResult::pass(
                Gate::ImageSanity,
                "windows_build_number",
                format!("{KUSER}.NtBuildNumber reads {build}"),
            )),
            Ok(build) => {
                let mut result = GateResult::fail(
                    Gate::ImageSanity,
                    "windows_build_number",
                    "the build number read through this table is not a build number",
                );
                result.violate(format!(
                    "{KUSER}.NtBuildNumber at {kuser_va:#x} reads {build}, outside {}..{}",
                    NT_BUILD_RANGE.start, NT_BUILD_RANGE.end
                ));
                results.push(result);
            }
            Err(err) => results.push(GateResult::inconclusive(
                Gate::ImageSanity,
                "windows_build_number",
                format!("{KUSER}.NtBuildNumber could not be read: {err}"),
            )),
        }
    }

    // A kernel global that must hold a kernel pointer. A table describing a
    // different build puts this symbol at a different relative address, and the
    // bytes there are overwhelmingly unlikely to be a canonical kernel pointer.
    results.push(kernel_pointer_gate(
        table,
        probe,
        kernel_base,
        is_64bit,
        "PsActiveProcessHead",
    ));

    // Any one check here may be inapplicable, and each of those is an honest
    // fact about a build: Windows XP has no `_KUSER_SHARED_DATA.NtBuildNumber`
    // and there is nothing left to prove about it. All of them at once is a
    // different claim. `NotApplicable` does not block admission, so a table
    // declaring none of the members and symbols this gate reads would be graded
    // `Verified` on the strength of gates 1-3 alone — and those match on GUID,
    // age and architecture, which is exactly what a hand-edited or corrupted
    // symbol pack still gets right. Gate 4 is the only check that can falsify
    // such a table, so a table that escapes all of it has not been checked
    // against this image at all, and that must read as unproved rather than as
    // nothing to prove.
    if results
        .iter()
        .all(|result| result.outcome == GateOutcome::NotApplicable)
    {
        results.push(GateResult::not_evaluated(
            Gate::ImageSanity,
            "windows_image_sanity",
            format!(
                "this table declares no {KUSER}.NtMajorVersion, no {KUSER}.NtBuildNumber and no \
                 'PsActiveProcessHead', so nothing in it was read against this image"
            ),
        ));
    }
    results
}

fn kernel_pointer_gate(
    table: &SymbolTable,
    probe: &LayerProbe,
    kernel_base: u64,
    is_64bit: bool,
    symbol: &str,
) -> GateResult {
    use seance_symbols::ImageProbe;

    let check = "windows_kernel_pointer";
    if !table.has_symbol(symbol) {
        // Absent from this build's symbol set, so the check does not apply.
        // Distinct from the `symbol_address` failure below, where the symbol IS
        // declared and its address will not resolve — that is a real gap and
        // stays `not_evaluated`.
        return GateResult::not_applicable(
            Gate::ImageSanity,
            check,
            format!("this build's symbol set has no '{symbol}' to read"),
        );
    }
    let Ok(rva) = table.symbol_address(symbol) else {
        return GateResult::not_evaluated(
            Gate::ImageSanity,
            check,
            format!("'{symbol}' has no readable address in this table"),
        );
    };
    let Some(address) = kernel_base.checked_add(rva) else {
        let mut result = GateResult::fail(
            Gate::ImageSanity,
            check,
            "a symbol address does not fit above the kernel base",
        );
        result.violate(format!(
            "the kernel base {kernel_base:#x} plus '{symbol}' at {rva:#x} overflows"
        ));
        return result;
    };

    let width = if is_64bit { 8usize } else { 4 };
    let mut buf = [0u8; 8];
    if let Err(err) = probe.read_exact(address, &mut buf[..width]) {
        return GateResult::inconclusive(
            Gate::ImageSanity,
            check,
            format!("'{symbol}' at {address:#x} could not be read: {err}"),
        );
    }
    let value = u64::from_le_bytes(buf);
    let floor = if is_64bit {
        KERNEL_HALF_START_X64
    } else {
        KERNEL_HALF_START_X86
    };
    let canonical = seance_memory::object::is_canonical(value, if is_64bit { 8 } else { 4 });
    if value >= floor && canonical {
        GateResult::pass(
            Gate::ImageSanity,
            check,
            format!("'{symbol}' at {address:#x} holds the kernel pointer {value:#x}"),
        )
    } else {
        let mut result = GateResult::fail(
            Gate::ImageSanity,
            check,
            "a kernel global does not hold a kernel pointer through this table",
        );
        result.violate(format!(
            "'{symbol}' at {address:#x} holds {value:#x}, which is not a canonical kernel address"
        ));
        result
    }
}

/// Read the version facts the profile needs.
///
/// `_KUSER_SHARED_DATA` first, because it carries the build number and the PE
/// header does not. The kernel's own optional header is the fallback for major
/// and minor, and it is a real fallback rather than a guess: those two fields
/// are the kernel image's own statement of the Windows version it belongs to.
/// Which of the two was used is recorded, because a profile with no build number
/// forces every stage that needs one to fail closed.
fn read_kernel_build(
    space: &Arc<dyn MemoryLayer>,
    symbols: &Arc<SymbolTable>,
    image: &KernelImage,
    kuser_va: u64,
    report: &mut DiscoveryReport,
) -> Result<KernelBuild, DiscoveryError> {
    let mut major: Option<u32> = None;
    let mut minor: Option<u32> = None;
    let mut build: Option<u32> = None;

    if symbols.has_type("_KUSER_SHARED_DATA") {
        let reader = StructReader::new(Arc::clone(space), Arc::clone(symbols));
        match reader.object(kuser_va, "_KUSER_SHARED_DATA") {
            Ok(kuser) => {
                // Sanity-filtered on the way in, not on the way out. A mapped
                // page of zeros reads perfectly and yields major 0, which
                // `KernelBuild::is_win8_or_later` would answer `Some(false)`
                // for, and a stage would then decode `MMPTE_SOFTWARE` through the
                // pre-Windows-8 bit layout because a page nothing wrote to
                // said so.
                major = kuser
                    .unsigned("NtMajorVersion")
                    .ok()
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| NT_MAJOR_VERSIONS.contains(&u64::from(*v)));
                minor = kuser
                    .unsigned("NtMinorVersion")
                    .ok()
                    .and_then(|v| u32::try_from(v).ok());
                build = kuser
                    .unsigned("NtBuildNumber")
                    .ok()
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| NT_BUILD_RANGE.contains(&u64::from(*v)));
            }
            Err(err) => report.note(format!(
                "_KUSER_SHARED_DATA at {kuser_va:#x} could not be read: {err}"
            )),
        }
    } else {
        report.note("the symbol table declares no _KUSER_SHARED_DATA".to_string());
    }

    // Both halves of the version have to come from the same structure. A major
    // version out of `_KUSER_SHARED_DATA` paired with a minor version that
    // could not be read there is not a version, it is half of one, and pairing
    // it with the other half from the PE header would report a version neither
    // structure states. When the pair is incomplete the whole reading is
    // discarded, including the build number, so that `version_source` names
    // one structure and every fact in the profile came from it.
    if major.is_none() || minor.is_none() {
        major = None;
        minor = None;
        build = None;
    }

    // Whether `_KUSER_SHARED_DATA` answered for the version. The build number
    // may only be completed from `NtBuildLab` below when it did: a build number
    // beside a version the structure did not state is a profile assembled from
    // two structures, which is the thing the discard above exists to prevent.
    let version_from_kuser = major.is_some();

    if major.is_some() {
        report.version_source = Some("kuser_shared_data");
    } else if image.os_major != 0 {
        report.version_source = Some("pe_optional_header");
        report.note(
            "the Windows version came from the kernel's PE optional header, which carries no \
             build number; any stage needing the build must fail closed"
                .to_string(),
        );
        major = Some(image.os_major);
        minor = Some(image.os_minor);
    }

    let (Some(major), Some(minor)) = (major, minor) else {
        return Err(DiscoveryError::VersionUnavailable {
            detail: format!(
                "neither _KUSER_SHARED_DATA at {kuser_va:#x} nor the kernel's PE optional header \
                 gave a major and minor version"
            ),
        });
    };

    let build_lab = read_build_lab(space, symbols, image.base);

    // `_KUSER_SHARED_DATA.NtBuildNumber` does not exist on every build — Windows
    // XP's `_KUSER_SHARED_DATA` has no such member at all — so on those images
    // the build number has to come from `NtBuildLab`, whose first field IS the
    // build number: `2600.xpsp_sp2_gdr.050301-1519`.
    //
    // This is not a guess dressed up as a reading. The leading field is the
    // build by definition of the string's format, it is range-checked the same
    // way `NtBuildNumber` is, and `build_source` records which of the two the
    // number came from so a report never implies the kernel stated it directly.
    //
    // Without this, six analysis stages fail closed on every XP-era image —
    // correctly, since each needs the build to choose a structure layout — and
    // the capture yields a process list and nothing else.
    //
    // It is available only when `_KUSER_SHARED_DATA` answered for the version.
    // The fallback exists for a structure that is *present and silent* about the
    // build, not for a reading that was thrown away: completing a discarded
    // reading from a third structure would put a build number next to a version
    // that came from the PE header, and a stage branching on that pair would be
    // choosing a layout from facts no one structure stated together.
    let mut build_source = build.map(|_| "kuser_shared_data");
    if build.is_none() {
        match build_lab.as_deref().and_then(build_from_lab) {
            Some(from_lab) if version_from_kuser => {
                build = Some(from_lab);
                build_source = Some("nt_build_lab");
                report.note(format!(
                    "the build number {from_lab} came from NtBuildLab; this build's \
                     _KUSER_SHARED_DATA declares no NtBuildNumber"
                ));
            }
            Some(from_lab) => report.note(format!(
                "NtBuildLab names build {from_lab}, and it was not taken: the version did not \
                 come from _KUSER_SHARED_DATA, so a build number beside it would belong to no \
                 structure that stated the version"
            )),
            None => {}
        }
    }

    Ok(KernelBuild {
        pdb: image.pdb.pdb.clone(),
        guid: image.pdb.guid.clone(),
        age: image.pdb.age,
        build_lab,
        major,
        minor,
        build,
        build_source,
    })
}

/// The build number at the head of an `NtBuildLab` string.
///
/// The format is `<build>.<revision>.<arch>.<branch>.<date-time>`, so the
/// leading run of digits before the first separator is the build. Anything else
/// — a lab string that does not begin with digits, or a number outside the
/// range any Windows build has occupied — yields `None` rather than a guess.
fn build_from_lab(lab: &str) -> Option<u32> {
    let digits: String = lab.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let build: u32 = digits.parse().ok()?;
    NT_BUILD_RANGE.contains(&u64::from(build)).then_some(build)
}

/// The `NtBuildLab` string, when the kernel has one and it is in the evidence.
///
/// A build lab string — `22000.1.amd64fre.co_release.210604-1628` — names the
/// exact branch and build date, which is the fact an examiner quotes when
/// stating what was running. Absent rather than empty when it cannot be read:
/// an empty string in a report reads as "the kernel had no build lab", which is
/// a different claim from "we could not read it".
fn read_build_lab(
    space: &Arc<dyn MemoryLayer>,
    symbols: &Arc<SymbolTable>,
    kernel_base: u64,
) -> Option<String> {
    let rva = symbols.symbol_address("NtBuildLab").ok()?;
    let address = kernel_base.checked_add(rva)?;
    // The string runs to a NUL whose position is unknown, and the page it sits
    // in may end before it does, so shorter reads are tried in turn rather than
    // padding a long one.
    for len in [MAX_BUILD_LAB_BYTES, 64, 32, 16] {
        let mut buf = vec![0u8; len];
        if read_exact_or_fail(space.as_data_source(), address, &mut buf, "NtBuildLab").is_err() {
            continue;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let text = buf.get(..end)?;
        if text.is_empty() || !text.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
            return None;
        }
        return std::str::from_utf8(text).ok().map(str::to_string);
    }
    None
}

/// Locate `KdDebuggerDataBlock` through the symbol table and corroborate it with
/// its `KDBG` owner tag.
///
/// The address comes from the symbol table, which is the only offset-free way to
/// get it; the tag then says whether the block is really there. An address whose
/// tag reads as something else is reported as *nothing*, not as a located block:
/// an examiner following a wrong `KdDebuggerDataBlock` into a report has been
/// given a fact that is not one.
fn locate_kdbg(
    space: &Arc<dyn MemoryLayer>,
    symbols: &Arc<SymbolTable>,
    kernel_base: u64,
    is_64bit: bool,
    report: &mut DiscoveryReport,
) -> Option<Found<u64>> {
    let rva = symbols.symbol_address("KdDebuggerDataBlock").ok()?;
    let address = kernel_base.checked_add(rva)?;
    let tag_offset = if is_64bit {
        kernel::KDBG_TAG_TO_BLOCK_X64
    } else {
        kernel::KDBG_TAG_TO_BLOCK_X86
    };
    let tag_at = address.checked_add(tag_offset)?;

    let mut tag = [0u8; 4];
    match read_exact_or_fail(
        space.as_data_source(),
        tag_at,
        &mut tag,
        "_DBGKD_DEBUG_DATA_HEADER.OwnerTag",
    ) {
        Ok(()) if &tag == kernel::KDBG_TAG => Some(Found::new(address, Evidence::Confirmed)),
        Ok(()) => {
            report.note(format!(
                "KdDebuggerDataBlock resolves to {address:#x}, where the owner tag reads {:?} \
                 rather than KDBG, so no debugger data block is reported",
                String::from_utf8_lossy(&tag)
            ));
            None
        }
        Err(_) => {
            report.note(format!(
                "KdDebuggerDataBlock resolves to {address:#x}, and its owner tag is not in the \
                 evidence, so the block is reported without corroboration"
            ));
            // Deliberately not `Validated`: that grade means an independent
            // check was made and passed, and here none could be made at all.
            // Overstating it would let a profile whose weakest fact is an
            // unchecked address describe itself as validated throughout.
            Some(Found::new(address, Evidence::Scanned))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_from_lab;

    #[test]
    fn the_build_number_is_the_leading_field_of_the_build_lab() {
        // The XP image in the parity corpus. Its `_KUSER_SHARED_DATA` declares
        // no `NtBuildNumber` at all, so without this the build is never
        // established and six analysis stages fail closed on every XP-era
        // capture — correctly, but the capture then yields almost nothing.
        assert_eq!(build_from_lab("2600.xpsp_sp2_gdr.050301-1519"), Some(2600));
        assert_eq!(
            build_from_lab("22000.1.amd64fre.co_release.210604-1628"),
            Some(22000)
        );
        assert_eq!(
            build_from_lab("7601.24214.amd64fre.win7sp1_ldr"),
            Some(7601)
        );
    }

    #[test]
    fn a_lab_string_that_does_not_begin_with_a_build_yields_nothing() {
        // Better no build number — every stage that needs one then fails closed
        // and says so — than a number invented from a string that was not one.
        assert_eq!(build_from_lab(""), None);
        assert_eq!(build_from_lab("amd64fre.rs_prerelease.190318-1202"), None);
        assert_eq!(build_from_lab(".2600"), None);
    }

    #[test]
    fn a_build_number_outside_any_shipped_range_is_refused() {
        // A lab string read out of the wrong bytes can begin with digits.
        assert_eq!(build_from_lab("1.2.3"), None);
        assert_eq!(build_from_lab("999999999.x"), None);
    }

    use super::*;
    // Only the tests read a gate's outcome back; importing it at file scope
    // makes `cargo clippy --workspace --all-features -- -D warnings`, which
    // compiles without `cfg(test)`, fail on an unused import.
    use seance_symbols::GateOutcome;

    use crate::automagic::dtb::test_support::Image;
    use crate::automagic::isf::test_support::{windows_isf, TempDir};
    use crate::automagic::kernel::test_support::{IMAGE_SIZE, KERNEL_PHYS, KERNEL_VA, PML4};
    use crate::automagic::pe::test_support::PeBuilder;

    // Physical layout of the end-to-end fixture. Everything is stated rather
    // than derived so a failing test points at one address.
    const PDPT: u64 = 0x2000;
    const PD: u64 = 0x3000;
    const PT: u64 = 0x4000;
    const PDPT_KUSER: u64 = 0x5000;
    const PD_KUSER: u64 = 0x6000;
    const PT_KUSER: u64 = 0x7000;
    const PDPT_USER: u64 = 0x8000;
    const PD_USER: u64 = 0x9000;
    const PT_USER: u64 = 0xA000;
    const KUSER_PHYS: u64 = 0xB000;
    /// A second page with exactly one self-reference and nothing behind it.
    const DECOY_PML4: u64 = 0x10_0000;

    /// Offsets the test ISF declares for `_KUSER_SHARED_DATA`.
    const NT_BUILD_NUMBER_OFFSET: u64 = 592;
    const NT_MAJOR_OFFSET: u64 = 620;
    const NT_MINOR_OFFSET: u64 = 624;
    /// Address the test ISF declares for the `NtBuildLab` symbol, as an RVA.
    const NT_BUILD_LAB_RVA: u64 = 4096;

    const BUILD_LAB: &[u8] = b"22000.1.amd64fre.co_release.210604-1628";

    fn guid() -> String {
        pe::format_pdb_guid(&PeBuilder::default().guid_raw)
    }

    /// A complete synthetic Windows x64 image: page tables, a kernel PE with a
    /// CodeView record, `_KUSER_SHARED_DATA` mapped on both sides, and an
    /// `NtBuildLab` string where the test ISF's symbol points.
    fn windows_image(with_decoy: bool) -> Image {
        let mut image = Image::new(IMAGE_SIZE);

        // The self-referential entry that makes this page findable at all.
        image.put64(PML4, 0x1ED, PML4 | 1);
        // Kernel image: 0xFFFFF80000020000 -> PML4[0x1F0], PDPT[0], PD[0], PT[0x20].
        image.put64(PML4, 0x1F0, PDPT | 1);
        image.put64(PDPT, 0, PD | 1);
        image.put64(PD, 0, PT | 1);
        for page in 0..32u64 {
            image.put64(PT, 0x20 + page, (KERNEL_PHYS + page * 0x1000) | 1);
        }
        // Kernel-side _KUSER_SHARED_DATA: 0xFFFFF78000000000 ->
        // PML4[0x1EF], PDPT[0], PD[0], PT[0].
        image.put64(PML4, 0x1EF, PDPT_KUSER | 1);
        image.put64(PDPT_KUSER, 0, PD_KUSER | 1);
        image.put64(PD_KUSER, 0, PT_KUSER | 1);
        image.put64(PT_KUSER, 0, KUSER_PHYS | 1);
        // User-side _KUSER_SHARED_DATA: 0x7FFE0000 ->
        // PML4[0], PDPT[1], PD[0x1FF], PT[0x1E0]. The same physical page, which
        // is the Windows invariant the DTB check looks for.
        image.put64(PML4, 0, PDPT_USER | 1);
        image.put64(PDPT_USER, 1, PD_USER | 1);
        image.put64(PD_USER, 0x1FF, PT_USER | 1);
        image.put64(PT_USER, 0x1E0, KUSER_PHYS | 1);

        image.write(KERNEL_PHYS, &PeBuilder::default().build());
        // Just past the PE image, and the rest of the page is already zero, so
        // the string is NUL-terminated by the fixture itself.
        image.write(KERNEL_PHYS + NT_BUILD_LAB_RVA, BUILD_LAB);
        image.write(KUSER_PHYS + NT_MAJOR_OFFSET, &10u32.to_le_bytes());
        image.write(KUSER_PHYS + NT_MINOR_OFFSET, &0u32.to_le_bytes());
        image.write(KUSER_PHYS + NT_BUILD_NUMBER_OFFSET, &22000u32.to_le_bytes());

        if with_decoy {
            // A page that passes the self-reference test and maps nothing. It
            // sits below the real one, so it is tried first: the point of the
            // test is that a candidate is only accepted when a kernel proves out
            // through it.
            image.put64(DECOY_PML4, 0x1EE, DECOY_PML4 | 1);
        }
        image
    }

    /// Physical frame of the PML5 in the LA57 fixture.
    const PML5: u64 = 0x1B_0000;

    /// The four-level fixture, lifted to five levels (LA57).
    ///
    /// A PML5 is placed above the PML4 and made the top-level table: it
    /// self-references (so the sweep finds it) and points at the PML4 for both
    /// the kernel half (PML5 index `0x1FF`, where every `0xFFFFF8…` address
    /// lands) and the user half (index `0`, where `0x7FFE0000` lands). The
    /// PML4's own self-reference is removed, because on LA57 the top-level table
    /// is the PML5 — so a four-level walk of this image finds no directory table
    /// base, and only the five-level walk reaches the kernel.
    fn windows_image_la57() -> Image {
        let mut image = windows_image(false);
        image.put64(PML4, 0x1ED, 0); // the PML4 no longer self-references
        image.put64(PML5, 0x1FF, PML4 | 1); // kernel half -> PML4
        image.put64(PML5, 0, PML4 | 1); // user half -> PML4
        image.put64(PML5, 0x1EC, PML5 | 1); // the PML5's own self-reference
        image
    }

    fn options() -> DiscoveryOptions {
        DiscoveryOptions {
            // The whole fixture is four megabytes; sweeping the default regions
            // would spend the test's time reading past the end of it.
            dtb_scan_regions: vec![0x2_0000..IMAGE_SIZE as u64],
            scan: ScanConfig {
                chunk_size: 0x1_0000,
                ..ScanConfig::default()
            },
            ..DiscoveryOptions::default()
        }
    }

    fn symbol_store(label: &str) -> TempDir {
        let dir = TempDir::new(label);
        let guid = guid();
        dir.write(
            &format!("ntkrnlmp.pdb/{guid}-1.json"),
            &windows_isf("ntkrnlmp.pdb", &guid, 1),
        );
        dir
    }

    /// A store whose ISF has been altered before it is written out.
    ///
    /// The alteration is textual and deliberate: these tests need symbol tables
    /// that are structurally valid and *wrong about this image* in one specific
    /// way, which is exactly the shape of a corrupt or hand-edited symbol pack
    /// and exactly what the gates exist to catch.
    fn altered_store(label: &str, alter: impl Fn(String) -> String) -> TempDir {
        let dir = TempDir::new(label);
        let guid = guid();
        dir.write(
            &format!("ntkrnlmp.pdb/{guid}-1.json"),
            &alter(windows_isf("ntkrnlmp.pdb", &guid, 1)),
        );
        dir
    }

    /// A store whose ISF declares one extra kernel global at `rva`.
    fn store_with_symbol(label: &str, symbol: &'static str, rva: u64) -> TempDir {
        altered_store(label, move |isf| {
            let ty = r#"{"kind": "base", "name": "unsigned char"}"#;
            let declaration =
                format!(r#""{symbol}": {{"address": {rva}, "type": {ty}}}, "NtBuildLab""#);
            isf.replace(r#""NtBuildLab""#, &declaration)
        })
    }

    /// `ROADMAP` §3.8a: an image whose header states ARM64 fails as
    /// *unsupported*, before any sweep, rather than as "no directory table
    /// base found" after one -- the second reads as an image with no kernel in
    /// it, and the first names the limit of this tool.
    #[test]
    fn an_arm64_image_is_refused_as_unsupported_before_any_sweep() {
        use seance_core::data_source::{ByteSliceDataSource, DataSource};
        use seance_memory::meta::LayerMeta;
        use seance_memory::{MemoryImageFormat, PhysicalLayer};

        let dir = symbol_store("arm64-gate");
        // The same bytes a discoverable x64 image has: only the header's
        // architecture differs, so a refusal here is the gate and not the bytes.
        let bytes = windows_image(false).bytes;
        let stated = |architecture: LayerArch| -> Arc<dyn MemoryLayer> {
            let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.clone()));
            let meta = LayerMeta::new(MemoryImageFormat::WindowsCrashDump64)
                .with_architecture(architecture);
            Arc::new(PhysicalLayer::new(source, meta).expect("a non-empty image"))
        };
        discover_reported(
            stated(LayerArch::X64),
            std::slice::from_ref(&dir.path),
            &options(),
        )
        .expect("the same bytes discover when the header states x64");

        let err = discover_reported(
            stated(LayerArch::Arm64),
            std::slice::from_ref(&dir.path),
            &options(),
        )
        .expect_err("an ARM64 image is refused");
        match &err {
            DiscoveryError::UnsupportedArchitecture {
                architecture,
                detail,
            } => {
                assert_eq!(architecture, "arm64");
                assert!(detail.contains("header"), "{detail}");
            }
            other => panic!("expected UnsupportedArchitecture, got {other}"),
        }
        let text = err.to_string();
        assert!(text.contains("ARM64") || text.contains("arm64"), "{text}");
        assert!(text.contains("unsupported"), "{text}");
        assert!(
            !text.contains("no usable directory table base was found")
                && !text.contains("no Windows kernel was found"),
            "the refusal must not read as a sweep that found nothing: {text}"
        );
        assert!(text.contains("limit of this tool"), "{text}");
    }

    #[test]
    fn a_whole_windows_image_is_discovered_from_its_bytes_alone() {
        let dir = symbol_store("end-to-end");
        let layer = windows_image(false).layer();
        let (profile, report) =
            discover_reported(layer, std::slice::from_ref(&dir.path), &options())
                .expect("a Windows image");

        assert_eq!(profile.dtb.value, PML4);
        assert_eq!(profile.kernel_base.value, KERNEL_VA);
        assert_eq!(profile.architecture, LayerArch::X64);
        assert!(profile.is_64bit());
        assert_eq!(profile.pointer_size(), 8);
        assert_eq!(profile.build.pdb, "ntkrnlmp.pdb");
        assert_eq!(profile.build.guid, guid());
        assert_eq!(profile.build.age, 1);
        assert_eq!(profile.build.major, 10);
        assert_eq!(profile.build.minor, 0);
        assert_eq!(profile.build.build, Some(22000));
        assert_eq!(profile.build.is_win8_or_later(), Some(true));
        assert_eq!(
            profile.build.build_lab.as_deref(),
            Some("22000.1.amd64fre.co_release.210604-1628")
        );
        assert_eq!(report.version_source, Some("kuser_shared_data"));

        // The double mapping of _KUSER_SHARED_DATA is the offset-free Windows
        // invariant, and it is the strongest thing available before symbols.
        let accepted = report
            .attempts
            .last()
            .expect("at least one candidate was tried");
        assert_eq!(accepted.kuser, Some(KuserCheck::Shared));
        assert!(accepted.refused.is_none());
    }

    #[test]
    fn a_five_level_la57_windows_image_is_discovered_from_its_bytes_alone() {
        // VOL-MEM-001: a Windows image running LA57 (five-level paging) is
        // discovered. The DTB recovered is the PML5, not the PML4 — proof the
        // five-level walk was used, since the PML4 does not self-reference here
        // and a four-level walk of the PML5 reaches no kernel.
        let dir = symbol_store("la57");
        let layer = windows_image_la57().layer();
        let (profile, report) =
            discover_reported(layer, std::slice::from_ref(&dir.path), &options())
                .expect("a five-level Windows image is discovered");

        assert_eq!(profile.dtb.value, PML5, "the DTB is the PML5, not the PML4");
        assert_eq!(profile.kernel_base.value, KERNEL_VA);
        assert_eq!(profile.build.build, Some(22000));
        assert_eq!(profile.architecture, LayerArch::X64);
        // The accepted candidate was walked in the five-level mode.
        let accepted = report.attempts.last().expect("a candidate was tried");
        assert_eq!(accepted.mode, PagingMode::Intel32eLa57);
        assert_eq!(accepted.kuser, Some(KuserCheck::Shared));
    }

    #[test]
    fn a_scanned_directory_table_base_is_validated_rather_than_merely_scanned() {
        // The grade matters: "we found one page that referred to itself" and "we
        // found the kernel through it" support very different confidence in
        // everything downstream.
        let dir = symbol_store("evidence");
        let layer = windows_image(false).layer();
        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &options()).expect("a Windows image");
        assert_eq!(profile.dtb.evidence, Evidence::Validated);
        // The kernel was found by the boot-mapping method, which is a search,
        // so it is validated rather than confirmed.
        assert_eq!(profile.kernel_base.evidence, Evidence::Validated);
        assert_eq!(profile.weakest_evidence(), Evidence::Validated);
    }

    #[test]
    fn a_decoy_page_that_refers_to_itself_is_not_reported_as_the_directory_table_base() {
        // The failure this whole module is built to avoid. The decoy is tried
        // first and translates nothing, so no kernel proves out through it and
        // discovery moves on rather than reporting an address space assembled
        // out of unrelated bytes.
        let dir = symbol_store("decoy");
        let layer = windows_image(true).layer();
        let (profile, report) =
            discover_reported(layer, std::slice::from_ref(&dir.path), &options())
                .expect("a Windows image");
        assert_eq!(profile.dtb.value, PML4);
        assert!(
            report.attempts.iter().any(|a| a.dtb == DECOY_PML4),
            "the decoy must have been tried and refused: {:?}",
            report.attempts
        );
        let decoy = report
            .attempts
            .iter()
            .find(|a| a.dtb == DECOY_PML4)
            .expect("the decoy attempt");
        assert!(decoy.refused.is_some(), "{decoy:?}");
    }

    #[test]
    fn a_supplied_directory_table_base_is_recorded_as_supplied_however_well_it_works() {
        // An examiner reading a report is entitled to know that the tool was
        // told the answer rather than having found it.
        let dir = symbol_store("supplied");
        let layer = windows_image(false).layer();
        let mut options = DiscoveryOptions::with_supplied_dtb(PML4, PagingMode::Intel32e);
        options.scan = ScanConfig {
            chunk_size: 0x1_0000,
            ..ScanConfig::default()
        };
        options.dtb_scan_regions = vec![0x2_0000..IMAGE_SIZE as u64];
        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &options).expect("a Windows image");
        assert_eq!(profile.dtb.value, PML4);
        assert_eq!(profile.dtb.evidence, Evidence::Supplied);
        assert_eq!(profile.weakest_evidence(), Evidence::Supplied);
    }

    #[test]
    fn a_supplied_directory_table_base_that_is_wrong_fails_rather_than_producing_an_answer() {
        let dir = symbol_store("supplied-wrong");
        let layer = windows_image(false).layer();
        let mut options = DiscoveryOptions::with_supplied_dtb(PT_USER, PagingMode::Intel32e);
        options.scan = ScanConfig {
            chunk_size: 0x1_0000,
            ..ScanConfig::default()
        };
        // No scanning, so the supplied value is the only candidate.
        options.dtb_scan_regions = Vec::new();
        match discover(layer, std::slice::from_ref(&dir.path), &options) {
            Err(DiscoveryError::NoKernel { attempts, .. }) => assert_eq!(attempts, 1),
            other => panic!("expected NoKernel, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_symbol_file_is_an_error_that_names_the_guid_rather_than_a_fallback() {
        // The actionable failure. An examiner cannot do anything with "symbols
        // not found"; a GUID and an age can be taken to a symbol store and
        // turned into a working case. Nothing here offers a nearest match.
        let empty = TempDir::new("no-symbols");
        let layer = windows_image(false).layer();
        match discover(layer, std::slice::from_ref(&empty.path), &options()) {
            Err(DiscoveryError::SymbolsNotFound {
                pdb,
                guid: wanted,
                age,
                directories,
                ..
            }) => {
                assert_eq!(pdb, "ntkrnlmp.pdb");
                assert_eq!(wanted, guid());
                assert_eq!(age, 1);
                assert_eq!(directories, 1);
                assert_eq!(wanted.len(), 32);
            }
            other => panic!("expected SymbolsNotFound, got {other:?}"),
        }
    }

    #[test]
    fn a_symbol_file_for_a_different_build_is_never_substituted_for_the_missing_one() {
        // A store holding the neighbouring build's symbols must produce exactly
        // the same refusal as an empty one. A near-match table reads
        // _EPROCESS.UniqueProcessId at the wrong offset and returns a full,
        // confident, wrong process list.
        let dir = TempDir::new("wrong-build");
        let other = "0000000000000000000000000000FFFF";
        dir.write(
            &format!("ntkrnlmp.pdb/{other}-1.json"),
            &windows_isf("ntkrnlmp.pdb", other, 1),
        );
        // Right GUID, wrong age: two ages of one GUID are different files.
        let right = guid();
        dir.write(
            &format!("ntkrnlmp.pdb/{right}-2.json"),
            &windows_isf("ntkrnlmp.pdb", &right, 2),
        );
        let layer = windows_image(false).layer();
        match discover(layer, std::slice::from_ref(&dir.path), &options()) {
            Err(DiscoveryError::SymbolsNotFound { guid: wanted, .. }) => {
                assert_eq!(wanted, guid())
            }
            other => panic!("expected SymbolsNotFound, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_table_base_outside_the_configured_sweep_window_is_still_found() {
        // The shipped window is the low tens of megabytes, where every Windows
        // from XP to 11 has put its top-level page table — until a large-memory
        // Windows 11 puts it higher. A window that finds nothing has not shown
        // that the image holds no kernel, so the whole acquisition is swept
        // before discovery refuses.
        let dir = symbol_store("outside-the-window");
        let layer = windows_image(false).layer();
        let mut narrow = options();
        // Stops short of the fixture's PML4 at 0x1AE000, exactly as the shipped
        // window stops short of a table above 90 MiB.
        narrow.dtb_scan_regions = vec![0x2_0000..0x10_0000];
        let (profile, report) = discover_reported(layer, std::slice::from_ref(&dir.path), &narrow)
            .expect("the image is a Windows image whichever window was configured");
        assert_eq!(profile.dtb.value, PML4);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("whole acquisition")),
            "the report must say the answer came from the wider sweep: {:?}",
            report.notes
        );
    }

    #[test]
    fn the_whole_image_is_not_reswept_when_the_configured_window_already_answered() {
        // The second sweep costs a full read of the acquisition. It must stay
        // on the failure path: paying it on every image would turn a seconds-
        // long discovery into a minutes-long one for nothing.
        let dir = symbol_store("no-resweep");
        let layer = windows_image(false).layer();
        let (_, report) = discover_reported(layer, std::slice::from_ref(&dir.path), &options())
            .expect("a Windows image");
        assert!(
            !report
                .notes
                .iter()
                .any(|note| note.contains("whole acquisition")),
            "nothing should have been reswept: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_supplied_directory_table_base_that_is_wrong_is_never_answered_by_sweeping_elsewhere() {
        // An examiner who names a base is entitled to a failure naming their
        // value. Quietly finding a different one and reporting a profile built
        // on it answers a question nobody asked, and the report would carry
        // Evidence::Supplied for a base the examiner never supplied.
        let dir = symbol_store("supplied-not-reswept");
        let layer = windows_image(false).layer();
        let mut options = DiscoveryOptions::with_supplied_dtb(PT_USER, PagingMode::Intel32e);
        options.scan = ScanConfig {
            chunk_size: 0x1_0000,
            ..ScanConfig::default()
        };
        // A window that cannot see the real PML4 at 0x1AE000, so the wider
        // sweep would find it — and must not, because the examiner named a
        // different base.
        options.dtb_scan_regions = vec![0x2_0000..0x10_0000];
        match discover(layer, std::slice::from_ref(&dir.path), &options) {
            Err(DiscoveryError::NoKernel { .. }) => {}
            other => panic!("expected NoKernel, got {other:?}"),
        }
    }

    #[test]
    fn a_pagefile_attached_to_the_kernel_space_resolves_a_swapped_kernel_page() {
        // Kernel space has to be built before the build number is known,
        // because the build number is read through it — so its paging spec
        // cannot say where `MMPTE_SOFTWARE.PageFileLow` sits, a software PTE is
        // classified with no pagefile index, and the page stays a hole however
        // many pagefiles were attached. Until the layout was re-stated once the
        // build was established, every pagefile attached to the kernel space
        // was dead for the whole analysis while the record said it was
        // attached.
        //
        use seance_core::data_source::ByteSliceDataSource;

        // The fixture's PT maps VAs at 0xFFFFF80000000000 + index * 0x1000.
        const SWAPPED_VA: u64 = 0xFFFF_F800_0010_0000;
        const SWAPPED_PT_INDEX: u64 = 0x100;
        // PageFileHigh = 1 at bit 32 (x64), PageFileLow = 0 at bits 15:12 on
        // Windows 8 and later, and the valid, prototype and transition bits all
        // clear: this page is on disk, not gone.
        const SOFTWARE_PTE: u64 = 1 << 32;
        const IN_PAGEFILE_AT: usize = 0x1000;
        const RECOVERED: &[u8] = b"swapped-out kernel bytes";

        let dir = symbol_store("kernel-pagefile");
        let mut image = windows_image(false);
        image.put64(PT, SWAPPED_PT_INDEX, SOFTWARE_PTE);
        let layer = image.layer();

        let mut pagefile = vec![0u8; 0x2000];
        pagefile[IN_PAGEFILE_AT..IN_PAGEFILE_AT + RECOVERED.len()].copy_from_slice(RECOVERED);
        let mut with_swap = options();
        with_swap.pagefiles = vec![SwapFile {
            index: 0,
            label: "pagefile.sys".to_string(),
            source: Arc::new(ByteSliceDataSource::new(pagefile)),
        }];

        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &with_swap).expect("a Windows image");
        let mut buf = vec![0u8; RECOVERED.len()];
        let read = profile
            .kernel_space
            .read_at(SWAPPED_VA, &mut buf)
            .expect("the swapped page resolves from the attached pagefile");
        assert_eq!(read, RECOVERED.len());
        assert_eq!(&buf[..], RECOVERED);
    }

    #[test]
    fn an_image_with_no_page_tables_at_all_reports_what_the_sweep_did() {
        // "No DTB found" from a sweep that examined nothing is a different
        // statement from one that examined four thousand pages, and the error
        // has to carry the difference.
        let dir = symbol_store("no-tables");
        let layer = Image::new(IMAGE_SIZE).layer();
        match discover(layer, std::slice::from_ref(&dir.path), &options()) {
            Err(DiscoveryError::NoDirectoryTableBase {
                candidates,
                pages_examined,
                ..
            }) => {
                assert_eq!(candidates, 0);
                assert!(pages_examined > 0, "the sweep must say it looked");
            }
            other => panic!("expected NoDirectoryTableBase, got {other:?}"),
        }
    }

    #[test]
    fn the_symbol_table_is_proved_against_the_image_rather_than_merely_loaded() {
        // Gate 4 is the only check that can falsify a table which has already
        // matched on GUID and age. A table that never ran it stays Unverified,
        // and a profile must be able to say which it is.
        let dir = symbol_store("gate-four");
        let layer = windows_image(false).layer();
        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &options()).expect("a Windows image");
        let gates = &profile.symbols.admission().gates;
        let sanity: Vec<_> = gates
            .iter()
            .filter(|g| g.gate == Gate::ImageSanity)
            .collect();
        assert!(
            sanity.iter().any(|g| g.check == "windows_nt_version"),
            "the NT version check must have run: {sanity:?}"
        );
        assert!(
            !sanity.is_empty(),
            "gate 4 must leave a record either way: {gates:?}"
        );
        assert_ne!(profile.symbols.state(), AdmissionState::Rejected);
    }

    #[test]
    fn a_symbol_table_the_image_falsifies_is_refused_rather_than_handed_to_every_stage() {
        // The failure gate 4 exists for, and the one no later stage could
        // catch. GUID and age match exactly, so selection is correct; the
        // table's _KUSER_SHARED_DATA layout is not this image's, and reading
        // NtMajorVersion through it yields a version no Windows ever shipped.
        // A profile carrying this table would produce a full process list at
        // offsets belonging to another build, every field of it parsing.
        let dir = symbol_store("falsified");
        let mut image = windows_image(false);
        image.write(KUSER_PHYS + NT_MAJOR_OFFSET, &7u32.to_le_bytes());
        match discover(image.layer(), std::slice::from_ref(&dir.path), &options()) {
            Err(DiscoveryError::SymbolsRejected {
                guid: refused,
                source,
                ..
            }) => {
                assert_eq!(refused, guid());
                // The refusal has to name the failing check, because that is
                // what the finding written into the case record quotes.
                assert!(source.to_string().contains("NtMajorVersion"), "{source}");
            }
            other => panic!("expected SymbolsRejected, got {other:?}"),
        }
    }

    #[test]
    fn a_build_number_the_table_cannot_describe_is_recorded_as_inapplicable_not_as_a_pass() {
        // "This build never had that member" and "we checked and it was fine"
        // must not render the same, or a check that could not run reads in a
        // report exactly like one that ran and held.
        //
        // The absence is recorded as INAPPLICABLE rather than unproved. Windows
        // XP genuinely has no `_KUSER_SHARED_DATA.NtBuildNumber` — the build
        // comes from `NtBuildLab`, which is why `build_from_lab` exists — and
        // calling that a gap held every XP capture at `Unverified`, which then
        // stamped its analysis stages as short of evidence they had read in
        // full. What must survive that change is everything below: the check is
        // still recorded, still named, and is never a pass.
        let dir = altered_store("no-build-member", |isf| {
            isf.replace("NtBuildNumber", "NtBuildNumberAbsent")
        });
        let layer = windows_image(false).layer();
        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &options()).expect("a Windows image");
        let admission = profile.symbols.admission();

        let recorded = admission
            .gates
            .iter()
            .find(|gate| gate.check == "windows_build_number")
            .expect("the check is recorded rather than skipped");
        assert_ne!(
            recorded.outcome,
            GateOutcome::Pass,
            "a member this table does not declare was never read, so it cannot have passed: {}",
            recorded.detail
        );
        assert_eq!(recorded.outcome, GateOutcome::NotApplicable);
        assert!(
            recorded.detail.contains("NtBuildLab"),
            "the record says where the build number comes from instead: {}",
            recorded.detail
        );

        // Named in its own list, so a report can show which checks this build
        // supported without calling any of them outstanding.
        let inapplicable = admission.inapplicable_checks();
        assert!(
            inapplicable.contains(&"windows_build_number"),
            "{inapplicable:?}"
        );
        let unproved = admission.unproved_checks();
        assert!(
            !unproved.contains(&"windows_build_number"),
            "a check with nothing left to prove is not an outstanding one: {unproved:?}"
        );

        // The gate itself still ran: the member this table does declare was
        // read and passed. Without this the whole of gate 4 could collapse into
        // "nothing here applies" and the assertions above would still hold.
        let version = admission
            .gates
            .iter()
            .find(|gate| gate.check == "windows_nt_version")
            .expect("the version check is recorded");
        assert_eq!(
            version.outcome,
            GateOutcome::Pass,
            "the declared member was read through the table: {}",
            version.detail
        );
    }

    #[test]
    fn a_table_declaring_nothing_gate_four_reads_is_not_graded_verified_on_no_checks_at_all() {
        // The hole the `NotApplicable` outcome opens if nothing closes it. One
        // inapplicable check is an honest fact about a build; every check in
        // the gate inapplicable at once means gate 4 established nothing, and
        // `NotApplicable` does not block admission. Gates 1-3 match identity,
        // architecture and layout coherence — all of which a hand-edited symbol
        // pack still satisfies, which is why gate 4 exists — so without this
        // the table this fixture builds reads as `Verified` having never been
        // checked against the image at all.
        //
        // The fixture ISF declares no `PsActiveProcessHead`, so removing the
        // two `_KUSER_SHARED_DATA` members leaves gate 4 with nothing to read.
        let dir = altered_store("nothing-to-read", |isf| {
            isf.replace("NtMajorVersion", "NtMajorVersionAbsent")
                .replace("NtBuildNumber", "NtBuildNumberAbsent")
        });
        let layer = windows_image(false).layer();
        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &options()).expect("a Windows image");
        let admission = profile.symbols.admission();

        assert!(
            admission
                .gates
                .iter()
                .filter(|gate| gate.gate == Gate::ImageSanity)
                .all(|gate| gate.outcome != GateOutcome::Pass),
            "the fixture must leave gate 4 with nothing it could read: {:?}",
            admission.gates
        );
        let unproved = admission.unproved_checks();
        assert!(
            unproved.contains(&"windows_image_sanity"),
            "a gate that read nothing is outstanding, not inapplicable: {unproved:?}"
        );
        assert_eq!(profile.symbols.state(), AdmissionState::Unverified);
        assert!(!profile.symbols_verified());
    }

    #[test]
    fn half_a_version_from_kuser_shared_data_is_discarded_rather_than_completed_from_elsewhere() {
        // A major version from one structure and a minor version from another
        // is a version neither structure states. The whole reading is dropped
        // and the PE header answers for both, which also drops the build
        // number, so every stage that needs a build fails closed instead of
        // branching on a layout chosen from a spliced version.
        let dir = altered_store("half-version", |isf| {
            isf.replace("NtMinorVersion", "NtMinorVersionAbsent")
        });
        let layer = windows_image(false).layer();
        let (profile, report) =
            discover_reported(layer, std::slice::from_ref(&dir.path), &options())
                .expect("a Windows image");
        assert_eq!(report.version_source, Some("pe_optional_header"));
        assert_eq!(profile.build.major, 10);
        assert_eq!(profile.build.minor, 0);
        assert_eq!(
            profile.build.build, None,
            "the build number must not survive a fallback to a header that has none"
        );
        assert_eq!(profile.build.is_win8_or_later(), None);
    }

    #[test]
    fn a_debugger_data_block_is_confirmed_only_when_its_owner_tag_reads_kdbg() {
        // The symbol table gives the address; the tag says whether the block is
        // really there. An examiner following a wrong KdDebuggerDataBlock into
        // a report has been given a fact that is not one.
        const RVA: u64 = 0x2000;
        let dir = store_with_symbol("kdbg-confirmed", "KdDebuggerDataBlock", RVA);
        let mut image = windows_image(false);
        image.write(
            KERNEL_PHYS + RVA + kernel::KDBG_TAG_TO_BLOCK_X64,
            kernel::KDBG_TAG,
        );
        let profile = discover(image.layer(), std::slice::from_ref(&dir.path), &options())
            .expect("a Windows image");
        let kdbg = profile.kdbg.expect("the tag corroborates the address");
        assert_eq!(kdbg.value, KERNEL_VA + RVA);
        assert_eq!(kdbg.evidence, Evidence::Confirmed);
    }

    #[test]
    fn a_debugger_data_block_whose_owner_tag_says_something_else_is_reported_as_nothing() {
        const RVA: u64 = 0x2000;
        let dir = store_with_symbol("kdbg-wrong-tag", "KdDebuggerDataBlock", RVA);
        // Nothing is written at the tag, so it reads as four zero bytes: the
        // address resolves and the block is not there.
        let layer = windows_image(false).layer();
        let (profile, report) =
            discover_reported(layer, std::slice::from_ref(&dir.path), &options())
                .expect("a Windows image");
        assert!(profile.kdbg.is_none());
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("KdDebuggerDataBlock")),
            "the refusal must be visible to an examiner: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_debugger_data_block_whose_tag_is_not_in_the_evidence_is_not_graded_as_validated() {
        // "We checked and it passed" and "we could not check" are different
        // facts. Grading an unchecked address `Validated` would let a profile
        // whose weakest fact was never tested describe itself as validated
        // throughout, and `weakest_evidence` is what a finding carries.
        const RVA: u64 = 0x10_0000; // Far above the 32 pages the fixture maps.
        let dir = store_with_symbol("kdbg-unreadable", "KdDebuggerDataBlock", RVA);
        let layer = windows_image(false).layer();
        let profile =
            discover(layer, std::slice::from_ref(&dir.path), &options()).expect("a Windows image");
        let kdbg = profile.kdbg.expect("the address still resolved");
        assert_eq!(kdbg.value, KERNEL_VA + RVA);
        assert_eq!(kdbg.evidence, Evidence::Scanned);
        assert_eq!(profile.weakest_evidence(), Evidence::Scanned);
    }

    #[test]
    fn one_directory_table_base_named_by_two_sources_is_only_a_candidate_once() {
        // The attempt budget bounds the work, and each attempt costs a full
        // kernel search. An image where the examiner, the acquisition header
        // and the sweep all name the same page must not spend that budget
        // proving one address space over and over while a real candidate
        // further down the list is never reached.
        let layer = windows_image(false).layer();
        let mut report = DiscoveryReport::default();
        let options = DiscoveryOptions {
            dtb: Some(PML4),
            paging_mode: Some(PagingMode::Intel32e),
            ..options()
        };
        let candidates = gather_dtb_candidates(&layer, &options, &mut report);
        assert_eq!(
            candidates.iter().filter(|c| c.dtb == PML4).count(),
            1,
            "{candidates:?}"
        );
        // The first source to name it wins, so the answer carries the grade of
        // the strongest source rather than of the last one to agree.
        assert_eq!(candidates[0].source, DtbSource::Supplied);
        // The sweep still ran, and its account of itself is still reported.
        assert!(!report.dtb_scans.is_empty());
    }

    #[test]
    fn a_search_stopped_by_the_attempt_cap_says_so_rather_than_reading_as_exhaustive() {
        // A cap that fired and a search that finished must not produce the same
        // sentence: "no kernel was found through any of 1 directory table
        // base(s)" is a conclusion the first has not earned.
        let dir = symbol_store("attempt-cap");
        let layer = windows_image(true).layer();
        let options = DiscoveryOptions {
            max_dtb_attempts: 1,
            ..options()
        };
        match discover(layer, std::slice::from_ref(&dir.path), &options) {
            Err(DiscoveryError::NoKernel { attempts, detail }) => {
                assert_eq!(attempts, 1);
                assert!(detail.contains("max_dtb_attempts"), "{detail}");
            }
            other => panic!("expected NoKernel, got {other:?}"),
        }
    }

    #[test]
    fn the_profile_serialises_every_fact_and_the_evidence_behind_it() {
        let dir = symbol_store("json");
        let layer = windows_image(false).layer();
        let (profile, report) =
            discover_reported(layer, std::slice::from_ref(&dir.path), &options())
                .expect("a Windows image");
        let json = profile.to_json();
        assert_eq!(json["dtb"], PML4);
        assert_eq!(json["kernel_base"], KERNEL_VA);
        assert_eq!(json["dtb_evidence"], "validated");
        assert_eq!(json["pdb_guid"], guid());
        assert_eq!(json["nt_build"], 22000);
        assert_eq!(json["pointer_size"], 8);

        let json = report.to_json();
        assert_eq!(json["version_source"], "kuser_shared_data");
        assert!(json["attempts"].as_array().is_some());
        assert!(!json["dtb_scans"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_zero_attempt_budget_is_a_configuration_error_rather_than_an_empty_answer() {
        let dir = symbol_store("budget");
        let layer = windows_image(false).layer();
        let options = DiscoveryOptions {
            max_dtb_attempts: 0,
            ..options()
        };
        assert!(matches!(
            discover(layer, std::slice::from_ref(&dir.path), &options),
            Err(DiscoveryError::Configuration { .. })
        ));
    }

    #[test]
    fn the_mode_order_puts_pae_ahead_of_plain_thirty_two_bit_paging() {
        // A PAE image's fourth page directory also satisfies the plain 32-bit
        // self-reference test, and reading a PAE image as plain 32-bit starts
        // every translation one level too low — which does not fail, it
        // resolves the wrong table.
        let pae = MODE_ORDER
            .iter()
            .position(|m| *m == PagingMode::IntelPae)
            .unwrap();
        let flat = MODE_ORDER
            .iter()
            .position(|m| *m == PagingMode::Intel32)
            .unwrap();
        assert!(pae < flat);
        assert_eq!(MODE_ORDER[0], PagingMode::Intel32e);
    }

    #[test]
    fn every_directory_table_base_source_carries_its_own_evidence_grade() {
        assert_eq!(DtbSource::Supplied.evidence(), Evidence::Supplied);
        assert_eq!(DtbSource::AcquisitionHeader.evidence(), Evidence::Confirmed);
        assert_eq!(DtbSource::LowStubCr3.evidence(), Evidence::Confirmed);
        assert_eq!(DtbSource::SelfReference.evidence(), Evidence::Validated);
        assert_eq!(DtbSource::SelfReference.as_str(), "self_reference");
    }
}
