//! What every Linux analysis stage needs before it can read anything.
//!
//! A Linux memory image has no header and no `KdDebuggerDataBlock`. There is no
//! structure the machine wrote down saying "the page tables start here". What
//! there *is* is the kernel banner — the `Linux version …` string the kernel
//! keeps in its own `.rodata` — and that single string is enough to reach
//! everything else:
//!
//! 1. the banner's **physical** address comes from sweeping the image for it;
//! 2. the banner's **virtual** address comes from the matching ISF's
//!    `linux_banner` symbol;
//! 3. the difference between them is the kernel text mapping's virtual-to-
//!    physical shift, which relocation and KASLR change from boot to boot;
//! 4. applying that shift to the top-level page table's symbol address gives
//!    the directory table base.
//!
//! Every one of those four steps is recorded on the profile, because "the DTB
//! was derived from `init_level4_pgt` and then confirmed by translating the
//! banner back to the address it was found at" and "the DTB was a guess" support
//! very different confidence in everything downstream.
//!
//! The type is deliberately not constructible from parts a caller guessed at:
//! [`crate::discovery`] builds it, and nothing else does.

use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::formats::linux_swap::{
    LinuxSwapHeader, SwapBodySurvey, BODY_NOT_ACQUIRED, BODY_READS_AS_ZEROS,
};
use seance_memory::layer::{MemoryHole, MemoryLayer};
use seance_memory::translate::{PagingMode, PagingSpec, PteSemantics, TableCache};
use seance_symbols::probe::{ProbeError, ProbeResult};
use seance_symbols::{AdmissionState, ImageProbe, SymbolTable};

/// How a fact about the image was established, and that fact paired with it.
///
/// Not a Linux idea, so it lives in [`seance_memory::binding`] and is
/// re-exported here for the same reason the Windows tier re-exports it: a stage
/// should be able to name the grade of what it rests on without importing the
/// binding directly.
pub use seance_memory::binding::{Evidence, Found};

/// The virtual-to-physical shift of the kernel's own text mapping, and how it
/// was established.
///
/// On x86-64 Linux the kernel image is mapped at `__START_KERNEL_map` plus its
/// physical load address, so every kernel *symbol* address minus this shift is
/// a physical address — until the page tables are up, at which point ordinary
/// translation takes over. Discovery needs it for exactly one thing: turning
/// the top-level page table's symbol address into the physical address the
/// hardware was actually using.
///
/// It is **not** a constant. Relocatable kernels and KASLR move the image, and
/// a hardcoded `0xFFFFFFFF80000000` produces a directory table base that is
/// wrong by however far the kernel was relocated — which does not fail, it
/// walks a page table that is not one and yields confident nonsense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelShift {
    /// `virtual - physical` for the kernel text mapping.
    pub shift: u64,
    /// Virtual address the banner was found at, per the symbol table.
    pub banner_virtual: u64,
    /// Physical address the banner was found at, by sweeping the image.
    pub banner_physical: u64,
}

/// Where a profile's struct layouts and symbol addresses came from.
///
/// A report has to be able to state this, and the two cases are not equivalent
/// evidence. A symbol file is an artefact outside the evidence, matched to it by
/// banner and then checked against the kernel's own type information — when that
/// check passes, two independently produced descriptions agree. Symbols read out
/// of the image cannot describe a different build than the one captured, which
/// is better provenance, but nothing independent corroborates them: the source
/// that would have disagreed is the one that produced the answer.
///
/// Neither is "the good one". They fail differently, and an examiner asked which
/// was used must be able to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolOrigin {
    /// An ISF file the lab holds, matched to this image by its banner.
    SymbolFile {
        /// Path it was read from, so the same analysis can be run again.
        path: String,
    },
    /// The kernel's own account of itself, read out of this image.
    ImageDerived {
        /// Physical offset the kernel's BTF was found at.
        btf_at: u64,
        /// Physical offset the kernel's symbol table was found at.
        kallsyms_at: u64,
        /// Types the BTF described.
        type_count: usize,
        /// Symbols the kernel's table held.
        symbol_count: usize,
        /// SHA-256 of the generated ISF document.
        ///
        /// This stands in for a file path. Generation is deterministic, so a
        /// defence expert who regenerates the symbols from the same image gets
        /// this hash, and a different hash means a different analysis.
        sha256: String,
    },
}

impl SymbolOrigin {
    /// A stable token for machine consumers and report templates.
    pub fn kind(&self) -> &'static str {
        match self {
            SymbolOrigin::SymbolFile { .. } => "symbol_file",
            SymbolOrigin::ImageDerived { .. } => "image_derived",
        }
    }

    /// Whether an independent source corroborated these layouts.
    ///
    /// False for image-derived symbols — not because they are suspect, but
    /// because the check that would corroborate them compares the table against
    /// the BTF it was built from, and a source cannot corroborate itself.
    pub fn is_corroborated_by_an_independent_source(&self) -> bool {
        matches!(self, SymbolOrigin::SymbolFile { .. })
    }

    /// Serializable form, for the profile artifact.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            SymbolOrigin::SymbolFile { path } => serde_json::json!({
                "kind": self.kind(),
                "path": path,
            }),
            SymbolOrigin::ImageDerived {
                btf_at,
                kallsyms_at,
                type_count,
                symbol_count,
                sha256,
            } => serde_json::json!({
                "kind": self.kind(),
                "btf_physical_offset": btf_at,
                "btf_physical_offset_hex": format!("{btf_at:#x}"),
                "kallsyms_physical_offset": kallsyms_at,
                "kallsyms_physical_offset_hex": format!("{kallsyms_at:#x}"),
                "type_count": type_count,
                "symbol_count": symbol_count,
                "generated_isf_sha256": sha256,
            }),
        }
    }

    /// What a report should say about where the layouts came from.
    pub fn statement(&self) -> String {
        match self {
            SymbolOrigin::SymbolFile { path } => format!(
                "Struct layouts and symbol addresses were taken from the symbol file {path}, \
                 matched to this image by the kernel banner and cross-checked against the type \
                 information the kernel carries about itself."
            ),
            SymbolOrigin::ImageDerived {
                btf_at,
                kallsyms_at,
                type_count,
                symbol_count,
                sha256,
            } => format!(
                "No symbol file in the locations searched described this kernel. Struct layouts \
                 were therefore taken from the type information the kernel carries about itself \
                 (BTF, at physical offset {btf_at:#x}, {type_count} types) and symbol addresses \
                 from the kernel's own symbol table (kallsyms, at physical offset \
                 {kallsyms_at:#x}, {symbol_count} symbols), both read out of this image. These \
                 cannot describe a kernel other than the one captured. They are, however, a \
                 single source: the cross-check that would otherwise test the layouts compares \
                 them against the same BTF they were built from, so it was not performed. The \
                 layouts were instead tested by reading known kernel structures through them. \
                 The generated symbol document has SHA-256 {sha256} and is reproducible from \
                 this image."
            ),
        }
    }
}

/// The Linux kernel build a symbol table was matched against.
///
/// There is no GUID and no build number: on Linux the banner *is* the identity,
/// and two kernels with the same version string but different compilers or
/// build timestamps are different kernels with different layouts. That is why
/// the whole banner is kept rather than a parsed version triple, and why
/// matching is byte-equality on the normalised banner and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBuild {
    /// The normalised banner, as recovered from the image and as the ISF
    /// declares it. Both sides went through
    /// [`seance_symbols::normalize_banner`], so this is one string, not two
    /// that happen to look alike.
    pub banner: String,
    /// The release fragment of the banner — `3.2.0-4-amd64` — when it could be
    /// taken from it. Presentational only: nothing branches on it, because a
    /// version string is not a layout.
    pub release: Option<String>,
    /// Where the layouts came from, so a defence expert can obtain the same
    /// ones and repeat the analysis.
    pub symbols_from: SymbolOrigin,
}

impl LinuxBuild {
    /// The release fragment of a banner: the word after `Linux version `.
    ///
    /// Returns `None` rather than a guess when the banner does not have that
    /// shape, because a wrong release string in a report is a claim about the
    /// machine that nothing in the evidence supports.
    pub fn release_from_banner(banner: &str) -> Option<String> {
        let rest = banner.strip_prefix("Linux version ")?;
        let release = rest.split_whitespace().next()?;
        if release.is_empty() {
            return None;
        }
        Some(release.to_string())
    }

    /// The kernel's `major.minor` version, when the release states one.
    ///
    /// # This is not enough to select a swap-entry layout, and nothing may use
    /// it that way
    ///
    /// Linux's swap PTE encoding has moved three times on x86-64 — type at bits
    /// 5:1 through 3.x, at 13:9 through 4.x, and at 63:59 with the offset
    /// stored inverted since the L1TF mitigation — so it is tempting to branch
    /// on "is this 4.19 or later". That branch is wrong. The L1TF change was
    /// backported into the 4.4, 4.9, 4.14 and 4.17 stable series and into
    /// distribution kernels below 4.19 (Ubuntu shipped it on 4.15), so a kernel
    /// that calls itself 4.15 may use either layout and its version cannot say
    /// which. A decode against the wrong one does not fail; it returns another
    /// page's contents.
    ///
    /// So this is published as a *fact about the build* an examiner can act on —
    /// context for the swap-entry layout, which the swap resolver selects by
    /// corroborating a decode against an attached area's bounds rather than by
    /// branching on this version — and not as a selector.
    ///
    /// `None` when the banner had no release, or when the release does not open
    /// with two decimal numbers. A version invented from a string that did not
    /// state one would be a claim about the machine with nothing behind it.
    pub fn version(&self) -> Option<(u32, u32)> {
        let release = self.release.as_deref()?;
        let mut parts = release.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        // `5.10.0-8-amd64`: the minor ends at the first character that is not a
        // digit, because everything after it is Debian's packaging suffix and
        // not part of the upstream version.
        let minor_field = parts.next()?;
        let digits: String = minor_field
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.is_empty() {
            return None;
        }
        let minor = digits.parse::<u32>().ok()?;
        Some((major, minor))
    }
}

/// Why a page this machine swapped out is identified but not read.
///
/// Stated on every Linux profile record, because the alternative is silence,
/// and silence about swap reads as "there was nothing swapped out". A Windows
/// capture can attach a pagefile and resolve those pages; a Linux capture
/// cannot, and an examiner comparing the two tiers has to be told which they
/// are looking at rather than inferring it from an absence.
///
/// Half of it is now answered. Under `PteSemantics::Linux` the address space
/// separates an entry the kernel used to record that a page's contents left
/// memory from an address that was never mapped, which is a distinction the
/// earlier `Bare` semantics could not make.
///
/// The other half is a refusal, and not a limitation to be worked around
/// locally. The bit positions holding the swap area and the page within it are
/// a property of the kernel **source**: they have moved three times on x86-64,
/// and the L1TF inversion was backported below 4.19, so the kernel's own
/// version string cannot select between the layouts and nothing else in a
/// memory image states it. A decode against the wrong layout does not fail — it
/// yields a plausible offset and returns some other page's contents. Naming no
/// location is the only answer that cannot be wrong.
pub const SWAP_NOT_RESOLVED: &str =
    "Pages this machine had swapped out are identified, and can be read once the swap area is \
     attached — but none is attached to this analysis, so their contents are not read. This \
     address space runs under Linux page-table-entry semantics, so a non-present entry that is \
     neither empty nor PROT_NONE is reported as an entry the kernel used to record that this \
     page's contents left memory — a different finding from an address that was never mapped. To \
     read them, acquire the swap area from its block device or partition (a swap file copied \
     through the filesystem reads back as zeros) and attach it with SEANCE_SWAPFILES as \
     index=path, where the index is the area's swp_type. The x86-64 swap-entry layout changed \
     once (the L1TF inversion, backported into stable and distribution kernels below 4.19) and a \
     single entry does not say which layout wrote it, so both are decoded and the page is read \
     only through the attached area whose bounds one layout's offset falls inside; an entry that \
     no attached area corroborates, or that two would, stays a hole rather than being guessed. \
     The same encoding also carries page-migration and hardware-poison entries, which name no \
     swap area at all and are left unresolved by the same rule.";

/// The swap statement when a swap area is attached and swapped pages resolve.
pub const SWAP_RESOLVED: &str =
    "Pages this machine had swapped out are read from the attached swap area(s). A swapped page's \
     entry is decoded and corroborated against an attached area's bounds before a byte is read: \
     the x86-64 layout changed once (the L1TF inversion) and a single entry does not say which \
     wrote it, so both are decoded and the page is read only through the area whose bounds one \
     layout's offset falls inside. An entry no attached area corroborates, or that two would \
     (page-migration and hardware-poison entries share the encoding), stays a hole rather than \
     being read from the wrong place. A page read from swap was written there at some earlier \
     point and may predate the capture.";

/// What to say about an attachment that does not parse as a Linux swap area.
///
/// Written once and read from both places that have to explain it — the
/// attach-time warning and the profile record's swap statement — for the reason
/// [`BODY_READS_AS_ZEROS`] gives: the same explanation written twice drifts into
/// two explanations.
///
/// It states the observation before the diagnosis, because the observation is
/// what the tool can stand behind. The observation is that the `SWAPSPACE2`
/// signature `mkswap` writes at the end of an area's first page is not there;
/// the causes listed after it are the ordinary ones, and these bytes alone
/// cannot tell them apart.
pub const NOT_A_SWAP_AREA: &str =
    "A Linux swap area opens with a page mkswap wrote, ending in the SWAPSPACE2 signature, and \
     this attachment does not carry it: nothing here identifies it as a swap area, so no page is \
     read through it and an entry naming its index stays a hole rather than being answered out of \
     bytes that may belong to something else entirely. The ordinary causes are a file of another \
     kind (a Windows pagefile.sys is read by the Windows tier, not this one), a whole-disk image \
     attached where the swap partition inside it was meant, an area whose first page was not \
     acquired, and a mistyped path that landed on some other readable file. Attach the swap \
     partition or the area itself, as index=path where the index is the area's swp_type.";

/// The head of an attached area, enough for a swap header and no more.
///
/// The `SWAPSPACE2` magic sits at `page_size - 10`, and 64 KiB is the largest
/// page size a swap area may have been created with, so one 64 KiB read settles
/// the parse whatever architecture wrote the area. Truncated to what was
/// actually read, so a short file is refused as short rather than parsed out of
/// a buffer of zeros this function supplied.
fn head_of(source: &dyn DataSource) -> Vec<u8> {
    let mut head = vec![0u8; 65536.min(source.size() as usize).max(4096)];
    let read = source.read_at(0, &mut head).unwrap_or(0);
    head.truncate(read);
    head
}

/// One attached swap area, and what a bounded sample of its body held.
///
/// The label and the survey travel together because the record has to be able to
/// name the area it will not read from. An examiner with two areas attached
/// needs to know which one the acquisition lost, not that one of them is empty.
pub struct SwapAreaBody {
    /// The `swp_type` this attachment answers for — the index side of
    /// `SEANCE_SWAPFILES`' `index=path`, and the number a decoded `swp_entry_t`
    /// names.
    ///
    /// Carried because the label is not an identifier. Two hosts' areas attach
    /// as `/mnt/a/swapfile` and `/mnt/b/swapfile` and land in the record with
    /// the same name, and a warning about "swapfile" then tells an examiner
    /// which of them to re-acquire only by accident. The index is what the
    /// examiner typed and what an entry names, so it is what the record says.
    pub index: u8,
    /// What the area is called in the record — normally its file name.
    pub label: String,
    /// Whether the attachment parses as a Linux swap area at all.
    ///
    /// Carried separately from the survey because the survey cannot express it:
    /// an attachment whose header never parsed has nothing sampled, nothing
    /// read and nothing found, which is the same three counts a swap area whose
    /// body could not be read produces. They are different findings with
    /// different remedies, and only this flag tells them apart. It matters
    /// because the resolver keeps a parsed header or nothing at all
    /// (`VirtualLayer::with_swap`), so not one page is ever read through an
    /// attachment this is false for.
    pub header_parsed: bool,
    /// What a bounded sample of its body held. All zero counts when
    /// `header_parsed` is false: there was no body to sample.
    pub survey: SwapBodySurvey,
}

impl SwapAreaBody {
    /// Survey an attached area's body, so what is said about it rests on bytes
    /// that were read rather than on the fact that a header parsed.
    ///
    /// An attachment whose header does not parse at all — a Windows pagefile
    /// handed to the wrong tier, an unrecognised blob — is recorded as what it
    /// is: `header_parsed` false and an empty survey, because there was no swap
    /// body to sample. Nothing is claimed about what it holds, and nothing may
    /// be read through it either: the same parse decides both here and in the
    /// resolver.
    pub fn survey(file: &seance_memory::translate::SwapFile) -> Self {
        let header = LinuxSwapHeader::parse(&head_of(file.source.as_ref()), None);
        Self {
            index: file.index,
            label: file.label.clone(),
            header_parsed: header.is_ok(),
            survey: header
                .map(|header| header.survey_body(file.source.as_ref()))
                .unwrap_or_default(),
        }
    }

    /// How the record and the warnings name this attachment.
    ///
    /// Name and index together, always, because neither identifies an
    /// attachment on its own: the name is what the examiner recognises and the
    /// index is what makes it unique, and a run with two areas called
    /// `swapfile` is a run where a finding reported under the name alone cannot
    /// be acted on.
    pub fn named(&self) -> String {
        format!("'{}' (attached as swap index {})", self.label, self.index)
    }

    /// What to tell the examiner at attach time, if anything.
    ///
    /// The profile record is read after the run; this is read during it, while
    /// the machine the swap area came from may still be reachable and the area
    /// can be acquired again properly. Three things are worth saying: that an
    /// attachment is not a swap area at all, that one that is could not be read
    /// behind its header page, and that one that could be read holds nothing but
    /// zeros. Each takes its explanation from the constant the record uses for
    /// the same finding — [`NOT_A_SWAP_AREA`], [`BODY_NOT_ACQUIRED`] and
    /// [`BODY_READS_AS_ZEROS`] — so there is one account of each hazard and not
    /// two that drift.
    ///
    /// The order matters: the three are mutually exclusive by construction, and
    /// each is checked before the weaker statement that would otherwise absorb
    /// it.
    pub fn attach_warning(&self) -> Option<String> {
        if !self.header_parsed {
            return Some(format!(
                "{} is attached as a swap area, but it does not parse as one, so no swapped \
                 page will be read through it. {NOT_A_SWAP_AREA}",
                self.named()
            ));
        }
        if self.survey.body_was_not_read() {
            return Some(format!(
                "swap area {} is attached and its header page parses, but not one of the {} \
                 body pages sampled across it could be read, so nothing has been observed about \
                 what it holds: a page whose entry names it is reported as located with its slot \
                 unread, neither as recovered nor as empty. {BODY_NOT_ACQUIRED}",
                self.named(),
                self.survey.pages_sampled
            ));
        }
        self.survey.reads_as_all_zero().then(|| {
            format!(
                "swap area {} is attached and its header parses, but all {} of the {} body \
                 pages sampled across it read back as zeros, so it is not shown to hold any \
                 swapped page's contents: a page whose slot holds bytes is still read from it, \
                 and a slot that reads as zeros will be reported as located with nothing \
                 published. {BODY_READS_AS_ZEROS}",
                self.named(),
                self.survey.pages_read,
                self.survey.pages_sampled
            )
        })
    }
}

/// The swap block a Linux profile record carries.
///
/// A free function rather than only a method so the exact value the record
/// carries can be asserted without standing up a whole profile — a test that
/// checked only the constant would not catch the block being dropped from
/// [`LinuxProfile::to_json`], which is the way this statement would actually
/// disappear.
fn swap_statement(
    semantics: PteSemantics,
    version: Option<(u32, u32)>,
    areas: &[SwapAreaBody],
) -> serde_json::Value {
    let areas_attached = areas.len();
    let attached = areas_attached > 0;
    // Attachments that are not Linux swap areas at all. Named as well as
    // counted, for the same reason the empty ones are: this is a mistake an
    // examiner can go and correct, and they have to know which attachment it is.
    let not_swap: Vec<&SwapAreaBody> = areas.iter().filter(|area| !area.header_parsed).collect();
    // Areas whose body was sampled and held nothing but zeros. Reported by name
    // as well as by count: this is an acquisition defect an examiner can go and
    // fix, and "one of your two areas is empty" does not tell them which.
    let empty: Vec<&SwapAreaBody> = areas
        .iter()
        .filter(|area| area.survey.reads_as_all_zero())
        .collect();
    // Areas that ARE swap areas and whose body could not be read at all: the
    // third state, spelled out because neither of the other two describes it.
    // `reads_as_all_zero` is false here, and deliberately so — nothing was read,
    // and "we read nothing" is not "we read zeros" — which leaves a reader who
    // knows only those two words to file this case under "not empty", where it
    // becomes the strongest claim in this block resting on the weakest evidence
    // in it. The three sets are disjoint by construction: an area with data has
    // pages read and one of them non-zero, an empty one has pages read and none,
    // and this one has none read at all.
    let unread: Vec<&SwapAreaBody> = areas
        .iter()
        .filter(|area| area.header_parsed && area.survey.body_was_not_read())
        .collect();
    let with_data = areas
        .iter()
        .filter(|area| area.survey.pages_with_data > 0)
        .count();
    // Whether an attached area was OBSERVED to hold swapped page contents. An
    // observation, not a capability, and the difference is why it reads this
    // way rather than as "an area is attached and did not disqualify itself".
    //
    // True takes bytes: a body page that was read and held something other than
    // zero. An area whose whole sampled body is zeros is not shown to hold
    // anything and must not make this true the way an area with data does —
    // that is the whole of MEM-011. An attachment whose header never parsed is
    // not a swap area at all and no page is ever read through it. And an area
    // whose body could not be read produced no observation either way, so it
    // cannot support this any more than the other two can: a claim that swapped
    // pages are read from an attachment whose every byte behind the header page
    // is missing is a claim about evidence that was never acquired.
    //
    // False is the narrower statement, and it is narrow deliberately: it says no
    // attached area was SHOWN to hold swapped contents, and emphatically not
    // that a recovered page cannot have come from swap. The sample is a few
    // dozen pages of an area that is routinely several GiB — on the ground-truth
    // corpus a correct acquisition yields data in one of the sixty-four pages
    // sampled — and both resolvers read any slot that actually holds bytes
    // whatever the sample found. What the record has to say about that is the
    // key below, so no reader is left to infer it from this one.
    let resolvable = with_data > 0;
    // Whether a swapped page whose entry names an attached area is still read
    // from it where that slot holds bytes. True of every attachment that parsed
    // as a swap area, whatever its body sampled as, because that is what
    // `crate::swap::resolve_page` and `VirtualLayer::with_swap` actually do: the
    // survey is a necessary condition for refusing a page of zeros, never a
    // sufficient one for refusing a page. False only when nothing attached is a
    // swap area, where the resolver reads nothing at all.
    //
    // It exists so `resolvable: false` cannot be read as a denial of a read the
    // tool performed. An examiner who saw a page tagged as reached via swap, and
    // a record that said swapped pages resolve to nothing, would have to
    // conclude one of the two was lying.
    let slot_reads = areas.iter().any(|area| area.header_parsed);
    let names = |areas: &[&SwapAreaBody]| {
        areas
            .iter()
            .map(|area| area.named())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let named = names(&empty);
    let unrecognised = names(&not_swap);
    let unacquired = names(&unread);
    // What is attached and cannot be read from, appended to whichever base
    // statement the run earns. The clauses read the same way after any base,
    // because the finding they report is the same either way: this attachment
    // yields nothing, and here is why and what to do about it.
    let mut caveats = String::new();
    if !not_swap.is_empty() {
        caveats.push_str(&format!(
            " Attached but not read from: {unrecognised}. {NOT_A_SWAP_AREA}"
        ));
    }
    if !unread.is_empty() {
        caveats.push_str(&format!(
            " Not one body page sampled across {unacquired} could be read, so nothing is \
             observed about what that area holds and no page is published from it: a page whose \
             entry names it is reported as located with its slot unread — neither recovered, nor \
             empty, nor an address that was never mapped. {BODY_NOT_ACQUIRED}"
        ));
    }
    if !empty.is_empty() {
        caveats.push_str(&format!(
            " Nothing sampled across the body of {named} was anything but zeros, from its first \
             slot to its last, so that area is not shown to hold any swapped page's contents. A \
             page whose entry names it is read where its slot holds bytes; a slot that reads as \
             zeros is reported as located with nothing published, rather than as a recovered page \
             of zeros. {BODY_READS_AS_ZEROS}"
        ));
    }
    let statement = if !attached {
        SWAP_NOT_RESOLVED.to_string()
    } else if resolvable {
        format!("{SWAP_RESOLVED}{caveats}")
    } else if slot_reads {
        // A swap area is attached and the sample found nothing in any of them.
        // This says what was and was not observed, and stops there: the sample
        // is a few dozen pages of each area, so "not shown to hold contents" is
        // as far as it reaches, and a page whose slot holds bytes is read here
        // exactly as it would be anywhere else.
        format!(
            "Swap area(s) are attached, and not one of them was shown to hold any swapped page's \
             contents. What was put to their bodies is a bounded sample of a few dozen pages \
             each, so that is what the sample found and not a census of what the areas hold: an \
             area acquired correctly off its block device but lightly used can sample as nothing \
             but zeros, and an area whose body could not be read was not observed either way. A \
             page whose entry names an attached swap area is still read from it \
             wherever that slot holds bytes, so a page published from swap in this case does not \
             contradict this statement; a slot that itself reads as zeros, in an area whose whole \
             sample read as zeros, is reported as located with nothing published rather than as a \
             recovered page of zeros. A page this machine swapped out is still identified as a \
             page whose contents left memory, rather than reported as an address that was never \
             mapped.{caveats}"
        )
    } else {
        // Attached, and not one attachment is a Linux swap area, so the resolver
        // reads nothing through any of them. The identification still stands —
        // it comes from the page-table entry and not from the attachment — but
        // nothing beyond it may be claimed.
        format!(
            "Files are attached as swap areas, but not one of them is a Linux swap area, so no \
             swapped page's contents are read from this acquisition. A page this machine swapped \
             out is still identified as a page whose contents left memory, rather than reported \
             as an address that was never mapped.{caveats}"
        )
    };
    serde_json::json!({
        "attached": attached,
        "areas_attached": areas_attached,
        "areas_with_data": with_data,
        "areas_body_reads_as_zeros": empty.len(),
        // Areas that are swap areas and whose body could not be read at all.
        // Counted apart from the empty ones because nothing was observed here,
        // where an empty area was observed to hold zeros, and apart from the
        // unrecognised ones because this IS a swap area: a page whose entry
        // names it is located in it, and only its bytes are missing.
        "areas_body_not_read": unread.len(),
        // Attachments that are not Linux swap areas. Counted separately from the
        // empty ones because no page is read through these at all, where an
        // empty area still answers a slot that holds bytes.
        "areas_not_a_swap_area": not_swap.len(),
        // Whether an attached area was observed to hold swapped contents, and
        // what its being false does and does not mean: see `resolvable` above.
        "resolvable": resolvable,
        // And what the tool goes on doing regardless: see `slot_reads` above.
        // Read this before concluding anything from `resolvable: false`.
        "a_slot_holding_bytes_is_still_read": slot_reads,
        // That the bodies were sampled at all. An analysis run before this check
        // existed carries no such key, and a reader must not infer a pass from
        // its absence — the same rule `pte_semantics` follows, for the same
        // reason: a case from an earlier era must not read as though it had a
        // guarantee nothing gave it.
        "body_sampled": true,
        // And the same rule again for the header check beside it: this key says
        // every attachment was put to the swap-header parse and the answer is in
        // `header_parsed` below. A case analysed before the check carries no such
        // key, and its `resolvable` counted an unparsed attachment as a good
        // area — so absence here means the question was not asked, never that it
        // was asked and passed.
        "headers_checked": true,
        // And a third time, for the third state. This key says an area whose
        // body could not be read was told apart from one that was read and held
        // zeros. A case analysed before that distinction existed scored such an
        // area `resolvable: true` — the strongest claim in the block, on an area
        // nothing was ever read from — so absence here means the question was
        // not asked, never that it was asked and passed.
        "unread_bodies_checked": true,
        "areas": areas
            .iter()
            .map(|area| serde_json::json!({
                // The swp_type the area answers for, beside the label, because
                // two attachments may carry the same name and only this tells
                // an examiner which of them a finding is about.
                "index": area.index,
                "label": area.label,
                "header_parsed": area.header_parsed,
                "pages_sampled": area.survey.pages_sampled,
                "pages_read": area.survey.pages_read,
                "pages_with_data": area.survey.pages_with_data,
                "body_reads_as_zeros": area.survey.reads_as_all_zero(),
                // False whenever the body reads as zeros, and vice versa: the
                // two are answers to different questions and never both true.
                "body_not_read": area.header_parsed && area.survey.body_was_not_read(),
            }))
            .collect::<Vec<_>>(),
        // Whether the address space can tell a swap-family entry apart from an
        // address that was never mapped. True only under Linux semantics, which
        // is why the semantics travel beside it: an old case analysed under
        // `bare` must not read as though it had this.
        "entries_identified": semantics == PteSemantics::Linux,
        "pte_semantics": semantics.as_str(),
        "kernel_version": version.map(|(major, minor)| format!("{major}.{minor}")),
        "statement": statement,
    })
}

/// The swap block for a profile whose kernel pages under `mode`.
///
/// On an Intel mode it is [`swap_statement`] unchanged. On arm64 the address
/// space never tells a swap-family entry apart from an empty one — the bit
/// Linux uses for `PROT_NONE` moved between kernels, onto positions the other
/// layout reads as swap offset (see `PagingSpec::classify_invalid`) — so no
/// swapped page is identified, and no attached area is ever read from. The
/// block then says the tool could not look: `entries_identified`,
/// `resolvable` and `a_slot_holding_bytes_is_still_read` are all false, and
/// `swap_entries_decoded: false` (a key only this case carries) names why.
/// What the attachments are is still reported as surveyed.
fn swap_statement_for(
    mode: PagingMode,
    semantics: PteSemantics,
    version: Option<(u32, u32)>,
    areas: &[SwapAreaBody],
) -> serde_json::Value {
    let mut block = swap_statement(semantics, version, areas);
    if mode.is_intel() {
        return block;
    }
    let attached = if areas.is_empty() {
        String::new()
    } else {
        format!(
            " {} attachment(s) were surveyed and are listed below, but no page is read through \
             any of them.",
            areas.len()
        )
    };
    block["entries_identified"] = serde_json::json!(false);
    block["resolvable"] = serde_json::json!(false);
    block["a_slot_holding_bytes_is_still_read"] = serde_json::json!(false);
    block["swap_entries_decoded"] = serde_json::json!(false);
    block["statement"] = serde_json::json!(format!(
        "This is an arm64 kernel, and swap resolution does not run on arm64: a non-present entry \
         that is not empty is not told apart from an empty one, because the bit Linux marks \
         PROT_NONE with has moved between arm64 kernels onto positions another layout reads as \
         swap offset, and nothing in the image says which layout wrote it. So the tool could not \
         look for pages this machine swapped out. A page reported as not present here is not a \
         finding that it was never mapped; its entry travels verbatim for an examiner who knows \
         the kernel.{attached}"
    ));
    block
}

/// Everything discovery established about a Linux memory image.
///
/// Held by every analysis stage in this crate. Construction is the job of
/// [`crate::discovery`]; nothing else builds one from parts.
#[derive(Clone)]
pub struct LinuxProfile {
    /// The kernel address space: virtual addresses translated through the
    /// system page tables. This is what every stage reads through.
    pub kernel_space: Arc<dyn MemoryLayer>,
    /// The physical layer underneath, kept because the banner sweep and any
    /// later scan-based stage works on physical memory.
    pub physical: Arc<dyn MemoryLayer>,
    /// Symbols for the running kernel build.
    pub symbols: Arc<SymbolTable>,
    /// Directory table base used to build `kernel_space`.
    pub dtb: Found<u64>,
    /// The symbol the directory table base was derived from — `init_level4_pgt`
    /// on this Debian 3.2 build, `swapper_pg_dir` or `init_top_pgt` on others.
    ///
    /// Recorded because which of them a kernel declares is a fact about the
    /// build, and a report that says only "the DTB was 0x1605000" cannot be
    /// checked against the symbol pack.
    pub dtb_symbol: &'static str,
    /// The kernel text mapping's shift, and the two addresses it came from.
    pub kernel_shift: Found<KernelShift>,
    /// The build the symbols were matched to.
    pub build: LinuxBuild,
    /// Pointer width of the kernel address space.
    pub architecture: seance_memory::meta::Architecture,
    /// Paging parameters the kernel space was built under. Handed to every
    /// per-process address space so a process is read the same way the kernel
    /// is.
    ///
    /// Its **depth** is a proved fact, not a default: `CR4.LA57` appears in no
    /// capture, so discovery walked the kernel's tables at each candidate depth
    /// and kept the one that translated the banner back to the physical address
    /// the sweep found it at. Its **semantics** are `linux`, which is what lets
    /// a swapped page be told apart from an address that was never mapped —
    /// what lets a swapped page be read once its area is attached — see
    /// [`SWAP_RESOLVED`] and [`SWAP_NOT_RESOLVED`].
    pub paging: PagingSpec,
    /// Page-table entry memo, shared by the kernel space and every per-process
    /// space built from it.
    ///
    /// Shared deliberately: an entry is keyed by physical address and means the
    /// same thing in every address space, so a case with a hundred processes
    /// should hold one cache and not a hundred.
    pub cache: Arc<TableCache>,
    /// Swap areas the examiner attached (via `SEANCE_SWAPFILES`), each carrying
    /// the swap-area index (`swp_type`) it answers to. Empty unless one was
    /// supplied. Handed to every per-process address space so a page the kernel
    /// wrote out to swap resolves to its bytes rather than staying a hole — the
    /// entry is decoded and corroborated against the area's bounds inside the
    /// translation layer. See [`seance_memory::translate::VirtualLayer::with_swap`].
    pub swap: Vec<seance_memory::translate::SwapFile>,
}

impl std::fmt::Debug for LinuxProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxProfile")
            .field("dtb", &format_args!("{:#x}", self.dtb.value))
            .field("dtb_symbol", &self.dtb_symbol)
            .field(
                "kernel_shift",
                &format_args!("{:#x}", self.kernel_shift.value.shift),
            )
            .field("banner", &self.build.banner)
            .field("architecture", &self.architecture)
            .finish_non_exhaustive()
    }
}

impl LinuxProfile {
    /// Pointer width in bytes.
    pub fn pointer_size(&self) -> u64 {
        self.symbols.pointer_size()
    }

    /// The weakest evidence behind any fact in this profile.
    ///
    /// A result is only as trustworthy as the shakiest thing it rests on, so
    /// this is what a finding derived from the profile carries — not the
    /// strongest fact in it. [`Evidence`] orders strongest-first, which is what
    /// makes this a `max`.
    pub fn weakest_evidence(&self) -> Evidence {
        self.dtb.evidence.max(self.kernel_shift.evidence)
    }

    /// Whether the symbol table passed every admission gate.
    pub fn symbols_verified(&self) -> bool {
        self.symbols.state() == AdmissionState::Verified
    }

    /// What this profile can say about the machine's swap, published on the
    /// profile record.
    ///
    /// Identification without resolution, and stated rather than left out: see
    /// [`SWAP_NOT_RESOLVED`]. The kernel version travels with it because it is
    /// what an examiner decoding an entry by hand needs — it is emphatically
    /// *not* what this crate selects a layout on, for the reason
    /// [`LinuxBuild::version`] gives.
    ///
    /// `pte_semantics` is the address space's own account of itself, and it is
    /// the field that keeps two eras of case apart: `bare` means a non-present
    /// entry was read as absent and nothing further was claimed about it,
    /// `linux` means a swap-family entry was told apart from an address that
    /// was never mapped. A case analysed under the older semantics must not
    /// read as though it had the newer capability.
    pub fn swap_statement(&self) -> serde_json::Value {
        // Sampled here rather than carried on the profile because discovery
        // builds the profile and the analysis layer attaches the areas
        // afterwards; the survey is a fixed handful of reads either way.
        let areas: Vec<SwapAreaBody> = self.swap.iter().map(SwapAreaBody::survey).collect();
        swap_statement_for(
            self.paging.mode(),
            self.paging.semantics(),
            self.build.version(),
            &areas,
        )
    }

    /// Serializable form for the image-profile artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "dtb": self.dtb.value,
            "dtb_hex": format!("{:#x}", self.dtb.value),
            "dtb_evidence": self.dtb.evidence.as_str(),
            "dtb_symbol": self.dtb_symbol,
            "kernel_shift": self.kernel_shift.value.shift,
            "kernel_shift_hex": format!("{:#x}", self.kernel_shift.value.shift),
            "kernel_shift_evidence": self.kernel_shift.evidence.as_str(),
            "banner_virtual_address": format!("{:#x}", self.kernel_shift.value.banner_virtual),
            "banner_physical_address": format!("{:#x}", self.kernel_shift.value.banner_physical),
            "banner": self.build.banner,
            "release": self.build.release,
            // Kept for consumers that only ever wanted the path: a file when
            // there was one, and null rather than a plausible-looking string
            // when the layouts came out of the image. A reader that does not
            // know about `symbols_from` must not be handed something it will
            // print as a provenance claim.
            "symbol_file": match &self.build.symbols_from {
                SymbolOrigin::SymbolFile { path } => serde_json::Value::String(path.clone()),
                SymbolOrigin::ImageDerived { .. } => serde_json::Value::Null,
            },
            "symbols_from": self.build.symbols_from.to_json(),
            "symbols_origin": self.build.symbols_from.kind(),
            "symbols_independently_corroborated": self
                .build
                .symbols_from
                .is_corroborated_by_an_independent_source(),
            "symbols_provenance_statement": self.build.symbols_from.statement(),
            "architecture": self.architecture.as_str(),
            "pointer_size": self.pointer_size(),
            "paging_mode": self.paging.mode().as_str(),
            "symbols_state": self.symbols.state().as_str(),
            "symbols_verified": self.symbols_verified(),
            "symbols_sha256": self.symbols.provenance().to_json(),
            "symbols_admission": self.symbols.admission().to_json(),
            "weakest_evidence": self.weakest_evidence().as_str(),
            // Swap, stated rather than omitted. An examiner reading a Windows
            // profile beside this one sees a pagefile attached there and
            // nothing here, and without this block the difference reads as
            // "this machine had nothing swapped out".
            "swap": self.swap_statement(),
        })
    }
}

/// A memory layer as a [`seance_symbols::ImageProbe`], so symbol admission's
/// gate 4 can read typed fields out of the image it is being admitted against.
///
/// The one rule an implementor must not break is that an unbacked byte is an
/// error rather than a zero. Gate 4's whole job is to falsify a symbol table
/// that describes a different kernel, and fabricated zeros satisfy almost any
/// sanity check — a `task_struct.comm` of sixteen NULs would "read" perfectly
/// through a table for the wrong build.
#[derive(Debug)]
pub struct LinuxLayerProbe {
    layer: Arc<dyn MemoryLayer>,
    pointer_size: u8,
    identifier: Option<String>,
}

impl LinuxLayerProbe {
    /// A probe over `layer`, whose pointers are `pointer_size` bytes wide and
    /// whose kernel identified itself with `identifier` — for Linux, the
    /// normalised banner recovered from the image.
    pub fn new(layer: Arc<dyn MemoryLayer>, pointer_size: u8, identifier: Option<String>) -> Self {
        Self {
            layer,
            pointer_size,
            identifier,
        }
    }
}

impl ImageProbe for LinuxLayerProbe {
    fn read_exact(&self, address: u64, buf: &mut [u8]) -> ProbeResult<()> {
        if address.checked_add(buf.len() as u64).is_none() {
            return Err(ProbeError::Unavailable(format!(
                "reading {} byte(s) at {address:#x} runs past the top of the address space",
                buf.len()
            )));
        }
        seance_core::io::read_exact_or_fail(
            self.layer.as_data_source(),
            address,
            buf,
            "symbol gate read",
        )
        .map_err(|err| match MemoryHole::from_io(&err) {
            Some(hole) => ProbeError::Unmapped {
                address: hole.address,
                length: hole.length,
                reason: hole.reason.as_str().to_string(),
            },
            None => ProbeError::Io(err.to_string()),
        })
    }

    fn pointer_size(&self) -> u8 {
        self.pointer_size
    }

    fn image_identifier(&self) -> Option<String> {
        self.identifier.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_release_is_taken_from_the_banner_or_not_at_all() {
        assert_eq!(
            LinuxBuild::release_from_banner(
                "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3)"
            ),
            Some("3.2.0-4-amd64".to_string())
        );
        // Anything that is not a banner yields nothing rather than a fragment
        // of itself: a release string invented from a string that was not a
        // banner is a claim about the machine with nothing behind it.
        assert_eq!(LinuxBuild::release_from_banner("not a banner"), None);
        assert_eq!(LinuxBuild::release_from_banner("Linux version "), None);
    }

    #[test]
    fn the_kernel_version_is_taken_from_the_release_or_not_at_all() {
        // Published so an examiner decoding a swap entry by hand knows which
        // kernel they are decoding for. Explicitly NOT a layout selector: the
        // L1TF inversion was backported below 4.19, so `>= (4, 19)` would pick
        // the wrong bits on exactly the widely-deployed enterprise kernels.
        // Nothing in this crate branches on it, and the assertions below are
        // about the parse refusing to invent a version, not about a threshold.
        let build = |release: Option<&str>| LinuxBuild {
            banner: "Linux version x".to_string(),
            release: release.map(str::to_string),
            symbols_from: SymbolOrigin::SymbolFile {
                path: "/symbols/x.json".to_string(),
            },
        };

        assert_eq!(build(Some("3.2.0-4-amd64")).version(), Some((3, 2)));
        assert_eq!(build(Some("5.10.0-8-amd64")).version(), Some((5, 10)));
        assert_eq!(build(Some("4.19.0")).version(), Some((4, 19)));
        assert_eq!(build(Some("6.1.55")).version(), Some((6, 1)));

        // And a release that does not open with two numbers yields nothing.
        // A version invented from a string that did not state one is a claim
        // about the machine, and one that would go on to choose a bit layout.
        assert_eq!(build(Some("vmlinuz")).version(), None);
        assert_eq!(build(Some("5")).version(), None);
        assert_eq!(build(Some("5.x")).version(), None);
        assert_eq!(build(None).version(), None);
    }

    #[test]
    fn an_arm64_profile_says_swap_entries_were_not_looked_at_not_that_none_exist() {
        // On arm64 no swap-family entry is told apart from an empty one (see
        // `PagingSpec::classify_invalid`), so no swapped page is identified and
        // no slot is ever read, whatever is attached. The record has to say the
        // tool could not look, never that the pages were never mapped.
        use seance_memory::translate::{Arm64Granule, Arm64Regime, Ttbr};
        let arm64 =
            PagingMode::Arm64(Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr1, 48).unwrap());
        for areas in [vec![], vec![populated(0, "swap-area.raw")]] {
            let block = swap_statement_for(arm64, PteSemantics::Linux, Some((4, 19)), &areas);
            assert_eq!(block["entries_identified"], serde_json::json!(false));
            assert_eq!(block["resolvable"], serde_json::json!(false));
            assert_eq!(
                block["a_slot_holding_bytes_is_still_read"],
                serde_json::json!(false)
            );
            assert_eq!(block["swap_entries_decoded"], serde_json::json!(false));
            assert_eq!(block["attached"], serde_json::json!(!areas.is_empty()));
            let statement = block["statement"].as_str().expect("a statement");
            for needle in ["arm64", "could not look", "not a finding that"] {
                assert!(statement.contains(needle), "{needle}: {statement}");
            }
            assert!(!statement.contains("are identified"), "{statement}");
        }
        // An Intel profile is untouched by the routing.
        let intel = swap_statement_for(
            PagingMode::Intel32e,
            PteSemantics::Linux,
            Some((5, 10)),
            &[],
        );
        assert_eq!(
            intel,
            swap_statement(PteSemantics::Linux, Some((5, 10)), &[])
        );
    }

    #[test]
    fn the_profile_states_the_swap_situation_attached_or_not() {
        // Every page this machine had swapped out must be accounted for: under
        // `PteSemantics::Linux` the address space tells a swap-family entry apart
        // from an address that was never mapped, and the block says whether the
        // contents were read. With no swap area attached they are not, and the
        // statement says how to attach one; with one attached they are.

        // No swap area attached: identified, not read, and told how to read.
        let block = swap_statement(PteSemantics::Linux, Some((5, 10)), &[]);
        assert_eq!(block["attached"], serde_json::json!(false));
        assert_eq!(block["resolvable"], serde_json::json!(false));
        assert_eq!(block["areas_attached"], serde_json::json!(0));
        assert_eq!(block["entries_identified"], serde_json::json!(true));
        assert_eq!(block["pte_semantics"], serde_json::json!("linux"));
        assert_eq!(block["kernel_version"], serde_json::json!("5.10"));

        let statement = block["statement"].as_str().expect("a statement");
        assert!(statement.contains("SEANCE_SWAPFILES"), "{statement}");
        assert!(statement.contains("4.19"), "{statement}");
        assert!(
            statement.contains("stays a hole rather than being guessed"),
            "the statement has to say why an uncorroborated decode is refused"
        );
        assert!(
            statement.contains("migration"),
            "the encoding is not swap alone, and the statement has to say so"
        );

        // A swap area attached: swapped pages are read, and the statement says so.
        let attached = swap_statement(
            PteSemantics::Linux,
            Some((5, 10)),
            &[populated(0, "swap-area.raw")],
        );
        assert_eq!(attached["attached"], serde_json::json!(true));
        assert_eq!(attached["resolvable"], serde_json::json!(true));
        assert_eq!(attached["areas_attached"], serde_json::json!(1));
        assert!(attached["statement"]
            .as_str()
            .expect("a statement")
            .contains("read from the attached swap area"));

        // A case analysed under the older semantics must not read as though it
        // had the capability. This is the field that keeps the two eras apart,
        // so it has to actually follow the semantics rather than be a constant.
        let older = swap_statement(PteSemantics::Bare, Some((5, 10)), &[]);
        assert_eq!(older["entries_identified"], serde_json::json!(false));
        assert_eq!(older["pte_semantics"], serde_json::json!("bare"));

        // A build whose version never settled says so rather than reporting a
        // number. A fabricated version is exactly the wrong kind of help to an
        // examiner about to decode an entry by hand.
        let unknown = swap_statement(PteSemantics::Linux, None, &[]);
        assert_eq!(unknown["kernel_version"], serde_json::Value::Null);

        // And the record has to carry it. A statement that exists and is never
        // emitted is the same silence the block was written to end, and nothing
        // else in this file would fail if it were dropped from `to_json`.
        // Written as the escaped form so this assertion cannot match itself.
        let source = include_str!("profile.rs");
        assert!(
            source.contains("\"swap\": self.swap_statement()"),
            "the Linux profile record no longer carries the swap statement"
        );
    }

    /// Refuse a fixture label that any of the block's own sentences already
    /// contains.
    ///
    /// Every "the record names the attachment" assertion in this module is a
    /// `contains(label)`, and those are only worth something while the label is
    /// a string the record could only be printing because it was told to.
    /// [`NOT_A_SWAP_AREA`] lists `pagefile.sys` among the ordinary causes, so a
    /// fixture called exactly that made three such assertions pass whether or
    /// not the attachment was ever named. Failing here is how the next one gets
    /// caught at the fixture instead of never.
    fn a_name_the_prose_does_not_already_carry(label: &str) {
        for sentence in [
            NOT_A_SWAP_AREA,
            BODY_NOT_ACQUIRED,
            BODY_READS_AS_ZEROS,
            SWAP_RESOLVED,
            SWAP_NOT_RESOLVED,
        ] {
            assert!(
                !sentence.contains(label),
                "the fixture label {label:?} already appears in the block's own prose, so an \
                 assertion that the record names this attachment would pass without it"
            );
        }
    }

    /// An area whose body was surveyed and held data, as a real acquisition off
    /// the block device does.
    fn populated(index: u8, label: &str) -> SwapAreaBody {
        a_name_the_prose_does_not_already_carry(label);
        SwapAreaBody {
            index,
            label: label.to_string(),
            header_parsed: true,
            survey: SwapBodySurvey {
                pages_sampled: 64,
                pages_read: 64,
                pages_with_data: 51,
            },
        }
    }

    /// An area whose header parsed and whose every sampled body page was zeros —
    /// a swap file copied through the filesystem.
    fn body_of_zeros(index: u8, label: &str) -> SwapAreaBody {
        a_name_the_prose_does_not_already_carry(label);
        SwapAreaBody {
            index,
            label: label.to_string(),
            header_parsed: true,
            survey: SwapBodySurvey {
                pages_sampled: 64,
                pages_read: 64,
                pages_with_data: 0,
            },
        }
    }

    #[test]
    fn an_attached_area_whose_body_reads_as_zeros_does_not_read_as_one_with_data() {
        // The hazard: a swap file copied through the filesystem attaches, bounds-
        // corroborates entries, and hands back zeros. The record must not let
        // that area make the case read as one where swapped pages were read.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[body_of_zeros(1, "swapfile")],
        );

        // It IS attached, and the record says so: refusing the attachment would
        // report these pages as belonging to an area nobody attached.
        assert_eq!(block["attached"], serde_json::json!(true));
        assert_eq!(block["areas_attached"], serde_json::json!(1));
        // But nothing can be read from it, which is what `resolvable` means.
        assert_eq!(block["resolvable"], serde_json::json!(false));
        assert_eq!(block["areas_with_data"], serde_json::json!(0));
        assert_eq!(block["areas_body_reads_as_zeros"], serde_json::json!(1));

        // The counts the verdict rests on travel with it, per area.
        let area = &block["areas"][0];
        assert_eq!(area["label"], serde_json::json!("swapfile"));
        assert_eq!(area["pages_sampled"], serde_json::json!(64));
        assert_eq!(area["pages_read"], serde_json::json!(64));
        assert_eq!(area["pages_with_data"], serde_json::json!(0));
        assert_eq!(area["body_reads_as_zeros"], serde_json::json!(true));

        let statement = block["statement"].as_str().expect("a statement");
        assert!(statement.contains("swapfile"), "name the area: {statement}");
        assert!(
            statement.contains("filefrag"),
            "name the remedy, once, from the one place it is written: {statement}"
        );

        // A case analysed before this check existed must not read as though its
        // areas had passed it — the same rule `pte_semantics` follows. The key is
        // absent there and true here; nothing infers a pass from silence.
        assert_eq!(block["body_sampled"], serde_json::json!(true));
    }

    #[test]
    fn an_area_that_was_attached_but_holds_nothing_is_worth_saying_out_loud() {
        // The profile record is read after the run; a warning is read during it,
        // while the examiner still has the machine and can re-acquire the area
        // properly. Both say the same thing because both take it from the same
        // constant.
        assert!(
            populated(0, "sda2").attach_warning().is_none(),
            "an area with data in it is not a problem to warn about"
        );
        let warning = body_of_zeros(1, "swapfile")
            .attach_warning()
            .expect("an attached area holding nothing is worth a warning");
        assert!(warning.contains("swapfile"), "name the area: {warning}");
        assert!(
            warning.contains("64"),
            "say how much was sampled: {warning}"
        );
        assert!(
            warning.contains("filefrag"),
            "name the remedy, from the one place it is written: {warning}"
        );
    }

    #[test]
    fn a_populated_area_beside_an_empty_one_is_still_read_from() {
        // The other half, and it matters as much: one bad acquisition must not
        // suppress a good one. Pages in the populated area are still read, and
        // the statement names the area that yields nothing.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[populated(0, "sda2"), body_of_zeros(1, "swapfile")],
        );
        assert_eq!(block["areas_attached"], serde_json::json!(2));
        assert_eq!(block["areas_with_data"], serde_json::json!(1));
        assert_eq!(block["areas_body_reads_as_zeros"], serde_json::json!(1));
        assert_eq!(
            block["resolvable"],
            serde_json::json!(true),
            "an area with data is attached, so swapped pages naming it are read"
        );

        let statement = block["statement"].as_str().expect("a statement");
        assert!(
            statement.contains("read from the attached swap area"),
            "the resolved statement still stands for the good area: {statement}"
        );
        assert!(
            statement.contains("swapfile") && !statement.contains("sda2"),
            "only the area that yields nothing is named as such: {statement}"
        );
    }

    /// An attachment whose header never parsed: a Windows pagefile handed to
    /// this tier, a disk image attached where the partition inside it was meant,
    /// a mistyped path onto some other readable file. Nothing of a swap body was
    /// sampled because there was no swap body to sample.
    fn not_a_swap_area(index: u8, label: &str) -> SwapAreaBody {
        a_name_the_prose_does_not_already_carry(label);
        SwapAreaBody {
            index,
            label: label.to_string(),
            header_parsed: false,
            survey: SwapBodySurvey::default(),
        }
    }

    #[test]
    fn an_attachment_that_is_not_a_swap_area_is_never_reported_as_resolvable() {
        // `SEANCE_SWAPFILES` attaches whatever path it is handed, and nothing
        // validates the file before it lands in the profile. The resolver keeps
        // a parsed header or nothing, so it reads not one page through an
        // attachment like this — and the record must not say otherwise.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[not_a_swap_area(1, "/mnt/evidence/pagefile.sys")],
        );

        // It IS attached, and the record says so rather than quietly dropping it:
        // an examiner who attached a file is owed an account of it.
        assert_eq!(block["attached"], serde_json::json!(true));
        assert_eq!(block["areas_attached"], serde_json::json!(1));
        // But no page can be read through it, which is what `resolvable` means.
        assert_eq!(
            block["resolvable"],
            serde_json::json!(false),
            "an attachment that is not a swap area resolves nothing, and an empty \
             survey is the absence of observations, not an area in good order"
        );
        assert_eq!(block["areas_not_a_swap_area"], serde_json::json!(1));
        assert_eq!(block["areas_with_data"], serde_json::json!(0));
        // Not the other finding: its body did not read as zeros, it has no body.
        assert_eq!(block["areas_body_reads_as_zeros"], serde_json::json!(0));

        let area = &block["areas"][0];
        assert_eq!(area["index"], serde_json::json!(1));
        assert_eq!(
            area["label"],
            serde_json::json!("/mnt/evidence/pagefile.sys")
        );
        assert_eq!(area["header_parsed"], serde_json::json!(false));
        assert_eq!(area["pages_sampled"], serde_json::json!(0));

        let statement = block["statement"].as_str().expect("a statement");
        assert!(
            !statement.starts_with("Pages this machine had swapped out are read from"),
            "not one swapped page is read here, so the statement must not open by \
             saying they are: {statement}"
        );
        assert!(
            statement.contains("/mnt/evidence/pagefile.sys"),
            "name the attachment, so the examiner knows which one to replace: {statement}"
        );
        assert!(
            statement.contains("SWAPSPACE2"),
            "say what was looked for and not found: {statement}"
        );
        assert!(
            statement.contains("still identified"),
            "the identification stands on the page-table entry and not on the \
             attachment, and the statement must keep saying so: {statement}"
        );

        // A case analysed before this check existed must not read as though its
        // attachments had passed it — the same rule `pte_semantics` and
        // `body_sampled` follow. The key is absent there and true here.
        assert_eq!(block["headers_checked"], serde_json::json!(true));
    }

    #[test]
    fn a_real_swap_area_beside_an_attachment_that_is_not_one_is_still_read_from() {
        // The other half: one wrong path must not suppress a good acquisition.
        // Pages in the real area are still read, and the record still says which
        // attachment yields nothing.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[
                populated(0, "sda2"),
                not_a_swap_area(1, "/mnt/evidence/pagefile.sys"),
            ],
        );
        assert_eq!(block["areas_attached"], serde_json::json!(2));
        assert_eq!(block["areas_with_data"], serde_json::json!(1));
        assert_eq!(block["areas_not_a_swap_area"], serde_json::json!(1));
        assert_eq!(
            block["resolvable"],
            serde_json::json!(true),
            "a swap area holding data is attached, so pages naming it are read"
        );

        let statement = block["statement"].as_str().expect("a statement");
        assert!(
            statement.contains("read from the attached swap area"),
            "the resolved statement stands for the area that is one: {statement}"
        );
        assert!(
            statement.contains("/mnt/evidence/pagefile.sys") && !statement.contains("sda2"),
            "only the attachment that is not a swap area is named as such: {statement}"
        );
    }

    #[test]
    fn an_attachment_that_is_not_a_swap_area_is_worth_saying_out_loud_at_attach_time() {
        // Read during the run, while the examiner may still be able to attach the
        // right thing — the record is only read afterwards. It says the same
        // thing the record says because both take it from the same constant.
        let warning = not_a_swap_area(1, "/mnt/evidence/pagefile.sys")
            .attach_warning()
            .expect("an attachment that is not a swap area is worth a warning");
        assert!(
            warning.contains("/mnt/evidence/pagefile.sys"),
            "name the attachment: {warning}"
        );
        assert!(
            warning.contains("SWAPSPACE2"),
            "say what was looked for and not found: {warning}"
        );
        assert!(
            populated(0, "sda2").attach_warning().is_none(),
            "a swap area holding data is not a problem to warn about"
        );
    }

    /// An area that IS a swap area and whose body could not be read at all: a
    /// `dd` that stopped after the first page, a sparse copy that lost the body,
    /// a source that errors behind the header. Nothing was observed about what
    /// it holds, which is a third finding and not either of the other two.
    fn body_not_read(index: u8, label: &str) -> SwapAreaBody {
        a_name_the_prose_does_not_already_carry(label);
        SwapAreaBody {
            index,
            label: label.to_string(),
            header_parsed: true,
            survey: SwapBodySurvey {
                pages_sampled: 64,
                pages_read: 0,
                pages_with_data: 0,
            },
        }
    }

    #[test]
    fn an_area_whose_body_was_never_read_is_not_reported_as_one_in_good_order() {
        // The gap a two-state record leaves: `reads_as_all_zero` is false here,
        // and rightly so — nothing was read, and "we read nothing" is not "we
        // read zeros" — but a record that takes "not shown to be empty" for
        // "shown to hold contents" then makes the unqualified claim that swapped
        // pages are read from the attached area, on an area whose every byte
        // behind the header page is missing.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[body_not_read(0, "truncated.raw")],
        );

        assert_eq!(block["attached"], serde_json::json!(true));
        assert_eq!(block["areas_attached"], serde_json::json!(1));
        assert_eq!(
            block["resolvable"],
            serde_json::json!(false),
            "not one page of this area's body came back, so nothing about what it \
             holds was observed and the record must not read as though it had been"
        );
        assert_eq!(block["areas_with_data"], serde_json::json!(0));
        assert_eq!(
            block["areas_body_reads_as_zeros"],
            serde_json::json!(0),
            "zero observations are not observations of zeros: this is the other finding"
        );
        assert_eq!(block["areas_body_not_read"], serde_json::json!(1));

        let area = &block["areas"][0];
        assert_eq!(area["header_parsed"], serde_json::json!(true));
        assert_eq!(area["pages_sampled"], serde_json::json!(64));
        assert_eq!(area["pages_read"], serde_json::json!(0));
        assert_eq!(area["body_not_read"], serde_json::json!(true));
        assert_eq!(area["body_reads_as_zeros"], serde_json::json!(false));

        let statement = block["statement"].as_str().expect("a statement");
        assert!(
            !statement.starts_with("Pages this machine had swapped out are read from"),
            "no byte of this area was read, so the statement must not open by saying \
             swapped pages are read from it: {statement}"
        );
        assert!(
            statement.contains("truncated.raw"),
            "name the area whose body is missing, so the examiner knows which one to \
             re-acquire: {statement}"
        );
        assert!(
            statement.contains("still identified"),
            "the identification rests on the page-table entry and not on the area: {statement}"
        );
    }

    #[test]
    fn an_area_whose_body_was_never_read_is_worth_saying_out_loud_at_attach_time() {
        // Said during the run, while the area may still be re-acquirable — the
        // same reason the other two hazards are said then.
        let warning = body_not_read(0, "truncated.raw")
            .attach_warning()
            .expect("an area whose body was not acquired is worth a warning");
        assert!(
            warning.contains("truncated.raw"),
            "name the area: {warning}"
        );
        assert!(
            warning.contains("64"),
            "say how many places were looked at: {warning}"
        );
    }

    #[test]
    fn an_area_that_sampled_as_zeros_does_not_deny_the_reads_still_performed() {
        // The other direction of the same failure. The survey is a bounded
        // sample: on the ground-truth corpus a correctly acquired area yields
        // data in one of the sixty-four pages sampled, and both resolvers read
        // any slot that actually holds bytes whatever the sample found. A record
        // that says "no swapped page's contents are read from this acquisition"
        // denies, machine-readably, a read the tool performs — which is as bad
        // for an examiner as the claim it was written to prevent.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[body_of_zeros(1, "swapfile")],
        );

        assert_eq!(
            block["a_slot_holding_bytes_is_still_read"],
            serde_json::json!(true),
            "the area parses, so the resolver reads a page whose entry names it \
             wherever that slot holds bytes; the record must say so"
        );

        let statement = block["statement"].as_str().expect("a statement");
        assert!(
            !statement.contains("no swapped page's contents are read from this acquisition"),
            "the sample is a sample and not a census, so the record must not deny a \
             read the resolver performs: {statement}"
        );
        assert!(
            statement.contains("holds bytes"),
            "say what is still read — a slot that holds bytes: {statement}"
        );
    }

    #[test]
    fn two_attachments_of_the_same_name_are_told_apart_by_the_index_they_answer_for() {
        // `SEANCE_SWAPFILES` is index=path, and two machines' `/mnt/*/swapfile`
        // attach under different indices with the same file name. A warning or a
        // record entry that carries only the name leaves the examiner unable to
        // tell which attachment it is about.
        let block = swap_statement(
            PteSemantics::Linux,
            Some((5, 15)),
            &[body_of_zeros(0, "swapfile"), body_not_read(1, "swapfile")],
        );
        assert_eq!(block["areas"][0]["index"], serde_json::json!(0));
        assert_eq!(block["areas"][1]["index"], serde_json::json!(1));

        let statement = block["statement"].as_str().expect("a statement");
        assert!(
            statement.contains("'swapfile' (attached as swap index 0)")
                && statement.contains("'swapfile' (attached as swap index 1)"),
            "each finding has to name the attachment it is about by its index as \
             well as its name, or the two cannot be told apart: {statement}"
        );
        assert_ne!(
            body_of_zeros(0, "swapfile").attach_warning(),
            body_of_zeros(1, "swapfile").attach_warning(),
            "two identically named attachments must not produce the same warning"
        );
    }

    #[test]
    fn the_weakest_fact_is_what_a_finding_carries() {
        // Ordering is strongest-first, so `max` is the weakest link. A profile
        // whose shift was scanned must not report the DTB's grade.
        assert!(Evidence::Validated < Evidence::Scanned);
        assert_eq!(
            Evidence::Validated.max(Evidence::Scanned),
            Evidence::Scanned
        );
    }
}
