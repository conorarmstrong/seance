//! Finding the directory table base by its self-referential entry, and
//! deciding whether a candidate is real.
//!
//! # What the DTB is, and what a wrong one does
//!
//! Every virtual address in the image is translated through a page-table
//! hierarchy, and the DTB is the physical address of the top of that hierarchy.
//! A memory image publishes it nowhere: raw memory has no header, and even a
//! crash dump's `DirectoryTableBase` is only as good as the dump writer.
//!
//! A wrong DTB does not fail loudly. It produces an address space that
//! translates *some* addresses successfully, because page-table pages look
//! alike, and everything read through it is bytes from unrelated physical
//! memory that parse perfectly into a plausible, wholly fictitious analysis. So
//! a candidate here is never reported on the strength of the scan alone: the
//! caller must find the kernel through it, and only then does the candidate
//! become evidence.
//!
//! # How the scan works
//!
//! Windows maps its own page tables into the virtual address space so the
//! memory manager can edit them, and it does that with a **self-referential
//! entry**: one entry of the top-level table points back at the table itself.
//! That makes the top-level table findable in physical memory without knowing
//! anything else about the image — it is the page containing an entry whose
//! frame number is the page's own physical address.
//!
//! Older Windows put that entry at a fixed index, different per paging mode:
//!
//! | Mode | Entry size | Self-reference index |
//! |---|---|---|
//! | 32-bit, no PAE | 4 bytes | `0x300` |
//! | PAE | 8 bytes | `0x3`, in the fourth page directory |
//! | x86-64 | 8 bytes | `0x1ED` |
//! | x86-64 with LA57 | 8 bytes | same test, applied to the PML5 |
//!
//! LA57 (five-level) self-references by exactly the same rules as four-level
//! x86-64 — the PML5 and PML4 differ only in the depth of the walk — so the
//! sweep finds the same candidate pages, and the `automagic` mode order now
//! offers the mode (last, mirroring the four-level sweep rather than repeating
//! it). A candidate is only *accepted* when a kernel proves out through it, and
//! that happens under five-level walking only for a genuinely five-level image:
//! a four-level machine is proven at four levels first and never reaches it.
//!
//! Windows 10 randomised the x64 index, so that column becomes a *range*
//! (`0x100..=0x1FF`, the upper half of the PML4, which is where the kernel
//! lives) and the page must contain **exactly one** self-reference. Exactly one
//! is the discriminator: a table of repeated or coincidental values usually has
//! zero or many, and a real top-level table has precisely one by construction.
//!
//! PAE is the awkward case. Its top-level table is the four-entry
//! page-directory-pointer table, which is 32 bytes and contains no
//! self-reference at all; the self-reference lives in the fourth page
//! *directory*. So the scan finds that directory and then steps back 0x4000 to
//! the pointer table, verifying that the four pointer-table entries really do
//! name the four page directories that follow it. A walker that skipped that
//! verification would report a page directory as a DTB and translate every
//! address one level too low.

// `scan_dtb_candidates` and its siblings take a *slice* of regions so a caller can
// sweep several disjoint windows. Handing them one is ordinary use, not the
// `vec![a..b]`-meant-`a..b` mistake this lint is looking for.
#![allow(clippy::single_range_in_vec_init)]

use std::ops::Range;

use seance_core::io::read_exact_or_fail;
use seance_memory::layer::MemoryLayer;
use seance_memory::translate::{PagingMode, VirtualLayer};

/// The page size every mode here uses for its tables.
pub const PAGE_SIZE: u64 = 4096;

/// `_KUSER_SHARED_DATA` in user space. Fixed in every Windows version, in
/// every process.
pub const KUSER_SHARED_DATA_USER_VA: u64 = 0x7FFE_0000;
/// `_KUSER_SHARED_DATA` in kernel space on a 32-bit Windows.
pub const KUSER_SHARED_DATA_KERNEL_VA_X86: u64 = 0xFFDF_0000;
/// `_KUSER_SHARED_DATA` in kernel space on a 64-bit Windows.
pub const KUSER_SHARED_DATA_KERNEL_VA_X64: u64 = 0xFFFF_F780_0000_0000;

/// Distance from the fourth PAE page directory back to the pointer table above
/// it: four page directories.
const PAE_PDPT_BACKSTEP: u64 = 4 * PAGE_SIZE;
/// Entries in a PAE page-directory-pointer table.
const PAE_PDPT_ENTRIES: usize = 4;
/// Bytes of a PAE page-directory-pointer table. Not a page — the detail that
/// breaks scanners assuming every paging table is 4 KiB.
const PAE_PDPT_BYTES: usize = PAE_PDPT_ENTRIES * 8;

/// A page-table entry's present bit.
const PRESENT: u64 = 1;
/// A page-table entry's large-page bit, which on a top-level table is reserved.
const LARGE_PAGE: u64 = 1 << 7;

/// One physical address that might be a directory table base, with the
/// evidence the scan found for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtbCandidate {
    /// The candidate directory table base, in physical memory.
    pub dtb: u64,
    /// The paging mode whose rules found it. Two modes can both produce a
    /// candidate from one image, and they are not interchangeable: the same
    /// bytes under 32-bit and PAE rules translate the same virtual address to
    /// different physical addresses.
    pub mode: PagingMode,
    /// Index of the self-referential entry, which an examiner can compare
    /// against the fixed indices Windows used before randomisation.
    pub self_ref_index: u64,
    /// The page the self-reference was found in. Equal to `dtb` except on PAE,
    /// where the self-reference is in a page directory 0x4000 above the pointer
    /// table that is the real base.
    pub self_ref_page: u64,
}

/// What one sweep of physical memory found, including what it could not do.
#[derive(Debug, Clone, Default)]
pub struct DtbScanOutcome {
    /// Candidates in ascending physical order.
    pub candidates: Vec<DtbCandidate>,
    /// Pages actually read and examined.
    pub pages_examined: u64,
    /// Pages inside the requested regions that the acquisition does not hold.
    /// Published because "we found no DTB" means something quite different
    /// when half the search region was never captured.
    pub pages_unreadable: u64,
    /// Whether a cap stopped the sweep before it finished the requested
    /// regions. A truncated sweep that found nothing has not shown that there
    /// is nothing to find.
    pub truncated: bool,
}

impl DtbScanOutcome {
    /// Serializable form for the discovery artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "candidates": self.candidates.len(),
            "pages_examined": self.pages_examined,
            "pages_unreadable": self.pages_unreadable,
            "truncated": self.truncated,
        })
    }
}

/// The physical regions Windows has been observed to place its top-level page
/// table in, which is where a sweep should look first.
///
/// A sweep of the whole image is always correct and is what
/// [`scan_dtb_candidates`] does when handed the full range; these regions exist
/// because the top-level table is allocated very early in boot and has landed
/// in the low tens of megabytes on every Windows from XP to 11. The Windows 11
/// answer of `0x1ae000` and the Windows XP answer of `0x39000` are both inside
/// the first region.
pub fn default_scan_regions() -> Vec<Range<u64>> {
    vec![
        // Everything from just above the low 1 MiB to 16 MiB: covers every
        // fixed-index Windows and the randomised Windows 10/11 window.
        0x0003_0000..0x0103_0000,
        // Large-memory systems have been seen with the table higher up.
        0x0103_0000..0x05A0_0000,
    ]
}

/// Per-mode parameters of the self-reference test.
#[derive(Debug, Clone, Copy)]
struct SelfRefRules {
    /// Bytes per paging entry.
    entry_size: usize,
    /// Bits of an entry that hold the frame's physical address.
    frame_mask: u64,
    /// Bits that must be clear in a *present* entry of the scanned table. A set
    /// reserved bit proves the page is not a table of this kind, so the whole
    /// page is rejected rather than searched further.
    reserved_bits: u64,
    /// Lowest acceptable self-reference index.
    index_low: u64,
    /// Highest acceptable self-reference index, inclusive.
    index_high: u64,
}

/// `None` for a mode that has no self-referencing entry to look for. ARM64
/// page tables carry no such entry — the x64 self-reference is a Windows
/// convention on Intel paging — so an ARM64 mode cannot be swept by this
/// test at all, and a caller refuses rather than scanning under borrowed rules.
fn rules_for(mode: PagingMode) -> Option<SelfRefRules> {
    Some(match mode {
        // A 32-bit non-PAE page directory: 1024 four-byte entries, the frame in
        // bits 31:12, and the self-reference at the index that maps the page
        // tables at 0xC0000000.
        PagingMode::Intel32 => SelfRefRules {
            entry_size: 4,
            frame_mask: 0xFFFF_F000,
            reserved_bits: 0,
            index_low: 0x300,
            index_high: 0x300,
        },
        // The fourth PAE page directory. Frames are 40 bits wide, but the mask
        // used to match the self-reference is the one upstream uses, and it is
        // wider than the architectural width only in bits that are zero in any
        // real entry.
        PagingMode::IntelPae => SelfRefRules {
            entry_size: 8,
            frame_mask: 0x0003_FFFF_FFFF_F000,
            reserved_bits: 0,
            index_low: 0x3,
            index_high: 0x3,
        },
        // A PML4, or the PML5 that sits above one under LA57. Bit 7 is reserved
        // at both of those levels, so a present entry with it set proves the
        // page is not a top-level table. The index range is the upper half of
        // the table, where every Windows kernel lives, which covers both the
        // historical 0x1ED and the randomised choices.
        //
        // The two modes share an arm because the test genuinely is the same
        // one: LA57 adds a level to the *walk* and changes nothing about an
        // entry's width, its frame field or which of its bits are reserved, and
        // the upper half of a PML5 is indices 0x100..=0x1FF exactly as it is
        // for a PML4. They are named rather than wildcarded so that a mode
        // added later — one with a different entry width or a different
        // reserved set — has to state its own rules instead of silently
        // inheriting these: a self-reference test run under the wrong rules
        // reports a page that is not a top-level table as a directory table
        // base, and every address translated through it is confidently wrong.
        //
        // The LA57 case is reached now: `MODE_ORDER` offers the five-level mode,
        // and the depth of a Windows image is established the only sound way —
        // by which walk depth proves a kernel out through the candidate, not by
        // any header field. The rules are shared because the self-reference test
        // genuinely is the same at both depths.
        PagingMode::Intel32e | PagingMode::Intel32eLa57 => SelfRefRules {
            entry_size: 8,
            frame_mask: 0x0003_FFFF_FFFF_F000,
            reserved_bits: LARGE_PAGE,
            index_low: 0x100,
            index_high: 0x1FF,
        },
        PagingMode::Arm64(_) => return None,
    })
}

fn entry_at(page: &[u8], offset: usize, entry_size: usize) -> Option<u64> {
    let end = offset.checked_add(entry_size)?;
    let slice = page.get(offset..end)?;
    let mut raw = [0u8; 8];
    raw[..entry_size].copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

/// The index of the single self-referential entry in `page`, if there is
/// exactly one and it is at an acceptable index.
///
/// Returns `None` for zero self-references (the overwhelmingly common case),
/// for more than one (a top-level table refers to itself once by construction;
/// a page with several matching values is a coincidence, not a table), for an
/// index outside the mode's range, and for any page containing a present entry
/// with a reserved bit set.
pub fn self_reference_index(page: &[u8], page_pa: u64, mode: PagingMode) -> Option<u64> {
    if page_pa == 0 {
        // Physical zero would match any entry whose frame bits are all clear,
        // which is most of memory.
        return None;
    }
    let rules = rules_for(mode)?;
    let mut found: Option<u64> = None;
    let mut matches = 0u32;

    let mut offset = 0usize;
    let mut index = 0u64;
    while let Some(entry) = entry_at(page, offset, rules.entry_size) {
        let present = (entry & PRESENT) != 0;
        if present && rules.reserved_bits != 0 && (entry & rules.reserved_bits) != 0 {
            return None;
        }
        if present && (entry & rules.frame_mask) == page_pa {
            matches = matches.saturating_add(1);
            if matches > 1 {
                return None;
            }
            found = Some(index);
        }
        offset = offset.checked_add(rules.entry_size)?;
        index = index.saturating_add(1);
    }

    let index = found?;
    if index < rules.index_low || index > rules.index_high {
        return None;
    }
    Some(index)
}

/// Verify the PAE pointer table that should sit 0x4000 below a self-referential
/// page directory.
///
/// The four entries must name the four page directories immediately above the
/// table, in order. Without this check the scan would report the page directory
/// itself as the base, and every translation would then start one level too
/// low — which does not fail, it just resolves the wrong table.
fn pae_pointer_table(physical: &dyn MemoryLayer, self_ref_page: u64) -> Option<u64> {
    let base = self_ref_page.checked_sub(PAE_PDPT_BACKSTEP)?;
    if base == 0 {
        return None;
    }
    let mut buf = [0u8; PAE_PDPT_BYTES];
    read_exact_or_fail(
        physical.as_data_source(),
        base,
        &mut buf,
        "PAE page directory pointer table",
    )
    .ok()?;
    for slot in 0..PAE_PDPT_ENTRIES {
        let entry = entry_at(&buf, slot * 8, 8)?;
        let expected = base.checked_add((slot as u64 + 1) * PAGE_SIZE)?;
        if (entry & 0xFFFF_FFFF_FFFF_F000) != expected {
            return None;
        }
    }
    Some(base)
}

/// Whether every present entry of a top-level table names a frame the
/// acquisition could actually contain.
///
/// A page of random bytes that happens to contain one self-reference will
/// almost always also contain entries pointing far above the top of physical
/// memory. This rejects those cheaply, before the expensive work of building an
/// address space and hunting for the kernel through it.
///
/// Large-page entries are skipped: their frame field is aligned differently and
/// the point here is a bound, not an exact decode.
fn table_pointers_are_plausible(
    physical: &dyn MemoryLayer,
    table_pa: u64,
    table_bytes: usize,
    mode: PagingMode,
) -> bool {
    let Some(rules) = rules_for(mode) else {
        return false;
    };
    let mut buf = vec![0u8; table_bytes];
    if read_exact_or_fail(
        physical.as_data_source(),
        table_pa,
        &mut buf,
        "top-level paging table",
    )
    .is_err()
    {
        return false;
    }
    let ceiling = physical.max_address();
    let mut present = 0usize;
    let mut above = 0usize;
    let mut offset = 0usize;
    while let Some(entry) = entry_at(&buf, offset, rules.entry_size) {
        if (entry & PRESENT) != 0 && (entry & LARGE_PAGE) == 0 {
            present += 1;
            if entry & rules.frame_mask > ceiling {
                above += 1;
            }
        }
        offset += rules.entry_size;
    }
    // A few tables may sit in memory the acquisition lacks: a capture that stops short of the top of
    // RAM (the M57 "Terry" Vista image ends 1.7 MiB below it, and its real directory names three page
    // tables there) is a valid directory of an unacquired page or two, not a random page. Random bytes
    // name frames above the top far more often than not, so only a directory whose tables are
    // overwhelmingly out of range is refused: more than a tenth of its present entries.
    above * MAX_ABOVE_CEILING_DENOMINATOR <= present
}

/// A directory table base is refused when more than one in this many of its present entries names a
/// frame above the top of the acquisition (see [`table_pointers_are_plausible`]).
const MAX_ABOVE_CEILING_DENOMINATOR: usize = 10;

/// Sweep `regions` of physical memory for directory-table-base candidates under
/// one paging mode.
///
/// Bounded in both directions that matter: `max_pages` caps the work, and
/// `max_candidates` caps the result. Hitting either sets
/// [`DtbScanOutcome::truncated`], because a sweep that stopped early and found
/// nothing has proved nothing.
///
/// Pages the acquisition does not hold are skipped and counted, never treated
/// as pages of zeros — a page of zeros contains no self-reference, so silently
/// substituting one would turn "we do not have this memory" into "we looked and
/// it was not there".
pub fn scan_dtb_candidates(
    physical: &dyn MemoryLayer,
    mode: PagingMode,
    regions: &[Range<u64>],
    max_candidates: usize,
    max_pages: u64,
) -> DtbScanOutcome {
    let mut outcome = DtbScanOutcome::default();
    if max_candidates == 0 || max_pages == 0 {
        outcome.truncated = true;
        return outcome;
    }
    let mut page = vec![0u8; PAGE_SIZE as usize];

    for region in regions {
        let mut address = region.start - (region.start % PAGE_SIZE);
        while address < region.end {
            if outcome
                .pages_examined
                .saturating_add(outcome.pages_unreadable)
                >= max_pages
            {
                outcome.truncated = true;
                return outcome;
            }
            match read_exact_or_fail(
                physical.as_data_source(),
                address,
                &mut page,
                "candidate paging table",
            ) {
                Ok(()) => {
                    outcome.pages_examined = outcome.pages_examined.saturating_add(1);
                    if let Some(index) = self_reference_index(&page, address, mode) {
                        if let Some(candidate) = promote(physical, mode, address, index) {
                            outcome.candidates.push(candidate);
                            if outcome.candidates.len() >= max_candidates {
                                outcome.truncated = true;
                                return outcome;
                            }
                        }
                    }
                }
                Err(_) => {
                    outcome.pages_unreadable = outcome.pages_unreadable.saturating_add(1);
                }
            }
            match address.checked_add(PAGE_SIZE) {
                Some(next) => address = next,
                // The region runs to the top of the address space; there is no
                // next page to examine.
                None => break,
            }
        }
    }
    outcome
}

/// Turn a page with a self-reference into a candidate, applying the per-mode
/// structural checks that follow it.
fn promote(
    physical: &dyn MemoryLayer,
    mode: PagingMode,
    self_ref_page: u64,
    self_ref_index: u64,
) -> Option<DtbCandidate> {
    let (dtb, table_bytes) = match mode {
        PagingMode::IntelPae => (pae_pointer_table(physical, self_ref_page)?, PAE_PDPT_BYTES),
        _ => (self_ref_page, PAGE_SIZE as usize),
    };
    if !table_pointers_are_plausible(physical, dtb, table_bytes, mode) {
        return None;
    }
    Some(DtbCandidate {
        dtb,
        mode,
        self_ref_index,
        self_ref_page,
    })
}

/// How far an address space corroborates that it is a Windows kernel space.
///
/// Ordered from strongest to weakest, and reported rather than collapsed into a
/// boolean, because the weak answers mean genuinely different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KuserCheck {
    /// `_KUSER_SHARED_DATA` translates in both the kernel and the user half of
    /// the space, to the same physical page. That double mapping is a Windows
    /// invariant and is very hard to produce by accident.
    Shared,
    /// Only the kernel-side mapping resolved. Still meaningful — that address
    /// is mapped in no other operating system — but the corroborating half is
    /// missing, which happens when the acquisition did not capture the user
    /// mapping's page tables.
    KernelOnly,
    /// Neither address resolved. Not proof the candidate is wrong: recent
    /// Windows has begun relocating the kernel-side mapping, so this check
    /// abstains rather than rejecting.
    Absent,
}

/// Test an address space against Windows' `_KUSER_SHARED_DATA` double mapping.
///
/// Deliberately offset-free. It compares *translations*, not structure fields,
/// so it works before any symbol table exists — which is exactly when a DTB
/// candidate has to be judged. Reading `NtMajorVersion` at a constant offset
/// would be the alternative, and a constant structure offset is the thing this
/// crate refuses to have.
pub fn kuser_shared_data_check(space: &VirtualLayer, is_64bit: bool) -> KuserCheck {
    let kernel_va = if is_64bit {
        KUSER_SHARED_DATA_KERNEL_VA_X64
    } else {
        KUSER_SHARED_DATA_KERNEL_VA_X86
    };
    let Ok(kernel) = space.translate(kernel_va) else {
        return KuserCheck::Absent;
    };
    match space.translate(KUSER_SHARED_DATA_USER_VA) {
        Ok(user) if user.phys == kernel.phys => KuserCheck::Shared,
        _ => KuserCheck::KernelOnly,
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A hand-built physical image with page tables in it.
    ///
    /// Everything is written by physical address so a test can state exactly
    /// which entry lives where, which is the only way to be sure a walker is
    /// being tested rather than a fixture.
    pub(crate) struct Image {
        pub bytes: Vec<u8>,
    }

    impl Image {
        pub(crate) fn new(size: usize) -> Self {
            Self {
                bytes: vec![0u8; size],
            }
        }

        pub(crate) fn put64(&mut self, table: u64, index: u64, value: u64) {
            let at = (table + index * 8) as usize;
            self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }

        pub(crate) fn put32(&mut self, table: u64, index: u64, value: u32) {
            let at = (table + index * 4) as usize;
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }

        pub(crate) fn write(&mut self, address: u64, data: &[u8]) {
            let at = address as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
        }

        pub(crate) fn layer(self) -> std::sync::Arc<dyn MemoryLayer> {
            use seance_core::data_source::DataSource;
            let source: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(self.bytes),
            );
            std::sync::Arc::new(
                seance_memory::PhysicalLayer::raw(source).expect("a non-empty image"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::Image;
    use super::*;
    use seance_memory::translate::{PagingSpec, PteSemantics};

    const PML4: u64 = 0x1AE000;
    const PDPT: u64 = 0x2000;
    const PD: u64 = 0x3000;
    const PT: u64 = 0x4000;
    const SELF_REF_INDEX: u64 = 0x1ED;

    /// An x64 image whose PML4 self-references at the historical index and
    /// which maps one kernel page.
    fn x64_image() -> Image {
        let mut image = Image::new(0x400000);
        image.put64(PML4, SELF_REF_INDEX, PML4 | 1);
        image.put64(PML4, 0x1F0, PDPT | 1);
        image.put64(PDPT, 0, PD | 1);
        image.put64(PD, 0, PT | 1);
        image.put64(PT, 0, 0x8000 | 1);
        image
    }

    fn scan(layer: &dyn MemoryLayer, mode: PagingMode) -> DtbScanOutcome {
        scan_dtb_candidates(layer, mode, &[0x1000..0x400000], 16, 4096)
    }

    #[test]
    fn a_page_with_exactly_one_self_reference_at_a_valid_index_is_a_candidate() {
        let layer = x64_image().layer();
        let outcome = scan(&*layer, PagingMode::Intel32e);
        assert_eq!(outcome.candidates.len(), 1, "{:?}", outcome.candidates);
        let found = outcome.candidates[0];
        assert_eq!(found.dtb, PML4);
        assert_eq!(found.self_ref_index, SELF_REF_INDEX);
        assert_eq!(found.self_ref_page, PML4);
        assert_eq!(found.mode, PagingMode::Intel32e);
        assert!(!outcome.truncated);
        assert_eq!(outcome.pages_unreadable, 0);
    }

    #[test]
    fn the_five_level_mode_has_rules_of_its_own_rather_than_no_rules() {
        // The defect this closes: `rules_for` matched `PagingMode`
        // exhaustively, so the five-level variant `seance_memory` needed for
        // LA57 could not be added without this crate failing to build — which
        // is why LA57 went unfixed for a wave. The arm has to be a real one:
        // a top-level table is a top-level table whether it is a PML4 or the
        // PML5 above it, so the same self-reference test applies, and a scan
        // run under this mode must find the same candidate rather than nothing.
        let layer = x64_image().layer();
        let outcome = scan(&*layer, PagingMode::Intel32eLa57);
        assert_eq!(outcome.candidates.len(), 1, "{:?}", outcome.candidates);
        assert_eq!(outcome.candidates[0].dtb, PML4);
        assert_eq!(outcome.candidates[0].mode, PagingMode::Intel32eLa57);

        // Identical rules, asserted field by field rather than by sharing an
        // arm, so a later edit to either one shows up here instead of silently
        // giving a five-level scan the four-level index range.
        let four = rules_for(PagingMode::Intel32e).expect("x64 has self-reference rules");
        let five = rules_for(PagingMode::Intel32eLa57).expect("LA57 has self-reference rules");
        assert_eq!(five.entry_size, four.entry_size);
        assert_eq!(five.frame_mask, four.frame_mask);
        assert_eq!(five.reserved_bits, four.reserved_bits);
        assert_eq!(five.index_low, four.index_low);
        assert_eq!(five.index_high, four.index_high);

        // And the rules stay a per-mode statement: the 32-bit modes must not
        // have been folded in with them.
        assert_ne!(
            rules_for(PagingMode::Intel32).expect("rules").entry_size,
            five.entry_size
        );
        assert_ne!(
            rules_for(PagingMode::IntelPae).expect("rules").index_high,
            five.index_high
        );
    }

    /// An ARM64 mode has no self-referencing entry to look for, so it has no
    /// rules and a sweep under it finds nothing rather than a candidate found
    /// under Intel rules (`ROADMAP` §3.8a).
    #[test]
    fn an_arm64_mode_has_no_self_reference_rules_and_sweeps_nothing() {
        use seance_memory::translate::spec::{Arm64Granule, Arm64Regime, Ttbr};
        let regime = Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr1, 48).expect("a 48-bit regime");
        let mode = PagingMode::Arm64(regime);
        assert!(rules_for(mode).is_none());
        let layer = x64_image().layer();
        let outcome = scan(&*layer, mode);
        assert!(outcome.candidates.is_empty(), "{:?}", outcome.candidates);
    }

    #[test]
    fn a_decoy_page_with_two_self_references_is_not_a_candidate() {
        // A real top-level table refers to itself exactly once, by
        // construction. A page of values that happen to match in several places
        // is a coincidence, and accepting it would build an address space out
        // of unrelated bytes that still translates some addresses.
        let mut image = x64_image();
        image.put64(PML4, 0x120, PML4 | 1);
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32e).candidates.is_empty());
    }

    #[test]
    fn a_self_reference_outside_the_kernel_half_of_the_pml4_is_not_a_candidate() {
        let mut image = Image::new(0x400000);
        // Index 0x40 is in the user half; Windows never puts the recursive
        // mapping there.
        image.put64(PML4, 0x40, PML4 | 1);
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32e).candidates.is_empty());
    }

    #[test]
    fn a_self_reference_that_is_not_marked_present_is_not_a_candidate() {
        let mut image = Image::new(0x400000);
        image.put64(PML4, SELF_REF_INDEX, PML4);
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32e).candidates.is_empty());
    }

    #[test]
    fn a_page_with_a_reserved_bit_set_in_a_present_entry_is_not_a_pml4() {
        // Bit 7 is reserved in a PML4 entry. A page containing one is some
        // other kind of structure, whatever else it looks like.
        let mut image = x64_image();
        image.put64(PML4, 0x10, 0x9000 | 1 | (1 << 7));
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32e).candidates.is_empty());
    }

    #[test]
    fn a_table_pointing_above_the_top_of_physical_memory_is_not_a_candidate() {
        let mut image = x64_image();
        // A frame far above a four-megabyte image: no acquisition could hold it.
        image.put64(PML4, 0x10, 0x0000_00FF_0000_0000 | 1);
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32e).candidates.is_empty());
    }

    /// A capture that stops short of the top of RAM still holds the real directory: three of its
    /// 200-odd tables sit in memory that was not acquired (the M57 "Terry" Vista image, `HUNT`-found
    /// 2026-10-22: 535,130,112 bytes of a 512 MiB machine, a directory naming `0x1ff41000`,
    /// `0x1ff51000` and `0x1ff53000` above a layer ending at `0x1fe56fff`). SYNTHETIC: the same
    /// proportions on a 4 MiB image.
    #[test]
    fn a_directory_with_a_few_tables_in_unacquired_top_memory_is_still_a_candidate() {
        let mut image = Image::new(0x400000);
        let pd = 0x39000u64;
        image.put32(pd, 0x300, (pd as u32) | 0x63);
        for i in 0x301..0x3C0u64 {
            image.put32(pd, i, (0x100000 + 0x1000 * (i as u32 - 0x301)) | 0x63);
        }
        // Three tables just above the layer's last byte.
        for (k, i) in [0x3E0u64, 0x3E1, 0x3E2].into_iter().enumerate() {
            image.put32(pd, i, (0x401000 + 0x2000 * k as u32) | 0x63);
        }
        let layer = image.layer();
        let outcome = scan(&*layer, PagingMode::Intel32);
        assert_eq!(outcome.candidates.len(), 1, "{:?}", outcome.candidates);
        assert_eq!(outcome.candidates[0].dtb, pd);
    }

    /// The same directory with most of its tables out of range is refused, as a random page is.
    #[test]
    fn a_directory_most_of_whose_tables_are_out_of_range_is_not_a_candidate() {
        let mut image = Image::new(0x400000);
        let pd = 0x39000u64;
        image.put32(pd, 0x300, (pd as u32) | 0x63);
        for i in 0x301..0x3C0u64 {
            image.put32(pd, i, (0x1000_0000 + 0x1000 * (i as u32 - 0x301)) | 0x63);
        }
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32).candidates.is_empty());
    }

    #[test]
    fn physical_page_zero_is_never_reported_as_a_directory_table_base() {
        // Every all-zero page "self-references" address zero, and an image is
        // mostly all-zero pages.
        let image = Image::new(0x400000);
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::Intel32e).candidates.is_empty());
        assert!(self_reference_index(&[0u8; 4096], 0, PagingMode::Intel32e).is_none());
    }

    #[test]
    fn a_thirty_two_bit_page_directory_self_references_at_index_0x300() {
        let mut image = Image::new(0x400000);
        let pd = 0x39000u64;
        image.put32(pd, 0x300, (pd as u32) | 1);
        let layer = image.layer();
        let outcome = scan(&*layer, PagingMode::Intel32);
        assert_eq!(outcome.candidates.len(), 1);
        assert_eq!(outcome.candidates[0].dtb, pd);
        assert_eq!(outcome.candidates[0].self_ref_index, 0x300);

        // The same bytes read as a PML4 also self-reference, at eight-byte
        // index 0x180, and that is not a defect in the test: a self-reference
        // is a fact about bytes, and the bytes do not say which paging mode
        // wrote them. This is precisely why a candidate from this module is
        // never reported on its own — the caller must translate through it and
        // find the kernel before it becomes evidence.
        let ambiguous = scan(&*layer, PagingMode::Intel32e);
        assert_eq!(ambiguous.candidates.len(), 1);
        assert_eq!(ambiguous.candidates[0].self_ref_index, 0x180);
        assert_eq!(ambiguous.candidates[0].dtb, pd);
    }

    #[test]
    fn a_pae_candidate_is_the_pointer_table_not_the_page_directory_that_found_it() {
        // The self-reference lives in the fourth page directory; the directory
        // table base is the 32-byte pointer table 0x4000 below it. Reporting
        // the directory would start every walk one level too low, which does
        // not fail — it resolves the wrong table.
        let mut image = Image::new(0x400000);
        let pdpt = 0x30000u64;
        let fourth_pd = pdpt + 4 * PAGE_SIZE;
        for slot in 0..4u64 {
            image.put64(pdpt, slot, (pdpt + (slot + 1) * PAGE_SIZE) | 1);
        }
        image.put64(fourth_pd, 3, fourth_pd | 1);
        let layer = image.layer();
        let outcome = scan(&*layer, PagingMode::IntelPae);
        assert_eq!(outcome.candidates.len(), 1, "{:?}", outcome.candidates);
        assert_eq!(outcome.candidates[0].dtb, pdpt);
        assert_eq!(outcome.candidates[0].self_ref_page, fourth_pd);
        assert_eq!(outcome.candidates[0].self_ref_index, 3);
    }

    #[test]
    fn a_pae_self_reference_without_a_matching_pointer_table_is_discarded() {
        let mut image = Image::new(0x400000);
        let fourth_pd = 0x34000u64;
        image.put64(fourth_pd, 3, fourth_pd | 1);
        // The pointer table below it names nothing.
        let layer = image.layer();
        assert!(scan(&*layer, PagingMode::IntelPae).candidates.is_empty());
    }

    #[test]
    fn a_sweep_that_hits_its_page_budget_says_so_rather_than_reporting_nothing_found() {
        let layer = x64_image().layer();
        let outcome =
            scan_dtb_candidates(&*layer, PagingMode::Intel32e, &[0x1000..0x400000], 16, 4);
        assert!(outcome.truncated);
        assert!(outcome.candidates.is_empty());
        assert_eq!(outcome.pages_examined, 4);
        // And the same sweep with a real budget does find it, which proves the
        // budget was what stopped it.
        assert_eq!(scan(&*layer, PagingMode::Intel32e).candidates.len(), 1);
    }

    #[test]
    fn a_sweep_that_hits_its_candidate_budget_is_marked_truncated() {
        let mut image = x64_image();
        // A second, independent self-referential page.
        let other = 0x1B0000u64;
        image.put64(other, 0x1EE, other | 1);
        let layer = image.layer();
        let outcome =
            scan_dtb_candidates(&*layer, PagingMode::Intel32e, &[0x1000..0x400000], 1, 4096);
        assert_eq!(outcome.candidates.len(), 1);
        assert!(outcome.truncated);
    }

    #[test]
    fn a_zero_budget_produces_a_truncated_outcome_rather_than_an_empty_answer() {
        let layer = x64_image().layer();
        assert!(scan_dtb_candidates(&*layer, PagingMode::Intel32e, &[0..0x1000], 0, 10).truncated);
        assert!(scan_dtb_candidates(&*layer, PagingMode::Intel32e, &[0..0x1000], 10, 0).truncated);
    }

    #[test]
    fn the_scan_outcome_serialises_the_facts_a_report_needs() {
        let layer = x64_image().layer();
        let json = scan(&*layer, PagingMode::Intel32e).to_json();
        assert_eq!(json["candidates"], 1);
        assert_eq!(json["truncated"], false);
        assert_eq!(json["pages_unreadable"], 0);
    }

    #[test]
    fn the_kuser_check_reports_a_shared_mapping_a_kernel_only_one_and_neither() {
        // Kernel and user halves mapped to the same frame: the Windows
        // invariant, and the strongest offset-free corroboration available
        // before symbols exist.
        let mut image = Image::new(0x400000);
        image.put64(PML4, SELF_REF_INDEX, PML4 | 1);
        // Kernel side: 0xFFFFF78000000000 -> PML4[0x1EF], PDPT[0], PD[0], PT[0].
        image.put64(PML4, 0x1EF, PDPT | 1);
        image.put64(PDPT, 0, PD | 1);
        image.put64(PD, 0, PT | 1);
        image.put64(PT, 0, 0x8000 | 1);
        // User side: 0x7FFE0000 -> PML4[0], PDPT[1], PD[0x1FF], PT[0x1E0].
        image.put64(PML4, 0, 0x5000 | 1);
        image.put64(0x5000, 1, 0x6000 | 1);
        image.put64(0x6000, 0x1FF, 0x7000 | 1);
        image.put64(0x7000, 0x1E0, 0x8000 | 1);
        let layer = image.layer();
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        let space = VirtualLayer::new(layer.clone(), PML4, spec).expect("a usable base");
        assert_eq!(kuser_shared_data_check(&space, true), KuserCheck::Shared);

        // Remove the user mapping: the check weakens rather than rejecting.
        let mut image = Image::new(0x400000);
        image.put64(PML4, SELF_REF_INDEX, PML4 | 1);
        image.put64(PML4, 0x1EF, PDPT | 1);
        image.put64(PDPT, 0, PD | 1);
        image.put64(PD, 0, PT | 1);
        image.put64(PT, 0, 0x8000 | 1);
        let layer = image.layer();
        let space = VirtualLayer::new(layer, PML4, spec).expect("a usable base");
        assert_eq!(
            kuser_shared_data_check(&space, true),
            KuserCheck::KernelOnly
        );

        // Neither side mapped: the check abstains. It must not reject, because
        // recent Windows has begun relocating the kernel-side mapping.
        let mut image = Image::new(0x400000);
        image.put64(PML4, SELF_REF_INDEX, PML4 | 1);
        let layer = image.layer();
        let space = VirtualLayer::new(layer, PML4, spec).expect("a usable base");
        assert_eq!(kuser_shared_data_check(&space, true), KuserCheck::Absent);
    }

    #[test]
    fn pages_the_acquisition_does_not_hold_are_counted_not_treated_as_zeros() {
        // A region above the end of a small image. Every page is unreadable,
        // and the sweep must say so: "we found no DTB" means something quite
        // different when the search region was never captured.
        let layer = Image::new(0x10000).layer();
        let outcome =
            scan_dtb_candidates(&*layer, PagingMode::Intel32e, &[0x20000..0x30000], 16, 4096);
        assert_eq!(outcome.pages_examined, 0);
        assert_eq!(outcome.pages_unreadable, 16);
        assert!(outcome.candidates.is_empty());
    }
}
