//! Resolving a process's swapped-out pages against an attached swap area.
//!
//! When the kernel writes an anonymous page out to swap, it leaves a
//! `swp_entry_t` in the page-table entry that governed it, and the page's
//! contents move to a slot in a swap area on disk. The memory capture alone
//! cannot read that page — the bytes are not in it — but if the examiner has
//! also acquired the swap area, the two together can.
//!
//! # What this does, and the two facts it will not assume
//!
//! Two things stand between a `swp_entry_t` and the bytes, and neither is in the
//! PTE:
//!
//! 1. **The bit layout.** On x86-64 it changed once — the L1TF mitigation (4.19,
//!    backported below it) began storing the offset inverted and moved the type
//!    to the top bits. A single PTE does not say which layout wrote it.
//! 2. **Which area, and whether this is even a swap-file entry.** The same
//!    encoding also carries migration entries, hardware-poison markers and
//!    device-private entries, none of which name a location on disk.
//!
//! Rather than pick a layout from the kernel version and hope, this settles both
//! against the evidence the examiner supplied. Each candidate layout is decoded
//! and kept only if its `swp_type` names an *attached* area and its `swp_offset`
//! lands **inside that area's bounds**. The L1TF inversion makes the wrong
//! layout produce a wildly out-of-range slot, so the bounds are a real
//! discriminator — the same principle the page-table proof uses to choose a DTB:
//! the reading that *works* against independent evidence is the one this capture
//! used. When more than one candidate survives, nothing is read and the
//! ambiguity is reported; when none does, the entry is left as an unresolved
//! swap-family entry rather than forced to name a page.
//!
//! # Acquiring the swap area
//!
//! See [`seance_memory::formats::linux_swap`] — a swap *file* copied through the
//! filesystem reads back as zeros, and must be acquired from its physical
//! extents off the block device. Such an area still attaches, and still
//! corroborates the entries that name it; what it cannot do is answer for their
//! contents, so a slot that reads as zeros in an area whose sampled body reads
//! as zeros throughout is reported as [`SwapResolution::BodyReadsAsZeros`] and
//! never as a page recovered from swap.

use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;
use seance_memory::formats::linux_swap::{
    decode_x86_64, LinuxSwapHeader, SwapBodySurvey, SwapHeaderError, SwpEntry, X86SwapLayout,
    BODY_READS_AS_ZEROS,
};
use seance_memory::translate::{PagingMode, TranslateError, VirtualLayer};
use std::sync::Arc;

use crate::profile::LinuxProfile;

/// The candidate `swp_entry_t` layouts to try for a proven architecture.
///
/// x86-64 (a four- or five-level Intel walk) is the only architecture this build
/// decodes, and it has exactly the two layouts. Any other paging mode returns an
/// empty slice, so a swapped page on it is left unresolved rather than decoded
/// with bits that are not its.
pub fn layouts_for(profile: &LinuxProfile) -> &'static [X86SwapLayout] {
    match profile.paging.mode() {
        PagingMode::Intel32e | PagingMode::Intel32eLa57 => {
            &[X86SwapLayout::PostL1tf, X86SwapLayout::PreL1tf]
        }
        _ => &[],
    }
}

/// A swap area the examiner attached, and the index it answers to.
pub struct AttachedSwapArea {
    /// The parsed header — dimensions and identity.
    pub header: LinuxSwapHeader,
    /// The area's bytes, page 0 being the header.
    source: Arc<dyn DataSource>,
    /// The `swp_type` this area answers to — its position in `swapon` order,
    /// `0` for the first area. A `swp_entry_t` names its area by this index and
    /// nothing in the area's own header records it, so the examiner supplies it.
    pub index: u8,
    /// A human label for the area (a path, a device name), for the record.
    pub label: String,
    /// What a bounded sample of the body held when the area was attached.
    ///
    /// Surveyed once, here, rather than per page: it is a property of the
    /// acquisition, it costs a fixed handful of reads, and a page-by-page answer
    /// would ask the same question thousands of times over. See
    /// [`Self::body_reads_as_all_zero`] for what it is for.
    pub body: SwapBodySurvey,
}

impl AttachedSwapArea {
    /// Attach an area from its bytes, reading and validating its header.
    pub fn open(
        source: Arc<dyn DataSource>,
        index: u8,
        label: impl Into<String>,
    ) -> Result<Self, SwapHeaderError> {
        let mut head = vec![0u8; 65536.min(source.size() as usize).max(4096)];
        // A short read still lets the header parse decide; parse reads only the
        // first page it needs.
        let _ = source.read_at(0, &mut head);
        let header = LinuxSwapHeader::parse(&head, None)?;
        let body = header.survey_body(source.as_ref());
        Ok(Self {
            header,
            source,
            index,
            label: label.into(),
            body,
        })
    }

    /// Whether this area's body was sampled and held nothing but zeros.
    ///
    /// An area that reads this way is attached all the same — every page whose
    /// entry names it is still located, and refusing the attachment would make
    /// those pages report as belonging to an area nobody attached, which is a
    /// worse account of the evidence than the truth. What changes is what may be
    /// claimed about a slot in it that reads as zeros: not that the kernel
    /// swapped out a page of zeros, only that there are no contents to publish.
    /// See [`SwapResolution::BodyReadsAsZeros`], which is where the two halves of
    /// that judgement are put together.
    pub fn body_reads_as_all_zero(&self) -> bool {
        self.body.reads_as_all_zero()
    }

    /// Read the page at swap slot `slot`, or `None` if the slot is out of the
    /// area's bounds or its bytes were not acquired.
    fn read_slot(&self, slot: u64) -> Option<Vec<u8>> {
        let at = self.header.slot_byte_offset(slot)?;
        let mut page = vec![0u8; self.header.page_size];
        read_exact_or_fail(self.source.as_ref(), at, &mut page, "a swapped page")
            .ok()
            .map(|_| page)
    }
}

/// One layout that decoded an entry to a slot inside an attached area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corroborated {
    pub layout: X86SwapLayout,
    pub swap_type: u8,
    pub slot: u64,
}

/// The outcome of resolving one virtual address that a `swp_entry_t` governed.
pub enum SwapResolution {
    /// The address was resident after all — not a swap case.
    Resident,
    /// Exactly one layout decoded the entry into an attached area's bounds, so
    /// the location is corroborated and the page was read.
    Recovered {
        /// Which layout the evidence selected.
        layout: X86SwapLayout,
        /// The swap area index the entry named.
        swap_type: u8,
        /// The slot within that area.
        slot: u64,
        /// The area's label and UUID, for the record.
        area_label: String,
        area_uuid: Option<String>,
        /// The recovered page.
        bytes: Vec<u8>,
    },
    /// More than one layout landed inside an attached area. Nothing is read: to
    /// pick one would be to guess exactly what this refuses to guess.
    Ambiguous {
        entry: u64,
        candidates: Vec<Corroborated>,
    },
    /// A `swp_entry_t`, but no attached area corroborates it: the area it names
    /// was not attached, or this is a migration / hardware-poison /
    /// device-private entry, which share the encoding and name no disk location.
    Unattached { entry: u64 },
    /// Exactly one layout decoded the entry into an *attached* area's bounds — so
    /// the location IS corroborated — but that slot's bytes were not acquired, so
    /// there was nothing to read. Distinct from [`Self::Unattached`] because the
    /// right area is present and this is a genuine swap location: the gap is the
    /// acquisition's, not the examiner's, and telling them to attach an area they
    /// already attached would be wrong.
    SlotUnread {
        layout: X86SwapLayout,
        swap_type: u8,
        slot: u64,
        area_label: String,
    },
    /// Exactly one layout decoded the entry into an *attached* area's bounds, the
    /// slot itself reads as zeros, and so does every other body page sampled
    /// across that area.
    ///
    /// The sibling of [`Self::SlotUnread`], and separated from it for the same
    /// reason it is separated from [`Self::Unattached`]: the location is
    /// corroborated and the examiner has done nothing wrong that attaching
    /// something else would fix. Here the slot's bytes *were* read — they are
    /// zeros, as is every other body page sampled across the area — and handing
    /// those back as [`Self::Recovered`] would report a page recovered from swap
    /// when the acquisition may hold no swapped page at all. That is the
    /// acquisition trap `seance_memory::formats::linux_swap` documents, and the
    /// remedy is in [`BODY_READS_AS_ZEROS`].
    ///
    /// Both conditions are required, and the second is what keeps the first from
    /// eating good evidence: a slot that holds real bytes is recovered however
    /// the area's survey came out. A lightly used area that really was acquired
    /// off the block device samples as zeros too, and on such an area this
    /// answer means what it says and no more — this page's slot is empty, and
    /// the acquisition is worth checking before that is read as "the kernel
    /// swapped out a page of zeros".
    BodyReadsAsZeros {
        layout: X86SwapLayout,
        swap_type: u8,
        slot: u64,
        area_label: String,
        /// The sample the verdict rests on, so the note can say how much of the
        /// body was looked at rather than asserting emptiness bare.
        survey: SwapBodySurvey,
    },
    /// The address is not present for a reason other than a swap entry.
    NotSwap { reason: String },
}

impl SwapResolution {
    /// One sentence a report can carry.
    pub fn note(&self) -> String {
        match self {
            SwapResolution::Resident => "the page was resident in the capture".to_string(),
            SwapResolution::Recovered {
                layout,
                swap_type,
                slot,
                area_label,
                ..
            } => format!(
                "recovered from swap area {swap_type} ('{area_label}') slot {slot}, read with the \
                 {layout:?} x86-64 swap-entry layout, which is the one that decoded the entry \
                 inside the attached area's bounds"
            ),
            SwapResolution::Ambiguous { candidates, .. } => format!(
                "the swap entry decoded into an attached area under {} different layouts, so no \
                 single location is proven and none was read",
                candidates.len()
            ),
            SwapResolution::Unattached { .. } => "the page's contents are in a swap area that is \
                 not attached, or the entry is a migration / poison / device-private marker that \
                 names no swap location"
                .to_string(),
            SwapResolution::SlotUnread {
                layout,
                swap_type,
                slot,
                area_label,
            } => format!(
                "the page is in swap area {swap_type} ('{area_label}') slot {slot} (decoded with \
                 the {layout:?} x86-64 layout, corroborated by that area's bounds), but that \
                 slot's bytes were not in the acquired swap area, so there was nothing to read"
            ),
            SwapResolution::BodyReadsAsZeros {
                layout,
                swap_type,
                slot,
                area_label,
                survey,
            } => format!(
                "the page is in swap area {swap_type} ('{area_label}') slot {slot} (decoded with \
                 the {layout:?} x86-64 layout, corroborated by that area's bounds), but no \
                 contents are published for it: that slot reads as zeros, and so did all {} of \
                 the body pages sampled across the rest of that area. {BODY_READS_AS_ZEROS}",
                survey.pages_read
            ),
            SwapResolution::NotSwap { reason } => reason.clone(),
        }
    }
}

/// Resolve the virtual address `va` in `process`, reading its page from swap when
/// the evidence corroborates where it went.
///
/// `layouts` are the candidate encodings to try — [`layouts_for`] returns the
/// right set for a proven architecture and an empty slice for one this build
/// does not decode.
pub fn resolve_page(
    process: &VirtualLayer,
    va: u64,
    areas: &[AttachedSwapArea],
    layouts: &[X86SwapLayout],
) -> SwapResolution {
    let entry = match process.translate(va) {
        Ok(_) => return SwapResolution::Resident,
        Err(TranslateError::LinuxSwapEntry { entry, .. }) => entry,
        Err(other) => {
            return SwapResolution::NotSwap {
                reason: other.to_string(),
            }
        }
    };

    // Decode under each candidate layout and keep those whose (area, slot) lands
    // inside an attached area. De-duplicate on the resolved byte location so the
    // two layouts agreeing on the same slot — which cannot happen through the
    // inversion, but must not be double-counted if it did — is one candidate.
    let mut corroborated: Vec<(Corroborated, usize, u64)> = Vec::new();
    for &layout in layouts {
        let SwpEntry { swap_type, offset } = decode_x86_64(entry, layout);
        for (i, area) in areas.iter().enumerate() {
            if area.index != swap_type {
                continue;
            }
            let Some(byte) = area.header.slot_byte_offset(offset) else {
                continue;
            };
            let already = corroborated.iter().any(|(_, ai, b)| *ai == i && *b == byte);
            if !already {
                corroborated.push((
                    Corroborated {
                        layout,
                        swap_type,
                        slot: offset,
                    },
                    i,
                    byte,
                ));
            }
        }
    }

    match corroborated.as_slice() {
        [] => SwapResolution::Unattached { entry },
        [(only, area_index, _)] => {
            let area = &areas[*area_index];
            match area.read_slot(only.slot) {
                // Two conditions, and both are needed. The area-level one is the
                // signature: a body that reads as zeros throughout is what a swap
                // file copied through the filesystem looks like. The page-level
                // one is what stops the guard eating good evidence — the
                // ground-truth capture the gated `swap_real_capture_test` runs
                // against is a real acquisition off a block device whose survey
                // finds data in exactly one of the sixty-four pages it samples,
                // because that machine had only 16 MiB swapped out of a much
                // larger area. A
                // sample landing a slot to either side would have condemned
                // seventy-one pages that read back byte-exact against their
                // markers. So the survey decides nothing on its own: a slot that
                // actually holds bytes is recovered whatever the survey found,
                // and only a slot that is *itself* zeros, in an area that
                // sampled as zeros throughout, is refused.
                Some(bytes)
                    if area.body_reads_as_all_zero() && bytes.iter().all(|byte| *byte == 0) =>
                {
                    SwapResolution::BodyReadsAsZeros {
                        layout: only.layout,
                        swap_type: only.swap_type,
                        slot: only.slot,
                        area_label: area.label.clone(),
                        survey: area.body,
                    }
                }
                Some(bytes) => SwapResolution::Recovered {
                    layout: only.layout,
                    swap_type: only.swap_type,
                    slot: only.slot,
                    area_label: area.label.clone(),
                    area_uuid: area.header.uuid_string(),
                    bytes,
                },
                // Corroborated — the right area is attached and the slot is in
                // bounds — but the slot's bytes were not acquired. That is a
                // different finding from "no area corroborates this entry", so it
                // must not be collapsed into `Unattached`, whose note would tell
                // the examiner to attach an area they already attached.
                None => SwapResolution::SlotUnread {
                    layout: only.layout,
                    swap_type: only.swap_type,
                    slot: only.slot,
                    area_label: area.label.clone(),
                },
            }
        }
        many => SwapResolution::Ambiguous {
            entry,
            candidates: many.iter().map(|(c, _, _)| c.clone()).collect(),
        },
    }
}
