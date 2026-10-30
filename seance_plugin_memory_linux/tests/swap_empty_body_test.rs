//! A swap area whose header parses and whose body reads as zeros.
//!
//! This is the acquisition trap `seance_memory::formats::linux_swap` documents:
//! `cp /swapfile` copies the `mkswap`-written header page faithfully and returns
//! zeros for every page after it, because the swapped pages live in fallocate'd
//! extents the filesystem still records as unwritten. The area attaches, a
//! `swp_entry_t` decodes, its slot lands inside the area's bounds, and a page of
//! zeros comes back — which must never be reported as a page recovered from
//! swap.
//!
//! Both halves are proved here from bytes written by the test: an area whose
//! body is zeros must not yield a recovery, and an otherwise identical area with
//! bytes in its slots must still yield one, byte-exactly. A guard that quietly
//! downgraded good evidence would be worse than the defect it closes.
//!
//! The area's body has three states and not two — it holds data, it reads as
//! zeros, or it could not be read at all — and the last of them is here too,
//! because it is the one a record with words for only two files under whichever
//! of them is wrong for it.

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::formats::linux_swap::X86SwapLayout;
use seance_memory::translate::{PagingMode, PagingSpec, PteSemantics, VirtualLayer};
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::profile::SwapAreaBody;
use seance_plugin_memory_linux::swap::{self, AttachedSwapArea, SwapResolution};
use std::sync::Arc;

/// The candidate layouts an x86-64 profile would supply. Both are tried here for
/// the same reason production tries both: the area's bounds, not a kernel
/// version, decide which one wrote the entry.
const X86_64_LAYOUTS: &[X86SwapLayout] = &[X86SwapLayout::PostL1tf, X86SwapLayout::PreL1tf];

/// Page size of both the synthetic capture and the synthetic swap area.
const PAGE: u64 = 4096;
/// Physical addresses of the four page tables the walk reads, in walk order.
const PML4: u64 = 0x1000;
const PDPT: u64 = 0x2000;
const PD: u64 = 0x3000;
const PT: u64 = 0x4000;
/// The virtual address whose PTE is a `swp_entry_t`.
const SWAPPED_VA: u64 = 0x0000_0000_0040_1000;
/// The slot that entry names within swap area 0.
const SLOT: u64 = 300;
/// A slot the body survey's spread does not land on, for the case below where a
/// real acquisition's only data sits between two samples.
const SLOT_BETWEEN_SAMPLES: u64 = 305;
/// Highest usable page index of the synthetic area — a 2 MiB area.
const LAST_PAGE: u32 = 511;

/// Encode a `swp_entry_t` the way the kernel does since the L1TF mitigation
/// (`__swp_entry` in `arch/x86/include/asm/pgtable_64.h`): the offset inverted
/// and shifted down, the type in the top five bits.
fn post_l1tf_entry(swap_type: u64, slot: u64) -> u64 {
    ((!slot << 14) >> 5) | (swap_type << 59)
}

/// A physical image holding one four-level page table whose leaf PTE is a swap
/// entry, so a translation of [`SWAPPED_VA`] hands the resolver a real entry
/// read out of real bytes rather than a value handed to it.
fn capture_with_a_swapped_page(slot: u64) -> Arc<dyn MemoryLayer> {
    let mut bytes = vec![0u8; 0x10_0000];
    let mut entry = |table: u64, index: u64, value: u64| {
        let at = (table + index * 8) as usize;
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    // Present + writable table pointers down to the PT, then the swap entry.
    entry(PML4, (SWAPPED_VA >> 39) & 0x1FF, PDPT | 0x3);
    entry(PDPT, (SWAPPED_VA >> 30) & 0x1FF, PD | 0x3);
    entry(PD, (SWAPPED_VA >> 21) & 0x1FF, PT | 0x3);
    entry(PT, (SWAPPED_VA >> 12) & 0x1FF, post_l1tf_entry(0, slot));
    Arc::new(PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes))).expect("an image"))
}

/// The address space that capture describes, under Linux PTE semantics — which
/// is what tells a swap-family entry apart from an address never mapped.
fn address_space(physical: &Arc<dyn MemoryLayer>) -> VirtualLayer {
    VirtualLayer::new(
        Arc::clone(physical),
        PML4,
        PagingSpec::new(PagingMode::Intel32e, PteSemantics::Linux),
    )
    .expect("a virtual layer")
}

/// A swap area: one `mkswap` header page followed by `LAST_PAGE` body pages.
///
/// `populate` names slots to fill with a marker, so the same builder produces
/// both the trap (nothing populated: the body reads as zeros) and the control
/// (slots populated: a real acquisition off the block device).
fn swap_area(populate: &[u64]) -> Arc<dyn DataSource> {
    let page = PAGE as usize;
    let mut bytes = vec![0u8; (LAST_PAGE as usize + 1) * page];
    bytes[1024..1028].copy_from_slice(&1u32.to_le_bytes()); // version
    bytes[1028..1032].copy_from_slice(&LAST_PAGE.to_le_bytes());
    bytes[1036..1052].copy_from_slice(&[0x5Au8; 16]); // uuid
    bytes[page - 10..page].copy_from_slice(b"SWAPSPACE2");
    for slot in populate {
        let at = (*slot * PAGE) as usize;
        bytes[at..at + 8].copy_from_slice(b"SWAPMARK");
        bytes[at + 8..at + 16].copy_from_slice(&slot.to_le_bytes());
    }
    Arc::new(ByteSliceDataSource::new(bytes))
}

/// **The defect.** An area copied through the filesystem parses, attaches, and
/// bounds-corroborates the entry — and every byte it would hand back is a zero
/// the acquisition invented. Reporting that as a page recovered from swap tells
/// the examiner a page was read when nothing was.
#[test]
fn a_page_in_an_all_zero_swap_body_is_never_reported_as_recovered() {
    let physical = capture_with_a_swapped_page(SLOT);
    let space = address_space(&physical);
    let area = AttachedSwapArea::open(swap_area(&[]), 0, "swapfile-copied-through-the-fs")
        .expect("the header page copies faithfully, so this parses");

    let resolution = swap::resolve_page(&space, SWAPPED_VA, &[area], X86_64_LAYOUTS);

    match &resolution {
        SwapResolution::Recovered { slot, bytes, .. } => {
            assert!(
                bytes.iter().any(|b| *b != 0),
                "slot {slot} was reported as recovered from swap, but every byte of it is a \
                 zero the acquisition invented: the area's body was never acquired"
            );
            panic!("an area with no body must not yield a recovery at all");
        }
        SwapResolution::BodyReadsAsZeros {
            swap_type,
            slot,
            survey,
            ..
        } => {
            // The location is still stated — the entry decoded and the area is
            // attached — and the sample the verdict rests on is published with
            // it rather than the emptiness being asserted bare.
            assert_eq!((*swap_type, *slot), (0, SLOT));
            assert!(survey.pages_read > 1, "more than one page was looked at");
            assert_eq!(survey.pages_with_data, 0);
        }
        other => panic!("expected the all-zero-body finding, got: {}", other.note()),
    }
    let note = resolution.note();
    assert!(
        note.contains("zero"),
        "the note must say the area's body reads as zeros: {note}"
    );
    assert!(
        note.contains("filefrag") || note.contains("block device"),
        "the note must name the remedy — acquire the area from the block device: {note}"
    );
    assert!(
        note.contains("300"),
        "the slot is still known and must still be reported, so an examiner who \
         re-acquires the area knows where to look: {note}"
    );
}

/// **The control, and it matters as much.** The same area with bytes in its
/// slots is a real acquisition, and its pages must still resolve byte-exactly.
#[test]
fn a_populated_swap_body_still_recovers_its_pages_byte_exactly() {
    let physical = capture_with_a_swapped_page(SLOT);
    let space = address_space(&physical);
    let area =
        AttachedSwapArea::open(swap_area(&[SLOT]), 0, "swap-area.raw").expect("valid swap header");

    match swap::resolve_page(&space, SWAPPED_VA, &[area], X86_64_LAYOUTS) {
        SwapResolution::Recovered {
            swap_type,
            slot,
            bytes,
            ..
        } => {
            assert_eq!((swap_type, slot), (0, SLOT));
            let mut want = b"SWAPMARK".to_vec();
            want.extend_from_slice(&SLOT.to_le_bytes());
            assert_eq!(&bytes[..16], &want[..], "the recovered page's own bytes");
        }
        other => panic!("a populated area must still recover: {}", other.note()),
    }
}

/// A body that could not be read **at all** is a different finding, and the
/// existing one covers it. Nothing was observed, so nothing may be concluded
/// about what the area holds — only that this slot's bytes are not here.
#[test]
fn a_truncated_area_still_reports_its_slot_as_unread_rather_than_empty() {
    let physical = capture_with_a_swapped_page(SLOT);
    let space = address_space(&physical);
    // The header page and nothing behind it, as a half-finished copy leaves it.
    let mut bytes = Vec::new();
    let full = swap_area(&[]);
    bytes.resize(PAGE as usize, 0);
    full.read_at(0, &mut bytes).expect("read the header page");
    let area = AttachedSwapArea::open(
        Arc::new(ByteSliceDataSource::new(bytes)),
        0,
        "truncated.raw",
    )
    .expect("the header still parses");

    match swap::resolve_page(&space, SWAPPED_VA, &[area], X86_64_LAYOUTS) {
        SwapResolution::SlotUnread { slot, .. } => assert_eq!(slot, SLOT),
        other => panic!("expected the slot to read as unacquired: {}", other.note()),
    }
}

/// **The lesson the real corpus taught.** A swap area acquired correctly off the
/// block device, but lightly used, can have a body sample find nothing: the
/// ground-truth capture that was at `~/linux-lab` (deleted 2026-10-26) held 16 MiB of swapped
/// pages in a much larger area, and its survey finds data in exactly one of the
/// sixty-four pages sampled. Land the sample one slot to either side and a
/// blind area-level verdict would have thrown away seventy-one pages that were
/// recovered and matched their markers byte for byte.
///
/// So the area survey is a necessary condition and not a sufficient one: a page
/// whose slot actually holds bytes is recovered whatever the survey found.
#[test]
fn a_page_whose_slot_holds_bytes_is_recovered_even_when_the_survey_found_none() {
    let physical = capture_with_a_swapped_page(SLOT_BETWEEN_SAMPLES);
    let space = address_space(&physical);
    let area = AttachedSwapArea::open(
        swap_area(&[SLOT_BETWEEN_SAMPLES]),
        0,
        "lightly-used-but-properly-acquired",
    )
    .expect("valid swap header");
    assert!(
        area.body_reads_as_all_zero(),
        "this fixture is only meaningful while the survey misses the one populated slot: {:?}",
        area.body
    );

    match swap::resolve_page(&space, SWAPPED_VA, &[area], X86_64_LAYOUTS) {
        SwapResolution::Recovered { slot, bytes, .. } => {
            let mut want = b"SWAPMARK".to_vec();
            want.extend_from_slice(&SLOT_BETWEEN_SAMPLES.to_le_bytes());
            assert_eq!(slot, SLOT_BETWEEN_SAMPLES);
            assert_eq!(&bytes[..16], &want[..], "the page's own bytes are there");
        }
        other => panic!(
            "a slot holding real bytes must still be recovered: {}",
            other.note()
        ),
    }
}

/// **The same defect, on the path production actually takes.**
///
/// `swap::resolve_page` is the standalone resolver, used where a stage wants the
/// resolution *reported*. But an ordinary stage does not call it: `space.rs`
/// attaches the areas to the address space with `VirtualLayer::with_swap`, and a
/// read of a swapped virtual address goes through `linux_swap_run` inside the
/// layer. That is a second decode-and-corroborate path, and a guard on the first
/// leaves the one every stage uses untouched — so `proc_maps`, the environment
/// stage and anything else reading process memory would still be handed 4,096
/// zeros the acquisition invented, presented as the process's own bytes and
/// tagged `swap` as though they had been recovered.
///
/// The layer's answer for a page it will not vouch for is a hole, which the
/// address space already reports as `swapped_out`. That is the honest one.
#[test]
fn reading_a_swapped_address_through_the_layer_returns_a_hole_not_invented_zeros() {
    let physical = capture_with_a_swapped_page(SLOT);
    let space = address_space(&physical).with_swap(vec![seance_memory::translate::SwapFile {
        index: 0,
        label: "swapfile-copied-through-the-fs".to_string(),
        source: swap_area(&[]),
    }]);

    let mut got = [0xAAu8; 16];
    let read = space.as_data_source().read_at(SWAPPED_VA, &mut got);

    assert!(
        matches!(read, Err(_) | Ok(0)),
        "the layer answered a swapped address out of an area whose body was never \
         acquired: {read:?}, bytes {got:?}. Every one of those bytes is a zero the \
         acquisition invented, and the layer would present them as the process's memory."
    );
    assert_eq!(
        got, [0xAAu8; 16],
        "the buffer must be left as the caller set it, not overwritten with zeros"
    );
}

/// And the guard must not cost a real acquisition its evidence. The ground-truth
/// corpus finds data in only one of sixty-four sampled pages, so an area-level
/// verdict alone would sit one unlucky sample away from discarding every real
/// page. A slot that holds bytes is answered whatever the survey found.
#[test]
fn a_populated_slot_still_reads_through_the_layer_even_when_the_survey_found_none() {
    let physical = capture_with_a_swapped_page(SLOT_BETWEEN_SAMPLES);
    let space = address_space(&physical).with_swap(vec![seance_memory::translate::SwapFile {
        index: 0,
        label: "block-device-acquisition".to_string(),
        source: swap_area(&[SLOT_BETWEEN_SAMPLES]),
    }]);

    let mut got = [0u8; 16];
    let n = space
        .as_data_source()
        .read_at(SWAPPED_VA, &mut got)
        .expect("a slot holding real bytes must still be readable through the layer");

    assert_eq!(n, 16, "the whole read must be served from the swap area");
    assert_eq!(&got[..8], b"SWAPMARK");
    assert_eq!(
        u64::from_le_bytes(got[8..16].try_into().unwrap()),
        SLOT_BETWEEN_SAMPLES,
        "the bytes must come from the slot the entry named, not from a neighbour"
    );
}

/// An attachment that is not a Linux swap area at all: the bytes of something
/// else entirely, with no `mkswap` header anywhere in them.
///
/// A Windows `pagefile.sys` handed to the Linux tier reads like this, and so
/// does a whole-disk image attached in place of the partition inside it, and so
/// does a mistyped path that lands on a readable file. Filled with a repeating
/// pattern rather than zeros so nothing here can pass for an empty body: the
/// point is that these bytes are not a swap area, not that they are blank.
fn not_a_swap_area_at_all() -> Arc<dyn DataSource> {
    let bytes: Vec<u8> = (0..(LAST_PAGE as usize + 1) * PAGE as usize)
        .map(|i| (i % 251) as u8 | 1)
        .collect();
    Arc::new(ByteSliceDataSource::new(bytes))
}

/// **The attachment nothing can ever be read through.** `SEANCE_SWAPFILES`
/// attaches whatever path it is given, so an examiner can attach a Windows
/// pagefile, a disk image with a partition-table prefix, or a mistyped path.
/// None of them is a Linux swap area, and the layer resolves not one page
/// through them — so the run must be told at attach time, and the profile
/// record must not go on to claim swapped pages were read from an attachment
/// like this.
#[test]
fn an_attachment_that_is_not_a_swap_area_is_reported_as_such_and_reads_nothing() {
    // The label carries a path in front of the file name on purpose. The
    // assertion below is that the warning NAMES this attachment, and
    // `NOT_A_SWAP_AREA` lists `pagefile.sys` itself among the ordinary causes —
    // so a fixture called exactly that would satisfy `contains` whether or not
    // the attachment was ever named. The guard keeps that true as the sentence
    // is edited.
    let label = "/mnt/evidence/pagefile.sys";
    assert!(
        !seance_plugin_memory_linux::profile::NOT_A_SWAP_AREA.contains(label),
        "the fixture label is already in the sentence, so naming it proves nothing"
    );
    let file = seance_memory::translate::SwapFile {
        index: 3,
        label: label.to_string(),
        source: not_a_swap_area_at_all(),
    };
    let area = SwapAreaBody::survey(&file);
    assert!(
        !area.header_parsed,
        "these bytes carry no mkswap header, and the record has to say so rather \
         than leave an empty survey to be read as an area in good order"
    );
    // The control, from the same builder: a real area does parse, so the flag is
    // reporting the parse and not simply refusing everything.
    assert!(
        SwapAreaBody::survey(&seance_memory::translate::SwapFile {
            index: 0,
            label: "swap-area.raw".to_string(),
            source: swap_area(&[SLOT]),
        })
        .header_parsed,
        "a real mkswap-written area must still parse"
    );

    let warning = area
        .attach_warning()
        .expect("an attachment that is not a swap area is worth saying out loud");
    assert!(warning.contains(label), "name the attachment: {warning}");
    assert!(
        warning.contains("index 3"),
        "and the index it was attached under, which is what tells two \
         identically named attachments apart: {warning}"
    );

    // And the reason it must be said: the layer resolves nothing through it.
    let physical = capture_with_a_swapped_page(SLOT);
    let space = address_space(&physical).with_swap(vec![file]);
    let mut got = [0xAAu8; 16];
    let read = space.as_data_source().read_at(SWAPPED_VA, &mut got);
    assert!(
        matches!(read, Err(_) | Ok(0)),
        "a swapped page cannot be resolved through an attachment that is not a swap \
         area, so the address must stay a hole: {read:?}"
    );
}

/// **The third state, from bytes.** An area whose header page parses over a body
/// nothing can be read from — a `dd` that stopped after the first page, a sparse
/// copy that lost the body, a source that errors behind the header — is neither
/// an area that holds data nor an area that reads as zeros. The survey says so
/// honestly (`pages_read` is zero and `reads_as_all_zero` is false, because "we
/// read nothing" is not "we read zeros"), and the attach-time warning has to say
/// so too: an examiner who is not told now may never learn that the evidence
/// they attached stops after 4,096 bytes.
#[test]
fn an_area_whose_body_was_never_acquired_is_reported_at_attach_time() {
    // The header page and nothing behind it, as an interrupted copy leaves it.
    let mut bytes = vec![0u8; PAGE as usize];
    swap_area(&[])
        .read_at(0, &mut bytes)
        .expect("read the header page");
    let file = seance_memory::translate::SwapFile {
        index: 0,
        label: "truncated.raw".to_string(),
        source: Arc::new(ByteSliceDataSource::new(bytes)),
    };

    let area = SwapAreaBody::survey(&file);
    assert!(
        area.header_parsed,
        "the mkswap-written page copied faithfully, so this is a swap area"
    );
    assert!(
        area.survey.pages_sampled > 1,
        "the body was put to a real sample: {:?}",
        area.survey
    );
    assert_eq!(
        area.survey.pages_read, 0,
        "not one sampled page of the body came back: {:?}",
        area.survey
    );
    assert!(
        !area.survey.reads_as_all_zero(),
        "and that must not be recorded as an area that reads as zeros, which is a \
         conclusion drawn from no observation at all"
    );
    assert!(
        area.survey.body_was_not_read(),
        "it is the third state, and it has a word of its own: {:?}",
        area.survey
    );

    let warning = area
        .attach_warning()
        .expect("an area whose body was never acquired is worth saying out loud");
    assert!(
        warning.contains("truncated.raw"),
        "name the attachment: {warning}"
    );
    assert!(
        warning.contains("64"),
        "say how many places were looked at, so the emptiness of the sample is \
         quantified rather than asserted: {warning}"
    );
}
