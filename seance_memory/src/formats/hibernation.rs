//! Windows hibernation files (`hiberfil.sys`).
//!
//! When Windows hibernates it writes the whole of physical memory to
//! `hiberfil.sys` and powers off. That file is a memory capture the machine took
//! of itself, and it is often the only one available: it sits on the disk image
//! an examiner already has, no live acquisition required, and it records the
//! state of the machine at a moment nobody chose in advance.
//!
//! It is also the artefact most often walked past. The file is present on nearly
//! every Windows laptop, it is large, and it looks like an opaque blob — so it
//! gets carved for strings at best. Séance treats it as what it is: evidence
//! with a header that states, unambiguously, whether there is a memory image
//! inside it and when the machine wrote it.
//!
//! # What the header says
//!
//! The first four bytes are a signature, and its value is a finding in itself:
//!
//! | Signature | Meaning |
//! |---|---|
//! | `hibr` / `HIBR` | A complete hibernation image. The machine hibernated and has not resumed since. |
//! | `wake` / `WAKE` | The machine resumed from this image. The pages are still on disk but the kernel has marked them consumed. |
//! | `RSTR` | Restored — the resume completed and the file was marked reusable. |
//! | all zero | The file is allocated but holds no image, which is what a machine that has never hibernated looks like. |
//!
//! `wake` and `RSTR` matter: the data is usually still there, because Windows
//! marks the file rather than wiping it. An examiner should be told a resumed
//! image is present and potentially recoverable rather than have the file
//! silently ignored because its signature was not `hibr`.
//!
//! # What this module does
//!
//! It **identifies** the file and reports its state, the system time recorded at
//! hibernation, and the page size — enough for "this machine hibernated at 14:32
//! on the 3rd" to reach the timeline. And it **reconstructs the physical address
//! space**: [`open`] walks the restore sets, decompresses each Xpress page block
//! (see [`crate::formats::xpress`]), and places every recovered page at its
//! physical address, so the hibernation file becomes an ordinary memory image
//! the rest of the platform analyses like any other.
//!
//! # Scope of the reconstruction
//!
//! [`open`] reconstructs the x64 image-version-9 layout of both the NT10
//! (Windows 10/11) and the older NT6.2/6.3 (Windows 8/8.1/Server 2012[R2]) eras.
//! The two share the version but place the restore-set pointers eight bytes
//! apart, and they read the flag bits of a table header differently; `open`
//! picks the layout by which one's kernel pointer lands on a real table and
//! carries that choice through the walk (see [`HeaderLayout`] and the table
//! header constants beside it for the observed bit meanings, with the offsets
//! they were read at). Both page codecs are decoded — plain Xpress
//! (`XpressFast`/`XpressMax`) and Xpress-Huffman (`XpressHuffFast`/
//! `XpressHuffMax`), the latter being what Windows 10/11 writes for nearly the
//! whole kernel set. A page block that does not decode is left a counted gap
//! rather than guessed.
//!
//! Validation is against ground truth, not plausibility: a Windows 11 build
//! 26200 capture whose guest had filled 65,536 pages with a known per-page
//! marker reconstructs with all 65,536 present and byte-exact, both restore
//! sets walked to the page counts the header states (40,004 and 511,499), and
//! discovery walks its page tables to ntoskrnl; a Server 2012 R2 capture walks
//! both sets to its counts (16,664 and 113,548) with every block decoding
//! (`seance_memory/tests/hibernation_corpus_test.rs`). Each set's walk is
//! checked against the header's count for it and the check is recorded on the
//! layer, so a set that ends early is stated with both numbers rather than
//! passed off as the end of the set.
//!
//! The older Windows 7 (NT6.1) x64 layout — a linked list of range tables with
//! Xpress-magic block streams, wholly unlike the NT6.2 run above — is
//! implemented as an explicit opt-in only ([`open_legacy_nt61_x64_unvalidated`],
//! selected in the module dispatch by `SEANCE_HIBER_LEGACY=nt61-x64`). Its
//! structure is transcribed from reference sources but no Windows 7 corpus
//! exists here to validate the output, so it is never the default and every
//! layer it returns is stamped [`IncompleteReason::Unvalidated`]. Layouts older
//! still (Vista/XP, 32-bit) are identified but not reconstructed.
//!
//! Volatility 3 has no hibernation layer at all, so there is no upstream to be
//! consistent with here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::io::IncompleteReason;

use super::FormatError;
use crate::format::MemoryImageFormat;
use crate::meta::LayerMeta;
use crate::segmented::{Segment, SegmentedLayer};

/// Bytes of header read to identify and describe the file.
pub const HEADER_BYTES: usize = 0x200;

/// Page size the reconstruction assumes, after the header confirms it.
const HIBER_PAGE: u64 = 0x1000;
/// A single compression table restores at most sixteen pages (64 KiB); the
/// `PageCount` field is four bits, and this is also the reference decoder's cap.
const MAX_TABLE_PAGES: usize = 16;

// `PO_MEMORY_IMAGE` field offsets. Both the NT10 (Windows 10/11) and the older
// NT6.2/6.3 (Windows 8/8.1/Server 2012[R2]) x64 headers carry image version 9,
// but Win10 inserted an 8-byte field ahead of the restore-set pointers, so the
// two pairs sit at different offsets. Which one an image uses is decided by the
// bytes (see `restore_pointers`), not by the version — confirmed against real
// `hiberfil.sys` captures of both eras.
const OFF_PAGE_SIZE: usize = 0x18;
// NT10 (Win10/11): boot@0x68, kernel@0x70.
const OFF_BOOT_RESTORE_NT10: usize = 0x68;
const OFF_KERNEL_RESTORE_NT10: usize = 0x70;
// NT6.2/6.3 (Win8/8.1/2012[R2]): boot@0x60, kernel@0x68 — eight bytes earlier.
const OFF_BOOT_RESTORE_NT62: usize = 0x60;
const OFF_KERNEL_RESTORE_NT62: usize = 0x68;
// `NumPagesForLoader`: the pages the boot restore set holds. Equal to the walked
// boot-set total on both real captures (40,004 on Windows 11 26200; 16,664 on
// Server 2012 R2).
const OFF_LOADER_PAGES: usize = 0x58;
// The pages the kernel restore set holds. Not a published field name: a u64
// inside the performance block that equalled the walked kernel-set total on
// one real capture of each layout (511,499 at 0x238 on Windows 11 26200;
// 113,548 at 0x1c8 on Server 2012 R2), each preceded by a u64 repeating the
// loader count. It is used to *check* a walk, never to drive one.
const OFF_KERNEL_COUNT_NT10: usize = 0x238;
const OFF_KERNEL_COUNT_NT62: usize = 0x1c8;

/// The `MemoryImageFormat` these routines speak for.
const FMT: MemoryImageFormat = MemoryImageFormat::WindowsHibernation;

/// Reconstruct the physical address space a Windows hibernation file records.
///
/// The file stores the machine's physical memory as two *restore sets* — the
/// boot-loader set and the kernel set — each a linear run of **compression
/// tables**. A table names up to sixteen physical page ranges and carries the
/// compressed bytes that restore them, plain Xpress or Xpress-Huffman by a flag
/// in its header (see [`crate::formats::xpress`]). This walks both sets,
/// decompresses each table, and places every recovered page at its physical
/// address, producing a sparse [`SegmentedLayer`] over the pages the machine
/// actually saved.
///
/// # Scope
///
/// Handles the x64 image-version-9 layout of both the NT10 (Windows 10/11) and
/// the NT6.2/6.3 (Windows 8/8.1/Server 2012[R2]) eras, choosing between them by
/// the bytes (see [`restore_pointers`]). Both page codecs — plain Xpress and
/// Xpress-Huffman — are decoded; a block that does not decode is left a counted
/// gap rather than guessed, so a page is either the bytes Windows wrote or an
/// honest hole.
///
/// # Errors
///
/// [`FormatError::NotThisFormat`] if the header is not `HIBR`;
/// [`FormatError::Unsupported`] if it is a hibernation image whose page size or
/// layout this reader does not implement; [`FormatError::Malformed`] if it is a
/// `HIBR` image from which not a single page could be restored.
pub fn open(source: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
    let header = read_at(
        source.as_ref(),
        0,
        HIBER_PAGE as usize,
        "the hibernation header page",
    )?;
    if header.len() < 0x80 {
        return Err(FormatError::not_this(
            FMT,
            "shorter than a hibernation header page",
        ));
    }
    match &header[0..4] {
        b"HIBR" | b"hibr" => {}
        other => {
            return Err(FormatError::not_this(
                FMT,
                format!("signature {:?} is not a resumable hibernation image", other),
            ))
        }
    }
    // MEM-040: the NT10 kernel page count is the furthest header field read.
    if header.len() < OFF_KERNEL_COUNT_NT10 + 8 {
        return Err(FormatError::malformed(
            FMT,
            format!(
                "the image is signed as a resumable hibernation file but is {} bytes long, \
                 shorter than the {:#x}-byte header this reader needs",
                header.len(),
                OFF_KERNEL_COUNT_NT10 + 8
            ),
        ));
    }

    let page_size = u32::from_le_bytes([
        header[OFF_PAGE_SIZE],
        header[OFF_PAGE_SIZE + 1],
        header[OFF_PAGE_SIZE + 2],
        header[OFF_PAGE_SIZE + 3],
    ]);
    if page_size as u64 != HIBER_PAGE {
        return Err(FormatError::unsupported(
            FMT,
            format!("page size {page_size:#x} is not the 4096-byte layout this reader restores"),
        ));
    }

    let u64_at = |off: usize| -> u64 {
        u64::from_le_bytes([
            header[off],
            header[off + 1],
            header[off + 2],
            header[off + 3],
            header[off + 4],
            header[off + 5],
            header[off + 6],
            header[off + 7],
        ])
    };
    let file_size = source.size();
    let (layout, boot, kernel) = restore_pointers(source.as_ref(), &u64_at, file_size);

    // Pass one: read every table header of both sets, and nothing else. A
    // set's tables and its stop are recorded before a single block is
    // decompressed, so the pages can be laid out in physical order into one
    // buffer and each block is read and decoded exactly once.
    //
    // One stop per set, named. A set that stopped early is the difference
    // between "this address held nothing" and "this address was never
    // restored", and until 2026-09-15 the walk ended silently: on the corpus
    // file it restored 163 MiB of an 8.5 GB image and said nothing.
    let mut sets: Vec<RestoreSet> = Vec::new();
    for (name, start_page, header_count) in [
        ("boot", boot, u64_at(OFF_LOADER_PAGES)),
        ("kernel", kernel, u64_at(layout.kernel_count_offset())),
    ] {
        if start_page == 0 {
            continue;
        }
        let start = start_page.saturating_mul(HIBER_PAGE);
        if start >= file_size {
            continue;
        }
        let (tables, stop) =
            walk_restore_set(source.as_ref(), start, file_size, layout, header_count)?;
        sets.push(RestoreSet { name, tables, stop });
    }

    if sets.iter().all(|set| set.tables.is_empty()) {
        return Err(FormatError::malformed(
            FMT,
            "the image is a resumable hibernation file but no page could be restored from either \
             restore set; its restore-set pointers or compression tables are not the layout this \
             reader decodes (Windows 8 and later, x64)",
        ));
    }

    // Every physical page any table describes gets one slot in the buffer,
    // slots in physical-page order — tables name pages in the order Windows
    // wrote them, which is not that — so a run of consecutive pages is a run
    // of consecutive slots. A page named twice has one slot and the later
    // table's bytes, as before.
    let described: BTreeSet<u64> = sets
        .iter()
        .flat_map(|set| set.tables.iter())
        .flat_map(|table| table.ranges.iter())
        .flat_map(|&(start_page, count)| start_page..start_page + count)
        .collect();
    let slots: BTreeMap<u64, usize> = described
        .into_iter()
        .enumerate()
        .map(|(slot, page)| (page, slot))
        .collect();
    let slot_count = slots.len();
    // Zero-filled and lazily committed: a slot whose block does not decode is
    // never touched, never mapped, and costs nothing.
    let mut buffer: Vec<u8> = vec![0u8; slot_count * HIBER_PAGE as usize];
    let mut filled: Vec<bool> = vec![false; slot_count];
    let mut undecoded_pages: u64 = 0;

    // Pass two: decode each block into its pages' slots.
    for table in sets.iter().flat_map(|set| set.tables.iter()) {
        let raw_len = table.total_pages * HIBER_PAGE as usize;
        let block = read_at(
            source.as_ref(),
            table.block_offset,
            table.compressed_size,
            "a hibernation page block",
        )?;
        let decoded: Option<Vec<u8>> = if block.len() < table.compressed_size {
            None
        } else if table.compressed_size == raw_len {
            // Stored at its full uncompressed size — not compressed at all,
            // whatever the flags nominally say (9 boot and 126 kernel tables
            // on the 26200 capture).
            Some(block)
        } else if table.huffman {
            super::xpress::decompress_huffman(&block, raw_len).filter(|data| data.len() == raw_len)
        } else {
            super::xpress::decompress_exact(&block, raw_len)
        };
        match decoded {
            Some(data) => {
                let mut page_index = 0usize;
                for &(start_page, count) in &table.ranges {
                    for k in 0..count {
                        let from = page_index * HIBER_PAGE as usize;
                        let slot = slots[&(start_page + k)];
                        let to = slot * HIBER_PAGE as usize;
                        buffer[to..to + HIBER_PAGE as usize]
                            .copy_from_slice(&data[from..from + HIBER_PAGE as usize]);
                        filled[slot] = true;
                        page_index += 1;
                    }
                }
            }
            // A block that will not decode is left a gap rather than guessed.
            None => undecoded_pages += table.total_pages as u64,
        }
    }

    // Segments: each maximal run of consecutive physical pages whose slots
    // were filled. Slots are in page order, so a run of pages is a run of
    // slots and the buffer offset is the slot's.
    let mut segments: Vec<Segment> = Vec::new();
    let mut restored_pages: u64 = 0;
    let mut max_page: u64 = 0;
    let mut run: Option<(u64, usize, u64)> = None; // (first page, first slot, pages)
    let mut prev_page: u64 = 0;
    for (&page, &slot) in &slots {
        if !filled[slot] {
            continue;
        }
        restored_pages += 1;
        max_page = max_page.max(page + 1);
        match run {
            Some((_, _, ref mut pages)) if page == prev_page + 1 => *pages += 1,
            _ => {
                if let Some((first_page, first_slot, pages)) = run {
                    segments.push(Segment::new(
                        first_slot as u64 * HIBER_PAGE,
                        first_page * HIBER_PAGE,
                        pages * HIBER_PAGE,
                    ));
                }
                run = Some((page, slot, 1));
            }
        }
        prev_page = page;
    }
    if let Some((first_page, first_slot, pages)) = run {
        segments.push(Segment::new(
            first_slot as u64 * HIBER_PAGE,
            first_page * HIBER_PAGE,
            pages * HIBER_PAGE,
        ));
    }

    let records: Vec<SetRecord> = sets
        .iter()
        .map(|set| SetRecord {
            name: set.name,
            stop: set.stop.clone(),
            tables: set.tables.len(),
            unknown_flag_tables: set.tables.iter().filter(|t| t.unknown_flag).count(),
        })
        .collect();
    assemble_layer(
        Restored {
            buffer,
            segments,
            restored_pages,
            max_page,
        },
        undecoded_pages,
        None,
        &records,
        file_size,
    )
}

/// One restore set as pass one read it.
struct RestoreSet {
    name: &'static str,
    tables: Vec<TableRef>,
    stop: RestoreStop,
}

/// What the layer records about one restore set.
struct SetRecord {
    name: &'static str,
    stop: RestoreStop,
    /// Tables the walk read.
    tables: usize,
    /// Tables whose header carried the uninterpreted bit 29.
    unknown_flag_tables: usize,
}

/// A compression table as its header describes it, before its block is read.
struct TableRef {
    /// File offset of the compressed block (just past the range entries).
    block_offset: u64,
    /// Bytes in the block.
    compressed_size: usize,
    /// Whether the block is Xpress-Huffman rather than plain Xpress.
    huffman: bool,
    /// Whether the header carries the bit this reader does not interpret.
    unknown_flag: bool,
    /// `(start_page, page_count)` in table order; the decoded bytes fill them
    /// in that order.
    ranges: Vec<(u64, u64)>,
    /// Pages across all ranges.
    total_pages: usize,
}

/// The restored pages as one buffer plus the segments that map it.
struct Restored {
    buffer: Vec<u8>,
    segments: Vec<Segment>,
    restored_pages: u64,
    max_page: u64,
}

/// Lay out pages keyed by physical page number into a `Restored`: each maximal
/// run of consecutive pages becomes one segment. Used by the NT6.1 path, which
/// decodes as it walks.
fn pages_to_restored(pages: BTreeMap<u64, Vec<u8>>) -> Restored {
    let mut buffer: Vec<u8> = Vec::with_capacity(pages.len() * HIBER_PAGE as usize);
    let mut segments: Vec<Segment> = Vec::new();
    let mut run_start: Option<u64> = None;
    let mut run_file_off: u64 = 0;
    let mut run_pages: u64 = 0;
    let mut prev_page: u64 = 0;
    let mut max_page: u64 = 0;
    for (page, bytes) in pages {
        let file_off = buffer.len() as u64;
        buffer.extend_from_slice(&bytes);
        max_page = max_page.max(page + 1);
        match run_start {
            Some(_) if page == prev_page + 1 => run_pages += 1,
            _ => {
                if let Some(start) = run_start {
                    segments.push(Segment::new(
                        run_file_off,
                        start * HIBER_PAGE,
                        run_pages * HIBER_PAGE,
                    ));
                }
                run_start = Some(page);
                run_file_off = file_off;
                run_pages = 1;
            }
        }
        prev_page = page;
    }
    if let Some(start) = run_start {
        segments.push(Segment::new(
            run_file_off,
            start * HIBER_PAGE,
            run_pages * HIBER_PAGE,
        ));
    }
    let restored_pages = buffer.len() as u64 / HIBER_PAGE;
    Restored {
        buffer,
        segments,
        restored_pages,
        max_page,
    }
}

/// Build the `SegmentedLayer` over restored pages, with every fact about how
/// complete the restoration is stated on its metadata.
///
/// Peak memory is the size of the restored image — the pages the machine
/// actually saved, not its whole RAM — and that cost is inherent: the pages are
/// compressed in the file, so serving them means holding the decompressed
/// bytes somewhere. They are held in one owned buffer (the backing for a
/// `ByteSliceDataSource`) rather than a paged store: a single 64-bit heap
/// allocation is not a practical constraint, and a chunked backing would trade
/// that for boundary-handling complexity without lowering the peak.
///
/// `unvalidated`, when set, carries the reason string for an
/// [`IncompleteReason::Unvalidated`] stamp on the whole layer — used by the
/// older-layout path whose output no corpus has ever confirmed.
fn assemble_layer(
    restored: Restored,
    undecoded_pages: u64,
    unvalidated: Option<String>,
    sets: &[SetRecord],
    file_size: u64,
) -> Result<SegmentedLayer, FormatError> {
    let Restored {
        buffer,
        segments,
        restored_pages,
        max_page,
    } = restored;
    let mut meta = LayerMeta::new(FMT)
        .with_declared_size(max_page * HIBER_PAGE)
        .with_note("hibernation_pages_restored", restored_pages)
        .with_note("hibernation_state", "hibernated");
    if let Some(reason) = unvalidated {
        meta = meta
            .with_note("hibernation_reconstruction", "unvalidated")
            .with_incomplete(IncompleteReason::Unvalidated, reason);
    }
    if undecoded_pages > 0 {
        meta = meta.with_incomplete(
            IncompleteReason::Compressed,
            format!(
                "{undecoded_pages} page(s) are in compression blocks that did not decode (a \
                 malformed or unsupported block); they are left as gaps rather than decoded \
                 incorrectly"
            ),
        );
    }

    // **A restore set that stopped early is stated.** The reconstruction then
    // covers part of the address space it declares, and an absence in it is not
    // an absence in the machine. The numbers are both given, because the
    // shortfall is the fact: a reader comparing them can see how much of the
    // image this is.
    let restored_bytes = restored_pages.saturating_mul(HIBER_PAGE);
    let declared = max_page.saturating_mul(HIBER_PAGE);
    meta = meta.with_note("hibernation_restored_bytes", restored_bytes);
    if !sets.is_empty() {
        // The record of each set: how many pages its tables described, how
        // many the header says it holds, and where it ended — so a reader can
        // see the check that was made, not only its verdict.
        let record: Vec<serde_json::Value> = sets
            .iter()
            .map(|set| {
                let mut r = set.stop.to_json(set.name);
                r["tables"] = serde_json::json!(set.tables);
                r["tables_with_uninterpreted_bit_29"] = serde_json::json!(set.unknown_flag_tables);
                r
            })
            .collect();
        meta = meta.with_note("hibernation_restore_sets", record);
    }
    for set in sets {
        if set.stop.is_complete() {
            continue;
        }
        meta = meta.with_incomplete(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{}. {restored_bytes} of the {declared} byte(s) this image declares were \
                 restored ({}.{}%).",
                set.stop.detail(set.name, file_size),
                // One decimal place, from the same arithmetic. Whole per cent
                // rounded 1.588% to "1%", and a document quoting the true
                // figure then disagreed with the record.
                restored_bytes
                    .saturating_mul(1000)
                    .checked_div(declared)
                    .unwrap_or(0)
                    / 10,
                restored_bytes
                    .saturating_mul(1000)
                    .checked_div(declared)
                    .unwrap_or(0)
                    % 10,
            ),
        );
    }

    let backing: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(buffer));
    SegmentedLayer::new(backing, segments, meta).map_err(|e| FormatError::layer(FMT, e))
}

// --- NT 6.1 (Windows 7 / Server 2008 R2) x64 — STRUCTURE-ONLY, UNVALIDATED ---
//
// This layout predates the linear NT6.2 run [`open`] decodes and is shaped
// entirely differently: a *linked list* of one-page range tables, each followed
// a page later by a stream of Xpress "magic" blocks. The structure below is
// transcribed from the MoonSols Hibr2Bin reference. No Windows 7 corpus is
// available to confirm the output, so this is not wired into format detection;
// a caller must opt in explicitly, and every layer it produces is stamped
// [`IncompleteReason::Unvalidated`] — the loudest honesty signal the pipeline
// has. A structurally plausible but wrong page is worse than an honest refusal,
// so the contract here is "here is what the bytes would mean if the layout is
// right, and you have been told it was never checked", never "here is memory".

/// Fixed file offset of the first NT6.1 x64 range table (page 6).
const NT61_INITIAL_OFFSET: u64 = 0x6000;
/// `Link`: `NextTable`(u64, a page number) + `EntryCount`(u32) + `Padding`(u32).
const NT61_LINK_SIZE: u64 = 16;
/// `Range`: `StartPage`(u64) + `EndPage`(u64); `PageCount = EndPage - StartPage`.
const NT61_RANGE_SIZE: u64 = 16;
/// A cap on ranges per table, so a corrupt `EntryCount` cannot allocate wildly.
const NT61_MAX_RANGES: usize = 0x200;

/// Xpress "magic" block: `\x81\x81xpress` then a little-endian info word, inside
/// a fixed 0x20-byte header. `CompressedSize = ((info >> 10) + 1)` rounded up to
/// 8; `UncompressedPages = (info & 0x3ff) + 1`.
const XPRESS_MAGIC: &[u8] = b"\x81\x81xpress";
const XPRESS_HEADER_SIZE: usize = 0x20;

/// Reconstruct the physical address space of an **NT6.1 (Windows 7) x64**
/// hibernation file. See the module note and the block comment above: this is an
/// explicit, opt-in, **unvalidated** path — the returned layer is always stamped
/// [`IncompleteReason::Unvalidated`]. Callers must never present its pages as
/// confirmed memory.
///
/// # Errors
///
/// As [`open`], plus [`FormatError::Malformed`] if the NT6.1 linked list yields
/// no page (which, for a genuine NT6.2 image fed here by mistake, it will).
pub fn open_legacy_nt61_x64_unvalidated(
    source: Arc<dyn DataSource>,
) -> Result<SegmentedLayer, FormatError> {
    let header = read_at(
        source.as_ref(),
        0,
        HIBER_PAGE as usize,
        "the hibernation header page",
    )?;
    if header.len() < 0x80 {
        return Err(FormatError::not_this(
            FMT,
            "shorter than a hibernation header page",
        ));
    }
    match &header[0..4] {
        b"HIBR" | b"hibr" => {}
        other => {
            return Err(FormatError::not_this(
                FMT,
                format!("signature {:?} is not a resumable hibernation image", other),
            ))
        }
    }
    let page_size = u32::from_le_bytes([
        header[OFF_PAGE_SIZE],
        header[OFF_PAGE_SIZE + 1],
        header[OFF_PAGE_SIZE + 2],
        header[OFF_PAGE_SIZE + 3],
    ]);
    if page_size as u64 != HIBER_PAGE {
        return Err(FormatError::unsupported(
            FMT,
            format!("page size {page_size:#x} is not the 4096-byte layout this reader restores"),
        ));
    }

    let file_size = source.size();
    let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut undecoded_pages: u64 = 0;
    walk_restore_set_nt61(
        source.as_ref(),
        NT61_INITIAL_OFFSET,
        file_size,
        &mut pages,
        &mut undecoded_pages,
    )?;

    if pages.is_empty() {
        return Err(FormatError::malformed(
            FMT,
            "no page could be restored under the NT6.1 (Windows 7) x64 layout; either this is not \
             a Windows 7 hibernation image or its linked list of range tables is not the structure \
             this unvalidated reader transcribes",
        ));
    }

    assemble_layer(
        pages_to_restored(pages),
        undecoded_pages,
        Some(
            "reconstructed with the NT6.1 (Windows 7 / Server 2008 R2) x64 hibernation layout — a \
             structure transcribed from reference sources but never validated against a real \
             Windows 7 capture, because no such corpus exists here. Every restored page is \
             unverified: it is what the bytes would mean if the layout is correct, not confirmed \
             memory."
                .to_string(),
        ),
        // The NT6.1 walk has its own break conditions and does not yet name
        // them. Its whole output is already stamped `unvalidated` above, which
        // is the stronger statement; a stop reason per table would be an
        // improvement on a path no corpus has ever exercised.
        &[],
        file_size,
    )
}

/// Follow the NT6.1 linked list of range tables from `start`, decoding each
/// table's Xpress-magic block stream into `pages`.
///
/// Each table page is `Link { NextTable, EntryCount, Padding }` followed by
/// `EntryCount` `{ StartPage, EndPage }` ranges; the compressed pages for the
/// table begin one full page after the table start and decode (plain Xpress) to
/// a flat page stream that fills the ranges in order. `NextTable == 0`, a short
/// read, or a structurally invalid table ends the walk — the same terminate-on-
/// first-bad-table discipline as the NT6.2 path.
fn walk_restore_set_nt61(
    source: &dyn DataSource,
    start: u64,
    file_size: u64,
    pages: &mut BTreeMap<u64, Vec<u8>>,
    undecoded_pages: &mut u64,
) -> Result<(), FormatError> {
    // The whole address space holds at most this many pages; no single table can
    // legitimately claim more, and it bounds a corrupt `EntryCount`/range count.
    let page_ceiling = file_size / HIBER_PAGE + 1;
    let mut off = start;
    let mut visited: usize = 0;
    // A table sits on a page; there are at most this many pages to land on, so a
    // cyclic or self-referential `NextTable` cannot loop forever.
    let table_ceiling = (file_size / HIBER_PAGE + 1) as usize;
    while off != 0 && off + NT61_LINK_SIZE <= file_size {
        visited += 1;
        if visited > table_ceiling {
            break;
        }
        let link = read_at(
            source,
            off,
            NT61_LINK_SIZE as usize,
            "an NT6.1 range-table link",
        )?;
        if link.len() < NT61_LINK_SIZE as usize {
            break;
        }
        let next_table = u64::from_le_bytes(link[0..8].try_into().expect("8 bytes present"));
        let entry_count =
            u32::from_le_bytes(link[8..12].try_into().expect("4 bytes present")) as usize;
        if entry_count == 0 || entry_count > NT61_MAX_RANGES {
            break;
        }

        let ranges_bytes = read_at(
            source,
            off + NT61_LINK_SIZE,
            entry_count * NT61_RANGE_SIZE as usize,
            "NT6.1 range entries",
        )?;
        if ranges_bytes.len() < entry_count * NT61_RANGE_SIZE as usize {
            break;
        }
        let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(entry_count);
        let mut total_pages: u64 = 0;
        let mut table_ok = true;
        for e in 0..entry_count {
            let base = e * NT61_RANGE_SIZE as usize;
            let start_page = u64::from_le_bytes(
                ranges_bytes[base..base + 8]
                    .try_into()
                    .expect("8 bytes present"),
            );
            let end_page = u64::from_le_bytes(
                ranges_bytes[base + 8..base + 16]
                    .try_into()
                    .expect("8 bytes present"),
            );
            if end_page <= start_page {
                table_ok = false;
                break;
            }
            let count = end_page - start_page;
            total_pages += count;
            if total_pages > page_ceiling {
                table_ok = false;
                break;
            }
            ranges.push((start_page, count));
        }
        if !table_ok || total_pages == 0 {
            break;
        }

        // The compressed page bytes begin one full page after the table start.
        let block_off = off + HIBER_PAGE;
        match decode_xpress_magic_stream(source, block_off, file_size, total_pages)? {
            Some(data) => {
                let mut page_index = 0usize;
                for (start_page, count) in ranges {
                    for k in 0..count {
                        let from = page_index * HIBER_PAGE as usize;
                        let to = from + HIBER_PAGE as usize;
                        if let Some(bytes) = data.get(from..to) {
                            pages.insert(start_page + k, bytes.to_vec());
                        }
                        page_index += 1;
                    }
                }
            }
            None => *undecoded_pages += total_pages,
        }

        off = next_table.saturating_mul(HIBER_PAGE);
    }
    Ok(())
}

/// Decode the sequence of Xpress-magic blocks at `off` until `needed_pages`
/// worth of decompressed bytes exist, returning the concatenated pages.
///
/// Returns `None` (a counted gap, not an error) at the first block that does not
/// begin with the magic, is short-read, or does not decode — the same
/// leave-a-gap-rather-than-guess discipline as the NT6.2 path.
fn decode_xpress_magic_stream(
    source: &dyn DataSource,
    mut off: u64,
    file_size: u64,
    needed_pages: u64,
) -> Result<Option<Vec<u8>>, FormatError> {
    let needed = needed_pages * HIBER_PAGE;
    let mut out: Vec<u8> = Vec::new();
    while (out.len() as u64) < needed {
        if off + XPRESS_HEADER_SIZE as u64 > file_size {
            return Ok(None);
        }
        let head = read_at(source, off, XPRESS_HEADER_SIZE, "an Xpress magic header")?;
        if head.len() < XPRESS_HEADER_SIZE || &head[0..XPRESS_MAGIC.len()] != XPRESS_MAGIC {
            return Ok(None);
        }
        let info = u32::from_le_bytes([
            head[XPRESS_MAGIC.len()],
            head[XPRESS_MAGIC.len() + 1],
            head[XPRESS_MAGIC.len() + 2],
            head[XPRESS_MAGIC.len() + 3],
        ]);
        let compressed_size = (((info >> 10) + 1) as usize + 7) & !7;
        let uncompressed_pages = ((info & 0x3FF) + 1) as usize;
        let raw_len = uncompressed_pages * HIBER_PAGE as usize;

        let data_off = off + XPRESS_HEADER_SIZE as u64;
        let block = read_at(source, data_off, compressed_size, "an Xpress magic block")?;
        if block.len() < compressed_size {
            return Ok(None);
        }
        if compressed_size == raw_len {
            // Stored at full size — not compressed, whatever the magic implies.
            out.extend_from_slice(&block);
        } else {
            let decoded = super::xpress::decompress(&block, raw_len);
            match decoded.get(..raw_len) {
                Some(bytes) => out.extend_from_slice(bytes),
                None => return Ok(None),
            }
        }
        off = data_off + compressed_size as u64;
    }
    Ok(Some(out))
}

/// Which `PO_MEMORY_IMAGE` layout an image uses. The two eras share image
/// version 9 but disagree on where the restore-set pointers sit *and* on what
/// the top bits of a table header mean, so the layout is one decision carried
/// through the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderLayout {
    /// Windows 10/11: boot@0x68, kernel@0x70.
    Nt10,
    /// Windows 8/8.1/Server 2012[R2]: boot@0x60, kernel@0x68.
    Nt62,
}

/// The packed table header: `RangeCount` in the low byte, then the compressed
/// size, then flag bits. **The size is the low 21 bits of the upper 24, not
/// 22.** On the Windows 11 build 26200 capture bit 29 is set on 15,326 of the
/// 31,969 kernel tables (the first at byte 33,609,845, header `0x60179002`);
/// read as part of a 22-bit size that is 2,103,184 bytes for a sixteen-page
/// table, and the walk stepped into the compressed data and ended. Read as a
/// flag over a 21-bit size it is 6,032, and the next table begins exactly there.
/// Twenty-one bits (2 MiB) is ample: a table restores at most sixteen pages and
/// its block is never larger than the 65,536 bytes those pages occupy.
///
/// What bit 29 *means* is not established: tables with and without it decode
/// with the same codec, its runs are interleaved with the others, and no
/// public description names it. It is ignored, and stated as ignored.
const TABLE_SIZE_MASK: u32 = 0x1F_FFFF;
const TABLE_FLAG_UNKNOWN_BIT29: u32 = 1 << 29;
/// NT10: bit 30 is `HuffmanCompressed`. On the 26200 capture 30,479 of 31,969
/// kernel tables carry it; none decodes as plain Xpress (the first
/// back-reference reaches before the output) and 30,354 decode as
/// Xpress-Huffman to exactly their page count (the rest are stored). Bit 31
/// was never observed set on this layout.
const TABLE_HUFFMAN_NT10: u32 = 1 << 30;
/// NT6.2/6.3: bits 30..=31 are a two-bit method — `XpressFast`, `XpressMax`,
/// `XpressHuffFast`, `XpressHuffMax` — so Huffman is bit 31, and bit 30 alone
/// is plain Xpress (103 such tables on the 2012 R2 capture, every one decoding
/// as plain to its page count; 131 with bit 31 decode as Huffman).
const TABLE_HUFFMAN_NT62: u32 = 1 << 31;

impl HeaderLayout {
    fn kernel_count_offset(self) -> usize {
        match self {
            HeaderLayout::Nt10 => OFF_KERNEL_COUNT_NT10,
            HeaderLayout::Nt62 => OFF_KERNEL_COUNT_NT62,
        }
    }

    /// Whether a table header's flags say its block is Xpress-Huffman.
    fn is_huffman(self, header: u32) -> bool {
        match self {
            HeaderLayout::Nt10 => header & TABLE_HUFFMAN_NT10 != 0,
            HeaderLayout::Nt62 => header & TABLE_HUFFMAN_NT62 != 0,
        }
    }
}

/// The parts of a packed table header, or why it is not one.
fn parse_table_header(head: &[u8]) -> Result<(u32, usize, usize), String> {
    let header = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let range_count = (header & 0xFF) as usize;
    let compressed_size = ((header >> 8) & TABLE_SIZE_MASK) as usize;
    if range_count == 0 || range_count > MAX_TABLE_PAGES || compressed_size == 0 {
        return Err(format!(
            "the packed header {header:#010x} declares {range_count} range(s) and \
             {compressed_size} compressed byte(s), which is not a table this reader \
             recognises (1 to {MAX_TABLE_PAGES} ranges and a non-zero size)"
        ));
    }
    Ok((header, range_count, compressed_size))
}

/// Whether `page` begins a plausible compression table.
///
/// The discriminator between the two header layouts: on an NT10 image the kernel
/// pointer at 0x70 lands on a real table, on an NT6.2/6.3 image that offset is a
/// different field whose value is not a page number and points nowhere. Applies
/// the same validity gate the walk itself uses, so "valid here" means "the walk
/// would find a table here".
fn points_at_table(source: &dyn DataSource, page: u64, file_size: u64) -> bool {
    if page == 0 {
        return false;
    }
    let off = page.saturating_mul(HIBER_PAGE);
    if off == 0 || off.checked_add(4).is_none_or(|end| end > file_size) {
        return false;
    }
    let head = match read_at(
        source,
        off,
        4 + MAX_TABLE_PAGES * 8,
        "a restore-pointer probe",
    ) {
        Ok(h) if h.len() >= 4 => h,
        _ => return false,
    };
    let Ok((_, range_count, _)) = parse_table_header(&head) else {
        return false;
    };
    if head.len() < 4 + range_count * 8 {
        return false;
    }
    let mut total = 0usize;
    for r in 0..range_count {
        let v = u64::from_le_bytes(head[4 + r * 8..4 + r * 8 + 8].try_into().unwrap());
        total += ((v & 0xF) + 1) as usize;
    }
    total != 0 && total <= MAX_TABLE_PAGES
}

/// The header layout and the boot and kernel restore-set start pages, choosing
/// between NT10 and NT6.2/6.3 by which one's kernel pointer lands on a real
/// table.
///
/// The kernel pointer decides because it is the field the two layouts disagree
/// on that is *checkable*: NT10's 0x70 kernel page is a table, NT6.x's 0x70 is
/// unrelated bytes. (The boot pointer cannot discriminate — both layouts put a
/// valid table pointer at the *other's* kernel offset.) NT10 is tried first and
/// is the fallback, so a modern image is never mis-read as an older one.
fn restore_pointers(
    source: &dyn DataSource,
    u64_at: &impl Fn(usize) -> u64,
    file_size: u64,
) -> (HeaderLayout, u64, u64) {
    let nt10 = (
        u64_at(OFF_BOOT_RESTORE_NT10),
        u64_at(OFF_KERNEL_RESTORE_NT10),
    );
    if points_at_table(source, nt10.1, file_size) {
        return (HeaderLayout::Nt10, nt10.0, nt10.1);
    }
    let nt62 = (
        u64_at(OFF_BOOT_RESTORE_NT62),
        u64_at(OFF_KERNEL_RESTORE_NT62),
    );
    if points_at_table(source, nt62.1, file_size) {
        return (HeaderLayout::Nt62, nt62.0, nt62.1);
    }
    (HeaderLayout::Nt10, nt10.0, nt10.1)
}

/// Where a restore-set walk ended, and whether that was the end of the set.
///
/// **This exists because the walk stopping was silent.** Every unexpected byte
/// in a table header ends a set, and a set that ends 30 MB into an 8.5 GB file
/// produced a layer whose segments covered 1.5% of the address space it
/// declared — with nothing on the record saying the walk had stopped.
/// Every downstream claim over such an image ("this process is not here", "the
/// rules matched nothing") is then a claim about the part that was restored,
/// which is not the claim it reads as.
///
/// A set has no terminator of its own: it is a linear run of tables and the
/// bytes after the last one are whatever follows in the file. So the walk
/// always ends on bytes that are not a table, and *that* cannot tell a
/// finished set from a broken one. What can is the header: it states how many
/// pages each set holds, and a walk whose tables describe exactly that many is
/// complete. Every variant carries both numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreStop {
    /// The set ran to the end of the file.
    EndOfFile {
        /// Pages the set's tables described.
        pages: u64,
        /// Pages the header says the set holds.
        header_count: u64,
    },
    /// The walk reached bytes that are not a table header.
    EndOfSet {
        /// Byte offset of those bytes.
        at: u64,
        /// What was wrong with them as a header, in the format's own terms.
        detail: String,
        /// Pages the set's tables described.
        pages: u64,
        /// Pages the header says the set holds.
        header_count: u64,
    },
    /// The file ended mid-table: a truncated acquisition.
    ShortRead {
        /// Byte offset the read started at.
        at: u64,
        /// Bytes asked for.
        wanted: usize,
        /// Bytes the source held.
        got: usize,
        /// Pages the set's tables described before the truncation.
        pages: u64,
        /// Pages the header says the set holds.
        header_count: u64,
    },
}

impl RestoreStop {
    /// Pages the set's tables described.
    pub fn pages(&self) -> u64 {
        match self {
            RestoreStop::EndOfFile { pages, .. }
            | RestoreStop::EndOfSet { pages, .. }
            | RestoreStop::ShortRead { pages, .. } => *pages,
        }
    }

    /// Pages the header says the set holds.
    pub fn header_count(&self) -> u64 {
        match self {
            RestoreStop::EndOfFile { header_count, .. }
            | RestoreStop::EndOfSet { header_count, .. }
            | RestoreStop::ShortRead { header_count, .. } => *header_count,
        }
    }

    /// Whether the walk described every page the header counts for the set.
    /// A truncated file is never complete, whatever the counts say.
    pub fn is_complete(&self) -> bool {
        !matches!(self, RestoreStop::ShortRead { .. }) && self.pages() == self.header_count()
    }

    /// The set's record for the layer metadata.
    pub fn to_json(&self, set: &str) -> serde_json::Value {
        let (kind, at) = match self {
            RestoreStop::EndOfFile { .. } => ("end_of_file", None),
            RestoreStop::EndOfSet { at, .. } => ("end_of_set", Some(*at)),
            RestoreStop::ShortRead { at, .. } => ("short_read", Some(*at)),
        };
        serde_json::json!({
            "set": set,
            "pages": self.pages(),
            "header_count": self.header_count(),
            "complete": self.is_complete(),
            "ended": kind,
            "ended_at": at,
        })
    }

    /// The sentence the layer carries for an examiner when the set is not
    /// complete.
    pub fn detail(&self, set: &str, file_size: u64) -> String {
        let pages = self.pages();
        let header_count = self.header_count();
        match self {
            RestoreStop::EndOfFile { .. } => format!(
                "the {set} restore set ran to the end of the file after its tables described \
                 {pages} of the {header_count} page(s) the header states it holds"
            ),
            RestoreStop::EndOfSet { at, detail, .. } => format!(
                "the {set} restore set stopped at byte {at} of {file_size} after its tables \
                 described {pages} of the {header_count} page(s) the header states it holds: \
                 {detail}. The pages its remaining tables describe were NOT restored, so an \
                 address absent from this image is not an address that was absent from the \
                 machine"
            ),
            RestoreStop::ShortRead {
                at, wanted, got, ..
            } => format!(
                "the {set} restore set stopped at byte {at} of {file_size} after its tables \
                 described {pages} of the {header_count} page(s) the header states it holds: \
                 {wanted} byte(s) were needed and {got} were there, so the file is truncated \
                 at that point and the pages above it were not restored"
            ),
        }
    }
}

/// Walk one restore set from `start`, reading table headers only.
///
/// A Windows-8-and-later restore set is a linear sequence of tables with no
/// forward links: each table is followed immediately by the next, and the set
/// ends at the first header that is not a valid table (a range count of zero or
/// more than sixteen, or a zero compressed size). Whether that end is the
/// *set's* end is decided against `header_count` — see [`RestoreStop`].
fn walk_restore_set(
    source: &dyn DataSource,
    start: u64,
    file_size: u64,
    layout: HeaderLayout,
    header_count: u64,
) -> Result<(Vec<TableRef>, RestoreStop), FormatError> {
    let mut tables: Vec<TableRef> = Vec::new();
    let mut pages: u64 = 0;
    let mut off = start;
    loop {
        if off + 4 > file_size {
            return Ok((
                tables,
                RestoreStop::EndOfFile {
                    pages,
                    header_count,
                },
            ));
        }
        // Header plus the maximum range array in one read: a 4-byte packed
        // header then up to sixteen 8-byte range entries.
        let head = read_at(
            source,
            off,
            4 + MAX_TABLE_PAGES * 8,
            "a hibernation table header",
        )?;
        if head.len() < 4 {
            return Ok((
                tables,
                RestoreStop::ShortRead {
                    at: off,
                    wanted: 4,
                    got: head.len(),
                    pages,
                    header_count,
                },
            ));
        }
        let (header, range_count, compressed_size) = match parse_table_header(&head) {
            Ok(parts) => parts,
            Err(detail) => {
                return Ok((
                    tables,
                    RestoreStop::EndOfSet {
                        at: off,
                        detail,
                        pages,
                        header_count,
                    },
                ))
            }
        };
        if head.len() < 4 + range_count * 8 {
            return Ok((
                tables,
                RestoreStop::ShortRead {
                    at: off,
                    wanted: 4 + range_count * 8,
                    got: head.len(),
                    pages,
                    header_count,
                },
            ));
        }

        // Each entry: PageCount (4 bits, stored as count-1) and StartPage (28
        // bits), in a little-endian 64-bit unit.
        let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(range_count);
        let mut total_pages: usize = 0;
        for r in 0..range_count {
            let v = u64::from_le_bytes(
                head[4 + r * 8..4 + r * 8 + 8]
                    .try_into()
                    .expect("8 bytes present"),
            );
            let page_count = (v & 0xF) + 1;
            let start_page = (v >> 4) & 0x0FFF_FFFF;
            ranges.push((start_page, page_count));
            total_pages += page_count as usize;
        }
        if total_pages == 0 || total_pages > MAX_TABLE_PAGES {
            return Ok((
                tables,
                RestoreStop::EndOfSet {
                    at: off,
                    detail: format!(
                        "the table's {range_count} range(s) describe {total_pages} page(s), \
                         which is outside the 1 to {MAX_TABLE_PAGES} a table can hold"
                    ),
                    pages,
                    header_count,
                },
            ));
        }

        let block_offset = off + 4 + (range_count as u64) * 8;
        if block_offset + compressed_size as u64 > file_size {
            return Ok((
                tables,
                RestoreStop::ShortRead {
                    at: block_offset,
                    wanted: compressed_size,
                    got: file_size.saturating_sub(block_offset) as usize,
                    pages,
                    header_count,
                },
            ));
        }
        tables.push(TableRef {
            block_offset,
            compressed_size,
            huffman: layout.is_huffman(header),
            unknown_flag: header & TABLE_FLAG_UNKNOWN_BIT29 != 0,
            ranges,
            total_pages,
        });
        pages += total_pages as u64;
        off = block_offset + compressed_size as u64;
    }
}

/// Read `len` bytes at `off`, returning however many the source held (a short
/// read at a truncated file is not an error here — it ends a set).
fn read_at(
    source: &dyn DataSource,
    off: u64,
    len: usize,
    what: &str,
) -> Result<Vec<u8>, FormatError> {
    let mut buf = vec![0u8; len];
    let n = source
        .read_at(off, &mut buf)
        .map_err(|e| FormatError::io(FMT, what.to_string(), e))?;
    buf.truncate(n);
    Ok(buf)
}

/// The state a hibernation file's signature reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HibernationState {
    /// `hibr`/`HIBR` — a complete image the machine has not resumed from.
    Hibernated,
    /// `wake`/`WAKE` — the machine resumed from this image. The pages are
    /// normally still present; the kernel marks the file rather than wiping it.
    Resumed,
    /// `RSTR` — restore completed and the file was marked reusable.
    Restored,
    /// All-zero signature: allocated but never written. A machine that has
    /// never hibernated looks like this.
    Inactive,
}

impl HibernationState {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            HibernationState::Hibernated => "hibernated",
            HibernationState::Resumed => "resumed",
            HibernationState::Restored => "restored",
            HibernationState::Inactive => "inactive",
        }
    }

    /// Whether page data is expected to still be present.
    ///
    /// True for every state except `Inactive`. Resuming marks the file, it does
    /// not clear it, so a resumed or restored hibernation file is still worth
    /// recovering — which is exactly the case an examiner loses by treating any
    /// signature other than `hibr` as "nothing here".
    pub fn may_hold_an_image(self) -> bool {
        !matches!(self, HibernationState::Inactive)
    }

    /// A sentence for a report.
    pub fn describe(self) -> &'static str {
        match self {
            HibernationState::Hibernated => {
                "the machine hibernated and has not resumed since, so this file holds a complete \
                 capture of physical memory as it was at that moment"
            }
            HibernationState::Resumed => {
                "the machine resumed from this image; Windows marks the file as consumed rather \
                 than clearing it, so the pages are normally still present and recoverable"
            }
            HibernationState::Restored => {
                "the restore completed and the file was marked reusable; its pages are normally \
                 still present until overwritten by the next hibernation"
            }
            HibernationState::Inactive => {
                "the file is allocated but holds no image, which is what a machine that has never \
                 hibernated looks like"
            }
        }
    }
}

impl fmt::Display for HibernationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the hibernation header states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibernationHeader {
    /// The signature as it appeared, for the record.
    pub signature: [u8; 4],
    /// What that signature means.
    pub state: HibernationState,
    /// Page size in bytes, when the header states a believable one.
    pub page_size: Option<u32>,
    /// The system time written at hibernation, as a Windows FILETIME.
    ///
    /// This is the fact that reaches the timeline: the moment the machine was
    /// suspended.
    pub system_time: Option<u64>,
    /// Number of pages the header claims are stored, when stated.
    pub pages_stored: Option<u32>,
    /// First page of the page-table that maps the stored pages, when stated.
    pub first_table_page: Option<u32>,
}

impl HibernationHeader {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "signature": String::from_utf8_lossy(&self.signature),
            "state": self.state.as_str(),
            "state_detail": self.state.describe(),
            "may_hold_an_image": self.state.may_hold_an_image(),
            "page_size": self.page_size,
            "system_time_filetime": self.system_time,
            "pages_stored": self.pages_stored,
            "first_table_page": self.first_table_page,
        })
    }
}

/// Whether these bytes begin a Windows hibernation file.
///
/// Deliberately strict. `hiberfil.sys` is identified by content rather than by
/// name so that a renamed or carved copy is still found, but a four-byte
/// signature is a low bar on its own — the all-zero case in particular would
/// match any zeroed region. An all-zero header is only accepted as an inactive
/// hibernation file when the caller already believes the file is one, which is
/// what [`identify_named`] is for.
pub fn identify(header: &[u8]) -> Option<HibernationHeader> {
    if header.len() < 8 {
        return None;
    }
    let signature = [header[0], header[1], header[2], header[3]];
    let state = match &signature {
        b"hibr" | b"HIBR" => HibernationState::Hibernated,
        b"wake" | b"WAKE" => HibernationState::Resumed,
        b"RSTR" => HibernationState::Restored,
        _ => return None,
    };
    let found = parse(signature, state, header);

    // `RSTR` is not only a hibernation signature: an NTFS `$LogFile` restart
    // page starts with the same four bytes (see seance_plugin_logfile's
    // `parse_restart_page`), and so do the LFS-style logs Windows services
    // keep — MSDTC.LOG among them. Every NTFS volume carries a $LogFile, so
    // taking the signature alone reported an ordinary log as a hibernation
    // capture of physical memory that then "failed to decode": a claim about
    // the evidence that was never true, on every Windows image examined.
    //
    // The other signatures are distinctive enough to stand alone. This one has
    // to corroborate: a real `PO_MEMORY_IMAGE` carries a power-of-two page size
    // and a plausible hibernation time at fixed offsets, and an NTFS restart
    // page holds its update-sequence array and LSNs there instead. Requiring
    // one of the two keeps a carved hibernation file identifiable while
    // rejecting the log pages.
    if state == HibernationState::Restored
        && found.page_size.is_none()
        && found.system_time.is_none()
    {
        return None;
    }

    Some(found)
}

/// As [`identify`], but for a file the caller already knows is `hiberfil.sys`.
///
/// Only this path accepts an all-zero signature, because only here is there
/// independent evidence that the file is a hibernation file at all. Reporting
/// "present but inactive" is useful — it distinguishes a machine that never
/// hibernates from one whose hibernation file was not collected.
pub fn identify_named(header: &[u8]) -> Option<HibernationHeader> {
    if let Some(found) = identify(header) {
        return Some(found);
    }
    if header.len() >= 8 && header[..8].iter().all(|&b| b == 0) {
        return Some(HibernationHeader {
            signature: [0; 4],
            state: HibernationState::Inactive,
            page_size: None,
            system_time: None,
            pages_stored: None,
            first_table_page: None,
        });
    }
    None
}

/// Read the fields that follow the signature.
///
/// The layout moved between Windows versions, so every field is read
/// defensively and range-checked: a value that cannot be right is reported as
/// absent rather than as a number. A header that states a 3-byte page size has
/// told us it is a layout we do not know, and saying "unknown" is the honest
/// answer.
fn parse(signature: [u8; 4], state: HibernationState, header: &[u8]) -> HibernationHeader {
    let u32_at = |off: usize| -> Option<u32> {
        header
            .get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_at = |off: usize| -> Option<u64> {
        header
            .get(off..off + 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    };

    // `PO_MEMORY_IMAGE`: Signature, Version, CheckSum, LengthSelf, PageSelf,
    // PageSize, then the system-state fields. Offsets are stable across the
    // versions that use this header; later builds moved the rest.
    let page_size =
        u32_at(0x18).filter(|&size| size.is_power_of_two() && (512..=65536).contains(&size));
    let system_time = u64_at(0x20).filter(|&t| plausible_filetime(t));
    let pages_stored = u32_at(0x58).filter(|&n| n > 0 && n < 0x4000_0000);
    let first_table_page = u32_at(0x5C).filter(|&n| n > 0 && n < 0x4000_0000);

    HibernationHeader {
        signature,
        state,
        page_size,
        system_time,
        pages_stored,
        first_table_page,
    }
}

/// Whether a FILETIME could be a real hibernation time.
///
/// Between 1990 and 2100. A hibernation file written before Windows existed, or
/// a century hence, is a field read from the wrong offset — and a fabricated
/// timestamp on a timeline is worse than an absent one.
fn plausible_filetime(value: u64) -> bool {
    /// 1990-01-01 in FILETIME units.
    const LOWER: u64 = 119_600_064_000_000_000;
    /// 2100-01-01 in FILETIME units.
    const UPPER: u64 = 156_953_952_000_000_000;
    (LOWER..UPPER).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with(signature: &[u8; 4]) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_BYTES];
        h[..4].copy_from_slice(signature);
        h[0x18..0x1C].copy_from_slice(&4096u32.to_le_bytes());
        // 2024-06-01 12:00:00 UTC in FILETIME.
        h[0x20..0x28].copy_from_slice(&133_614_720_000_000_000u64.to_le_bytes());
        h[0x58..0x5C].copy_from_slice(&262_144u32.to_le_bytes());
        h[0x5C..0x60].copy_from_slice(&17u32.to_le_bytes());
        h
    }

    /// An NTFS `$LogFile` restart page: `RSTR`, then the update-sequence array
    /// offset and count, then LSNs — not a `PO_MEMORY_IMAGE`. Found by scanning
    /// the CFReDS "Hacking Case" image, where $LogFile and MSDTC.LOG were both
    /// reported as hibernation captures that failed to decode.
    fn ntfs_restart_page() -> Vec<u8> {
        let mut h = vec![0u8; HEADER_BYTES];
        h[..4].copy_from_slice(b"RSTR");
        // UpdateSequenceArrayOffset / Count, as ntfs writes them.
        h[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        h[6..8].copy_from_slice(&0x9u16.to_le_bytes());
        // $LogFile LSN: a counter, not a FILETIME, and not a page size.
        h[8..16].copy_from_slice(&0x0000_0000_0001_A2B3u64.to_le_bytes());
        h
    }

    #[test]
    fn an_ntfs_logfile_restart_page_is_not_a_hibernation_file() {
        assert!(
            identify(&ntfs_restart_page()).is_none(),
            "RSTR alone is shared with NTFS $LogFile; without a plausible page \
             size or hibernation time it must not be called a memory image"
        );
    }

    #[test]
    fn a_restored_hibernation_file_is_still_identified() {
        // The corroboration gate must not cost a real RSTR hibernation file.
        let found = identify(&header_with(b"RSTR")).expect("a real RSTR header still identifies");
        assert_eq!(found.state, HibernationState::Restored);
        assert_eq!(found.page_size, Some(4096));
    }

    #[test]
    fn a_named_hibernation_file_keeps_its_restored_signature() {
        // identify_named has independent evidence the file is hiberfil.sys, so
        // it accepts what the unnamed path now declines.
        let found = identify_named(&ntfs_restart_page());
        assert!(
            found.is_none(),
            "a page that is not a hibernation header is still not one when named"
        );
    }

    #[test]
    fn a_hibernated_machine_is_identified_and_its_state_reported() {
        let found = identify(&header_with(b"hibr")).expect("hibr is a hibernation file");
        assert_eq!(found.state, HibernationState::Hibernated);
        assert!(found.state.may_hold_an_image());
        assert_eq!(found.page_size, Some(4096));
        assert_eq!(found.pages_stored, Some(262_144));
        assert_eq!(found.first_table_page, Some(17));
        assert!(found.system_time.is_some());
    }

    #[test]
    fn a_resumed_image_is_still_reported_as_holding_data() {
        // The case that is most often lost: Windows marks the file on resume
        // rather than clearing it, so a `wake` signature still means there is a
        // memory image on the disk. Treating anything but `hibr` as empty
        // discards it.
        for sig in [b"wake", b"WAKE"] {
            let found = identify(&header_with(sig)).expect("a resumed image is still an image");
            assert_eq!(found.state, HibernationState::Resumed);
            assert!(found.state.may_hold_an_image());
        }
        let restored = identify(&header_with(b"RSTR")).expect("restored is still an image");
        assert_eq!(restored.state, HibernationState::Restored);
        assert!(restored.state.may_hold_an_image());
    }

    #[test]
    fn the_signature_is_matched_in_both_cases_windows_uses() {
        assert!(identify(&header_with(b"hibr")).is_some());
        assert!(identify(&header_with(b"HIBR")).is_some());
    }

    #[test]
    fn an_unrelated_file_is_not_claimed_as_a_hibernation_file() {
        // Content detection runs over every file in an image, so a loose
        // signature match would claim thousands of unrelated files.
        assert!(identify(b"MZ\x90\x00 this is a PE file").is_none());
        assert!(identify(b"SQLite format 3\0").is_none());
        assert!(identify(&[0u8; 64]).is_none(), "zeroes are not a signature");
        assert!(identify(b"hi").is_none(), "too short to judge");
    }

    #[test]
    fn an_all_zero_header_is_inactive_only_when_the_file_is_known_to_be_one() {
        // By name it is a fact worth reporting: this machine has a hibernation
        // file and has never used it. By content alone it would match every
        // zeroed region in the image.
        let zeroes = vec![0u8; HEADER_BYTES];
        assert!(identify(&zeroes).is_none());
        let named = identify_named(&zeroes).expect("named, so the zeroes mean something");
        assert_eq!(named.state, HibernationState::Inactive);
        assert!(!named.state.may_hold_an_image());
    }

    #[test]
    fn a_field_that_cannot_be_right_is_absent_rather_than_wrong() {
        // The header layout moved between Windows versions. A value read from
        // the wrong offset must not become a page size or a timestamp — a
        // fabricated hibernation time on the timeline is worse than none.
        let mut h = header_with(b"hibr");
        h[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes()); // not a page size
        h[0x20..0x28].copy_from_slice(&1u64.to_le_bytes()); // year 1601
        let found = identify(&h).unwrap();
        assert_eq!(found.page_size, None);
        assert_eq!(found.system_time, None);
    }

    #[test]
    fn a_page_size_must_be_a_power_of_two_in_a_believable_range() {
        for bad in [0u32, 3, 100, 1_048_576] {
            let mut h = header_with(b"hibr");
            h[0x18..0x1C].copy_from_slice(&bad.to_le_bytes());
            assert_eq!(
                identify(&h).unwrap().page_size,
                None,
                "{bad} is not a page size"
            );
        }
        for good in [512u32, 4096, 8192, 65536] {
            let mut h = header_with(b"hibr");
            h[0x18..0x1C].copy_from_slice(&good.to_le_bytes());
            assert_eq!(identify(&h).unwrap().page_size, Some(good));
        }
    }

    #[test]
    fn a_non_hibernation_source_is_declined_by_the_reconstructor() {
        use seance_core::data_source::ByteSliceDataSource;
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 0x2000]));
        let err = open(src).expect_err("an all-zero file is not a resumable image");
        assert!(err.is_not_this_format(), "got {err:?}");
    }

    #[test]
    fn a_hibr_header_with_no_restore_data_is_malformed_not_a_silent_empty() {
        use seance_core::data_source::ByteSliceDataSource;
        // A valid HIBR signature and page size but no restore sets (the restore
        // page fields are zero): nothing can be reconstructed, and that must be a
        // stated failure rather than an empty success.
        let mut bytes = vec![0u8; 0x2000];
        bytes[..4].copy_from_slice(b"HIBR");
        bytes[0x18..0x1C].copy_from_slice(&4096u32.to_le_bytes());
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let err = open(src).expect_err("no restore data must not be a silent empty layer");
        assert!(matches!(err, FormatError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn a_hibr_file_shorter_than_the_header_fields_is_malformed_not_a_panic() {
        use seance_core::data_source::ByteSliceDataSource;
        // MEM-040: 0x80 passed the old guard and 0x23f is one byte short of the
        // NT10 kernel page count at 0x238..0x240.
        for len in [0x80usize, 0x100, 0x1d0, 0x23f] {
            let mut bytes = vec![0u8; len];
            bytes[..4].copy_from_slice(b"HIBR");
            bytes[0x18..0x1C].copy_from_slice(&4096u32.to_le_bytes());
            let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
            let err = open(src).expect_err("a truncated header must be refused");
            assert!(
                matches!(err, FormatError::Malformed { .. }),
                "{len:#x} bytes: got {err:?}"
            );
        }
    }

    #[test]
    fn a_restore_pointer_at_the_top_of_the_address_space_does_not_overflow() {
        use seance_core::data_source::ByteSliceDataSource;
        // Found by the hibernation fuzz target: a pointer of u64::MAX pages
        // saturates to u64::MAX bytes, and adding the table-header width to
        // that overflowed.
        let mut bytes = vec![0u8; 0x2000];
        bytes[..4].copy_from_slice(b"HIBR");
        bytes[0x18..0x1C].copy_from_slice(&4096u32.to_le_bytes());
        bytes[0x60..0x78].fill(0xff);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let err = open(src).expect_err("no restorable page");
        assert!(matches!(err, FormatError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn a_hibr_file_exactly_the_header_fields_long_does_not_panic() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut bytes = vec![0u8; 0x240];
        bytes[..4].copy_from_slice(b"HIBR");
        bytes[0x18..0x1C].copy_from_slice(&4096u32.to_le_bytes());
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let err = open(src).expect_err("no restore data");
        assert!(matches!(err, FormatError::Malformed { .. }), "got {err:?}");
    }

    // --- NT6.2+ table-header bits, as observed in real captures (MEM-026) ---
    use crate::layer::MemoryLayer;
    //
    // The builders below replicate the packed-header bit patterns read from two
    // real hibernation files — a Windows 11 build 26200 capture (NT10 layout)
    // and a Server 2012 R2 capture (NT6.2/6.3 layout) — so the dispatch they
    // pin is the one those files exercise. The page blocks themselves are
    // hand-built streams, not Windows output; the codecs are validated
    // separately against Microsoft's own compressor and the real captures.

    fn nt62_header(img: &mut [u8], boot_off: usize, kernel_off: usize, kernel_page: u64) {
        img[..4].copy_from_slice(b"HIBR");
        img[OFF_PAGE_SIZE..OFF_PAGE_SIZE + 4].copy_from_slice(&4096u32.to_le_bytes());
        img[boot_off..boot_off + 8].copy_from_slice(&0u64.to_le_bytes());
        img[kernel_off..kernel_off + 8].copy_from_slice(&kernel_page.to_le_bytes());
    }

    /// Write one compression table at `off`: the packed header (`range_count`
    /// low byte, `compressed` in bits 8..=28, `flags` OR-ed in), one range of
    /// `page_count` pages at `start_page`, then `data`. Returns the offset just
    /// past it.
    fn put_table(
        img: &mut [u8],
        off: usize,
        flags: u32,
        start_page: u64,
        page_count: u64,
        data: &[u8],
    ) -> usize {
        let header: u32 = 1 | ((data.len() as u32) << 8) | flags;
        img[off..off + 4].copy_from_slice(&header.to_le_bytes());
        let range: u64 = (start_page << 4) | (page_count - 1);
        img[off + 4..off + 12].copy_from_slice(&range.to_le_bytes());
        img[off + 12..off + 12 + data.len()].copy_from_slice(data);
        off + 12 + data.len()
    }

    /// A plain-Xpress stream for one page of `fill`: a literal, then a
    /// 4095-byte back-reference at distance 1 through the extended-length
    /// encoding (token length 7 → nibble 15 → byte 255 → u16 = 4095 − 3).
    fn plain_page_stream(fill: u8) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&(1u32 << 30).to_le_bytes()); // bit 31 literal, bit 30 match
        s.push(fill);
        s.extend_from_slice(&7u16.to_le_bytes()); // distance 1, length escapes
        s.push(0x0f); // nibble 15: escapes again
        s.push(0xff); // byte 255: escapes to the u16 form
        s.extend_from_slice(&4092u16.to_le_bytes()); // whole length less the folded 3
        s
    }

    /// An Xpress-Huffman stream for one page of `fill`: a two-symbol code (the
    /// literal, and the match symbol with log2-offset 0 and escaped length),
    /// one literal, then a 4095-byte match at distance 1.
    fn huffman_page_stream(fill: u8) -> Vec<u8> {
        let mut table = vec![0u8; 256];
        // Symbol `fill` (a literal) and symbol 271 (match, length 15 → escaped):
        // both length 1, so canonically `fill` = code 0, 271 = code 1.
        let lit = fill as usize;
        table[lit / 2] |= if lit.is_multiple_of(2) { 0x01 } else { 0x10 };
        table[271 / 2] |= 0x10;
        let mut s = table;
        s.extend_from_slice(&0x4000u16.to_le_bytes()); // bits: 0 (literal), 1 (match)
        s.extend_from_slice(&0u16.to_le_bytes()); // the word the offset read loads
        s.push(0xff); // length 15 + 255 → escapes to the u16 form
        s.extend_from_slice(&4092u16.to_le_bytes()); // 4095 less the minimum match
        s
    }

    fn page_is(layer: &SegmentedLayer, page: u64, fill: u8) -> bool {
        let mut buf = vec![0u8; HIBER_PAGE as usize];
        match layer.read_at(page * HIBER_PAGE, &mut buf) {
            Ok(n) if n == HIBER_PAGE as usize => buf.iter().all(|&b| b == fill),
            _ => false,
        }
    }

    fn incompletes(layer: &SegmentedLayer, reason: IncompleteReason) -> Vec<String> {
        use crate::layer::MemoryLayer;
        layer
            .layer_meta()
            .incomplete()
            .iter()
            .filter(|i| i.reason == reason)
            .map(|i| i.detail.clone())
            .collect()
    }

    /// The Windows 11 26200 capture sets bit 29 of the packed header on 15,326
    /// of its 31,969 kernel tables (the first at byte 33,609,845, header
    /// `0x60179002`). Read as part of a 22-bit size that is 2,103,184 bytes for
    /// a 16-page table; read as a flag over a 21-bit size it is 6,032, and the
    /// next table sits exactly there. The size is the low 21 bits.
    #[test]
    fn a_table_header_with_bit_29_set_is_a_table_whose_size_is_the_low_21_bits() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut img = vec![0u8; 8 * HIBER_PAGE as usize];
        nt62_header(&mut img, OFF_BOOT_RESTORE_NT10, OFF_KERNEL_RESTORE_NT10, 2);
        img[OFF_KERNEL_COUNT_NT10..OFF_KERNEL_COUNT_NT10 + 8].copy_from_slice(&2u64.to_le_bytes());
        let t = 2 * HIBER_PAGE as usize;
        // Stored (uncompressed) pages, so the framing alone is under test.
        let next = put_table(&mut img, t, 1 << 29, 0x100, 1, &[0xAA; 0x1000]);
        put_table(&mut img, next, 0, 0x200, 1, &[0xBB; 0x1000]);

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open(src).expect("both tables restore");
        assert!(page_is(&layer, 0x100, 0xAA), "the bit-29 table's page");
        assert!(
            page_is(&layer, 0x200, 0xBB),
            "the table after it, reached by the 21-bit size"
        );
        assert!(
            incompletes(&layer, IncompleteReason::UnresolvedStructure).is_empty(),
            "a set that restored every page its header counts is complete"
        );
    }

    /// On the NT10 layout bit 30 marks an Xpress-Huffman block: 30,479 of the
    /// 26200 capture's 31,969 kernel tables carry it, none decodes as plain
    /// Xpress (the first back-reference points before the start of the output)
    /// and 30,354 decode as Huffman to exactly their page count.
    #[test]
    fn on_the_nt10_layout_bit_30_marks_an_xpress_huffman_block() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut img = vec![0u8; 8 * HIBER_PAGE as usize];
        nt62_header(&mut img, OFF_BOOT_RESTORE_NT10, OFF_KERNEL_RESTORE_NT10, 2);
        img[OFF_KERNEL_COUNT_NT10..OFF_KERNEL_COUNT_NT10 + 8].copy_from_slice(&2u64.to_le_bytes());
        let t = 2 * HIBER_PAGE as usize;
        let next = put_table(&mut img, t, 1 << 30, 0x100, 1, &huffman_page_stream(b'A'));
        put_table(&mut img, next, 0, 0x200, 1, &plain_page_stream(b'B'));

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open(src).expect("both tables restore");
        assert!(page_is(&layer, 0x100, b'A'), "bit 30: Xpress-Huffman");
        assert!(page_is(&layer, 0x200, b'B'), "no flag: plain Xpress");
        assert!(incompletes(&layer, IncompleteReason::Compressed).is_empty());
    }

    /// On the NT6.2/6.3 layout the same bit means the opposite: bit 30 alone is
    /// `XpressMax`, plain Xpress (103 such tables in the 2012 R2 capture, every
    /// one decoding as plain to its page count), and bit 31 is the Huffman
    /// methods (131 tables there, decoded by the production path already).
    #[test]
    fn on_the_nt62_layout_bit_30_is_plain_xpress_and_bit_31_is_huffman() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut img = vec![0u8; 8 * HIBER_PAGE as usize];
        nt62_header(&mut img, OFF_BOOT_RESTORE_NT62, OFF_KERNEL_RESTORE_NT62, 2);
        img[OFF_KERNEL_COUNT_NT62..OFF_KERNEL_COUNT_NT62 + 8].copy_from_slice(&2u64.to_le_bytes());
        let t = 2 * HIBER_PAGE as usize;
        let next = put_table(&mut img, t, 1 << 30, 0x100, 1, &plain_page_stream(b'P'));
        put_table(
            &mut img,
            next,
            1 << 31,
            0x200,
            1,
            &huffman_page_stream(b'H'),
        );

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open(src).expect("both tables restore");
        assert!(page_is(&layer, 0x100, b'P'), "bit 30: XpressMax, plain");
        assert!(page_is(&layer, 0x200, b'H'), "bit 31: Xpress-Huffman");
        assert!(incompletes(&layer, IncompleteReason::Compressed).is_empty());
    }

    /// Tables name pages in the order Windows wrote them, not physical order:
    /// a later table can hold the page just below an earlier table's. The
    /// pages must still come back from their own addresses, and a run of
    /// consecutive pages assembled from two tables reads through as one.
    #[test]
    fn pages_restored_out_of_physical_order_read_back_from_their_own_addresses() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut img = vec![0u8; 8 * HIBER_PAGE as usize];
        nt62_header(&mut img, OFF_BOOT_RESTORE_NT10, OFF_KERNEL_RESTORE_NT10, 2);
        img[OFF_KERNEL_COUNT_NT10..OFF_KERNEL_COUNT_NT10 + 8].copy_from_slice(&3u64.to_le_bytes());
        let t = 2 * HIBER_PAGE as usize;
        let next = put_table(&mut img, t, 0, 0x101, 1, &[0xAA; 0x1000]);
        let next = put_table(&mut img, next, 0, 0x300, 1, &[0xCC; 0x1000]);
        put_table(&mut img, next, 0, 0x100, 1, &[0xBB; 0x1000]);

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open(src).expect("all three restore");
        assert!(page_is(&layer, 0x100, 0xBB));
        assert!(page_is(&layer, 0x101, 0xAA));
        assert!(page_is(&layer, 0x300, 0xCC));
        // 0x100 and 0x101 are one run and read through as one.
        let mut two = vec![0u8; 2 * HIBER_PAGE as usize];
        let n = layer.read_at(0x100 * HIBER_PAGE, &mut two).unwrap();
        assert_eq!(n, 2 * HIBER_PAGE as usize);
        assert!(two[..HIBER_PAGE as usize].iter().all(|&b| b == 0xBB));
        assert!(two[HIBER_PAGE as usize..].iter().all(|&b| b == 0xAA));
        assert_eq!(layer.segments().len(), 2, "{:?}", layer.segments());
    }

    /// A plain block that does not decode to its pages is a counted gap. Before
    /// this was pinned, a Huffman block fed to the plain decoder produced a
    /// short garbage stream, and the pages it did cover were placed as memory.
    #[test]
    fn a_plain_block_that_does_not_decode_to_its_pages_is_a_gap_not_a_page() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut img = vec![0u8; 8 * HIBER_PAGE as usize];
        nt62_header(&mut img, OFF_BOOT_RESTORE_NT10, OFF_KERNEL_RESTORE_NT10, 2);
        img[OFF_KERNEL_COUNT_NT10..OFF_KERNEL_COUNT_NT10 + 8].copy_from_slice(&2u64.to_le_bytes());
        let t = 2 * HIBER_PAGE as usize;
        // A back-reference before any output, then literals: not a page.
        let mut bad = (1u32 << 31).to_le_bytes().to_vec();
        bad.extend_from_slice(&[0x10, 0x00, b'x', b'y', b'z']);
        let next = put_table(&mut img, t, 0, 0x100, 1, &bad);
        put_table(&mut img, next, 0, 0x200, 1, &plain_page_stream(b'B'));

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open(src).expect("the good table restores");
        assert!(
            !layer.is_valid(0x100 * HIBER_PAGE, HIBER_PAGE),
            "a page whose block did not decode is absent, not garbage"
        );
        assert!(page_is(&layer, 0x200, b'B'));
        let gaps = incompletes(&layer, IncompleteReason::Compressed);
        assert!(
            gaps.iter().any(|d| d.contains("1 page(s)")),
            "the gap is counted: {gaps:?}"
        );
    }

    /// A set that ends before the page count its header states is incomplete,
    /// and says both numbers.
    #[test]
    fn a_set_that_stops_short_of_its_header_count_says_how_far_it_got() {
        use seance_core::data_source::ByteSliceDataSource;
        let mut img = vec![0u8; 8 * HIBER_PAGE as usize];
        nt62_header(&mut img, OFF_BOOT_RESTORE_NT10, OFF_KERNEL_RESTORE_NT10, 2);
        img[OFF_KERNEL_COUNT_NT10..OFF_KERNEL_COUNT_NT10 + 8].copy_from_slice(&3u64.to_le_bytes());
        let t = 2 * HIBER_PAGE as usize;
        let next = put_table(&mut img, t, 0, 0x100, 1, &[0xAA; 0x1000]);
        // Then bytes that are not a table: 200 ranges.
        img[next..next + 4].copy_from_slice(&0xe900_b1c8u32.to_le_bytes());

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open(src).expect("one table restores");
        let stops = incompletes(&layer, IncompleteReason::UnresolvedStructure);
        assert_eq!(stops.len(), 1, "{stops:?}");
        let at = next as u64;
        assert!(
            stops[0].contains(&format!("stopped at byte {at} ")),
            "{}",
            stops[0]
        );
        assert!(
            stops[0].contains("1 of the 3 page(s)"),
            "both numbers are stated: {}",
            stops[0]
        );
        assert!(stops[0].contains("0xe900b1c8"), "{}", stops[0]);
    }

    // --- NT 6.1 (Windows 7) x64, structure-only path ---

    /// Write a *stored* (uncompressed) Xpress-magic block of `page_count` pages
    /// at `off`, each page filled with `fill`. The stored case exercises the
    /// block framing and the range assignment without depending on an Xpress
    /// *encoder* (the decoder itself is validated by the NT6.2 tests).
    fn put_stored_xpress_block(img: &mut [u8], off: usize, page_count: u32, fill: u8) {
        img[off..off + XPRESS_MAGIC.len()].copy_from_slice(XPRESS_MAGIC);
        // compressed_size == raw_len marks the block stored, whatever the magic.
        let raw = page_count * HIBER_PAGE as u32;
        let info: u32 = ((raw - 1) << 10) | (page_count - 1);
        img[off + XPRESS_MAGIC.len()..off + XPRESS_MAGIC.len() + 4]
            .copy_from_slice(&info.to_le_bytes());
        let data = off + XPRESS_HEADER_SIZE;
        for b in img.iter_mut().skip(data).take(raw as usize) {
            *b = fill;
        }
    }

    /// Write an NT6.1 x64 range table at `off`: `Link { next_table_page,
    /// entry_count }` then one `Range { start_page, end_page }`.
    fn put_nt61_table(
        img: &mut [u8],
        off: usize,
        next_table_page: u64,
        start_page: u64,
        end_page: u64,
    ) {
        img[off..off + 8].copy_from_slice(&next_table_page.to_le_bytes());
        img[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes()); // EntryCount
        let r = off + NT61_LINK_SIZE as usize;
        img[r..r + 8].copy_from_slice(&start_page.to_le_bytes());
        img[r + 8..r + 16].copy_from_slice(&end_page.to_le_bytes());
    }

    fn nt61_header(img: &mut [u8]) {
        img[..4].copy_from_slice(b"HIBR");
        img[OFF_PAGE_SIZE..OFF_PAGE_SIZE + 4].copy_from_slice(&4096u32.to_le_bytes());
    }

    #[test]
    fn nt61_x64_reconstructs_pages_and_is_stamped_unvalidated() {
        use crate::layer::MemoryLayer;
        use seance_core::data_source::ByteSliceDataSource;

        // 12 pages: header(0), … , table at page 6, its block at page 7 (0x20
        // header + two 4 KiB pages ends at 0x9020, inside the file).
        let mut img = vec![0u8; 12 * HIBER_PAGE as usize];
        nt61_header(&mut img);
        let table = NT61_INITIAL_OFFSET as usize; // page 6
        put_nt61_table(&mut img, table, 0, 0x100, 0x102); // 2 pages: 0x100,0x101
        put_stored_xpress_block(&mut img, table + HIBER_PAGE as usize, 2, 0xAA);
        // Distinguish the second page so the range walk order is observable.
        let second = table + HIBER_PAGE as usize + XPRESS_HEADER_SIZE + HIBER_PAGE as usize;
        for b in img.iter_mut().skip(second).take(HIBER_PAGE as usize) {
            *b = 0xBB;
        }

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open_legacy_nt61_x64_unvalidated(src).expect("NT6.1 image reconstructs");

        // Physical page 0x100 restored as 0xAA, 0x101 as 0xBB.
        let mut buf = vec![0u8; HIBER_PAGE as usize];
        let n = layer.read_at(0x100 * HIBER_PAGE, &mut buf).unwrap();
        assert_eq!(n, HIBER_PAGE as usize);
        assert!(
            buf.iter().all(|&b| b == 0xAA),
            "page 0x100 is the first block page"
        );
        layer.read_at(0x101 * HIBER_PAGE, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0xBB),
            "page 0x101 is the second block page"
        );

        // The layer must announce, loudly, that this path is unvalidated.
        let stamped = layer
            .layer_meta()
            .incomplete()
            .iter()
            .any(|i| i.reason == IncompleteReason::Unvalidated);
        assert!(
            stamped,
            "an NT6.1 reconstruction must carry the Unvalidated stamp"
        );
        assert_eq!(
            layer.layer_meta().note("hibernation_reconstruction"),
            Some(&serde_json::json!("unvalidated"))
        );
    }

    #[test]
    fn nt61_x64_follows_the_table_linked_list() {
        use seance_core::data_source::ByteSliceDataSource;

        // Table 1 at page 6 links to table 2 at page 9 (past table 1's one-page
        // block at page 7, which ends at 0x8020). Table 2's block is at page 10.
        let mut img = vec![0u8; 12 * HIBER_PAGE as usize];
        nt61_header(&mut img);
        let t1 = NT61_INITIAL_OFFSET as usize; // page 6
        put_nt61_table(&mut img, t1, 9, 0x100, 0x101); // 1 page: 0x100
        put_stored_xpress_block(&mut img, t1 + HIBER_PAGE as usize, 1, 0x11);
        let t2 = 9 * HIBER_PAGE as usize; // page 9
        put_nt61_table(&mut img, t2, 0, 0x200, 0x201); // 1 page: 0x200
        put_stored_xpress_block(&mut img, t2 + HIBER_PAGE as usize, 1, 0x22);

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        let layer = open_legacy_nt61_x64_unvalidated(src).expect("both tables reconstruct");

        let mut buf = vec![0u8; HIBER_PAGE as usize];
        layer.read_at(0x100 * HIBER_PAGE, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x11), "first table's page");
        layer.read_at(0x200 * HIBER_PAGE, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0x22),
            "second table's page, reached via NextTable"
        );
    }

    #[test]
    fn nt61_path_is_opt_in_the_default_reader_declines_the_layout() {
        use seance_core::data_source::ByteSliceDataSource;
        // The same NT6.1 image the opt-in path reconstructs: the default NT6.2
        // reader has zero restore pages here and must refuse rather than guess.
        let mut img = vec![0u8; 12 * HIBER_PAGE as usize];
        nt61_header(&mut img);
        let table = NT61_INITIAL_OFFSET as usize;
        put_nt61_table(&mut img, table, 0, 0x100, 0x102);
        put_stored_xpress_block(&mut img, table + HIBER_PAGE as usize, 2, 0xAA);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
        assert!(
            open(src).is_err(),
            "the NT6.2 reader must not silently accept an NT6.1 image"
        );
    }
}
