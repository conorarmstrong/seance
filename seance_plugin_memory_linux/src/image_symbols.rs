//! Symbols recovered from the image itself, when no symbol file describes it.
//!
//! # What this is for
//!
//! Reading a memory capture needs a description of the kernel that produced it:
//! that `task_struct.comm` is at byte 3008, that `init_task` is at some
//! address. Neither is knowable from the bytes alone and both move with every
//! build, so the description normally arrives as an ISF file matched to the
//! image by its `linux_banner`.
//!
//! When no such file exists the analysis stops — and for a custom build, an
//! appliance, or a kernel old enough that nobody publishes symbols any more,
//! none ever will. But a kernel from roughly 2020 onward carries both halves of
//! that description *in the image*: its own type information as BTF, and its
//! own symbol table as kallsyms. This assembles them into an ISF and lets
//! discovery proceed.
//!
//! # Why this is the fallback and not the default
//!
//! It is tempting to prefer these symbols, since they cannot possibly describe
//! a different build than the one captured. That reasoning is right about
//! provenance and wrong about corroboration.
//!
//! A matched ISF file is checked against the image's own BTF before it is
//! admitted ([`crate::discovery`]'s layout-agreement gate). When it passes,
//! **two independently produced descriptions of the kernel agree**, and a
//! defect in either one is detectable. Symbols recovered here have perfect
//! provenance and no second source: if this crate's BTF or kallsyms decoding is
//! wrong, nothing in the pipeline disagrees with it, because the thing that
//! would have disagreed is what produced the answer.
//!
//! So the matched file stays primary, this is used when there is no
//! alternative, and every surface that reports a result obtained this way says
//! it is single-source. That is the disclosure an examiner has to be able to
//! make on the stand, and it is why [`crate::discovery`] must not run the
//! layout-agreement gate against a table produced here — comparing BTF against
//! itself would pass every time and manufacture a corroboration that does not
//! exist.
//!
//! # Reproducibility
//!
//! There is no file path to cite, so the SHA-256 of the generated document
//! takes its place. Generation is deterministic — the same image yields the
//! same bytes and the same hash — which is what lets a defence expert
//! regenerate the symbols from the evidence and confirm they are the ones the
//! analysis used.

use seance_core::data_source::DataSource;
use seance_core::io::read_full;
use seance_memory::btf::Btf;
use seance_memory::kallsyms::Kallsyms;
use seance_symbols::IsfSource;

/// How far into an image to sweep for the kernel's symbol table.
///
/// The sweep costs about a minute per 15 GiB. This is the same bound the BTF
/// search uses, for the same reason: a capture larger than this gets the search
/// over its first 16 GiB and is told so, rather than adding unbounded minutes
/// to every discovery.
const KALLSYMS_SEARCH_LIMIT: u64 = 16 * 1024 * 1024 * 1024;

/// Only the kernel's own BTF describes this many types.
///
/// A module's BTF carries a handful. Accepting one would build a symbol table
/// describing a fraction of the kernel.
const KERNEL_BTF_MIN_TYPES: usize = 20_000;

/// Whether an examiner's lab permits symbols taken from the evidence.
///
/// Not every lab does, and that is a legitimate position rather than a
/// misunderstanding: a standard operating procedure may require that layouts
/// come from a symbol file the lab has itself validated, precisely so the
/// analysis rests on something outside the evidence. [`Self::Refuse`] restores
/// the older behaviour, where a missing symbol file is the end of the analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImageDerivedSymbols {
    /// Recover symbols from the image when no symbol file matches, and disclose
    /// that this is what happened.
    #[default]
    Allow,
    /// Never. A missing symbol file fails discovery.
    Refuse,
}

/// Symbols assembled from what the kernel says about itself.
#[derive(Debug, Clone)]
pub struct RecoveredSymbols {
    /// The generated ISF, ready to compile, with its hashes.
    pub source: IsfSource,
    /// Physical offset the kernel's BTF was found at.
    pub btf_at: u64,
    /// Physical offset the kernel's symbol table was found at.
    pub kallsyms_at: u64,
    /// Types the BTF described.
    pub type_count: usize,
    /// Symbols the kernel's table held.
    pub symbol_count: usize,
}

impl RecoveredSymbols {
    /// One sentence an examiner can read, and a report can print.
    pub fn summary(&self) -> String {
        format!(
            "layouts from the kernel's own BTF at physical offset {:#x} ({} types) and addresses \
             from its own symbol table at physical offset {:#x} ({} symbols), both read out of \
             this image",
            self.btf_at, self.type_count, self.kallsyms_at, self.symbol_count
        )
    }
}

/// Why symbols could not be recovered from an image, or that they were.
///
/// The unsuccessful outcomes are kept apart because they send an examiner
/// somewhere different: a kernel with no BTF is an old kernel and needs a
/// symbol file, whereas a sweep that ran out of budget has established nothing
/// and can be retried.
#[derive(Debug)]
pub enum Recovery {
    /// Both halves were found and the document generated.
    Recovered(Box<RecoveredSymbols>),
    /// The lab's policy is [`ImageDerivedSymbols::Refuse`].
    Refused,
    /// This kernel carries no BTF of its own — anything much before 2020.
    NoBtf,
    /// BTF is present but the kernel's symbol table was not located.
    NoKallsyms,
    /// The sweep hit [`KALLSYMS_SEARCH_LIMIT`] before finding both halves.
    Capped {
        /// Bytes swept.
        scanned: u64,
        /// Bytes the image holds.
        total: u64,
    },
    /// Both halves were found but would not assemble into a usable document.
    NotUsable(String),
}

impl Recovery {
    /// What to tell an examiner when this did not produce symbols.
    ///
    /// Empty when it did. Each sentence names the next thing to do, because an
    /// examiner reading it has just been told the image cannot be analysed and
    /// the useful part is what to try instead.
    pub fn note(&self) -> String {
        match self {
            Recovery::Recovered(_) => String::new(),
            Recovery::Refused => " Symbols could have been recovered from the image, but this \
                 run was configured to refuse them, so only a matching symbol file will do."
                .to_string(),
            Recovery::NoBtf => " This kernel carries no type information of its own in the \
                 image, so its layouts cannot be recovered from the evidence and a symbol file \
                 is the only way to read it."
                .to_string(),
            Recovery::NoKallsyms => " This kernel's own type information is in the image, but \
                 its symbol table was not located, so member offsets could be recovered from the \
                 evidence and the addresses to read them at could not."
                .to_string(),
            Recovery::Capped { scanned, total } => format!(
                " A search for the kernel's own description of itself covered {scanned} of \
                 {total} bytes before reaching its limit, so whether this image can describe \
                 itself was not established either way."
            ),
            Recovery::NotUsable(why) => format!(
                " The kernel's own description of itself is in the image but did not assemble \
                 into usable layouts: {why}"
            ),
        }
    }
}

/// Assemble symbols from the kernel's own account of itself.
///
/// # No banner is stamped into the document
///
/// It would be easy to: the sweep has already read one out of the image. But a
/// document that declares an identity is checked against the identity the image
/// declares, and both would be the same string taken from the same bytes. The
/// check would pass because it could not fail, which is the circularity this
/// whole path has to avoid rather than repeat.
///
/// So the generated document declares no build, the identity gate records that
/// plainly, and what establishes that these symbols belong to this image is the
/// page-table proof: translating `linux_banner` through tables rooted where
/// these symbols say, and landing on the physical address the sweep found the
/// string at. A wrong table does not survive that.
///
/// It also could not be stamped correctly here even if it should be. An image
/// holds the banner several times over and the copies do not all normalise to
/// one string; which one the kernel's own symbol refers to is settled by the
/// proof, which happens after this returns.
pub fn recover(image: &dyn DataSource, policy: ImageDerivedSymbols) -> Recovery {
    recover_limited(image, policy, KALLSYMS_SEARCH_LIMIT)
}

/// [`recover`] with the sweep bound injectable, so a test can exercise the
/// capped outcome without a 16 GiB fixture.
pub(crate) fn recover_limited(
    image: &dyn DataSource,
    policy: ImageDerivedSymbols,
    limit: u64,
) -> Recovery {
    if policy == ImageDerivedSymbols::Refuse {
        return Recovery::Refused;
    }

    // One sweep, both halves. Each is expensive enough that sweeping twice
    // would double the cost of every discovery that needs this path, and they
    // sit in the same image.
    let Some(found) = sweep(image, limit) else {
        let total = image.size();
        return if limit < total {
            Recovery::Capped {
                scanned: limit,
                total,
            }
        } else {
            Recovery::NoBtf
        };
    };

    let (btf, btf_at, kallsyms, kallsyms_at) = match found {
        Sweep::Both {
            btf,
            btf_at,
            kallsyms,
            kallsyms_at,
        } => (btf, btf_at, kallsyms, kallsyms_at),
        // BTF found, symbol table not: only an absence if the whole image was
        // swept. Under the cap it is the same unestablished outcome as finding
        // neither, and must not be reported as "not located".
        Sweep::BtfOnly => {
            let total = image.size();
            return if limit < total {
                Recovery::Capped {
                    scanned: limit,
                    total,
                }
            } else {
                Recovery::NoKallsyms
            };
        }
    };

    let type_count = btf.type_count();
    let symbol_count = kallsyms.len();
    match seance_memory::btf_isf::to_isf_source_with_symbols(&btf, None, Some(&kallsyms)) {
        Ok(source) => Recovery::Recovered(Box::new(RecoveredSymbols {
            source,
            btf_at,
            kallsyms_at,
            type_count,
            symbol_count,
        })),
        Err(why) => Recovery::NotUsable(why.to_string()),
    }
}

/// What one pass over the image turned up.
enum Sweep {
    Both {
        btf: Box<Btf>,
        btf_at: u64,
        kallsyms: Box<Kallsyms>,
        kallsyms_at: u64,
    },
    /// BTF was found and swept past; no symbol table anywhere.
    BtfOnly,
}

/// Sweep once for both halves.
///
/// Windows overlap, so a structure straddling a boundary is not missed. The
/// overlap is sized for the larger of the two: a kernel's BTF runs to a few
/// megabytes and its symbol table to about three and a half.
fn sweep(image: &dyn DataSource, limit: u64) -> Option<Sweep> {
    const WINDOW: u64 = 64 * 1024 * 1024;
    const OVERLAP: u64 = 16 * 1024 * 1024;

    let end = image.size().min(limit);
    let mut buffer = vec![0u8; WINDOW.min(end.max(1)) as usize];
    let mut btf: Option<(Box<Btf>, u64)> = None;
    let mut kallsyms: Option<(Box<Kallsyms>, u64)> = None;

    let mut at = 0u64;
    while at < end {
        let want = WINDOW.min(end - at) as usize;
        if want > buffer.len() {
            buffer.resize(want, 0);
        }
        if fill_window(image, at, &mut buffer[..want]) {
            let window = &buffer[..want];
            if btf.is_none() {
                if let Some((found, parsed)) = Btf::find_in(window, KERNEL_BTF_MIN_TYPES) {
                    btf = Some((Box::new(parsed), at + found as u64));
                }
            }
            if kallsyms.is_none() {
                if let Some((found, table)) = Kallsyms::find_in(window) {
                    kallsyms = Some((Box::new(table), at + found as u64));
                }
            }
            // Both halves in hand: moved out rather than cloned, since a
            // kernel's BTF runs to six megabytes and its symbol table to two
            // hundred thousand entries. The other arm puts back whatever it
            // moved — taking unconditionally would discard a BTF found in this
            // window while still waiting on the symbol table.
            match (btf, kallsyms) {
                (Some((btf, btf_at)), Some((kallsyms, kallsyms_at))) => {
                    return Some(Sweep::Both {
                        btf,
                        btf_at,
                        kallsyms,
                        kallsyms_at,
                    })
                }
                (held_btf, held_kallsyms) => {
                    btf = held_btf;
                    kallsyms = held_kallsyms;
                }
            }
        }
        at = at.saturating_add(WINDOW.saturating_sub(OVERLAP));
    }

    btf.map(|_| Sweep::BtfOnly)
}

/// Read one window, zero-filling whatever the image does not hold.
///
/// A raw image serves every byte. A LiME/AVML layer serves only the ranges the
/// acquisition captured and returns an error for a read that touches a hole —
/// and x86 memory always has holes: the first page, the legacy ROM area at
/// `0x9f000..0x100000`, the PCI aperture below 4 GiB. Treating that error as
/// "skip the window" discarded 64 MiB of real evidence around every hole, so a
/// kernel whose `.rodata` sat there was reported absent from a LiME capture
/// while the same bytes decoded from a raw one: a false absence.
///
/// Zero-filling the hole is chosen over sweeping per captured segment because
/// it leaves the window and overlap arithmetic exactly as it is: windows still
/// advance by `WINDOW - OVERLAP` over the address space, so a structure that
/// straddles a window boundary is still seen whole, and the physical offset
/// reported for a find is still `at + found`. A hole holds no evidence, so
/// zeros there fabricate nothing — and neither decoder accepts a run of zeros
/// as a candidate. Nothing is done at all until a whole-window read fails or
/// comes up short, so a raw image pays no extra cost.
///
/// Returns `false` only when not one byte of the window could be read.
fn fill_window(image: &dyn DataSource, at: u64, buffer: &mut [u8]) -> bool {
    // `read_full`, never a bare `read_at`. One `read_at` is PERMITTED to return
    // fewer bytes than asked for, and a sparse `PhysicalLayer` does exactly
    // that by design: it clips every read at the end of the acquired run the
    // read started in, because a short count there is the truth and a full one
    // would be a hole served as memory. LiME, AVML, QEMU and segmented captures
    // all arrive through that layer, so this is the normal case for a Linux
    // image, not an edge one.
    //
    // Taking `is_ok()` as a filled window returned `true` on the first short
    // read and skipped the whole refinement below. `sweep` reuses ONE 64 MiB
    // buffer and advances by 48 MiB, so the unwritten tail still held the
    // PREVIOUS window's bytes, and both decoders then scanned them as though
    // they sat at `at`. Two ways that reaches a report: a BTF or symbol table
    // found in the stale tail is given a physical offset it was never read from
    // — up to 48 MiB out, so regenerating from the evidence at that offset
    // finds something else there — and a structure straddling the short read is
    // assembled out of two unrelated regions, whose member offsets then drive
    // every later read. This path is single-source by construction, so nothing
    // downstream disagrees with either.
    //
    // Every byte of the window must come from the image or be zeroed. None may
    // be left over from the last one.
    let want = buffer.len();
    if read_full(image, at, buffer) == want {
        return true;
    }
    // Refine on a short or failed read: megabyte chunks, then pages within a
    // chunk that came up short. Anything still unread at page granularity is a
    // hole, and is zeroed.
    const CHUNK: usize = 1024 * 1024;
    const PAGE: usize = 4096;
    let mut any = false;
    for (index, chunk) in buffer.chunks_mut(CHUNK).enumerate() {
        let chunk_at = at + (index * CHUNK) as u64;
        let chunk_want = chunk.len();
        if read_full(image, chunk_at, chunk) == chunk_want {
            any = true;
            continue;
        }
        for (page_index, page) in chunk.chunks_mut(PAGE).enumerate() {
            let page_at = chunk_at + (page_index * PAGE) as u64;
            let got = read_full(image, page_at, page);
            if got > 0 {
                any = true;
            }
            // Only the bytes the image did not serve: a page clipped at the end
            // of an acquired run keeps the ones it did.
            page[got..].fill(0);
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::io::Write as _;
    use std::sync::Arc;

    /// One AVML block — header, snappy frame stream, trailer — as the
    /// acquisition tool writes it. `end` is the last byte's address, inclusive.
    fn avml_block(start: u64, payload: &[u8]) -> Vec<u8> {
        const MAGIC: u32 = 0x4C4D_5641;
        const VERSION: u32 = 2;
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&(start + payload.len() as u64 - 1).to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        let mut encoder = snap::write::FrameEncoder::new(Vec::new());
        encoder.write_all(payload).expect("in-memory write");
        out.extend_from_slice(&encoder.into_inner().expect("in-memory encode"));
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out
    }

    /// A `DataSource` that CLIPS, exactly as `PhysicalLayer` does: a read is
    /// served only as far as the end of the acquired run it started in, and the
    /// short count is returned verbatim rather than being padded or refused.
    /// That is the documented contract — `Ok(n)` "may be less than `buf.len()`"
    /// — and it is what every real Linux capture arrives through.
    #[derive(Debug)]
    struct ClippingSource {
        /// Bytes available from offset 0 up to this address. Beyond it, nothing.
        run_end: u64,
        fill: u8,
    }

    impl DataSource for ClippingSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            if offset >= self.run_end {
                return Ok(0);
            }
            let available = (self.run_end - offset).min(buf.len() as u64) as usize;
            buf[..available].fill(self.fill);
            Ok(available)
        }

        fn size(&self) -> u64 {
            self.run_end
        }
    }

    /// **The stale tail.** A short read must never leave the previous window's
    /// bytes in the buffer.
    ///
    /// `sweep` reuses one 64 MiB buffer and advances by 48 MiB, so whatever a
    /// read does not overwrite is real memory content from 48 MiB earlier in the
    /// image. Treating a short read as a filled window skipped the refinement
    /// entirely and handed that tail to the BTF and kallsyms decoders as though
    /// it sat at `at`. A table found there is reported at a physical offset it
    /// was never read from, and a structure straddling the boundary is spliced
    /// out of two unrelated regions — neither detectable downstream, because
    /// this path is single-source by construction.
    #[test]
    fn a_short_read_zeroes_the_tail_rather_than_leaving_the_last_window_in_it() {
        const RUN_END: u64 = 0x3000; // ends inside the window, mid-page
        let mut buffer = vec![0xAAu8; 0x8000];

        let source = ClippingSource {
            run_end: RUN_END,
            fill: 0x5A,
        };
        let filled = fill_window(&source, 0, &mut buffer);

        assert!(filled, "the acquired part of the window was readable");
        assert!(
            buffer[..RUN_END as usize].iter().all(|&b| b == 0x5A),
            "every byte the image served must survive"
        );
        assert!(
            buffer[RUN_END as usize..].iter().all(|&b| b == 0),
            "the tail past the end of the acquired run must be zeroed, not left \
             holding the previous window's bytes — 0xAA here stands for real \
             memory content from 48 MiB earlier in the image"
        );
    }

    /// A window entirely past the end of the capture is reported as unread, so
    /// the sweep can say nothing rather than scanning a buffer of zeros it would
    /// otherwise have to treat as evidence.
    #[test]
    fn a_window_wholly_past_the_capture_reads_nothing() {
        let source = ClippingSource {
            run_end: 0x1000,
            fill: 0x5A,
        };
        let mut buffer = vec![0xAAu8; 0x2000];
        assert!(!fill_window(&source, 0x8000, &mut buffer));
        assert!(
            buffer.iter().all(|&b| b == 0),
            "nothing was read, so nothing of the last window may remain"
        );
    }

    /// **The false absence.** A LiME/AVML capture with the x86 legacy hole at
    /// `0x9f000..0x100000`: the layer refuses a read across it, and the sweep
    /// used to drop the whole 64 MiB window on that refusal — everything the
    /// capture held on either side of the hole went unexamined. The window
    /// must instead come back with the captured bytes intact and the hole as
    /// zeros.
    #[test]
    fn a_window_that_touches_a_memory_hole_is_zero_filled_not_discarded() {
        const LOW_END: u64 = 0x9f000;
        const HIGH_START: u64 = 0x100000;
        const HIGH_LEN: u64 = 0x40000;
        let mut file = avml_block(0, &vec![0xAAu8; LOW_END as usize]);
        file.extend_from_slice(&avml_block(HIGH_START, &vec![0xBBu8; HIGH_LEN as usize]));
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(file));
        let layer = seance_memory::formats::avml::open(source).expect("a well-formed capture");

        let mut window = vec![0x11u8; (HIGH_START + HIGH_LEN) as usize];
        // What the sweep saw before: the layer's own read fails on the hole.
        assert!(
            layer.read_at(0, &mut window).is_err(),
            "the layer must refuse a read across a hole, or this test proves nothing"
        );
        assert!(
            fill_window(&layer, 0, &mut window),
            "a window with captured bytes in it must be examined"
        );
        assert!(
            window[..LOW_END as usize].iter().all(|&b| b == 0xAA),
            "the bytes below the hole must be the capture's"
        );
        assert!(
            window[LOW_END as usize..HIGH_START as usize]
                .iter()
                .all(|&b| b == 0),
            "the hole must be zeros, not stale buffer contents"
        );
        assert!(
            window[HIGH_START as usize..].iter().all(|&b| b == 0xBB),
            "the bytes above the hole must be the capture's"
        );

        // A window that lies entirely in a hole holds nothing to examine.
        let mut nothing = vec![0u8; 0x1000];
        assert!(!fill_window(&layer, LOW_END, &mut nothing));
    }

    #[test]
    fn a_lab_that_refuses_image_derived_symbols_gets_no_sweep() {
        let image = ByteSliceDataSource::new(vec![0u8; 4096]);
        let outcome = recover(&image, ImageDerivedSymbols::Refuse);
        assert!(
            matches!(outcome, Recovery::Refused),
            "a refusing policy must not sweep and must not recover"
        );
        assert!(
            outcome.note().contains("configured to refuse"),
            "the note must say the policy refused, not that the image lacks the data"
        );
    }

    #[test]
    fn an_image_with_no_kernel_in_it_recovers_nothing() {
        let image = ByteSliceDataSource::new(vec![0u8; 1024 * 1024]);
        let outcome = recover(&image, ImageDerivedSymbols::Allow);
        assert!(
            matches!(outcome, Recovery::NoBtf),
            "a megabyte of zeros carries no kernel BTF, got {outcome:?}"
        );
    }

    /// A capped sweep is not an absence, and must not be reported as one.
    #[test]
    fn a_sweep_that_ran_out_of_budget_says_so_rather_than_claiming_absence() {
        let image = ByteSliceDataSource::new(vec![0u8; 8 * 1024 * 1024]);
        let outcome = recover_limited(&image, ImageDerivedSymbols::Allow, 1024 * 1024);
        match outcome {
            Recovery::Capped { scanned, total } => {
                assert_eq!(scanned, 1024 * 1024);
                assert_eq!(total, 8 * 1024 * 1024);
            }
            other => panic!("a capped sweep must report Capped, got {other:?}"),
        }
    }

    /// Every unsuccessful outcome tells the examiner something different.
    #[test]
    fn each_failure_note_names_a_different_next_step() {
        let notes = [
            Recovery::Refused.note(),
            Recovery::NoBtf.note(),
            Recovery::NoKallsyms.note(),
            Recovery::Capped {
                scanned: 1,
                total: 2,
            }
            .note(),
        ];
        for note in &notes {
            assert!(
                !note.is_empty(),
                "an unsuccessful outcome must say something"
            );
        }
        for (i, a) in notes.iter().enumerate() {
            for b in notes.iter().skip(i + 1) {
                assert_ne!(a, b, "two outcomes give the examiner the same sentence");
            }
        }
    }
}
