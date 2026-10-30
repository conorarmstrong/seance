//! QEMU `savevm` (suspend-to-disk) reader: the `pc.ram` block becomes the
//! segment list.
//!
//! A savevm file is QEMU's migration stream written to disk: an eight-byte
//! header, then a sequence of *sections*, each introduced by a one-byte marker.
//! The only section that holds guest memory is `ram`, and inside it memory
//! arrives as a stream of `(address | flags)` big-endian words, each optionally
//! followed by a block name and a page of bytes.
//!
//! ## Scope: what phase 1 covers, and what it refuses
//!
//! The format is far larger than its memory-bearing part, and the parts that
//! are not covered are refused rather than guessed at. Concretely:
//!
//! | Construct | Handling |
//! |---|---|
//! | `pc.ram` uncompressed pages (`RAM_SAVE_FLAG_PAGE`) | Mapped. A pass of consecutive pages becomes **one strided run** — see below. |
//! | `pc.ram` fill-byte pages (`RAM_SAVE_FLAG_COMPRESS`, one repeated byte) | Mapped and **expanded on read**, as [`crate::layer::Encoding::Encoded`] runs, and likewise collapsed into strided runs. |
//! | The same guest address sent more than once | The **last** copy is kept — see below. |
//! | RAM blocks other than `pc.ram` (`pc.bios`, `vga.vram`, …) | Not mapped, as upstream. They are device memory, not guest RAM. |
//! | `RAM_SAVE_FLAG_XBZRLE` | Hard error naming it, as upstream. |
//! | Missing `QEVM_CONFIGURATION` / unknown machine type | **Hard error.** See below. |
//! | Device sections after `ram` | The walk stops there and says so; savevm sections carry no length prefix, so they cannot be skipped. |
//!
//! ## Pages are collapsed into strided runs, and the cap counts runs
//!
//! A savevm writes an eight-byte address word before every page, so no two
//! pages are contiguous in the file even when they are contiguous in the guest.
//! Modelled one [`crate::segmented::Segment`] per page, that put
//! [`crate::layer::MAX_SEGMENTS`] (1,048,576) between this reader and 4 GiB of
//! `pc.ram`: every larger guest was refused outright, by a ceiling the index
//! imposed rather than one the evidence did.
//!
//! Pages whose guest addresses are consecutive *and* whose records are equally
//! spaced in the file are therefore accumulated into one strided
//! [`crate::segmented::Segment`] — chunk 4096, stride 4104 for a bulk
//! uncompressed pass, stride 9 for a run of fill-byte pages. A whole migration
//! pass collapses to a single run, the cap bounds **runs** rather than pages,
//! and nothing about the page-to-address mapping is approximated: the stride is
//! *observed* from the first two records of a run, and any page that does not
//! land exactly where the stride says starts a new run. Raising the cap instead
//! would have swapped a hard refusal for an allocation proportional to guest
//! size, which is the same refusal arriving later and less legibly.
//!
//! ## Why an unknown machine type is a hard error
//!
//! Above roughly 3.5 GiB of guest RAM, x86 machine types leave a **PCI hole**
//! in the guest physical address space, and QEMU's stream stores addresses
//! *below* the hole. Reconstructing the guest's real physical addresses
//! therefore requires knowing where that machine type puts the hole
//! (`layers/qemu.py:60-80`). Volatility, when the configuration section is
//! absent, falls back to scanning for a machine-type string and finally
//! **guesses `pc-*-2.0`** (`layers/qemu.py:371`). A wrong guess shifts every
//! physical address above the hole by up to 1 GiB — silently, and in a way that
//! makes every subsequent page-table walk and pool scan wrong while looking
//! entirely plausible. So this reader refuses, and names the machine type it
//! could not place.
//!
//! Because the machine types with a known hole layout are all i386/x86 ones,
//! the guest page size is 4096 by construction; nothing here has to read
//! QEMU's trailing JSON description to find it.
//!
//! ## Fill-byte pages are evidence, not holes
//!
//! `RAM_SAVE_FLAG_COMPRESS` is QEMU's run-length case: the stream stores one
//! byte and the loader (`ram_handle_compressed`) writes 4096 copies of it. The
//! page **is** in the acquisition and its contents **are** known exactly.
//!
//! Reporting those addresses as [`crate::layer::HoleReason::Unmapped`] — as
//! this reader once did — understates the capture in the direction that hides
//! evidence: "the acquisition never had these bytes" instead of "the
//! acquisition recorded that this page is 4096 copies of `0x00`". Those are
//! opposite sentences in a report, and the second one is true. A page of zeros
//! the suspect's machine really did hold is exactly the kind of finding that
//! gets read as "the tool lost this".
//!
//! So [`QemuLayer`] maps them and expands them on read. Each is one
//! [`crate::layer::Encoding::Encoded`] run — 1 stored byte at a file offset,
//! decoding as a unit to 4096 memory bytes — which is what that encoding was
//! defined for, and [`DataSource::physical_map`] locates them to the
//! compression unit with
//! [`seance_core::data_source::ExtentPrecision::Compressed`] rather than
//! pretending to a byte-exact device offset they do not have. Nothing is
//! fabricated: every byte served is the byte the acquisition recorded.
//!
//! ## A re-sent page is the ordinary shape of the stream, and the last one wins
//!
//! `QEVM` is the migration wire format, not a snapshot container, and `savevm`
//! drives the same iterative state machine a live `migrate` does
//! (`qemu_savevm_state` → `qemu_savevm_state_iterate` → `…_complete_precopy`).
//! Nothing in the format says a guest address appears at most once: an iterative
//! or live pre-copy stream re-sends a page every time it is dirtied again, and
//! the last copy is the one that was current when the stream closed. The
//! destination has no merge rule either — `ram_load` simply writes each page
//! into guest RAM at the address on the record as it arrives — so the semantics
//! are *last writer wins*, by construction.
//!
//! Both alternatives are wrong in a way that reaches a report:
//!
//! - **Refusing** the image (which is what handing two segments for one address
//!   to [`SegmentedLayer`] does, and what this reader did) makes a legitimate
//!   migration snapshot fail to open, and the examiner sees "unreadable" for an
//!   image that is perfectly readable.
//! - **Keeping the first** copy serves a page the guest had already overwritten
//!   as though it were the captured state — a stale page, indistinguishable from
//!   a current one.
//!
//! So a repeat replaces the page already recorded for that address — splitting
//! the run that held it, if it was in the middle of one — and what that cost is
//! published as two notes, always, including when they are zero:
//! `qemu_resent_pages` (distinct guest pages the stream sent more than once)
//! and `qemu_superseded_copies` (earlier records discarded in favour of a later
//! one). They are deliberately not one number — one page re-sent a thousand
//! times and a thousand pages re-sent once are the same total and completely
//! different snapshots. They are notes rather than an incompleteness: nothing
//! is missing, and an iterative stream is not a defect.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::{DataSource, PhysicalMap};
use seance_core::io::{read_exact_or_fail, read_full, IncompleteReason};
use tracing::debug;

use super::{Endian, FormatError};
use crate::format::MemoryImageFormat;
#[cfg(test)]
use crate::layer::backed_len;
use crate::layer::{LayerError, MappedRange, MemoryHole, MemoryLayer, MAX_SEGMENTS};
use crate::meta::LayerMeta;
use crate::segmented::{Segment, SegmentedLayer};

const FORMAT: MemoryImageFormat = MemoryImageFormat::QemuSaveVm;

/// `QEVM` followed by a big-endian version word of 3.
const QEVM_MAGIC: [u8; 8] = [b'Q', b'E', b'V', b'M', 0, 0, 0, 3];

// Section markers (`migration/savevm.h`, `QEMU_VM_*`).
const QEVM_EOF: u8 = 0x00;
const QEVM_SECTION_START: u8 = 0x01;
const QEVM_SECTION_PART: u8 = 0x02;
const QEVM_SECTION_END: u8 = 0x03;
const QEVM_SECTION_FULL: u8 = 0x04;
const QEVM_CONFIGURATION: u8 = 0x07;
const QEVM_SECTION_FOOTER: u8 = 0x7E;

// Per-page flags, stored in the low bits of the address word.
const FLAG_COMPRESS: u64 = 0x02;
const FLAG_MEM_SIZE: u64 = 0x04;
const FLAG_PAGE: u64 = 0x08;
const FLAG_EOS: u64 = 0x10;
const FLAG_CONTINUE: u64 = 0x20;
const FLAG_XBZRLE: u64 = 0x40;

/// Guest page size. See the module note: every machine type this reader accepts
/// is x86, so this is 4096 by construction rather than by assumption.
const PAGE_SIZE: u64 = 4096;

/// The one RAM block that is guest memory.
const RAM_BLOCK: &[u8] = b"pc.ram";

/// The name of the savevm section that carries guest memory.
const RAM_SECTION: &[u8] = b"ram";

/// The only `ram` section layout this reader understands.
const RAM_VERSION_ID: u32 = 4;

/// Upper bound on the machine-type string. Real values are ~20 bytes.
const MAX_MACHINE_TYPE_BYTES: u32 = 256;

/// Upper bound on entries in the RAM block-size list. Real guests declare a
/// handful.
const MAX_RAM_BLOCKS: usize = 4096;

/// Where a machine type puts the PCI hole in guest physical address space.
///
/// Transcribed from `layers/qemu.py:60-80`, which in turn cites the QEMU
/// sources for each machine family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PciHole {
    /// The hole only exists if the guest has at least this much RAM.
    minimum: u64,
    /// First guest-physical address of the hole.
    start: u64,
    /// One past the last guest-physical address of the hole.
    end: u64,
}

impl PciHole {
    fn span(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// The hole layout for `machine`, or `None` if it is not one this reader can
/// place.
///
/// Implemented as prefix matching rather than the seven regexes upstream uses;
/// the patterns reduce to "microvm", "xen", and the two `pc-` families, with
/// `pc-i440fx-0.x`/`-1.x` being the only case that differs from its family.
fn pci_hole_for(machine: &str) -> Option<PciHole> {
    const TOP: u64 = 0x1_0000_0000;

    if machine == "microvm" {
        return Some(PciHole {
            minimum: 0xC000_0000,
            start: 0xC000_0000,
            end: TOP,
        });
    }
    if machine == "xen" {
        return Some(PciHole {
            minimum: 0xF000_0000,
            start: 0xF000_0000,
            end: TOP,
        });
    }
    if let Some(version) = machine.strip_prefix("pc-i440fx-") {
        if !starts_with_word_char(version) {
            return None;
        }
        // `^pc-i440fx-[01]\.\d$` is the "old default" layout; every other
        // version, including the catch-all, uses the new one.
        let old_default =
            matches!(version.as_bytes(), [b'0' | b'1', b'.', d] if d.is_ascii_digit());
        return Some(PciHole {
            minimum: 0xE000_0000,
            start: if old_default {
                0xE000_0000
            } else {
                0xC000_0000
            },
            end: TOP,
        });
    }
    if let Some(version) = machine.strip_prefix("pc-q35-") {
        if !starts_with_word_char(version) {
            return None;
        }
        return Some(PciHole {
            minimum: 0xB000_0000,
            start: 0x8000_0000,
            end: TOP,
        });
    }
    None
}

/// Upstream's catch-all patterns require at least one `\w` after the family
/// prefix, so a bare `pc-q35-` matches nothing.
fn starts_with_word_char(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// Open a QEMU savevm file as a memory layer.
///
/// # Errors
///
/// - [`FormatError::NotThisFormat`] when the `QEVM` magic or version word is
///   absent.
/// - [`FormatError::Unsupported`] when the machine type is missing or has no
///   known PCI hole layout, when XBZRLE pages are present, or when the `ram`
///   section declares a `version_id` other than 4. All of these would otherwise
///   produce a confidently wrong address space.
/// - [`FormatError::Malformed`] when the section stream is structurally broken,
///   or when no `pc.ram` page was found at all.
/// - [`FormatError::Io`] when a structural read is short. Truncated evidence
///   fails closed.
pub fn open(source: Arc<dyn DataSource>) -> Result<QemuLayer, FormatError> {
    // The walker borrows the source while it scans; the layer then takes
    // ownership of it, so keep a second handle alive for the borrow.
    let scanning = Arc::clone(&source);
    let mut walker = Walker::new(&*scanning);
    walker.check_header()?;
    walker.walk()?;
    walker.build(source)
}

/// A run of `pc.ram` pages: consecutive guest addresses whose records are
/// equally spaced in the savevm file.
///
/// This is the compact form the walker accumulates in, and the reason the
/// reader's cost is proportional to the *shape* of the stream rather than to
/// the size of the guest. A bulk migration pass — every page of a block, in
/// order, one after another in the file — is a single `PageRun` however large
/// the guest is.
#[derive(Debug, Clone, Copy)]
struct PageRun {
    /// Guest-physical address of the run's first page.
    address: u64,
    /// File offset of the first page's stored bytes: its payload, or its single
    /// fill byte.
    file_offset: u64,
    /// Pages in the run. Zero marks a run every one of whose pages was
    /// superseded, which is kept in place so the surviving runs keep their
    /// indices and is dropped at build time.
    pages: u64,
    /// File distance from one page's stored bytes to the next's, **observed**
    /// from the first two members rather than assumed from the format. Until
    /// the run holds two pages it is just the stored length, and is unused.
    stride: u64,
    /// Whether the pages are `RAM_SAVE_FLAG_COMPRESS` fill bytes, which are one
    /// stored byte standing for a whole page. A run is all one kind or the
    /// other: the two have different stored lengths and different reads.
    fill: bool,
    /// Whether the stream had already sent these addresses before. Carried per
    /// run rather than per page, which is why a page that continues a run must
    /// agree with it: `qemu_resent_pages` is the sum of the page counts of the
    /// runs marked here, and a mixed run would overstate it.
    resent: bool,
}

impl PageRun {
    /// Bytes the file stores for one page of this run.
    fn stored_len(&self) -> u64 {
        if self.fill {
            1
        } else {
            PAGE_SIZE
        }
    }

    /// Guest bytes the run covers.
    fn length(&self) -> u64 {
        self.pages.saturating_mul(PAGE_SIZE)
    }

    /// One past the run's last guest address.
    fn end(&self) -> u64 {
        self.address.saturating_add(self.length())
    }

    /// Where a page continuing this run would have to be stored.
    fn next_file_offset(&self) -> Option<u64> {
        self.pages
            .checked_mul(self.stride)?
            .checked_add(self.file_offset)
    }
}

/// One pass over the savevm section stream.
struct Walker<'a> {
    ds: &'a dyn DataSource,
    size: u64,
    /// Cursor into the savevm file.
    index: u64,
    /// Accumulated page runs, in the order the stream produced them. Runs whose
    /// pages were all superseded are left in place with `pages == 0`.
    runs: Vec<PageRun>,
    /// Run start address to index in `runs`, for the live runs only.
    ///
    /// Ordered rather than hashed, and keyed per *run* rather than per page:
    /// finding the run that already holds a re-sent address is one
    /// `range(..=address).next_back()`, and the index costs one entry per run
    /// instead of one per guest page. A per-page index is what makes opening a
    /// large guest cost memory proportional to its size.
    by_address: BTreeMap<u64, usize>,
    /// The run the next page may continue, if it continues one at all.
    open_run: Option<usize>,
    /// How many earlier **copies** were replaced, which is not how many pages
    /// were re-sent: a page the stream sends four times replaces three copies.
    /// Both numbers are published, separately and under their own names,
    /// because "300 pages of this guest were re-sent" and "one page was re-sent
    /// 300 times" are different accounts of the same stream and only one of
    /// them is true of any given image.
    superseded_copies: u64,
    machine: Option<String>,
    hole: Option<PciHole>,
    /// `true` once the hole was switched off because the guest is too small for
    /// it to exist, which is a different fact from never having had one.
    hole_disabled_by_size: bool,
    ram_blocks: Vec<(String, u64)>,
    /// The block the current run of `CONTINUE` pages belongs to.
    current_block: Vec<u8>,
    /// A `ram` section reached `QEVM_SECTION_END`, so no more memory follows.
    ram_ended: bool,
    /// Why the walk stopped short of the EOF marker, if it did.
    stopped: Option<String>,
}

impl<'a> Walker<'a> {
    fn new(ds: &'a dyn DataSource) -> Self {
        Walker {
            ds,
            size: ds.size(),
            index: 0,
            runs: Vec::new(),
            by_address: BTreeMap::new(),
            open_run: None,
            superseded_copies: 0,
            machine: None,
            hole: None,
            hole_disabled_by_size: false,
            ram_blocks: Vec::new(),
            current_block: Vec::new(),
            ram_ended: false,
            stopped: None,
        }
    }

    // ── Primitive reads. Every one fails closed on a short read. ────────────

    fn take(&mut self, len: usize, what: &str) -> Result<Vec<u8>, FormatError> {
        let mut buf = vec![0u8; len];
        read_exact_or_fail(self.ds, self.index, &mut buf, what)
            .map_err(|e| FormatError::io(FORMAT, format!("{what} at {:#x}", self.index), e))?;
        self.advance(len as u64, what)?;
        Ok(buf)
    }

    fn peek_u8(&self, at: u64, what: &str) -> Result<u8, FormatError> {
        let mut buf = [0u8; 1];
        read_exact_or_fail(self.ds, at, &mut buf, what)
            .map_err(|e| FormatError::io(FORMAT, format!("{what} at {at:#x}"), e))?;
        Ok(buf[0])
    }

    fn read_u8(&mut self, what: &str) -> Result<u8, FormatError> {
        let value = self.peek_u8(self.index, what)?;
        self.advance(1, what)?;
        Ok(value)
    }

    fn read_be_u32(&mut self, what: &str) -> Result<u32, FormatError> {
        let raw = self.take(4, what)?;
        super::u32_at(&raw, 0, Endian::Big)
            .ok_or_else(|| FormatError::malformed(FORMAT, format!("{what} is truncated")))
    }

    fn read_be_u64(&mut self, what: &str) -> Result<u64, FormatError> {
        let raw = self.take(8, what)?;
        super::u64_at(&raw, 0, Endian::Big)
            .ok_or_else(|| FormatError::malformed(FORMAT, format!("{what} is truncated")))
    }

    fn advance(&mut self, by: u64, what: &str) -> Result<(), FormatError> {
        self.index = self.index.checked_add(by).ok_or_else(|| {
            FormatError::malformed(FORMAT, format!("{what} advances the cursor past u64::MAX"))
        })?;
        Ok(())
    }

    fn stop(&mut self, reason: String) {
        debug!(reason = %reason, "QEVM section walk stopped");
        if self.stopped.is_none() {
            self.stopped = Some(reason);
        }
    }

    // ── The walk ────────────────────────────────────────────────────────────

    fn check_header(&mut self) -> Result<(), FormatError> {
        let mut magic = [0u8; 8];
        read_exact_or_fail(self.ds, 0, &mut magic, "QEVM header")
            .map_err(|_| FormatError::not_this(FORMAT, "source is shorter than the QEVM header"))?;
        if magic[0..4] != QEVM_MAGIC[0..4] {
            return Err(FormatError::not_this(FORMAT, "no QEVM magic"));
        }
        if magic != QEVM_MAGIC {
            return Err(FormatError::not_this(
                FORMAT,
                format!(
                    "QEVM version word {:02x?} is not the supported version 3",
                    &magic[4..8]
                ),
            ));
        }
        self.index = 8;
        Ok(())
    }

    /// Read the configuration section and resolve the PCI hole *before* any RAM
    /// is walked, because the hole changes every address the RAM stream yields.
    fn resolve_machine_type(&mut self) -> Result<(), FormatError> {
        if self.index < self.size
            && self.peek_u8(self.index, "first section marker")? == QEVM_CONFIGURATION
        {
            self.advance(1, "configuration marker")?;
            let len = self.read_be_u32("configuration length")?;
            if len == 0 || len > MAX_MACHINE_TYPE_BYTES {
                return Err(FormatError::malformed(
                    FORMAT,
                    format!("configuration section declares an implausible length of {len}"),
                ));
            }
            let raw = self.take(len as usize, "configuration machine type")?;
            let machine = String::from_utf8_lossy(&raw)
                .trim_end_matches('\0')
                .to_string();
            self.machine = Some(machine);
        }

        let Some(machine) = self.machine.clone() else {
            return Err(FormatError::unsupported(
                FORMAT,
                "no QEVM_CONFIGURATION section, so the machine type is unknown. The PCI hole \
                 fixup is machine-type dependent, and guessing it (as upstream does, defaulting \
                 to pc-*-2.0) shifts every guest-physical address above the hole",
            ));
        };
        let Some(hole) = pci_hole_for(&machine) else {
            return Err(FormatError::unsupported(
                FORMAT,
                format!(
                    "machine type {machine:?} has no known PCI hole layout, so guest-physical \
                     addresses above the hole cannot be reconstructed"
                ),
            ));
        };
        self.hole = Some(hole);
        Ok(())
    }

    fn walk(&mut self) -> Result<(), FormatError> {
        self.resolve_machine_type()?;

        let mut sections: HashMap<u32, (Vec<u8>, u32)> = HashMap::new();
        let mut current_id: Option<u32> = None;

        loop {
            if self.index >= self.size {
                self.stop("the stream ended without a QEVM_EOF marker".to_string());
                break;
            }
            let marker = self.read_u8("section marker")?;
            match marker {
                QEVM_EOF => break,
                QEVM_SECTION_START | QEVM_SECTION_FULL => {
                    let id = self.read_be_u32("section id")?;
                    let name_len = self.read_u8("section name length")?;
                    let name = self.take(usize::from(name_len), "section name")?;
                    let _instance_id = self.read_be_u32("section instance id")?;
                    let version_id = self.read_be_u32("section version id")?;
                    sections.insert(id, (name.clone(), version_id));
                    current_id = Some(id);
                    if !self.extract_data(&name, version_id)? {
                        break;
                    }
                }
                QEVM_SECTION_PART | QEVM_SECTION_END => {
                    let id = self.read_be_u32("section id")?;
                    current_id = Some(id);
                    let Some((name, version_id)) = sections.get(&id).cloned() else {
                        self.stop(format!(
                            "section continuation refers to id {id}, which was never started"
                        ));
                        break;
                    };
                    // A section end is not a terminator: QEMU writes the final
                    // chunk of an iterated section's payload *after* it
                    // (`qemu_savevm_state_complete_precopy_iterable`), so the
                    // last of the guest's RAM arrives here.
                    if !self.extract_data(&name, version_id)? {
                        break;
                    }
                    if marker == QEVM_SECTION_END && name == RAM_SECTION {
                        self.ram_ended = true;
                    }
                }
                QEVM_SECTION_FOOTER => {
                    let id = self.read_be_u32("section footer id")?;
                    if current_id != Some(id) {
                        return Err(FormatError::malformed(
                            FORMAT,
                            format!(
                                "section footer names id {id} but the open section is {:?}",
                                current_id
                            ),
                        ));
                    }
                }
                other => {
                    self.stop(format!(
                        "unrecognised section marker {other:#04x} at offset {:#x}",
                        self.index - 1
                    ));
                    break;
                }
            }
        }
        Ok(())
    }

    /// Consume a section's payload. `Ok(false)` means the walk cannot continue
    /// and a stop reason has been recorded.
    fn extract_data(&mut self, name: &[u8], version_id: u32) -> Result<bool, FormatError> {
        if name == RAM_SECTION {
            if version_id != RAM_VERSION_ID {
                return Err(FormatError::unsupported(
                    FORMAT,
                    format!(
                        "ram section declares version_id {version_id}; only {RAM_VERSION_ID} \
                         is understood"
                    ),
                ));
            }
            self.read_ram_pages()?;
            return Ok(true);
        }
        if name == b"dirty-bitmap".as_slice() {
            self.advance(1, "dirty-bitmap section")?;
            return Ok(true);
        }
        if name == b"pbs-state".as_slice() {
            let len = self.read_be_u64("pbs-state length")?;
            self.advance(len, "pbs-state payload")?;
            return Ok(true);
        }
        // Device sections carry no length prefix, so there is no way to step
        // over one. Upstream reads the next payload byte as a section marker
        // and usually stops on the first 0x00; saying so out loud is the honest
        // version of the same behaviour.
        self.stop(format!(
            "section {:?} at offset {:#x} has no length prefix and cannot be stepped over",
            String::from_utf8_lossy(name),
            self.index
        ));
        Ok(false)
    }

    /// Walk one `ram` section's page stream, up to its end-of-stream flag.
    fn read_ram_pages(&mut self) -> Result<(), FormatError> {
        loop {
            if self.index >= self.size {
                return Err(FormatError::malformed(
                    FORMAT,
                    "the ram section ended without an end-of-stream flag",
                ));
            }
            let word = self.read_be_u64("ram page header")?;
            let flags = word & (PAGE_SIZE - 1);
            let address = self.apply_pci_hole(word & !(PAGE_SIZE - 1));

            if flags & FLAG_MEM_SIZE != 0 {
                self.read_block_sizes()?;
            }

            if flags & (FLAG_COMPRESS | FLAG_PAGE) != 0 {
                if flags & FLAG_CONTINUE == 0 {
                    // The name length is a single byte, so it is bounded at 255
                    // by the format itself and needs no cap of ours.
                    let name_len = self.read_u8("ram block name length")?;
                    self.current_block = self.take(usize::from(name_len), "ram block name")?;
                }
                let is_guest_ram = self.current_block == RAM_BLOCK;
                if flags & FLAG_COMPRESS != 0 {
                    let byte_at = self.index;
                    if is_guest_ram {
                        // The page is acquired: one byte standing for 4096
                        // copies of itself. It gets a segment like any other,
                        // and `QemuLayer` expands it on read.
                        self.push_page(byte_at, address, true)?;
                    }
                    self.advance(1, "compressed page byte")?;
                } else {
                    let payload_at = self.index;
                    if is_guest_ram {
                        self.push_page(payload_at, address, false)?;
                    }
                    self.advance(PAGE_SIZE, "ram page payload")?;
                }
            }

            if flags & FLAG_XBZRLE != 0 {
                return Err(FormatError::unsupported(
                    FORMAT,
                    "the ram stream uses XBZRLE delta compression, which has no decoder here",
                ));
            }
            if flags & FLAG_EOS != 0 {
                return Ok(());
            }
        }
    }

    /// The `RAM_SAVE_FLAG_MEM_SIZE` record: a list of `(name, total bytes)`.
    ///
    /// The list has no terminator. It ends when the next byte is zero, which is
    /// the high byte of the following page header's big-endian address word —
    /// so the cursor is deliberately *not* advanced past it.
    fn read_block_sizes(&mut self) -> Result<(), FormatError> {
        for _ in 0..MAX_RAM_BLOCKS {
            let name_len = self.peek_u8(self.index, "ram block list name length")?;
            if name_len == 0 {
                return Ok(());
            }
            self.advance(1, "ram block list name length")?;
            let name = self.take(usize::from(name_len), "ram block list name")?;
            let total = self.read_be_u64("ram block list size")?;
            self.ram_blocks
                .push((String::from_utf8_lossy(&name).to_string(), total));

            if name == RAM_BLOCK {
                self.reconsider_pci_hole(total);
            }
        }
        Err(FormatError::malformed(
            FORMAT,
            format!("the ram block list exceeds {MAX_RAM_BLOCKS} entries"),
        ))
    }

    /// The hole only exists above a machine-type-specific amount of RAM. A
    /// smaller guest has no hole, and applying one would shift every address.
    fn reconsider_pci_hole(&mut self, pc_ram_bytes: u64) {
        if let Some(hole) = self.hole {
            if pc_ram_bytes < hole.minimum {
                debug!(
                    pc_ram_bytes,
                    minimum = hole.minimum,
                    "QEVM guest is below the PCI hole minimum; no hole applied"
                );
                self.hole = None;
                self.hole_disabled_by_size = true;
            }
        }
    }

    fn apply_pci_hole(&self, address: u64) -> u64 {
        match self.hole {
            Some(hole) if address >= hole.start => address.saturating_add(hole.span()),
            _ => address,
        }
    }

    /// Record one mapped page, continuing the run it belongs to where it can.
    ///
    /// A savevm interleaves an eight-byte address word before every page, so
    /// two pages adjacent in the guest's address space are 4104 bytes apart in
    /// the file. They do not share a *contiguous* extent — but they do share a
    /// strided run, and collapsing a bulk pass into one is what removed this
    /// reader's 4 GiB guest ceiling. See the module documentation.
    ///
    /// A fill-byte page passes through here too, with `is_fill` set and
    /// `file_offset` naming its single stored byte. Its run's chunks are one
    /// stored byte each, decoding to a whole page; [`QemuLayer`] is the only
    /// thing that reads through them.
    ///
    /// # A guest address the stream has already sent
    ///
    /// Replaces the earlier copy rather than adding a second run for the same
    /// address, splitting the run that held it if the address was in its middle.
    /// An iterative or live pre-copy stream re-sends every page it sees dirtied
    /// again, and the destination writes each copy over the last, so the newest
    /// record is what the guest held when the stream closed — see the module
    /// note. The two things this must not do are refuse the image (a legitimate
    /// snapshot then reads as unreadable) and keep the first copy (a page the
    /// guest had already overwritten is then served as current evidence).
    fn push_page(
        &mut self,
        file_offset: u64,
        address: u64,
        is_fill: bool,
    ) -> Result<(), FormatError> {
        let resent = self.supersede(address)?;
        self.append(file_offset, address, is_fill, resent)
    }

    /// Drop `address` from the run that already carries it, reporting whether
    /// there was one.
    ///
    /// Guest addresses are page-aligned by construction — the stream's address
    /// word is masked to the page, and the PCI-hole displacement is a
    /// page-aligned constant — so a run's pages divide cleanly and the head and
    /// tail below are whole pages.
    fn supersede(&mut self, address: u64) -> Result<bool, FormatError> {
        let Some((&start, &at)) = self.by_address.range(..=address).next_back() else {
            return Ok(false);
        };
        let run = self.runs[at];
        if address >= run.end() {
            return Ok(false);
        }
        self.superseded_copies = self.superseded_copies.saturating_add(1);

        let head_pages = (address - run.address) / PAGE_SIZE;
        let tail_pages = run.pages - head_pages - 1;

        if head_pages == 0 && tail_pages == 0 {
            // The run was this one page. Leaving a zero-page run behind keeps
            // every other run's index valid; `build` drops it.
            self.by_address.remove(&start);
            self.runs[at].pages = 0;
            if self.open_run == Some(at) {
                self.open_run = None;
            }
            return Ok(true);
        }
        if head_pages == 0 {
            // The run now starts one page later, and one stride further into
            // the file.
            {
                let run = &mut self.runs[at];
                run.address += PAGE_SIZE;
                run.file_offset += run.stride;
                run.pages -= 1;
            }
            let moved = self.runs[at].address;
            self.by_address.remove(&start);
            self.by_address.insert(moved, at);
            return Ok(true);
        }
        if tail_pages == 0 {
            self.runs[at].pages -= 1;
            return Ok(true);
        }
        // The address is inside the run: the head keeps the index and the key,
        // and the tail becomes a run of its own. Both keep the original's
        // `resent` value, because only the page between them was sent twice.
        let tail = PageRun {
            address: address + PAGE_SIZE,
            file_offset: run.file_offset + (head_pages + 1) * run.stride,
            pages: tail_pages,
            stride: run.stride,
            fill: run.fill,
            resent: run.resent,
        };
        self.runs[at].pages = head_pages;
        self.push_run(tail)?;
        Ok(true)
    }

    /// Continue the open run with this page, or start a new one.
    fn append(
        &mut self,
        file_offset: u64,
        address: u64,
        is_fill: bool,
        resent: bool,
    ) -> Result<(), FormatError> {
        let stored = if is_fill { 1 } else { PAGE_SIZE };
        if let Some(at) = self.open_run {
            let run = self.runs[at];
            // A page may only join a run it continues in **both** spaces, and
            // whose two published per-page facts it shares. Everything else
            // starts a new run, which is why the collapse can never move a
            // page's bytes: a stride that does not describe this record is a
            // stride the run does not get to claim.
            let continues = run.pages > 0
                && run.fill == is_fill
                && run.resent == resent
                && run.end() == address;
            if continues {
                if run.pages == 1 {
                    // The second page fixes the run's stride. It has to leave
                    // the first page's stored bytes intact, or the two records
                    // overlap in the file and one is being read out of the
                    // other's bytes. A page stored *before* the run's first is
                    // not a continuation either, and saturates to a stride of
                    // zero, which fails the same check.
                    let stride = file_offset.saturating_sub(run.file_offset);
                    if stride >= stored {
                        let open = &mut self.runs[at];
                        open.stride = stride;
                        open.pages = 2;
                        return Ok(());
                    }
                } else if run.next_file_offset() == Some(file_offset) {
                    self.runs[at].pages += 1;
                    return Ok(());
                }
            }
        }
        self.push_run(PageRun {
            address,
            file_offset,
            pages: 1,
            stride: stored,
            fill: is_fill,
            resent,
        })
    }

    /// Add a run, refusing above the run cap.
    ///
    /// The cap bounds runs, which is what [`MAX_SEGMENTS`] was always meant to
    /// bound. Reaching it now takes a stream whose pages are genuinely scattered
    /// — over a million separate places — rather than merely a large guest, and
    /// it is still a refusal, because a partial map of a guest's RAM presented
    /// as a whole one is exactly the quiet wrongness this crate exists to
    /// prevent.
    fn push_run(&mut self, run: PageRun) -> Result<(), FormatError> {
        if self.runs.len() >= MAX_SEGMENTS {
            return Err(FormatError::unsupported(
                FORMAT,
                format!(
                    "the pc.ram pages of this stream do not reduce to fewer than {MAX_SEGMENTS} \
                     runs of consecutive, evenly spaced pages, so the guest cannot be indexed \
                     without exceeding the run cap. Refusing rather than mapping part of the guest"
                ),
            ));
        }
        let at = self.runs.len();
        self.by_address.insert(run.address, at);
        self.runs.push(run);
        self.open_run = Some(at);
        Ok(())
    }

    // ── Result assembly ─────────────────────────────────────────────────────

    fn build(self, source: Arc<dyn DataSource>) -> Result<QemuLayer, FormatError> {
        // Runs emptied by a later copy of every page they held are bookkeeping,
        // not memory, and only the survivors describe the snapshot.
        let live: Vec<PageRun> = self.runs.iter().copied().filter(|r| r.pages > 0).collect();
        if live.is_empty() {
            // A fill-byte page is mapped like any other, so an image made
            // entirely of them still produces runs and never reaches here.
            let detail = match &self.stopped {
                Some(reason) => {
                    format!("no pc.ram pages were mapped; the walk stopped: {reason}")
                }
                None => "no pc.ram pages were found in the stream".to_string(),
            };
            return Err(FormatError::malformed(FORMAT, detail));
        }

        let machine = self.machine.clone().unwrap_or_default();
        let pc_ram_bytes = self
            .ram_blocks
            .iter()
            .find(|(name, _)| name == "pc.ram")
            .map(|(_, size)| *size);

        // Counted over the pages that survived, not over the records the
        // stream carried: a fill-byte page a later copy superseded is not served
        // as a fill byte, and saying otherwise would describe the image as
        // holding run-length pages it does not hold.
        let fill_page_count: u64 = live
            .iter()
            .filter(|r| r.fill)
            .fold(0u64, |acc, r| acc.saturating_add(r.pages));
        let first_fill_address = live.iter().filter(|r| r.fill).map(|r| r.address).min();
        let mapped_pages: u64 = live.iter().fold(0u64, |acc, r| acc.saturating_add(r.pages));

        let mut segments = Vec::with_capacity(live.len());
        for run in &live {
            let length = run.pages.checked_mul(PAGE_SIZE).ok_or_else(|| {
                FormatError::malformed(
                    FORMAT,
                    format!(
                        "the run of {} pc.ram page(s) at {:#x} extends past the end of the 64-bit \
                         address space",
                        run.pages, run.address
                    ),
                )
            })?;
            // Chunk 4096 in both spaces for an ordinary page; 4096 memory bytes
            // from one stored byte for a fill page, which `QemuLayer` expands
            // and `SegmentedLayer` refuses to serve raw.
            segments.push(Segment::chunked(
                run.file_offset,
                run.address,
                length,
                PAGE_SIZE,
                run.stored_len(),
                run.stride,
            ));
        }

        let mut meta = LayerMeta::new(FORMAT)
            .with_note("qemu_machine_type", machine)
            .with_note("qemu_page_size", PAGE_SIZE)
            // Runs and pages are separate numbers because the collapse makes
            // them separate facts: a bulk pass of a million pages is one run,
            // and reporting only the run count would understate the capture by
            // six orders of magnitude.
            .with_note("qemu_mapped_runs", live.len() as u64)
            .with_note("qemu_mapped_pages", mapped_pages)
            .with_note("qemu_compressed_pages", fill_page_count);

        match self.hole {
            Some(hole) => {
                meta = meta
                    .with_note("qemu_pci_hole_start", hole.start)
                    .with_note("qemu_pci_hole_end", hole.end);
            }
            None => {
                meta = meta.with_note(
                    "qemu_pci_hole_applied",
                    if self.hole_disabled_by_size {
                        "no: the guest is below the machine type's hole minimum"
                    } else {
                        "no"
                    },
                );
            }
        }

        if let Some(bytes) = pc_ram_bytes {
            meta = meta.with_note("qemu_pc_ram_bytes", bytes);
            // The top of the guest's physical address space: RAM plus the hole
            // it is displaced by, which is what `size()` should be compared to.
            let declared_top = match self.hole {
                Some(hole) if bytes > hole.start => bytes.saturating_add(hole.span()),
                _ => bytes,
            };
            meta = meta.with_declared_size(declared_top);
        }

        if fill_page_count > 0 {
            let first = first_fill_address
                .map(|a| format!("{a:#x}"))
                .unwrap_or_else(|| "unknown".to_string());
            // Recorded, not flagged incomplete: these pages are acquired and
            // are served in full. What a report should say about them is how
            // they were stored, which is a note.
            meta = meta.with_note(
                "qemu_fill_byte_pages",
                format!(
                    "{fill_page_count} pc.ram page(s), the first at {first}, are stored as a single \
                     repeated byte (RAM_SAVE_FLAG_COMPRESS) and are expanded on read"
                ),
            );
        }

        // Two numbers, because they answer different questions and the stream
        // does not constrain either from the other: a snapshot can re-send one
        // page a thousand times or a thousand pages once, and both would be
        // "1000" to a single counter. `qemu_resent_pages` is how much of the
        // guest was re-sent; `qemu_superseded_copies` is how many earlier
        // records this reader discarded in favour of a later one.
        //
        // Stated even when they are zero. "No page in this snapshot was sent
        // twice" is an answer an examiner asking what this reader dropped is
        // entitled to, and an absent key cannot be told apart from a reader
        // that never looked.
        //
        // Counted as the pages of the runs marked re-sent, which is why a page
        // may not join a run whose `resent` value differs from its own: a run
        // mixing the two would credit fresh pages to this number.
        let resent_pages: u64 = live
            .iter()
            .filter(|r| r.resent)
            .fold(0u64, |acc, r| acc.saturating_add(r.pages));
        meta = meta
            .with_note("qemu_resent_pages", resent_pages)
            .with_note("qemu_superseded_copies", self.superseded_copies);

        if resent_pages > 0 {
            // Not an incompleteness: nothing is missing. It is provenance — the
            // stream was iterative, and for these addresses the bytes served are
            // the last copy the stream carried, which is what the destination
            // would have applied and therefore what the guest held.
            meta = meta.with_note(
                "qemu_superseded_pages",
                format!(
                    "{resent_pages} pc.ram page(s) were sent more than once, as an iterative \
                     or live pre-copy migration stream does, and {} earlier copy/copies were \
                     discarded in favour of a later one. The last copy of each page was kept, \
                     because the destination applies pages in arrival order and the later copy \
                     is the one the guest held when the stream closed",
                    self.superseded_copies
                ),
            );
        }

        if let Some(reason) = &self.stopped {
            if self.ram_ended {
                // RAM was fully delivered before the walk stopped, so nothing
                // memory-bearing was missed. Recorded, but not an incompleteness.
                meta = meta.with_note("qemu_walk_stopped", reason.clone());
            } else {
                meta.push_incomplete(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the section walk stopped before the ram section was closed, so any \
                         memory after that point is not mapped: {reason}"
                    ),
                );
            }
        }

        // The segment index is a real `SegmentedLayer`, so sorting, overlap
        // rejection, bounds, chunk arithmetic and hole sizing are the shared
        // implementation and not a second copy of them. Overlap rejection stays
        // meaningful here — two pages at one address are resolved by
        // `push_page` before they get this far, so what reaches it is a
        // genuinely malformed run.
        let index = SegmentedLayer::new(source, segments, meta)
            .map_err(|e| FormatError::layer(FORMAT, e))?;
        Ok(QemuLayer { index })
    }
}

/// A guest-physical address space over a QEMU `savevm` snapshot.
///
/// Ordinary pages are byte-for-byte in the file. Fill-byte pages
/// (`RAM_SAVE_FLAG_COMPRESS`) are one stored byte standing for 4096 copies of
/// itself, and are expanded here — see the module documentation for why that is
/// recovery rather than fabrication. Addresses the snapshot never carried are
/// [`MemoryHole`]s, exactly as for any other segment format.
#[derive(Debug)]
pub struct QemuLayer {
    /// The validated, sorted page runs. A run of ordinary pages is strided —
    /// 4096-byte chunks, 4104 apart in the file for a bulk pass. A run of
    /// fill-byte pages is *encoded*: each chunk is one stored byte standing for
    /// a whole page, which is why the shared layer refuses to serve one and
    /// this reader expands it instead.
    index: SegmentedLayer,
}

impl QemuLayer {
    /// The page runs, sorted by guest-physical address.
    ///
    /// One run per group of consecutive, evenly-spaced pages, not one per page:
    /// use [`Segment::chunk_count`] for the pages a run holds and
    /// [`Segment::chunk_containing`] to place an address inside it.
    pub fn segments(&self) -> &[Segment] {
        self.index.segments()
    }

    /// Bytes of guest RAM the snapshot holds, fill-byte pages included.
    pub fn mapped_len(&self) -> u64 {
        self.index.mapped_len()
    }

    /// The savevm file the pages live in.
    pub fn inner(&self) -> &Arc<dyn DataSource> {
        self.index.inner()
    }

    /// How many mapped pages are stored as a single repeated byte.
    ///
    /// Derived from the index rather than from a second table beside it: a
    /// fill-byte run is exactly a run whose chunks store fewer bytes than they
    /// decode to, so the two cannot drift apart.
    pub fn fill_page_count(&self) -> usize {
        self.index
            .segments()
            .iter()
            .filter(|s| s.is_encoded())
            .fold(0u64, |acc, s| acc.saturating_add(s.chunk_count())) as usize
    }

    fn find(&self, address: u64) -> Option<Segment> {
        let segments = self.index.segments();
        let index = segments.partition_point(|s| s.memory_offset <= address);
        if index == 0 {
            return None;
        }
        let segment = segments[index - 1];
        if address - segment.memory_offset < segment.length {
            Some(segment)
        } else {
            None
        }
    }

    fn next_start(&self, address: u64) -> Option<u64> {
        let segments = self.index.segments();
        let index = segments.partition_point(|s| s.memory_offset <= address);
        segments.get(index).map(|s| s.memory_offset)
    }

    fn hole_at(&self, address: u64) -> MemoryHole {
        let span = self.index.size();
        let end = self.next_start(address).unwrap_or(span);
        MemoryHole::unmapped(address, end.saturating_sub(address))
    }

    /// The byte a fill-byte page repeats.
    ///
    /// `read_exact_or_fail`, not a best-effort read: a fill-byte page whose one
    /// byte is past the end of a truncated snapshot has no known content, and
    /// filling a page with a default would be the exact fabrication this reader
    /// exists to avoid.
    fn fill_byte(&self, file_offset: u64) -> io::Result<u8> {
        let mut byte = [0u8; 1];
        read_exact_or_fail(
            &**self.index.inner(),
            file_offset,
            &mut byte,
            "QEMU fill-byte page",
        )?;
        Ok(byte[0])
    }
}

impl DataSource for QemuLayer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let span = self.index.size();
        if buf.is_empty() || offset >= span {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(span - offset);
        let end = offset + want;

        let mut pos = offset;
        let mut written = 0usize;
        while pos < end {
            let Some(segment) = self.find(pos) else {
                return Err(self.hole_at(pos).into_io());
            };
            // Per chunk, i.e. per page: within a strided run the file offset of
            // an address is not its distance from the run's start, and reading
            // it that way would serve the bytes of a different guest page.
            let Some(chunk) = segment.chunk_containing(pos) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the run at {:#x}+{:#x} was indexed as holding guest address {pos:#x} but \
                         cannot locate the page for it",
                        segment.memory_offset, segment.length
                    ),
                ));
            };
            let within = pos - chunk.memory_offset;
            let take = (chunk.length - within).min(end - pos) as usize;
            if !chunk.is_identity() {
                let byte = self.fill_byte(chunk.file_offset)?;
                buf[written..written + take].fill(byte);
                written += take;
                pos += take as u64;
                continue;
            }
            let got = read_full(
                &**self.index.inner(),
                chunk.file_offset + within,
                &mut buf[written..written + take],
            );
            written += got;
            pos += got as u64;
            if got < take {
                // The snapshot file is shorter than its own page stream claims.
                // The honest short count says so; nothing downstream sees
                // fabricated bytes.
                return Ok(written);
            }
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.index.size()
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.index.get_underlying_path()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.index.open_sibling(suffix)
    }

    /// Locate a guest range in the savevm file.
    ///
    /// Answered by the segment index, which already distinguishes an ordinary
    /// chunk (located exactly) from a fill-byte chunk (located to its
    /// compression unit, at [`seance_core::data_source::ExtentPrecision::Compressed`],
    /// because the position is known to the stored byte and not to the guest
    /// byte). Keeping a second copy of that walk here is how the two would come
    /// to disagree about where a page is.
    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        self.index.physical_map(offset, len)
    }
}

impl MemoryLayer for QemuLayer {
    fn min_address(&self) -> u64 {
        self.index.min_address()
    }

    fn max_address(&self) -> u64 {
        self.index.max_address()
    }

    /// Project onto the savevm file.
    ///
    /// An ordinary page yields an [`crate::layer::Encoding::Identity`] run
    /// clipped to the request. A fill-byte page yields one
    /// [`crate::layer::Encoding::Encoded`] run covering the **whole** page with
    /// `mapped_length` of 1, which is what that encoding contract means: one
    /// stored byte decoding, as a unit, to the run's `length`. Clipping such a
    /// run would describe a blob that decodes to fewer bytes than it does. A run
    /// may therefore begin below `offset` or end above `offset + length`; use
    /// [`MemoryLayer::is_valid`] rather than [`crate::layer::covered_len`] to
    /// ask whether the request was backed.
    ///
    /// Answered by the segment index. Both distinctions this needs — a chunk's
    /// own file offset inside a strided run, and an encoded chunk described
    /// whole — are properties the index already carries, so a second walk here
    /// would only be a copy that could come to disagree with the one `read_at`
    /// and `is_valid` go through.
    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
        self.index.mapping(offset, length)
    }

    /// Whether every byte of the request is backed.
    ///
    /// Asked of the segment index, not by summing [`QemuLayer::mapping`]: an
    /// `Encoded` run deliberately describes its whole page rather than the
    /// clipped request, so summing run lengths would answer a different
    /// question and would report a request inside a fill-byte page as
    /// over-covered.
    fn is_valid(&self, offset: u64, length: u64) -> bool {
        self.index.is_valid(offset, length)
    }

    fn layer_meta(&self) -> &LayerMeta {
        self.index.layer_meta()
    }

    fn as_data_source(&self) -> &dyn DataSource {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::Encoding;
    use seance_core::data_source::{ByteSliceDataSource, DeviceImageSource, ExtentPrecision};

    // ── Synthetic fixtures, built byte by byte ──────────────────────────────

    /// Builds a savevm byte stream. Every field is written explicitly so a test
    /// can produce a malformed one by asking for it.
    struct Builder {
        out: Vec<u8>,
    }

    impl Builder {
        fn new() -> Self {
            let mut out = Vec::new();
            out.extend_from_slice(&QEVM_MAGIC);
            Builder { out }
        }

        fn be32(&mut self, v: u32) {
            self.out.extend_from_slice(&v.to_be_bytes());
        }

        fn be64(&mut self, v: u64) {
            self.out.extend_from_slice(&v.to_be_bytes());
        }

        fn configuration(mut self, machine: &str) -> Self {
            self.out.push(QEVM_CONFIGURATION);
            self.be32(machine.len() as u32);
            self.out.extend_from_slice(machine.as_bytes());
            self
        }

        fn section_start(mut self, id: u32, name: &str, version_id: u32) -> Self {
            self.out.push(QEVM_SECTION_START);
            self.be32(id);
            self.out.push(name.len() as u8);
            self.out.extend_from_slice(name.as_bytes());
            self.be32(0); // instance id
            self.be32(version_id);
            self
        }

        /// Close an iterated `ram` section the way QEMU does: the SECTION_END
        /// marker is followed by the section's *final* payload chunk, which
        /// here is empty and so is just an end-of-stream word.
        fn ram_section_end(mut self, id: u32) -> Self {
            self.out.push(QEVM_SECTION_END);
            self.be32(id);
            self.be64(FLAG_EOS);
            self
        }

        /// A bare SECTION_END marker with no payload behind it.
        fn section_end_marker(mut self, id: u32) -> Self {
            self.out.push(QEVM_SECTION_END);
            self.be32(id);
            self
        }

        fn footer(mut self, id: u32) -> Self {
            self.out.push(QEVM_SECTION_FOOTER);
            self.be32(id);
            self
        }

        fn eof(mut self) -> Self {
            self.out.push(QEVM_EOF);
            self
        }

        /// The `RAM_SAVE_FLAG_MEM_SIZE` record. The list has no terminator; the
        /// next page header's zero high byte ends it, exactly as in a real file.
        fn mem_size(mut self, blocks: &[(&str, u64)]) -> Self {
            let total: u64 = blocks.iter().map(|(_, s)| *s).sum();
            self.be64(total | FLAG_MEM_SIZE);
            for (name, size) in blocks {
                self.out.push(name.len() as u8);
                self.out.extend_from_slice(name.as_bytes());
                self.be64(*size);
            }
            self
        }

        fn page(mut self, address: u64, block: Option<&str>, fill: u8) -> Self {
            let mut flags = FLAG_PAGE;
            if block.is_none() {
                flags |= FLAG_CONTINUE;
            }
            self.be64(address | flags);
            if let Some(name) = block {
                self.out.push(name.len() as u8);
                self.out.extend_from_slice(name.as_bytes());
            }
            self.out.resize(self.out.len() + PAGE_SIZE as usize, fill);
            self
        }

        fn compressed_page(mut self, address: u64, block: Option<&str>, byte: u8) -> Self {
            let mut flags = FLAG_COMPRESS;
            if block.is_none() {
                flags |= FLAG_CONTINUE;
            }
            self.be64(address | flags);
            if let Some(name) = block {
                self.out.push(name.len() as u8);
                self.out.extend_from_slice(name.as_bytes());
            }
            self.out.push(byte);
            self
        }

        fn xbzrle_page(mut self, address: u64) -> Self {
            self.be64(address | FLAG_XBZRLE);
            self
        }

        fn eos(mut self) -> Self {
            self.be64(FLAG_EOS);
            self
        }

        /// A device section: a name, then a payload with no length prefix,
        /// which is exactly why the walk cannot step over it.
        fn device_section(mut self, id: u32, name: &str) -> Self {
            self.out.push(QEVM_SECTION_START);
            self.be32(id);
            self.out.push(name.len() as u8);
            self.out.extend_from_slice(name.as_bytes());
            self.be32(0);
            self.be32(1);
            self.out.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
            self
        }

        fn finish(self) -> Vec<u8> {
            self.out
        }
    }

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    /// Two contiguous pages, then a gap, then one more: a small guest whose
    /// machine type has a PCI hole that its size switches off.
    fn small_guest() -> Builder {
        Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x4000)])
            .page(0x0000, Some("pc.ram"), 0xA1)
            .page(0x1000, None, 0xA2)
            .page(0x3000, None, 0xB3)
            .eos()
            .ram_section_end(0)
            .footer(0)
            .eof()
    }

    // ── Valid image ─────────────────────────────────────────────────────────

    /// The `is_valid` override must agree with the trait's definition of it.
    ///
    /// Answered from the segment index rather than from `mapping`, which avoids
    /// building a run list and is therefore an optimisation of a definition the
    /// trait states as `backed_len` over `mapping`. Two paths to one answer can
    /// drift, and a drift is invisible from either side: the index would call a
    /// page present while a read through `mapping` refuses it, or the reverse.
    ///
    /// A fill-byte page is included deliberately — it is stored as a single
    /// compressed byte and projected as an `Encoded` run over the whole page,
    /// which is exactly the shape that made summing run lengths wrong.
    #[test]
    fn the_is_valid_override_agrees_with_backed_len_over_mapping() {
        let layer = open(source(guest_with_fill_page(0x22))).expect("a well-formed savevm");

        let definition = |offset: u64, len: u64| match layer.mapping(offset, len) {
            Ok(runs) => backed_len(&runs, offset, len) == len,
            Err(_) => false,
        };

        for &(offset, len) in &[
            (0u64, 1u64),
            (0, 0x1000),
            (0x400, 0x100),   // inside a stored page
            (0x0FF0, 0x20),   // across a stored page into the fill page
            (0x1400, 0x100),  // inside the fill page
            (0x1FF0, 0x20),   // out of the fill page into a stored one
            (0x2000, 0x1000), // the last captured page, exactly
            (0x2FF0, 0x20),   // off the end of what was captured
            (0x8000, 0x10),   // above the top
        ] {
            assert_eq!(
                layer.is_valid(offset, len),
                definition(offset, len),
                "is_valid disagreed with backed_len over mapping at \
                 offset {offset:#x} len {len:#x}"
            );
        }
    }

    #[test]
    fn a_valid_savevm_maps_its_pc_ram_pages() {
        let layer = open(source(small_guest().finish())).expect("a well-formed savevm");

        assert_eq!(layer.min_address(), 0);
        assert_eq!(layer.max_address(), 0x3FFF);
        assert_eq!(layer.mapped_len(), 0x3000, "three pages were captured");

        let mut page = vec![0u8; 0x1000];
        assert_eq!(layer.read_at(0, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xA1));
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xA2));
        layer.read_at(0x3000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xB3));
    }

    #[test]
    fn a_bulk_pass_of_contiguous_pages_collapses_into_one_strided_run() {
        // **The defect this fixes.** Pages 0x0000 and 0x1000 are adjacent in the
        // guest's address space but 4104 bytes apart in the file, because each
        // carries its own eight-byte address word. Modelled as one segment per
        // page, that put MAX_SEGMENTS (1,048,576) between this reader and 4 GiB
        // of pc.ram and refused every larger guest outright. They share one
        // strided run instead: chunk 4096, stride 4104.
        let pages = 64u64;
        let mut builder = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", pages * PAGE_SIZE)]);
        for i in 0..pages {
            let block = if i == 0 { Some("pc.ram") } else { None };
            builder = builder.page(i * PAGE_SIZE, block, (i % 251) as u8);
        }
        let layer = open(source(builder.eos().ram_section_end(0).eof().finish()))
            .expect("a well-formed bulk pass");

        assert_eq!(
            layer.segments().len(),
            1,
            "a bulk pass is one run, not one run per page"
        );
        let run = layer.segments()[0];
        assert_eq!(run.memory_offset, 0);
        assert_eq!(run.length, pages * PAGE_SIZE);
        assert_eq!(run.chunk, PAGE_SIZE, "one chunk per guest page");
        assert_eq!(
            run.chunk_stored, PAGE_SIZE,
            "an ordinary page is not encoded"
        );
        assert_eq!(
            run.stride,
            PAGE_SIZE + 8,
            "the eight bytes between chunks are the next page's address word"
        );
        assert_eq!(run.chunk_count(), pages);
        assert_eq!(layer.mapped_len(), pages * PAGE_SIZE);
        assert_eq!(layer.layer_meta().note("qemu_mapped_runs").unwrap(), 1);
        assert_eq!(layer.layer_meta().note("qemu_mapped_pages").unwrap(), pages);

        // Every page still reads its own bytes: the collapse is a change of
        // description, never of where a guest address points.
        let mut page = vec![0u8; PAGE_SIZE as usize];
        for i in 0..pages {
            layer.read_at(i * PAGE_SIZE, &mut page).unwrap();
            assert!(
                page.iter().all(|&b| b == (i % 251) as u8),
                "page {i} served the wrong bytes"
            );
        }
        // And a read straddling a chunk boundary does not splice the address
        // word in between into the guest's memory.
        let mut across = vec![0u8; 16];
        layer.read_at(PAGE_SIZE - 8, &mut across).unwrap();
        assert!(across[..8].iter().all(|&b| b == 0));
        assert!(across[8..].iter().all(|&b| b == 1));
    }

    #[test]
    fn pages_the_stream_does_not_lay_out_evenly_stay_separate_runs() {
        // The collapse is only ever allowed where the stream really is even.
        // `small_guest` has a gap in the guest address space after its second
        // page, so the third cannot join the run — and a run that claimed it
        // would be reading it from the wrong offset.
        let layer = open(source(small_guest().finish())).unwrap();
        assert_eq!(layer.segments().len(), 2);
        assert_eq!(layer.segments()[0].chunk_count(), 2);
        assert_eq!(layer.segments()[0].memory_offset, 0);
        assert_eq!(layer.segments()[1].chunk_count(), 1);
        assert_eq!(layer.segments()[1].memory_offset, 0x3000);
        assert_eq!(layer.layer_meta().note("qemu_mapped_runs").unwrap(), 2);
        assert_eq!(layer.layer_meta().note("qemu_mapped_pages").unwrap(), 3);
    }

    #[test]
    fn the_gap_between_runs_is_a_hole_and_not_zeros() {
        let layer = open(source(small_guest().finish())).unwrap();
        let mut buf = vec![0u8; 0x1000];
        let err = layer.read_at(0x2000, &mut buf).expect_err("never captured");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x2000, 0x1000));
    }

    #[test]
    fn blocks_other_than_pc_ram_are_not_mapped() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000), ("vga.vram", 0x1000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .page(0x0000, Some("vga.vram"), 0x22)
            .page(0x1000, Some("pc.ram"), 0x33)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("device memory is simply skipped");
        assert_eq!(layer.mapped_len(), 0x2000);
        // The two guest pages are still one run, and its stride is the real
        // distance between their records — the vga.vram page sits between them
        // in the file. The stride is observed, never assumed from the format.
        assert_eq!(layer.segments().len(), 1);
        assert!(
            layer.segments()[0].stride > PAGE_SIZE + 8,
            "the skipped vga.vram record widens the stride"
        );
        let mut page = vec![0u8; 0x1000];
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x11), "not the vga.vram page");
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x33));
    }

    #[test]
    fn the_final_chunk_after_a_section_end_is_still_read() {
        // QEMU writes the last of the guest's RAM *after* the SECTION_END
        // marker. Treating that marker as a terminator loses it silently.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .section_end_marker(0)
            .page(0x1000, Some("pc.ram"), 0x99)
            .eos()
            .footer(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("both chunks are RAM");
        assert_eq!(layer.mapped_len(), 0x2000);
        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x99));
    }

    #[test]
    fn metadata_records_the_machine_type_and_the_hole_decision() {
        let layer = open(source(small_guest().finish())).unwrap();
        let meta = layer.layer_meta();
        assert_eq!(meta.format(), Some(MemoryImageFormat::QemuSaveVm));
        assert_eq!(
            meta.note("qemu_machine_type").unwrap().as_str(),
            Some("pc-i440fx-2.0")
        );
        assert_eq!(meta.note("qemu_page_size").unwrap(), 4096);
        assert_eq!(meta.note("qemu_pc_ram_bytes").unwrap(), 0x4000);
        assert_eq!(meta.declared_size(), Some(0x4000));
        assert!(meta
            .note("qemu_pci_hole_applied")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("below the machine type's hole minimum")));
        assert_eq!(
            meta.architecture(),
            None,
            "the format proves no architecture"
        );
        assert!(meta.incomplete().is_empty());
    }

    // ── PCI hole ────────────────────────────────────────────────────────────

    #[test]
    fn the_pci_hole_shifts_addresses_above_it_for_a_large_guest() {
        // 4 GiB of pc.ram, so the hole exists: an address at 0xC0000000 in the
        // stream is really 0x100000000 in the guest.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x1_0000_0000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .page(0xC000_0000, None, 0x22)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("a large guest");

        let mut page = vec![0u8; 0x1000];
        layer
            .read_at(0x1_0000_0000, &mut page)
            .expect("the shifted address");
        assert!(page.iter().all(|&b| b == 0x22));
        // And the pre-fixup address is a hole, not a second copy of the page.
        assert!(layer.read_at(0xC000_0000, &mut page).is_err());

        let meta = layer.layer_meta();
        assert_eq!(meta.note("qemu_pci_hole_start").unwrap(), 0xC000_0000u64);
        assert_eq!(meta.note("qemu_pci_hole_end").unwrap(), 0x1_0000_0000u64);
        assert_eq!(
            meta.declared_size(),
            Some(0x1_4000_0000),
            "4 GiB of RAM displaced by the 1 GiB hole"
        );
    }

    #[test]
    fn the_machine_type_table_matches_the_upstream_patterns() {
        let start = |m: &str| pci_hole_for(m).map(|h| h.start);
        // "Old default" i440fx is the only version-sensitive case.
        assert_eq!(start("pc-i440fx-0.9"), Some(0xE000_0000));
        assert_eq!(start("pc-i440fx-1.7"), Some(0xE000_0000));
        assert_eq!(start("pc-i440fx-2.0"), Some(0xC000_0000));
        assert_eq!(start("pc-i440fx-9.1"), Some(0xC000_0000));
        assert_eq!(start("pc-i440fx-10.0"), Some(0xC000_0000));
        assert_eq!(start("pc-i440fx-focal"), Some(0xC000_0000));
        assert_eq!(start("pc-q35-8.2"), Some(0x8000_0000));
        assert_eq!(start("pc-q35-jammy"), Some(0x8000_0000));
        assert_eq!(start("microvm"), Some(0xC000_0000));
        assert_eq!(start("xen"), Some(0xF000_0000));
        // Not placeable: no family prefix, or a prefix with nothing after it.
        assert_eq!(start("virt-8.2"), None);
        assert_eq!(start("pc-q35-"), None);
        assert_eq!(start("pc-i440fx-"), None);
        assert_eq!(start(""), None);
        assert_eq!(
            pci_hole_for("pc-q35-8.2").map(|h| h.minimum),
            Some(0xB000_0000)
        );
    }

    fn guest_with_machine(machine: &str) -> Vec<u8> {
        Builder::new()
            .configuration(machine)
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish()
    }

    #[test]
    fn an_absent_configuration_section_fails_closed_rather_than_guessing() {
        let image = Builder::new()
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let err = open(source(image)).expect_err("upstream guesses pc-*-2.0 here; we must not");
        match err {
            FormatError::Unsupported { ref detail, .. } => {
                assert!(detail.contains("machine type is unknown"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_unplaceable_machine_type_fails_closed_and_names_itself() {
        let err = open(source(guest_with_machine("virt-8.2")))
            .expect_err("no known hole layout for an ARM virt machine");
        match err {
            FormatError::Unsupported { ref detail, .. } => {
                assert!(detail.contains("virt-8.2"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_q35_guest_is_read() {
        let layer = open(source(guest_with_machine("pc-q35-8.2"))).expect("q35 is placeable");
        assert_eq!(layer.mapped_len(), 0x1000);
    }

    // ── Fill-byte (RAM_SAVE_FLAG_COMPRESS) pages ────────────────────────────

    /// One ordinary page, one fill-byte page, one more ordinary page.
    fn guest_with_fill_page(fill: u8) -> Vec<u8> {
        Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x3000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .compressed_page(0x1000, None, fill)
            .page(0x2000, None, 0x33)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish()
    }

    #[test]
    fn a_fill_byte_page_is_expanded_rather_than_reported_as_a_hole() {
        // The defect this guards: RAM_SAVE_FLAG_COMPRESS stores one byte
        // meaning "this page is 4096 copies of me". Reporting the address as an
        // unmapped hole told an examiner the acquisition never held those
        // bytes, when the acquisition recorded their contents exactly. "Never
        // captured" and "captured as a fill byte" are opposite sentences.
        let layer = open(source(guest_with_fill_page(0x5A))).expect("three pages of guest RAM");

        assert_eq!(layer.mapped_len(), 0x3000, "the fill-byte page is acquired");
        assert_eq!(layer.fill_page_count(), 1);
        assert!(layer.is_valid(0x1000, 0x1000));

        let mut page = vec![0u8; 0x1000];
        assert_eq!(layer.read_at(0x1000, &mut page).unwrap(), 0x1000);
        assert!(
            page.iter().all(|&b| b == 0x5A),
            "4096 copies of the byte the snapshot recorded"
        );

        // The pages either side stay located correctly: a fill page occupies
        // one byte of the file, not 4096.
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x11));
        layer.read_at(0x2000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x33));

        // A read straddling the boundary gets both sides, in order.
        let mut across = vec![0u8; 0x20];
        assert_eq!(layer.read_at(0x0FF0, &mut across).unwrap(), 0x20);
        assert!(across[..0x10].iter().all(|&b| b == 0x11));
        assert!(across[0x10..].iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn a_zero_fill_page_and_a_page_nobody_captured_never_render_alike() {
        // The distinction the whole crate exists for, in the one place a QEMU
        // snapshot makes it easy to lose: a guest page the machine really did
        // hold as zeros was CAPTURED, and reads as zeros; the address between
        // it and the next page was not, and errors.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x4000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .compressed_page(0x1000, None, 0x00)
            .page(0x3000, None, 0x33)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).unwrap();

        let mut page = vec![0u8; 0x1000];
        assert_eq!(layer.read_at(0x1000, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0), "captured zeros");
        assert!(layer.is_valid(0x1000, 0x1000));

        let err = layer
            .read_at(0x2000, &mut page)
            .expect_err("this address was never captured");
        assert_eq!(MemoryHole::from_io(&err).unwrap().address, 0x2000);
        assert!(!layer.is_valid(0x2000, 0x1000));
    }

    #[test]
    fn a_fill_byte_page_maps_as_one_encoded_run_of_a_single_stored_byte() {
        let layer = open(source(guest_with_fill_page(0x5A))).unwrap();
        let runs = layer
            .mapping(0x1400, 0x100)
            .expect("the page is backed, encoded");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].encoding, Encoding::Encoded);
        assert_eq!(
            (runs[0].offset, runs[0].length),
            (0x1000, 0x1000),
            "an encoded run describes the whole unit it decodes to"
        );
        assert_eq!(runs[0].mapped_length, 1, "one stored byte");

        // An ordinary page is still an ordinary identity run.
        let runs = layer.mapping(0x2400, 0x100).unwrap();
        assert_eq!(runs[0].encoding, Encoding::Identity);
        assert_eq!((runs[0].offset, runs[0].length), (0x2400, 0x100));
    }

    #[test]
    fn a_fill_byte_page_is_located_to_its_compression_unit_not_to_a_byte() {
        // Over a device image, so "which offset in the evidence file" has a
        // real answer to give.
        let device: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(Arc::new(
            ByteSliceDataSource::new(guest_with_fill_page(0x5A)),
        )));
        let layer = open(device).unwrap();
        let map = layer.physical_map(0x1400, 0x100);
        assert_eq!(
            map.precision,
            ExtentPrecision::Compressed,
            "the position is known to the stored byte, not to the guest byte"
        );
        assert_eq!(map.extents.len(), 1);
        assert!(
            map.extents[0].device_offset.is_some(),
            "the compression unit IS on the device"
        );
        assert_eq!(map.extents[0].length, 0x100);

        // An ordinary page is still exact.
        let map = layer.physical_map(0x2400, 0x100);
        assert_eq!(map.precision, ExtentPrecision::Exact);
    }

    #[test]
    fn an_image_of_nothing_but_fill_byte_pages_is_a_complete_image() {
        // It used to be refused as "nothing could be mapped". Every page in it
        // is present and its contents are known.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .compressed_page(0x0000, Some("pc.ram"), 0xAA)
            .compressed_page(0x1000, None, 0xBB)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("both pages are acquired");
        assert_eq!(layer.mapped_len(), 0x2000);
        assert_eq!(layer.fill_page_count(), 2);
        assert_eq!(
            layer.segments().len(),
            1,
            "consecutive fill pages are one run"
        );
        let mut page = vec![0u8; 0x1000];
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xAA));
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xBB));
        assert!(layer.layer_meta().incomplete().is_empty());
    }

    #[test]
    fn a_run_of_fill_byte_pages_collapses_and_each_page_keeps_its_own_byte() {
        // A large guest's savevm is mostly RAM_SAVE_FLAG_COMPRESS pages, so
        // leaving those a segment each would have left the 4 GiB ceiling
        // standing for exactly the images that hit it. They collapse too, into
        // an *encoded* strided run: nine file bytes per page — the eight-byte
        // address word and the one stored byte — each decoding to 4096 guest
        // bytes.
        let pages = 32u64;
        let mut builder = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", pages * PAGE_SIZE)]);
        for i in 0..pages {
            let block = if i == 0 { Some("pc.ram") } else { None };
            builder = builder.compressed_page(i * PAGE_SIZE, block, (0x40 + i) as u8);
        }
        let layer = open(source(builder.eos().ram_section_end(0).eof().finish()))
            .expect("a pass of fill-byte pages is a complete capture");

        assert_eq!(layer.segments().len(), 1, "one run, not one run per page");
        let run = layer.segments()[0];
        assert!(run.is_encoded());
        assert_eq!(run.chunk, PAGE_SIZE, "each chunk decodes to a whole page");
        assert_eq!(run.chunk_stored, 1, "one stored byte per page");
        assert_eq!(run.stride, 9, "the address word plus the stored byte");
        assert_eq!(run.chunk_count(), pages);
        assert_eq!(layer.mapped_len(), pages * PAGE_SIZE);
        assert_eq!(layer.fill_page_count(), pages as usize);

        // Each page expands to *its own* stored byte. Collapsing the run must
        // not make them all the first page's byte, which is the failure this
        // shape invites.
        let mut page = vec![0u8; PAGE_SIZE as usize];
        for i in 0..pages {
            layer.read_at(i * PAGE_SIZE, &mut page).unwrap();
            assert!(
                page.iter().all(|&b| b == (0x40 + i) as u8),
                "page {i} expanded the wrong stored byte"
            );
        }
    }

    // ── Re-sent pages (iterative / live pre-copy streams) ───────────────────

    #[test]
    fn a_page_the_stream_sent_twice_keeps_the_later_copy() {
        // The defect this guards, in both directions. `QEVM` is the migration
        // wire format: an iterative or live pre-copy stream re-sends a page
        // every time it is dirtied again, and the destination writes each copy
        // over the last. Handing both copies to `SegmentedLayer` made it refuse
        // the whole image as overlapping segments, so a legitimate snapshot read
        // as "unreadable memory image"; keeping the first copy instead would
        // have served a page the guest had already overwritten as the captured
        // state. Neither is what the guest held.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x3000)])
            .page(0x0000, Some("pc.ram"), 0xA1)
            .page(0x1000, None, 0x11) // dirtied again after this was sent
            .page(0x2000, None, 0xA3)
            .page(0x1000, None, 0x22) // the copy that was current at close
            .eos()
            .ram_section_end(0)
            .footer(0)
            .eof()
            .finish();

        let layer = open(source(image)).expect("an iterative stream is a valid snapshot");

        assert_eq!(
            layer.segments().len(),
            3,
            "three distinct guest pages, not four segments"
        );
        assert_eq!(layer.mapped_len(), 0x3000);

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0x22),
            "the last copy is what the guest held when the stream closed"
        );

        // The pages around it are unaffected.
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xA1));
        layer.read_at(0x2000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xA3));

        // And an examiner is told the stream was iterative rather than left to
        // infer it: nothing is missing, so this is a note, not incompleteness.
        let note = layer
            .layer_meta()
            .note("qemu_superseded_pages")
            .and_then(|v| v.as_str())
            .expect("a re-sent page is recorded");
        assert!(
            note.starts_with("1 pc.ram page(s) were sent more than once"),
            "{note}"
        );
        assert!(layer.layer_meta().incomplete().is_empty());
        assert_eq!(layer.layer_meta().note("qemu_mapped_runs").unwrap(), 3);
    }

    #[test]
    fn a_page_resent_inside_a_run_splits_it_and_only_that_page_counts_as_resent() {
        // A pre-copy stream re-sends pages a bulk pass already carried, and the
        // re-sent one is usually in the middle of a run. The run has to give
        // that page up — head, tail, and the later copy on its own — because
        // keeping it would serve the page the guest had already overwritten.
        // The pages either side of the split were not re-sent, and must not be
        // counted as though they were.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x4000)])
            .page(0x0000, Some("pc.ram"), 0xA0)
            .page(0x1000, None, 0xA1)
            .page(0x2000, None, 0xA2)
            .page(0x3000, None, 0xA3)
            .page(0x1000, None, 0xB1) // dirtied again, sent last
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("an iterative stream is a valid snapshot");

        // The head at 0x0000, the tail at 0x2000..0x4000, and the later copy.
        assert_eq!(layer.segments().len(), 3);
        assert_eq!(layer.mapped_len(), 0x4000, "the guest is fully mapped");
        assert_eq!(layer.layer_meta().note("qemu_mapped_pages").unwrap(), 4);

        let mut page = vec![0u8; 0x1000];
        for (address, expected) in [(0x0000u64, 0xA0u8), (0x2000, 0xA2), (0x3000, 0xA3)] {
            layer.read_at(address, &mut page).unwrap();
            assert!(
                page.iter().all(|&b| b == expected),
                "the split moved the bytes at {address:#x}"
            );
        }
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0xB1),
            "the last copy is what the guest held when the stream closed"
        );

        assert_eq!(
            layer.layer_meta().note("qemu_resent_pages").unwrap(),
            1,
            "the pages either side of the split were never re-sent"
        );
        assert_eq!(
            layer.layer_meta().note("qemu_superseded_copies").unwrap(),
            1
        );
        assert!(layer.layer_meta().incomplete().is_empty());
    }

    #[test]
    fn a_page_resent_as_a_fill_byte_page_is_served_as_the_fill_byte() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x1000, Some("pc.ram"), 0x11)
            .compressed_page(0x1000, None, 0x5A) // the guest zeroed/filled it
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("one page, sent twice");

        assert_eq!(layer.segments().len(), 1);
        assert_eq!(layer.fill_page_count(), 1);
        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn a_fill_byte_page_a_later_copy_supersedes_stops_being_a_fill_page() {
        // The bookkeeping half of the same fix: the set of fill-byte offsets
        // must describe only segments that survive. A stale entry in it is how
        // the ordinary page that replaced a fill page would be served as 4096
        // copies of one byte belonging to the record before it.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .compressed_page(0x1000, Some("pc.ram"), 0x5A)
            .page(0x1000, None, 0x11)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("one page, sent twice");

        assert_eq!(layer.segments().len(), 1);
        assert_eq!(
            layer.fill_page_count(),
            0,
            "the surviving copy is an ordinary page"
        );
        assert!(
            layer.layer_meta().note("qemu_fill_byte_pages").is_none(),
            "no page in this image is served as a fill byte"
        );
        assert_eq!(layer.layer_meta().note("qemu_compressed_pages").unwrap(), 0);

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x11));

        // The run is an ordinary identity run, not an encoded one.
        let runs = layer.mapping(0x1000, 0x1000).unwrap();
        assert_eq!(runs[0].encoding, Encoding::Identity);
        assert_eq!(runs[0].mapped_length, 0x1000);
    }

    #[test]
    fn a_stream_that_sends_no_page_twice_says_nothing_about_superseding() {
        // The prose note must stay reserved for the fact it names: a snapshot
        // with no re-sent page must not acquire a claim about iteration. The
        // two numbers are still stated, as zero — "nothing was superseded" and
        // "nobody looked" must not render alike.
        let layer = open(source(small_guest().finish())).unwrap();
        assert!(layer.layer_meta().note("qemu_superseded_pages").is_none());
        assert_eq!(layer.layer_meta().note("qemu_resent_pages").unwrap(), 0);
        assert_eq!(
            layer.layer_meta().note("qemu_superseded_copies").unwrap(),
            0
        );
    }

    #[test]
    fn a_page_sent_many_times_is_one_re_sent_page_and_many_discarded_copies() {
        // The counter this guards used to increment once per replacement and be
        // published as "N pc.ram page(s) were sent more than once". A guest with
        // one hot page in a long pre-copy stream then reported hundreds of
        // re-sent pages when one page was re-sent hundreds of times — the same
        // overstatement, of the same shape, as counting refused translations as
        // suppressed page tables. The two facts are now counted and named
        // separately.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x0000, Some("pc.ram"), 0xA1)
            .page(0x1000, None, 0x11)
            .page(0x1000, None, 0x22)
            .page(0x1000, None, 0x33)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("an iterative stream is a valid snapshot");

        assert_eq!(layer.segments().len(), 2, "two distinct guest pages");
        assert_eq!(
            layer.layer_meta().note("qemu_resent_pages").unwrap(),
            1,
            "one page was re-sent, whatever the copy count"
        );
        assert_eq!(
            layer.layer_meta().note("qemu_superseded_copies").unwrap(),
            2,
            "two earlier copies of it were discarded"
        );
        let note = layer
            .layer_meta()
            .note("qemu_superseded_pages")
            .and_then(|v| v.as_str())
            .expect("the prose names both");
        let opening = "1 pc.ram page(s) were sent more than once";
        assert!(note.starts_with(opening), "{note}");
        assert!(note.contains("2 earlier copy/copies"), "{note}");

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x1000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x33), "the last copy is served");
    }

    /// A savevm file with one byte the storage cannot produce — the shape a
    /// snapshot has when the write was cut short or a sector is bad.
    #[derive(Debug)]
    struct ByteMissing {
        inner: ByteSliceDataSource,
        missing: u64,
    }

    impl DataSource for ByteMissing {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            if offset == self.missing {
                return Ok(0);
            }
            self.inner.read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.size()
        }
    }

    #[test]
    fn a_fill_byte_the_snapshot_file_cannot_produce_fails_closed() {
        // The one stored byte IS the page's entire content. If it cannot be
        // read the content is unknown, and filling 4096 bytes with a default
        // would be precisely the fabrication that expanding these pages must
        // never become.
        let bytes = guest_with_fill_page(0x5A);
        let intact = open(source(bytes.clone())).expect("the stream parses");
        let runs = intact.mapping(0x1000, 1).expect("the fill page is backed");
        let fill_at = runs[0].mapped_offset;

        let broken: Arc<dyn DataSource> = Arc::new(ByteMissing {
            inner: ByteSliceDataSource::new(bytes),
            missing: fill_at,
        });
        // The walk never reads the fill byte — it steps over it — so the layer
        // still opens. The read is where the truth comes out.
        let layer = open(broken).expect("the section stream is intact");
        let mut page = vec![0u8; 0x1000];
        let err = layer
            .read_at(0x1000, &mut page)
            .expect_err("a page whose stored byte is unreadable has no known content");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("fill-byte"), "{err}");
        assert!(page.iter().all(|&b| b == 0), "nothing was fabricated");

        // And the pages either side are untouched by the failure.
        layer.read_at(0x2000, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0x33));
    }

    #[test]
    fn xbzrle_pages_fail_closed_by_name() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .xbzrle_page(0x1000)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let err = open(source(image)).expect_err("XBZRLE has no decoder");
        match err {
            FormatError::Unsupported { ref detail, .. } => {
                assert!(detail.contains("XBZRLE"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // ── The walk stopping ───────────────────────────────────────────────────

    #[test]
    fn a_device_section_after_ram_stops_the_walk_without_flagging_incompleteness() {
        // RAM was closed before the device section, so nothing memory-bearing
        // was missed: it is a note, not an incompleteness.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x1000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .ram_section_end(0)
            .footer(0)
            .device_section(1, "cpu_common")
            .finish();
        let layer = open(source(image)).expect("RAM is complete");
        assert_eq!(layer.mapped_len(), 0x1000);
        assert!(
            layer.layer_meta().incomplete().is_empty(),
            "device state is not memory"
        );
        let stopped = layer.layer_meta().note("qemu_walk_stopped").unwrap();
        assert!(
            stopped.as_str().is_some_and(|s| s.contains("cpu_common")),
            "{stopped}"
        );
    }

    #[test]
    fn a_walk_that_stops_before_ram_closes_is_flagged_incomplete() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x2000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .footer(0)
            .device_section(1, "kvm-tpr-opt")
            .finish();
        let layer = open(source(image)).expect("what was found is still evidence");
        let incomplete = layer.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::UnresolvedStructure);
        assert!(
            incomplete[0].detail.contains("kvm-tpr-opt"),
            "{}",
            incomplete[0].detail
        );
    }

    #[test]
    fn a_stream_that_never_reaches_ram_is_refused_rather_than_returning_an_empty_layer() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .device_section(1, "timer")
            .finish();
        let err = open(source(image)).expect_err("no memory was found at all");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("no pc.ram pages"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_section_continuation_for_an_unopened_id_stops_the_walk() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x1000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .ram_section_end(0)
            .footer(0)
            .section_end_marker(7) // never started
            .eof()
            .finish();
        let layer = open(source(image)).expect("RAM was already complete");
        let stopped = layer.layer_meta().note("qemu_walk_stopped").unwrap();
        assert!(
            stopped
                .as_str()
                .is_some_and(|s| s.contains("never started")),
            "{stopped}"
        );
    }

    // ── Truncated image ─────────────────────────────────────────────────────

    #[test]
    fn a_truncated_header_is_not_claimed() {
        for cut in [0usize, 1, 4, 7] {
            let bytes = QEVM_MAGIC[..cut].to_vec();
            let err = open(source(bytes)).expect_err("a partial header is not a savevm");
            assert!(err.is_not_this_format(), "cut {cut}: {err}");
        }
    }

    #[test]
    fn a_stream_truncated_inside_a_section_header_fails_closed() {
        let full = small_guest().finish();
        // 8 header bytes, then the configuration section: cutting mid-string
        // leaves a machine type that must not be parsed from a padded buffer.
        let err = open(source(full[..14].to_vec()))
            .expect_err("a half-read section header must not parse");
        assert!(matches!(err, FormatError::Io { .. }), "{err}");
    }

    #[test]
    fn a_stream_truncated_inside_the_ram_page_stream_fails_closed() {
        let full = small_guest().finish();
        for cut in [full.len() - 0x2000, full.len() - 0x1800, full.len() - 12] {
            let err = open(source(full[..cut].to_vec()))
                .expect_err("a cut page stream must not yield a layer");
            match err {
                FormatError::Malformed { ref detail, .. } => {
                    assert!(detail.contains("end-of-stream"), "cut {cut}: {detail}")
                }
                FormatError::Io { .. } => {}
                other => panic!("cut {cut}: unexpected error: {other}"),
            }
        }
    }

    // ── Malformed streams ───────────────────────────────────────────────────

    #[test]
    fn a_wrong_version_word_is_not_claimed() {
        let mut bytes = QEVM_MAGIC.to_vec();
        bytes[7] = 2;
        bytes.resize(0x100, 0);
        let err = open(source(bytes)).expect_err("version 2 is not supported");
        assert!(err.is_not_this_format());
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn non_qemu_bytes_are_not_claimed() {
        let err = open(source(vec![0x5A; 0x1000])).expect_err("no QEVM magic");
        assert!(err.is_not_this_format());
        assert!(open(source(Vec::new())).unwrap_err().is_not_this_format());
    }

    #[test]
    fn an_unknown_ram_version_id_fails_closed() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", 5)
            .mem_size(&[("pc.ram", 0x1000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let err = open(source(image)).expect_err("only version 4 is understood");
        match err {
            FormatError::Unsupported { ref detail, .. } => {
                assert!(detail.contains("version_id 5"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_mismatched_section_footer_is_refused() {
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x1000)])
            .page(0x0000, Some("pc.ram"), 0x11)
            .eos()
            .ram_section_end(0)
            .footer(9) // an id that was never the open section
            .eof()
            .finish();
        let err = open(source(image)).expect_err("a footer mismatch means a misparse");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("footer"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_absurd_configuration_length_does_not_allocate_and_is_refused() {
        let mut out = QEVM_MAGIC.to_vec();
        out.push(QEVM_CONFIGURATION);
        out.extend_from_slice(&u32::MAX.to_be_bytes());
        out.resize(0x100, 0);
        let err = open(source(out)).expect_err("a hostile length must not be honoured");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("implausible length"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn duplicate_page_addresses_are_resolved_to_the_later_copy_and_never_silently() {
        // This test used to require the whole image be refused, on the reading
        // that a savevm never repeats an address so a repeat meant corruption.
        // `QEVM` is the migration wire format and an iterative or live pre-copy
        // stream re-sends every page it sees dirtied again, so refusing turned a
        // legitimate snapshot into "unreadable memory image". The rule kept from
        // that decision is the half that mattered: a superseded page must never
        // be served as the captured state, and the resolution must be on the
        // record rather than silent.
        //
        // A guest of exactly one page, sent twice — the degenerate case, where
        // discarding the earlier copy leaves the layer with nothing if the
        // bookkeeping is wrong.
        let image = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .mem_size(&[("pc.ram", 0x1000)])
            .page(0x0000, Some("pc.ram"), 0x11) // overwritten by the guest
            .page(0x0000, None, 0x22) // current when the stream closed
            .eos()
            .ram_section_end(0)
            .eof()
            .finish();
        let layer = open(source(image)).expect("an iterative stream is a valid snapshot");

        assert_eq!(
            layer.segments().len(),
            1,
            "one guest page, not two segments"
        );
        assert_eq!(layer.mapped_len(), 0x1000);

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x0000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0x22),
            "the last copy is what the guest held; 0x11 was already overwritten"
        );
        assert!(
            !page.contains(&0x11),
            "a superseded page must never be served as the captured state"
        );

        // Not silent: an examiner is told the address was carried twice and
        // which copy was kept.
        assert_eq!(layer.layer_meta().note("qemu_resent_pages").unwrap(), 1);
        assert_eq!(
            layer.layer_meta().note("qemu_superseded_copies").unwrap(),
            1
        );
        let note = layer
            .layer_meta()
            .note("qemu_superseded_pages")
            .and_then(|v| v.as_str())
            .expect("the resolution is recorded, not silent");
        assert!(note.contains("sent more than once"), "{note}");
        // Nothing is missing: the guest's whole address space is mapped.
        assert!(layer.layer_meta().incomplete().is_empty());
    }

    #[test]
    fn a_hostile_ram_block_list_is_capped_rather_than_looping() {
        let mut out = Builder::new()
            .configuration("pc-i440fx-2.0")
            .section_start(0, "ram", RAM_VERSION_ID)
            .finish();
        out.extend_from_slice(&(FLAG_MEM_SIZE).to_be_bytes());
        // More block entries than any real guest declares, and no page stream
        // behind them.
        for _ in 0..(MAX_RAM_BLOCKS + 16) {
            out.push(1);
            out.push(b'x');
            out.extend_from_slice(&0x1000u64.to_be_bytes());
        }
        let err = open(source(out)).expect_err("the block list must be capped");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("block list"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
