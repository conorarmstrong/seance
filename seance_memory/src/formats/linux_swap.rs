//! The Linux swap area header.
//!
//! A swap file or partition begins with one page of metadata, and everything
//! after it is page-aligned swapped-out memory. This module reads that page:
//! enough to say *this is swap*, *these are its dimensions*, and *this is the
//! identifier that ties it to the machine it came from* — without which an
//! attached swap file is an anonymous blob an examiner has to take on trust.
//!
//! # Layout
//!
//! Transcribed from the kernel's `union swap_header` (`include/linux/swap.h`)
//! and confirmed against a real swap file (see the fixture named below):
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 1024 | `bootbits` — reserved for a partition's boot sector |
//! | 1024 | 4 | `version` (little-endian; 1 is the only version in use) |
//! | 1028 | 4 | `last_page` — highest usable page index |
//! | 1032 | 4 | `nr_badpages` |
//! | 1036 | 16 | `uuid` |
//! | 1052 | 16 | `volume_name` (label), NUL-padded |
//! | `page_size - 10` | 10 | magic, `SWAPSPACE2` |
//!
//! The magic sits at the *end* of the first page, so finding it also confirms
//! the page size: a header claiming to be swap but whose magic is not at
//! `page_size - 10` has been read with the wrong page size, and every offset
//! computed from it afterwards would be wrong.
//!
//! # Status: header parser plus `swp_entry_t` decode, wired into swap resolution
//!
//! This module parses the container (the header, above) and decodes the two
//! x86-64 `swp_entry_t` layouts ([`decode_x86_64`], below). Both halves are used
//! by `seance_plugin_memory_linux::swap`, which locates a swapped page from its
//! PTE and reads it back out of an attached area, choosing the layout by which
//! one decodes into the attached area's bounds rather than by the kernel version
//! — see that module and [`X86SwapLayout`].
//!
//! # The swap-entry layout is kernel source, not machine state
//!
//! Linux's `swp_entry_t` bit layout in a PTE is a compile-time property of the
//! kernel and changed once on x86-64: the L1TF mitigation (4.19, backported
//! below it) began storing the offset inverted and moved the type to the top
//! bits. Nothing in a single PTE says which layout wrote it, so [`decode_x86_64`]
//! is given the layout to use and the *caller* settles which one against the
//! evidence — see [`LinuxSwapHeader::slot_byte_offset`] and the swap resolver.
//!
//! # Acquiring a swap file: reading it through the filesystem returns zeros
//!
//! This is not a detail of this module, but it decides whether anything this
//! module reads is worth reading, so it is written down where the next person
//! will find it.
//!
//! A Linux swap **file** (as opposed to a swap partition) is normally created
//! with `fallocate`, which on ext4 produces extents flagged `unwritten`:
//! blocks are reserved on disk but the filesystem records that nothing has been
//! written to them, and short-circuits any read of them to zeros. The swap
//! subsystem then writes pages through the block layer with `bio`, straight to
//! those physical blocks, using an extent map built at `swapon` — and never
//! touches ext4's bookkeeping, because it is deliberately bypassing it.
//!
//! The consequence is that **`cp /swapfile evidence/` yields a file of zeros**,
//! with no error and no warning, while the swapped memory sits intact on the
//! disk underneath. Observed directly on an Ubuntu host with 4.5 GiB of swap in
//! use: reading one extent through the filesystem gave 0 non-zero bytes in a
//! mebibyte; reading the same physical blocks off the block device gave 724,505.
//! The header page is the exception and reads back fine — `mkswap` writes it
//! through the filesystem, so its single extent is not `unwritten`. An examiner
//! who checks only that the copy "looks like swap" therefore gets a valid
//! header and an empty body, which is the worst possible failure: it passes
//! inspection.
//!
//! To acquire one properly, read the **physical extents** — `filefrag -v` gives
//! them — from the underlying block device, and reassemble them at their
//! logical offsets. A swap *partition* has no such problem; it is the block
//! device.
//!
//! Because that failure passes inspection, this module offers a check for it:
//! [`LinuxSwapHeader::survey_body`] reads a bounded, evenly spread sample of the
//! body and reports what was in it, so a caller can tell an area it can read
//! from from one it cannot before it claims to have recovered a page. The
//! wording every such caller uses is [`BODY_READS_AS_ZEROS`].
//!
//! What it does give an examiner today: a swap file identified as such, sized,
//! and carrying the UUID that matches it against `/etc/fstab`, `swapon --show`
//! output, or another swap area recovered from the same host.

use seance_core::data_source::DataSource;
use std::fmt;

/// Bytes of boot-sector space before the header proper.
const BOOTBITS: usize = 1024;
/// `SWAPSPACE2`, at `page_size - MAGIC.len()`.
const MAGIC: &[u8; 10] = b"SWAPSPACE2";
/// The only swap version in use. Version 0 predates 2.6 and is not written by
/// any kernel this tool will meet.
const SUPPORTED_VERSION: u32 = 1;

/// Page sizes a swap area may have been created with, largest first.
///
/// Probed in this order when the caller does not know the page size. Largest
/// first because a 64 KiB area's magic lies beyond where a 4 KiB probe looks,
/// so trying small first would never be wrong — but trying large first settles
/// it in one comparison for the architectures that use it (arm64, ppc64).
const CANDIDATE_PAGE_SIZES: [usize; 4] = [65536, 16384, 8192, 4096];

/// Why a candidate swap header was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapHeaderError {
    /// Fewer bytes than one header page.
    TooShort { have: usize, need: usize },
    /// No `SWAPSPACE2` at the end of the first page, for any page size tried.
    NoMagic,
    /// The magic was found but the version is not one this reader understands.
    /// The area is swap; its layout is not one whose offsets can be trusted.
    UnsupportedVersion(u32),
    /// `last_page` is zero: the area declares no usable pages at all.
    NoUsablePages,
}

impl fmt::Display for SwapHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwapHeaderError::TooShort { have, need } => write!(
                f,
                "{have} byte(s) is short of the {need}-byte header page a swap area begins with"
            ),
            SwapHeaderError::NoMagic => write!(
                f,
                "no SWAPSPACE2 signature at the end of the first page for any supported page \
                 size, so this is not a Linux swap area"
            ),
            SwapHeaderError::UnsupportedVersion(v) => write!(
                f,
                "swap version {v} is not version {SUPPORTED_VERSION}; the area is swap but its \
                 layout is not one whose page offsets can be trusted"
            ),
            SwapHeaderError::NoUsablePages => write!(
                f,
                "the header declares last_page = 0, so the area holds no swapped pages"
            ),
        }
    }
}

impl std::error::Error for SwapHeaderError {}

/// Why an area whose body reads as zeros is a finding and not a page.
///
/// The one place this sentence lives. It is needed wherever the tool has to
/// explain an area it attached but will not read from — the swap resolver's
/// per-page note and the Linux profile record's swap statement, at least — and
/// the same explanation written twice drifts into two explanations.
///
/// It states the observation and the likeliest cause separately on purpose. The
/// observation ("these pages read as zeros") is grounded in bytes the tool read;
/// the cause is the acquisition trap described at the top of this module, and an
/// area that was `swapon`-ed but never written to reads exactly the same way. An
/// examiner who is told both can tell which they have; one who is told only the
/// diagnosis cannot.
pub const BODY_READS_AS_ZEROS: &str =
    "A body that reads as zeros holds nothing to recover, and the first thing to check is the \
     acquisition: a swap FILE copied through the filesystem reads back this way, because its \
     pages sit in fallocate'd extents the filesystem still records as unwritten while the kernel \
     wrote them straight to disk with bio calls — the mkswap-written header page copies \
     faithfully, so the result is a valid header over an empty body. Re-acquire the area from the \
     block device holding it (`filefrag -v` names the file's physical extents, which are read and \
     reassembled at their logical offsets) or acquire the swap partition itself. An area nothing \
     was ever written to reads this way too, and so does a lightly used one whose sampled slots \
     happen never to have been written: these bytes alone cannot tell the three apart.";

/// Why an area whose body could not be read at all is a third finding.
///
/// The one place this sentence lives, for the reason [`BODY_READS_AS_ZEROS`]
/// gives: it is needed wherever the tool has to explain an area that is a swap
/// area and whose body it never saw — the attach-time warning and the profile
/// record, at least — and the same explanation written twice drifts into two.
///
/// It exists because "nothing was read" and "zeros were read" are different
/// findings with different remedies, and a record with words for only two of the
/// three states has to file this one under one of the others. Filed as an area
/// holding data it becomes a claim nothing supports; filed as an area of zeros
/// it becomes a conclusion drawn from no observation. So it is stated as what it
/// is: the places were chosen, and not one of them came back.
pub const BODY_NOT_ACQUIRED: &str =
    "The header page parses and not one sampled page of the body could be read, which is what a \
     copy interrupted after the first page leaves behind — and a source that errors behind the \
     header, a sparse copy whose body was never written, and an area whose header declares more \
     pages than the attachment holds all read the same way from here. Nothing was observed about \
     what this area holds, so nothing is concluded about it: it is not shown to be empty, and \
     its slots are not shown to be zeros. Re-acquire the area whole from the block device or \
     partition holding it, and check its size against the last_page and page size the header \
     declares, which is the length the area says it should be.";

/// How many body pages a survey reads before it decides.
///
/// A swap area is routinely several GiB and may be far larger, and this runs on
/// every area an examiner attaches, so reading a body whole is not an option:
/// the cost has to be a constant rather than a fraction of the evidence. Sixty
/// four pages is 256 KiB on a 4 KiB area — one seek per sample, negligible
/// beside opening the capture — and it is enough that a genuinely populated area
/// has to be extraordinarily sparse to hide from it.
pub const BODY_SAMPLE_PAGES: u32 = 64;

/// What a bounded sample of a swap area's body found.
///
/// Three counts rather than a verdict, because the counts are what a report can
/// stand behind: this many slots were looked at, this many could be read, this
/// many held a byte that was not zero. [`Self::reads_as_all_zero`] is the
/// reading that matters, and it is stated in terms of the counts so nobody has
/// to guess what it was derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SwapBodySurvey {
    /// Distinct slots the survey chose to look at.
    pub pages_sampled: u32,
    /// Of those, the ones whose full page came back.
    pub pages_read: u32,
    /// Of those read, the ones holding at least one non-zero byte.
    pub pages_with_data: u32,
}

impl SwapBodySurvey {
    /// Whether every body page that could be read held nothing but zeros.
    ///
    /// False when nothing could be read at all: an area whose body was not
    /// acquired *at all* (a truncated file) is a different finding from one
    /// whose body was read and was empty, and the caller already has an answer
    /// for the slot it cannot read. Claiming "all zeros" on the strength of zero
    /// observations would be a conclusion drawn from no evidence.
    pub fn reads_as_all_zero(&self) -> bool {
        self.pages_read > 0 && self.pages_with_data == 0
    }

    /// Whether places were chosen across the body and not one of them came back.
    ///
    /// The third state, and the one a single "is it empty?" question cannot
    /// express. A body that holds data, a body that reads as zeros and a body
    /// that was never acquired are three findings with three remedies, and a
    /// caller that asks only [`Self::reads_as_all_zero`] gets the same `false`
    /// for the first and the last of them — correctly, in both cases — and must
    /// not go on to read that `false` as "this area holds swapped pages". This
    /// is what tells the last one apart. See [`BODY_NOT_ACQUIRED`].
    ///
    /// It requires a place to have been chosen, so it stays false for a survey
    /// that never ran: an attachment carrying no swap header has no body for
    /// this to be a finding about, and `Default` must not read as one.
    pub fn body_was_not_read(&self) -> bool {
        self.pages_sampled > 0 && self.pages_read == 0
    }
}

/// A parsed Linux swap area header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSwapHeader {
    /// Page size the area was created with, established from where the magic
    /// sits rather than assumed.
    pub page_size: usize,
    /// Header version. Always [`SUPPORTED_VERSION`] once parsing succeeds.
    pub version: u32,
    /// Highest usable page index. Page 0 is the header itself.
    pub last_page: u32,
    /// Pages `mkswap` marked unusable. They hold no recoverable data.
    pub nr_badpages: u32,
    /// The area's UUID, or `None` when unset (all zero).
    ///
    /// The forensically useful field: it is what matches a recovered swap file
    /// against `/etc/fstab`, `swapon --show`, or a second area from the same
    /// host. An anonymous blob of swapped pages cannot be tied to a machine;
    /// this ties it.
    pub uuid: Option<[u8; 16]>,
    /// The area's label, or `None` when unset.
    pub label: Option<String>,
}

impl LinuxSwapHeader {
    /// Parse the header from the start of a swap area.
    ///
    /// `data` need only cover the first page; the rest of the area is not read.
    /// When `page_size` is `None` the size is established from where the magic
    /// lies, which is also what validates it.
    pub fn parse(data: &[u8], page_size: Option<usize>) -> Result<Self, SwapHeaderError> {
        let candidates: &[usize] = match page_size {
            Some(size) => &[size][..],
            None => &CANDIDATE_PAGE_SIZES[..],
        };

        // Smallest candidate that could possibly fit, for the error message —
        // reporting the largest would tell an examiner they need 64 KiB when
        // 4 KiB would have done.
        let smallest = candidates.iter().copied().min().unwrap_or(4096);
        if data.len() < smallest {
            return Err(SwapHeaderError::TooShort {
                have: data.len(),
                need: smallest,
            });
        }

        let page_size = candidates
            .iter()
            .copied()
            .find(|&size| data.len() >= size && &data[size - MAGIC.len()..size] == MAGIC.as_slice())
            .ok_or(SwapHeaderError::NoMagic)?;

        let word = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let version = word(BOOTBITS);
        if version != SUPPORTED_VERSION {
            return Err(SwapHeaderError::UnsupportedVersion(version));
        }

        let last_page = word(BOOTBITS + 4);
        if last_page == 0 {
            return Err(SwapHeaderError::NoUsablePages);
        }
        let nr_badpages = word(BOOTBITS + 8);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&data[BOOTBITS + 12..BOOTBITS + 28]);
        // All-zero means unset, not "the nil UUID". Reporting 00000000-... as
        // this area's identifier would let two unrelated swap files appear to
        // match each other.
        let uuid = (uuid != [0u8; 16]).then_some(uuid);

        let raw_label = &data[BOOTBITS + 28..BOOTBITS + 44];
        let label = String::from_utf8_lossy(raw_label)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        let label = (!label.is_empty()).then_some(label);

        Ok(Self {
            page_size,
            version,
            last_page,
            nr_badpages,
            uuid,
            label,
        })
    }

    /// The UUID in canonical `8-4-4-4-12` form, if the area has one.
    pub fn uuid_string(&self) -> Option<String> {
        let u = self.uuid?;
        Some(format!(
            "{}-{}-{}-{}-{}",
            hex(&u[0..4]),
            hex(&u[4..6]),
            hex(&u[6..8]),
            hex(&u[8..10]),
            hex(&u[10..16])
        ))
    }

    /// Total bytes the area spans, header page included.
    ///
    /// Saturating: a corrupt `last_page` cannot be made to wrap this into a
    /// small number that would then read as a short file.
    pub fn total_bytes(&self) -> u64 {
        (self.last_page as u64)
            .saturating_add(1)
            .saturating_mul(self.page_size as u64)
    }

    /// Byte offset of swap page `index` within the area.
    ///
    /// `None` when the index is past `last_page`, or is 0 — page 0 is the
    /// header, never a swapped page. Returning an offset for either would hand
    /// a caller a location that decodes to something, which is worse than
    /// refusing: a swapped page read from the header page yields the header,
    /// and a page past the end yields whatever follows the file.
    pub fn page_offset(&self, index: u32) -> Option<u64> {
        if index == 0 || index > self.last_page {
            return None;
        }
        Some((index as u64) * (self.page_size as u64))
    }

    /// Byte offset of the swap **slot** `offset`, as it arrives from a decoded
    /// `swp_entry_t`.
    ///
    /// The same rule as [`Self::page_offset`], widened to the 64-bit offset a
    /// decoded entry carries: a slot of 0 is the header, and a slot past
    /// `last_page` is outside this area. Returning `None` for either is what lets
    /// a caller use "the decoded slot lands inside this area" to CORROBORATE that
    /// a `swp_entry_t` belongs to this area and was decoded with the right
    /// layout — the L1TF inversion makes a wrong layout produce a wildly
    /// out-of-range slot, so the bounds are a real check rather than a formality.
    pub fn slot_byte_offset(&self, slot: u64) -> Option<u64> {
        if slot == 0 || slot > self.last_page as u64 {
            return None;
        }
        Some(slot * self.page_size as u64)
    }

    /// Read a bounded, evenly spread sample of the area's body and report what
    /// was there.
    ///
    /// This is what separates an acquisition that captured the swapped pages
    /// from one that captured only the header — see [`BODY_READS_AS_ZEROS`] and
    /// the acquisition section at the top of this module. It is deliberately an
    /// **area**-level question: a genuinely zero-filled anonymous page can be
    /// swapped out like any other, so one zero page proves nothing, and only the
    /// whole body reading as zeros is a signature.
    ///
    /// It is a signal about the acquisition, not a verdict about any page, and a
    /// caller must not treat it as one on its own. A machine with a few MiB
    /// swapped out of a multi-GiB area is a real acquisition whose sample can
    /// easily come back empty: on the ground-truth capture this crate is tested
    /// against, exactly one of the sixty-four sampled pages holds data. What a
    /// survey of nothing but zeros licenses is refusing to publish the zeros at a
    /// slot that is *itself* zeros — not discarding a slot that holds bytes.
    ///
    /// # The sample, and why it is shaped this way
    ///
    /// [`BODY_SAMPLE_PAGES`] slots, spread evenly from slot 1 to `last_page`
    /// inclusive, both ends included. Spread rather than taken from the front
    /// because the front is the part of the area a real acquisition is most
    /// likely to have data in — Linux's swap allocator hands out the lowest free
    /// cluster first — so a front-loaded sample flatters a bad acquisition on the
    /// one hand and, on the other, would call a real area empty when its surviving
    /// data happens to sit past the front. An even spread has to be wrong about
    /// the whole body to be wrong at all.
    ///
    /// Slots repeat when the area has fewer body pages than the sample has
    /// places; each distinct slot is read once, so the counts stay counts of
    /// pages rather than of attempts.
    pub fn survey_body(&self, source: &dyn DataSource) -> SwapBodySurvey {
        let last = u64::from(self.last_page);
        let places = u64::from(BODY_SAMPLE_PAGES);
        let mut survey = SwapBodySurvey::default();
        let mut page = vec![0u8; self.page_size];
        let mut previous: Option<u64> = None;
        for place in 0..places {
            // Slot 1 is the first body page (slot 0 is the header), and the last
            // place lands exactly on `last_page`.
            let slot = if places == 1 {
                1
            } else {
                1 + (place * (last - 1)) / (places - 1)
            };
            if previous == Some(slot) {
                continue;
            }
            previous = Some(slot);
            let Some(at) = self.slot_byte_offset(slot) else {
                continue;
            };
            survey.pages_sampled += 1;
            // A short read is not a page of zeros: it is a page that was not
            // acquired, and it must not be counted as evidence of emptiness.
            if source.read_at(at, &mut page).unwrap_or(0) == page.len() {
                survey.pages_read += 1;
                if page.iter().any(|byte| *byte != 0) {
                    survey.pages_with_data += 1;
                }
            }
        }
        survey
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// How a non-present PTE encodes a `swp_entry_t` on x86-64.
///
/// The encoding is a property of the kernel source, not the machine, and it
/// changed once on x86-64: the L1TF mitigation (commit `00839ee3b299`, merged in
/// 4.19 and backported to the stable series below it) began storing the swap
/// **offset** bit-inverted, and moved the swap **type** from the low bits to the
/// top five. Which one a capture uses cannot be read from a single PTE — but it
/// can be *settled by the evidence*: only one layout decodes an entry to a slot
/// that lands inside the swap area the examiner attached (see
/// [`LinuxSwapHeader::slot_byte_offset`]), because the inversion sends the wrong
/// layout's offset far out of range. That is the same principle the page-table
/// proof uses to choose a DTB: the layout that *works* against independent
/// evidence is the one this capture used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86SwapLayout {
    /// Linux ≤ 4.18 (and un-backported stable): type at bits 13:9, offset at
    /// bits 63:14, neither inverted.
    PreL1tf,
    /// Linux ≥ 4.19 (and backported stable): type at bits 63:59, offset at bits
    /// 58:9 **stored inverted**, per `arch/x86/include/asm/pgtable_64.h`.
    PostL1tf,
}

/// A `swp_entry_t` decoded from a PTE: which swap area, and where within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwpEntry {
    /// The swap area index (`swp_type`) — which of the system's swap areas holds
    /// the page. `0` is the first area brought up with `swapon`.
    pub swap_type: u8,
    /// The page's slot within that area (`swp_offset`). Multiply by the page
    /// size for a byte offset — [`LinuxSwapHeader::slot_byte_offset`] does that
    /// and bounds-checks it.
    pub offset: u64,
}

/// Bits of type field, `SWP_TYPE_BITS` in the kernel.
const SWP_TYPE_BITS: u32 = 5;
/// First offset bit, `_PAGE_BIT_PROTNONE + 1` — protnone is bit 8.
const SWP_OFFSET_FIRST_BIT: u32 = 9;

/// Decode a non-present x86-64 PTE as a `swp_entry_t` under `layout`.
///
/// Transcribed from `__swp_type`/`__swp_offset` in
/// `arch/x86/include/asm/pgtable_64.h`. The caller must have established the
/// architecture is x86-64 (a proven four- or five-level Intel walk); this does
/// no gating of its own, and applying it to a 32-bit or PAE entry would read the
/// wrong bits.
pub fn decode_x86_64(entry: u64, layout: X86SwapLayout) -> SwpEntry {
    let type_mask = (1u64 << SWP_TYPE_BITS) - 1;
    match layout {
        X86SwapLayout::PreL1tf => SwpEntry {
            // type = (val >> SWP_TYPE_FIRST_BIT) & mask ; offset = val >> OFFSET_FIRST_BIT
            swap_type: ((entry >> SWP_OFFSET_FIRST_BIT) & type_mask) as u8,
            offset: entry >> (SWP_OFFSET_FIRST_BIT + SWP_TYPE_BITS),
        },
        X86SwapLayout::PostL1tf => SwpEntry {
            // type = (val >> (64 - TYPE_BITS)) & mask
            swap_type: ((entry >> (64 - SWP_TYPE_BITS)) & type_mask) as u8,
            // offset = (~val << TYPE_BITS) >> (OFFSET_FIRST_BIT + TYPE_BITS)
            offset: (!entry << SWP_TYPE_BITS) >> (SWP_OFFSET_FIRST_BIT + SWP_TYPE_BITS),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    /// A synthetic header, so the boundary cases can be built deliberately.
    fn header(page_size: usize, version: u32, last_page: u32, uuid: [u8; 16]) -> Vec<u8> {
        let mut page = vec![0u8; page_size];
        page[BOOTBITS..BOOTBITS + 4].copy_from_slice(&version.to_le_bytes());
        page[BOOTBITS + 4..BOOTBITS + 8].copy_from_slice(&last_page.to_le_bytes());
        page[BOOTBITS + 12..BOOTBITS + 28].copy_from_slice(&uuid);
        page[page_size - MAGIC.len()..page_size].copy_from_slice(MAGIC);
        page
    }

    #[test]
    fn a_well_formed_header_parses() {
        let uuid = [0x11u8; 16];
        let parsed = LinuxSwapHeader::parse(&header(4096, 1, 100, uuid), None).expect("parses");
        assert_eq!(parsed.page_size, 4096);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.last_page, 100);
        assert_eq!(parsed.uuid, Some(uuid));
    }

    #[test]
    fn the_page_size_is_established_from_the_magic_not_assumed() {
        // A 64 KiB area's magic lies far beyond where a 4 KiB probe looks. If
        // the reader assumed 4 KiB it would reject this, and if it assumed the
        // magic's position it would compute every page offset wrongly.
        let parsed =
            LinuxSwapHeader::parse(&header(65536, 1, 10, [0u8; 16]), None).expect("parses");
        assert_eq!(parsed.page_size, 65536);
        assert_eq!(parsed.page_offset(1), Some(65536));
    }

    #[test]
    fn a_file_without_the_magic_is_not_swap() {
        assert_eq!(
            LinuxSwapHeader::parse(&vec![0u8; 8192], None),
            Err(SwapHeaderError::NoMagic)
        );
    }

    #[test]
    fn a_short_file_says_how_short() {
        assert_eq!(
            LinuxSwapHeader::parse(&[0u8; 100], None),
            Err(SwapHeaderError::TooShort {
                have: 100,
                need: 4096
            })
        );
    }

    #[test]
    fn an_unsupported_version_is_refused_rather_than_read_anyway() {
        // The area IS swap — the magic matched — but its layout is not one whose
        // offsets can be trusted, which is a different finding from "not swap".
        assert_eq!(
            LinuxSwapHeader::parse(&header(4096, 7, 10, [0u8; 16]), None),
            Err(SwapHeaderError::UnsupportedVersion(7))
        );
    }

    #[test]
    fn an_area_declaring_no_usable_pages_is_refused() {
        assert_eq!(
            LinuxSwapHeader::parse(&header(4096, 1, 0, [0u8; 16]), None),
            Err(SwapHeaderError::NoUsablePages)
        );
    }

    #[test]
    fn an_all_zero_uuid_is_absent_rather_than_the_nil_uuid() {
        // Otherwise two unrelated swap files, neither carrying an identifier,
        // would appear to match each other.
        let parsed = LinuxSwapHeader::parse(&header(4096, 1, 10, [0u8; 16]), None).unwrap();
        assert_eq!(parsed.uuid, None);
        assert_eq!(parsed.uuid_string(), None);
    }

    #[test]
    fn page_zero_is_the_header_and_never_a_swapped_page() {
        let parsed = LinuxSwapHeader::parse(&header(4096, 1, 10, [0u8; 16]), None).unwrap();
        assert_eq!(
            parsed.page_offset(0),
            None,
            "page 0 holds the header; returning its offset would decode the \
             header as somebody's memory"
        );
        assert_eq!(parsed.page_offset(1), Some(4096));
        assert_eq!(parsed.page_offset(10), Some(40960));
        assert_eq!(
            parsed.page_offset(11),
            None,
            "past last_page there is nothing, and an offset here would read \
             whatever follows the file"
        );
    }

    #[test]
    fn a_corrupt_last_page_cannot_wrap_the_size() {
        let parsed = LinuxSwapHeader::parse(&header(4096, 1, u32::MAX, [0u8; 16]), None).unwrap();
        assert_eq!(parsed.total_bytes(), (u32::MAX as u64 + 1) * 4096);
    }

    #[test]
    fn the_pre_l1tf_layout_matches_the_kernels_encoding() {
        // The vector the translate walk documents: swap type 2 at bits 13:9,
        // offset 0x9ABC above bit 14, present bit and PROT_NONE clear.
        let entry = (2u64 << 9) | (0x9ABCu64 << 14);
        let decoded = decode_x86_64(entry, X86SwapLayout::PreL1tf);
        assert_eq!(decoded.swap_type, 2);
        assert_eq!(decoded.offset, 0x9ABC);
    }

    #[test]
    fn the_post_l1tf_layout_round_trips_the_kernel_encoder() {
        // Encode as the kernel does (arch/x86/include/asm/pgtable_64.h __swp_entry):
        //   (~offset << SWP_OFFSET_SHIFT >> SWP_TYPE_BITS) | (type << (64 - TYPE_BITS))
        // then confirm the decode recovers both halves.
        let encode = |ty: u64, off: u64| -> u64 {
            let shift = SWP_OFFSET_FIRST_BIT + SWP_TYPE_BITS; // SWP_OFFSET_SHIFT = 14
            ((!off << shift) >> SWP_TYPE_BITS) | (ty << (64 - SWP_TYPE_BITS))
        };
        for (ty, off) in [(0u64, 1u64), (0, 0x1_0000), (3, 0x3_ABCD), (17, 42)] {
            let entry = encode(ty, off);
            let decoded = decode_x86_64(entry, X86SwapLayout::PostL1tf);
            assert_eq!(decoded.swap_type as u64, ty, "type for ({ty},{off})");
            assert_eq!(decoded.offset, off, "offset for ({ty},{off})");
        }
    }

    #[test]
    fn the_inversion_sends_the_wrong_layout_out_of_a_real_areas_bounds() {
        // A real post-L1TF entry from the ground-truth capture: page 0 of the
        // workload, in swap slot 1 of area 0. Decoded correctly it is slot 1;
        // decoded with the pre-L1TF layout it is an astronomically large slot —
        // which is exactly what lets an attached area's bounds pick the layout.
        let entry = 0x07ff_ffff_ffff_fc02;
        let area = LinuxSwapHeader::parse(&header(4096, 1, 524_287, [0u8; 16]), None).unwrap();

        let post = decode_x86_64(entry, X86SwapLayout::PostL1tf);
        assert_eq!(post.swap_type, 0);
        assert_eq!(post.offset, 1);
        assert_eq!(area.slot_byte_offset(post.offset), Some(4096));

        let pre = decode_x86_64(entry, X86SwapLayout::PreL1tf);
        assert!(
            area.slot_byte_offset(pre.offset).is_none(),
            "the wrong layout's slot {} must fall outside the area, so bounds disambiguate",
            pre.offset
        );
    }

    #[test]
    fn slot_zero_and_out_of_range_slots_are_refused() {
        let area = LinuxSwapHeader::parse(&header(4096, 1, 10, [0u8; 16]), None).unwrap();
        assert_eq!(area.slot_byte_offset(0), None, "slot 0 is the header");
        assert_eq!(area.slot_byte_offset(1), Some(4096));
        assert_eq!(area.slot_byte_offset(10), Some(40960));
        assert_eq!(area.slot_byte_offset(11), None, "past last_page");
        assert_eq!(area.slot_byte_offset(u64::MAX), None);
    }

    /// A whole area: the header page followed by `last_page` body pages, with
    /// the named slots carrying a byte that is not zero.
    fn area(page_size: usize, last_page: u32, populated: &[u32]) -> Vec<u8> {
        let mut bytes = header(page_size, 1, last_page, [0u8; 16]);
        bytes.resize((last_page as usize + 1) * page_size, 0);
        for slot in populated {
            let at = *slot as usize * page_size;
            bytes[at] = 0xAB;
        }
        bytes
    }

    /// A source that answers every read with zeros and counts the reads, so a
    /// test can assert what a survey of an enormous area actually costs.
    #[derive(Debug, Default)]
    struct CountingZeros {
        reads: std::sync::atomic::AtomicU64,
        size: u64,
    }

    impl DataSource for CountingZeros {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if offset >= self.size {
                return Ok(0);
            }
            let n = buf.len().min((self.size - offset) as usize);
            buf[..n].fill(0);
            Ok(n)
        }

        fn size(&self) -> u64 {
            self.size
        }
    }

    #[test]
    fn a_body_of_nothing_but_zeros_is_reported_as_carrying_no_data() {
        // The acquisition trap: `cp /swapfile` copies the header faithfully and
        // returns zeros for every page behind it.
        let bytes = area(4096, 511, &[]);
        let header = LinuxSwapHeader::parse(&bytes, None).unwrap();
        let survey = header.survey_body(&ByteSliceDataSource::new(bytes));
        assert!(survey.pages_read > 0, "the pages were readable");
        assert_eq!(survey.pages_with_data, 0);
        assert!(survey.reads_as_all_zero());
        assert!(
            !survey.body_was_not_read(),
            "these pages were read; what they held is an observation"
        );
    }

    #[test]
    fn one_populated_page_at_the_far_end_keeps_the_body_populated() {
        // Why the sample is spread across the area rather than taken from the
        // front: an area whose only surviving data is near its end is a real
        // acquisition, and calling it empty would discard it.
        let bytes = area(4096, 511, &[511]);
        let header = LinuxSwapHeader::parse(&bytes, None).unwrap();
        let survey = header.survey_body(&ByteSliceDataSource::new(bytes));
        assert_eq!(survey.pages_with_data, 1);
        assert!(!survey.reads_as_all_zero());
    }

    #[test]
    fn a_body_that_could_not_be_read_at_all_is_not_called_all_zero() {
        // Nothing was observed, so nothing is claimed. A truncated area — the
        // header page and no body — is a different finding from a body that was
        // read and held zeros, and the slot-level answer for it already exists.
        let bytes = area(4096, 511, &[]);
        let header = LinuxSwapHeader::parse(&bytes, None).unwrap();
        let survey = header.survey_body(&ByteSliceDataSource::new(bytes[..4096].to_vec()));
        assert_eq!(survey.pages_read, 0);
        assert!(!survey.reads_as_all_zero());
        // And it is not merely "not all zero" either: it has a name of its own,
        // because a caller with only the two answers files this case under
        // whichever of them is wrong for it.
        assert!(survey.body_was_not_read());
        // A survey that never ran is not this finding. An attachment with no
        // swap header has no body for the question to be about.
        assert!(!SwapBodySurvey::default().body_was_not_read());
    }

    #[test]
    fn the_survey_reads_a_bounded_number_of_pages_however_large_the_area() {
        // A 16 TiB area must cost the same as a 2 MiB one: this runs on every
        // attached area, and reading a body whole is not an option.
        let header = LinuxSwapHeader::parse(&header(4096, 1, u32::MAX, [0u8; 16]), None).unwrap();
        let source = CountingZeros {
            reads: std::sync::atomic::AtomicU64::new(0),
            size: header.total_bytes(),
        };
        let survey = header.survey_body(&source);
        assert_eq!(survey.pages_sampled, BODY_SAMPLE_PAGES);
        assert_eq!(
            source.reads.load(std::sync::atomic::Ordering::Relaxed),
            u64::from(BODY_SAMPLE_PAGES)
        );
        assert!(survey.reads_as_all_zero());
    }

    #[test]
    fn a_tiny_area_is_sampled_without_reading_a_slot_twice() {
        // With fewer body pages than samples the spread collapses onto repeated
        // slots. Counting one page twice would inflate every published figure.
        let bytes = area(4096, 3, &[]);
        let header = LinuxSwapHeader::parse(&bytes, None).unwrap();
        let survey = header.survey_body(&ByteSliceDataSource::new(bytes));
        assert_eq!(survey.pages_sampled, 3, "slots 1, 2 and 3, each once");
        assert_eq!(survey.pages_read, 3);
    }
}
