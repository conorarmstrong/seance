//! The symbol table a Linux kernel keeps of itself.
//!
//! [`crate::btf`] recovers the kernel's **types** from a capture. This recovers
//! its **symbol addresses**, and between them they are what an ISF file
//! contains — so a capture from a kernel carrying both describes itself
//! completely, and needs no symbol file matched to it from outside.
//!
//! `CONFIG_KALLSYMS` is on in every distribution kernel and has been for
//! twenty years, so unlike BTF this is not a modern-kernels-only capability.
//!
//! # Layout
//!
//! Transcribed from `scripts/kallsyms.c` (`write_src`) and
//! `kernel/kallsyms_internal.h`, and confirmed against running kernels. The same
//! arrays appear in two orders, and the **one** thing that moved between them is
//! where `kallsyms_offsets`/`kallsyms_relative_base` live:
//!
//! | Symbol | Contents |
//! |---|---|
//! | `kallsyms_offsets` | one `i32` per symbol |
//! | `kallsyms_relative_base` | the base those offsets are relative to |
//! | `kallsyms_num_syms` | count, `unsigned int` |
//! | `kallsyms_names` | the compressed name stream |
//! | `kallsyms_markers` | one entry per 256 symbols, indexing into the stream: a `u32` (`.long`) on current kernels, an `unsigned long` (`PTR`) on older ones |
//! | `kallsyms_token_table` | 256 NUL-terminated token strings |
//! | `kallsyms_token_index` | 256 `u16` offsets into the token table |
//!
//! - **Pre-6.4:** `offsets, relative_base, num_syms, names, markers,
//!   token_table, token_index` — offsets first, token index last.
//! - **6.4+:** `num_syms, names, markers, token_table, token_index, offsets,
//!   relative_base` — the offset array moved to *after* the token index, and 6.2
//!   appended `kallsyms_seqs_of_names` after `relative_base`.
//!
//! The `num_syms … token_index` run is identical in both, so the decoder reaches
//! the token index and works back to the names the same way regardless; only the
//! offset array's home differs, and it tries both and keeps the one that yields
//! real kernel addresses.
//!
//! # Alignment
//!
//! `scripts/kallsyms.c` emits every one of those labels through `output_label`,
//! which precedes it with `ALGN` — `.balign 8` on a 64-bit kernel. So **each
//! array begins on an 8-byte boundary**, and an array whose length is not a
//! multiple of eight is followed by zero padding before the next one. That
//! matters most for `kallsyms_offsets`: it is one `i32` per symbol, so whenever
//! `kallsyms_num_syms` is odd there are four bytes of padding between the last
//! offset and `kallsyms_relative_base`. A decoder that reads the base flush
//! against the offsets reads half of one and half of the other, on every kernel
//! with an odd symbol count — which is half of them. The same rule puts padding
//! between `kallsyms_markers` and the token table whenever the marker count is
//! odd.
//!
//! Older kernels wrote `.align 8` instead, and what that means is the
//! assembler's choice: x86's reads it as 8 bytes, the arm64 assembler as
//! 2^8 = **256**. So an older arm64 kernel starts every array on a 256-byte
//! boundary, with up to 255 bytes of zeros between arrays (the Debian 4.19
//! arm64 MMUShell dump: `relative_base` at `…c00`, `num_syms` at `…d00`, the
//! names at `…e00`). The decoder tries 8 and 256, and each candidate still has
//! to pass the whole self-checking decode.
//!
//! # Names
//!
//! Each entry in the stream is a length byte (two, when the top bit is set)
//! followed by that many **token indices**. Each index selects a string from
//! the token table, and the concatenation is the symbol. The very first
//! character of the concatenation is the symbol's *type* letter — `T` for a
//! text symbol, `d` for local data, and so on — and is not part of the name.
//!
//! # Addresses
//!
//! Config-dependent, which is why the raw `i32` is not simply added to a base:
//!
//! - Without `CONFIG_KALLSYMS_BASE_RELATIVE`, `kallsyms_addresses` holds
//!   absolute `unsigned long`s and there are no offsets at all.
//! - With it, `relative_base + (u32)offset`.
//! - With `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` as well — the x86-64 SMP default —
//!   a **non-negative** offset is an absolute address in its own right, and a
//!   negative one means `relative_base - 1 - offset`.
//!
//! Which of the last two a table uses is not recorded in it, so it is read
//! from the offsets: under `ABSOLUTE_PERCPU` every kernel symbol is negative,
//! and a table with no negative offset at all (arm64; a uniprocessor x86-64
//! kernel) is plain base-relative.
//!
//! The third case is why a per-CPU symbol appears at address 0 in
//! `/proc/kallsyms`: those are absolute offsets into the per-CPU area, not
//! kernel virtual addresses. Adding a base to them would place them in the
//! middle of the kernel image and name the wrong bytes.
//!
//! # Finding it without symbols
//!
//! There is a chicken-and-egg problem: the arrays are located by symbols, and
//! the symbols are what is being recovered. The way in is
//! `kallsyms_token_index`, which is 256 `u16`s beginning at zero and never
//! decreasing — a shape that does not occur by accident. Everything else is
//! reached from it by structure, and every step is checked: the decode is only
//! accepted if walking exactly `num_syms` entries lands exactly on the marker
//! array. A layout that is off by one byte fails that.

use std::collections::HashMap;

/// Tokens in the table, fixed by the format.
const TOKENS: usize = 256;
/// `kallsyms_token_index` is one `u16` per token.
const TOKEN_INDEX_LEN: usize = TOKENS * 2;
/// The token table is small; this bounds the backward walk that finds it.
const MAX_TOKEN_TABLE: usize = 8 * 1024;
/// 256 tokens, each at least one byte and its NUL, so the table cannot be
/// shorter than this and still hold them.
const MIN_TOKEN_TABLE: usize = 256;
/// Largest gap between consecutive token offsets. Tokens are short byte
/// sequences chosen for how often they occur, not long strings.
const MAX_TOKEN_STEP: usize = 64;
/// Symbols per marker entry, from `kallsyms.c`.
const SYMBOLS_PER_MARKER: usize = 256;
/// Refuse a table smaller than this: a real kernel declares tens of thousands,
/// and accepting a handful would mean accepting a coincidence.
const MIN_PLAUSIBLE_SYMBOLS: usize = 1_000;
/// Refuse an implausible count rather than allocating for it.
const MAX_PLAUSIBLE_SYMBOLS: usize = 4_000_000;

/// One recovered symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    /// The type letter `nm` would print: `T`, `t`, `D`, `d`, `b`, `A`, ...
    pub kind: char,
}

/// A kernel's own symbol table, recovered from a capture.
#[derive(Debug, Clone, Default)]
pub struct Kallsyms {
    symbols: Vec<Symbol>,
    by_name: HashMap<String, u64>,
}

impl Kallsyms {
    /// Every symbol, in table order.
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// How many were recovered.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Address of a symbol by name.
    ///
    /// When a name occurs more than once — static functions of the same name in
    /// different translation units are common — the first in table order wins,
    /// and the ambiguity is visible through [`Kallsyms::symbols`].
    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    /// Find and decode a kernel symbol table inside a block of memory.
    ///
    /// Returns the offset the table's `kallsyms_token_index` was found at,
    /// alongside the decoded symbols.
    pub fn find_in(haystack: &[u8]) -> Option<(usize, Self)> {
        let mut at = 0usize;
        while at + TOKEN_INDEX_LEN <= haystack.len() {
            let found = find_token_index(haystack, at)?;
            if let Some(table) = decode_at(haystack, found) {
                return Some((found, table));
            }
            // A candidate that did not validate: step past it and keep looking.
            at = found + 2;
        }
        None
    }
}

/// Offset of the next plausible `kallsyms_token_index`.
///
/// The shape is 256 `u16`s that start at zero and never decrease, with the last
/// inside a token table small enough to be one. Arbitrary data satisfies that
/// vanishingly rarely, and anything that slips through fails the full decode.
fn find_token_index(haystack: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while at + TOKEN_INDEX_LEN <= haystack.len() {
        if haystack[at] == 0 && haystack[at + 1] == 0 {
            let mut previous = 0u16;
            let mut ok = true;
            for i in 1..TOKENS {
                let value = u16::from_le_bytes([haystack[at + i * 2], haystack[at + i * 2 + 1]]);
                // Offsets **strictly** increase, and by a small step. Every
                // token is a distinct non-empty string stored with its NUL, so
                // consecutive offsets differ by at least one byte and — since
                // the tokens are short byte sequences chosen for frequency — by
                // no more than a few dozen.
                //
                // Non-decreasing alone is far too weak: a run of zeros
                // satisfies it, and memory is full of those. Against a 15 GiB
                // capture that filter admitted 172,493 candidates, each costing
                // a full structural walk to reject. Strict growth with a
                // bounded step rejects a zero run on its first comparison.
                let step = value.wrapping_sub(previous);
                if value <= previous || step as usize > MAX_TOKEN_STEP {
                    ok = false;
                    break;
                }
                previous = value;
            }
            // The whole table is 256 short strings, so its length lands in a
            // narrow band: too small and the tokens cannot hold their NULs, too
            // large and this is not a token table.
            if ok && (MIN_TOKEN_TABLE..MAX_TOKEN_TABLE).contains(&(previous as usize)) {
                return Some(at);
            }
        }
        at += 2;
    }
    None
}

/// Try to decode a complete table given a candidate `kallsyms_token_index`.
///
/// Every step is validated against the next, so a wrong candidate fails rather
/// than producing plausible nonsense.
fn decode_at(image: &[u8], token_index_at: usize) -> Option<Kallsyms> {
    let index: Vec<u16> = (0..TOKENS)
        .map(|i| {
            u16::from_le_bytes([
                image[token_index_at + i * 2],
                image[token_index_at + i * 2 + 1],
            ])
        })
        .collect();

    // The token table ends where the index begins. Its length is the last
    // token's offset plus that token's own length, so the start is found by
    // trying candidates and keeping the one that lands exactly here.
    let table_at = locate_token_table(image, token_index_at, &index)?;
    let tokens: Vec<&[u8]> = index
        .iter()
        .map(|&off| {
            let start = table_at + off as usize;
            let end = image[start..token_index_at]
                .iter()
                .position(|&b| b == 0)
                .map(|n| start + n)?;
            Some(&image[start..end])
        })
        .collect::<Option<Vec<_>>>()?;

    // `kallsyms_markers` ends where the token table begins. Its entries are
    // `.long` on current kernels and `PTR` — eight bytes on a 64-bit kernel —
    // on older ones (the 4.19 arm64 Debian build is one), so both widths are
    // tried and the rest of the decode, which proves itself, keeps the one
    // that works. Nothing is told the version; the bytes are.
    let markers_end = table_at;
    let (align, num_syms, names) = LAYOUTS.iter().find_map(|&(align, width)| {
        let (markers_at, marker_count) = locate_markers(image, markers_end, width, align)?;

        // Each marker covers 256 symbols, so the count bounds `num_syms` to a
        // 256-wide window; the exact value comes from the field itself,
        // checked against that window.
        let num_syms = locate_num_syms(
            image,
            markers_at,
            markers_at,
            marker_count,
            width,
            align,
            &tokens,
        )?;

        // `kallsyms_names` begins one label alignment after `num_syms`: the
        // count is a 4-byte `unsigned int` and the stream that follows is
        // aligned.
        let names_at = num_syms.1 + align;
        // The stream ends where the MARKER ARRAY begins, not where the token
        // table does — `markers_end` is the far side of the markers. Passing
        // the wrong one let every symbol decode correctly and then failed the
        // boundary check, one whole array too late.
        let names = decode_names(image, names_at, markers_at, num_syms.0, align, &tokens)?;
        Some((align, num_syms, names))
    })?;

    // `kallsyms_offsets` and `kallsyms_relative_base` sit either side of the
    // `num_syms`/`names`/`markers`/`token` group, and *which* side moved between
    // kernel versions — the one difference that decides where the addresses are:
    //
    //   pre-6.4:  offsets, relative_base, num_syms, names, markers, tokens…
    //   6.4+:     num_syms, names, markers, tokens…, offsets, relative_base, seqs
    //
    // The names/markers/tokens run is in the same relative order in both, so
    // everything up to here decoded identically; only the offset array's home
    // differs. In the old layout it ends 8 bytes (`relative_base`) before
    // `num_syms`; in the new one it begins right after `token_index`, with
    // `relative_base` following it. (6.4 reordered these and 6.2 appended
    // `kallsyms_seqs_of_names`, which is why a decoder written for the old
    // layout read symbol-name bytes as addresses on a 6.8 capture.)
    //
    // Try the old layout, then the new one, and keep whichever produces real
    // addresses — a `relative_base` in the kernel's high half and a decode that
    // passes the sanity check below. Nothing is told the version; the bytes are.
    let num_syms_at = num_syms.1;
    let count = num_syms.0;

    // Every array label is 8-aligned (see *Alignment* in the module docs), so
    // the offset array — one `i32` per symbol — occupies its length rounded up
    // to eight, and `relative_base` sits after that rounding, not flush against
    // the last offset. Reading it flush is right only when `num_syms` is even;
    // on an odd count it reads four bytes of the last offset and four of the
    // base, fails the high-half check, and the whole table is reported absent.
    let offsets_span = align_up(count.checked_mul(4)?, align)?;

    // Old layout: [offsets][pad][relative_base(8)][pad][num_syms].
    let old = num_syms_at
        .checked_sub(align)
        .and_then(|base_at| base_at.checked_sub(offsets_span).map(|o| (o, base_at)));
    // New layout: [token_index(512)][offsets][pad to 8][relative_base(8)]. The
    // index is 512 bytes from its own 8-aligned label, so the offsets abut it.
    let new = align_up(token_index_at + TOKEN_INDEX_LEN, align).and_then(|offsets_at| {
        offsets_at
            .checked_add(offsets_span)
            .map(|base_at| (offsets_at, base_at))
    });

    for (offsets_at, base_at) in [old, new].into_iter().flatten() {
        if let Some(table) = resolve_with(image, offsets_at, base_at, count, &names) {
            return Some(table);
        }
    }
    None
}

/// Round `value` up to a multiple of `to` (a power of two), or `None` on overflow.
fn align_up(value: usize, to: usize) -> Option<usize> {
    value.checked_add(to - 1).map(|v| v & !(to - 1))
}

/// The kernel's virtual-address high half. A `kallsyms_relative_base` is a
/// kernel `.data` address, so a candidate that is not up here read the wrong
/// bytes — the cheapest discriminator between the two array layouts, and one
/// that holds for x86-64 (`0xffffffff8…`) and arm64 (`0xffff…`) alike.
const KERNEL_HIGH_HALF: u64 = 0xffff_0000_0000_0000;

/// Resolve every symbol's address given a candidate `kallsyms_offsets` start and
/// `kallsyms_relative_base` position, returning `None` if the candidate did not
/// read a plausible table (a non-kernel base, an out-of-range read, or addresses
/// that are nearly all identical — the signatures of decoding the wrong bytes).
fn resolve_with(
    image: &[u8],
    offsets_at: usize,
    base_at: usize,
    count: usize,
    names: &[(char, String)],
) -> Option<Kallsyms> {
    let relative_base = u64::from_le_bytes(image.get(base_at..base_at + 8)?.try_into().ok()?);
    if relative_base < KERNEL_HIGH_HALF {
        return None;
    }
    // The whole offset array must be inside the image.
    image.get(offsets_at..offsets_at + count.checked_mul(4)?)?;

    let raw_at = |i: usize| {
        i32::from_le_bytes(
            image[offsets_at + i * 4..offsets_at + i * 4 + 4]
                .try_into()
                .expect("four bytes, bounds checked above"),
        )
    };
    // `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` (x86-64 SMP only) stores every kernel
    // symbol as a negative offset. A table with no negative offset at all was
    // built without it — arm64, or a uniprocessor x86-64 kernel — and every
    // offset there is `relative_base + offset`. Reading such a table by the
    // absolute rule puts every symbol below 2 GiB.
    let absolute_percpu = (0..count).any(|i| raw_at(i) < 0);

    let mut symbols = Vec::with_capacity(count);
    let mut by_name = HashMap::with_capacity(count);
    for (i, (kind, name)) in names.iter().enumerate() {
        let raw = raw_at(i);
        let address = if absolute_percpu {
            resolve_address(raw, relative_base)
        } else {
            relative_base.wrapping_add(raw as u32 as u64)
        };
        by_name.entry(name.clone()).or_insert(address);
        symbols.push(Symbol {
            name: name.clone(),
            address,
            kind: *kind,
        });
    }

    // A table whose addresses are nearly all identical, or nearly all zero, is
    // a decode that "worked" against the wrong bytes.
    let distinct = symbols
        .iter()
        .map(|s| s.address)
        .collect::<std::collections::HashSet<_>>()
        .len();
    if distinct * 4 < symbols.len() {
        return None;
    }

    Some(Kallsyms { symbols, by_name })
}

/// `kallsyms_sym_address`, transcribed.
///
/// The `ABSOLUTE_PERCPU` rule is the one that matters: a non-negative offset is
/// already an absolute value. Adding a base to it — which is what the simpler
/// reading of this array does — would move every per-CPU symbol into the middle
/// of the kernel image and name the wrong bytes.
fn resolve_address(raw: i32, relative_base: u64) -> u64 {
    if raw >= 0 {
        raw as u64
    } else {
        relative_base
            .wrapping_sub(1)
            .wrapping_sub(raw as i64 as u64)
    }
}

/// Find where the token table starts, given where it ends.
///
/// The index gives each token's offset *within* the table, so for a candidate
/// start every token's terminating NUL must land exactly where the next token
/// begins. That pins the start precisely — one byte out and 255 of the 256
/// terminators fall in the wrong place.
///
/// The table does **not** end flush against the index. It is padded to
/// alignment: on the kernel this was built against the last token is `"__"` at
/// offset 887, ending at 890, in a table of 896 — six zero bytes of slack.
/// Requiring the last token to end exactly at `ends_at` therefore rejected the
/// real table, which is what made this whole decoder find nothing.
fn locate_token_table(image: &[u8], ends_at: usize, index: &[u16]) -> Option<usize> {
    let last = *index.last()? as usize;
    for len in (last + 2)..=MAX_TOKEN_TABLE.min(ends_at) {
        let start = ends_at.checked_sub(len)?;
        if tokens_fit(image, start, ends_at, index) {
            return Some(start);
        }
    }
    None
}

/// Whether all 256 tokens sit consistently in a table beginning at `start`.
fn tokens_fit(image: &[u8], start: usize, ends_at: usize, index: &[u16]) -> bool {
    for k in 0..TOKENS {
        let from = match start.checked_add(index[k] as usize) {
            Some(v) if v < ends_at => v,
            _ => return false,
        };
        if k + 1 < TOKENS {
            // Token k runs to the byte before token k+1 starts, and that byte
            // is its NUL.
            let next = match start.checked_add(index[k + 1] as usize) {
                Some(v) if v > from && v <= ends_at => v,
                _ => return false,
            };
            if image[next - 1] != 0 || image[from..next - 1].contains(&0) {
                return false;
            }
        } else {
            // The last token terminates somewhere at or before the end, and
            // everything after it is the alignment padding.
            let Some(nul) = image[from..ends_at].iter().position(|&b| b == 0) else {
                return false;
            };
            if image[from + nul + 1..ends_at].iter().any(|&b| b != 0) {
                return false;
            }
        }
    }
    true
}

/// The (label alignment, marker width) pairs a kernel has emitted its
/// kallsyms arrays with, most common first.
///
/// - Alignment: current kernels put `.balign 8` before every label. Older
///   ones wrote `.align 8`, which x86's assembler reads as 8 bytes and the
///   arm64 assembler as 2^8 = 256 — so an older arm64 kernel starts every
///   array on a 256-byte boundary (seen on the Debian 4.19 arm64 MMUShell
///   dump).
/// - Marker width: `.long` now, and `PTR` (an `unsigned long`, 8 bytes on a
///   64-bit kernel) on older kernels.
///
/// Every candidate still has to pass the whole self-checking decode.
const LAYOUTS: [(usize, usize); 4] = [(8, 4), (8, 8), (256, 8), (256, 4)];

/// One `kallsyms_markers` entry of `width` bytes at `at`.
fn marker_at(image: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = image.get(at..at.checked_add(width)?)?;
    let mut word = [0u8; 8];
    word[..width].copy_from_slice(bytes);
    Some(u64::from_le_bytes(word))
}

/// Find `kallsyms_markers`, entries of `width` bytes, which ends where the
/// token table begins.
///
/// Its first entry is zero — symbol 0 sits at the start of the name stream —
/// and the rest never decrease.
fn locate_markers(
    image: &[u8],
    ends_at: usize,
    width: usize,
    align: usize,
) -> Option<(usize, usize)> {
    let word = |at: usize| marker_at(image, at, width).unwrap_or(0);
    let mut at = ends_at.checked_sub(width)?;
    // The token table's label is aligned, so the array's last entry can be
    // followed by zero padding — one word when four-byte markers are odd in
    // number under 8-byte alignment, up to 255 bytes under 256. A real last
    // marker is never zero (it is the stream offset of a symbol beyond the
    // first 256), so trailing zero words shorter than one alignment are
    // padding, not data.
    while at >= width && word(at) == 0 && ends_at - at < align {
        at -= width;
    }
    // Walk back one entry at a time while the sequence stays a valid marker
    // array.
    let mut count = 1usize;
    while let Some(previous) = at.checked_sub(width) {
        if previous + width > image.len() {
            return None;
        }
        if word(previous) > word(at) {
            break;
        }
        at = previous;
        count += 1;
        // A kernel has at most a few thousand markers; a longer run means the
        // walk has left the array and is climbing through unrelated data.
        if count > MAX_PLAUSIBLE_SYMBOLS / SYMBOLS_PER_MARKER {
            return None;
        }
    }
    if word(at) != 0 || count < 2 {
        return None;
    }
    // The walk stops at the first *decrease*, and the name stream before the
    // markers is padded to alignment with zeros — which do not decrease against
    // `markers[0]`, itself zero. So the walk overshoots into the padding and
    // lands at its start, inflating the count by however many pad words there
    // were. `markers[1]` is non-zero, so the real `markers[0]` is the LAST zero
    // of that run: step forward while a zero is followed by another zero.
    while at + 2 * width <= image.len() && word(at) == 0 && word(at + width) == 0 {
        at += width;
        count -= 1;
    }
    if count < 2 {
        return None;
    }
    Some((at, count))
}

/// Find `kallsyms_num_syms` and the start of the name stream.
///
/// The count is a plain `unsigned int` sitting in front of a multi-megabyte
/// stream of compressed names, so a backward scan for "an integer in the right
/// range" finds hundreds of coincidences before it reaches the real one — every
/// four bytes of that stream that happen to fall in the window looks like a
/// candidate. Taking the first is how this returned nothing usable.
///
/// Each candidate is therefore *proved* instead. `kallsyms_markers[1]` is the
/// byte offset of symbol 256 within the stream, so decoding exactly 256 symbols
/// from a correct start must consume exactly that many bytes. Nothing but the
/// real start satisfies it.
fn locate_num_syms(
    image: &[u8],
    names_end: usize,
    markers_at: usize,
    marker_count: usize,
    marker_width: usize,
    align: usize,
    tokens: &[&[u8]],
) -> Option<(usize, usize)> {
    let low = marker_count.saturating_sub(1) * SYMBOLS_PER_MARKER + 1;
    let high = marker_count * SYMBOLS_PER_MARKER;
    if high < MIN_PLAUSIBLE_SYMBOLS || low > MAX_PLAUSIBLE_SYMBOLS {
        return None;
    }
    // The offset of symbol 256, which is what proves a candidate.
    let second_marker =
        usize::try_from(marker_at(image, markers_at + marker_width, marker_width)?).ok()?;
    if second_marker == 0 {
        return None;
    }

    let mut at = names_end.checked_sub(8)?;
    let floor = names_end.saturating_sub(64 * 1024 * 1024);
    while at > floor {
        if at + 4 <= image.len() {
            let value = u32::from_le_bytes(image[at..at + 4].try_into().unwrap()) as usize;
            if (low..=high).contains(&value) {
                // The stream begins one alignment on: the count is 4 bytes
                // and the stream that follows is aligned.
                let names_at = at + align;
                if names_at + second_marker <= names_end
                    && consumed_by(image, names_at, names_end, SYMBOLS_PER_MARKER, tokens)
                        == Some(second_marker)
                {
                    return Some((value, at));
                }
            }
        }
        at = at.checked_sub(8)?;
    }
    None
}

/// Bytes that decoding `count` symbols from `from` consumes, or `None` if the
/// stream runs out or a name is not valid UTF-8 first.
fn consumed_by(
    image: &[u8],
    from: usize,
    to: usize,
    count: usize,
    tokens: &[&[u8]],
) -> Option<usize> {
    let mut at = from;
    for _ in 0..count {
        if at >= to {
            return None;
        }
        let mut len = image[at] as usize;
        at += 1;
        if len & 0x80 != 0 {
            if at >= to {
                return None;
            }
            len = (len & 0x7F) | ((image[at] as usize) << 7);
            at += 1;
        }
        // A zero-length name does not occur: every symbol carries at least its
        // type letter.
        if len == 0 || at + len > to {
            return None;
        }
        // The first token must begin with a plausible type letter, which is the
        // cheapest way to reject a run of arbitrary bytes.
        let first = tokens[image[at] as usize].first().copied()?;
        if !first.is_ascii_alphabetic() {
            return None;
        }
        at += len;
    }
    Some(at - from)
}

/// Walk the compressed name stream, expanding each entry.
///
/// The decode must consume exactly the bytes between the stream's start and the
/// marker array. Landing anywhere else means the layout was misread, and that
/// check is what makes a false candidate fail rather than yield rubbish.
fn decode_names(
    image: &[u8],
    from: usize,
    to: usize,
    count: usize,
    align: usize,
    tokens: &[&[u8]],
) -> Option<Vec<(char, String)>> {
    if !(MIN_PLAUSIBLE_SYMBOLS..=MAX_PLAUSIBLE_SYMBOLS).contains(&count) || from >= to {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    let mut at = from;
    for _ in 0..count {
        if at >= to {
            return None;
        }
        let mut len = image[at] as usize;
        at += 1;
        // The top bit means a second length byte follows.
        if len & 0x80 != 0 {
            if at >= to {
                return None;
            }
            len = (len & 0x7F) | ((image[at] as usize) << 7);
            at += 1;
        }
        if at + len > to {
            return None;
        }

        let mut expanded = Vec::new();
        for &code in &image[at..at + len] {
            expanded.extend_from_slice(tokens[code as usize]);
        }
        at += len;

        // The first character is the symbol's type, not part of its name.
        let mut chars = expanded.into_iter();
        let kind = chars.next()? as char;
        let name = String::from_utf8(chars.collect()).ok()?;
        out.push((kind, name));
    }
    // The stream is padded to alignment before the marker array, so the decode
    // ends at or just before it — on the kernel this was built against, four
    // bytes short. What must hold is that nothing but padding remains: a
    // misread layout does not land within a few zero bytes of the boundary.
    if at > to || to - at >= align || image[at..to].iter().any(|&b| b != 0) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_negative_offset_is_already_absolute() {
        // The ABSOLUTE_PERCPU rule. Adding a base here would move every per-CPU
        // symbol into the middle of the kernel image.
        assert_eq!(resolve_address(0, 0xFFFF_FFFF_8D80_0000), 0);
        assert_eq!(resolve_address(0x1000, 0xFFFF_FFFF_8D80_0000), 0x1000);
    }

    #[test]
    fn a_negative_offset_is_relative_to_the_base() {
        // relative_base - 1 - offset, with offset negative.
        let base = 0xFFFF_FFFF_8D80_0000u64;
        assert_eq!(resolve_address(-1, base), base);
        assert_eq!(resolve_address(-0x1001, base), base + 0x1000);
    }

    #[test]
    fn an_all_zero_run_is_not_a_token_index() {
        // Padding is 256 zero u16s, which satisfies "starts at zero and never
        // decreases" and is not a token index.
        let zeros = vec![0u8; TOKEN_INDEX_LEN * 2];
        assert_eq!(find_token_index(&zeros, 0), None);
    }

    #[test]
    fn a_decreasing_run_is_not_a_token_index() {
        let mut data = vec![0u8; TOKEN_INDEX_LEN];
        for i in 1..TOKENS {
            let v = (TOKENS - i) as u16;
            data[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        assert_eq!(find_token_index(&data, 0), None);
    }

    #[test]
    fn a_plausible_token_index_is_recognised() {
        let mut data = vec![0u8; TOKEN_INDEX_LEN];
        for i in 1..TOKENS {
            data[i * 2..i * 2 + 2].copy_from_slice(&((i * 3) as u16).to_le_bytes());
        }
        assert_eq!(find_token_index(&data, 0), Some(0));
    }

    #[test]
    fn a_name_stream_that_does_not_end_where_it_should_is_refused() {
        // The decode must land exactly on the marker array. This is what makes
        // a wrong layout fail instead of producing plausible rubbish.
        let tokens: Vec<&[u8]> = vec![b"T", b"a"];
        // One token, index 0, which expands to the type letter 'T'.
        let stream = vec![1u8, 0u8];
        let padded = [stream.as_slice(), &[0u8; 16]].concat();
        // Claim the stream ends 16 bytes later than it does.
        assert!(decode_names(&padded, 0, padded.len(), 1, 8, &tokens).is_none());
    }

    #[test]
    fn an_implausible_symbol_count_is_refused_before_allocating() {
        let tokens: Vec<&[u8]> = vec![b"T"];
        assert!(decode_names(&[0u8; 16], 0, 16, 0, 8, &tokens).is_none());
        assert!(decode_names(&[0u8; 16], 0, 16, usize::MAX, 8, &tokens).is_none());
    }

    /// Build a complete, structurally valid kallsyms block in the kernel's own
    /// array order — `offsets`, `relative_base`, `num_syms`, `names`, `markers`,
    /// `token_table`, `token_index` — for one named symbol (`linux_banner`,
    /// symbol 0) followed by `n - 1` filler symbols. Symbol `i` is given a
    /// negative offset that resolves to `relative_base + i * 0x100`, so
    /// `linux_banner` lands exactly on `relative_base` and every address is
    /// distinct.
    fn synthetic_kallsyms(n: usize, relative_base: u64) -> Vec<u8> {
        synthetic_kallsyms_as(n, relative_base, 4, true, 8)
    }

    /// [`synthetic_kallsyms`] with the two build choices that vary between
    /// kernels made explicit: `marker_bytes` is the width of each
    /// `kallsyms_markers` entry (`4`, `.long`; `8`, the `PTR` older kernels
    /// emit), and `absolute_percpu` whether offsets follow the
    /// `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` rule (negative, `base - 1 - raw`) or
    /// the plain base-relative one (non-negative, `base + raw`) that every
    /// kernel without it — arm64 among them — uses.
    fn synthetic_kallsyms_as(
        n: usize,
        relative_base: u64,
        marker_bytes: usize,
        absolute_percpu: bool,
        align: usize,
    ) -> Vec<u8> {
        assert!(
            (MIN_PLAUSIBLE_SYMBOLS..=1280).contains(&n),
            "n must be plausible and small enough to build quickly"
        );
        // Token 0 spells the whole "T" + "linux_banner"; token 1 the filler
        // "t" + "filler"; the rest are a single 'x' so the 256-entry index is
        // well formed and long enough to be recognised as a token table.
        let mut tokens: Vec<Vec<u8>> = Vec::with_capacity(TOKENS);
        tokens.push(b"Tlinux_banner".to_vec());
        tokens.push(b"tfiller".to_vec());
        for _ in 2..TOKENS {
            tokens.push(b"x".to_vec());
        }
        let mut index = Vec::with_capacity(TOKENS);
        let mut table = Vec::new();
        for tok in &tokens {
            index.push(table.len() as u16);
            table.extend_from_slice(tok);
            table.push(0);
        }
        pad_to(&mut table, align); // alignment slack, exactly as the kernel emits

        // offsets: symbol i -> negative raw so resolve_address gives base + i*0x100.
        let mut out = Vec::new();
        for i in 0..n {
            let raw: i32 = if absolute_percpu {
                -(1 + (i as i32) * 0x100)
            } else {
                (i as i32) * 0x100
            };
            out.extend_from_slice(&raw.to_le_bytes());
        }
        pad_to(&mut out, align); // every label is `.balign 8`
        out.extend_from_slice(&relative_base.to_le_bytes()); // kallsyms_relative_base
        pad_to(&mut out, align); // a no-op under 8-byte alignment
        out.extend_from_slice(&(n as u32).to_le_bytes()); // kallsyms_num_syms
        pad_to(&mut out, align); // names begin one alignment past the count

        // names: symbol 0 = token 0, every filler = token 1; each entry is a
        // one-byte length followed by that many token indices.
        for i in 0..n {
            out.push(1);
            out.push(if i == 0 { 0 } else { 1 });
        }
        pad_to(&mut out, align);

        // markers: one per 256 symbols, each the byte offset of that symbol in
        // the (2-bytes-per-entry) name stream.
        for m in 0..n.div_ceil(SYMBOLS_PER_MARKER) {
            let marker = (m * SYMBOLS_PER_MARKER * 2) as u64;
            out.extend_from_slice(&marker.to_le_bytes()[..marker_bytes]);
        }
        pad_to(&mut out, align);

        out.extend_from_slice(&table);
        for &off in &index {
            out.extend_from_slice(&off.to_le_bytes());
        }
        out
    }

    /// The zero padding `.balign 8` inserts before the next label.
    fn pad_to_8(out: &mut Vec<u8>) {
        pad_to(out, 8);
    }

    /// The zero padding an `align`-byte label alignment inserts.
    fn pad_to(out: &mut Vec<u8>, align: usize) {
        while !out.len().is_multiple_of(align) {
            out.push(0);
        }
    }

    /// The 6.4+ array order: the `num_syms`/`names`/`markers`/`token` group comes
    /// first and `offsets`/`relative_base` follow the token index (with
    /// `seqs_of_names` after, appended in 6.2). Same symbols as
    /// [`synthetic_kallsyms`], different array home for the offsets — the one
    /// difference the decoder must handle to read a modern capture.
    fn synthetic_kallsyms_new_layout(n: usize, relative_base: u64) -> Vec<u8> {
        assert!(
            (MIN_PLAUSIBLE_SYMBOLS..=1280).contains(&n),
            "n must be plausible and small enough to build quickly"
        );
        let mut tokens: Vec<Vec<u8>> = Vec::with_capacity(TOKENS);
        tokens.push(b"Tlinux_banner".to_vec());
        tokens.push(b"tfiller".to_vec());
        for _ in 2..TOKENS {
            tokens.push(b"x".to_vec());
        }
        let mut index = Vec::with_capacity(TOKENS);
        let mut table = Vec::new();
        for tok in &tokens {
            index.push(table.len() as u16);
            table.extend_from_slice(tok);
            table.push(0);
        }
        while table.len() % 8 != 0 {
            table.push(0);
        }

        let mut out = Vec::new();
        // Leading .rodata: on a real capture something always precedes the block,
        // and `num_syms` is never at file offset 0 (the backward scan that proves
        // it excludes the very first word). 64 aligned bytes stand in for that.
        out.extend_from_slice(&[0xABu8; 64]);
        out.extend_from_slice(&(n as u32).to_le_bytes()); // kallsyms_num_syms
        pad_to_8(&mut out); // names begin 8 bytes past the count
        for i in 0..n {
            out.push(1);
            out.push(if i == 0 { 0 } else { 1 }); // names
        }
        pad_to_8(&mut out);
        for m in 0..n.div_ceil(SYMBOLS_PER_MARKER) {
            out.extend_from_slice(&((m * SYMBOLS_PER_MARKER * 2) as u32).to_le_bytes());
            // markers
        }
        pad_to_8(&mut out);
        out.extend_from_slice(&table); // token_table
        for &off in &index {
            out.extend_from_slice(&off.to_le_bytes()); // token_index
        }
        // 6.4+: offsets and relative_base come AFTER the token index. The index
        // is 512 bytes from an 8-aligned label, so the offsets land flush.
        assert!(
            out.len().is_multiple_of(8),
            "offsets follow the index flush"
        );
        for i in 0..n {
            let raw: i32 = -(1 + (i as i32) * 0x100);
            out.extend_from_slice(&raw.to_le_bytes()); // kallsyms_offsets
        }
        pad_to_8(&mut out); // an odd count leaves four bytes before the base
        out.extend_from_slice(&relative_base.to_le_bytes()); // kallsyms_relative_base
        out.extend_from_slice(&[0u8; 8]); // kallsyms_seqs_of_names stub (6.2+)
        out
    }

    /// **An odd symbol count, in both layouts.** `kallsyms_offsets` is one
    /// `i32` per symbol and `kallsyms_relative_base` is 8-aligned, so an odd
    /// count puts four bytes of padding between them. Reading the base flush
    /// against the offsets took half of the last offset and half of the base,
    /// failed the high-half check, and reported the table absent — on a real
    /// 6.8.0-1061-aws capture with 202,525 symbols, and on every kernel whose
    /// count is odd. The earlier guards only ever built multiples of four.
    #[test]
    fn an_odd_symbol_count_still_finds_the_relative_base_in_both_layouts() {
        let base = 0xFFFF_FFFF_8D80_0000u64;
        for n in [1001usize, 1023] {
            let old = synthetic_kallsyms(n, base);
            let (_, k) = Kallsyms::find_in(&old)
                .unwrap_or_else(|| panic!("pre-6.4 block with {n} symbols must decode"));
            assert_eq!(k.len(), n);
            assert_eq!(k.address_of("linux_banner"), Some(base), "pre-6.4, n={n}");

            let new = synthetic_kallsyms_new_layout(n, base);
            let (_, k) = Kallsyms::find_in(&new)
                .unwrap_or_else(|| panic!("6.4+ block with {n} symbols must decode"));
            assert_eq!(k.len(), n);
            assert_eq!(k.address_of("linux_banner"), Some(base), "6.4+, n={n}");
        }
    }

    /// **An odd marker count.** The token table's label is 8-aligned too, so
    /// five markers (1025–1280 symbols) leave a zero word between the array
    /// and the table. The backward walk from the table must step over it
    /// rather than reading it as a one-entry marker array and giving up.
    #[test]
    fn an_odd_marker_count_leaves_padding_the_walk_must_step_over() {
        let base = 0xFFFF_FFFF_8D80_0000u64;
        let n = 1100usize;
        assert!(!n.div_ceil(SYMBOLS_PER_MARKER).is_multiple_of(2));
        for blob in [
            synthetic_kallsyms(n, base),
            synthetic_kallsyms_new_layout(n, base),
        ] {
            let (_, k) = Kallsyms::find_in(&blob).expect("a block with five markers must decode");
            assert_eq!(k.len(), n);
            assert_eq!(k.address_of("linux_banner"), Some(base));
        }
    }

    #[test]
    fn a_modern_6_4_block_decodes_though_offsets_moved_after_the_token_index() {
        // The 6.8 regression: kernel 6.4 moved `kallsyms_offsets` and
        // `kallsyms_relative_base` from before `num_syms` to after the token
        // index. A decoder that only knew the old order read symbol-name bytes as
        // addresses and rejected every modern capture at the sanity check.
        let base = 0xFFFF_FFFF_B754_7D70u64;
        let blob = synthetic_kallsyms_new_layout(1024, base);
        let (_at, k) = Kallsyms::find_in(&blob).expect("a 6.4+ block must decode");
        assert_eq!(k.len(), 1024);
        assert_eq!(
            k.address_of("linux_banner"),
            Some(base),
            "linux_banner (symbol 0) must resolve to relative_base under the new layout"
        );
    }

    #[test]
    fn a_complete_block_decodes_symbol_addresses_in_the_kernels_own_layout() {
        // The regression guard for the offsets-location bug: the kernel lays
        // `kallsyms_offsets` at the START of the block, before `num_syms`, with
        // the token index LAST. Reading offsets after the token index made every
        // recovered address unrelated `.rodata` bytes while the names, located
        // correctly, still came out right — so a names-only check passed a table
        // whose addresses were entirely wrong.
        let base = 0xFFFF_FFFF_8D80_0000u64;
        let blob = synthetic_kallsyms(1024, base);
        let (_at, k) = Kallsyms::find_in(&blob).expect("a complete block must decode");
        assert_eq!(k.len(), 1024);
        assert_eq!(
            k.address_of("linux_banner"),
            Some(base),
            "linux_banner (symbol 0) must resolve to relative_base, not stray bytes"
        );
        // Addresses must be real, distinct kernel VAs — the symptom of the bug
        // was addresses like 0x626f6c67 ('glob'), far below the kernel range.
        let banner = k.address_of("linux_banner").unwrap();
        assert!(
            banner >> 32 == 0xffff_ffff,
            "must be a kernel virtual address"
        );
    }

    /// **Eight-byte markers.** Older kernels (this 4.19 arm64 build among
    /// them, confirmed on the MMUShell Debian dump) emit `kallsyms_markers`
    /// as `PTR` — an `unsigned long` each — where later ones emit `.long`.
    /// Read as four-byte words the array is a zero every other word, and the
    /// whole table was reported absent.
    #[test]
    fn an_eight_byte_marker_array_as_older_kernels_emit_decodes() {
        let base = 0xFFFF_FFFF_8D80_0000u64;
        for n in [1024usize, 1100] {
            let blob = synthetic_kallsyms_as(n, base, 8, true, 8);
            let (_, k) = Kallsyms::find_in(&blob)
                .unwrap_or_else(|| panic!("{n} symbols with 8-byte markers must decode"));
            assert_eq!(k.len(), n);
            assert_eq!(k.address_of("linux_banner"), Some(base));
        }
    }

    /// **No `CONFIG_KALLSYMS_ABSOLUTE_PERCPU`.** Only x86-64 SMP kernels set
    /// it; everywhere else (arm64 included) every offset is non-negative and
    /// means `relative_base + offset`. Reading those as absolute put every
    /// symbol below 2 GiB.
    #[test]
    fn a_table_with_no_negative_offset_is_read_base_relative_as_on_arm64() {
        let base = 0xFFFF_0000_0808_0000u64;
        let blob = synthetic_kallsyms_as(1024, base, 4, false, 8);
        let (_, k) = Kallsyms::find_in(&blob).expect("a base-relative block must decode");
        assert_eq!(k.address_of("linux_banner"), Some(base));
        assert_eq!(k.symbols()[5].address, base + 5 * 0x100);
    }

    /// **256-byte label alignment.** Older kernels emitted `.align 8` before
    /// every kallsyms label, which the arm64 assembler reads as 2^8 = 256
    /// bytes (x86's reads it as 8). On the MMUShell Debian 4.19 arm64 dump
    /// every array starts on a 256-byte boundary — `kallsyms_relative_base`
    /// at `…c00`, `kallsyms_num_syms` at `…d00`, the names at `…e00` — and
    /// a decoder that assumed eight found nothing.
    #[test]
    fn a_block_whose_labels_are_256_byte_aligned_as_old_arm64_kernels_emit_decodes() {
        let base = 0xFFFF_0000_0808_0000u64;
        for n in [1024usize, 1100] {
            let blob = synthetic_kallsyms_as(n, base, 8, false, 256);
            let (_, k) = Kallsyms::find_in(&blob)
                .unwrap_or_else(|| panic!("{n} symbols, 256-aligned labels, must decode"));
            assert_eq!(k.len(), n);
            assert_eq!(k.address_of("linux_banner"), Some(base));
            assert_eq!(k.symbols()[7].address, base + 7 * 0x100);
        }
    }
}
