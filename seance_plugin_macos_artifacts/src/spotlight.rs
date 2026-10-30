//! Spotlight metadata store — `.Spotlight-V100/Store-V2/store.db`.
//!
//! Spotlight indexes rich metadata for every file it sees — **including files
//! that have since been deleted** — which is what makes the store worth
//! reading. A version-2 store opens with an `8tsd` header and is then a
//! sequence of 16 KiB blocks, each tagged `2pbd` and carrying a type id, laid
//! out at page granularity and reached by following five chains the header
//! names.
//!
//! # What is recovered, and what is not
//!
//! Three of the block kinds are plainly structured and are decoded:
//!
//! * **`0x11` — the property table.** The metadata attributes this store's own
//!   index holds: `kMDItemContentType`, `kMDItemWhereFroms`,
//!   `kMDItemPhysicalSize`, `_kMDItemFileName` and the rest, each with the
//!   property and value type the table declares for it.
//! * **`0x21` — the category table**, which holds **two different kinds of
//!   entry** and is reported as two (see below).
//! * **`0x81` — two tables, and they are two.** The fourth chain's maps an id
//!   to a list of category ids; the fifth's maps an id to the same label once
//!   per language. Both number their entries from 1, so merging them makes a
//!   folder's `kMDItemKind` read as a content-type list.
//! * **`0x09` and `0x4009` — the item blocks**, which hold the per-file
//!   records and are **zlib-compressed**. The stream starts at block offset
//!   **20**, and the `u32` at offset 16 is the uncompressed length counting
//!   those twenty bytes. All 74 item blocks in the corpus's larger store
//!   inflate, and the one in its smaller store.
//!
//! A sixth structure is read for one purpose: the `2mbd` block on page 1
//! **lists the store's item blocks**, which is a second, independent statement
//! of that population. The blocks themselves are found by scanning every page
//! for the `2pbd` tag, and the map is what turns "the scan found 74" into "the
//! scan found 74 and the store says 74". Where the two disagree, the pages are
//! named.
//!
//! # The item records
//!
//! An inflated item block is a flat sequence of records, each a little-endian
//! `u32` byte count then that many bytes, and **they tile the block exactly**:
//! 14,934 records across the 74 blocks with **no byte left over**, which is the
//! test the layout has to pass. Each record opens with the item id, a flag
//! byte, one variable-size number this reader has not established the meaning
//! of, the parent item's id, and the time the index wrote the record in
//! microseconds since the Unix epoch — every one of the 14,934 between
//! 2021-02-11 and 2021-04-06, which brackets the image's acquisition.
//!
//! Then comes the **attribute stream**: the metadata values, as pairs of a
//! *delta* added to a running property id and a value whose shape comes from
//! the type that id declares. There is no terminator and no padding — the
//! stream ends when the record does — so **one value read at the wrong width
//! desynchronises everything after it**, which is why exact tiling is the test
//! and why a type this reader cannot decode stops the walk instead of being
//! skipped. All 14,936 records in both stores tile, with **428,124 values
//! decoded** and nothing left over.
//!
//! ## The numbers are big-endian behind a length byte
//!
//! The leading one-bits of a number's first byte count the bytes that follow;
//! whatever low bits of the first byte remain are the value's high bits, and
//! the rest are big-endian. It is UTF-8's length trick applied to an integer,
//! and a little-endian reading of the same bytes yields plausible nonsense —
//! this reading is what makes sibling item ids come out consecutive
//! (`c1 33 ac` and `c1 33 ad` are 78,764 and 78,765) and every index time land
//! in the acquisition window.
//!
//! ## What is still not established
//!
//! * The **widest number form**, `0xff` and eight bytes: its byte count is
//!   pinned but its value is not, and it occurs **once** in the corpus. See
//!   [`WIDEST_FORM_NOTE`] — a value read through it is flagged, not quoted.
//! * The record's **flag byte** and the **unnamed number** before the parent
//!   reference. Both are read and published as what they are.
//! * `value_type`'s other bits. Only `0x02` (a list) and `0x80` (localised)
//!   are established to change the wire format; a decoder that ignores the
//!   rest tiles every record.
//! * The **leading byte** of each localised-label entry, and the two bytes
//!   `0x16 0x02` themselves: the category table shows the second standing
//!   before a language tag, which is inference from that table rather than
//!   proof from an item record.
//! * Nine of the 33 value shapes rest on **one to five observations plus
//!   plausibility rather than on tiling** — the integer and date arrays, the
//!   two float types, the blobs. Tiling is a razor for the frequent pairs and
//!   nearly blind for the rare ones, and saying so is the difference between a
//!   measurement and a claim.
//!
//! ## What this reader used to say about those blocks, and why it was wrong
//!
//! It reported the item blocks as **not decodable**, on the strength of a real
//! measurement — 7.7 to 8.0 bits per byte with almost every byte value present
//! — and a marker search that found no `bv41`, `bv4$`, `bvx1`, `bvx2`, `bvxn`,
//! `bvx-`, LZ4 frame magic **or zlib header** anywhere it looked. The search
//! looked at offset 0 and offset 32. The zlib header is at offset 20. High
//! entropy is what compressed data looks like, so the measurement was
//! corroborating the wrong conclusion, and "no marker found" was recorded as
//! "no marker present". The entropy machinery is kept and pointed at the one
//! thing it is good for: a block this reader does **not** decode, where it says
//! whether the bytes look compressed or look like structure that was missed.
//!
//! # What an item record does and does not say
//!
//! Spotlight indexes files that have since been **deleted**, so an item is not
//! evidence that the file is on the volume now — and the reverse holds: a file
//! absent from the store is not a file Spotlight never indexed. A volume's
//! index is **split across stores**, so a parent chain can run into an item
//! this file does not hold: 967 of the larger store's 14,934 items are in that
//! position and are reported without an absolute path rather than with a
//! partial one dressed as absolute. And **two records can carry one item id** —
//! four pairs do — where the store kept a superseded version alongside the
//! current one; both are emitted with their own index times, because
//! deduplicating on the id alone picks the older stub.
//!
//! ## What this reader used to say about those blocks, and why it was wrong
//!
//! It reported the item blocks as **not decodable**, on the strength of a real
//! measurement — 7.7 to 8.0 bits per byte with almost every byte value present
//! — and a marker search that found no `bv41`, `bv4$`, `bvx1`, `bvx2`, `bvxn`,
//! `bvx-`, LZ4 frame magic **or zlib header** anywhere it looked. The search
//! looked at offset 0 and offset 32. The zlib header is at offset 20. High
//! entropy is what compressed data looks like, so the measurement was
//! corroborating the wrong conclusion, and "no marker found" was recorded as
//! "no marker present". The entropy machinery is kept and pointed at the one
//! thing it is good for: a block this reader does **not** decode, where it says
//! whether the bytes look compressed or look like structure that was missed.
//!
//! # The category table is two tables
//!
//! Its entries are `u32 id` then a NUL-terminated string, and the string comes
//! in two forms separated by the two bytes `0x16 0x02`:
//!
//! * with no separator, a **content type** — `public.message`,
//!   `com.apple.mail.emlx`, `com.apple.ichat.transcript`;
//! * with one, a **localised display name** and its locale —
//!   `Safari` + `en_GB`, `الإنتاجية` + `ar`, and an empty locale for the base
//!   name.
//!
//! On the corpus's larger store that is **397 content types and 3,703
//! localised names** out of 4,100 entries; on its smaller one, 133 and 41 out
//! of 174. Calling all 4,100 "content types" would put three thousand
//! localisation strings in a case as though they were observations about
//! files, so the two are separated and only the content types are emitted as
//! records. No entry in any store has a lone `0x16`, so the separator is exact.
//!
//! # These tables are observations, not a shipped constant
//!
//! Checked, because emitting Apple's own fixed table as evidence would be the
//! worse error: the two stores in the corpus hold **59 properties and 174
//! categories** against **136 and 4,100**, they diverge, and **44 ids common
//! to both carry different values**. The tables are built up per volume as
//! Spotlight meets things, so a category id means nothing outside the store it
//! came from — which is why every record names its store.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use tracing::info;

use crate::{basename_lower, stamp_incomplete, Staged};

/// Largest store this reader stages. A busy volume's store reaches tens of
/// megabytes; the cap stops a corrupt size from staging a disk.
const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
/// Largest number of blocks walked.
const MAX_BLOCKS: usize = 200_000;
/// Largest number of property-table entries read.
const MAX_PROPERTIES: usize = 100_000;
/// Largest number of category-table entries read.
const MAX_CATEGORIES: usize = 1_000_000;
/// Largest number of per-item records read from one store. The corpus's larger
/// store holds 14,934.
const MAX_ITEMS: usize = 5_000_000;

/// The parent reference that means an item has no parent in this store.
///
/// Written as the widest variable-size form there is — `0xff` and eight bytes
/// of `0xff`. The corpus's smaller store uses it on its one real item, and
/// reporting it as parent id 18,446,744,073,709,551,615 would put a number in
/// a case where the file says "none".
const NO_PARENT: u64 = u64::MAX;
/// Longest name read from either table.
const MAX_NAME_BYTES: usize = 4096;
/// How many base display labels are sampled onto the store record. A count
/// plus a sample; the whole list is a display vocabulary, not evidence.
const MAX_SAMPLED_DISPLAY_NAMES: usize = 32;

/// `8tsd` at offset 0 of a version-2 store.
const STORE_MAGIC: &[u8; 4] = b"8tsd";
/// `2pbd` at the start of every block.
const BLOCK_MAGIC: &[u8; 4] = b"2pbd";
/// Fixed part of a block before its entries.
const BLOCK_HEADER_BYTES: usize = 32;
/// The five chain heads the store header names, at `0x30`.
const CHAIN_HEADS_AT: usize = 0x30;
const CHAIN_HEADS: usize = 5;

/// The two bytes that separate a localised display name from its locale in the
/// category table. Exact: no entry in any corpus store carries a lone `0x16`.
const LOCALE_SEPARATOR: &[u8; 2] = &[0x16, 0x02];

/// `2mbd` at the start of the store's map block.
const MAP_MAGIC: &[u8; 4] = b"2mbd";
/// The page the map block sits on.
const MAP_PAGE: usize = 1;
/// Where the map's entries begin, and how big each is.
const MAP_ENTRIES_AT: usize = 16;
const MAP_ENTRY_BYTES: usize = 16;
/// Offset within a map entry of the page it names.
const MAP_ENTRY_PAGE_AT: usize = 12;

/// Where an item block's compressed stream begins.
///
/// **Not** [`BLOCK_HEADER_BYTES`]. An item block's `2pbd` header is twenty
/// bytes, not thirty-two, and the zlib stream starts immediately after it:
/// every one of the 74 item blocks in the corpus's larger store inflates from
/// this offset, and none of them from 0 or 32. An earlier reading of this
/// format looked for a compression marker at offset 32, found none, and
/// concluded from that absence that the item records were compressed or
/// encrypted by an unidentified scheme. They were zlib, twelve bytes earlier.
/// A marker search that misses by an offset returns the same answer as a
/// marker that is not there.
const ITEM_STREAM_AT: usize = 20;

/// Largest inflated item block accepted from one block's stream.
///
/// The corpus's largest inflates to 134,832 bytes from a 16 KiB block. The cap
/// is what stops a corrupt logical size from turning a compression ratio into
/// a memory budget.
const MAX_ITEM_BLOCK_BYTES: u32 = 64 * 1024 * 1024;

/// Block type ids, as the blocks' own `id` field carries them.
const BLOCK_PROPERTIES: u32 = 0x11;
const BLOCK_CATEGORIES: u32 = 0x21;
const BLOCK_UNKNOWN_41: u32 = 0x41;
const BLOCK_INDEX: u32 = 0x81;
const BLOCK_ITEMS: u32 = 0x09;
const BLOCK_ITEMS_ALT: u32 = 0x4009;

/// Bits per byte above which a payload is reported as compressed or encrypted
/// rather than as structure this reader failed to read.
///
/// Applied to **one** thing: a block this reader does not decode. It says
/// whether the bytes look compressed or look like structure that was missed,
/// and nothing is decoded differently because of the answer.
///
/// The threshold sits where it does because on the corpus's two stores the two
/// populations are far apart — the decoded tables measure 3.31 to 6.28 bits
/// per byte and the compressed item streams 7.72 to 7.98, a gap of nearly a
/// bit and a half. **That gap is also the trap this reader fell into once.**
/// A high measurement on the item blocks was read as evidence that they could
/// not be decoded, when it was evidence that they were compressed — which is
/// exactly what a decodable zlib stream measures. Entropy can say a block is
/// not plaintext. It cannot say a block cannot be read.
const HIGH_ENTROPY_BITS: f64 = 7.0;

/// Shortest payload the entropy threshold is applied to.
///
/// **A threshold applied to a sample too small to support it is a wrong answer
/// dressed as a measurement.** Entropy over 256 symbols is bounded by
/// `log2(n)` for `n` bytes, so a 191-byte payload cannot exceed about 7.6 even
/// if it is perfectly random, and in practice measures lower. The corpus holds
/// exactly such a block — 191 bytes of an item kind measuring 6.68 — which a
/// bare threshold would have called structured, and two index tables of 21 and
/// 334 bytes measuring 1.60 and 2.27, which it would have called structured
/// correctly but for no reason the sample supports. At 1 KiB, uniform bytes
/// measure about 7.7 and the threshold separates cleanly. Anything shorter is
/// reported as **too short to measure** rather than as either.
const MIN_ENTROPY_SAMPLE_BYTES: usize = 1024;

/// What the entropy of a block's payload establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntropyVerdict {
    /// Long enough to measure, and measures as compressed or encrypted.
    HighEntropy,
    /// Long enough to measure, and does not.
    Structured,
    /// Too short for the threshold to mean anything.
    TooShort,
}

/// What a block kind is, for the inventory.
fn block_kind(id: u32) -> &'static str {
    match id {
        BLOCK_PROPERTIES => "property_table",
        BLOCK_CATEGORIES => "category_table",
        BLOCK_UNKNOWN_41 => "unnamed_0x41",
        BLOCK_INDEX => "index_table",
        BLOCK_ITEMS => "item_records",
        BLOCK_ITEMS_ALT => "item_records_alt",
        _ => "unrecognised",
    }
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    let s = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Shannon entropy of `bytes`, in bits per byte.
///
/// Computed rather than quoted, so "this block is compressed or encrypted" is
/// a measurement of the examiner's own evidence.
fn entropy_bits(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut histogram = [0usize; 256];
    for &b in bytes {
        histogram[usize::from(b)] += 1;
    }
    let total = bytes.len() as f64;
    let sum = -histogram
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>();
    // A payload of one repeated byte sums to exactly zero, and negating that
    // gives negative zero, which formats as "-0.00". A screen reporting a
    // measurement of minus zero bits per byte reads as a broken tool, so the
    // sign is dropped at the only point it can be wrong.
    if sum == 0.0 {
        0.0
    } else {
        sum
    }
}

/// How wide the variable-size form is that a number was written in.
///
/// Carried out of the reader for one reason: **the widest form's value is not
/// established.** Its byte count is — `0xff` and eight bytes, and no other
/// count tiles — but which way round those eight bytes go is settled by a
/// single sample in the whole corpus. See [`WIDEST_FORM_NOTE`].
const WIDEST_VAR_NUM_BYTES: usize = 9;

/// Why a value read through the widest variable-size form is reported with a
/// caveat rather than as a fact.
const WIDEST_FORM_NOTE: &str =
    "This value was written in the widest variable-size form — 0xff and eight bytes — whose \
     byte count is established but whose value is not. Every narrower form is demonstrably \
     big-endian, because reading it that way is what makes the index times land in the \
     acquisition window and the sibling item ids come out consecutive; the widest form occurs \
     ONCE in the corpus, on a Finder-flags field, where big-endian gives 36,310,271,995,674,623 \
     and a little-endian signed reading gives -32768, whose low sixteen bits are exactly the \
     kIsAlias flag the item should carry. Both readings consume the same nine bytes, so the \
     record's own structure cannot choose between them. The number here is the big-endian \
     reading, for consistency with the forms that are proven, and it is flagged because one \
     sample is not evidence.";

/// Read one of the store's variable-size numbers at `p`, returning it and the
/// offset past it.
///
/// The encoding counts the leading one-bits of the first byte to get the
/// number of bytes that follow; whatever low bits of the first byte remain
/// after those ones and the zero that ends them are the value's high bits, and
/// the following bytes are big-endian. It is UTF-8's length trick applied to
/// an integer, and it is why a naive little-endian read of this format
/// produces plausible nonsense.
///
/// Returns `None` at the end of the buffer, which is how the walk stops
/// without assuming a length it was not given.
fn var_num(data: &[u8], p: usize) -> Option<(u64, usize)> {
    let first = *data.get(p)?;
    if first == 0 {
        return Some((0, p + 1));
    }
    let extra = first.leading_ones() as usize;
    if extra == 0 {
        return Some((u64::from(first), p + 1));
    }
    // `0xff` is the widest form: eight one-bits, no terminating zero, no value
    // bits in the first byte, and a full big-endian `u64` after it. The
    // corpus's smaller store uses it once, for a parent reference of
    // `0xffffffffffffffff` — see [`NO_PARENT`].
    let value_bits = 7usize.saturating_sub(extra);
    let mut value = if value_bits == 0 {
        0
    } else {
        u64::from(first & ((1u8 << value_bits) - 1))
    };
    for i in 0..extra {
        value = (value << 8) | u64::from(*data.get(p + 1 + i)?);
    }
    Some((value, p + 1 + extra))
}

/// The `value_type` bit that turns a value into a length-prefixed list.
///
/// The one bit of `value_type` that is established to change the wire format,
/// and it is load-bearing: it separates a date from an array of dates, an
/// integer from an array of integers, and a single category id from a
/// reference into the list table. It is set on exactly the properties whose
/// names are plural — `kMDItemContentTypeTree`, `kMDItemLanguages`,
/// `kMDItemWhereFroms`, `kMDItemUsedDates`, `kMDStoreAccumulatedSizes`.
const VALUE_MULTI: u8 = 0x02;

/// The `value_type` bit that, on property type 15, sends a reference to the
/// localised-label table instead of the category table.
const VALUE_LOCALISED: u8 = 0x80;

/// The nominal element width a `property_type` declares, which is what a
/// list's length prefix is counted in.
///
/// **The prefix is `element count × this width`, not the byte length on the
/// wire.** For the raw-`f64` types the two coincide; for the integer types
/// they do not, because the elements are variable-size numbers. Reading the
/// prefix as a byte count decodes `kMDStoreAccumulatedCounts`'s nineteen
/// buckets as far fewer.
fn nominal_width(property_type: u8) -> Option<usize> {
    match property_type {
        0 | 2 | 11 | 14 => Some(1),
        6 | 9 | 15 => Some(4),
        7 | 8 | 10 | 12 => Some(8),
        _ => None,
    }
}

/// One attribute value, as the format carries it.
#[derive(Debug, Clone, PartialEq)]
enum AttrValue {
    /// A variable-size number, or a list of them.
    Ints(Vec<u64>),
    /// A number written in the widest variable-size form, whose value
    /// interpretation is not established. See [`WIDEST_FORM_NOTE`].
    WidestForm(u64),
    /// A 32- or 64-bit IEEE-754 value, written raw and little-endian.
    Float(f64),
    /// One or more `CFAbsoluteTime` seconds — the epoch is 2001-01-01 UTC.
    Dates(Vec<f64>),
    /// A length-prefixed run of bytes read as text. The length includes the
    /// NUL terminator, and a localised value carries the `0x16 0x02`
    /// separator inside it.
    Strings(Vec<String>),
    /// The same label once per language. Which variant is which language is
    /// not established from an item record: the separator `0x16 0x02` stands
    /// before a language tag in the **category** table, which is inference
    /// from that table rather than proof from here.
    Localised(Vec<String>),
    /// A length-prefixed run of bytes that is not text — a UUID, an XML
    /// property list, an opaque structure.
    Blob(Vec<u8>),
    /// A category-table id.
    Category(u32),
    /// An id in the table of category-id lists.
    ListRef(u32),
    /// An id in the table of localised label sets.
    LabelRef(u32),
}

/// One decoded attribute of one item.
#[derive(Debug, Clone)]
struct Attribute {
    property_id: u32,
    value: AttrValue,
}

/// Why an attribute walk stopped before the end of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttrStop {
    /// It reached the end of the record, which is the only correct ending.
    Tiled,
    /// A property id the store's own table does not carry.
    UnknownProperty(u32),
    /// A property type this reader has not established a value encoding for.
    /// Nothing is read past it, because the next byte's meaning depends on
    /// this value's length.
    UnestablishedType(u8),
    /// A value ran past the end of the record.
    Truncated,
}

/// Decode one item record's attribute stream.
///
/// The stream is pairs of a **delta** and a value, with the delta added to a
/// running property id that starts at zero — so the ids come out in ascending
/// order. Absolute ids instead of a running sum tile 1 record in 14,936.
///
/// There is no terminator and no padding: the stream ends when the record
/// does, which means a single value read at the wrong width desynchronises
/// everything after it. That is why a type this reader cannot decode stops the
/// walk rather than being skipped — its length is not stated anywhere.
fn read_attributes(
    body: &[u8],
    properties: &BTreeMap<u32, Property>,
) -> (Vec<Attribute>, AttrStop) {
    let mut out = Vec::new();
    let mut property_id = 0u64;
    let mut p = 0usize;
    while p < body.len() {
        let Some((delta, q)) = var_num(body, p) else {
            return (out, AttrStop::Truncated);
        };
        property_id = property_id.saturating_add(delta);
        let id = match u32::try_from(property_id) {
            Ok(id) => id,
            Err(_) => return (out, AttrStop::Truncated),
        };
        let Some(property) = properties.get(&id) else {
            return (out, AttrStop::UnknownProperty(id));
        };
        match read_attr_value(body, q, property) {
            Some((value, next)) => {
                out.push(Attribute {
                    property_id: id,
                    value,
                });
                p = next;
            }
            None => {
                return (
                    out,
                    if value_encoding_established(property) {
                        AttrStop::Truncated
                    } else {
                        AttrStop::UnestablishedType(property.property_type)
                    },
                )
            }
        }
    }
    (out, AttrStop::Tiled)
}

/// Whether this reader has an established encoding for a property's values.
///
/// Separate from reading one so that a stream which stops can say **which** of
/// the two things happened: a value that ran past the end of the record, or a
/// declared type nobody has established an encoding for. They call for
/// different work and reporting one as the other sends the next reader to the
/// wrong place.
fn value_encoding_established(property: &Property) -> bool {
    let multi = property.value_type & VALUE_MULTI != 0;
    match property.property_type {
        0 | 2 | 6 | 7 | 8 | 11 | 12 | 14 | 15 => true,
        // A list of raw floats does not occur in either store, so its length
        // prefix is not established. Property types 1, 3, 4 and 5 occur only
        // on Apple's unused placeholder rows and are never referenced.
        9 | 10 => !multi,
        _ => false,
    }
}

/// Read one value, whose shape comes from the property's own declared type.
fn read_attr_value(body: &[u8], p: usize, property: &Property) -> Option<(AttrValue, usize)> {
    let multi = property.value_type & VALUE_MULTI != 0;
    let width = nominal_width(property.property_type)?;
    match property.property_type {
        // Integers, singly or as a list of variable-size numbers whose count
        // is the prefix divided by the nominal width.
        0 | 2 | 6 | 7 | 8 => {
            if multi {
                let (declared, mut q) = var_num(body, p)?;
                let count = (declared as usize).checked_div(width)?;
                let mut values = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    let (value, next) = var_num(body, q)?;
                    values.push(value);
                    q = next;
                }
                Some((AttrValue::Ints(values), q))
            } else {
                let (value, q) = var_num(body, p)?;
                // The widest form's value is not established, so it does not
                // leave this reader as a plain number.
                if q - p == WIDEST_VAR_NUM_BYTES {
                    Some((AttrValue::WidestForm(value), q))
                } else {
                    Some((AttrValue::Ints(vec![value]), q))
                }
            }
        }
        // Raw IEEE-754, little-endian. A list of them is not established:
        // neither type occurs with the multi bit set in either store.
        9 if !multi => {
            let s = body.get(p..p + 4)?;
            let bits = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
            Some((AttrValue::Float(f64::from(f32::from_bits(bits))), p + 4))
        }
        10 if !multi => {
            let value = read_f64(body, p)?;
            Some((AttrValue::Float(value), p + 8))
        }
        // Text. The multi form is the same on the wire; what a run holding
        // more than one NUL-terminated string means is NOT established —
        // every such value in the corpus holds exactly one — so the run is
        // split on NUL and the count is what it is.
        11 => {
            let (declared, q) = var_num(body, p)?;
            let end = q.checked_add(declared as usize)?;
            let run = body.get(q..end)?;
            let parts = split_strings(run);
            // A localised value holds the same label once per language —
            // `kMDItemProfileName` carries 31 of them — so it is reported as
            // one label with the number of spellings behind it. A list of 31
            // strings in a case reads as 31 observations.
            if property.value_type & VALUE_LOCALISED != 0 {
                Some((AttrValue::Localised(parts), end))
            } else {
                Some((AttrValue::Strings(parts), end))
            }
        }
        // Dates. Singly, eight raw bytes; as a list, a byte count and that
        // many bytes of raw `f64`.
        12 => {
            if multi {
                let (declared, q) = var_num(body, p)?;
                let end = q.checked_add(declared as usize)?;
                let run = body.get(q..end)?;
                let values = run
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|c| f64::from_le_bytes(*c))
                    .collect();
                Some((AttrValue::Dates(values), end))
            } else {
                let value = read_f64(body, p)?;
                Some((AttrValue::Dates(vec![value]), p + 8))
            }
        }
        14 => {
            let (declared, q) = var_num(body, p)?;
            let end = q.checked_add(declared as usize)?;
            let run = body.get(q..end)?;
            Some((AttrValue::Blob(run.to_vec()), end))
        }
        // An interned reference. Which table it is into depends on both bits.
        15 => {
            let (value, q) = var_num(body, p)?;
            let id = u32::try_from(value).ok()?;
            let value = if property.value_type & VALUE_LOCALISED != 0 {
                AttrValue::LabelRef(id)
            } else if multi {
                AttrValue::ListRef(id)
            } else {
                AttrValue::Category(id)
            };
            Some((value, q))
        }
        _ => None,
    }
}

fn read_f64(body: &[u8], p: usize) -> Option<f64> {
    let s = body.get(p..p + 8)?;
    Some(f64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Split a length-prefixed text run into its strings.
///
/// The run is NUL-terminated and a localised value carries the two bytes
/// `0x16 0x02` before the terminator. Both are dropped here: the separator's
/// own meaning is **not** established — the category table shows it standing
/// before a language tag, which is inference from that table and not proof
/// from an item record — so what is kept is the text before it.
fn split_strings(run: &[u8]) -> Vec<String> {
    run.split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let text = match part.windows(2).position(|w| w == LOCALE_SEPARATOR) {
                Some(at) => &part[..at],
                None => part,
            };
            String::from_utf8_lossy(text).into_owned()
        })
        .collect()
}

/// One per-item metadata record, as far as this reader has established the
/// record's shape.
#[derive(Debug, Clone)]
struct Item {
    /// The item id, which is what a parent reference and the index tables
    /// point at. Meaningful only within this store.
    id: u64,
    /// The record's flag byte. `0`, `1`, `0x20`, `0x42` and `0x62` occur in
    /// the corpus; what they select is not established, so the byte is
    /// reported and not interpreted.
    flags: u8,
    /// The varint between the flags and the parent reference. **Not
    /// established.** It runs 0 to 190,374 across the corpus, which suits a
    /// file-system node id, but nothing in these bytes demonstrates that — so
    /// it is carried out as the number it is under a name that claims nothing.
    unnamed_field: u64,
    /// The id of the item this one sits under.
    parent_id: u64,
    /// When the index last wrote this item, in microseconds since the Unix
    /// epoch. Established by measurement: all 14,934 records in the corpus's
    /// larger store land between 2021-02-11 and 2021-04-06, which brackets the
    /// image's acquisition, and none falls outside it.
    indexed_us: u64,
    /// How many bytes of this record are the attribute stream.
    attribute_bytes: usize,
    /// The attributes decoded out of that stream.
    attributes: Vec<Attribute>,
    /// Why the attribute walk stopped. Anything but [`AttrStop::Tiled`] means
    /// this record is reported with what was read before the stop and the
    /// reason, never with a resynchronised remainder.
    stop: AttrStop,
}

impl Item {
    /// The indexing time as an RFC 3339 instant, or `None` when the number
    /// does not land in a window a Spotlight index could have written in.
    fn indexed_at(&self) -> Option<String> {
        let secs = i64::try_from(self.indexed_us / 1_000_000).ok()?;
        // Spotlight shipped in 2005 (Tiger). A number outside 2004-01-01 to
        // 2100-01-01 is not a date this reader will render as one, because a
        // field it has read wrongly must not leave the building looking like
        // an observation.
        if !(1_072_915_200..=4_102_444_800).contains(&secs) {
            return None;
        }
        // The field is microseconds, so this is exact rather than rounded.
        let nanos = u32::try_from((self.indexed_us % 1_000_000) * 1000).ok()?;
        Some(chrono::DateTime::from_timestamp(secs, nanos)?.to_rfc3339())
    }
}

/// What walking one inflated item block found, including what it did not.
#[derive(Debug, Default)]
struct ItemWalk {
    items: Vec<Item>,
    /// Bytes of the inflated block the walk did not consume. **Zero on every
    /// block in the corpus**, which is the test the record layout has to pass:
    /// the records tile the block exactly or the layout is wrong.
    leftover: usize,
    /// A record declared more bytes than the block held.
    short_record: bool,
    /// The item cap stopped the walk.
    capped: bool,
}

/// Walk the item records in one inflated item block.
///
/// Each record is a little-endian `u32` byte count and then that many bytes.
/// The count is trusted only as far as the block goes: a record claiming more
/// than is there ends the walk and is reported, rather than being read against
/// whatever follows.
fn read_items(inflated: &[u8], properties: &BTreeMap<u32, Property>, budget: usize) -> ItemWalk {
    let mut walk = ItemWalk::default();
    let mut p = 0usize;
    while p + 4 <= inflated.len() {
        if walk.items.len() >= budget {
            walk.capped = true;
            break;
        }
        let Some(size) = le_u32(inflated, p) else {
            break;
        };
        if size == 0 {
            // The block's trailing slack, which is zeroed.
            break;
        }
        let start = p + 4;
        let Some(end) = start.checked_add(size as usize) else {
            walk.short_record = true;
            break;
        };
        let Some(body) = inflated.get(start..end) else {
            walk.short_record = true;
            break;
        };
        match read_item(body, properties) {
            Some(item) => walk.items.push(item),
            // A record whose fixed fields do not fit is not read against the
            // next record's bytes; the walk stops and says so.
            None => {
                walk.short_record = true;
                break;
            }
        }
        p = end;
    }
    walk.leftover = inflated.len().saturating_sub(p);
    walk
}

/// The fixed fields at the head of one item record, and then its attributes.
fn read_item(body: &[u8], properties: &BTreeMap<u32, Property>) -> Option<Item> {
    let (id, q) = var_num(body, 0)?;
    let flags = *body.get(q)?;
    let (unnamed_field, q) = var_num(body, q + 1)?;
    let (parent_id, q) = var_num(body, q)?;
    let (indexed_us, q) = var_num(body, q)?;
    let stream = body.get(q..).unwrap_or_default();
    let (attributes, stop) = read_attributes(stream, properties);
    Some(Item {
        id,
        flags,
        unnamed_field,
        parent_id,
        indexed_us,
        attribute_bytes: stream.len(),
        attributes,
        stop,
    })
}

/// One block of the store.
#[derive(Debug, Clone)]
struct Block {
    /// Page index, which is how the header and the chains name a block.
    page: u32,
    /// Absolute byte offset.
    at: usize,
    /// Size the block declares.
    size: u32,
    /// Bytes of it in use.
    used: u32,
    /// Type id.
    id: u32,
    /// Page of the next block in this chain, as the block states it. Only
    /// meaningful on the chained kinds — the item blocks carry payload here.
    next: u32,
    /// Bits per byte of the payload, and how many distinct byte values it
    /// holds. Both are how "compressed or encrypted" is established.
    entropy: f64,
    distinct_bytes: usize,
}

impl Block {
    fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        self.slice_from(data, BLOCK_HEADER_BYTES)
    }

    /// The block's bytes from `offset` to whichever comes first of the bytes
    /// it declares in use and the end of what was staged.
    fn slice_from<'a>(&self, data: &'a [u8], offset: usize) -> &'a [u8] {
        let used = (self.used.min(self.size) as usize).max(offset);
        let end = (self.at + used).min(data.len());
        data.get(self.at + offset..end).unwrap_or_default()
    }

    /// The compressed stream an item block carries, decompressed.
    ///
    /// Returns `None` when the block is not an item kind or the stream will
    /// not inflate, and the caller reports that rather than assuming it.
    fn inflate(&self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.is_item_kind() {
            return None;
        }
        let stream = self.slice_from(data, ITEM_STREAM_AT);
        if stream.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        let declared = self.logical_size(data);
        // Bounded by what the block itself declares, with the fixed slack a
        // corrupt length cannot widen: a decompressor asked for an unbounded
        // output is a way to spend a case's memory on a bad four bytes.
        let limit = u64::from(declared.min(MAX_ITEM_BLOCK_BYTES)).max(1) + 64;
        use std::io::Read as _;
        let mut reader = flate2::read::ZlibDecoder::new(stream).take(limit);
        reader.read_to_end(&mut out).ok()?;
        Some(out)
    }

    /// The uncompressed length the block declares, which counts the
    /// [`ITEM_STREAM_AT`] bytes ahead of the compressed stream as well as the
    /// stream's own output.
    fn logical_size(&self, data: &[u8]) -> u32 {
        le_u32(data, self.at + 16).unwrap_or(0)
    }

    /// What this block's payload entropy establishes, if anything.
    fn verdict(&self, data: &[u8]) -> EntropyVerdict {
        if self.payload(data).len() < MIN_ENTROPY_SAMPLE_BYTES {
            EntropyVerdict::TooShort
        } else if self.entropy >= HIGH_ENTROPY_BITS {
            EntropyVerdict::HighEntropy
        } else {
            EntropyVerdict::Structured
        }
    }

    /// True when this block's id is one of the per-item kinds. A statement
    /// about the block's declared type, separate from what its payload
    /// measures.
    fn is_item_kind(&self) -> bool {
        matches!(self.id, BLOCK_ITEMS | BLOCK_ITEMS_ALT)
    }
}

/// The store's own list of where its item blocks are.
///
/// **This is a second, independent statement of the item-block population**,
/// which is why it is read at all: the blocks themselves are found by scanning
/// every page for the `2pbd` tag, and the map is what turns "the scan found
/// 74" into "the scan found 74 and the store says 74". On the corpus the two
/// agree exactly, in both stores. Where they disagree the disagreement is
/// reported rather than resolved — a page the map names that the scan cannot
/// read is a gap in the item population, and the reverse is a block the store
/// no longer lists.
///
/// The map's entries carry two further fields whose meaning is **not**
/// established, and they are not read.
#[derive(Debug, Default)]
struct ItemMap {
    /// The count the map's own header states.
    declared: usize,
    /// The pages its entries name.
    pages: BTreeSet<u32>,
}

fn read_item_map(data: &[u8], page_size: usize) -> Option<ItemMap> {
    let at = MAP_PAGE.checked_mul(page_size)?;
    if data.get(at..at + 4)? != &MAP_MAGIC[..] {
        return None;
    }
    let declared = le_u32(data, at + 8)? as usize;
    let mut pages = BTreeSet::new();
    for i in 0..declared.min(MAX_BLOCKS) {
        let entry = at + MAP_ENTRIES_AT + i * MAP_ENTRY_BYTES;
        let Some(page) = le_u32(data, entry + MAP_ENTRY_PAGE_AT) else {
            break;
        };
        pages.insert(page);
    }
    Some(ItemMap { declared, pages })
}

/// Everything the item blocks yielded, and everything they did not.
#[derive(Debug, Default)]
struct ItemCensus {
    items: Vec<Item>,
    /// Item blocks whose stream inflated.
    inflated: usize,
    /// Item blocks whose stream did not, which is reported and not assumed
    /// away: a block that will not inflate is a gap in the item population,
    /// and the entropy of its payload says whether it is another compression
    /// or something else.
    not_inflated: Vec<u32>,
    /// Bytes of inflated block that the record walk did not consume. The
    /// layout's own test: **zero on every block in the corpus.**
    leftover_bytes: usize,
    /// Blocks where a record declared more bytes than the block held.
    short_records: usize,
    capped: bool,
}

/// Why an attribute stream did not tile its record, counted over a store.
#[derive(Debug, Default)]
struct AttrShortfalls {
    /// Records whose attributes were read to the last byte. Anything else is
    /// a record this reader did not finish.
    tiled: usize,
    unknown_property: BTreeSet<u32>,
    unestablished_type: BTreeSet<u8>,
    truncated: usize,
}

/// Inflate every item block and walk the records in it.
fn read_item_blocks(
    data: &[u8],
    blocks: &[Block],
    properties: &BTreeMap<u32, Property>,
) -> ItemCensus {
    let mut census = ItemCensus::default();
    for block in blocks.iter().filter(|b| b.is_item_kind()) {
        let Some(inflated) = block.inflate(data) else {
            census.not_inflated.push(block.page);
            continue;
        };
        census.inflated += 1;
        let budget = MAX_ITEMS.saturating_sub(census.items.len());
        let walk = read_items(&inflated, properties, budget);
        census.leftover_bytes += walk.leftover;
        if walk.short_record {
            census.short_records += 1;
        }
        census.capped |= walk.capped;
        census.items.extend(walk.items);
        if census.items.len() >= MAX_ITEMS {
            census.capped = true;
            break;
        }
    }
    census
}

/// Read every block in the store, by scanning at page granularity.
///
/// Scanned rather than chained on purpose: the chains the header names reach
/// only the structured kinds — 12 of the 86 blocks in the corpus's larger
/// store — and the item blocks are reached through a map this reader does not
/// decode. A scan finds all of them, and the header's chains are then used to
/// say which were reachable and which were not.
fn read_blocks(data: &[u8], page_size: usize) -> Vec<Block> {
    let mut out = Vec::new();
    if page_size == 0 {
        return out;
    }
    let mut at = 0usize;
    while at + BLOCK_HEADER_BYTES <= data.len() {
        if out.len() >= MAX_BLOCKS {
            break;
        }
        if data.get(at..at + 4) == Some(&BLOCK_MAGIC[..]) {
            let size = le_u32(data, at + 4).unwrap_or(0);
            let used = le_u32(data, at + 8).unwrap_or(0);
            let id = le_u32(data, at + 12).unwrap_or(0);
            let next = le_u32(data, at + 20).unwrap_or(0);
            let mut block = Block {
                page: (at / page_size) as u32,
                at,
                size,
                used,
                id,
                next,
                entropy: 0.0,
                distinct_bytes: 0,
            };
            let payload = block.payload(data);
            block.entropy = entropy_bits(payload);
            block.distinct_bytes = payload.iter().collect::<BTreeSet<_>>().len();
            out.push(block);
        }
        at += page_size;
    }
    out
}

/// The pages the header's five chains reach.
///
/// Cycle-guarded: a `next` pointing back into the chain ends the walk rather
/// than looping, and a `next` past the file ends it too.
fn reachable_pages(data: &[u8], blocks: &[Block]) -> BTreeSet<u32> {
    let by_page: BTreeMap<u32, &Block> = blocks.iter().map(|b| (b.page, b)).collect();
    let mut seen = BTreeSet::new();
    for i in 0..CHAIN_HEADS {
        let Some(head) = le_u32(data, CHAIN_HEADS_AT + 4 * i) else {
            break;
        };
        let mut page = head;
        while page != 0 && !seen.contains(&page) {
            let Some(block) = by_page.get(&page) else {
                break;
            };
            seen.insert(page);
            // The item blocks carry payload where the chained kinds carry a
            // pointer, so a chain is only followed through a kind that has one.
            if matches!(block.id, BLOCK_ITEMS | BLOCK_ITEMS_ALT) {
                break;
            }
            page = block.next;
        }
    }
    seen
}

/// Pages one of the header's chains reaches, in chain order.
///
/// Which chain a block sits on is not decoration: the two `0x81` tables are
/// **different namespaces** and are told apart only by their chain. The fourth
/// chain's table maps an id to a list of category ids; the fifth's maps an id
/// to one category id per language. On the corpus's larger store, id 61 in the
/// first is `[public.item, dyn.ah62d4rv4ge8042pu, public.data]` and id 61 in
/// the second is `Folder` in forty languages. Reading one as the other puts a
/// content-type list where a display label belongs.
fn chain_pages(data: &[u8], blocks: &[Block], chain: usize) -> Vec<u32> {
    let by_page: BTreeMap<u32, &Block> = blocks.iter().map(|b| (b.page, b)).collect();
    let mut out = Vec::new();
    let Some(head) = le_u32(data, CHAIN_HEADS_AT + 4 * chain) else {
        return out;
    };
    let mut page = head;
    while page != 0 && !out.contains(&page) {
        let Some(block) = by_page.get(&page) else {
            break;
        };
        if block.is_item_kind() {
            break;
        }
        out.push(page);
        page = block.next;
    }
    out
}

/// The chain that heads the table of category-id lists.
const CHAIN_LIST_TABLE: usize = 3;
/// The chain that heads the table of localised label sets.
const CHAIN_LOC_TABLE: usize = 4;

/// The `0x81` tables, keyed by entry id.
///
/// Both tile their blocks exactly on the corpus — 264 list entries in 4,980
/// bytes and 171 label sets in 27,052 — which is what establishes the two
/// entry shapes. A list entry's body is a whole number of four-byte category
/// ids; a label entry's body carries one leading byte this reader does not
/// interpret and then a whole number of them. Every one of the 264 list bodies
/// is `0 mod 4` long and every one of the 171 label bodies is `1 mod 4`, with
/// no exception in either store.
#[derive(Debug, Default)]
struct IdTables {
    lists: BTreeMap<u32, Vec<u32>>,
    labels: BTreeMap<u32, Vec<u32>>,
    /// Entries whose declared length ran past the block, which end the walk of
    /// that block and are reported rather than being read against what
    /// follows.
    truncated: usize,
}

/// Read one `0x81` table.
///
/// An entry's body is a whole number of four-byte category ids, possibly
/// behind some leading bytes this reader does not interpret — and **the entry
/// states how many** by its own length: `len % 4` of them. On the corpus that
/// is 0 for every one of the 264 list entries and 1 for every one of the 171
/// label entries, so a fixed "one leading byte on the label table" reading
/// fits equally well; the remainder rule is used because it is the entry's own
/// arithmetic rather than a property of which chain it was found on.
fn read_id_table(data: &[u8], blocks: &[Block], chain: usize) -> (BTreeMap<u32, Vec<u32>>, usize) {
    let by_page: BTreeMap<u32, &Block> = blocks.iter().map(|b| (b.page, b)).collect();
    let mut out = BTreeMap::new();
    let mut truncated = 0usize;
    for page in chain_pages(data, blocks, chain) {
        let Some(block) = by_page.get(&page) else {
            continue;
        };
        if block.id != BLOCK_INDEX {
            continue;
        }
        let payload = block.payload(data);
        let mut p = 0usize;
        while p + 4 < payload.len() {
            let Some(id) = le_u32(payload, p) else { break };
            if id == 0 {
                break;
            }
            let Some((len, q)) = var_num(payload, p + 4) else {
                truncated += 1;
                break;
            };
            let len = len as usize;
            let Some(body) = payload.get(q..q + len) else {
                truncated += 1;
                break;
            };
            let ids = body
                .get(len % 4..)
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect();
            out.insert(id, ids);
            p = q + len;
        }
    }
    (out, truncated)
}

fn read_id_tables(data: &[u8], blocks: &[Block]) -> IdTables {
    let (lists, a) = read_id_table(data, blocks, CHAIN_LIST_TABLE);
    let (labels, b) = read_id_table(data, blocks, CHAIN_LOC_TABLE);
    IdTables {
        lists,
        labels,
        truncated: a + b,
    }
}

/// One entry of the property table.
#[derive(Debug, Clone)]
struct Property {
    id: u32,
    name: String,
    property_type: u8,
    value_type: u8,
}

/// Apple's own padding in the low property ids. Counted, never emitted as an
/// attribute this store held.
const PROPERTY_PLACEHOLDER: &str = "_kMDXXXX___DUMMY";

impl Property {
    /// True for one of Apple's unused table slots, which carry a fixed name
    /// and are never referenced by an item.
    fn is_placeholder(&self) -> bool {
        self.name == PROPERTY_PLACEHOLDER
    }
}

/// Read the property table: `u32 id`, `u8 property type`, `u8 value type`,
/// then a NUL-terminated name.
fn read_properties(data: &[u8], blocks: &[Block]) -> (Vec<Property>, usize, bool) {
    let mut out = Vec::new();
    let mut placeholders = 0usize;
    let mut capped = false;
    for block in blocks.iter().filter(|b| b.id == BLOCK_PROPERTIES) {
        let payload = block.payload(data);
        let mut p = 0usize;
        while p + 6 < payload.len() {
            if out.len() + placeholders >= MAX_PROPERTIES {
                capped = true;
                break;
            }
            let Some(id) = le_u32(payload, p) else { break };
            if id == 0 {
                break;
            }
            let property_type = payload[p + 4];
            let value_type = payload[p + 5];
            let start = p + 6;
            let Some(len) = payload[start..]
                .iter()
                .take(MAX_NAME_BYTES)
                .position(|&b| b == 0)
            else {
                break;
            };
            let name = String::from_utf8_lossy(&payload[start..start + len]).into_owned();
            if name == PROPERTY_PLACEHOLDER {
                placeholders += 1;
            }
            // Placeholders are kept in the table and filtered at emission.
            // An attribute stream that referenced one has to decode or say
            // why not; dropping them here would report a reference to
            // Apple's own unused slot as a property this store has not got.
            out.push(Property {
                id,
                name,
                property_type,
                value_type,
            });
            p = start + len + 1;
        }
    }
    (out, placeholders, capped)
}

/// One entry of the category table, in whichever of its two forms it takes.
#[derive(Debug, Clone)]
enum Category {
    /// No locale separator: a content type or identifier.
    ContentType { id: u32, value: String },
    /// A localised display name and its locale. The locale is empty on the
    /// base name.
    ///
    /// The entry's id is deliberately not kept: these are not emitted as
    /// records, so an id nothing cites is a field nobody reads.
    DisplayName { name: String, locale: String },
}

/// Read the category table: `u32 id` then a NUL-terminated string, split on
/// the `0x16 0x02` separator.
fn read_categories(data: &[u8], blocks: &[Block]) -> (Vec<Category>, BTreeMap<u32, String>, bool) {
    let mut out = Vec::new();
    // Every entry by id, whichever of the two forms it takes, because an item
    // record's references reach both: a content-type reference lands on the
    // first kind and a localised-label reference lands, through the label
    // table, on the second.
    let mut by_id: BTreeMap<u32, String> = BTreeMap::new();
    let mut capped = false;
    for block in blocks.iter().filter(|b| b.id == BLOCK_CATEGORIES) {
        let payload = block.payload(data);
        let mut p = 0usize;
        while p + 4 < payload.len() {
            if out.len() >= MAX_CATEGORIES {
                capped = true;
                break;
            }
            let Some(id) = le_u32(payload, p) else { break };
            if id == 0 {
                break;
            }
            let start = p + 4;
            let Some(len) = payload[start..]
                .iter()
                .take(MAX_NAME_BYTES)
                .position(|&b| b == 0)
            else {
                break;
            };
            let raw = &payload[start..start + len];
            let text = match raw.windows(2).position(|w| w == &LOCALE_SEPARATOR[..]) {
                Some(cut) => &raw[..cut],
                None => raw,
            };
            by_id.insert(id, String::from_utf8_lossy(text).into_owned());
            out.push(
                match raw.windows(2).position(|w| w == &LOCALE_SEPARATOR[..]) {
                    Some(cut) => Category::DisplayName {
                        name: String::from_utf8_lossy(&raw[..cut]).into_owned(),
                        locale: String::from_utf8_lossy(&raw[cut + 2..]).into_owned(),
                    },
                    None => Category::ContentType {
                        id,
                        value: String::from_utf8_lossy(raw).into_owned(),
                    },
                },
            );
            p = start + len + 1;
        }
    }
    (out, by_id, capped)
}

/// Everything an item's values are resolved against: the store's own tables.
///
/// All three are per-store. An id resolved against another store's tables
/// yields a plausible wrong answer, which is why this is passed by reference
/// from the store being read and never cached.
struct Vocabulary<'a> {
    properties: &'a BTreeMap<u32, Property>,
    categories: &'a BTreeMap<u32, String>,
    tables: &'a IdTables,
}

/// Seconds between the Unix epoch and `CFAbsoluteTime`'s, which is
/// 2001-01-01T00:00:00Z.
const CF_EPOCH_OFFSET: f64 = 978_307_200.0;

/// Render a `CFAbsoluteTime` as an instant, or `None` when the number is not
/// one a Spotlight index could have written.
fn cf_absolute_time(seconds: f64) -> Option<String> {
    if !seconds.is_finite() {
        return None;
    }
    let unix = seconds + CF_EPOCH_OFFSET;
    // 1970 to 2100. A value outside that is a field this reader has read
    // wrongly, and it leaves the building as the number it is rather than as
    // a date somebody might put in a report.
    if !(0.0..=4_102_444_800.0).contains(&unix) {
        return None;
    }
    let secs = unix.trunc() as i64;
    // Microseconds, not nanoseconds. An `f64` holding six hundred million
    // seconds resolves to about a quarter of a microsecond, so the nanosecond
    // digits of one are noise — and a timestamp printed to nine places claims
    // a precision the format cannot carry.
    let micros = ((unix - unix.trunc()) * 1e6).round().clamp(0.0, 999_999.0) as u32;
    Some(chrono::DateTime::from_timestamp(secs, micros * 1000)?.to_rfc3339())
}

impl Vocabulary<'_> {
    /// One attribute value as JSON, with every interned reference resolved
    /// against this store's tables.
    ///
    /// A reference that does not resolve is reported as the unresolved id it
    /// is — the corpus holds exactly one, a two-attribute stub whose content
    /// type is `0xfeffffff` — rather than dropped or rendered as empty.
    fn value_json(&self, value: &AttrValue) -> Value {
        match value {
            AttrValue::Ints(v) if v.len() == 1 => json!(v[0]),
            AttrValue::Ints(v) => json!(v),
            AttrValue::WidestForm(n) => json!({
                "value": n,
                "value_established": false,
                "note": WIDEST_FORM_NOTE,
            }),
            AttrValue::Float(f) => json!(f),
            AttrValue::Dates(v) => {
                let rendered: Vec<Value> = v
                    .iter()
                    .map(|s| match cf_absolute_time(*s) {
                        Some(when) => json!(when),
                        None => json!({ "cf_absolute_time": s, "usable": false }),
                    })
                    .collect();
                if rendered.len() == 1 {
                    rendered.into_iter().next().unwrap_or(Value::Null)
                } else {
                    json!(rendered)
                }
            }
            AttrValue::Strings(v) if v.len() == 1 => json!(v[0]),
            AttrValue::Strings(v) => json!(v),
            AttrValue::Localised(v) if v.len() == 1 => json!(v[0]),
            AttrValue::Localised(v) => match v.first() {
                Some(first) => json!({ "label": first, "localisations": v.len() }),
                None => Value::Null,
            },
            // Not rendered as text: a property list or a UUID shown as
            // lossy UTF-8 is a string nobody can check. The length is the
            // claim, and the bytes are available to a reader who wants them.
            AttrValue::Blob(b) => json!({ "bytes": b.len(), "hex": hex_prefix(b) }),
            AttrValue::Category(id) => match self.categories.get(id) {
                Some(text) => json!(text),
                None => json!({ "category_id": id, "resolved": false }),
            },
            AttrValue::ListRef(id) => match self.tables.lists.get(id) {
                Some(ids) => json!(self.category_names(ids)),
                None => json!({ "list_id": id, "resolved": false }),
            },
            AttrValue::LabelRef(id) => match self.tables.labels.get(id) {
                // One label per language, and which language is which is not
                // established, so the first is taken and the count is given.
                Some(ids) => match ids.first().and_then(|c| self.categories.get(c)) {
                    Some(text) if ids.len() > 1 => {
                        json!({ "label": text, "localisations": ids.len() })
                    }
                    Some(text) => json!(text),
                    None => json!({ "label_id": id, "resolved": false }),
                },
                None => json!({ "label_id": id, "resolved": false }),
            },
        }
    }

    fn category_names(&self, ids: &[u32]) -> Vec<Value> {
        ids.iter()
            .map(|id| match self.categories.get(id) {
                Some(text) => json!(text),
                None => json!({ "category_id": id, "resolved": false }),
            })
            .collect()
    }

    /// The property name an id stands for in this store.
    fn name_of(&self, id: u32) -> Option<&str> {
        self.properties.get(&id).map(|p| p.name.as_str())
    }
}

/// The first bytes of a blob, in hex, so an examiner can recognise it.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(32)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// The property names whose values are lifted onto an item record under a
/// stable key, so a screen and a search do not depend on Apple's spelling.
///
/// Everything else the record carries is emitted too, under its own
/// `kMDItem…` name — this list decides what gets a second, stable home, not
/// what is kept.
const LIFTED: &[(&str, &str)] = &[
    ("_kMDItemFileName", "file_name"),
    ("kMDItemDisplayName", "display_name"),
    ("kMDItemContentType", "content_type"),
    ("kMDItemContentTypeTree", "content_type_tree"),
    ("kMDItemKind", "kind"),
    ("kMDItemLogicalSize", "logical_size"),
    ("kMDItemPhysicalSize", "physical_size"),
    ("_kMDItemOwnerUserID", "uid"),
    ("_kMDItemOwnerGroupID", "gid"),
    ("kMDItemWhereFroms", "where_from"),
    ("kMDItemContentCreationDate", "created"),
    ("kMDItemContentModificationDate", "modified"),
    ("kMDItemDateAdded", "added"),
    ("kMDItemLastUsedDate", "last_used"),
    ("kMDItemUseCount", "use_count"),
    ("kMDItemVersion", "version"),
    ("kMDItemCFBundleIdentifier", "bundle_id"),
];

/// How far up a parent chain the path reconstruction will walk.
const MAX_PATH_DEPTH: usize = 128;

/// An item's name and parent, which is all path reconstruction needs.
struct Tree {
    names: BTreeMap<u64, String>,
    parents: BTreeMap<u64, u64>,
}

impl Tree {
    fn build(items: &[Item], vocabulary: &Vocabulary<'_>) -> Self {
        let mut names = BTreeMap::new();
        let mut parents = BTreeMap::new();
        for item in items {
            parents.insert(item.id, item.parent_id);
            for attribute in &item.attributes {
                if vocabulary.name_of(attribute.property_id) == Some("_kMDItemFileName") {
                    if let AttrValue::Strings(v) = &attribute.value {
                        if let Some(first) = v.first() {
                            names.insert(item.id, first.clone());
                        }
                    }
                }
            }
        }
        Tree { names, parents }
    }

    /// The path of `id`, and whether it reaches a root this store holds.
    ///
    /// **Both halves are returned because only one of them is a path.** A
    /// chain that runs into an item this store has not got gives the segments
    /// below that point and nothing above, and rendering that as an absolute
    /// path would state a location the evidence does not support. 967 of the
    /// corpus's 14,934 items are in that position.
    fn path_of(&self, id: u64) -> (String, bool) {
        let mut segments: Vec<&str> = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut current = id;
        let mut complete = false;
        for _ in 0..MAX_PATH_DEPTH {
            if !seen.insert(current) {
                // A cycle is not a path. It stops here and the answer is
                // reported incomplete rather than repeated until the cap.
                break;
            }
            match self.names.get(&current) {
                Some(name) => segments.push(name),
                None => {
                    // The store's own root item carries no name, and reaching
                    // it is what makes a path complete.
                    complete = current == 1 || current == 2;
                    break;
                }
            }
            match self.parents.get(&current) {
                Some(&parent) if parent != current && parent != NO_PARENT => current = parent,
                _ => {
                    complete = true;
                    break;
                }
            }
        }
        segments.reverse();
        let joined = segments.join("/");
        (
            if complete {
                format!("/{joined}")
            } else {
                joined
            },
            complete,
        )
    }
}

// --- artifact emission -------------------------------------------------------

pub struct SpotlightStoreParser;

/// True when a name is a Spotlight store's.
///
/// Used only to decide whether a file that failed to parse deserves a word.
/// Selection is by the `8tsd` magic: many files are called `store.db`.
fn named_as_store(name: &str) -> bool {
    let b = basename_lower(name);
    b == "store.db" || b == ".store.db" || b.ends_with(".store.db")
}

/// Whether the name places this file inside a Spotlight metadata store.
///
/// Used only to decide whether a failure to read has to leave a record. The
/// directory is what makes the file's identity a claim rather than a guess:
/// `store.db` is one of the most-reused names on a disk, and a refusal record
/// for every one of them would be noise, while silence for the one under
/// `.Spotlight-V100/Store-V2` would hide a missing index.
fn in_spotlight_store_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let path = lower.replace('\\', "/");
    path.contains(".spotlight-v100/") || path.contains("/store-v2/")
}

/// The record a file that sits in a Spotlight store and would not read leaves
/// behind, so that a store which could not be parsed never renders as a volume
/// that was never indexed.
fn refusal_artifact(artifact: &Artifact, file_name: &str, staged: &Staged) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("SpotlightStoreStatus"));
    meta.insert("subtype".into(), json!("spotlight_store_not_parsed"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(false));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    // The two failures look identical to a reader and are not the same thing:
    // a short read means the imaging stopped, an absent magic means the file
    // is some other format — a version-1 store, or not a store at all.
    let (reason, detail) = match staged.incomplete_reason() {
        Some(reason) => (
            reason,
            format!(
                "{}; the version-2 store header could not be read from what was staged",
                staged.detail(file_name)
            ),
        ),
        None => (
            IncompleteReason::UnresolvedStructure,
            format!(
                "the whole file was staged ({} bytes) and does not open with the version-2 \
                 store magic 8tsd, so it is either an earlier store format or not a Spotlight \
                 store at all",
                staged.got
            ),
        ),
    };
    meta.insert("failure_reason".into(), json!(reason.as_str()));
    meta.insert("failure_detail".into(), json!(detail.clone()));
    meta.insert(
        "message".into(),
        json!(
            "This file sits in a Spotlight metadata store and was not read, so nothing is \
               reported from it. Absence of a Spotlight record for this volume is NOT evidence \
               that Spotlight never indexed it."
        ),
    );
    let _ = stamp_incomplete(&mut meta, "content", &[(reason, detail.clone())]);
    meta.insert(
        "name".into(),
        json!(format!("Spotlight store not parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!("{file_name} was not parsed: {detail}")),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("spotlight_store_not_parsed")
}

fn provenance(meta: &mut Map<String, Value>, file_name: &str) {
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert("source_format".into(), json!("spotlight_store_v2"));
}

/// The sentence every record from a store carries about the item blocks.
const ITEMS_NOTE: &str =
    "Spotlight indexes metadata for files that have since been DELETED, so an item here is not \
     evidence that the file is on the volume now — and the reverse holds too: absence of a file \
     from this store is NOT evidence that Spotlight never indexed it. A volume's index is split \
     across stores, and this is one of them. Every id in these records — property, category, \
     item, parent — is meaningful only inside this store.";

/// Everything read out of one store, for the record that describes it.
struct StoreFacts<'a> {
    header: &'a Header,
    blocks: &'a [Block],
    /// Pages the header's five chains reach, which is how the record can say
    /// how many blocks the chains do *not* reach.
    reachable: &'a BTreeSet<u32>,
    properties: &'a [Property],
    /// Apple's `_kMDXXXX___DUMMY` padding, counted and not emitted.
    placeholders: usize,
    categories: &'a [Category],
    /// What the per-item blocks yielded.
    census: &'a ItemCensus,
    /// The store's own list of its item blocks, when it has one.
    item_map: Option<&'a ItemMap>,
    /// The two `0x81` tables an item's references resolve against.
    tables: &'a IdTables,
    /// Which reader caps bit, by name.
    capped: &'a [&'a str],
}

fn store_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    facts: &StoreFacts<'_>,
) -> Artifact {
    let StoreFacts {
        header,
        blocks,
        reachable,
        properties,
        placeholders,
        categories,
        census,
        item_map,
        tables,
        capped,
    } = *facts;
    let mut meta = Map::new();
    meta.insert("type".into(), json!("SpotlightStore"));
    meta.insert("subtype".into(), json!("store_v2"));
    provenance(&mut meta, file_name);
    meta.insert("file_name".into(), json!(file_name));
    meta.insert("store_version".into(), json!(2));
    meta.insert("flags".into(), json!(header.flags));
    // 0x24 is the granularity blocks are laid out at, not the header's length:
    // an earlier reading called it `header_size`, which is what a reader would
    // have quoted.
    meta.insert("page_size".into(), json!(header.page_size));
    meta.insert("block_size".into(), json!(header.block_size));
    meta.insert("block0_size".into(), json!(header.block0_size));
    meta.insert("ios_store".into(), json!(header.ios_store));
    meta.insert("chain_heads".into(), json!(header.chain_heads));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));

    // The block inventory: what the store is made of, by kind — which is what
    // each block's own id DECLARES it to be, separate from what its payload
    // measures. Both are reported, because on the corpus they disagree once:
    // a 191-byte item block is too short for an entropy threshold to mean
    // anything.
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut item_blocks = 0usize;
    let mut item_bytes = 0u64;
    let not_inflated: BTreeSet<u32> = census.not_inflated.iter().copied().collect();
    // The entropy machinery now measures exactly one thing: a block this
    // reader does NOT decode. That is the 0x41 block, whose purpose is
    // unestablished, and any item block whose stream will not inflate. It used
    // to be pointed at every item block, on the reading that they were
    // compressed or encrypted by an unidentified scheme; they are zlib, and
    // the measurement's job is now to say what an outlier is rather than to
    // stand in for a decode.
    let mut high_blocks = 0usize;
    let mut high_low = f64::MAX;
    let mut high_high = 0.0f64;
    let mut structured_low = f64::MAX;
    let mut structured_high = 0.0f64;
    let mut structured_blocks = 0usize;
    let mut too_short = 0usize;
    let mut undecoded = 0usize;
    for block in blocks {
        *by_kind.entry(block_kind(block.id)).or_default() += 1;
        if block.is_item_kind() {
            item_blocks += 1;
            item_bytes += u64::from(block.used.min(block.size));
        }
        let decoded = match block.id {
            BLOCK_PROPERTIES | BLOCK_CATEGORIES | BLOCK_INDEX => true,
            BLOCK_ITEMS | BLOCK_ITEMS_ALT => !not_inflated.contains(&block.page),
            _ => false,
        };
        if decoded {
            continue;
        }
        undecoded += 1;
        match block.verdict(&staged.bytes) {
            EntropyVerdict::HighEntropy => {
                high_blocks += 1;
                high_low = high_low.min(block.entropy);
                high_high = high_high.max(block.entropy);
            }
            EntropyVerdict::Structured => {
                structured_blocks += 1;
                structured_low = structured_low.min(block.entropy);
                structured_high = structured_high.max(block.entropy);
            }
            EntropyVerdict::TooShort => too_short += 1,
        }
    }
    meta.insert("blocks".into(), json!(blocks.len()));
    meta.insert("blocks_by_kind".into(), json!(by_kind));
    meta.insert(
        "blocks_reached_by_the_header_chains".into(),
        json!(reachable.len()),
    );
    meta.insert("item_blocks".into(), json!(item_blocks));
    meta.insert("item_block_bytes".into(), json!(item_bytes));
    meta.insert("item_blocks_decompressed".into(), json!(census.inflated));

    // The store's own count of its item blocks, against the scan's.
    if let Some(map) = item_map {
        meta.insert(
            "item_blocks_named_by_the_stores_map".into(),
            json!(map.declared),
        );
        let found: BTreeSet<u32> = blocks
            .iter()
            .filter(|b| b.is_item_kind())
            .map(|b| b.page)
            .collect();
        let missed: Vec<u32> = map.pages.difference(&found).copied().collect();
        let extra: Vec<u32> = found.difference(&map.pages).copied().collect();
        meta.insert(
            "item_blocks_the_map_and_the_scan_agree_on".into(),
            json!(map.pages.intersection(&found).count()),
        );
        if !missed.is_empty() {
            // A page the store lists and the scan cannot read is a gap in the
            // item population, not a difference of opinion.
            meta.insert(
                "item_block_pages_the_map_names_but_the_scan_did_not_find".into(),
                json!(missed),
            );
        }
        if !extra.is_empty() {
            meta.insert(
                "item_block_pages_found_that_the_map_does_not_name".into(),
                json!(extra),
            );
        }
    } else {
        meta.insert("stores_item_map_present".into(), json!(false));
    }
    if tables.truncated > 0 {
        // An entry that runs past its block ends the walk of that block. The
        // count is published because the references that would have landed in
        // those entries now resolve to nothing, and a reader seeing an
        // unresolved reference is owed the reason.
        meta.insert(
            "id_table_entries_that_ran_past_their_block".into(),
            json!(tables.truncated),
        );
    }
    meta.insert("category_id_lists".into(), json!(tables.lists.len()));
    meta.insert("localised_label_sets".into(), json!(tables.labels.len()));

    // --- the per-item records ------------------------------------------------
    let ids: BTreeSet<u64> = census.items.iter().map(|i| i.id).collect();
    let orphans = census
        .items
        .iter()
        .filter(|i| i.parent_id != NO_PARENT && !ids.contains(&i.parent_id))
        .count();
    let rootless = census
        .items
        .iter()
        .filter(|i| i.parent_id == NO_PARENT)
        .count();
    let undated = census
        .items
        .iter()
        .filter(|i| i.indexed_at().is_none())
        .count();
    let attribute_bytes: u64 = census.items.iter().map(|i| i.attribute_bytes as u64).sum();
    meta.insert("items".into(), json!(census.items.len()));
    meta.insert("item_ids_distinct".into(), json!(ids.len()));
    if census.items.len() > ids.len() {
        // Two records for one id is the store holding a superseded version of
        // an item. Reported, because silently keeping one of them would be a
        // choice made on the examiner's behalf.
        meta.insert(
            "items_with_a_repeated_id".into(),
            json!(census.items.len() - ids.len()),
        );
        meta.insert(
            "repeated_id_note".into(),
            json!(
                "Two records for one item id are two versions of it, and the store keeps both. \
                   On the corpus the older of each pair is a stub carrying two attributes while \
                   the newer is the full record, so **deduplicating on item id without \
                   comparing indexed_at picks the wrong one**. Both are emitted, each with its \
                   own index time."
            ),
        );
    }
    if orphans > 0 {
        meta.insert(
            "items_whose_parent_is_not_in_this_store".into(),
            json!(orphans),
        );
        meta.insert(
            "orphan_note".into(),
            json!(
                "These items name a parent item this store does not hold, so their path cannot \
                   be assembled from this file alone. That is a property of the evidence, not a \
                   parse failure: a volume's index is split across stores and the parent may be \
                   in one this case does not have."
            ),
        );
    }
    // The two fields this reader can read and cannot interpret. Published as
    // what was seen rather than dropped: an examiner who knows what a flag
    // byte selects can use them, and the next person to work on this format
    // starts from the corpus's own range instead of guessing at it.
    let flags_seen: BTreeSet<u8> = census.items.iter().map(|i| i.flags).collect();
    if !flags_seen.is_empty() {
        meta.insert(
            "item_flag_bytes_seen".into(),
            json!(flags_seen.iter().copied().collect::<Vec<u8>>()),
        );
    }
    if let (Some(low), Some(high)) = (
        census.items.iter().map(|i| i.unnamed_field).min(),
        census.items.iter().map(|i| i.unnamed_field).max(),
    ) {
        meta.insert(
            "item_unnamed_field_range".into(),
            json!(format!("{low}–{high}")),
        );
        meta.insert(
            "item_unnamed_field_note".into(),
            json!(
                "Every item record carries one variable-size number between its flag byte and \
                   its parent reference whose meaning is NOT established. Its range across this \
                   store is given so that it is on the record as something read and not \
                   interpreted, rather than being quietly dropped."
            ),
        );
    }
    if rootless > 0 {
        // The file's own way of saying "no parent", not a parent this reader
        // failed to find.
        meta.insert("items_with_no_parent_recorded".into(), json!(rootless));
    }
    if undated > 0 {
        meta.insert("items_with_no_usable_index_time".into(), json!(undated));
    }
    if let (Some(first), Some(last)) = (
        census.items.iter().filter_map(|i| i.indexed_at()).min(),
        census.items.iter().filter_map(|i| i.indexed_at()).max(),
    ) {
        meta.insert("items_indexed_first".into(), json!(first));
        meta.insert("items_indexed_last".into(), json!(last));
    }
    // --- the attribute streams, and where they stopped --------------------
    let mut shortfalls = AttrShortfalls::default();
    let mut attributes_decoded = 0usize;
    for item in &census.items {
        attributes_decoded += item.attributes.len();
        match item.stop {
            AttrStop::Tiled => shortfalls.tiled += 1,
            AttrStop::UnknownProperty(id) => {
                shortfalls.unknown_property.insert(id);
            }
            AttrStop::UnestablishedType(t) => {
                shortfalls.unestablished_type.insert(t);
            }
            AttrStop::Truncated => shortfalls.truncated += 1,
        }
    }
    meta.insert("item_attribute_bytes".into(), json!(attribute_bytes));
    meta.insert("item_attributes_read".into(), json!(attributes_decoded));
    meta.insert(
        "items_whose_attributes_tiled".into(),
        json!(shortfalls.tiled),
    );
    // A record whose stream did not reach its last byte is reported with what
    // was read before the stop and the reason — never resynchronised, because
    // a value read at the wrong width desynchronises everything after it and
    // the format states no length this reader could skip to.
    let unfinished = census.items.len().saturating_sub(shortfalls.tiled);
    if unfinished > 0 {
        meta.insert(
            "items_whose_attributes_did_not_tile".into(),
            json!(unfinished),
        );
        if !shortfalls.unknown_property.is_empty() {
            meta.insert(
                "attribute_property_ids_not_in_this_stores_table".into(),
                json!(shortfalls.unknown_property),
            );
        }
        if !shortfalls.unestablished_type.is_empty() {
            meta.insert(
                "attribute_property_types_not_established".into(),
                json!(shortfalls.unestablished_type),
            );
        }
        if shortfalls.truncated > 0 {
            meta.insert(
                "items_whose_attributes_ran_past_the_record".into(),
                json!(shortfalls.truncated),
            );
        }
    }

    // The test the record layout has to pass, reported so a reader can check
    // it rather than take it on trust.
    meta.insert(
        "item_record_bytes_not_accounted_for".into(),
        json!(census.leftover_bytes),
    );
    if census.short_records > 0 {
        meta.insert(
            "item_blocks_with_a_short_record".into(),
            json!(census.short_records),
        );
    }
    if !census.not_inflated.is_empty() {
        meta.insert(
            "item_blocks_not_decompressed".into(),
            json!(census.not_inflated.len()),
        );
        meta.insert(
            "item_block_pages_not_decompressed".into(),
            json!(census.not_inflated),
        );
    }

    // --- what is left undecoded, and what its bytes measure ------------------
    meta.insert("blocks_not_decoded".into(), json!(undecoded));
    meta.insert("high_entropy_blocks".into(), json!(high_blocks));
    if high_blocks > 0 {
        // The measurement, not a quotation of one: an examiner can check it
        // against the block offsets this record names.
        meta.insert(
            "high_entropy_bits_per_byte".into(),
            json!(format!("{high_low:.2}–{high_high:.2}")),
        );
    }
    if structured_blocks > 0 {
        meta.insert(
            "structured_block_entropy_bits_per_byte".into(),
            json!(format!("{structured_low:.2}–{structured_high:.2}")),
        );
    }
    if too_short > 0 {
        meta.insert("blocks_too_short_to_measure".into(), json!(too_short));
        meta.insert(
            "entropy_sample_note".into(),
            json!(format!(
                "{too_short} undecoded block(s) carry fewer than {MIN_ENTROPY_SAMPLE_BYTES} \
                 bytes of payload, which is too few for an entropy threshold to establish \
                 anything: entropy over 256 symbols is bounded by log2(n), so a short payload \
                 cannot measure as compressed even when it is. They are counted here and called \
                 neither."
            )),
        );
    }

    let content_types = categories
        .iter()
        .filter(|c| matches!(c, Category::ContentType { .. }))
        .count();
    let display_names = categories.len() - content_types;
    meta.insert(
        "properties_named".into(),
        json!(properties.iter().filter(|p| !p.is_placeholder()).count()),
    );
    meta.insert("property_placeholders".into(), json!(placeholders));
    meta.insert("category_entries".into(), json!(categories.len()));
    meta.insert("content_types".into(), json!(content_types));
    meta.insert("localised_display_names".into(), json!(display_names));
    if display_names > 0 {
        // Counted and not emitted: three thousand localisation strings in a
        // case, filed as observations about files, would be worse than a
        // number.
        meta.insert(
            "display_name_note".into(),
            json!(
                "The category table also holds localised display names, separated from their \
                   locale by the bytes 0x16 0x02. They are counted here and NOT emitted as \
                   records: they are Spotlight's display vocabulary, not observations about \
                   files."
            ),
        );
        // The base labels the index categorises under — `Productivity`,
        // `Volume`, `Safari`. Bounded, and the only use these entries are put
        // to, because the localised variants of each say nothing further.
        let base_names: Vec<&str> = categories
            .iter()
            .filter_map(|c| match c {
                Category::DisplayName { name, locale } if locale.is_empty() => Some(name.as_str()),
                _ => None,
            })
            .take(MAX_SAMPLED_DISPLAY_NAMES)
            .collect();
        if !base_names.is_empty() {
            meta.insert("display_name_sample".into(), json!(base_names));
        }
    }
    let locales: BTreeSet<&str> = categories
        .iter()
        .filter_map(|c| match c {
            Category::DisplayName { locale, .. } if !locale.is_empty() => Some(locale.as_str()),
            _ => None,
        })
        .collect();
    if !locales.is_empty() {
        meta.insert("display_name_locales".into(), json!(locales.len()));
    }

    meta.insert("note".into(), json!(ITEMS_NOTE));

    // Incompleteness is stamped for the things that are actually missing, each
    // named with its count. There is no blanket sentence: this reader used to
    // carry one saying the per-item records could not be decoded at all, and
    // a standing disclaimer is what a reader learns to skip.
    let mut reasons: Vec<(IncompleteReason, String)> = Vec::new();
    if unfinished > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{unfinished} of {} per-item record(s) have an attribute stream that did not \
                 reach the end of the record, so part of what this store holds about them was \
                 not read. Each such record says where its own stream stopped and why.",
                census.items.len()
            ),
        ));
    }
    if undecoded > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{undecoded} of this store's {} block(s) were not decoded: either a block kind \
                 this reader does not read, or an item block whose compressed stream would not \
                 inflate. The entropy of each is measured and reported.",
                blocks.len()
            ),
        ));
    }
    if orphans > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{orphans} item(s) name a parent this store does not hold, so no absolute path \
                 can be stated for them from this file. A volume's Spotlight index is split \
                 across stores and the missing parent may be in one this case does not have."
            ),
        ));
    }
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(file_name)));
    }
    if !capped.is_empty() {
        reasons.push((
            IncompleteReason::CapReached,
            format!("a reader cap was reached in: {}", capped.join(", ")),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    let named_properties = properties.iter().filter(|p| !p.is_placeholder()).count();
    meta.insert(
        "name".into(),
        json!(format!(
            "Spotlight store: {} indexed item(s), {content_types} content type(s){}",
            census.items.len(),
            if header.ios_store { " (iOS)" } else { "" }
        )),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "Spotlight Store-V2, {} block(s) of {} bytes: {} indexed items from \
             {}/{item_blocks} item block(s), {content_types} content types, \
             {named_properties} indexed attributes",
            blocks.len(),
            header.block_size,
            census.items.len(),
            census.inflated
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("store_v2")
}

fn property_artifact(artifact: &Artifact, file_name: &str, property: &Property) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("SpotlightProperty"));
    meta.insert("subtype".into(), json!("spotlight_property"));
    provenance(&mut meta, file_name);
    meta.insert("property_id".into(), json!(property.id));
    meta.insert("attribute".into(), json!(property.name));
    meta.insert("property_type".into(), json!(property.property_type));
    meta.insert("value_type".into(), json!(property.value_type));
    // An id means nothing outside its own store: the corpus's two stores hold
    // 44 ids in common that carry different values.
    meta.insert(
        "scope_note".into(),
        json!(
            "A property id is meaningful only within the store it came from; two stores on the \
               same machine hold the same ids with different meanings."
        ),
    );
    meta.insert("name".into(), json!(property.name.clone()));
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "Spotlight indexed the attribute {} (id {}, property type {}, value type {})",
            property.name, property.id, property.property_type, property.value_type
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("spotlight_property")
}

/// One indexed item: what Spotlight recorded about one file or folder.
fn item_artifact(
    artifact: &Artifact,
    file_name: &str,
    item: &Item,
    vocabulary: &Vocabulary<'_>,
    tree: &Tree,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("SpotlightItem"));
    meta.insert("subtype".into(), json!("spotlight_item"));
    provenance(&mut meta, file_name);
    meta.insert("item_id".into(), json!(item.id));
    if item.parent_id == NO_PARENT {
        meta.insert("parent_item_id".into(), Value::Null);
        meta.insert("parent_recorded".into(), json!(false));
    } else {
        meta.insert("parent_item_id".into(), json!(item.parent_id));
    }
    if let Some(when) = item.indexed_at() {
        meta.insert("indexed_at".into(), json!(when));
    } else {
        meta.insert("indexed_at_usable".into(), json!(false));
        meta.insert("indexed_raw_microseconds".into(), json!(item.indexed_us));
    }
    // Read and not interpreted, on every record rather than only in the
    // aggregate, so the screen that shows an item shows what was not read
    // about it.
    meta.insert("record_flags".into(), json!(item.flags));
    meta.insert("unnamed_field".into(), json!(item.unnamed_field));

    // Every attribute this store recorded, under its own name.
    let mut attributes = Map::new();
    for attribute in &item.attributes {
        let key = match vocabulary.name_of(attribute.property_id) {
            Some(name) => name.to_string(),
            // A property the table does not carry stops the walk, so this
            // cannot normally happen; if it ever does, the id is the name.
            None => format!("property_{}", attribute.property_id),
        };
        attributes.insert(key, vocabulary.value_json(&attribute.value));
    }
    // And the handful that get a stable key as well, so a screen does not
    // depend on Apple's spelling.
    for (apple, stable) in LIFTED {
        if let Some(value) = attributes.get(*apple) {
            meta.insert((*stable).into(), value.clone());
        }
    }
    meta.insert("attribute_count".into(), json!(attributes.len()));
    meta.insert("attributes".into(), Value::Object(attributes));

    // The path, and whether it is one.
    let (path, complete) = tree.path_of(item.id);
    if !path.is_empty() {
        meta.insert("path".into(), json!(path));
    }
    meta.insert("path_complete".into(), json!(complete));
    if !complete {
        meta.insert(
            "path_note".into(),
            json!(
                "The parent chain runs into an item this store does not hold, so the segments \
                   above this point are not known and the value is NOT an absolute path. A \
                   volume's Spotlight index is split across stores; the missing parent may be \
                   in one this case does not have."
            ),
        );
    }

    // Where the attribute stream stopped, if it did not reach the end.
    match item.stop {
        AttrStop::Tiled => {}
        AttrStop::UnknownProperty(id) => {
            stamp_item_shortfall(
                &mut meta,
                format!(
                    "the attribute stream referenced property id {id}, which is not in this \
                     store's own property table, so nothing after it was read"
                ),
            );
        }
        AttrStop::UnestablishedType(t) => {
            stamp_item_shortfall(
                &mut meta,
                format!(
                    "the attribute stream reached property type {t}, whose value encoding this \
                     reader has not established. The format states no length to skip, so \
                     nothing after it was read rather than read against a guess"
                ),
            );
        }
        AttrStop::Truncated => {
            stamp_item_shortfall(
                &mut meta,
                "an attribute value ran past the end of the record, so nothing after it was read"
                    .to_string(),
            );
        }
    }

    let label = meta
        .get("file_name")
        .and_then(|v| v.as_str())
        .or_else(|| meta.get("display_name").and_then(|v| v.as_str()))
        .unwrap_or("(no name recorded)")
        .to_string();
    meta.insert("name".into(), json!(label.clone()));
    let kind = meta
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown content type");
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "Spotlight indexed {label} ({kind}), item {} in {file_name}",
            item.id
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("spotlight_item")
}

/// Record that one item's attribute stream did not reach the end of its
/// record, in the terms the rest of the product reads incompleteness in.
fn stamp_item_shortfall(meta: &mut Map<String, Value>, detail: String) {
    meta.insert("attributes_complete".into(), json!(false));
    let _ = stamp_incomplete(
        meta,
        "content",
        &[(IncompleteReason::UnresolvedStructure, detail)],
    );
}

fn content_type_artifact(artifact: &Artifact, file_name: &str, id: u32, value: &str) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("SpotlightContentType"));
    meta.insert("subtype".into(), json!("spotlight_content_type"));
    provenance(&mut meta, file_name);
    meta.insert("category_id".into(), json!(id));
    meta.insert("content_type".into(), json!(value));
    meta.insert(
        "scope_note".into(),
        json!(
            "A content type in this table is one this volume's index knew about — which may be \
               because of a file since deleted. It is not evidence that such a file is on the \
               volume now, and the per-item records that would name the files are not decodable \
               from this store."
        ),
    );
    meta.insert("name".into(), json!(value.to_string()));
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "Spotlight knew the content type {value} (category {id})"
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("spotlight_content_type")
}

/// The store header, as its own fields state it.
struct Header {
    flags: u32,
    page_size: u32,
    block0_size: u32,
    block_size: u32,
    ios_store: bool,
    chain_heads: Vec<u32>,
}

fn read_header(data: &[u8]) -> Option<Header> {
    if data.len() < CHAIN_HEADS_AT + 4 * CHAIN_HEADS || data.get(0..4) != Some(&STORE_MAGIC[..]) {
        return None;
    }
    let chain_heads: Vec<u32> = (0..CHAIN_HEADS)
        .filter_map(|i| le_u32(data, CHAIN_HEADS_AT + 4 * i))
        .collect();
    Some(Header {
        flags: le_u32(data, 4)?,
        page_size: le_u32(data, 0x24)?,
        block0_size: le_u32(data, 0x28)?,
        block_size: le_u32(data, 0x2c)?,
        // The first chain head is the property table's page. A store with no
        // property block is the iOS shape.
        ios_store: chain_heads.first().copied().unwrap_or(0) == 0,
        chain_heads,
    })
}

impl ForensicsModule for SpotlightStoreParser {
    fn id(&self) -> &str {
        "macos.spotlight_store"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Selection is by the magic, because many files are called
        // `store.db`. The name is used for one thing only: deciding whether a
        // file that failed to read has to SAY so.
        let staged = Staged::read(ds.as_ref(), MAX_STORE_BYTES);
        let Some(header) = read_header(&staged.bytes) else {
            // A file anywhere on the disk called `store.db` that is not a
            // version-2 store is not this module's business and leaves
            // nothing. But one sitting in a Spotlight store directory is:
            // returning silence there would make "this store would not read"
            // indistinguishable from "this volume had no Spotlight index",
            // and the item blocks this module cannot decode make that
            // distinction the whole point of the record.
            if named_as_store(name) && in_spotlight_store_path(name) {
                return Ok(vec![refusal_artifact(artifact, name, &staged)]);
            }
            return Ok(Vec::new());
        };
        let page_size = if header.page_size == 0 {
            4096
        } else {
            header.page_size as usize
        };

        let blocks = read_blocks(&staged.bytes, page_size);
        let reachable = reachable_pages(&staged.bytes, &blocks);
        let (properties, placeholders, properties_capped) = read_properties(&staged.bytes, &blocks);
        let (categories, category_text, categories_capped) =
            read_categories(&staged.bytes, &blocks);
        let item_map = read_item_map(&staged.bytes, page_size);
        let by_id: BTreeMap<u32, Property> = properties.iter().map(|p| (p.id, p.clone())).collect();
        let census = read_item_blocks(&staged.bytes, &blocks, &by_id);
        let tables = read_id_tables(&staged.bytes, &blocks);
        let mut capped: Vec<&str> = Vec::new();
        if properties_capped {
            capped.push("the property table");
        }
        if categories_capped {
            capped.push("the category table");
        }
        if census.capped {
            capped.push("the per-item records");
        }

        let mut out = Vec::with_capacity(properties.len() + categories.len() + 1);
        out.push(store_artifact(
            artifact,
            name,
            &staged,
            &StoreFacts {
                header: &header,
                blocks: &blocks,
                reachable: &reachable,
                properties: &properties,
                placeholders,
                categories: &categories,
                census: &census,
                item_map: item_map.as_ref(),
                tables: &tables,
                capped: &capped,
            },
        ));
        for property in properties.iter().filter(|p| !p.is_placeholder()) {
            out.push(property_artifact(artifact, name, property));
        }
        for category in &categories {
            if let Category::ContentType { id, value } = category {
                out.push(content_type_artifact(artifact, name, *id, value));
            }
        }
        let vocabulary = Vocabulary {
            properties: &by_id,
            categories: &category_text,
            tables: &tables,
        };
        let tree = Tree::build(&census.items, &vocabulary);
        for item in &census.items {
            out.push(item_artifact(artifact, name, item, &vocabulary, &tree));
        }

        info!(
            "SpotlightStoreParser: {name} — {} block(s), {} attribute(s), {} content type(s)",
            blocks.len(),
            properties.len(),
            out.len().saturating_sub(properties.len() + 1)
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;
    use uuid::Uuid;

    // --- fixture construction ------------------------------------------------
    //
    // A store is written from literal offsets rather than through the reader's
    // own constants, so a mistake in those cannot make a test agree with
    // itself.

    const PAGE: usize = 4096;
    const BLOCK: usize = 16384;

    /// A store under construction: blocks are appended at page granularity and
    /// their page indices handed back, exactly as the real layout puts them.
    struct StoreBuilder {
        bytes: Vec<u8>,
    }

    impl StoreBuilder {
        fn new() -> Self {
            // One page of header, then blocks start at page 5 as the real
            // stores do.
            StoreBuilder {
                bytes: vec![0u8; 5 * PAGE],
            }
        }

        /// Append a block of `id` carrying `payload`, and return its page.
        fn block(&mut self, id: u32, payload: &[u8], next_page: u32) -> u32 {
            let page = (self.bytes.len() / PAGE) as u32;
            let mut block = vec![0u8; BLOCK];
            block[0..4].copy_from_slice(BLOCK_MAGIC);
            block[4..8].copy_from_slice(&(BLOCK as u32).to_le_bytes());
            block[8..12]
                .copy_from_slice(&((BLOCK_HEADER_BYTES + payload.len()) as u32).to_le_bytes());
            block[12..16].copy_from_slice(&id.to_le_bytes());
            block[20..24].copy_from_slice(&next_page.to_le_bytes());
            block[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + payload.len()].copy_from_slice(payload);
            self.bytes.extend_from_slice(&block);
            page
        }

        /// Append an item block: a twenty-byte header, the uncompressed
        /// length at offset 16 counting those twenty bytes, and `records`
        /// deflated from offset 20.
        fn item_block(&mut self, id: u32, records: &[Vec<u8>]) -> u32 {
            let mut plain = Vec::new();
            for record in records {
                plain.extend_from_slice(&(record.len() as u32).to_le_bytes());
                plain.extend_from_slice(record);
            }
            let compressed = deflate(&plain);
            let page = (self.bytes.len() / PAGE) as u32;
            let mut block = vec![0u8; BLOCK];
            block[0..4].copy_from_slice(BLOCK_MAGIC);
            block[4..8]
                .copy_from_slice(&((ITEM_STREAM_AT + compressed.len()) as u32).to_le_bytes());
            block[8..12].copy_from_slice(&(BLOCK as u32).to_le_bytes());
            block[12..16].copy_from_slice(&id.to_le_bytes());
            block[16..20].copy_from_slice(&((ITEM_STREAM_AT + plain.len()) as u32).to_le_bytes());
            block[ITEM_STREAM_AT..ITEM_STREAM_AT + compressed.len()].copy_from_slice(&compressed);
            self.bytes.extend_from_slice(&block);
            page
        }

        /// Finish, writing the header with the five chain heads.
        fn finish(mut self, heads: [u32; CHAIN_HEADS]) -> Vec<u8> {
            self.bytes[0..4].copy_from_slice(STORE_MAGIC);
            self.bytes[4..8].copy_from_slice(&0x0000_0101u32.to_le_bytes());
            self.bytes[0x24..0x28].copy_from_slice(&(PAGE as u32).to_le_bytes());
            self.bytes[0x28..0x2c].copy_from_slice(&(BLOCK as u32).to_le_bytes());
            self.bytes[0x2c..0x30].copy_from_slice(&(BLOCK as u32).to_le_bytes());
            for (i, head) in heads.iter().enumerate() {
                let at = CHAIN_HEADS_AT + 4 * i;
                self.bytes[at..at + 4].copy_from_slice(&head.to_le_bytes());
            }
            self.bytes
        }
    }

    /// The index time the fixture's items carry: 2021-03-28T06:34:39.766864Z
    /// in microseconds since the Unix epoch, which is a real value read out of
    /// the corpus.
    const FIXTURE_INDEXED_US: u64 = 1_616_913_279_766_864;

    /// zlib-compress `plain`, so a fixture item block is built the way the
    /// real ones are rather than through the reader's own code.
    fn deflate(plain: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(plain).expect("in-memory write");
        encoder.finish().expect("in-memory finish")
    }

    /// Encode one of the store's variable-size numbers.
    ///
    /// Written out here rather than derived from [`var_num`] on purpose: a
    /// fixture built with the reader's own decoder inverted agrees with the
    /// reader whether or not either is right.
    fn put_var_num(out: &mut Vec<u8>, value: u64) {
        if value <= 0x7f {
            out.push(value as u8);
            return;
        }
        // The smallest number of trailing bytes that holds the number. With
        // `extra` of them the first byte contributes `7 - extra` value bits,
        // so the capacity is `7 + 7 * extra` — except the widest form, `0xff`,
        // which has no terminating zero, contributes none, and carries a full
        // `u64` behind it.
        for extra in 1usize..=7 {
            if value < (1u64 << (7 + 7 * extra)) {
                let ones = (0xffu16 << (8 - extra)) as u8;
                let high = (value >> (8 * extra)) as u8;
                debug_assert!(
                    high < (1u8 << (7 - extra)),
                    "{value} does not fit the {extra}-byte form"
                );
                out.push(ones | high);
                for i in (0..extra).rev() {
                    out.push((value >> (8 * i)) as u8);
                }
                return;
            }
        }
        out.push(0xff);
        out.extend_from_slice(&value.to_be_bytes());
    }

    /// One item record's body: id, flags, the unnamed field, the parent id,
    /// the index time in microseconds, then the attribute bytes.
    fn item_record(
        id: u64,
        flags: u8,
        unnamed: u64,
        parent: u64,
        indexed_us: u64,
        attributes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_var_num(&mut out, id);
        out.push(flags);
        put_var_num(&mut out, unnamed);
        put_var_num(&mut out, parent);
        put_var_num(&mut out, indexed_us);
        out.extend_from_slice(attributes);
        out
    }

    /// Build one attribute-stream pair: the delta from the previous property
    /// id, then a value written the way the format writes it.
    struct Attrs {
        bytes: Vec<u8>,
        last: u32,
    }

    impl Attrs {
        fn new() -> Self {
            Attrs {
                bytes: Vec::new(),
                last: 0,
            }
        }

        fn delta(&mut self, id: u32) {
            // Ids ascend within a record, because the stream carries the
            // difference and never zero. A fixture that writes them out of
            // order is a broken fixture, not a test of a store that does.
            assert!(
                id > self.last,
                "attribute ids ascend: {id} after {}",
                self.last
            );
            put_var_num(&mut self.bytes, u64::from(id - self.last));
            self.last = id;
        }

        /// A variable-size number value.
        fn int(mut self, id: u32, value: u64) -> Self {
            self.delta(id);
            put_var_num(&mut self.bytes, value);
            self
        }

        /// A list of them, behind a prefix counted in the nominal element
        /// width rather than in bytes on the wire.
        fn ints(mut self, id: u32, width: usize, values: &[u64]) -> Self {
            self.delta(id);
            put_var_num(&mut self.bytes, (values.len() * width) as u64);
            for value in values {
                put_var_num(&mut self.bytes, *value);
            }
            self
        }

        /// A length-prefixed text run. The length includes the NUL.
        fn text(mut self, id: u32, parts: &[&str]) -> Self {
            self.delta(id);
            let mut run = Vec::new();
            for part in parts {
                run.extend_from_slice(part.as_bytes());
                run.push(0);
            }
            put_var_num(&mut self.bytes, run.len() as u64);
            self.bytes.extend_from_slice(&run);
            self
        }

        /// A localised text run: each variant, the separator, its locale, NUL.
        fn localised(mut self, id: u32, variants: &[(&str, &str)]) -> Self {
            self.delta(id);
            let mut run = Vec::new();
            for (text, locale) in variants {
                run.extend_from_slice(text.as_bytes());
                run.extend_from_slice(LOCALE_SEPARATOR);
                run.extend_from_slice(locale.as_bytes());
                run.push(0);
            }
            put_var_num(&mut self.bytes, run.len() as u64);
            self.bytes.extend_from_slice(&run);
            self
        }

        /// One `CFAbsoluteTime`, eight raw little-endian bytes.
        fn date(mut self, id: u32, seconds: f64) -> Self {
            self.delta(id);
            self.bytes.extend_from_slice(&seconds.to_le_bytes());
            self
        }

        /// Several, behind a byte-count prefix.
        fn dates(mut self, id: u32, seconds: &[f64]) -> Self {
            self.delta(id);
            put_var_num(&mut self.bytes, (seconds.len() * 8) as u64);
            for value in seconds {
                self.bytes.extend_from_slice(&value.to_le_bytes());
            }
            self
        }

        fn float32(mut self, id: u32, value: f32) -> Self {
            self.delta(id);
            self.bytes.extend_from_slice(&value.to_le_bytes());
            self
        }

        fn blob(mut self, id: u32, bytes: &[u8]) -> Self {
            self.delta(id);
            put_var_num(&mut self.bytes, bytes.len() as u64);
            self.bytes.extend_from_slice(bytes);
            self
        }

        fn done(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// One entry of either `0x81` table: `u32 id`, a length, and that many
    /// bytes of four-byte category ids behind `len % 4` leading bytes.
    fn id_table_entry(id: u32, lead: &[u8], ids: &[u32]) -> Vec<u8> {
        let mut body = lead.to_vec();
        for value in ids {
            body.extend_from_slice(&value.to_le_bytes());
        }
        let mut out = id.to_le_bytes().to_vec();
        put_var_num(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }

    /// One property-table entry: `u32 id`, `u8 property type`,
    /// `u8 value type`, NUL-terminated name.
    fn property_entry(id: u32, ptype: u8, vtype: u8, name: &str) -> Vec<u8> {
        let mut out = id.to_le_bytes().to_vec();
        out.push(ptype);
        out.push(vtype);
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out
    }

    /// One category-table entry: `u32 id`, NUL-terminated string.
    fn category_entry(id: u32, value: &str) -> Vec<u8> {
        let mut out = id.to_le_bytes().to_vec();
        out.extend_from_slice(value.as_bytes());
        out.push(0);
        out
    }

    /// A localised display name, with the exact two-byte separator.
    fn localised_entry(id: u32, name: &str, locale: &str) -> Vec<u8> {
        let mut out = id.to_le_bytes().to_vec();
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(LOCALE_SEPARATOR);
        out.extend_from_slice(locale.as_bytes());
        out.push(0);
        out
    }

    /// A payload that measures as compressed: every byte value, evenly.
    fn high_entropy(len: usize) -> Vec<u8> {
        // A fixed permutation walk, so the fixture is deterministic and its
        // entropy is genuinely near 8 bits rather than near zero.
        let mut out = Vec::with_capacity(len);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..len {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((x >> 24) as u8);
        }
        out
    }

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name }),
        );
        SpotlightStoreParser
            .process(&art)
            .expect("never fails the pipeline")
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    fn store_of(out: &[Artifact]) -> &Value {
        of_type(out, "SpotlightStore")
            .first()
            .copied()
            .expect("a store record")
    }

    fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|x| x.as_str())
    }
    fn n(v: &Value, key: &str) -> Option<i64> {
        v.get(key).and_then(|x| x.as_i64())
    }

    /// A store with one of each block kind, built to the measured layout.
    ///
    /// The tables are padded past [`MIN_ENTROPY_SAMPLE_BYTES`], as the real
    /// ones are (1.7 KB to 16 KB), so the structured measurement exists and
    /// the fixture is not quietly exercising the too-short path.
    fn typical_store() -> Vec<u8> {
        let mut b = StoreBuilder::new();

        // The property table, with one property of every shape this reader
        // has established, plus one it has not and one of Apple's unused
        // placeholder slots.
        let mut props = Vec::new();
        props.extend(property_entry(1, 0, 0, PROPERTY_PLACEHOLDER));
        props.extend(property_entry(P_TREE, 15, 74, "kMDItemContentTypeTree"));
        props.extend(property_entry(P_TYPE, 15, 72, "kMDItemContentType"));
        props.extend(property_entry(P_NAME, 11, 76, "_kMDItemFileName"));
        props.extend(property_entry(P_SIZE, 7, 72, "kMDItemLogicalSize"));
        props.extend(property_entry(P_FROM, 11, 66, "kMDItemWhereFroms"));
        props.extend(property_entry(P_KIND, 15, 131, "kMDItemKind"));
        props.extend(property_entry(P_MADE, 12, 64, "kMDItemContentCreationDate"));
        props.extend(property_entry(
            P_SCORE,
            9,
            76,
            "_kMDItemStaticInterestScore",
        ));
        props.extend(property_entry(P_LABEL, 11, 131, "kMDItemDisplayName"));
        props.extend(property_entry(P_UUID, 14, 12, "kMDStoreUUID"));
        props.extend(property_entry(P_USED, 12, 2, "kMDItemUsedDates"));
        props.extend(property_entry(P_COUNTS, 6, 14, "kMDStoreAccumulatedCounts"));
        props.extend(property_entry(
            P_UNKNOWN_TYPE,
            3,
            0,
            "_kMDItemNotEstablished",
        ));
        props.extend(property_entry(P_AFTER, 12, 64, "kMDItemLastUsedDate"));
        let p = b.block(BLOCK_PROPERTIES, &props, 0);

        // The category table, in both of its forms.
        let mut cats = Vec::new();
        cats.extend(category_entry(1, "public.folder"));
        cats.extend(category_entry(2, "public.directory"));
        cats.extend(category_entry(3, "public.item"));
        cats.extend(category_entry(4, "public.png"));
        cats.extend(localised_entry(5, "Folder", ""));
        cats.extend(localised_entry(6, "Ordner", "de"));
        cats.extend(localised_entry(7, "الإنتاجية", "ar"));
        let c = b.block(BLOCK_CATEGORIES, &cats, 0);

        // The two `0x81` tables, which are different namespaces reached by
        // different chains and both carry an entry numbered 1.
        let lists = id_table_entry(1, &[], &[1, 2, 3]);
        let list_page = b.block(BLOCK_INDEX, &lists, 0);
        let labels = id_table_entry(1, &[0x20], &[5, 6]);
        let label_page = b.block(BLOCK_INDEX, &labels, 0);

        b.item_block(
            BLOCK_ITEMS,
            &[
                // The volume root: no name, and its parent written as the
                // nine-byte "none" form.
                item_record(2, 1, 0, NO_PARENT, FIXTURE_INDEXED_US, &[]),
                // A folder under it.
                item_record(
                    100,
                    0x20,
                    2709,
                    2,
                    FIXTURE_INDEXED_US + 1,
                    &Attrs::new()
                        .int(P_TREE, 1)
                        .int(P_TYPE, 1)
                        .text(P_NAME, &["Users"])
                        .int(P_KIND, 1)
                        .done(),
                ),
                // And a file under that, carrying one of everything.
                item_record(
                    101,
                    0x20,
                    2710,
                    100,
                    FIXTURE_INDEXED_US + 2,
                    &Attrs::new()
                        .int(P_TYPE, 4)
                        .text(P_NAME, &["report.png"])
                        .int(P_SIZE, 2048)
                        .text(
                            P_FROM,
                            &["https://example.invalid/a", "https://example.invalid/b"],
                        )
                        .date(P_MADE, FIXTURE_CF_SECONDS)
                        .float32(P_SCORE, 1.0)
                        .localised(P_LABEL, &[("Report", ""), ("Bericht", "de")])
                        .blob(P_UUID, &[0xde, 0xad, 0xbe, 0xef])
                        .dates(P_USED, &[FIXTURE_CF_SECONDS, FIXTURE_CF_SECONDS + 86_400.0])
                        .ints(P_COUNTS, 4, &[0, 4, 5752])
                        .done(),
                ),
            ],
        );
        b.item_block(
            BLOCK_ITEMS_ALT,
            &[
                // An item whose parent this store does not hold, so no
                // absolute path can be stated for it.
                item_record(
                    200,
                    0,
                    4523,
                    999_999,
                    FIXTURE_INDEXED_US + 3,
                    &Attrs::new().text(P_NAME, &["orphan.txt"]).done(),
                ),
                // And one whose stream reaches a property type this reader
                // has not established, which must stop the walk there.
                item_record(
                    201,
                    0,
                    4524,
                    100,
                    FIXTURE_INDEXED_US + 4,
                    &Attrs::new()
                        .text(P_NAME, &["stops-here.txt"])
                        .int(P_UNKNOWN_TYPE, 7)
                        // Which must not be read: the stream stops above.
                        .date(P_AFTER, FIXTURE_CF_SECONDS)
                        .done(),
                ),
            ],
        );
        b.finish([p, c, 0, list_page, label_page])
    }

    // The fixture's property ids, named so a test reads as the attribute it
    // is about rather than as a number.
    const P_TREE: u32 = 7;
    const P_TYPE: u32 = 10;
    const P_NAME: u32 = 16;
    const P_SIZE: u32 = 17;
    const P_FROM: u32 = 18;
    const P_KIND: u32 = 20;
    const P_MADE: u32 = 27;
    const P_SCORE: u32 = 30;
    const P_LABEL: u32 = 32;
    const P_UUID: u32 = 33;
    const P_USED: u32 = 36;
    const P_COUNTS: u32 = 40;
    const P_UNKNOWN_TYPE: u32 = 44;
    const P_AFTER: u32 = 50;

    /// 2021-02-12T00:00:00Z as `CFAbsoluteTime`, a real value from the corpus.
    const FIXTURE_CF_SECONDS: f64 = 634_780_800.0;

    // --- the header and the inventory ----------------------------------------

    #[test]
    fn a_hand_written_store_decodes_its_header_and_its_block_inventory() {
        let out = run(typical_store(), "store.db");
        let store = store_of(&out);
        assert_eq!(n(store, "store_version"), Some(2));
        // 0x24 is the page granularity, not the header's length. An earlier
        // reading called it `header_size`, which is what a reader would have
        // quoted off the screen.
        assert_eq!(n(store, "page_size"), Some(PAGE as i64));
        assert_eq!(n(store, "block_size"), Some(BLOCK as i64));
        assert_eq!(store["ios_store"], json!(false));
        assert_eq!(n(store, "blocks"), Some(6));
        assert_eq!(store["blocks_by_kind"]["property_table"], json!(1));
        assert_eq!(store["blocks_by_kind"]["category_table"], json!(1));
        // Two `0x81` blocks, because the two id tables are separate
        // namespaces reached by separate chains.
        assert_eq!(store["blocks_by_kind"]["index_table"], json!(2));
        assert_eq!(store["blocks_by_kind"]["item_records"], json!(1));
        assert_eq!(store["blocks_by_kind"]["item_records_alt"], json!(1));
        // The header's chains reach the four structured blocks and neither
        // item block, which is the fact that makes the item count meaningful.
        assert_eq!(n(store, "blocks_reached_by_the_header_chains"), Some(4));
    }

    #[test]
    fn a_store_with_no_property_block_is_reported_as_the_ios_shape() {
        let mut b = StoreBuilder::new();
        let c = b.block(BLOCK_CATEGORIES, &category_entry(1, "public.item"), 0);
        let out = run(b.finish([0, c, 0, 0, 0]), "store.db");
        assert_eq!(store_of(&out)["ios_store"], json!(true));
    }

    // --- the property table ---------------------------------------------------

    #[test]
    fn the_property_table_names_the_attributes_the_index_held() {
        let out = run(typical_store(), "store.db");
        let props = of_type(&out, "SpotlightProperty");
        let names: Vec<&str> = props.iter().filter_map(|p| s(p, "attribute")).collect();
        assert_eq!(
            &names[..4],
            &[
                "kMDItemContentTypeTree",
                "kMDItemContentType",
                "_kMDItemFileName",
                "kMDItemLogicalSize"
            ]
        );
        assert_eq!(n(props[1], "property_id"), Some(i64::from(P_TYPE)));
        assert_eq!(n(props[1], "property_type"), Some(15));
        assert_eq!(n(props[1], "value_type"), Some(72));
        // An id means nothing outside its own store, and the record says so.
        assert!(s(props[0], "scope_note")
            .expect("a note")
            .contains("only within the store"));
    }

    #[test]
    fn apples_placeholder_properties_are_counted_and_never_emitted_as_attributes() {
        let out = run(typical_store(), "store.db");
        let store = store_of(&out);
        assert_eq!(
            n(store, "properties_named"),
            Some(14),
            "fourteen real attributes; the fifteenth table row is Apple's placeholder"
        );
        assert_eq!(
            n(store, "property_placeholders"),
            Some(1),
            "the low property ids are Apple's own padding; emitting _kMDXXXX___DUMMY as an \
             attribute this volume indexed would be inventing one"
        );
        assert!(of_type(&out, "SpotlightProperty")
            .iter()
            .all(|p| s(p, "attribute") != Some(PROPERTY_PLACEHOLDER)));
    }

    // --- the category table, which is two tables ------------------------------

    /// The distinction this reader would be worst without: on the corpus's
    /// larger store, 3,703 of 4,100 entries are localisation strings, and
    /// calling them content types would file three thousand of them in a case
    /// as observations about files.
    #[test]
    fn a_localised_display_name_is_never_reported_as_a_content_type() {
        let out = run(typical_store(), "store.db");
        let store = store_of(&out);
        assert_eq!(n(store, "category_entries"), Some(7));
        assert_eq!(n(store, "content_types"), Some(4));
        assert_eq!(n(store, "localised_display_names"), Some(3));
        assert_eq!(
            n(store, "display_name_locales"),
            Some(2),
            "de and ar; the empty locale on the base name is not a locale"
        );
        assert!(s(store, "display_name_note")
            .expect("a note")
            .contains("NOT emitted as records"));
        // The base label is sampled, which is the only use those entries get.
        assert_eq!(store["display_name_sample"], json!(["Folder"]));

        let types: Vec<&str> = of_type(&out, "SpotlightContentType")
            .iter()
            .filter_map(|c| s(c, "content_type"))
            .collect();
        assert_eq!(&types[..2], &["public.folder", "public.directory"]);
        assert!(
            !types
                .iter()
                .any(|t| t.contains("Produktiv") || t.contains('\u{16}')),
            "a localisation string must not appear as a content type"
        );
    }

    #[test]
    fn a_content_type_record_says_what_its_presence_does_and_does_not_prove() {
        let out = run(typical_store(), "store.db");
        let png = of_type(&out, "SpotlightContentType")
            .into_iter()
            .find(|c| s(c, "content_type") == Some("public.png"))
            .expect("the png content type");
        assert_eq!(n(png, "category_id"), Some(4));
        let note = s(png, "scope_note").expect("a note");
        assert!(note.contains("since deleted"));
        assert!(
            note.contains("not evidence that such a file is on the volume now"),
            "the presence of a content type is not the presence of a file"
        );
    }

    // --- the item blocks ------------------------------------------------------

    /// The records are read, and what is not read is a number.
    #[test]
    fn the_item_records_are_decompressed_and_tile_their_blocks_exactly() {
        let out = run(typical_store(), "store.db");
        let store = store_of(&out);
        assert_eq!(n(store, "item_blocks"), Some(2));
        assert_eq!(
            n(store, "item_blocks_decompressed"),
            Some(2),
            "both blocks are zlib from offset 20, as the real ones are"
        );
        assert!(store.get("item_blocks_not_decompressed").is_none());
        assert_eq!(n(store, "items"), Some(5));
        assert_eq!(n(store, "item_ids_distinct"), Some(5));
        // The layout's own test. A record walk that leaves bytes behind has
        // the layout wrong, and the number is published so a reader can check
        // that rather than take it on trust.
        assert_eq!(
            n(store, "item_record_bytes_not_accounted_for"),
            Some(0),
            "the records must tile the inflated block exactly"
        );
        assert!(store.get("item_blocks_with_a_short_record").is_none());

        // What is NOT read, stated as a count rather than left to be inferred
        // from the absence of a file name.
        assert_eq!(
            n(store, "items_whose_attributes_tiled"),
            Some(4),
            "four of the five records' attribute streams reach their last byte; the fifth \
             stops at a property type this reader has not established"
        );
        assert_eq!(n(store, "items_whose_attributes_did_not_tile"), Some(1));
        assert_eq!(
            store["attribute_property_types_not_established"],
            json!([3]),
            "and the type is named, so the next reader knows what to work on"
        );

        // The index times, which are established.
        assert_eq!(
            s(store, "items_indexed_first"),
            Some("2021-03-28T06:34:39.766864+00:00")
        );
        assert_eq!(
            s(store, "items_indexed_last"),
            Some("2021-03-28T06:34:39.766868+00:00")
        );
        assert!(store.get("items_with_no_usable_index_time").is_none());

        // And the one item whose parent this store does not hold.
        assert_eq!(
            n(store, "items_whose_parent_is_not_in_this_store"),
            Some(1),
            "item 2 names parent 1, which is not in this store"
        );
        assert!(s(store, "orphan_note")
            .expect("a note")
            .contains("not a parse failure"));

        // Nothing is left undecoded but the 0x41-class block, which this
        // fixture has none of.
        assert_eq!(n(store, "blocks_not_decoded"), Some(0));
        assert_eq!(n(store, "high_entropy_blocks"), Some(0));

        assert_eq!(
            s(store, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
        // Incompleteness is stamped for what is specifically missing, each
        // with its count — not as a standing disclaimer a reader learns to
        // skip.
        let detail = s(store, "content_incomplete_detail").expect("a sentence");
        assert!(
            detail.contains(
                "1 of 5 per-item record(s) have an attribute stream that did not \
                             reach the end"
            ),
            "{detail}"
        );
        assert!(
            detail.contains("1 item(s) name a parent this store does not hold"),
            "{detail}"
        );
        // And the inference this record must refuse is on the record itself.
        assert!(
            s(store, "note")
                .expect("a note")
                .contains("NOT evidence that Spotlight never indexed it"),
            "absence from this record must never read as absence from the index"
        );
        assert!(
            s(store, "note").expect("a note").contains("DELETED"),
            "nor may an item here read as a file that is on the volume now"
        );
    }

    /// The variable-size number encoding, which is the one piece of this
    /// format that a little-endian assumption decodes into plausible nonsense.
    #[test]
    fn a_variable_size_number_is_read_big_endian_behind_a_leading_ones_length() {
        // One byte, top bit clear.
        assert_eq!(var_num(&[0x00], 0), Some((0, 1)));
        assert_eq!(var_num(&[0x7f], 0), Some((0x7f, 1)));
        // Two bytes: `10` then six value bits, then one byte.
        assert_eq!(var_num(&[0x8a, 0x95], 0), Some((0x0a95, 2)));
        // Three: `110` then five, then two bytes big-endian. This is the
        // reading that makes sibling item ids come out consecutive —
        // `c1 33 ac` and `c1 33 ad` are 78,764 and 78,765, both real values
        // from page 177 of the corpus's larger store.
        assert_eq!(var_num(&[0xc1, 0x33, 0xac], 0), Some((78_764, 3)));
        assert_eq!(var_num(&[0xc1, 0x33, 0xad], 0), Some((78_765, 3)));
        // Eight: `1111111` then a zero, so no value bits in the first byte and
        // seven bytes following. This is how every index time is written.
        assert_eq!(
            var_num(&[0xfe, 0x05, 0xbe, 0x92, 0xf5, 0xac, 0x51, 0x50], 0),
            Some((FIXTURE_INDEXED_US, 8))
        );
        // Nine: `0xff` has eight one-bits, no terminating zero and no value
        // bits, and carries a full big-endian u64 behind it. The corpus's
        // smaller store writes its one rootless item's parent this way, and an
        // earlier reading of this format refused the form outright — which
        // dropped that item silently.
        assert_eq!(
            var_num(&[0xff, 1, 2, 3, 4, 5, 6, 7, 8], 0),
            Some((0x0102_0304_0506_0708, 9))
        );
        assert_eq!(
            var_num(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0),
            Some((NO_PARENT, 9))
        );
        // And a truncated number ends the walk instead of reading past the
        // buffer.
        assert_eq!(var_num(&[0xc1, 0x33], 0), None);
        assert_eq!(var_num(&[], 0), None);
    }

    /// The encoder the fixtures use and the reader agree, which is what makes
    /// the fixtures above evidence of anything.
    #[test]
    fn the_fixture_encoder_and_the_reader_round_trip() {
        for value in [
            0u64,
            1,
            0x7f,
            0x80,
            0x0a95,
            78_764,
            190_374,
            FIXTURE_INDEXED_US,
            (1u64 << 56) - 1,
        ] {
            let mut bytes = Vec::new();
            put_var_num(&mut bytes, value);
            assert_eq!(
                var_num(&bytes, 0),
                Some((value, bytes.len())),
                "{value} encoded as {bytes:02x?}"
            );
        }
    }

    #[test]
    fn a_record_claiming_more_bytes_than_the_block_holds_stops_the_walk_and_says_so() {
        // The failure this has to refuse: reading a record's fields out of the
        // next record's bytes, which yields a plausible item that never
        // existed.
        let mut plain = Vec::new();
        plain.extend_from_slice(&64u32.to_le_bytes());
        plain.extend_from_slice(&item_record(9, 0, 0, 2, FIXTURE_INDEXED_US, &[0x07]));
        let walk = read_items(&plain, &BTreeMap::new(), MAX_ITEMS);
        assert!(
            walk.items.is_empty(),
            "no item is invented from short bytes"
        );
        assert!(walk.short_record);
    }

    #[test]
    fn an_item_block_that_will_not_inflate_is_reported_and_measured_not_skipped() {
        // A block whose id declares it an item block but whose stream is not
        // zlib. It must be counted as a gap in the item population, and its
        // entropy is then what says whether it looks like another compression
        // or like structure this reader missed.
        let mut b = StoreBuilder::new();
        let p = b.block(
            BLOCK_PROPERTIES,
            &property_entry(2, 0, 0, "kMDItemFSName"),
            0,
        );
        b.block(BLOCK_ITEMS, &high_entropy(10_000), 0);
        let out = run(b.finish([p, 0, 0, 0, 0]), "store.db");
        let store = store_of(&out);
        assert_eq!(n(store, "item_blocks"), Some(1));
        assert_eq!(n(store, "item_blocks_decompressed"), Some(0));
        assert_eq!(n(store, "item_blocks_not_decompressed"), Some(1));
        assert_eq!(n(store, "items"), Some(0));
        assert_eq!(
            n(store, "blocks_not_decoded"),
            Some(1),
            "a block that would not inflate is not decoded, whatever its id says"
        );
        assert_eq!(n(store, "high_entropy_blocks"), Some(1));
        let measured = s(store, "high_entropy_bits_per_byte").expect("a measurement");
        let low: f64 = measured
            .split('–')
            .next()
            .unwrap()
            .parse()
            .expect("a number");
        assert!(low > 7.0, "and its payload measures: {measured}");
    }

    #[test]
    fn an_undecoded_block_that_is_plainly_not_compressed_is_not_called_compressed() {
        // The label follows the measurement in both directions. An item block
        // that will not inflate AND whose payload is low-entropy is structure
        // this reader missed, not a cipher — and reporting it as compressed
        // would tell an examiner to stop looking.
        let mut b = StoreBuilder::new();
        let p = b.block(
            BLOCK_PROPERTIES,
            &property_entry(2, 0, 0, "kMDItemFSName"),
            0,
        );
        b.block(BLOCK_ITEMS, &vec![b'A'; 4000], 0);
        let out = run(b.finish([p, 0, 0, 0, 0]), "store.db");
        let store = store_of(&out);
        assert_eq!(
            n(store, "item_blocks"),
            Some(1),
            "the block's own id still declares it an item block"
        );
        assert_eq!(n(store, "item_blocks_not_decompressed"), Some(1));
        assert_eq!(n(store, "blocks_not_decoded"), Some(1));
        assert_eq!(
            n(store, "high_entropy_blocks"),
            Some(0),
            "a low-entropy payload is not reported as compressed"
        );
        assert_eq!(
            s(store, "structured_block_entropy_bits_per_byte"),
            Some("0.00–0.00"),
            "4,000 bytes of one repeated value: measurable, and measures as structure"
        );
        // And no item is claimed from it.
        assert_eq!(n(store, "items"), Some(0));
    }

    // --- selection and robustness ---------------------------------------------

    #[test]
    fn a_file_that_is_not_a_version_two_store_is_passed_over_in_silence() {
        for bytes in [
            b"not a store".to_vec(),
            vec![0u8; 8192],
            b"SQLite format 3\0".to_vec(),
        ] {
            assert!(run(bytes, "store.db").is_empty());
        }
    }

    #[test]
    fn a_store_under_another_name_is_still_read_because_selection_is_by_magic() {
        let out = run(typical_store(), "carved-0007.bin");
        assert!(!of_type(&out, "SpotlightContentType").is_empty());
    }

    #[test]
    fn a_chain_that_points_at_itself_ends_the_walk_rather_than_looping() {
        let mut b = StoreBuilder::new();
        // A category block whose `next` is its own page.
        let page = (b.bytes.len() / PAGE) as u32;
        let c = b.block(BLOCK_CATEGORIES, &category_entry(1, "public.item"), page);
        assert_eq!(c, page);
        let out = run(b.finish([0, c, 0, 0, 0]), "store.db");
        assert_eq!(
            n(store_of(&out), "blocks_reached_by_the_header_chains"),
            Some(1)
        );
    }

    #[test]
    fn a_chain_head_pointing_past_the_file_is_survived() {
        let mut b = StoreBuilder::new();
        let c = b.block(BLOCK_CATEGORIES, &category_entry(1, "public.item"), 0);
        let out = run(b.finish([9_999_999, c, 0, 0, 0]), "store.db");
        // The head reaches nothing; the block is still inventoried by the scan.
        let store = store_of(&out);
        assert_eq!(n(store, "blocks"), Some(1));
        assert_eq!(n(store, "blocks_reached_by_the_header_chains"), Some(1));
    }

    #[test]
    fn a_truncated_entry_at_the_end_of_a_table_stops_the_read_rather_than_inventing_a_name() {
        let mut b = StoreBuilder::new();
        // An id with no NUL-terminated name after it.
        let mut cats = category_entry(1, "public.message");
        cats.extend_from_slice(&2u32.to_le_bytes());
        cats.extend_from_slice(b"com.apple.unterminated");
        let c = b.block(BLOCK_CATEGORIES, &cats, 0);
        let out = run(b.finish([0, c, 0, 0, 0]), "store.db");
        let types: Vec<&str> = of_type(&out, "SpotlightContentType")
            .iter()
            .filter_map(|x| s(x, "content_type"))
            .collect();
        assert_eq!(
            types,
            vec!["public.message"],
            "an entry with no terminator is not completed with whatever followed it"
        );
    }

    #[test]
    fn every_emitted_record_names_its_source_file_and_format() {
        let out = run(typical_store(), "store.db");
        assert!(out.len() > 3);
        for a in &out {
            assert_eq!(s(&a.metadata, "source_format"), Some("spotlight_store_v2"));
            assert_eq!(s(&a.metadata, "source_file_name"), Some("store.db"));
        }
    }

    // --- the real stores ------------------------------------------------------

    /// **The real Spotlight stores from the Magnet 2021 macOS image.**
    ///
    #[test]
    fn a_store_that_will_not_read_says_so_rather_than_leaving_the_volume_looking_unindexed() {
        // A truncated store: the directory says what it is, the bytes do not.
        let out = run(
            b"nope".to_vec(),
            ".Spotlight-V100/Store-V2/08E38AC0-8C6B-43EA-B854-C191A2633BD0/store.db",
        );
        let status = of_type(&out, "SpotlightStoreStatus")
            .first()
            .copied()
            .expect("a refusal record");
        assert_eq!(status["detected"], json!(false));
        assert_eq!(
            s(status, "failure_reason"),
            Some(IncompleteReason::UnresolvedStructure.as_str()),
            "the whole file was staged, so the shortfall is the format and not the read"
        );
        assert!(s(status, "failure_detail")
            .expect("detail")
            .contains("8tsd"));
        assert!(
            s(status, "message")
                .expect("a message")
                .contains("NOT evidence that Spotlight never indexed it"),
            "the inference a silent nothing would have invited must be refused in words"
        );
        assert_eq!(status["content_incomplete"], json!(true));
        // And nothing is claimed from it.
        assert!(of_type(&out, "SpotlightStore").is_empty());
        assert!(of_type(&out, "SpotlightProperty").is_empty());
        assert!(of_type(&out, "SpotlightContentType").is_empty());
    }

    #[test]
    fn a_store_db_that_is_not_a_spotlight_store_at_all_leaves_nothing() {
        // `store.db` is one of the most-reused names on a disk — Firefox, App
        // Store receipts, a dozen applications' own caches. A refusal record
        // for every one of them would be noise that buries the real ones, so
        // the directory has to agree before anything is said.
        for name in [
            "store.db",
            "Library/Application Support/SomeApp/store.db",
            "private/var/folders/zz/store.db",
        ] {
            let out = run(b"SQLite format 3\0".to_vec(), name);
            assert!(
                out.is_empty(),
                "{name} is not in a Spotlight store directory and must leave nothing"
            );
        }
    }

    #[test]
    fn the_path_test_reads_either_separator_and_either_case() {
        // An image walked on Windows hands paths back with backslashes, and
        // the directory names are mixed-case as Apple writes them.
        assert!(in_spotlight_store_path(
            ".Spotlight-V100/Store-V2/UUID/store.db"
        ));
        assert!(in_spotlight_store_path(
            "Volumes\\Macintosh HD\\.Spotlight-V100\\Store-V2\\UUID\\store.db"
        ));
        assert!(in_spotlight_store_path(
            "system/volumes/data/.spotlight-v100/store-v2/uuid/store.db"
        ));
        assert!(!in_spotlight_store_path("Library/Caches/store.db"));
    }

    // --- the attribute stream -------------------------------------------------

    /// One item, decoded value by value. Each shape in this record is a
    /// separate encoding, and reading any of them at the wrong width
    /// desynchronises everything after it — the stream has no terminator.
    #[test]
    fn an_items_attributes_decode_to_their_values_with_every_reference_resolved() {
        let out = run(typical_store(), "store.db");
        let item = of_type(&out, "SpotlightItem")
            .into_iter()
            .find(|i| n(i, "item_id") == Some(101))
            .expect("the file record");
        let attrs = &item["attributes"];

        // A length-prefixed string, whose length includes the NUL.
        assert_eq!(attrs["_kMDItemFileName"], json!("report.png"));
        // A variable-size integer.
        assert_eq!(attrs["kMDItemLogicalSize"], json!(2048));
        // Several NUL-terminated strings inside one length prefix. The value
        // that answers "where did this file come from".
        assert_eq!(
            attrs["kMDItemWhereFroms"],
            json!(["https://example.invalid/a", "https://example.invalid/b"])
        );
        // A raw little-endian f64 read as CFAbsoluteTime — seconds from
        // 2001-01-01, not 1970, which is a thirty-one-year error if taken as
        // a Unix time.
        assert_eq!(
            attrs["kMDItemContentCreationDate"],
            json!("2021-02-12T00:00:00+00:00")
        );
        // A raw little-endian f32.
        assert_eq!(attrs["_kMDItemStaticInterestScore"], json!(1.0));
        // A blob, which is NOT rendered as text: a property list shown as
        // lossy UTF-8 is a string nobody can check.
        assert_eq!(attrs["kMDStoreUUID"]["bytes"], json!(4));
        assert_eq!(attrs["kMDStoreUUID"]["hex"], json!("deadbeef"));
        // A list of dates behind a byte count.
        assert_eq!(
            attrs["kMDItemUsedDates"],
            json!(["2021-02-12T00:00:00+00:00", "2021-02-13T00:00:00+00:00"])
        );
        // And a list of integers behind a prefix counted in the NOMINAL
        // element width rather than in bytes on the wire: three four-byte
        // elements are announced as twelve and occupy five.
        assert_eq!(attrs["kMDStoreAccumulatedCounts"], json!([0, 4, 5752]));

        // A localised string: the same label once per language inside one
        // length prefix, reported as one label and a count rather than as two
        // observations about the file.
        assert_eq!(
            attrs["kMDItemDisplayName"],
            json!({ "label": "Report", "localisations": 2 })
        );
        // The interned reference, resolved against this store's own table.
        assert_eq!(item["content_type"], json!("public.png"));
    }

    #[test]
    fn the_two_id_tables_are_different_namespaces_and_are_not_merged() {
        // Both tables carry an entry numbered 1 and they mean different
        // things. Merging them is what makes a folder's kind read as a
        // content-type list.
        let out = run(typical_store(), "store.db");
        let folder = of_type(&out, "SpotlightItem")
            .into_iter()
            .find(|i| n(i, "item_id") == Some(100))
            .expect("the folder record");
        assert_eq!(
            folder["content_type_tree"],
            json!(["public.folder", "public.directory", "public.item"]),
            "entry 1 of the list table"
        );
        assert_eq!(
            folder["kind"],
            json!({ "label": "Folder", "localisations": 2 }),
            "entry 1 of the label table, which is a different entry 1"
        );
    }

    #[test]
    fn a_localised_value_is_one_label_and_a_count_not_a_list_of_spellings() {
        // `kMDItemProfileName` carries thirty-one spellings of one name on
        // the corpus. Emitting those as thirty-one strings would read as
        // thirty-one observations about the file.
        let out = run(typical_store(), "store.db");
        let folder = of_type(&out, "SpotlightItem")
            .into_iter()
            .find(|i| n(i, "item_id") == Some(100))
            .expect("the folder record");
        assert_eq!(folder["kind"]["label"], json!("Folder"));
        assert_eq!(folder["kind"]["localisations"], json!(2));
    }

    #[test]
    fn the_parent_chain_reconstructs_a_path_and_refuses_to_state_one_it_cannot() {
        let out = run(typical_store(), "store.db");
        let items = of_type(&out, "SpotlightItem");
        let by_id = |id: i64| {
            items
                .iter()
                .find(|i| n(i, "item_id") == Some(id))
                .copied()
                .unwrap_or_else(|| panic!("item {id}"))
        };

        assert_eq!(s(by_id(101), "path"), Some("/Users/report.png"));
        assert_eq!(by_id(101)["path_complete"], json!(true));

        // The item whose parent this store does not hold. What is known is
        // the leaf, and it is NOT presented with a leading slash — an
        // absolute path would state a location the evidence does not support.
        let orphan = by_id(200);
        assert_eq!(s(orphan, "path"), Some("orphan.txt"));
        assert_eq!(orphan["path_complete"], json!(false));
        assert!(s(orphan, "path_note")
            .expect("a note")
            .contains("NOT an absolute path"));
    }

    #[test]
    fn an_attribute_stream_that_reaches_an_unestablished_type_stops_and_says_where() {
        // The failure this must refuse: skipping a value whose length is not
        // stated anywhere and reading the rest of the record against the
        // wrong offset, which yields attributes that look real.
        let out = run(typical_store(), "store.db");
        let item = of_type(&out, "SpotlightItem")
            .into_iter()
            .find(|i| n(i, "item_id") == Some(201))
            .expect("the record that stops");
        // What was read before the stop is kept.
        assert_eq!(item["file_name"], json!("stops-here.txt"));
        // And what was after it is not invented.
        assert!(
            item["attributes"].get("kMDItemLastUsedDate").is_none(),
            "the attribute after the unestablished type must not be read"
        );
        assert_eq!(item["attributes_complete"], json!(false));
        assert_eq!(
            s(item, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
        let detail = s(item, "content_incomplete_detail").expect("a sentence");
        assert!(detail.contains("property type 3"), "{detail}");
        assert!(detail.contains("states no length to skip"), "{detail}");
    }

    #[test]
    fn a_store_with_no_map_block_says_so_rather_than_claiming_agreement() {
        // The fixture writes no `2mbd` block, and a reader that silently
        // reported nothing would be indistinguishable from one whose scan and
        // map agreed.
        let out = run(typical_store(), "store.db");
        let store = store_of(&out);
        assert_eq!(store["stores_item_map_present"], json!(false));
        assert!(store.get("item_blocks_named_by_the_stores_map").is_none());
    }

    #[test]
    fn a_map_naming_a_page_the_scan_cannot_read_reports_the_disagreement() {
        // The whole point of reading the store's own map: it is a second
        // statement of the item-block population, and a page it names that
        // the scan cannot read is a gap in that population.
        let mut b = StoreBuilder::new();
        let p = b.block(
            BLOCK_PROPERTIES,
            &property_entry(2, 0, 0, "kMDItemFSName"),
            0,
        );
        let item_page = b.item_block(
            BLOCK_ITEMS,
            &[item_record(9, 0, 0, 0, FIXTURE_INDEXED_US, &[])],
        );
        // The map names that block and one more that is not there.
        let mut bytes = b.finish([p, 0, 0, 0, 0]);
        let at = MAP_PAGE * PAGE;
        bytes[at..at + 4].copy_from_slice(MAP_MAGIC);
        bytes[at + 4..at + 8].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&2u32.to_le_bytes());
        for (i, page) in [item_page, 4096].iter().enumerate() {
            let entry = at + MAP_ENTRIES_AT + i * MAP_ENTRY_BYTES + MAP_ENTRY_PAGE_AT;
            bytes[entry..entry + 4].copy_from_slice(&page.to_le_bytes());
        }
        let out = run(bytes, "store.db");
        let store = store_of(&out);
        assert_eq!(n(store, "item_blocks_named_by_the_stores_map"), Some(2));
        assert_eq!(
            n(store, "item_blocks_the_map_and_the_scan_agree_on"),
            Some(1)
        );
        assert_eq!(
            store["item_block_pages_the_map_names_but_the_scan_did_not_find"],
            json!([4096]),
            "the page is named, so the gap is one an examiner can go and look at"
        );
    }

    /// Two distinct stores are held (the tree mounts one of them at three
    /// paths). Every figure below is pinned, including the two that decide
    /// whether this reader is honest: that the item blocks measure as
    /// compressed or encrypted, and that the category table's localisation
    /// strings are not counted as content types.
    #[test]
    fn the_real_spotlight_stores_yield_their_vocabularies_and_measure_what_they_cannot_read() {
        let root = home("ctf-evidence/macos2021/tree");
        let big = root.join(
            "System/Volumes/Data/.Spotlight-V100/Store-V2/\
             08E38AC0-8C6B-43EA-B854-C191A2633BD0/store.db",
        );
        let small = root.join(
            "Volumes/Macintosh HD - Data/.Spotlight-V100/Store-V2/\
             9FCCAA69-44EF-4FCB-B3AB-2040BCB5C72A/store.db",
        );
        let (Ok(big_bytes), Ok(small_bytes)) = (std::fs::read(&big), std::fs::read(&small)) else {
            eprintln!("skipping: the macOS Spotlight corpus is not present (gitignored)");
            return;
        };
        assert_eq!(big_bytes.len(), 1_429_504);
        assert_eq!(small_bytes.len(), 118_784);

        // --- the Data volume's store ---
        let out = run(big_bytes, "store.db");
        let store = store_of(&out);
        assert_eq!(n(store, "page_size"), Some(4096));
        assert_eq!(n(store, "block_size"), Some(16384));
        assert_eq!(store["ios_store"], json!(false));
        assert_eq!(n(store, "blocks"), Some(86));
        assert_eq!(store["blocks_by_kind"]["property_table"], json!(1));
        assert_eq!(store["blocks_by_kind"]["category_table"], json!(7));
        assert_eq!(store["blocks_by_kind"]["index_table"], json!(3));
        assert_eq!(store["blocks_by_kind"]["item_records"], json!(71));
        assert_eq!(store["blocks_by_kind"]["item_records_alt"], json!(3));
        assert_eq!(
            n(store, "blocks_reached_by_the_header_chains"),
            Some(12),
            "the five chains reach twelve of the 86; the rest are the item blocks, which are \
             found by a scan and reported as unreached"
        );

        assert_eq!(n(store, "properties_named"), Some(130));
        assert_eq!(n(store, "property_placeholders"), Some(6));
        assert_eq!(n(store, "category_entries"), Some(4100));
        assert_eq!(
            (
                n(store, "content_types"),
                n(store, "localised_display_names")
            ),
            (Some(397), Some(3703)),
            "397 content types and 3,703 localisation strings; calling all 4,100 content types \
             would put three thousand display strings in a case as observations about files"
        );

        // --- the per-item records -------------------------------------------
        assert_eq!(n(store, "item_blocks"), Some(74));
        assert_eq!(
            n(store, "item_blocks_decompressed"),
            Some(74),
            "every item block is a zlib stream from block offset 20"
        );
        assert!(store.get("item_blocks_not_decompressed").is_none());
        assert_eq!(n(store, "items"), Some(14_934));
        assert_eq!(
            n(store, "item_record_bytes_not_accounted_for"),
            Some(0),
            "14,934 records tile 74 inflated blocks with nothing left over, which is the test \
             the record layout has to pass — a layout read wrongly leaves a remainder"
        );
        assert!(store.get("item_blocks_with_a_short_record").is_none());
        assert_eq!(
            n(store, "item_ids_distinct"),
            Some(14_930),
            "four ids appear twice, which is the store holding a superseded version of an item"
        );
        assert_eq!(n(store, "items_with_a_repeated_id"), Some(4));
        // The two fields read and not interpreted, published as what was
        // seen. Five distinct flag bytes, and a number this reader will not
        // name.
        assert_eq!(
            store["item_flag_bytes_seen"],
            json!([0, 1, 32, 66, 98]),
            "the flag bytes are reported as the bytes they are, not decoded into words this \
             reader cannot justify"
        );
        assert_eq!(s(store, "item_unnamed_field_range"), Some("0–190374"));
        assert!(s(store, "item_unnamed_field_note")
            .expect("a note")
            .contains("NOT established"));
        assert_eq!(
            n(store, "items_whose_parent_is_not_in_this_store"),
            Some(967),
            "967 items name a parent this store does not hold, so no path can be assembled for \
             them from this file — a property of the evidence, reported rather than hidden"
        );
        // Every one of the 14,934 index times lands inside the window the
        // image was acquired in, which is what establishes the field as a
        // microsecond Unix time rather than leaving it a plausible guess.
        assert!(store.get("items_with_no_usable_index_time").is_none());
        assert!(
            store.get("items_with_no_parent_recorded").is_none(),
            "no item in this store writes the no-parent sentinel"
        );
        assert_eq!(
            s(store, "items_indexed_first"),
            Some("2021-02-11T01:55:56.844795+00:00")
        );
        assert_eq!(
            s(store, "items_indexed_last"),
            Some("2021-04-06T04:46:19.342194+00:00")
        );

        assert_eq!(n(store, "item_attribute_bytes"), Some(3_223_444));
        assert_eq!(
            n(store, "item_attributes_read"),
            Some(428_087),
            "every attribute of every record, and every one of them decoded"
        );
        assert_eq!(
            n(store, "items_whose_attributes_tiled"),
            Some(14_934),
            "every record's attribute stream ends on the record's last byte. The stream has no \
             terminator, so one value read at the wrong width desynchronises everything after \
             it — which makes this the test the value encodings have to pass"
        );
        assert!(store.get("items_whose_attributes_did_not_tile").is_none());
        assert!(store
            .get("attribute_property_types_not_established")
            .is_none());
        assert!(store
            .get("attribute_property_ids_not_in_this_stores_table")
            .is_none());

        // The store's own map of its item blocks, against the page scan. Two
        // independent statements of the same population.
        assert_eq!(n(store, "item_blocks_named_by_the_stores_map"), Some(74));
        assert_eq!(
            n(store, "item_blocks_the_map_and_the_scan_agree_on"),
            Some(74)
        );
        assert!(store
            .get("item_block_pages_the_map_names_but_the_scan_did_not_find")
            .is_none());
        assert!(store
            .get("item_block_pages_found_that_the_map_does_not_name")
            .is_none());

        // --- the known answer: the file system this index describes ---------
        //
        // The image is mounted, so a decoded size is checkable against the
        // file itself. This is the one check in this test that owes nothing
        // to the store's internal consistency.
        let items = of_type(&out, "SpotlightItem");
        assert_eq!(items.len(), 14_934);
        let complete = items
            .iter()
            .filter(|i| i["path_complete"] == json!(true))
            .count();
        assert_eq!(
            complete, 12_808,
            "12,808 items' parent chains reach a root this store holds, so an absolute path can \
             be stated for them; the rest are reported without one"
        );

        let mut checked = 0usize;
        let mut agreed = 0usize;
        let mut disagreed: Vec<String> = Vec::new();
        for item in &items {
            if item["path_complete"] != json!(true) {
                continue;
            }
            let (Some(path), Some(size)) = (s(item, "path"), n(item, "logical_size")) else {
                continue;
            };
            let rel = path.trim_start_matches('/');
            // The data volume is firmlinked, so the tree mounts it at both.
            for base in ["", "System/Volumes/Data/"] {
                let on_disk = root.join(format!("{base}{rel}"));
                if let Ok(file) = std::fs::metadata(&on_disk) {
                    if file.is_file() {
                        checked += 1;
                        if file.len() as i64 == size {
                            agreed += 1;
                        } else {
                            disagreed.push(path.to_string());
                        }
                        break;
                    }
                }
            }
        }
        assert_eq!(
            (agreed, checked),
            (8782, 8797),
            "8,782 of the 8,797 reconstructed paths that resolve to a real file on the mounted \
             image carry a decoded kMDItemLogicalSize equal to that file's actual length. \
             Nothing in this reader knows the file system; if the path reconstruction or the \
             integer decode were wrong this number would collapse"
        );
        // And the fifteen that differ are all files the operating system
        // rewrites in place, so the index is older than the acquisition —
        // which is a fact about the evidence and not a decode error.
        assert_eq!(disagreed.len(), 15);
        for path in &disagreed {
            assert!(
                path.ends_with("-wal")
                    || path.ends_with(".plist")
                    || path.contains("/com.apple.ap.promotedcontentd/"),
                "every disagreement must be a file macOS rewrites in place: {path}"
            );
        }

        // Named items, decoded end to end. `checkra1n` is a jailbreak tool,
        // which is the kind of thing this store is read to find.
        let checkra1n = items
            .iter()
            .find(|i| s(i, "file_name") == Some("checkra1n.app"))
            .expect("the jailbreak tool this image carries");
        assert_eq!(s(checkra1n, "path"), Some("/Applications/checkra1n.app"));
        assert_eq!(
            s(checkra1n, "content_type"),
            Some("com.apple.application-bundle")
        );
        assert_eq!(checkra1n["kind"]["label"], json!("Application"));
        assert_eq!(s(checkra1n, "bundle_id"), Some("kim.cracksby.checkra1n"));
        assert_eq!(s(checkra1n, "version"), Some("beta 0.12.2"));
        assert_eq!(n(checkra1n, "use_count"), Some(6));
        assert_eq!(n(checkra1n, "uid"), Some(501), "the console user, not root");
        assert_eq!(n(checkra1n, "gid"), Some(80), "admin");
        assert_eq!(
            s(checkra1n, "last_used"),
            Some("2021-02-22T04:06:32.022643+00:00")
        );
        assert_eq!(
            checkra1n["content_type_tree"][0],
            json!("com.apple.application-bundle")
        );

        let cupsd = items
            .iter()
            .find(|i| s(i, "file_name") == Some("cupsd.conf.pre-update"))
            .expect("a file whose size the mounted image confirms");
        assert_eq!(
            s(cupsd, "path"),
            Some("/private/etc/cups/cupsd.conf.pre-update")
        );
        assert_eq!(
            n(cupsd, "logical_size"),
            Some(6538),
            "and the file on the mounted image is 6,538 bytes"
        );
        assert_eq!(n(cupsd, "physical_size"), Some(8192), "two 4 KiB pages");
        assert_eq!(n(cupsd, "gid"), Some(26), "the CUPS group");

        // The entropy machinery now measures only what is NOT decoded, which
        // in this store is the single 0x41 block — and that one is empty, so
        // it is reported as unmeasurable rather than given a verdict.
        assert_eq!(n(store, "blocks_not_decoded"), Some(1));
        assert_eq!(n(store, "high_entropy_blocks"), Some(0));
        assert_eq!(n(store, "blocks_too_short_to_measure"), Some(1));
        assert!(s(store, "entropy_sample_note")
            .expect("a note")
            .contains("bounded by log2(n)"));

        // The attributes this volume's index actually held.
        let attributes: std::collections::BTreeSet<&str> = of_type(&out, "SpotlightProperty")
            .iter()
            .filter_map(|p| s(p, "attribute"))
            .collect();
        for expected in [
            "kMDItemContentType",
            "kMDItemContentTypeTree",
            "kMDItemWhereFroms",
            "kMDItemPhysicalSize",
            "_kMDItemFileName",
        ] {
            assert!(attributes.contains(expected), "{expected} is in this store");
        }

        // And the content types, which is what the index knew about.
        let types: std::collections::BTreeSet<&str> = of_type(&out, "SpotlightContentType")
            .iter()
            .filter_map(|c| s(c, "content_type"))
            .collect();
        assert_eq!(types.len(), 397);
        for expected in [
            "public.message",
            "com.apple.mail.emlx",
            "com.apple.ichat.transcript",
            "public.vcard",
        ] {
            assert!(types.contains(expected), "{expected} is in this store");
        }
        assert!(
            !types.iter().any(|t| t.contains('\u{16}')),
            "no content type carries the locale separator"
        );

        // --- the smaller store, which proves the tables are per-volume ---
        let out = run(small_bytes, "store.db");
        let small_store = store_of(&out);
        assert_eq!(n(small_store, "properties_named"), Some(53));
        assert_eq!(n(small_store, "property_placeholders"), Some(6));
        assert_eq!(n(small_store, "category_entries"), Some(174));
        assert_eq!(
            (
                n(small_store, "content_types"),
                n(small_store, "localised_display_names")
            ),
            (Some(133), Some(41))
        );
        assert_eq!(n(small_store, "item_blocks"), Some(1));
        assert_eq!(n(small_store, "item_blocks_decompressed"), Some(1));
        assert_eq!(
            n(small_store, "items"),
            Some(2),
            "a store with two items in it, which is what a barely-indexed volume looks like"
        );
        assert_eq!(
            n(small_store, "item_record_bytes_not_accounted_for"),
            Some(0)
        );
        // This store's real item writes its parent as the widest
        // variable-size form there is, nine bytes of `0xff`, which is the
        // file saying "no parent" rather than naming one. It is reported as
        // that and not as parent id 18,446,744,073,709,551,615 — and a reader
        // that refused the form would have dropped the item and reported one
        // where there are two.
        assert_eq!(n(small_store, "items_with_no_parent_recorded"), Some(1));
        assert_eq!(
            n(small_store, "items_whose_parent_is_not_in_this_store"),
            Some(1),
            "the other item names parent 0, which this store does not hold"
        );
        // Nothing here is left undecoded but the empty 0x41 block, and an
        // empty payload gets no entropy verdict — so the honesty machinery
        // reports one unmeasurable block and no verdict, rather than calling
        // an empty block structured.
        assert_eq!(n(small_store, "blocks_not_decoded"), Some(1));
        assert_eq!(n(small_store, "high_entropy_blocks"), Some(0));
        assert_eq!(n(small_store, "blocks_too_short_to_measure"), Some(1));
        assert!(small_store
            .get("structured_block_entropy_bits_per_byte")
            .is_none());
        // The two stores' tables differ, which is what makes them observations
        // rather than a shipped constant — and why every record names its
        // store.
        assert!(
            n(small_store, "properties_named") != n(store, "properties_named"),
            "two stores on one machine hold different vocabularies"
        );
    }
}
