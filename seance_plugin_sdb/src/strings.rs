//! The string table, and the reference that points into it.
//!
//! # The six bytes that decide whether a database reads at all
//!
//! A `STRINGREF` is a four-byte offset, and it is relative to the **string
//! table's own tag word** — not to the table's payload. The two differ by six
//! bytes: the tag's `u16` and its `u32` length.
//!
//! Resolving from the payload does not fail. It lands six bytes into the first
//! entry and reads the middle of a UTF-16 string as a tag word and a length,
//! producing entries of millions of bytes and strings of replacement
//! characters. Measured on `frxmain.sdb`: from the tag it gives
//! `"3.0.0.17"` and `"Microsoft Windows Program Frameworks and Dependencies
//! Database"`; from the payload, `"<not a string tag: 0x33 len 3145774>"`.
//!
//! That is why this is resolved through a **validated** table rather than by
//! arithmetic: a reference is only honoured when it names an entry the table
//! walk actually found.
//!
//! # What the seven real databases show
//!
//! Every one of the 344,727 `STRINGREF` occurrences across all seven resolves,
//! and in each file the number of **distinct** references equals the number of
//! table entries exactly. So every entry is referenced and no reference points
//! anywhere else — an internal consistency this reader can check without a
//! second tool, which is what makes the resolution trustworthy here.

use std::collections::BTreeMap;

use crate::format::{Tag, TagType};

/// The top-level tag that holds the string table.
pub const TAG_STRINGTABLE: u16 = 0x7801;
/// The tag each entry in the table carries.
pub const TAG_STRINGTABLE_ITEM: u16 = 0x8801;

/// Bytes of an entry's header: the tag word and its length.
const ENTRY_HEADER: usize = 6;

/// A validated string table.
///
/// Built by walking the table's own entries, so a reference can only resolve to
/// an offset the walk found. A reference into the middle of an entry is refused
/// rather than decoded — see the module comment for what decoding it produces.
#[derive(Clone, Debug, Default)]
pub struct StringTable {
    /// Where the table's tag word sits, which is the base every reference is
    /// relative to.
    pub tag_at: usize,
    /// Reference offset → the decoded string.
    entries: BTreeMap<u32, String>,
    /// Set when the table's own walk stopped short.
    pub incomplete: Option<String>,
}

impl StringTable {
    /// How many entries the table holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve a reference, or `None` when the table does not hold an entry at
    /// that offset.
    ///
    /// `None` is a refusal, not a miss: the offsets are exactly those the table
    /// walk found, so anything else points into the middle of an entry or
    /// outside the table, and decoding from there manufactures a string.
    pub fn resolve(&self, reference: u32) -> Option<&str> {
        self.entries.get(&reference).map(String::as_str)
    }

    /// Every reference the table holds, for a caller that needs the population.
    pub fn references(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries.keys().copied()
    }
}

/// Build the string table from a walked stream.
///
/// `None` when the stream holds no string table — which no real database does,
/// so its absence is itself worth a caller's attention.
pub fn build(body: &[u8], tags: &[Tag]) -> Option<StringTable> {
    let table = tags
        .iter()
        .find(|t| t.tag == TAG_STRINGTABLE && t.depth == 0)?;

    let mut out = StringTable {
        tag_at: table.at,
        ..Default::default()
    };
    let end = table
        .payload_at
        .saturating_add(table.payload_len)
        .min(body.len());
    let mut p = table.payload_at;

    while p + ENTRY_HEADER <= end {
        let tag = u16::from_le_bytes([body[p], body[p + 1]]);
        let len = u32::from_le_bytes([body[p + 2], body[p + 3], body[p + 4], body[p + 5]]) as usize;
        // The entries are `STRING`-typed. A tag of another type means the walk
        // has lost the entry boundary, and continuing would read lengths out of
        // string data.
        if TagType::from_tag(tag) != Some(TagType::StringData) {
            out.incomplete = Some(format!(
                "The string table's entry at offset {} carries the tag 0x{tag:04X}, which is \
                 not a string. The entries after it were not read, so a reference into them \
                 will not resolve — and will be reported as unresolved rather than decoded \
                 from bytes whose boundaries are not known.",
                p - table.at
            ));
            break;
        }
        let data_at = p + ENTRY_HEADER;
        if data_at + len > end {
            out.incomplete = Some(format!(
                "The string table's entry at offset {} declares {len} bytes, which run past \
                 the end of the table. It and anything after it were not read.",
                p - table.at
            ));
            break;
        }
        // The reference is relative to the TABLE'S TAG, not its payload. Six
        // bytes, and getting it wrong yields strings rather than an error.
        let reference = (p - table.at) as u32;
        out.entries
            .insert(reference, utf16le(&body[data_at..data_at + len]));
        p = data_at + len;
    }
    Some(out)
}

/// Decode UTF-16LE, dropping the trailing NUL the format includes in the
/// length.
///
/// Lossy on purpose: a string this build cannot decode cleanly is still
/// evidence, and replacing an unpaired surrogate is better than dropping the
/// entry that held it.
fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
