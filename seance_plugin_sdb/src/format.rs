//! The shim-database tag stream.
//!
//! # What an `.sdb` is
//!
//! Windows' application-compatibility shim databases. `sysmain.sdb` ships with
//! the operating system and holds the compatibility fixes for thousands of
//! programs; a **custom** `.sdb` installed with `sdbinst.exe` is a documented
//! persistence and defence-evasion technique, because a shim can inject a DLL
//! into a process the shimmed program starts.
//!
//! `ROADMAP` §1.7.
//!
//! # The format, as measured
//!
//! Twelve-byte header: major `u32`, minor `u32`, then a four-byte magic —
//! `sdbf` for a plain database, `zdbf` for a compressed one. The tag stream
//! starts at byte 12.
//!
//! Each tag is a little-endian `u16`: the top nibble is a **type**, the low
//! twelve bits an **id**. The type decides the size of what follows, so a
//! reader that does not know a tag's id can still walk past it — which is what
//! makes an honest census of unnamed tags possible at all.
//!
//! All seven databases staged from the Windows 11 ARM64 ISO consume **exactly**
//! from byte 12 to EOF under this walk, and each has the same three top-level
//! tags in the same order: `0x7802`, `0x7001`, `0x7801`.
//!
//! # The thing only real files taught
//!
//! Nine `QWORD` tags (id `0x53DB`) in `sysmain.sdb` and `appraiser.sdb` begin
//! inside their parent list and **end three bytes past its declared size**.
//!
//! That is in Microsoft's own shipped files. A reader has three choices and two
//! of them fabricate: clamping the read to the parent yields a wrong 64-bit
//! number, and reading past the parent trusts a length the parent contradicts.
//! So the tag is reported with **no value** and the overrun is stated. The
//! parent's declared size remains what the outer walk follows — following it is
//! what makes the file consume exactly.

use std::fmt;

/// Bytes of the file header before the tag stream.
pub const HEADER_BYTES: usize = 12;

/// Magic of a plain database.
pub const MAGIC_SDBF: &[u8; 4] = b"sdbf";
/// Magic of a zlib-compressed database.
pub const MAGIC_ZDBF: &[u8; 4] = b"zdbf";

/// The major version this build has measured. Anything else is stamped
/// `unvalidated` rather than refused: the tag stream may still walk, and
/// refusing would lose a database over a number in its header.
pub const KNOWN_MAJOR_VERSION: u32 = 3;

/// How deep the walk will nest before it calls the stream hostile.
///
/// The deepest real database nests 5. A crafted one can nest a list inside
/// itself indefinitely, and in an ingest pipeline an unbounded recursion is an
/// outage rather than a parse error.
pub const MAX_DEPTH: usize = 32;

/// How many tags the walk will read before it stops.
///
/// The largest real database holds 499,083. The ceiling is generous and finite:
/// a crafted stream of two-byte NULL tags would otherwise emit one record per
/// two bytes of a multi-gigabyte file.
pub const MAX_TAGS: usize = 4_000_000;

/// A tag's type, from the top nibble of its `u16`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagType {
    /// No payload.
    Null,
    Byte,
    Word,
    Dword,
    Qword,
    /// A four-byte offset into the string table.
    StringRef,
    /// A `u32` length, then child tags.
    List,
    /// A `u32` length, then UTF-16LE.
    StringData,
    /// A `u32` length, then bytes.
    Binary,
}

impl TagType {
    /// The type a tag word declares, or `None` for a nibble the format does not
    /// define — which is where a walk must stop rather than guess a size.
    pub fn from_tag(tag: u16) -> Option<Self> {
        match tag >> 12 {
            0x1 => Some(Self::Null),
            0x2 => Some(Self::Byte),
            0x3 => Some(Self::Word),
            0x4 => Some(Self::Dword),
            0x5 => Some(Self::Qword),
            0x6 => Some(Self::StringRef),
            0x7 => Some(Self::List),
            0x8 => Some(Self::StringData),
            0x9 => Some(Self::Binary),
            _ => None,
        }
    }

    /// Bytes of payload for a fixed-size type; `None` for the three that
    /// declare their own length.
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            Self::Null => Some(0),
            Self::Byte => Some(1),
            Self::Word => Some(2),
            Self::Dword => Some(4),
            Self::Qword => Some(8),
            Self::StringRef => Some(4),
            Self::List | Self::StringData | Self::Binary => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Byte => "byte",
            Self::Word => "word",
            Self::Dword => "dword",
            Self::Qword => "qword",
            Self::StringRef => "stringref",
            Self::List => "list",
            Self::StringData => "string",
            Self::Binary => "binary",
        }
    }
}

/// Why a walk stopped short of the end of the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalkLimit {
    /// A tag word whose type nibble the format does not define. The walk cannot
    /// know how many bytes to skip, so it stops here rather than guessing.
    UndefinedType { at: usize, tag: u16 },
    /// A sized tag whose length runs past the end of the stream.
    LengthPastEnd { at: usize, tag: u16, declared: u64 },
    /// The nesting ceiling.
    DepthCeiling { at: usize },
    /// The tag ceiling.
    TagCeiling,
    /// Fewer than two bytes remain, so there is no tag word to read.
    Trailing { at: usize, bytes: usize },
}

impl fmt::Display for WalkLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndefinedType { at, tag } => write!(
                f,
                "the tag 0x{tag:04X} at byte {at} declares type nibble 0x{:X}, which this \
                 format does not define; the walk cannot know its size and stopped here \
                 rather than guessing one",
                tag >> 12
            ),
            Self::LengthPastEnd { at, tag, declared } => write!(
                f,
                "the tag 0x{tag:04X} at byte {at} declares {declared} bytes, which run past \
                 the end of the stream"
            ),
            Self::DepthCeiling { at } => write!(
                f,
                "the tag stream nests deeper than {MAX_DEPTH} at byte {at}; the deepest real \
                 database nests 5, and an unbounded recursion in an ingest is an outage"
            ),
            Self::TagCeiling => write!(
                f,
                "the tag ceiling of {MAX_TAGS} was reached; the largest real database holds \
                 499,083"
            ),
            Self::Trailing { at, bytes } => {
                write!(f, "{bytes} byte(s) remain at {at}, fewer than a tag word")
            }
        }
    }
}

/// One tag, as walked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    /// Byte offset of the tag word within the stream.
    pub at: usize,
    pub tag: u16,
    pub tag_type: TagType,
    /// Depth below the top level.
    pub depth: usize,
    /// Byte offset of the payload.
    pub payload_at: usize,
    /// Payload length.
    pub payload_len: usize,
    /// Set when the payload extends past the parent list's declared end.
    ///
    /// The tag is reported and its value is **not** decoded. See the module
    /// comment: this is real, in Microsoft's own files, and both ways of
    /// "handling" it fabricate.
    pub overruns_parent_by: Option<usize>,
}

impl Tag {
    /// The tag's twelve-bit id.
    pub fn id(&self) -> u16 {
        self.tag & 0x0FFF
    }

    /// Whether this tag's payload can be read at all.
    pub fn value_readable(&self) -> bool {
        self.overruns_parent_by.is_none()
    }
}

/// The result of walking a tag stream.
#[derive(Clone, Debug, Default)]
pub struct Walk {
    pub tags: Vec<Tag>,
    /// Byte offset the walk reached. Equal to the stream length on all seven
    /// real databases.
    pub reached: usize,
    /// Why it stopped short, if it did.
    pub limit: Option<WalkLimit>,
}

impl Walk {
    /// Whether the walk consumed the whole stream.
    pub fn complete(&self, stream_len: usize) -> bool {
        self.limit.is_none() && self.reached == stream_len
    }
}

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Walk the tag stream of `body`, which must be the whole file including its
/// twelve-byte header.
pub fn walk(body: &[u8]) -> Walk {
    let mut out = Walk::default();
    if body.len() < HEADER_BYTES {
        out.limit = Some(WalkLimit::Trailing {
            at: 0,
            bytes: body.len(),
        });
        return out;
    }
    let end = body.len();
    out.reached = walk_range(body, HEADER_BYTES, end, 0, &mut out.tags, &mut out.limit);
    out
}

/// Walk `[start, end)`, returning the offset reached.
fn walk_range(
    d: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    tags: &mut Vec<Tag>,
    limit: &mut Option<WalkLimit>,
) -> usize {
    if depth >= MAX_DEPTH {
        if limit.is_none() {
            *limit = Some(WalkLimit::DepthCeiling { at: start });
        }
        return start;
    }
    let mut p = start;
    while p + 2 <= end {
        if tags.len() >= MAX_TAGS {
            if limit.is_none() {
                *limit = Some(WalkLimit::TagCeiling);
            }
            return p;
        }
        let Some(tag) = le_u16(d, p) else {
            return p;
        };
        let Some(tag_type) = TagType::from_tag(tag) else {
            if limit.is_none() {
                *limit = Some(WalkLimit::UndefinedType { at: p, tag });
            }
            return p;
        };
        let word_at = p;
        p += 2;

        let (payload_at, payload_len) = match tag_type.fixed_size() {
            Some(n) => (p, n),
            None => {
                let Some(declared) = le_u32(d, p) else {
                    if limit.is_none() {
                        *limit = Some(WalkLimit::LengthPastEnd {
                            at: word_at,
                            tag,
                            declared: 0,
                        });
                    }
                    return word_at;
                };
                p += 4;
                let declared = declared as usize;
                // A length past the end of the STREAM is unreadable. A length
                // past the parent is a different thing, handled below.
                if p.saturating_add(declared) > d.len() {
                    if limit.is_none() {
                        *limit = Some(WalkLimit::LengthPastEnd {
                            at: word_at,
                            tag,
                            declared: declared as u64,
                        });
                    }
                    return word_at;
                }
                (p, declared)
            }
        };

        // Does the payload finish inside the region we were told to walk?
        let payload_end = payload_at.saturating_add(payload_len);
        let overruns_parent_by = (payload_end > end).then(|| payload_end - end);

        tags.push(Tag {
            at: word_at,
            tag,
            tag_type,
            depth,
            payload_at,
            payload_len,
            overruns_parent_by,
        });

        if tag_type == TagType::List {
            // A list's children are walked inside its own declared bounds. The
            // walk then resumes at the list's declared end, which is what makes
            // every real database consume exactly even where a child straddles
            // that boundary.
            walk_range(
                d,
                payload_at,
                payload_end.min(d.len()),
                depth + 1,
                tags,
                limit,
            );
        }
        p = payload_end.min(d.len());
        if p > end {
            // The straddling child took us past our own region; stop where the
            // region ends and let the caller resume from its declared bound.
            return end;
        }
    }
    if p < end {
        // Fewer than two bytes left in this region. At the top level that is
        // trailing data worth naming; inside a list it is padding.
        if depth == 0 && limit.is_none() && end - p > 0 {
            *limit = Some(WalkLimit::Trailing {
                at: p,
                bytes: end - p,
            });
        }
        return end;
    }
    p
}
