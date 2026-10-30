//! Firehose entries (`0x6001`) inside a decompressed `.tracev3` chunkset,
//! parsed to **unresolved references**: every tracepoint's kind, time, thread,
//! the location of its format string and its argument items — but no text.
//! Turning a reference into a sentence needs the same machine's `uuidtext` and
//! `dsc` catalogues; that is [`crate::unifiedlog_resolve`]'s job.
//!
//! # Layout
//!
//! A firehose entry's payload opens with a 32-byte preamble: `u64` first and
//! `u32` second process id (the pair a catalog's process entries are keyed
//! on), `u8` ttl, `u8` collapsed, 2 reserved bytes, then — the point private
//! data offsets are counted from — `u16` public-data size (counting itself and
//! the 14 bytes after it), `u16` private-data virtual offset (`0x1000` when the
//! entry holds no private data), two `u16` unknowns and the `u64` base
//! continuous time.
//!
//! The public data is a run of tracepoints, each a 24-byte header — `u8`
//! activity type (`0x2` activity, `0x3` trace, `0x4` log, `0x6` signpost,
//! `0x7` loss), `u8` log type, `u16` flags, `u32` format-string offset, `u64`
//! thread id, `u32` + `u16` continuous-time delta, `u16` data size — then that
//! many bytes, padded to 8. The data holds type-specific fields selected by
//! the flags, the formatter fields that say where the format string lives
//! (main executable, shared cache, absolute, UUID-relative), and then the
//! argument items: a `u8` and a `u8` count, each item a `u8` type and `u8`
//! size, numbers inline, strings as a `u16` offset and `u16` size into the
//! string area after the items (and after any backtrace).
//!
//! Private arguments are not in the public data. Where the machine recorded
//! them the entry carries a private region, and they are read from it; where
//! it did not, the item is **reported as withheld (`<private>`), never as an
//! empty value**, because an empty argument and a withheld one are different
//! facts.
//!
//! The field layout was read against the corpus fixtures and follows the
//! community reading in Mandiant's `macos-UnifiedLogs` (Apache-2.0) and
//! libyal's dtformats notes; neither is the answer to what a file says.

use crate::unifiedlog_chunks::pad8;

/// Bytes in a firehose preamble after the entry's own 16-byte preamble.
const PREAMBLE_BYTES: usize = 32;
/// Offset, inside the preamble, that private offsets are counted from.
const PRIVATE_BASE: usize = 16;
/// Bytes in a tracepoint header.
const TRACEPOINT_BYTES: usize = 24;
/// The private-data virtual offset that means "no private data".
const NO_PRIVATE_DATA: u16 = 0x1000;

pub(crate) const ACTIVITY: u8 = 0x2;
pub(crate) const TRACE: u8 = 0x3;
pub(crate) const LOG: u8 = 0x4;
pub(crate) const SIGNPOST: u8 = 0x6;
pub(crate) const LOSS: u8 = 0x7;

// Tracepoint flags.
const HAS_CURRENT_AID: u16 = 0x0001;
const HAS_UNIQUE_PID: u16 = 0x0010;
const HAS_LARGE_OFFSET: u16 = 0x0020;
const HAS_PERSONA: u16 = 0x0040;
const HAS_PRIVATE_DATA: u16 = 0x0100;
/// In a log or signpost entry: the subsystem. In an activity: another id.
const HAS_SUBSYSTEM_OR_OTHER_AID: u16 = 0x0200;
const HAS_RULES: u16 = 0x0400;
const HAS_OVERSIZE: u16 = 0x0800;
const HAS_CONTEXT_DATA: u16 = 0x1000;
const HAS_NAME: u16 = 0x8000;

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at.checked_add(8)?).map(|s| {
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        u64::from_le_bytes(b)
    })
}

/// Where a tracepoint's format string lives.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FormatLocation {
    /// The process's main executable's `uuidtext` entry.
    MainExe,
    /// The shared cache (`dsc`) the process's catalog entry names, at an
    /// offset widened by these two fields when they are set.
    SharedCache {
        large_offset: u16,
        large_shared_cache: u16,
        /// The `0xc` ("large shared cache") formatter rather than `0x4`.
        large_form: bool,
    },
    /// An image the process loaded, found by address in the catalog's
    /// per-process UUID table.
    Absolute { alt_index: u16 },
    /// The `uuidtext` entry named by this UUID, carried in the entry itself.
    UuidRelative(String),
    /// Formatter bits this reader does not know.
    Unknown(u16),
    /// The entry kind carries no format string (a loss record).
    NotApplicable,
}

impl FormatLocation {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::MainExe => "main_exe",
            Self::SharedCache { .. } => "shared_cache",
            Self::Absolute { .. } => "absolute",
            Self::UuidRelative(_) => "uuid_relative",
            Self::Unknown(_) => "unknown",
            Self::NotApplicable => "none",
        }
    }
}

/// One argument's value, as the entry holds it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ItemValue {
    Number(i64),
    Text(String),
    /// Arbitrary bytes the format string decodes (`%P`, `%{…}.*P`).
    Bytes(Vec<u8>),
    /// Withheld by the operating system: the machine did not record it.
    Private,
    /// A zero-length object argument, which the OS renders `(null)`.
    Null,
    /// A dynamic precision or width argument (`%.*s`).
    Precision(u64),
    /// The item points at bytes the entry does not hold.
    Missing,
}

/// One argument.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Item {
    pub(crate) item_type: u8,
    pub(crate) value: ItemValue,
    /// Read from the entry's private region rather than its public data.
    pub(crate) from_private_data: bool,
    /// The size the item declares for a value held elsewhere (a string area
    /// or the private region); 0 for inline values.
    pub(crate) declared_size: u16,
}

/// A loss record: the log dropped entries between two times.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Loss {
    pub(crate) start_time: u64,
    pub(crate) end_time: u64,
    pub(crate) count: u64,
}

/// One tracepoint, with its format string still a reference.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Tracepoint {
    pub(crate) activity_type: u8,
    pub(crate) log_type: u8,
    pub(crate) flags: u16,
    /// The format-string offset in the header, to be read per `location`.
    pub(crate) format_offset: u32,
    pub(crate) thread_id: u64,
    /// The chunk's base continuous time plus this entry's delta.
    pub(crate) continuous_time: u64,
    pub(crate) pc_id: Option<u32>,
    pub(crate) location: FormatLocation,
    pub(crate) subsystem_id: Option<u16>,
    pub(crate) activity_id: Option<u32>,
    pub(crate) unique_pid: Option<u64>,
    pub(crate) signpost_id: Option<u64>,
    pub(crate) signpost_name: Option<u32>,
    pub(crate) oversize_ref: Option<u32>,
    pub(crate) items: Vec<Item>,
    pub(crate) backtrace_frames: usize,
    pub(crate) loss: Option<Loss>,
    /// Why this tracepoint is less than whole, in words.
    pub(crate) flaw: Option<String>,
}

/// One firehose entry's tracepoints.
#[derive(Debug, Clone, Default)]
pub(crate) struct FirehoseChunk {
    /// The catalog process key; read by the resolver.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) first_proc_id: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) second_proc_id: u32,
    pub(crate) base_continuous_time: u64,
    pub(crate) collapsed: bool,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) private_virtual_offset: u16,
    pub(crate) tracepoints: Vec<Tracepoint>,
    /// Why the walk stopped early, in words.
    pub(crate) flaw: Option<String>,
}

/// Cursor over one tracepoint's data.
struct Cursor<'a> {
    d: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.d.get(self.at)?;
        self.at += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let v = le_u16(self.d, self.at)?;
        self.at += 2;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let v = le_u32(self.d, self.at)?;
        self.at += 4;
        Some(v)
    }
    fn u64(&mut self) -> Option<u64> {
        let v = le_u64(self.d, self.at)?;
        self.at += 8;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.d.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(v)
    }
    fn rest(&self) -> &'a [u8] {
        self.d.get(self.at..).unwrap_or_default()
    }
}

/// The formatter fields: where the format string lives.
fn formatter(c: &mut Cursor<'_>, flags: u16) -> Option<FormatLocation> {
    Some(match flags & 0x000e {
        0x0002 => FormatLocation::MainExe,
        0x0004 => {
            let large_offset = if flags & HAS_LARGE_OFFSET != 0 {
                c.u16()?
            } else {
                0
            };
            FormatLocation::SharedCache {
                large_offset,
                large_shared_cache: 0,
                large_form: false,
            }
        }
        0x000c => {
            let large_offset = if flags & HAS_LARGE_OFFSET != 0 {
                c.u16()?
            } else {
                0
            };
            let large_shared_cache = c.u16()?;
            FormatLocation::SharedCache {
                large_offset,
                large_shared_cache,
                large_form: true,
            }
        }
        0x0008 => FormatLocation::Absolute {
            alt_index: c.u16()?,
        },
        0x000a => {
            let uuid = c.take(16)?;
            FormatLocation::UuidRelative(uuid.iter().map(|b| format!("{b:02X}")).collect())
        }
        other => FormatLocation::Unknown(other),
    })
}

/// Item types whose value is an offset and size into a string area.
const STRING_ITEMS: [u8; 14] = [
    0x20, 0x21, 0x22, 0x25, 0x30, 0x31, 0x32, 0x35, 0x40, 0x41, 0x42, 0x81, 0xf1, 0xf2,
];
/// Of those, the ones whose value is in the private region.
const PRIVATE_STRING_ITEMS: [u8; 7] = [0x21, 0x25, 0x31, 0x35, 0x41, 0x81, 0xf1];
/// Arbitrary-data items, whose value is bytes rather than text.
const BYTES_ITEMS: [u8; 5] = [0x30, 0x31, 0x32, 0x35, 0xf2];
/// Numbers carried inline.
const NUMBER_ITEMS: [u8; 2] = [0x00, 0x02];
/// A private number (value, if recorded, in the private region).
const PRIVATE_NUMBER: u8 = 0x01;
/// A sensitive number (likewise).
const SENSITIVE_NUMBER: u8 = 0x05;
/// Sensitive items the OS always withholds.
const SENSITIVE_ITEMS: [u8; 2] = [0x45, 0x85];
/// Dynamic precision / width.
const PRECISION_ITEMS: [u8; 2] = [0x10, 0x12];
/// Object items, which render `(null)` at size 0.
const OBJECT_ITEMS: [u8; 2] = [0x40, 0x42];

fn number(bytes: &[u8]) -> Option<i64> {
    Some(match bytes.len() {
        1 => i64::from(bytes[0] as i8),
        2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        4 => i64::from(i32::from_le_bytes(bytes.try_into().ok()?)),
        8 => i64::from_le_bytes(bytes.try_into().ok()?),
        _ => return None,
    })
}

fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// An item as declared, before its value is found.
struct Declared {
    item_type: u8,
    inline: Option<Vec<u8>>,
    offset: u16,
    size: u16,
}

/// Read the item list, any backtrace, and the public values; private values
/// are filled in later from the private region. Returns the flaw, if any.
fn items(
    c: &mut Cursor<'_>,
    flags: u16,
    out: &mut Vec<Item>,
    backtrace_frames: &mut usize,
) -> Option<String> {
    // Fewer than six bytes cannot hold the item header and one item.
    if c.rest().len() < 6 {
        return None;
    }
    let (Some(_), Some(count)) = (c.u8(), c.u8()) else {
        return Some("the item header is cut short".into());
    };
    let mut declared: Vec<Declared> = Vec::with_capacity(count as usize);
    for n in 0..count {
        let (Some(item_type), Some(size)) = (c.u8(), c.u8()) else {
            push_declared(&declared, out);
            return Some(format!(
                "{count} items are declared and the entry holds bytes for {n}"
            ));
        };
        let mut d = Declared {
            item_type,
            inline: None,
            offset: 0,
            size: 0,
        };
        if NUMBER_ITEMS.contains(&item_type) || PRECISION_ITEMS.contains(&item_type) {
            let Some(b) = c.take(size as usize) else {
                push_declared(&declared, out);
                return Some(format!(
                    "{count} items are declared and the entry holds bytes for {n}"
                ));
            };
            d.inline = Some(b.to_vec());
        } else if STRING_ITEMS.contains(&item_type)
            || item_type == PRIVATE_NUMBER
            || item_type == SENSITIVE_NUMBER
            || SENSITIVE_ITEMS.contains(&item_type)
        {
            let (Some(offset), Some(sz)) = (c.u16(), c.u16()) else {
                push_declared(&declared, out);
                return Some(format!(
                    "{count} items are declared and the entry holds bytes for {n}"
                ));
            };
            d.offset = offset;
            d.size = sz;
        } else {
            push_declared(&declared, out);
            return Some(format!(
                "item {} of {count} has type {item_type:#04x}, which this reader does not know, \
                 so it and the items after it were not read",
                n + 1
            ));
        }
        declared.push(d);
    }

    // String offsets count from here, the end of the item list — a
    // backtrace, when there is one, sits first in that area and the offsets
    // step over it (seen on the Monterey corpus's LiveData, where the first
    // string of an entry with a 282-byte backtrace is at offset 282).
    let strings = c.rest();
    // A backtrace sits between the items and the strings, when the flag says
    // so or its signature is there.
    let rest = c.rest();
    if flags & HAS_CONTEXT_DATA != 0 || rest.starts_with(&[1, 0, 18]) {
        match backtrace(c) {
            Some(frames) => *backtrace_frames = frames,
            None => {
                push_declared(&declared, out);
                return Some("the backtrace runs past the end of the entry".into());
            }
        }
    }

    let mut flaw = None;
    for d in &declared {
        let value = if let Some(b) = &d.inline {
            if PRECISION_ITEMS.contains(&d.item_type) {
                ItemValue::Precision(number(b).map(|v| v as u64).unwrap_or_default())
            } else {
                match number(b) {
                    Some(v) => ItemValue::Number(v),
                    None => {
                        flaw.get_or_insert_with(|| {
                            format!("a number item is {} bytes wide, which is not a width this reader decodes", b.len())
                        });
                        ItemValue::Missing
                    }
                }
            }
        } else if PRIVATE_STRING_ITEMS.contains(&d.item_type)
            || d.item_type == PRIVATE_NUMBER
            || d.item_type == SENSITIVE_NUMBER
            || SENSITIVE_ITEMS.contains(&d.item_type)
        {
            // Filled from the private region, if the entry has one.
            ItemValue::Private
        } else if d.size == 0 && OBJECT_ITEMS.contains(&d.item_type) {
            ItemValue::Null
        } else {
            let size = (d.size & 0x7fff) as usize;
            match strings.get(d.offset as usize..d.offset as usize + size) {
                Some(b) if BYTES_ITEMS.contains(&d.item_type) => ItemValue::Bytes(b.to_vec()),
                Some(b) => ItemValue::Text(text(b)),
                None => {
                    flaw.get_or_insert_with(|| {
                        format!(
                            "a string argument points at bytes {}..{} of a {}-byte string area",
                            d.offset,
                            d.offset as usize + size,
                            strings.len()
                        )
                    });
                    ItemValue::Missing
                }
            }
        };
        out.push(Item {
            item_type: d.item_type,
            value,
            from_private_data: false,
            declared_size: d.size,
        });
    }
    flaw
}

/// Items read before a failure are kept, as `Missing`, so the count of what
/// was declared survives.
fn push_declared(declared: &[Declared], out: &mut Vec<Item>) {
    for d in declared {
        let value = match &d.inline {
            Some(b) if PRECISION_ITEMS.contains(&d.item_type) => {
                ItemValue::Precision(number(b).map(|v| v as u64).unwrap_or_default())
            }
            Some(b) => number(b)
                .map(ItemValue::Number)
                .unwrap_or(ItemValue::Missing),
            None => ItemValue::Missing,
        };
        out.push(Item {
            item_type: d.item_type,
            value,
            from_private_data: false,
            declared_size: d.size,
        });
    }
}

/// Skip a backtrace, returning its frame count.
fn backtrace(c: &mut Cursor<'_>) -> Option<usize> {
    c.take(3)?;
    let uuids = c.u8()? as usize;
    let frames = c.u16()? as usize;
    c.take(uuids * 16)?;
    c.take(frames * 4)?;
    c.take(frames)?;
    c.take((4 - frames % 4) % 4)?;
    Some(frames)
}

/// A trace entry's arguments are stored reversed: values, then sizes, then
/// the count, read from the end.
fn trace_items(data: &[u8], out: &mut Vec<Item>) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let mut r: Vec<u8> = data.to_vec();
    r.reverse();
    let count = r[0] as usize;
    let Some(sizes) = r.get(1..1 + count) else {
        return Some("the trace entry's argument sizes run past the entry".into());
    };
    let mut at = 1 + count;
    let mut values = Vec::new();
    for &size in sizes {
        let Some(b) = r.get(at..at + size as usize) else {
            return Some("a trace argument runs past the entry".into());
        };
        // Reversed bytes read big-endian are the little-endian value.
        let mut le = b.to_vec();
        le.reverse();
        values.push(match number(&le) {
            Some(v) => ItemValue::Number(v),
            None => ItemValue::Missing,
        });
        at += size as usize;
    }
    values.reverse();
    for v in values {
        out.push(Item {
            item_type: 0,
            value: v,
            from_private_data: false,
            declared_size: 0,
        });
    }
    None
}

/// Parse one tracepoint's type-specific data.
fn tracepoint_body(t: &mut Tracepoint, data: &[u8]) -> Option<(u16, u16)> {
    let mut c = Cursor { d: data, at: 0 };
    let flags = t.flags;
    let mut private_range = None;
    let short = |what: &str| format!("the {what} runs past the entry's {} bytes", data.len());
    macro_rules! need {
        ($e:expr, $what:expr) => {
            match $e {
                Some(v) => v,
                None => {
                    t.flaw = Some(short($what));
                    return private_range;
                }
            }
        };
    }
    match t.activity_type {
        LOG => {
            if flags & HAS_CURRENT_AID != 0 {
                t.activity_id = Some(need!(c.u32(), "activity id"));
                need!(c.u32(), "activity sentinel");
            }
            if flags & HAS_PERSONA != 0 {
                need!(c.u32(), "persona");
            }
            if flags & HAS_PRIVATE_DATA != 0 {
                let off = need!(c.u16(), "private range");
                let size = need!(c.u16(), "private range");
                private_range = Some((off, size));
            }
            t.pc_id = Some(need!(c.u32(), "pc id"));
            t.location = need!(formatter(&mut c, flags), "formatter");
            if flags & HAS_SUBSYSTEM_OR_OTHER_AID != 0 {
                t.subsystem_id = Some(need!(c.u16(), "subsystem"));
            }
            if flags & HAS_RULES != 0 {
                need!(c.u8(), "ttl");
            }
            if flags & HAS_OVERSIZE != 0 {
                t.oversize_ref = Some(need!(c.u32(), "oversize reference"));
            }
        }
        ACTIVITY => {
            if t.log_type != 0x3 {
                t.activity_id = Some(need!(c.u32(), "activity id"));
                need!(c.u32(), "activity sentinel");
            }
            if flags & HAS_UNIQUE_PID != 0 {
                t.unique_pid = Some(need!(c.u64(), "unique pid"));
            }
            if flags & HAS_CURRENT_AID != 0 {
                need!(c.u64(), "current activity id");
            }
            if flags & HAS_PERSONA != 0 {
                need!(c.u32(), "persona");
            }
            if flags & HAS_SUBSYSTEM_OR_OTHER_AID != 0 {
                need!(c.u64(), "other activity id");
            }
            t.pc_id = Some(need!(c.u32(), "pc id"));
            t.location = need!(formatter(&mut c, flags), "formatter");
        }
        SIGNPOST => {
            if flags & HAS_CURRENT_AID != 0 {
                t.activity_id = Some(need!(c.u32(), "activity id"));
                need!(c.u32(), "activity sentinel");
            }
            if flags & HAS_PERSONA != 0 {
                need!(c.u32(), "persona");
            }
            if flags & HAS_PRIVATE_DATA != 0 {
                let off = need!(c.u16(), "private range");
                let size = need!(c.u16(), "private range");
                private_range = Some((off, size));
            }
            t.pc_id = Some(need!(c.u32(), "pc id"));
            t.location = need!(formatter(&mut c, flags), "formatter");
            if flags & HAS_SUBSYSTEM_OR_OTHER_AID != 0 {
                t.subsystem_id = Some(need!(c.u16(), "subsystem"));
            }
            t.signpost_id = Some(need!(c.u64(), "signpost id"));
            if flags & HAS_RULES != 0 {
                need!(c.u8(), "ttl");
            }
            if flags & HAS_OVERSIZE != 0 {
                t.oversize_ref = Some(need!(c.u32(), "oversize reference"));
            }
            if flags & HAS_NAME != 0 {
                let mut name = need!(c.u32(), "signpost name");
                let wide = match t.location {
                    FormatLocation::SharedCache {
                        large_offset,
                        large_shared_cache,
                        ..
                    } => large_offset != 0 || large_shared_cache != 0,
                    _ => false,
                };
                if wide {
                    need!(c.u16(), "signpost name");
                    name = name.wrapping_add(0x8000_0000);
                }
                t.signpost_name = Some(name);
            }
        }
        TRACE => {
            t.pc_id = Some(need!(c.u32(), "pc id"));
            t.location = FormatLocation::MainExe;
            if let Some(flaw) = trace_items(c.rest(), &mut t.items) {
                t.flaw = Some(flaw);
            }
            return private_range;
        }
        LOSS => {
            let start_time = need!(c.u64(), "loss record");
            let end_time = need!(c.u64(), "loss record");
            let count = need!(c.u64(), "loss record");
            t.loss = Some(Loss {
                start_time,
                end_time,
                count,
            });
            t.location = FormatLocation::NotApplicable;
            return private_range;
        }
        _ => {}
    }
    if let FormatLocation::Unknown(bits) = t.location {
        t.flaw = Some(format!(
            "the formatter bits {bits:#06x} name no format-string location this reader knows, \
             so the arguments after them were not read"
        ));
        return private_range;
    }
    let mut frames = 0;
    if let Some(flaw) = items(&mut c, flags, &mut t.items, &mut frames) {
        t.flaw = Some(flaw);
    }
    t.backtrace_frames = frames;
    private_range
}

/// Fill a tracepoint's private items from the entry's private region.
fn fill_private(t: &mut Tracepoint, region: &[u8], start: usize) {
    if fill_private_items(&mut t.items, region, start) && t.flaw.is_none() {
        t.flaw = Some("a private argument runs past the entry's private region".into());
    }
}

/// Fill private items, in order, from `region` starting at `start`. True
/// when one ran past the region (it is then `Missing`).
fn fill_private_items(items: &mut [Item], region: &[u8], start: usize) -> bool {
    let mut at = start;
    let mut short = false;
    for item in items.iter_mut() {
        let is_private_string = PRIVATE_STRING_ITEMS.contains(&item.item_type);
        let is_private_number =
            item.item_type == PRIVATE_NUMBER || item.item_type == SENSITIVE_NUMBER;
        if !(is_private_string || is_private_number) || item.value != ItemValue::Private {
            continue;
        }
        // A size of zero — or, for a number, the bare 0x8000 marker — is the
        // OS saying it recorded nothing: the item stays withheld.
        let size = match item.declared_size {
            0 | 0x8000 => continue,
            s => (s & 0x7fff) as usize,
        };
        let Some(b) = region.get(at..at + size) else {
            short = true;
            item.value = ItemValue::Missing;
            continue;
        };
        at += size;
        item.from_private_data = true;
        item.value = if is_private_number {
            number(b)
                .map(ItemValue::Number)
                .unwrap_or(ItemValue::Missing)
        } else if BYTES_ITEMS.contains(&item.item_type) {
            ItemValue::Bytes(b.to_vec())
        } else {
            ItemValue::Text(text(b))
        };
    }
    short
}

/// Parse a firehose entry's payload (the bytes after its 16-byte entry
/// preamble). `None` when not even the firehose preamble fits.
pub(crate) fn parse_firehose(payload: &[u8]) -> Option<FirehoseChunk> {
    let pre = payload.get(..PREAMBLE_BYTES)?;
    let public_size = le_u16(pre, 16)? as usize;
    let private_virtual_offset = le_u16(pre, 18)?;
    let mut chunk = FirehoseChunk {
        first_proc_id: le_u64(pre, 0)?,
        second_proc_id: le_u32(pre, 8)?,
        collapsed: pre[13] == 1,
        private_virtual_offset,
        base_continuous_time: le_u64(pre, 24)?,
        ..Default::default()
    };
    // The public size counts itself and the 14 bytes after it.
    let public_len = public_size.saturating_sub(16);
    let public_end = PREAMBLE_BYTES + public_len;
    let public = match payload.get(PREAMBLE_BYTES..public_end) {
        Some(p) => p,
        None => {
            chunk.flaw = Some(format!(
                "the preamble declares {public_len} bytes of public data and the entry holds {}",
                payload.len() - PREAMBLE_BYTES
            ));
            &payload[PREAMBLE_BYTES..]
        }
    };

    let mut ranges: Vec<Option<(u16, u16)>> = Vec::new();
    let mut at = 0usize;
    while at + TRACEPOINT_BYTES <= public.len() {
        let h = &public[at..at + TRACEPOINT_BYTES];
        let activity_type = h[0];
        if activity_type == 0 {
            // Zero after the last tracepoint: the rest is remnant space.
            break;
        }
        let data_size = le_u16(h, 22).unwrap_or_default() as usize;
        let start = at + TRACEPOINT_BYTES;
        let Some(data) = public.get(start..start + data_size) else {
            chunk.flaw.get_or_insert_with(|| {
                format!(
                    "tracepoint {} declares {data_size} bytes and runs past the public data, so \
                     it and anything after it were not read",
                    chunk.tracepoints.len() + 1
                )
            });
            break;
        };
        let delta = u64::from(le_u32(h, 16).unwrap_or_default())
            | (u64::from(le_u16(h, 20).unwrap_or_default()) << 32);
        let mut t = Tracepoint {
            activity_type,
            log_type: h[1],
            flags: le_u16(h, 2).unwrap_or_default(),
            format_offset: le_u32(h, 4).unwrap_or_default(),
            thread_id: le_u64(h, 8).unwrap_or_default(),
            continuous_time: chunk.base_continuous_time.wrapping_add(delta),
            pc_id: None,
            location: FormatLocation::NotApplicable,
            subsystem_id: None,
            activity_id: None,
            unique_pid: None,
            signpost_id: None,
            signpost_name: None,
            oversize_ref: None,
            items: Vec::new(),
            backtrace_frames: 0,
            loss: None,
            flaw: None,
        };
        if ![ACTIVITY, TRACE, LOG, SIGNPOST, LOSS].contains(&activity_type) {
            t.flaw = Some(format!(
                "activity type {activity_type:#04x} is not one this reader knows; the \
                 tracepoint's header is reported and its data is not read"
            ));
            ranges.push(None);
        } else {
            ranges.push(tracepoint_body(&mut t, data));
        }
        chunk.tracepoints.push(t);
        at = start + data_size + pad8(data_size);
    }

    // Private values, where the entry recorded any.
    if private_virtual_offset != NO_PRIVATE_DATA {
        let private_len =
            usize::from(NO_PRIVATE_DATA - private_virtual_offset.min(NO_PRIVATE_DATA));
        let from_base = PRIVATE_BASE + usize::from(private_virtual_offset);
        // A collapsed entry — or one whose virtual offset lies past the bytes
        // held — keeps its private region straight after the public data.
        let region = if chunk.collapsed || from_base > payload.len() {
            payload.get(public_end..public_end + private_len)
        } else {
            payload.get(from_base..)
        };
        match region {
            Some(region) => {
                for (t, range) in chunk.tracepoints.iter_mut().zip(&ranges) {
                    if let Some((offset, size)) = range {
                        if *size == 0 {
                            continue;
                        }
                        let start = usize::from(offset.saturating_sub(private_virtual_offset));
                        fill_private(t, region, start);
                    }
                }
            }
            None => {
                chunk.flaw.get_or_insert_with(|| {
                    format!(
                        "the entry declares {private_len} bytes of private data that it does \
                         not hold, so its private arguments are reported as withheld"
                    )
                });
            }
        }
    }
    Some(chunk)
}

/// Bytes of an oversize entry's header, after its 16-byte entry preamble.
const OVERSIZE_HEADER_BYTES: usize = 32;

/// An oversize entry (`0x6002`): the arguments of one tracepoint too large for
/// its firehose entry, joined to it by the process pair and `data_ref`.
///
/// After the entry preamble: `u64` first and `u32` second process id, `u8`
/// ttl, three reserved bytes, `u64` continuous time, `u32` data reference,
/// `u16` public-data size and `u16` private-data size; then the public data —
/// the same item list and string area a firehose tracepoint carries — and the
/// private data, from which private items are read in order.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Oversize {
    pub(crate) first_proc_id: u64,
    pub(crate) second_proc_id: u32,
    pub(crate) continuous_time: u64,
    pub(crate) data_ref: u32,
    pub(crate) items: Vec<Item>,
    /// Why the entry is less than whole, in words.
    pub(crate) flaw: Option<String>,
}

/// Parse an oversize entry's payload (the bytes after its 16-byte entry
/// preamble). `None` when not even its header fits.
pub(crate) fn parse_oversize(payload: &[u8]) -> Option<Oversize> {
    let h = payload.get(..OVERSIZE_HEADER_BYTES)?;
    let public_len = usize::from(le_u16(h, 28)?);
    let private_len = usize::from(le_u16(h, 30)?);
    let mut o = Oversize {
        first_proc_id: le_u64(h, 0)?,
        second_proc_id: le_u32(h, 8)?,
        continuous_time: le_u64(h, 16)?,
        data_ref: le_u32(h, 24)?,
        ..Default::default()
    };
    let body = &payload[OVERSIZE_HEADER_BYTES..];
    let public = match body.get(..public_len) {
        Some(p) => p,
        None => {
            o.flaw = Some(format!(
                "the entry declares {public_len} bytes of public data and holds {}",
                body.len()
            ));
            body
        }
    };
    let mut c = Cursor { d: public, at: 0 };
    let mut frames = 0;
    if let Some(flaw) = items(&mut c, 0, &mut o.items, &mut frames) {
        o.flaw.get_or_insert(flaw);
    }
    if private_len > 0 {
        let region = body
            .get(public_len..public_len + private_len)
            .or_else(|| body.get(public_len.min(body.len())..));
        let held = region.map_or(0, <[u8]>::len);
        if held < private_len {
            o.flaw.get_or_insert_with(|| {
                format!("the entry declares {private_len} bytes of private data and holds {held}")
            });
        }
        if fill_private_items(&mut o.items, region.unwrap_or_default(), 0) {
            o.flaw
                .get_or_insert_with(|| "a private argument runs past the private data".into());
        }
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    /// The payload of the single firehose entry a fixture file holds.
    fn fixture_payload(rel: &str) -> Option<Vec<u8>> {
        let p = corpus().join(rel);
        let Ok(raw) = std::fs::read(&p) else {
            eprintln!("skipping: {} is not present", p.display());
            return None;
        };
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 0x6001);
        let size = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
        Some(raw[16..16 + size].to_vec())
    }

    fn texts(chunk: &FirehoseChunk) -> Vec<(String, bool)> {
        chunk
            .tracepoints
            .iter()
            .flat_map(|t| t.items.iter())
            .filter_map(|i| match &i.value {
                ItemValue::Text(s) => Some((s.clone(), i.from_private_data)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_big_sur_firehose_chunkset_yields_its_tracepoints() {
        let Some(p) = fixture_payload("Chunkset Tests/big_sur_firehose_chunkset.raw") else {
            return;
        };
        let chunk = parse_firehose(&p).expect("a firehose entry");
        assert!(chunk.flaw.is_none(), "{:?}", chunk.flaw);
        assert_eq!((chunk.first_proc_id, chunk.second_proc_id), (0x69, 0xec));
        assert_eq!(chunk.tracepoints.len(), BIG_SUR_FIREHOSE_TRACEPOINTS);
        let first = &chunk.tracepoints[0];
        assert_eq!(first.activity_type, BIG_SUR_FIRST.0);
        assert_eq!(first.format_offset, BIG_SUR_FIRST.1);
        assert_eq!(first.location.as_str(), BIG_SUR_FIRST.2);
        assert!(chunk.tracepoints.iter().all(|t| t.flaw.is_none()));
    }

    #[test]
    fn private_items_are_marked_private_not_rendered_empty() {
        // An entry with no private region: every private argument is
        // reported as withheld — never as an empty string.
        let Some(p) = fixture_payload("Chunkset Tests/big_sur_firehose_chunkset.raw") else {
            return;
        };
        let chunk = parse_firehose(&p).expect("a firehose entry");
        assert_eq!(chunk.private_virtual_offset, 0x1000, "no private region");
        let private_typed: Vec<&Item> = chunk
            .tracepoints
            .iter()
            .flat_map(|t| t.items.iter())
            .filter(|i| {
                [
                    0x01, 0x05, 0x21, 0x25, 0x31, 0x35, 0x41, 0x45, 0x81, 0x85, 0xf1,
                ]
                .contains(&i.item_type)
            })
            .collect();
        assert!(
            !private_typed.is_empty(),
            "the fixture holds private arguments"
        );
        assert!(private_typed.iter().all(|i| i.value == ItemValue::Private));

        // An entry whose private region is zeros: the machine did record the
        // arguments, and what it recorded was a one-byte empty string. That is
        // read as recorded, marked as private data, and is not "withheld".
        let Some(p) = fixture_payload("Chunkset Tests/big_sur_firehose_private_zeros.raw") else {
            return;
        };
        let chunk = parse_firehose(&p).expect("a firehose entry");
        assert_eq!(
            chunk.tracepoints.len(),
            10,
            "Mandiant's reading also has 10"
        );
        assert!(chunk.collapsed);
        let recorded: Vec<&Item> = chunk
            .tracepoints
            .iter()
            .flat_map(|t| t.items.iter())
            .filter(|i| i.from_private_data)
            .collect();
        assert!(!recorded.is_empty());
        assert!(recorded
            .iter()
            .all(|i| i.value == ItemValue::Text(String::new())));

        // A machine that recorded real private values: read from the private
        // region and marked as coming from it, beside a public one in the
        // same entry.
        let Some(p) = fixture_payload("Chunkset Tests/private_public_data.raw") else {
            return;
        };
        let chunk = parse_firehose(&p).expect("a firehose entry");
        assert_eq!(
            chunk.tracepoints.len(),
            51,
            "Mandiant's reading also has 51"
        );
        let t = texts(&chunk);
        assert!(t.contains(&("EMAIL_PRIVATE_LINK_MENU_TITLE".into(), true)));
        assert!(t.contains(&("Send private link by email \u{2026}".into(), false)));
    }

    /// A tracepoint header, then `data`, padded.
    fn tracepoint(kind: u8, flags: u16, fmt: u32, data: &[u8], out: &mut Vec<u8>) {
        out.push(kind);
        out.push(0);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&fmt.to_le_bytes());
        out.extend_from_slice(&7u64.to_le_bytes()); // thread
        out.extend_from_slice(&100u32.to_le_bytes()); // delta
        out.extend_from_slice(&0u16.to_le_bytes()); // delta upper
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0u8, (8 - data.len() % 8) % 8));
    }

    fn preamble(public: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&5u64.to_le_bytes());
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&((public.len() + 16) as u16).to_le_bytes());
        out.extend_from_slice(&0x1000u16.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&1_000u64.to_le_bytes());
        out.extend_from_slice(public);
        out
    }

    #[test]
    fn a_synthetic_log_entry_carries_its_reference_items_and_time() {
        // A log entry, main_exe (flags 0x2), pc_id, then one number item
        // and one public string item.
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu32.to_le_bytes()); // pc_id
        data.extend_from_slice(&[0x02, 2]); // unknown, 2 items
        data.extend_from_slice(&[0x00, 4]);
        data.extend_from_slice(&42i32.to_le_bytes());
        data.extend_from_slice(&[0x22, 4]);
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(b"hello\0");
        let mut public = Vec::new();
        tracepoint(LOG, 0x0002, 0x1234, &data, &mut public);
        let chunk = parse_firehose(&preamble(&public)).expect("an entry");
        assert_eq!(chunk.tracepoints.len(), 1);
        let t = &chunk.tracepoints[0];
        assert_eq!(t.location, FormatLocation::MainExe);
        assert_eq!(t.format_offset, 0x1234);
        assert_eq!(t.continuous_time, 1_100);
        assert_eq!(t.thread_id, 7);
        assert_eq!(t.pc_id, Some(0xABCD));
        assert_eq!(t.items[0].value, ItemValue::Number(42));
        assert_eq!(t.items[1].value, ItemValue::Text("hello".into()));
        assert!(t.flaw.is_none());
    }

    #[test]
    fn a_tracepoint_whose_item_run_overflows_the_entry_is_marked_incomplete() {
        // Three items declared, bytes for one.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[0x02, 3]);
        data.extend_from_slice(&[0x00, 4]);
        data.extend_from_slice(&1i32.to_le_bytes());
        let mut public = Vec::new();
        tracepoint(LOG, 0x0002, 0, &data, &mut public);
        let chunk = parse_firehose(&preamble(&public)).expect("an entry");
        let t = &chunk.tracepoints[0];
        assert_eq!(t.items.len(), 1, "the item that was there is kept");
        assert!(t.flaw.as_deref().unwrap().contains("items"));

        // A string item pointing past the string area is Missing, not empty.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[0x02, 1, 0x22, 4]);
        data.extend_from_slice(&40u16.to_le_bytes());
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(b"hi\0");
        let mut public = Vec::new();
        tracepoint(LOG, 0x0002, 0, &data, &mut public);
        let chunk = parse_firehose(&preamble(&public)).expect("an entry");
        let t = &chunk.tracepoints[0];
        assert_eq!(t.items[0].value, ItemValue::Missing);
        assert!(t.flaw.is_some());

        // A tracepoint whose data size runs past the public data stops the
        // walk with the earlier ones kept.
        let mut public = Vec::new();
        tracepoint(LOG, 0x0002, 0, &[0, 0, 0, 0], &mut public);
        let mut bad = Vec::new();
        tracepoint(LOG, 0x0002, 0, &[0; 8], &mut bad);
        bad[22] = 0xff; // data size 0x00ff, far past the bytes held
        public.extend_from_slice(&bad);
        let chunk = parse_firehose(&preamble(&public)).expect("an entry");
        assert_eq!(chunk.tracepoints.len(), 1);
        assert!(chunk.flaw.as_deref().unwrap().contains("runs past"));
    }

    #[test]
    fn a_loss_record_says_how_many_entries_were_dropped() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u64.to_le_bytes());
        data.extend_from_slice(&20u64.to_le_bytes());
        data.extend_from_slice(&3u64.to_le_bytes());
        let mut public = Vec::new();
        tracepoint(LOSS, 0, 0, &data, &mut public);
        let chunk = parse_firehose(&preamble(&public)).expect("an entry");
        assert_eq!(
            chunk.tracepoints[0].loss,
            Some(Loss {
                start_time: 10,
                end_time: 20,
                count: 3
            })
        );
        assert_eq!(chunk.tracepoints[0].location, FormatLocation::NotApplicable);
    }

    /// Every firehose entry in every `.tracev3` of the six corpus archives,
    /// walked: the count of tracepoints and of those this reader could not
    /// read whole. The breadth check for the parser; the flaw count is pinned
    /// so that a change in it is seen.
    #[allow(clippy::type_complexity)]
    pub(crate) fn corpus_firehose_census() -> Option<(
        usize,
        usize,
        Vec<String>,
        std::collections::BTreeMap<String, (usize, usize)>,
    )> {
        use crate::unifiedlog_chunks::{decompress_chunkset, walk_entries, TAG_FIREHOSE};
        let archives = std::fs::read_dir(corpus()).ok()?;
        let (mut total, mut flawed, mut samples) = (0usize, 0usize, Vec::new());
        let mut per_archive = std::collections::BTreeMap::new();
        for a in archives.flatten() {
            if !a.file_name().to_string_lossy().ends_with(".logarchive") {
                continue;
            }
            let before = total;
            let mut dumps = 0usize;
            let mut stack = vec![a.path()];
            while let Some(dir) = stack.pop() {
                for e in std::fs::read_dir(&dir).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                        continue;
                    }
                    if p.extension().is_none_or(|x| x != "tracev3") {
                        continue;
                    }
                    let d = std::fs::read(&p).unwrap();
                    let mut off = 0usize;
                    while off + 16 <= d.len() {
                        let tag = u32::from_le_bytes(d[off..off + 4].try_into().unwrap());
                        let size =
                            u64::from_le_bytes(d[off + 8..off + 16].try_into().unwrap()) as usize;
                        let Some(body) = d.get(off + 16..off + 16 + size) else {
                            break;
                        };
                        if tag == 0x600d {
                            let bytes = decompress_chunkset(body).unwrap();
                            for entry in walk_entries(&bytes).entries {
                                if entry.tag == 0x6003 || entry.tag == 0x6004 {
                                    dumps += 1;
                                }
                                if entry.tag != TAG_FIREHOSE {
                                    continue;
                                }
                                let chunk = parse_firehose(entry.payload).unwrap();
                                if let Some(f) = &chunk.flaw {
                                    if samples.len() < 12 {
                                        samples.push(format!("{p:?}: chunk: {f}"));
                                    }
                                }
                                for t in &chunk.tracepoints {
                                    total += 1;
                                    if let Some(f) = &t.flaw {
                                        flawed += 1;
                                        if samples.len() < 12 {
                                            samples.push(format!("{p:?}: {f}"));
                                        }
                                    }
                                }
                            }
                        }
                        off = off + 16 + size;
                        off += (8 - off % 8) % 8;
                    }
                }
            }
            per_archive.insert(
                a.file_name().to_string_lossy().into_owned(),
                (total - before, dumps),
            );
        }
        Some((total, flawed, samples, per_archive))
    }

    #[test]
    fn every_corpus_firehose_entry_is_read_or_its_flaw_is_said() {
        let Some((total, flawed, samples, per_archive)) = corpus_firehose_census() else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        assert_eq!((total, flawed), CORPUS_CENSUS, "{samples:#?}");
        // Per archive: firehose tracepoints, and statedump + simpledump
        // entries. As a comparison, not an answer key: Mandiant's tests quote
        // Apple's own `log raw-dump` as 747,294 entries for the Big Sur archive
        // — this reader's tracepoint count — and their all-logs totals equal
        // tracepoints + dumps here for High Sierra (569,796), Big Sur
        // (747,616) and Monterey (2,397,109). On Tahoe theirs is 4,288,584,
        // one more than this reader's 4,288,583; that entry is not attributed.
        let want: std::collections::BTreeMap<String, (usize, usize)> = [
            ("system_logs_high_sierra.logarchive", (569_583, 213)),
            ("system_logs_big_sur.logarchive", (747_294, 322)),
            (
                "system_logs_big_sur_private_enabled.logarchive",
                (887_406, 484),
            ),
            (
                "system_logs_big_sur_public_private_data_mix.logarchive",
                (1_287_385, 243),
            ),
            ("system_logs_monterey.logarchive", (2_233_905, 163_204)),
            ("system_logs_tahoe.logarchive", (4_175_071, 113_512)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(per_archive, want);
    }

    const CORPUS_CENSUS: (usize, usize) = (9_900_644, 0);

    /// The first oversize entry in a raw chunkset or entry file.
    fn oversize_payload(rel: &str) -> Option<Vec<u8>> {
        let p = corpus().join(rel);
        let Ok(raw) = std::fs::read(&p) else {
            eprintln!("skipping: {} is not present", p.display());
            return None;
        };
        crate::unifiedlog_chunks::walk_entries(&raw)
            .entries
            .into_iter()
            .find(|e| e.tag == crate::unifiedlog_chunks::TAG_OVERSIZE)
            .map(|e| e.payload.to_vec())
    }

    #[test]
    fn the_big_sur_oversize_entry_yields_its_reference_and_strings() {
        let Some(p) = oversize_payload("Chunkset Tests/big_sur_oversize_chunkset.raw") else {
            return;
        };
        let o = parse_oversize(&p).expect("an oversize entry");
        assert_eq!(
            (o.first_proc_id, o.second_proc_id, o.data_ref),
            (96, 245, 1)
        );
        assert_eq!(o.continuous_time, 0x1_4E56_668A);
        assert_eq!(o.items.len(), 5);
        assert_eq!(
            o.items[0].value,
            ItemValue::Text("system kext collection".into())
        );
        assert_eq!(
            o.items[1].value,
            ItemValue::Text("/System/Library/KernelCollections/SystemKernelExtensions.kc".into())
        );
        assert!(o.flaw.is_none());
    }

    #[test]
    fn an_oversize_entrys_private_strings_are_read_from_its_private_region() {
        let Some(p) = oversize_payload("Oversize Tests/oversize_private_strings.raw") else {
            return;
        };
        let o = parse_oversize(&p).expect("an oversize entry");
        assert_eq!(o.items.len(), 1);
        assert!(o.items[0].from_private_data);
        match &o.items[0].value {
            ItemValue::Text(t) => assert!(t.starts_with("updated queuedEvents[4]=("), "{t}"),
            v => panic!("a private string, not {v:?}"),
        }
        assert!(o.flaw.is_none());
    }

    #[test]
    fn an_oversize_entry_cut_short_is_marked_not_dropped() {
        // Header declaring 40 public bytes, and only 10 held.
        let mut p = Vec::new();
        p.extend_from_slice(&7u64.to_le_bytes());
        p.extend_from_slice(&8u32.to_le_bytes());
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(&99u64.to_le_bytes());
        p.extend_from_slice(&3u32.to_le_bytes());
        p.extend_from_slice(&40u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&[0x22, 0x01, 0x22, 0x04, 0, 0, 0x10, 0, 0, 0]);
        let o = parse_oversize(&p).expect("the header fits");
        assert_eq!((o.first_proc_id, o.second_proc_id, o.data_ref), (7, 8, 3));
        assert!(
            o.flaw.as_deref().is_some_and(|f| f.contains("40")),
            "{:?}",
            o.flaw
        );
        assert!(parse_oversize(&p[..20]).is_none());
    }

    const BIG_SUR_FIREHOSE_TRACEPOINTS: usize = 50;
    const BIG_SUR_FIRST: (u8, u32, &str) = (4, 480_432, "main_exe");
}
