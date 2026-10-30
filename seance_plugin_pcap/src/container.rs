//! The capture container reader: classic pcap and pcapng.
//!
//! This layer knows nothing about Ethernet, IP or ports. Its whole job is to
//! walk a capture file's framing — the 24-byte classic header and its 16-byte
//! records, or pcapng's block stream — and hand each packet's bytes up with the
//! two facts the layers above cannot recover on their own: which interface the
//! packet arrived on, and what the timestamp means. Timestamp resolution is
//! per-interface in pcapng, so a fixed 10^-6 assumption silently mis-dates every
//! packet in a nanosecond capture by three orders of magnitude.
//!
//! Everything here reads attacker-controlled bytes. No arithmetic on a length or
//! an offset taken from the file may be unchecked, and no malformed input may
//! panic, loop forever, or be presented as a complete read.
//!
//! Every way a read can fall short has its own field on [`CaptureMeta`]. None
//! of them shares a value with "nothing was here": a packet with no timestamp
//! is `None`, not the epoch; a drop count the file never stated is absent from
//! [`CaptureMeta::interface_statistics`], not zero; and a walk that stopped
//! early says where and why in [`CaptureMeta::stopped`], not `true`.

use std::collections::BTreeMap;

/// Which of the three on-disk capture layouts this file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    /// Classic libpcap, `0xA1B2C3D4`, fractional field in microseconds.
    PcapMicro,
    /// Classic libpcap, `0xA1B23C4D`, fractional field in nanoseconds.
    PcapNano,
    /// pcapng block stream, `0x0A0D0D0A` with byte-order magic `0x1A2B3C4D`.
    PcapNg,
}

/// The unit an interface's timestamps are counted in, as `if_tsresol` declares
/// it: `Pow10(n)` is 10^-n seconds, `Pow2(n)` is 2^-n seconds. Both are legal,
/// and hardware timestampers do emit the second; a reader that only knows the
/// first either refuses the interface or, worse, re-dates every packet on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsResol {
    Pow10(u8),
    Pow2(u8),
}

/// One capture interface. Classic pcap has exactly one, synthesised from the
/// file header; pcapng has one per IDB, in the order the IDBs appear, which is
/// the order an EPB's `interface_id` indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub linktype: u16,
    pub snaplen: u32,
    /// The unit this interface's timestamps are counted in. The pcapng default
    /// is `Pow10(6)`.
    pub ts_resol: TsResol,
    pub name: Option<String>,
}

/// The provenance a pcapng Section Header Block carries: `shb_hardware`,
/// `shb_os`, `shb_userappl`. A merged capture has one section per merged file,
/// each with its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SectionInfo {
    pub hardware: Option<String>,
    pub os: Option<String>,
    pub application: Option<String>,
}

/// The counters an Interface Statistics Block states for one interface. Each
/// is `None` when no ISB stated it, which is a different fact from a stated
/// zero: the first means the capture engine said nothing about its losses, the
/// second means it said there were none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterfaceStatistics {
    /// `isb_ifrecv`: packets the interface received, the denominator any drop
    /// figure needs to be read as a rate.
    pub if_received: Option<u64>,
    /// `isb_ifdrop`: packets the interface dropped for want of buffer.
    pub if_drops: Option<u64>,
    /// `isb_osdrop`: packets the operating system dropped before the capture
    /// interface saw them.
    pub os_drops: Option<u64>,
}

/// Why the walk stopped before the end of the file, and where. Everything after
/// `at` is unread — not empty, not absent — and `bytes.len() - at` is how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// A block's declared length was below its own framing or not a multiple
    /// of four; advancing by it would make no progress or lose alignment.
    BlockLengthInvalid { at: u64, declared: u32 },
    /// A block (or classic record) declared more bytes than the file had left.
    BlockPastEof {
        at: u64,
        declared: u32,
        remaining: u64,
    },
    /// The file ended inside a block or record header.
    HeaderShort { at: u64 },
    /// An Interface Description Block would not parse, so every later packet's
    /// attribution and timestamp would be a guess.
    InterfaceBlockShort { at: u64 },
    /// A Section Header Block this build cannot read — a byte-order magic that
    /// is neither value, or a major version it has never been shown.
    UnreadableSection { at: u64 },
}

impl StopReason {
    /// A stable name for reports to quote.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::BlockLengthInvalid { .. } => "block_length_invalid",
            Self::BlockPastEof { .. } => "block_past_eof",
            Self::HeaderShort { .. } => "header_short",
            Self::InterfaceBlockShort { .. } => "interface_block_short",
            Self::UnreadableSection { .. } => "unreadable_section",
        }
    }

    /// The file offset the walk stopped at.
    pub fn at(&self) -> u64 {
        match self {
            Self::BlockLengthInvalid { at, .. }
            | Self::BlockPastEof { at, .. }
            | Self::HeaderShort { at }
            | Self::InterfaceBlockShort { at }
            | Self::UnreadableSection { at } => *at,
        }
    }
}

/// What the walk learned about the capture as a whole, including the parts of
/// it that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureMeta {
    pub format: CaptureFormat,
    /// The byte order of the first section; later sections may differ.
    pub little_endian: bool,
    pub major: u16,
    pub minor: u16,
    pub interfaces: Vec<Interface>,
    /// True when the file declared more interfaces than [`MAX_INTERFACES`]
    /// and the table is therefore incomplete.
    pub cap_reached_interfaces: bool,
    /// One entry per pcapng Section Header Block, in file order. Empty for
    /// classic pcap, which has no provenance.
    pub sections: Vec<SectionInfo>,
    /// True when the file had more sections than [`MAX_SECTIONS`].
    pub cap_reached_sections: bool,
    /// pcapng block types this build does not decode, by type code. pcapng is
    /// extensible, so these are normal — but a Name Resolution Block (4) and a
    /// Decryption Secrets Block (10) each carry evidence, and a count that does
    /// not name the type says nothing about what went unread.
    pub unknown_block_types: BTreeMap<u32, u64>,
    /// True when more than [`MAX_UNKNOWN_BLOCK_TYPES`] distinct unknown types
    /// were seen; the table then holds the first ones only.
    pub cap_reached_unknown_block_types: bool,
    /// Unknown blocks of a type the table had no room for. Still a count of
    /// blocks that were there and were not read, just not by type.
    pub unknown_blocks_past_type_cap: u64,
    /// Packet blocks naming an interface no IDB declared (or one past the
    /// interface cap). Withheld, because there is no resolution to read their
    /// clock through and no linktype to decode them with; counted, because the
    /// traffic was there.
    pub packets_on_undeclared_interface: u64,
    /// EPB or SPB blocks shorter than their own fixed fields: a packet record
    /// was there and nothing about it could be read.
    pub packet_blocks_short: u64,
    /// Packets emitted with `ts_micros: None` because their record carries
    /// no timestamp at all: a Simple Packet Block, or a classic record with
    /// both timestamp fields zero, which is how the bulk carver spells
    /// "unknown".
    pub packets_without_timestamp: u64,
    /// Packets emitted with `ts_micros: None` because a timestamp was present
    /// and could not be converted: the interface's resolution is one no 64-bit
    /// count can date a real capture at, or the scaled instant overflowed.
    pub packets_with_unresolvable_timestamp: u64,
    /// EPBs whose declared captured length exceeded the bytes their block
    /// held. The bytes held are what is emitted, but the disagreement is
    /// evidence of damage or forgery, not ordinary snaplen truncation.
    pub over_claimed_packets: u64,
    /// Blocks whose trailing copy of the total length disagreed with the
    /// leading one. Read anyway, because the bytes are evidence; counted,
    /// because the format's own redundancy check failed.
    pub mismatched_block_trailers: u64,
    /// Option lists that ended inside an option rather than at opt_endofopt.
    /// The option that was cut is not read, and when it is `if_tsresol` the
    /// default stands in for it.
    pub truncated_options: u64,
    /// Where and why the walk stopped short of the end of the file. `None`
    /// means every byte was read.
    pub stopped: Option<StopReason>,
    /// How far into the file the walk got. Equal to the file length when
    /// `stopped` is `None`, and to `stopped.at()` otherwise.
    pub bytes_read: u64,
    /// The last counters each ISB stated, keyed by the interface's index in
    /// [`Self::interfaces`]. An interface with no entry had no ISB.
    pub interface_statistics: BTreeMap<u32, InterfaceStatistics>,
    /// The sum over interfaces of the last `isb_ifdrop` each stated. ISB
    /// counters are cumulative since the start of the capture, so the last
    /// value is the total and summing the periodic ones would inflate it.
    pub reported_drops: u64,
    /// The same for `isb_osdrop`.
    pub reported_os_drops: u64,
    /// ISBs whose counters could not be attributed or read: a block shorter
    /// than its fixed fields, one naming an interface no IDB declared, or a
    /// counter option that is not the eight bytes the spec requires. Absent
    /// from the totals, which therefore understate what the file said.
    pub unreadable_statistics: u64,
}

/// One packet, borrowed straight out of the capture buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub iface: u32,
    /// Microseconds since the Unix epoch, resolved through the interface's
    /// `if_tsresol`. `None` when the block carries no timestamp or the one it
    /// carries cannot be converted; never the epoch standing in for either.
    pub ts_micros: Option<u64>,
    /// Bytes present in the file for this packet.
    pub data: &'a [u8],
    /// Length the packet had on the wire; > data.len() means the capture truncated it.
    pub orig_len: u32,
}

/// The three ways a file can fail to be a capture at all. Anything that goes
/// wrong *after* the header is a partial read, recorded on [`CaptureMeta`],
/// not an error — the packets read before the damage are evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    NotACapture,
    UnsupportedVersion { major: u16, minor: u16 },
    HeaderTruncated,
}

/// The most interfaces the walk will keep. A file of nothing but IDBs
/// otherwise costs about twice its own size in memory.
pub const MAX_INTERFACES: usize = 4096;
/// The most sections the walk will keep provenance for, for the same reason.
pub const MAX_SECTIONS: usize = 4096;
/// The most distinct unknown block types the walk will count by type. The
/// type code is the file's to choose, so without a cap the table grows with
/// the file.
pub const MAX_UNKNOWN_BLOCK_TYPES: usize = 256;

/// Classic libpcap magic with the fractional field in microseconds, as the
/// number it denotes rather than the bytes it lands as.
const PCAP_MAGIC_MICRO: u32 = 0xA1B2_C3D4;
/// The same header with the fractional field counted in nanoseconds.
const PCAP_MAGIC_NANO: u32 = 0xA1B2_3C4D;
/// The classic file header, and the per-record header inside it.
const CLASSIC_HEADER_LEN: usize = 24;
const CLASSIC_RECORD_HEADER_LEN: usize = 16;

/// pcapng block types. The Section Header Block's type is a palindrome by
/// design, so it reads the same in either byte order — which is why the format
/// needs a separate byte-order magic inside the block.
const BLOCK_SHB: u32 = 0x0A0D_0D0A;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_SPB: u32 = 0x0000_0003;
const BLOCK_ISB: u32 = 0x0000_0005;
const BLOCK_EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// Type, total length, and the trailing copy of the total length.
const BLOCK_FRAMING_LEN: usize = 12;

const OPT_END_OF_OPT: u16 = 0;
const OPT_SHB_HARDWARE: u16 = 2;
const OPT_SHB_OS: u16 = 3;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_ISB_IFRECV: u16 = 4;
const OPT_ISB_IFDROP: u16 = 5;
const OPT_ISB_OSDROP: u16 = 7;

/// The pcapng default timestamp resolution when an interface declares none.
const DEFAULT_TS_RESOL: TsResol = TsResol::Pow10(6);

/// Walk a whole capture. Returns the metadata and calls `on_packet` per packet.
/// Never panics on malformed input; stops at the first unrecoverable point and records it
/// in CaptureMeta.
pub fn read_capture(
    bytes: &[u8],
    on_packet: &mut dyn FnMut(Packet<'_>),
) -> Result<CaptureMeta, CaptureError> {
    // Detection is by content: Case 001's capture is named `.pcap` and is
    // pcapng, and a capture carved out of unallocated space has no name at all.
    let first_word = bytes.get(..4).ok_or(CaptureError::NotACapture)?;
    let raw = [first_word[0], first_word[1], first_word[2], first_word[3]];
    let little_reading = u32::from_le_bytes(raw);
    let big_reading = u32::from_be_bytes(raw);

    if little_reading == BLOCK_SHB {
        read_pcapng(bytes, on_packet)
    } else if let Some((format, little_endian)) = classic_format(little_reading, big_reading) {
        read_classic(bytes, format, little_endian, on_packet)
    } else {
        Err(CaptureError::NotACapture)
    }
}

/// Which classic layout, and in which byte order, the four magic bytes name.
/// The nanosecond magics share the header's shape exactly, so a reader that
/// only knows the microsecond pair either refuses a valid file or accepts it
/// and reports every timestamp a thousand times too fine.
fn classic_format(little_reading: u32, big_reading: u32) -> Option<(CaptureFormat, bool)> {
    match (little_reading, big_reading) {
        (PCAP_MAGIC_MICRO, _) => Some((CaptureFormat::PcapMicro, true)),
        (_, PCAP_MAGIC_MICRO) => Some((CaptureFormat::PcapMicro, false)),
        (PCAP_MAGIC_NANO, _) => Some((CaptureFormat::PcapNano, true)),
        (_, PCAP_MAGIC_NANO) => Some((CaptureFormat::PcapNano, false)),
        _ => None,
    }
}

/// A file offset as the report will quote it.
fn file_offset(offset: usize) -> u64 {
    u64::try_from(offset).unwrap_or(u64::MAX)
}

fn empty_meta(format: CaptureFormat, little_endian: bool, major: u16, minor: u16) -> CaptureMeta {
    CaptureMeta {
        format,
        little_endian,
        major,
        minor,
        interfaces: Vec::new(),
        cap_reached_interfaces: false,
        sections: Vec::new(),
        cap_reached_sections: false,
        unknown_block_types: BTreeMap::new(),
        cap_reached_unknown_block_types: false,
        unknown_blocks_past_type_cap: 0,
        packets_on_undeclared_interface: 0,
        packet_blocks_short: 0,
        packets_without_timestamp: 0,
        packets_with_unresolvable_timestamp: 0,
        over_claimed_packets: 0,
        mismatched_block_trailers: 0,
        truncated_options: 0,
        stopped: None,
        bytes_read: 0,
        interface_statistics: BTreeMap::new(),
        reported_drops: 0,
        reported_os_drops: 0,
        unreadable_statistics: 0,
    }
}

// ---------------------------------------------------------------------------
// Endian-aware, bounds-checked field reads
//
// Every one of these returns None rather than panicking when the field runs
// past the end of the slice, because "the field is not there" is the ordinary
// case in a capture recovered from damaged media.
// ---------------------------------------------------------------------------

fn u16_at(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let field = bytes.get(offset..end)?;
    let raw = [field[0], field[1]];
    Some(if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn u32_at(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let field = bytes.get(offset..end)?;
    let raw = [field[0], field[1], field[2], field[3]];
    Some(if little {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn u64_at(bytes: &[u8], offset: usize, little: bool) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let field = bytes.get(offset..end)?;
    let raw = [
        field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
    ];
    Some(if little {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

impl TsResol {
    /// Convert a timestamp counted in this resolution to microseconds since
    /// the epoch, or `None` when no honest microsecond value exists.
    ///
    /// The exponent comes out of the file. A resolution so fine that a u64
    /// tick count runs out before 1970-01-01T00:00:02Z — 10^-20 s, 2^-64 s —
    /// cannot date any packet in any real capture, and dividing anyway rounds
    /// every instant to the epoch, which a timeline reads as a fact. A coarse
    /// resolution whose scaled count overflows is a date past the year
    /// 584,000; saturating would present it as a real instant.
    pub fn ticks_to_micros(self, ticks: u64) -> Option<u64> {
        match self {
            TsResol::Pow10(n) if n > FINEST_POW10 => None,
            TsResol::Pow2(n) if n > FINEST_POW2 => None,
            TsResol::Pow10(n) if n >= 6 => {
                // n - 6 <= 13 here, so the divisor fits with room to spare.
                let divisor = 10u64.checked_pow(u32::from(n - 6))?;
                Some(ticks / divisor)
            }
            TsResol::Pow10(n) => {
                let multiplier = 10u64.checked_pow(u32::from(6 - n))?;
                ticks.checked_mul(multiplier)
            }
            // Widened so the multiply cannot overflow before the shift takes
            // the fraction back off; n <= 63, so the shift is in range.
            TsResol::Pow2(n) => {
                let micros = (u128::from(ticks) * 1_000_000) >> n;
                u64::try_from(micros).ok()
            }
        }
    }
}

/// The finest exponents at which a u64 tick count still reaches past the first
/// second of 1970: 10^19 and 2^63 ticks per second. Anything finer cannot date
/// a packet in any real capture.
const FINEST_POW10: u8 = 19;
const FINEST_POW2: u8 = 63;

/// A pcapng option list: `[code u16][length u16][value]`, the value padded out
/// to the next 4-byte boundary with the padding *not* counted in the declared
/// length. Advancing by the declared length alone lands mid-option and reads
/// the remainder of the list as garbage.
struct Options<'a> {
    body: &'a [u8],
    offset: usize,
    little: bool,
    /// Set when the list ended inside an option rather than at opt_endofopt
    /// or at the clean end of the body. A proper opt_endofopt means "there
    /// were no more options"; a short read means "there were more and we could
    /// not read them", and only the second silently changes how every
    /// timestamp on an interface is read.
    truncated: bool,
}

impl<'a> Options<'a> {
    fn new(body: &'a [u8], little: bool) -> Self {
        Self {
            body,
            offset: 0,
            little,
            truncated: false,
        }
    }

    /// Run `visit` over every option, then record on `meta` whether the list
    /// was cut short.
    fn for_each(
        body: &'a [u8],
        little: bool,
        meta: &mut CaptureMeta,
        mut visit: impl FnMut(u16, &'a [u8]),
    ) {
        let mut options = Self::new(body, little);
        for (code, value) in options.by_ref() {
            visit(code, value);
        }
        if options.truncated {
            meta.truncated_options = meta.truncated_options.saturating_add(1);
        }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.body.len() {
            // Writers may omit opt_endofopt when there are no options at all,
            // so running out of body exactly at an option boundary is clean.
            return None;
        }
        // offset < body.len() here, so these small additions cannot overflow.
        let header = (
            u16_at(self.body, self.offset, self.little),
            u16_at(self.body, self.offset.saturating_add(2), self.little),
        );
        let (Some(code), Some(declared)) = header else {
            self.truncated = true;
            return None;
        };
        if code == OPT_END_OF_OPT {
            return None;
        }
        let declared = usize::from(declared);
        let value_start = self.offset.saturating_add(4);
        let value = value_start
            .checked_add(declared)
            .and_then(|end| self.body.get(value_start..end));
        let Some(value) = value else {
            self.truncated = true;
            return None;
        };
        // The value slice was in range, so its padded end is at most three
        // bytes past the body and cannot overflow either.
        self.offset = value_start.saturating_add(declared.next_multiple_of(4));
        Some((code, value))
    }
}

/// A pcapng string option. Writers differ over whether the declared length
/// includes a terminator, so a trailing NUL is dropped rather than carried into
/// a report as a control character; anything that is not UTF-8 is kept lossily
/// rather than discarded, because the bytes are still evidence of the writer.
fn option_string(value: &[u8]) -> String {
    let value = match value.split_last() {
        Some((0, head)) => head,
        _ => value,
    };
    String::from_utf8_lossy(value).into_owned()
}

// ---------------------------------------------------------------------------
// Classic pcap
// ---------------------------------------------------------------------------

fn read_classic(
    bytes: &[u8],
    format: CaptureFormat,
    little_endian: bool,
    on_packet: &mut dyn FnMut(Packet<'_>),
) -> Result<CaptureMeta, CaptureError> {
    if bytes.len() < CLASSIC_HEADER_LEN {
        return Err(CaptureError::HeaderTruncated);
    }
    let major = u16_at(bytes, 4, little_endian).ok_or(CaptureError::HeaderTruncated)?;
    let minor = u16_at(bytes, 6, little_endian).ok_or(CaptureError::HeaderTruncated)?;
    // libpcap has only ever written 2.4. Parsing anything else hopefully is how
    // a reader silently mis-decodes a format it has never been shown.
    if (major, minor) != (2, 4) {
        return Err(CaptureError::UnsupportedVersion { major, minor });
    }

    let snaplen = u32_at(bytes, 16, little_endian).ok_or(CaptureError::HeaderTruncated)?;
    let network = u32_at(bytes, 20, little_endian).ok_or(CaptureError::HeaderTruncated)?;
    // The upper half of the classic `network` field carries libpcap's
    // FCS-length flags, not part of the link type, so only the low 16 bits name
    // the LINKTYPE the frames are in.
    let linktype = (network & 0xFFFF) as u16;

    // The fractional field's meaning is fixed by the magic, but an examiner is
    // owed the capture's real resolution rather than the microseconds we
    // rounded it to.
    let ts_resol = match format {
        CaptureFormat::PcapNano => TsResol::Pow10(9),
        _ => DEFAULT_TS_RESOL,
    };

    let mut meta = empty_meta(format, little_endian, major, minor);
    // Classic pcap has no IDB: the file header is the only interface record
    // there is, and every record in the file belongs to it.
    meta.interfaces.push(Interface {
        linktype,
        snaplen,
        ts_resol,
        name: None,
    });

    let mut offset = CLASSIC_HEADER_LEN;
    while offset < bytes.len() {
        let Some(data_start) = offset.checked_add(CLASSIC_RECORD_HEADER_LEN) else {
            meta.stopped = Some(StopReason::HeaderShort {
                at: file_offset(offset),
            });
            break;
        };
        let (Some(ts_sec), Some(ts_frac), Some(incl_len), Some(orig_len)) = (
            u32_at(bytes, offset, little_endian),
            u32_at(bytes, offset.saturating_add(4), little_endian),
            u32_at(bytes, offset.saturating_add(8), little_endian),
            u32_at(bytes, offset.saturating_add(12), little_endian),
        ) else {
            // Fewer than sixteen bytes left: the file ends inside a record
            // header, and a file that ends mid-record has not been read whole.
            meta.stopped = Some(StopReason::HeaderShort {
                at: file_offset(offset),
            });
            break;
        };

        // data_start + incl_len is the classic overflow site, and incl_len is
        // whatever the file says it is.
        let data = data_start
            .checked_add(incl_len as usize)
            .and_then(|data_end| bytes.get(data_start..data_end));
        let Some(data) = data else {
            meta.stopped = Some(StopReason::BlockPastEof {
                at: file_offset(offset),
                declared: incl_len,
                remaining: file_offset(bytes.len().saturating_sub(offset)),
            });
            break;
        };

        // Both fields zero is a record with no timestamp: the bulk packet
        // carver writes zeros to mean unknown, and the epoch is never an
        // observation. A u32 of seconds times a million fits a u64 with
        // room to spare, and the fraction is at most a u32.
        let ts_micros = if ts_sec == 0 && ts_frac == 0 {
            meta.packets_without_timestamp = meta.packets_without_timestamp.saturating_add(1);
            None
        } else {
            let seconds_micros = u64::from(ts_sec).saturating_mul(1_000_000);
            let fraction_micros = match format {
                CaptureFormat::PcapNano => u64::from(ts_frac) / 1_000,
                _ => u64::from(ts_frac),
            };
            Some(seconds_micros.saturating_add(fraction_micros))
        };
        on_packet(Packet {
            iface: 0,
            ts_micros,
            data,
            orig_len,
        });
        // In range: data was sliced out of bytes ending here.
        offset = data_start.saturating_add(data.len());
    }

    meta.bytes_read = match meta.stopped {
        Some(reason) => reason.at(),
        None => file_offset(bytes.len()),
    };
    Ok(meta)
}

// ---------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------

fn read_pcapng(
    bytes: &[u8],
    on_packet: &mut dyn FnMut(Packet<'_>),
) -> Result<CaptureMeta, CaptureError> {
    // The block type alone is four weak bytes that occur by chance in
    // compressed data; the byte-order magic is what makes the detection safe,
    // and it also decides how every length in the file is read.
    let little_endian = match section_byte_order(bytes, 0) {
        Some(Some(little)) => little,
        Some(None) => return Err(CaptureError::NotACapture),
        None => return Err(CaptureError::HeaderTruncated),
    };
    let major = u16_at(bytes, 12, little_endian).ok_or(CaptureError::HeaderTruncated)?;
    let minor = u16_at(bytes, 14, little_endian).ok_or(CaptureError::HeaderTruncated)?;
    if major != 1 {
        return Err(CaptureError::UnsupportedVersion { major, minor });
    }

    let mut meta = empty_meta(CaptureFormat::PcapNg, little_endian, major, minor);
    walk_blocks(bytes, little_endian, &mut meta, on_packet);
    Ok(meta)
}

/// Read the byte-order magic of the SHB starting at `offset`. The outer `None`
/// is a magic that is not there at all; the inner is one that is there and is
/// neither value.
fn section_byte_order(bytes: &[u8], offset: usize) -> Option<Option<bool>> {
    let magic_at = offset.checked_add(8)?;
    let little = u32_at(bytes, magic_at, true)?;
    if little == BYTE_ORDER_MAGIC {
        return Some(Some(true));
    }
    // Same bytes, other order: cannot be short if the first read was not.
    if u32_at(bytes, magic_at, false) == Some(BYTE_ORDER_MAGIC) {
        return Some(Some(false));
    }
    Some(None)
}

/// Walk the block stream from the section header onwards. Everything that goes
/// wrong from here is a partial read recorded on `meta`, never an error: the
/// packets read before the damage are evidence, and returning `Err` would throw
/// them away.
fn walk_blocks(
    bytes: &[u8],
    initial_little: bool,
    meta: &mut CaptureMeta,
    on_packet: &mut dyn FnMut(Packet<'_>),
) {
    let mut little = initial_little;
    // A capture merged from several captures carries several sections, and each
    // section numbers its interfaces from zero again. Interfaces accumulate so
    // that a packet's reported id stays a valid index into `meta.interfaces`.
    let mut iface_base = 0usize;
    let mut offset = 0usize;

    let stopped = loop {
        if offset >= bytes.len() {
            break None;
        }
        let at = file_offset(offset);
        // The block type is the same in both orders when it is an SHB, which
        // is what lets the byte order be decided before anything else is read.
        let Some(block_type) = u32_at(bytes, offset, little) else {
            break Some(StopReason::HeaderShort { at });
        };
        if block_type == BLOCK_SHB {
            // Every field of a section header, its own length included, is in
            // the order its own byte-order magic declares — not the previous
            // section's. A merged capture whose sections differ in endianness
            // is legal, and reading the second SHB's length in the first
            // section's order walks off the end of the file.
            match section_byte_order(bytes, offset) {
                Some(Some(section_little)) => little = section_little,
                Some(None) => break Some(StopReason::UnreadableSection { at }),
                None => break Some(StopReason::HeaderShort { at }),
            }
        }
        let Some(declared) = u32_at(bytes, offset.saturating_add(4), little) else {
            // Fewer bytes left than a block header needs: the file ends inside
            // the framing itself.
            break Some(StopReason::HeaderShort { at });
        };
        let total = declared as usize;
        // A length below the framing it describes makes no progress — zero
        // advances not at all, eight advances back into the length field — so a
        // reader that trusts it spins forever on attacker-controlled input. A
        // length that is not a multiple of four means block alignment is lost,
        // and every subsequent block boundary would be a guess.
        if total < BLOCK_FRAMING_LEN || !total.is_multiple_of(4) {
            break Some(StopReason::BlockLengthInvalid { at, declared });
        }
        let block_end = match offset.checked_add(total) {
            Some(end) if end <= bytes.len() => end,
            _ => {
                break Some(StopReason::BlockPastEof {
                    at,
                    declared,
                    remaining: file_offset(bytes.len().saturating_sub(offset)),
                });
            }
        };
        // In range because total >= BLOCK_FRAMING_LEN and block_end <= len.
        let body = &bytes[offset + 8..block_end - 4];
        // The trailing copy of the length exists so the stream can be walked
        // backwards. This reader walks forwards, so the leading copy governs —
        // but a disagreement means a validating reader sees a different packet
        // stream from this one, and that is corruption or tampering on record.
        if u32_at(bytes, block_end - 4, little) != Some(declared) {
            meta.mismatched_block_trailers = meta.mismatched_block_trailers.saturating_add(1);
        }

        match block_type {
            BLOCK_SHB => {
                if !read_section_header(body, little, meta) {
                    // A section whose version this build cannot read leaves the
                    // interface table of everything after it unknown, so the
                    // remainder is unread rather than empty.
                    break Some(StopReason::UnreadableSection { at });
                }
                iface_base = meta.interfaces.len();
            }
            BLOCK_IDB => {
                let Some(interface) = read_interface_description(body, little, meta) else {
                    // Without a complete interface table every later packet's
                    // attribution and timestamp would be a guess.
                    break Some(StopReason::InterfaceBlockShort { at });
                };
                // Past the cap the interface is not kept; packets naming it
                // are then unattributable and counted as such, never guessed.
                if meta.interfaces.len() < MAX_INTERFACES {
                    meta.interfaces.push(interface);
                } else {
                    meta.cap_reached_interfaces = true;
                }
            }
            BLOCK_EPB => emit_enhanced_packet(body, little, iface_base, meta, on_packet),
            BLOCK_SPB => emit_simple_packet(body, little, iface_base, meta, on_packet),
            BLOCK_ISB => read_interface_statistics(body, little, iface_base, meta),
            // pcapng is extensible by design, so an unrecognised block is
            // normal — but it is a piece of the capture this build did not
            // read, and an examiner is entitled to know one was there.
            other => count_unknown_block(other, meta),
        }

        offset = block_end;
    };

    meta.stopped = stopped;
    meta.bytes_read = match stopped {
        Some(reason) => reason.at(),
        None => file_offset(bytes.len()),
    };
}

fn count_unknown_block(block_type: u32, meta: &mut CaptureMeta) {
    if let Some(count) = meta.unknown_block_types.get_mut(&block_type) {
        *count = count.saturating_add(1);
    } else if meta.unknown_block_types.len() < MAX_UNKNOWN_BLOCK_TYPES {
        meta.unknown_block_types.insert(block_type, 1);
    } else {
        meta.cap_reached_unknown_block_types = true;
        meta.unknown_blocks_past_type_cap = meta.unknown_blocks_past_type_cap.saturating_add(1);
    }
}

/// Read a section header's version and provenance options, the byte order
/// having been decided from its magic by the caller. Returns `false` when this
/// build cannot read the section.
fn read_section_header(body: &[u8], little: bool, meta: &mut CaptureMeta) -> bool {
    if u16_at(body, 4, little) != Some(1) {
        return false;
    }

    // Byte-order magic, version, and the 8-byte section length, which this
    // reader does not need: the block stream is walked forwards.
    const SHB_FIXED_LEN: usize = 16;
    let options = body.get(SHB_FIXED_LEN..).unwrap_or(&[]);
    let mut section = SectionInfo::default();
    Options::for_each(options, little, meta, |code, value| match code {
        OPT_SHB_HARDWARE => section.hardware = Some(option_string(value)),
        OPT_SHB_OS => section.os = Some(option_string(value)),
        // `shb_userappl = Mergecap` is the evidence that a capture is a
        // derived product merged from others, which nothing else in the
        // file records and an examiner quoting it has to be told.
        OPT_SHB_USERAPPL => section.application = Some(option_string(value)),
        _ => {}
    });
    if meta.sections.len() < MAX_SECTIONS {
        meta.sections.push(section);
    } else {
        meta.cap_reached_sections = true;
    }
    true
}

fn read_interface_description(
    body: &[u8],
    little: bool,
    meta: &mut CaptureMeta,
) -> Option<Interface> {
    let linktype = u16_at(body, 0, little)?;
    let snaplen = u32_at(body, 4, little)?;

    let mut ts_resol = DEFAULT_TS_RESOL;
    let mut name = None;
    let options = body.get(8..).unwrap_or(&[]);
    Options::for_each(options, little, meta, |code, value| match code {
        OPT_IF_NAME => name = Some(option_string(value)),
        OPT_IF_TSRESOL => {
            if let Some(&encoded) = value.first() {
                // The top bit selects a power of two instead of a power of
                // ten; the low seven bits are the exponent either way.
                ts_resol = if encoded & 0x80 == 0 {
                    TsResol::Pow10(encoded)
                } else {
                    TsResol::Pow2(encoded & 0x7F)
                };
            }
        }
        _ => {}
    });

    Some(Interface {
        linktype,
        snaplen,
        ts_resol,
        name,
    })
}

fn emit_enhanced_packet(
    body: &[u8],
    little: bool,
    iface_base: usize,
    meta: &mut CaptureMeta,
    on_packet: &mut dyn FnMut(Packet<'_>),
) {
    // Interface id, the two timestamp halves, captured length, original length.
    const EPB_FIXED_LEN: usize = 20;

    let (Some(iface_id), Some(ts_high), Some(ts_low), Some(captured_len), Some(orig_len)) = (
        u32_at(body, 0, little),
        u32_at(body, 4, little),
        u32_at(body, 8, little),
        u32_at(body, 12, little),
        u32_at(body, 16, little),
    ) else {
        meta.packet_blocks_short = meta.packet_blocks_short.saturating_add(1);
        return;
    };

    let available = body.len().saturating_sub(EPB_FIXED_LEN);
    // The block's own length is the authority; a captured length that exceeds
    // it is not to be trusted against it. But the bytes held are then what is
    // emitted, and `orig_len > data.len()` is the same signal an honestly
    // snaplen-clipped packet gives — so the disagreement is counted, or file
    // damage is handed up looking like ordinary truncation.
    let present = (captured_len as usize).min(available);
    if present < captured_len as usize {
        meta.over_claimed_packets = meta.over_claimed_packets.saturating_add(1);
    }
    let data = body
        .get(EPB_FIXED_LEN..EPB_FIXED_LEN.saturating_add(present))
        .unwrap_or(&[]);

    let attributed = iface_base
        .checked_add(iface_id as usize)
        .and_then(|i| Some((i, meta.interfaces.get(i)?)));
    let Some((index, interface)) = attributed else {
        // No IDB declared this interface, so there is no timestamp resolution
        // to read the packet's clock through and no linktype to decode its
        // bytes with. Counting it says the traffic was there; timestamping it
        // at a guessed resolution would put it at an invented instant.
        meta.packets_on_undeclared_interface =
            meta.packets_on_undeclared_interface.saturating_add(1);
        return;
    };

    let ticks = (u64::from(ts_high) << 32) | u64::from(ts_low);
    let ts_micros = interface.ts_resol.ticks_to_micros(ticks);
    if ts_micros.is_none() {
        meta.packets_with_unresolvable_timestamp =
            meta.packets_with_unresolvable_timestamp.saturating_add(1);
    }
    on_packet(Packet {
        // In range: the table is capped far below u32::MAX.
        iface: u32::try_from(index).unwrap_or(u32::MAX),
        ts_micros,
        data,
        orig_len,
    });
}

fn emit_simple_packet(
    body: &[u8],
    little: bool,
    iface_base: usize,
    meta: &mut CaptureMeta,
    on_packet: &mut dyn FnMut(Packet<'_>),
) {
    // The original length is the SPB's only field.
    const SPB_FIXED_LEN: usize = 4;

    let Some(orig_len) = u32_at(body, 0, little) else {
        meta.packet_blocks_short = meta.packet_blocks_short.saturating_add(1);
        return;
    };
    // An SPB names no interface, so it belongs to the first one its section
    // declared — and if that section declared none, the packet cannot be
    // attributed or decoded at all.
    let Some(interface) = meta.interfaces.get(iface_base) else {
        meta.packets_on_undeclared_interface =
            meta.packets_on_undeclared_interface.saturating_add(1);
        return;
    };
    // An SPB carries no captured length: the bytes actually present are only
    // recoverable from the block's own total length, bounded by the snaplen the
    // interface was capturing at. Taking the original length as the captured
    // one reads past the block on every truncated packet.
    let mut limit = orig_len as usize;
    // A snaplen of zero is how some writers spell "no limit".
    if interface.snaplen > 0 {
        limit = limit.min(interface.snaplen as usize);
    }
    let present = limit.min(body.len().saturating_sub(SPB_FIXED_LEN));
    let data = body
        .get(SPB_FIXED_LEN..SPB_FIXED_LEN.saturating_add(present))
        .unwrap_or(&[]);

    // An SPB has no timestamp of its own and there is nothing in the file
    // to derive one from. Zero would be the epoch presented as an observation.
    meta.packets_without_timestamp = meta.packets_without_timestamp.saturating_add(1);
    on_packet(Packet {
        iface: u32::try_from(iface_base).unwrap_or(0),
        ts_micros: None,
        data,
        orig_len,
    });
}

/// The ISB is the only place a capture states how much of itself is missing.
/// Nothing downstream can reconstruct a drop count, so losing it turns "the
/// network record is short by 1,203 packets" into silence.
///
/// Every ISB counter is cumulative since the start of the capture, and a
/// writer that rolls its ring buffer emits one ISB per roll. The last value an
/// interface states is its total; summing them reports several times the real
/// loss.
fn read_interface_statistics(body: &[u8], little: bool, iface_base: usize, meta: &mut CaptureMeta) {
    // Interface id and the two timestamp halves.
    const ISB_FIXED_LEN: usize = 12;

    let (Some(iface_id), Some(options)) = (u32_at(body, 0, little), body.get(ISB_FIXED_LEN..))
    else {
        meta.unreadable_statistics = meta.unreadable_statistics.saturating_add(1);
        return;
    };
    // Counters for an interface no IDB declared cannot be attributed, and
    // keying them by a guessed index would let a later section's interface
    // inherit them.
    let index = iface_base
        .checked_add(iface_id as usize)
        .filter(|&i| i < meta.interfaces.len())
        .and_then(|i| u32::try_from(i).ok());
    let Some(index) = index else {
        meta.unreadable_statistics = meta.unreadable_statistics.saturating_add(1);
        return;
    };

    let mut stats = meta
        .interface_statistics
        .get(&index)
        .copied()
        .unwrap_or_default();
    let mut unreadable = 0u64;
    Options::for_each(options, little, meta, |code, value| {
        let slot = match code {
            OPT_ISB_IFRECV => &mut stats.if_received,
            OPT_ISB_IFDROP => &mut stats.if_drops,
            OPT_ISB_OSDROP => &mut stats.os_drops,
            _ => return,
        };
        // The spec fixes these at eight bytes. Anything else is a count that
        // was stated and cannot be read, which must not become "no drops".
        match (value.len(), u64_at(value, 0, little)) {
            (8, Some(counter)) => *slot = Some(counter),
            _ => unreadable = unreadable.saturating_add(1),
        }
    });
    meta.unreadable_statistics = meta.unreadable_statistics.saturating_add(unreadable);
    meta.interface_statistics.insert(index, stats);

    meta.reported_drops = meta
        .interface_statistics
        .values()
        .filter_map(|s| s.if_drops)
        .fold(0u64, u64::saturating_add);
    meta.reported_os_drops = meta
        .interface_statistics
        .values()
        .filter_map(|s| s.os_drops)
        .fold(0u64, u64::saturating_add);
}

#[cfg(test)]
#[path = "container_tests.rs"]
mod container_tests;
