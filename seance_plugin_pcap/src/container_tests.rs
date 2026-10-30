use super::*;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Fixtures
//
// Every capture format here is a stream of fixed-width fields in one of two
// byte orders, so the fixtures assemble the bytes field by field the way a
// capture tool writes them. Opaque byte literals would hide exactly the thing
// these tests exist to pin down: which field is where, and in which endianness.
// ---------------------------------------------------------------------------

/// A field-at-a-time byte assembler in a chosen byte order.
struct Buf {
    little: bool,
    bytes: Vec<u8>,
}

impl Buf {
    fn new(little: bool) -> Self {
        Self {
            little,
            bytes: Vec::new(),
        }
    }

    fn u8(&mut self, v: u8) {
        self.bytes.push(v);
    }

    fn u16(&mut self, v: u16) {
        if self.little {
            self.bytes.extend_from_slice(&v.to_le_bytes());
        } else {
            self.bytes.extend_from_slice(&v.to_be_bytes());
        }
    }

    fn u32(&mut self, v: u32) {
        if self.little {
            self.bytes.extend_from_slice(&v.to_le_bytes());
        } else {
            self.bytes.extend_from_slice(&v.to_be_bytes());
        }
    }

    fn u64(&mut self, v: u64) {
        if self.little {
            self.bytes.extend_from_slice(&v.to_le_bytes());
        } else {
            self.bytes.extend_from_slice(&v.to_be_bytes());
        }
    }

    fn i64(&mut self, v: i64) {
        self.u64(v as u64);
    }

    fn raw(&mut self, v: &[u8]) {
        self.bytes.extend_from_slice(v);
    }

    /// pcapng pads every option value and every block body out to the next
    /// 4-byte boundary, and the padding is *not* counted in the declared length.
    fn pad4(&mut self) {
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }

    fn done(self) -> Vec<u8> {
        self.bytes
    }
}

const SHB_TYPE: u32 = 0x0A0D_0D0A;
const IDB_TYPE: u32 = 0x0000_0001;
const SPB_TYPE: u32 = 0x0000_0003;
const ISB_TYPE: u32 = 0x0000_0005;
const EPB_TYPE: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

const OPT_END: u16 = 0;
const OPT_SHB_HARDWARE: u16 = 2;
const OPT_SHB_OS: u16 = 3;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_ISB_IFRECV: u16 = 4;
const OPT_ISB_IFDROP: u16 = 5;
const OPT_ISB_OSDROP: u16 = 7;

/// Classic pcap magic as it is *stored*, i.e. the number, not the byte order.
const PCAP_MAGIC_MICRO: u32 = 0xA1B2_C3D4;
const PCAP_MAGIC_NANO: u32 = 0xA1B2_3C4D;

const LINKTYPE_ETHERNET: u16 = 1;

/// One encoded option: code, the *unpadded* value length, then the value padded
/// out to a 4-byte boundary.
fn option(little: bool, code: u16, value: &[u8]) -> Vec<u8> {
    let mut b = Buf::new(little);
    b.u16(code);
    b.u16(value.len() as u16);
    b.raw(value);
    b.pad4();
    b.done()
}

fn end_of_options(little: bool) -> Vec<u8> {
    option(little, OPT_END, &[])
}

/// Wrap a body in the 12 bytes of framing every pcapng block carries: type,
/// total length, body (padded), and the total length again so the stream can be
/// walked backwards.
fn ng_block(little: bool, block_type: u32, body: &[u8]) -> Vec<u8> {
    let padded = body.len().next_multiple_of(4);
    let total = (12 + padded) as u32;
    let mut b = Buf::new(little);
    b.u32(block_type);
    b.u32(total);
    b.raw(body);
    b.pad4();
    b.u32(total);
    b.done()
}

fn shb_versioned(little: bool, major: u16, minor: u16, options: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Buf::new(little);
    body.u32(BYTE_ORDER_MAGIC);
    body.u16(major);
    body.u16(minor);
    body.i64(-1); // section length: not known in advance, as every real writer emits
    for opt in options {
        body.raw(opt);
    }
    if !options.is_empty() {
        body.raw(&end_of_options(little));
    }
    ng_block(little, SHB_TYPE, &body.done())
}

fn shb(little: bool, options: &[Vec<u8>]) -> Vec<u8> {
    shb_versioned(little, 1, 0, options)
}

fn idb(little: bool, linktype: u16, snaplen: u32, options: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Buf::new(little);
    body.u16(linktype);
    body.u16(0); // reserved
    body.u32(snaplen);
    for opt in options {
        body.raw(opt);
    }
    if !options.is_empty() {
        body.raw(&end_of_options(little));
    }
    ng_block(little, IDB_TYPE, &body.done())
}

/// An Enhanced Packet Block. `ts` is in the interface's own resolution units.
fn epb(little: bool, iface: u32, ts: u64, data: &[u8], orig_len: u32) -> Vec<u8> {
    let mut body = Buf::new(little);
    body.u32(iface);
    body.u32((ts >> 32) as u32);
    body.u32(ts as u32);
    body.u32(data.len() as u32);
    body.u32(orig_len);
    body.raw(data);
    body.pad4();
    ng_block(little, EPB_TYPE, &body.done())
}

/// A Simple Packet Block. It carries no captured length and no timestamp: the
/// captured length has to be derived from the block's own total length, which
/// is the only place it is written down.
fn spb(little: bool, data: &[u8], orig_len: u32) -> Vec<u8> {
    let mut body = Buf::new(little);
    body.u32(orig_len);
    body.raw(data);
    body.pad4();
    ng_block(little, SPB_TYPE, &body.done())
}

/// An Interface Statistics Block carrying the given counter options, each an
/// 8-byte value as the spec requires.
fn isb(little: bool, iface: u32, counters: &[(u16, u64)]) -> Vec<u8> {
    let mut body = Buf::new(little);
    body.u32(iface);
    body.u32(0); // timestamp high
    body.u32(0); // timestamp low
    for &(code, value) in counters {
        let mut v = Buf::new(little);
        v.u64(value);
        body.raw(&option(little, code, &v.done()));
    }
    body.raw(&end_of_options(little));
    ng_block(little, ISB_TYPE, &body.done())
}

fn isb_with_ifdrop(little: bool, iface: u32, ifdrop: u64) -> Vec<u8> {
    isb(little, iface, &[(OPT_ISB_IFDROP, ifdrop)])
}

fn if_tsresol(little: bool, pow10: u8) -> Vec<u8> {
    let mut v = Buf::new(little);
    v.u8(pow10);
    option(little, OPT_IF_TSRESOL, &v.done())
}

/// The 24-byte classic pcap file header.
fn classic_header(little: bool, nano: bool, linktype: u32, snaplen: u32) -> Vec<u8> {
    classic_header_versioned(little, nano, 2, 4, linktype, snaplen)
}

fn classic_header_versioned(
    little: bool,
    nano: bool,
    major: u16,
    minor: u16,
    linktype: u32,
    snaplen: u32,
) -> Vec<u8> {
    let mut b = Buf::new(little);
    b.u32(if nano {
        PCAP_MAGIC_NANO
    } else {
        PCAP_MAGIC_MICRO
    });
    b.u16(major);
    b.u16(minor);
    b.u32(0); // thiszone
    b.u32(0); // sigfigs
    b.u32(snaplen);
    b.u32(linktype);
    b.done()
}

/// One classic 16-byte record header plus its captured bytes. `ts_frac` is
/// microseconds or nanoseconds depending on the file's magic.
fn classic_record(little: bool, ts_sec: u32, ts_frac: u32, data: &[u8], orig_len: u32) -> Vec<u8> {
    let mut b = Buf::new(little);
    b.u32(ts_sec);
    b.u32(ts_frac);
    b.u32(data.len() as u32);
    b.u32(orig_len);
    b.raw(data);
    b.done()
}

/// A frame body. The container layer must not care what is inside it, so this
/// is deliberately not a valid Ethernet frame.
fn frame(marker: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| marker.wrapping_add(i as u8)).collect()
}

// 2020-09-19T02:40:49Z, the hour the Case 001 C2 channel opens.
const TS_SEC: u32 = 1_600_483_249;
const TS_MICROS_AT_936MS: u64 = 1_600_483_249_936_000;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A packet copied out of the borrowed capture buffer so tests can compare
/// whole packets rather than fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedPacket {
    iface: u32,
    ts_micros: Option<u64>,
    data: Vec<u8>,
    orig_len: u32,
}

fn walk(bytes: &[u8]) -> Result<(CaptureMeta, Vec<OwnedPacket>), CaptureError> {
    let mut packets = Vec::new();
    let meta = read_capture(bytes, &mut |p: Packet<'_>| {
        packets.push(OwnedPacket {
            iface: p.iface,
            ts_micros: p.ts_micros,
            data: p.data.to_vec(),
            orig_len: p.orig_len,
        })
    })?;
    Ok((meta, packets))
}

/// Walk, expecting the header to be readable. Returns metadata and packets.
fn walk_ok(bytes: &[u8]) -> (CaptureMeta, Vec<OwnedPacket>) {
    walk(bytes).expect("the fixture's header is well formed, so the walk must start")
}

// ---------------------------------------------------------------------------
// Classic pcap
// ---------------------------------------------------------------------------

/// A little-endian classic capture is the commonest thing an examiner is handed.
/// Reading the magic the wrong way round turns every field in the file into
/// noise, so this pins the whole 24-byte header and one record end to end.
#[test]
fn a_little_endian_classic_capture_yields_its_packet_with_microsecond_timestamps() {
    let mut bytes = classic_header(true, false, LINKTYPE_ETHERNET as u32, 262_144);
    // The magic as it lands on disk little-endian: D4 C3 B2 A1.
    assert_eq!(&bytes[..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
    let payload = frame(0x10, 60);
    bytes.extend_from_slice(&classic_record(true, TS_SEC, 936_000, &payload, 60));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.format, CaptureFormat::PcapMicro);
    assert!(meta.little_endian);
    assert_eq!((meta.major, meta.minor), (2, 4));
    assert_eq!(
        meta.interfaces,
        vec![Interface {
            linktype: LINKTYPE_ETHERNET,
            snaplen: 262_144,
            ts_resol: TsResol::Pow10(6),
            name: None,
        }],
        "classic pcap has no IDB, so the file header is the only interface record there is"
    );
    assert_eq!(meta.stopped, None);
    assert_eq!(meta.bytes_read, bytes.len() as u64);
    assert!(meta.unknown_block_types.is_empty());
    assert_eq!(meta.reported_drops, 0);
    assert!(
        meta.interface_statistics.is_empty(),
        "classic pcap has no ISB, so no drop count was ever stated — which is not the same \
         as a stated count of zero"
    );

    assert_eq!(
        packets,
        vec![OwnedPacket {
            iface: 0,
            ts_micros: Some(TS_MICROS_AT_936MS),
            data: payload,
            orig_len: 60,
        }]
    );
}

/// The same file written by a big-endian host. The magic is the only thing that
/// says so, and every subsequent field — including the packet lengths — depends
/// on getting it right. Read little-endian, a 60-byte packet's length reads as
/// 0x3C000000, which is a billion-byte allocation or a panic.
#[test]
fn a_big_endian_classic_capture_is_read_through_its_reversed_magic() {
    let mut bytes = classic_header(false, false, LINKTYPE_ETHERNET as u32, 65_535);
    assert_eq!(&bytes[..4], &[0xA1, 0xB2, 0xC3, 0xD4]);
    let payload = frame(0x20, 64);
    bytes.extend_from_slice(&classic_record(false, TS_SEC, 936_000, &payload, 64));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.format, CaptureFormat::PcapMicro);
    assert!(!meta.little_endian);
    assert_eq!(meta.interfaces[0].snaplen, 65_535);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].ts_micros, Some(TS_MICROS_AT_936MS));
    assert_eq!(packets[0].data, payload);
}

/// The nanosecond magics share the classic header's shape exactly, so a reader
/// that only compares against the microsecond magics either refuses the file or
/// — worse — accepts it and reports timestamps a thousand times too fine. Here
/// 123_456_789 ns is 123_456 µs; read as microseconds it would put the packet
/// 123 seconds later than it happened.
#[test]
fn the_nanosecond_magic_scales_the_fractional_field_down_to_microseconds() {
    for little in [true, false] {
        let mut bytes = classic_header(little, true, LINKTYPE_ETHERNET as u32, 65_535);
        let expected_magic: [u8; 4] = if little {
            [0x4D, 0x3C, 0xB2, 0xA1]
        } else {
            [0xA1, 0xB2, 0x3C, 0x4D]
        };
        assert_eq!(&bytes[..4], &expected_magic);

        let payload = frame(0x30, 40);
        bytes.extend_from_slice(&classic_record(little, TS_SEC, 123_456_789, &payload, 40));

        let (meta, packets) = walk_ok(&bytes);

        assert_eq!(meta.format, CaptureFormat::PcapNano);
        assert_eq!(
            meta.interfaces[0].ts_resol,
            TsResol::Pow10(9),
            "the synthesised interface must say the capture's real resolution, \
             not the microseconds the packets were rounded to"
        );
        assert_eq!(
            packets[0].ts_micros,
            Some(TS_SEC as u64 * 1_000_000 + 123_456),
            "little_endian={little}"
        );
    }
}

/// snaplen truncation is the one form of missing evidence the capture itself
/// admits to. If `orig_len` is thrown away, a stream that is short because the
/// capture was is indistinguishable from one that was short on the wire.
#[test]
fn a_packet_captured_short_of_its_wire_length_keeps_the_length_it_had_on_the_wire() {
    let mut bytes = classic_header(true, false, LINKTYPE_ETHERNET as u32, 40);
    let payload = frame(0x40, 40);
    bytes.extend_from_slice(&classic_record(true, TS_SEC, 0, &payload, 1514));

    let (_meta, packets) = walk_ok(&bytes);

    assert_eq!(packets[0].data.len(), 40);
    assert_eq!(
        packets[0].orig_len, 1514,
        "the wire length is what tells an examiner the rest of this packet was never recorded"
    );
}

/// A capture cut off mid-record — the ordinary shape of a file recovered from
/// unallocated space, or of one whose writer was killed. The records before the
/// damage are evidence and must survive; the damage must be on the record too.
/// The bulk packet carver writes every record with `ts_sec = ts_usec = 0` and
/// says in its notes that the timestamps are unknown. A reader that turns
/// that into `Some(0)` dates every carved flow to 1970-01-01T00:00:00Z on the
/// case timeline — the epoch presented as an observation. Both fields zero
/// is "no timestamp", counted as such; a nonzero fraction is a stated
/// instant, however early.
#[test]
fn a_classic_record_with_both_timestamp_fields_zero_has_no_timestamp_rather_than_the_epoch() {
    let mut bytes = classic_header(true, false, LINKTYPE_ETHERNET as u32, 65_535);
    bytes.extend_from_slice(&classic_record(true, 0, 0, &frame(0x10, 40), 40));
    bytes.extend_from_slice(&classic_record(true, 0, 5, &frame(0x11, 40), 40));
    bytes.extend_from_slice(&classic_record(true, TS_SEC, 0, &frame(0x12, 40), 40));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 3);
    assert_eq!(
        packets[0].ts_micros, None,
        "zero and zero is unknown, not the epoch"
    );
    assert_eq!(packets[1].ts_micros, Some(5));
    assert_eq!(
        packets[2].ts_micros,
        Some(u64::from(TS_SEC) * 1_000_000),
        "a zero fraction beside a nonzero second is a stated instant"
    );
    assert_eq!(meta.packets_without_timestamp, 1);
    assert_eq!(meta.stopped, None);
}

#[test]
fn a_classic_record_cut_short_by_the_end_of_file_is_reported_rather_than_dropped() {
    let mut bytes = classic_header(true, false, LINKTYPE_ETHERNET as u32, 65_535);
    let payload = frame(0x50, 32);
    bytes.extend_from_slice(&classic_record(true, TS_SEC, 1, &payload, 32));
    // A second record header, cut off after eight of its sixteen bytes.
    bytes.extend_from_slice(&classic_record(true, TS_SEC, 2, &frame(0x60, 32), 32)[..8]);

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(
        packets.len(),
        1,
        "the intact record before the tear is evidence"
    );
    assert_eq!(packets[0].data, payload);
    let tear = (bytes.len() - 8) as u64;
    assert_eq!(
        meta.stopped,
        Some(StopReason::HeaderShort { at: tear }),
        "a file that ends mid-record has not been read completely, and saying nothing \
         presents a partial capture as a whole one"
    );
    assert_eq!(
        meta.bytes_read, tear,
        "the examiner is owed how much of the file was read, not just that it was not all of it"
    );
}

/// A record whose declared captured length runs off the end of the file. The
/// arithmetic here (offset + incl_len) is the classic overflow site, and the
/// declared length is attacker-controlled.
#[test]
fn a_classic_record_claiming_more_bytes_than_the_file_holds_stops_the_walk_safely() {
    let mut bytes = classic_header(true, false, LINKTYPE_ETHERNET as u32, 65_535);
    let mut b = Buf::new(true);
    b.u32(TS_SEC);
    b.u32(0);
    b.u32(u32::MAX); // incl_len
    b.u32(u32::MAX); // orig_len
    bytes.extend_from_slice(&b.done());
    bytes.extend_from_slice(&frame(0x70, 8));

    let (meta, packets) = walk_ok(&bytes);

    assert!(packets.is_empty());
    assert_eq!(
        meta.stopped,
        Some(StopReason::BlockPastEof {
            at: 24,
            declared: u32::MAX,
            remaining: 24,
        }),
        "the record header was read, so the reason names what it declared against what was left"
    );
    assert_eq!(meta.bytes_read, 24);
}

/// Classic pcap has only ever been version 2.4. Anything else is a file this
/// build has not been shown to read, and guessing at it is how a reader
/// silently mis-parses a format it does not know.
#[test]
fn an_unknown_classic_pcap_version_is_named_rather_than_guessed_at() {
    let bytes = classic_header_versioned(true, false, 3, 0, LINKTYPE_ETHERNET as u32, 65_535);
    assert_eq!(
        walk(&bytes),
        Err(CaptureError::UnsupportedVersion { major: 3, minor: 0 })
    );
}

/// A file header shorter than its own 24 bytes cannot even be checked for a
/// version, so it is a distinct outcome from "not a capture".
#[test]
fn a_classic_header_shorter_than_twenty_four_bytes_is_reported_as_a_truncated_header() {
    let bytes = classic_header(true, false, LINKTYPE_ETHERNET as u32, 65_535);
    assert_eq!(walk(&bytes[..20]), Err(CaptureError::HeaderTruncated));
}

// ---------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------

/// The shape of Case 001's own capture: a section header naming the box and the
/// tool that wrote it, one Ethernet interface, and packets. `shb_userappl =
/// Mergecap` is the evidence that the file is a *derived* product merged from
/// other captures — something an examiner quoting it under oath has to be told,
/// and something no other part of the file records.
#[test]
fn a_pcapng_section_header_records_the_os_and_application_that_wrote_the_capture() {
    let mut bytes = shb(
        true,
        &[
            option(true, OPT_SHB_OS, b"Linux 5.8.0-kali1-amd64"),
            option(true, OPT_SHB_USERAPPL, b"Mergecap (Wireshark) 3.2.6"),
        ],
    );
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 262_144, &[]));
    let first = frame(0x80, 60);
    let second = frame(0x90, 64);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &first, 60));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS + 1_500, &second, 64));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.format, CaptureFormat::PcapNg);
    assert!(meta.little_endian);
    assert_eq!((meta.major, meta.minor), (1, 0));
    assert_eq!(meta.sections.len(), 1);
    assert_eq!(
        meta.sections[0].os.as_deref(),
        Some("Linux 5.8.0-kali1-amd64")
    );
    assert_eq!(
        meta.sections[0].application.as_deref(),
        Some("Mergecap (Wireshark) 3.2.6")
    );
    assert_eq!(
        meta.sections[0].hardware, None,
        "an option that is absent must not be invented"
    );
    assert_eq!(
        meta.interfaces,
        vec![Interface {
            linktype: LINKTYPE_ETHERNET,
            snaplen: 262_144,
            ts_resol: TsResol::Pow10(6),
            name: None,
        }]
    );
    assert_eq!(meta.stopped, None);
    assert_eq!(meta.bytes_read, bytes.len() as u64);
    assert!(meta.unknown_block_types.is_empty());
    assert_eq!(meta.packets_on_undeclared_interface, 0);

    assert_eq!(
        packets,
        vec![
            OwnedPacket {
                iface: 0,
                ts_micros: Some(TS_MICROS_AT_936MS),
                data: first,
                orig_len: 60,
            },
            OwnedPacket {
                iface: 0,
                ts_micros: Some(TS_MICROS_AT_936MS + 1_500),
                data: second,
                orig_len: 64,
            },
        ]
    );
}

/// pcapng's block type is byte-order agnostic — `0A0D0D0A` reads the same
/// either way, which is exactly why the format carries a separate byte-order
/// magic inside the SHB. A reader that assumes little-endian reads a big-endian
/// section's block lengths as astronomically large and walks straight off the
/// end of the file.
#[test]
fn a_big_endian_pcapng_section_is_driven_by_its_byte_order_magic() {
    let mut bytes = shb(false, &[option(false, OPT_SHB_OS, b"SunOS 5.11")]);
    bytes.extend_from_slice(&idb(false, LINKTYPE_ETHERNET, 65_535, &[]));
    let payload = frame(0xA0, 48);
    bytes.extend_from_slice(&epb(false, 0, TS_MICROS_AT_936MS, &payload, 48));

    assert_eq!(&bytes[..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
    assert_eq!(
        &bytes[8..12],
        &[0x1A, 0x2B, 0x3C, 0x4D],
        "big-endian sections store the byte-order magic in its natural order"
    );

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.format, CaptureFormat::PcapNg);
    assert!(!meta.little_endian);
    assert_eq!(meta.sections[0].os.as_deref(), Some("SunOS 5.11"));
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].ts_micros, Some(TS_MICROS_AT_936MS));
    assert_eq!(packets[0].data, payload);
}

/// Option values are padded to a 4-byte boundary but the declared length is the
/// *unpadded* one, so a reader that advances by the declared length alone lands
/// mid-option and reads the rest of the list as garbage. Both options here are
/// unaligned, and the value that follows each one is what proves the padding was
/// skipped: a misread if_tsresol silently rescales every timestamp in the file.
#[test]
fn an_option_whose_length_is_not_a_multiple_of_four_is_padded_before_the_next_option() {
    let mut bytes = shb(
        true,
        &[
            option(true, OPT_SHB_HARDWARE, b"x86"), // 3 bytes, one byte of padding
            option(true, OPT_SHB_OS, b"Kali"),
        ],
    );
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[
            option(true, OPT_IF_NAME, b"enp0s3"), // 6 bytes, two bytes of padding
            if_tsresol(true, 9),
        ],
    ));
    bytes.extend_from_slice(&epb(
        true,
        0,
        1_600_483_249_936_000_123,
        &frame(0xB0, 32),
        32,
    ));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.sections[0].hardware.as_deref(), Some("x86"));
    assert_eq!(meta.sections[0].os.as_deref(), Some("Kali"));
    assert_eq!(meta.interfaces[0].name.as_deref(), Some("enp0s3"));
    assert_eq!(meta.interfaces[0].ts_resol, TsResol::Pow10(9));
    assert_eq!(packets[0].ts_micros, Some(TS_MICROS_AT_936MS));
}

/// With no if_tsresol the spec's default is 10^-6, and the same 64-bit count
/// therefore means a different instant than it would at 10^-9. These two
/// fixtures differ in one option byte and nothing else; if the reader ignores
/// it they produce the same timestamp, which is the bug.
#[test]
fn an_explicit_if_tsresol_changes_what_the_same_timestamp_count_means() {
    let counts: u64 = 1_600_483_249_936_000;

    let mut micro = shb(true, &[]);
    micro.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    micro.extend_from_slice(&epb(true, 0, counts, &frame(0xC0, 16), 16));

    let mut nano = shb(true, &[]);
    nano.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(true, 9)],
    ));
    nano.extend_from_slice(&epb(true, 0, counts, &frame(0xC0, 16), 16));

    let (micro_meta, micro_packets) = walk_ok(&micro);
    let (nano_meta, nano_packets) = walk_ok(&nano);

    assert_eq!(micro_meta.interfaces[0].ts_resol, TsResol::Pow10(6));
    assert_eq!(nano_meta.interfaces[0].ts_resol, TsResol::Pow10(9));
    assert_eq!(micro_packets[0].ts_micros, Some(counts));
    assert_eq!(
        nano_packets[0].ts_micros,
        Some(counts / 1_000),
        "at 10^-9 the same count is a thousandth of the elapsed time, not the same instant"
    );
}

/// A Simple Packet Block has no captured length field and no timestamp: the
/// number of bytes actually present is only recoverable from the block's own
/// total length. A reader that takes the SPB's one length field — the *original*
/// length — as the captured length reads past the block on any truncated packet.
#[test]
fn a_simple_packet_block_takes_its_captured_length_from_the_block_length() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let payload = frame(0xD0, 16);
    bytes.extend_from_slice(&spb(true, &payload, 16));
    // A following EPB proves the walk resumed at the right offset.
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0xE0, 20), 20));

    let (_meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].data, payload);
    assert_eq!(packets[0].orig_len, 16);
    assert_eq!(
        packets[0].iface, 0,
        "an SPB names no interface, so it belongs to the first one declared"
    );
    assert_eq!(packets[1].data, frame(0xE0, 20));
}

/// The Interface Statistics Block is the only place in a capture where the
/// evidence itself states how much of it is missing. Nothing downstream can
/// reconstruct a drop count, so losing it turns "the network record is short by
/// 1,203 packets" into silence.
#[test]
fn an_interface_statistics_block_reports_the_drops_the_capture_engine_counted() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0xF0, 24), 24));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 1_203));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 1_203);
    assert_eq!(
        meta.interface_statistics.get(&0).and_then(|s| s.if_drops),
        Some(1_203),
        "the count belongs to the interface the ISB named"
    );
    assert!(
        meta.unknown_block_types.is_empty(),
        "an ISB is a block this build understands, not an unknown one"
    );
    assert_eq!(meta.unreadable_statistics, 0);
    assert_eq!(packets.len(), 1);
}

/// Big-endian ISBs matter as much as little-endian ones: a 64-bit drop count
/// read the wrong way round is not a slightly wrong number, it is 2^56 times
/// too large.
#[test]
fn a_big_endian_interface_statistics_block_reports_its_drops_the_right_way_round() {
    let mut bytes = shb(false, &[]);
    bytes.extend_from_slice(&idb(false, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&isb_with_ifdrop(false, 0, 7));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 7);
}

/// pcapng is extensible by design, so an unrecognised block is normal and must
/// not end the walk — but it is also a piece of the capture this build did not
/// read, and an examiner is entitled to know one was there.
#[test]
fn an_unrecognised_block_type_is_counted_and_the_walk_continues_past_it() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x11, 20), 20));
    bytes.extend_from_slice(&ng_block(
        true,
        0x0000_0BAD,
        b"an extension this build does not read",
    ));
    let after = frame(0x22, 28);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS + 10, &after, 28));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(
        meta.unknown_block_types,
        BTreeMap::from([(0x0000_0BAD, 1)]),
        "the refusal must name what it refused: an examiner needs to know whether the \
         skipped block was a Name Resolution Block or a Decryption Secrets Block"
    );
    assert_eq!(
        meta.stopped, None,
        "an unknown block is skipped, not a tear"
    );
    assert_eq!(
        packets.len(),
        2,
        "the packet after the unknown block is still evidence"
    );
    assert_eq!(packets[1].data, after);
}

/// The same tear as the classic-pcap case, in pcapng's framing.
#[test]
fn a_truncated_final_block_is_reported_rather_than_dropped() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let kept = frame(0x33, 40);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &kept, 40));
    let cut = epb(true, 0, TS_MICROS_AT_936MS + 5, &frame(0x44, 40), 40);
    bytes.extend_from_slice(&cut[..cut.len() / 2]);

    let (meta, packets) = walk_ok(&bytes);

    let tear = (bytes.len() - cut.len() / 2) as u64;
    assert_eq!(
        meta.stopped,
        Some(StopReason::BlockPastEof {
            at: tear,
            declared: cut.len() as u32,
            remaining: (cut.len() / 2) as u64,
        })
    );
    assert_eq!(meta.bytes_read, tear);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, kept);
}

/// A block header cut off in the middle of its own length field — fewer than
/// the eight bytes needed to know what the block even is.
#[test]
fn a_block_header_shorter_than_its_length_field_ends_the_walk_as_a_tear() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x55, 16), 16));
    bytes.extend_from_slice(&[0x06, 0x00, 0x00]); // three bytes of a block type

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    let tear = (bytes.len() - 3) as u64;
    assert_eq!(meta.stopped, Some(StopReason::HeaderShort { at: tear }));
    assert_eq!(meta.bytes_read, tear);
}

/// A declared block length smaller than the 12 bytes of framing it describes.
/// Advancing by it makes no progress — zero advances not at all, eight advances
/// backwards past the length field — so a reader that trusts it either spins
/// forever or re-reads the same bytes until it overflows an offset. Neither is
/// acceptable on attacker-controlled input.
#[test]
fn a_block_length_smaller_than_its_own_framing_stops_the_walk_instead_of_looping() {
    for absurd_length in [0u32, 8, 11] {
        let mut bytes = shb(true, &[]);
        bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
        let kept = frame(0x66, 24);
        bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &kept, 24));

        let bad_at = bytes.len() as u64;
        let mut bad = Buf::new(true);
        bad.u32(EPB_TYPE);
        bad.u32(absurd_length);
        bytes.extend_from_slice(&bad.done());
        bytes.extend_from_slice(&frame(0x77, 64));

        let (meta, packets) = walk_ok(&bytes);

        assert_eq!(packets.len(), 1, "absurd_length={absurd_length}");
        assert_eq!(packets[0].data, kept, "absurd_length={absurd_length}");
        assert_eq!(
            meta.stopped,
            Some(StopReason::BlockLengthInvalid {
                at: bad_at,
                declared: absurd_length,
            }),
            "absurd_length={absurd_length}: the rest of the capture was not read, and \
             an unread remainder must never render as an empty one"
        );
        assert_eq!(meta.bytes_read, bad_at, "absurd_length={absurd_length}");
    }
}

/// A block length larger than the whole file. `offset + length` is the overflow
/// site; with overflow-checks on in release this is a production panic, and
/// without the bounds check it is an out-of-range slice.
#[test]
fn a_block_length_larger_than_the_file_is_reported_as_a_truncated_tail() {
    for absurd_length in [0x1000_0000u32, u32::MAX, u32::MAX - 3] {
        let mut bytes = shb(true, &[]);
        bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
        let kept = frame(0x88, 24);
        bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &kept, 24));

        let bad_at = bytes.len() as u64;
        let mut bad = Buf::new(true);
        bad.u32(EPB_TYPE);
        bad.u32(absurd_length);
        bad.u32(0);
        bytes.extend_from_slice(&bad.done());

        let (meta, packets) = walk_ok(&bytes);

        assert_eq!(packets.len(), 1, "absurd_length={absurd_length}");
        assert_eq!(packets[0].data, kept, "absurd_length={absurd_length}");
        // A length that is not a multiple of four is wrong in itself, before
        // the file's size comes into it; the other two are well-formed numbers
        // the file is simply too short for.
        let expected = if absurd_length.is_multiple_of(4) {
            StopReason::BlockPastEof {
                at: bad_at,
                declared: absurd_length,
                remaining: 12,
            }
        } else {
            StopReason::BlockLengthInvalid {
                at: bad_at,
                declared: absurd_length,
            }
        };
        assert_eq!(
            meta.stopped,
            Some(expected),
            "absurd_length={absurd_length}"
        );
        assert_eq!(meta.bytes_read, bad_at, "absurd_length={absurd_length}");
    }
}

/// An EPB whose captured length exceeds the bytes its own block contains. The
/// block length is the authority; the captured length is not to be trusted
/// against it.
#[test]
fn an_epb_claiming_more_captured_bytes_than_its_block_holds_does_not_read_past_it() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));

    let mut body = Buf::new(true);
    body.u32(0); // interface
    body.u32(0); // ts high
    body.u32(0); // ts low
    body.u32(4_000); // captured length, far beyond the block
    body.u32(4_000);
    body.raw(&frame(0x99, 16));
    bytes.extend_from_slice(&ng_block(true, EPB_TYPE, &body.done()));
    let after = frame(0xAA, 20);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &after, 20));

    let (meta, packets) = walk_ok(&bytes);

    // The over-claiming block yields only the 16 bytes it actually holds, and
    // its wire length is kept so the shortfall is visible; the next block is
    // untouched by it.
    assert!(
        packets[0].data.len() <= 16,
        "no packet may carry bytes the block did not contain"
    );
    assert_eq!(packets[0].orig_len, 4_000);
    assert!(
        packets.iter().any(|p| p.data == after),
        "the following block is intact and must still be walked"
    );
    assert_eq!(meta.reported_drops, 0);
    assert_eq!(
        meta.over_claimed_packets, 1,
        "a block that disagrees with itself is evidence of damage, and clamping it \
         silently hands file damage up as ordinary snaplen truncation"
    );
}

/// The same over-claiming EPB, asserted per packet rather than across all of
/// them. `an_epb_claiming_more_captured_bytes_than_its_block_holds_does_not_read_past_it`
/// above bounds *every* packet at the clamped block's sixteen bytes while also
/// requiring the twenty-byte packet that follows it, which no reader can
/// satisfy; this states the behaviour that test was reaching for — the
/// over-claiming block is clamped to what it holds, and the intact block after
/// it is unaffected.
#[test]
fn an_epb_over_claiming_its_captured_length_is_clamped_without_shortening_the_next_block() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));

    let mut body = Buf::new(true);
    body.u32(0); // interface
    body.u32(0); // ts high
    body.u32(0); // ts low
    body.u32(4_000); // captured length, far beyond the block
    body.u32(4_000);
    let held = frame(0x99, 16);
    body.raw(&held);
    bytes.extend_from_slice(&ng_block(true, EPB_TYPE, &body.done()));
    let after = frame(0xAA, 20);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &after, 20));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 2);
    assert_eq!(
        packets[0].data, held,
        "the block's own length is the authority over the captured length it declares"
    );
    assert_eq!(
        packets[0].orig_len, 4_000,
        "the wire length is still what the file claimed, and clamping the captured \
         bytes must not quietly rewrite it"
    );
    assert_eq!(
        packets[1].data, after,
        "the following block is intact and must be read at its own full length"
    );
    assert_eq!(meta.reported_drops, 0);
    assert_eq!(meta.over_claimed_packets, 1);
}

/// A block length that is not a multiple of four. pcapng aligns every block to
/// four bytes, so a length that is not aligned means the stream's block
/// boundaries are lost from here on; continuing would report every later block
/// at a guessed offset.
#[test]
fn a_block_length_that_is_not_four_byte_aligned_ends_the_walk_rather_than_guessing() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let kept = frame(0x12, 24);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &kept, 24));

    let bad_at = bytes.len() as u64;
    let mut bad = Buf::new(true);
    bad.u32(EPB_TYPE);
    bad.u32(30); // twelve bytes of framing and a body that ends mid-word
    bytes.extend_from_slice(&bad.done());
    bytes.extend_from_slice(&frame(0x13, 64));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, kept);
    assert_eq!(
        meta.stopped,
        Some(StopReason::BlockLengthInvalid {
            at: bad_at,
            declared: 30,
        })
    );
    assert_eq!(meta.bytes_read, bad_at);
}

/// A capture merged from two captures — the shape `shb_userappl = Mergecap`
/// announces — carries a second section, and the second section numbers its
/// interfaces from zero again. A reader that keeps one flat interface list and
/// indexes it with the raw interface id attributes the second section's traffic
/// to the first section's NIC, at the first section's timestamp resolution.
#[test]
fn a_second_section_numbers_its_interfaces_from_zero_again() {
    let mut bytes = shb(true, &[option(true, OPT_SHB_OS, b"Kali")]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[option(true, OPT_IF_NAME, b"eth0")],
    ));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x21, 16), 16));

    bytes.extend_from_slice(&shb(true, &[]));
    bytes.extend_from_slice(&idb(
        true,
        113, // Linux SLL
        262_144,
        &[option(true, OPT_IF_NAME, b"any"), if_tsresol(true, 9)],
    ));
    let second_section = frame(0x22, 16);
    bytes.extend_from_slice(&epb(
        true,
        0, // the second section's own interface zero, not the first section's
        1_600_483_249_936_000_000,
        &second_section,
        16,
    ));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces.len(), 2);
    assert_eq!(meta.interfaces[1].name.as_deref(), Some("any"));
    assert_eq!(meta.sections.len(), 2);
    assert_eq!(meta.sections[0].os.as_deref(), Some("Kali"));
    assert_eq!(
        meta.sections[1].os, None,
        "the second section declared no OS, and the first section's must not be \
         carried over as if it had"
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[1].data, second_section);
    assert_eq!(
        packets[1].iface, 1,
        "the reported interface must index the interfaces this walk reported, so the \
         packet resolves to the NIC its own section declared"
    );
    assert_eq!(
        packets[1].ts_micros,
        Some(TS_MICROS_AT_936MS),
        "the second section's interface counts nanoseconds, and reading it at the \
         first section's microseconds would date the packet in 52-thousand AD"
    );
}

/// An EPB naming an interface no IDB declared. There is no linktype and no
/// timestamp resolution for it, so the packet cannot be honestly timestamped —
/// but it must not panic on the index either.
#[test]
fn a_packet_naming_an_interface_that_was_never_declared_does_not_index_out_of_bounds() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 7, TS_MICROS_AT_936MS, &frame(0xBB, 16), 16));
    let known = frame(0xCC, 16);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &known, 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces.len(), 1);
    assert!(
        packets.iter().any(|p| p.data == known),
        "one unattributable packet must not cost the packets around it"
    );
    assert_eq!(
        packets.len(),
        1,
        "the unattributable packet must be withheld, not dated at a guessed resolution"
    );
    assert_eq!(
        meta.packets_on_undeclared_interface, 1,
        "withheld is not the same as absent: the traffic was there"
    );
    assert!(
        meta.unknown_block_types.is_empty(),
        "an EPB is not an unknown block type; conflating the two hides whether a packet \
         or an extension block went unread"
    );
}

/// A second IDB adds a second interface, and an EPB's interface_id indexes the
/// IDBs in declaration order. Getting this wrong attributes traffic to the wrong
/// NIC — and, when the two differ in if_tsresol, to the wrong time.
#[test]
fn a_second_interface_block_is_indexed_by_the_order_the_blocks_declared_it() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[option(true, OPT_IF_NAME, b"eth0")],
    ));
    bytes.extend_from_slice(&idb(
        true,
        113, // Linux SLL
        262_144,
        &[option(true, OPT_IF_NAME, b"any"), if_tsresol(true, 9)],
    ));
    bytes.extend_from_slice(&epb(
        true,
        1,
        1_600_483_249_936_000_000,
        &frame(0xDD, 16),
        16,
    ));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces.len(), 2);
    assert_eq!(meta.interfaces[0].name.as_deref(), Some("eth0"));
    assert_eq!(meta.interfaces[1].linktype, 113);
    assert_eq!(meta.interfaces[1].ts_resol, TsResol::Pow10(9));
    assert_eq!(packets[0].iface, 1);
    assert_eq!(
        packets[0].ts_micros,
        Some(TS_MICROS_AT_936MS),
        "the second interface's own resolution governs its own packets"
    );
}

/// pcapng version 1.0 is the only one written. A major version this build has
/// not been shown to read must be named, not parsed hopefully.
#[test]
fn an_unknown_pcapng_major_version_is_named_rather_than_guessed_at() {
    let bytes = shb_versioned(true, 2, 0, &[]);
    assert_eq!(
        walk(&bytes),
        Err(CaptureError::UnsupportedVersion { major: 2, minor: 0 })
    );
}

// ---------------------------------------------------------------------------
// Timestamp resolution
// ---------------------------------------------------------------------------

/// `if_tsresol` with its top bit set counts timestamps in 2^-n seconds, which is
/// legal and which some hardware timestampers emit. A reader that cannot express
/// that and falls back to the 10^-6 default dates every packet on the interface
/// about 976x too early — here 1.024 ms after the epoch instead of one second —
/// and presents the result as an observation. A mis-dated packet on the case
/// timeline is a false alibi.
#[test]
fn an_if_tsresol_selecting_a_power_of_two_is_honoured_rather_than_read_as_microseconds() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(true, 0x80 | 10)],
    ));
    bytes.extend_from_slice(&epb(true, 0, 1_024, &frame(0x14, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces[0].ts_resol, TsResol::Pow2(10));
    assert_eq!(
        packets[0].ts_micros,
        Some(1_000_000),
        "1024 ticks of 2^-10 s is exactly one second"
    );
    assert_eq!(meta.packets_without_timestamp, 0);
}

/// The power-of-two conversion cannot be done by dividing by a power of ten
/// rounded to the nearest one. 2^-20 s is 0.954 us, and over a modern epoch
/// timestamp treating it as a microsecond puts the packet 21 months late.
#[test]
fn a_power_of_two_resolution_is_converted_exactly_rather_than_approximated_by_a_power_of_ten() {
    // 2^20 ticks/s over TS_SEC seconds plus 0.5 s.
    let ticks = (u64::from(TS_SEC) << 20) + (1 << 19);
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(true, 0x80 | 20)],
    ));
    bytes.extend_from_slice(&epb(true, 0, ticks, &frame(0x15, 16), 16));

    let (_meta, packets) = walk_ok(&bytes);

    assert_eq!(
        packets[0].ts_micros,
        Some(u64::from(TS_SEC) * 1_000_000 + 500_000)
    );
}

/// A resolution coarser than microseconds scales *up*. The multiply arm is
/// unreached by every other fixture, so a millisecond capture mis-scaled by a
/// thousand would otherwise go unnoticed.
#[test]
fn an_interface_counting_milliseconds_has_its_timestamps_scaled_up_to_microseconds() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(true, 3)],
    ));
    bytes.extend_from_slice(&epb(true, 0, 1_600_483_249_936, &frame(0x16, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces[0].ts_resol, TsResol::Pow10(3));
    assert_eq!(packets[0].ts_micros, Some(TS_MICROS_AT_936MS));
}

/// A resolution so fine that no 64-bit tick count reaches past the first two
/// seconds of 1970 — 10^-20 s, or 2^-64 s — cannot date any packet in any real
/// capture. Rounding the instant to zero presents 1970-01-01T00:00:00Z as an
/// observation, which on a timeline beside the EVTX records is not "unknown"
/// but a positive claim that the traffic predates the incident by fifty years.
/// The packet is evidence and is kept; its time is not, and the loss is counted.
#[test]
fn an_if_tsresol_finer_than_any_tick_count_can_date_leaves_the_packet_undated_rather_than_at_the_epoch(
) {
    for (encoded, expected) in [
        (100u8, TsResol::Pow10(100)),
        (20, TsResol::Pow10(20)),
        (0x80 | 64, TsResol::Pow2(64)),
        (0x80 | 127, TsResol::Pow2(127)),
    ] {
        let mut bytes = shb(true, &[]);
        bytes.extend_from_slice(&idb(
            true,
            LINKTYPE_ETHERNET,
            65_535,
            &[if_tsresol(true, encoded)],
        ));
        let payload = frame(0x17, 16);
        bytes.extend_from_slice(&epb(true, 0, 1_600_000_000_000_000, &payload, 16));

        let (meta, packets) = walk_ok(&bytes);

        assert_eq!(
            meta.interfaces[0].ts_resol, expected,
            "encoded={encoded:#04x}: the declared resolution is reported as declared"
        );
        assert_eq!(
            packets.len(),
            1,
            "encoded={encoded:#04x}: the packet is still evidence"
        );
        assert_eq!(packets[0].data, payload);
        assert_eq!(
            packets[0].ts_micros, None,
            "encoded={encoded:#04x}: an instant this resolution cannot express is not the epoch"
        );
        assert_eq!(meta.packets_without_timestamp, 0, "encoded={encoded:#04x}");
        assert_eq!(
            meta.packets_with_unresolvable_timestamp, 1,
            "encoded={encoded:#04x}: a timestamp that was there and could not be read \
             is not the same fact as a block that carries none"
        );
        assert_eq!(meta.stopped, None, "encoded={encoded:#04x}");
    }
}

/// 10^-19 s is the finest power-of-ten resolution at which a u64 still covers
/// more than a second, so it is representable; the packet gets a real time.
#[test]
fn the_finest_representable_power_of_ten_resolution_still_dates_its_packets() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(true, 19)],
    ));
    bytes.extend_from_slice(&epb(
        true,
        0,
        15_000_000_000_000_000_000,
        &frame(0x18, 16),
        16,
    ));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets[0].ts_micros, Some(1_500_000));
    assert_eq!(meta.packets_with_unresolvable_timestamp, 0);
}

/// A coarse resolution whose tick count, scaled up, does not fit a u64 is a
/// date beyond the year 584,000. Saturating would present that as the largest
/// representable instant — a fabricated date — so it is undated and counted.
#[test]
fn a_scaled_timestamp_that_overflows_is_undated_rather_than_saturated() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(
        true,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(true, 0)],
    ));
    bytes.extend_from_slice(&epb(true, 0, u64::MAX, &frame(0x19, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets[0].ts_micros, None);
    assert_eq!(meta.packets_with_unresolvable_timestamp, 1);
}

/// A Simple Packet Block carries no timestamp, and there is nothing in the
/// file to derive one from. Emitting zero puts every SPB at the Unix epoch on
/// the case timeline and makes a flow that mixes EPBs and SPBs first-seen in
/// 1970. The type has to be able to say "no time", and the count has to say
/// how many packets are undated for that reason.
#[test]
fn a_simple_packet_block_carries_no_timestamp_and_is_not_dated_to_the_epoch() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&spb(true, &frame(0x1A, 16), 16));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x1B, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].ts_micros, None);
    assert_eq!(packets[1].ts_micros, Some(TS_MICROS_AT_936MS));
    assert_eq!(meta.packets_without_timestamp, 1);
    assert_eq!(meta.packets_with_unresolvable_timestamp, 0);
}

/// The SPB's one length field is the *wire* length. The fixture in
/// `a_simple_packet_block_takes_its_captured_length_from_the_block_length` has
/// the two equal, so a reader that took the wire length as the captured one
/// would pass it; this one does not.
#[test]
fn a_simple_packet_block_whose_wire_length_exceeds_the_block_reports_only_the_bytes_the_block_holds(
) {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let held = frame(0x1C, 16);
    bytes.extend_from_slice(&spb(true, &held, 1_514));
    let after = frame(0x1D, 20);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &after, 20));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].data, held);
    assert_eq!(packets[0].orig_len, 1_514);
    assert_eq!(packets[1].data, after);
    assert_eq!(
        meta.over_claimed_packets, 0,
        "an SPB declares no captured length, so it cannot over-claim one; snaplen \
         truncation is the ordinary case, not damage"
    );
}

/// The interface's snaplen bounds what an SPB can hold. A writer that wrote 64
/// bytes into an SPB on a 40-byte-snaplen interface has contradicted itself,
/// and the bytes past the snaplen were never part of the packet as captured.
#[test]
fn a_simple_packet_block_is_bounded_by_its_interface_snaplen() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 40, &[]));
    bytes.extend_from_slice(&spb(true, &frame(0x1E, 64), 64));

    let (_meta, packets) = walk_ok(&bytes);

    assert_eq!(packets[0].data.len(), 40);
    assert_eq!(packets[0].orig_len, 64);
}

// ---------------------------------------------------------------------------
// Interface statistics
// ---------------------------------------------------------------------------

/// `isb_ifdrop` is a counter *since the start of the capture*, and dumpcap
/// writes an ISB every time its ring buffer rolls. Summing the three values
/// below reports 750 lost packets where the engine said 400 — an inflated
/// figure on the one number in the file that states how much is missing, and
/// the inflation scales with how often the writer emitted statistics.
#[test]
fn periodic_interface_statistics_blocks_are_cumulative_and_are_not_summed() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 100));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x2A, 16), 16));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 250));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 400));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 400);
    assert_eq!(
        meta.interface_statistics.get(&0).and_then(|s| s.if_drops),
        Some(400)
    );
}

/// Two interfaces each report their own cumulative count, and the capture-wide
/// total is the sum of each interface's *last* figure — the ISB's interface id
/// is what keeps them apart.
#[test]
fn drop_counts_are_kept_per_interface_and_totalled_across_them() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&idb(true, 113, 65_535, &[]));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 10));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 1, 5));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 12));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 1, 5));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 17);
    assert_eq!(
        meta.interface_statistics.get(&0).and_then(|s| s.if_drops),
        Some(12)
    );
    assert_eq!(
        meta.interface_statistics.get(&1).and_then(|s| s.if_drops),
        Some(5)
    );
}

/// `isb_osdrop` is the packets the operating system dropped before the capture
/// interface saw them — a separate loss from `isb_ifdrop`, and one a reader that
/// only knows option 5 reports as zero. `isb_ifrecv` is the denominator without
/// which no drop figure can be read as a rate.
#[test]
fn os_drops_and_received_counts_are_read_separately_from_interface_drops() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&isb(
        true,
        0,
        &[
            (OPT_ISB_IFRECV, 500_000),
            (OPT_ISB_IFDROP, 1_203),
            (OPT_ISB_OSDROP, 9_999),
        ],
    ));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 1_203);
    assert_eq!(meta.reported_os_drops, 9_999);
    let stats = &meta.interface_statistics[&0];
    assert_eq!(stats.if_received, Some(500_000));
    assert_eq!(stats.if_drops, Some(1_203));
    assert_eq!(stats.os_drops, Some(9_999));
}

/// An ISB that states a drop count in a field this build cannot read — four
/// bytes where the spec says eight — must not read as "no drops reported". The
/// difference between "the engine said nothing" and "the engine said something
/// we could not read" is the whole of what the examiner is told about
/// completeness.
#[test]
fn a_drop_count_that_is_present_but_unreadable_is_counted_rather_than_read_as_zero() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let mut body = Buf::new(true);
    body.u32(0);
    body.u32(0);
    body.u32(0);
    body.raw(&option(true, OPT_ISB_IFDROP, &1_203u32.to_le_bytes()));
    body.raw(&end_of_options(true));
    bytes.extend_from_slice(&ng_block(true, ISB_TYPE, &body.done()));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 0);
    assert_eq!(
        meta.interface_statistics.get(&0).and_then(|s| s.if_drops),
        None,
        "a count that could not be read must not become a stated zero"
    );
    assert_eq!(meta.unreadable_statistics, 1);
}

/// An ISB shorter than its own fixed fields, and one naming an interface no
/// IDB declared: each is a statistics block whose counters cannot be
/// attributed, so they are absent from the totals and the absence is counted.
#[test]
fn a_statistics_block_that_cannot_be_attributed_is_counted_and_kept_out_of_the_totals() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&ng_block(true, ISB_TYPE, &[0u8; 8]));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 9, 77));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.reported_drops, 0);
    assert!(meta.interface_statistics.is_empty());
    assert_eq!(meta.unreadable_statistics, 2);
    assert!(meta.unknown_block_types.is_empty());
}

// ---------------------------------------------------------------------------
// Where and why the walk stopped
// ---------------------------------------------------------------------------

/// A bad block in the middle of a large capture. The old `truncated_tail` bool
/// read as "the last packet was clipped"; here one packet of a thousand and one
/// was read, and the examiner needs the offset the walk stopped at to know that
/// almost the whole file went unread.
#[test]
fn a_mid_file_structural_failure_records_where_it_stopped_and_how_much_went_unread() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x3A, 16), 16));
    let bad_at = bytes.len() as u64;
    let mut bad = Buf::new(true);
    bad.u32(EPB_TYPE);
    bad.u32(17);
    bytes.extend_from_slice(&bad.done());
    bytes.extend_from_slice(&frame(0x3B, 12));
    for i in 0..1_000u64 {
        bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS + i, &frame(0x3C, 40), 40));
    }

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    let stopped = meta.stopped.expect("the walk did not finish the file");
    assert_eq!(
        stopped,
        StopReason::BlockLengthInvalid {
            at: bad_at,
            declared: 17,
        }
    );
    assert_eq!(stopped.at(), bad_at);
    assert_eq!(stopped.reason(), "block_length_invalid");
    assert_eq!(meta.bytes_read, bad_at);
    assert!(
        (bytes.len() as u64 - meta.bytes_read) > 50_000,
        "the unread remainder is the examiner's measure of how partial this read was"
    );
}

/// A section header this build cannot read — its byte-order magic is neither
/// value — leaves the byte order of everything after it unknown, and the
/// remainder is unread rather than empty.
#[test]
fn a_section_header_with_an_unreadable_byte_order_magic_stops_the_walk_by_name() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x3D, 16), 16));
    let second_at = bytes.len() as u64;
    let mut second = shb(true, &[]);
    second[8..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    bytes.extend_from_slice(&second);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x3E, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    assert_eq!(
        meta.stopped,
        Some(StopReason::UnreadableSection { at: second_at })
    );
    assert_eq!(meta.bytes_read, second_at);
    assert_eq!(
        meta.sections.len(),
        1,
        "the unreadable section is not a section"
    );
}

/// A later section with a major version this build does not read is the same
/// refusal as a first one — but mid-file it is a stop, not an error, because
/// the packets before it are evidence.
#[test]
fn a_later_section_of_an_unsupported_version_stops_the_walk_rather_than_being_parsed_hopefully() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x3F, 16), 16));
    let second_at = bytes.len() as u64;
    bytes.extend_from_slice(&shb_versioned(true, 2, 0, &[]));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    assert_eq!(
        meta.stopped,
        Some(StopReason::UnreadableSection { at: second_at })
    );
}

/// An IDB whose body is shorter than its fixed fields. Without a complete
/// interface table every later packet's attribution would be a guess.
#[test]
fn an_interface_block_shorter_than_its_fixed_fields_stops_the_walk_by_name() {
    let mut bytes = shb(true, &[]);
    let idb_at = bytes.len() as u64;
    bytes.extend_from_slice(&ng_block(true, IDB_TYPE, &[1, 0]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x40, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert!(packets.is_empty());
    assert_eq!(
        meta.stopped,
        Some(StopReason::InterfaceBlockShort { at: idb_at })
    );
    assert_eq!(meta.bytes_read, idb_at);
}

/// Every stop reason has a stable name for the report to quote and carries the
/// offset it stopped at.
#[test]
fn every_stop_reason_names_itself_stably_and_carries_its_offset() {
    let reasons = [
        (
            StopReason::BlockLengthInvalid {
                at: 10,
                declared: 17,
            },
            "block_length_invalid",
        ),
        (
            StopReason::BlockPastEof {
                at: 20,
                declared: 4_000,
                remaining: 12,
            },
            "block_past_eof",
        ),
        (StopReason::HeaderShort { at: 30 }, "header_short"),
        (
            StopReason::InterfaceBlockShort { at: 40 },
            "interface_block_short",
        ),
        (
            StopReason::UnreadableSection { at: 50 },
            "unreadable_section",
        ),
    ];
    for (i, (reason, name)) in reasons.iter().enumerate() {
        assert_eq!(reason.reason(), *name);
        assert_eq!(reason.at(), (i as u64 + 1) * 10);
    }
}

// ---------------------------------------------------------------------------
// Block-level damage that does not stop the walk
// ---------------------------------------------------------------------------

/// pcapng writes every block's length twice so the stream can be walked
/// backwards. When the two disagree, a forward-walking reader and a validating
/// one see different packet streams — Wireshark and libpcap refuse such a
/// file. The block is still read here, because its bytes are evidence, but the
/// disagreement is corruption or tampering and goes on the record.
#[test]
fn a_block_whose_trailing_length_disagrees_with_its_leading_one_is_read_and_counted() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let payload = frame(0x4A, 16);
    let mut block = epb(true, 0, TS_MICROS_AT_936MS, &payload, 16);
    let end = block.len();
    block[end - 4..].copy_from_slice(&9_999u32.to_le_bytes());
    bytes.extend_from_slice(&block);
    let after = frame(0x4B, 20);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS + 1, &after, 20));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].data, payload);
    assert_eq!(packets[1].data, after);
    assert_eq!(meta.mismatched_block_trailers, 1);
    assert_eq!(meta.stopped, None);
}

/// An option whose declared length runs past the end of the option list. A
/// proper opt_endofopt means "there were no more options"; a short read means
/// "there were more and we could not read them" — and when the option that
/// was cut is if_tsresol, the difference is every timestamp on the interface
/// being a thousand times out.
#[test]
fn an_option_cut_short_by_the_end_of_its_block_is_counted_rather_than_read_as_end_of_options() {
    let mut body = Buf::new(true);
    body.u16(LINKTYPE_ETHERNET);
    body.u16(0);
    body.u32(65_535);
    body.u16(OPT_IF_TSRESOL);
    body.u16(9); // declares nine bytes of value...
    body.raw(&[9, 0, 0, 0]); // ...and the block ends after four
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&ng_block(true, IDB_TYPE, &body.done()));
    bytes.extend_from_slice(&epb(true, 0, 1_000_000_000, &frame(0x4C, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.truncated_options, 1);
    assert_eq!(
        meta.interfaces[0].ts_resol,
        TsResol::Pow10(6),
        "the option was not read, so the default stands — but the count says it was not read"
    );
    assert_eq!(packets.len(), 1);
    assert_eq!(meta.stopped, None);
}

/// The same cut inside a section header, where the option lost is the
/// Mergecap provenance an examiner quoting the capture has to be told about.
#[test]
fn a_section_header_option_cut_short_is_counted() {
    let mut body = Buf::new(true);
    body.u32(BYTE_ORDER_MAGIC);
    body.u16(1);
    body.u16(0);
    body.i64(-1);
    body.u16(OPT_SHB_USERAPPL);
    body.u16(26); // "Mergecap (Wireshark) 3.2.6"...
    body.raw(b"Merg"); // ...cut after four bytes
    let mut bytes = ng_block(true, SHB_TYPE, &body.done());
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.truncated_options, 1);
    assert_eq!(
        meta.sections[0].application, None,
        "four bytes of a name are not the name"
    );
}

/// A well-formed option list that ends without opt_endofopt is how many
/// writers end a block with no options at all, and must not be counted as cut.
#[test]
fn a_block_with_no_options_at_all_is_not_a_truncated_option_list() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&isb_with_ifdrop(true, 0, 1));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.truncated_options, 0);
}

/// Two different unknown block types are two different refusals. A Name
/// Resolution Block carries the address-to-name mappings the plan wants next;
/// a Decryption Secrets Block carries TLS keys. Counting them as "2 unknown"
/// names neither.
#[test]
fn each_unknown_block_type_is_counted_under_its_own_type_code() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&ng_block(true, 0x0000_0004, b"name resolution"));
    bytes.extend_from_slice(&ng_block(true, 0x0000_000A, b"decryption secrets"));
    bytes.extend_from_slice(&ng_block(true, 0x0000_0004, b"name resolution again"));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x4D, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(
        meta.unknown_block_types,
        BTreeMap::from([(0x0000_0004, 2), (0x0000_000A, 1)])
    );
    assert_eq!(packets.len(), 1);
}

/// An EPB or SPB whose body is shorter than its own fixed fields is a packet
/// record that was there and could not be read at all — which is neither an
/// unknown block type nor a packet on an undeclared interface.
#[test]
fn a_packet_block_shorter_than_its_fixed_fields_is_counted_as_its_own_kind_of_loss() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&ng_block(true, EPB_TYPE, &[0u8; 16]));
    bytes.extend_from_slice(&ng_block(true, SPB_TYPE, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x4E, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    assert_eq!(meta.packet_blocks_short, 2);
    assert_eq!(meta.packets_on_undeclared_interface, 0);
    assert!(meta.unknown_block_types.is_empty());
}

/// The over-claim with `orig_len` equal to the bytes held: `orig_len >
/// data.len()` no longer flags it, so the only trace of the block's
/// self-contradiction is the counter.
#[test]
fn an_over_claiming_epb_whose_wire_length_matches_its_bytes_is_still_counted_as_damage() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let mut body = Buf::new(true);
    body.u32(0);
    body.u32(0);
    body.u32(0);
    body.u32(u32::MAX);
    body.u32(8);
    body.raw(&frame(0x4F, 8));
    bytes.extend_from_slice(&ng_block(true, EPB_TYPE, &body.done()));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data.len(), 8);
    assert_eq!(packets[0].orig_len, 8);
    assert_eq!(meta.over_claimed_packets, 1);
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

/// `cat little.pcapng big.pcapng > merged.pcapng` is a legal file: every
/// section has its own byte-order magic and every field of an SHB, including
/// its own total length, is in the order that magic declares. A reader that
/// reads the second SHB's length in the first section's order sees 0x1C000000
/// bytes, walks off the end of the file, and reports half a valid capture as
/// an unreadable tail.
#[test]
fn a_second_section_in_the_opposite_byte_order_is_read_through_its_own_magic() {
    let mut bytes = shb(true, &[option(true, OPT_SHB_USERAPPL, b"dumpcap")]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    let first = frame(0x5A, 16);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &first, 16));

    bytes.extend_from_slice(&shb(false, &[option(false, OPT_SHB_USERAPPL, b"snoop")]));
    bytes.extend_from_slice(&idb(false, LINKTYPE_ETHERNET, 65_535, &[]));
    let second = frame(0x5B, 24);
    bytes.extend_from_slice(&epb(false, 0, TS_MICROS_AT_936MS + 7, &second, 24));
    let third = frame(0x5C, 32);
    bytes.extend_from_slice(&epb(false, 0, TS_MICROS_AT_936MS + 9, &third, 32));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.stopped, None);
    assert_eq!(meta.bytes_read, bytes.len() as u64);
    assert_eq!(meta.interfaces.len(), 2);
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[1].data, second);
    assert_eq!(packets[1].iface, 1);
    assert_eq!(packets[1].ts_micros, Some(TS_MICROS_AT_936MS + 7));
    assert_eq!(packets[2].data, third);
    assert_eq!(meta.sections.len(), 2);
    assert_eq!(meta.sections[0].application.as_deref(), Some("dumpcap"));
    assert_eq!(meta.sections[1].application.as_deref(), Some("snoop"));
    assert!(
        meta.little_endian,
        "the capture-level byte order is the first section's"
    );
}

/// Mergecap output has one section per merged file, each with its own
/// provenance. Keeping one set of fields means the last section wins and the
/// reported hardware/os/application may belong to a different section than
/// the packets being quoted.
#[test]
fn each_section_keeps_its_own_provenance_rather_than_the_last_one_overwriting_the_rest() {
    let mut bytes = shb(
        true,
        &[
            option(true, OPT_SHB_HARDWARE, b"x86"),
            option(true, OPT_SHB_OS, b"Linux 5.8.0-kali1-amd64"),
            option(true, OPT_SHB_USERAPPL, b"Mergecap (Wireshark) 3.2.6"),
        ],
    );
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&shb(true, &[option(true, OPT_SHB_OS, b"Windows 10")]));
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&shb(true, &[]));
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(
        meta.sections,
        vec![
            SectionInfo {
                hardware: Some("x86".into()),
                os: Some("Linux 5.8.0-kali1-amd64".into()),
                application: Some("Mergecap (Wireshark) 3.2.6".into()),
            },
            SectionInfo {
                hardware: None,
                os: Some("Windows 10".into()),
                application: None,
            },
            SectionInfo {
                hardware: None,
                os: None,
                application: None,
            },
        ]
    );
    assert!(!meta.cap_reached_sections);
}

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

/// The interface table is the one structure in the walk that accumulates
/// rather than streams, so a file of nothing but IDBs costs about twice its
/// own size in memory with no bound. Past the cap, IDBs are not kept and the
/// table is stamped incomplete; packets on the interfaces that were not kept
/// cannot be attributed and are counted as such rather than guessed at.
#[test]
fn the_interface_table_is_capped_and_the_cap_is_on_the_record() {
    let mut bytes = shb(true, &[]);
    for _ in 0..=MAX_INTERFACES {
        bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    }
    bytes.extend_from_slice(&epb(
        true,
        MAX_INTERFACES as u32,
        TS_MICROS_AT_936MS,
        &frame(0x6A, 16),
        16,
    ));
    let kept = frame(0x6B, 16);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &kept, 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces.len(), MAX_INTERFACES);
    assert!(meta.cap_reached_interfaces);
    assert_eq!(meta.stopped, None, "the cap does not end the walk");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, kept);
    assert_eq!(meta.packets_on_undeclared_interface, 1);
}

/// A capture with fewer interfaces than the cap is not stamped as capped: the
/// stamp means "there were more", never "there could have been".
#[test]
fn an_interface_table_below_the_cap_is_not_stamped_as_capped() {
    let mut bytes = shb(true, &[]);
    for _ in 0..MAX_INTERFACES {
        bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    }

    let (meta, _packets) = walk_ok(&bytes);

    assert_eq!(meta.interfaces.len(), MAX_INTERFACES);
    assert!(!meta.cap_reached_interfaces);
}

/// The table of unknown block types is keyed by a 32-bit code the file
/// chooses, so a file of twelve-byte blocks each with a fresh code grows it
/// without bound. Past the cap the blocks are still counted — they were there
/// and were not read — but under one figure rather than by type.
#[test]
fn the_unknown_block_type_table_is_capped_and_later_types_are_still_counted() {
    let mut bytes = shb(true, &[]);
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    for code in 0..(MAX_UNKNOWN_BLOCK_TYPES as u32 + 3) {
        bytes.extend_from_slice(&ng_block(true, 0x4000_0000 | code, &[]));
    }
    // A type already in the table is still counted there past the cap.
    bytes.extend_from_slice(&ng_block(true, 0x4000_0000, &[]));
    let kept = frame(0x6D, 16);
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &kept, 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.unknown_block_types.len(), MAX_UNKNOWN_BLOCK_TYPES);
    assert_eq!(meta.unknown_block_types[&0x4000_0000], 2);
    assert!(meta.cap_reached_unknown_block_types);
    assert_eq!(meta.unknown_blocks_past_type_cap, 3);
    assert_eq!(meta.stopped, None);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, kept);
}

/// Sections accumulate the same way, and a file of nothing but SHBs is the
/// same shape of amplification.
#[test]
fn the_section_table_is_capped_and_the_cap_is_on_the_record() {
    let mut bytes = Vec::new();
    for _ in 0..=MAX_SECTIONS {
        bytes.extend_from_slice(&shb(true, &[]));
    }
    bytes.extend_from_slice(&idb(true, LINKTYPE_ETHERNET, 65_535, &[]));
    bytes.extend_from_slice(&epb(true, 0, TS_MICROS_AT_936MS, &frame(0x6C, 16), 16));

    let (meta, packets) = walk_ok(&bytes);

    assert_eq!(meta.sections.len(), MAX_SECTIONS);
    assert!(meta.cap_reached_sections);
    assert_eq!(meta.stopped, None);
    assert_eq!(
        packets.len(),
        1,
        "the packets after the capped sections are still read"
    );
}

// ---------------------------------------------------------------------------
// Refusals and the malformed corpus
// ---------------------------------------------------------------------------

/// Detection is by content, because the extension lies: Case 001's capture is
/// named `.pcap` and is pcapng. The converse must hold too — a file that is not
/// a capture must be refused rather than half-parsed into a plausible-looking
/// empty flow list.
#[test]
fn bytes_that_are_not_a_capture_at_all_are_refused_rather_than_guessed_at() {
    for junk in [
        b"MZ\x90\x00this is a PE file and not a capture".to_vec(),
        b"SQLite format 3\0".to_vec(),
        vec![0u8; 4096],
        (0u8..=255).cycle().take(1024).collect::<Vec<u8>>(),
    ] {
        assert_eq!(walk(&junk), Err(CaptureError::NotACapture), "{junk:02x?}");
    }
}

/// `0A0D0D0A` alone is four weak bytes that occur by chance in compressed data.
/// The byte-order magic is what makes the detection safe, so a file with the
/// block type but not the magic is not a capture.
#[test]
fn a_pcapng_block_type_without_the_byte_order_magic_is_not_a_capture() {
    let mut bytes = shb(true, &[]);
    bytes[8..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(walk(&bytes), Err(CaptureError::NotACapture));
}

/// Fewer bytes than a section header block needs to declare its byte order.
#[test]
fn a_pcapng_section_header_cut_off_before_its_magic_is_a_truncated_header() {
    let bytes = shb(true, &[]);
    assert_eq!(walk(&bytes[..10]), Err(CaptureError::HeaderTruncated));
}

/// An empty file is nothing at all, and must not be read as an empty capture.
#[test]
fn an_empty_file_is_not_an_empty_capture() {
    assert_eq!(walk(&[]), Err(CaptureError::NotACapture));
}

/// A capture with every block type this build knows, plus one it does not — the
/// base the malformed corpus below is cut from.
fn kitchen_sink_pcapng(little: bool) -> Vec<u8> {
    let mut bytes = shb(
        little,
        &[
            option(little, OPT_SHB_HARDWARE, b"x86"),
            option(little, OPT_SHB_OS, b"Linux 5.8.0-kali1-amd64"),
            option(little, OPT_SHB_USERAPPL, b"Mergecap (Wireshark) 3.2.6"),
        ],
    );
    bytes.extend_from_slice(&idb(
        little,
        LINKTYPE_ETHERNET,
        262_144,
        &[
            option(little, OPT_IF_NAME, b"enp0s3"),
            if_tsresol(little, 9),
        ],
    ));
    bytes.extend_from_slice(&idb(little, 113, 65_535, &[]));
    bytes.extend_from_slice(&epb(
        little,
        0,
        1_600_483_249_936_000_123,
        &frame(0x01, 60),
        1514,
    ));
    bytes.extend_from_slice(&spb(little, &frame(0x02, 16), 16));
    bytes.extend_from_slice(&ng_block(little, 0x0000_0BAD, b"unknown"));
    bytes.extend_from_slice(&isb(
        little,
        0,
        &[
            (OPT_ISB_IFRECV, 1_000),
            (OPT_ISB_IFDROP, 42),
            (OPT_ISB_OSDROP, 3),
        ],
    ));
    bytes.extend_from_slice(&epb(little, 1, 1_600_483_249_936_100, &frame(0x03, 40), 40));
    bytes.extend_from_slice(&shb(
        !little,
        &[option(!little, OPT_SHB_USERAPPL, b"snoop")],
    ));
    bytes.extend_from_slice(&idb(
        !little,
        LINKTYPE_ETHERNET,
        65_535,
        &[if_tsresol(!little, 0x80 | 10)],
    ));
    bytes.extend_from_slice(&epb(!little, 0, 1_600_483_249 << 10, &frame(0x04, 24), 24));
    bytes
}

/// The process-wide panic hook is left alone here on purpose. Replacing it
/// with a silencer while this loop runs mutes every other test's panic
/// message on the parallel threads, and an assertion failing inside the
/// loop would leave the silencer installed for the rest of the run. A
/// caught panic prints its message once; that is the cheaper trap.
fn walk_must_not_panic(bytes: &[u8], what: &str) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut count = 0usize;
        let _ = read_capture(bytes, &mut |_p: Packet<'_>| count += 1);
    }));
    assert!(
        outcome.is_ok(),
        "read_capture panicked on {what}; malformed captures are the normal case, \
         and a panic here takes the whole ingest down"
    );
}

/// Every prefix of a valid capture is a file an examiner can be handed: a
/// capture recovered from unallocated space, one copied off a failing disk, one
/// a writer was killed halfway through. None of them may panic.
#[test]
fn truncating_a_valid_capture_at_every_seventh_byte_never_panics() {
    for little in [true, false] {
        let full = kitchen_sink_pcapng(little);
        for cut in (0..=full.len()).step_by(7) {
            walk_must_not_panic(
                &full[..cut],
                &format!("pcapng little={little} cut at {cut}"),
            );
        }
    }

    let mut classic = classic_header(true, false, LINKTYPE_ETHERNET as u32, 65_535);
    classic.extend_from_slice(&classic_record(
        true,
        TS_SEC,
        936_000,
        &frame(0x04, 60),
        1514,
    ));
    classic.extend_from_slice(&classic_record(true, TS_SEC, 936_100, &frame(0x05, 40), 40));
    for cut in (0..=classic.len()).step_by(7) {
        walk_must_not_panic(&classic[..cut], &format!("classic pcap cut at {cut}"));
    }
}

/// Truncation is only half of corruption. Flipping bytes inside an otherwise
/// valid capture is what a bad sector does, and it produces the absurd lengths
/// and out-of-range interface ids that the bounds checks exist for.
#[test]
fn corrupting_every_seventh_byte_of_a_valid_capture_never_panics() {
    for little in [true, false] {
        let full = kitchen_sink_pcapng(little);
        for at in (0..full.len()).step_by(7) {
            for patch in [0x00u8, 0xFF] {
                let mut corrupt = full.clone();
                corrupt[at] = patch;
                walk_must_not_panic(
                    &corrupt,
                    &format!("pcapng little={little} byte {at} set to {patch:#04x}"),
                );
            }
        }
    }
}
