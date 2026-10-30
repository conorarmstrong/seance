//! Hand-built fixtures for the object-model tests: two synthetic ISFs, a
//! segmented byte image with a deliberate unmapped window in the middle of it,
//! and a second image whose ISF declares four-byte pointers.
//!
//! Everything here is built by hand rather than captured, so a test asserting
//! that a member came from offset 24 is asserting against bytes that were
//! placed at offset 24 for that reason. The hole between the two segments is
//! the point of the whole fixture: it is what proves that an unacquired member
//! errors instead of reading as zero. The second, 32-bit fixture exists for the
//! same kind of reason: it is what proves that pointer width is read out of the
//! symbol table rather than assumed from the host.

use std::sync::{Arc, OnceLock};

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use super::StructReader;
use crate::format::MemoryImageFormat;
use crate::layer::MemoryLayer;
use crate::meta::{Architecture, LayerMeta};
use crate::segmented::{Segment, SegmentedLayer};

/// A small, complete, internally consistent ISF describing the fixture image.
///
/// Deliberately not a real Windows or Linux profile: every offset here is one
/// a test can check by hand, and nothing about the tests depends on a layout
/// that a future symbol pack might change.
pub(crate) const FIXTURE_ISF: &str = r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-object-fixture", "version": "1.0.0"},
    "linux": {"symbols": [], "types": []}
  },
  "base_types": {
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "char": {"size": 1, "signed": true, "kind": "char", "endian": "little"},
    "__be32": {"size": 4, "signed": false, "kind": "int", "endian": "big"},
    "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
  },
  "user_types": {
    "endian_probe": {"size": 8, "kind": "struct", "fields": {
      "le": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}},
      "be": {"offset": 4, "type": {"kind": "base", "name": "__be32"}}
    }},
    "list_head": {"size": 16, "kind": "struct", "fields": {
      "next": {"offset": 0, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "list_head"}}},
      "prev": {"offset": 8, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "list_head"}}}
    }},
    "inner": {"size": 8, "kind": "struct", "fields": {
      "magic": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}},
      "depth": {"offset": 4, "type": {"kind": "base", "name": "int"}}
    }},
    "proc": {"size": 104, "kind": "struct", "fields": {
      "pid": {"offset": 0, "type": {"kind": "base", "name": "int"}},
      "uid": {"offset": 4, "type": {"kind": "base", "name": "unsigned int"}},
      "links": {"offset": 8, "type": {"kind": "struct", "name": "list_head"}},
      "ticks": {"offset": 24, "type": {"kind": "base", "name": "unsigned long long"}},
      "inner": {"offset": 32, "type": {"kind": "struct", "name": "inner"}},
      "name": {"offset": 40, "type": {"kind": "array", "count": 16,
               "subtype": {"kind": "base", "name": "char"}}},
      "parent": {"offset": 56, "type": {"kind": "pointer",
                 "subtype": {"kind": "struct", "name": "proc"}}},
      "state": {"offset": 64, "type": {"kind": "enum", "name": "proc_state"}},
      "flag": {"offset": 68, "type": {"kind": "bitfield", "bit_position": 3, "bit_length": 1,
               "type": {"kind": "base", "name": "unsigned int"}}},
      "nibble": {"offset": 72, "type": {"kind": "bitfield", "bit_position": 0, "bit_length": 4,
                 "type": {"kind": "base", "name": "int"}}},
      "handler": {"offset": 80, "type": {"kind": "pointer", "subtype": {"kind": "function"}}},
      "slots": {"offset": 88, "type": {"kind": "array", "count": 4,
                "subtype": {"kind": "base", "name": "unsigned int"}}}
    }},
    "table": {"size": 80, "kind": "struct", "fields": {
      "flat": {"offset": 0, "type": {"kind": "array", "count": 4,
               "subtype": {"kind": "base", "name": "unsigned int"}}},
      "buckets": {"offset": 16, "type": {"kind": "array", "count": 2,
                  "subtype": {"kind": "array", "count": 4,
                              "subtype": {"kind": "struct", "name": "inner"}}}}
    }}
  },
  "enums": {
    "proc_state": {"size": 4, "base": "unsigned int",
                   "constants": {"RUNNING": 0, "SLEEPING": 1, "ZOMBIE": 2}}
  },
  "symbols": {
    "proc_list_head": {"address": 4096, "type": {"kind": "struct", "name": "list_head"}},
    "init_proc": {"address": 4352, "type": {"kind": "struct", "name": "proc"}}
  }
}"#;

/// A second synthetic ISF that declares **four-byte** pointers.
///
/// Its only purpose is to prove that pointer width comes from the document and
/// not from the machine Séance is running on. Every test using it reads bytes
/// that are deliberately followed by `0xFFFFFFFF`, so a read of the host's
/// eight bytes would produce a wildly different — and entirely plausible —
/// address rather than failing.
pub(crate) const FIXTURE32_ISF: &str = r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-object-fixture", "version": "1.0.0"},
    "linux": {"symbols": [], "types": []}
  },
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
  },
  "user_types": {
    "link32": {"size": 8, "kind": "struct", "fields": {
      "next": {"offset": 0, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "link32"}}},
      "prev": {"offset": 4, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "link32"}}}
    }},
    "node32": {"size": 20, "kind": "struct", "fields": {
      "id": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}},
      "links": {"offset": 4, "type": {"kind": "struct", "name": "link32"}},
      "next_node": {"offset": 12, "type": {"kind": "pointer",
                    "subtype": {"kind": "struct", "name": "node32"}}},
      "guard": {"offset": 16, "type": {"kind": "base", "name": "unsigned int"}}
    }}
  }
}"#;

/// First address of the low segment.
pub(crate) const LOW_BASE: u64 = 0x1000;
/// Length of each segment.
pub(crate) const SEGMENT_LEN: u64 = 0x1000;
/// First address with nothing behind it.
pub(crate) const HOLE_START: u64 = LOW_BASE + SEGMENT_LEN;
/// First address of the high segment, one past the end of the hole.
pub(crate) const HIGH_BASE: u64 = 0x3000;
/// Highest addressable byte in the fixture layer.
pub(crate) const MAX_ADDRESS: u64 = HIGH_BASE + SEGMENT_LEN - 1;

/// Head of the well-formed circular list: A, B, C, back to the head.
pub(crate) const HEAD_MAIN: u64 = 0x1000;
/// Head of a list whose single entry links to itself.
pub(crate) const HEAD_CYCLE: u64 = 0x1010;
/// Head of a list whose first entry lies in the unmapped window.
pub(crate) const HEAD_HOLE: u64 = 0x1020;
/// Head whose forward link is null, so the list never closes.
pub(crate) const HEAD_NULL: u64 = 0x1030;
/// Head of the staircase: a chain of distinct links that never comes back.
pub(crate) const HEAD_CHAIN: u64 = 0x1040;
/// Head of a list whose tail loops back to its *second* entry rather than to
/// the head, so only the visited set can catch it.
pub(crate) const HEAD_LOOP: u64 = 0x1050;

/// First link of the staircase.
pub(crate) const STAIR_BASE: u64 = 0x1800;
/// Distance between staircase links.
pub(crate) const STAIR_STRIDE: u64 = 0x10;
/// How many staircase links there are. The last one's forward pointer is null,
/// so an uncapped walk of it ends somewhere provable rather than wandering off
/// the end of the segment.
pub(crate) const STAIR_COUNT: u64 = 16;

/// First link of the three-link loop.
pub(crate) const LOOP_BASE: u64 = 0x1A00;

/// First process in the well-formed list.
pub(crate) const PROC_A: u64 = 0x1100;
/// Second process; its `parent` points at [`PROC_A`].
pub(crate) const PROC_B: u64 = 0x1200;
/// Third process; its forward link closes the list.
pub(crate) const PROC_C: u64 = 0x1300;
/// A process whose forward link points at itself.
pub(crate) const PROC_D: u64 = 0x1400;
/// A process whose `parent` pointer is not in canonical 48-bit form.
pub(crate) const PROC_E: u64 = 0x1500;
/// A process positioned so that its later members fall in the hole, and its
/// `parent` pointer straddles the boundary.
pub(crate) const PROC_STRADDLE: u64 = 0x1FC4;
/// The container address of the entry [`HEAD_HOLE`] links to, inside the hole.
pub(crate) const PROC_IN_HOLE: u64 = 0x2100;
/// An `endian_probe` holding the same four bytes twice, once declared
/// little-endian and once big-endian.
pub(crate) const ENDIAN_PROBE: u64 = 0x1600;

/// Offset of `links` inside `proc`, as the fixture ISF declares it. Tests use
/// it to state the expected `CONTAINING_RECORD` arithmetic explicitly.
pub(crate) const LINKS_OFFSET: u64 = 8;

/// First address of the 32-bit fixture's single segment, and the head of its
/// list.
pub(crate) const HEAD32: u64 = 0x1000;
/// First `node32` of the 32-bit list.
pub(crate) const NODE32_A: u64 = 0x1100;
/// Second `node32`; the list closes back to the head from here.
pub(crate) const NODE32_B: u64 = 0x1140;
/// Offset of `links` inside `node32`.
pub(crate) const LINKS32_OFFSET: u64 = 4;

/// Compile one of the fixture ISFs.
fn compile(isf: &str) -> Arc<SymbolTable> {
    let source = seance_symbols::load_slice(isf.as_bytes(), &DecompressLimits::default())
        .expect("the fixture ISF must load");
    Arc::new(
        SymbolTable::compile_source(source, &CompileOptions::default())
            .unwrap_or_else(|err| panic!("the fixture ISF must compile: {err}")),
    )
}

/// The compiled fixture symbol table, built once per test binary.
pub(crate) fn symbols() -> Arc<SymbolTable> {
    static TABLE: OnceLock<Arc<SymbolTable>> = OnceLock::new();
    Arc::clone(TABLE.get_or_init(|| compile(FIXTURE_ISF)))
}

/// The compiled four-byte-pointer symbol table.
pub(crate) fn symbols32() -> Arc<SymbolTable> {
    static TABLE: OnceLock<Arc<SymbolTable>> = OnceLock::new();
    Arc::clone(TABLE.get_or_init(|| compile(FIXTURE32_ISF)))
}

/// The fixture image: two mapped segments with an unmapped window between them.
struct Image {
    bytes: Vec<u8>,
}

impl Image {
    fn new() -> Self {
        Self {
            bytes: vec![0u8; (SEGMENT_LEN * 2) as usize],
        }
    }

    /// Where an address lives in the backing buffer. Panics on an unmapped
    /// address, which in a fixture means the test author placed a structure
    /// somewhere the image does not cover.
    fn offset_of(address: u64) -> usize {
        if (LOW_BASE..LOW_BASE + SEGMENT_LEN).contains(&address) {
            (address - LOW_BASE) as usize
        } else if (HIGH_BASE..HIGH_BASE + SEGMENT_LEN).contains(&address) {
            (address - HIGH_BASE + SEGMENT_LEN) as usize
        } else {
            panic!("fixture address {address:#x} is not inside a mapped segment");
        }
    }

    fn put(&mut self, address: u64, data: &[u8]) {
        for (index, byte) in data.iter().enumerate() {
            let offset = Image::offset_of(address + index as u64);
            self.bytes[offset] = *byte;
        }
    }

    fn put_u32(&mut self, address: u64, value: u32) {
        self.put(address, &value.to_le_bytes());
    }

    fn put_u64(&mut self, address: u64, value: u64) {
        self.put(address, &value.to_le_bytes());
    }

    /// Write one `proc`, member by member, at the offsets the fixture ISF
    /// declares.
    fn put_proc(&mut self, at: u64, pid: i32, uid: u32, next: u64, prev: u64, parent: u64) {
        self.put_u32(at, pid as u32);
        self.put_u32(at + 4, uid);
        self.put_u64(at + 8, next);
        self.put_u64(at + 16, prev);
        self.put_u64(at + 24, 0x0123_4567_89AB_CDEF);
        self.put_u32(at + 32, 0xDEAD_BEEF);
        self.put_u32(at + 36, (-2i32) as u32);
        self.put(at + 40, b"init");
        self.put_u64(at + 56, parent);
        self.put_u32(at + 64, 2);
        self.put_u32(at + 68, 0b1000);
        self.put_u32(at + 72, 0x0000_000F);
        self.put_u64(at + 80, 0x1234);
        for (index, value) in [10u32, 20, 30, 40].into_iter().enumerate() {
            self.put_u32(at + 88 + (index as u64 * 4), value);
        }
    }

    fn build(self) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(self.bytes));
        Arc::new(
            SegmentedLayer::new(
                source,
                vec![
                    Segment::new(0, LOW_BASE, SEGMENT_LEN),
                    Segment::new(SEGMENT_LEN, HIGH_BASE, SEGMENT_LEN),
                ],
                LayerMeta::new(MemoryImageFormat::Lime).with_architecture(Architecture::X64),
            )
            .expect("a well-formed fixture segment list"),
        )
    }
}

/// Build the fixture image.
///
/// The map, which every test in this module reads against:
///
/// | Address | What |
/// |---|---|
/// | `0x1000` | list head: A, B, C, back to the head |
/// | `0x1010` | list head whose one entry links to itself |
/// | `0x1020` | list head whose first entry is in the hole |
/// | `0x1030` | list head with a null forward link |
/// | `0x1040` | list head of the staircase at `0x1800` |
/// | `0x1050` | list head of the three-link loop at `0x1A00` |
/// | `0x1100` | `proc` A: `pid` -1, `uid` 1000, no parent |
/// | `0x1200` | `proc` B: parent is A |
/// | `0x1300` | `proc` C: forward link closes the list |
/// | `0x1400` | `proc` D: forward link points at itself |
/// | `0x1500` | `proc` E: a non-canonical `parent` pointer |
/// | `0x1600` | `endian_probe`: `01 02 03 04` twice |
/// | `0x1800` | sixteen links, each pointing at the next, the last one null |
/// | `0x1A00` | three links whose last one points back at the second |
/// | `0x1FC4` | `proc` straddling the top of the low segment |
/// | `0x2000`..`0x3000` | unmapped: never acquired |
fn image() -> Arc<dyn MemoryLayer> {
    let mut image = Image::new();

    // The well-formed circular list. A link address is the address of the
    // embedded `links` member, eight bytes into the containing `proc`.
    image.put_u64(HEAD_MAIN, PROC_A + LINKS_OFFSET);
    image.put_u64(HEAD_MAIN + 8, PROC_C + LINKS_OFFSET);
    image.put_proc(PROC_A, -1, 1000, PROC_B + LINKS_OFFSET, HEAD_MAIN, 0);
    image.put_proc(
        PROC_B,
        2,
        1001,
        PROC_C + LINKS_OFFSET,
        PROC_A + LINKS_OFFSET,
        PROC_A,
    );
    image.put_proc(PROC_C, 3, 1002, HEAD_MAIN, PROC_B + LINKS_OFFSET, PROC_A);

    // A list of one entry that links to itself rather than back to the head.
    image.put_u64(HEAD_CYCLE, PROC_D + LINKS_OFFSET);
    image.put_proc(PROC_D, 4, 1003, PROC_D + LINKS_OFFSET, HEAD_CYCLE, 0);

    // A list whose first entry lies in the unmapped window.
    image.put_u64(HEAD_HOLE, PROC_IN_HOLE + LINKS_OFFSET);

    // A head whose forward link is null.
    image.put_u64(HEAD_NULL, 0);

    // A staircase: every link points at a fresh address, so the visited set
    // never fires and only the entry cap can end the walk.
    image.put_u64(HEAD_CHAIN, STAIR_BASE);
    for index in 0..STAIR_COUNT {
        let here = STAIR_BASE + index * STAIR_STRIDE;
        let next = if index + 1 == STAIR_COUNT {
            0
        } else {
            here + STAIR_STRIDE
        };
        image.put_u64(here, next);
    }

    // A loop that closes onto the second entry rather than onto the head, so
    // the walk cannot mistake it for a list that wrapped.
    image.put_u64(HEAD_LOOP, LOOP_BASE);
    image.put_u64(LOOP_BASE, LOOP_BASE + 0x10);
    image.put_u64(LOOP_BASE + 0x10, LOOP_BASE + 0x20);
    image.put_u64(LOOP_BASE + 0x20, LOOP_BASE + 0x10);

    // A process with a pointer that no 48-bit canonical address space can hold.
    image.put_proc(PROC_E, 5, 1004, 0, 0, 0x0000_8000_0000_0000);

    // The same four bytes twice: read little-endian at +0 and big-endian at +4.
    // Only the symbol table can say which, and it says a different thing for
    // each of them.
    image.put(
        ENDIAN_PROBE,
        &[0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04],
    );

    // The straddler: everything up to `name` is inside the low segment, and
    // `parent` at +56 begins four bytes before the hole.
    image.put_u32(PROC_STRADDLE, 7);
    image.put_u32(PROC_STRADDLE + 4, 42);
    image.put(PROC_STRADDLE + 40, b"straddle");

    image.build()
}

/// A reader over the fixture image whose structures and pointers share one
/// space, which is the ordinary case.
pub(crate) fn fixture() -> StructReader {
    StructReader::new(image(), symbols())
}

/// Write a four-byte little-endian value into the 32-bit fixture image.
fn put32(bytes: &mut [u8], address: u64, value: u32) {
    let at = (address - HEAD32) as usize;
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// The 32-bit fixture image: one segment, two `node32`s, and a list head.
///
/// Every pointer is followed immediately by `0xFFFFFFFF`, so a reader that took
/// its pointer width from the host rather than from the ISF would produce
/// `0xFFFFFFFF_00001140` where the evidence holds `0x1140` — a difference that
/// is obvious in a test and invisible in a report.
fn image32() -> Arc<dyn MemoryLayer> {
    let mut bytes = vec![0u8; SEGMENT_LEN as usize];

    // The head, which is a bare `link32`.
    put32(&mut bytes, HEAD32, (NODE32_A + LINKS32_OFFSET) as u32);
    put32(&mut bytes, HEAD32 + 4, (NODE32_B + LINKS32_OFFSET) as u32);

    // Node A: links to B, points at B, and is followed by a full-width guard.
    put32(&mut bytes, NODE32_A, 1);
    put32(&mut bytes, NODE32_A + 4, (NODE32_B + LINKS32_OFFSET) as u32);
    put32(&mut bytes, NODE32_A + 8, HEAD32 as u32);
    put32(&mut bytes, NODE32_A + 12, NODE32_B as u32);
    put32(&mut bytes, NODE32_A + 16, 0xFFFF_FFFF);

    // Node B: closes the list back to the head.
    put32(&mut bytes, NODE32_B, 2);
    put32(&mut bytes, NODE32_B + 4, HEAD32 as u32);
    put32(&mut bytes, NODE32_B + 8, (NODE32_A + LINKS32_OFFSET) as u32);
    put32(&mut bytes, NODE32_B + 12, 0);
    put32(&mut bytes, NODE32_B + 16, 0xFFFF_FFFF);

    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Arc::new(
        SegmentedLayer::new(
            source,
            vec![Segment::new(0, HEAD32, SEGMENT_LEN)],
            LayerMeta::new(MemoryImageFormat::Lime).with_architecture(Architecture::X86),
        )
        .expect("a well-formed fixture segment list"),
    )
}

/// A reader over the four-byte-pointer fixture.
pub(crate) fn fixture32() -> StructReader {
    StructReader::new(image32(), symbols32())
}

/// A reader shaped like pool scanning: the structures are read out of one
/// layer, and the pointers inside them resolve in a different one.
///
/// Both layers hold the same bytes, so a test can tell the two apart only by
/// which `Arc` an object came back holding — which is exactly the property that
/// must not silently degrade.
pub(crate) fn physical_reader() -> (StructReader, Arc<dyn MemoryLayer>) {
    let scanned = image();
    let native = image();
    (
        StructReader::with_native(scanned, Arc::clone(&native), symbols()),
        native,
    )
}
