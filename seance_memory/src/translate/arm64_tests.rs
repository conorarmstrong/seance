//! ARM64 (VMSAv8-64) translation, proved against tables written by hand.
//!
//! # Fixture provenance
//!
//! No ARM64 memory capture exists on the machine this was written on, so
//! every table here is synthetic: written from the descriptor layout in ARM
//! DDI 0487 section D8.3 ("VMSAv8-64 translation table descriptor formats")
//! and the input-address split in D8.2. That is a fixture written from the
//! same specification the code implements, and it is recorded as such. What
//! keeps each test from being the implementation reading itself is that the
//! expected physical address is **worked by hand in the test's own comment**
//! — the index each level takes, the bits the descriptor contributes, the
//! offset carried through — and the assertion is against that number, never
//! against anything the walker computed.
//!
//! # Descriptor layout used (D8.3.1, 48-bit OA, no FEAT_LPA/LPA2)
//!
//! ```text
//! bit 0        valid
//! bit 1        type: table (1) / block (0) above level 3; page (1) / reserved (0) at level 3
//! bits 4:2     AttrIndx          bit 5   NS      bits 7:6  AP[2:1]
//! bits 9:8     SH                bit 10  AF      bit 11    nG
//! bit 16       nT (block, FEAT_BBM)
//! bits 47:n    output address, n = 12/14/16 for a page, 21/25/29 for a
//!              level-2 block, 30 for a 4 KiB level-1 block
//! bits 49:48   RES0 (OA[49:48] only under FEAT_LPA2)
//! bit 50       GP                bit 51  DBM     bit 52    Contiguous
//! bit 53       PXN               bit 54  UXN     bits 58:55 software
//! table descriptor: bits 47:m next-level table address (m = granule shift),
//!              bit 59 PXNTable, bit 60 UXNTable, bits 62:61 APTable, bit 63 NSTable
//! ```

use crate::translate::spec::{
    Arm64Granule, Arm64Regime, EntryKind, LeafRule, PagingMode, PagingSpec, PteSemantics, Ttbr,
    ARM64_PXN_BIT, ARM64_TABLE_BIT, ARM64_UXN_BIT, PRESENT_BIT, WINDOWS_TRANSITION_BIT,
};
use crate::translate::test_image::{Harness, Image};
use crate::translate::walk::TranslateError;

/// Valid + table (bits 1:0 = 0b11).
const TABLE: u64 = PRESENT_BIT | ARM64_TABLE_BIT;
/// Valid + page at level 3 (bits 1:0 = 0b11), with AF (bit 10) and SH=inner
/// (bits 9:8 = 0b11) as Linux sets them, so the attribute bits are proved to
/// be outside the frame.
const PAGE: u64 = PRESENT_BIT | ARM64_TABLE_BIT | (1 << 10) | (0b11 << 8);
/// Valid + block (bits 1:0 = 0b01), same attributes.
const BLOCK: u64 = PRESENT_BIT | (1 << 10) | (0b11 << 8);

fn regime(granule: Arm64Granule, ttbr: Ttbr, va_bits: u8) -> PagingMode {
    PagingMode::Arm64(Arm64Regime::new(granule, ttbr, va_bits).expect("a defined width"))
}

/// 4 KiB granule, 48-bit TTBR1 regime, four levels: L0 at 0x1000, L1 at
/// 0x2000, L2 at 0x3000, L3 at 0x4000, one page at 0x5000.
///
/// Indexed like the Intel `x64_image` fixture so the two are comparable:
/// L0 0, L1 0, L2 2, L3 1.
fn arm64_4k_kernel_image() -> Image {
    let mut image = Image::new();
    image.entry64(0x1000, 0, 0x2000 | TABLE);
    image.entry64(0x2000, 0, 0x3000 | TABLE);
    image.entry64(0x3000, 2, 0x4000 | TABLE);
    image.entry64(0x4000, 1, 0x5000 | PAGE);
    image.fill(0x5000, 0x1000, 0xAB);
    image
}

/// The kernel address the fixture maps.
///
/// Worked by hand for a 48-bit regime with a 4 KiB granule (D8.2.1: the
/// input address is split 9/9/9/9/12):
///
/// ```text
/// va            = 0xFFFF_0000_0040_1ABC
/// bits 63:48    = 0xFFFF            all one -> TTBR1 regime (D8.2.3)
/// bits 47:39    = 0                 L0 index 0
/// bits 38:30    = 0                 L1 index 0
/// bits 29:21    = 0x401ABC >> 21    = 2     L2 index 2
/// bits 20:12    = (0x401ABC >> 12) & 0x1FF = 0x401 & 0x1FF = 1   L3 index 1
/// bits 11:0     = 0xABC             page offset
/// ```
const KERNEL_VA: u64 = 0xFFFF_0000_0040_1ABC;

#[test]
fn a_4k_page_translates_through_four_levels_of_a_ttbr1_regime() {
    // L3[1] holds output address 0x5000 at bits 47:12, so the physical
    // address is 0x5000 | 0xABC = 0x5ABC.
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(arm64_4k_kernel_image(), mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect("a fully mapped page");
    assert_eq!(t.phys, 0x5ABC);
    assert_eq!(t.run_len, 0x1000);
    assert_eq!(t.level, 3, "the level 3 table ended the walk");
    assert!(!t.no_execute);
    assert_eq!(t.page_base(), 0x5000);
}

#[test]
fn the_ttbr_value_carries_an_asid_and_cnp_that_are_stripped_before_it_is_used() {
    // TTBR1_EL1 (D13.2.x): bits 63:48 ASID, bits 47:1 BADDR, bit 0 CnP. A
    // register value read out of a crash dump or VMCOREINFO carries all
    // three, and a walker that used it whole would read the top table from
    // an address 2^48 or more above the image.
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(arm64_4k_kernel_image(), mode, PteSemantics::Bare);
    let ttbr1 = (0x0005u64 << 48) | 0x1000 | 1;
    let t = harness
        .walk()
        .translate(ttbr1, KERNEL_VA)
        .expect("the ASID and CnP are not part of the table address");
    assert_eq!(t.phys, 0x5ABC);
}

#[test]
fn a_lower_half_address_is_not_canonical_for_the_ttbr1_regime_and_vice_versa() {
    // D8.2.3: bits 63:48 all zero select TTBR0, all one select TTBR1, any
    // other value faults. The kernel's layer must not walk a user address
    // through the kernel's tables — the indices would land somewhere, and
    // somewhere is somebody else's page.
    let image = arm64_4k_kernel_image();
    let ttbr1 = Harness::new(
        image,
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48),
        PteSemantics::Bare,
    );
    let user_va = 0x0000_0000_0040_1ABC;
    let err = ttbr1
        .walk()
        .translate(0x1000, user_va)
        .expect_err("a TTBR0 address under the TTBR1 spec");
    assert!(
        matches!(err, TranslateError::NonCanonical { .. }),
        "{err:?}"
    );
    assert_eq!(err.hole_reason(), None, "there is no such address here");

    // Same tables, a TTBR0 regime: the same indices reach the same page from
    // the lower-half address, and the kernel address is now the foreign one.
    let ttbr0 = Harness::new(
        arm64_4k_kernel_image(),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48),
        PteSemantics::Bare,
    );
    assert_eq!(
        ttbr0.walk().translate(0x1000, user_va).unwrap().phys,
        0x5ABC
    );
    let err = ttbr0.walk().translate(0x1000, KERNEL_VA).unwrap_err();
    assert!(
        matches!(err, TranslateError::NonCanonical { .. }),
        "{err:?}"
    );

    // Bit 47 set with bits 63:48 clear is still TTBR0's: there is no sign
    // bit, the regime is 48 bits wide and 0x8000_0000_0000 is inside it.
    assert!(ttbr0.spec_is_canonical(0x0000_8000_0000_0000));
    // Anything with bits 63:48 neither all clear nor all set belongs to
    // neither regime.
    for va in [
        0x8000_0000_0000_0000u64,
        0xFFFE_0000_0000_0000,
        0x0001_0000_0040_1ABC,
    ] {
        assert!(!ttbr0.spec_is_canonical(va), "{va:#x} under TTBR0");
        assert!(!ttbr1.spec_is_canonical(va), "{va:#x} under TTBR1");
    }
}

#[test]
fn a_2_mib_block_at_level_2_ends_the_walk_with_its_attribute_bits_outside_the_frame() {
    // D8.3.1: a level-2 block descriptor under a 4 KiB granule holds output
    // address bits 47:21; bits 20:0 are attributes or reserved (bit 16 is
    // nT). Worked by hand:
    //
    //   va            = 0xFFFF_0000_0060_1234
    //   bits 29:21    = 0x601234 >> 21 = 3        L2 index 3
    //   bits 20:0     = 0x601234 & 0x1F_FFFF = 0x1234   offset in the block
    //   descriptor    = 0x0080_0000 | nT | AF | SH | 0b01
    //   OA            = bits 47:21 = 0x0080_0000
    //   phys          = 0x0080_0000 + 0x1234 = 0x0080_1234
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x3000, 3, 0x0080_0000 | (1 << 16) | BLOCK);
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1000, 0xFFFF_0000_0060_1234)
        .expect("a 2 MiB block");
    assert_eq!(t.phys, 0x0080_1234);
    assert_eq!(t.run_len, 1 << 21);
    assert_eq!(t.level, 2);
}

#[test]
fn a_1_gib_block_at_level_1_ends_the_walk() {
    // A 4 KiB granule permits a block at level 1 (D8.3.1); output address
    // bits 47:30. Worked by hand:
    //
    //   va            = 0xFFFF_0000_4000_2000
    //   bits 47:39    = 0                          L0 index 0
    //   bits 38:30    = 0x4000_2000 >> 30 = 1      L1 index 1
    //   bits 29:0     = 0x2000                     offset in the block
    //   descriptor    = 0x4000_0000 | AF | SH | 0b01
    //   phys          = 0x4000_0000 + 0x2000 = 0x4000_2000
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x2000, 1, 0x4000_0000 | BLOCK);
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1000, 0xFFFF_0000_4000_2000)
        .expect("a 1 GiB block");
    assert_eq!(t.phys, 0x4000_2000);
    assert_eq!(t.run_len, 1 << 30);
    assert_eq!(t.level, 1);
}

#[test]
fn a_block_encoding_at_a_level_only_feat_lpa2_permits_is_refused_not_reported_absent() {
    // Without FEAT_LPA2 a 4 KiB granule permits no level-0 block: bits 1:0
    // = 0b01 there is a reserved encoding the hardware faults on (D8.3.1).
    // With FEAT_LPA2 on (`TCR_EL1.DS = 1`, register state no image records)
    // the same bits are a valid 512 GiB block whose output address is bits
    // 47:39 plus 49:48. Nothing in the entry tells the two apart when bits
    // 49:48 are clear, so this build states neither a frame (a walker that
    // honoured the block would resolve 512 GiB to one frame it cannot vouch
    // for) nor absence (an examiner told "not present" would stop looking
    // at a region that may be mapped). It is refused as undecodable, with
    // the entry verbatim, and it is not a hole in the acquisition.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x1000, 0, 0x2000 | BLOCK);
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(spec.levels()[0].leaf, LeafRule::Arm64TableOrLpaBlock);
    match spec.classify(0x2000 | BLOCK, 0) {
        Some(EntryKind::Unnameable { detail }) => {
            assert!(detail.contains("FEAT_LPA2"), "{detail}");
            assert!(detail.contains("512 GiB"), "{detail}");
        }
        other => panic!("expected an undecodable block, got {other:?}"),
    }

    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect_err("an undecodable descriptor must not translate");
    match &err {
        TranslateError::AddressOverflow { va, detail } => {
            assert_eq!(*va, KERNEL_VA);
            assert!(detail.contains("FEAT_LPA2"), "{detail}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(
        err.hole_reason(),
        None,
        "a limitation of this build says nothing about the acquisition"
    );
    assert!(
        !matches!(err, TranslateError::NotPresent { .. }),
        "could not decode is never reported as not there"
    );

    // The downward enumeration says the same thing: the region is blind
    // for the stated reason, not absent, and the outcome is incomplete.
    use crate::translate::enumerate::{
        Blindness, EnumerateLimits, MappingRun, MappingSink, SinkFlow,
    };
    use seance_core::io::IncompleteReason;
    #[derive(Default)]
    struct Collect {
        runs: Vec<MappingRun>,
        blind: Vec<(u64, u64, u64, &'static str, IncompleteReason)>,
    }
    impl MappingSink for Collect {
        fn run(&mut self, run: &MappingRun) -> SinkFlow {
            self.runs.push(*run);
            SinkFlow::Continue
        }
        fn blind(&mut self, blindness: &Blindness) -> SinkFlow {
            match blindness {
                Blindness::Unnameable {
                    va_start,
                    bytes,
                    entry,
                    detail,
                } => self
                    .blind
                    .push((*va_start, *bytes, *entry, detail, blindness.reason())),
                other => panic!("expected an undecodable entry, got {other:?}"),
            }
            SinkFlow::Continue
        }
    }
    let mut sink = Collect::default();
    let outcome = harness
        .walk()
        .enumerate(0x1000, &EnumerateLimits::default(), &mut sink);
    assert!(sink.runs.is_empty(), "{:?}", sink.runs);
    assert_eq!(sink.blind.len(), 1, "{:?}", sink.blind);
    let (va_start, bytes, entry, detail, reason) = sink.blind[0];
    assert_eq!(va_start, 0xFFFF_0000_0000_0000);
    assert_eq!(bytes, 1 << 39, "a level-0 entry governs 512 GiB");
    assert_eq!(entry, 0x2000 | BLOCK, "the entry travels verbatim");
    assert!(detail.contains("FEAT_LPA2"), "{detail}");
    assert_eq!(reason, IncompleteReason::UnresolvedStructure);
    assert_eq!(
        outcome.absent_entries, 511,
        "the other level-0 slots are zero and absent; the refused one is not among them"
    );
    assert_eq!(outcome.blind_bytes, 1 << 39);
    assert!(!outcome.is_complete(), "{outcome:?}");
}

#[test]
fn a_block_encoding_at_a_level_no_feature_permits_is_reserved_and_absent() {
    // A 16 KiB granule permits a level-1 block under FEAT_LPA2 but never a
    // level-0 one (D8.3.1); a 48-bit 16 KiB regime has a two-entry level 0,
    // and 0b01 there is reserved under every feature the architecture
    // defines. That is a descriptor the hardware faults on whatever the
    // register state, so it is reported absent — with the entry verbatim,
    // as every invalid entry is — and not as undecodable.
    //
    // Address: L0 index 1 (bit 47), L1 index 0, L2 index 0, L3 index 0,
    // offset 0 -> 0xFFFF_8000_0000_0000 under TTBR1.
    let mode = regime(Arm64Granule::Kb16, Ttbr::Ttbr1, 48);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(spec.levels()[0].leaf, LeafRule::Arm64TableOnly);
    assert_eq!(spec.levels()[1].leaf, LeafRule::Arm64TableOrLpaBlock);
    assert_eq!(spec.classify(0x8000 | BLOCK, 0), Some(EntryKind::Invalid));

    let mut image = Image::new();
    image.entry64(0x4000, 1, 0x8000 | BLOCK);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x4000, 0xFFFF_8000_0000_0000)
        .expect_err("a reserved descriptor");
    match &err {
        TranslateError::NotPresent {
            level,
            level_name,
            entry,
            invalid_bits,
            ..
        } => {
            assert_eq!(*level, 0);
            assert_eq!(*level_name, "level 0 translation table");
            assert_eq!(*entry, 0x8000 | BLOCK, "the entry travels verbatim");
            assert_eq!(*invalid_bits, 47, "a 16 KiB level-0 entry governs 128 TiB");
        }
        other => panic!("expected an invalid entry, got {other:?}"),
    }
}

#[test]
fn a_level_3_descriptor_with_the_type_bit_clear_is_reserved_not_a_page() {
    // At level 3 bits 1:0 = 0b01 is reserved (D8.3.1); only 0b11 is a page.
    // Reading it as a block — the meaning the same bits have one level up —
    // would return a frame the tables never described.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | BLOCK);
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect_err("a reserved level-3 descriptor");
    assert!(
        matches!(
            err,
            TranslateError::NotPresent {
                level: 3,
                level_name: "level 3 translation table",
                ..
            }
        ),
        "{err:?}"
    );
    // And a plainly invalid one, valid bit clear, is absent as usual.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | ARM64_TABLE_BIT);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness.walk().translate(0x1000, KERNEL_VA).unwrap_err();
    assert!(matches!(err, TranslateError::NotPresent { level: 3, .. }));
}

#[test]
fn the_frame_mask_stops_at_bit_47_so_gp_dbm_and_software_bits_are_not_address() {
    // Bits 50 (GP), 51 (DBM — Linux's PTE_WRITE), 52 (Contiguous) and 58:55
    // (software: Linux's PTE_DIRTY at 55, PTE_SPECIAL at 56) sit above the
    // 48-bit output address. An Intel-shaped 52-bit mask would fold GP and
    // DBM into the frame and move every writable page 2^50 bytes away.
    let mut image = arm64_4k_kernel_image();
    image.entry64(
        0x4000,
        1,
        0x5000 | PAGE | (1 << 50) | (1 << 51) | (1 << 52) | (1 << 55) | (1 << 56) | (1 << 63),
    );
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness.walk().translate(0x1000, KERNEL_VA).unwrap();
    assert_eq!(t.phys, 0x5ABC);
    assert!(!t.no_execute, "none of those bits is PXN");
}

#[test]
fn output_address_bits_that_exist_only_under_feat_lpa2_are_refused_not_masked() {
    // Bits 49:48 of a 4 KiB descriptor are RES0 for a 48-bit output address
    // and OA[49:48] under FEAT_LPA2 (TCR_EL1.DS = 1, which no image
    // records). Masking them off would answer 256 TiB below the truth.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | PAGE | (1 << 48));
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect_err("an inexpressible frame must not translate");
    assert!(
        matches!(err, TranslateError::AddressOverflow { .. }),
        "{err:?}"
    );
    assert_eq!(
        err.hole_reason(),
        None,
        "it says nothing about the acquisition"
    );

    // A table descriptor with the same bits set names a next-level table
    // this reading cannot address either, and is refused before the walk
    // reads somebody else's table at the masked address.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x2000, 0, 0x3000 | TABLE | (1 << 49));
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness.walk().translate(0x1000, KERNEL_VA).unwrap_err();
    assert!(
        matches!(err, TranslateError::AddressOverflow { .. }),
        "{err:?}"
    );
}

#[test]
fn the_execute_never_bit_reported_is_the_one_for_the_regimes_own_exception_level() {
    // D8.3.1 bits 53 (PXN) and 54 (UXN). Linux sets UXN on every kernel
    // page and PXN on every user page, so the bit that answers "was this
    // page executable by its owner?" is PXN under TTBR1 and UXN under TTBR0.
    // Reporting the other one would call every kernel page non-executable.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | PAGE | ARM64_UXN_BIT);
    let kernel = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, kernel, PteSemantics::Bare);
    let t = harness.walk().translate(0x1000, KERNEL_VA).unwrap();
    assert!(
        !t.no_execute,
        "UXN alone does not stop the kernel executing"
    );

    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | PAGE | ARM64_PXN_BIT);
    let harness = Harness::new(image, kernel, PteSemantics::Bare);
    let t = harness.walk().translate(0x1000, KERNEL_VA).unwrap();
    assert!(t.no_execute, "PXN is the kernel's execute-never");

    let user = regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48);
    let user_va = 0x0000_0000_0040_1ABC;
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | PAGE | ARM64_PXN_BIT);
    let harness = Harness::new(image, user, PteSemantics::Bare);
    assert!(
        !harness
            .walk()
            .translate(0x1000, user_va)
            .unwrap()
            .no_execute
    );
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | PAGE | ARM64_UXN_BIT);
    let harness = Harness::new(image, user, PteSemantics::Bare);
    assert!(
        harness
            .walk()
            .translate(0x1000, user_va)
            .unwrap()
            .no_execute
    );
}

#[test]
fn a_39_bit_regime_starts_at_level_1_with_three_full_tables() {
    // 4 KiB granule, T0SZ = 25 (VA_BITS 39, the Android default): D8.2
    // gives the initial lookup level as 1, so the walk is L1/L2/L3 with
    // 9/9/9 index bits over a 12-bit offset. Worked by hand:
    //
    //   va            = (5 << 30) | (7 << 21) | (9 << 12) | 0x123
    //                 = 0x1_4000_0000 + 0xE0_0000 + 0x9000 + 0x123
    //                 = 0x1_40E0_9123
    //   bits 38:30    = 5     L1 index
    //   bits 29:21    = 7     L2 index
    //   bits 20:12    = 9     L3 index
    //   bits 11:0     = 0x123
    //   L3[9]         = 0x7000 | page  ->  phys 0x7123
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 39);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(spec.levels().len(), 3);
    assert_eq!(spec.level_name(0), Some("level 1 translation table"));
    assert_eq!(spec.levels()[0].index_bits, 9);
    assert_eq!(spec.levels()[0].leaf, LeafRule::Arm64Block);

    let mut image = Image::new();
    image.entry64(0x1000, 5, 0x2000 | TABLE);
    image.entry64(0x2000, 7, 0x3000 | TABLE);
    image.entry64(0x3000, 9, 0x7000 | PAGE);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1000, 0x1_40E0_9123)
        .expect("a page in a 39-bit space");
    assert_eq!(t.phys, 0x7123);
    assert_eq!(t.level, 2, "the third table walked is ARM's level 3");

    // Bit 39 set is outside a 39-bit TTBR0 regime and is refused, not
    // masked down to 39 bits.
    let err = harness
        .walk()
        .translate(0x1000, 0x80_0000_0000 | 0x1_40E0_9123)
        .unwrap_err();
    assert!(
        matches!(err, TranslateError::NonCanonical { .. }),
        "{err:?}"
    );
    assert_eq!(spec.max_virtual_address(), (1 << 39) - 1);
}

#[test]
fn a_16k_granule_walks_11_bit_indices_over_a_14_bit_offset() {
    // 16 KiB granule, 47-bit TTBR0 regime: D8.2 gives three levels
    // (L1/L2/L3) of 2048 entries — 11 index bits each — over a 14-bit
    // offset; 11 + 11 + 11 + 14 = 47. A table descriptor's next-level
    // address is bits 47:14. Worked by hand:
    //
    //   va            = (3 << 36) | (5 << 25) | (6 << 14) | 0x2ABC
    //                 = 0x30_0000_0000 + 0xA00_0000 + 0x1_8000 + 0x2ABC
    //                 = 0x30_0A01_AABC
    //   bits 46:36    = 3     L1 index
    //   bits 35:25    = 5     L2 index
    //   bits 24:14    = 6     L3 index
    //   bits 13:0     = 0x2ABC
    //   L3[6]         = 0x1_0000 | page  ->  phys 0x1_2ABC
    let mode = regime(Arm64Granule::Kb16, Ttbr::Ttbr0, 47);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(spec.levels().len(), 3);
    assert_eq!(spec.level_name(0), Some("level 1 translation table"));
    assert_eq!(
        spec.levels()
            .iter()
            .map(|l| l.index_bits)
            .collect::<Vec<_>>(),
        vec![11, 11, 11]
    );
    assert_eq!(spec.page_offset_bits(), 14);
    assert_eq!(
        spec.levels()[0].leaf,
        LeafRule::Arm64TableOrLpaBlock,
        "a 16 KiB granule permits a level-1 block only under FEAT_LPA2, which this build does not decode"
    );

    let mut image = Image::new();
    image.entry64(0x4000, 3, 0x8000 | TABLE);
    image.entry64(0x8000, 5, 0xC000 | TABLE);
    image.entry64(0xC000, 6, 0x1_0000 | PAGE);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x4000, 0x30_0A01_AABC)
        .expect("a 16 KiB page");
    assert_eq!(t.phys, 0x1_2ABC);
    assert_eq!(t.run_len, 1 << 14);

    // A 32 MiB block at level 2: output address bits 47:25, and the low 25
    // bits of the address — (6 << 14) | 0x2ABC = 0x1_AABC — carry through.
    //   L2[5] = 0x0200_0000 | block  ->  phys 0x0200_0000 + 0x1_AABC = 0x0201_AABC
    let mut image = Image::new();
    image.entry64(0x4000, 3, 0x8000 | TABLE);
    image.entry64(0x8000, 5, 0x0200_0000 | BLOCK);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x4000, 0x30_0A01_AABC)
        .expect("a 32 MiB block");
    assert_eq!(t.phys, 0x0201_AABC);
    assert_eq!(t.run_len, 1 << 25);

    // The block encoding at level 1 is reserved under this granule without
    // FEAT_LPA2 and a 64 GiB block with it; the image does not say which,
    // so it is refused as undecodable, not reported absent.
    let mut image = Image::new();
    image.entry64(0x4000, 3, 0x8000 | BLOCK);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x4000, 0x30_0A01_AABC)
        .unwrap_err();
    match &err {
        TranslateError::AddressOverflow { detail, .. } => {
            assert!(detail.contains("FEAT_LPA2"), "{detail}");
            assert!(detail.contains("64 GiB"), "{detail}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(err.hole_reason(), None);
}

#[test]
fn a_16k_48_bit_regime_has_a_two_entry_level_0_above_three_full_tables() {
    // 48 - 14 = 34 bits to index; 34 = 1 + 11 + 11 + 11, so level 0 has one
    // index bit and two entries — what Linux's CONFIG_ARM64_16K_PAGES with
    // VA_BITS 48 builds. A walker that assumed every top table is 512
    // entries would mask the TTBR to 4 KiB and index it with nine bits.
    let mode = regime(Arm64Granule::Kb16, Ttbr::Ttbr1, 48);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(
        spec.levels()
            .iter()
            .map(|l| l.index_bits)
            .collect::<Vec<_>>(),
        vec![1, 11, 11, 11]
    );
    assert_eq!(spec.level_name(0), Some("level 0 translation table"));
    assert_eq!(spec.region_bits_at(0), Some(47));
}

#[test]
fn a_64k_granule_walks_13_bit_indices_over_a_16_bit_offset() {
    // 64 KiB granule, 42-bit TTBR0 regime: D8.2 gives two levels (L2/L3) of
    // 8192 entries — 13 index bits — over a 16-bit offset; 13 + 13 + 16 =
    // 42. A table descriptor's next-level address is bits 47:16. Worked by
    // hand:
    //
    //   va            = (2 << 29) | (3 << 16) | 0x1234
    //                 = 0x4000_0000 + 0x3_0000 + 0x1234 = 0x4003_1234
    //   bits 41:29    = 2     L2 index
    //   bits 28:16    = 3     L3 index
    //   bits 15:0     = 0x1234
    //   L3[3]         = 0x3_0000 | page  ->  phys 0x3_1234
    let mode = regime(Arm64Granule::Kb64, Ttbr::Ttbr0, 42);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(spec.levels().len(), 2);
    assert_eq!(spec.level_name(0), Some("level 2 translation table"));
    assert_eq!(spec.level_name(1), Some("level 3 translation table"));
    assert_eq!(
        spec.levels()
            .iter()
            .map(|l| l.index_bits)
            .collect::<Vec<_>>(),
        vec![13, 13]
    );
    assert_eq!(spec.page_offset_bits(), 16);

    // The level-2 table is 8192 x 8 = 64 KiB at 0x1_0000; the level-3 table
    // at 0x2_0000.
    let mut image = Image::new();
    image.entry64(0x1_0000, 2, 0x2_0000 | TABLE);
    image.entry64(0x2_0000, 3, 0x3_0000 | PAGE);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1_0000, 0x4003_1234)
        .expect("a 64 KiB page");
    assert_eq!(t.phys, 0x3_1234);
    assert_eq!(t.run_len, 1 << 16);

    // A 512 MiB block at level 2: output address bits 47:29, and the low 29
    // bits — (3 << 16) | 0x1234 = 0x3_1234 — carry through.
    //   L2[2] = 0x2000_0000 | block  ->  phys 0x2000_0000 + 0x3_1234 = 0x2003_1234
    let mut image = Image::new();
    image.entry64(0x1_0000, 2, 0x2000_0000 | BLOCK);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1_0000, 0x4003_1234)
        .expect("a 512 MiB block");
    assert_eq!(t.phys, 0x2003_1234);
    assert_eq!(t.run_len, 1 << 29);
}

#[test]
fn a_64k_descriptor_with_feat_lpa_output_bits_is_refused() {
    // Under a 64 KiB granule bits 15:12 are RES0 for a 48-bit output
    // address and OA[51:48] under FEAT_LPA. Masking them off would answer
    // 256 TiB or more below the truth.
    let mode = regime(Arm64Granule::Kb64, Ttbr::Ttbr0, 42);
    let mut image = Image::new();
    image.entry64(0x1_0000, 2, 0x2_0000 | TABLE);
    image.entry64(0x2_0000, 3, 0x3_0000 | PAGE | (1 << 12));
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness.walk().translate(0x1_0000, 0x4003_1234).unwrap_err();
    assert!(
        matches!(err, TranslateError::AddressOverflow { .. }),
        "{err:?}"
    );
}

#[test]
fn a_64k_48_bit_regime_starts_at_level_1_with_a_64_entry_table() {
    // 48 - 16 = 32 bits to index; 32 = 6 + 13 + 13. Linux's
    // CONFIG_ARM64_64K_PAGES with VA_BITS 48: a 64-entry PGD.
    let mode = regime(Arm64Granule::Kb64, Ttbr::Ttbr1, 48);
    let spec = PagingSpec::new(mode, PteSemantics::Bare);
    assert_eq!(
        spec.levels()
            .iter()
            .map(|l| l.index_bits)
            .collect::<Vec<_>>(),
        vec![6, 13, 13]
    );
    assert_eq!(spec.level_name(0), Some("level 1 translation table"));
    assert_eq!(
        spec.levels()[0].leaf,
        LeafRule::Arm64TableOrLpaBlock,
        "FEAT_LPA permits a 4 TiB level-1 block under a 64 KiB granule; this build refuses it"
    );

    // A 0b01 descriptor there is that 4 TiB block on FEAT_LPA hardware and
    // a reserved, faulting encoding without it. Nothing in the image says
    // which, so it is refused as undecodable — never absent, never a frame.
    //   VA 0xFFFF_0000_0000_0000: L1 index 0, L2 index 0, L3 index 0.
    match spec.classify(0x2_0000 | BLOCK, 0) {
        Some(EntryKind::Unnameable { detail }) => {
            assert!(detail.contains("FEAT_LPA"), "{detail}");
            assert!(detail.contains("4 TiB"), "{detail}");
        }
        other => panic!("expected an undecodable block, got {other:?}"),
    }
    let mut image = Image::new();
    image.entry64(0x1_0000, 0, 0x2_0000 | BLOCK);
    let harness = Harness::new(image, mode, PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x1_0000, 0xFFFF_0000_0000_0000)
        .unwrap_err();
    assert!(
        matches!(err, TranslateError::AddressOverflow { .. }),
        "{err:?}"
    );
    assert_eq!(err.hole_reason(), None);
}

#[test]
fn every_arm64_regime_indexes_exactly_its_own_width() {
    // The property `every_mode_indexes_exactly_its_virtual_address_width`
    // pins for Intel, over every width the architecture defines and every
    // granule: if the derived level list and the declared width disagree,
    // every index is shifted and every translation is wrong but plausible.
    for granule in [Arm64Granule::Kb4, Arm64Granule::Kb16, Arm64Granule::Kb64] {
        for va_bits in 25..=48u8 {
            for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
                let spec = PagingSpec::new(regime(granule, ttbr, va_bits), PteSemantics::Bare);
                let indexed: u32 = spec.levels().iter().map(|l| l.index_bits).sum();
                assert_eq!(
                    indexed + spec.page_offset_bits(),
                    u32::from(va_bits),
                    "{granule} {va_bits}-bit {ttbr:?}"
                );
                assert!(!spec.levels().is_empty());
                assert!(spec.levels().len() <= 4);
                // Only the top table may be partial.
                for level in &spec.levels()[1..] {
                    assert_eq!(level.index_bits, granule.index_bits());
                }
                // The last level is always ARM's level 3 and always a page.
                assert_eq!(
                    spec.levels().last().unwrap().leaf,
                    LeafRule::Arm64Page,
                    "{granule} {va_bits}"
                );
                assert_eq!(
                    spec.level_name(spec.levels().len() - 1),
                    Some("level 3 translation table")
                );
                // And the round trip through the indices holds for the
                // regime's own base.
                let base = spec.min_virtual_address();
                let indices: Vec<u64> = (0..spec.levels().len())
                    .map(|level| spec.index_at(base, level).unwrap())
                    .collect();
                assert_eq!(
                    spec.virtual_address_from_indices(&indices, 0),
                    Some(base),
                    "{granule} {va_bits}-bit {ttbr:?} base"
                );
                assert!(spec.is_canonical(base));
                assert!(spec.is_canonical(spec.max_virtual_address()));
            }
        }
    }
}

#[test]
fn a_width_the_architecture_does_not_define_is_refused_at_construction() {
    // TxSZ is 16..=39 without FEAT_LPA2; a 52-bit regime needs a descriptor
    // layout this build does not decode, and a 24-bit one does not exist.
    assert!(Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr0, 24).is_err());
    assert!(Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr0, 52).is_err());
    assert!(Arm64Regime::new(Arm64Granule::Kb64, Ttbr::Ttbr1, 52).is_err());
    assert!(Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr0, 25).is_ok());
    assert!(Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr1, 48).is_ok());
}

#[test]
fn a_ttbr1_regime_reconstructs_its_addresses_with_the_upper_bits_set() {
    // Every TTBR1 address has bits 63:va_bits set; that is the regime, not
    // a sign. A reconstruction that returned the indexed value would report
    // every kernel mapping 0xFFFF_0000_0000_0000 too low — at a perfectly
    // ordinary user address.
    let spec = PagingSpec::new(
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48),
        PteSemantics::Bare,
    );
    let indices: Vec<u64> = (0..4)
        .map(|level| spec.index_at(KERNEL_VA, level).unwrap())
        .collect();
    assert_eq!(indices, vec![0, 0, 2, 1]);
    assert_eq!(
        spec.virtual_address_from_indices(&indices, 0xABC),
        Some(KERNEL_VA)
    );
    assert_eq!(spec.min_virtual_address(), 0xFFFF_0000_0000_0000);
    assert_eq!(spec.max_virtual_address(), u64::MAX);
    assert_eq!(spec.next_canonical(0), Some(0xFFFF_0000_0000_0000));
    assert_eq!(
        spec.next_canonical(0xFFFF_0000_0000_0001),
        Some(0xFFFF_0000_0000_0001)
    );
    assert_eq!(spec.upper_half_top_indices(), Some(0..512));

    // A 39-bit TTBR1 regime: the base is 0xFFFF_FF80_0000_0000.
    let spec = PagingSpec::new(
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 39),
        PteSemantics::Bare,
    );
    assert_eq!(spec.min_virtual_address(), 0xFFFF_FF80_0000_0000);
    assert!(spec.is_canonical(0xFFFF_FF80_0000_0000));
    assert!(!spec.is_canonical(0xFFFF_FF7F_FFFF_FFFF));

    // And a TTBR0 regime has nothing above its top.
    let spec = PagingSpec::new(
        regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48),
        PteSemantics::Bare,
    );
    assert_eq!(spec.min_virtual_address(), 0);
    assert_eq!(spec.next_canonical(1 << 48), None);
    assert_eq!(spec.upper_half_top_indices(), None);
}

#[test]
fn windows_conventions_are_not_applied_to_a_bare_arm64_descriptor_or_a_valid_one() {
    // `Bare` claims nothing beyond the valid bit, whatever bits 10 and 11 hold.
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let bare = PagingSpec::new(mode, PteSemantics::Bare);
    let transition_looking = WINDOWS_TRANSITION_BIT | 0x5000;
    assert!(!bare.entry_is_present(transition_looking));
    assert_eq!(
        bare.classify(transition_looking, 3),
        Some(EntryKind::Invalid)
    );
    // Under Windows, a VALID descriptor's bits 10 and 11 are the access flag
    // and nG, not Prototype and Transition: the entry is an ordinary page and
    // its frame is read from the hardware layout.
    let win = PagingSpec::new(mode, PteSemantics::Windows);
    let valid = 0x5000 | PAGE | WINDOWS_TRANSITION_BIT;
    assert!(win.entry_is_present(valid));
    assert!(matches!(
        win.classify(valid, 3),
        Some(EntryKind::Leaf {
            frame: 0x5000,
            size_log2: 12,
            ..
        })
    ));
}

/// `_MMPTE_TRANSITION`, read out of Microsoft's own PDB for the Windows 11
/// ARM64 kernel build 28000 (`ntkrnlmp.pdb` GUID `0382994831D35A1367EF9CC7C56B3F26`, age
/// 1): `Valid` bit 0, `Protection` bits 5:1, `Prototype` bit 10, `Transition` bit 11,
/// `PageFrameNumber` bits 51:12. Protection is arbitrary, and bit 1 (the descriptor's type
/// bit) is its low bit, so the entries below vary it: the walk must not read that bit.
#[test]
fn a_windows_arm64_transition_pte_recovers_a_standby_page() {
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let win = PagingSpec::new(mode, PteSemantics::Windows);
    for protection in [0u64, 1, 4, 31] {
        let entry = 0x5000 | WINDOWS_TRANSITION_BIT | (protection << 1);
        assert!(win.entry_is_present(entry), "protection {protection}");
        assert!(
            matches!(
                win.classify(entry, 3),
                Some(EntryKind::Leaf {
                    frame: 0x5000,
                    size_log2: 12,
                    ..
                })
            ),
            "protection {protection}"
        );
    }
    // The same bits above the last level name a page table that is on the
    // standby list, never a block.
    let table = 0x4000 | WINDOWS_TRANSITION_BIT | (4 << 1);
    assert_eq!(win.classify(table, 2), Some(EntryKind::Table));
    assert_eq!(win.table_pa_of_entry(table, 2), Some(0x4000));
    // Through the walk: L3[1] in transition, frame 0x5000, which holds 0xAB.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, 0x5000 | WINDOWS_TRANSITION_BIT | (4 << 1));
    let harness = Harness::new(image, mode, PteSemantics::Windows);
    let t = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect("a standby page is evidence");
    assert_eq!(t.phys, 0x5ABC);
    // And through a transition page table (L2[2] in transition).
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x3000, 2, 0x4000 | WINDOWS_TRANSITION_BIT | (4 << 1));
    let harness = Harness::new(image, mode, PteSemantics::Windows);
    let t = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect("a standby page table is read");
    assert_eq!(t.phys, 0x5ABC);
    // A transition frame above 2^48 is refused, never masked.
    let high = (1u64 << 48) | WINDOWS_TRANSITION_BIT;
    assert!(matches!(
        win.classify(high, 3),
        Some(EntryKind::Unnameable { .. })
    ));
}

/// `_MMPTE_PROTOTYPE` has `Prototype` at bit 10; `_MMPTE_SOFTWARE` has `PageFileLow` at bits
/// 17:14 (build 28000; bits 9:6 on build 26300) and `PageFileHigh` at bits 63:32 on both.
#[test]
fn a_windows_arm64_prototype_and_pagefile_pte_are_named_and_not_followed() {
    use crate::translate::spec::{InvalidEntry, WINDOWS_PROTOTYPE_BIT};
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let win = PagingSpec::new(mode, PteSemantics::Windows);
    let proto = WINDOWS_PROTOTYPE_BIT | (0x1228_4044u64 << 12);
    assert!(!win.entry_is_present(proto));
    assert_eq!(win.classify_invalid(proto), InvalidEntry::Prototype);
    assert_eq!(win.prototype_address(proto), None);
    let software = (3u64 << 14) | (0x1234u64 << 32);
    assert!(!win.entry_is_present(software));
    // The pagefile number is claimed only once the caller states the layout.
    assert_eq!(
        win.classify_invalid(software),
        InvalidEntry::PageFile {
            index: None,
            page_number: 0x1234
        }
    );
    // `PageFileLow` is at bits 17:14 on build 28000 and 9:6 on build 26300, and a spec is not told the build,
    // so stating the layout still names no pagefile on ARM64 (`arm64_windows_26300_real_test.rs`).
    let stated = win.with_win8_pagefile_layout(true);
    assert_eq!(
        stated.classify_invalid(software),
        InvalidEntry::PageFile {
            index: None,
            page_number: 0x1234
        }
    );
    // A software entry with no PageFileHigh (a demand-zero PTE: only Protection set) names
    // no location.
    assert_eq!(win.classify_invalid(0x20), InvalidEntry::NotPresent);
    assert!(!win.uniform_table_heuristic_applies());
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, software);
    let harness = Harness::new(image, mode, PteSemantics::Windows);
    // The walk names the pagefile page (0x1234 pages in), and the
    // pagefile number only because the layout was never stated here.
    match harness.walk().translate(0x1000, KERNEL_VA).unwrap_err() {
        TranslateError::SwappedOut {
            swap_index: None,
            swap_offset,
            ..
        } => {
            assert_eq!(swap_offset, 0x1234 << 12)
        }
        other => panic!("expected a pagefile location, got {other:?}"),
    }
}

#[test]
fn linux_conventions_on_arm64_claim_absence_and_nothing_more() {
    // On x86-64 Linux, `_PAGE_PROTNONE` is a fixed bit and everything else
    // non-present is a `swp_entry_t`. On arm64 the present-invalid marker
    // has moved — bit 58 (`PTE_PROT_NONE`) in older kernels, bit 11
    // (`PTE_PRESENT_INVALID`, aliased on nG) in the 7.0 headers this was
    // checked against — and each is a swap-offset bit under the other
    // layout. No version-free predicate separates them, so neither reading
    // is asserted and the entry travels verbatim.
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48);
    let linux = PagingSpec::new(mode, PteSemantics::Linux);
    use crate::translate::spec::InvalidEntry;
    assert_eq!(linux.classify_invalid(0), InvalidEntry::NotPresent);
    // An old-layout swap entry: type 2 at bits 7:2, offset 0x9ABC above bit 8.
    let old_swap = (2u64 << 2) | (0x9ABCu64 << 8);
    // A new-layout swap entry: type 2 at bits 10:6, offset above bit 12.
    let new_swap = (2u64 << 6) | (0x9ABCu64 << 12);
    // A present-invalid page under each layout.
    let old_prot_none = 1u64 << 58 | (0x5000);
    let new_prot_none = 1u64 << 11 | (0x5000);
    for entry in [old_swap, new_swap, old_prot_none, new_prot_none] {
        assert_eq!(
            linux.classify_invalid(entry),
            InvalidEntry::NotPresent,
            "{entry:#x}: no arm64 layout is selected"
        );
        assert!(!linux.entry_is_present(entry));
    }

    let mut image = arm64_4k_kernel_image();
    image.entry64(0x4000, 1, new_swap);
    let harness = Harness::new(image, mode, PteSemantics::Linux);
    let err = harness
        .walk()
        .translate(0x1000, 0x0000_0000_0040_1ABC)
        .unwrap_err();
    match err {
        TranslateError::NotPresent { entry, .. } => assert_eq!(entry, new_swap),
        other => panic!("expected plain absence with the entry verbatim, got {other:?}"),
    }
}

#[test]
fn the_uniform_table_heuristic_never_fires_on_an_arm64_windows_space() {
    // A level-3 table of 512 identical present pages is an ordinary mapping
    // — a zero page mapped 512 times — and the Windows 10 pattern was only
    // ever observed on x64. Hiding it here would delete 2 MiB of a real
    // address space on an unobserved convention.
    let mut image = arm64_4k_kernel_image();
    for index in 0..512u64 {
        image.entry64(0x4000, index, 0x5000 | PAGE);
    }
    let mode = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    let harness = Harness::new(image, mode, PteSemantics::Windows);
    let t = harness
        .walk()
        .translate(0x1000, KERNEL_VA)
        .expect("a real mapping, not a decoy");
    assert_eq!(t.phys, 0x5ABC);
    assert_eq!(
        harness.suppressed.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn the_downward_enumeration_agrees_with_the_walk_on_every_arm64_shape() {
    // Pages and blocks at each permitted level, in both regimes, through the
    // same classifier: every run the enumeration reports must translate to
    // the same frame, size and execute-never bit through the upward walk.
    use crate::translate::enumerate::{EnumerateLimits, MappingRun, MappingSink, SinkFlow};

    #[derive(Default)]
    struct Collect(Vec<MappingRun>);
    impl MappingSink for Collect {
        fn run(&mut self, run: &MappingRun) -> SinkFlow {
            self.0.push(*run);
            SinkFlow::Continue
        }
        fn blind(&mut self, blindness: &crate::translate::enumerate::Blindness) -> SinkFlow {
            panic!("no blindness expected: {blindness:?}");
        }
    }

    let mut image = arm64_4k_kernel_image();
    image.entry64(0x2000, 1, 0x4000_0000 | BLOCK | ARM64_PXN_BIT);
    image.entry64(0x3000, 3, 0x0080_0000 | BLOCK);
    // Index 3, not 2: adjacent in both spaces the two pages would coalesce
    // under TTBR1 (where UXN is not the regime's bit) and not under TTBR0,
    // which is a different property from the one this test pins.
    image.entry64(0x4000, 3, 0x6000 | PAGE | ARM64_UXN_BIT);
    for (ttbr, base) in [(Ttbr::Ttbr1, 0xFFFF_0000_0000_0000u64), (Ttbr::Ttbr0, 0)] {
        let harness = Harness::new(
            {
                let mut copy = Image::new();
                copy.bytes.copy_from_slice(&image.bytes);
                copy
            },
            regime(Arm64Granule::Kb4, ttbr, 48),
            PteSemantics::Bare,
        );
        let mut sink = Collect::default();
        let outcome = harness
            .walk()
            .enumerate(0x1000, &EnumerateLimits::default(), &mut sink);
        assert!(outcome.is_complete(), "{outcome:?}");
        let expected: Vec<(u64, u64, u64)> = vec![
            (base | 0x0040_1000, 0x5000, 0x1000),
            (base | 0x0040_3000, 0x6000, 0x1000),
            (base | 0x0060_0000, 0x0080_0000, 1 << 21),
            (base | 0x4000_0000, 0x4000_0000, 1 << 30),
        ];
        assert_eq!(
            sink.0
                .iter()
                .map(|r| (r.va_start, r.phys_start, r.len))
                .collect::<Vec<_>>(),
            expected,
            "{ttbr:?}"
        );
        for run in &sink.0 {
            let t = harness.walk().translate(0x1000, run.va_start).unwrap();
            assert_eq!(
                t.page_base(),
                run.phys_start,
                "{ttbr:?} {:#x}",
                run.va_start
            );
            assert_eq!(t.run_len, run.page_bytes);
            assert_eq!(t.no_execute, run.no_execute, "{ttbr:?} {:#x}", run.va_start);
            assert!(harness.spec_is_canonical(run.va_start));
        }
    }
}

#[test]
fn arm64_identifiers_are_stable_for_artifact_metadata() {
    // The name is what a report and a re-run are matched on. The granule and
    // the register are in it; the width is not one of a fixed set and is
    // published as its own note by the layer, so two regimes of different
    // widths share a name and differ in the note.
    let kernel = regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48);
    assert_eq!(kernel.as_str(), "arm64_4k_ttbr1");
    assert_eq!(kernel.to_string(), "arm64_4k_ttbr1 (48-bit VA)");
    assert_eq!(
        regime(Arm64Granule::Kb16, Ttbr::Ttbr0, 47).as_str(),
        "arm64_16k_ttbr0"
    );
    assert_eq!(
        regime(Arm64Granule::Kb64, Ttbr::Ttbr1, 42).to_string(),
        "arm64_64k_ttbr1 (42-bit VA)"
    );
    assert!(!kernel.is_intel());
    assert!(PagingMode::Intel32e.is_intel());
    assert_eq!(
        kernel.arm64().map(|r| (r.granule(), r.ttbr(), r.va_bits())),
        Some((Arm64Granule::Kb4, Ttbr::Ttbr1, 48))
    );
    assert_eq!(PagingMode::Intel32e.arm64(), None);
    // No ARM64 name collides with an Intel one, and the two regimes of one
    // granule never share a name: a TTBR0 case re-opened as TTBR1 would
    // refuse every address it was built for.
    assert_ne!(
        regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48).as_str(),
        kernel.as_str()
    );
}

// ---------------------------------------------------------------------------
// A regime built from a raw `TCR_EL1` (MEM-043).
//
// Field positions from ARM DDI 0487, D17 `TCR_EL1`: T0SZ 5:0, EPD0 7,
// TG0 15:14, T1SZ 21:16, A1 22, EPD1 23, TG1 31:30, IPS 34:32, TBI0 37,
// TBI1 38, HPD0 41, HPD1 42, DS 59.
// ---------------------------------------------------------------------------

/// The `TCR_EL1` QEMU recorded for the MMUShell `aarch64/linux` guest.
const MMUSHELL_LINUX_TCR: u64 = 0x32_b559_3519;
/// The `TCR_EL1` QEMU recorded for the MMUShell `aarch64/linux_debian` guest.
const MMUSHELL_DEBIAN_TCR: u64 = 0x40_0032_b550_3510;

#[test]
fn a_raw_tcr_el1_builds_the_regime_the_hardware_used() {
    // Real register values (seance_memory/tests/arm64_mmushell_real_test.rs
    // documents where they were read from); no dump is needed to decode them.
    //
    // 0x32_b559_3519: T0SZ = 0x19 = 25 and T1SZ = 0x59 & 0x3f = 25 (39-bit),
    // TG0 = 0b00 (4K), TG1 = 0b10 (4K), IPS = 0b010 (40-bit), TBI0 = 1,
    // TBI1 = 0, HPD = 0, EPD = 0, DS = 0.
    for (tcr, va_bits) in [(MMUSHELL_LINUX_TCR, 39u8), (MMUSHELL_DEBIAN_TCR, 48u8)] {
        let kernel = Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr1).expect("a recorded TCR");
        assert_eq!(kernel.granule(), Arm64Granule::Kb4, "{tcr:#x}");
        assert_eq!(kernel.ttbr(), Ttbr::Ttbr1);
        assert_eq!(kernel.va_bits(), va_bits, "{tcr:#x}");
        assert_eq!(kernel.ips_bits(), 40, "IPS = 0b010");
        assert!(!kernel.tbi(), "TBI1 = 0");
        assert!(!kernel.hierarchical_permissions_disabled());
        assert!(!kernel.walks_disabled());

        let user = Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr0).expect("a recorded TCR");
        assert_eq!(user.granule(), Arm64Granule::Kb4);
        assert_eq!(user.va_bits(), va_bits);
        assert!(user.tbi(), "TBI0 = 1");
        assert!(!user.walks_disabled());
    }
}

#[test]
fn a_regime_built_without_a_tcr_keeps_the_defaults_it_always_had() {
    let r = Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr0, 48).unwrap();
    assert_eq!(r.ips_bits(), 48);
    assert!(!r.tbi());
    assert!(!r.hierarchical_permissions_disabled());
    assert!(!r.walks_disabled());
}

/// A `TCR_EL1` with T0SZ = T1SZ = 16 (48-bit), IPS 40-bit, and the given
/// TG0 / TG1 encodings.
fn tcr_with_granules(tg0: u64, tg1: u64) -> u64 {
    16 | (16 << 16) | (tg0 << 14) | (tg1 << 30) | (0b010 << 32)
}

#[test]
fn tg1_and_tg0_encode_granules_differently() {
    // D17 TCR_EL1: TG0 0b00 4K, 0b01 64K, 0b10 16K; TG1 0b01 16K, 0b10 4K,
    // 0b11 64K. Reading one field with the other's table swaps 4K and 16K.
    for (tg0, granule) in [
        (0b00, Arm64Granule::Kb4),
        (0b01, Arm64Granule::Kb64),
        (0b10, Arm64Granule::Kb16),
    ] {
        let r = Arm64Regime::from_tcr_el1(tcr_with_granules(tg0, 0b10), Ttbr::Ttbr0).unwrap();
        assert_eq!(r.granule(), granule, "TG0 {tg0:#b}");
    }
    for (tg1, granule) in [
        (0b01, Arm64Granule::Kb16),
        (0b10, Arm64Granule::Kb4),
        (0b11, Arm64Granule::Kb64),
    ] {
        let r = Arm64Regime::from_tcr_el1(tcr_with_granules(0b00, tg1), Ttbr::Ttbr1).unwrap();
        assert_eq!(r.granule(), granule, "TG1 {tg1:#b}");
    }
}

#[test]
fn a_reserved_granule_encoding_is_refused_by_name() {
    let err = Arm64Regime::from_tcr_el1(tcr_with_granules(0b11, 0b10), Ttbr::Ttbr0).unwrap_err();
    assert!(err.contains("TG0"), "{err}");
    let err = Arm64Regime::from_tcr_el1(tcr_with_granules(0b00, 0b00), Ttbr::Ttbr1).unwrap_err();
    assert!(err.contains("TG1"), "{err}");
    // The other regime's reserved field does not stop this one being built.
    assert!(Arm64Regime::from_tcr_el1(tcr_with_granules(0b00, 0b00), Ttbr::Ttbr0).is_ok());
}

#[test]
fn a_txsz_outside_16_to_39_is_refused() {
    let base = tcr_with_granules(0b00, 0b10) & !0x3f & !(0x3f << 16);
    for txsz in [15u64, 40, 63] {
        assert!(
            Arm64Regime::from_tcr_el1(base | txsz | (16 << 16), Ttbr::Ttbr0).is_err(),
            "T0SZ {txsz}"
        );
        assert!(
            Arm64Regime::from_tcr_el1(base | 16 | (txsz << 16), Ttbr::Ttbr1).is_err(),
            "T1SZ {txsz}"
        );
    }
    assert_eq!(
        Arm64Regime::from_tcr_el1(base | 39 | (16 << 16), Ttbr::Ttbr0)
            .unwrap()
            .va_bits(),
        25
    );
}

#[test]
fn a_tcr_with_ds_set_under_a_4k_or_64k_granule_is_refused_by_name() {
    let err = Arm64Regime::from_tcr_el1(MMUSHELL_DEBIAN_TCR | (1 << 59), Ttbr::Ttbr1).unwrap_err();
    assert!(err.contains("DS") && err.contains("LPA2"), "{err}");
    assert!(
        err.contains("16 KiB"),
        "it says which granule is decoded: {err}"
    );
    // 64 KiB: TG0 = 0b01, TG1 = 0b11.
    let tcr = tcr_with_granules(0b01, 0b11) | (1 << 59);
    for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
        let err = Arm64Regime::from_tcr_el1(tcr, ttbr).unwrap_err();
        assert!(err.contains("DS") && err.contains("LPA2"), "{err}");
    }
}

// ---------------------------------------------------------------------------
// FEAT_LPA2 under a 16 KiB granule (`TCR_EL1.DS = 1`), MEM-043.
//
// ARM DDI 0487 D8.3: with DS = 1 the shareability field (bits 9:8) of a block or
// page descriptor is output-address bits 51:50, bits 49:48 are output-address
// bits 49:48, a table descriptor's next-level address takes the same two
// pairs, and a 16 KiB level-1 descriptor with the type bit clear is a 64 GiB
// block. `TTBRn_EL1.BADDR` is bits 47:1 with address bits 51:48 in bits 5:2.
// The real-capture test (`tests/arm64_16k_lpa2_real_test.rs`) has every high
// address bit clear; these tables put them in.
// ---------------------------------------------------------------------------

/// A `TCR_EL1` for a 16 KiB TTBR1 regime of 52 bits (T1SZ = 12) with the given
/// `IPS` and `DS`; TG1 = 0b01 is 16 KiB.
fn tcr_16k_52(ips: u64, ds: bool) -> u64 {
    (12 << 16) | (0b01 << 30) | (ips << 32) | (u64::from(ds) << 59)
}

fn lpa2_mode(ips: u64) -> PagingMode {
    PagingMode::Arm64(
        Arm64Regime::from_tcr_el1(tcr_16k_52(ips, true), Ttbr::Ttbr1).expect("a 16 KiB LPA2 TCR"),
    )
}

#[test]
fn a_52_bit_width_and_a_52_bit_ips_exist_only_under_ds() {
    let r = Arm64Regime::from_tcr_el1(tcr_16k_52(0b110, true), Ttbr::Ttbr1).unwrap();
    assert!(r.lpa2());
    assert_eq!((r.va_bits(), r.ips_bits()), (52, 52));
    // The same register without DS: 52 bits of VA and 52 of IPS are not decoded.
    assert!(Arm64Regime::from_tcr_el1(tcr_16k_52(0b110, false), Ttbr::Ttbr1).is_err());
    let r48 = Arm64Regime::from_tcr_el1(
        (16 << 16) | (0b01 << 30) | (0b110 << 32) | (1 << 59),
        Ttbr::Ttbr1,
    )
    .unwrap();
    assert_eq!(r48.ips_bits(), 52, "IPS = 0b110 under DS is 52 bits");
    assert!(
        !Arm64Regime::from_tcr_el1((16 << 16) | (0b01 << 30) | (0b110 << 32), Ttbr::Ttbr1)
            .unwrap()
            .lpa2()
    );
    // Wider than LPA2 defines (T1SZ = 11) is refused even under DS.
    let wide = (11 << 16) | (0b01 << 30) | (0b110 << 32) | (1 << 59);
    assert!(Arm64Regime::from_tcr_el1(wide, Ttbr::Ttbr1).is_err());
}

/// 16 KiB, 52-bit TTBR1 regime, four levels: L0 (32 entries) at 0x1000, L1 at
/// 0x4000, L2 at 0x8000, L3 at 0xC000, one page at `frame`.
///
/// ```text
/// va         = 0xFFF0_0000_0000_4123
/// bits 63:52 = 0xFFF          all one -> TTBR1
/// bits 51:47 = 0              L0 index 0 (five bits, a 32-entry table)
/// bits 46:36 = 0              L1 index 0
/// bits 35:25 = 0              L2 index 0
/// bits 24:14 = 0x4123 >> 14   = 1   L3 index 1
/// bits 13:0  = 0x4123 & 0x3FFF = 0x123   page offset
/// ```
const LPA2_VA: u64 = 0xFFF0_0000_0000_4123;

fn lpa2_image(leaf: u64) -> Image {
    let mut image = Image::new();
    image.entry64(0x1000, 0, 0x4000 | TABLE);
    image.entry64(0x4000, 0, 0x8000 | TABLE);
    image.entry64(0x8000, 0, 0xC000 | TABLE);
    image.entry64(0xC000, 1, leaf);
    image
}

#[test]
fn an_lpa2_page_names_output_address_bits_51_to_48_from_9_8_and_49_48() {
    // Frame 0x4_0000 (a 16 KiB-aligned address), OA[49:48] = 0b01 in bits 49:48,
    // OA[51:50] = 0b11 in bits 9:8, AF set. By hand:
    //   pa = (0b11 << 50) | (0b01 << 48) | 0x4_0000 | 0x123
    //      = 0x000C_0000_0000_0000 | 0x0001_0000_0000_0000 | 0x4_0123
    //      = 0x000D_0000_0004_0123
    let leaf = 0x4_0000 | PRESENT_BIT | ARM64_TABLE_BIT | (1 << 10) | (0b11 << 8) | (0b01 << 48);
    let harness = Harness::new(lpa2_image(leaf), lpa2_mode(0b110), PteSemantics::Bare);
    let t = harness
        .walk()
        .translate(0x1000, LPA2_VA)
        .expect("an LPA2 page");
    assert_eq!(t.phys, 0x000D_0000_0004_0123);

    // With every high bit clear it is the plain frame: shareability is gone, not
    // misread as address.
    let leaf = 0x4_0000 | PRESENT_BIT | ARM64_TABLE_BIT | (1 << 10);
    let harness = Harness::new(lpa2_image(leaf), lpa2_mode(0b110), PteSemantics::Bare);
    assert_eq!(
        harness.walk().translate(0x1000, LPA2_VA).unwrap().phys,
        0x4_0123
    );
}

#[test]
fn an_lpa2_output_address_above_ips_is_an_address_size_fault() {
    // The same descriptor under IPS = 0b101 (48 bits): its address is above the
    // width the register allows, so the hardware faults and nothing is stated.
    let leaf = 0x4_0000 | PRESENT_BIT | ARM64_TABLE_BIT | (1 << 10) | (0b11 << 8) | (0b01 << 48);
    let harness = Harness::new(lpa2_image(leaf), lpa2_mode(0b101), PteSemantics::Bare);
    let err = harness
        .walk()
        .translate(0x1000, LPA2_VA)
        .expect_err("an address above IPS must not translate");
    assert!(
        matches!(err, TranslateError::AddressOverflow { .. }),
        "{err:?}"
    );
    // A next-level table address above IPS is refused before the walk reads it.
    let mut image = lpa2_image(0x4_0000 | PRESENT_BIT | ARM64_TABLE_BIT);
    image.entry64(0x4000, 0, 0x8000 | TABLE | (0b01 << 8));
    let harness = Harness::new(image, lpa2_mode(0b101), PteSemantics::Bare);
    assert!(harness.walk().translate(0x1000, LPA2_VA).is_err());
}

#[test]
fn a_16k_level_1_block_under_lpa2_is_a_64_gib_block() {
    // Level 1 of a 16 KiB regime indexes bits 46:36, so a block there spans 2^36
    // bytes = 64 GiB. Output address bits 47:36 come from the descriptor; bits
    // 35:0 of the virtual address are the offset. By hand, for a block at
    // 0x30_0000_0000 (bit 37 and 36 set) and VA offset 0x1234_5678:
    //   pa = 0x30_0000_0000 + 0x1234_5678 = 0x30_1234_5678
    let spec = PagingSpec::new(lpa2_mode(0b110), PteSemantics::Bare);
    assert_eq!(spec.levels()[1].leaf, LeafRule::Arm64Block);
    let block = 0x30_0000_0000 | PRESENT_BIT | (1 << 10);
    match spec.classify(block, 1) {
        Some(EntryKind::Leaf {
            frame, size_log2, ..
        }) => assert_eq!((frame, size_log2), (0x30_0000_0000, 36)),
        other => panic!("expected a 64 GiB block, got {other:?}"),
    }
    let mut image = Image::new();
    image.entry64(0x1000, 0, 0x4000 | TABLE);
    image.entry64(0x4000, 0, block);
    let harness = Harness::new(image, lpa2_mode(0b110), PteSemantics::Bare);
    let va = 0xFFF0_0000_0000_0000 | 0x1234_5678;
    assert_eq!(
        harness.walk().translate(0x1000, va).unwrap().phys,
        0x30_1234_5678
    );
    // Without LPA2 the same level and bits are an undecodable block, as before.
    let plain = PagingSpec::new(
        regime(Arm64Granule::Kb16, Ttbr::Ttbr1, 48),
        PteSemantics::Bare,
    );
    assert_eq!(plain.levels()[1].leaf, LeafRule::Arm64TableOrLpaBlock);
}

#[test]
fn an_lpa2_ttbr_carries_address_bits_51_to_48_in_bits_5_to_2() {
    // A 52-bit regime's level 0 is a 32-entry, 256-byte table, so its base may
    // sit at an address with bit 8 set. TTBR = base | BADDR[51:48] << 2 | CnP:
    //   base 0x4000_0100, BADDR[51:48] = 0b0101 -> bits 4 and 2 -> 0x14, CnP 1
    //   TTBR = 0x4000_0115
    //   root = 0x0005_0000_4000_0100  (bit 48 and bit 50 from BADDR, bit 8 kept)
    // Read as a descriptor, bits 9:8 = 0b01 would have put a stray bit 50 in.
    let spec = PagingSpec::new(lpa2_mode(0b110), PteSemantics::Bare);
    assert_eq!(spec.root_table_pa(0x4000_0115), Some(0x0005_0000_4000_0100));
    // Without LPA2 the base is read as it always was: a 47-bit regime's top table
    // is a full 2,048-entry (16 KiB) table, so the alignment strips bits 13:0.
    let plain = PagingSpec::new(
        regime(Arm64Granule::Kb16, Ttbr::Ttbr1, 47),
        PteSemantics::Bare,
    );
    assert_eq!(plain.root_table_pa(0x4000_0115), Some(0x4000_0000));
}

#[test]
fn every_ips_encoding_decodes_to_its_width_and_the_reserved_one_is_refused() {
    let base = tcr_with_granules(0b00, 0b10) & !(0b111 << 32);
    for (ips, bits) in [
        (0b000u64, 32u8),
        (0b001, 36),
        (0b010, 40),
        (0b011, 42),
        (0b100, 44),
        (0b101, 48),
        // 52 bits exists only under FEAT_LPA; with DS = 0 a 4K descriptor
        // names 48 bits at most, and FEAT_LPA descriptors are refused.
        (0b110, 48),
    ] {
        let r = Arm64Regime::from_tcr_el1(base | (ips << 32), Ttbr::Ttbr1).unwrap();
        assert_eq!(r.ips_bits(), bits, "IPS {ips:#b}");
    }
    assert!(Arm64Regime::from_tcr_el1(base | (0b111 << 32), Ttbr::Ttbr1).is_err());
}

#[test]
fn tbi_hpd_and_epd_are_read_per_regime() {
    let base = tcr_with_granules(0b00, 0b10);
    let tcr = base | (1 << 38) | (1 << 42) | (1 << 23);
    let kernel = Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr1).unwrap();
    assert!(kernel.tbi() && kernel.hierarchical_permissions_disabled() && kernel.walks_disabled());
    let user = Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr0).unwrap();
    assert!(!user.tbi() && !user.hierarchical_permissions_disabled() && !user.walks_disabled());
    let tcr = base | (1 << 37) | (1 << 41) | (1 << 7);
    let user = Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr0).unwrap();
    assert!(user.tbi() && user.hierarchical_permissions_disabled() && user.walks_disabled());
    let kernel = Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr1).unwrap();
    assert!(!kernel.tbi() && !kernel.hierarchical_permissions_disabled());
}

// ---------------------------------------------------------------------------
// IPS: an output address above the regime's physical width is an Address
// size fault (D8.5), not a translation (MEM-043).
//
// Synthetic by necessity: no descriptor in the real MMUShell trees names an
// address above their 40-bit IPS, so the real data cannot exercise the
// fault. The rule is defined wholly by the architecture.
// ---------------------------------------------------------------------------

/// Every run and every blindness an enumeration reports.
#[derive(Default)]
struct Recorded {
    runs: Vec<crate::translate::enumerate::MappingRun>,
    blind: Vec<crate::translate::enumerate::Blindness>,
}

impl crate::translate::enumerate::MappingSink for Recorded {
    fn run(
        &mut self,
        run: &crate::translate::enumerate::MappingRun,
    ) -> crate::translate::enumerate::SinkFlow {
        self.runs.push(*run);
        crate::translate::enumerate::SinkFlow::Continue
    }
    fn blind(
        &mut self,
        blindness: &crate::translate::enumerate::Blindness,
    ) -> crate::translate::enumerate::SinkFlow {
        self.blind.push(blindness.clone());
        crate::translate::enumerate::SinkFlow::Continue
    }
}

fn enumerate_all(harness: &Harness, dtb: u64) -> Recorded {
    let mut sink = Recorded::default();
    harness.walk().enumerate(
        dtb,
        &crate::translate::enumerate::EnumerateLimits::default(),
        &mut sink,
    );
    sink
}

/// A 4K / 39-bit TTBR1 regime (T1SZ = 25, TG1 = 4K) with the given IPS
/// encoding.
fn tcr_4k_39_ttbr1(ips: u64) -> PagingMode {
    let tcr = (25u64 << 16) | (0b10 << 30) | (ips << 32);
    PagingMode::Arm64(Arm64Regime::from_tcr_el1(tcr, Ttbr::Ttbr1).expect("a defined TCR"))
}

/// 39-bit regime, three levels: L1 at 0x1000, L2 at 0x2000, L3 at 0x3000.
///
/// ```text
/// va         = 0xFFFF_FF80_0000_1ABC     (base of a 39-bit TTBR1 space + 0x1ABC)
/// bits 38:30 = 0      L1 index 0
/// bits 29:21 = 0      L2 index 0
/// bits 20:12 = 1      L3 index 1
/// bits 11:0  = 0xABC  offset
/// ```
const VA_39: u64 = 0xFFFF_FF80_0000_1ABC;

fn image_39_with_leaf(leaf: u64) -> Image {
    let mut image = Image::new();
    image.entry64(0x1000, 0, 0x2000 | TABLE);
    image.entry64(0x2000, 0, 0x3000 | TABLE);
    image.entry64(0x3000, 1, leaf);
    image
}

#[test]
fn an_output_address_above_ips_is_an_address_size_fault_not_a_translation() {
    // L3[1] names PA 2^40. Under IPS = 0b010 (40 bits: PA 0..2^40) that
    // address does not exist on the machine and the hardware raises an
    // Address size fault; masking it to 40 bits would answer with page 0.
    let leaf = (1u64 << 40) | PAGE;
    let harness = Harness::new(
        image_39_with_leaf(leaf),
        tcr_4k_39_ttbr1(0b010),
        PteSemantics::Bare,
    );
    let err = harness
        .walk()
        .translate(0x1000, VA_39)
        .expect_err("an output address above IPS");
    match &err {
        TranslateError::AddressOverflow { detail, .. } => {
            assert!(detail.contains("Address size fault"), "{detail}");
            assert!(detail.contains("IPS"), "{detail}");
        }
        other => panic!("expected an address-size refusal, got {other:?}"),
    }
    assert_eq!(err.hole_reason(), None, "a refusal, never an absent page");

    let seen = enumerate_all(&harness, 0x1000);
    assert!(seen.runs.is_empty(), "{:?}", seen.runs);
    assert!(
        seen.blind.iter().any(|b| matches!(
            b,
            crate::translate::enumerate::Blindness::Unnameable { entry, detail, .. }
                if *entry == leaf && detail.contains("Address size fault")
        )),
        "the entry is carried verbatim: {:?}",
        seen.blind
    );

    // Control: the same tree under IPS = 0b100 (44 bits) translates.
    let harness = Harness::new(
        image_39_with_leaf(leaf),
        tcr_4k_39_ttbr1(0b100),
        PteSemantics::Bare,
    );
    let t = harness
        .walk()
        .translate(0x1000, VA_39)
        .expect("inside 44 bits");
    assert_eq!(t.phys, (1u64 << 40) | 0xABC);
}

#[test]
fn a_table_address_above_ips_is_an_address_size_fault_too() {
    // L2[0] names a next-level table at 2^40: under IPS = 40 bits the walk
    // faults before it reads anything there.
    let mut image = image_39_with_leaf(0x5000 | PAGE);
    let table = (1u64 << 40) | 0x3000 | TABLE;
    image.entry64(0x2000, 0, table);
    let harness = Harness::new(image, tcr_4k_39_ttbr1(0b010), PteSemantics::Bare);
    let err = harness.walk().translate(0x1000, VA_39).unwrap_err();
    assert!(
        matches!(&err, TranslateError::AddressOverflow { detail, .. } if detail.contains("Address size fault")),
        "{err:?}"
    );
    let seen = enumerate_all(&harness, 0x1000);
    assert!(seen.runs.is_empty());
    assert!(seen.blind.iter().any(|b| matches!(
        b,
        crate::translate::enumerate::Blindness::Unnameable { entry, .. } if *entry == table
    )));
}

#[test]
fn a_regime_whose_ips_was_never_recorded_enforces_only_the_48_bit_descriptor_width() {
    // `Arm64Regime::new` knows no IPS; it must not invent one narrower than
    // the descriptor format, or a real 44-bit machine would lose its top RAM.
    let leaf = (1u64 << 40) | PAGE;
    let harness = Harness::new(
        image_39_with_leaf(leaf),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 39),
        PteSemantics::Bare,
    );
    assert_eq!(
        harness.walk().translate(0x1000, VA_39).unwrap().phys,
        (1u64 << 40) | 0xABC
    );
}

// ---------------------------------------------------------------------------
// Top-byte-ignore (MEM-043). D8.8 / `TCR_EL1.TBI0`, `TBI1`: with TBI on for
// a regime the hardware ignores address bits 63:56 — bit 55 selects the TTBR
// — so a tagged pointer translates exactly as its untagged form. With it off
// the tagged pointer faults. Synthetic tables; the rule is the manual's, and
// the corpus test pins it against the recorded TCR_EL1 as well.
// ---------------------------------------------------------------------------

/// 48-bit, 4K both halves, IPS 48, plus `extra` bits.
fn tcr_4k_48(extra: u64) -> u64 {
    16 | (16 << 16) | (0b10 << 30) | (0b101 << 32) | extra
}

fn tbi_harness(tcr: u64, ttbr: Ttbr) -> Harness {
    Harness::new(
        arm64_4k_kernel_image(),
        PagingMode::Arm64(Arm64Regime::from_tcr_el1(tcr, ttbr).unwrap()),
        PteSemantics::Bare,
    )
}

#[test]
fn a_tagged_pointer_translates_only_in_a_regime_whose_tbi_is_on() {
    const TBI0: u64 = 1 << 37;
    const TBI1: u64 = 1 << 38;
    let user_va = 0x0000_0000_0040_1ABCu64;
    let tagged_user = user_va | (0x2a << 56);
    let tagged_kernel = (KERNEL_VA & 0x00ff_ffff_ffff_ffff) | (0x2a << 56);

    // TBI0 on, TBI1 off: the arm64 Linux default, and what both MMUShell
    // guests recorded.
    let tcr = tcr_4k_48(TBI0);
    let user = tbi_harness(tcr, Ttbr::Ttbr0);
    assert_eq!(
        user.walk()
            .translate(0x1000, tagged_user)
            .expect("TBI0 = 1")
            .phys,
        0x5ABC
    );
    assert!(user.spec_is_canonical(tagged_user));
    let kernel = tbi_harness(tcr, Ttbr::Ttbr1);
    assert!(matches!(
        kernel.walk().translate(0x1000, tagged_kernel),
        Err(TranslateError::NonCanonical { .. })
    ));
    assert_eq!(
        kernel.walk().translate(0x1000, KERNEL_VA).unwrap().phys,
        0x5ABC
    );

    // TBI1 on: the tagged kernel pointer translates; TBI0 off: the tagged
    // user pointer faults.
    let tcr = tcr_4k_48(TBI1);
    let kernel = tbi_harness(tcr, Ttbr::Ttbr1);
    assert_eq!(
        kernel
            .walk()
            .translate(0x1000, tagged_kernel)
            .expect("TBI1 = 1")
            .phys,
        0x5ABC
    );
    let user = tbi_harness(tcr, Ttbr::Ttbr0);
    assert!(matches!(
        user.walk().translate(0x1000, tagged_user),
        Err(TranslateError::NonCanonical { .. })
    ));
}

#[test]
fn tbi_ignores_the_top_byte_only_and_bit_55_still_selects_the_regime() {
    let user = tbi_harness(tcr_4k_48(1 << 37), Ttbr::Ttbr0);
    // Bits 55:48 are not part of the tag: an address with them set is not a
    // tagged TTBR0 address, it is a fault (or TTBR1's, if all set).
    for va in [
        0x0080_0000_0040_1ABCu64,
        0x2A01_0000_0040_1ABC,
        0xFFFF_0000_0040_1ABC,
    ] {
        assert!(!user.spec_is_canonical(va), "{va:#x}");
    }
    let kernel = tbi_harness(tcr_4k_48(1 << 38), Ttbr::Ttbr1);
    // Bit 55 clear under TBI1 is a TTBR0 address, not a tagged kernel one.
    assert!(!kernel.spec_is_canonical(0xFF7F_0000_0040_1ABC));
    assert!(kernel.spec_is_canonical(0x00FF_0000_0040_1ABC));
    // A regime built with `new` never untags.
    let plain = Harness::new(
        arm64_4k_kernel_image(),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48),
        PteSemantics::Bare,
    );
    assert!(!plain.spec_is_canonical(0x2A00_0000_0040_1ABC));
}

#[test]
fn next_canonical_under_tbi_still_answers_with_the_untagged_space() {
    // The layer's byte space is the untagged one; resuming an enumeration at
    // a tagged alias would walk the same pages twice under another name.
    let spec = PagingSpec::new(
        PagingMode::Arm64(Arm64Regime::from_tcr_el1(tcr_4k_48(1 << 38), Ttbr::Ttbr1).unwrap()),
        PteSemantics::Bare,
    );
    assert_eq!(spec.next_canonical(0), Some(0xFFFF_0000_0000_0000));
    assert_eq!(
        spec.next_canonical(0x00FF_0000_0000_0000),
        Some(0xFFFF_0000_0000_0000)
    );
}

// ---------------------------------------------------------------------------
// Hierarchical execute-never (MEM-043). D8.4.2 (hierarchical permission
// controls): a table descriptor's PXNTable (bit 59) / UXNTable (bit 60)
// forces PXN / UXN on every translation below it, OR'd with the leaf's own
// bit, unless TCR_EL1.HPDn disables hierarchical permissions.
//
// Synthetic by necessity: no table descriptor in the real MMUShell trees
// sets bits 63:59, so the real data cannot exercise the rule. The rule is a
// spec-defined OR, and the expected answers below are the manual's.
// ---------------------------------------------------------------------------

const PXN_TABLE: u64 = 1 << 59;
const UXN_TABLE: u64 = 1 << 60;

/// The 4K / 48-bit fixture with `bits` set on the level-1 table descriptor
/// (L1[0] at 0x2000, pointing at the L2 table).
fn image_with_l1_table_bits(bits: u64) -> Image {
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x2000, 0, 0x3000 | TABLE | bits);
    image
}

fn nx_through_walk_and_enumeration(harness: &Harness, va: u64) -> (bool, bool) {
    let walked = harness
        .walk()
        .translate(0x1000, va)
        .expect("mapped")
        .no_execute;
    let seen = enumerate_all(harness, 0x1000);
    assert!(seen.blind.is_empty(), "{:?}", seen.blind);
    let run = seen
        .runs
        .iter()
        .find(|r| r.va_start <= va && va - r.va_start < r.len)
        .expect("the enumeration reports the page");
    (walked, run.no_execute)
}

#[test]
fn an_xntable_bit_on_a_table_descriptor_makes_every_leaf_below_it_no_execute() {
    // TTBR1: PXNTable on L1[0]; the L3 page has PXN clear. The kernel could
    // not execute it.
    let harness = Harness::new(
        image_with_l1_table_bits(PXN_TABLE),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48),
        PteSemantics::Bare,
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, KERNEL_VA),
        (true, true),
        "PXNTable forces PXN below it"
    );

    // TTBR0: UXNTable is the regime's own bit.
    let user_va = 0x0000_0000_0040_1ABC;
    let harness = Harness::new(
        image_with_l1_table_bits(UXN_TABLE),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48),
        PteSemantics::Bare,
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, user_va),
        (true, true)
    );

    // The other exception level's table bit does not answer this regime's
    // question, exactly as the leaf's other XN bit does not.
    let harness = Harness::new(
        image_with_l1_table_bits(PXN_TABLE),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr0, 48),
        PteSemantics::Bare,
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, user_va),
        (false, false)
    );
    let harness = Harness::new(
        image_with_l1_table_bits(UXN_TABLE),
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48),
        PteSemantics::Bare,
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, KERNEL_VA),
        (false, false)
    );
}

#[test]
fn an_intel_xd_bit_on_a_non_leaf_entry_makes_every_page_below_it_no_execute() {
    // Intel SDM Vol. 3A 4.6: with EFER.NXE = 1, an instruction fetch is not
    // allowed from a linear address if XD is set in ANY paging-structure
    // entry used to translate it — not only in the leaf. The same rule the
    // ARM64 table bits follow, so both walkers must fold it the same way.
    use crate::translate::spec::NX_BIT;
    const VA: u64 = 0x0040_1000; // PML4 0, PDPT 0, PD 2, PT 1.
    let x64 = |pml4e_nx: u64, pde_nx: u64| {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT | pml4e_nx);
        image.entry64(0x2000, 0, 0x3000 | PRESENT_BIT);
        image.entry64(0x3000, 2, 0x4000 | PRESENT_BIT | pde_nx);
        image.entry64(0x4000, 1, 0x5000 | PRESENT_BIT);
        Harness::new(image, PagingMode::Intel32e, PteSemantics::Bare)
    };
    assert_eq!(
        nx_through_walk_and_enumeration(&x64(0, 0), VA),
        (false, false)
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&x64(0, NX_BIT), VA),
        (true, true),
        "XD on the PDE forces it below"
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&x64(NX_BIT, 0), VA),
        (true, true),
        "XD on the PML4E forces it below"
    );

    // PAE: a PDE's XD applies below it too. A PDPTE has no XD bit (bit 63 is
    // reserved there), so it is never read as one.
    let pae = |pdpte_bits: u64, pde_nx: u64| {
        let mut image = Image::new();
        image.entry64(0x1000, 0, 0x2000 | PRESENT_BIT | pdpte_bits);
        image.entry64(0x2000, 2, 0x3000 | PRESENT_BIT | pde_nx);
        image.entry64(0x3000, 1, 0x5000 | PRESENT_BIT);
        Harness::new(image, PagingMode::IntelPae, PteSemantics::Bare)
    };
    assert_eq!(
        nx_through_walk_and_enumeration(&pae(0, NX_BIT), VA),
        (true, true)
    );
    let spec = PagingSpec::new(PagingMode::IntelPae, PteSemantics::Bare);
    assert!(!spec.table_execute_never(0x2000 | PRESENT_BIT | NX_BIT, 0));
    assert!(spec.table_execute_never(0x3000 | PRESENT_BIT | NX_BIT, 1));
    // 32-bit paging has no XD at all.
    let spec = PagingSpec::new(PagingMode::Intel32, PteSemantics::Bare);
    assert!(!spec.table_execute_never(u64::from(u32::MAX), 0));
}

#[test]
fn hierarchical_execute_never_is_not_folded_when_tcr_el1_hpd_disables_it() {
    // HPD1 = 1 (bit 42): the hardware ignores PXNTable in TTBR1's tables.
    let harness = Harness::new(
        image_with_l1_table_bits(PXN_TABLE),
        PagingMode::Arm64(Arm64Regime::from_tcr_el1(tcr_4k_48(1 << 42), Ttbr::Ttbr1).unwrap()),
        PteSemantics::Bare,
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, KERNEL_VA),
        (false, false)
    );
}

#[test]
fn a_table_xn_bit_governs_only_its_own_subtree() {
    // L2 has two table entries: L2[2] (the fixture's, to L3 at 0x4000) with
    // PXNTable, and L2[3] to a second L3 at 0x6000 without it. Only the first
    // subtree is execute-never.
    let mut image = arm64_4k_kernel_image();
    image.entry64(0x3000, 2, 0x4000 | TABLE | PXN_TABLE);
    image.entry64(0x3000, 3, 0x6000 | TABLE);
    image.entry64(0x6000, 0, 0x7000 | PAGE);
    let harness = Harness::new(
        image,
        regime(Arm64Granule::Kb4, Ttbr::Ttbr1, 48),
        PteSemantics::Bare,
    );
    // L2 index 3 -> bits 29:21 = 3 -> 0x60_0000.
    let sibling = 0xFFFF_0000_0060_0123;
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, KERNEL_VA),
        (true, true)
    );
    assert_eq!(
        nx_through_walk_and_enumeration(&harness, sibling),
        (false, false)
    );
}
