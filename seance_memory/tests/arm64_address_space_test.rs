//! An ARM64 address space end to end through the public API: two regimes
//! over one physical image, each its own [`VirtualLayer`], read through the
//! primitives the rest of Séance already has.
//!
//! # Fixture provenance
//!
//! Synthetic. No ARM64 capture exists on the machine this was written on, so
//! the tables are written from ARM DDI 0487 D8.2/D8.3 and the expected
//! physical addresses are worked by hand in the comments — the same footing
//! as `seance_memory/src/translate/arm64_tests.rs`, stated here as well
//! because a reader of this file alone is owed it.

use std::sync::Arc;

use seance_core::data_source::ByteSliceDataSource;
use seance_core::io::read_exact_or_fail;
use seance_memory::layer::{HoleReason, LayerError, MemoryHole, MemoryLayer};
use seance_memory::physical::PhysicalLayer;
use seance_memory::translate::{
    Arm64Granule, Arm64Regime, PagingMode, PagingSpec, PteSemantics, TranslateError, Ttbr,
    VirtualLayer,
};

/// Valid + table / page (bits 1:0 = 0b11), AF set.
const TABLE: u64 = 0b11;
const PAGE: u64 = 0b11 | (1 << 10);

fn put(bytes: &mut [u8], table: u64, index: u64, value: u64) {
    let at = (table + index * 8) as usize;
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// One physical image holding a kernel hierarchy rooted at 0x1000 and a
/// process hierarchy rooted at 0x10000, 4 KiB granule, 48-bit regimes.
///
/// Kernel (TTBR1 = 0x1000):
///   L0[0] -> 0x2000, L1[0] -> 0x3000, L2[2] -> 0x4000, L3[1] -> page 0x8000
///   which is VA 0xFFFF_0000_0040_1000 (L0 0, L1 0, L2 2, L3 1, offset 0).
///   L3[2] is invalid: VA 0xFFFF_0000_0040_2000 is not present.
///
/// Process (TTBR0 = 0x10000):
///   L0[0] -> 0x11000, L1[0] -> 0x12000, L2[0] -> 0x13000, L3[5] -> page
///   0x9000, which is VA 0x0000_0000_0000_5000.
fn image() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x10_0000];
    put(&mut bytes, 0x1000, 0, 0x2000 | TABLE);
    put(&mut bytes, 0x2000, 0, 0x3000 | TABLE);
    put(&mut bytes, 0x3000, 2, 0x4000 | TABLE);
    put(&mut bytes, 0x4000, 1, 0x8000 | PAGE);
    bytes[0x8000..0x8008].copy_from_slice(&0xDEAD_BEEF_0000_0001u64.to_le_bytes());

    put(&mut bytes, 0x10000, 0, 0x11000 | TABLE);
    put(&mut bytes, 0x11000, 0, 0x12000 | TABLE);
    put(&mut bytes, 0x12000, 0, 0x13000 | TABLE);
    put(&mut bytes, 0x13000, 5, 0x9000 | PAGE);
    bytes[0x9000..0x9008].copy_from_slice(&0x0BAD_F00D_0000_0002u64.to_le_bytes());
    bytes
}

fn physical() -> Arc<dyn MemoryLayer> {
    Arc::new(PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(image()))).unwrap())
}

fn mode(ttbr: Ttbr) -> PagingMode {
    PagingMode::Arm64(Arm64Regime::new(Arm64Granule::Kb4, ttbr, 48).unwrap())
}

#[test]
fn a_kernel_regime_composes_with_the_primitives_seance_already_had() {
    let space = VirtualLayer::new(
        physical(),
        // TTBR1_EL1 as a register value: ASID 7 in bits 63:48, CnP set.
        (7u64 << 48) | 0x1000 | 1,
        PagingSpec::new(mode(Ttbr::Ttbr1), PteSemantics::Linux),
    )
    .expect("a usable TTBR1");

    let mut field = [0u8; 8];
    read_exact_or_fail(
        space.as_data_source(),
        0xFFFF_0000_0040_1000,
        &mut field,
        "task_struct.pid",
    )
    .expect("the page is mapped and acquired");
    assert_eq!(u64::from_le_bytes(field), 0xDEAD_BEEF_0000_0001);

    // The next page is not mapped, and the reason survives to the caller.
    let err = read_exact_or_fail(
        space.as_data_source(),
        0xFFFF_0000_0040_2000,
        &mut field,
        "task_struct.pid",
    )
    .expect_err("an absent page must not parse");
    let hole = MemoryHole::from_io(&err).expect("a typed hole");
    assert_eq!(hole.reason, HoleReason::NotPresent);

    // The space is the top 2^48 bytes and nothing below them.
    assert_eq!(space.min_address(), 0xFFFF_0000_0000_0000);
    assert_eq!(space.max_address(), u64::MAX);
    assert_eq!(space.next_addressable(0), Some(0xFFFF_0000_0000_0000));
    assert_eq!(space.next_addressable(u64::MAX), Some(u64::MAX));

    // A user address is not this regime's, and is refused as no such
    // address rather than walked through the kernel's tables.
    let err = space.translate(0x5000).unwrap_err();
    assert!(
        matches!(err, TranslateError::NonCanonical { .. }),
        "{err:?}"
    );
    let err = space.mapping(0x5000, 8).unwrap_err();
    assert!(matches!(err, LayerError::OutOfRange { .. }), "{err:?}");

    // Layer metadata carries the whole claim the space rests on: which
    // register, which granule, how wide.
    let json = space.layer_meta().to_json();
    assert_eq!(json["notes"]["paging_mode"], "arm64_4k_ttbr1");
    assert_eq!(json["notes"]["arm64_granule"], "4k");
    assert_eq!(json["notes"]["arm64_ttbr"], "ttbr1");
    assert_eq!(json["notes"]["arm64_va_bits"], 48);
    assert_eq!(
        json["notes"]["min_virtual_address"],
        0xFFFF_0000_0000_0000u64
    );
    assert_eq!(json["notes"]["max_phys_addr_bits"], 48);
    assert_eq!(space.uniform_tables_suppressed(), 0);
}

#[test]
fn a_process_regime_over_the_same_image_is_its_own_layer_rooted_at_its_own_ttbr0() {
    let process = VirtualLayer::new(
        physical(),
        0x10000,
        PagingSpec::new(mode(Ttbr::Ttbr0), PteSemantics::Linux),
    )
    .expect("a usable TTBR0");

    let mut field = [0u8; 8];
    read_exact_or_fail(process.as_data_source(), 0x5000, &mut field, "a heap word")
        .expect("the process page is mapped");
    assert_eq!(u64::from_le_bytes(field), 0x0BAD_F00D_0000_0002);

    assert_eq!(process.min_address(), 0);
    assert_eq!(process.max_address(), (1u64 << 48) - 1);
    // Nothing above the top of a TTBR0 regime: the kernel's addresses are
    // another layer's.
    assert_eq!(process.next_addressable(1u64 << 48), None);
    let err = process.translate(0xFFFF_0000_0040_1000).unwrap_err();
    assert!(
        matches!(err, TranslateError::NonCanonical { .. }),
        "{err:?}"
    );

    // The kernel's page is not reachable through the process's tables even
    // at the corresponding lower-half address: the two hierarchies are
    // different tables, not one hierarchy seen from two ends.
    let err = process.translate(0x0000_0000_0040_1000).unwrap_err();
    assert!(matches!(err, TranslateError::NotPresent { .. }), "{err:?}");

    let json = process.layer_meta().to_json();
    assert_eq!(json["notes"]["paging_mode"], "arm64_4k_ttbr0");
    assert_eq!(json["notes"]["arm64_ttbr"], "ttbr0");
    assert_eq!(json["notes"]["min_virtual_address"], 0);
}

#[test]
fn a_mapping_across_a_kernel_page_is_one_run_at_the_physical_address_the_tables_name() {
    let space = VirtualLayer::new(
        physical(),
        0x1000,
        PagingSpec::new(mode(Ttbr::Ttbr1), PteSemantics::Bare),
    )
    .unwrap();
    let runs = space.mapping(0xFFFF_0000_0040_1FF0, 0x10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].offset, 0xFFFF_0000_0040_1FF0);
    assert_eq!(runs[0].mapped_offset, 0x8FF0);
    assert_eq!(runs[0].length, 0x10);
    // One byte further is the absent page, reported as a hole in virtual
    // space with the size of the region the level-3 entry governs.
    let err = space.mapping(0xFFFF_0000_0040_2000, 0x10).unwrap_err();
    let hole = err.hole().expect("an absent page is a hole");
    assert_eq!(hole.address, 0xFFFF_0000_0040_2000);
    assert_eq!(hole.length, 0x1000);
    assert_eq!(hole.reason, HoleReason::NotPresent);
}
