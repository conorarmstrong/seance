//! What a damaged, truncated or hostile hive must do: produce an error that
//! names the fault, and never a panic or a hang.
//!
//! A registry hive is attacker-influenced data recovered from unallocated
//! space as often as from a file, so every one of these is a case this reader
//! will meet.

use super::builder::{base_block, reseal, HiveBuilder, TestKey, TestValue};
use crate::{Hive, HiveError, Tolerances};

/// Where the base block says the root cell is.
fn root_cell_offset(image: &[u8]) -> u32 {
    u32::from_le_bytes([image[0x24], image[0x25], image[0x26], image[0x27]])
}

#[test]
fn a_buffer_that_is_not_a_hive_is_refused_by_name() {
    assert!(matches!(
        Hive::new(b"regf"),
        Err(HiveError::Truncated { .. })
    ));
    let mut near_miss = vec![0u8; 8192];
    near_miss[..4].copy_from_slice(b"reg&");
    assert!(matches!(
        Hive::new(&near_miss),
        Err(HiveError::BadSignature { .. })
    ));
    // A valid signature over an otherwise empty base block is still not a
    // hive, and must say so rather than be read.
    let mut empty = vec![0u8; 8192];
    empty[..4].copy_from_slice(b"regf");
    assert!(Hive::new(&empty).is_err());
}

#[test]
fn the_header_fields_this_reader_cannot_stand_over_are_refused() {
    let good = base_block(7, 7, 5, 0x1000);
    assert!(Hive::new(&[good.clone(), vec![0u8; 0x1000]].concat()).is_ok());

    for (offset, value, what) in [
        (0x14usize, 2u32, "major version"),
        (0x18, 9, "minor version"),
        (0x1C, 6, "file type: a transaction log is not a hive"),
        (0x20, 2, "file format"),
        (0x2C, 3, "clustering factor: not a sector size over 512"),
    ] {
        let mut buf = good.clone();
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        reseal(&mut buf);
        let image = [buf, vec![0u8; 0x1000]].concat();
        assert!(
            matches!(Hive::new(&image), Err(HiveError::Unsupported { .. })),
            "{what} must be refused"
        );
    }

    // The clustering factors that DO exist must all open: 1 is what Windows
    // writes, and 2, 4 and 8 are 1K, 2K and 4K sectors. Refusing one of these
    // would lose every key in a hive over a field this reader does not use.
    for factor in [1u32, 2, 4, 8] {
        let mut buf = good.clone();
        buf[0x2C..0x30].copy_from_slice(&factor.to_le_bytes());
        reseal(&mut buf);
        let image = [buf, vec![0u8; 0x1000]].concat();
        assert!(
            Hive::new(&image).is_ok(),
            "clustering factor {factor} is a real sector size and must open"
        );
    }

    // A checksum that does not verify is a corrupt base block.
    let mut bad_sum = good.clone();
    bad_sum[0x1FC..0x200].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let image = [bad_sum, vec![0u8; 0x1000]].concat();
    assert!(matches!(
        Hive::new(&image),
        Err(HiveError::ChecksumMismatch { .. })
    ));
}

/// The two tolerances, and the checks they must NOT relax.
#[test]
fn dirtiness_and_a_short_tail_are_tolerated_only_when_asked_for() {
    let dirty = [base_block(8, 7, 5, 0x1000), vec![0u8; 0x1000]].concat();
    let hive = Hive::without_validation(&dirty).unwrap();
    assert!(matches!(
        hive.validate(),
        Err(HiveError::SequenceNumberMismatch {
            primary: 8,
            secondary: 7
        })
    ));
    assert!(hive
        .validate_allowing(Tolerances {
            dirty: true,
            ..Default::default()
        })
        .is_ok());

    // Declares 0x2000 of bins, holds 0x1000.
    let short = [base_block(7, 7, 5, 0x2000), vec![0u8; 0x1000]].concat();
    let hive = Hive::without_validation(&short).unwrap();
    assert!(matches!(
        hive.validate(),
        Err(HiveError::InvalidSizeField { .. })
    ));
    assert!(hive
        .validate_allowing(Tolerances {
            short_data: true,
            ..Default::default()
        })
        .is_ok());
    assert_eq!(hive.declared_data_size(), 0x2000);
    assert_eq!(hive.present_data_size(), 0x1000);

    // Both at once — a shadow copy of a hive from a running machine — must
    // open under both tolerances. Handling only one of the two loses the hive.
    let both = [base_block(9, 7, 5, 0x2000), vec![0u8; 0x1000]].concat();
    let hive = Hive::without_validation(&both).unwrap();
    assert!(hive.validate_allowing(Tolerances::lenient()).is_ok());

    // A declared size that is not page-aligned is corruption, not shortness,
    // and no tolerance covers it.
    let mut misaligned = base_block(7, 7, 5, 0x1234);
    reseal(&mut misaligned);
    let image = [misaligned, vec![0u8; 0x2000]].concat();
    let hive = Hive::without_validation(&image).unwrap();
    assert!(hive.validate_allowing(Tolerances::lenient()).is_err());
}

/// Cell bounds. Each of these is a byte pattern that would let a careless
/// reader index outside the buffer.
#[test]
fn a_cell_that_does_not_fit_is_an_error_not_a_panic() {
    let image = HiveBuilder::new().build(&TestKey::new("ROOT").with_subkey(TestKey::new("Child")));

    // Root cell offset past the end of the data.
    let mut past_end = image.clone();
    past_end[0x24..0x28].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    reseal(&mut past_end);
    let hive = Hive::new(&past_end).unwrap();
    assert!(matches!(
        hive.root_key_node(),
        Err(HiveError::CellOutOfBounds { .. })
    ));

    // A cell whose size field claims more than the data holds. The root cell
    // is wherever the header says it is, which is not a fixed offset once the
    // builder has written the children first.
    let mut huge_cell = image.clone();
    let cell = 4096 + root_cell_offset(&image) as usize;
    huge_cell[cell..cell + 4].copy_from_slice(&(-0x7FFF_0000i32).to_le_bytes());
    reseal(&mut huge_cell);
    let hive = Hive::new(&huge_cell).unwrap();
    assert!(matches!(
        hive.root_key_node(),
        Err(HiveError::CellOutOfBounds { .. })
    ));

    // A cell marked free where an allocated one must be.
    let mut freed = image.clone();
    freed[cell..cell + 4].copy_from_slice(&0x20i32.to_le_bytes());
    reseal(&mut freed);
    let hive = Hive::new(&freed).unwrap();
    assert!(matches!(
        hive.root_key_node(),
        Err(HiveError::CellNotAllocated { .. })
    ));

    // A size field that is not a multiple of eight.
    let mut odd = image.clone();
    odd[cell..cell + 4].copy_from_slice(&(-13i32).to_le_bytes());
    reseal(&mut odd);
    let hive = Hive::new(&odd).unwrap();
    assert!(matches!(
        hive.root_key_node(),
        Err(HiveError::InvalidSizeField { .. })
    ));
}

/// A key node whose name length runs past its own cell. The length field is
/// attacker-controlled and the name is the last field, so this is the classic
/// over-read.
#[test]
fn a_name_longer_than_its_cell_is_refused() {
    let image = HiveBuilder::new().build(&TestKey::new("ROOT"));
    let mut overlong = image.clone();
    let name_len = 4096 + root_cell_offset(&image) as usize + 4 + 0x48;
    overlong[name_len..name_len + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
    reseal(&mut overlong);
    let hive = Hive::new(&overlong).unwrap();
    let root = hive.root_key_node().expect("the node itself still parses");
    assert!(root.name().is_err(), "the name must not read past the cell");
}

/// A subkey list that points back at the key it belongs to. Following it
/// without a depth bound is an infinite walk — a tool that hangs on a crafted
/// hive is a denial of service in an ingest pipeline.
#[test]
fn a_cycle_in_the_subkey_index_terminates() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Child"));
    let image = HiveBuilder::new()
        .index_form(super::builder::IndexForm::IndexRoot)
        .build(&root);

    // Point the root's `ri` at itself: every entry now resolves to the index
    // root, which is not a leaf, so the walk must bottom out rather than spin.
    let mut cyclic = image.clone();
    let subkeys_offset_field = 4096 + root_cell_offset(&image) as usize + 4 + 0x1C;
    let ri_offset = u32::from_le_bytes([
        cyclic[subkeys_offset_field],
        cyclic[subkeys_offset_field + 1],
        cyclic[subkeys_offset_field + 2],
        cyclic[subkeys_offset_field + 3],
    ]);
    let ri_entries = 4096 + ri_offset as usize + 4 + 4;
    cyclic[ri_entries..ri_entries + 4].copy_from_slice(&ri_offset.to_le_bytes());
    reseal(&mut cyclic);

    let hive = Hive::new(&cyclic).unwrap();
    let root = hive.root_key_node().unwrap();
    // Whatever it decides, it has to decide it — in bounded time.
    if let Some(Ok(subkeys)) = root.subkeys() {
        let count = subkeys.take(10_000).count();
        assert!(count < 10_000, "a cyclic index must not iterate forever");
    }
}

/// An index root names three sublists and one of them will not read. The
/// other two keys must still enumerate — one damaged list must not cost the
/// hive — and the enumeration must say that it is short, because a key that
/// reports two subkeys when it declared three is a false absence unless the
/// reader carries the shortfall (HIVE-002).
#[test]
fn a_damaged_ri_sublist_is_reported_not_swallowed() {
    let root = TestKey::new("ROOT")
        .with_subkey(TestKey::new("Alpha"))
        .with_subkey(TestKey::new("Beta"))
        .with_subkey(TestKey::new("Gamma"));
    let image = HiveBuilder::new()
        .index_form(super::builder::IndexForm::IndexRoot)
        .build(&root);

    // Point the second `ri` entry past the end of the hive.
    let mut damaged = image.clone();
    let subkeys_offset_field = 4096 + root_cell_offset(&image) as usize + 4 + 0x1C;
    let ri_offset = u32::from_le_bytes([
        damaged[subkeys_offset_field],
        damaged[subkeys_offset_field + 1],
        damaged[subkeys_offset_field + 2],
        damaged[subkeys_offset_field + 3],
    ]);
    let second_entry = 4096 + ri_offset as usize + 4 + 4 + 4;
    let bad_offset = 0x7FFF_FFF0u32;
    damaged[second_entry..second_entry + 4].copy_from_slice(&bad_offset.to_le_bytes());
    reseal(&mut damaged);

    let hive = Hive::new(&damaged).unwrap();
    let root = hive.root_key_node().unwrap();
    let subkeys = root
        .subkeys()
        .expect("root declares subkeys")
        .expect("index root reads");
    assert!(subkeys.is_incomplete());
    let unresolved = subkeys.unresolved_sublists();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].offset, bad_offset);

    let names: Vec<String> = subkeys
        .map(|k| k.unwrap().name().unwrap().to_string_lossy())
        .collect();
    assert_eq!(names, ["Alpha", "Gamma"]);

    // And the undamaged image is whole, so "nothing lost" is a positive
    // statement rather than a default.
    let hive = Hive::new(&image).unwrap();
    let subkeys = hive.root_key_node().unwrap().subkeys().unwrap().unwrap();
    assert!(!subkeys.is_incomplete());
    assert_eq!(subkeys.count(), 3);
}

/// A value whose data cell lies outside the hive, and one whose declared size
/// exceeds what its cell holds. Both must be errors rather than reads of
/// whatever is next in memory.
#[test]
fn value_data_is_bounded_by_its_cell() {
    let root = TestKey::new("ROOT").with_value(TestValue::new("V", 3, vec![9u8; 64]));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let value_offset = hive
        .root_key_node()
        .unwrap()
        .values()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .cell_offset();

    // Data offset past the end.
    let mut bad = image.clone();
    let field = 4096 + value_offset as usize + 4 + 8;
    bad[field..field + 4].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    reseal(&mut bad);
    let hive = Hive::new(&bad).unwrap();
    let value = hive
        .root_key_node()
        .unwrap()
        .values()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(value.data().is_err());

    // Declared data size larger than the cell that holds it.
    let mut oversize = image.clone();
    let size_field = 4096 + value_offset as usize + 4 + 4;
    oversize[size_field..size_field + 4].copy_from_slice(&0x0000_FFFFu32.to_le_bytes());
    reseal(&mut oversize);
    let hive = Hive::new(&oversize).unwrap();
    let value = hive
        .root_key_node()
        .unwrap()
        .values()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(value.data().is_err(), "a value may not read past its cell");
}

/// Random bytes behind a valid base block. Nothing here may panic: the fuzz
/// target and the carver both feed this reader exactly such buffers.
#[test]
fn arbitrary_bytes_behind_a_valid_header_never_panic() {
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..64 {
        let mut image = base_block(7, 7, 5, 0x1000);
        let body: Vec<u8> = (0..0x1000).map(|_| (next() & 0xFF) as u8).collect();
        image.extend_from_slice(&body);
        let hive = match Hive::new(&image) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if let Ok(root) = hive.root_key_node() {
            let _ = root.name().map(|n| n.to_string_lossy());
            if let Some(Ok(subkeys)) = root.subkeys() {
                for key in subkeys.take(256).flatten() {
                    let _ = key.name().map(|n| n.to_string_lossy());
                }
            }
            if let Some(Ok(values)) = root.values() {
                for value in values.take(256).flatten() {
                    let _ = value.name().map(|n| n.to_string_lossy());
                    let _ = value.data().and_then(|d| d.into_vec());
                }
            }
        }
    }
}
