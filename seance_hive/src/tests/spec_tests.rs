//! The specification, asserted.
//!
//! Every offset and size below is quoted from Maxim Suhanov's *Windows
//! registry file format specification* (CC BY 4.0), and read out of a buffer
//! this test builds at exactly those offsets. A parser that drifts from the
//! document fails here rather than in an examiner's report, and a reader of
//! this file can check the numbers against the document without decoding any
//! arithmetic.
//!
//! `docs/SPEC_CROSSCHECK.md` carries the same table in prose, field by field,
//! with what this implementation does about each.

use super::builder::{base_block, reseal};
use crate::{Hive, KeyValueDataType};

/// Base block, table 1 of the specification. Offsets in decimal as the
/// document gives them.
#[test]
fn the_base_block_fields_are_where_the_specification_puts_them() {
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(b"regf"); //    0, 4: signature
    buf[4..8].copy_from_slice(&11u32.to_le_bytes()); //    4, 4: primary sequence
    buf[8..12].copy_from_slice(&11u32.to_le_bytes()); //   8, 4: secondary sequence
    buf[12..20].copy_from_slice(&0x01D9_1234_5678_9ABCu64.to_le_bytes()); // 12, 8: last written
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); //  20, 4: major version
    buf[24..28].copy_from_slice(&6u32.to_le_bytes()); //  24, 4: minor version
    buf[28..32].copy_from_slice(&0u32.to_le_bytes()); //  28, 4: file type, 0 = primary
    buf[32..36].copy_from_slice(&1u32.to_le_bytes()); //  32, 4: file format, 1 = direct
    buf[36..40].copy_from_slice(&0x20u32.to_le_bytes()); // 36, 4: root cell offset
    buf[40..44].copy_from_slice(&0x1000u32.to_le_bytes()); // 40, 4: hive bins data size
    buf[44..48].copy_from_slice(&1u32.to_le_bytes()); //  44, 4: clustering factor
    reseal(&mut buf); //                                 508, 4: checksum

    let image = [buf, vec![0u8; 0x1000]].concat();
    let hive = Hive::without_validation(&image).unwrap();

    assert_eq!(hive.sequence_numbers(), (11, 11));
    assert_eq!(hive.last_written_filetime(), 0x01D9_1234_5678_9ABC);
    assert_eq!(hive.major_version(), 1);
    assert_eq!(hive.minor_version(), 6);
    assert_eq!(hive.file_type(), 0);
    assert_eq!(hive.file_format(), 1);
    assert_eq!(hive.root_cell_offset(), 0x20);
    assert_eq!(hive.declared_data_size(), 0x1000);
    assert_eq!(hive.clustering_factor(), 1);
    assert_eq!(hive.stored_checksum(), hive.computed_checksum());
    assert!(hive.validate().is_ok());
}

/// The checksum rule, including the two values the specification maps away:
/// "if result equals -1, set to -2; if 0, set to 1".
#[test]
fn the_checksum_maps_away_its_two_ambiguous_values() {
    // All zeros XOR to 0, which the rule turns into 1.
    let mut zeros = vec![0u8; 4096];
    zeros[0..4].copy_from_slice(b"regf");
    // "regf" itself contributes, so neutralise it for the arithmetic.
    let sig = u32::from_le_bytes(*b"regf");
    zeros[4..8].copy_from_slice(&sig.to_le_bytes());
    let image = [zeros, vec![0u8; 0x1000]].concat();
    let hive = Hive::without_validation(&image).unwrap();
    assert_eq!(
        hive.computed_checksum(),
        1,
        "a base block that XORs to zero checksums as 1, never 0"
    );

    // And a block that XORs to all-ones checksums as 0xFFFFFFFE.
    let mut ones = vec![0u8; 4096];
    ones[0..4].copy_from_slice(b"regf");
    ones[4..8].copy_from_slice(&(!sig).to_le_bytes());
    let image = [ones, vec![0u8; 0x1000]].concat();
    let hive = Hive::without_validation(&image).unwrap();
    assert_eq!(hive.computed_checksum(), 0xFFFF_FFFE);
}

/// Key node, table 5. Offsets in decimal as the document gives them; the name
/// begins at 76, which is also the structure's fixed size.
#[test]
fn the_key_node_fields_are_where_the_specification_puts_them() {
    let name = b"WindowsNT";
    let mut cell = vec![0u8; 4 + 76 + name.len()];
    let size = (cell.len().div_ceil(8) * 8) as i32;
    cell.resize(size as usize, 0);
    cell[0..4].copy_from_slice(&(-size).to_le_bytes());
    let nk = &mut cell[4..];
    nk[0..2].copy_from_slice(b"nk"); //     0, 2: signature
    nk[2..4].copy_from_slice(&0x0024u16.to_le_bytes()); // 2, 2: flags (COMP_NAME|HIVE_ENTRY)
    nk[4..12].copy_from_slice(&0x01D8_0000_0000_0001u64.to_le_bytes()); // 4, 8: last written
    nk[16..20].copy_from_slice(&u32::MAX.to_le_bytes()); // 16, 4: parent
    nk[20..24].copy_from_slice(&3u32.to_le_bytes()); //    20, 4: number of subkeys
    nk[28..32].copy_from_slice(&u32::MAX.to_le_bytes()); // 28, 4: subkeys list offset
    nk[36..40].copy_from_slice(&7u32.to_le_bytes()); //    36, 4: number of key values
    nk[40..44].copy_from_slice(&u32::MAX.to_le_bytes()); // 40, 4: key values list offset
    nk[48..52].copy_from_slice(&u32::MAX.to_le_bytes()); // 48, 4: class name offset
    nk[72..74].copy_from_slice(&(name.len() as u16).to_le_bytes()); // 72, 2: key name length
    nk[76..76 + name.len()].copy_from_slice(name); //      76, n: key name

    let mut base = base_block(7, 7, 6, 0x1000);
    base[36..40].copy_from_slice(&0u32.to_le_bytes());
    reseal(&mut base);
    let mut body = cell;
    body.resize(0x1000, 0);
    let image = [base, body].concat();

    let hive = Hive::new(&image).unwrap();
    let root = hive.root_key_node().unwrap();
    assert_eq!(root.flags(), 0x0024);
    assert_eq!(root.last_written_filetime(), 0x01D8_0000_0000_0001);
    assert_eq!(root.parent_offset(), None, "0xFFFFFFFF means no parent");
    assert_eq!(root.subkey_count(), 3);
    assert_eq!(root.value_count(), 7);
    assert_eq!(root.name().unwrap().to_string_lossy(), "WindowsNT");
    assert!(
        root.class_name().is_none(),
        "0xFFFFFFFF means no class name"
    );
    // The counts say three and seven; the offsets say there is no list. The
    // reader believes the offsets, because a count with nothing behind it is
    // the shape a damaged hive has.
    assert!(root.subkeys().is_none());
    assert!(root.values().is_none());
}

/// Key value, table 8: name length at 2, data size at 4, data offset at 8,
/// data type at 12, flags at 16, name at 20.
#[test]
fn the_key_value_fields_are_where_the_specification_puts_them() {
    use super::builder::{HiveBuilder, TestKey, TestValue};
    let root = TestKey::new("ROOT").with_value(TestValue::new(
        "ProductName",
        1,
        b"W\0i\0n\0\0\0".to_vec(),
    ));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let value = hive
        .root_key_node()
        .unwrap()
        .values()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(value.name().unwrap().to_string_lossy(), "ProductName");
    assert_eq!(value.data_size(), 8);
    assert_eq!(value.data_type().unwrap(), KeyValueDataType::RegSZ);
    assert_eq!(value.data().unwrap().into_vec().unwrap(), b"W\0i\0n\0\0\0");
}

/// The inline rule, quoted: "When the most significant bit is 1, data (4 bytes
/// or less) is stored in the Data offset field directly." A size field with
/// that bit set and a length above four is therefore corrupt, and must not be
/// read as either shape.
#[test]
fn an_inline_value_longer_than_four_bytes_is_corrupt() {
    use super::builder::{HiveBuilder, TestKey, TestValue};
    let root = TestKey::new("ROOT").with_value(TestValue::new("V", 3, vec![1, 2, 3, 4]));
    let image = HiveBuilder::new().build(&root);
    let offset = {
        let hive = Hive::new(&image).unwrap();
        hive.root_key_node()
            .unwrap()
            .values()
            .unwrap()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .cell_offset()
    };
    let mut bad = image.clone();
    let size_field = 4096 + offset as usize + 4 + 4;
    bad[size_field..size_field + 4].copy_from_slice(&(0x8000_0000u32 | 9).to_le_bytes());
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
}

/// Cell size semantics, quoted: "the size is positive if a cell is unallocated
/// or negative if a cell is allocated", aligned to 8 bytes.
#[test]
fn a_cells_sign_says_whether_it_is_allocated() {
    use super::builder::{HiveBuilder, TestKey};
    let image = HiveBuilder::new().build(&TestKey::new("ROOT"));
    let hive = Hive::new(&image).unwrap();
    assert!(hive.root_key_node().is_ok(), "a negative size is allocated");

    let root_offset = hive.root_cell_offset() as usize;
    let mut freed = image.clone();
    let at = 4096 + root_offset;
    let size = i32::from_le_bytes([freed[at], freed[at + 1], freed[at + 2], freed[at + 3]]);
    freed[at..at + 4].copy_from_slice(&(-size).to_le_bytes());
    reseal(&mut freed);
    let hive = Hive::new(&freed).unwrap();
    assert!(
        hive.root_key_node().is_err(),
        "a positive size is unallocated and must not be read as live data"
    );
}
