//! Reading a well-formed hive: the keys, the values, the data, the names.

use super::builder::{HiveBuilder, IndexForm, TestKey, TestValue};
use crate::{Hive, KeyValueDataType};

/// The subkey names of the named key, found anywhere below the root.
fn names_of(hive: &Hive<'_>, of_key: &str) -> Vec<String> {
    let root = hive.root_key_node().expect("root");
    let key = if of_key.is_empty() {
        root
    } else {
        find(&root, of_key).expect("named key")
    };
    key.subkeys()
        .expect("subkeys present")
        .expect("subkeys parse")
        .map(|k| k.unwrap().name().unwrap().to_string_lossy())
        .collect()
}

fn find<'a>(from: &crate::KeyNode<'a>, name: &str) -> Option<crate::KeyNode<'a>> {
    let subkeys = from.subkeys()?.ok()?;
    let children: Vec<_> = subkeys.flatten().collect();
    for child in &children {
        if child.name().unwrap().to_string_lossy() == name {
            return Some(*child);
        }
    }
    children.iter().find_map(|child| find(child, name))
}

#[test]
fn the_root_key_is_found_and_named() {
    let image = HiveBuilder::new().build(&TestKey::new("ROOT").with_time(0x01D9_0000_0000_0000));
    let hive = Hive::new(&image).expect("a hive this crate wrote is one it can read");
    let root = hive.root_key_node().expect("root key node");
    assert_eq!(root.name().unwrap().to_string_lossy(), "ROOT");
    assert_eq!(root.last_written_filetime(), 0x01D9_0000_0000_0000);
    assert_eq!(root.subkey_count(), 0);
    assert_eq!(root.value_count(), 0);
    assert!(root.subkeys().is_none(), "no subkeys is None, not an error");
    assert!(root.values().is_none(), "no values is None, not an error");
}

/// Every subkey-index form a hive can use. A reader that handles only the
/// common one loses keys on hives it claims to support, and loses them
/// silently — the key is simply not there.
#[test]
fn subkeys_are_found_through_every_index_form() {
    for form in [
        IndexForm::FastLeaf,
        IndexForm::HashLeaf,
        IndexForm::IndexLeaf,
        IndexForm::IndexRoot,
    ] {
        let root = TestKey::new("ROOT")
            .with_subkey(TestKey::new("Alpha"))
            .with_subkey(TestKey::new("Beta"))
            .with_subkey(TestKey::new("Gamma"));
        let image = HiveBuilder::new().index_form(form).build(&root);
        let hive = Hive::new(&image).unwrap();
        assert_eq!(
            names_of(&hive, ""),
            vec!["Alpha", "Beta", "Gamma"],
            "an index form this reader does not walk loses keys silently"
        );
    }
}

#[test]
fn subkeys_nest() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Software").with_subkey(
        TestKey::new("Microsoft").with_subkey(TestKey::new("Windows").with_value(TestValue::new(
            "CurrentVersion",
            1,
            utf16("10.0"),
        ))),
    ));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    assert_eq!(names_of(&hive, ""), vec!["Software"]);
    assert_eq!(names_of(&hive, "Software"), vec!["Microsoft"]);
    assert_eq!(names_of(&hive, "Microsoft"), vec!["Windows"]);
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(core::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[test]
fn values_carry_their_name_type_and_bytes() {
    let root = TestKey::new("ROOT")
        .with_value(TestValue::new("StringValue", 1, utf16("hello")))
        .with_value(TestValue::new(
            "DwordValue",
            4,
            0x1234_5678u32.to_le_bytes().to_vec(),
        ))
        .with_value(TestValue::new(
            "QwordValue",
            11,
            0x1122_3344_5566_7788u64.to_le_bytes().to_vec(),
        ))
        .with_value(TestValue::new(
            "BinaryValue",
            3,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11],
        ));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let root = hive.root_key_node().unwrap();
    assert_eq!(root.value_count(), 4);

    let values: Vec<_> = root
        .values()
        .expect("values present")
        .expect("values parse")
        .map(|v| v.unwrap())
        .collect();

    assert_eq!(values[0].name().unwrap().to_string_lossy(), "StringValue");
    assert_eq!(values[0].data_type().unwrap(), KeyValueDataType::RegSZ);
    assert_eq!(
        values[0].data().unwrap().into_vec().unwrap(),
        utf16("hello")
    );

    assert_eq!(values[1].data_type().unwrap(), KeyValueDataType::RegDWord);
    assert_eq!(
        values[1].data().unwrap().into_vec().unwrap(),
        0x1234_5678u32.to_le_bytes()
    );

    assert_eq!(values[2].data_type().unwrap(), KeyValueDataType::RegQWord);
    assert_eq!(values[3].data_type().unwrap(), KeyValueDataType::RegBinary);
    assert_eq!(
        values[3].data().unwrap().into_vec().unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]
    );
}

/// Four bytes or fewer live in the offset field itself. A reader that follows
/// the field as an offset instead reads whatever cell happens to be there —
/// the wrong bytes, with no error to say so, which is the worst kind of wrong
/// for a tool that gets quoted.
#[test]
fn small_values_are_stored_in_the_offset_field_itself() {
    let root = TestKey::new("ROOT")
        .with_value(TestValue::new("Inline4", 4, vec![0x01, 0x02, 0x03, 0x04]))
        .with_value(TestValue::new("Inline1", 3, vec![0xFF]))
        .with_value(TestValue::new("Empty", 0, vec![]));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let root = hive.root_key_node().unwrap();
    let values: Vec<_> = root
        .values()
        .unwrap()
        .unwrap()
        .map(|v| v.unwrap())
        .collect();
    assert_eq!(
        values[0].data().unwrap().into_vec().unwrap(),
        vec![0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(values[1].data().unwrap().into_vec().unwrap(), vec![0xFF]);
    assert!(values[2].data().unwrap().into_vec().unwrap().is_empty());
}

/// Windows 10 Anniversary Update (RS1) onward soft-deletes a value by
/// flagging its `vk` cell rather than removing it. That flag must survive the
/// read as a distinct label: a tombstoned value is deleted-value evidence,
/// and folding it into the ordinary listing with no marker would misstate the
/// registry's current state — the same forensic-honesty failure as reporting
/// a carved fragment as a whole file.
#[test]
fn tombstoned_values_are_labelled_and_excluded_from_the_live_listing() {
    let root = TestKey::new("ROOT")
        .with_value(TestValue::new("LiveValue", 1, utf16("still here")))
        .with_value(TestValue::new("DeletedValue", 1, utf16("soft-deleted")).tombstoned());
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let root = hive.root_key_node().unwrap();
    assert_eq!(root.value_count(), 2, "the vk list still has both cells");

    let values: Vec<_> = root
        .values()
        .expect("values present")
        .expect("values parse")
        .map(|v| v.unwrap())
        .collect();
    assert_eq!(values.len(), 2, "the walk surfaces both cells");

    let live: Vec<_> = values
        .iter()
        .find(|v| !v.is_tombstoned())
        .into_iter()
        .collect();
    let tombstoned: Vec<_> = values.iter().filter(|v| v.is_tombstoned()).collect();

    assert_eq!(live.len(), 1, "exactly one value is live");
    assert_eq!(live[0].name().unwrap().to_string_lossy(), "LiveValue");

    assert_eq!(tombstoned.len(), 1, "exactly one value is tombstoned");
    assert_eq!(
        tombstoned[0].name().unwrap().to_string_lossy(),
        "DeletedValue"
    );

    // A "current data" listing built by filtering on the label must not
    // contain the tombstoned value under any name.
    assert!(
        !live
            .iter()
            .any(|v| v.name().unwrap().to_string_lossy() == "DeletedValue"),
        "a tombstoned value must never appear in the live listing unlabelled"
    );
}

/// A value larger than one cell is split across segments listed by a `db`
/// record. This is how a ShimCache or an AmCache blob is stored — the exact
/// values this product reads — so getting it wrong loses the artifact.
#[test]
fn a_value_too_large_for_one_cell_is_reassembled_in_order() {
    let builder = HiveBuilder::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    // Written by hand rather than through TestKey: the big-data form needs its
    // own cells, and the test is about exactly that shape.
    let image = builder.build_with_big_value("BigBlob", &payload, 16_344);
    let hive = Hive::new(&image).unwrap();
    let root = hive.root_key_node().unwrap();
    let value = root
        .values()
        .unwrap()
        .unwrap()
        .map(|v| v.unwrap())
        .find(|v| v.name().unwrap().to_string_lossy() == "BigBlob")
        .expect("the big value");
    let read = value.data().unwrap().into_vec().unwrap();
    assert_eq!(read.len(), payload.len(), "every segment must be read");
    assert_eq!(read, payload, "segments must be joined in list order");
}

/// Names come in two encodings and the flag says which. Reading a compressed
/// name as UTF-16 produces Chinese characters where a path should be.
#[test]
fn names_honour_the_compressed_name_flag() {
    let root = TestKey::new("ROOT")
        .utf16_name()
        .with_subkey(TestKey::new("Compressed"))
        .with_subkey(TestKey::new("Wide").utf16_name());
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let root = hive.root_key_node().unwrap();
    assert_eq!(root.name().unwrap().to_string_lossy(), "ROOT");
    assert_eq!(names_of(&hive, ""), vec!["Compressed", "Wide"]);

    let mut value_root = TestKey::new("ROOT");
    value_root.values.push(TestValue {
        name: "WideName",
        data_type: 1,
        data: utf16("x"),
        compressed_name: false,
        tombstoned: false,
    });
    let image = HiveBuilder::new().build(&value_root);
    let hive = Hive::new(&image).unwrap();
    let name = hive
        .root_key_node()
        .unwrap()
        .values()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .name()
        .unwrap()
        .to_string_lossy();
    assert_eq!(name, "WideName");
}

#[test]
fn every_registry_data_type_is_named() {
    for (code, want) in [
        (0u32, KeyValueDataType::RegNone),
        (1, KeyValueDataType::RegSZ),
        (2, KeyValueDataType::RegExpandSZ),
        (3, KeyValueDataType::RegBinary),
        (4, KeyValueDataType::RegDWord),
        (5, KeyValueDataType::RegDWordBigEndian),
        (6, KeyValueDataType::RegLink),
        (7, KeyValueDataType::RegMultiSZ),
        (8, KeyValueDataType::RegResourceList),
        (9, KeyValueDataType::RegFullResourceDescriptor),
        (10, KeyValueDataType::RegResourceRequirementsList),
        (11, KeyValueDataType::RegQWord),
    ] {
        let root = TestKey::new("ROOT").with_value(TestValue::new("V", code, vec![1, 2, 3, 4]));
        let image = HiveBuilder::new().build(&root);
        let hive = Hive::new(&image).unwrap();
        let got = hive
            .root_key_node()
            .unwrap()
            .values()
            .unwrap()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .data_type()
            .unwrap();
        assert_eq!(got, want, "data type {code}");
    }

    // An unknown type is reported as itself rather than guessed at.
    let root = TestKey::new("ROOT").with_value(TestValue::new("V", 4242, vec![1]));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let got = hive
        .root_key_node()
        .unwrap()
        .values()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .data_type()
        .unwrap();
    assert_eq!(got, KeyValueDataType::Unknown(4242));
}

/// The registry plugin formats a value's type with `Debug` and matches on the
/// text. That makes these names an interface, not an implementation detail.
#[test]
fn the_debug_names_of_the_data_types_are_the_ones_callers_match_on() {
    assert_eq!(format!("{:?}", KeyValueDataType::RegSZ), "RegSZ");
    assert_eq!(
        format!("{:?}", KeyValueDataType::RegExpandSZ),
        "RegExpandSZ"
    );
    assert_eq!(format!("{:?}", KeyValueDataType::RegDWord), "RegDWord");
    assert_eq!(format!("{:?}", KeyValueDataType::RegQWord), "RegQWord");
    assert_eq!(format!("{:?}", KeyValueDataType::RegMultiSZ), "RegMultiSZ");
    assert_eq!(format!("{:?}", KeyValueDataType::RegBinary), "RegBinary");
}

/// A hive can disagree with itself: a key's own subkey count and the number of
/// offsets its index names are separate fields, and a damaged index or a delete
/// that did not decrement the count leaves them different.
///
/// Neither is corrected here. `subkey_count` is what the key claims,
/// `listed_len` is what can actually be walked, and a reader that reconciled
/// them would present a key's contents as settled while the hive itself
/// disagreed about them (§2.2 detection 8).
#[test]
fn a_keys_declared_subkey_count_and_its_index_are_reported_separately() {
    let root = TestKey::new("ROOT").with_subkey(
        TestKey::new("Vendor")
            .declaring_subkeys(9)
            .with_subkey(TestKey::new("Alpha"))
            .with_subkey(TestKey::new("Beta")),
    );
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();

    let vendor = hive
        .root_key_node()
        .unwrap()
        .subkeys()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(vendor.subkey_count(), 9, "what the key claims");

    let subkeys = vendor.subkeys().unwrap().unwrap();
    assert_eq!(subkeys.listed_len(), 2, "what the index names");
    // Nothing failed to read: the index is intact and short, which is a
    // different fact from part of it being unreadable.
    assert!(!subkeys.is_incomplete());
    assert!(subkeys.unresolved_sublists().is_empty());
    assert_eq!(names_of(&hive, "Vendor"), vec!["Alpha", "Beta"]);
}

/// `listed_len` answers the same number before, during and after the walk, so
/// a caller can read it either side of enumerating.
#[test]
fn the_listed_subkey_count_does_not_change_as_the_walk_consumes_it() {
    let root = TestKey::new("ROOT")
        .with_subkey(TestKey::new("Alpha"))
        .with_subkey(TestKey::new("Beta"))
        .with_subkey(TestKey::new("Gamma"));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let mut subkeys = hive.root_key_node().unwrap().subkeys().unwrap().unwrap();
    assert_eq!(subkeys.listed_len(), 3);
    subkeys.next().unwrap().unwrap();
    assert_eq!(subkeys.listed_len(), 3);
    while subkeys.next().is_some() {}
    assert_eq!(subkeys.listed_len(), 3);
}

/// A key declaring no subkeys has no index at all, so there is nothing to
/// have counted — `subkeys()` is `None` rather than an empty enumeration.
#[test]
fn a_key_declaring_no_subkeys_has_no_index_to_count() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Leaf"));
    let image = HiveBuilder::new().build(&root);
    let hive = Hive::new(&image).unwrap();
    let leaf = hive
        .root_key_node()
        .unwrap()
        .subkeys()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(leaf.subkey_count(), 0);
    assert!(leaf.subkeys().is_none());
}

/// `fuzz/fuzz_targets/hive_parser.rs` opens raw bytes with `Hive::new` and
/// recursively walks every key and value it reaches — no artifact-type or
/// name filter sits in front of it the way the plugin-based targets have, but
/// the walk itself could still stop short of subkeys or values if a future
/// change made either `Option` collapse early. Pinning that a nested subkey
/// and both a live and a tombstoned value are all reached on a well-formed
/// hive is what keeps that walk counted as real coverage rather than the
/// `usnjrnl_parser.rs` failure mode, where a fuzz target's input shape
/// decoded to nothing and nobody noticed.
#[test]
fn the_fuzz_targets_walk_reaches_subkeys_and_both_live_and_tombstoned_values() {
    let root = TestKey::new("ROOT").with_subkey(
        TestKey::new("Software")
            .with_value(TestValue::new("Live", 1, utf16("here")))
            .with_value(TestValue::new("Gone", 1, utf16("was here")).tombstoned()),
    );
    let image = HiveBuilder::new().build(&root);

    let hive = Hive::new(&image).expect("a well-formed hive opens");
    let root = hive.root_key_node().expect("root key node reads");

    let subkeys: Vec<_> = root
        .subkeys()
        .expect("root has a subkey")
        .expect("subkey index reads")
        .map(|k| k.unwrap())
        .collect();
    assert_eq!(subkeys.len(), 1, "the walk must reach the subkey");
    assert_eq!(subkeys[0].name().unwrap().to_string_lossy(), "Software");

    let values: Vec<_> = subkeys[0]
        .values()
        .expect("the subkey has values")
        .expect("value list reads")
        .map(|v| v.unwrap())
        .collect();
    assert_eq!(values.len(), 2, "the walk must reach both value cells");
    assert!(
        values
            .iter()
            .any(|v| !v.is_tombstoned() && v.name().unwrap().to_string_lossy() == "Live"),
        "the walk must reach the live value, labelled as live"
    );
    assert!(
        values
            .iter()
            .any(|v| v.is_tombstoned() && v.name().unwrap().to_string_lossy() == "Gone"),
        "the walk must reach the tombstoned value, labelled distinctly"
    );
}

/// The leaf forms (`lf`, `lh`, `li`) are read in place and the index root
/// (`ri`) is resolved up front (ROADMAP §5.9). The two paths must agree: the
/// same children in the same order, and `listed_len` the same number before,
/// part-way through and after the walk, whichever form the index takes.
#[test]
fn leaf_and_root_enumerations_agree_offset_for_offset() {
    let names = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"];
    let mut per_form = Vec::new();
    for (i, form) in [
        IndexForm::FastLeaf,
        IndexForm::HashLeaf,
        IndexForm::IndexLeaf,
        IndexForm::IndexRoot,
    ]
    .into_iter()
    .enumerate()
    {
        let mut root = TestKey::new("ROOT");
        for name in names {
            root = root.with_subkey(TestKey::new(name));
        }
        let image = HiveBuilder::new().index_form(form).build(&root);
        let hive = Hive::new(&image).unwrap();
        let key = hive.root_key_node().unwrap();

        let full: Vec<u32> = key
            .subkeys()
            .unwrap()
            .unwrap()
            .map(|k| k.unwrap().cell_offset())
            .collect();

        let mut walk = key.subkeys().unwrap().unwrap();
        assert_eq!(walk.listed_len(), names.len(), "form #{i} before the walk");
        let first_two: Vec<u32> = walk
            .by_ref()
            .take(2)
            .map(|k| k.unwrap().cell_offset())
            .collect();
        assert_eq!(walk.listed_len(), names.len(), "form #{i} part-way");
        let rest: Vec<u32> = walk.by_ref().map(|k| k.unwrap().cell_offset()).collect();
        assert_eq!(walk.listed_len(), names.len(), "form #{i} after the walk");
        assert!(!walk.is_incomplete(), "form #{i} intact index is complete");
        assert_eq!([first_two, rest].concat(), full, "form #{i} resumed walk");

        let in_order: Vec<String> = full
            .iter()
            .map(|&o| {
                crate::KeyNode::from_cell_offset(hive, o)
                    .unwrap()
                    .name()
                    .unwrap()
                    .to_string_lossy()
            })
            .collect();
        per_form.push(in_order);
    }
    for (i, got) in per_form.iter().enumerate() {
        assert_eq!(got, &names.to_vec(), "form #{i} order");
    }
}
