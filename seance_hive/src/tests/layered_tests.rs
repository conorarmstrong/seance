//! Layered keys (minor version 6), on hives this crate's builder wrote from
//! the specification. These pin the mechanism; the real differencing hives
//! are graded in `layered_corpus_tests`.

use super::builder::{HiveBuilder, TestKey};
use crate::{Hive, LayerSemantics, LayeredKeyBits};

fn bits_of_only_subkey(image: &[u8]) -> Option<LayeredKeyBits> {
    let hive = Hive::new(image).expect("builder hive reads");
    let root = hive.root_key_node().unwrap();
    let child = root.subkeys().unwrap().unwrap().next().unwrap().unwrap();
    child.layered_key_bits()
}

#[test]
fn every_layer_semantics_value_and_the_inherit_class_bit_decode_in_a_minor_6_hive() {
    let cases = [
        (0x00, LayerSemantics::None, false),
        (0x01, LayerSemantics::Tombstone, false),
        (0x02, LayerSemantics::SupersedeLocal, false),
        (0x03, LayerSemantics::SupersedeTree, false),
        (0x80, LayerSemantics::None, true),
        (0x83, LayerSemantics::SupersedeTree, true),
    ];
    for (raw, semantics, inherit_class) in cases {
        let image = HiveBuilder::new()
            .minor_version(6)
            .build(&TestKey::new("ROOT").with_subkey(TestKey::new("K").with_layer_bits(raw)));
        assert_eq!(
            bits_of_only_subkey(&image),
            Some(LayeredKeyBits {
                semantics,
                inherit_class,
                raw
            }),
            "raw byte {raw:#04x}"
        );
    }
}

#[test]
fn a_hive_below_minor_6_has_no_layered_key_bits_whatever_the_byte_holds() {
    // Byte 0x0D is spare before minor 6; a stray value there is not a layer.
    let image = HiveBuilder::new()
        .minor_version(5)
        .build(&TestKey::new("ROOT").with_subkey(TestKey::new("K").with_layer_bits(0x01)));
    assert_eq!(bits_of_only_subkey(&image), None);
}

// ---- The merged view -------------------------------------------------------

use super::builder::TestValue;
use crate::{HiveError, LayeredClass, LayeredHive, LayeredKey, MAX_LAYERS};

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;

const NONE: u8 = 0x00;
const TOMBSTONE: u8 = 0x01;
const SUPERSEDE_LOCAL: u8 = 0x02;
const SUPERSEDE_TREE: u8 = 0x03;
const INHERIT_CLASS: u8 = 0x80;

fn base(root: &TestKey) -> Vec<u8> {
    HiveBuilder::new().build(root)
}

fn delta(root: &TestKey) -> Vec<u8> {
    HiveBuilder::new().minor_version(6).build(root)
}

fn stack<'a>(base: &'a [u8], deltas: &'a [Vec<u8>]) -> LayeredHive<'a> {
    LayeredHive::new(
        Hive::new(base).unwrap(),
        deltas.iter().map(|d| Hive::new(d).unwrap()).collect(),
    )
    .expect("stack opens")
}

/// Walk down the merged view by exact name.
fn at<'a>(hive: &LayeredHive<'a>, path: &[&str]) -> Option<LayeredKey<'a>> {
    let mut key = hive.root().expect("root");
    for segment in path {
        key = key
            .subkeys()
            .keys
            .into_iter()
            .find(|k| k.name() == *segment)?;
    }
    Some(key)
}

fn subkey_names(key: &LayeredKey<'_>) -> Vec<String> {
    key.subkeys()
        .keys
        .iter()
        .map(|k| k.name().to_string())
        .collect()
}

fn value_names(key: &LayeredKey<'_>) -> Vec<String> {
    key.values().values.iter().map(|v| v.name.clone()).collect()
}

fn dword(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

#[test]
fn a_delta_value_overrides_the_base_value_of_the_same_name_ignoring_case() {
    // The real chain does exactly this: the base Environment key holds
    // `Path` (REG_EXPAND_SZ) and the delta writes `PATH` (REG_SZ).
    let b = base(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("Env")
                .with_value(TestValue::new("Path", REG_EXPAND_SZ, b"old".to_vec()))
                .with_value(TestValue::new("OS", REG_SZ, b"nt".to_vec())),
        ),
    );
    let d = [delta(&TestKey::new("ROOT").with_subkey(
        TestKey::new("Env").with_value(TestValue::new("PATH", REG_SZ, b"new!".to_vec())),
    ))];
    let hive = stack(&b, &d);
    let env = at(&hive, &["Env"]).expect("Env merged");
    assert_eq!(env.contributing_layers(), &[1, 0]);
    let values = env.values();
    let path: Vec<_> = values
        .values
        .iter()
        .filter(|v| v.name.eq_ignore_ascii_case("path"))
        .collect();
    assert_eq!(path.len(), 1, "one Path, not two");
    assert_eq!(path[0].name, "PATH");
    assert_eq!(path[0].layer, 1);
    assert_eq!(path[0].value.data().unwrap().as_slice(), b"new!");
    assert!(values.values.iter().any(|v| v.name == "OS" && v.layer == 0));
    assert_eq!(values.shadowed.len(), 1);
    assert_eq!(values.shadowed[0].name, "Path");
    assert_eq!(values.shadowed[0].layer, 0);
    assert!(values.faults.is_empty());
}

#[test]
fn a_tombstoned_value_in_a_delta_hides_the_value_below_it_and_is_reported() {
    let b = base(
        &TestKey::new("ROOT").with_subkey(TestKey::new("K").with_value(TestValue::new(
            "Gone",
            REG_DWORD,
            dword(1),
        ))),
    );
    let d = [delta(&TestKey::new("ROOT").with_subkey(
        TestKey::new("K").with_value(TestValue::new("Gone", 0, Vec::new()).tombstoned()),
    ))];
    let hive = stack(&b, &d);
    let k = at(&hive, &["K"]).unwrap();
    let values = k.values();
    assert!(values.values.is_empty(), "{:?}", value_names(&k));
    assert_eq!(values.tombstoned.len(), 1);
    assert_eq!(values.tombstoned[0].layer, 1);
    assert_eq!(values.shadowed.len(), 1, "the base value is still evidence");
}

#[test]
fn a_tombstoned_key_hides_the_base_key_and_its_subtree_and_is_reported() {
    let b = base(
        &TestKey::new("ROOT")
            .with_subkey(TestKey::new("Keep"))
            .with_subkey(TestKey::new("Doomed").with_subkey(TestKey::new("Child"))),
    );
    let d = [delta(
        &TestKey::new("ROOT").with_subkey(TestKey::new("DOOMED").with_layer_bits(TOMBSTONE)),
    )];
    let hive = stack(&b, &d);
    let root = hive.root().unwrap();
    let subkeys = root.subkeys();
    assert_eq!(subkey_names(&root), vec!["Keep"]);
    assert_eq!(
        subkeys.tombstoned,
        vec![crate::TombstonedKey {
            name: "DOOMED".into(),
            layer: 1
        }]
    );
}

#[test]
fn a_tombstone_over_nothing_hides_nothing_but_is_still_reported() {
    let b = base(&TestKey::new("ROOT").with_subkey(TestKey::new("Keep")));
    let d = [delta(
        &TestKey::new("ROOT").with_subkey(TestKey::new("Never").with_layer_bits(TOMBSTONE)),
    )];
    let hive = stack(&b, &d);
    let root = hive.root().unwrap();
    assert_eq!(subkey_names(&root), vec!["Keep"]);
    assert_eq!(root.subkeys().tombstoned.len(), 1);
}

#[test]
fn supersede_tree_hides_the_lower_layers_values_and_subkeys() {
    let b = base(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("K")
                .with_value(TestValue::new("Old", REG_DWORD, dword(1)))
                .with_subkey(TestKey::new("OldChild")),
        ),
    );
    let d = [delta(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("K")
                .with_layer_bits(SUPERSEDE_TREE)
                .with_value(TestValue::new("New", REG_DWORD, dword(2)))
                .with_subkey(TestKey::new("NewChild").with_layer_bits(SUPERSEDE_TREE)),
        ),
    )];
    let hive = stack(&b, &d);
    let k = at(&hive, &["K"]).unwrap();
    assert_eq!(k.contributing_layers(), &[1]);
    assert_eq!(value_names(&k), vec!["New"]);
    assert_eq!(subkey_names(&k), vec!["NewChild"]);
}

#[test]
fn supersede_local_hides_the_lower_layers_values_but_not_their_subkeys() {
    let b = base(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("K")
                .with_value(TestValue::new("Old", REG_DWORD, dword(1)))
                .with_subkey(TestKey::new("OldChild")),
        ),
    );
    let d = [delta(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("K")
                .with_layer_bits(SUPERSEDE_LOCAL)
                .with_value(TestValue::new("New", REG_DWORD, dword(2))),
        ),
    )];
    let hive = stack(&b, &d);
    let k = at(&hive, &["K"]).unwrap();
    assert_eq!(k.contributing_layers(), &[1]);
    assert_eq!(value_names(&k), vec!["New"]);
    assert_eq!(subkey_names(&k), vec!["OldChild"]);
}

#[test]
fn a_key_deleted_then_recreated_does_not_resurrect_the_deleted_subtree() {
    let b = base(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("K")
                .with_value(TestValue::new("Old", REG_DWORD, dword(1)))
                .with_subkey(TestKey::new("OldChild")),
        ),
    );
    let d = [
        delta(&TestKey::new("ROOT").with_subkey(TestKey::new("K").with_layer_bits(TOMBSTONE))),
        delta(
            &TestKey::new("ROOT")
                .with_subkey(TestKey::new("K").with_subkey(TestKey::new("NewChild"))),
        ),
    ];
    let hive = stack(&b, &d);
    let k = at(&hive, &["K"]).expect("recreated at layer 2");
    assert_eq!(k.contributing_layers(), &[2]);
    assert!(value_names(&k).is_empty());
    assert_eq!(subkey_names(&k), vec!["NewChild"]);
}

#[test]
fn the_class_name_follows_the_inherit_class_bit() {
    let b = base(
        &TestKey::new("ROOT")
            .with_subkey(TestKey::new("Inherits").with_class("BASE"))
            .with_subkey(TestKey::new("Own").with_class("BASE"))
            .with_subkey(TestKey::new("Blank").with_class("BASE")),
    );
    let d = [delta(
        &TestKey::new("ROOT")
            .with_subkey(TestKey::new("Inherits").with_layer_bits(INHERIT_CLASS))
            .with_subkey(
                TestKey::new("Own")
                    .with_layer_bits(SUPERSEDE_TREE)
                    .with_class("DELTA"),
            )
            .with_subkey(TestKey::new("Blank").with_layer_bits(NONE)),
    )];
    let hive = stack(&b, &d);
    let class = |name: &str| match at(&hive, &[name]).unwrap().class_name() {
        LayeredClass::Named { layer, name } => Some((layer, name.unwrap().to_string_lossy())),
        LayeredClass::NoClass { layer } => Some((layer, String::new())),
        LayeredClass::NotDeterminable => None,
    };
    assert_eq!(class("Inherits"), Some((0, "BASE".into())));
    assert_eq!(class("Own"), Some((1, "DELTA".into())));
    assert_eq!(
        class("Blank"),
        Some((1, String::new())),
        "inherit-class 0 means the delta's own (absent) class"
    );
}

#[test]
fn the_class_is_not_determinable_when_every_node_in_the_stack_inherits() {
    // A supersede cuts the stack at the delta, and the delta's node says
    // "inherit": the class is in a layer this stack does not reach. That is
    // not the same answer as "the key has no class".
    let b = base(&TestKey::new("ROOT").with_subkey(TestKey::new("K").with_class("BASE")));
    let d = [delta(&TestKey::new("ROOT").with_subkey(
        TestKey::new("K").with_layer_bits(SUPERSEDE_TREE | INHERIT_CLASS),
    ))];
    let hive = stack(&b, &d);
    let k = at(&hive, &["K"]).unwrap();
    assert_eq!(k.contributing_layers(), &[1]);
    assert_eq!(k.class_name(), LayeredClass::NotDeterminable);
}

#[test]
fn two_subkeys_of_one_layer_whose_names_fold_equal_are_a_fault_not_a_silent_replacement() {
    // Windows would not write this; a hostile or damaged hive can. The first
    // is kept and the second is reported, not silently swapped in.
    let d = [delta(
        &TestKey::new("ROOT")
            .with_subkey(TestKey::new("Dup").with_value(TestValue::new(
                "First",
                REG_DWORD,
                dword(1),
            )))
            .with_subkey(TestKey::new("DUP").with_value(TestValue::new(
                "Second",
                REG_DWORD,
                dword(2),
            ))),
    )];
    let b = base(&TestKey::new("ROOT"));
    let hive = stack(&b, &d);
    let root = hive.root().unwrap();
    let subkeys = root.subkeys();
    assert_eq!(subkeys.keys.len(), 1);
    assert_eq!(subkeys.faults.len(), 1, "the colliding subkey is reported");
    assert_eq!(subkeys.faults[0].layer, 1);
    assert!(subkeys.is_incomplete());
}

#[test]
fn a_base_layer_value_with_flag_0x2_is_not_a_tombstone() {
    // Below minor 6 the vk flag is spare, for the same reason the nk byte is:
    // a stray bit there is not a deletion.
    let b = base(&TestKey::new("ROOT").with_subkey(
        TestKey::new("K").with_value(TestValue::new("Live", REG_DWORD, dword(1)).tombstoned()),
    ));
    let d = [delta(&TestKey::new("ROOT").with_subkey(TestKey::new("K")))];
    let hive = stack(&b, &d);
    let values = at(&hive, &["K"]).unwrap().values();
    assert_eq!(values.values.len(), 1, "{:?}", values.tombstoned.len());
    assert_eq!(values.values[0].name, "Live");
    assert!(values.tombstoned.is_empty());
}

#[test]
fn a_root_whose_name_will_not_decode_is_refused_rather_than_named_empty() {
    let b = base(&TestKey::new("ROOT"));
    let mut d = delta(&TestKey::new("ROOT"));
    let nk_at = {
        let hive = Hive::new(&d).unwrap();
        4096 + hive.root_cell_offset() as usize + 4
    };
    // nk+0x48: key name length. Point it past the end of the cell.
    d[nk_at + 0x48..nk_at + 0x4A].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let hive = LayeredHive::new(
        Hive::new(&b).unwrap(),
        vec![Hive::without_validation(&d).unwrap()],
    )
    .unwrap();
    assert!(
        hive.root().is_err(),
        "a merged root with no readable name is not presented as \"\""
    );
}

#[test]
fn the_last_written_time_is_the_newest_in_the_stack_and_the_newest_layer_wins_a_value() {
    let b = base(
        &TestKey::new("ROOT").with_subkey(
            TestKey::new("K")
                .with_time(300)
                .with_value(TestValue::new("V", REG_DWORD, dword(0))),
        ),
    );
    let d =
        [
            delta(&TestKey::new("ROOT").with_subkey(
                TestKey::new("K").with_time(500).with_value(TestValue::new(
                    "V",
                    REG_DWORD,
                    dword(1),
                )),
            )),
            delta(&TestKey::new("ROOT").with_subkey(
                TestKey::new("K").with_time(400).with_value(TestValue::new(
                    "V",
                    REG_DWORD,
                    dword(2),
                )),
            )),
        ];
    let hive = stack(&b, &d);
    let k = at(&hive, &["K"]).unwrap();
    assert_eq!(k.last_written_filetime(), 500);
    let values = k.values();
    assert_eq!(values.values.len(), 1);
    assert_eq!(values.values[0].layer, 2);
    assert_eq!(values.values[0].value.data().unwrap().as_slice(), dword(2));
    assert_eq!(values.shadowed.len(), 2);
}

#[test]
fn a_key_only_a_delta_holds_is_in_the_merged_view() {
    let b = base(&TestKey::new("ROOT").with_subkey(TestKey::new("A")));
    let d = [delta(&TestKey::new("ROOT").with_subkey(TestKey::new("B")))];
    let hive = stack(&b, &d);
    assert_eq!(subkey_names(&hive.root().unwrap()), vec!["A", "B"]);
    assert_eq!(at(&hive, &["B"]).unwrap().contributing_layers(), &[1]);
}

#[test]
fn a_hive_below_minor_6_is_refused_as_a_delta_and_the_stack_is_bounded() {
    let b = base(&TestKey::new("ROOT"));
    let not_a_delta = base(&TestKey::new("ROOT"));
    let refused = LayeredHive::new(
        Hive::new(&b).unwrap(),
        vec![Hive::new(&not_a_delta).unwrap()],
    );
    assert!(matches!(
        refused,
        Err(HiveError::Unsupported { value: 5, .. })
    ));

    let d = delta(&TestKey::new("ROOT"));
    let too_many = vec![Hive::new(&d).unwrap(); MAX_LAYERS];
    assert!(matches!(
        LayeredHive::new(Hive::new(&b).unwrap(), too_many),
        Err(HiveError::StructureTooDeep { limit: MAX_LAYERS })
    ));
    let at_limit = vec![Hive::new(&d).unwrap(); MAX_LAYERS - 1];
    assert!(LayeredHive::new(Hive::new(&b).unwrap(), at_limit).is_ok());
}

#[test]
fn a_delta_whose_index_will_not_read_is_a_fault_not_a_short_answer() {
    let b = base(&TestKey::new("ROOT").with_subkey(TestKey::new("FromBase")));
    let mut d = delta(&TestKey::new("ROOT").with_subkey(TestKey::new("FromDelta")));
    // Break the delta root's subkey-list signature.
    let list = {
        let hive = Hive::new(&d).unwrap();
        let root = hive.root_key_node().unwrap();
        let _ = root;
        let nk_at = 4096 + hive.root_cell_offset() as usize + 4;
        u32::from_le_bytes(d[nk_at + 0x1C..nk_at + 0x20].try_into().unwrap()) as usize
    };
    d[4096 + list + 4..4096 + list + 6].copy_from_slice(b"zz");
    let deltas = [d];
    let hive = LayeredHive::new(
        Hive::new(&b).unwrap(),
        deltas
            .iter()
            .map(|d| Hive::without_validation(d).unwrap())
            .collect(),
    )
    .unwrap();
    let root = hive.root().unwrap();
    let subkeys = root.subkeys();
    assert_eq!(subkey_names(&root), vec!["FromBase"]);
    assert_eq!(subkeys.faults.len(), 1);
    assert_eq!(subkeys.faults[0].layer, 1);
    assert!(subkeys.is_incomplete());
}

#[test]
fn a_chain_that_tombstones_its_own_root_is_refused_rather_than_read_as_empty() {
    let b = delta(&TestKey::new("ROOT").with_layer_bits(TOMBSTONE));
    let hive = LayeredHive::new(Hive::new(&b).unwrap(), Vec::new()).unwrap();
    assert!(matches!(
        hive.root(),
        Err(HiveError::Unsupported { value: 1, .. })
    ));
}
