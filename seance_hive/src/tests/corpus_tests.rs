//! The known answers on real hives, past the security ring: the key tree
//! and the unallocated walk (`ROADMAP` §5.9).
//!
//! Every number here was decoded by hand — a Python walk over the raw cell
//! chain, independent of this crate — before the assertion was written, and
//! the plaso `SAM` is small enough (20,480 bytes of bins) that the whole tree
//! was listed and checked rather than sampled.

use super::corpus_hive;
use crate::unallocated::RecoveredCell;
use crate::{Hive, KeyNode};

/// Walk one path down from the root by name, returning the node.
fn descend<'a>(root: KeyNode<'a>, path: &[&str]) -> KeyNode<'a> {
    let mut node = root;
    for segment in path {
        let subkeys = node
            .subkeys()
            .unwrap_or_else(|| panic!("{segment}: parent has no subkeys"))
            .expect("subkey index reads");
        node = subkeys
            .map(|k| k.expect("subkey reads"))
            .find(|k| k.name().unwrap().to_string_lossy() == *segment)
            .unwrap_or_else(|| panic!("no subkey named {segment}"));
    }
    node
}

/// The `SAM` key tree, by hand:
///
/// ```text
/// 0x20   CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}   1 subkey
/// 0xa8   SAM                       3 subkeys   130560137965001370
/// 0x410  Domains                   2 subkeys
/// 0x498  Builtin                   3 subkeys   130560033663588374
/// 0x928  Aliases                  16 subkeys   130560137964221369
/// 0x9b0  Names                    14 subkeys   130560033663588374
/// ```
///
/// with `Names`' fourteen children `Administrators`, `Backup Operators`,
/// `Cryptographic Operators`, `Distributed COM Users`, `Event Log Readers`,
/// `Guests`, `IIS_IUSRS`, `Network Configuration Operators`, `Performance Log
/// Users`, `Performance Monitor Users`, `Power Users`, `Remote Desktop Users`,
/// `Replicator` and `Users`, every one last written 130560033663588374. The
/// live root's parent field holds `0x4f8`, not the `0xFFFFFFFF` sentinel,
/// which is why a consumer ends a chain on the root flag.
#[test]
fn the_real_sam_hives_key_tree_reads_to_its_known_answer() {
    let Some(bytes) = corpus_hive("SAM") else {
        return;
    };
    let hive = Hive::without_validation(&bytes).expect("open SAM");
    let root = hive.root_key_node().expect("root");
    assert_eq!(root.cell_offset(), 0x20);
    assert_eq!(
        root.name().unwrap().to_string_lossy(),
        "CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}"
    );
    assert_eq!(root.subkey_count(), 1);

    let sam = descend(root, &["SAM"]);
    assert_eq!(sam.cell_offset(), 0xa8);
    assert_eq!(sam.subkey_count(), 3);
    assert_eq!(sam.last_written_filetime(), 130_560_137_965_001_370);

    let names = descend(root, &["SAM", "Domains", "Builtin", "Aliases", "Names"]);
    assert_eq!(names.cell_offset(), 0x9b0);
    assert_eq!(names.parent_offset(), Some(0x928));
    assert_eq!(names.subkey_count(), 14);
    assert_eq!(names.last_written_filetime(), 130_560_033_663_588_374);
    let mut children: Vec<(String, u32, u64)> = names
        .subkeys()
        .unwrap()
        .unwrap()
        .map(|k| {
            let k = k.unwrap();
            (
                k.name().unwrap().to_string_lossy(),
                k.cell_offset(),
                k.last_written_filetime(),
            )
        })
        .collect();
    children.sort();
    let expected_names = [
        "Administrators",
        "Backup Operators",
        "Cryptographic Operators",
        "Distributed COM Users",
        "Event Log Readers",
        "Guests",
        "IIS_IUSRS",
        "Network Configuration Operators",
        "Performance Log Users",
        "Performance Monitor Users",
        "Power Users",
        "Remote Desktop Users",
        "Replicator",
        "Users",
    ];
    assert_eq!(
        children.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
        expected_names
    );
    for (name, offset) in [
        ("Power Users", 0x26b0u32),
        ("Network Configuration Operators", 0x2628),
        ("Cryptographic Operators", 0x2728),
    ] {
        let child = children.iter().find(|c| c.0 == name).unwrap();
        assert_eq!(child.1, offset, "{name} lives at {offset:#x}");
        assert_eq!(child.2, 130_560_033_663_588_374);
    }
    // `Aliases` declares sixteen subkeys: fourteen RID-named keys plus
    // `Members` and `Names`.
    let aliases = descend(root, &["SAM", "Domains", "Builtin", "Aliases"]);
    assert_eq!(aliases.cell_offset(), 0x928);
    assert_eq!(aliases.subkey_count(), 16);
    assert_eq!(aliases.last_written_filetime(), 130_560_137_964_221_369);
}

/// The `SAM`'s free space, by hand: fourteen free cells, of which six open
/// with a key or value signature —
///
/// ```text
/// 0x27b0  vk  name ""  inline, 0 bytes  type 546
/// 0x3218  nk  "Power Users"                      parent 0x9b0  130560137964065369
/// 0x3318  vk  name ""  inline, 0 bytes  type 556
/// 0x3520  nk  "Network Configuration Operators"  parent 0x9b0  130560137964065369
/// 0x3e90  vk  name ""  inline, 0 bytes  type 547
/// 0x4078  nk  "Cryptographic Operators"          parent 0x9b0  130560137964221369
/// ```
///
/// — and the other eight (at `0x3948`, `0x3b48`, `0x3ff8`, `0x4110`,
/// `0x43c8`, `0x47d0`, `0x4d90`, `0x4fb8`) open with neither and are not
/// yielded. The three keys are namesakes of live children of `0x9b0` at
/// other offsets with earlier times: this walk recovers them, and it is the
/// consumer's job to say they are not deletions.
///
/// The file is 262,144 bytes for 20,480 bytes of declared bins. The walk
/// used to report that slack as a broken chain on every real hive.
#[test]
fn the_real_sam_hives_free_space_yields_its_six_signed_cells_and_the_walk_runs_whole() {
    let Some(bytes) = corpus_hive("SAM") else {
        return;
    };
    let hive = Hive::without_validation(&bytes).expect("open SAM");
    assert_eq!(hive.declared_data_size(), 20_480);
    assert_eq!(hive.present_data_size(), 262_144 - 4096);

    let mut walk = hive.unallocated_cells();
    let cells: Vec<_> = walk.by_ref().collect();
    assert!(!walk.is_capped());
    assert!(
        !walk.is_incomplete(),
        "the slack past the declared bins is not damage"
    );

    let mut found: Vec<(u32, String)> = Vec::new();
    for cell in &cells {
        match &cell.cell {
            RecoveredCell::Key(node) => {
                found.push((
                    cell.bin_offset,
                    format!("nk {}", node.name().unwrap().to_string_lossy()),
                ));
                assert_eq!(node.parent_offset(), Some(0x9b0));
            }
            RecoveredCell::Value(value) => {
                found.push((
                    cell.bin_offset,
                    format!("vk {:?}", value.data_type().unwrap()),
                ));
                assert_eq!(value.name().unwrap().to_string_lossy(), "");
                assert_eq!(value.data_size(), 0);
            }
            RecoveredCell::Undecodable { signature, error } => {
                panic!("nothing in SAM's free space is undecodable: {signature:?} {error}")
            }
        }
    }
    found.sort();
    assert_eq!(
        found,
        vec![
            (0x27b0, "vk Unknown(546)".to_string()),
            (0x3218, "nk Power Users".to_string()),
            (0x3318, "vk Unknown(556)".to_string()),
            (0x3520, "nk Network Configuration Operators".to_string()),
            (0x3e90, "vk Unknown(547)".to_string()),
            (0x4078, "nk Cryptographic Operators".to_string()),
        ]
    );
    let times: Vec<u64> = cells
        .iter()
        .filter_map(|c| match &c.cell {
            RecoveredCell::Key(node) => Some(node.last_written_filetime()),
            _ => None,
        })
        .collect();
    assert_eq!(
        times,
        vec![
            130_560_137_964_065_369,
            130_560_137_964_065_369,
            130_560_137_964_221_369
        ]
    );
}

/// The larger hives walk whole too, and what they hold is counted rather
/// than sampled: `SOFTWARE` (35,385,344 bytes of bins) yields 47 keys and
/// 255 values, `SYSTEM` 51 values and no key, `NTUSER-WIN7.DAT` one key
/// (`mqs`) and seven values, and neither `NTUSER.DAT` nor
/// `NTUSER-CCLEANER.DAT` any. Measured on 2026-09-19 after the walk was
/// fixed to stop counting allocated cells toward its ceiling: before that
/// `SOFTWARE` hit the 200,000-cell ceiling with nothing recovered.
#[test]
fn every_real_hive_walks_whole_and_its_free_space_counts_are_pinned() {
    for (name, keys, values) in [
        ("SOFTWARE", 47usize, 255usize),
        ("SYSTEM", 0, 51),
        ("NTUSER-WIN7.DAT", 1, 7),
        ("NTUSER.DAT", 0, 0),
        ("NTUSER-CCLEANER.DAT", 0, 0),
    ] {
        let Some(bytes) = corpus_hive(name) else {
            return;
        };
        let hive = Hive::without_validation(&bytes).unwrap_or_else(|e| panic!("open {name}: {e}"));
        let mut walk = hive.unallocated_cells();
        let (mut k, mut v) = (0usize, 0usize);
        for cell in walk.by_ref() {
            match cell.cell {
                RecoveredCell::Key(_) => k += 1,
                RecoveredCell::Value(_) => v += 1,
                RecoveredCell::Undecodable { .. } => {}
            }
        }
        assert!(!walk.is_capped(), "{name} must not hit the ceiling");
        assert!(!walk.is_incomplete(), "{name} must walk whole");
        assert_eq!((k, v), (keys, values), "{name}: recovered keys and values");
    }
}
