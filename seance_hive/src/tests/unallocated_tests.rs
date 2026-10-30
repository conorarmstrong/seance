//! `Hive::unallocated_cells`: recovering `nk`/`vk`-shaped cells from a hive's
//! free space, distinguished from the live tree.

use super::builder::{HiveBuilder, TestKey, TestValue};
use crate::unallocated::RecoveredCell;
use crate::Hive;

/// A key written, then marked free at the hive level (its cell's size field
/// flipped from allocated to unallocated) while its bytes are left untouched
/// and no live index names it — a deletion that has not yet been overwritten.
/// The walk must find it, at its real bin offset, with its name and value
/// intact.
#[test]
fn a_deleted_key_is_recovered_from_unallocated_space_with_its_name_and_values() {
    let live_root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted =
        TestKey::new("DeletedKey").with_value(TestValue::new("Marker", 1, b"still here".to_vec()));
    let (image, deleted_offset) = HiveBuilder::new().build_with_deleted_key(&live_root, &deleted);
    let hive = Hive::new(&image).expect("a hive this crate wrote is one it can read");

    // Confirm it is genuinely gone from the live tree first: recovering it
    // from free space is only meaningful if the ordinary walk does not also
    // see it.
    let root = hive.root_key_node().expect("root key node");
    let live_names: Vec<String> = root
        .subkeys()
        .expect("root has a live subkey")
        .expect("subkeys parse")
        .map(|k| k.unwrap().name().unwrap().to_string_lossy())
        .collect();
    assert_eq!(live_names, vec!["Live"]);

    let recovered: Vec<_> = hive.unallocated_cells().collect();
    let found = recovered
        .iter()
        .find(|cell| cell.bin_offset == deleted_offset)
        .unwrap_or_else(|| panic!("no unallocated cell recovered at {deleted_offset:#x}"));

    match &found.cell {
        RecoveredCell::Key(node) => {
            assert_eq!(node.name().unwrap().to_string_lossy(), "DeletedKey");
            let values: Vec<_> = node
                .values()
                .expect("deleted key has a value")
                .expect("values parse")
                .map(|v| v.unwrap())
                .collect();
            assert_eq!(values.len(), 1);
            assert_eq!(values[0].name().unwrap().to_string_lossy(), "Marker");
            assert_eq!(values[0].data().unwrap().into_vec().unwrap(), b"still here");
        }
        other => panic!("expected a recovered key, got {other:?}"),
    }
}

/// The walk must never fold a recovered cell into the live tree's own types:
/// a caller can tell recovered evidence apart by the type it comes back as,
/// not by remembering to check a flag.
#[test]
fn recovered_cells_are_never_the_live_iterator_types() {
    let live_root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted = TestKey::new("Ghost");
    let (image, _) = HiveBuilder::new().build_with_deleted_key(&live_root, &deleted);
    let hive = Hive::new(&image).unwrap();

    let recovered: Vec<_> = hive.unallocated_cells().collect();
    assert!(
        recovered
            .iter()
            .any(|c| matches!(c.cell, RecoveredCell::Key(_))),
        "the deleted key must show up as a RecoveredCell::Key"
    );
    // The type system already keeps this apart from `SubKeyNodes` /
    // `KeyValues` — there is no shared `Iterator<Item = Result<KeyNode>>`
    // both walks could be confused for — so this test exists to pin the
    // *contents*: a name recovered from free space must not silently
    // reappear among the live subkey names.
    let root = hive.root_key_node().unwrap();
    let live_names: Vec<String> = root
        .subkeys()
        .unwrap()
        .unwrap()
        .map(|k| k.unwrap().name().unwrap().to_string_lossy())
        .collect();
    assert!(!live_names.contains(&"Ghost".to_string()));
}

/// A free cell that never held a key or value must not be mis-parsed into a
/// fabricated key name — it is either skipped outright or, if its bytes
/// happen to open with a `nk`/`vk` signature, reported as undecodable.
#[test]
fn a_garbage_free_cell_is_not_mistaken_for_a_decoded_key() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    // Deterministic "garbage": a repeating counter, long enough to fill a
    // real cell, chosen so it does not open with `nk` or `vk` (0x00, 0x01
    // are neither) — a fixed pattern rather than a seeded RNG so the test
    // cannot flake on the one draw in ~2^32 that would coincidentally carve.
    let garbage: Vec<u8> = (0u8..64).collect();
    let (image, garbage_offset) = HiveBuilder::new().build_with_garbage_free_cell(&root, &garbage);
    let hive = Hive::new(&image).unwrap();

    let recovered: Vec<_> = hive.unallocated_cells().collect();
    let at_garbage: Vec<_> = recovered
        .iter()
        .filter(|c| c.bin_offset == garbage_offset)
        .collect();
    assert!(
        at_garbage.is_empty(),
        "a cell with no nk/vk signature must not be yielded at all, got {at_garbage:?}"
    );
    // And nothing anywhere in the result claims a fabricated key name: every
    // recovered Key must be the one real deleted key this test did not add,
    // i.e. there must be no Key/Value variant at all in this hive.
    assert!(
        recovered
            .iter()
            .all(|c| matches!(c.cell, RecoveredCell::Undecodable { .. })
                || !matches!(c.cell, RecoveredCell::Key(_) | RecoveredCell::Value(_))),
        "no genuine key/value shape exists in this hive's free space: {recovered:?}"
    );
}

/// A cell that opens with a real `nk` signature but whose structure does not
/// hold up (a name length running past the cell) must be reported as
/// undecodable, not silently dropped and not misread as a shorter, wrong
/// name.
#[test]
fn a_truncated_nk_signature_in_free_space_is_reported_undecodable() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    // Fewer than the 0x4C fixed bytes an `nk` cell needs, but it does open
    // with the signature: a plausible fragment of a key node cut short by
    // whatever overwrote the rest of the cell.
    let mut fragment = vec![0u8; 16];
    fragment[0..2].copy_from_slice(b"nk");
    let (image, fragment_offset) =
        HiveBuilder::new().build_with_garbage_free_cell(&root, &fragment);
    let hive = Hive::new(&image).unwrap();

    let recovered: Vec<_> = hive.unallocated_cells().collect();
    let found = recovered
        .iter()
        .find(|c| c.bin_offset == fragment_offset)
        .unwrap_or_else(|| panic!("expected an undecodable candidate at {fragment_offset:#x}"));
    match &found.cell {
        RecoveredCell::Undecodable { signature, .. } => assert_eq!(signature, b"nk"),
        other => panic!("expected Undecodable, got {other:?}"),
    }
}

/// A handful of deleted cells must not trip the ceiling meant for a hive
/// crafted (or corrupted) to hold an unreasonable amount of free space.
#[test]
fn a_small_hive_is_not_capped() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted = TestKey::new("Ghost");
    let (image, _) = HiveBuilder::new().build_with_deleted_key(&root, &deleted);
    let hive = Hive::new(&image).unwrap();

    let mut walk = hive.unallocated_cells();
    let recovered: Vec<_> = walk.by_ref().collect();
    assert!(!recovered.is_empty(), "the deleted key should be found");
    assert!(
        !walk.is_capped(),
        "a handful of cells must not trip a 200,000-cell ceiling"
    );
    assert!(!walk.is_incomplete());
}

/// The walk is bounded: [`crate::unallocated::MAX_UNALLOCATED_CELLS`] caps how
/// many cells it steps over, and hitting the cap is reported on the record
/// rather than read as "that was every unallocated cell in the hive".
#[test]
fn the_walk_reports_when_it_is_capped() {
    use crate::unallocated::MAX_UNALLOCATED_CELLS;

    let root = TestKey::new("ROOT");
    let image =
        HiveBuilder::new().build_with_many_empty_free_cells(&root, MAX_UNALLOCATED_CELLS + 10);
    let hive = Hive::new(&image).unwrap();

    let mut walk = hive.unallocated_cells();
    let recovered: Vec<_> = walk.by_ref().collect();
    assert!(
        recovered.is_empty(),
        "none of these free cells carry a recognisable signature"
    );
    assert!(
        walk.is_capped(),
        "stepping over MAX_UNALLOCATED_CELLS + 10 cells must trip the ceiling"
    );
}

/// A hive whose hive-bin header is corrupt must say so through
/// `is_incomplete`, not present a short walk as though it were complete —
/// the free-space counterpart of `SubKeyNodes::is_incomplete`.
#[test]
fn a_broken_bin_header_is_reported_incomplete_not_silently_short() {
    const BASE_BLOCK_BYTES: usize = 4096;
    const HBIN_SIZE_FIELD_OFFSET: usize = 0x08;

    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted = TestKey::new("Ghost");
    let (mut image, _) = HiveBuilder::new().build_with_deleted_key(&root, &deleted);

    // Corrupt the (only) hive bin's declared size so it is no longer a
    // multiple of the bin alignment: a bin header this reader cannot trust.
    let hbin_size_field = BASE_BLOCK_BYTES + HBIN_SIZE_FIELD_OFFSET;
    image[hbin_size_field..hbin_size_field + 4].copy_from_slice(&0x21u32.to_le_bytes());

    // `Hive::new` validates the base block, not hive-bin headers, so this
    // still opens; the corruption is downstream of it.
    let hive = Hive::new(&image).expect("base block is untouched");
    let mut walk = hive.unallocated_cells();
    while walk.next().is_some() {}
    assert!(
        walk.is_incomplete(),
        "a bin whose declared size is not bin-aligned must be reported, not silently truncated"
    );
}

/// Every real hive on disk is longer than the hive-bin data its base block
/// declares — Windows grows the file in 256 KiB steps, so `SAM` from the
/// plaso corpus is 262,144 bytes holding 20,480 bytes of bins. The zeros
/// past the declared size are slack, not a broken bin chain: a walk that
/// reaches them has seen every bin and must say it ran whole, not that the
/// hive is damaged. Before this the walk reported every real hive incomplete.
#[test]
fn slack_past_the_declared_bins_is_the_end_of_the_walk_not_damage() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted = TestKey::new("Ghost");
    let (mut image, deleted_offset) = HiveBuilder::new().build_with_deleted_key(&root, &deleted);
    // 256 KiB of zeros after the one declared bin, as Windows leaves it.
    image.resize(image.len() + 0x40000, 0);
    let hive = Hive::new(&image).unwrap();

    let mut walk = hive.unallocated_cells();
    let recovered: Vec<_> = walk.by_ref().collect();
    assert!(recovered.iter().any(|c| c.bin_offset == deleted_offset));
    assert!(
        !walk.is_incomplete(),
        "zeros past the declared hive-bin size are slack, not a broken chain"
    );
    assert!(!walk.is_capped());
}

/// The converse: a bin chain that breaks **inside** the declared size is
/// still damage, and the slack rule must not hide it.
#[test]
fn a_chain_broken_inside_the_declared_size_is_still_incomplete() {
    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted = TestKey::new("Ghost");
    let (mut image, _) = HiveBuilder::new().build_with_deleted_key(&root, &deleted);
    // Declare two bins' worth of data but supply zeros where the second bin's
    // header should be.
    let one_bin = image.len() - 0x1000;
    image.resize(0x1000 + one_bin * 2, 0);
    image[0x28..0x2C].copy_from_slice(&((one_bin * 2) as u32).to_le_bytes());
    super::builder::reseal(&mut image);
    let hive = Hive::new(&image).unwrap();

    let mut walk = hive.unallocated_cells();
    while walk.next().is_some() {}
    assert!(
        walk.is_incomplete(),
        "the base block promised a second bin and none is there"
    );
}

/// The ceiling is on **unallocated** cells, as its name says. Allocated
/// cells are the live tree's business and stepping over them costs nothing
/// worth capping: a 37 MB `SOFTWARE` hive holds more than 200,000 allocated
/// cells before its first free one, and a cap that counted those reached it
/// before recovering anything, on the one hive most worth walking.
#[test]
fn allocated_cells_do_not_count_toward_the_ceiling() {
    use crate::unallocated::MAX_UNALLOCATED_CELLS;

    let root = TestKey::new("ROOT").with_subkey(TestKey::new("Live"));
    let deleted = TestKey::new("Ghost");
    let (image, deleted_offset) = HiveBuilder::new()
        .build_with_many_empty_allocated_cells_then_deleted_key(
            &root,
            &deleted,
            MAX_UNALLOCATED_CELLS + 10,
        );
    let hive = Hive::new(&image).unwrap();

    let mut walk = hive.unallocated_cells();
    let recovered: Vec<_> = walk.by_ref().collect();
    assert!(
        recovered.iter().any(|c| c.bin_offset == deleted_offset),
        "the deleted key past 200,010 allocated cells must be reached"
    );
    assert!(!walk.is_capped());
}
