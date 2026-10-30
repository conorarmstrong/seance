#![no_main]
//! `seance_hive`'s own hive-open + key/value walk.
//!
//! Every other registry fuzz target (`registry_parser.rs`) goes through
//! `seance_plugin_registry`, which layers transaction-log replay and a raw
//! deleted-cell scanner on top of this crate. This target is the crate
//! underneath, alone: `Hive::new` on raw bytes, then a recursive walk of
//! every key and value it reaches. A crafted `nk`/`vk`/`db` cell is exactly
//! where an offset or a length taken from evidence runs a read past the
//! buffer it came from, so the property under test is "does not panic, does
//! not read out of bounds" — not that anything decoded is correct.

use libfuzzer_sys::fuzz_target;
use seance_hive::{Hive, KeyNode};

/// How deep a crafted `ri` index or a self-referential key can drive the
/// walk before it is cut off. `seance_hive` already bounds its own subkey
/// index recursion (`MAX_INDEX_DEPTH`), but the *tree* walk below is this
/// target's own recursion over key nodes, and needs its own bound for the
/// same reason: a fuzz input is not obliged to be a tree.
const MAX_WALK_DEPTH: u32 = 128;

/// Open `data` as a hive and walk every key and value reachable from the
/// root. The same shape (`Hive::new`, then a recursive key/value walk) is
/// pinned by `seance_hive`'s own
/// `the_fuzz_targets_walk_reaches_subkeys_and_both_live_and_tombstoned_values`
/// test, on a well-formed hive, so this target cannot silently stop reaching
/// real parsing without a test noticing — the failure mode `usnjrnl_parser.rs`
/// hit, where a fuzz target's input shape decoded to nothing and was still
/// counted as coverage.
pub fn walk_hive(data: &[u8]) {
    let Ok(hive) = Hive::new(data) else {
        return;
    };
    let Ok(root) = hive.root_key_node() else {
        return;
    };
    walk_key(&root, 0);
}

fn walk_key(key: &KeyNode<'_>, depth: u32) {
    if depth > MAX_WALK_DEPTH {
        return;
    }

    let _ = key.name();
    let _ = key.class_name();
    let _ = key.last_written_filetime();
    let _ = key.security();

    if let Some(Ok(values)) = key.values() {
        for value in values.flatten() {
            let _ = value.name();
            let _ = value.data_type();
            let _ = value.data();
            let _ = value.is_tombstoned();
        }
    }

    if let Some(Ok(subkeys)) = key.subkeys() {
        for subkey in subkeys.flatten() {
            walk_key(&subkey, depth + 1);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    walk_hive(data);
});
