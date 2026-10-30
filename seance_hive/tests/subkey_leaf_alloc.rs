//! Enumerating a leaf-indexed key's subkeys allocates nothing (ROADMAP §5.9).
//!
//! Its own test binary, because it installs a counting global allocator and
//! that must not count what the unit tests allocate on other threads. The
//! test runs single-threaded inside this binary: there is one `#[test]`.
//!
//! The mechanism is pinned on a real hive — plaso's `SAM`, whose
//! `SAM\Domains\Account\Users\Names` key holds its subkeys in a hash leaf —
//! and skips, saying so, when the corpus is not on disk. It pins that the
//! leaf forms (`lf`, `lh`, `li`) are read in place; an index root (`ri`) still
//! resolves eagerly, because it carries the unresolved-sublist record and the
//! depth bound.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use seance_hive::{Hive, KeyNode};

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged; the only
// addition is a relaxed counter increment.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// plaso's SAM, or `None` (with a printed skip) when the corpus is absent.
/// Same convention as the crate's `corpus_hive`: a named corpus that cannot
/// deliver the file panics, and `SEANCE_REQUIRE_CORPUS` turns a skip into a
/// failure.
fn corpus_sam() -> Option<Vec<u8>> {
    let dir = match std::env::var("SEANCE_HIVE_CORPUS") {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(_) => {
            let default = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../reference/plaso/test_data");
            if !default.is_dir() {
                let required =
                    std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty());
                assert!(!required, "SEANCE_REQUIRE_CORPUS set but no hive corpus");
                eprintln!(
                    "SKIPPED (no corpus): {} is not a directory — this test measured nothing",
                    default.display()
                );
                return None;
            }
            default
        }
    };
    let path = dir.join("SAM");
    assert!(
        path.is_file(),
        "{} is missing from the hive corpus",
        path.display()
    );
    Some(std::fs::read(path).expect("read SAM"))
}

fn child<'a>(key: &KeyNode<'a>, name: &str) -> KeyNode<'a> {
    key.subkeys()
        .expect("has subkeys")
        .expect("subkeys parse")
        .map(|k| k.expect("key node"))
        .find(|k| k.name().expect("name").to_string_lossy() == name)
        .unwrap_or_else(|| panic!("no subkey {name}"))
}

#[test]
fn enumerating_a_leaf_indexed_keys_subkeys_allocates_nothing() {
    let Some(bytes) = corpus_sam() else { return };
    let hive = Hive::without_validation(&bytes).expect("SAM opens");
    let mut key = hive.root_key_node().expect("root");
    for name in ["SAM", "Domains", "Account", "Users", "Names"] {
        key = child(&key, name);
    }
    assert!(key.subkey_count() > 1, "Names should hold several subkeys");

    ALLOCATIONS.store(0, Ordering::SeqCst);
    let subkeys = key.subkeys().expect("present").expect("parses");
    let listed = subkeys.listed_len();
    let mut seen = 0usize;
    let mut offset_sum = 0u64;
    for node in subkeys {
        offset_sum += u64::from(node.expect("key node").cell_offset());
        seen += 1;
    }
    let allocations = ALLOCATIONS.load(Ordering::SeqCst);

    assert_eq!(seen, listed);
    assert_eq!(seen as u32, key.subkey_count());
    assert!(offset_sum > 0);
    assert_eq!(
        allocations, 0,
        "enumerating a leaf-indexed key's subkeys allocated {allocations} time(s)"
    );
}
