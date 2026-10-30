//! What this reader has to do, stated before it did any of it.

pub mod builder;
mod corpus_tests;
mod fault_tests;
mod layered_corpus_tests;
mod layered_tests;
mod read_tests;
mod security_tests;
mod spec_tests;
mod unallocated_tests;

/// A real hive from the corpus, or `None` when the gate is not provisioned.
///
/// The corpus is the directory named by `SEANCE_HIVE_CORPUS`, and when that
/// is unset, `reference/plaso/test_data` beside this crate — where the plaso
/// hives live on every checkout that has fetched them — so the known-answer
/// tests run by default on a provisioned machine rather than only when
/// somebody remembers the variable (`ROADMAP` §5.9). The contract is the one
/// `seance_core::test_support::corpus` keeps: an unprovisioned corpus skips
/// and says so; a corpus that was named (by the variable, or by the default
/// directory existing) and cannot deliver the file panics, because reporting
/// a pass would claim a comparison that never ran; and
/// `SEANCE_REQUIRE_CORPUS` turns the skip into a failure too.
///
/// Gated by hand rather than through that helper because this crate has
/// **no dependencies at all** — that independence is why the whole product
/// could relicense to MIT, and a dev-dependency for a test helper is not
/// worth spending it.
pub(crate) fn corpus_hive(name: &str) -> Option<Vec<u8>> {
    let dir = match std::env::var("SEANCE_HIVE_CORPUS") {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(_) => {
            let default = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("reference")
                .join("plaso")
                .join("test_data");
            if !default.is_dir() {
                let required =
                    std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty());
                assert!(
                    !required,
                    "SEANCE_HIVE_CORPUS is not set and {} is not a directory, but \
                     SEANCE_REQUIRE_CORPUS demands a corpus. This run would have reported a \
                     pass having compared nothing.",
                    default.display()
                );
                eprintln!(
                    "SKIPPED (no corpus): SEANCE_HIVE_CORPUS is not set and {} is not a \
                     directory — this test compared nothing",
                    default.display()
                );
                return None;
            }
            default
        }
    };
    let path = dir.join(name);
    assert!(
        path.is_file(),
        "{} is missing from the hive corpus at {}. The gate is ON and cannot open — a pass \
         here would report a comparison that never ran.",
        path.display(),
        dir.display()
    );
    Some(std::fs::read(&path).expect("read the corpus hive"))
}
