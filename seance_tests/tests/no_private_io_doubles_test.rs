//! Guard: `DataSource` test doubles come from `seance_core::test_support`
//! (or `seance_core::data_source::ByteSliceDataSource`), never from a private
//! copy in a plugin's tests.
//!
//! A private double asserts a private contract. The VSS copy of an in-memory
//! source zero-filled reads past its end and reported them as full reads —
//! exactly the fabricated-zeros behaviour `test_support` exists to forbid —
//! and a plugin could pass its own copy of a short-read test while breaking
//! the real invariant. ROADMAP §5.11 retired the copies; this test keeps them
//! retired.
//!
//! If a test needs a shape `test_support` does not offer, add it there, with
//! its own test, rather than defining it here and there again.

use std::fs;
use std::path::{Path, PathBuf};

/// The names the retired copies went by. `test_support.rs`'s own module doc
/// lists the same aliases.
const RETIRED_NAMES: &[&str] = &[
    "ShortSource",
    "ShortReadSource",
    "UnderDeliveringSource",
    "OversizedSource",
    "OversizeSource",
    "OverReportSource",
    "HugeDeclaredSource",
    "LyingSizeSource",
    "HalfReadSource",
    "ChunkedSource",
    "MemSource",
    "TruncatedSource",
    "DribbleSource",
];

/// The files allowed to define these shapes: the shared module itself, and
/// this guard (whose matcher test spells the pattern out in string literals).
const HOME: &[&str] = &[
    "seance_core/src/test_support.rs",
    "seance_tests/tests/no_private_io_doubles_test.rs",
];

/// Directories never walked: build output, vendored/JS trees and VCS state.
const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "frontend"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("seance_tests sits one level below the workspace root")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                continue;
            }
            walk(&path, out);
        } else if kind.is_file() && name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// `struct <Name>` followed by a non-identifier character, so `MemSourceX`
/// or a doc sentence that merely names a type does not match.
fn defines_retired_double(line: &str) -> Option<&'static str> {
    let code = line.split("//").next().unwrap_or("");
    for name in RETIRED_NAMES {
        let needle = format!("struct {name}");
        let mut from = 0;
        while let Some(at) = code[from..].find(&needle) {
            let start = from + at;
            let end = start + needle.len();
            let before_ok = start == 0
                || !code[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let after_ok = !code[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            if before_ok && after_ok {
                return Some(name);
            }
            from = end;
        }
    }
    None
}

#[test]
fn no_crate_defines_a_private_short_read_or_in_memory_source() {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 500,
        "the walk found only {} .rs files under {} — it is not looking at the workspace",
        files.len(),
        root.display()
    );

    let mut hits = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if HOME.contains(&rel.as_str()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if let Some(name) = defines_retired_double(line) {
                hits.push(format!("{rel}:{} defines {name}", i + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "{} private DataSource double(s) found; use seance_core::test_support \
         (TruncatedSource / DribbleSource / StallingSource / UnreadableSource) or \
         seance_core::data_source::ByteSliceDataSource instead:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// The shape-based check. The name list above only catches a copy that kept
/// its old name; a copy renamed `Dribble`, `MemorySource` or `Mem` passed it
/// (an adversarial review found seven). This check keys on the SHAPE instead:
/// a struct whose only field is a `Vec<u8>` and which implements
/// `DataSource` in the same file is an in-memory byte source, which is what
/// `ByteSliceDataSource` (or, with a chunk cap, `DribbleSource`) already is.
///
/// Returns the struct names in `text` that have that shape.
fn byte_vec_sources(text: &str) -> Vec<String> {
    // Strip line comments so a doc sentence cannot define a struct.
    let code: String = text
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let squashed: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut names = Vec::new();
    let mut rest = squashed.as_str();
    while let Some(at) = rest.find("struct ") {
        let after = &rest[at + "struct ".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let tail = after[name.len()..].trim_start();
        let body = if let Some(t) = tail.strip_prefix('(') {
            t.split_once(')').map(|(b, _)| b.to_string())
        } else if let Some(t) = tail.strip_prefix('{') {
            t.split_once('}').map(|(b, _)| {
                // `data: Vec<u8>,` -> `Vec<u8>`; more than one field is not this shape.
                let fields: Vec<&str> = b
                    .split(',')
                    .map(str::trim)
                    .filter(|f| !f.is_empty())
                    .collect();
                if fields.len() == 1 {
                    fields[0]
                        .rsplit_once(':')
                        .map_or(String::new(), |(_, ty)| ty.to_string())
                } else {
                    String::new()
                }
            })
        } else {
            None
        };
        if let Some(body) = body {
            let ty = body
                .trim()
                .trim_start_matches("pub(crate)")
                .trim_start_matches("pub")
                .trim();
            if !name.is_empty() && !ty.contains(',') && ty.replace(' ', "") == "Vec<u8>" {
                let implements = squashed.contains(&format!("DataSource for {name} "))
                    || squashed.contains(&format!("DataSource for {name}{{"));
                if implements && !names.contains(&name) {
                    names.push(name.clone());
                }
            }
        }
        rest = &after[name.len()..];
    }
    names
}

/// Copies of the in-memory shape that predate the shape check and are not yet
/// retired, as `path::Name`. This list may only SHRINK: a new copy fails the
/// check below, and so does an entry here whose copy has gone (delete the
/// line). Several of these are in crates other work streams own; retiring
/// them is open ROADMAP §5.11 work, and until then they are named here rather
/// than claimed gone.
const NOT_YET_RETIRED: &[&str] = &[
    "fuzz/fuzz_targets/carving_engine.rs::FuzzDataSource",
    "seance_carving/src/checks.rs::Bytes",
    "seance_carving/src/engine.rs::InMemorySlice", // production code, not a test double
    "seance_carving/src/ext2_indirect.rs::Mem",
    "seance_carving/src/formats/evtx.rs::Mem",
    "seance_carving/src/formats/ole2.rs::Mem",
    "seance_carving/src/formats/tar.rs::Mem",
    "seance_carving/src/tests.rs::MemorySource",
    "seance_container_archive/src/bzip2.rs::MemorySource",
    "seance_container_archive/src/gzip.rs::MemorySource",
    "seance_container_archive/src/ole2.rs::MemorySource",
    "seance_container_archive/src/sevenz.rs::MemorySource",
    "seance_container_archive/src/xz.rs::MemorySource",
    "seance_container_archive/tests/archive_chain.rs::MemorySource",
    "seance_core/src/data_source_tests.rs::MockDataSource",
    "seance_core/src/file_detection.rs::TestDataSource",
    "seance_plugin_email/src/lib.rs::OneBytePerCall",
    "seance_plugin_evtx/src/tests.rs::MockEvtxSource",
    "seance_plugin_exif/src/tests.rs::FourBytesPerCall",
    "seance_plugin_fat/src/tests.rs::MockFatSource",
    "seance_plugin_file_analysis/src/encryption.rs::MemorySource",
    "seance_plugin_file_analysis/src/lib.rs::MemorySource",
    "seance_plugin_iso9660/tests/rock_ridge.rs::Bytes",
    "seance_plugin_jumplists/src/lib.rs::MemoryDataSource",
    "seance_plugin_lnk/src/tests.rs::MockDataSource",
    "seance_plugin_pcap/src/lib.rs::MemorySource",
    "seance_plugin_plist/src/tests.rs::MockDataSource",
    "seance_plugin_prefetch/src/tests.rs::MockDataSource",
    "seance_plugin_sdb/src/tests.rs::Mem",
    "seance_plugin_shellbags/src/tests.rs::MockDataSource",
    "seance_plugin_squashfs/tests/module_test.rs::Bytes",
    "seance_plugin_vss/src/vss_source.rs::MemVolume",
    "seance_search/tests/byte_sweep_test.rs::FailsAfter",
    "seance_tests/src/lnk_jumplist_tests.rs::BytesSource",
    "seance_tests/src/orchestrator_integration_test.rs::MemoryDataSource",
];

/// Files allowed to define the shape: the honest in-memory source's home and
/// the shared doubles module.
const SHAPE_HOME: &[&str] = &[
    "seance_core/src/data_source.rs",
    "seance_core/src/test_support.rs",
    "seance_tests/tests/no_private_io_doubles_test.rs",
];

#[test]
fn no_new_private_in_memory_source_under_any_name() {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files);

    let mut found = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if SHAPE_HOME.contains(&rel.as_str()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for name in byte_vec_sources(&text) {
            found.push(format!("{rel}::{name}"));
        }
    }
    let new: Vec<&String> = found
        .iter()
        .filter(|f| !NOT_YET_RETIRED.contains(&f.as_str()))
        .collect();
    let gone: Vec<&&str> = NOT_YET_RETIRED
        .iter()
        .filter(|n| !found.iter().any(|f| f == *n))
        .collect();
    assert!(
        new.is_empty(),
        "{} private in-memory DataSource double(s) (a struct holding only Vec<u8> that \
         implements DataSource); use seance_core::data_source::ByteSliceDataSource or \
         seance_core::test_support::DribbleSource:\n{}",
        new.len(),
        new.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        gone.is_empty(),
        "retired — delete these lines from NOT_YET_RETIRED so the list keeps shrinking:\n{}",
        gone.iter().map(|s| **s).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn the_shape_matcher_sees_through_a_rename() {
    let tuple = "#[derive(Debug)]\nstruct Dribble(Vec<u8>);\nimpl DataSource for Dribble {\n}";
    assert_eq!(byte_vec_sources(tuple), vec!["Dribble".to_string()]);
    // forensic-lint: allow RAGGED-STRING -- Rust source text under test, indentation is its shape.
    let named = "struct MemorySource {\n    data: Vec<u8>,\n}\nimpl DataSource for MemorySource {}";
    assert_eq!(byte_vec_sources(named), vec!["MemorySource".to_string()]);
    // Two fields (a chunk cap, a stats counter) is some other shape.
    let two = "struct S { data: Vec<u8>, chunk: usize }\nimpl DataSource for S {}";
    assert!(byte_vec_sources(two).is_empty());
    // Holding bytes without implementing DataSource is not a source.
    assert!(byte_vec_sources("struct Blob(Vec<u8>);").is_empty());
    // A comment is not a definition.
    assert!(byte_vec_sources("// struct M(Vec<u8>);\nimpl DataSource for M {}").is_empty());
}

#[test]
fn the_matcher_finds_a_definition_and_ignores_mentions() {
    assert_eq!(
        defines_retired_double("    struct MemSource(Vec<u8>);"),
        Some("MemSource")
    );
    assert_eq!(
        defines_retired_double("pub(crate) struct ShortSource {"),
        Some("ShortSource")
    );
    assert_eq!(defines_retired_double("struct MemSourceTable {"), None);
    assert_eq!(defines_retired_double("// struct MemSource was here"), None);
    assert_eq!(defines_retired_double("let s = MemSource(v);"), None);
}
