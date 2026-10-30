//! The source-kind label's marker vocabulary is made of types the parsers in
//! this tree actually write (ROADMAP §1.4).
//!
//! The label lists records by the COALESCE discriminator `idx_artifacts_record_type`
//! computes — `type` first — so a marker must be emitted as `type`, not only as
//! `subtype` or `record_type`. A marker whose name drifts from what its parser
//! writes would never match, and every source it should have labelled would
//! quietly read as holding no mobile evidence. This walks the plugin sources
//! for emitted `type` literals, the way `UI_TESTING.md`'s emitted-type grep
//! does.

use seance_api::source_kind::{MARKERS, UNREAD_STORE_TYPES};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The production part of a plugin source file: `None` for a test file
/// (`tests.rs`, `*_tests.rs`, `test_*.rs`, anything under a `tests/`
/// directory), and otherwise the text with every inline `#[cfg(test)] mod x {
/// ... }` block removed. A test module whose braces do not balance takes the
/// rest of the file with it, which can only drop production code — stricter,
/// never looser: a type written only by a test fixture must not pass for one a
/// parser writes.
fn production_text(path: &Path, text: &str) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let in_tests_dir = path
        .components()
        .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "test_support");
    if in_tests_dir
        || name == "tests.rs"
        || name.ends_with("_tests.rs")
        || name.starts_with("test_")
    {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..i]);
        let after = rest[i + "#[cfg(test)]".len()..].trim_start();
        let is_inline_mod = after.starts_with("mod ")
            && after
                .find(['{', ';'])
                .is_some_and(|j| after.as_bytes()[j] == b'{');
        if !is_inline_mod {
            // `mod x;` (its file is excluded by `test_module_files`) or a
            // single item: keep scanning after the attribute.
            rest = after;
            continue;
        }
        let open = after.find('{').unwrap();
        let mut depth = 0usize;
        let mut close = None;
        for (k, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + k + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match close {
            Some(c) => rest = &after[c..],
            None => return Some(out),
        }
    }
    out.push_str(rest);
    Some(out)
}

/// The files of out-of-line test modules (`#[cfg(test)] mod x;`), whatever
/// they are named.
fn test_module_files(path: &Path, text: &str) -> Vec<PathBuf> {
    let dir = match path.file_name().and_then(|n| n.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => path.parent().unwrap().to_path_buf(),
        _ => path.with_extension(""),
    };
    let mut out = Vec::new();
    for (i, _) in text.match_indices("#[cfg(test)]") {
        let after = text[i + "#[cfg(test)]".len()..].trim_start();
        let Some(decl) = after.strip_prefix("mod ") else {
            continue;
        };
        let ident: String = decl
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if decl[ident.len()..].trim_start().starts_with(';') {
            out.push(dir.join(format!("{ident}.rs")));
            out.push(dir.join(&ident).join("mod.rs"));
        }
    }
    out
}

/// Every `type` a text writes: the JSON-macro form `"type": "T"` and the
/// map-insert forms `"type".into(), json!("T")` / `"type".to_string(), json!("T")`.
fn types_in(text: &str) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    for (i, _) in text.match_indices("\"type\"") {
        let rest = text[i + 6..].trim_start();
        let rest = if let Some(r) = rest.strip_prefix(':') {
            r.trim_start()
        } else if let Some(r) = rest
            .strip_prefix(".into(),")
            .or_else(|| rest.strip_prefix(".to_string(),"))
        {
            let r = r.trim_start();
            match r.strip_prefix("json!(") {
                Some(r) => r,
                None => continue,
            }
        } else {
            continue;
        };
        if let Some(r) = rest.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                types.insert(r[..end].to_string());
            }
        }
    }
    types
}

/// Per production plugin source file: the types it writes, and its text.
fn emitting_files() -> Vec<(PathBuf, BTreeSet<String>, String)> {
    let mut files = Vec::new();
    for e in std::fs::read_dir(workspace()).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("seance_plugin_") {
            rust_files(&e.path().join("src"), &mut files);
        }
    }
    assert!(files.len() > 100, "the plugin sources were not found");
    let texts: Vec<(PathBuf, String)> = files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            (f, text)
        })
        .collect();
    let excluded: BTreeSet<PathBuf> = texts
        .iter()
        .flat_map(|(f, t)| test_module_files(f, t))
        .collect();
    let mut out = Vec::new();
    for (f, text) in texts {
        if excluded.contains(&f) {
            continue;
        }
        if let Some(prod) = production_text(&f, &text) {
            let types = types_in(&prod);
            if !types.is_empty() {
                out.push((f, types, prod));
            }
        }
    }
    out
}

fn emitted_types() -> BTreeSet<String> {
    emitting_files()
        .into_iter()
        .flat_map(|(_, types, _)| types)
        .collect()
}

#[test]
fn a_type_written_only_in_a_test_module_or_test_file_does_not_count() {
    let text = "#[cfg(test)]\nmod tests;\n\
                fn emit() { json!({\"type\": \"Real\"}) }\n\
                #[cfg(test)]\nmod inline { fn f() { json!({\"type\": \"FixtureOnly\"}); } }\n\
                fn more() { json!({\"type\": \"AfterTests\"}) }";
    let lib = Path::new("seance_plugin_x/src/lib.rs");
    let prod = production_text(lib, text).unwrap();
    let types = types_in(&prod);
    assert!(types.contains("Real"), "{types:?}");
    assert!(types.contains("AfterTests"), "{types:?}");
    assert!(!types.contains("FixtureOnly"), "{types:?}");
    for test_file in [
        "seance_plugin_x/src/tests.rs",
        "seance_plugin_x/src/emit_tests.rs",
        "seance_plugin_x/src/tests/fixtures.rs",
    ] {
        assert!(
            production_text(Path::new(test_file), text).is_none(),
            "{test_file}"
        );
    }
    let fixture = "#[cfg(test)]\nmod fixtures;";
    assert!(
        test_module_files(lib, fixture).contains(&PathBuf::from("seance_plugin_x/src/fixtures.rs"))
    );
}

/// A marker that needs a field value (`platform: android`, `source:
/// packages.xml`, ...) must have that key and every accepted value written as
/// literals in a production file that also emits the type. A value that drifts
/// from what the parser writes would match nothing, and every source it should
/// label would read as holding no marker.
#[test]
fn every_marker_field_value_is_written_beside_its_type_in_production_code() {
    let files = emitting_files();
    let mut missing = Vec::new();
    for m in MARKERS {
        let Some((key, values)) = m.field else {
            continue;
        };
        for value in values {
            let found = files.iter().any(|(_, types, text)| {
                types.contains(m.record_type)
                    && text.contains(&format!("\"{key}\""))
                    && text.contains(&format!("\"{value}\""))
            });
            if !found {
                missing.push(format!("{} {key}={value}", m.record_type));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "marker field values no production file writes beside the type: {missing:?}"
    );
}

#[test]
fn every_marker_type_in_the_vocabulary_is_a_type_some_plugin_in_this_tree_emits() {
    let emitted = emitted_types();
    // The walk itself must see known emissions, or an empty set would pass
    // nothing and fail everything for the wrong reason.
    assert!(
        emitted.contains("InstalledApp"),
        "the emitted-type walk is broken"
    );
    let missing: Vec<&str> = MARKERS
        .iter()
        .map(|m| m.record_type)
        .chain(UNREAD_STORE_TYPES.iter().copied())
        .filter(|t| !emitted.contains(*t))
        .collect();
    assert!(
        missing.is_empty(),
        "marker types no plugin emits as `type`: {missing:?}"
    );
}
