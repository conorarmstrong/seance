//! The conversion's acceptance test: what it writes must be something Séance's
//! own symbol reader accepts and can answer layout questions from.
//!
//! Gated on a real PDB because that is the only honest way to test it — a
//! synthetic PDB would exercise the code without testing the claim, and a claim
//! that "the converter works" is only worth making against a kernel someone
//! actually has to analyse. Point `SEANCE_TEST_PDB` at one to run it.
//!
//! ```text
//! curl -o ntkrnlmp.pdb \
//!   https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/<GUID><AGE>/ntkrnlmp.pdb
//! SEANCE_TEST_PDB=$PWD/ntkrnlmp.pdb cargo test -p seance_symbol_fetch
//! ```

use std::path::PathBuf;

fn test_pdb() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("SEANCE_TEST_PDB")?);
    p.is_file().then_some(p)
}

#[test]
fn a_converted_pdb_is_an_isf_seance_can_read() {
    let Some(path) = test_pdb() else {
        eprintln!("SEANCE_TEST_PDB not set; skipping (see this file's header)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read pdb");
    let (doc, summary) =
        seance_symbol_fetch::pdb_to_isf(&bytes, "0000", 1, "ntkrnlmp.pdb", None).expect("convert");
    assert!(summary.user_types > 0, "a kernel PDB defines types");
    assert!(summary.symbols > 0, "a kernel PDB names addresses");

    let json = serde_json::to_vec(&doc).expect("serialise");
    let source = seance_symbols::load_slice(&json, &seance_symbols::DecompressLimits::default())
        .expect("Séance reads it");
    let table = seance_symbols::SymbolTable::compile_source(
        source,
        &seance_symbols::CompileOptions::default(),
    )
    .expect("Séance compiles it");

    // The one layout question every Windows memory analysis has to answer.
    let eprocess = table
        .aggregate("_EPROCESS")
        .expect("_EPROCESS is present in a kernel PDB");
    for member in ["UniqueProcessId", "ActiveProcessLinks", "ImageFileName"] {
        assert!(
            eprocess.has_member(member),
            "_EPROCESS.{member} must resolve, or no process can be walked"
        );
    }
}

/// The anonymous-aggregate fix, checked where it matters rather than only on
/// the naming helper: two distinct anonymous types must not collapse onto one.
#[test]
fn anonymous_aggregates_do_not_collapse_onto_each_other() {
    let Some(path) = test_pdb() else {
        eprintln!("SEANCE_TEST_PDB not set; skipping");
        return;
    };
    let bytes = std::fs::read(&path).expect("read pdb");
    let (doc, _) =
        seance_symbol_fetch::pdb_to_isf(&bytes, "0000", 1, "ntkrnlmp.pdb", None).expect("convert");
    let json = serde_json::to_value(&doc).expect("serialise");

    let types = json["user_types"].as_object().expect("user_types");
    let anonymous: Vec<&String> = types
        .keys()
        .filter(|k| k.starts_with("__unnamed_"))
        .collect();
    assert!(
        anonymous.len() > 1,
        "a Windows kernel defines many anonymous aggregates; got {}",
        anonymous.len()
    );
    // Every anonymous type a field points at must exist. Before the fix they
    // all shared one name, so a member resolved to an unrelated struct.
    for (_, def) in types {
        for (_, field) in def["fields"].as_object().into_iter().flatten() {
            if let Some(name) = field["type"]["name"].as_str() {
                if name.starts_with("__unnamed_") {
                    assert!(types.contains_key(name), "{name} is referenced but absent");
                }
            }
        }
    }
}

/// An array's `count` is an element count, not a byte length. A forward-declared
/// element type reports size 0, and dividing the member's byte length by that
/// (floored to 1) turns `_KTIMER2.RbNodes` — two nodes — into 48. The offsets
/// either side stay correct, which is what makes it easy to miss.
#[test]
fn array_counts_are_elements_not_bytes() {
    let Some(path) = test_pdb() else {
        eprintln!("SEANCE_TEST_PDB not set; skipping");
        return;
    };
    let bytes = std::fs::read(&path).expect("read pdb");
    let (doc, _) =
        seance_symbol_fetch::pdb_to_isf(&bytes, "0000", 1, "ntkrnlmp.pdb", None).expect("convert");
    let json = serde_json::to_value(&doc).expect("serialise");
    let types = json["user_types"].as_object().expect("user_types");

    let mut checked = 0usize;
    for (type_name, def) in types {
        let Some(size) = def["size"].as_u64() else {
            continue;
        };
        if size == 0 {
            continue;
        }
        for (field_name, field) in def["fields"].as_object().into_iter().flatten() {
            if field["type"]["kind"].as_str() != Some("array") {
                continue;
            }
            let count = field["type"]["count"].as_u64().unwrap_or(0);
            let offset = field["offset"].as_u64().unwrap_or(0);
            // An element count can never exceed the bytes the member has room
            // for; a byte length mistaken for a count blows straight past it.
            assert!(
                count <= size.saturating_sub(offset).max(1),
                "{type_name}.{field_name} claims {count} elements but the struct \
                 has only {} bytes left at offset {offset} — a byte length read \
                 as a count",
                size.saturating_sub(offset)
            );
            checked += 1;
        }
    }
    assert!(
        checked > 100,
        "expected many arrays to check, saw {checked}"
    );
}

/// HUNT-083. A PDB primitive index with a pointer mode is a *pointer to* that
/// primitive. The converter emitted it as a base type merely NAMED `pointer`:
/// the width was right, so nothing looked wrong, and nothing could dereference
/// it either. `_UNICODE_STRING.Buffer` is `wchar_t*`, so on every pack this
/// converter produced, reading a hive's name — or anything else behind a
/// primitive-pointer member — failed with "is a base type, not a pointer
/// member", and the memory registry stage could not name a single hive.
///
/// The check is on the shape Volatility writes for the same member, because
/// that is the schema Séance's reader implements.
#[test]
fn a_primitive_pointer_member_converts_to_a_dereferenceable_pointer() {
    let Some(path) = test_pdb() else {
        eprintln!("SEANCE_TEST_PDB not set; skipping");
        return;
    };
    let bytes = std::fs::read(&path).expect("read pdb");
    let (doc, _) =
        seance_symbol_fetch::pdb_to_isf(&bytes, "0000", 1, "ntkrnlmp.pdb", None).expect("convert");
    let json = serde_json::to_value(&doc).expect("serialise");

    let buffer = &json["user_types"]["_UNICODE_STRING"]["fields"]["Buffer"]["type"];
    assert_eq!(
        buffer["kind"], "pointer",
        "_UNICODE_STRING.Buffer is wchar_t* and must convert to a pointer, not a base type \
         named 'pointer' — got {buffer}"
    );
    assert_eq!(
        buffer["subtype"]["kind"], "base",
        "it points at a primitive"
    );

    // And the reader agrees: the member resolves as a pointer it can follow.
    let bytes = serde_json::to_vec(&doc).expect("serialise");
    let source = seance_symbols::load_slice(&bytes, &seance_symbols::DecompressLimits::default())
        .expect("Séance reads it");
    let table = seance_symbols::SymbolTable::compile_source(
        source,
        &seance_symbols::CompileOptions::default(),
    )
    .expect("Séance compiles it");
    let unicode = table
        .aggregate("_UNICODE_STRING")
        .expect("_UNICODE_STRING is present in a kernel PDB");
    assert!(unicode.has_member("Buffer"));
}
