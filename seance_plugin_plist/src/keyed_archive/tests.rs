//! What resolution must recover, and what it must refuse to rearrange.

use super::*;
use plist::{Uid, Value};

/// Build an archive: `$objects` plus a `$top` pointing at one of them.
fn archive(objects: Vec<Value>, root: u64) -> Dictionary {
    let mut top = Dictionary::new();
    top.insert("root".into(), Value::Uid(Uid::new(root)));

    let mut dict = Dictionary::new();
    dict.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
    dict.insert("$version".into(), Value::Integer(100_000.into()));
    dict.insert("$objects".into(), Value::Array(objects));
    dict.insert("$top".into(), Value::Dictionary(top));
    dict
}

fn dict(pairs: &[(&str, Value)]) -> Value {
    let mut d = Dictionary::new();
    for (k, v) in pairs {
        d.insert((*k).into(), v.clone());
    }
    Value::Dictionary(d)
}

// ── recognition ────────────────────────────────────────────────────────────

/// All three parts are required. A plist that merely has a `$objects` key is
/// not an archive, and rearranging it would restructure a file that was already
/// in the form its author intended.
#[test]
fn only_a_real_archive_is_treated_as_one() {
    assert!(is_keyed_archive(&archive(
        vec![Value::String("$null".into())],
        0
    )));

    let mut no_archiver = archive(vec![Value::String("$null".into())], 0);
    no_archiver.remove("$archiver");
    assert!(!is_keyed_archive(&no_archiver));
    assert!(resolve(&no_archiver).is_none());

    let mut no_top = archive(vec![Value::String("$null".into())], 0);
    no_top.remove("$top");
    assert!(!is_keyed_archive(&no_top));

    // A different archiver is not this format.
    let mut other = archive(vec![Value::String("$null".into())], 0);
    other.insert(
        "$archiver".into(),
        Value::String("NSKeyedUnarchiver".into()),
    );
    assert!(!is_keyed_archive(&other));

    // An ordinary preferences plist that happens to use the key.
    let mut ordinary = Dictionary::new();
    ordinary.insert("$objects".into(), Value::Array(vec![]));
    assert!(!is_keyed_archive(&ordinary));
    assert!(resolve(&ordinary).is_none());
}

// ── resolution ─────────────────────────────────────────────────────────────

/// **The point of the module.** Unresolved, this file is a numbered list of
/// fragments and a `UID(2)` string; the fact that *this* account owns *this*
/// URL is only in the references.
#[test]
fn a_reference_graph_becomes_the_structure_it_encodes() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[
            ("account", Value::Uid(Uid::new(2))),
            ("url", Value::Uid(Uid::new(3))),
        ]),
        Value::String("alice@example.com".into()),
        Value::String("https://example.com/report.pdf".into()),
    ];
    let resolved = resolve(&archive(objects, 1)).expect("a real archive");

    assert_eq!(resolved["resolved_from"], json!("NSKeyedArchiver"));
    assert_eq!(resolved["object_count"], json!(4));
    let root = &resolved["root"]["root"];
    assert_eq!(root["account"], json!("alice@example.com"));
    assert_eq!(
        root["url"],
        json!("https://example.com/report.pdf"),
        "the URL and the account it belongs to are joined only by the references"
    );
}

/// Index 0 is conventionally the string `$null`, which is how the format spells
/// an absent object. Rendering it as the literal text would put the string
/// "$null" into a report where a value was simply not set.
#[test]
fn the_null_object_becomes_a_null_and_not_the_word() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[("optional", Value::Uid(Uid::new(0)))]),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    assert_eq!(
        resolved["root"]["root"]["optional"],
        serde_json::Value::Null
    );
}

/// `$class` names the archived type. Knowing a dictionary was an NSURL rather
/// than an NSString is frequently the point, so it is followed like any other
/// reference.
#[test]
fn the_class_reference_is_resolved_too() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[
            ("NS.relative", Value::Uid(Uid::new(2))),
            ("$class", Value::Uid(Uid::new(3))),
        ]),
        Value::String("file:///Users/alice/report.pdf".into()),
        dict(&[("$classname", Value::String("NSURL".into()))]),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    let root = &resolved["root"]["root"];
    assert_eq!(root["NS.relative"], json!("file:///Users/alice/report.pdf"));
    assert_eq!(
        root["$class"]["$classname"],
        json!("NSURL"),
        "the archived type must survive resolution"
    );
}

#[test]
fn an_array_of_references_resolves_element_by_element() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[(
            "NS.objects",
            Value::Array(vec![
                Value::Uid(Uid::new(2)),
                Value::Uid(Uid::new(3)),
                Value::Uid(Uid::new(0)),
            ]),
        )]),
        Value::String("first".into()),
        Value::String("second".into()),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    assert_eq!(
        resolved["root"]["root"]["NS.objects"],
        json!(["first", "second", serde_json::Value::Null])
    );
}

// ── the awkward cases ──────────────────────────────────────────────────────

/// **Object graphs are graphs.** A parent referencing a child that references
/// the parent is ordinary, and following it naively does not terminate.
#[test]
fn a_cycle_terminates_and_says_where_it_closed() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[
            ("name", Value::Uid(Uid::new(3))),
            ("child", Value::Uid(Uid::new(2))),
        ]),
        dict(&[("parent", Value::Uid(Uid::new(1)))]),
        Value::String("the parent".into()),
    ];
    let resolved = resolve(&archive(objects, 1)).expect("must not hang");

    let root = &resolved["root"]["root"];
    assert_eq!(root["name"], json!("the parent"));
    assert_eq!(
        root["child"]["parent"],
        json!({ "$cycle_to_object": 1 }),
        "the loop must be named where it closes, so the shape survives"
    );
}

/// The same object referenced twice on *different* paths is not a cycle, and
/// must resolve both times. Confusing the two would drop real data.
#[test]
fn an_object_referenced_twice_on_different_paths_resolves_both_times() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[
            ("from", Value::Uid(Uid::new(2))),
            ("to", Value::Uid(Uid::new(2))),
        ]),
        Value::String("shared@example.com".into()),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    let root = &resolved["root"]["root"];
    assert_eq!(root["from"], json!("shared@example.com"));
    assert_eq!(
        root["to"],
        json!("shared@example.com"),
        "a shared object is not a cycle and must not be elided"
    );
}

/// A reference outside the array is a fact about the file. Reporting it as an
/// absent value would hide damage that an examiner needs to know about.
#[test]
fn a_dangling_reference_is_reported_rather_than_silently_dropped() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[("missing", Value::Uid(Uid::new(99)))]),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    assert_eq!(
        resolved["root"]["root"]["missing"],
        json!({ "$dangling_reference": 99 }),
        "a reference to an object that is not there must be visible, not read as null"
    );
}

/// Nesting is bounded, and the bound is disclosed rather than silently applied.
#[test]
fn deep_nesting_stops_and_says_that_it_did() {
    // A chain of dictionaries, each referring to the next, longer than the cap.
    let mut objects = vec![Value::String("$null".into())];
    let depth = MAX_DEPTH + 20;
    for i in 1..=depth {
        let next = if i == depth { 0 } else { i + 1 };
        objects.push(dict(&[("next", Value::Uid(Uid::new(next as u64)))]));
    }
    let resolved = resolve(&archive(objects, 1)).expect("must not overflow the stack");
    assert_eq!(
        resolved["truncated"],
        json!(true),
        "a walk that stopped short must say so; a reader cannot tell a bounded \
         graph from a complete one by looking at it"
    );
}

/// Values that are not references pass through unchanged. Resolution rebuilds
/// structure; it must not reinterpret data.
#[test]
fn ordinary_values_are_not_altered_by_resolution() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[
            ("count", Value::Integer(42.into())),
            ("enabled", Value::Boolean(true)),
            ("ratio", Value::Real(0.5)),
        ]),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    let root = &resolved["root"]["root"];
    assert_eq!(root["count"], json!(42));
    assert_eq!(root["enabled"], json!(true));
    assert_eq!(root["ratio"], json!(0.5));
}

/// HUNT-112. A graph where many parents share the same children is not deep,
/// does not cycle, and resolves within the resolution count — and inlining it
/// produces an output exponentially larger than the file. A `.nib` is exactly
/// that shape, and a folder of them ran the server to 28 GB resident and out of
/// memory.
#[test]
fn a_shared_subgraph_cannot_inflate_the_output_without_bound() {
    // Ten levels, each object holding four references to the level below: 4^10
    // paths through eleven objects.
    let mut objects = vec![Value::String("$null".into())];
    let levels = 10;
    for level in 0..levels {
        let child = (level + 2) as u64;
        let child = if level + 1 == levels { 0 } else { child };
        objects.push(dict(&[
            ("a", Value::Uid(Uid::new(child))),
            ("b", Value::Uid(Uid::new(child))),
            ("c", Value::Uid(Uid::new(child))),
            ("d", Value::Uid(Uid::new(child))),
        ]));
    }
    let resolved = resolve(&archive(objects, 1)).expect("an archive");
    let rendered = serde_json::to_string(&resolved).expect("serialisable");
    assert!(
        rendered.len() < 4 * 1024 * 1024,
        "the resolved form must stay bounded; it was {} bytes",
        rendered.len()
    );
    assert_eq!(
        resolved["truncated"],
        json!(true),
        "a walk that stopped short must say so"
    );
    assert!(
        resolved["truncation_reason"].is_string(),
        "and must say which bound it hit"
    );
}

/// The bound that catches an archive whose *output* is large without its walk
/// being long: a few references to an object holding a great many values.
#[test]
fn an_archive_whose_resolved_form_would_not_fit_stops_and_says_so() {
    let big: Vec<Value> = (0..20_000).map(|n| Value::Integer(n.into())).collect();
    let mut objects = vec![Value::String("$null".into())];
    // One parent holding fifty references to the same large array.
    let refs: Vec<(&str, Value)> = Vec::new();
    let mut parent = Dictionary::new();
    for i in 0..50 {
        parent.insert(format!("ref{i}"), Value::Uid(Uid::new(2)));
    }
    let _ = refs;
    objects.push(Value::Dictionary(parent));
    objects.push(Value::Array(big));

    let resolved = resolve(&archive(objects, 1)).expect("an archive");
    assert_eq!(resolved["truncated"], json!(true));
    assert_eq!(
        resolved["truncation_reason"],
        json!("output size"),
        "fifty references is nowhere near the resolution bound; the size is what stopped it"
    );
    let rendered = serde_json::to_string(&resolved).expect("serialisable");
    assert!(
        rendered.len() < 8 * 1024 * 1024,
        "the resolved form must stay bounded; it was {} bytes",
        rendered.len()
    );
}

/// The bound must not fire on an ordinary archive: a resolved login-items list
/// is complete and says so.
#[test]
fn an_ordinary_archive_is_not_reported_as_truncated() {
    let objects = vec![
        Value::String("$null".into()),
        dict(&[("name", Value::Uid(Uid::new(2)))]),
        Value::String("Ada".into()),
    ];
    let resolved = resolve(&archive(objects, 1)).unwrap();
    assert_eq!(resolved["truncated"], json!(false));
    assert_eq!(resolved["truncation_reason"], serde_json::Value::Null);
}

/// HUNT-114. When the output budget is reached inside a container, the walk of
/// that container stops rather than visiting every remaining sibling and
/// emitting a truncation marker for each. A million-element array past the
/// budget yielded a million markers — the very output the budget exists to
/// bound — and on a folder of 34,000 property lists those markers were most of
/// a ten-gigabyte resident set. The resolved form must stay small.
#[test]
fn a_container_past_the_budget_stops_instead_of_marking_every_sibling() {
    // One enormous array of strings, well past the node budget.
    let big: Vec<Value> = (0..1_000_000)
        .map(|i| Value::String(format!("s{i}")))
        .collect();
    let objects = vec![Value::String("$null".into()), Value::Array(big)];

    let resolved = resolve(&archive(objects, 1)).expect("an archive");
    assert_eq!(resolved["truncated"], json!(true));
    assert_eq!(resolved["truncation_reason"], json!("output size"));

    let rendered = serde_json::to_string(&resolved["keyed_archive"]).expect("serialisable");
    assert!(
        rendered.len() < 1024 * 1024,
        "a truncated array must not render a marker per element; it was {} bytes",
        rendered.len()
    );
}

/// `HUNT-114` residual. `MAX_NODES` and `MAX_RESOLUTIONS` bound how many
/// values the walk visits, not how large any one of them is. A single big
/// string shared by many different objects — the same shape as the class-name
/// and key strings a real `.nib` reuses everywhere — is visited many times
/// (each reference is a distinct resolution on a distinct path, not a cycle),
/// and every visit clones the full string into the transient tree. Five
/// thousand references to one 2 MiB string is ~10 GB inlined, while the walk
/// itself is nowhere near the node or resolution ceiling: the old code had
/// nothing left to stop it.
#[test]
fn a_shared_large_leaf_cannot_inflate_transient_bytes_without_bound() {
    // One 2 MiB string, referenced from 5,000 distinct sibling positions.
    // 5,000 * 2 MiB = ~10 GB if each reference inlined its own copy — the
    // "OLD code" case this test exists to make impossible to reach.
    const LEAF_MIB: usize = 2 * 1024 * 1024;
    const REFERENCES: usize = 5_000;

    let mut objects = vec![
        Value::String("$null".into()),
        Value::String("x".repeat(LEAF_MIB)),
    ];
    let root_array: Vec<Value> = (0..REFERENCES).map(|_| Value::Uid(Uid::new(1))).collect();
    objects.push(Value::Array(root_array));

    let resolved = resolve(&archive(objects, 2)).expect("an archive");

    assert_eq!(
        resolved["truncated"],
        json!(true),
        "a walk that would have inlined ~10 GB must stop and say so"
    );
    assert_eq!(
        resolved["truncation_reason"],
        json!("transient bytes"),
        "the node and resolution counts here are both tiny; only a byte bound catches this"
    );

    // The bound must actually have held: the resolved form — the transient
    // tree this test exists to keep small — stays a small, fixed multiple of
    // the ceiling, not gigabytes.
    let rendered = serde_json::to_string(&resolved["root"]).expect("serialisable");
    assert!(
        rendered.len() < 16 * 1024 * 1024,
        "the transient tree must stay bounded; the serialised form was {} bytes",
        rendered.len()
    );
}

/// The bound above must not fire on an ordinary archive. Real archives carry
/// a handful of distinct, moderately sized strings (URLs, paths, names) with
/// little or no sharing — nothing like the pathological case above — and must
/// resolve exactly as before: fully, and marked complete.
#[test]
fn an_ordinary_archive_with_several_distinct_strings_resolves_in_full() {
    fn text_for(i: u64) -> String {
        format!("{i}-").repeat(10 * 1024 / 2)
    }

    // Index 0 is "$null"; indices 1..=10 are ten distinct 10 KB strings
    // (representative of real archive text: paths, URLs, names), and index 11
    // is the dictionary referencing all ten — put last so none of its UIDs
    // shift as the strings are appended.
    let mut objects = vec![Value::String("$null".into())];
    let mut fields = Dictionary::new();
    for i in 0..10u64 {
        let idx = objects.len() as u64;
        objects.push(Value::String(text_for(i)));
        fields.insert(format!("field{i}"), Value::Uid(Uid::new(idx)));
    }
    objects.push(Value::Dictionary(fields));
    let root = (objects.len() - 1) as u64;

    let resolved = resolve(&archive(objects, root)).expect("an archive");

    assert_eq!(
        resolved["truncated"],
        json!(false),
        "an ordinary archive must not be reported as truncated"
    );
    assert_eq!(resolved["truncation_reason"], serde_json::Value::Null);
    for i in 0..10u64 {
        assert_eq!(
            resolved["root"]["root"][format!("field{i}")],
            json!(text_for(i)),
            "field{i} must resolve to its full string, unchanged"
        );
    }
}
