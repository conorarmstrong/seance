//! `INDEX.BTR` (HUNT-195): the index tree walked from its root.
//!
//! Two kinds of test, kept apart. The `synthetic_*` tests build a tiny index
//! in the test, from the layout in `wmi_index.rs`, and pin the mechanism only;
//! they are not evidence about any real repository. The `*_oracle` and
//! `*_repository_*` tests read four real repositories when their directories
//! are named (`SEANCE_FLARE_WMI_DIR`, `SEANCE_PERSEVERANCE_OBJECTS_DATA`; see
//! `documentation/VALIDATION.md` `WMI-4`) and compare against
//! `tests/fixtures/wmi/index_answer_key.json`, which
//! `independent_index_decoder.py` wrote and `dissect.cim` 3.13 confirmed.

use crate::wmi::scan_with_mapping;
use crate::wmi_index::{indexed_records, INDEX_PAGE, INDEX_SIGNATURE};
use crate::wmi_mapping::{choose_active, parse_mapping, Mapping, MappingForm, PageMap, UNMAPPED};
use crate::AsepEnumerator;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

// --- synthetic: the mechanism ------------------------------------------------

/// One synthetic index page: `own` logical number, `children` (one more than
/// `keys`), one single-part key per string.
fn page(own: u32, children: &[u32], keys: &[&str]) -> Vec<u8> {
    assert_eq!(children.len(), keys.len() + 1);
    let n = keys.len();
    let mut p = vec![0u8; INDEX_PAGE];
    let mut at = 0usize;
    let put32 = |p: &mut Vec<u8>, v: u32, at: &mut usize| {
        p[*at..*at + 4].copy_from_slice(&v.to_le_bytes());
        *at += 4;
    };
    put32(&mut p, INDEX_SIGNATURE, &mut at);
    put32(&mut p, own, &mut at);
    put32(&mut p, 0, &mut at);
    put32(&mut p, 0, &mut at);
    put32(&mut p, n as u32, &mut at);
    for _ in 0..n {
        put32(&mut p, 0, &mut at);
    }
    for &c in children {
        put32(&mut p, c, &mut at);
    }
    let put16 = |p: &mut Vec<u8>, v: usize, at: &mut usize| {
        p[*at..*at + 2].copy_from_slice(&(v as u16).to_le_bytes());
        *at += 2;
    };
    for k in 0..n {
        put16(&mut p, 2 * k, &mut at); // key k starts at table slot 2k
    }
    put16(&mut p, 2 * n, &mut at);
    for k in 0..n {
        put16(&mut p, 1, &mut at); // one part
        put16(&mut p, k, &mut at); // string k
    }
    put16(&mut p, n, &mut at);
    let mut off = 0usize;
    let mut offsets = Vec::new();
    for k in keys {
        offsets.push(off);
        off += k.len() + 1;
    }
    offsets.push(off);
    for o in offsets {
        put16(&mut p, o, &mut at);
    }
    for k in keys {
        p[at..at + k.len()].copy_from_slice(k.as_bytes());
        at += k.len() + 1;
    }
    p
}

/// A mapping whose logical page `l` is physical page `l - 1` (logical 0 unused).
fn map_of(logical_pages: usize, root: u32) -> PageMap {
    let mut logical = vec![UNMAPPED];
    logical.extend((0..logical_pages as u32 - 1).collect::<Vec<_>>());
    PageMap {
        sequence: 1,
        physical_pages: logical_pages as u32 - 1,
        logical,
        free: Vec::new(),
        first_entry_aux: root,
        root_in_page_zero: false,
    }
}

fn file_of(pages: &[Vec<u8>]) -> Vec<u8> {
    pages.concat()
}

#[test]
fn synthetic_tree_collects_reachable_references_and_ignores_a_mapped_orphan() {
    // Root (logical 1) holds two keys, one a reference, and child 2; page 2
    // holds one reference; page 3 is mapped, holds a reference and is reached
    // by nobody.
    let idx = file_of(&[
        page(1, &[2, 0, 0], &["NS_a/CD_x.5.100.200", "NS_a/plain"]),
        page(2, &[0, 0], &["NS_a/I_y.7.8.9"]),
        page(3, &[0, 0], &["NS_a/I_z.1.2.3"]),
    ]);
    let set = indexed_records(&idx, &map_of(4, 1)).expect("a well-formed tree");
    let want: HashSet<_> = [(5, 100, 200), (7, 8, 9)].into_iter().collect();
    assert_eq!(
        set.refs, want,
        "the orphan page's reference must not be named"
    );
    assert_eq!(set.pages_visited, 2);
    assert_eq!(set.keys_total, 3);
}

/// A Windows 11 index file ends before the mapping's physical page count: the last pages are on the
/// free list, and the file was never extended to hold them (`HUNT-195`, the lab repository: 643 pages
/// held, 645 accounted for, pages 643 and 644 free). That is not a mismatch about the tree.
#[test]
fn synthetic_trailing_free_pages_missing_from_the_file_do_not_refuse_the_index() {
    let idx = file_of(&[
        page(1, &[0, 0], &["NS_a/CD_x.5.100.200"]),
        page(2, &[0], &[]),
    ]);
    let mut map = map_of(3, 1);
    map.physical_pages = 4; // the file holds 2 pages; physical pages 2 and 3 are accounted for
    map.free = vec![3, 2];
    let set = indexed_records(&idx, &map).expect("trailing free pages need not be in the file");
    assert_eq!(set.refs, [(5, 100, 200)].into_iter().collect());
}

/// The same shortfall where a page the mapping puts a logical page on is not in the file is a
/// truncated index, and is refused.
#[test]
fn synthetic_a_mapped_page_missing_from_the_file_still_refuses_the_index() {
    let idx = file_of(&[page(1, &[0, 0], &["NS_a/CD_x.5.100.200"])]);
    let mut map = map_of(3, 1);
    map.physical_pages = 2; // logical 2 is mapped to physical page 1, past the 1-page file
    let err = indexed_records(&idx, &map).unwrap_err();
    assert!(err.contains("physical pages"), "{err}");
}

/// A file longer than the mapping accounts for is refused too.
#[test]
fn synthetic_a_file_longer_than_the_mapping_accounts_for_is_refused() {
    let idx = file_of(&[page(1, &[0], &[]), page(2, &[0], &[])]);
    let mut map = map_of(2, 1);
    map.physical_pages = 1;
    assert!(indexed_records(&idx, &map).is_err());
}

#[test]
fn synthetic_cycle_is_refused() {
    let idx = file_of(&[
        page(1, &[2, 0], &["a.1.2.3"]),
        page(2, &[1, 0], &["b.4.5.6"]),
    ]);
    let why = indexed_records(&idx, &map_of(3, 1)).unwrap_err();
    assert!(why.contains("reached twice"), "{why}");
}

#[test]
fn synthetic_overlarge_key_count_is_refused_before_allocating() {
    let mut idx = file_of(&[page(1, &[0, 0], &["a.1.2.3"])]);
    idx[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    let why = indexed_records(&idx, &map_of(2, 1)).unwrap_err();
    assert!(why.contains("more than a page holds"), "{why}");
}

#[test]
fn synthetic_truncated_page_is_refused() {
    let mut idx = file_of(&[page(1, &[0, 0], &["a.1.2.3"])]);
    // A count that fits the page's size cap but runs the child list off its end.
    idx[16..20].copy_from_slice(&800u32.to_le_bytes());
    let why = indexed_records(&idx, &map_of(2, 1)).unwrap_err();
    assert!(why.contains("truncated") || why.contains("past"), "{why}");
}

#[test]
fn synthetic_bad_signature_is_refused() {
    let mut idx = file_of(&[page(1, &[0, 0], &["a.1.2.3"])]);
    idx[0] = 0;
    let why = indexed_records(&idx, &map_of(2, 1)).unwrap_err();
    assert!(why.contains("signature"), "{why}");
}

#[test]
fn synthetic_page_that_names_another_logical_number_is_refused() {
    let idx = file_of(&[page(9, &[0, 0], &["a.1.2.3"])]);
    let why = indexed_records(&idx, &map_of(2, 1)).unwrap_err();
    assert!(why.contains("names itself"), "{why}");
}

#[test]
fn synthetic_child_that_is_not_mapped_is_refused() {
    let idx = file_of(&[page(1, &[3, 0], &["a.1.2.3"])]);
    let why = indexed_records(&idx, &map_of(2, 1)).unwrap_err();
    assert!(why.contains("not mapped"), "{why}");
}

#[test]
fn synthetic_file_that_does_not_match_the_mapping_is_refused() {
    let idx = file_of(&[page(1, &[0, 0], &["a.1.2.3"])]);
    let why = indexed_records(&idx, &map_of(3, 1)).unwrap_err();
    assert!(why.contains("physical pages"), "{why}");
}

// --- real repositories, when named -------------------------------------------

struct Repo {
    key: &'static str,
    dir: PathBuf,
}

fn repos() -> Option<Vec<Repo>> {
    let flare = seance_core::test_support::corpus::dir("SEANCE_FLARE_WMI_DIR");
    let pers = seance_core::test_support::corpus::path("SEANCE_PERSEVERANCE_OBJECTS_DATA");
    let mut out = Vec::new();
    if let Some(f) = flare {
        for (key, name) in [
            ("flare_deleted_instance", "deleted-instance"),
            ("flare_overwritten_instance", "overwritten-instance"),
            ("flare_wmikatz", "wmikatz"),
        ] {
            out.push(Repo {
                key,
                dir: f.join("win7").join(name),
            });
        }
    }
    if let Some(p) = pers {
        out.push(Repo {
            key: "perseverance",
            dir: p.parent().expect("a file in a directory").to_path_buf(),
        });
    }
    (!out.is_empty()).then_some(out)
}

fn answer_key() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/wmi/index_answer_key.json"))
        .expect("the answer key parses")
}

fn active_mapping(dir: &Path) -> Mapping {
    let candidates: Vec<Result<Mapping, String>> = ["MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"]
        .iter()
        .map(|n| {
            let b = std::fs::read(dir.join(n)).expect("read a mapping file");
            parse_mapping(&b, MappingForm::Vista)
        })
        .collect();
    let i = choose_active(&candidates).expect("a well-formed mapping");
    candidates[i].clone().unwrap()
}

fn triple(v: &Value) -> (u32, u32, u32) {
    let a = v.as_array().expect("a triple");
    (
        a[0].as_u64().unwrap() as u32,
        a[1].as_u64().unwrap() as u32,
        a[2].as_u64().unwrap() as u32,
    )
}

/// The index walked from its root names exactly the references the independent
/// decoder (and `dissect.cim`) found, and the descriptor-listed records it does
/// not name are exactly the answer key's: 4, 4, 4 and 23.
#[test]
fn the_index_of_each_real_repository_matches_the_independent_decoder() {
    let Some(repos) = repos() else { return };
    let key = answer_key();
    for repo in repos {
        let want = &key[repo.key];
        let m = active_mapping(&repo.dir);
        assert_eq!(
            m.sequence as u64,
            want["sequence"].as_u64().unwrap(),
            "{}",
            repo.key
        );
        let idx_map = m
            .index
            .as_ref()
            .expect("a Vista mapping has an index section");
        assert_eq!(
            idx_map.first_entry_aux as u64,
            want["index_root_logical_page"].as_u64().unwrap(),
            "{} root",
            repo.key
        );
        let idx = std::fs::read(repo.dir.join("INDEX.BTR")).expect("read INDEX.BTR");
        let set = indexed_records(&idx, idx_map).unwrap_or_else(|e| panic!("{}: {e}", repo.key));
        assert_eq!(
            set.refs.len() as u64,
            want["index_data_references"].as_u64().unwrap(),
            "{} references",
            repo.key
        );
        assert_eq!(
            set.pages_visited as u64,
            want["index_pages_visited"].as_u64().unwrap(),
            "{} pages",
            repo.key
        );

        let obj = std::fs::read(repo.dir.join("OBJECTS.DATA")).expect("read OBJECTS.DATA");
        let out = scan_with_mapping(&obj, Some(&m.objects));
        let listed: HashSet<_> = out.listed_descriptors.iter().copied().collect();
        assert_eq!(
            listed.len() as u64,
            want["descriptors_listed"].as_u64().unwrap(),
            "{} descriptors",
            repo.key
        );
        let mut unindexed: Vec<_> = listed.difference(&set.refs).copied().collect();
        unindexed.sort();
        let mut expected: Vec<_> = want["listed_not_indexed"]
            .as_array()
            .unwrap()
            .iter()
            .map(triple)
            .collect();
        expected.sort();
        assert_eq!(unindexed, expected, "{} listed but not indexed", repo.key);
        assert!(
            set.refs.is_subset(&listed),
            "{}: the index names a record no descriptor lists",
            repo.key
        );
    }
}

/// `HUNT-195`: what the descriptors the index does not name are. In the three Flare repositories (four each) and
/// the Perseverance one (23), read from the bytes the descriptor points at, every one of them reads as a class
/// definition of a system class (`__Provider`, `__Win32Provider`, `__IndicationRelated`, a provider-registration
/// class, `__NamespaceOperationEvent`, `__PARAMETERS`): each holds a system-class name (a `__` name) or the CIM
/// type names a definition declares and an instance does not (`string`, `boolean`, `sint32`, `uint32`,
/// `uint64`, `datetime`, `object:`), the rest of its strings are property names and qualifiers (`abstract`,
/// `SUBTYPE`, `singleton`), and none names a subscription class. So the "listed but not indexed" state seen on real repositories belongs to class definitions, not to
/// subscription records. This is a reading of the strings, not a decode of the record header.
#[test]
fn the_descriptors_the_index_does_not_name_are_system_class_definitions() {
    let Some(repos) = repos() else { return };
    let key = answer_key();
    let subscription = [
        "__EventFilter",
        "__FilterToConsumerBinding",
        "CommandLineEventConsumer",
        "ActiveScriptEventConsumer",
        "NTEventLogEventConsumer",
        "SMTPEventConsumer",
        "LogFileEventConsumer",
    ];
    let word = |buf: &[u8], at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
    for repo in repos {
        let obj = std::fs::read(repo.dir.join("OBJECTS.DATA")).expect("read OBJECTS.DATA");
        for t in key[repo.key]["listed_not_indexed"].as_array().unwrap() {
            let (_, id, size) = triple(t);
            let mut offset = None;
            'pages: for page in 0..obj.len() / crate::wmi::PAGE_SIZE {
                for i in 0..crate::wmi::PAGE_SIZE / 16 {
                    let at = page * crate::wmi::PAGE_SIZE + i * 16;
                    if word(&obj, at) == 0 && word(&obj, at + 4) == 0 && word(&obj, at + 8) == 0 {
                        break;
                    }
                    if word(&obj, at) == id && word(&obj, at + 8) == size && word(&obj, at + 4) != 0
                    {
                        offset = Some(word(&obj, at + 4) as usize);
                        break 'pages;
                    }
                }
            }
            let offset =
                offset.unwrap_or_else(|| panic!("{}: no descriptor {id}/{size}", repo.key));
            let record = &obj[offset..(offset + size as usize).min(obj.len())];
            // Names are ASCII in these records (the strings of a class definition are stored as bytes).
            let text = String::from_utf8_lossy(record).to_string();
            assert!(
                text.contains("__")
                    || ["string", "boolean", "sint32", "uint32", "uint64", "datetime", "object:"]
                        .iter()
                        .any(|ty| text.contains(ty)),
                "{}: {id}/{size} names no system class and declares no CIM type, so it does not read as a class definition",
                repo.key
            );
            for name in subscription {
                assert!(
                    !text.contains(name),
                    "{}: {id}/{size} names the subscription class {name}",
                    repo.key
                );
            }
        }
    }
}

fn run(dir: &Path) -> Vec<Artifact> {
    let ds = FileDataSource::new(dir.join("OBJECTS.DATA")).expect("open OBJECTS.DATA");
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    AsepEnumerator::new().process(&art).expect("process")
}

fn of_type<'a>(produced: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    produced
        .iter()
        .filter(|a| {
            a.metadata.get("type").and_then(Value::as_str) == Some(ty)
                || (ty == "AsepEntry"
                    && a.metadata.get("type").and_then(Value::as_str) == Some("RecoveredAsepEntry"))
        })
        .collect()
}

/// End to end on the real files: every subscription record each repository
/// holds is named by its index, and the coverage record says the index was
/// read, with the numbers the independent decoder gave.
#[test]
fn every_subscription_record_in_the_real_repositories_is_named_by_the_index() {
    let Some(repos) = repos() else { return };
    let key = answer_key();
    for repo in repos {
        let produced = run(&repo.dir);
        let cov = of_type(&produced, "AsepCoverage");
        assert_eq!(cov.len(), 1);
        let scan = &cov[0].metadata["wmi_scan"];
        let want = &key[repo.key];
        assert_eq!(scan["index_read"], json!(true), "{} {scan}", repo.key);
        assert_eq!(scan["index_walked"], json!(true));
        assert_eq!(
            scan["index_data_references"], want["index_data_references"],
            "{}",
            repo.key
        );
        assert_eq!(
            scan["descriptors_listed_not_indexed"],
            json!(want["listed_not_indexed"].as_array().unwrap().len()),
            "{}",
            repo.key
        );
        // None of the 4 / 23 unindexed descriptors is a subscription-class
        // record in these four repositories, so none is listed-not-indexed.
        assert_eq!(
            scan["records_listed_not_indexed"],
            json!(0),
            "{} {scan}",
            repo.key
        );
        let decoded = scan["records_decoded"].as_u64().unwrap();
        assert!(decoded > 0, "{} holds subscription records", repo.key);
        let rows = of_type(&produced, "AsepEntry");
        assert_eq!(rows.len() as u64, scan["records_matched"].as_u64().unwrap());
        // A record in a page the mapping drops is a superseded copy (the
        // Flare "deleted" and "overwritten" repositories hold such copies);
        // every other record sits in a mapped page and must be named by the index.
        let mut indexed = 0u64;
        for row in &rows {
            let liveness = row.metadata["repository_liveness"].as_str().unwrap();
            if liveness == "superseded_page" {
                assert_eq!(row.metadata["record_indexed"], Value::Null);
                continue;
            }
            assert_eq!(
                liveness, "indexed",
                "{} {}",
                repo.key, row.metadata["entry_name"]
            );
            assert_eq!(row.metadata["record_indexed"], json!(true));
            assert!(
                row.metadata["scan_basis"]
                    .as_str()
                    .unwrap()
                    .contains("walked from its root"),
                "{}",
                row.metadata["scan_basis"]
            );
            indexed += 1;
        }
        assert_eq!(
            scan["records_indexed"].as_u64().unwrap(),
            indexed,
            "{}",
            repo.key
        );
        if repo.key.starts_with("flare") {
            for name in ["BVTConsumer", "BVTFilter"] {
                assert!(
                    rows.iter().any(|r| r.metadata["entry_name"] == name
                        && r.metadata["repository_liveness"] == "indexed"),
                    "{}: {name} is among the indexed records",
                    repo.key
                );
            }
        } else {
            // WMI-3: the attacker's filter, two bindings and consumer.
            assert!(rows
                .iter()
                .any(|r| r.metadata["entry_name"] == "Windows Update"
                    && r.metadata["wmi_record_class"] == "CommandLineEventConsumer"
                    && r.metadata["repository_liveness"] == "indexed"));
            assert_eq!(decoded, 6);
            assert_eq!(indexed, 6);
        }
    }
}

/// `HUNT-195` / `WMI-7`: a second decoder graded the Windows 11 repository. python-cim 1.1 (flare-wmi, a
/// different parser of the same format; `scripts/oracle/wmi_cim_instances.py`) walks the repository by
/// class and lists the instances of the event-subscription classes: 4 filters, 3 consumers and 3 bindings.
/// The product's index walk names the same ten records, with the same names and the same filter and
/// consumer in each binding, and no record the other decoder does not list is indexed.
#[test]
fn the_windows_11_repository_agrees_with_a_second_decoder_on_every_subscription_record() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_WIN11_WMI_DIR") else {
        return;
    };
    let produced = run(&dir);
    let rows = of_type(&produced, "AsepEntry");
    let mut ours_named = std::collections::BTreeSet::new();
    let mut ours_bindings = std::collections::BTreeSet::new();
    for r in &rows {
        let m = &r.metadata;
        if m["repository_liveness"] != "indexed" {
            continue;
        }
        let class = m["wmi_record_class"].as_str().unwrap();
        if class.eq_ignore_ascii_case("__FilterToConsumerBinding") {
            ours_bindings.insert(format!(
                "{} -> {}",
                m["binding_filter_ref"].as_str().unwrap(),
                m["binding_consumer_ref"].as_str().unwrap()
            ));
        } else {
            ours_named.insert(format!("{class}\t{}", m["entry_name"].as_str().unwrap()));
        }
    }
    let mut theirs_named = std::collections::BTreeSet::new();
    let mut theirs_bindings = std::collections::BTreeSet::new();
    for line in include_str!("../tests/fixtures/wmi_win11_python_cim.tsv").lines() {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f[0], "root\\subscription", "{line}");
        if f[1] == "__FilterToConsumerBinding" {
            theirs_bindings.insert(f[2].to_string());
        } else {
            theirs_named.insert(format!("{}\t{}", f[1], f[2]));
        }
    }
    assert_eq!(theirs_named.len(), 7);
    assert_eq!(theirs_bindings.len(), 3);
    assert_eq!(ours_named, theirs_named);
    assert_eq!(ours_bindings, theirs_bindings);
}

/// Windows Server 2003's index names its root in the header of logical page 0, not in the mapping: the walk starts
/// there, logical page 0 itself is not a node of the walk, and a page the root does not reach is not named.
#[test]
fn a_server_2003_index_is_walked_from_the_root_page_zero_names() {
    let mut p0 = page(0, &[0, 0], &["NS_a/I_page_zero.9.9.9"]);
    p0[12..16].copy_from_slice(&2u32.to_le_bytes());
    let idx = file_of(&[
        p0,
        page(1, &[0, 0], &["NS_a/I_orphan.1.2.3"]),
        page(2, &[3, 0], &["NS_a/CD_root.5.100.200"]),
        page(3, &[0, 0], &["NS_a/I_child.7.8.9"]),
    ]);
    let map = PageMap {
        sequence: 1,
        physical_pages: 4,
        logical: vec![0, 1, 2, 3],
        free: Vec::new(),
        first_entry_aux: 0,
        root_in_page_zero: true,
    };
    let set = indexed_records(&idx, &map).expect("a well-formed tree");
    let want: HashSet<_> = [(5, 100, 200), (7, 8, 9)].into_iter().collect();
    assert_eq!(
        set.refs, want,
        "the root's tree, not page 0's own key and not the orphan"
    );
    // Page 0 unmapped: there is nowhere to read the root from.
    let mut unmapped = map.clone();
    unmapped.logical[0] = UNMAPPED;
    assert!(indexed_records(&idx, &unmapped)
        .unwrap_err()
        .contains("page 0"));
}

/// The in-image route: the neighbour bundle a filesystem walker attaches
/// carries `INDEX.BTR` beside `OBJECTS.DATA`, so a repository read out of a
/// disk image is graded by its index too, not only a loose directory.
#[test]
fn the_index_is_reached_through_the_neighbour_bundle_too() {
    use seance_core::data_source::{ByteSliceDataSource, SiblingBundleSource};
    let Some(repos) = repos() else { return };
    let repo = repos
        .iter()
        .find(|r| r.key == "flare_wmikatz")
        .unwrap_or(&repos[0]);
    let file = |n: &str| -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(
            std::fs::read(repo.dir.join(n)).expect("read a repository file"),
        ))
    };
    let relatives = ["MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP", "INDEX.BTR"]
        .iter()
        .map(|n| (n.to_string(), file(n)))
        .collect();
    let ds = SiblingBundleSource::new(file("OBJECTS.DATA"), Default::default())
        .with_relatives(relatives);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let scan = &of_type(&produced, "AsepCoverage")[0].metadata["wmi_scan"];
    assert_eq!(scan["index_read"], json!(true), "{scan}");
    assert_eq!(
        scan["index_data_references"],
        answer_key()[repo.key]["index_data_references"]
    );
}

// ---- The Windows 11 lab repository (`HUNT-195`): planted subscriptions, graded against
// what was planted. `SEANCE_WIN11_WMI_DIR` names `forensic_corpora/lab_win11_wmi`.

/// `(entry name, class, planted after, last repository commit before it was made)`. The
/// last column is the header time the record carries, which `GROUND-TRUTH.txt` explains.
const PLANTED: &[(&str, &str, &str)] = &[
    (
        "SeanceMarkerFilter",
        "__EventFilter",
        "2026-10-22T02:43:44Z",
    ),
    (
        "SeanceMarkerConsumer",
        "ActiveScriptEventConsumer",
        "2026-10-22T02:43:44Z",
    ),
    (
        "SeanceSecondFilter",
        "__EventFilter",
        "2026-10-22T02:49:58Z",
    ),
    (
        "SeanceSecondConsumer",
        "CommandLineEventConsumer",
        "2026-10-22T02:49:58Z",
    ),
    ("SeanceThirdFilter", "__EventFilter", "2026-10-22T02:51:12Z"),
];

fn entry<'a>(rows: &[&'a Artifact], name: &str) -> &'a Artifact {
    rows.iter()
        .copied()
        .find(|r| r.metadata["entry_name"] == name)
        .unwrap_or_else(|| panic!("no entry named {name}"))
}

/// A real `ActiveScriptEventConsumer` instance, written by Windows, decodes to what was planted: its
/// name, engine and the exact script, and the filter and binding beside it.
#[test]
fn a_planted_active_script_consumer_decodes_to_what_was_planted() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_WIN11_WMI_DIR") else {
        return;
    };
    let produced = run(&dir);
    let rows = of_type(&produced, "AsepEntry");
    let consumer = entry(&rows, "SeanceMarkerConsumer");
    let m = &consumer.metadata;
    assert_eq!(m["wmi_record_class"], "ActiveScriptEventConsumer");
    let strings: Vec<&str> = m["data_strings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(strings.contains(&"SeanceMarkerConsumer"));
    assert!(strings.contains(&"VBScript"));
    let script = "Set fso = CreateObject(\"Scripting.FileSystemObject\") : Set f = \
        fso.CreateTextFile(\"C:\\Windows\\Temp\\seance-wmi-marker.txt\", True) : f.WriteLine \
        \"SEANCE-WMI-ASEC-7F3A9C\" : f.Close";
    assert!(
        strings.contains(&script),
        "the planted script, byte for byte: {strings:?}"
    );
    assert!(m["consumer_action"]
        .as_str()
        .unwrap()
        .contains("VBScript script of 177 characters"));
    assert_eq!(m["consumer_bound_filters"], json!(["SeanceMarkerFilter"]));
    let filter = entry(&rows, "SeanceMarkerFilter");
    assert!(filter.metadata["runs_when"]
        .as_str()
        .unwrap()
        .contains("TargetInstance.Hour = 3 AND TargetInstance.Minute = 17"));
    assert!(rows
        .iter()
        .any(|r| r.metadata["entry_name"] == "SeanceMarkerFilter -> SeanceMarkerConsumer"));
}

/// The header time a WMI record carries is **not** the time the instance was made: every planted
/// record carries a time before it was created, by 76 minutes, 6 minutes and 3 seconds in three
/// waves on one machine. It is published as a record time and never as an install time.
#[test]
fn a_wmi_record_time_is_not_published_as_the_time_the_subscription_was_installed() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_WIN11_WMI_DIR") else {
        return;
    };
    let produced = run(&dir);
    let rows = of_type(&produced, "AsepEntry");
    for (name, class, planted_after) in PLANTED {
        let m = &entry(&rows, name).metadata;
        assert_eq!(m["wmi_record_class"], *class, "{name}");
        assert_eq!(
            m["installed_time"],
            Value::Null,
            "{name}: not claimed as an install time"
        );
        assert_eq!(m["installed_time_status"], "unavailable", "{name}");
        let record_time = m["record_time"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no record time"));
        assert!(
            record_time < *planted_after,
            "{name}: the record time {record_time} is before it was planted at {planted_after}"
        );
        assert!(m["record_time_basis"]
            .as_str()
            .unwrap()
            .contains("no earlier than"));
    }
    // The records Windows wrote itself carry the image's own time.
    let scm = entry(&rows, "SCM Event Log Filter");
    assert!(scm.metadata["record_time"]
        .as_str()
        .unwrap()
        .starts_with("2024-04-01"));
    // The timeline says what the time is.
    let events: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert!(!events.is_empty());
    for e in events {
        assert_eq!(
            e.metadata["timestamp_desc"],
            "WMI repository record time (the subscription was made no earlier than this)"
        );
    }
}

/// The Windows 11 lab repository's `INDEX.BTR` is walked (`HUNT-195`): the mapping accounts for 645
/// physical pages and the file holds 643, the two missing being free. The index names all ten live
/// records: the seven planted (two filters, two consumers and a binding in the first two waves, a lone
/// filter in the third) and Windows' own three `SCM Event Log` records. The first wave's three records
/// were rewritten by the second commit and survive as older copies in a superseded page, which the
/// scan reports as such and the index does not name.
#[test]
fn the_windows_11_lab_index_is_walked_and_names_every_planted_record() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_WIN11_WMI_DIR") else {
        return;
    };
    let produced = run(&dir);
    let scan = &of_type(&produced, "AsepCoverage")[0].metadata["wmi_scan"];
    assert_eq!(scan["index_read"], json!(true), "{scan}");
    assert_eq!(scan["records_indexed"], json!(10), "{scan}");
    assert_eq!(scan["records_listed_not_indexed"], json!(0), "{scan}");
    let rows = of_type(&produced, "AsepEntry");
    let live = |name: &str| {
        rows.iter()
            .filter(|r| r.metadata["entry_name"] == name)
            .filter(|r| r.metadata["repository_liveness"] == json!("indexed"))
            .count()
    };
    for (name, _, _) in PLANTED {
        assert_eq!(live(name), 1, "{name}: exactly one record the index names");
    }
    let other: Vec<_> = rows
        .iter()
        .filter(|r| r.metadata["repository_liveness"] != json!("indexed"))
        .map(|r| {
            (
                r.metadata["entry_name"].clone(),
                r.metadata["repository_liveness"].clone(),
            )
        })
        .collect();
    assert_eq!(other.len(), 3, "{other:?}");
    assert!(
        other.iter().all(|(_, l)| l == &json!("superseded_page")),
        "{other:?}"
    );
}

// ---- The Windows Server 2003 R2 SP2 x64 repository (`HUNT-195`): the XP-era form, graded against python-cim.
// `SEANCE_W2K3_WMI_DIR` names `forensic_corpora/lab_w2k3_wmi` (the `FS` directory of a fresh evaluation install with
// one ActiveScriptEventConsumer, its filter and its binding planted by `mofcomp`, `~/legacy-lab/mofiso/plant.mof`).

/// The names python-cim lists, as `(class, name)` for filters and consumers and `(filter, consumer)` for bindings.
type NamePairs = std::collections::BTreeSet<(String, String)>;

fn python_cim_names(tsv: &str) -> (NamePairs, NamePairs) {
    let quoted = |s: &str| -> String {
        let start = s.find("Name=\"").expect("a Name") + 6;
        s[start..start + s[start..].find('"').unwrap()].to_string()
    };
    let mut named = std::collections::BTreeSet::new();
    let mut bindings = std::collections::BTreeSet::new();
    for line in tsv.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f[0], "root\\subscription", "{line}");
        if f[1] == "__FilterToConsumerBinding" {
            let (filter, consumer) = f[2].split_once(" -> ").unwrap();
            bindings.insert((quoted(filter), quoted(consumer)));
        } else {
            named.insert((f[1].to_string(), f[2].to_string()));
        }
    }
    (named, bindings)
}

/// A Server 2003 repository keeps its mapping in `MAPPINGn.MAP` with the XP-era layout (4-byte entries, a data section
/// then an index section in each file), not the Vista one: it used to be refused ("footer at byte 424 is 0x76") and every
/// record said `not_established`. Read as it is, the index is walked from the root page 0 names, every one of the 189
/// records the repository holds is named by it, and they are the 189 python-cim lists.
#[test]
fn a_windows_server_2003_repository_is_read_through_its_xp_era_mapping_and_index_and_agrees_with_python_cim(
) {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_W2K3_WMI_DIR") else {
        return;
    };
    let produced = run(&dir);
    let scan = &of_type(&produced, "AsepCoverage")[0].metadata["wmi_scan"];
    assert_eq!(scan["mapping_read"], json!(true), "{scan}");
    assert_eq!(scan["index_read"], json!(true), "{scan}");
    assert_eq!(scan["index_walked"], json!(true), "{scan}");
    let rows = of_type(&produced, "AsepEntry");
    assert_eq!(rows.len(), 189);
    for r in &rows {
        assert_eq!(
            r.metadata["repository_liveness"], "indexed",
            "{}",
            r.metadata["entry_name"]
        );
    }
    let (want_named, want_bindings) =
        python_cim_names(include_str!("../tests/fixtures/wmi_w2k3_python_cim.tsv"));
    assert_eq!(want_named.len() + want_bindings.len(), 189);
    let mut got_named = std::collections::BTreeSet::new();
    let mut got_bindings = std::collections::BTreeSet::new();
    let name_of = |reference: &str| {
        let start = reference.find("Name=\"").unwrap() + 6;
        reference[start..start + reference[start..].find('"').unwrap()].to_string()
    };
    for r in &rows {
        let m = &r.metadata;
        let class = m["wmi_record_class"].as_str().unwrap();
        if class.eq_ignore_ascii_case("__FilterToConsumerBinding") {
            got_bindings.insert((
                name_of(m["binding_filter_ref"].as_str().unwrap()),
                name_of(m["binding_consumer_ref"].as_str().unwrap()),
            ));
        } else {
            got_named.insert((
                class.to_string(),
                m["entry_name"].as_str().unwrap().to_string(),
            ));
        }
    }
    assert_eq!(got_named, want_named);
    assert_eq!(got_bindings, want_bindings);
}

// ---- The Windows XP repository (`HUNT-195`): OBJECTS.MAP with INDEX.MAP, graded against python-cim on the same bytes.
// `SEANCE_XP_WMI_DIR` names `forensic_corpora/lab_xp_wmi`: OBJECTS.MAP, INDEX.MAP, OBJECTS.DATA and INDEX.BTR of the 2004
// Windows XP disk of the CFReDS Hacking Case (`4Dell_Latitude_CPi.E01`, inodes 11943, 11944, 5507, 5508). python-cim reads
// only the numbered form, so the oracle is given the same two mapping files joined into one `MAPPING1.MAP`.

/// Windows XP names the index's mapping in its own file. It used to be left unread ("no XP index is held": it was, on the
/// disk the data mapping came from). Now the index is walked from the root page 0 names and every one of the six
/// subscription records the repository holds is named by it; they are the six python-cim lists.
#[test]
fn a_windows_xp_repository_is_read_through_its_index_map_and_agrees_with_python_cim() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_XP_WMI_DIR") else {
        return;
    };
    let produced = run(&dir);
    let scan = &of_type(&produced, "AsepCoverage")[0].metadata["wmi_scan"];
    assert_eq!(scan["mapping_read"], json!(true), "{scan}");
    assert_eq!(scan["index_read"], json!(true), "{scan}");
    assert_eq!(scan["index_walked"], json!(true), "{scan}");
    let rows = of_type(&produced, "AsepEntry");
    assert_eq!(rows.len(), 6);
    for r in &rows {
        assert_eq!(
            r.metadata["repository_liveness"], "indexed",
            "{}",
            r.metadata["entry_name"]
        );
    }
    let (want_named, want_bindings) =
        python_cim_names(include_str!("../tests/fixtures/wmi_xp_python_cim.tsv"));
    assert_eq!(want_named.len() + want_bindings.len(), 6);
    let mut got_named = std::collections::BTreeSet::new();
    let name_of = |reference: &str| {
        let start = reference.find("Name=\"").unwrap() + 6;
        reference[start..start + reference[start..].find('"').unwrap()].to_string()
    };
    let mut got_binding_filters = std::collections::BTreeSet::new();
    for r in &rows {
        let m = &r.metadata;
        let class = m["wmi_record_class"].as_str().unwrap();
        if class.eq_ignore_ascii_case("__FilterToConsumerBinding") {
            got_binding_filters.insert(name_of(m["binding_filter_ref"].as_str().unwrap()));
        } else {
            got_named.insert((
                class.to_string(),
                m["entry_name"].as_str().unwrap().to_string(),
            ));
        }
    }
    assert_eq!(got_named, want_named);
    let want_filters: std::collections::BTreeSet<String> =
        want_bindings.iter().map(|(f, _)| f.clone()).collect();
    assert_eq!(got_binding_filters, want_filters);
}

// ---- A deleted subscription on Windows Server 2003 R2 (`HUNT-195`).
// `SEANCE_W2K3_WMI_DELETED_DIR` names `forensic_corpora/lab_w2k3_wmi_deleted`: `before/` and `after/` hold the
// five repository files of the lab VM after a subscription (`SeanceDeletedFilter7F3A`, `SeanceDeletedConsumer7F3A`,
// an ActiveScriptEventConsumer, and their binding) was made by `mofcomp` and after the three instances were deleted
// through the WMI API, each taken after `net stop winmgmt`. The python-cim 1.1 listings of both are fixtures.

const DELETED_MARKER: &str = "SEANCE-WMI-DELETED-9B24E1";

/// The entries published as live (`AsepEntry`), not the recovered ones: `of_type` takes both under that name.
fn live_entries(produced: &[Artifact]) -> Vec<&Artifact> {
    produced
        .iter()
        .filter(|a| a.metadata.get("type").and_then(Value::as_str) == Some("AsepEntry"))
        .collect()
}

/// The ranges the descriptor table of physical page `page` of `OBJECTS.DATA` covers, as absolute file offsets,
/// read here from the bytes (16-byte entries: id, offset, size, checksum; a zero entry ends the table).
fn page_descriptor_ranges(objects: &[u8], page: usize) -> Vec<(u32, usize, usize)> {
    let base = page * INDEX_PAGE;
    let mut out = Vec::new();
    for i in (0..INDEX_PAGE).step_by(16) {
        let w = |k: usize| {
            u32::from_le_bytes(objects[base + i + k..base + i + k + 4].try_into().unwrap())
        };
        if w(0) == 0 && w(4) == 0 && w(8) == 0 {
            break;
        }
        out.push((w(0), base + w(4) as usize, w(8) as usize));
    }
    out
}

/// Deleting a subscription does not leave a record "listed by a mapped page and named by no index key": WMI
/// rewrites the page without the three descriptors, so the instances' bytes stay in the file as residue in the
/// current page (no descriptor lists them) and as copies in the page it left (mapped to no logical page). The
/// scan publishes every copy as recovered, none as live, and the live set equals the 189 records python-cim
/// lists after the deletion, the 189 it listed before the subscription was made.
#[test]
fn a_deleted_subscription_leaves_residue_the_scan_publishes_as_recovered_and_the_index_no_longer_names(
) {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_W2K3_WMI_DELETED_DIR") else {
        return;
    };
    let live_names = |produced: &[Artifact]| {
        let mut named = std::collections::BTreeSet::new();
        let mut bindings = std::collections::BTreeSet::new();
        let name_of = |reference: &str| {
            let start = reference.find("Name=\"").unwrap() + 6;
            reference[start..start + reference[start..].find('"').unwrap()].to_string()
        };
        for r in live_entries(produced) {
            let m = &r.metadata;
            assert_eq!(m["repository_liveness"], "indexed", "{}", m["entry_name"]);
            let class = m["wmi_record_class"].as_str().unwrap();
            if class.eq_ignore_ascii_case("__FilterToConsumerBinding") {
                bindings.insert((
                    name_of(m["binding_filter_ref"].as_str().unwrap()),
                    name_of(m["binding_consumer_ref"].as_str().unwrap()),
                ));
            } else {
                named.insert((
                    class.to_string(),
                    m["entry_name"].as_str().unwrap().to_string(),
                ));
            }
        }
        (named, bindings)
    };

    // Before the deletion: the three records are live, named by the index, and python-cim lists them.
    let before = run(&dir.join("before"));
    let scan = &of_type(&before, "AsepCoverage")[0].metadata["wmi_scan"];
    assert_eq!(scan["index_read"], json!(true), "{scan}");
    assert_eq!(scan["records_indexed"], json!(192), "{scan}");
    assert_eq!(scan["records_listed_not_indexed"], json!(0), "{scan}");
    let (got_named, got_bindings) = live_names(&before);
    let (want_named, want_bindings) = python_cim_names(include_str!(
        "../tests/fixtures/wmi_w2k3_deleted_before_python_cim.tsv"
    ));
    assert_eq!(want_named.len() + want_bindings.len(), 192);
    assert_eq!(got_named, want_named);
    assert_eq!(got_bindings, want_bindings);
    assert!(got_named.contains(&(
        "__EventFilter".to_string(),
        "SeanceDeletedFilter7F3A".to_string()
    )));
    assert!(got_named.contains(&(
        "ActiveScriptEventConsumer".to_string(),
        "SeanceDeletedConsumer7F3A".to_string()
    )));

    // After it: the live set is the 189 records python-cim lists, none of them the deleted three, and no record is
    // listed by a mapped page and named by no key.
    let after = run(&dir.join("after"));
    let scan = &of_type(&after, "AsepCoverage")[0].metadata["wmi_scan"];
    assert_eq!(scan["index_read"], json!(true), "{scan}");
    assert_eq!(scan["records_indexed"], json!(189), "{scan}");
    assert_eq!(scan["records_listed_not_indexed"], json!(0), "{scan}");
    assert_eq!(scan["descriptors_listed_not_indexed"], json!(0), "{scan}");
    let (got_named, got_bindings) = live_names(&after);
    let (want_named, want_bindings) = python_cim_names(include_str!(
        "../tests/fixtures/wmi_w2k3_deleted_after_python_cim.tsv"
    ));
    assert_eq!(want_named.len() + want_bindings.len(), 189);
    assert_eq!(got_named, want_named);
    assert_eq!(got_bindings, want_bindings);
    assert!(!got_named.iter().any(|(_, n)| n.contains("SeanceDeleted")));

    // The deleted records are still in the file and the scan publishes them, as recovered, never as live.
    let objects = std::fs::read(dir.join("after").join("OBJECTS.DATA")).expect("read OBJECTS.DATA");
    let deleted: Vec<&Artifact> = of_type(&after, "RecoveredAsepEntry")
        .into_iter()
        .filter(|a| a.metadata.to_string().contains("SeanceDeleted"))
        .collect();
    let by = |provenance: &str, class: &str| {
        deleted
            .iter()
            .filter(|a| {
                a.metadata["repository_liveness"] == provenance
                    && a.metadata["wmi_record_class"] == class
            })
            .count()
    };
    // Residue in the current page: the consumer and the binding (the filter's bytes were overwritten when the page
    // was rebuilt, so no copy of it survives there).
    assert_eq!(
        by("unreferenced_in_mapped_page", "ActiveScriptEventConsumer"),
        1
    );
    assert_eq!(
        by("unreferenced_in_mapped_page", "__FilterToConsumerBinding"),
        1
    );
    assert_eq!(by("unreferenced_in_mapped_page", "__EventFilter"), 0);
    // Copies in pages the mapping no longer names: two generations of the page, five records in all.
    assert_eq!(by("superseded_page", "ActiveScriptEventConsumer"), 2);
    assert_eq!(by("superseded_page", "__FilterToConsumerBinding"), 2);
    assert_eq!(by("superseded_page", "__EventFilter"), 1);
    assert_eq!(deleted.len(), 7);
    for a in &deleted {
        let m = &a.metadata;
        assert!(
            m["evidence_state"] == "recovered" || m["evidence_state"] == "superseded",
            "{m}"
        );
        assert_ne!(m["record_indexed"], json!(true));
        assert!(
            m["enabled_basis"]
                .as_str()
                .unwrap()
                .contains("not in force as found"),
            "{}",
            m["enabled_basis"]
        );
        // The script the consumer ran is recovered from the residue and the copies.
        if m["wmi_record_class"] == "ActiveScriptEventConsumer" {
            assert!(m.to_string().contains(DELETED_MARKER), "{m}");
        }
        // Independent of the scan: no descriptor of the record's page covers the residue in the current page.
        if m["repository_liveness"] == "unreferenced_in_mapped_page" {
            let offset = m["record_offset"].as_u64().unwrap() as usize;
            let page = m["record_page"].as_u64().unwrap() as usize;
            assert!(page_descriptor_ranges(&objects, page)
                .iter()
                .all(|&(_, start, len)| offset < start || offset >= start + len));
        }
    }

    // The same three records were listed by the descriptor table of the page they sat in before the deletion.
    let objects_before =
        std::fs::read(dir.join("before").join("OBJECTS.DATA")).expect("read OBJECTS.DATA");
    for r in live_entries(&before)
        .into_iter()
        .filter(|a| a.metadata.to_string().contains("SeanceDeleted"))
    {
        let m = &r.metadata;
        let offset = m["record_offset"].as_u64().unwrap() as usize;
        let page = m["record_page"].as_u64().unwrap() as usize;
        assert!(
            page_descriptor_ranges(&objects_before, page)
                .iter()
                .any(
                    |&(id, start, len)| id as u64 == m["record_id"].as_u64().unwrap()
                        && start == offset
                        && len == m["record_size"].as_u64().unwrap() as usize
                ),
            "{m}"
        );
    }
}

// ---- A power cut while WMI commits (`HUNT-195`, `WMI-12`).
// `loopA/` and `loopF/` under the same directory: the repository after a VBScript created 400 subscriptions (a filter,
// a consumer and a binding each) on the Server 2003 lab VM and deleted the even-numbered ones, the VM hard-killed
// after it finished (`loopA`) and 10 s into it (`loopF`, mid-commit).

/// After a completed run the 200 surviving subscriptions are live and indexed. Killed mid-commit, the repository
/// is the one the last commit left: nothing written after it is live, and the 609 records the cut left in
/// unmapped pages are published as recovered. In neither is a descriptor listed by a mapped page and named by no key.
#[test]
fn a_power_cut_while_wmi_commits_leaves_the_last_commit_live_and_the_rest_recovered_not_unlinked() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_W2K3_WMI_DELETED_DIR") else {
        return;
    };
    let numbers = |name: &str| {
        let out = run(&dir.join(name));
        let scan = of_type(&out, "AsepCoverage")[0].metadata["wmi_scan"].clone();
        let live = live_entries(&out).len();
        let recovered = of_type(&out, "AsepEntry").len() - live;
        (live, recovered, scan)
    };
    let (live, recovered, scan) = numbers("loopA");
    assert_eq!((live, recovered), (789, 22), "{scan}");
    assert_eq!(scan["records_indexed"], json!(789), "{scan}");
    assert_eq!(scan["records_listed_not_indexed"], json!(0), "{scan}");
    assert_eq!(scan["descriptors_listed_not_indexed"], json!(0), "{scan}");
    let (live, recovered, scan) = numbers("loopF");
    assert_eq!((live, recovered), (189, 609), "{scan}");
    assert_eq!(scan["records_indexed"], json!(189), "{scan}");
    assert_eq!(scan["records_in_unmapped_pages"], json!(609), "{scan}");
    assert_eq!(scan["records_listed_not_indexed"], json!(0), "{scan}");
    assert_eq!(scan["descriptors_listed_not_indexed"], json!(0), "{scan}");
}
