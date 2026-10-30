//! Layered keys graded on real differencing-hive chains: Windows Server 2022
//! Nano Server container images from the public Microsoft Container Registry
//! (`mcr.microsoft.com/dotnet/runtime:8.0-nanoserver-ltsc2022`, chain A, and
//! `.../dotnet/sdk:8.0-nanoserver-ltsc2022`, chain B, which shares chain A's
//! base and first five deltas).
//!
//! Where the answers come from, and how much each one proves:
//!
//! * **PATH** is a published known answer. The images' Dockerfiles
//!   (github.com/dotnet/dotnet-docker, `src/runtime/8.0/nanoserver-ltsc2022`
//!   and `src/sdk/8.0/nanoserver-ltsc2022`) run `setx /M PATH` in exactly two
//!   layers, and the image configs' build history names which. The merged
//!   value must be the second layer's over the first's over the base's.
//! * **The tombstones, the class name and the value counts** are read from
//!   the artifacts' own bytes. The full-walk counts are a cross-check against
//!   an independent Python walk of the same reading of the specification —
//!   it catches this crate misapplying the rules, not the rules being wrong.
//!
//! The hives are under the Windows container base-image licence, which
//! restricts redistribution, so they are **not** in the repository. The
//! corpus is the directory named by `SEANCE_LAYERED_HIVE_CORPUS`, or
//! `~/forensic_corpora/windows_container_layered_hives`; absent, each test
//! skips and says so, and `SEANCE_REQUIRE_CORPUS` makes that a failure.
//! `SOURCE.md` in that directory records every blob's digest and URL.

use std::path::{Path, PathBuf};

use crate::{Hive, KeyValueDataType, LayeredHive, LayeredKey};

fn corpus_dir() -> Option<PathBuf> {
    let dir = match std::env::var("SEANCE_LAYERED_HIVE_CORPUS") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join("forensic_corpora")
            .join("windows_container_layered_hives"),
    };
    if dir.is_dir() {
        return Some(dir);
    }
    let required = std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty());
    assert!(
        !required,
        "{} is not a directory, but SEANCE_REQUIRE_CORPUS demands the layered-hive corpus",
        dir.display()
    );
    eprintln!(
        "SKIPPED (no corpus): {} is not a directory — this test compared nothing",
        dir.display()
    );
    None
}

/// The files of one chain, base first, then each delta upwards, cut to the
/// first `layers` when given.
fn chain_files(
    dir: &Path,
    chain: char,
    delta: &str,
    base: &str,
    layers: Option<usize>,
) -> Vec<PathBuf> {
    let mut files = vec![dir
        .join("extracted/L1_7a186637240e/Files/Windows/System32/config")
        .join(base)];
    let parent = match chain {
        'A' => dir.join("extracted"),
        _ => dir.join("sdk_chain/extracted"),
    };
    let mut layer_dirs: Vec<PathBuf> = std::fs::read_dir(&parent)
        .expect("chain directory")
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("Hives").is_dir())
        .collect();
    // L2..L6 and L02..L16 both sort by name into build order.
    layer_dirs.sort();
    files.extend(
        layer_dirs
            .iter()
            .map(|d| d.join("Hives").join(format!("{delta}_Delta"))),
    );
    if let Some(n) = layers {
        files.truncate(n);
    }
    for f in &files {
        assert!(
            f.is_file(),
            "{} missing: the corpus is incomplete",
            f.display()
        );
    }
    files
}

fn read_chain(
    dir: &Path,
    chain: char,
    delta: &str,
    base: &str,
    layers: Option<usize>,
) -> Vec<Vec<u8>> {
    chain_files(dir, chain, delta, base, layers)
        .iter()
        .map(|f| std::fs::read(f).unwrap())
        .collect()
}

fn stack(bytes: &[Vec<u8>]) -> LayeredHive<'_> {
    let hives: Vec<Hive<'_>> = bytes
        .iter()
        .map(|b| Hive::new(b).expect("a real hive from the corpus validates"))
        .collect();
    let (base, deltas) = hives.split_first().unwrap();
    LayeredHive::new(*base, deltas.to_vec()).expect("stack opens")
}

/// Walk down by case-insensitive name, as the path is written.
fn at<'a>(hive: &LayeredHive<'a>, path: &str) -> LayeredKey<'a> {
    let mut key = hive.root().expect("root");
    for segment in path.split('\\') {
        let subkeys = key.subkeys();
        assert!(subkeys.faults.is_empty(), "{segment}: {:?}", subkeys.faults);
        key = subkeys
            .keys
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(segment))
            .unwrap_or_else(|| panic!("no merged subkey {segment} on the way to {path}"));
    }
    key
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

const ENVIRONMENT: &str = r"ControlSet001\Control\Session Manager\Environment";

/// The merged PATH: (name as spelt, layer, type, text without its NUL).
fn merged_path(hive: &LayeredHive<'_>) -> (String, usize, KeyValueDataType, String) {
    let values = at(hive, ENVIRONMENT).values();
    assert!(values.faults.is_empty());
    let paths: Vec<_> = values
        .values
        .iter()
        .filter(|v| v.name.eq_ignore_ascii_case("PATH"))
        .collect();
    assert_eq!(paths.len(), 1, "exactly one PATH in the merged view");
    let v = paths[0];
    let text = utf16(v.value.data().unwrap().as_slice());
    (
        v.name.clone(),
        v.layer,
        v.value.data_type().unwrap(),
        text.trim_end_matches('\0').to_string(),
    )
}

const DOTNET_PATH: &str = r"C:\Windows\system32;C:\Windows;;C:\Program Files\dotnet";

#[test]
fn chain_a_merged_path_is_the_published_setx_answer_from_the_fourth_layer() {
    let Some(dir) = corpus_dir() else { return };
    let bytes = read_chain(&dir, 'A', "System", "SYSTEM", None);
    assert_eq!(bytes.len(), 6);
    let hive = stack(&bytes);
    let (name, layer, data_type, text) = merged_path(&hive);
    assert_eq!(text, DOTNET_PATH);
    assert_eq!(name, "PATH");
    // Layer 3 is L4 0f65c5c3fc5a, the `setx /M PATH` step.
    assert_eq!(layer, 3);
    assert_eq!(data_type, KeyValueDataType::RegSZ);

    // The base's own value is hidden, not lost: a different spelling and type.
    let env = at(&hive, ENVIRONMENT).values();
    let base_path: Vec<_> = env
        .shadowed
        .iter()
        .filter(|v| v.name.eq_ignore_ascii_case("PATH"))
        .collect();
    assert_eq!(base_path.len(), 1);
    assert_eq!(base_path[0].name, "Path");
    assert_eq!(base_path[0].layer, 0);
    assert_eq!(
        base_path[0].value.data_type().unwrap(),
        KeyValueDataType::RegExpandSZ
    );
    assert_eq!(
        utf16(base_path[0].value.data().unwrap().as_slice()).trim_end_matches('\0'),
        r"%SystemRoot%\system32;%SystemRoot%;"
    );
}

#[test]
fn chain_b_merged_path_is_the_second_setx_over_the_first_and_cut_below_it_is_the_first() {
    let Some(dir) = corpus_dir() else { return };
    let bytes = read_chain(&dir, 'B', "System", "SYSTEM", None);
    assert_eq!(bytes.len(), 16);
    let hive = stack(&bytes);
    let (_, layer, _, text) = merged_path(&hive);
    assert_eq!(
        text,
        format!(r"{DOTNET_PATH};C:\Program Files\powershell;C:\Program Files\MinGit\cmd")
    );
    // Layer 10 is L11 95b11a568d8c.
    assert_eq!(layer, 10);

    // The same chain stopped below L11 presents L4's answer.
    let cut = read_chain(&dir, 'B', "System", "SYSTEM", Some(10));
    let (_, layer, _, text) = merged_path(&stack(&cut));
    assert_eq!((layer, text.as_str()), (3, DOTNET_PATH));

    // And the base with only L2 above it presents the base's own.
    let low = read_chain(&dir, 'A', "System", "SYSTEM", Some(2));
    let (name, layer, _, text) = merged_path(&stack(&low));
    assert_eq!(
        (name.as_str(), layer, text.as_str()),
        ("Path", 0, r"%SystemRoot%\system32;%SystemRoot%;")
    );
}

#[test]
fn the_real_key_tombstone_is_absent_from_the_merged_view_and_reported() {
    let Some(dir) = corpus_dir() else { return };
    let bytes = read_chain(&dir, 'B', "System", "SYSTEM", None);
    let hive = stack(&bytes);
    let listener = at(
        &hive,
        r"ControlSet001\Control\WMI\Autologger\Diagtrack-Listener",
    );
    assert_eq!(listener.contributing_layers(), &[15, 10, 3, 0]);
    let subkeys = listener.subkeys();
    let guid = "{976A8310-986E-4640-8BFB-7736EE6D9B65}";
    assert!(
        !subkeys
            .keys
            .iter()
            .any(|k| k.name().eq_ignore_ascii_case(guid)),
        "a tombstoned key is not in the merged view"
    );
    let tomb: Vec<_> = subkeys
        .tombstoned
        .iter()
        .filter(|t| t.name.eq_ignore_ascii_case(guid))
        .collect();
    assert_eq!(tomb.len(), 1);
    assert_eq!(
        tomb[0].layer, 15,
        "in L16 f40b92220811, the `RUN dotnet help` step"
    );
}

#[test]
fn the_real_value_tombstone_hides_the_dword_below_it_until_a_later_layer_sets_it_again() {
    let Some(dir) = corpus_dir() else { return };
    let key = r"ControlSet001\Control\Windows Containers";

    // Base + L2: L2 sets it as a REG_DWORD.
    let low = read_chain(&dir, 'A', "System", "SYSTEM", Some(2));
    let hive = stack(&low);
    let values = at(&hive, key).values();
    let v: Vec<_> = values
        .values
        .iter()
        .filter(|v| v.name == "CryptoSpecializeNeeded")
        .collect();
    assert_eq!(v.len(), 1);
    assert_eq!(
        (v[0].layer, v[0].value.data_type().unwrap()),
        (1, KeyValueDataType::RegDWord)
    );

    // Base + L2..L4: L4 tombstones it.
    let mid = read_chain(&dir, 'A', "System", "SYSTEM", Some(4));
    let hive = stack(&mid);
    let values = at(&hive, key).values();
    assert!(values
        .values
        .iter()
        .all(|v| v.name != "CryptoSpecializeNeeded"));
    assert_eq!(values.tombstoned.len(), 1);
    assert_eq!(values.tombstoned[0].layer, 3);
    assert!(values
        .shadowed
        .iter()
        .any(|v| v.layer == 1 && v.name == "CryptoSpecializeNeeded"));

    // The full chain A: a later layer writes it again.
    let full = read_chain(&dir, 'A', "System", "SYSTEM", None);
    let hive = stack(&full);
    let values = at(&hive, key).values();
    let v: Vec<_> = values
        .values
        .iter()
        .filter(|v| v.name == "CryptoSpecializeNeeded")
        .collect();
    assert_eq!(v.len(), 1);
    assert!(v[0].layer > 3);
}

#[test]
fn a_real_supersede_tree_key_takes_its_class_from_the_delta_and_nothing_from_the_base() {
    let Some(dir) = corpus_dir() else { return };
    let bytes = read_chain(&dir, 'A', "System", "SYSTEM", None);
    let hive = stack(&bytes);
    let data = at(&hive, r"ControlSet001\Control\Lsa\Data");
    assert_eq!(data.contributing_layers(), &[3]);
    let delta_node = data.node_in_layer(3).unwrap();
    assert_eq!(
        delta_node.layered_key_bits().unwrap().semantics,
        crate::LayerSemantics::SupersedeTree
    );
    assert!(
        data.node_in_layer(0).unwrap().class_name().is_none(),
        "the base Data has no class"
    );
    let crate::LayeredClass::Named { layer, name } = data.class_name() else {
        panic!(
            "Lsa\\Data has a class in its delta: {:?}",
            data.class_name()
        );
    };
    assert_eq!(layer, 3);
    let class = name.unwrap();
    assert_eq!(class, delta_node.class_name().unwrap().unwrap());
    assert_eq!(class.to_string_lossy().chars().count(), 8);
}

/// Every merged key and value, and every fault, over a whole chain.
fn walk(key: &LayeredKey<'_>, keys: &mut usize, values: &mut usize, faults: &mut usize) {
    *keys += 1;
    let v = key.values();
    *values += v.values.len();
    *faults += v.faults.len();
    let s = key.subkeys();
    *faults += s.faults.len();
    for child in &s.keys {
        walk(child, keys, values, faults);
    }
}

#[test]
fn whole_chains_merge_with_no_faults_to_the_independent_walks_counts() {
    let Some(dir) = corpus_dir() else { return };
    // (chain, delta, base, layers, merged keys, merged values), from the
    // independent Python walk described in the module documentation.
    let cases = [
        ('A', "System", "SYSTEM", None, 8_119, 19_847),
        ('A', "Software", "SOFTWARE", None, 11_596, 21_537),
        ('B', "System", "SYSTEM", None, 8_139, 19_916),
        ('B', "Software", "SOFTWARE", None, 11_641, 21_970),
        ('A', "System", "SYSTEM", Some(2), 8_105, 19_703),
    ];
    for (chain, delta, base, layers, want_keys, want_values) in cases {
        let bytes = read_chain(&dir, chain, delta, base, layers);
        let hive = stack(&bytes);
        let (mut keys, mut values, mut faults) = (0, 0, 0);
        walk(&hive.root().unwrap(), &mut keys, &mut values, &mut faults);
        assert_eq!(
            (keys, values, faults),
            (want_keys, want_values, 0),
            "chain {chain} {delta} {layers:?}"
        );
    }
}

/// Paths of every merged key whose class is not determinable.
fn not_determinable(key: &LayeredKey<'_>, path: &str, out: &mut Vec<(String, u8)>) {
    if key.class_name() == crate::LayeredClass::NotDeterminable {
        let top = key.contributing_layers()[0];
        let raw = key
            .node_in_layer(top)
            .unwrap()
            .layered_key_bits()
            .unwrap()
            .raw;
        out.push((path.to_string(), raw));
    }
    for child in key.subkeys().keys {
        not_determinable(&child, &format!("{path}\\{}", child.name()), out);
    }
}

/// The keys whose merged class is not determinable, on the real chains.
///
/// Pinned from a full walk of each merged view (this crate's own reading,
/// so a regression pin, not an independent answer): exactly two keys, both
/// in chain B's SOFTWARE, both `SupersedeTree` with *Inherit class* set
/// (byte `0x83`), and none in either SYSTEM chain or chain A. Reading those
/// two as "no class" would claim a fact the hives do not record.
#[test]
fn only_two_real_keys_have_a_class_the_stack_cannot_determine() {
    let Some(dir) = corpus_dir() else { return };
    for (chain, delta, base, want) in [
        ('A', "System", "SYSTEM", 0),
        ('A', "Software", "SOFTWARE", 0),
        ('B', "System", "SYSTEM", 0),
        ('B', "Software", "SOFTWARE", 2),
    ] {
        let bytes = read_chain(&dir, chain, delta, base, None);
        let hive = stack(&bytes);
        let mut out = Vec::new();
        not_determinable(&hive.root().unwrap(), "", &mut out);
        assert_eq!(out.len(), want, "chain {chain} {delta}: {out:?}");
        assert!(out.iter().all(|(_, raw)| *raw == 0x83), "{out:?}");
        if want > 0 {
            assert!(
                out.iter()
                    .all(|(p, _)| p.contains("NetworkServiceTriggers")),
                "{out:?}"
            );
        }
    }
}
