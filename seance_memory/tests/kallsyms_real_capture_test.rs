//! kallsyms recovery, against a kernel's own symbol table.
//!
//! # What this establishes
//!
//! [`seance_memory::btf`] recovers a kernel's **types** from a capture and
//! `btf_isf` renders them as an ISF — but an ISF is types *and* symbol
//! addresses, and BTF carries none. This is the other half: the addresses, read
//! out of the same image.
//!
//! Verified against `/proc/kallsyms` taken from the running host, which is a
//! table the kernel printed itself. Address for address, name for name — not a
//! sample, and not a fixture this project wrote. Two defects earlier in this
//! work survived full test suites precisely because implementation and fixture
//! shared one misreading, so a format this project decodes is checked against
//! something it did not produce. See `documentation/TESTING.md`.
//!
//! # Same boot, or nothing
//!
//! The capture and the `/proc/kallsyms` copy must come from the same boot.
//! KASLR relocates the kernel on every start, so a `kallsyms.txt.gz` from a
//! later boot would disagree with the capture on every address while being
//! perfectly correct about the kernel it came from. The corpus pair was taken
//! six days into an uptime that had begun well before the capture.
//!
//! # Corpus
//!
//! `SEANCE_LINUX_MEM` must name a directory holding `oberon_mem.lime.compressed`
//! and `kallsyms.txt.gz`. Absent, these skip; named and missing, they fail.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::test_support::corpus;
use seance_memory::kallsyms::Kallsyms;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const CORPUS_VAR: &str = "SEANCE_LINUX_MEM";
const CAPTURE: &str = "oberon_mem.lime.compressed";
const GROUND_TRUTH: &str = "kallsyms.txt.gz";

/// `/proc/kallsyms` as the kernel printed it: name → every (address, type) it
/// was printed with.
///
/// A **set**, not a single address. The same name occurs many times in a kernel
/// — `umask_show` is a sysfs handler defined in dozens of drivers — so checking
/// a recovered symbol against "the first address printed for that name" reports
/// a mismatch for every occurrence but one. That is what this test did on its
/// first run, and the disagreements it produced were its own.
fn ground_truth() -> Option<HashMap<String, HashSet<(u64, char)>>> {
    use std::io::Read;
    let path = corpus::file(CORPUS_VAR, GROUND_TRUTH)?;
    let file = std::fs::File::open(path).expect("the gate proved this exists");
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .expect("the ground truth is gzip");

    let mut map = HashMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(address), Some(_kind), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        // A symbol qualified by a module — `foo [bar]` — is not in the kernel's
        // static table and cannot be recovered from it.
        if parts.next().is_some() {
            continue;
        }
        if let Ok(address) = u64::from_str_radix(address, 16) {
            let kind = _kind.chars().next().unwrap_or('?');
            map.entry(name.to_string())
                .or_insert_with(HashSet::new)
                .insert((address, kind));
        }
    }
    Some(map)
}

/// Recover the table once, and share it.
///
/// Each sweep decodes 15 GiB of compressed capture, so four tests each doing
/// their own cost four times the wall clock and contend for the same cores.
/// The sweep is deterministic, so one result serves all of them.
fn recovered() -> Option<&'static Kallsyms> {
    static ONCE: std::sync::OnceLock<Option<Kallsyms>> = std::sync::OnceLock::new();
    // Absent corpus: skip, which is what `None` means to the caller. Corpus
    // present but nothing recovered: fail, loudly, here — otherwise every test
    // below returns early and reports a pass for a decode that did not happen.
    // Three of them did exactly that on the first run.
    corpus::file(CORPUS_VAR, CAPTURE)?;
    let table = ONCE.get_or_init(sweep_for_kallsyms).as_ref();
    assert!(
        table.is_some(),
        "the capture is present and no kallsyms table was recovered from it. \
         CONFIG_KALLSYMS is on in every distribution kernel, so the table IS in \
         the image and this is a failure to locate or decode it"
    );
    table
}

/// Sweep the capture for the kernel's symbol table, as production would.
fn sweep_for_kallsyms() -> Option<Kallsyms> {
    let path = corpus::file(CORPUS_VAR, CAPTURE)?;
    let source: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("gate checked"));
    let layer = seance_memory::formats::avml::open(source).expect("the capture opens");

    const WINDOW: u64 = 64 * 1024 * 1024;
    const OVERLAP: u64 = 8 * 1024 * 1024;
    let top = layer
        .segments()
        .iter()
        .map(|s| s.memory_offset + s.length)
        .max()
        .unwrap_or(0);

    let mut buffer = vec![0u8; WINDOW as usize];
    let mut at = 0u64;
    while at < top {
        let want = WINDOW.min(top - at) as usize;
        if layer.read_at(at, &mut buffer[..want]).is_ok() {
            if let Some((_, table)) = Kallsyms::find_in(&buffer[..want]) {
                return Some(table);
            }
        }
        at += WINDOW - OVERLAP;
    }
    None
}

/// **The one that matters.** The recovered table agrees with the kernel's own.
#[test]
fn recovered_symbols_match_what_the_kernel_printed() {
    let Some(truth) = ground_truth() else { return };
    let Some(table) = recovered() else { return };

    // The static table holds fewer symbols than /proc/kallsyms prints, because
    // the latter includes loaded modules. It should still be most of them.
    assert!(
        table.len() > 100_000,
        "only {} symbols recovered, which is too few to be a kernel's table",
        table.len()
    );

    let mut matched = 0usize;
    let mut disagreed: Vec<String> = Vec::new();
    let mut absent = 0usize;

    let mut disagreements = 0usize;
    for symbol in table.symbols() {
        match truth.get(&symbol.name) {
            Some(printed) if printed.iter().any(|&(a, _)| a == symbol.address) => matched += 1,
            Some(printed) => {
                disagreements += 1;
                if disagreed.len() < 12 {
                    disagreed.push(format!(
                        "{}: recovered {:#x}, kernel printed {:?}",
                        symbol.name,
                        symbol.address,
                        printed
                            .iter()
                            .map(|&(a, _)| format!("{a:#x}"))
                            .collect::<Vec<_>>()
                    ));
                }
            }
            // A name the kernel did not print under that spelling. Counted
            // rather than failed: duplicates resolve to their first occurrence
            // on both sides, and the two need not pick the same one.
            None => absent += 1,
        }
    }

    assert!(
        disagreements == 0,
        "{disagreements} of {} symbol(s) carry an address the kernel never printed \
         for that name. The first few: {:#?}",
        table.len(),
        disagreed
    );
    assert!(
        matched > 100_000,
        "only {matched} symbols matched by address ({absent} names not printed by \
         the kernel); that is too few to call the decode verified"
    );
}

/// The symbols a Linux memory tier actually needs are among them, at the right
/// addresses.
///
/// This is the point of the exercise: these are what discovery must resolve and
/// what BTF cannot supply.
#[test]
fn the_symbols_discovery_needs_are_recovered() {
    let Some(truth) = ground_truth() else { return };
    let Some(table) = recovered() else { return };

    for name in ["linux_banner", "init_task", "_stext", "_text"] {
        let recovered = table
            .address_of(name)
            .unwrap_or_else(|| panic!("{name} was not recovered from the capture"));
        let printed = truth
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not in the ground truth"));
        assert!(
            printed.iter().any(|&(a, _)| a == recovered),
            "{name}: recovered {recovered:#x}, kernel printed {:?}",
            printed
                .iter()
                .map(|&(a, _)| format!("{a:#x}"))
                .collect::<Vec<_>>()
        );
    }
}

/// Per-CPU symbols land at their absolute offsets, not shifted by the base.
///
/// The `ABSOLUTE_PERCPU` rule is the one place a plausible-looking simplification
/// silently misplaces thousands of symbols: a non-negative offset is already an
/// address, and adding `relative_base` to it moves every per-CPU symbol into the
/// middle of the kernel image.
#[test]
fn per_cpu_symbols_are_not_shifted_by_the_relative_base() {
    let Some(truth) = ground_truth() else { return };
    let Some(table) = recovered() else { return };

    // These sit at low absolute addresses in /proc/kallsyms precisely because
    // they are per-CPU offsets rather than kernel virtual addresses.
    let low: Vec<&seance_memory::kallsyms::Symbol> = table
        .symbols()
        .iter()
        .filter(|s| s.address < 0x1000_0000)
        .collect();
    assert!(
        low.len() > 100,
        "only {} per-CPU style symbols recovered; the ABSOLUTE_PERCPU branch is \
         probably not being taken",
        low.len()
    );
    for symbol in low.iter().take(200) {
        if let Some(printed) = truth.get(&symbol.name) {
            assert!(
                printed.iter().any(|&(a, _)| a == symbol.address),
                "{}: recovered {:#x}, kernel printed {:?} — the per-CPU branch \
                 shifted it",
                symbol.name,
                symbol.address,
                printed
                    .iter()
                    .map(|&(a, _)| format!("{a:#x}"))
                    .collect::<Vec<_>>()
            );
        }
    }
}

/// Type letters match what the kernel printed.
///
/// The first character of an expanded name is the symbol's type and must be
/// split off it. This checks that against `/proc/kallsyms` rather than by
/// heuristic: an earlier version of this test flagged any name beginning with
/// its own type letter, and 5,683 of 202,525 do so entirely by coincidence —
/// `t` with `tcp_`, `task_`, `trace_`, and so on. That measured the English
/// language, not the decoder.
#[test]
fn symbol_type_letters_match_what_the_kernel_printed() {
    let Some(truth) = ground_truth() else { return };
    let Some(table) = recovered() else { return };

    let mut checked = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    for symbol in table.symbols() {
        // Only names the kernel printed exactly once: for a repeated name there
        // is no way to say which occurrence this is.
        let Some(printed) = truth.get(&symbol.name).filter(|set| set.len() == 1) else {
            continue;
        };
        let (_, kind) = *printed.iter().next().expect("exactly one");
        if kind != symbol.kind && wrong.len() < 12 {
            wrong.push(format!(
                "{}: recovered type '{}', kernel printed '{kind}'",
                symbol.name, symbol.kind
            ));
        }
        checked += 1;
    }
    assert!(
        wrong.is_empty(),
        "type letters disagree with the kernel for: {wrong:#?}"
    );
    assert!(
        checked > 50_000,
        "only {checked} uniquely-named symbols compared"
    );
}

/// `_stext` is a text symbol, named exactly that.
#[test]
fn a_known_symbol_keeps_its_name_and_type() {
    let Some(table) = recovered() else { return };
    let stext = table
        .symbols()
        .iter()
        .find(|s| s.name == "_stext")
        .expect("_stext must be recovered under exactly that name");
    assert_eq!(stext.kind, 'T');
}

/// **The whole point: a capture that describes itself completely.**
///
/// BTF supplies the types, kallsyms the addresses, and together they are what an
/// ISF file contains. A table compiled from the pair can answer both "where is
/// `task_struct.comm`" and "where is `init_task`" — with nothing matched by
/// banner, nothing downloaded, and no possibility of describing a different
/// build, because both halves came out of this image.
#[test]
fn btf_and_kallsyms_together_compile_to_a_complete_symbol_table() {
    let Some(table) = recovered() else { return };
    let Some(btf_path) = corpus::file(CORPUS_VAR, "vmlinux.btf") else {
        return;
    };
    let btf = seance_memory::btf::Btf::parse(&std::fs::read(btf_path).expect("gate checked"))
        .expect("the kernel's BTF parses");

    let source = seance_memory::btf_isf::to_isf_source_with_symbols(
        &btf,
        Some("Linux version 6.8.0-1061-aws"),
        Some(table),
    )
    .expect("converts");

    let compiled = seance_symbols::SymbolTable::compile_source(
        source,
        &seance_symbols::CompileOptions::default(),
    )
    .expect("a document built from the kernel's own BTF and kallsyms must compile");

    // Types, from BTF.
    let size = compiled
        .size_of("task_struct")
        .expect("task_struct must be described");
    let comm = compiled
        .member_offset("task_struct", "comm")
        .expect("task_struct.comm must resolve");
    assert!(comm < size);

    // Addresses, from kallsyms — the half BTF could never supply, and the half
    // Linux discovery cannot proceed without.
    for name in ["linux_banner", "init_task", "_stext"] {
        let address = compiled
            .symbol_address(name)
            .unwrap_or_else(|e| panic!("{name} did not resolve: {e:?}"));
        assert_eq!(
            Some(address),
            table.address_of(name),
            "{name} changed value passing through the ISF"
        );
    }
}

/// A types-only document still claims no addresses.
///
/// The two forms must stay distinguishable: one can corroborate a symbol file,
/// the other can replace it, and confusing them would let a table that knows no
/// addresses be presented as though it did.
#[test]
fn without_kallsyms_the_document_still_claims_no_addresses() {
    let Some(btf_path) = corpus::file(CORPUS_VAR, "vmlinux.btf") else {
        return;
    };
    let btf = seance_memory::btf::Btf::parse(&std::fs::read(btf_path).expect("gate checked"))
        .expect("parses");
    let doc = seance_memory::btf_isf::to_isf_json(&btf, None).expect("converts");
    assert_eq!(doc["symbols"], serde_json::json!({}));
}
