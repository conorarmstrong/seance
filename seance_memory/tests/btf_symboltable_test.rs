//! BTF → ISF → `SymbolTable`, against a real kernel's type information.
//!
//! # What this closes
//!
//! `seance_memory::btf` could read a kernel's own type description but nothing
//! consumed it, so an examiner got no benefit. This exercises the whole chain:
//! the BTF a kernel wrote, rendered as an ISF document, compiled by
//! `seance_symbols` through its ordinary admission gates, and queried for the
//! member offsets a Linux memory tier actually reads.
//!
//! Compiling through the real parser is the point. `SymbolTable::compile` runs
//! the gates — duplicate member names, bitfields out of range, members that
//! overrun their aggregate, type references that do not resolve — so a document
//! this converter produces is held to the same standard as an ISF from disk. A
//! parallel symbol path that skipped them would be a second place for those
//! checks to be missing.
//!
//! # Corpus
//!
//! `SEANCE_LINUX_MEM` must name a directory holding `vmlinux.btf`, a copy of
//! `/sys/kernel/btf/vmlinux` from an Ubuntu host running `6.8.0-1061-aws`.
//! Absent, these skip; named and missing, they fail.

use seance_core::test_support::corpus;
use seance_memory::btf::Btf;
use seance_memory::btf_isf::{to_isf_json, to_isf_source, PRODUCER_NAME};

const CORPUS_VAR: &str = "SEANCE_LINUX_MEM";
const BTF_FILE: &str = "vmlinux.btf";

fn kernel_btf() -> Option<Btf> {
    let path = corpus::file(CORPUS_VAR, BTF_FILE)?;
    Some(Btf::parse(&std::fs::read(path).expect("the gate proved this exists")).expect("parses"))
}

/// A real kernel's BTF renders to a document the ISF parser accepts.
#[test]
fn a_real_kernels_btf_renders_to_a_parseable_isf_document() {
    let Some(btf) = kernel_btf() else { return };
    let doc = to_isf_json(&btf, Some("Linux version 6.8.0-1061-aws")).expect("converts");

    let json = doc.to_string();
    let parsed = seance_symbols::IsfDocument::parse(json.as_bytes()).expect(
        "the ISF parser must accept a document generated from a kernel's own BTF; \
         a failure here means the converter emits something the schema does not allow",
    );

    // Thousands of structs, not a handful: a converter that quietly dropped
    // most of them would still produce a valid document.
    assert!(
        parsed.user_types.len() > 5_000,
        "only {} user types survived the conversion",
        parsed.user_types.len()
    );
    assert_eq!(parsed.metadata.format, "6.2.0");
    assert_eq!(
        parsed
            .metadata
            .producer
            .as_ref()
            .and_then(|p| p.name.as_deref()),
        Some(PRODUCER_NAME),
        "provenance must survive: a report has to be able to say the layout came \
         from BTF in the image rather than a symbol file matched by banner"
    );
}

/// **The end of the chain.** A `SymbolTable` compiles, and answers.
#[test]
fn a_symboltable_compiles_from_btf_and_answers_member_offsets() {
    let Some(btf) = kernel_btf() else { return };
    let table = seance_symbols::SymbolTable::compile_source(
        to_isf_source(&btf, Some("Linux version 6.8.0-1061-aws")).expect("converts"),
        &seance_symbols::CompileOptions::default(),
    )
    .expect(
        "a document generated from a kernel's own BTF must survive the admission \
         gates. If this fails, the converter is emitting something the gates \
         reject and the message names which gate",
    );

    // The members a Linux memory tier reads. Offsets are not pinned to values —
    // they are properties of one build — but each must resolve and lie inside
    // its struct, which is what a misaligned conversion would break.
    let size = table
        .size_of("task_struct")
        .expect("task_struct must have a size");
    assert!(
        (1024..=65536).contains(&size),
        "task_struct is {size} bytes, which is not plausible"
    );

    for member in ["comm", "pid", "tgid", "mm", "parent"] {
        let offset = table
            .member_offset("task_struct", member)
            .unwrap_or_else(|e| panic!("task_struct.{member} did not resolve: {e:?}"));
        assert!(
            offset < size,
            "task_struct.{member} at {offset} is outside the {size}-byte struct"
        );
    }
}

/// The compiled table agrees with the BTF it was generated from.
///
/// The converter and the compiler are separate pieces of machinery with
/// separate notions of what an offset is — BTF counts bits, ISF counts bytes.
/// This checks the two ends of the pipeline against each other across a wide
/// sample rather than the handful of members above.
#[test]
fn compiled_offsets_match_the_btf_they_came_from() {
    let Some(btf) = kernel_btf() else { return };
    let table = seance_symbols::SymbolTable::compile_source(
        to_isf_source(&btf, None).expect("converts"),
        &seance_symbols::CompileOptions::default(),
    )
    .expect("compiles");

    let mut compared = 0usize;
    for name in btf.composite_names().take(2000) {
        let Some(composite) = btf.composite(name) else {
            continue;
        };
        if composite.size == 0 {
            continue;
        }
        for member in &composite.members {
            // Anonymous members are keyed by a generated name and bitfields do
            // not have a byte offset; both are covered elsewhere.
            if member.name.is_empty() || member.bitfield_size.is_some() {
                continue;
            }
            let Some(expected) = member.byte_offset() else {
                continue;
            };
            if let Ok(actual) = table.member_offset(name, &member.name) {
                assert_eq!(
                    actual, expected,
                    "{name}.{} is byte {expected} in the BTF and {actual} in the \
                     compiled table",
                    member.name
                );
                compared += 1;
            }
        }
    }
    assert!(
        compared > 5_000,
        "only {compared} members compared, too few to mean anything"
    );
}

/// **Enumerations cross from BTF, with the kernel's own values** (`MEM-042`).
///
/// Every value below is independent of this converter: `module_state`,
/// `mod_mem_type` and `bpf_prog_type` are the kernel's source
/// (`include/linux/module.h`, `include/uapi/linux/bpf.h`), and the sign, width
/// and 64-bit constants were read from this same blob with `bpftool btf dump
/// file vmlinux.btf` — a second reader of the format, not this crate's.
/// Before this, the generated document's `enums` section was empty and every
/// enum-typed member was typed as a 4-byte signed `int` — wrong in width for
/// the 1-byte `scsi_cmnd_submitter` and the 8-byte `ENUM64` kinds.
#[test]
fn enumerations_cross_from_btf_with_the_kernels_own_values() {
    let Some(btf) = kernel_btf() else { return };
    let doc = to_isf_json(&btf, None).expect("converts");
    let table = seance_symbols::SymbolTable::compile_source(
        to_isf_source(&btf, None).expect("converts"),
        &seance_symbols::CompileOptions::default(),
    )
    .expect("compiles with its enumerations");

    // module_state: unsigned, four constants.
    assert_eq!(doc["enums"]["module_state"]["base"], "unsigned int");
    for (name, value) in [
        ("MODULE_STATE_LIVE", 0),
        ("MODULE_STATE_COMING", 1),
        ("MODULE_STATE_GOING", 2),
        ("MODULE_STATE_UNFORMED", 3),
    ] {
        assert_eq!(
            table.enum_value("module_state", name).ok(),
            Some(value),
            "module_state.{name}"
        );
    }
    assert_eq!(
        table.enum_constant_name("module_state", 0).ok().flatten(),
        Some("MODULE_STATE_LIVE")
    );
    // The member is typed by the enumeration, not by a stand-in int.
    assert_eq!(
        doc["user_types"]["module"]["fields"]["state"]["type"],
        serde_json::json!({ "kind": "enum", "name": "module_state" })
    );

    // mod_mem_type: SIGNED (MOD_INVALID is -1), the 6.4+ module-memory index.
    assert_eq!(doc["enums"]["mod_mem_type"]["base"], "int");
    assert_eq!(table.enum_value("mod_mem_type", "MOD_TEXT").ok(), Some(0));
    assert_eq!(
        table.enum_value("mod_mem_type", "MOD_INIT_RODATA").ok(),
        Some(6)
    );
    assert_eq!(
        table.enum_value("mod_mem_type", "MOD_INVALID").ok(),
        Some(-1)
    );

    // bpf_prog_type: UAPI-fixed numbering.
    assert_eq!(
        table.enum_constant_name("bpf_prog_type", 8).ok().flatten(),
        Some("BPF_PROG_TYPE_CGROUP_SKB")
    );

    // A 1-byte enum is one byte wide, not four.
    assert_eq!(doc["enums"]["scsi_cmnd_submitter"]["size"], 1);
    assert_eq!(doc["enums"]["scsi_cmnd_submitter"]["base"], "unsigned char");
    assert_eq!(
        doc["user_types"]["scsi_cmnd"]["fields"]["submitter"]["type"],
        serde_json::json!({ "kind": "enum", "name": "scsi_cmnd_submitter" })
    );

    // ENUM64: 8 bytes wide, constants above 2^32 exact.
    assert_eq!(doc["enums"]["netdev_priv_flags"]["size"], 8);
    assert_eq!(
        table
            .enum_value("netdev_priv_flags", "IFF_SEE_ALL_HWTSTAMP_REQUESTS")
            .ok(),
        Some(8_589_934_592)
    );

    // Two different enumerations share the name `energy_perf_value_index` in
    // this kernel (EPP_* and EPB_*). Neither is emitted under that name — a
    // lookup by it could not say which was meant — rather than one silently
    // standing in for the other.
    assert!(doc["enums"].get("energy_perf_value_index").is_none());
    assert!(table.enumeration("energy_perf_value_index").is_err());
}

/// No symbol addresses are invented, all the way through the chain.
///
/// BTF carries none. A table that resolved `init_task` to an address would be
/// resolving it to a fabrication, and reading there returns whatever is mapped.
#[test]
fn the_compiled_table_claims_no_symbol_addresses() {
    let Some(btf) = kernel_btf() else { return };
    let doc = to_isf_json(&btf, None).expect("converts");
    assert_eq!(
        doc["symbols"],
        serde_json::json!({}),
        "the generated document must carry no symbols; addresses come from \
         kallsyms, which is separate work"
    );

    let table = seance_symbols::SymbolTable::compile_source(
        to_isf_source(&btf, None).expect("converts"),
        &seance_symbols::CompileOptions::default(),
    )
    .expect("compiles");

    for symbol in ["init_task", "swapper_pg_dir", "linux_banner"] {
        assert!(
            table.symbol_address(symbol).is_err(),
            "{symbol} resolved to an address, but BTF carries none — this table \
             is inventing one"
        );
    }
}
