//! The binding against the shapes that actually occur in evidence.
//!
//! Every case here is taken from a real build difference, because unit tests
//! against a made-up layout are what let the original defect through: the
//! Windows fixtures named `xp_profile` and `xp_process_image` declared
//! `TypeIndex` and `InfoMask`, which are **Vista** members, so the tests
//! asserted the wrong layout under the right name and the XP path was never
//! exercised.
//!
//! So the fixture below is deliberately an **XP-shaped** object header: it has
//! `NameInfoOffset` and no `InfoMask`, which is the exact pair that killed
//! eight analysis stages on a real Windows XP capture.

use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use super::{
    first_declared_member, first_member, required_offset, required_size, Field, MemberSet,
    MemberSpec, MemberUse, StageId, TypeSpec, TypeUse,
};
use crate::layer::MemoryLayer;
use crate::object::StructReader;
use crate::physical::PhysicalLayer;

/// A symbol table shaped like the builds this module exists for.
///
/// - `_OBJECT_HEADER` carries `NameInfoOffset` and **no** `InfoMask`: the
///   Windows XP / 2003 layout.
/// - `ucred` reaches its uid through an embedded `cr_posix`, the macOS shape
///   whose fallback runs in both directions across the 129 Kernel Debug Kit
///   packs.
/// - The capability set is named `kernel_cap_struct` and **not** `kernel_cap_t`,
///   the Debian-3.2 difference that makes Volatility fail this way itself.
/// - `shadowed_name` is declared as both a base type and a user type, so a
///   lookup by name alone is refused: a symbol table that cannot answer, which
///   is a different claim from a build that has no such member.
/// - `external_ref.outer` points at `kernel!_MISSING`, a reference into another
///   symbol table that was never loaded. It compiles — this is how the
///   hand-written pool-header fragments point at the real kernel table — and
///   fails at the point of use, which is the second way a table cannot answer.
const FIXTURE_ISF: &str = r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-binding-fixture", "version": "1.0.0"},
    "linux": {"symbols": [], "types": []}
  },
  "base_types": {
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"},
    "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"},
    "shadowed_name": {"size": 4, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_OBJECT_HEADER": {"size": 32, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}},
      "NameInfoOffset": {"offset": 16, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 24, "type": {"kind": "base", "name": "unsigned int"}}
    }},
    "posix_cred": {"size": 4, "kind": "struct", "fields": {
      "cr_uid": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}
    }},
    "ucred": {"size": 8, "kind": "struct", "fields": {
      "cr_ref": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}},
      "cr_posix": {"offset": 4, "type": {"kind": "struct", "name": "posix_cred"}}
    }},
    "kernel_cap_struct": {"size": 4, "kind": "struct", "fields": {
      "cap": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}
    }},
    "shadowed_name": {"size": 4, "kind": "struct", "fields": {
      "field": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}
    }},
    "external_ref": {"size": 8, "kind": "struct", "fields": {
      "outer": {"offset": 0, "type": {"kind": "struct", "name": "kernel!_MISSING"}}
    }}
  }
}"#;

/// Total size of the fixture image, in bytes.
const IMAGE_LEN: usize = 64;
/// Address of the fully readable `_OBJECT_HEADER`.
const HEADER: u64 = 0x00;
/// Address of an `_OBJECT_HEADER` whose members run off the top of the address
/// space, so a read of one fails without the member being absent.
const HEADER_OFF_THE_END: u64 = 0x30;
/// Value written at `_OBJECT_HEADER.NameInfoOffset`.
const NAME_INFO_OFFSET: u64 = 0x2A;
/// Value written at `_OBJECT_HEADER.PointerCount`.
const POINTER_COUNT: u64 = 7;

const STAGE: StageId = StageId::new(
    "pool_scan",
    "MemoryPoolScan",
    false,
    "Process objects found by scanning the kernel pool.",
);

fn symbols() -> Arc<SymbolTable> {
    let source = seance_symbols::load_slice(FIXTURE_ISF.as_bytes(), &DecompressLimits::default())
        .expect("the fixture ISF must load");
    Arc::new(
        SymbolTable::compile_source(source, &CompileOptions::default())
            .unwrap_or_else(|err| panic!("the fixture ISF must compile: {err}")),
    )
}

/// A reader over a small flat image with one readable object header at zero.
fn reader() -> StructReader {
    let mut bytes = vec![0u8; IMAGE_LEN];
    bytes[0..4].copy_from_slice(&(POINTER_COUNT as u32).to_le_bytes());
    bytes[16] = NAME_INFO_OFFSET as u8;
    bytes[24..28].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let layer: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(source).expect("the fixture image is non-empty"));
    StructReader::new(layer, symbols())
}

// ── Alternative names ───────────────────────────────────────────────────────

#[test]
fn a_member_present_under_the_first_candidate_resolves_to_it() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "name_info",
            &["_OBJECT_HEADER"],
            &["NameInfoOffset", "InfoMask"],
        )],
    );
    let binding = SET.bind(&reader()).expect("nothing here is required");
    let bound = binding.member("name_info").expect("declared key");
    assert_eq!(bound.member(), Some("NameInfoOffset"));
    assert_eq!(bound.type_name(), Some("_OBJECT_HEADER"));
    assert_eq!(bound.offset(), Some(16));
}

/// The build declares only the *second* spelling, and the binding has to say
/// which one it used: an examiner reading a report needs to know the layout the
/// analysis worked from.
#[test]
fn a_member_present_only_under_the_second_candidate_resolves_and_names_it() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "name_info",
            &["_OBJECT_HEADER"],
            &["InfoMask", "NameInfoOffset"],
        )],
    );
    let binding = SET.bind(&reader()).expect("nothing here is required");
    let bound = binding.member("name_info").expect("declared key");
    assert_eq!(
        bound.member(),
        Some("NameInfoOffset"),
        "the second candidate is the one this build has"
    );
    assert_eq!(bound.offset(), Some(16));
    assert_eq!(bound.candidates(), &["InfoMask", "NameInfoOffset"]);
}

/// The regression test for the defect this module exists to remove.
///
/// Against the unfixed code this is `reader.member_offset(TYPE, "InfoMask")?`,
/// which returns `Err` and takes eight analysis stages down with it. Here it is
/// an answer: this build has no such member, and nothing was missed.
#[test]
fn a_member_under_neither_candidate_is_not_declared_and_is_not_an_error() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "info_mask",
            &["_OBJECT_HEADER"],
            &["InfoMask", "TypeIndex"],
        )],
    );
    let binding = SET
        .bind(&reader())
        .expect("a build-variant member this kernel never had must not fail a stage");
    let bound = binding.member("info_mask").expect("declared key");
    assert_eq!(bound.resolution(), &MemberUse::NotDeclared);
    assert_eq!(
        bound.offset_field(),
        Field::NotDeclared { member: "InfoMask" },
        "the canonical candidate is what a report names"
    );
    assert_eq!(bound.to_json()["kind"], "not_declared");
}

/// The macOS credential shape, which needs a fallback in *both* directions:
/// `cr_posix.cr_uid` is absent in 6 Kernel Debug Kit packs where `cr_uid`
/// exists, and `cr_uid` is absent in the other 123.
#[test]
fn a_member_reached_through_an_embedded_struct_resolves_in_either_order() {
    const PREFERRING_POSIX: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "uid",
            &["ucred"],
            &["cr_posix.cr_uid", "cr_uid"],
        )],
    );
    const PREFERRING_FLAT: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "uid",
            &["ucred"],
            &["cr_uid", "cr_posix.cr_uid"],
        )],
    );
    let reader = reader();

    let first = PREFERRING_POSIX.bind(&reader).expect("optional");
    assert_eq!(
        first.member("uid").expect("declared key").member(),
        Some("cr_posix.cr_uid")
    );
    assert_eq!(first.member("uid").expect("declared key").offset(), Some(4));

    // This build has no flat `cr_uid`, so the fallback carries it.
    let second = PREFERRING_FLAT.bind(&reader).expect("optional");
    assert_eq!(
        second.member("uid").expect("declared key").member(),
        Some("cr_posix.cr_uid")
    );
}

/// Debian 3.2 names the capability set `kernel_cap_t`; other kernels name it
/// `kernel_cap_struct`. Volatility fails on exactly this, recording the plugin
/// as an unexpected error rather than as a naming difference.
#[test]
fn a_type_this_build_names_differently_resolves_to_the_name_it_has() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[TypeSpec::new(
            "caps",
            &["kernel_cap_t", "kernel_cap_struct"],
        )],
        &[MemberSpec::new(
            "cap",
            &["kernel_cap_t", "kernel_cap_struct"],
            &["cap"],
        )],
    );
    let binding = SET.bind(&reader()).expect("optional");
    let caps = binding.type_of("caps").expect("declared key");
    assert_eq!(caps.type_name(), Some("kernel_cap_struct"));
    assert_eq!(caps.size(), Some(4));
    assert_eq!(
        binding.member("cap").expect("declared key").type_name(),
        Some("kernel_cap_struct")
    );
}

#[test]
fn a_type_under_no_candidate_name_is_not_declared_and_is_not_an_error() {
    const SET: MemberSet = MemberSet::new(STAGE, &[TypeSpec::new("caps", &["kernel_cap_t"])], &[]);
    let binding = SET
        .bind(&reader())
        .expect("a type this kernel never had must not fail a stage");
    let caps = binding.type_of("caps").expect("declared key");
    assert_eq!(caps.resolution(), &TypeUse::NotDeclared);
    assert_eq!(
        caps.size_field(),
        Field::NotDeclared {
            member: "kernel_cap_t"
        }
    );
}

/// A name that exists but is not an aggregate has no members to reach. That is
/// a statement about this build's layout, not about the symbol table, so it is
/// an absence and not a failure.
#[test]
fn a_member_asked_of_a_non_aggregate_type_is_absent_rather_than_fatal() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "count",
            &["unsigned int"],
            &["NameInfoOffset"],
        )],
    );
    let binding = SET.bind(&reader()).expect("optional");
    assert_eq!(
        binding.member("count").expect("declared key").resolution(),
        &MemberUse::NotDeclared
    );
}

// ── Absence versus a table that cannot answer ───────────────────────────────

/// The distinction the four-way split exists for. A shadowed name is a symbol
/// table that refuses to say which layout was meant; reporting that as "this
/// build has no such member" would be a fabricated claim about the machine.
#[test]
fn a_symbol_table_that_cannot_answer_is_unavailable_not_absent() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new("x", &["shadowed_name"], &["field"])],
    );
    let binding = SET.bind(&reader()).expect("optional");
    let bound = binding.member("x").expect("declared key");
    assert!(
        matches!(bound.resolution(), MemberUse::Unavailable { .. }),
        "got {:?}",
        bound.resolution()
    );
    let field = bound.offset_field();
    assert!(field.is_unavailable());
    assert!(
        !field.is_not_declared(),
        "a broken table is not evidence that the kernel lacks the field"
    );
}

/// The second way a table cannot answer, and the one that reaches the binding
/// disguised as absence.
///
/// A reference the document never bound stays in the arena as its own entry and
/// fails at the point of use. Walking a member path through it asks the reader
/// for an aggregate and does not get one, so before the reader named the
/// unresolved reference this landed on the same error as "that name is a scalar,
/// not a struct" — and the binding, correctly treating *that* as a fact about
/// the build's layout, reported a symbol table it could not read as **this
/// kernel has no such member**. That is a fabricated claim about the suspect's
/// machine, and it is the mirror image of the defect this module exists to
/// remove.
#[test]
fn a_member_behind_an_unresolved_type_reference_is_unavailable_not_absent() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "through_the_missing_table",
            &["external_ref"],
            &["outer.anything"],
        )],
    );
    let binding = SET.bind(&reader()).expect("nothing here is required");
    let bound = binding
        .member("through_the_missing_table")
        .expect("declared key");
    assert!(
        matches!(bound.resolution(), MemberUse::Unavailable { .. }),
        "a reference that was never bound is a table that could not answer, got {:?}",
        bound.resolution()
    );
    let field = bound.offset_field();
    assert!(field.is_unavailable());
    assert!(
        !field.is_not_declared(),
        "a symbol table the analysis could not load is not evidence about the kernel's layout"
    );

    // And the low-level idiom agrees, because every tier reaches this through
    // one of the two.
    assert!(
        first_member(&reader(), "external_ref", &["outer.anything"]).is_err(),
        "first_member must not fold an unresolved reference into 'this build has no such member'"
    );
}

#[test]
fn first_member_separates_absence_from_a_table_that_cannot_answer() {
    let reader = reader();
    assert_eq!(
        first_member(&reader, "_OBJECT_HEADER", &["InfoMask", "NameInfoOffset"])
            .expect("neither candidate is a table failure"),
        Some("NameInfoOffset")
    );
    assert_eq!(
        first_member(&reader, "_OBJECT_HEADER", &["InfoMask"]).expect("absence is not a failure"),
        None
    );
    assert!(
        first_member(&reader, "shadowed_name", &["field"]).is_err(),
        "a table that cannot answer must not be reported as an absent member"
    );
}

// ── Required ────────────────────────────────────────────────────────────────

/// The only route to a stage failure, and it has to say what is lost.
#[test]
fn a_required_member_that_is_absent_fails_naming_the_member_and_what_is_lost() {
    const WITHOUT_IT: &str =
        "no object's name can be recovered, so every handle would be reported unnamed";
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new("info_mask", &["_OBJECT_HEADER"], &["InfoMask"]).required(WITHOUT_IT)],
    );
    let err = SET
        .bind(&reader())
        .expect_err("a required member this build lacks is a stage failure");
    assert_eq!(err.class(), "required_not_declared");
    assert_eq!(err.stage(), "pool_scan");
    let text = err.to_string();
    assert!(text.contains("InfoMask"), "{text}");
    assert!(text.contains("pool_scan"), "{text}");
    assert!(text.contains(WITHOUT_IT), "{text}");
}

#[test]
fn a_required_member_this_build_has_binds_without_complaint() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[
            MemberSpec::new("name_info", &["_OBJECT_HEADER"], &["NameInfoOffset"])
                .required("no object name can be located"),
        ],
    );
    let binding = SET.bind(&reader()).expect("this build has the member");
    assert_eq!(binding.member("name_info").unwrap().offset(), Some(16));
}

#[test]
fn a_required_type_that_is_absent_fails_naming_what_is_lost() {
    const WITHOUT_IT: &str = "no pool allocation can be sized, so no candidate can be found at all";
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[TypeSpec::new("pool_header", &["_POOL_HEADER"]).required(WITHOUT_IT)],
        &[],
    );
    let err = SET.bind(&reader()).expect_err("required and absent");
    let text = err.to_string();
    assert!(text.contains("_POOL_HEADER"), "{text}");
    assert!(text.contains(WITHOUT_IT), "{text}");
}

// ── One required value, without a whole declaration ─────────────────────────

/// The sentence an examiner gets when a stage stops for a stride it cannot do
/// without.
///
/// The raw form these sites used — `reader.size_of(T)?` — reaches the examiner
/// through a stage error's `#[error(transparent)]` variant as a bare
/// `SymbolError`, which names neither the stage nor what stopping cost. Both
/// have to be in the text, so both are asserted.
#[test]
fn a_required_size_this_build_lacks_names_the_stage_the_type_and_what_is_lost() {
    const WITHOUT_IT: &str =
        "a handle table entry has no width, so no entry after the first can be located and every \
         process would be reported as holding no handles";
    let err = required_size(&symbols(), STAGE, &["_HANDLE_TABLE_ENTRY"], WITHOUT_IT)
        .expect_err("the fixture has no _HANDLE_TABLE_ENTRY");
    assert_eq!(err.class(), "required_not_declared");
    let text = err.to_string();
    assert!(text.contains("_HANDLE_TABLE_ENTRY"), "{text}");
    assert!(text.contains("pool_scan"), "{text}");
    assert!(text.contains(WITHOUT_IT), "{text}");
}

/// A table that cannot answer must not arrive as "this build has no such type".
///
/// `has_type` is `type_id(..).is_ok()`, so a pre-flight built on it answers
/// `false` for a shadowed name and the stage then tells an examiner the kernel
/// lacks a type it may well have.
#[test]
fn a_required_size_the_table_cannot_answer_is_unresolved_not_absent() {
    let err = required_size(
        &symbols(),
        STAGE,
        &["shadowed_name"],
        "nothing can be strided",
    )
    .expect_err("a name declared in two blocks cannot be sized");
    assert_eq!(
        err.class(),
        "required_unresolved",
        "a shadowed name is a table this analysis could not read, not a fact about the kernel"
    );
    assert!(err.to_string().contains("shadowed_name"), "{err}");
}

#[test]
fn a_required_size_this_build_declares_is_the_size_the_table_gives() {
    assert_eq!(
        required_size(&symbols(), STAGE, &["_OBJECT_HEADER"], "unused here")
            .expect("the fixture declares it"),
        32
    );
}

/// The type-name half varies too: Debian 3.2 names a capability set
/// `kernel_cap_t` where other kernels name it `kernel_cap_struct`, and asking
/// for the first must not fail a stage the second satisfies.
#[test]
fn a_required_size_takes_the_first_name_this_build_declares() {
    assert_eq!(
        required_size(
            &symbols(),
            STAGE,
            &["kernel_cap_t", "kernel_cap_struct"],
            "unused here",
        )
        .expect("the second candidate is declared"),
        4
    );
}

#[test]
fn a_required_offset_this_build_lacks_names_the_member_and_what_is_lost() {
    const WITHOUT_IT: &str = "an object's name cannot be located";
    let err = required_offset(
        &reader(),
        STAGE,
        &["_OBJECT_HEADER"],
        &["InfoMask"],
        WITHOUT_IT,
    )
    .expect_err("the XP-shaped fixture has no InfoMask");
    assert_eq!(err.class(), "required_not_declared");
    let text = err.to_string();
    assert!(text.contains("InfoMask"), "{text}");
    assert!(text.contains("pool_scan"), "{text}");
    assert!(text.contains(WITHOUT_IT), "{text}");
}

#[test]
fn a_required_offset_this_build_declares_is_the_offset_the_table_gives() {
    assert_eq!(
        required_offset(
            &reader(),
            STAGE,
            &["_OBJECT_HEADER"],
            &["InfoMask", "NameInfoOffset"],
            "unused here",
        )
        .expect("the second candidate is declared"),
        16
    );
}

#[test]
fn a_required_offset_the_table_cannot_answer_is_unresolved_not_absent() {
    let err = required_offset(
        &reader(),
        STAGE,
        &["external_ref"],
        &["outer.anything"],
        "nothing can be located",
    )
    .expect_err("a reference the document never bound cannot be walked");
    assert_eq!(err.class(), "required_unresolved");
}

/// A stage holding a table rather than a reader had no absence-aware idiom at
/// all, so it used `has_member` — which answers `false` for a member the table
/// refuses to disambiguate exactly as it does for one the build never had.
#[test]
fn first_declared_member_separates_absence_from_a_table_that_cannot_answer() {
    let symbols = symbols();
    assert_eq!(
        first_declared_member(&symbols, "_OBJECT_HEADER", &["InfoMask", "NameInfoOffset"])
            .expect("neither candidate is a table failure"),
        Some("NameInfoOffset")
    );
    assert_eq!(
        first_declared_member(&symbols, "_OBJECT_HEADER", &["InfoMask"])
            .expect("absence is not a failure"),
        None
    );
    assert_eq!(
        first_declared_member(&symbols, "_POOL_HEADER", &["PoolTag"])
            .expect("a type this build has no name for is absence, not a failure"),
        None
    );
    assert!(
        first_declared_member(&symbols, "shadowed_name", &["field"]).is_err(),
        "a table that cannot say which layout was meant must not be reported as an absent member"
    );
}

// ── Malformed declarations ──────────────────────────────────────────────────

#[test]
fn a_key_the_stage_never_declared_is_refused_rather_than_answered_not_declared() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "name_info",
            &["_OBJECT_HEADER"],
            &["NameInfoOffset"],
        )],
    );
    let binding = SET.bind(&reader()).expect("optional");
    let err = binding
        .member("nmae_info")
        .expect_err("a typo must not read as 'this build has no such member'");
    assert_eq!(err.class(), "undeclared_key");
}

#[test]
fn a_key_declared_twice_is_refused_because_a_lookup_would_be_ambiguous() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[
            MemberSpec::new("name_info", &["_OBJECT_HEADER"], &["NameInfoOffset"]),
            MemberSpec::new("name_info", &["_OBJECT_HEADER"], &["Body"]),
        ],
    );
    let err = SET.bind(&reader()).expect_err("duplicate key");
    assert_eq!(err.class(), "duplicate_key");
}

#[test]
fn a_declaration_with_no_candidate_names_is_refused() {
    const SET: MemberSet =
        MemberSet::new(STAGE, &[], &[MemberSpec::new("nothing", &["ucred"], &[])]);
    let err = SET.bind(&reader()).expect_err("nothing to look for");
    assert_eq!(err.class(), "no_candidates");
}

// ── Reading through the binding ─────────────────────────────────────────────

#[test]
fn reading_a_declared_member_yields_the_value_the_image_holds() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[
            MemberSpec::new(
                "name_info",
                &["_OBJECT_HEADER"],
                &["NameInfoOffset", "InfoMask"],
            ),
            MemberSpec::new("pointer_count", &["_OBJECT_HEADER"], &["PointerCount"]),
        ],
    );
    let reader = reader();
    let binding = SET.bind(&reader).expect("optional");
    let obj = reader.object(HEADER, "_OBJECT_HEADER").expect("an object");
    assert_eq!(
        binding.read_unsigned(&obj, "name_info").expect("declared"),
        Field::Known(NAME_INFO_OFFSET)
    );
    assert_eq!(
        binding
            .read_unsigned(&obj, "pointer_count")
            .expect("declared"),
        Field::Known(POINTER_COUNT)
    );
}

/// The XP case at the point of use: the stage runs, reads what exists, and
/// records the absent column as absent instead of dying.
#[test]
fn reading_a_member_this_build_lacks_yields_not_declared_rather_than_an_error() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "info_mask",
            &["_OBJECT_HEADER"],
            &["InfoMask"],
        )],
    );
    let reader = reader();
    let binding = SET.bind(&reader).expect("optional");
    let obj = reader.object(HEADER, "_OBJECT_HEADER").expect("an object");
    assert_eq!(
        binding.read_unsigned(&obj, "info_mask").expect("declared"),
        Field::NotDeclared { member: "InfoMask" }
    );
}

/// The member exists and the bytes do not. That is damage to the evidence, and
/// it must not render as the build lacking the field.
#[test]
fn reading_a_member_whose_bytes_were_not_acquired_yields_unavailable() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "name_info",
            &["_OBJECT_HEADER"],
            &["NameInfoOffset"],
        )],
    );
    let reader = reader();
    let binding = SET.bind(&reader).expect("optional");
    let obj = reader
        .object(HEADER_OFF_THE_END, "_OBJECT_HEADER")
        .expect("an object");
    let field = binding.read_unsigned(&obj, "name_info").expect("declared");
    assert!(field.is_unavailable(), "got {field:?}");
    assert!(!field.is_not_declared());
}

/// The offset is real, and the bytes at it inside an unrelated structure parse
/// perfectly. Refusing is the only way this does not become a confident wrong
/// value.
#[test]
fn reading_a_member_from_an_object_of_the_wrong_type_is_refused() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[],
        &[MemberSpec::new(
            "name_info",
            &["_OBJECT_HEADER"],
            &["NameInfoOffset"],
        )],
    );
    let reader = reader();
    let binding = SET.bind(&reader).expect("optional");
    let wrong = reader.object(HEADER, "ucred").expect("an object");
    let err = binding
        .read_unsigned(&wrong, "name_info")
        .expect_err("a member read off the wrong structure must not answer");
    assert_eq!(err.class(), "wrong_object_type");
    let text = err.to_string();
    assert!(text.contains("ucred"), "{text}");
    assert!(text.contains("_OBJECT_HEADER"), "{text}");
}

// ── The layout report ───────────────────────────────────────────────────────

/// Without this record a report says a column is empty and cannot say whether
/// the kernel had no such field or the analysis looked under a name this kernel
/// does not use.
#[test]
fn the_layout_report_says_which_candidate_this_build_declared() {
    const SET: MemberSet = MemberSet::new(
        STAGE,
        &[TypeSpec::new(
            "caps",
            &["kernel_cap_t", "kernel_cap_struct"],
        )],
        &[
            MemberSpec::new(
                "name_info",
                &["_OBJECT_HEADER"],
                &["InfoMask", "NameInfoOffset"],
            ),
            MemberSpec::new("info_mask", &["_OBJECT_HEADER"], &["InfoMask"]),
        ],
    );
    let binding = SET.bind(&reader()).expect("optional");
    let json = binding.to_json();

    assert_eq!(json["stage"], "pool_scan");
    assert_eq!(json["types"][0]["kind"], "declared");
    assert_eq!(json["types"][0]["type"], "kernel_cap_struct");
    assert_eq!(json["types"][0]["size"], 4);

    let members = json["members"].as_array().expect("an array");
    let resolved = &members[0];
    assert_eq!(resolved["key"], "name_info");
    assert_eq!(resolved["kind"], "declared");
    assert_eq!(resolved["member"], "NameInfoOffset");
    assert_eq!(resolved["offset"], 16);
    assert_eq!(resolved["candidates"][0], "InfoMask");

    let absent = &members[1];
    assert_eq!(absent["kind"], "not_declared");
    assert_eq!(absent["required"], false);
    assert!(
        absent.get("offset").is_none(),
        "there was never an offset: {absent}"
    );
}
