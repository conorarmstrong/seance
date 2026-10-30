//! What the shim-database reader has to do, stated against measured ground
//! truth.
//!
//! # The fixtures, and why they are gated
//!
//! Seven real Microsoft databases, staged from
//! `~/winarm/28000.1_PROFESSIONAL_ARM64_EN-US.ISO` (Windows 11
//! Professional ARM64 EN-US build 28000.1). They are **not committed**: they
//! are Microsoft-copyrighted binaries and this repository is MIT throughout.
//! `test_data/README.md` carries the extraction recipe.
//!
//! Gate: `SEANCE_SDB_SAMPLES`, a directory. Unset skips; set to a missing path
//! panics, because a pass there would report a comparison that never ran.
//!
//! # The census below was measured
//!
//! Walking `sysmain.sdb` gives **77** distinct tag ids and 339,377
//! occurrences. Every number in this file
//! came from walking the staged fixtures with this reader and cross-checking
//! against an independent Python walk; none was copied from elsewhere.
//!
//! | file                  |     bytes | tags    | distinct ids | depth |
//! |-----------------------|----------:|--------:|-------------:|------:|
//! | appraiser.sdb (zdbf)  | 9,734,396 | 499,083 |           92 |     4 |
//! | drvmain.sdb           |   182,092 |   9,938 |           32 |     3 |
//! | frxmain.sdb           |     4,246 |     389 |           24 |     3 |
//! | msimain.sdb           | 3,490,328 |  68,346 |           43 |     5 |
//! | pcamain.sdb           |    67,240 |   5,153 |           31 |     3 |
//! | shellFeatureInbox.sdb |    13,832 |   1,132 |           31 |     5 |
//! | sysmain.sdb           | 4,249,986 | 339,377 |           77 |     4 |

use crate::container::{self, Container, OpenError};
use crate::entities;
use crate::format::{self, TagType, WalkLimit};
use crate::strings;
use std::collections::BTreeSet;

/// The measured census, file by file: `(name, body bytes, tags, distinct ids,
/// max depth)`.
const CENSUS: &[(&str, usize, usize, usize, usize)] = &[
    ("appraiser.sdb", 9_734_396, 499_083, 92, 4),
    ("drvmain.sdb", 182_092, 9_938, 32, 3),
    ("frxmain.sdb", 4_246, 389, 24, 3),
    ("msimain.sdb", 3_490_328, 68_346, 43, 5),
    ("pcamain.sdb", 67_240, 5_153, 31, 3),
    ("shellFeatureInbox.sdb", 13_832, 1_132, 31, 5),
    ("sysmain.sdb", 4_249_986, 339_377, 77, 4),
];

/// A staged fixture, or `None` when the gate is not provisioned.
fn sample(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var("SEANCE_SDB_SAMPLES").ok()?;
    let path = std::path::Path::new(&dir).join(name);
    assert!(
        path.is_file(),
        "{} is missing from the corpus named by SEANCE_SDB_SAMPLES. The gate is ON and \
         cannot open — a pass here would report a comparison that never ran. \
         test_data/README.md carries the extraction recipe.",
        path.display()
    );
    Some(std::fs::read(&path).expect("read the sample"))
}

// --- The container ---------------------------------------------------------

/// A plain database opens as its own bytes.
#[test]
fn a_plain_database_opens_as_its_own_bytes() {
    let Some(bytes) = sample("sysmain.sdb") else {
        return;
    };
    let o = container::open(&bytes).expect("opens");
    assert_eq!(o.container, Container::Plain);
    assert_eq!(o.major_version, 3);
    assert_eq!(o.minor_version, 0);
    assert_eq!(o.body.len(), bytes.len());
    assert!(o.declared_inflated_len.is_none());
    assert!(o.incomplete.is_none());
}

/// A compressed database is inflated and then parsed like any other.
///
/// `appraiser.sdb` is 2,046,855 bytes declaring 9,734,396, and inflates to
/// exactly that — whose first bytes are an ordinary `sdbf` header.
#[test]
fn a_compressed_shim_database_is_inflated_and_parsed_like_any_other() {
    let Some(bytes) = sample("appraiser.sdb") else {
        return;
    };
    assert_eq!(bytes.len(), 2_046_855, "the fixture as shipped");
    let o = container::open(&bytes).expect("opens");
    assert_eq!(o.container, Container::ZlibCompressed);
    assert_eq!(o.declared_inflated_len, Some(9_734_396));
    assert_eq!(
        o.body.len(),
        9_734_396,
        "the declared length and the inflated length agree on this file"
    );
    assert!(
        o.incomplete.is_none(),
        "nothing was short or in disagreement: {:?}",
        o.incomplete
    );
    assert_eq!(
        &o.body[8..12],
        b"sdbf",
        "the inflated bytes are an ordinary plain database"
    );
    // And it walks like one.
    let w = format::walk(&o.body);
    assert!(w.complete(o.body.len()));
}

/// A file named `.sdb` that carries neither magic produces **nothing**.
///
/// Not a parse failure, not an empty record — nothing. A file merely named
/// `.sdb` is not a shim database, and inventing a failure for it would put a
/// refusal in the case that describes no evidence.
#[test]
fn a_file_named_sdb_that_carries_neither_magic_produces_nothing() {
    let mut not_one = vec![0u8; 64];
    not_one[8..12].copy_from_slice(b"junk");
    assert!(matches!(
        container::open(&not_one),
        Err(OpenError::NotAShimDatabase)
    ));

    // Shorter than the header is its own answer.
    assert!(matches!(
        container::open(&[0u8; 8]),
        Err(OpenError::TooShort { bytes: 8 })
    ));
    assert!(matches!(
        container::open(&[]),
        Err(OpenError::TooShort { bytes: 0 })
    ));
}

/// A declared inflated length that disagrees with what came out is
/// **reported**, not ignored and not believed.
#[test]
fn a_declared_length_that_disagrees_with_the_inflated_length_is_reported() {
    let Some(bytes) = sample("appraiser.sdb") else {
        return;
    };
    let mut lied = bytes.clone();
    lied[16..20].copy_from_slice(&1_234u32.to_le_bytes());
    let o = container::open(&lied).expect("still opens");
    assert_eq!(o.declared_inflated_len, Some(1_234));
    assert_eq!(
        o.body.len(),
        9_734_396,
        "the inflated bytes are what was walked"
    );
    let note = o.incomplete.as_deref().unwrap_or("");
    assert!(
        note.contains("declares an inflated length of 1234")
            && note.contains("inflated to 9734396"),
        "both numbers must be on the record: {note:?}"
    );
}

// --- The tag stream --------------------------------------------------------

/// Every real database consumes **exactly**, and its census matches.
///
/// Exact consumption is the property that makes the rest trustworthy: a walk
/// that ended early would produce a short tag list that read as the whole
/// database.
#[test]
fn walking_every_real_shim_database_consumes_the_file_exactly() {
    for (name, body_len, tags, distinct, depth) in CENSUS {
        let Some(bytes) = sample(name) else {
            return;
        };
        let o = container::open(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(o.body.len(), *body_len, "{name}: body length");

        let w = format::walk(&o.body);
        assert_eq!(
            w.limit, None,
            "{name}: the walk stopped short: {:?}",
            w.limit
        );
        assert_eq!(
            w.reached,
            o.body.len(),
            "{name}: the walk must consume to EOF"
        );
        assert!(w.complete(o.body.len()), "{name}");
        assert_eq!(w.tags.len(), *tags, "{name}: tag occurrences");
        let ids: BTreeSet<u16> = w.tags.iter().map(|t| t.id()).collect();
        assert_eq!(ids.len(), *distinct, "{name}: distinct tag ids");
        assert_eq!(
            w.tags.iter().map(|t| t.depth).max().unwrap_or(0),
            *depth,
            "{name}: maximum nesting depth"
        );
    }
}

/// Every real database has the same three top-level tags, in the same order.
#[test]
fn every_real_database_has_the_same_three_top_level_tags() {
    for (name, ..) in CENSUS {
        let Some(bytes) = sample(name) else {
            return;
        };
        let o = container::open(&bytes).expect("opens");
        let w = format::walk(&o.body);
        let top: Vec<u16> = w
            .tags
            .iter()
            .filter(|t| t.depth == 0)
            .map(|t| t.tag)
            .collect();
        assert_eq!(
            top,
            vec![0x7802u16, 0x7001, 0x7801],
            "{name}: the three top-level tags"
        );
    }
}

/// **The thing only real files taught.** A child tag that ends past its
/// parent's declared size is reported with no value, and the walk still
/// consumes exactly.
///
/// Nine `QWORD` tags with id `0x53DB` do this in `sysmain.sdb`, and more in
/// `appraiser.sdb`. Both alternatives fabricate: clamping the read to the
/// parent yields a wrong 64-bit number, and reading past the parent trusts a
/// length the parent contradicts. So the tag is carried and its value is not.
#[test]
fn a_child_that_overruns_its_parent_is_reported_without_a_value() {
    let Some(bytes) = sample("sysmain.sdb") else {
        return;
    };
    let o = container::open(&bytes).expect("opens");
    let w = format::walk(&o.body);

    let overrunning: Vec<_> = w.tags.iter().filter(|t| !t.value_readable()).collect();
    assert_eq!(
        overrunning.len(),
        9,
        "sysmain.sdb holds nine tags whose payload ends past their parent"
    );
    for t in &overrunning {
        assert_eq!(t.tag, 0x53DB, "all nine are the same tag");
        assert_eq!(t.tag_type, TagType::Qword);
        assert_eq!(
            t.overruns_parent_by,
            Some(3),
            "each ends exactly three bytes past its parent"
        );
    }
    // And the file still consumes exactly: the parent's declared size is what
    // the outer walk follows, which is what makes that true.
    assert!(w.complete(o.body.len()));
}

/// The type nibble census across all seven, which is what makes an honest
/// report of unnamed tags possible: a reader that does not know a tag's id can
/// still walk past it, because the **type** gives the size.
#[test]
fn the_type_nibble_census_matches_across_all_seven() {
    let mut total = std::collections::BTreeMap::new();
    for (name, ..) in CENSUS {
        let Some(bytes) = sample(name) else {
            return;
        };
        let o = container::open(&bytes).expect("opens");
        for t in format::walk(&o.body).tags {
            *total.entry(t.tag_type.as_str()).or_insert(0usize) += 1;
        }
    }
    // Measured. Note there is not a single BYTE tag in any of the seven, which
    // is why a fixture inventing one would be a shape the evidence lacks.
    assert_eq!(total.get("null"), Some(&20_410));
    assert_eq!(total.get("word"), Some(&1_249));
    assert_eq!(total.get("dword"), Some(&172_594));
    assert_eq!(total.get("qword"), Some(&25_597));
    assert_eq!(total.get("stringref"), Some(&344_727));
    assert_eq!(total.get("list"), Some(&166_207));
    assert_eq!(total.get("string"), Some(&94_210));
    assert_eq!(total.get("binary"), Some(&98_424));
    assert_eq!(
        total.get("byte"),
        None,
        "no BYTE tag occurs in any of the seven"
    );
    assert_eq!(
        total.values().sum::<usize>(),
        923_418,
        "total tag occurrences across all seven"
    );
}

// --- What must not be believed ---------------------------------------------

/// An undefined type nibble stops the walk and says **where**.
///
/// The type is what gives a tag's size, so a nibble the format does not define
/// leaves the walk unable to know how many bytes to skip. Guessing would
/// resynchronise on the wrong byte and emit tags that are not in the file.
#[test]
fn an_undefined_tag_type_nibble_stops_the_walk_and_says_where() {
    // A minimal plain database whose stream holds one NULL tag then a bad one.
    let mut d = vec![0u8; format::HEADER_BYTES];
    d[0..4].copy_from_slice(&3u32.to_le_bytes());
    d[8..12].copy_from_slice(b"sdbf");
    d.extend_from_slice(&0x1001u16.to_le_bytes()); // NULL, id 1
    d.extend_from_slice(&0xA123u16.to_le_bytes()); // nibble 0xA: undefined
    d.extend_from_slice(&[0xFF; 8]);

    let w = format::walk(&d);
    assert_eq!(w.tags.len(), 1, "the good tag is kept");
    match w.limit {
        Some(WalkLimit::UndefinedType { at, tag }) => {
            assert_eq!(tag, 0xA123);
            assert_eq!(at, format::HEADER_BYTES + 2, "the byte it stopped at");
        }
        other => panic!("expected an undefined-type limit, got {other:?}"),
    }
    assert!(!w.complete(d.len()), "and the walk is not complete");
    // The message names the nibble, so a reader can tell this from a truncation.
    let text = w.limit.unwrap().to_string();
    assert!(text.contains("0xA"), "got {text:?}");
}

/// A sized tag whose length runs past the end of the stream is refused rather
/// than read short.
#[test]
fn a_declared_length_past_the_end_of_the_stream_is_refused() {
    let mut d = vec![0u8; format::HEADER_BYTES];
    d[0..4].copy_from_slice(&3u32.to_le_bytes());
    d[8..12].copy_from_slice(b"sdbf");
    d.extend_from_slice(&0x8001u16.to_le_bytes()); // STRING
    d.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // 1 MiB, in a 18-byte file

    let w = format::walk(&d);
    assert!(
        w.tags.is_empty(),
        "nothing may be emitted from bytes not there"
    );
    assert!(matches!(
        w.limit,
        Some(WalkLimit::LengthPastEnd { declared, .. }) if declared == 0x0010_0000
    ));
}

/// A deeply nested tag stream hits the depth ceiling instead of the stack.
///
/// The deepest real database nests 5. In an ingest pipeline an unbounded
/// recursion is an outage, not a parse error.
#[test]
fn a_deeply_nested_tag_stream_hits_the_depth_cap_instead_of_the_stack() {
    // Build lists nested far past MAX_DEPTH, innermost first.
    let depth = format::MAX_DEPTH + 8;
    let mut payload: Vec<u8> = Vec::new();
    for _ in 0..depth {
        let mut next = Vec::new();
        next.extend_from_slice(&0x7001u16.to_le_bytes());
        next.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        next.extend_from_slice(&payload);
        payload = next;
    }
    let mut d = vec![0u8; format::HEADER_BYTES];
    d[0..4].copy_from_slice(&3u32.to_le_bytes());
    d[8..12].copy_from_slice(b"sdbf");
    d.extend_from_slice(&payload);

    let w = format::walk(&d);
    assert!(
        matches!(w.limit, Some(WalkLimit::DepthCeiling { .. })),
        "got {:?}",
        w.limit
    );
    assert!(
        w.tags.iter().all(|t| t.depth < format::MAX_DEPTH),
        "no tag may be emitted from past the ceiling"
    );
    assert!(
        !w.complete(d.len()),
        "and the stream is not claimed complete"
    );
}

/// A major version this build has not measured is not refused — the stream may
/// still walk — but nothing pretends the version was recognised.
#[test]
fn an_unmeasured_major_version_still_opens_and_is_not_claimed_as_known() {
    let mut d = vec![0u8; format::HEADER_BYTES];
    d[0..4].copy_from_slice(&99u32.to_le_bytes());
    d[8..12].copy_from_slice(b"sdbf");
    d.extend_from_slice(&0x1001u16.to_le_bytes());

    let o = container::open(&d).expect("a version is not a reason to refuse a database");
    assert_eq!(o.major_version, 99);
    assert_ne!(
        o.major_version,
        format::KNOWN_MAJOR_VERSION,
        "and the caller can see it is not the measured one"
    );
    assert!(format::walk(&o.body).complete(o.body.len()));
}

// --- The string table ------------------------------------------------------

/// Per-file string-table entry counts, measured.
const TABLE_ENTRIES: &[(&str, usize, usize)] = &[
    // (file, table entries, STRINGREF occurrences)
    ("appraiser.sdb", 51_091, 191_592),
    ("drvmain.sdb", 1_307, 4_373),
    ("frxmain.sdb", 41, 145),
    ("msimain.sdb", 3_427, 23_967),
    ("pcamain.sdb", 628, 2_192),
    ("shellFeatureInbox.sdb", 149, 468),
    ("sysmain.sdb", 37_567, 121_990),
];

/// A reference resolves against the string table's **tag**, not its payload.
///
/// The two differ by six bytes, and resolving from the payload does not fail —
/// it reads the middle of a UTF-16 string as a tag word and a length. On
/// `frxmain.sdb` the tag base gives `"3.0.0.17"`; the payload base gives a
/// "tag" of `0x33` declaring 3,145,774 bytes.
#[test]
fn a_string_reference_resolves_against_the_string_table_tag_not_its_payload() {
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    let o = container::open(&bytes).expect("opens");
    let w = format::walk(&o.body);
    let table = strings::build(&o.body, &w.tags).expect("a string table");

    // Measured on this file: the table's tag sits at 2,708 and its payload at
    // 2,714.
    assert_eq!(table.tag_at, 2_708);
    assert_eq!(table.len(), 41);
    assert!(table.incomplete.is_none());

    // The two references whose strings were read by hand off the bytes.
    assert_eq!(table.resolve(6), Some("3.0.0.17"));
    assert_eq!(
        table.resolve(30),
        Some("Microsoft Windows Program Frameworks and Dependencies Database")
    );
    assert_eq!(table.resolve(162), Some("MSVBVM??.DLL"));
    assert_eq!(table.resolve(194), Some("Visual Basic"));

    // And the payload-relative reading of the same reference -- six bytes on --
    // is not an entry, so it is refused rather than decoded.
    assert_eq!(
        table.resolve(6 + 6),
        None,
        "six bytes off is where the arithmetic mistake lands, and it must not resolve"
    );
}

/// **Every** reference in **every** real database resolves.
///
/// And in each file the number of distinct references equals the number of
/// table entries exactly: every entry is referenced, and no reference points
/// anywhere else. That is an internal consistency this reader can check without
/// a second tool, and it is what makes the resolution trustworthy here.
#[test]
fn every_string_reference_in_every_real_database_resolves() {
    let mut total_refs = 0usize;
    for (name, entries, occurrences) in TABLE_ENTRIES {
        let Some(bytes) = sample(name) else {
            return;
        };
        let o = container::open(&bytes).expect("opens");
        let w = format::walk(&o.body);
        let table = strings::build(&o.body, &w.tags)
            .unwrap_or_else(|| panic!("{name}: every real database holds a string table"));
        assert!(
            table.incomplete.is_none(),
            "{name}: the table walk stopped short: {:?}",
            table.incomplete
        );
        assert_eq!(table.len(), *entries, "{name}: table entries");

        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0usize;
        for t in w.tags.iter().filter(|t| t.tag_type == TagType::StringRef) {
            count += 1;
            let r = u32::from_le_bytes(
                o.body[t.payload_at..t.payload_at + 4]
                    .try_into()
                    .expect("four bytes"),
            );
            assert!(
                table.resolve(r).is_some(),
                "{name}: reference {r} at byte {} does not resolve",
                t.at
            );
            seen.insert(r);
        }
        assert_eq!(count, *occurrences, "{name}: STRINGREF occurrences");
        assert_eq!(
            seen.len(),
            *entries,
            "{name}: every table entry is referenced and nothing else is"
        );
        total_refs += count;
    }
    assert_eq!(
        total_refs, 344_727,
        "STRINGREF occurrences across all seven"
    );
}

/// A reference into the middle of another string is refused, not decoded.
///
/// This is the whole reason the table is built by walking its entries rather
/// than resolved by arithmetic. Decoding from a mid-string offset reads UTF-16
/// bytes as a tag and a length, and produces a string.
#[test]
fn a_string_reference_into_the_middle_of_another_string_is_refused_not_decoded() {
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    let o = container::open(&bytes).expect("opens");
    let w = format::walk(&o.body);
    let table = strings::build(&o.body, &w.tags).expect("a table");

    let valid: Vec<u32> = table.references().collect();
    let first = valid[0];
    let second = valid[1];
    // Every offset strictly between two entries is inside the first one.
    for off in (first + 1)..second {
        assert_eq!(
            table.resolve(off),
            None,
            "offset {off} is inside the entry at {first} and must not resolve"
        );
    }
}

/// A string table whose entries stop making sense is reported, and the
/// references into the unread part are refused rather than decoded.
#[test]
fn a_string_table_that_stops_making_sense_says_so_and_refuses_the_rest() {
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    let o = container::open(&bytes).expect("opens");
    let w = format::walk(&o.body);
    let table = strings::build(&o.body, &w.tags).expect("a table");
    let refs: Vec<u32> = table.references().collect();
    let third = refs[2];

    // Corrupt the third entry's tag so it is not a string.
    let mut broken = o.body.clone();
    let at = table.tag_at + third as usize;
    broken[at..at + 2].copy_from_slice(&0x1234u16.to_le_bytes());
    let w2 = format::walk(&broken);
    let t2 = strings::build(&broken, &w2.tags).expect("still a table");

    assert_eq!(t2.len(), 2, "the two entries before the break are kept");
    let note = t2.incomplete.as_deref().unwrap_or("");
    assert!(
        note.contains("0x1234") && note.contains("not a string"),
        "the break must be named: {note:?}"
    );
    assert!(
        t2.resolve(third).is_none(),
        "and a reference into the unread part is refused"
    );
}

// --- The entities ----------------------------------------------------------

/// Per-file entity counts and the database's own identity, measured.
const ENTITIES: &[(&str, usize, usize, &str, &str)] = &[
    // (file, shimmed executables, matching criteria, database name, version)
    (
        "appraiser.sdb",
        13_430,
        29_617,
        "Microsoft Windows Application Compatibility Fix Database",
        "3.0.0.17",
    ),
    (
        "drvmain.sdb",
        5,
        16,
        "Microsoft Driver Compatibility Database",
        "3.0.0.17",
    ),
    (
        "frxmain.sdb",
        14,
        14,
        "Microsoft Windows Program Frameworks and Dependencies Database",
        "3.0.0.17",
    ),
    (
        "msimain.sdb",
        0,
        0,
        "Microsoft System Installer Compatibility Database",
        "3.0.0.16",
    ),
    (
        "pcamain.sdb",
        287,
        311,
        "Microsoft Windows Program Compatibility Assistant Database",
        "3.0.0.17",
    ),
    (
        "shellFeatureInbox.sdb",
        45,
        61,
        "Microsoft Windows Shell Feature Compatibility Database",
        "3.0.0.17",
    ),
    (
        "sysmain.sdb",
        13_871,
        27_581,
        "Microsoft Windows Application Compatibility Fix Database",
        "3.0.0.16",
    ),
];

fn read_all(name: &str) -> Option<(container::Opened, format::Walk, strings::StringTable)> {
    let bytes = sample(name)?;
    let o = container::open(&bytes).expect("opens");
    let w = format::walk(&o.body);
    let t = strings::build(&o.body, &w.tags).expect("a string table");
    Some((o, w, t))
}

/// The entities are under `0x7001`, not `0x7802`.
///
/// This is worth a test of its own because the conventional reading of the
/// numbers puts the database at `0x7802`, and `0x7802` holds ten index
/// descriptors and no entities at all. A reader that took it for the database
/// would report every real file as holding nothing.
#[test]
fn the_entities_are_under_the_database_tag_and_not_the_index_tag() {
    let Some((o, w, t)) = read_all("frxmain.sdb") else {
        return;
    };
    let (db, exes) = entities::read(&o.body, &w.tags, &t);
    let db = db.expect("a database");
    assert_eq!(exes.len(), 14, "frxmain names fourteen executables");
    assert_eq!(db.executables, 14);

    // And the index tag really is present and really holds no entities.
    let index = w
        .tags
        .iter()
        .find(|x| x.tag == entities::TAG_INDEXES && x.depth == 0)
        .expect("an index tag");
    let index_end = index.payload_at + index.payload_len;
    assert!(
        !w.tags
            .iter()
            .any(|x| x.tag == entities::TAG_EXE && x.at >= index.payload_at && x.at < index_end),
        "no executable lives under the index tag, which is why reading it as the database \
         would report every file as empty"
    );
}

/// Every real database's identity and entity counts.
#[test]
fn every_real_database_reports_its_identity_and_its_executables() {
    for (name, exe_count, criteria, db_name, version) in ENTITIES {
        let Some((o, w, t)) = read_all(name) else {
            return;
        };
        let (db, exes) = entities::read(&o.body, &w.tags, &t);
        let db = db.unwrap_or_else(|| panic!("{name}: a database"));
        assert_eq!(db.name.as_deref(), Some(*db_name), "{name}: database name");
        assert_eq!(db.version.as_deref(), Some(*version), "{name}: version");
        assert_eq!(exes.len(), *exe_count, "{name}: shimmed executables");
        assert_eq!(db.matching_criteria, *criteria, "{name}: matching criteria");
        assert!(
            db.database_guid.as_deref().map(str::len) == Some(32),
            "{name}: a 16-byte GUID as 32 hex digits, got {:?}",
            db.database_guid
        );
        assert!(
            db.created_filetime.is_some_and(|f| f > 0),
            "{name}: a creation time"
        );
        // The record must not claim the database is registered with Windows.
        let j = db.to_json();
        assert_eq!(j["installed"], serde_json::json!(false));
        assert!(
            j["installed_basis"]
                .as_str()
                .unwrap_or("")
                .contains("not established by the file existing on disk"),
            "{name}: the file's existence is not its installation"
        );
    }
}

/// A shim entry carries the application it shims, and states that it is not
/// evidence the program ran.
///
/// Read off `frxmain.sdb`: the entry named `MSVBVM??.DLL` is `"Visual Basic"`
/// by `"Microsoft Corporation"`.
#[test]
fn a_shim_entry_names_its_application_and_claims_no_execution() {
    let Some((o, w, t)) = read_all("frxmain.sdb") else {
        return;
    };
    let (_, exes) = entities::read(&o.body, &w.tags, &t);
    let vb = exes
        .iter()
        .find(|e| e.name.as_deref() == Some("MSVBVM??.DLL"))
        .expect("the Visual Basic entry");
    assert_eq!(vb.app_name.as_deref(), Some("Visual Basic"));
    assert_eq!(vb.vendor.as_deref(), Some("Microsoft Corporation"));
    assert_eq!(vb.wildcard_name.as_deref(), Some("MSVBVM??.DLL"));
    assert_eq!(vb.exe_guid.as_deref().map(str::len), Some(32));
    assert_eq!(
        vb.matching_files,
        vec!["*".to_string()],
        "its one matching criterion"
    );

    let j = vb.to_json();
    assert_eq!(j["execution_evidence"], serde_json::json!(false));
    assert!(
        j["basis"]
            .as_str()
            .unwrap_or("")
            .contains("not a record that such a program was ever present or ever ran"),
        "got {:?}",
        j["basis"]
    );
}

/// Tags this build does not name are **listed by id**, not omitted.
///
/// Otherwise a record would read as everything the database holds about an
/// executable, when it is what this reader could name.
#[test]
fn an_unnamed_tag_is_carried_by_numeric_id_and_never_given_a_guessed_name() {
    let Some((o, w, t)) = read_all("frxmain.sdb") else {
        return;
    };
    let (_, exes) = entities::read(&o.body, &w.tags, &t);
    let with_extras = exes
        .iter()
        .find(|e| !e.unnamed_tags.is_empty())
        .expect("a real entry carries tags this build does not name");
    let j = with_extras.to_json();
    let ids = j["unnamed_tags"].as_array().expect("the id list");
    assert!(!ids.is_empty());
    for id in ids {
        let s = id.as_str().unwrap_or("");
        assert!(
            s.starts_with("0x") && s.len() == 6,
            "an unnamed tag is reported as its id: {s:?}"
        );
    }
    assert!(
        j["unnamed_tags_note"]
            .as_str()
            .unwrap_or("")
            .contains("does not read as everything the database holds"),
        "got {:?}",
        j["unnamed_tags_note"]
    );
}

/// The coverage record states how many tag ids this build could not name — and
/// says that this is a fact about the reader, not about what is documented.
#[test]
fn the_coverage_record_states_how_many_tags_had_no_name() {
    let Some((o, w, t)) = read_all("sysmain.sdb") else {
        return;
    };
    let c = entities::coverage(&o.body, &o, &w, &t);
    assert_eq!(c.tags_walked, 339_377);
    assert_eq!(c.distinct_tag_ids, 77);
    assert!(
        c.unnamed_tag_ids > 0 && c.unnamed_tag_ids < c.distinct_tag_ids,
        "some but not all ids are unnamed: {} of {}",
        c.unnamed_tag_ids,
        c.distinct_tag_ids
    );
    assert_eq!(c.string_table_entries, 37_567);
    assert_eq!(c.string_refs, 121_990);
    assert_eq!(c.unresolved_string_refs, 0, "every reference resolves");
    assert_eq!(
        c.tags_without_a_readable_value, 9,
        "the nine QWORDs that overrun their parent"
    );
    assert!(c.walk_complete);

    let j = c.to_json();
    let note = j["unnamed_tag_ids_note"].as_str().unwrap_or("");
    assert!(
        note.contains("statement about this reader's table"),
        "the census must not read as a claim about what Microsoft documents: {note:?}"
    );
    assert!(
        j["unreadable_value_note"]
            .as_str()
            .unwrap_or("")
            .contains("Microsoft's own shipped databases"),
        "got {:?}",
        j["unreadable_value_note"]
    );
    // Nothing is incomplete on a database that walked cleanly at a known
    // version.
    assert!(j["content_incomplete"].is_null(), "{j:?}");
}

/// A database whose major version this build has not measured is stamped
/// `unvalidated` — the tags it yielded are reported, and not claimed as
/// validated against a known layout.
#[test]
fn a_database_whose_major_version_is_not_three_is_stamped_unvalidated() {
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    let mut odd = bytes.clone();
    odd[0..4].copy_from_slice(&7u32.to_le_bytes());
    let o = container::open(&odd).expect("opens");
    let w = format::walk(&o.body);
    let t = strings::build(&o.body, &w.tags).expect("a table");
    let j = entities::coverage(&o.body, &o, &w, &t).to_json();
    assert_eq!(j["format_version"], "7.0");
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("unvalidated")
    );
    assert!(
        j["format_version_note"]
            .as_str()
            .unwrap_or("")
            .contains("not validated against a known layout"),
        "got {:?}",
        j["format_version_note"]
    );
}

// --- The module ------------------------------------------------------------

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::{ForensicsModule, InputCapability};
use std::sync::Arc;

#[derive(Debug)]
struct Mem(Vec<u8>);
impl DataSource for Mem {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = offset as usize;
        if off >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

fn artifact_named(name: &str, bytes: Vec<u8>) -> Artifact {
    let src: Arc<dyn DataSource> = Arc::new(Mem(bytes));
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": name, "path": format!("/Windows/apppatch/{name}") }),
    )
}

/// The module declares what it is and what it needs.
#[test]
fn the_module_declares_its_identity_and_its_input_need() {
    let m = crate::SdbParser;
    assert_eq!(m.id(), "plugin.windows.sdb_parser");
    assert_eq!(m.version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(m.input_capability(), InputCapability::RandomAccess);
    assert!(m.subscribes_to().contains(&ArtifactType::FileEntry));
}

/// A real database becomes a coverage record, a database record and one record
/// per shimmed executable.
#[test]
fn a_real_database_becomes_its_records() {
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    let out = crate::SdbParser
        .process(&artifact_named("frxmain.sdb", bytes))
        .expect("the module runs");
    let types: Vec<&str> = out
        .iter()
        .map(|a| a.metadata["type"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        types
            .iter()
            .filter(|t| **t == "ShimDatabaseCoverage")
            .count(),
        1
    );
    assert_eq!(types.iter().filter(|t| **t == "ShimDatabase").count(), 1);
    assert_eq!(
        types.iter().filter(|t| **t == "ShimExe").count(),
        14,
        "one per shimmed executable"
    );
    // Every record is parented to the file it came from.
    assert!(out.iter().all(|a| a.parent_id.is_some()));
}

/// Recognition is by **content**, not by name.
///
/// A file named `.sdb` that carries neither magic produces nothing at all.
/// Inventing a parse failure for it would put a statement in the case about
/// something that is not evidence of anything.
#[test]
fn a_file_named_sdb_that_is_not_one_produces_no_records() {
    let mut junk = vec![0u8; 512];
    junk[8..12].copy_from_slice(b"junk");
    let out = crate::SdbParser
        .process(&artifact_named("custom.sdb", junk))
        .expect("runs");
    assert!(out.is_empty(), "got {out:?}");

    // And a real database under a name that is not `.sdb` is not read either:
    // the extension decides whether to LOOK, so a whole disk is not opened.
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    let out = crate::SdbParser
        .process(&artifact_named("notes.txt", bytes))
        .expect("runs");
    assert!(out.is_empty());
}

/// A database with no data source, or too short to sniff, is silent.
#[test]
fn a_database_with_nothing_to_read_is_silent() {
    let no_source = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        serde_json::json!({ "name": "x.sdb" }),
    );
    assert!(crate::SdbParser
        .process(&no_source)
        .expect("runs")
        .is_empty());

    let tiny = artifact_named("x.sdb", vec![0u8; 4]);
    assert!(crate::SdbParser.process(&tiny).expect("runs").is_empty());
}

/// A short read is **reported**, and what was read is still published.
///
/// A database read short is not a database that holds nothing, and the records
/// from the readable part must not read as its whole contents.
#[test]
fn a_truncated_shim_database_reports_short_read_and_keeps_what_it_read() {
    let Some(bytes) = sample("frxmain.sdb") else {
        return;
    };
    // A source that declares the full size and serves only half.
    #[derive(Debug)]
    struct Half(Vec<u8>, u64);
    impl DataSource for Half {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.1
        }
    }
    let full = bytes.len() as u64;
    let src: Arc<dyn DataSource> = Arc::new(Half(bytes[..bytes.len() / 2].to_vec(), full));
    let art = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": "frxmain.sdb" }),
    );
    let out = crate::SdbParser.process(&art).expect("runs");
    let coverage = out
        .iter()
        .find(|a| a.metadata["type"] == "ShimDatabaseCoverage")
        .expect("a coverage record");
    assert_eq!(
        coverage.metadata["content_incomplete"],
        serde_json::json!(true)
    );
    assert_eq!(
        coverage.metadata["content_incomplete_reason"],
        serde_json::json!("short_read")
    );
    assert!(
        coverage.metadata["short_read_detail"]
            .as_str()
            .unwrap_or("")
            .contains("is not established"),
        "got {:?}",
        coverage.metadata["short_read_detail"]
    );
}
