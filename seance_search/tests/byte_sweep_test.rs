//! The case-wide byte sweep: bounded, resumable, scoped, grouped, and
//! encoding-aware. Every ceiling in these tests is checked by its number.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_search::sweep::{
    group_hits, sweep, sweep_with, GroupingBasis, PatternError, PatternKind, PatternSet,
    PatternSpec, RegionKind, ScopeError, ScopeExclusion, SearchScope, SweepBounds, SweepCursor,
    SweepError, SweepHit, SweepRequest, SweepResponse, SweepTarget, MAX_NEEDLES, MAX_PATTERN_BYTES,
    RAW_ENCODING,
};
use uuid::Uuid;

fn id(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn target(n: u8, bytes: &[u8]) -> SweepTarget {
    SweepTarget {
        artifact_id: id(n),
        artifact_type: "FileContent".to_string(),
        name: Some(format!("file{n}.txt")),
        path: Some(format!("/evidence/file{n}.txt")),
        region: RegionKind::Live,
        declared_size: bytes.len() as u64,
        content_hash: None,
        source: Arc::new(ByteSliceDataSource::new(bytes.to_vec())),
    }
}

fn with_region(mut t: SweepTarget, region: RegionKind) -> SweepTarget {
    t.region = region;
    t
}

fn bytes_pattern(hex: &str) -> PatternSet {
    PatternSet::compile(&[PatternSpec::bytes(hex)], &[]).expect("pattern compiles")
}

fn text_pattern(text: &str, codepages: &[&str]) -> PatternSet {
    let cps: Vec<String> = codepages.iter().map(|s| s.to_string()).collect();
    PatternSet::compile(&[PatternSpec::text(text)], &cps).expect("pattern compiles")
}

fn request(bounds: SweepBounds) -> SweepRequest {
    SweepRequest {
        scope: SearchScope::default(),
        bounds,
        resume: None,
    }
}

fn small_chunks(chunk: usize) -> SweepBounds {
    SweepBounds {
        max_hits: 10_000,
        max_bytes: u64::MAX,
        chunk_bytes: chunk,
    }
}

fn locations(hits: &[SweepHit]) -> Vec<(Uuid, u64)> {
    hits.iter().map(|h| (h.artifact_id, h.offset)).collect()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

// ---------------------------------------------------------------------------
// 1. The sweep itself
// ---------------------------------------------------------------------------

#[test]
fn a_sweep_finds_every_offset_across_several_objects_and_across_chunk_edges() {
    // "AB CD" at 1, 7 and 12 in the first object, once at 0 in the third,
    // never in the second. A 4-byte chunk makes the offset-7 match straddle
    // a chunk edge.
    let first = vec![
        0x00, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0xAB, 0xCD,
    ];
    let second = vec![0x11; 9];
    let third = vec![0xAB, 0xCD, 0xEE];
    let targets = vec![target(1, &first), target(2, &second), target(3, &third)];

    let response =
        sweep(targets, &bytes_pattern("AB CD"), &request(small_chunks(4))).expect("sweep runs");

    assert_eq!(
        locations(&response.hits),
        vec![(id(1), 1), (id(1), 7), (id(1), 12), (id(3), 0)]
    );
    assert!(response.hits.iter().all(|h| h.length == 2));
    assert!(response
        .hits
        .iter()
        .all(|h| h.encodings == vec![RAW_ENCODING.to_string()]));
    assert!(response.complete, "{}", response.coverage_statement);
    assert_eq!(response.next_cursor, None);
    assert_eq!(response.objects_offered, 3);
    assert_eq!(response.objects_searched, 3);
    assert_eq!(response.bytes_scanned, 14 + 9 + 3);
    assert_eq!(response.bytes_declared, 14 + 9 + 3);
    assert!(!response.hit_cap_reached);
    assert!(!response.byte_cap_reached);
    assert!(response.short_reads.is_empty());
    assert!(response.read_failures.is_empty());
}

#[test]
fn a_streaming_sink_sees_each_hit_as_it_is_found() {
    let targets = vec![target(1, b"xx-hit-xx-hit-xx"), target(2, b"hit")];
    let mut streamed = Vec::new();
    let response = sweep_with(
        targets,
        &bytes_pattern("686974"),
        &request(small_chunks(5)),
        &mut |hit| streamed.push((hit.artifact_id, hit.offset)),
    )
    .expect("sweep runs");
    assert_eq!(streamed, vec![(id(1), 3), (id(1), 10), (id(2), 0)]);
    assert_eq!(locations(&response.hits), streamed);
}

#[test]
fn overlapping_occurrences_are_each_reported() {
    let response = sweep(
        vec![target(1, b"aaaa")],
        &bytes_pattern("6161"),
        &request(small_chunks(3)),
    )
    .expect("sweep runs");
    assert_eq!(
        locations(&response.hits),
        vec![(id(1), 0), (id(1), 1), (id(1), 2)]
    );
}

#[test]
fn needles_of_different_lengths_are_each_found_exactly_once_at_a_chunk_edge() {
    // "abcd" at 2 and "cd" at 4 and 9, with a chunk small enough that the
    // short needle lies wholly inside the carried tail of a window.
    let data = b"xxabcdxxxcd".to_vec();
    let patterns = PatternSet::compile(
        &[PatternSpec::bytes("61626364"), PatternSpec::bytes("6364")],
        &[],
    )
    .expect("patterns compile");
    let response =
        sweep(vec![target(1, &data)], &patterns, &request(small_chunks(3))).expect("sweep runs");
    let mut found: Vec<(usize, u64)> = response
        .hits
        .iter()
        .map(|h| (h.pattern_index, h.offset))
        .collect();
    found.sort();
    assert_eq!(found, vec![(0, 2), (1, 4), (1, 9)]);
}

#[test]
fn a_needle_inside_another_needle_is_found_as_well_not_instead() {
    // An examiner searching "plan" and "planner" together must get every
    // hit each term would get alone; a search that consumes "plan" and
    // resumes after it silently loses "planner".
    let patterns = PatternSet::compile(
        &[PatternSpec::text("plan"), PatternSpec::text("planner")],
        &[],
    )
    .expect("patterns compile");
    let response = sweep(
        vec![target(1, b"the planner planned")],
        &patterns,
        &request(small_chunks(6)),
    )
    .expect("sweep runs");
    let mut found: Vec<(usize, u64)> = response
        .hits
        .iter()
        .map(|h| (h.pattern_index, h.offset))
        .collect();
    found.sort();
    assert_eq!(found, vec![(0, 4), (0, 12), (1, 4)]);
}

#[test]
fn the_hit_cap_is_reported_by_number_and_the_cursor_resumes_without_loss_or_repeat() {
    let first: Vec<u8> = b"..ab..ab..ab..ab..".to_vec();
    let second: Vec<u8> = b"ab.ab".to_vec();
    let third: Vec<u8> = b"nothing here".to_vec();
    let fourth: Vec<u8> = b"ab".to_vec();
    let all = || {
        vec![
            target(1, &first),
            target(2, &second),
            target(3, &third),
            target(4, &fourth),
        ]
    };
    let patterns = bytes_pattern("6162");

    let whole = sweep(all(), &patterns, &request(small_chunks(7))).expect("sweep runs");
    assert_eq!(whole.hits.len(), 7);
    assert!(whole.complete);

    let bounds = SweepBounds {
        max_hits: 3,
        max_bytes: u64::MAX,
        chunk_bytes: 7,
    };
    let mut cursor: Option<SweepCursor> = None;
    let mut pages = Vec::new();
    let mut collected: Vec<(Uuid, u64)> = Vec::new();
    loop {
        let req = SweepRequest {
            scope: SearchScope::default(),
            bounds,
            resume: cursor,
        };
        let page = sweep(all(), &patterns, &req).expect("page runs");
        assert_eq!(page.max_hits, 3);
        assert!(
            page.hits.len() <= 3 || page.hit_cap_reached,
            "a page over the cap must say the cap bit"
        );
        collected.extend(locations(&page.hits));
        cursor = page.next_cursor;
        pages.push(page);
        if cursor.is_none() {
            break;
        }
        assert!(pages.len() < 20, "paging must terminate");
    }
    assert!(
        pages.len() >= 3,
        "seven hits at three a page is at least three pages"
    );
    assert!(pages[0].hit_cap_reached);
    assert!(!pages[0].complete);
    assert!(pages.last().unwrap().complete);
    assert_eq!(
        collected,
        locations(&whole.hits),
        "paging must enumerate exactly the hits of one unbounded sweep, in order"
    );
    let distinct: BTreeSet<(Uuid, u64)> = collected.iter().copied().collect();
    assert_eq!(distinct.len(), collected.len(), "no hit reported twice");
}

#[test]
fn the_byte_cap_stops_mid_object_and_a_resume_finds_the_match_it_straddles() {
    // 10 bytes then "ab" at 10..12 in the first object; the cap lands at 11,
    // in the middle of the match.
    let mut first = vec![0u8; 10];
    first.extend_from_slice(b"ab......");
    let second = b"ab".to_vec();
    let all = || vec![target(1, &first), target(2, &second)];
    let patterns = bytes_pattern("6162");

    let bounds = SweepBounds {
        max_hits: 100,
        max_bytes: 11,
        chunk_bytes: 4,
    };
    let page = sweep(all(), &patterns, &request(bounds)).expect("sweep runs");
    assert!(page.byte_cap_reached);
    assert_eq!(page.max_bytes, 11);
    assert_eq!(page.bytes_scanned, 11, "exactly the budget was read");
    assert!(page.hits.is_empty(), "the match is not complete at byte 11");
    assert_eq!(
        page.next_cursor,
        Some(SweepCursor {
            artifact_id: id(1),
            offset: 11
        })
    );
    assert!(!page.complete);
    assert!(
        page.coverage_statement.contains("11"),
        "{}",
        page.coverage_statement
    );

    let rest = sweep(
        all(),
        &patterns,
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds {
                max_bytes: u64::MAX,
                ..bounds
            },
            resume: page.next_cursor,
        },
    )
    .expect("resume runs");
    assert_eq!(locations(&rest.hits), vec![(id(1), 10), (id(2), 0)]);
    assert_eq!(rest.objects_skipped_by_cursor, 0);
    assert_eq!(
        rest.bytes_scanned,
        7 + 2,
        "only bytes past the cursor count"
    );
    assert!(rest.complete);
}

#[test]
fn a_byte_cap_that_lands_exactly_on_the_end_of_the_stream_is_not_reported_as_hit() {
    let response = sweep(
        vec![target(1, b"abcd"), target(2, b"ef")],
        &bytes_pattern("6566"),
        &request(SweepBounds {
            max_hits: 100,
            max_bytes: 6,
            chunk_bytes: 4,
        }),
    )
    .expect("sweep runs");
    assert!(!response.byte_cap_reached, "nothing was left unscanned");
    assert!(response.complete);
    assert_eq!(response.next_cursor, None);
}

#[test]
fn a_resume_cursor_naming_an_object_the_stream_never_produces_is_refused() {
    let err = sweep(
        vec![target(1, b"abc")],
        &bytes_pattern("61"),
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds::default(),
            resume: Some(SweepCursor {
                artifact_id: id(9),
                offset: 0,
            }),
        },
    )
    .expect_err("an unknown resume point must be refused, not restarted");
    assert_eq!(err, SweepError::ResumePointNotFound { artifact_id: id(9) });
}

#[test]
fn a_resume_skips_the_objects_before_the_cursor_and_counts_them() {
    let all = || vec![target(1, b"ab"), target(2, b"ab"), target(3, b"ab")];
    let response = sweep(
        all(),
        &bytes_pattern("6162"),
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds::default(),
            resume: Some(SweepCursor {
                artifact_id: id(2),
                offset: 0,
            }),
        },
    )
    .expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(2), 0), (id(3), 0)]);
    assert_eq!(response.objects_skipped_by_cursor, 1);
    assert_eq!(response.objects_offered, 3);
    assert_eq!(response.objects_searched, 2);
}

#[test]
fn an_object_shorter_than_declared_is_a_short_read_not_a_clean_miss() {
    let mut short = target(1, &[0u8; 8]);
    short.declared_size = 64;
    let response = sweep(
        vec![short, target(2, b"ab")],
        &bytes_pattern("6162"),
        &request(SweepBounds::default()),
    )
    .expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(2), 0)]);
    assert_eq!(response.short_reads.len(), 1);
    assert_eq!(response.short_reads[0].artifact_id, id(1));
    assert_eq!(response.short_reads[0].declared_size, 64);
    assert_eq!(response.short_reads[0].bytes_read, 8);
    assert!(
        !response.complete,
        "a sweep that could not look at 56 declared bytes is not complete"
    );
    assert_eq!(
        response.next_cursor, None,
        "there is nothing to resume into"
    );
    assert!(
        response.coverage_statement.contains("8 of 64"),
        "{}",
        response.coverage_statement
    );
}

#[derive(Debug)]
struct FailsAfter {
    good: Vec<u8>,
}

impl DataSource for FailsAfter {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.good.len() {
            return Err(io::Error::other("sector unreadable"));
        }
        let n = buf.len().min(self.good.len() - offset);
        buf[..n].copy_from_slice(&self.good[offset..offset + n]);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.good.len() as u64 + 100
    }
}

#[test]
fn a_read_error_is_reported_with_its_offset_and_the_sweep_moves_on() {
    let failing = SweepTarget {
        artifact_id: id(1),
        artifact_type: "FileContent".to_string(),
        name: Some("bad.bin".to_string()),
        path: Some("/bad.bin".to_string()),
        region: RegionKind::Live,
        declared_size: 108,
        content_hash: None,
        source: Arc::new(FailsAfter {
            good: b"ab....ab".to_vec(),
        }),
    };
    let response = sweep(
        vec![failing, target(2, b"ab")],
        &bytes_pattern("6162"),
        &request(small_chunks(4)),
    )
    .expect("a bad object does not fail the sweep");
    assert_eq!(
        locations(&response.hits),
        vec![(id(1), 0), (id(1), 6), (id(2), 0)],
        "hits before the failure and in later objects are still reported"
    );
    assert_eq!(response.read_failures.len(), 1);
    assert_eq!(response.read_failures[0].artifact_id, id(1));
    assert_eq!(response.read_failures[0].offset, 8);
    assert!(response.read_failures[0]
        .error
        .contains("sector unreadable"));
    assert!(!response.complete);
    assert!(
        response.coverage_statement.contains("1 object"),
        "{}",
        response.coverage_statement
    );
}

// ---------------------------------------------------------------------------
// 2. Scope
// ---------------------------------------------------------------------------

#[test]
fn a_scope_that_excludes_unallocated_says_so_on_the_result() {
    let targets = vec![
        target(1, b"ab"),
        with_region(target(2, b"ab"), RegionKind::Unallocated),
        with_region(target(3, b"ab"), RegionKind::Slack),
        with_region(target(4, b"ab"), RegionKind::Recovered),
    ];
    let req = SweepRequest {
        scope: SearchScope {
            regions: vec![RegionKind::Live],
            ..SearchScope::default()
        },
        bounds: SweepBounds::default(),
        resume: None,
    };
    let response = sweep(targets, &bytes_pattern("6162"), &req).expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(1), 0)]);
    assert_eq!(response.regions_searched, vec![RegionKind::Live]);
    assert_eq!(
        response.regions_not_searched,
        vec![
            RegionKind::Slack,
            RegionKind::Unallocated,
            RegionKind::Recovered,
            RegionKind::Raw
        ]
    );
    assert_eq!(response.objects_excluded.region, 3);
    assert_eq!(
        response.objects_offered_by_region[&RegionKind::Unallocated],
        1
    );
    assert_eq!(response.objects_searched_by_region[&RegionKind::Live], 1);
    assert_eq!(
        response
            .objects_searched_by_region
            .get(&RegionKind::Unallocated),
        Some(&0)
    );
    let s = response.scope_statement.to_lowercase();
    assert!(s.contains("not searched"), "{s}");
    assert!(s.contains("unallocated"), "{s}");
    assert!(s.contains("slack"), "{s}");
    assert!(s.contains("recovered"), "{s}");
    assert!(s.contains("raw"), "{s}");
    assert_eq!(
        response.scope, req.scope,
        "the scope is echoed as requested"
    );
}

#[test]
fn a_scope_naming_slack_that_was_offered_no_slack_objects_reports_zero_offered() {
    let response = sweep(
        vec![target(1, b"ab")],
        &bytes_pattern("6162"),
        &request(SweepBounds::default()),
    )
    .expect("sweep runs");
    assert_eq!(response.regions_not_searched, Vec::<RegionKind>::new());
    assert_eq!(response.objects_offered_by_region[&RegionKind::Slack], 0);
    assert_eq!(response.objects_offered_by_region[&RegionKind::Live], 1);
    let s = response.scope_statement.to_lowercase();
    assert!(s.contains("slack: 0"), "{s}");
}

#[test]
fn a_scope_filters_by_type_extension_prefix_and_glob_and_counts_each_reason() {
    let mut wrong_type = target(1, b"ab");
    wrong_type.artifact_type = "TimelineEvent".to_string();
    let mut wrong_ext = target(2, b"ab");
    wrong_ext.name = Some("notes.docx".to_string());
    wrong_ext.path = Some("/evidence/Users/alice/notes.docx".to_string());
    let mut wrong_prefix = target(3, b"ab");
    wrong_prefix.name = Some("a.txt".to_string());
    wrong_prefix.path = Some("/other/a.txt".to_string());
    let mut wrong_glob = target(4, b"ab");
    wrong_glob.name = Some("b.txt".to_string());
    wrong_glob.path = Some("/evidence/Users/bob/b.txt".to_string());
    let mut admitted = target(5, b"ab");
    admitted.name = Some("c.TXT".to_string());
    admitted.path = Some("/evidence/Users/alice/deep/c.TXT".to_string());
    let mut nameless = target(6, b"ab");
    nameless.name = None;
    nameless.path = None;

    let req = SweepRequest {
        scope: SearchScope {
            artifact_types: Some(vec!["FileContent".to_string()]),
            extensions: Some(vec![".txt".to_string()]),
            path_prefix: Some("/evidence/".to_string()),
            path_glob: Some("/evidence/Users/alice/**".to_string()),
            regions: RegionKind::ALL.to_vec(),
        },
        bounds: SweepBounds::default(),
        resume: None,
    };
    let response = sweep(
        vec![
            wrong_type,
            wrong_ext,
            wrong_prefix,
            wrong_glob,
            admitted,
            nameless,
        ],
        &bytes_pattern("6162"),
        &req,
    )
    .expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(5), 0)]);
    assert_eq!(response.objects_excluded.artifact_type, 1);
    assert_eq!(
        response.objects_excluded.extension, 2,
        "the wrong extension and the nameless object"
    );
    assert_eq!(
        response.objects_excluded.path, 2,
        "the wrong prefix and the wrong glob"
    );
    assert_eq!(response.objects_excluded.region, 0);
    assert_eq!(response.objects_excluded.total(), 5);
    assert_eq!(response.objects_searched, 1);
    assert!(
        response.scope_statement.contains("txt"),
        "{}",
        response.scope_statement
    );
}

#[test]
fn a_glob_star_crosses_neither_a_slash_nor_a_backslash_and_either_separator_matches_the_other() {
    // Evidence paths come with both separators: the filesystem plugins build
    // `/`-separated paths, registry and shell-item paths carry backslashes.
    // A `*` must stop at either, or `C:\Users\*\NTUSER.DAT` would admit
    // every NTUSER.DAT at any depth below Users.
    let backslashes = SearchScope {
        path_glob: Some("C:\\Users\\*\\NTUSER.DAT".to_string()),
        ..SearchScope::default()
    }
    .compile()
    .expect("glob compiles");
    let mut direct = target(1, b"x");
    direct.path = Some("C:\\Users\\alice\\NTUSER.DAT".to_string());
    assert_eq!(backslashes.admits(&direct), Ok(()));
    let mut deeper = target(2, b"x");
    deeper.path = Some("C:\\Users\\alice\\x\\NTUSER.DAT".to_string());
    assert_eq!(
        backslashes.admits(&deeper),
        Err(ScopeExclusion::Path),
        "`*` must not cross a backslash"
    );
    let mut slashed = target(3, b"x");
    slashed.path = Some("C:/Users/alice/NTUSER.DAT".to_string());
    assert_eq!(
        backslashes.admits(&slashed),
        Ok(()),
        "a backslash in the glob matches a slash in the path"
    );
    let mut slashed_deeper = target(4, b"x");
    slashed_deeper.path = Some("C:/Users/alice/x/NTUSER.DAT".to_string());
    assert_eq!(
        backslashes.admits(&slashed_deeper),
        Err(ScopeExclusion::Path)
    );

    let slashes = SearchScope {
        path_glob: Some("C:/Users/*/NTUSER.DAT".to_string()),
        ..SearchScope::default()
    }
    .compile()
    .expect("glob compiles");
    assert_eq!(slashes.admits(&direct), Ok(()));
    assert_eq!(slashes.admits(&deeper), Err(ScopeExclusion::Path));

    let doublestar = SearchScope {
        path_glob: Some("C:\\Users\\**\\NTUSER.DAT".to_string()),
        ..SearchScope::default()
    }
    .compile()
    .expect("glob compiles");
    assert_eq!(
        doublestar.admits(&deeper),
        Ok(()),
        "`**` crosses separators"
    );
}

#[test]
fn an_empty_region_list_and_a_bad_glob_are_refused_not_run() {
    let no_regions = SearchScope {
        regions: vec![],
        ..SearchScope::default()
    };
    assert_eq!(no_regions.compile().err(), Some(ScopeError::NoRegions));
    let err = sweep(
        vec![target(1, b"ab")],
        &bytes_pattern("6162"),
        &SweepRequest {
            scope: no_regions,
            bounds: SweepBounds::default(),
            resume: None,
        },
    )
    .expect_err("refused");
    assert_eq!(err, SweepError::Scope(ScopeError::NoRegions));

    let bad_glob = SearchScope {
        path_glob: Some("[unclosed".to_string()),
        ..SearchScope::default()
    };
    assert!(matches!(
        bad_glob.compile(),
        Err(ScopeError::InvalidGlob(_))
    ));
}

#[test]
fn a_pattern_set_over_the_needle_ceiling_is_refused_not_built() {
    // A bytes pattern is exactly one needle, so MAX_NEEDLES + 1 distinct ones
    // is the smallest over-limit set.
    let specs: Vec<PatternSpec> = (0..=MAX_NEEDLES)
        .map(|n| PatternSpec::bytes(format!("{n:04x}")))
        .collect();
    assert_eq!(specs.len(), MAX_NEEDLES + 1);
    let err = PatternSet::compile(&specs, &[]).expect_err("over the ceiling");
    assert_eq!(
        err,
        PatternError::TooManyNeedles {
            needles: MAX_NEEDLES + 1,
            limit: MAX_NEEDLES
        }
    );
    // Exactly at the ceiling is still built.
    PatternSet::compile(&specs[..MAX_NEEDLES], &[]).expect("at the ceiling compiles");
}

#[test]
fn a_replacement_class_code_page_is_reported_absent_not_searched() {
    // WHATWG maps these labels to the "replacement" encoding, which has no
    // byte form of any text. It must be disclosed as absent, never searched.
    let labels = ["iso-2022-kr", "hz-gb-2312"];
    let cps: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    let set = PatternSet::compile(&[PatternSpec::text("abc")], &cps).expect("compiles");
    assert_eq!(
        set.codepages_absent(),
        &["iso-2022-kr".to_string(), "hz-gb-2312".to_string()]
    );
    assert!(set.codepages_resolved().is_empty());
    assert!(!set
        .encodings_searched()
        .iter()
        .any(|e| e.contains("replacement")));
}

#[test]
fn an_empty_type_or_extension_list_is_refused_not_stated_as_every_one() {
    // Some(empty) admits nothing, yet used to be described as "Every ...".
    let no_types = SearchScope {
        artifact_types: Some(vec![]),
        ..SearchScope::default()
    };
    assert_eq!(
        no_types.compile().err(),
        Some(ScopeError::EmptyArtifactTypes)
    );
    assert!(no_types.statement().contains("No artifact type admitted."));
    assert!(!no_types.statement().contains("Every artifact type"));

    let no_exts = SearchScope {
        extensions: Some(vec![]),
        ..SearchScope::default()
    };
    assert_eq!(no_exts.compile().err(), Some(ScopeError::EmptyExtensions));
    assert!(no_exts.statement().contains("No extension admitted."));
    assert!(!no_exts.statement().contains("Every extension"));

    let err = sweep(
        vec![target(1, b"ab")],
        &bytes_pattern("6162"),
        &SweepRequest {
            scope: no_exts,
            bounds: SweepBounds::default(),
            resume: None,
        },
    )
    .expect_err("refused");
    assert_eq!(err, SweepError::Scope(ScopeError::EmptyExtensions));
}

#[test]
fn the_default_scope_deserialises_with_every_region_and_serialises_them_by_name() {
    let scope: SearchScope = serde_json::from_str("{}").expect("empty object is the default");
    assert_eq!(scope, SearchScope::default());
    let json = serde_json::to_value(&scope).expect("serialises");
    assert_eq!(
        json["regions"],
        serde_json::json!(["live", "slack", "unallocated", "recovered", "raw"])
    );
    let narrowed: SearchScope =
        serde_json::from_str(r#"{"regions":["unallocated"],"extensions":["txt"]}"#)
            .expect("parses");
    assert_eq!(narrowed.regions, vec![RegionKind::Unallocated]);
    assert_eq!(
        narrowed.excluded_regions(),
        vec![
            RegionKind::Live,
            RegionKind::Slack,
            RegionKind::Recovered,
            RegionKind::Raw
        ]
    );
}

// ---------------------------------------------------------------------------
// 3. Grouping across copies
// ---------------------------------------------------------------------------

#[test]
fn hits_in_copies_of_one_object_collapse_into_one_group_keeping_every_location() {
    let same = b"xx-ab-xx-ab".to_vec();
    let other = b"ab".to_vec();
    let mut copy = target(2, &same);
    copy.path = Some("/backup/file1.txt".to_string());
    let response = sweep(
        vec![target(1, &same), copy, target(3, &other)],
        &bytes_pattern("6162"),
        &request(small_chunks(4)),
    )
    .expect("sweep runs");

    assert_eq!(response.grouping.hit_count, 5);
    assert_eq!(response.grouping.group_count, 2);
    assert_eq!(response.grouping.hits_without_content_hash, 0);
    let total_locations: usize = response
        .grouping
        .groups
        .iter()
        .map(|g| g.locations.len())
        .sum();
    assert_eq!(total_locations, 5, "grouping never drops a location");

    let copies = response
        .grouping
        .groups
        .iter()
        .find(|g| g.artifact_ids.len() == 2)
        .expect("one group spans the two copies");
    assert_eq!(copies.artifact_ids, vec![id(1), id(2)]);
    assert_eq!(copies.locations.len(), 4);
    match &copies.basis {
        GroupingBasis::ContentHash { sha256 } => {
            assert_eq!(sha256.len(), 64);
            use sha2::Digest;
            let expect = format!("{:x}", sha2::Sha256::digest(&same));
            assert_eq!(
                sha256, &expect,
                "the hash is the SHA-256 of the object's bytes"
            );
        }
        other => panic!("copies must group on content hash, got {other:?}"),
    }
    assert_eq!(response.hits.len(), 5, "the ungrouped list is intact");
}

#[test]
fn a_caller_supplied_hash_is_used_and_a_cut_object_groups_by_its_own_identity() {
    // Objects 1 and 2 hold different bytes but the caller says they hash
    // alike (it has hashed them in full elsewhere); the sweep must use what it
    // is told, not what it computed over a prefix.
    let mut a = target(1, b"ab..............");
    a.content_hash = Some("f".repeat(64));
    let mut b = target(2, b"ab..");
    b.content_hash = Some("f".repeat(64));
    // Object 3 has no hash and is cut by the byte cap, so it cannot be
    // matched to a copy.
    let c = target(3, b"ab..............");
    let response = sweep(
        vec![a, b, c],
        &bytes_pattern("6162"),
        &request(SweepBounds {
            max_hits: 100,
            max_bytes: 16 + 4 + 5,
            chunk_bytes: 4,
        }),
    )
    .expect("sweep runs");
    assert_eq!(response.grouping.hit_count, 3);
    assert_eq!(response.grouping.group_count, 2);
    assert_eq!(response.grouping.hits_without_content_hash, 1);
    let cut = response
        .grouping
        .groups
        .iter()
        .find(|g| g.artifact_ids == vec![id(3)])
        .expect("the cut object is its own group");
    match &cut.basis {
        GroupingBasis::ArtifactIdentity {
            artifact_id,
            reason,
        } => {
            assert_eq!(*artifact_id, id(3));
            assert!(reason.contains("5 of 16"), "{reason}");
        }
        other => panic!("a cut object has no content hash, got {other:?}"),
    }
    let trusted = response
        .grouping
        .groups
        .iter()
        .find(|g| g.artifact_ids.len() == 2)
        .expect("the caller's hashes joined objects 1 and 2");
    assert_eq!(
        trusted.basis,
        GroupingBasis::ContentHash {
            sha256: "f".repeat(64)
        }
    );
}

#[test]
fn group_hits_keys_on_kind_value_and_hash_and_never_drops_a_location() {
    let hit = |n: u8, offset: u64, kind: PatternKind, value: &str| SweepHit {
        artifact_id: id(n),
        artifact_type: "FileContent".to_string(),
        region: RegionKind::Live,
        path: None,
        offset,
        length: 2,
        pattern_index: 0,
        pattern_kind: kind,
        pattern_value: value.to_string(),
        encodings: vec!["utf-8".to_string()],
        endian_aliases: Vec::new(),
    };
    let hits = vec![
        hit(1, 0, PatternKind::Text, "ab"),
        hit(2, 5, PatternKind::Text, "ab"),
        hit(1, 9, PatternKind::Text, "ab"),
        hit(1, 0, PatternKind::Bytes, "6162"),
        hit(3, 0, PatternKind::Text, "ab"),
    ];
    let mut hashes = HashMap::new();
    hashes.insert(id(1), "h1".to_string());
    hashes.insert(id(2), "h1".to_string());
    let mut reasons = HashMap::new();
    reasons.insert(id(3), "resumed part way through the object".to_string());

    let grouping = group_hits(&hits, &hashes, &reasons);
    assert_eq!(grouping.hit_count, 5);
    assert_eq!(
        grouping.group_count, 3,
        "text/ab across copies, bytes/6162, and the unhashed object"
    );
    assert_eq!(grouping.hits_without_content_hash, 1);
    let total: usize = grouping.groups.iter().map(|g| g.locations.len()).sum();
    assert_eq!(total, 5);
    let text_group = &grouping.groups[0];
    assert_eq!(text_group.artifact_ids, vec![id(1), id(2)]);
    assert_eq!(text_group.locations.len(), 3);
    assert_eq!(
        grouping.groups[2].basis,
        GroupingBasis::ArtifactIdentity {
            artifact_id: id(3),
            reason: "resumed part way through the object".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// 4. Encodings
// ---------------------------------------------------------------------------

#[test]
fn a_text_pattern_is_found_as_utf8_utf16le_and_utf16be_and_each_hit_names_its_encoding() {
    let word = "cañón";
    let mut data = Vec::new();
    data.extend_from_slice(b"..");
    data.extend_from_slice(word.as_bytes()); // 2..8 (ñ and ó are two bytes each)
    data.extend_from_slice(b"..");
    let le_at = data.len() as u64;
    data.extend_from_slice(&utf16le(word)); // 10 bytes
    data.extend_from_slice(b"..");
    let be_at = data.len() as u64;
    data.extend_from_slice(&utf16be(word));

    let response = sweep(
        vec![target(1, &data)],
        &text_pattern(word, &[]),
        &request(small_chunks(5)),
    )
    .expect("sweep runs");
    let found: Vec<(u64, u64, Vec<String>)> = response
        .hits
        .iter()
        .map(|h| (h.offset, h.length, h.encodings.clone()))
        .collect();
    assert_eq!(
        found,
        vec![
            (2, 7, vec!["utf-8".to_string()]),
            (le_at, 10, vec!["utf-16le".to_string()]),
            (be_at, 10, vec!["utf-16be".to_string()]),
        ]
    );
    assert_eq!(
        response.encodings_searched,
        vec![
            "utf-8".to_string(),
            "utf-16le".to_string(),
            "utf-16be".to_string()
        ]
    );
    assert!(response
        .hits
        .iter()
        .all(|h| h.pattern_kind == PatternKind::Text));
    assert!(response.hits.iter().all(|h| h.pattern_value == word));
}

#[test]
fn windows_1252_bytes_are_found_and_labelled_and_a_latin1_label_is_shown_resolving_to_it() {
    // "cañón" in windows-1252 is 63 61 F1 F3 6E — not valid UTF-8.
    let cp1252 = vec![0x63, 0x61, 0xF1, 0xF3, 0x6E];
    let mut data = b"..".to_vec();
    data.extend_from_slice(&cp1252);
    let patterns = text_pattern("cañón", &["windows-1252", "iso-8859-1"]);
    assert_eq!(
        patterns.codepages_resolved(),
        &[
            seance_search::sweep::CodepageResolution {
                label: "windows-1252".to_string(),
                name: "windows-1252".to_string(),
                built_in: false,
            },
            seance_search::sweep::CodepageResolution {
                label: "iso-8859-1".to_string(),
                name: "windows-1252".to_string(),
                built_in: false,
            },
        ]
    );
    assert_eq!(
        patterns.encodings_searched(),
        &["utf-8", "utf-16le", "utf-16be", "windows-1252"]
    );
    let response =
        sweep(vec![target(1, &data)], &patterns, &request(small_chunks(3))).expect("sweep runs");
    assert_eq!(response.hits.len(), 1);
    assert_eq!(response.hits[0].offset, 2);
    assert_eq!(response.hits[0].length, 5);
    assert_eq!(response.hits[0].encodings, vec!["windows-1252".to_string()]);
}

#[test]
fn an_ascii_hit_lists_every_encoding_it_is_consistent_with_rather_than_guessing_one() {
    let response = sweep(
        vec![target(1, b"..plan..")],
        &text_pattern("plan", &["windows-1252", "ibm866"]),
        &request(small_chunks(3)),
    )
    .expect("sweep runs");
    assert_eq!(response.hits.len(), 1);
    assert_eq!(
        response.hits[0].encodings,
        vec![
            "utf-8".to_string(),
            "windows-1252".to_string(),
            "ibm866".to_string()
        ],
        "ASCII bytes are the same under every ASCII-compatible encoding, and the hit says so"
    );
}

#[test]
fn an_unknown_codepage_is_reported_absent_not_approximated() {
    let patterns = text_pattern("plan", &["windows-1252", "klingon-1"]);
    assert_eq!(patterns.codepages_absent(), &["klingon-1".to_string()]);
    assert_eq!(
        patterns.encodings_searched(),
        &["utf-8", "utf-16le", "utf-16be", "windows-1252"]
    );
    let response = sweep(
        vec![target(1, b"plan")],
        &patterns,
        &request(SweepBounds::default()),
    )
    .expect("sweep runs");
    assert_eq!(response.codepages_absent, vec!["klingon-1".to_string()]);
}

#[test]
fn a_codepage_that_cannot_represent_the_pattern_is_skipped_and_its_substitute_is_not_searched() {
    // encoding_rs substitutes a numeric character reference for a character
    // the code page lacks; searching for that would be searching for
    // something the examiner never typed.
    let patterns = text_pattern("日本", &["windows-1252"]);
    assert_eq!(patterns.encodings_skipped().len(), 1);
    assert_eq!(patterns.encodings_skipped()[0].pattern_index, 0);
    assert_eq!(patterns.encodings_skipped()[0].encoding, "windows-1252");
    assert!(
        patterns.encodings_skipped()[0].reason.contains("represent"),
        "{}",
        patterns.encodings_skipped()[0].reason
    );
    let response = sweep(
        vec![target(1, b"&#26085;&#26412;")],
        &patterns,
        &request(SweepBounds::default()),
    )
    .expect("sweep runs");
    assert!(response.hits.is_empty());
    assert_eq!(response.encodings_skipped.len(), 1);
}

#[test]
fn a_utf8_or_utf16_label_given_as_a_codepage_is_reported_as_already_built_in() {
    let patterns = text_pattern("plan", &["utf-8", "utf-16"]);
    let resolved = patterns.codepages_resolved();
    assert_eq!(resolved.len(), 2);
    assert!(resolved.iter().all(|r| r.built_in), "{resolved:?}");
    assert_eq!(
        resolved[1].name, "utf-16le",
        "the WHATWG 'utf-16' label is little-endian"
    );
    assert_eq!(
        patterns.encodings_searched(),
        &["utf-8", "utf-16le", "utf-16be"],
        "nothing is searched twice"
    );
    assert_eq!(patterns.needle_count(), 3);
}

#[test]
fn a_bytes_pattern_accepts_separators_and_refuses_bad_hex_empty_and_oversize_patterns() {
    let ok = PatternSet::compile(&[PatternSpec::bytes("ab cd:EF-01")], &[]).expect("compiles");
    assert_eq!(ok.needle_count(), 1);

    assert_eq!(
        PatternSet::compile(&[], &[]).err(),
        Some(PatternError::NoPatterns)
    );
    assert_eq!(
        PatternSet::compile(&[PatternSpec::bytes("")], &[]).err(),
        Some(PatternError::EmptyPattern { index: 0 })
    );
    assert_eq!(
        PatternSet::compile(&[PatternSpec::text("")], &[]).err(),
        Some(PatternError::EmptyPattern { index: 0 })
    );
    assert!(matches!(
        PatternSet::compile(&[PatternSpec::bytes("abc")], &[]).err(),
        Some(PatternError::BadHex { index: 0, .. })
    ));
    assert!(matches!(
        PatternSet::compile(&[PatternSpec::bytes("zz")], &[]).err(),
        Some(PatternError::BadHex { index: 0, .. })
    ));
    let long = "a".repeat(MAX_PATTERN_BYTES + 1);
    assert_eq!(
        PatternSet::compile(&[PatternSpec::text(long)], &[]).err(),
        Some(PatternError::TooLong {
            index: 0,
            encoding: "utf-8".to_string(),
            bytes: MAX_PATTERN_BYTES + 1,
            limit: MAX_PATTERN_BYTES,
        })
    );
}

#[test]
fn a_hit_and_a_response_serialise_with_the_encoding_and_the_ceilings() {
    let response = sweep(
        vec![target(1, b"plan")],
        &text_pattern("plan", &["windows-1252"]),
        &request(SweepBounds {
            max_hits: 7,
            max_bytes: 99,
            chunk_bytes: 8,
        }),
    )
    .expect("sweep runs");
    let json = serde_json::to_value(&response).expect("serialises");
    assert_eq!(json["max_hits"], 7);
    assert_eq!(json["max_bytes"], 99);
    assert_eq!(json["hit_cap_reached"], false);
    assert_eq!(
        json["hits"][0]["encodings"],
        serde_json::json!(["utf-8", "windows-1252"])
    );
    assert_eq!(json["hits"][0]["region"], "live");
    assert_eq!(json["hits"][0]["pattern_kind"], "text");
    assert_eq!(
        json["grouping"]["groups"][0]["basis"]["basis"],
        "content_hash"
    );
    let back: SweepResponse = serde_json::from_value(json).expect("round-trips");
    assert_eq!(back, response);
}

#[test]
fn a_non_ascii_ibm866_pattern_is_found_by_its_ibm866_bytes_and_labelled_ibm866_alone() {
    // "план" in IBM866 is AF AB A0 AD (the code page puts а..п at A0..AF);
    // in windows-1251 it would be EF EB E0 ED and in UTF-8 D0 BF D0 BB D0
    // B0 D0 BD, so a hit on these bytes is consistent with ibm866 only.
    let ibm866 = [0xAF, 0xAB, 0xA0, 0xAD];
    let mut data = b"..".to_vec();
    data.extend_from_slice(&ibm866);
    data.extend_from_slice(&[0xEF, 0xEB, 0xE0, 0xED]);
    let response = sweep(
        vec![target(1, &data)],
        &text_pattern("план", &["ibm866"]),
        &request(small_chunks(3)),
    )
    .expect("sweep runs");
    assert_eq!(response.hits.len(), 1);
    assert_eq!(response.hits[0].offset, 2);
    assert_eq!(response.hits[0].length, 4);
    assert_eq!(response.hits[0].encodings, vec!["ibm866".to_string()]);
}

#[test]
fn two_patterns_with_the_same_byte_form_are_refused_rather_than_reported_twice() {
    assert_eq!(
        PatternSet::compile(&[PatternSpec::text("plan"), PatternSpec::text("plan")], &[]).err(),
        Some(PatternError::Duplicate {
            index: 1,
            duplicate_of: 0
        })
    );
    assert_eq!(
        PatternSet::compile(
            &[
                PatternSpec::bytes("ab cd"),
                PatternSpec::text("x"),
                PatternSpec::bytes("ABCD")
            ],
            &[]
        )
        .err(),
        Some(PatternError::Duplicate {
            index: 2,
            duplicate_of: 0
        }),
        "the same bytes spelled differently are one pattern"
    );
    // The text "ab" and the bytes 61 62 are different patterns (one is
    // searched under every encoding, the other as given) and both stand.
    let ok = PatternSet::compile(&[PatternSpec::text("ab"), PatternSpec::bytes("6162")], &[])
        .expect("compiles");
    assert_eq!(ok.specs().len(), 2);
}

// ---------------------------------------------------------------------------
// 5. Sizes and counts that must add up
// ---------------------------------------------------------------------------

#[test]
fn bytes_beyond_the_declared_size_are_not_searched_and_the_result_says_so_by_number() {
    // The source holds "ab" twice, but the object is declared as 4 bytes, so
    // only the first occurrence is inside it. The 6 bytes past the declared
    // end are reported, not silently ignored.
    let mut source = target(1, b"..ab..ab..");
    source.declared_size = 4;
    let response = sweep(
        vec![source, target(2, b"ab")],
        &bytes_pattern("6162"),
        &request(small_chunks(3)),
    )
    .expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(1), 2), (id(2), 0)]);
    assert_eq!(response.beyond_declared_size.len(), 1);
    let beyond = &response.beyond_declared_size[0];
    assert_eq!(beyond.artifact_id, id(1));
    assert_eq!(beyond.declared_size, 4);
    assert_eq!(beyond.source_size, 10);
    assert_eq!(beyond.bytes_beyond, 6);
    assert_eq!(response.bytes_beyond_declared_size, 6);
    assert_eq!(response.bytes_scanned, 4 + 2);
    assert!(
        response.complete,
        "every declared byte was read; the declared extent is the object"
    );
    assert!(
        response.coverage_statement.contains("6 byte(s) beyond"),
        "{}",
        response.coverage_statement
    );
    assert!(
        response.coverage_statement.contains("not searched"),
        "{}",
        response.coverage_statement
    );
}

#[test]
fn an_empty_object_is_counted_as_empty_so_the_object_counts_add_up() {
    let response = sweep(
        vec![target(1, b""), target(2, b"ab"), target(3, b"")],
        &bytes_pattern("6162"),
        &request(SweepBounds::default()),
    )
    .expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(2), 0)]);
    assert_eq!(response.objects_offered, 3);
    assert_eq!(response.objects_empty, 2);
    assert_eq!(response.objects_searched, 1);
    assert_eq!(
        response.objects_offered,
        response.objects_searched
            + response.objects_empty
            + response.objects_excluded.total()
            + response.objects_skipped_by_cursor
    );
    assert!(response.complete);
}

#[test]
fn a_cursor_at_the_end_of_its_object_counts_that_object_as_passed_over() {
    let response = sweep(
        vec![target(1, b"ab"), target(2, b"ab")],
        &bytes_pattern("6162"),
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds::default(),
            resume: Some(SweepCursor {
                artifact_id: id(1),
                offset: 2,
            }),
        },
    )
    .expect("sweep runs");
    assert_eq!(locations(&response.hits), vec![(id(2), 0)]);
    assert_eq!(response.objects_skipped_by_cursor, 1);
    assert_eq!(response.objects_searched, 1);
    assert_eq!(response.objects_empty, 0);
    assert_eq!(
        response.objects_offered,
        response.objects_searched
            + response.objects_empty
            + response.objects_excluded.total()
            + response.objects_skipped_by_cursor
    );
}

#[test]
fn a_byte_ceiling_at_an_object_boundary_leaves_the_cursor_object_offered_but_unaccounted() {
    // A is read in full and the budget reaches zero. B is pulled, found to have
    // nowhere to go, and left for the next page: offered, but in no other count.
    let response = sweep(
        vec![target(1, b"abcd"), target(2, b"ab")],
        &bytes_pattern("6162"),
        &request(SweepBounds {
            max_bytes: 4,
            ..SweepBounds::default()
        }),
    )
    .expect("sweep runs");
    assert!(response.byte_cap_reached);
    assert!(!response.complete);
    assert_eq!(
        response.next_cursor,
        Some(SweepCursor {
            artifact_id: id(2),
            offset: 0
        })
    );
    assert_eq!(response.objects_offered, 2);
    assert_eq!(response.objects_searched, 1);
    assert_eq!(
        response.objects_offered,
        response.objects_searched
            + response.objects_empty
            + response.objects_excluded.total()
            + response.objects_skipped_by_cursor
            + 1,
        "the cursor's object is offered but not yet searched, empty, excluded or skipped"
    );
}

// ---------------------------------------------------------------------------
// 6. UTF-16 endian aliases
// ---------------------------------------------------------------------------
//
// UTF-16BE "cities" followed by any Latin-1 code unit contains UTF-16LE
// "cities" one byte later (the 00 high bytes line up either way), and
// UTF-16LE "cities" preceded by a Latin-1 code unit contains UTF-16BE
// "cities" one byte earlier. The bytes alone cannot say which the writer
// used, so one run of bytes must be one hit naming both, not two hits each
// pinning a different encoding.

/// (encoding, offset, folded) of each alias on a hit.
type Alias = (String, u64, bool);

fn alias_of(hit: &SweepHit) -> Vec<Alias> {
    hit.endian_aliases
        .iter()
        .map(|a| (a.encoding.clone(), a.offset, a.folded))
        .collect()
}

#[test]
fn a_utf16be_string_followed_by_latin1_text_is_one_hit_naming_both_endiannesses() {
    let mut data = b"xx".to_vec();
    data.extend_from_slice(&utf16be("cities")); // 2..14
    data.extend_from_slice(&utf16be(" and towns"));
    for chunk in [1usize, 2, 3, 5, 7, 12, 13, 14, 15, 64] {
        let response = sweep(
            vec![target(1, &data)],
            &text_pattern("cities", &[]),
            &request(small_chunks(chunk)),
        )
        .expect("sweep runs");
        assert_eq!(response.hits.len(), 1, "chunk {chunk}: {:?}", response.hits);
        let hit = &response.hits[0];
        assert_eq!(hit.offset, 2, "chunk {chunk}");
        assert_eq!(hit.length, 12, "chunk {chunk}");
        assert_eq!(
            hit.encodings,
            vec!["utf-16be".to_string(), "utf-16le".to_string()],
            "chunk {chunk}: both endiannesses are candidates"
        );
        assert_eq!(
            alias_of(hit),
            vec![("utf-16le".to_string(), 3, true)],
            "chunk {chunk}: the LE reading one byte later was folded into this hit"
        );
        assert!(hit.endian_ambiguous(), "chunk {chunk}");
        assert_eq!(response.hits_endian_ambiguous, 1, "chunk {chunk}");
        assert_eq!(response.endian_aliases_folded, 1, "chunk {chunk}");
        assert!(
            response
                .coverage_statement
                .contains("both UTF-16 endiannesses"),
            "chunk {chunk}: {}",
            response.coverage_statement
        );
        assert!(response.complete, "chunk {chunk}");
    }
}

#[test]
fn a_utf16le_string_preceded_by_latin1_text_is_reported_at_the_earlier_be_reading_with_le_as_its_alias(
) {
    // "go " LE is 67 00 6F 00 20 00; the 00 at byte 5 makes bytes 5..17 a
    // UTF-16BE "cities", one before the LE "cities" the writer put at 6.
    let mut data = utf16le("go ");
    data.extend_from_slice(&utf16le("cities")); // 6..18
    data.extend_from_slice(b"\xFF\xFE"); // not a Latin-1 code unit under either endianness
    let response = sweep(
        vec![target(1, &data)],
        &text_pattern("cities", &[]),
        &request(small_chunks(4)),
    )
    .expect("sweep runs");
    assert_eq!(response.hits.len(), 1, "{:?}", response.hits);
    let hit = &response.hits[0];
    assert_eq!(
        hit.offset, 5,
        "the hit sits at the earlier of the two readings"
    );
    assert_eq!(
        hit.encodings,
        vec!["utf-16be".to_string(), "utf-16le".to_string()]
    );
    assert_eq!(alias_of(hit), vec![("utf-16le".to_string(), 6, true)]);
}

#[test]
fn a_utf16_hit_with_no_opposite_reading_beside_it_is_pinned_to_its_encoding() {
    // BE "cities" followed by U+0416 (04 16): the byte after the string is
    // 04, not 00, so the LE reading one byte later does not exist. BE
    // "cities" at the very end of the object has no byte after it at all.
    let mut data = utf16be("cities");
    data.extend_from_slice(&utf16be("Ж"));
    data.extend_from_slice(b"|");
    let tail_at = data.len() as u64;
    data.extend_from_slice(&utf16be("cities"));
    let response = sweep(
        vec![target(1, &data)],
        &text_pattern("cities", &[]),
        &request(small_chunks(5)),
    )
    .expect("sweep runs");
    let found: Vec<(u64, Vec<String>, Vec<Alias>)> = response
        .hits
        .iter()
        .map(|h| (h.offset, h.encodings.clone(), alias_of(h)))
        .collect();
    assert_eq!(
        found,
        vec![
            (0, vec!["utf-16be".to_string()], vec![]),
            (tail_at, vec!["utf-16be".to_string()], vec![]),
        ]
    );
    assert_eq!(response.hits_endian_ambiguous, 0);
    assert_eq!(response.endian_aliases_folded, 0);
    assert!(response.hits.iter().all(|h| !h.endian_ambiguous()));
}

#[test]
fn a_run_of_one_repeated_code_unit_reports_every_reading_marked_rather_than_folding_a_chain() {
    // "aa" in a UTF-16BE run of four a's reads as BE at 0, 2 and 4 and as LE
    // at 1 and 3: every reading has a neighbour on both sides, so there is no
    // pair to fold. Every occurrence is reported, each naming the opposite
    // readings beside it, and none is counted as folded.
    let data = utf16be("aaaa");
    let response = sweep(
        vec![target(1, &data)],
        &text_pattern("aa", &[]),
        &request(small_chunks(3)),
    )
    .expect("sweep runs");
    let found: Vec<(u64, Vec<String>, Vec<Alias>)> = response
        .hits
        .iter()
        .map(|h| (h.offset, h.encodings.clone(), alias_of(h)))
        .collect();
    let be = || vec!["utf-16be".to_string()];
    let le = || vec!["utf-16le".to_string()];
    assert_eq!(
        found,
        vec![
            (0, be(), vec![("utf-16le".to_string(), 1, false)]),
            (
                1,
                le(),
                vec![
                    ("utf-16be".to_string(), 0, false),
                    ("utf-16be".to_string(), 2, false)
                ]
            ),
            (
                2,
                be(),
                vec![
                    ("utf-16le".to_string(), 1, false),
                    ("utf-16le".to_string(), 3, false)
                ]
            ),
            (
                3,
                le(),
                vec![
                    ("utf-16be".to_string(), 2, false),
                    ("utf-16be".to_string(), 4, false)
                ]
            ),
            (4, be(), vec![("utf-16le".to_string(), 3, false)]),
        ]
    );
    assert_eq!(response.hits_endian_ambiguous, 5);
    assert_eq!(response.endian_aliases_folded, 0);
}

#[test]
fn endian_alias_folding_is_the_same_whether_or_not_the_sweep_is_paged() {
    // Several folded pairs and one pinned hit, paged one hit at a time and
    // also cut by a byte ceiling that lands inside a pair, must enumerate
    // exactly the hits of one unbounded sweep.
    let mut data = Vec::new();
    for _ in 0..4 {
        data.extend_from_slice(&utf16be("cities are "));
        data.extend_from_slice(&utf16le("in cities."));
    }
    data.extend_from_slice(&utf16be("cities"));
    data.extend_from_slice(&utf16be("Ж"));
    let patterns = text_pattern("cities", &[]);
    let whole =
        sweep(vec![target(1, &data)], &patterns, &request(small_chunks(9))).expect("sweep runs");
    assert_eq!(whole.hits.len(), 9, "{:?}", whole.hits);
    assert_eq!(whole.endian_aliases_folded, 8);
    assert_eq!(whole.hits_endian_ambiguous, 8);

    for bounds in [
        SweepBounds {
            max_hits: 1,
            max_bytes: u64::MAX,
            chunk_bytes: 9,
        },
        SweepBounds {
            max_hits: 10_000,
            max_bytes: 13,
            chunk_bytes: 9,
        },
        SweepBounds {
            max_hits: 2,
            max_bytes: 25,
            chunk_bytes: 6,
        },
    ] {
        let mut cursor: Option<SweepCursor> = None;
        let mut collected: Vec<SweepHit> = Vec::new();
        let mut folded = 0;
        let mut pages = 0;
        loop {
            let page = sweep(
                vec![target(1, &data)],
                &patterns,
                &SweepRequest {
                    scope: SearchScope::default(),
                    bounds,
                    resume: cursor,
                },
            )
            .expect("page runs");
            collected.extend(page.hits.iter().cloned());
            folded += page.endian_aliases_folded;
            cursor = page.next_cursor;
            pages += 1;
            if cursor.is_none() {
                break;
            }
            assert!(pages < 200, "paging must terminate");
        }
        assert!(pages > 1, "{bounds:?} must page");
        assert_eq!(collected, whole.hits, "{bounds:?}");
        assert_eq!(folded, 8, "{bounds:?}");
    }
}

#[test]
fn an_endian_alias_serialises_on_the_hit_and_is_absent_when_there_is_none() {
    let mut data = utf16be("cities are");
    data.extend_from_slice(b"|");
    data.extend_from_slice(&utf16be("cities"));
    let response = sweep(
        vec![target(1, &data)],
        &text_pattern("cities", &[]),
        &request(SweepBounds::default()),
    )
    .expect("sweep runs");
    let json = serde_json::to_value(&response).expect("serialises");
    assert_eq!(
        json["hits"][0]["encodings"],
        serde_json::json!(["utf-16be", "utf-16le"])
    );
    assert_eq!(
        json["hits"][0]["endian_aliases"],
        serde_json::json!([{ "encoding": "utf-16le", "offset": 1, "folded": true }])
    );
    assert_eq!(
        json["hits"][1]["encodings"],
        serde_json::json!(["utf-16be"])
    );
    assert!(json["hits"][1].get("endian_aliases").is_none());
    assert_eq!(json["endian_aliases_folded"], 1);
    assert_eq!(json["hits_endian_ambiguous"], 1);
    let back: SweepResponse = serde_json::from_value(json).expect("round-trips");
    assert_eq!(back, response);
}
