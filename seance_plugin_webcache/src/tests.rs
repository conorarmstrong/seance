use super::*;
use seance_core::test_support::TruncatedSource;

/// The real `WebCacheV01.dat`, which lives at the WORKSPACE root.
///
/// `cargo test` runs each crate with its own directory as the working
/// directory, so the bare relative path this used to hold resolved to
/// `seance_plugin_webcache/test_data/…` and never existed. Both fixture-gated
/// tests below then printed "Skipping" and passed on every machine, including
/// the one measurement the orphan-container distinction rests on — a gate that
/// is always shut is not evidence, it just looks like it. The rest of the tree
/// resolves fixtures from `CARGO_MANIFEST_DIR`; so does this.
fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test_data/WebCacheV01.dat")
}

/// The fixture, through the corpus gate.
///
/// `None` means the corpus is not provisioned and the run has **said so** on
/// stderr; a `SEANCE_WEBCACHE` that names a file which is not there panics
/// rather than skipping. Before this, both fixture-gated tests below skipped on
/// a bare `if !path.exists()`, which `SEANCE_REQUIRE_CORPUS=1` cannot reach —
/// so `documentation/CI.md`'s promise that the flag turns every corpus skip
/// into a failure was not true of this crate, and the tests printed `ok` on
/// every machine in the project.
fn gated_fixture() -> Option<std::path::PathBuf> {
    let in_tree = fixture_path();
    if in_tree.is_file() {
        return Some(in_tree);
    }
    seance_core::test_support::corpus::path("SEANCE_WEBCACHE")
}

#[test]
fn clean_url_strips_ie_visited_decoration() {
    assert_eq!(
        clean_url("Visited: bob@https://evidence.test/page"),
        "https://evidence.test/page"
    );
    assert_eq!(clean_url("Visited: user@about:blank"), "about:blank");
    // A plain URL is unchanged; an email-looking value without a URL is kept.
    assert_eq!(
        clean_url("https://plain.example/"),
        "https://plain.example/"
    );
    assert_eq!(clean_url("someone@example.com"), "someone@example.com");
}

#[test]
fn filetime_decodes_to_rfc3339() {
    // 130019472000000000 (100ns since 1601) == 2013-01-06T12:00:00Z.
    assert_eq!(
        filetime_to_rfc3339(130_019_472_000_000_000).as_deref(),
        Some("2013-01-06T12:00:00+00:00")
    );
    assert!(filetime_to_rfc3339(0).is_none());
    assert!(filetime_to_rfc3339(1).is_none()); // before the Unix epoch
}

#[test]
fn build_record_shapes_a_history_entry() {
    let parent = Uuid::new_v4();
    let rec = build_record(
        Uuid::new_v4(),
        parent,
        "History",
        "Visited: alice@https://bank.example/login",
        Some("2013-01-06T12:00:00+00:00".to_string()),
        None,
        Some(7),
    );
    assert_eq!(rec.metadata["type"], "WebCacheEntry");
    assert_eq!(rec.metadata["container"], "History");
    assert_eq!(rec.metadata["url"], "https://bank.example/login");
    assert_eq!(
        rec.metadata["raw_url"],
        "Visited: alice@https://bank.example/login"
    );
    assert_eq!(rec.metadata["accessed_time"], "2013-01-06T12:00:00+00:00");
    assert_eq!(rec.metadata["access_count"], 7);
    assert_eq!(rec.parent_id, Some(parent));
    assert!(rec.metadata.get("modified_time").is_none());
}

#[test]
fn build_record_omits_raw_url_when_unchanged() {
    let rec = build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "Content",
        "https://cdn.example/app.js",
        None,
        None,
        None,
    );
    assert_eq!(rec.metadata["url"], "https://cdn.example/app.js");
    assert!(rec.metadata.get("raw_url").is_none());
}

#[test]
fn module_metadata() {
    let p = WebCacheParser;
    assert_eq!(p.id(), "plugin.browsers.webcache");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

/// Gated end-to-end test: runs only when a real WebCacheV01.dat is provided
/// (libesedb is read-only, so the ESE database cannot be synthesised). Mirrors
/// the SRUM parser's real-fixture test.
#[test]
fn parses_real_webcache_fixture_when_present() {
    use seance_core::data_source::FileDataSource;
    use std::sync::Arc;

    let Some(path) = gated_fixture() else {
        return;
    };
    let Ok(fds) = FileDataSource::new(path.clone()) else {
        eprintln!("Skipping: could not open {}", path.display());
        return;
    };
    let ds: Arc<dyn DataSource> = Arc::new(fds);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "WebCacheV01.dat" }),
    );
    let out = WebCacheParser.process(&art).unwrap();
    let entries = out
        .iter()
        .filter(|a| a.metadata["type"] == "WebCacheEntry")
        .count();
    assert!(entries > 0, "a real WebCacheV01.dat should yield entries");

    // The only other record this parser may emit is the single walk-status
    // record, and it appears only when a declared container or a row could not
    // be read. Anything else is a record type that does not belong here.
    let status: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.metadata["type"] == "WebCacheParseStatus")
        .collect();
    assert!(status.len() <= 1, "at most one walk-status record");
    assert_eq!(
        entries + status.len(),
        out.len(),
        "unexpected record type in WebCache output"
    );
    for s in &status {
        // If a real database does trip this, it must say WHICH containers were
        // unreadable — a bare flag on ordinary evidence would be noise an
        // examiner cannot act on.
        eprintln!("WebCache fixture: walk gaps: {}", s.metadata["detail"]);
        assert!(s.metadata["detail"].is_string());
        // And it must not claim a content gap over a healthy file. Measured on
        // this fixture: 21 declared containers, 21 `Container_<id>` tables,
        // 1549 rows and every one of them carrying a non-empty Url. Nothing
        // here is a container or a row the parser failed to read, so a content
        // flag on it would be the parser crying wolf.
        assert_eq!(
            s.metadata["unreadable_containers"]
                .as_array()
                .unwrap()
                .len(),
            0,
            "a healthy fixture reported an unreadable container table"
        );
        assert_eq!(s.metadata["container_list_unreadable"], json!(false));
        assert_eq!(
            s.metadata["rows_skipped"],
            json!(0),
            "every row of this fixture carries a readable Url; a skip here means the value \
             decoder, not the evidence, is at fault"
        );
    }

    // The stamp must stay off ordinary evidence, or it stops meaning anything
    // on the evidence that needs it.
    for e in out.iter().filter(|a| a.metadata["type"] == "WebCacheEntry") {
        assert!(
            e.metadata.get("content_incomplete").is_none(),
            "a healthy WebCacheV01.dat must not stamp its entries incomplete"
        );
        assert!(
            e.metadata.get("inventory_incomplete").is_none(),
            "nor short: a banner on ordinary evidence is a banner nobody reads"
        );
    }
    eprintln!("WebCache fixture: extracted {entries} entries");
}
#[test]
fn truncated_ese_is_not_staged() {
    // BUG-269: staging the readable prefix let libesedb open a partial database
    // and emit its subset of rows as though the whole WebCache was recovered.
    let src = TruncatedSource::new(vec![0xAAu8; 2048], 32768);
    let err = extract_to_temp(&src).expect_err("a truncated ESE database must not be staged");
    assert!(
        err.to_string().contains("WebCache"),
        "error names the database: {err}"
    );
}

#[test]
fn complete_ese_is_staged_from_short_reads() {
    use seance_core::test_support::DribbleSource;

    let bytes: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    let temp = extract_to_temp(&DribbleSource::new(bytes.clone(), 256))
        .expect("short reads must be looped, not treated as EOF");
    let staged = std::fs::read(temp.path()).unwrap();
    assert_eq!(staged, bytes);
    // The RAII guard removes the staged file when it drops at end of scope.
}

#[test]
fn a_negative_signed_timestamp_column_yields_no_date_rather_than_a_far_future_one() {
    // -1 reinterpreted as an unsigned FILETIME is year 30828: it passes every
    // epoch and range check and sorts to the end of any timeline.
    assert_eq!(as_filetime(&Value::I64(-1)), None);
    assert_eq!(as_filetime(&Value::I32(-1)), None);

    // A real FILETIME carried in a signed column still decodes.
    assert_eq!(
        as_filetime(&Value::I64(130_019_472_000_000_000)),
        Some(130_019_472_000_000_000)
    );
    // And an explicit DateTime column is passed through untouched.
    assert_eq!(
        as_filetime(&Value::DateTime(130_019_472_000_000_000)),
        Some(130_019_472_000_000_000)
    );
}

#[test]
fn a_negative_signed_count_column_yields_no_count_rather_than_an_astronomical_one() {
    // B8-011: -1 reinterpreted as unsigned is 1.8e19. Reported as `access_count`
    // it reads as a measured number of visits to a URL, which is a finding the
    // evidence does not support; absent is the only honest answer. WebCache reads
    // its counts through the shared seance_ese_util::value_to_u64; this pins that
    // the shared helper keeps the negative-refusing contract WebCache depends on.
    assert_eq!(value_to_u64(&Value::I64(-1)), None);
    assert_eq!(value_to_u64(&Value::I32(-1)), None);

    // Real counts in signed columns still decode, and so do unsigned ones.
    assert_eq!(value_to_u64(&Value::I64(7)), Some(7));
    assert_eq!(value_to_u64(&Value::I32(7)), Some(7));
    assert_eq!(value_to_u64(&Value::U32(7)), Some(7));
}

// --- B2-171: a database we could not read is not an empty one ---------------
//
// `table_by_name` and `iter_records` failures were bare `continue`s and an empty
// result only logged a `warn!`. Because the `Containers` table is an inventory,
// a `Container_<id>` that will not open is a container the database SAYS holds
// URLs and the parser could not reach — reported as "no history", that supports
// a claim ("this site was never visited") the evidence does not support. A real
// ESE database cannot be synthesised for a unit test, so the walk's outcome is
// pinned through the two functions that publish it.

fn some_gaps() -> WalkGaps {
    WalkGaps {
        unreadable_containers: vec![
            (3, "History".to_string(), "table_not_opened"),
            (9, "Cookies".to_string(), "records_not_iterated"),
        ],
        orphan_containers: Vec::new(),
        rows_skipped: 41,
        container_list_unreadable: false,
        catalog_enumerated: true,
    }
}

#[test]
fn a_clean_walk_leaves_records_unmarked_and_emits_no_status() {
    // The counterweight: if a complete parse were marked, the marks on the
    // damaged ones would carry no information.
    let gaps = WalkGaps::default();
    assert!(gaps.is_complete());

    let mut records = vec![build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "History",
        "https://plain.example/",
        None,
        None,
        None,
    )];
    stamp_gaps(&mut records, &gaps);
    assert!(records[0].metadata.get("content_incomplete").is_none());
    assert!(records[0].metadata.get("inventory_incomplete").is_none());
}

#[test]
fn gaps_are_stamped_on_every_entry_that_did_survive() {
    let mut records = vec![
        build_record(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "History",
            "https://a.example/",
            None,
            None,
            None,
        ),
        build_record(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Content",
            "https://b.example/",
            None,
            None,
            None,
        ),
    ];
    stamp_gaps(&mut records, &some_gaps());
    for r in &records {
        assert_eq!(r.metadata["content_incomplete"], json!(true));
        assert_eq!(
            r.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        // A container that would not open costs the list entries as well as
        // bytes, and the entry viewer is the only surface an examiner opens.
        assert_eq!(r.metadata["inventory_incomplete"], json!(true));
        // The entry itself is untouched otherwise.
        assert_eq!(r.metadata["type"], json!("WebCacheEntry"));
    }
}

#[test]
fn the_status_record_names_the_containers_that_could_not_be_read() {
    let parent = Uuid::new_v4();
    let status = gap_status_record(Uuid::new_v4(), parent, &some_gaps(), 5, 12);

    assert_eq!(status.metadata["type"], json!("WebCacheParseStatus"));
    assert_eq!(status.metadata["subtype"], json!("parse_incomplete"));
    assert_eq!(status.metadata["content_incomplete"], json!(true));
    assert_eq!(status.metadata["containers_declared"], json!(5));
    assert_eq!(status.metadata["rows_skipped"], json!(41));
    assert_eq!(status.metadata["entries_recovered"], json!(12));
    assert_eq!(status.parent_id, Some(parent));

    let unreadable = status.metadata["unreadable_containers"].as_array().unwrap();
    assert_eq!(unreadable.len(), 2);
    assert_eq!(unreadable[0]["container"], json!("History"));
    assert_eq!(unreadable[0]["container_id"], json!(3));
    assert_eq!(unreadable[0]["reason"], json!("table_not_opened"));
    assert_eq!(unreadable[1]["container"], json!("Cookies"));
    assert_eq!(unreadable[1]["reason"], json!("records_not_iterated"));

    // The marker must not carry the entries' own type, or grouping by
    // `metadata.$.type` files it as a browsing record.
    assert_ne!(status.metadata["type"], json!("WebCacheEntry"));
}

/// The case the status record exists for: nothing was recovered at all.
#[test]
fn an_unreadable_container_inventory_is_not_a_browser_that_was_never_used() {
    let gaps = WalkGaps {
        unreadable_containers: Vec::new(),
        orphan_containers: Vec::new(),
        rows_skipped: 0,
        container_list_unreadable: true,
        catalog_enumerated: true,
    };
    assert!(!gaps.is_complete());

    let status = gap_status_record(Uuid::new_v4(), Uuid::new_v4(), &gaps, 0, 0);
    assert_eq!(status.metadata["container_list_unreadable"], json!(true));
    assert_eq!(status.metadata["entries_recovered"], json!(0));
    assert!(status.metadata["detail"]
        .as_str()
        .unwrap()
        .contains("says nothing about what this database held"));
}

#[test]
fn a_single_refused_row_is_enough_to_make_the_walk_incomplete() {
    let gaps = WalkGaps {
        unreadable_containers: Vec::new(),
        orphan_containers: Vec::new(),
        rows_skipped: 1,
        container_list_unreadable: false,
        catalog_enumerated: true,
    };
    assert!(!gaps.is_complete());
    assert!(gaps.content_incomplete());
    let status = gap_status_record(Uuid::new_v4(), Uuid::new_v4(), &gaps, 4, 100);
    assert_eq!(status.metadata["rows_skipped"], json!(1));
}

// --- A container row without a table is not a damaged database ---------------
//
// The stamp above only means anything while it stays rare. Measured against a
// real WebCacheV01.dat (Windows 8.1, 21 containers): `Containers` declared ids
// 1-8, 10-17, 19-23 and the catalog held exactly those 21 `Container_<id>`
// tables — zero orphan rows. Scavenging removes the row and the table together,
// which is why ids 9 and 18 are absent from both. So an orphan row IS worth
// reporting; it is just not a content gap, and must not stamp entries that are
// themselves whole.

fn orphan_only_gaps() -> WalkGaps {
    WalkGaps {
        unreadable_containers: Vec::new(),
        orphan_containers: vec![(9, "MSHist012014051220140513".to_string())],
        rows_skipped: 0,
        container_list_unreadable: false,
        catalog_enumerated: true,
    }
}

#[test]
fn an_orphan_container_row_is_an_inventory_gap_not_a_content_one() {
    let gaps = orphan_only_gaps();
    // Worth telling the examiner about...
    assert!(!gaps.is_complete());
    // ...but not a claim that the recovered URLs are partial.
    assert!(!gaps.content_incomplete());

    let mut records = vec![build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "History",
        "https://a.example/",
        None,
        None,
        None,
    )];
    stamp_gaps(&mut records, &gaps);
    assert!(
        records[0].metadata.get("content_incomplete").is_none(),
        "an orphan container row must not brand every recovered URL as partial"
    );
    // ...but it must still reach the examiner where they are reading. The
    // status record is its own record type and the entry viewer never fetches
    // it, so an entry list short of a container the database names would
    // otherwise render as the complete browsing history.
    assert_eq!(
        records[0].metadata["inventory_incomplete"],
        json!(true),
        "the entry list is short of a declared container and must say so on the entries"
    );
    assert_eq!(
        records[0].metadata["inventory_incomplete_reason"],
        json!("unresolved_structure")
    );
}

#[test]
fn the_status_record_for_an_orphan_row_says_inventory_not_content() {
    let status = gap_status_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &orphan_only_gaps(),
        21,
        4000,
    );
    assert_eq!(
        status.metadata["status"],
        json!("ContainerRowsWithoutTables")
    );
    assert_eq!(status.metadata["content_incomplete"], json!(false));
    assert!(status.metadata.get("content_incomplete_reason").is_none());
    assert_eq!(status.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        status.metadata["inventory_incomplete_reason"],
        json!("unresolved_structure")
    );

    let orphans = status.metadata["orphan_containers"].as_array().unwrap();
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0]["container_id"], json!(9));
    assert_eq!(orphans[0]["reason"], json!("table_absent_from_catalog"));
    assert!(status.metadata["detail"]
        .as_str()
        .unwrap()
        .contains("are themselves complete"));
}

/// Every stamp this parser writes has to carry its sentence on the key the
/// examiner-facing reader displays.
///
/// `frontend/src/lib/incompleteness.ts` is the one place the pair is read, and
/// it takes the sentence from `content_incomplete_detail` /
/// `inventory_incomplete_detail`. This crate wrote only a bare `detail` on the
/// status record and no sentence at all on the entries, so an examiner looking
/// at a WebCache listing short of two containers was shown "unresolved
/// structure" and nothing else. Every assertion here fails against the unfixed
/// crate.
#[test]
fn every_webcache_stamp_carries_its_sentence_where_the_reader_looks() {
    let gaps = WalkGaps {
        unreadable_containers: vec![(4, "Content".to_string(), "table_not_opened")],
        orphan_containers: vec![(9, "MSHist012014051220140513".to_string())],
        rows_skipped: 2,
        container_list_unreadable: false,
        catalog_enumerated: true,
    };
    let mut records = vec![build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "History",
        "https://a.example/",
        None,
        None,
        None,
    )];
    stamp_gaps(&mut records, &gaps);

    let content = records[0].metadata["content_incomplete_detail"]
        .as_str()
        .expect("a content stamp must say what was not read");
    assert!(content.contains("1 container(s)"), "{content}");
    assert!(content.contains("2 row(s)"), "{content}");
    let inventory = records[0].metadata["inventory_incomplete_detail"]
        .as_str()
        .expect("an inventory stamp must say what is missing from the listing");
    assert!(inventory.contains("2 of the containers"), "{inventory}");

    let status = gap_status_record(Uuid::new_v4(), Uuid::new_v4(), &gaps, 21, 4000);
    let detail = status.metadata["detail"].as_str().unwrap();
    assert_eq!(status.metadata["content_incomplete_detail"], json!(detail));
    assert_eq!(
        status.metadata["inventory_incomplete_detail"],
        json!(detail)
    );

    // A database whose only fault is an inventory gap must not carry a content
    // sentence: it has nothing to say, and saying it anyway is the
    // over-correction this distinction exists to avoid.
    let orphan_status = gap_status_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &orphan_only_gaps(),
        21,
        4000,
    );
    assert!(orphan_status
        .metadata
        .get("content_incomplete_detail")
        .is_none());
    assert!(orphan_status.metadata["inventory_incomplete_detail"].is_string());

    // And the record that says the database could not be opened at all.
    let unreadable = unreadable_database_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "DatabaseNotStaged",
        "the database could not be staged for reading",
    );
    assert!(unreadable.metadata["content_incomplete_detail"].is_string());
    assert!(unreadable.metadata["inventory_incomplete_detail"].is_string());
}

#[test]
fn a_container_table_present_in_the_catalog_that_will_not_open_is_still_a_content_gap() {
    let catalog: HashSet<String> = ["Containers", "Container_3"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(
        classify_container_gap(Some(&catalog), "Container_3", "table_not_opened"),
        ContainerGap::Unreadable("table_not_opened"),
    );
    assert_eq!(
        classify_container_gap(Some(&catalog), "Container_9", "table_not_opened"),
        ContainerGap::Orphan,
    );
}

#[test]
fn an_unenumerable_catalog_cannot_be_used_to_call_a_container_absent() {
    // Fail closed: absence has not been established, so the stronger claim is
    // not made and the container is reported as unread.
    assert_eq!(
        classify_container_gap(None, "Container_9", "table_not_opened"),
        ContainerGap::Unreadable("table_not_opened"),
    );

    let gaps = WalkGaps {
        unreadable_containers: vec![(9, "History".to_string(), "table_not_opened")],
        orphan_containers: Vec::new(),
        rows_skipped: 0,
        container_list_unreadable: false,
        catalog_enumerated: false,
    };
    let status = gap_status_record(Uuid::new_v4(), Uuid::new_v4(), &gaps, 21, 4000);
    assert_eq!(status.metadata["catalog_enumerated"], json!(false));
    assert_eq!(status.metadata["content_incomplete"], json!(true));
}

/// The measurement the whole distinction rests on, pinned against the real
/// fixture: a healthy `WebCacheV01.dat` has no orphan container rows and no
/// unreadable container tables, so the `content_incomplete` stamp does not fire
/// on ordinary Windows evidence.
#[test]
fn the_real_fixtures_containers_and_tables_agree_exactly() {
    let Some(path) = gated_fixture() else {
        return;
    };
    let Ok(db) = EseDb::open(&path) else {
        eprintln!("Skipping: {} would not open", path.display());
        return;
    };
    let catalog = catalog_table_names(&db).expect("the fixture's catalog enumerates");
    let containers = db
        .table_by_name("Containers")
        .expect("the fixture has a Containers table");
    let cols = column_names(&containers);

    let mut declared = 0usize;
    let mut orphans: Vec<i64> = Vec::new();
    for rec in containers.iter_records().expect("Containers iterates") {
        let rec = rec.expect("every Containers row decodes");
        let id = col_value(&rec, &cols, "ContainerId")
            .and_then(|v| as_i64(&v))
            .expect("every Containers row carries a ContainerId");
        declared += 1;
        if !catalog.contains(&format!("Container_{id}")) {
            orphans.push(id);
        }
    }

    assert!(declared > 0, "the fixture declares containers");
    assert!(
        orphans.is_empty(),
        "a healthy WebCacheV01.dat has no orphan container rows, found {orphans:?} of \
         {declared} declared"
    );
    eprintln!("WebCache fixture: {declared} containers declared, all with tables");
}

/// B6-021: a file named `WebCacheV01.dat` that carries the ESE magic but cannot
/// be staged used to return nothing at all — indistinguishable from a browser
/// that was never used.
#[test]
fn an_unstageable_webcache_database_reports_itself() {
    // ESE magic at offset 4 so the content gate admits it, then a declared size
    // the source cannot satisfy.
    use std::sync::Arc;
    let mut available = vec![0u8; 4096];
    // ESE magic, as it appears on disk at offset 4.
    available[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
    let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(available, 1 << 20));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        json!({ "name": "WebCacheV01.dat" }),
    );

    let out = WebCacheParser.process(&art).unwrap();
    assert_eq!(
        out.len(),
        1,
        "an unreadable WebCache must not return nothing"
    );
    assert_eq!(out[0].metadata["type"], "WebCacheParseStatus");
    assert_eq!(out[0].metadata["status"], "DatabaseNotStaged");
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert_eq!(
        out[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

/// The same failure on an ESE database that is NOT a WebCache (SRUM, say) must
/// stay silent: a marker there would be a false claim about browsing history.
#[test]
fn an_unstageable_non_webcache_ese_database_stays_silent() {
    use std::sync::Arc;
    let mut available = vec![0u8; 4096];
    // ESE magic, as it appears on disk at offset 4.
    available[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
    let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(available, 1 << 20));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        json!({ "name": "SRUDB.dat" }),
    );
    assert!(WebCacheParser.process(&art).unwrap().is_empty());
}

/// HUNT-277. SYNTHETIC: eight KiB with the ESE signature at offset 4, declared
/// as larger than it is, so staging refuses it. That is the path that depends
/// on the file's name (a WebCache that cannot be staged is reported, any other
/// ESE database is not), and a prior version's `name` carries the shadow-copy
/// label, so only `file_name` identifies it. No real evidence is graded; the
/// real-database path is the gated fixture test above.
fn prior_version(file_name: &str, source: std::sync::Arc<dyn DataSource>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        json!({
            "type": "VssPriorVersion",
            "name": format!("{file_name} [shadow copy 2015-03-23T00:00:00Z]"),
            "file_name": file_name,
            "is_snapshot_version": true,
            "snapshot_label": "SHADOW COPY VERSION, not the live volume",
            "vss_snapshot_id": "snap-1",
            "vss_creation_time": "2015-03-23T00:00:00Z",
            "vss_stack_position": 1,
        }),
    )
}

fn short_ese() -> std::sync::Arc<dyn DataSource> {
    let mut bytes = vec![0u8; 8192];
    bytes[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
    std::sync::Arc::new(TruncatedSource::new(bytes, 1 << 20))
}

#[test]
fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
    let out = WebCacheParser
        .process(&prior_version("WebCacheV01.dat", short_ese()))
        .unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    let m = &out[0].metadata;
    assert_eq!(m["type"], "WebCacheParseStatus");
    assert_eq!(m["is_snapshot_version"], true);
    assert_eq!(m["vss_snapshot_id"], "snap-1");
    assert!(
        m.get("shadow_copy_sidecars_not_searched").is_some(),
        "{m:#?}"
    );

    // A ParsedRecord that is not a prior version is not this parser's.
    let plain = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(short_ese()),
        json!({ "type": "SomethingElse", "name": "WebCacheV01.dat" }),
    );
    assert!(WebCacheParser.process(&plain).unwrap().is_empty());

    // The same bytes as a live FileEntry are reported, but not stamped.
    let live = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(short_ese()),
        json!({ "name": "WebCacheV01.dat" }),
    );
    let live = WebCacheParser.process(&live).unwrap();
    assert_eq!(live.len(), 1);
    assert!(live[0].metadata.get("is_snapshot_version").is_none());

    // A prior version of some other ESE database is not a WebCache gap.
    let other = WebCacheParser
        .process(&prior_version("SRUDB.dat", short_ese()))
        .unwrap();
    assert!(other.is_empty(), "{other:#?}");
}

/// CR-047. SYNTHETIC: a source whose every read fails. An unreadable header
/// is "could not look", never "not this format": `process` must return the
/// error, not an empty success a report would read as "no such artefact".
#[test]
fn an_unreadable_header_is_could_not_look_not_not_this_format() {
    use seance_core::test_support::UnreadableSource;
    let ds: std::sync::Arc<dyn seance_core::data_source::DataSource> =
        std::sync::Arc::new(UnreadableSource::new(4096));
    let art = seance_core::artifact::Artifact::new(
        uuid::Uuid::new_v4(),
        seance_core::artifact::ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "WebCacheV01.dat" }),
    );
    let out = WebCacheParser.process(&art);
    assert!(
        matches!(out, Err(seance_core::module::ModuleError::IoError(_))),
        "an unreadable header must be an error, got {out:?}"
    );
}
