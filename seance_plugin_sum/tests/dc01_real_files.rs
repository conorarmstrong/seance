//! Known-answer check of the UAL parser against the real `Sum` directory of
//! DFIR Madness Case 001's domain controller (DC01, Server 2012 R2), ROADMAP
//! §5.2, `VALIDATION.md` `UAL-1`.
//!
//! Gated on `SEANCE_DC01_SUM_DIR`, a directory holding `Current.mdb` (MFT
//! inode 84733 of the C: volume) and `SystemIdentity.mdb` (inode 84695),
//! extracted with `icat`. Without it every test here returns without asserting
//! and says so; a skip is not a pass.
//!
//! The expected figures were read with a second, independent ESE reader
//! (`dissect.esedb`), not with this crate, and are recorded in `VALIDATION.md`.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_sum::SumParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

fn run(name: &str) -> Option<Vec<Artifact>> {
    let dir = match std::env::var("SEANCE_DC01_SUM_DIR") {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIPPED (not passed): SEANCE_DC01_SUM_DIR is not set");
            return None;
        }
    };
    let bytes = std::fs::read(std::path::Path::new(&dir).join(name)).expect("read the real file");
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    Some(SumParser::new().process(&artifact).expect("process"))
}

fn of<'a>(out: &'a [Artifact], subtype: &str) -> Vec<&'a Artifact> {
    out.iter()
        .filter(|a| a.subtype() == Some(subtype))
        .collect()
}

/// `Current.mdb`, ESE state 2 (dirty shutdown). The independent reader finds
/// CLIENTS, ROLE_ACCESS, DNS and VIRTUALMACHINES all empty, and `Svc.log`
/// (same directory) holds `c137\administrator` and `c137\citadel-dc01$`, so
/// "0 rows" is what the file holds and not what the server recorded.
#[test]
fn current_mdb_reads_empty_and_says_it_was_shut_down_dirty() {
    let Some(out) = run("Current.mdb") else {
        return;
    };
    let summary = of(&out, "ual_summary");
    assert_eq!(summary.len(), 1);
    let m = &summary[0].metadata;
    assert_eq!(m["client_access_records"], 0);
    assert_eq!(m["tables_parsed"].as_array().unwrap().len(), 4);
    assert_eq!(m["database_state"], "dirty_shutdown");
    assert_eq!(m["content_incomplete"], true);
    assert!(of(&out, "ual_client_access").is_empty());
}

/// `SystemIdentity.mdb`, ESE state 3 (clean): 3 SYSTEM_IDENTITY rows, 13
/// ROLE_IDS rows and 1 CHAINED_DATABASES row by the independent reader, and
/// every field the parser maps carries the independent reader's value.
#[test]
fn system_identity_mdb_matches_the_independent_reader() {
    let Some(out) = run("SystemIdentity.mdb") else {
        return;
    };
    assert_eq!(of(&out, "ual_role_id").len(), 13);
    assert_eq!(of(&out, "ual_chained_database").len(), 1);
    let ids = of(&out, "ual_system_identity");
    assert_eq!(ids.len(), 3);
    let hosts: Vec<(&str, &str)> = ids
        .iter()
        .map(|a| {
            (
                a.metadata["dns_host_name"].as_str().unwrap(),
                a.metadata["domain_name"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        hosts,
        [
            ("WIN-E0PO207ERMD", "WORKGROUP"),
            ("WIN-E0PO207ERMD", "C137.local"),
            ("CITADEL-DC01", "C137.local"),
        ]
    );
    for a in &ids {
        assert_eq!(a.metadata["os_build_number"], 9600);
        assert_eq!(a.metadata["os_version"], "6.3");
        // OSCurrentTimeZone 65116 = -420 minutes.
        assert_eq!(a.metadata["system_timezone"], "UTC-07:00");
    }
    // FILETIME 132448316944240000 -> 2020-09-17T15:54:54.424Z
    assert_eq!(
        ids[0].metadata["creation_time"],
        "2020-09-17T15:54:54.424+00:00"
    );
    let chained = of(&out, "ual_chained_database");
    assert_eq!(
        chained[0].metadata["file_name"],
        "{9D2CCF2E-F5C3-47F3-9BFA-49937CC468C0}.mdb"
    );
    // A clean database carries no dirty stamp.
    assert!(of(&out, "ual_summary")[0]
        .metadata
        .get("database_state")
        .is_none());
}
