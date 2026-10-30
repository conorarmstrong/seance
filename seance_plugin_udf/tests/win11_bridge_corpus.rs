//! UDF-BRIDGE-1: a real UDF 1.02 bridge disc read through both halves.
//!
//! The disc is Microsoft's Windows 11 25H2 Enterprise evaluation ISO
//! (`win11-25h2-enterprise-eval-x64-en-us.iso`, 7,092,807,680 bytes,
//! SHA-256 a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9).
//! It is 7 GB and Microsoft's to distribute, so it is never committed: point
//! `SEANCE_WIN11_ISO` at it. Unset, the test skips and says so;
//! `SEANCE_REQUIRE_CORPUS=1` turns the skip into a failure.
//!
//! Every expected value below came from tools independent of Séance:
//! 7-Zip 26.00 (`7zz l -tudf` lists 976 files and 94 folders; `7zz x -tudf`
//! for the hashed files) and xorriso 1.5 (`-ls /` shows the ISO 9660 half
//! holds README.TXT alone; `-extract /README.TXT` for its hash).

use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_iso9660::Iso9660Parser;
use seance_plugin_partition::FilesystemDetector;
use seance_plugin_udf::UdfParser;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn sha256_of(a: &Artifact) -> String {
    let ds = a.data.as_ref().expect("content attached");
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut off = 0u64;
    while off < ds.size() {
        let n = ds.read_at(off, &mut buf).expect("read");
        assert!(n > 0, "short read at {off}");
        h.update(&buf[..n]);
        off += n as u64;
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn by_path<'a>(out: &'a [Artifact], path: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.metadata["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("no entry {path}"))
}

#[test]
fn win11_bridge_reads_both_halves() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_WIN11_ISO") else {
        return;
    };
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open ISO"));
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({"name": "win11.iso"}),
    );

    // Partition detection names both halves and does not call either hidden.
    let fs = FilesystemDetector.process(&raw).expect("detect");
    let subtypes: Vec<&str> = fs
        .iter()
        .map(|a| a.metadata["subtype"].as_str().unwrap())
        .collect();
    assert_eq!(subtypes, ["iso9660", "udf"]);
    for a in &fs {
        assert_eq!(a.metadata["udf_bridge"], true);
        assert!(a.metadata.get("hidden").is_none());
        assert!(a.metadata.get("overlap_warning").is_none());
    }

    // The ISO 9660 half: README.TXT and nothing else.
    let iso = Iso9660Parser.process(&fs[0]).expect("iso9660");
    let iso_paths: Vec<&str> = iso
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .map(|a| a.metadata["path"].as_str().unwrap())
        .collect();
    assert_eq!(iso_paths, ["/README.TXT"]);
    assert_eq!(
        sha256_of(by_path(&iso, "/README.TXT")),
        "b1243f198c2f2fbab0408ba9d5b87ce4889a8ecf6f598e44c5ae39de2198ddf0"
    );

    // The UDF half: the whole install tree.
    let udf = UdfParser.process(&fs[1]).expect("udf");
    let vol = &udf
        .iter()
        .find(|a| a.metadata["type"].as_str() == Some("udf_volume"))
        .expect("volume record")
        .metadata;
    assert_eq!(vol["volume_set_identifier"], "d84dc000MS UDFBridge");
    assert_eq!(vol["domain_identifier"], "*OSTA UDF Compliant");
    assert_eq!(vol["anchor_sector"], 256);
    assert!(vol.get("udf_unreadable").is_none(), "{vol}");
    assert!(vol.get("directory_parse_incomplete").is_none(), "{vol}");
    assert!(
        vol.get("partition_extends_past_evidence").is_none(),
        "{vol}"
    );

    let entries: Vec<&Artifact> = udf
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();
    let dirs = entries
        .iter()
        .filter(|a| a.metadata["is_directory"] == true)
        .count();
    assert_eq!(entries.len() - dirs, 976, "files, as 7-Zip lists them");
    assert_eq!(dirs, 94, "folders, as 7-Zip lists them");
    assert!(entries.iter().all(|a| a.metadata.get("deleted").is_none()));
    assert!(entries
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));

    // Every File Entry carries a modification time with its recorded offset.
    assert!(entries.iter().all(|a| a.metadata["modified"].is_string()
        && a.metadata.get("timestamps_timezone_unspecified").is_none()));
    eprintln!(
        "UDF-BRIDGE-1 setup.exe modified = {}",
        by_path(&udf, "/setup.exe").metadata["modified"]
    );

    // Over 4 GiB: the extents are followed, not capped. The size alone
    // proves nothing (the data source reports the information length even
    // over a hole), so the whole 6.2 GB is hashed against 7-Zip's
    // extraction (`7zz x -tudf -so <iso> sources/install.wim | sha256sum`).
    let install = by_path(&udf, "/sources/install.wim");
    assert_eq!(install.metadata["size"], 6_225_286_811u64);
    assert!(install.metadata.get("content_incomplete").is_none());
    assert_eq!(install.metadata["data_runs_complete"], true);
    assert_eq!(
        sha256_of(install),
        "119100d92fa9516d47c9933f9c6f4e2b1940bd685762fdca6982e6d29b353985",
        "install.wim"
    );
    assert_eq!(
        by_path(&udf, "/sources/boot.wim").metadata["size"],
        593_147_852u64
    );

    for (p, want) in [
        (
            "/sources/uninstall.xml",
            "2c15a254e32c91ac155f668fc6ad75e230e1e2a78651cfe75d284016feafaf56",
        ),
        (
            "/setup.exe",
            "72a0bcac2d4de630ad094bfc312bd4431aa5c286c683de7e0650c1675e5fc7c5",
        ),
        (
            "/autorun.inf",
            "3378723cb5910e5f3afe1ee2200b8f0d08bab8c5d77f7ce9fcb5725aff525852",
        ),
        (
            "/bootmgr",
            "6374f092f1f09fa175a7a2ef03accc53144638c3378f02661e0d6fcecdfc5c88",
        ),
    ] {
        assert_eq!(sha256_of(by_path(&udf, p)), want, "{p}");
    }
}
