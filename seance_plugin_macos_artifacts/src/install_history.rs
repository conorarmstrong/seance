//! Software install history — `/Library/Receipts/InstallHistory.plist`.
//!
//! An ordered array of every OS update and package install: display name and
//! version, the date, the process that performed it (`softwareupdated`,
//! `installer`, the App Store), and the package identifiers. It is the
//! system-wide software-provenance timeline.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::info;

use crate::{basename_lower, to_rfc3339, Staged};

/// Largest InstallHistory.plist read into memory. These are KBs–MBs.
const MAX_PLIST_BYTES: u64 = 64 * 1024 * 1024;

/// Emits one `SoftwareInstall` record per install-history entry.
pub struct InstallHistoryParser;

fn is_install_history(name: &str) -> bool {
    basename_lower(name) == "installhistory.plist"
}

fn plist_date_unix(v: &plist::Value) -> Option<i64> {
    if let plist::Value::Date(d) = v {
        let st: std::time::SystemTime = (*d).into();
        st.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|dur| dur.as_secs() as i64)
    } else {
        None
    }
}

impl ForensicsModule for InstallHistoryParser {
    fn id(&self) -> &str {
        "macos.install_history"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_install_history(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let staged = Staged::read(ds.as_ref(), MAX_PLIST_BYTES);

        // A prefix of a plist normally will not parse, and returning nothing
        // would delete the system's whole software-provenance timeline from the
        // case with no record that the file was ever there.
        let lost = "so the OS updates and package installs it records could not be read";
        //
        // The same holds for a file read in full that will not parse, or whose
        // layout is not the array of dictionaries this reader knows: the file
        // was there and this reader could not read it, which is not the same
        // finding as a machine that installed nothing (HUNT-179).
        let value = match plist::from_bytes::<plist::Value>(&staged.bytes) {
            Ok(value) => value,
            Err(e) => {
                return Ok(vec![staged.unreadable_marker(
                    artifact.case_id,
                    artifact.id,
                    "SoftwareInstallIncomplete",
                    name,
                    "ParseFailed",
                    &format!("did not parse as a property list ({e})"),
                    lost,
                )]);
            }
        };
        let Some(entries) = value.as_array() else {
            return Ok(vec![staged.unreadable_marker(
                artifact.case_id,
                artifact.id,
                "SoftwareInstallIncomplete",
                name,
                "UnexpectedLayout",
                "its root is not the array of install dictionaries this reader knows",
                lost,
            )]);
        };

        let mut out = Vec::new();
        let mut unreadable = 0usize;
        for entry in entries {
            let Some(d) = entry.as_dictionary() else {
                unreadable += 1;
                continue;
            };
            let display_name = d.get("displayName").and_then(|v| v.as_string());
            let display_version = d.get("displayVersion").and_then(|v| v.as_string());
            let process_name = d.get("processName").and_then(|v| v.as_string());
            let content_type = d.get("contentType").and_then(|v| v.as_string());
            let date = d.get("date").and_then(plist_date_unix);
            let package_ids: Vec<String> = d
                .get("packageIdentifiers")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_string().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let mut meta = serde_json::Map::new();
            meta.insert("type".into(), json!("SoftwareInstall"));
            meta.insert("subtype".into(), json!("install_history"));
            meta.insert("display_name".into(), json!(display_name));
            meta.insert("display_version".into(), json!(display_version));
            meta.insert("process_name".into(), json!(process_name));
            meta.insert("content_type".into(), json!(content_type));
            meta.insert("package_identifiers".into(), json!(package_ids));
            if let Some(ts) = date {
                meta.insert("timestamp".into(), json!(ts));
                if let Some(r) = to_rfc3339(ts) {
                    meta.insert("timestamp_rfc3339".into(), json!(r));
                }
            }
            let label = display_name.unwrap_or("(unknown package)");
            let ver = display_version.map(|v| format!(" {v}")).unwrap_or_default();
            let by = process_name
                .map(|p| format!(" via {p}"))
                .unwrap_or_default();
            meta.insert("name".into(), json!(format!("Installed {label}{ver}{by}")));
            // An install read out of a partial file is real, but the installs
            // past the cut are missing: this row must not read as a complete
            // software timeline.
            staged.stamp(name, &mut meta);

            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    meta.into(),
                )
                .with_parent(artifact.id)
                .with_subtype("install_history"),
            );
        }

        // A partial read that yielded no installs still has to say the file was
        // there and was not read in full.
        if out.is_empty() {
            out.extend(staged.incomplete_marker(
                artifact.case_id,
                artifact.id,
                "SoftwareInstallIncomplete",
                name,
                lost,
            ));
        }

        // Entries that are not dictionaries hold no install this reader can
        // read. Skipped in silence, an array of nothing else read as a machine
        // that installed nothing, and a mixed one as a complete timeline.
        // (A short read already says the file was not read in full, above.)
        if unreadable > 0 && staged.incomplete_reason().is_none() {
            let mut marker = staged.unreadable_marker(
                artifact.case_id,
                artifact.id,
                "SoftwareInstallIncomplete",
                name,
                "EntriesUnreadable",
                &format!(
                    "{unreadable} of its {} entries are not install dictionaries",
                    entries.len()
                ),
                "so the installs those entries record, if any, could not be read",
            );
            marker.metadata["entries_unreadable"] = json!(unreadable);
            marker.metadata["entries_total"] = json!(entries.len());
            out.push(marker);
        }

        info!("InstallHistoryParser: {} installs from {name}", out.len());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        run_source(Arc::new(ByteSliceDataSource::new(bytes)), name)
    }

    fn run_source(src: Arc<dyn DataSource>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": name }),
        );
        InstallHistoryParser.process(&art).unwrap()
    }

    #[test]
    fn parses_install_history_entries() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
             <plist version=\"1.0\"><array>\
               <dict>\
                 <key>displayName</key><string>macOS 14.5</string>\
                 <key>displayVersion</key><string>14.5</string>\
                 <key>date</key><date>2024-05-15T10:00:00Z</date>\
                 <key>processName</key><string>softwareupdated</string>\
                 <key>packageIdentifiers</key><array><string>com.apple.pkg.update</string></array>\
                 <key>contentType</key><string>com.apple.software</string>\
               </dict>\
               <dict>\
                 <key>displayName</key><string>Some App</string>\
                 <key>processName</key><string>installer</string>\
               </dict>\
             </array></plist>";
        let out = run(xml.as_bytes().to_vec(), "InstallHistory.plist");
        assert_eq!(out.len(), 2);
        let m = &out[0].metadata;
        assert_eq!(m["display_name"], json!("macOS 14.5"));
        assert_eq!(m["process_name"], json!("softwareupdated"));
        assert_eq!(m["package_identifiers"], json!(["com.apple.pkg.update"]));
        assert_eq!(
            m["timestamp_rfc3339"].as_str().unwrap(),
            "2024-05-15T10:00:00+00:00"
        );
        assert!(out[0].metadata["name"]
            .as_str()
            .unwrap()
            .contains("macOS 14.5 14.5"));
    }

    #[test]
    fn ignores_other_plists() {
        let xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><array></array></plist>";
        assert!(run(xml.as_bytes().to_vec(), "SomethingElse.plist").is_empty());
    }

    /// The prefix of a plist will not parse, and returning nothing deleted the
    /// system's software-provenance timeline from the case without a trace.
    #[test]
    fn an_install_history_not_staged_in_full_is_still_reported() {
        let full = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <plist version=\"1.0\"><array><dict>\
               <key>displayName</key><string>macOS 14.5</string>\
             </dict></array></plist>"
            .as_bytes()
            .to_vec();
        let cut = full.len() / 2;
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::cut_to(full, cut));
        let out = run_source(src, "InstallHistory.plist");
        assert_eq!(out.len(), 1, "the file must not vanish");
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("SoftwareInstallIncomplete"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], json!("short_read"));
    }

    /// A file read in full carries no incompleteness stamp.
    #[test]
    fn a_fully_read_install_history_carries_no_incompleteness_stamp() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <plist version=\"1.0\"><array><dict>\
               <key>displayName</key><string>macOS 14.5</string>\
             </dict></array></plist>";
        let out = run(xml.as_bytes().to_vec(), "InstallHistory.plist");
        assert_eq!(out.len(), 1);
        assert!(out[0].metadata.get("content_incomplete").is_none());
    }

    /// HUNT-179. A file staged in full that does not parse returned nothing —
    /// read as "this machine installed nothing".
    #[test]
    fn an_install_history_that_will_not_parse_is_reported() {
        let out = run(
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><array><dict>".to_vec(),
            "InstallHistory.plist",
        );
        assert_eq!(out.len(), 1, "the file must not vanish: {out:?}");
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("SoftwareInstallIncomplete"));
        assert_eq!(m["status"], json!("ParseFailed"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
    }

    /// A root that is not an array is not the layout this reader knows.
    #[test]
    fn an_install_history_whose_root_is_not_an_array_is_reported() {
        let xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
                   <key>displayName</key><string>x</string></dict></plist>";
        let out = run(xml.as_bytes().to_vec(), "InstallHistory.plist");
        assert_eq!(out.len(), 1, "the file must not vanish: {out:?}");
        assert_eq!(out[0].metadata["status"], json!("UnexpectedLayout"));
        assert_eq!(
            out[0].metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
    }

    /// Entries that are not dictionaries cannot be read, and must not be
    /// counted as the absence of installs.
    #[test]
    fn entries_that_are_not_dictionaries_are_reported() {
        let xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><array>\
                   <string>not an install</string><integer>7</integer></array></plist>";
        let out = run(xml.as_bytes().to_vec(), "InstallHistory.plist");
        assert_eq!(out.len(), 1, "the file must not vanish: {out:?}");
        let m = &out[0].metadata;
        assert_eq!(m["status"], json!("EntriesUnreadable"));
        assert_eq!(m["entries_unreadable"], json!(2));
        assert_eq!(m["entries_total"], json!(2));
    }

    /// An empty array is a file that records no installs, and says so itself.
    #[test]
    fn an_empty_install_history_is_not_reported_as_unreadable() {
        let xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><array></array></plist>";
        assert!(run(xml.as_bytes().to_vec(), "InstallHistory.plist").is_empty());
    }

    /// The real file from the Magnet 2021 macOS image (gitignored corpus;
    /// skipped where absent): every entry is a dictionary, and none is
    /// reported unreadable.
    #[test]
    fn the_real_install_history_reads_without_a_marker() {
        let path = home("ctf-evidence/macos2021/tree/Library/Receipts/InstallHistory.plist");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!(
                "skipping: {} not present (gitignored corpus)",
                path.display()
            );
            return;
        };
        let out = run(bytes, "InstallHistory.plist");
        assert!(!out.is_empty());
        assert!(
            out.iter().all(|a| a.metadata["type"] == "SoftwareInstall"),
            "{:?}",
            out.iter().find(|a| a.metadata["type"] != "SoftwareInstall")
        );
    }
}
