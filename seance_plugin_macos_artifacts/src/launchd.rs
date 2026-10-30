//! launchd persistence — `LaunchAgents` / `LaunchDaemons` job plists.
//!
//! launchd is the primary macOS persistence mechanism: a job plist in one of the
//! Launch{Agents,Daemons} directories tells launchd what to run and when. This
//! is the macOS equivalent of the Windows ASEP sweep — "what will this machine
//! execute at boot or login, and why?" — for the most common location.
//!
//! Self-selection is by *content*, not path: any `.plist` that carries a `Label`
//! and a `Program`/`ProgramArguments` is a launchd job. The domain (user vs
//! system, Apple-shipped vs third-party) is refined from the path when the
//! ingest record carries one.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Value};
use tracing::info;

use crate::{basename_lower, Staged};

/// Largest job plist read into memory.
///
/// launchd jobs are tiny, which is exactly why a large one matters: a job
/// padded past a small cap was never read, and the cap became the whole answer
/// for it (HUNT-179). 64 MiB is the ceiling the other plist readers in this
/// crate use for files that are kilobytes in practice.
const MAX_PLIST_BYTES: u64 = 64 * 1024 * 1024;

/// Emits one `Persistence` record per launchd job plist.
pub struct LaunchdPersistenceParser;

/// Classify the autostart domain from the file's path, if the record has one.
fn domain_from_path(path: &str) -> &'static str {
    let p = path.to_lowercase();
    let apple = p.contains("/system/library/");
    if p.contains("launchdaemons") {
        if apple {
            "system_daemon_apple"
        } else {
            "system_daemon"
        }
    } else if p.contains("launchagents") {
        if apple {
            "agent_apple"
        } else if p.starts_with("/users/") || p.contains("/users/") {
            "user_agent"
        } else {
            "system_agent"
        }
    } else {
        "unknown"
    }
}

/// A plist `Value` array of strings joined into a command line.
fn program_arguments(v: &plist::Value) -> Option<Vec<String>> {
    v.as_array().map(|arr| {
        arr.iter()
            .filter_map(|e| e.as_string().map(|s| s.to_string()))
            .collect()
    })
}

impl ForensicsModule for LaunchdPersistenceParser {
    fn id(&self) -> &str {
        "macos.launchd_persistence"
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
        if !basename_lower(name).ends_with(".plist") {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("parent_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let domain = domain_from_path(path);

        // Read the whole plist.
        let staged = Staged::read(ds.as_ref(), MAX_PLIST_BYTES);

        // Self-selection is by content, so a plist that was not staged in full
        // cannot be ruled in OR out: the Label and ProgramArguments may sit
        // past the cut. Silence would state the file declared no autostart —
        // the one answer nothing in the bytes supports.
        //
        // Except where the path already rules it out. A plist whose recorded
        // location is outside every Launch{Agents,Daemons} directory is not a
        // job launchd loads at boot or login, and a marker for each such file
        // that was large or short was one for every big preference file on the
        // machine (HUNT-179). Where no path was recorded the marker stays: the
        // location cannot rule it out.
        let undecided = if !path.is_empty() && domain == "unknown" {
            None
        } else {
            staged.incomplete_marker(
                artifact.case_id,
                artifact.id,
                "PersistenceIncomplete",
                name,
                "so whether it declares a launchd job could not be determined",
            )
        };

        let value = match plist::from_bytes::<plist::Value>(&staged.bytes) {
            Ok(v) => v,
            Err(_) => return Ok(undecided.into_iter().collect()), // not a plist -> not ours
        };
        let Some(dict) = value.as_dictionary() else {
            return Ok(undecided.into_iter().collect());
        };

        // A launchd job is a plist with a Label and something to run.
        let label = dict.get("Label").and_then(|v| v.as_string());
        let has_program = dict.contains_key("Program") || dict.contains_key("ProgramArguments");
        let (Some(label), true) = (label, has_program) else {
            return Ok(undecided.into_iter().collect());
        };

        let program = dict.get("Program").and_then(|v| v.as_string());
        let program_args = dict.get("ProgramArguments").and_then(program_arguments);
        let run_at_load = dict.get("RunAtLoad").and_then(|v| v.as_boolean());
        let start_interval = dict
            .get("StartInterval")
            .and_then(|v| v.as_signed_integer());
        let has_calendar = dict.contains_key("StartCalendarInterval");
        let watch_paths = dict.get("WatchPaths").and_then(program_arguments);
        let queue_dirs = dict.get("QueueDirectories").and_then(program_arguments);
        let keep_alive = dict.get("KeepAlive").map(|v| match v {
            plist::Value::Boolean(b) => json!(b),
            _ => json!("conditional"),
        });
        let disabled = dict.get("Disabled").and_then(|v| v.as_boolean());

        // A plain sentence describing what runs and when — the ASEP-style "why".
        let target = program
            .map(|s| s.to_string())
            .or_else(|| program_args.as_ref().and_then(|a| a.first().cloned()))
            .unwrap_or_else(|| "(no program)".to_string());
        let trigger = if run_at_load == Some(true) {
            "at load (login/boot)".to_string()
        } else if let Some(secs) = start_interval {
            format!("every {secs}s")
        } else if has_calendar {
            "on a calendar schedule".to_string()
        } else if watch_paths.is_some() {
            "when watched paths change".to_string()
        } else if keep_alive.is_some() {
            "kept alive".to_string()
        } else {
            "on demand".to_string()
        };

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("Persistence"));
        meta.insert("subtype".into(), json!("launchd"));
        meta.insert("mechanism".into(), json!("launchd"));
        meta.insert("label".into(), json!(label));
        meta.insert("domain".into(), json!(domain));
        meta.insert("program".into(), json!(program));
        meta.insert("program_arguments".into(), json!(program_args));
        meta.insert("run_at_load".into(), json!(run_at_load));
        meta.insert("start_interval_seconds".into(), json!(start_interval));
        meta.insert("start_calendar_interval".into(), json!(has_calendar));
        meta.insert("watch_paths".into(), json!(watch_paths));
        meta.insert("queue_directories".into(), json!(queue_dirs));
        meta.insert("keep_alive".into(), keep_alive.unwrap_or(Value::Null));
        meta.insert("disabled".into(), json!(disabled));
        meta.insert("plist_path".into(), json!(path));
        meta.insert(
            "name".into(),
            json!(format!("launchd: {label} runs {target} {trigger}")),
        );
        // A job read out of a partial plist may be missing keys that change
        // what it does — a Disabled flag, a second trigger — so it must not
        // read as a full account of the job.
        staged.stamp(name, &mut meta);

        info!("LaunchdPersistenceParser: {label} ({domain})");
        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            meta.into(),
        )
        .with_parent(artifact.id)
        .with_subtype("launchd")])
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

    fn plist_xml(body: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>{body}</dict></plist>"
        )
        .into_bytes()
    }

    fn run(bytes: Vec<u8>, name: &str, path: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name, "path": path }),
        );
        LaunchdPersistenceParser.process(&art).unwrap()
    }

    #[test]
    fn parses_a_run_at_load_daemon() {
        let body = "<key>Label</key><string>com.evil.backdoor</string>\
             <key>ProgramArguments</key><array><string>/tmp/evil</string><string>-x</string></array>\
             <key>RunAtLoad</key><true/>";
        let out = run(
            plist_xml(body),
            "com.evil.backdoor.plist",
            "/Library/LaunchDaemons/com.evil.backdoor.plist",
        );
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("Persistence"));
        assert_eq!(m["label"], json!("com.evil.backdoor"));
        assert_eq!(m["domain"], json!("system_daemon"));
        assert_eq!(m["run_at_load"], json!(true));
        assert_eq!(m["program_arguments"], json!(["/tmp/evil", "-x"]));
        assert!(m["name"].as_str().unwrap().contains("at load"));
    }

    #[test]
    fn parses_a_start_interval_agent_and_classifies_apple_domain() {
        let body = "<key>Label</key><string>com.apple.periodic</string>\
             <key>Program</key><string>/usr/sbin/periodic</string>\
             <key>StartInterval</key><integer>3600</integer>";
        let out = run(
            plist_xml(body),
            "com.apple.periodic.plist",
            "/System/Library/LaunchAgents/com.apple.periodic.plist",
        );
        let m = &out[0].metadata;
        assert_eq!(m["domain"], json!("agent_apple"));
        assert_eq!(m["start_interval_seconds"], json!(3600));
        assert!(m["name"].as_str().unwrap().contains("every 3600s"));
    }

    #[test]
    fn a_plist_without_a_program_is_not_a_job() {
        let body = "<key>Label</key><string>x</string><key>Foo</key><string>bar</string>";
        assert!(run(plist_xml(body), "x.plist", "/tmp/x.plist").is_empty());
    }

    #[test]
    fn non_plist_content_is_ignored() {
        assert!(run(b"not a plist".to_vec(), "a.plist", "/tmp/a.plist").is_empty());
    }

    /// A LaunchDaemon whose prefix will not parse used to disappear entirely.
    /// Silence there reads as "this machine had no such autostart", which is
    /// the answer an examiner must never be given from bytes never seen.
    #[test]
    fn a_job_plist_not_staged_in_full_is_still_reported() {
        let full = plist_xml(
            "<key>Label</key><string>com.evil.backdoor</string>\
             <key>ProgramArguments</key><array><string>/tmp/evil</string></array>\
             <key>RunAtLoad</key><true/>",
        );
        let cut = full.len() / 2;
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::cut_to(full, cut));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "com.evil.backdoor.plist",
                    "path": "/Library/LaunchDaemons/com.evil.backdoor.plist" }),
        );
        let out = LaunchdPersistenceParser.process(&art).unwrap();
        assert_eq!(out.len(), 1, "the plist must not vanish");
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("PersistenceIncomplete"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], json!("short_read"));
    }

    /// A job read in full carries no incompleteness stamp.
    #[test]
    fn a_fully_read_job_plist_carries_no_incompleteness_stamp() {
        let body = "<key>Label</key><string>com.evil.backdoor</string>\
             <key>Program</key><string>/tmp/evil</string>";
        let out = run(plist_xml(body), "x.plist", "/Library/LaunchDaemons/x.plist");
        assert_eq!(out.len(), 1);
        assert!(out[0].metadata.get("content_incomplete").is_none());
    }

    /// HUNT-179. Any `.plist` over the old 4 MiB cap was staged short, its
    /// prefix would not parse, and the answer was `NotStagedInFull` — for a
    /// launchd job padded past the cap, the cap was the whole answer.
    #[test]
    fn a_launchd_job_larger_than_four_mib_is_read() {
        let body = format!(
            "<key>Label</key><string>com.evil.padded</string>\
             <key>ProgramArguments</key><array><string>/tmp/evil</string></array>\
             <key>RunAtLoad</key><true/>\
             <key>Padding</key><string>{}</string>",
            "A".repeat(5 * 1024 * 1024)
        );
        let out = run(
            plist_xml(&body),
            "com.evil.padded.plist",
            "/Library/LaunchDaemons/com.evil.padded.plist",
        );
        assert_eq!(
            out.len(),
            1,
            "{:?}",
            out.first().map(|a| &a.metadata["status"])
        );
        assert_eq!(out[0].metadata["type"], json!("Persistence"));
        assert_eq!(out[0].metadata["label"], json!("com.evil.padded"));
    }

    /// A large plist outside every launchd location was a `NotStagedInFull`
    /// marker too — one for every big preference file on the machine.
    #[test]
    fn a_plist_over_the_cap_outside_launchd_locations_leaves_no_marker() {
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
            plist_xml("<key>Foo</key><string>bar</string>"),
            MAX_PLIST_BYTES + 1,
        ));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "com.apple.huge.plist",
                    "path": "/Users/x/Library/Preferences/com.apple.huge.plist" }),
        );
        let out = LaunchdPersistenceParser.process(&art).unwrap();
        assert!(out.is_empty(), "not a launchd location: {out:?}");
    }

    /// Past the cap, in a launchd location, the marker is still the answer.
    #[test]
    fn a_plist_over_the_cap_in_a_launchd_location_is_reported() {
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
            plist_xml("<key>Label</key><string>x</string>"),
            MAX_PLIST_BYTES + 1,
        ));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "x.plist", "path": "/Library/LaunchAgents/x.plist" }),
        );
        let out = LaunchdPersistenceParser.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["type"], json!("PersistenceIncomplete"));
        assert_eq!(
            out[0].metadata["content_incomplete_reason"],
            json!("cap_reached")
        );
    }

    /// The Magnet 2021 macOS image's `/System/Library/LaunchDaemons`
    /// (gitignored corpus; skipped where absent): every job reads in full at
    /// the raised cap, and no file leaves a marker.
    #[test]
    fn the_real_launch_daemons_read_without_a_marker() {
        let dir = home("ctf-evidence/macos2021/tree/System/Library/LaunchDaemons");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            eprintln!(
                "skipping: {} not present (gitignored corpus)",
                dir.display()
            );
            return;
        };
        let mut jobs = 0;
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            let path = format!("/System/Library/LaunchDaemons/{name}");
            for a in run(bytes, &name, &path) {
                assert_eq!(
                    a.metadata["type"],
                    json!("Persistence"),
                    "{name}: {}",
                    a.metadata
                );
                jobs += 1;
            }
        }
        assert!(jobs > 300, "only {jobs} jobs read");
    }
}
