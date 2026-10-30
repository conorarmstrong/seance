//! **The in-memory `Triggers` decode graded against the disk's task XML.**
//!
//! The Windows 11 26200 memory capture's in-memory SOFTWARE hive holds 246
//! TaskCache tasks, each with a `Triggers` blob. The same machine's disk,
//! `win11-bitlocker-xts256.raw`, holds `C:\Windows\System32\Tasks\...`: the
//! task scheduler's own XML for the same registrations, `<Triggers>` in plain
//! text. Pairing a memory task with its XML by path gives a known answer per
//! task that neither decoder produced: the XML is parsed by the product's
//! own task parser (`seance_plugin_asep::task_xml`), not by anything here.
//!
//! Release-only: it decrypts a 61 GiB volume and reads a 10 GiB capture.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_bitlocker::{unlock_bitlocker, Credential};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::scheduled_tasks::{survey_scheduled_tasks, TaskValue};
use seance_plugin_mft::MftParser;

/// The BitLocker partition, from the image's GPT (as the chain test has it).
const VOLUME_OFFSET: u64 = 407_896_064;
const VOLUME_LENGTH: u64 = 66_060_288_000;
/// From `~/win11-lab/README.md`.
const RECOVERY_PASSWORD: &str = "633281-498102-426096-319726-225203-245927-337876-444884";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn existing(env: &str, default: &str) -> Option<PathBuf> {
    let p = std::env::var(env)
        .map(PathBuf::from)
        .unwrap_or_else(|_| root().join(default));
    p.exists().then_some(p)
}

/// Every file under `Windows\System32\Tasks` on the unlocked volume, by its
/// path below that directory, as `\Microsoft\Windows\...`.
fn disk_task_xml() -> BTreeMap<String, String> {
    let path = existing(
        "SEANCE_WIN11_BITLOCKER_IMAGE",
        "test_data/win11_bitlocker/win11-bitlocker-xts256.raw",
    )
    .expect("checked by the caller");
    let disk: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open image"));
    let volume: Arc<dyn DataSource> =
        Arc::new(WindowSource::new(disk, VOLUME_OFFSET, VOLUME_LENGTH));
    let unlocked = unlock_bitlocker(volume, &Credential::RecoveryKey(RECOVERY_PASSWORD.into()))
        .expect("the recovery password unlocks the volume");
    let plaintext = unlocked
        .decrypting_source
        .expect("an XTS volume exposes a decrypting source");
    let fs = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(plaintext),
        serde_json::json!({
            "name": "ntfs", "subtype": "ntfs",
            "filesystem_type": "NTFS", "type": "FileSystem",
        }),
    );
    let artifacts = MftParser::new().process(&fs).expect("MFT parse");
    let mut out = BTreeMap::new();
    for artifact in &artifacts {
        let Some(path) = artifact.metadata.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let normal = path.replace('/', "\\");
        let lower = normal.to_ascii_lowercase();
        let Some(at) = lower.find("\\windows\\system32\\tasks\\") else {
            continue;
        };
        if lower.contains(':') && !lower.starts_with("c:") {
            continue; // an alternate data stream
        }
        let Some(data) = &artifact.data else {
            continue;
        };
        let size = data.size();
        if size == 0 || size > 1 << 20 {
            continue;
        }
        let mut bytes = vec![0u8; size as usize];
        if data.read_at(0, &mut bytes).ok() != Some(bytes.len()) {
            continue;
        }
        let Ok(text) = seance_plugin_asep::task_xml::decode(&bytes) else {
            continue;
        };
        let key = normal[at + "\\windows\\system32\\tasks".len()..].to_string();
        out.insert(key, text);
    }
    out
}

/// The XML element a memory trigger kind corresponds to.
fn xml_kinds(kind: &str, schedule: Option<&str>) -> &'static [&'static str] {
    match (kind, schedule) {
        ("time", Some("once")) => &["TimeTrigger"],
        ("time", _) => &["CalendarTrigger"],
        ("boot", _) => &["BootTrigger"],
        ("logon", _) => &["LogonTrigger"],
        ("idle", _) => &["IdleTrigger"],
        ("registration", _) => &["RegistrationTrigger"],
        ("session_state_change", _) => &["SessionStateChangeTrigger"],
        ("event", _) => &["EventTrigger"],
        ("wnf_state_change", _) => &["WnfStateChangeTrigger"],
        _ => &[],
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "decrypts 61 GiB and reads a 10 GiB capture; run with --release"
)]
fn memory_task_triggers_agree_with_the_disk_task_xml_on_the_win11_corpus() {
    let (Some(capture), Some(_)) = (
        existing(
            "SEANCE_WIN11_MEMORY",
            "test_data/win11_bitlocker/memory-unlocked.raw",
        ),
        existing(
            "SEANCE_WIN11_BITLOCKER_IMAGE",
            "test_data/win11_bitlocker/win11-bitlocker-xts256.raw",
        ),
    ) else {
        eprintln!("skipping: the Windows 11 memory capture and disk image are both needed");
        return;
    };
    let source: Arc<dyn DataSource> = Arc::new(FileDataSource::new(capture).expect("open"));
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).expect("raw"));
    let symbols = vec![
        root().join("test_data/win11_bitlocker/symbols"),
        root().join("reference/volatility3/volatility3/symbols"),
    ];
    let profile =
        automagic::discover(physical, &symbols, &DiscoveryOptions::default()).expect("discovery");
    let memory = survey_scheduled_tasks(&profile);
    let disk = disk_task_xml();
    eprintln!("{} task XML files on disk", disk.len());
    for (k, _) in disk.iter().take(5) {
        eprintln!("  disk: {k}");
    }

    let mut graded = 0usize;
    let mut no_xml = Vec::new();
    let mut disagreements = Vec::new();
    for task in &memory.tasks {
        let TaskValue::Text(path) = &task.path else {
            continue;
        };
        let Some(triggers) = task.triggers.as_ref().filter(|t| t.is_whole()) else {
            continue;
        };
        let Some(xml) = disk
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(path))
            .map(|(_, v)| v)
        else {
            no_xml.push(path.clone());
            continue;
        };
        let parsed = seance_plugin_asep::task_xml::parse(xml).expect("the XML parses");
        graded += 1;
        let mut problems = Vec::new();
        if parsed.triggers.len() != triggers.triggers.len() {
            problems.push(format!(
                "{} trigger(s) in memory, {} in the XML",
                triggers.triggers.len(),
                parsed.triggers.len()
            ));
        }
        for (m, x) in triggers.triggers.iter().zip(&parsed.triggers) {
            let schedule = match &m.kind {
                seance_plugin_memory_windows::scheduled_tasks::TriggerKind::Time {
                    schedule,
                    ..
                } => Some(schedule.as_str()),
                _ => None,
            };
            if !xml_kinds(m.kind.name(), schedule).contains(&x.kind.as_str()) {
                problems.push(format!("kind {} vs {}", m.kind.name(), x.kind));
            }
            let m_start = m.start.as_ref().map(|s| s.text.clone());
            let x_start = x.start.clone();
            if m_start.as_deref().map(|s| s.trim_end_matches('Z'))
                != x_start.as_deref().map(|s| s.trim_end_matches('Z'))
            {
                problems.push(format!("start {m_start:?} vs {x_start:?}"));
            }
            if m.enabled != x.enabled.unwrap_or(true) {
                problems.push(format!("enabled {} vs {:?}", m.enabled, x.enabled));
            }
        }
        if !problems.is_empty() {
            disagreements.push((path.clone(), problems));
        }
    }
    eprintln!("graded {graded}; no XML for {}: {no_xml:?}", no_xml.len());
    for (path, problems) in &disagreements {
        eprintln!("  DISAGREE {path}: {problems:?}");
    }
    assert!(disagreements.is_empty(), "{} disagree", disagreements.len());
    assert!(graded > 0);
}
