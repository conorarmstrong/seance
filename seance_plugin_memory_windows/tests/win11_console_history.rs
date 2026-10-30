//! Console command history (`ROADMAP` §5.3, the `cmdscan` question) graded
//! against a **known answer**: a Windows 11 build 26200 capture taken from the
//! corpus VM while a `cmd.exe` held five commands whose text was recorded
//! beforehand (`~/win11-lab/console/GROUND-TRUTH.txt`), and against the
//! corpus capture, which holds no console host at all.
//!
//! The known-answer capture is 10 GiB and is not in the repository. Put it at
//! `~/win11-lab/console/mem.raw` or name it with `SEANCE_WIN11_CONSOLE_MEMORY`;
//! without it the test says so and returns. The symbol files are those of
//! `win11_kernel_dumps.rs`.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::console_history::{survey_console_history, ConsoleHistoryConfig};
use seance_plugin_memory_windows::process::{list_processes, ProcessListConfig, ProcessSymbols};
use seance_plugin_memory_windows::vad::VadSymbols;
use seance_plugin_memory_windows::WindowsProfile;

fn symbol_dirs() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
        let dirs: Vec<PathBuf> = list
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    vec![
        root.join("test_data/win11_bitlocker/symbols"),
        root.join("reference/volatility3/volatility3/symbols"),
    ]
}

fn open(path: PathBuf) -> WindowsProfile {
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open"));
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).expect("raw"));
    automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery on the capture")
}

fn console_capture() -> Option<PathBuf> {
    let p = match std::env::var("SEANCE_WIN11_CONSOLE_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?).join("win11-lab/console/mem.raw"),
    };
    p.exists().then_some(p)
}

fn corpus_capture() -> Option<PathBuf> {
    let p = std::env::var("SEANCE_WIN11_MEMORY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("test_data/win11_bitlocker/memory-unlocked.raw")
        });
    p.exists().then_some(p)
}

/// The five lines typed into the `cmd.exe`, in order, from GROUND-TRUTH.txt.
const TYPED: [&str; 5] = [
    "echo SEANCE-CMD-ONE-4417",
    "hostname",
    "echo SEANCE-CMD-TWO-9082",
    "dir C:\\Users",
    "echo SEANCE-CMD-THREE-5560",
];

/// **Known answer: the five typed commands come back, in order, from the one
/// console host that served the `cmd.exe`, and from nowhere else.**
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_typed_commands_are_recovered_from_the_console_host_on_the_known_answer_capture() {
    let Some(path) = console_capture() else {
        eprintln!("skipping: put the console capture at ~/win11-lab/console/mem.raw");
        return;
    };
    let profile = open(path);
    let ps = ProcessSymbols::from_profile(&profile).unwrap();
    let vs = VadSymbols::from_profile(&profile).unwrap();
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).unwrap();
    let survey =
        survey_console_history(&profile, &ps, &vs, &list, &ConsoleHistoryConfig::default());
    eprintln!("{}", survey.describe());

    // tasklist at capture: conhost.exe 2028, 5360, 5160 (6136 was the probe running tasklist itself); cmd.exe 5080.
    let mut pids: Vec<u64> = survey.hosts.iter().filter_map(|h| h.pid).collect();
    pids.sort_unstable();
    assert_eq!(pids, [2028, 5160, 5360]);
    assert!(survey
        .clients
        .iter()
        .any(|c| c.name == "cmd.exe" && c.pid == Some(5080)));

    eprintln!(
        "{}",
        serde_json::to_string_pretty(&survey.to_json()).unwrap()
    );
    assert_eq!(survey.histories_total(), 1);
    let host = survey
        .hosts
        .iter()
        .find(|h| h.pid == Some(5160))
        .expect("host 5160");
    let sweep = host.sweep.as_ref().expect("swept");
    assert_eq!(sweep.histories.len(), 1);
    let h = &sweep.histories[0];
    assert_eq!(h.application, "cmd.exe");
    assert_eq!(h.limit, 50);
    let got: Vec<&str> = h
        .commands
        .iter()
        .map(|c| c.text.as_deref().unwrap_or("<unreadable>"))
        .collect();
    assert_eq!(got, TYPED);
    assert!(h.is_complete());
    // Every host swept; the state of the heap is stated, not assumed.
    for h in &survey.hosts {
        assert!(h.sweep.is_some(), "{h:?}");
    }
}

/// **Negative control: the corpus capture holds no console host**, and the
/// stage says that in words rather than returning an empty table.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_corpus_capture_holds_no_console_host_and_the_stage_says_so() {
    let Some(path) = corpus_capture() else {
        eprintln!("skipping: corpus capture not present");
        return;
    };
    let profile = open(path);
    let ps = ProcessSymbols::from_profile(&profile).unwrap();
    let vs = VadSymbols::from_profile(&profile).unwrap();
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).unwrap();
    let survey =
        survey_console_history(&profile, &ps, &vs, &list, &ConsoleHistoryConfig::default());
    eprintln!("{}", survey.describe());
    assert!(survey.hosts.is_empty(), "{:?}", survey.hosts);
    assert!(survey.clients.is_empty(), "{:?}", survey.clients);
    assert_eq!(survey.histories_total(), 0);
    assert!(survey
        .describe()
        .contains("not evidence that nothing was typed"));
}
