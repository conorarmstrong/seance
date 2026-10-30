//! Outgoing RDP and BAM/DAM against real hives — the known answers `HUNT-127`
//! asked for (`RDP-1` and `BAM-1` in `documentation/VALIDATION.md`).
//!
//! Each hive is handed to [`crate::RegistryParser::process`] the way the NTFS
//! pipeline hands it over: a `FileEntry` artifact whose data source is the
//! file, named by its file name. The expected values were read off the same
//! files by an independent reader — a stand-alone Python `regf` walker that
//! shares no code with `seance_hive` — and every field below agreed.
//!
//! None of these hives is in the repository: they come from DFIR Madness Case
//! 001, NIST CFReDS "Windows Registry" (winreg), BelkaCTF 6 and the LoneWolf
//! scenario, whose redistribution terms this tree has not settled. Each is
//! named by its own variable, which **is** the path; an unset variable skips
//! loudly and a set-but-missing path fails (`seance_core::test_support::corpus`).
//!
//! | variable | file |
//! |---|---|
//! | `SEANCE_RDP_DC01_NTUSER` | Case 001 DC01 `Users/Administrator/NTUSER.DAT` (inode 84874) |
//! | `SEANCE_RDP_CFREDS_WIN7_NTUSER` | winreg `Win_7_IE09_(CFReDS)/…/Users/CFTT/NTUSER.DAT` |
//! | `SEANCE_RDP_CFREDS_WIN10_NTUSER` | winreg `Win10_10586_IE11+Edge_(CFReDS)/…/Users/CFTT/NTUSER.DAT` |
//! | `SEANCE_BAM_CASE001_DESKTOP_SYSTEM` | Case 001 desktop `Windows/System32/config/SYSTEM` |
//! | `SEANCE_BAM_BELKA6_SYSTEM` | BelkaCTF 6 `Windows/System32/config/SYSTEM` |
//! | `SEANCE_BAM_LONEWOLF_SYSTEM` | LoneWolf `Windows/System32/config/SYSTEM` |

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Every record `process()` emits for the hive the variable names.
fn records(var: &str, name: &str) -> Option<Vec<Value>> {
    let path = corpus::path(var)?;
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path.clone()).expect("open the corpus hive read-only"));
    let art = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({ "name": name, "path": path.display().to_string() }),
    );
    Some(
        crate::RegistryParser
            .process(&art)
            .expect("the parser runs")
            .into_iter()
            .map(|a| a.metadata)
            .collect(),
    )
}

fn of_type<'a>(all: &'a [Value], ty: &str) -> Vec<&'a Value> {
    all.iter().filter(|r| r["type"] == ty).collect()
}

fn starts(v: &Value, prefix: &str) -> bool {
    v.as_str().is_some_and(|s| s.starts_with(prefix))
}

// --- Outgoing RDP -------------------------------------------------------------

/// DC01's Administrator connected out to the desktop: `Default\MRU0` and a
/// `Servers\DESKTOP-SDN1RPT` key with its `UsernameHint`, each with its own
/// key time. Read independently: MRU0 = `DESKTOP-SDN1RPT` under a key written
/// at FILETIME 132449611339934009, `UsernameHint` = `C137\Administrator` under a
/// key written at 132449601855804446. The hive is dirty and its logs were not
/// taken, so both readers read the primary file; the record says so.
///
/// Since `HUNT-243` the two keys are one destination record, joined by host,
/// carrying both keys' paths and times, each time labelled with its key.
#[test]
fn rdp_dc01_administrator_names_the_desktop_it_connected_to() {
    let Some(all) = records("SEANCE_RDP_DC01_NTUSER", "NTUSER.DAT") else {
        return;
    };
    let rdp = of_type(&all, "RdpDestinationEntry");
    assert_eq!(
        rdp.len(),
        1,
        "one destination, in the MRU and in Servers: {rdp:#?}"
    );
    let r = rdp[0];
    assert_eq!(r["host"], "DESKTOP-SDN1RPT");
    assert_eq!(r["mru_position"], 0);
    assert_eq!(r["mru_positions"], serde_json::json!([0]));
    assert_eq!(r["username_hint"], r"C137\Administrator");
    assert_eq!(r["in_mru_list"], true);
    assert_eq!(r["in_servers_key"], true);

    assert!(starts(&r["mru_key_path"], "CsiTool-CreateHive-"));
    assert!(r["mru_key_path"]
        .as_str()
        .unwrap()
        .ends_with(r"\Software\Microsoft\Terminal Server Client\Default"));
    assert!(
        starts(&r["mru_key_last_written"], "2020-09-19T03:52:13.9934009"),
        "{}",
        r["mru_key_last_written"]
    );
    assert_eq!(
        r["mru_key_last_written_scope"],
        "the Terminal Server Client\\Default key, which holds every MRU destination; not \
         this destination"
    );

    assert!(r["servers_key_path"]
        .as_str()
        .unwrap()
        .ends_with(r"\Software\Microsoft\Terminal Server Client\Servers\DESKTOP-SDN1RPT"));
    assert!(
        starts(
            &r["servers_key_last_written"],
            "2020-09-19T03:36:25.5804446"
        ),
        "{}",
        r["servers_key_last_written"]
    );
    assert_eq!(
        r["servers_key_last_written_scope"],
        "this destination's own Servers subkey"
    );

    assert_eq!(r["connection_succeeded"], false);
    // HUNT-245: no port is stored, so the destination is the host itself.
    assert_eq!(r["destination"], "desktop-sdn1rpt");
    assert_eq!(r["ip_to_name_join_attempted"], false);
    assert_eq!(r["replay"]["hive_dirty"], true);
    assert_eq!(r["replay"]["recovered"], false);
}

/// The CFReDS winreg `CFTT` hives: a `Servers\10.11.11.127` key with a
/// `UsernameHint` and a `Default` key holding **no** `MRUn` — so exactly one
/// record, a Servers-only destination, and no invented MRU entry.
#[test]
fn rdp_cfreds_winreg_hives_hold_one_server_and_no_mru() {
    for (var, hint, written) in [
        (
            "SEANCE_RDP_CFREDS_WIN7_NTUSER",
            r"MSEDGEWIN10\cfreds-server1",
            "2016-11-03T15:43:19.9287109",
        ),
        (
            "SEANCE_RDP_CFREDS_WIN10_NTUSER",
            "cfreds-server1",
            "2016-11-13T01:47:09.4946052",
        ),
    ] {
        let Some(all) = records(var, "NTUSER.DAT") else {
            continue;
        };
        let rdp = of_type(&all, "RdpDestinationEntry");
        assert_eq!(rdp.len(), 1, "{var}: {rdp:#?}");
        let r = rdp[0];
        assert_eq!(r["host"], "10.11.11.127", "{var}");
        // HUNT-245: an IP address is not resolved to a name, and the record
        // says so rather than leaving the absence of a join unexplained.
        assert_eq!(r["destination"], "10.11.11.127", "{var}");
        assert_eq!(r["ip_to_name_join_attempted"], false, "{var}");
        assert!(r["mru_position"].is_null(), "{var}");
        assert_eq!(r["in_mru_list"], false, "{var}");
        assert!(r["mru_key_last_written"].is_null(), "{var}");
        assert_eq!(r["in_servers_key"], true, "{var}");
        assert_eq!(r["username_hint"], hint, "{var}");
        assert!(
            starts(&r["servers_key_last_written"], written),
            "{var}: {}",
            r["servers_key_last_written"]
        );
        assert_eq!(r["replay"]["hive_dirty"], false, "{var}");
    }
}

// --- BAM ----------------------------------------------------------------------

/// Per SID: executions, as the independent reader counted them (values other
/// than `Version` and `SequenceNumber`).
fn executions_by_sid(all: &[Value]) -> BTreeMap<String, u64> {
    of_type(all, "BamCoverage")
        .into_iter()
        .filter(|c| c["sid"].is_string())
        .map(|c| {
            (
                c["sid"].as_str().unwrap().to_string(),
                c["executions"].as_u64().unwrap(),
            )
        })
        .collect()
}

/// What every BAM hive here shares: `ControlSet001` is the only control set
/// and `Select\Current = 1`, every value is the documented 24 bytes, and a
/// `dam` key exists with no `UserSettings` beneath it.
fn assert_common(all: &[Value], layout: &str, entries: usize) {
    let bam = of_type(all, "BamEntry");
    assert_eq!(bam.len(), entries);
    for e in &bam {
        assert_eq!(e["decode_status"], "decoded", "{e}");
        assert_eq!(e["entry_length"], 24, "{e}");
        assert_eq!(e["service"], "bam", "{e}");
        assert_eq!(e["control_set"], "ControlSet001", "{e}");
        assert_eq!(e["layout"], layout, "{e}");
        assert_eq!(
            e["is_current_control_set"], true,
            "Select\\Current is 1, so ControlSet001 is the booted set: {e}"
        );
        let kind = e["target_kind"].as_str().unwrap();
        assert!(kind == "nt_device_path" || kind == "app_identity", "{e}");
    }
    let dam: Vec<_> = of_type(all, "BamCoverage")
        .into_iter()
        .filter(|c| c["service"] == "dam")
        .collect();
    assert_eq!(dam.len(), 1);
    assert_eq!(dam[0]["service_key_present"], true);
    assert_eq!(dam[0]["usersettings_present"], false);
}

fn find_entry<'a>(all: &'a [Value], sid: &str, target: &str, when: &str) -> &'a Value {
    of_type(all, "BamEntry")
        .into_iter()
        .find(|e| e["sid"] == sid && e["target"] == target && starts(&e["last_executed"], when))
        .unwrap_or_else(|| panic!("{target} for {sid} at {when} must be decoded"))
}

/// DFIR Madness Case 001's desktop: nine SIDs, 62 executions under
/// `bam\State\UserSettings`. The domain Administrator (`…-500`) ran `cmd.exe`
/// at 03:44:45 on 2020-09-19.
#[test]
fn bam_case001_desktop_decodes_nine_sids() {
    let Some(all) = records("SEANCE_BAM_CASE001_DESKTOP_SYSTEM", "SYSTEM") else {
        return;
    };
    let d = "S-1-5-21-2232410529-1445159330-2725690660";
    let l = "S-1-5-21-41211245-796119838-3940169921";
    let expected: BTreeMap<String, u64> = [
        ("S-1-5-18".to_string(), 1),
        (format!("{d}-1106"), 12),
        (format!("{d}-1108"), 13),
        (format!("{d}-500"), 13),
        (format!("{l}-1000"), 4),
        (format!("{l}-1001"), 16),
        ("S-1-5-90-0-1".to_string(), 1),
        ("S-1-5-90-0-2".to_string(), 1),
        ("S-1-5-90-0-3".to_string(), 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(executions_by_sid(&all), expected);
    assert_common(&all, "state_usersettings", 62);
    let e = find_entry(
        &all,
        &format!("{d}-500"),
        r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
        "2020-09-19T03:44:45.973107",
    );
    assert_eq!(e["target_kind"], "nt_device_path");
    assert_eq!(e["trailing_bytes_hex"], "00000000000000000000000002000000");
    assert!(starts(
        &e["key_last_written"],
        "2020-09-19T03:52:13.4427614"
    ));
}

/// BelkaCTF 6: three SIDs, 27 executions; the user ran `bdeunlock.exe` at
/// 22:57:50 on 2024-12-24.
#[test]
fn bam_belka6_decodes_three_sids() {
    let Some(all) = records("SEANCE_BAM_BELKA6_SYSTEM", "SYSTEM") else {
        return;
    };
    let u = "S-1-5-21-1548112901-4150280657-3748420248-1000";
    let expected: BTreeMap<String, u64> = [
        ("S-1-5-18".to_string(), 2),
        (u.to_string(), 24),
        ("S-1-5-90-0-1".to_string(), 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(executions_by_sid(&all), expected);
    assert_common(&all, "state_usersettings", 27);
    find_entry(
        &all,
        u,
        r"\Device\HarddiskVolume3\Windows\System32\bdeunlock.exe",
        "2024-12-24T22:57:50.651968",
    );
}

/// LoneWolf (Windows 10 1803, the older `bam\UserSettings` layout): four SIDs,
/// two of them with no executions, 28 in all — and `cmd.exe` at the time the
/// synthetic fixture in `bam_tests.rs` was derived from, now read off the hive.
#[test]
fn bam_lonewolf_decodes_the_pre_1809_layout() {
    let Some(all) = records("SEANCE_BAM_LONEWOLF_SYSTEM", "SYSTEM") else {
        return;
    };
    let u = "S-1-5-21-2734969515-1644526556-1039763013";
    let expected: BTreeMap<String, u64> = [
        (format!("{u}-1000"), 2),
        (format!("{u}-1001"), 26),
        ("S-1-5-90-0-1".to_string(), 0),
        ("S-1-5-90-0-2".to_string(), 0),
    ]
    .into_iter()
    .collect();
    assert_eq!(executions_by_sid(&all), expected);
    assert_common(&all, "usersettings", 28);
    find_entry(
        &all,
        &format!("{u}-1001"),
        r"\Device\HarddiskVolume4\Windows\System32\cmd.exe",
        "2018-04-05T02:05:02.333385",
    );
}
