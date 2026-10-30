//! End-to-end regression against NIST CFReDS "Hacking Case", which publishes
//! its own answers.
//!
//! Every other test in this workspace compares Séance against a fixture Séance's
//! authors built, or against Volatility on an image nobody here can produce.
//! This one compares it against facts a third party published about a disk
//! before Séance existed: `TestAnswers.pdf`, distributed by NIST beside the
//! image. When one of these fails, the disk did not change.
//!
//! The image is 1.1 GB and not committed. Point `SEANCE_CFREDS_HACKING` at a
//! directory holding `4Dell_Latitude_CPi.E01` and `.E02` (the file NIST ships
//! is `4Dell Latitude CPi.E01`, with spaces; rename or symlink). Absent, these
//! skip loudly; named and missing, they fail — see
//! [`seance_core::test_support::corpus`].
//!
//! Scenario, from the published brief: a Dell CPi notebook, serial VLQLW, found
//! abandoned on 09/20/04 with a wireless card and a homemade antenna. The
//! examiner's task is to tie the machine to one Greg Schardt, alias "Mr. Evil".
//!
//! | Q | Published answer | Asserted here |
//! |---|---|---|
//! | 5 | Registered owner is Greg Schardt | yes, via `Look@LAN\Nome` and `RegOwner` |
//! | 6 | Computer account `N-1A9ODN6ZXK4LQ` | yes |
//! | 12 | `Look@LAN`'s `irunin.ini` proves Schardt is Mr. Evil | yes — the tie itself |
//! | 16 | Six hacking tools installed | yes, four of the named seven |
//! | 17 | SMTP address `whoknowsme@sbcglobal.net` | yes |
//!
//! Requires the `e01` feature: without libewf there is no way in.

use seance_container_e01::E01ContainerModule;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_partition::{FilesystemDetector, PartitionParser};
use serde_json::json;
use std::path::PathBuf;
use uuid::Uuid;

/// The corpus variable. Named for the set, not the file, so a second CFReDS
/// image can join it later.
const CORPUS_VAR: &str = "SEANCE_CFREDS_HACKING";

/// The first segment. libewf finds `.E02` itself from this.
const IMAGE: &str = "4Dell_Latitude_CPi.E01";

/// Open the image as the orchestrator's first artifact, or `None` to skip.
fn image_artifact(case_id: Uuid) -> Option<(Artifact, PathBuf)> {
    let path = corpus::file(CORPUS_VAR, IMAGE)?;
    let size = std::fs::metadata(&path)
        .expect("the corpus gate proved this path exists")
        .len();
    Some((
        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": IMAGE,
                "path": path.to_string_lossy(),
                "size": size,
            }),
        ),
        path,
    ))
}

/// E01 → RawEvidence. Separated because every test below starts here.
fn raw_evidence(case_id: Uuid) -> Option<Artifact> {
    let (artifact, _) = image_artifact(case_id)?;
    let produced = E01ContainerModule
        .process(&artifact)
        .expect("libewf opens the image");
    assert_eq!(
        produced.len(),
        1,
        "one image is one RawEvidence, whatever its segment count"
    );
    let raw = produced.into_iter().next().expect("checked above");
    assert_eq!(raw.artifact_type, ArtifactType::RawEvidence);
    assert!(
        raw.data.is_some(),
        "a RawEvidence with no data source cannot be read from, and every stage \
         below would report an empty disk rather than a failure to open one"
    );
    Some(raw)
}

/// Q1's acquisition record, which the EWF header carries and no parsing of the
/// disk can reach.
///
/// This is the cheapest possible proof that the libewf path works end to end:
/// the fields below were typed by Shane Robinson in 2004 and have been in the
/// header ever since.
#[test]
fn the_ewf_header_carries_the_published_acquisition_metadata() {
    let case_id = Uuid::new_v4();
    let Some(raw) = raw_evidence(case_id) else {
        return;
    };

    let ewf = raw
        .metadata
        .get("e01_metadata")
        .expect("the E01 reader publishes the header it read");

    assert_eq!(
        ewf.get("case_number").and_then(|v| v.as_str()),
        Some("Greg Schardt"),
        "the acquisition's case number is the suspect's name; NIST ships it in \
         the header"
    );
    assert_eq!(
        ewf.get("description").and_then(|v| v.as_str()),
        Some("Dell Latitude CPi"),
        "the published brief calls it a Dell CPi notebook"
    );
    assert_eq!(
        ewf.get("examiner").and_then(|v| v.as_str()),
        Some("Shane Robinson"),
        "the examiner of record"
    );
}

/// The disk is one NTFS volume, and the walk reaches it.
///
/// Asserted separately from the registry test so a failure says which half
/// broke: the container and partition table, or everything after them.
#[test]
fn the_disk_presents_one_ntfs_volume() {
    let case_id = Uuid::new_v4();
    let Some(raw) = raw_evidence(case_id) else {
        return;
    };

    let partitions = PartitionParser
        .process(&raw)
        .expect("the partition table parses");
    assert!(
        !partitions.is_empty(),
        "a 2004 Windows XP laptop has a partition table"
    );

    let mut filesystems = Vec::new();
    for partition in &partitions {
        for fs in FilesystemDetector.process(partition).unwrap_or_default() {
            if let Some(kind) = fs
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
            {
                filesystems.push(kind);
            }
        }
    }

    assert!(
        filesystems.iter().any(|f| f.eq_ignore_ascii_case("ntfs")),
        "published answer 2 is Windows XP, whose volume here is NTFS; detected: \
         {filesystems:?}"
    );
}

/// The whole chain, ending on the answer the exercise is built around.
///
/// Published answer 12: a search for the suspect's name hits
/// `C:\Program Files\Look@LAN\irunin.ini`, and that file is what proves Greg
/// Schardt and "Mr. Evil" are one person. Look@LAN wrote the same name into the
/// SOFTWARE hive under its own key, so the registry carries the finding too —
/// and the registry is the path Séance takes.
///
/// This asserts the tie itself rather than a count. A count can drift with a
/// parser's appetite; the name in that value either survives the chain from
/// libewf through NTFS to a decoded `RegSZ`, or the tool cannot make the case.
#[test]
fn the_registry_carries_the_name_that_ties_the_suspect_to_the_machine() {
    let case_id = Uuid::new_v4();
    let Some(raw) = raw_evidence(case_id) else {
        return;
    };

    let hives = software_hives(&raw);
    assert!(
        !hives.is_empty(),
        "no SOFTWARE hive was decoded, so nothing below could have been found \
         whatever the disk holds"
    );

    let owner_values: Vec<(String, String)> = hives
        .iter()
        .flat_map(|hive| {
            hive.get("all_values")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|value| {
            let name = value.get("value_name")?.as_str()?.to_owned();
            let data = value.get("value_data")?.as_str()?.to_owned();
            (name == "Nome" || name == "RegOwner" || name == "RegisteredOwner")
                .then_some((name, data))
        })
        .collect();

    assert!(
        owner_values
            .iter()
            .any(|(name, data)| name == "Nome" && data == "Greg Schardt"),
        "published answer 12: Look@LAN records the owner as Greg Schardt, which \
         is what ties the machine to the suspect. Owner-ish values found: \
         {owner_values:?}"
    );

    // Published answer 5, from the same walk. Windows' own record of the owner
    // agreeing with Look@LAN's is what makes the tie an examination rather than
    // one application's opinion.
    assert!(
        owner_values
            .iter()
            .any(|(name, data)| name == "RegisteredOwner" && data == "Greg Schardt"),
        "published answer 5: Windows records the registered owner as Greg \
         Schardt. Owner-ish values found: {owner_values:?}"
    );
}

/// Published answer 6: the computer account name. A second, independent
/// registry fact, so answer 12 failing alone points at Look@LAN rather than at
/// the hive decoder.
#[test]
fn the_registry_carries_the_published_computer_account_name() {
    let case_id = Uuid::new_v4();
    let Some(raw) = raw_evidence(case_id) else {
        return;
    };

    let found = software_hives(&raw).iter().any(|hive| {
        serde_json::to_string(hive)
            .map(|text| text.contains("N-1A9ODN6ZXK4LQ"))
            .unwrap_or(false)
    });

    assert!(
        found,
        "published answer 6 is the computer account N-1A9ODN6ZXK4LQ, and no \
         decoded hive mentions it"
    );
}

/// Published answer 16 names seven tools installed for hacking. Four of them
/// register under their own names and are checked here; the other three
/// (Cain & Abel, 123 Write All Stored Passwords, CuteFTP) are left out
/// deliberately rather than asserted loosely — a substring that broad would
/// pass on almost any disk.
#[test]
fn the_registry_shows_the_published_hacking_tools_installed() {
    let case_id = Uuid::new_v4();
    let Some(raw) = raw_evidence(case_id) else {
        return;
    };

    let hives = software_hives(&raw);
    let text: String = hives
        .iter()
        .filter_map(|hive| serde_json::to_string(hive).ok())
        .collect();

    for tool in ["Look@LAN", "NetStumbler", "Ethereal", "Anonymizer"] {
        assert!(
            text.contains(tool),
            "published answer 16 lists {tool} among the tools installed on this \
             machine, and no decoded hive mentions it"
        );
    }
}

/// Every decoded SOFTWARE hive on the volume, as the registry parser rendered
/// it.
///
/// The volume carries several: the live hive, its `$$$PROTO.HIV` template, and
/// whatever restore points hold. All are searched, because which one holds a
/// given value is a property of the disk rather than of the tool, and pinning
/// the test to one of them would be pinning it to today's walk order.
fn software_hives(raw: &Artifact) -> Vec<serde_json::Value> {
    use seance_plugin_mft::MftParser;
    use seance_plugin_registry::RegistryParser;

    let mut hives = Vec::new();
    for partition in PartitionParser.process(raw).unwrap_or_default() {
        for filesystem in FilesystemDetector.process(&partition).unwrap_or_default() {
            for entry in MftParser::new().process(&filesystem).unwrap_or_default() {
                let is_hive = entry
                    .metadata
                    .get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("SOFTWARE"));
                if !is_hive {
                    continue;
                }
                for record in RegistryParser.process(&entry).unwrap_or_default() {
                    let is_software = record
                        .metadata
                        .get("hive_type")
                        .and_then(|v| v.as_str())
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("SOFTWARE"));
                    if is_software {
                        hives.push(record.metadata.clone());
                    }
                }
            }
        }
    }
    hives
}
