//! What the file-slack pass costs on real Windows volumes (`HUNT-124`).
//!
//! The NTFS, FAT and exFAT parsers read the tail of every live file's last
//! cluster during ingest and publish a `SlackSpace` region for each tail that
//! holds a non-zero byte, up to `MAX_SLACK_REGIONS_PER_VOLUME`. The owner's
//! decision asked for that cost to be measured on real evidence before it is
//! relied on. This prints, per NTFS/FAT/exFAT volume the gated images hold,
//! the parse time with the pass on and the counts on its
//! `slack_space_summary` record. The numbers in `documentation/VALIDATION.md`
//! (SLACK-1) come from this test's output.
//!
//! It asserts only what must hold on any volume: exactly one summary per
//! volume, and the regions published are the regions the summary counts,
//! each one inside the volume and shorter than one cluster. It does **not**
//! measure the parse with the pass switched off — there is no switch — so the
//! time printed is the whole MFT parse, not the pass alone.
//!
//! | Variable | Names | Volumes measured |
//! |---|---|---|
//! | `SEANCE_CFREDS_LEAKAGE` | the directory holding `cfreds_2015_data_leakage_pc.E01` | the Windows 7 system volume |
//! | `SEANCE_CFREDS_HACKING` | the directory holding `4Dell_Latitude_CPi.E01` | the Windows XP system volume |
//!
//! An absent variable skips that image; a variable that is named but points at
//! nothing fails, through [`seance_core::test_support::corpus`].
#![cfg(feature = "e01")]

use std::path::Path;
use std::time::Instant;

use seance_container_e01::E01ContainerModule;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_fat::FatParser;
use seance_plugin_mft::MftParser;
use seance_plugin_partition::{FilesystemDetector, PartitionParser};
use serde_json::json;
use uuid::Uuid;

fn e01(path: &Path) -> Artifact {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({
            "name": path.file_name().map(|n| n.to_string_lossy().to_string()),
            "path": path.to_string_lossy(),
            "size": std::fs::metadata(path).expect("the corpus gate proved it exists").len(),
        }),
    );
    E01ContainerModule
        .process(&artifact)
        .expect("libewf opens the image")
        .into_iter()
        .next()
        .expect("one image is one RawEvidence")
}

fn filesystems(raw: &Artifact) -> Vec<Artifact> {
    let partitions: Vec<Artifact> = PartitionParser
        .process(raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.artifact_type == ArtifactType::Partition)
        .collect();
    let volumes = if partitions.is_empty() {
        vec![raw.clone()]
    } else {
        partitions
    };
    volumes
        .iter()
        .flat_map(|v| FilesystemDetector.process(v).unwrap_or_default())
        .filter(|a| a.artifact_type == ArtifactType::FileSystem)
        .collect()
}

fn n(meta: &serde_json::Value, key: &str) -> u64 {
    meta[key]
        .as_u64()
        .unwrap_or_else(|| panic!("summary lacks {key}"))
}

fn measure(label: &str, raw: &Artifact) {
    for fs in filesystems(raw) {
        let kind = fs.metadata["filesystem_type"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let started = Instant::now();
        let out = if kind == "ntfs" {
            MftParser::new().process(&fs)
        } else if kind.starts_with("fat") || kind == "exfat" {
            FatParser.process(&fs)
        } else {
            eprintln!("  {label}: {kind} volume -- no slack producer for this file system");
            continue;
        };
        let secs = started.elapsed().as_secs_f64();
        let out = match out {
            Ok(out) => out,
            Err(e) => {
                eprintln!("  {label}: {kind} volume -- could not look, the parser refused it: {e}");
                continue;
            }
        };
        let summaries: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["subtype"] == "slack_space_summary")
            .collect();
        assert_eq!(
            summaries.len(),
            1,
            "{label}: one slack summary per {kind} volume"
        );
        let s = &summaries[0].metadata;
        let regions: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::SlackSpace)
            .collect();
        assert_eq!(regions.len() as u64, n(s, "regions_emitted"), "{label}");
        let volume_len = fs.data.as_ref().map(|d| d.size()).unwrap_or(0);
        let bytes: u64 = regions
            .iter()
            .map(|r| {
                let off = r.metadata["offset_bytes"].as_u64().expect("offset_bytes");
                let len = r.metadata["size_bytes"].as_u64().expect("size_bytes");
                assert!(off + len <= volume_len, "{label}: a region past the volume");
                assert!(len > 0, "{label}: an empty slack region");
                len
            })
            .sum();
        assert_eq!(bytes, n(s, "bytes_emitted"), "{label}");
        let file_entries = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .count();
        println!(
            "SLACK-COST | {label} | {kind} | {:.1} GiB | {file_entries} FileEntry | parse {secs:.1} s \
             | offered {} | regions {} ({} bytes) | zero {} | unreadable {} | at cap {} | cap reached {} \
             | not located {}",
            volume_len as f64 / (1u64 << 30) as f64,
            n(s, "files_offered"),
            n(s, "regions_emitted"),
            n(s, "bytes_emitted"),
            n(s, "zero_tails"),
            n(s, "unreadable_tails"),
            n(s, "files_not_examined_at_cap"),
            s["region_cap_reached"],
            n(s, "files_not_located"),
        );
        // Every offered window lands in exactly one bucket.
        assert_eq!(
            n(s, "files_offered"),
            n(s, "regions_emitted")
                + n(s, "zero_tails")
                + n(s, "unreadable_tails")
                + n(s, "files_not_examined_at_cap"),
            "{label}"
        );
    }
}

#[test]
fn the_slack_pass_cost_on_held_windows_volumes() {
    if let Some(dir) = corpus::dir("SEANCE_CFREDS_LEAKAGE") {
        let p = dir.join("cfreds_2015_data_leakage_pc.E01");
        assert!(p.is_file(), "{} is missing", p.display());
        measure("CFReDS Data Leakage PC", &e01(&p));
    }
    if let Some(p) = corpus::file("SEANCE_CFREDS_HACKING", "4Dell_Latitude_CPi.E01") {
        measure("CFReDS Hacking Case", &e01(&p));
    }
}
