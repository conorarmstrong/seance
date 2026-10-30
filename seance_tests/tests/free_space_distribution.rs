//! What the free-region ceiling costs on real volumes (`CARVE-011`, step 3).
//!
//! `seance_core::free_space` keeps the largest [`MAX_FREE_REGIONS`] free runs
//! of a volume and reports the rest as a count and a byte total. On the Magnet
//! 2022 Linux CTF ext4 volume that ceiling declines 37.6% of the free space.
//! One volume does not say whether that is typical, so this measures every held
//! volume it is pointed at and prints the distribution. The numbers recorded in
//! `documentation/VALIDATION.md` come from this test's output.
//!
//! It also grades the configurable ceiling end to end on real data. A lab that
//! sets `SEANCE_FREE_REGION_CAP` to at least the volume's run count gets every
//! run and a record that says it is complete. A lab that sets it one below
//! loses exactly the one smallest run, and the record says the ceiling was
//! configured. The ceiling is read from the environment, so this binary holds
//! **one** `#[test]`: no other test in the process can observe the variable
//! while it is set.
//!
//! Every volume is gated on its own variable. An absent variable skips that
//! volume; a variable that is named but points at nothing fails, through
//! [`seance_core::test_support::corpus`]:
//!
//! | Variable | Names | Volumes measured |
//! |---|---|---|
//! | `SEANCE_ALIHADI_NTFS` | the directory holding `NTFS-HiddenFiles.E01` | one NTFS volume |
//! | `SEANCE_CFREDS_HACKING` | the directory holding `4Dell_Latitude_CPi.E01` | the XP system volume |
//! | `SEANCE_CFREDS_LEAKAGE` | the directory holding `cfreds_2015_data_leakage_pc.E01` and the `rm#1`/`rm#2` media | the Win7 system volume and the two removable media |
//! | `SEANCE_LINUX_CTF` | the directory holding `LenovoFinal.E01` | the 67 GB ext4 volume and the EFI partition |
//! | `SEANCE_JAMMY_DISK` | the `linux-lab` VM disk itself, qcow2 or a raw conversion | its ext4 root and EFI partition |
//! | `SEANCE_NOBLE_DISK` | the `noble-lab` VM disk itself, qcow2 or a raw conversion | its ext4 root and EFI partition |
//!
//! Both VM disks are Ubuntu cloud images whose qcow2 clusters are
//! zlib-compressed, which `Qcow2ContainerModule` refuses rather than reading as
//! zeros. So a file whose name does not end in `.img`/`.qcow2` is read as a raw
//! disk: `qemu-img convert -O raw jammy.img jammy.raw` gives the same disk
//! (`qemu-img compare` confirms it). Given the qcow2, this test says it could
//! not look.
//!
//! A synthetic fixture cannot stand for any of this: the question is what real
//! volumes look like.
#![cfg(feature = "e01")]

use std::path::Path;
use std::sync::Arc;

use seance_container_e01::E01ContainerModule;
use seance_container_vdisk::Qcow2ContainerModule;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    free_space::{FREE_BYTE_CAP_ENV, FREE_REGION_CAP_ENV, MAX_FREE_REGIONS},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_ext4::Ext4Parser;
use seance_plugin_fat::FatParser;
use seance_plugin_mft::MftParser;
use seance_plugin_partition::{FilesystemDetector, PartitionParser};
use serde_json::{json, Value};
use uuid::Uuid;

/// The largest run count this test will re-run a volume at in full.
///
/// One region is one artifact held in memory. The Lenovo ext4 volume has 1.36
/// million runs, and a whole-volume pass over it is the ingest-time cost a lab
/// accepts by raising the ceiling; it is not a cost this test imposes on a
/// shared machine. Past this bound the full re-run is skipped and the output
/// says so.
const FULL_RERUN_MAX_RUNS: u64 = 250_000;

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

/// A VM disk: decoded through the qcow2 reader, or read as a raw disk when
/// its name says it is one. `None`, with the reason printed, when the qcow2
/// reader refuses it.
fn vm_disk(path: &Path) -> Option<Artifact> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name.ends_with(".img") || name.ends_with(".qcow2") {
        return qcow2(path);
    }
    let source: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path.to_path_buf()).expect("the raw disk opens"));
    Some(Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(source),
        json!({ "name": name }),
    ))
}

fn qcow2(path: &Path) -> Option<Artifact> {
    let source: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path.to_path_buf()).expect("the qcow2 opens"));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({
            "name": path.file_name().map(|n| n.to_string_lossy().to_string()),
            "subtype": "qcow2",
        }),
    );
    match Qcow2ContainerModule.process(&artifact) {
        Ok(out) => out.into_iter().find(|a| a.data.is_some()),
        Err(e) => {
            eprintln!(
                "  {}: could not look -- the qcow2 reader refused it: {e}",
                path.display()
            );
            None
        }
    }
}

/// Every filesystem the detector finds on a disk, partitioned or not.
fn filesystems(raw: &Artifact) -> Vec<Artifact> {
    let partitions: Vec<Artifact> = PartitionParser
        .process(raw)
        .unwrap_or_else(|e| {
            eprintln!("  could not look -- the partition parser refused the disk: {e}");
            Vec::new()
        })
        .into_iter()
        .filter(|p| p.artifact_type == ArtifactType::Partition)
        .collect();
    let volumes = if partitions.is_empty() {
        vec![raw.clone()]
    } else {
        partitions
    };
    let found: Vec<Artifact> = volumes
        .iter()
        .flat_map(|v| FilesystemDetector.process(v).unwrap_or_default())
        .filter(|a| a.artifact_type == ArtifactType::FileSystem)
        .collect();
    if !found.is_empty() {
        return found;
    }
    if partitions_empty(&volumes, raw) {
        eprintln!(
            "  could not look -- no partition and no filesystem was detected on the {}-byte image \
             ({:?})",
            raw.data.as_ref().map(|d| d.size()).unwrap_or(0),
            raw.artifact_type
        );
        return found;
    }
    // A volume image with no partition table: an NTFS boot sector ends in
    // 0x55AA, so it can read as an MBR whose entries detect as nothing. Try
    // the whole image as the volume before saying nothing was found.
    let whole: Vec<Artifact> = FilesystemDetector
        .process(raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.artifact_type == ArtifactType::FileSystem)
        .collect();
    if whole.is_empty() {
        eprintln!(
            "  could not look -- no filesystem was detected on {} partition(s) or on the whole image",
            volumes.len()
        );
    }
    whole
}

fn partitions_empty(volumes: &[Artifact], raw: &Artifact) -> bool {
    volumes.len() == 1 && volumes[0].id == raw.id
}

/// The parser that owns a detected filesystem, or `None` for a kind that
/// publishes no free regions.
fn parse(fs: &Artifact) -> Option<Result<Vec<Artifact>, String>> {
    let kind = fs.metadata["filesystem_type"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let out = if kind == "ntfs" {
        MftParser::new().process(fs)
    } else if kind.starts_with("ext") {
        Ext4Parser::new().process(fs)
    } else if kind.starts_with("fat") || kind == "exfat" {
        FatParser.process(fs)
    } else {
        return None;
    };
    Some(out.map_err(|e| e.to_string()))
}

fn allocation_map(produced: &[Artifact]) -> Option<&Artifact> {
    produced
        .iter()
        .find(|a| a.metadata.get("type").and_then(Value::as_str) == Some("allocation_map"))
}

fn regions(produced: &[Artifact]) -> Vec<&Artifact> {
    produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::UnallocatedSpace)
        .collect()
}

fn n(map: &Artifact, key: &str) -> u64 {
    map.metadata[key]
        .as_u64()
        .unwrap_or_else(|| panic!("the allocation map states {key}: {}", map.metadata))
}

/// The invariants any free-space pass must meet, whatever the volume.
fn assert_structure(label: &str, fs: &Artifact, produced: &[Artifact]) {
    let map = allocation_map(produced).expect("an allocation map");
    let emitted = regions(produced);
    let volume_bytes = fs.data.as_ref().map(|d| d.size()).unwrap_or(0);
    assert_eq!(
        emitted.len() as u64,
        n(map, "free_regions_emitted"),
        "{label}: the record counts the regions it emitted"
    );
    assert_eq!(
        n(map, "free_regions_emitted") + n(map, "free_runs_dropped"),
        n(map, "free_runs_found"),
        "{label}: every run found is either emitted or counted as dropped"
    );
    let mut spans: Vec<(u64, u64)> = emitted
        .iter()
        .map(|r| {
            (
                r.metadata["offset_bytes"].as_u64().expect("offset"),
                r.metadata["size_bytes"].as_u64().expect("size"),
            )
        })
        .collect();
    spans.sort_unstable();
    let mut previous_end = 0u64;
    for (offset, size) in &spans {
        assert!(*size > 0, "{label}: an empty region at {offset}");
        assert!(
            *offset >= previous_end,
            "{label}: regions overlap at {offset} after {previous_end}"
        );
        assert!(
            volume_bytes == 0 || offset + size <= volume_bytes,
            "{label}: a region at {offset}+{size} passes the volume's {volume_bytes} bytes"
        );
        previous_end = offset + size;
    }
    assert_eq!(
        spans.iter().map(|(_, s)| s).sum::<u64>(),
        n(map, "free_bytes_emitted"),
        "{label}: the record's byte total is the regions' own"
    );
    // Largest first: no dropped run is larger than the smallest kept one, so
    // the dropped runs' AVERAGE cannot exceed the smallest region. This is
    // what the selection guarantees; that the kept bytes outweigh the dropped
    // ones is not, and is measured below rather than asserted.
    let dropped = n(map, "free_runs_dropped");
    if dropped > 0 {
        let smallest_kept = spans.iter().map(|(_, s)| *s).min().unwrap_or(0);
        assert!(
            n(map, "free_bytes_dropped") <= smallest_kept.saturating_mul(dropped),
            "{label}: {dropped} dropped runs cover {} bytes, more than {dropped} x the smallest \
             kept region ({smallest_kept}); the ceiling did not keep the largest runs",
            n(map, "free_bytes_dropped")
        );
        assert_eq!(map.metadata["free_space_complete"], false);
    }
}

struct Row {
    label: String,
    runs_found: u64,
    emitted: u64,
    bytes_emitted: u64,
    dropped: u64,
    bytes_dropped: u64,
    cluster_size: u64,
    whole_volume: String,
}

fn set_caps(regions: Option<u64>) {
    match regions {
        Some(cap) => std::env::set_var(FREE_REGION_CAP_ENV, cap.to_string()),
        None => std::env::remove_var(FREE_REGION_CAP_ENV),
    }
    std::env::remove_var(FREE_BYTE_CAP_ENV);
}

fn measure(label: &str, raw: &Artifact, rows: &mut Vec<Row>) {
    for fs in filesystems(raw) {
        let kind = fs.metadata["filesystem_type"]
            .as_str()
            .unwrap_or("?")
            .to_string();
        let label = format!("{label} [{kind} at {}]", fs.metadata["offset_bytes"]);
        set_caps(None);
        let produced = match parse(&fs) {
            None => continue,
            Some(Err(e)) => {
                eprintln!("  {label}: could not look -- the parser refused the volume: {e}");
                continue;
            }
            Some(Ok(p)) => p,
        };
        let Some(map) = allocation_map(&produced) else {
            eprintln!("  {label}: could not look -- no allocation map was published");
            continue;
        };
        if map.metadata.get("free_runs_found").is_none() {
            eprintln!("  {label}: could not look -- the allocation map carries no free-space pass");
            continue;
        }
        assert_structure(&label, &fs, &produced);
        assert_eq!(map.metadata["free_region_cap"], MAX_FREE_REGIONS as u64);
        assert_eq!(map.metadata["free_region_cap_source"], "default");

        let runs_found = n(map, "free_runs_found");
        let dropped = n(map, "free_runs_dropped");
        let mut row = Row {
            label: label.clone(),
            runs_found,
            emitted: n(map, "free_regions_emitted"),
            bytes_emitted: n(map, "free_bytes_emitted"),
            dropped,
            bytes_dropped: n(map, "free_bytes_dropped"),
            cluster_size: map.metadata["allocation_cluster_size"]
                .as_u64()
                .unwrap_or(0),
            whole_volume: String::new(),
        };
        drop(produced);

        // The configured ceiling, on real data.
        if dropped > 0 && runs_found <= FULL_RERUN_MAX_RUNS {
            // A lab that asks for the whole volume gets it.
            set_caps(Some(runs_found));
            let whole = parse(&fs).expect("same kind").expect("it parsed once");
            assert_structure(&label, &fs, &whole);
            let map = allocation_map(&whole).expect("an allocation map");
            assert_eq!(n(map, "free_runs_dropped"), 0, "{label}: {}", map.metadata);
            assert_eq!(n(map, "free_regions_emitted"), runs_found);
            assert_eq!(map.metadata["free_region_cap"], runs_found);
            assert_eq!(map.metadata["free_region_cap_source"], "configured");
            row.whole_volume = format!("re-run at cap {runs_found}: 0 dropped");
        } else if dropped > 0 {
            row.whole_volume = format!(
                "not re-run: {runs_found} runs is past this test's {FULL_RERUN_MAX_RUNS}-run bound"
            );
        } else if runs_found >= 2 {
            // Under the default ceiling already: lower it by one and exactly
            // the smallest run goes, stated as a configured ceiling.
            set_caps(Some(runs_found - 1));
            let cut = parse(&fs).expect("same kind").expect("it parsed once");
            assert_structure(&label, &fs, &cut);
            let map = allocation_map(&cut).expect("an allocation map");
            assert_eq!(n(map, "free_runs_dropped"), 1, "{label}: {}", map.metadata);
            assert_eq!(map.metadata["free_region_cap_source"], "configured");
            assert_eq!(map.metadata["free_region_cap_reached"], true);
            let detail = map.metadata["free_space_incomplete_detail"]
                .as_str()
                .expect("the sentence");
            assert!(detail.contains(FREE_REGION_CAP_ENV), "{detail}");
            row.whole_volume = format!("re-run at cap {}: 1 dropped", runs_found - 1);
        } else {
            row.whole_volume = "fewer than two runs: nothing to re-run".into();
        }
        set_caps(None);
        rows.push(row);
    }
}

#[test]
fn the_region_ceiling_cost_on_every_held_volume() {
    let mut rows = Vec::new();
    if let Some(p) = corpus::file("SEANCE_ALIHADI_NTFS", "NTFS-HiddenFiles.E01") {
        measure("Ali Hadi NTFS-HiddenFiles", &e01(&p), &mut rows);
    }
    if let Some(p) = corpus::file("SEANCE_CFREDS_HACKING", "4Dell_Latitude_CPi.E01") {
        measure("CFReDS Hacking Case", &e01(&p), &mut rows);
    }
    if let Some(dir) = corpus::dir("SEANCE_CFREDS_LEAKAGE") {
        for (label, name) in [
            ("CFReDS Data Leakage PC", "cfreds_2015_data_leakage_pc.E01"),
            (
                "CFReDS Data Leakage RM#1",
                "cfreds_2015_data_leakage_rm#1.E01",
            ),
            (
                "CFReDS Data Leakage RM#2",
                "cfreds_2015_data_leakage_rm#2.E01",
            ),
        ] {
            let path = dir.join(name);
            assert!(path.is_file(), "{} is missing", path.display());
            measure(label, &e01(&path), &mut rows);
        }
    }
    if let Some(p) = corpus::file("SEANCE_LINUX_CTF", "LenovoFinal.E01") {
        measure("Magnet 2022 Linux CTF", &e01(&p), &mut rows);
    }
    if let Some(p) = corpus::path("SEANCE_JAMMY_DISK") {
        if let Some(disk) = vm_disk(&p) {
            measure("linux-lab jammy VM", &disk, &mut rows);
        }
    }
    if let Some(p) = corpus::path("SEANCE_NOBLE_DISK") {
        if let Some(disk) = vm_disk(&p) {
            measure("noble-lab VM", &disk, &mut rows);
        }
    }
    if rows.is_empty() {
        eprintln!("skipping: no free-space corpus variable is set");
        return;
    }
    eprintln!(
        "\n| Volume | Cluster | Runs found | Emitted | Bytes emitted | Dropped | Bytes dropped | \
         Free space declined | Configured ceiling |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|---|");
    for r in &rows {
        let total = r.bytes_emitted + r.bytes_dropped;
        let pct = if total == 0 {
            0.0
        } else {
            100.0 * r.bytes_dropped as f64 / total as f64
        };
        eprintln!(
            "| {} | {} | {} | {} | {} | {} | {} | {pct:.1}% | {} |",
            r.label,
            r.cluster_size,
            r.runs_found,
            r.emitted,
            r.bytes_emitted,
            r.dropped,
            r.bytes_dropped,
            r.whole_volume
        );
    }
}
