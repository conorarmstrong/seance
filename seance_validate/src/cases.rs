//! The known-answer case set.
//!
//! Each case mirrors a documented DFTT (Digital Forensics Tool Testing) result
//! and runs the *real* Séance pipeline against the image, so the report reflects
//! production behaviour. Cases are declarative and additive — extend this list
//! as more of the corpus is locked in. Each `image_rel` is relative to the
//! corpus root passed as `--corpus`, which holds one directory per image set —
//! `dftt/`, `alihadi_ntfs/`, `oberon_linux_swap/`, `win11_bitlocker/` — and
//! lives outside the repository (see `documentation/VALIDATION.md`). An absent
//! image is reported as Skipped by the runner.

use crate::{CheckOutcome, KnownAnswerCase};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_fat::FatParser;
use seance_plugin_partition::PartitionParser;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

fn raw_evidence(path: &Path) -> anyhow::Result<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf())?);
    Ok(Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": path.to_string_lossy(), "path": path.to_string_lossy() }),
    ))
}

fn fat_filesystem(path: &Path, subtype: &str, fs_type: &str) -> anyhow::Result<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf())?);
    Ok(Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        json!({ "subtype": subtype, "filesystem_type": fs_type }),
    ))
}

fn pass_or_fail(matched: bool, actual: String) -> CheckOutcome {
    if matched {
        CheckOutcome::Pass { actual }
    } else {
        CheckOutcome::Fail { actual }
    }
}

/// DFTT #1 — Extended DOS Partition Test: all six FAT16 partitions must be
/// found by walking the full EBR chain, and the 0x05 extended container must
/// never be surfaced as a data partition.
fn dftt1_extended_partition(img: &Path) -> anyhow::Result<CheckOutcome> {
    let produced = PartitionParser
        .process(&raw_evidence(img)?)
        .map_err(|e| anyhow::anyhow!("partition parse: {e}"))?;
    let partitions: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::Partition)
        .collect();
    let ptype = |p: &&Artifact| {
        p.metadata
            .get("partition_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_ascii_lowercase())
    };
    let fat16 = partitions
        .iter()
        .filter(|p| matches!(ptype(p).as_deref(), Some("0x04" | "0x06" | "0x0e")))
        .count();
    let container = partitions
        .iter()
        .any(|p| matches!(ptype(p).as_deref(), Some("0x05" | "0x0f" | "0x85")));
    let actual = format!(
        "{} partitions ({fat16} FAT16); extended-container-as-partition={container}",
        partitions.len()
    );
    Ok(pass_or_fail(
        partitions.len() == 6 && fat16 == 6 && !container,
        actual,
    ))
}

/// DFTT #9 — FAT Volume Label Test #1: the boot-sector volume label is LABEL1.
fn dftt9_fat_volume_label(img: &Path) -> anyhow::Result<CheckOutcome> {
    let fs = fat_filesystem(img, "fat16", "FAT16")?;
    let produced = FatParser
        .process(&fs)
        .map_err(|e| anyhow::anyhow!("fat parse: {e}"))?;
    let label = produced
        .iter()
        .find_map(|a| a.metadata.get("volume_label").and_then(|v| v.as_str()));
    Ok(pass_or_fail(
        label == Some("LABEL1"),
        format!("volume_label={label:?}"),
    ))
}

/// DFTT #5 — FAT Daylight Savings Test: summer.txt and winter.txt must both be
/// recovered, each carrying a parseable timestamp.
fn dftt5_fat_daylight(img: &Path) -> anyhow::Result<CheckOutcome> {
    let fs = fat_filesystem(img, "fat12", "FAT12")?;
    let produced = FatParser
        .process(&fs)
        .map_err(|e| anyhow::anyhow!("fat parse: {e}"))?;
    let files: Vec<&Artifact> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect();

    let mut issues = Vec::new();
    for want in ["summer.txt", "winter.txt"] {
        let f = files.iter().find(|a| {
            a.metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(|n| n.eq_ignore_ascii_case(want))
                .unwrap_or(false)
        });
        match f {
            None => issues.push(format!("{want}: missing")),
            Some(f) => {
                let has_ts = ["modified", "created", "mtime", "accessed"]
                    .iter()
                    .any(|k| f.metadata.get(*k).and_then(|v| v.as_str()).is_some());
                if !has_ts {
                    issues.push(format!("{want}: no timestamp"));
                }
            }
        }
    }
    let actual = format!("{} FileEntry artifacts; issues={issues:?}", files.len());
    Ok(pass_or_fail(issues.is_empty(), actual))
}

/// The full known-answer case set.
/// **WIN-1** — the E01 decoder returns the bytes FTK Imager acquired.
///
/// The acquisition log shipped beside this image publishes MD5 and SHA-1 of the
/// acquired data, computed by a different tool, on a different machine, in
/// 2023, before this decoder existed. It is the only case in this set that
/// checks Séance *read* an image rather than understood one — and a failure
/// says something worse than any parser being wrong: that what every other
/// finding was derived from is not what was acquired.
fn alihadi_e01_acquisition_digests(img: &Path) -> anyhow::Result<CheckOutcome> {
    use md5::Digest as _;

    const ACQUIRED_MD5: &str = "e7d5b36a407d5a02d0872d4dd3f3f9d0";
    const ACQUIRED_SHA1: &str = "5edc4c6efda9d266ecabcab5629694d0063e9d7f";

    let source = seance_container_e01::E01DataSource::open(&img.to_string_lossy())
        .map_err(|e| anyhow::anyhow!("E01 open: {e}"))?;
    let total = source.size();
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut offset = 0u64;

    while offset < total {
        let want = std::cmp::min(buffer.len() as u64, total - offset) as usize;
        let read = source.read_at(offset, &mut buffer[..want])?;
        if read == 0 {
            return Ok(CheckOutcome::Fail {
                actual: format!(
                    "the decoded stream stalled at {offset} of {total}, so it ends before \
                     the acquisition says it does"
                ),
            });
        }
        md5.update(&buffer[..read]);
        sha1.update(&buffer[..read]);
        offset += read as u64;
    }

    let (got_md5, got_sha1) = (
        format!("{:x}", md5.finalize()),
        format!("{:x}", sha1.finalize()),
    );
    // Both, in one pass: a stream matching on MD5 and not SHA-1 is a finding,
    // not a rounding error.
    let matched = got_md5 == ACQUIRED_MD5 && got_sha1 == ACQUIRED_SHA1;
    Ok(pass_or_fail(
        matched,
        format!("MD5 {got_md5}, SHA-1 {got_sha1} over {total} bytes"),
    ))
}

/// **MEM-1** — a Linux capture describes itself, and the description matches
/// what the kernel printed.
///
/// The ground truth is `/proc/kallsyms` captured from the same boot as the
/// memory image. That is **host-attested rather than third-party**: the machine
/// stating what its own symbol table held, not an independent laboratory's
/// published answer. It is recorded as such in the report, because the two are
/// not the same weight of evidence.
///
/// It is still the strongest memory check available here, and it is the only
/// one: the memory tier carries this tool's strongest claims and had no
/// known-answer coverage at all.
///
/// # It runs what ships
///
/// The symbols are recovered by
/// [`seance_plugin_memory_linux::image_symbols::recover`] — the path Linux
/// discovery takes when no symbol file matches — over the capture opened by the
/// product's own LiME/AVML reader. An earlier version of this case carried its
/// own window sweep instead, which meant the validation could pass or fail on
/// code the product does not run. The comparison is then made against the
/// `symbols` section of the ISF that path generated, since that document is
/// what every downstream address read comes from.
///
/// # A missing answer key is a FAIL, not a skip
///
/// If the capture is present but `kallsyms.txt.gz` is not, this returns an
/// error and the runner records FAIL. Skipped means "the image was absent, so
/// nothing was examined"; here the image *is* present and the case still
/// cannot say whether the product read it correctly. Reporting that as
/// Skipped would let a run with the evidence in hand count as coverage-not-
/// attempted, and a case whose answer key is missing cannot be reported as
/// coverage at all.
fn linux_capture_kallsyms_matches_the_kernel(img: &Path) -> anyhow::Result<CheckOutcome> {
    use seance_plugin_memory_linux::image_symbols::{self, ImageDerivedSymbols, Recovery};
    use std::io::Read as _;

    // The ground truth sits beside the capture.
    let truth_path = img
        .parent()
        .ok_or_else(|| anyhow::anyhow!("capture has no parent directory"))?
        .join("kallsyms.txt.gz");
    if !truth_path.exists() {
        anyhow::bail!(
            "the capture is present but kallsyms.txt.gz is not beside it; the answer this \
             case checks against is missing, so the case cannot run and is recorded as a \
             failure rather than a skip"
        );
    }
    let mut ground_truth = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&truth_path)?)
        .read_to_string(&mut ground_truth)?;

    // Name → every address the kernel printed for it. A set, because the same
    // name occurs many times in a kernel (static functions in different
    // translation units), and the recovered table keeps the first.
    let mut expected: std::collections::HashMap<String, std::collections::HashSet<u64>> =
        std::collections::HashMap::new();
    for line in ground_truth.lines() {
        let mut parts = line.split_whitespace();
        let (Some(address), Some(_kind), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        // A module-qualified symbol is not in the kernel's static table.
        if parts.next().is_some() {
            continue;
        }
        if let Ok(address) = u64::from_str_radix(address, 16) {
            expected
                .entry(name.to_string())
                .or_default()
                .insert(address);
        }
    }

    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img.to_path_buf())?);
    let layer = seance_memory::formats::avml::open(ds)
        .map_err(|e| anyhow::anyhow!("the capture did not open: {e:?}"))?;

    // The product's own recovery, over the product's own layer.
    let recovered = match image_symbols::recover(&layer, ImageDerivedSymbols::Allow) {
        Recovery::Recovered(recovered) => recovered,
        other => {
            return Ok(CheckOutcome::Fail {
                actual: format!(
                    "the product's image-derived symbol recovery produced no symbol table:{}",
                    other.note()
                ),
            })
        }
    };

    // The `symbols` section of the generated ISF: name → { "address": n }.
    let document: serde_json::Value = serde_json::from_slice(&recovered.source.json)
        .map_err(|e| anyhow::anyhow!("the generated ISF is not JSON: {e}"))?;
    let symbols = document
        .get("symbols")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("the generated ISF has no symbols section"))?;

    let mut checked = 0usize;
    let mut disagreed = Vec::new();
    // The magnitude, kept apart from the sample above.
    let mut mismatches = 0usize;
    for (name, entry) in symbols {
        let Some(addresses) = expected.get(name) else {
            continue;
        };
        let Some(address) = entry.get("address").and_then(|v| v.as_u64()) else {
            continue;
        };
        checked += 1;
        if !addresses.contains(&address) {
            // Counted ALWAYS, sampled only for the message. These were one
            // value: `disagreed.len()` was both the sample and the number the
            // report printed, so forty thousand disagreements read as "5
            // disagreed" — the sample size presented as the magnitude, in the
            // one document whose purpose is not to understate loss. The
            // `checked < 10_000` guard below exists for exactly that reason.
            mismatches += 1;
            if disagreed.len() < 5 {
                disagreed.push(format!("{name} at {address:#x}"));
            }
        }
    }

    if checked < 10_000 {
        return Ok(CheckOutcome::Fail {
            actual: format!(
                "only {checked} symbols could be compared against the kernel's own table, \
                 too few for the comparison to mean anything"
            ),
        });
    }
    Ok(pass_or_fail(
        mismatches == 0,
        format!(
            "{checked} of {} recovered symbols compared against /proc/kallsyms from the same \
             boot (table of {} symbols at physical offset {:#x}, via image-derived discovery); {}",
            symbols.len(),
            recovered.symbol_count,
            recovered.kallsyms_at,
            if mismatches == 0 {
                "every address matched".to_string()
            } else {
                format!(
                    "{mismatches} disagreed, e.g. {}{}",
                    disagreed.join(", "),
                    if mismatches > disagreed.len() {
                        format!(" (and {} more)", mismatches - disagreed.len())
                    } else {
                        String::new()
                    }
                )
            }
        ),
    ))
}

/// **BL-1** — a modern BitLocker volume unlocks with its recovery password and
/// decrypts to structure Windows wrote.
///
/// The ground truth here is **Windows' own output**: the recovery password was
/// generated by Windows when the volume was encrypted, and the plaintext being
/// asserted is an NTFS boot sector Windows formatted. Nothing in the expected
/// answer comes from Séance.
///
/// This is the corpus that found four defects in the BitLocker plugin, three of
/// which made it report a modern encrypted disk as *not encrypted* or refuse a
/// correct recovery password. A capability that failed that way had no
/// known-answer coverage at all before this case.
fn win11_bitlocker_unlocks_and_decrypts(img: &Path) -> anyhow::Result<CheckOutcome> {
    use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
    use seance_plugin_bitlocker::{unlock_bitlocker, Credential, EncryptionMethod};
    use std::sync::Arc;

    /// From the image's GPT: the BitLocker partition and its length.
    const VOLUME_OFFSET: u64 = 407_896_064;
    const VOLUME_LENGTH: u64 = 66_060_288_000;
    /// Generated by Windows for this volume.
    const RECOVERY: &str = "633281-498102-426096-319726-225203-245927-337876-444884";

    let disk: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img.to_path_buf())?);
    let volume: Arc<dyn DataSource> =
        Arc::new(WindowSource::new(disk, VOLUME_OFFSET, VOLUME_LENGTH));

    let unlocked = unlock_bitlocker(volume, &Credential::RecoveryKey(RECOVERY.to_string()))
        .map_err(|e| anyhow::anyhow!("unlock: {e}"))?;

    if unlocked.encryption_method != EncryptionMethod::AesXts256 {
        return Ok(CheckOutcome::Fail {
            actual: format!(
                "cipher {:?}, expected XTS-AES-256",
                unlocked.encryption_method
            ),
        });
    }

    let plain = unlocked
        .decrypting_source
        .ok_or_else(|| anyhow::anyhow!("an XTS volume must expose a decrypting source"))?;

    // Offset 0 of the decrypted volume must be the filesystem's own boot
    // sector. BitLocker keeps its VBR there and relocates the real one, so this
    // is only true if the relocation was undone.
    let mut boot = [0u8; 512];
    plain.read_at(0, &mut boot)?;
    let oem = String::from_utf8_lossy(&boot[3..11]).to_string();
    let signature_ok = boot[510..512] == [0x55, 0xAA];

    if oem == "NTFS    " && signature_ok {
        Ok(CheckOutcome::Pass {
            actual: format!(
                "XTS-AES-256; decrypted offset 0 is an NTFS boot sector ({oem:?}, 0x55AA)"
            ),
        })
    } else {
        Ok(CheckOutcome::Fail {
            actual: format!("decrypted offset 0 OEM {oem:?}, 0x55AA present: {signature_ok}"),
        })
    }
}

/// **MEM-2** — a Windows memory capture describes itself, and the description
/// matches the kernel Microsoft published.
///
/// The ground truth is **Microsoft's own PDB**: discovery recovers the kernel's
/// CodeView GUID from the image's bytes, and that GUID selects exactly one
/// symbol file on Microsoft's symbol server. A wrong directory table base or a
/// wrong kernel base does not produce a GUID that happens to match; it produces
/// no match at all.
///
/// The Windows memory tier is where this tool's strongest claims live — process
/// lists, handle tables, recovered files — and MEM-1 covers Linux only.
fn win11_memory_discovery_matches_microsofts_kernel(img: &Path) -> anyhow::Result<CheckOutcome> {
    use seance_core::data_source::{DataSource, FileDataSource};
    use seance_memory::{MemoryLayer, PhysicalLayer};
    use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
    use std::sync::Arc;

    /// The CodeView identity of the kernel this capture was taken from, which
    /// names `ntkrnlmp.pdb/E6426A07C26E66F8EB8594621A7B273B1` on Microsoft's
    /// symbol server.
    const KERNEL_GUID: &str = "E6426A07C26E66F8EB8594621A7B273B";
    const BUILD: u32 = 26200;

    let source: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img.to_path_buf())?);
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source)?);

    // Symbols sit beside the capture in the corpus.
    let symbol_dir = img
        .parent()
        .map(|d| d.join("symbols"))
        .ok_or_else(|| anyhow::anyhow!("capture has no parent directory"))?;

    let profile = automagic::discover(physical, &[symbol_dir], &DiscoveryOptions::default())
        .map_err(|e| anyhow::anyhow!("discovery: {e}"))?;

    let guid_ok = profile.build.guid == KERNEL_GUID;
    let build_ok = profile.build.build == Some(BUILD);

    if guid_ok && build_ok {
        Ok(CheckOutcome::Pass {
            actual: format!(
                "kernel {} build {} recovered from the image; dtb {:#x}, kernel base {:#x}",
                profile.build.guid, BUILD, profile.dtb.value, profile.kernel_base.value
            ),
        })
    } else {
        Ok(CheckOutcome::Fail {
            actual: format!(
                "recovered GUID {} build {:?}",
                profile.build.guid, profile.build.build
            ),
        })
    }
}

pub fn cases() -> Vec<KnownAnswerCase> {
    vec![
        KnownAnswerCase {
            id: "DFTT-1",
            description: "Extended DOS partition: all six FAT16 partitions, container not surfaced",
            capability: "partition-table",
            image_rel: "dftt/1-extend-part/1-extend-part/ext-part-test-2.dd",
            assertion: None,
            expected: "6 partitions, all FAT16, extended container not emitted",
            check: dftt1_extended_partition,
        },
        KnownAnswerCase {
            id: "DFTT-9",
            description: "FAT16 boot-sector volume label",
            capability: "fat-volume-label",
            image_rel: "dftt/9-fat-label/9-fat-label/9-fat-label.dd",
            assertion: None,
            expected: "volume label LABEL1",
            check: dftt9_fat_volume_label,
        },
        KnownAnswerCase {
            id: "DFTT-5",
            description: "FAT12 daylight-savings: summer.txt and winter.txt with timestamps",
            capability: "fat-timestamps",
            image_rel: "dftt/5-fat-daylight/5-fat-daylight/daylight.dd",
            assertion: None,
            expected: "both files recovered, each with a parseable timestamp",
            check: dftt5_fat_daylight,
        },
        KnownAnswerCase {
            id: "WIN-1",
            description: "E01 container: decoded stream matches FTK Imager's acquisition digests",
            capability: "e01-container",
            image_rel: "alihadi_ntfs/NTFS-HiddenFiles.E01",
            assertion: None,
            expected: "MD5 e7d5b36a407d5a02d0872d4dd3f3f9d0, SHA-1 \
                       5edc4c6efda9d266ecabcab5629694d0063e9d7f (from the image's own \
                       acquisition log)",
            check: alihadi_e01_acquisition_digests,
        },
        KnownAnswerCase {
            id: "BL-1",
            description: "BitLocker XTS-AES-256: recovery password unlocks, volume decrypts to NTFS",
            capability: "bitlocker-xts",
            image_rel: "win11_bitlocker/win11-bitlocker-xts256.raw",
            assertion: None,
            expected: "XTS-AES-256, and offset 0 of the decrypted volume is an NTFS boot \
                       sector (OEM \"NTFS    \", signature 0x55AA) written by Windows",
            check: win11_bitlocker_unlocks_and_decrypts,
        },
        KnownAnswerCase {
            id: "MEM-2",
            description: "Windows memory capture: kernel identity recovered from the image matches Microsoft's PDB",
            capability: "memory-windows-discovery",
            image_rel: "win11_bitlocker/memory-unlocked.raw",
            assertion: None,
            expected: "ntkrnlmp.pdb GUID E6426A07C26E66F8EB8594621A7B273B, build 26200",
            check: win11_memory_discovery_matches_microsofts_kernel,
        },
        KnownAnswerCase {
            id: "MEM-1",
            description: "Linux memory capture: recovered kallsyms match the kernel's own table",
            capability: "memory-linux-symbols",
            image_rel: "oberon_linux_swap/oberon_mem.lime.compressed",
            assertion: None,
            expected: "every recovered symbol carries an address /proc/kallsyms printed for \
                       that name, from the same boot (host-attested, not third-party)",
            check: linux_capture_kallsyms_matches_the_kernel,
        },
    ]
}
