//! End-to-end regression against a reproducible synthetic golden image.
//!
//! Unlike the CFReDS and Ali Hadi corpora — third-party evidence with published
//! answers — this image is *built from a declared layout* by
//! `scripts/build_golden_images.sh`, so the ground truth is that script: legible,
//! auditable, and reproducible on any machine without root. What these tests
//! assert is that Séance recovers exactly what the script wrote. Séance is
//! checked against `mkntfs` / `mke2fs` / `mtools` plus a fixed layout, never
//! against its own prior output, so this is a genuine regression gate rather
//! than a self-referential snapshot.
//!
//! One image carries four partitions on a GPT disk, so a single artifact
//! exercises the whole `E01 → partition → filesystem → file` chain for every
//! filesystem Séance walks natively on a disk:
//!
//! | Partition | Type GUID | Filesystem | Walked by |
//! |---|---|---|---|
//! | 1 | Microsoft Basic Data | NTFS  | `$MFT` parser |
//! | 2 | Linux Filesystem     | ext4  | ext4 parser |
//! | 3 | Microsoft Basic Data | FAT16 | FAT parser |
//! | 4 | Apple APFS           | APFS  | APFS parser |
//!
//! APFS is a partial case, honestly bounded: `mkapfs` builds a real container
//! and volume on Linux, but there is no rootless way to write *files* into APFS,
//! so partition 4's ground truth is structural — fixed container/volume UUIDs
//! and block size — while file *content* is asserted on NTFS/ext4/FAT. A
//! file-bearing APFS image still needs a real Mac capture; see
//! `documentation/TESTING.md`.
//!
//! Point `SEANCE_GOLDEN_IMAGES` at a directory holding `golden_multipart.E01`
//! (run the generator script to make it). Absent, these skip; named and missing,
//! they fail — see [`seance_core::test_support::corpus`].
//!
//! Requires the `e01` feature: without libewf there is no way in.

use seance_container_e01::E01ContainerModule;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
    test_support::corpus,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

const CORPUS_VAR: &str = "SEANCE_GOLDEN_IMAGES";
const IMAGE: &str = "golden_multipart.E01";

/// The raw disk size the generator produces (see the layout in the script).
const RAW_DISK_BYTES: u64 = 102_760_448;

/// Ground truth written into the file-bearing partitions by the generator. Keep
/// in lockstep with `scripts/build_golden_images.sh`.
const README: &str = "golden regression corpus\nbuilt by build_golden_images.sh\n";
/// `hello.txt` content differs per filesystem so a test can prove it read the
/// intended partition and not a neighbour.
const HELLO_NTFS: &str = "SEANCE GOLDEN NTFS\n";
const HELLO_EXT4: &str = "SEANCE GOLDEN EXT4\n";
const HELLO_FAT: &str = "SEANCE GOLDEN FAT\n";

/// The APFS partition's structural ground truth, fixed by `mkapfs` flags.
const APFS_VOLUME_NAME: &str = "GOLDENAPFS";
const APFS_VOLUME_UUID: &str = "55555555-6666-7777-8888-999999999999";

/// `data.bin` is the 256 bytes 0x00..=0xFF, an exact-content round-trip check.
fn data_bin() -> Vec<u8> {
    (0u8..=255).collect()
}

/// E01 → RawEvidence, or `None` to skip when the corpus is not provisioned.
fn raw_evidence() -> Option<Artifact> {
    let path = corpus::file(CORPUS_VAR, IMAGE)?;
    let size = std::fs::metadata(&path)
        .expect("the corpus gate proved this path exists")
        .len();
    let fe = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": IMAGE, "path": path.to_string_lossy(), "size": size }),
    );
    let raw = E01ContainerModule
        .process(&fe)
        .expect("libewf opens the image")
        .into_iter()
        .next()
        .expect("one image is one RawEvidence");
    assert!(
        raw.data.is_some(),
        "a RawEvidence with no data source reads as an empty disk"
    );
    Some(raw)
}

/// The partition artifacts (real partitions, not the unallocated-space gaps).
fn partitions(raw: &Artifact) -> Vec<Artifact> {
    seance_plugin_partition::PartitionParser
        .process(raw)
        .expect("partition table parses")
        .into_iter()
        .filter(|p| p.artifact_type == ArtifactType::Partition)
        .collect()
}

/// The single filesystem artifact detected inside a partition.
fn filesystem(part: &Artifact) -> Option<Artifact> {
    seance_plugin_partition::FilesystemDetector
        .process(part)
        .expect("filesystem detection runs")
        .into_iter()
        .next()
}

/// Walk a filesystem to its `FileEntry` artifacts, dispatching on its type.
fn files(fs: &Artifact) -> Vec<Artifact> {
    let fstype = fs.metadata["filesystem_type"].as_str().unwrap_or("");
    let out = match fstype {
        "NTFS" => seance_plugin_mft::MftParser::new().process(fs),
        "ext4" => seance_plugin_ext4::Ext4Parser::new().process(fs),
        s if s.starts_with("FAT") => seance_plugin_fat::FatParser.process(fs),
        other => panic!("unexpected filesystem type {other:?}"),
    }
    .unwrap_or_default();
    out.into_iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect()
}

/// Find a `FileEntry` by its `/`-rooted path.
fn by_path<'a>(files: &'a [Artifact], path: &str) -> &'a Artifact {
    files
        .iter()
        .find(|a| a.metadata.get("path").and_then(|v| v.as_str()) == Some(path))
        .unwrap_or_else(|| panic!("{path} not found among {} entries", files.len()))
}

/// Read an entry's whole content through its data source.
fn read_all(entry: &Artifact) -> Vec<u8> {
    let src = entry
        .data
        .as_ref()
        .expect("a file entry carries its content");
    let size = entry.metadata["size"].as_u64().expect("size is recorded") as usize;
    let mut buf = vec![0u8; size];
    let mut off = 0;
    while off < size {
        let n = src
            .read_at(off as u64, &mut buf[off..])
            .expect("file content is readable to its stated size");
        assert!(n > 0, "read stalled at {off} of {size}");
        off += n;
    }
    buf
}

/// Locate the filesystem of a given type, then return its file entries.
fn files_of_type(raw: &Artifact, fstype: &str) -> Vec<Artifact> {
    let part_fs = partitions(raw).into_iter().find_map(|p| {
        let fs = filesystem(&p)?;
        (fs.metadata["filesystem_type"].as_str() == Some(fstype)).then_some(fs)
    });
    let fs = part_fs.unwrap_or_else(|| panic!("no {fstype} partition detected"));
    files(&fs)
}

/// The E01 decodes to exactly the disk the generator imaged.
#[test]
fn the_e01_decodes_to_the_generated_disk_size() {
    let Some(raw) = raw_evidence() else { return };
    let size = raw.data.as_ref().expect("checked in raw_evidence").size();
    assert_eq!(
        size, RAW_DISK_BYTES,
        "the decoded disk is not the size the generator produced"
    );
}

/// The GPT carries the three partitions the generator laid down, in order, with
/// the expected type GUIDs — and each is recognised as its intended filesystem.
#[test]
fn the_three_partitions_and_their_filesystems_are_detected() {
    let Some(raw) = raw_evidence() else { return };
    let parts = partitions(&raw);
    assert_eq!(parts.len(), 4, "GPT has exactly four data partitions");

    let expect = [
        ("Microsoft Basic Data", "NTFS"),
        ("Linux Filesystem", "ext4"),
        ("FAT16", "FAT16"),
        ("Apple APFS", "APFS"),
    ];
    for (i, (part, (type_name, fstype))) in parts.iter().zip(expect).enumerate() {
        assert_eq!(
            part.metadata["partition_id"].as_u64(),
            Some(i as u64 + 1),
            "partitions are reported in on-disk order"
        );
        // The FAT partition uses the generic Basic Data type GUID like NTFS, so
        // the GUID name is only asserted where it is distinctive.
        if fstype != "FAT16" {
            assert_eq!(
                part.metadata["partition_type_name"].as_str(),
                Some(type_name),
                "partition {} type GUID name",
                i + 1
            );
        }
        let fs = filesystem(part).expect("each partition carries a filesystem");
        assert_eq!(
            fs.metadata["filesystem_type"].as_str(),
            Some(fstype),
            "partition {} filesystem type",
            i + 1
        );
    }
}

/// The full chain reaches file *content*: the three known files come back from
/// every filesystem, byte-for-byte as written, including the exact 0x00..0xFF
/// binary and the filesystem-specific tag that proves the right partition.
#[test]
fn every_filesystem_returns_the_written_files_byte_for_byte() {
    let Some(raw) = raw_evidence() else { return };

    for (fstype, hello) in [
        ("NTFS", HELLO_NTFS),
        ("ext4", HELLO_EXT4),
        ("FAT16", HELLO_FAT),
    ] {
        let entries = files_of_type(&raw, fstype);

        let hello_entry = by_path(&entries, "/hello.txt");
        assert_eq!(
            read_all(hello_entry),
            hello.as_bytes(),
            "{fstype}: /hello.txt content (and thus which partition we read)"
        );

        let readme_entry = by_path(&entries, "/readme.txt");
        assert_eq!(
            read_all(readme_entry),
            README.as_bytes(),
            "{fstype}: /readme.txt content"
        );

        let data_entry = by_path(&entries, "/data.bin");
        assert_eq!(
            read_all(data_entry),
            data_bin(),
            "{fstype}: /data.bin is not the exact 256 bytes 0x00..0xFF that were written"
        );
    }
}

/// The APFS partition parses to its container and volume. There is no rootless
/// way to write files into APFS on Linux, so the assertion is structural: the
/// volume the generator created, with the exact name and UUID `mkapfs` was told
/// to use, at the expected block size — and the volume's root directory is
/// reached and reported empty (the file counts the superblock records).
#[test]
fn the_apfs_volume_parses_with_its_declared_identity() {
    let Some(raw) = raw_evidence() else { return };

    let apfs_fs = partitions(&raw)
        .into_iter()
        .find_map(|p| {
            let fs = filesystem(&p)?;
            (fs.metadata["filesystem_type"].as_str() == Some("APFS")).then_some(fs)
        })
        .expect("the APFS partition is detected as an APFS filesystem");

    let out = seance_plugin_apfs::ApfsParser
        .process(&apfs_fs)
        .expect("the APFS container parses");

    // The volume superblock, with the identity the generator fixed via mkapfs.
    let volume = out
        .iter()
        .find(|a| {
            a.artifact_type == ArtifactType::FileSystem
                && a.metadata.get("volume_uuid").and_then(|v| v.as_str()) == Some(APFS_VOLUME_UUID)
        })
        .expect("the APFS volume is surfaced with its UUID");
    assert_eq!(
        volume.metadata["volume_name"].as_str(),
        Some(APFS_VOLUME_NAME),
        "the volume name mkapfs was given"
    );
    assert_eq!(
        volume.metadata["block_size"].as_u64(),
        Some(4096),
        "APFS default block size"
    );
    assert_eq!(
        volume.metadata["encrypted"].as_bool(),
        Some(false),
        "an unencrypted mkapfs volume"
    );
    assert_eq!(
        volume.metadata["num_files"].as_u64(),
        Some(0),
        "no files were written (none can be, rootless)"
    );

    // The filesystem walk reaches the volume root — proof the object map and
    // B-trees were traversed, not just the superblocks read.
    let root = out
        .iter()
        .find(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata.get("path").and_then(|v| v.as_str()) == Some("/")
        })
        .expect("the APFS volume root directory is reached");
    assert_eq!(
        root.metadata["is_directory"].as_bool(),
        Some(true),
        "the root is a directory"
    );
}

/// Wrap the golden disk in an Apple `.sparseimage` and confirm it parses to the
/// same partitions and filesystems as the E01. This proves the sparse-band
/// reader reconstructs a real multi-filesystem disk byte-accurately and composes
/// with the rest of the pipeline — the format examiners actually collect from
/// Macs (FUJI / RECON / ASLA). Built in-memory from the golden disk, so it needs
/// no extra fixture; the GPT's unallocated gaps exercise sparse (unwritten)
/// bands on real data too.
#[test]
fn a_sparseimage_of_the_golden_disk_parses_identically() {
    let Some(raw) = raw_evidence() else { return };
    let src = raw.data.as_ref().expect("checked in raw_evidence");
    let size = src.size();

    // Read the whole decoded disk, then re-encode it as a sparse image.
    let mut disk = vec![0u8; size as usize];
    let mut off = 0u64;
    while off < size {
        let n = src.read_at(off, &mut disk[off as usize..]).unwrap();
        assert!(n > 0, "read stalled at {off}");
        off += n as u64;
    }
    let image = build_sparseimage(&disk, 2048); // 1 MiB bands
    drop(disk);
    assert!(
        (image.len() as u64) < size,
        "the sparse image is smaller than the flat disk (holes not stored)"
    );

    let art = Artifact::new(
        raw.case_id,
        ArtifactType::Container,
        Some(Arc::new(ByteSliceDataSource::new(image))),
        json!({ "name": "golden.sparseimage", "subtype": "sparseimage" }),
    );
    let sparse_raw = seance_container_sparseimage::SparseImageContainerModule
        .process(&art)
        .expect("the sparse image opens")
        .into_iter()
        .next()
        .expect("one image is one RawEvidence");
    assert_eq!(
        sparse_raw.data.as_ref().unwrap().size(),
        size,
        "the sparse image decodes to the full logical disk size"
    );

    let fstypes: Vec<String> = partitions(&sparse_raw)
        .iter()
        .filter_map(filesystem)
        .filter_map(|fs| fs.metadata["filesystem_type"].as_str().map(String::from))
        .collect();
    assert_eq!(
        fstypes,
        vec!["NTFS", "ext4", "FAT16", "APFS"],
        "the sparse-image-decoded disk parses to the same filesystems as the E01"
    );
}

/// Encode `raw` as an Apple `.sparseimage`, allocating a physical band only for
/// bands that hold non-zero bytes. Mirrors `scripts/build_golden_images.sh`'s
/// sibling logic and the libmodi interpretation the reader was verified against.
fn build_sparseimage(raw: &[u8], sectors_per_band: u32) -> Vec<u8> {
    const SECTOR: usize = 512;
    const HEADER: usize = 4096;
    const BAND_ARRAY_OFF: usize = 0x40;
    let spb = sectors_per_band as usize;
    let band_bytes = spb * SECTOR;
    let total_sectors = raw.len().div_ceil(SECTOR);
    let nbands = total_sectors.div_ceil(spb);

    let mut header = vec![0u8; HEADER];
    header[0..4].copy_from_slice(b"sprs");
    header[4..8].copy_from_slice(&3u32.to_be_bytes());
    header[8..12].copy_from_slice(&sectors_per_band.to_be_bytes());
    header[0x0c..0x10].copy_from_slice(&1u32.to_be_bytes());
    header[0x10..0x14].copy_from_slice(&(total_sectors as u32).to_be_bytes());

    let mut bands = Vec::new();
    let mut phys = 0u32;
    for l in 0..nbands {
        let start = l * band_bytes;
        let end = (start + band_bytes).min(raw.len());
        let band = &raw[start.min(raw.len())..end];
        if band.iter().all(|&b| b == 0) {
            continue; // never-written band -> the reader zero-fills it
        }
        let off = BAND_ARRAY_OFF + phys as usize * 4;
        header[off..off + 4].copy_from_slice(&((l as u32) + 1).to_be_bytes());
        bands.extend_from_slice(band);
        bands.resize(bands.len() + (band_bytes - band.len()), 0); // pad a partial final band
        phys += 1;
    }
    header.extend_from_slice(&bands);
    header
}
