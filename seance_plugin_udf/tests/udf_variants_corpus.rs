//! UDF-VARIANTS-1: the UDF partition kinds and sector sizes beyond the plain
//! physical partition, graded on self-made images.
//!
//! These images are **self-made**, not real-world discs: no public image with
//! files in a VAT, sparable or metadata partition and a published answer key
//! could be found. They were written by two third-party UDF writers (NetBSD
//! `makefs -t udf` and udftools `mkudffs` 2.3, the latter populated read-write
//! by the Linux 5.15 kernel) from one synthetic payload, and every populated
//! image except the two makefs sparable ones and the 4096-byte-sector ones
//! was mounted by the Linux 5.15 UDF driver, whose file hashes matched the
//! payload. The corpus, its tools and oracle outputs are described in
//! `SOURCE.md` of the directory `SEANCE_UDF_IMAGES` names (on the lab host,
//! `~/forensic_corpora/udf_images`). The answer key is the payload itself,
//! hashed in `payload.sha256`.
//!
//! They pin that the translation layers work on volumes another writer
//! produced. They are not validation on a real burned disc.
//!
//! Unset, the test skips and says so; `SEANCE_REQUIRE_CORPUS=1` turns the
//! skip into a failure.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_partition::FilesystemDetector;
use seance_plugin_udf::UdfParser;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn sha256_of(a: &Artifact) -> String {
    let ds = a.data.as_ref().expect("content attached");
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut off = 0u64;
    while off < ds.size() {
        let n = ds.read_at(off, &mut buf).expect("read");
        assert!(n > 0, "short read at {off}");
        h.update(&buf[..n]);
        off += n as u64;
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `payload.sha256` as path -> hash, paths rooted at `/`.
fn answer_key(dir: &Path) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(dir.join("payload.sha256")).expect("payload.sha256");
    text.lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, p)| (p.trim_start_matches('.').to_string(), h.to_string()))
        .collect()
}

/// Run partition detection then the UDF reader over one image.
fn read_image(path: &Path) -> (Vec<Artifact>, serde_json::Value) {
    let ds: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path.to_path_buf()).expect("open image"));
    read_source(ds, &path.display().to_string())
}

fn read_bytes(img: Vec<u8>, name: &str) -> (Vec<Artifact>, serde_json::Value) {
    read_source(Arc::new(ByteSliceDataSource::new(img)), name)
}

fn read_source(ds: Arc<dyn DataSource>, name: &str) -> (Vec<Artifact>, serde_json::Value) {
    let raw = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        json!({ "name": name }),
    );
    let fs = FilesystemDetector.process(&raw).expect("detect");
    let udf = fs
        .iter()
        .find(|a| a.metadata["subtype"].as_str() == Some("udf"))
        .unwrap_or_else(|| panic!("{name}: partition layer found no UDF"));
    let out = UdfParser.process(udf).expect("udf");
    let vol = out
        .iter()
        .find(|a| a.metadata["type"].as_str() == Some("udf_volume"))
        .expect("a udf_volume record")
        .metadata
        .clone();
    (out, vol)
}

/// Every payload file is present with the payload's hash, the three payload
/// directories are present, and nothing says it stopped short.
fn assert_payload(
    name: &str,
    out: &[Artifact],
    vol: &serde_json::Value,
    key: &BTreeMap<String, String>,
) {
    assert!(
        vol.get("udf_unreadable").is_none(),
        "{name}: refused: {}",
        vol["udf_unreadable_reason"]
    );
    assert!(
        vol.get("directory_parse_incomplete").is_none(),
        "{name}: {}",
        vol["directory_parse_incomplete_reason"]
    );
    let live: Vec<&Artifact> = out
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata.get("deleted").is_none()
                && a.metadata.get("hidden").is_none()
        })
        .collect();
    for (path, hash) in key {
        let a = live
            .iter()
            .find(|a| a.metadata["path"].as_str() == Some(path.as_str()))
            .unwrap_or_else(|| panic!("{name}: no entry {path}"));
        assert!(
            a.metadata.get("content_incomplete").is_none(),
            "{name}: {path} incomplete"
        );
        assert_eq!(&sha256_of(a), hash, "{name}: {path}");
    }
    let dirs: Vec<&str> = live
        .iter()
        .filter(|a| a.metadata["is_directory"] == true)
        .map(|a| a.metadata["path"].as_str().unwrap())
        .collect();
    for d in ["/docs", "/docs/nested", "/unicode_dir_é"] {
        assert!(dirs.contains(&d), "{name}: no directory {d} in {dirs:?}");
    }
    let paths: Vec<&str> = live
        .iter()
        .map(|a| a.metadata["path"].as_str().unwrap())
        .collect();
    assert_eq!(live.len(), key.len() + 3, "{name}: live entries {paths:?}");
}

/// (image, expected partition-map kinds, block size, UDF revision)
const POPULATED: &[(&str, &[&str], u64, &str)] = &[
    ("plain_disk_udf201.img", &["physical"], 512, "2.01"),
    ("plain_disk_udf201_2k.img", &["physical"], 2048, "2.01"),
    ("plain_disk_udf201_4k.img", &["physical"], 4096, "2.01"),
    ("vat_cdr_udf150.img", &["physical", "virtual"], 2048, "1.50"),
    (
        "vat_dvdr_udf201.img",
        &["physical", "virtual"],
        2048,
        "2.01",
    ),
    ("vat_bdr_udf250.img", &["physical", "virtual"], 2048, "2.50"),
    (
        "kernel_sparable_cdrw_udf150.img",
        &["sparable"],
        2048,
        "1.50",
    ),
    (
        "kernel_sparable_dvdrw_udf201.img",
        &["sparable"],
        2048,
        "2.01",
    ),
    ("sparable_cdrw_udf150_32m.img", &["sparable"], 2048, "1.50"),
    ("sparable_dvdrw_udf201_64m.img", &["sparable"], 2048, "2.01"),
    (
        "metadata_bdre_udf250_32m.img",
        &["physical", "metadata"],
        2048,
        "2.50",
    ),
    (
        "metadata_disk_udf250_2k_32m.img",
        &["physical", "metadata"],
        2048,
        "2.50",
    ),
    (
        "metadata_disk_udf250.img",
        &["physical", "metadata"],
        512,
        "2.50",
    ),
    (
        "metadata_disk_udf250_4k.img",
        &["physical", "metadata"],
        4096,
        "2.50",
    ),
];

#[test]
fn every_populated_variant_reads_the_payload() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    let key = answer_key(&dir);
    assert_eq!(key.len(), 5);
    for (name, maps, bs, rev) in POPULATED {
        let (out, vol) = read_image(&dir.join("images").join(name));
        assert_payload(name, &out, &vol, &key);
        assert_eq!(vol["partition_map_kinds"], json!(maps), "{name}: maps");
        assert_eq!(vol["block_size"], json!(bs), "{name}: block size");
        assert_eq!(vol["udf_revision"], json!(rev), "{name}: revision");
    }
}

#[test]
fn write_once_tail_after_the_vat_is_not_called_truncation() {
    // On write-once media the partition spans the whole disc and the image
    // ends at the VAT, the last block written. That is not a truncated
    // acquisition and must not read as one.
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    for name in [
        "vat_cdr_udf150.img",
        "vat_dvdr_udf201.img",
        "vat_bdr_udf250.img",
    ] {
        let (_, vol) = read_image(&dir.join("images").join(name));
        assert!(
            vol.get("partition_extends_past_evidence").is_none(),
            "{name}: {vol}"
        );
        assert_eq!(vol["partition_unrecorded_after_vat"], true, "{name}");
    }
}

#[test]
fn kernel_deleted_file_identifier_is_listed_as_deleted() {
    // The Linux kernel wrote then removed `deleted_later.txt`; its FID
    // survives with the deleted characteristic (SOURCE.md, "Deleted-entry
    // bonus"). Its content was not left in the image, so none is claimed.
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    for name in [
        "kernel_sparable_cdrw_udf150.img",
        "kernel_sparable_dvdrw_udf201.img",
    ] {
        let (out, _) = read_image(&dir.join("images").join(name));
        let d = out
            .iter()
            .find(|a| a.metadata["name"].as_str() == Some("deleted_later.txt"))
            .unwrap_or_else(|| panic!("{name}: deleted FID not listed"));
        assert_eq!(d.metadata["deleted"], true, "{name}");
    }
    // mkudffs records the UDF 1.50 "Non-Allocatable Space" system file
    // (OSTA UDF 1.50 2.3.13) with the hidden characteristic. The kernel's
    // listing hides it; the reader lists it, marked hidden.
    let (out, _) = read_image(&dir.join("images/kernel_sparable_cdrw_udf150.img"));
    let n = out
        .iter()
        .find(|a| a.metadata["path"].as_str() == Some("/Non-Allocatable Space"))
        .expect("Non-Allocatable Space listed");
    assert_eq!(n.metadata["hidden"], true);
}

#[test]
fn empty_vat_volumes_from_mkudffs_read_as_empty_not_refused() {
    // mkudffs --new-file images: closed, VAT at the last block, no files.
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    for name in [
        "mkudffs_vat_cdr_udf150_empty.img",
        "mkudffs_vat_bdr_udf250_empty.img",
    ] {
        let (out, vol) = read_image(&dir.join("images").join(name));
        assert!(
            vol.get("udf_unreadable").is_none(),
            "{name}: {}",
            vol["udf_unreadable_reason"]
        );
        assert_eq!(
            vol["partition_map_kinds"],
            json!(["physical", "virtual"]),
            "{name}"
        );
        assert_eq!(
            out.iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
                .count(),
            0,
            "{name}"
        );
    }
}

// --- Mechanisms the corpus does not exercise, pinned by editing a copy ----
//
// No image in the corpus has a relocated sparing packet, an unreadable main
// metadata file, or an earlier VAT. Each test below loads a writer-made
// image into memory, makes the one change that models the case (resealing
// the descriptors it touches), and checks the payload still reads exactly.
// They are mechanism tests on edited self-made images, not validation.

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Recompute a descriptor's CRC (over its recorded CRC length) and tag checksum.
fn reseal(d: &mut [u8]) {
    let crc_len = u16_at(d, 10) as usize;
    let crc = seance_plugin_udf::tag::crc_itu(&d[16..16 + crc_len]);
    d[8..10].copy_from_slice(&crc.to_le_bytes());
    d[4] = (0..16)
        .filter(|&i| i != 4)
        .fold(0u8, |a, i| a.wrapping_add(d[i]));
}

fn load(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join("images").join(name)).expect("image")
}

fn entry<'a>(out: &'a [Artifact], path: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.metadata["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("no entry {path}"))
}

#[test]
fn relocated_sparing_packet_is_read_from_where_the_table_moved_it() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    let key = answer_key(&dir);
    const BS: usize = 2048;
    let name = "kernel_sparable_dvdrw_udf201.img";
    let mut img = load(&dir, name);
    let (out, vol) = read_bytes(img.clone(), name);
    assert_eq!(vol["sparing_relocated_packets"], 0);
    let start = vol["partition_start"].as_u64().unwrap() as usize;
    let packet = vol["sparing_packet_length"].as_u64().unwrap() as usize;

    // The packet holding big.bin's first block.
    let first = entry(&out, "/docs/big.bin").metadata["data_runs"][0][0]
        .as_u64()
        .unwrap() as usize
        / BS;
    let lbn = first - start;
    let pkt = lbn - lbn % packet;

    // Both sparing tables (from the map), and an available spare in them.
    let tables = [112usize, 32752];
    let t0 = tables[0] * BS;
    let count = u16_at(&img, t0 + 48) as usize;
    let slot = (0..count)
        .find(|&i| u32_at(&img, t0 + 56 + 8 * i) == 0xFFFF_FFFF)
        .expect("an available spare");
    let spare = u32_at(&img, t0 + 56 + 8 * slot + 4) as usize;

    // Move the packet to the spare, blank where it was, record the move.
    let from = (start + pkt) * BS;
    let bytes = img[from..from + packet * BS].to_vec();
    img[spare * BS..spare * BS + packet * BS].copy_from_slice(&bytes);
    img[from..from + packet * BS].fill(0);
    for t in tables {
        let o = t * BS + 56 + 8 * slot;
        img[o..o + 4].copy_from_slice(&(pkt as u32).to_le_bytes());
        let len = 16 + u16_at(&img, t * BS + 10) as usize;
        reseal(&mut img[t * BS..t * BS + len]);
    }

    let (out, vol) = read_bytes(img, name);
    assert_eq!(vol["sparing_relocated_packets"], 1);
    assert_payload(name, &out, &vol, &key);
}

#[test]
fn unreadable_main_metadata_file_falls_back_to_its_mirror() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    let key = answer_key(&dir);
    const BS: usize = 2048;
    let name = "metadata_bdre_udf250_32m.img";
    let mut img = load(&dir, name);
    // partition-maps.txt: the metadata file is partition block 1; the
    // partition starts at 384.
    let at = (384 + 1) * BS;
    assert_eq!(u16_at(&img, at), 266, "the main metadata file is an EFE");
    img[at + 20] ^= 0xFF; // inside the CRC: the tag no longer verifies
    let (out, vol) = read_bytes(img, name);
    assert_eq!(vol["metadata_file_read"], "mirror");
    assert_eq!(vol["metadata_main_file_error"], "descriptor_crc_mismatch");
    assert_payload(name, &out, &vol, &key);
}

#[test]
fn earlier_vat_is_located_and_counted_not_walked() {
    // An earlier session's VAT, modelled by pointing the newest VAT's
    // previous-VAT field at another of the VAT File Entries makefs wrote,
    // re-made to hold a copy of the table with no predecessor.
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_UDF_IMAGES") else {
        return;
    };
    let key = answer_key(&dir);
    const BS: usize = 2048;
    let name = "vat_dvdr_udf201.img";
    let mut img = load(&dir, name);
    let (_, vol) = read_bytes(img.clone(), name);
    assert!(vol.get("vat_earlier_icb_lbns").is_none());
    let start = vol["partition_start"].as_u64().unwrap() as usize;
    let vat_fe = vol["vat_block"].as_u64().unwrap() as usize * BS;
    // The newest VAT's table: one long_ad in the EFE (AD area at 216).
    let table_lbn = u32_at(&img, vat_fe + 216 + 4) as usize;
    let table = (start + table_lbn) * BS;
    // The earlier VAT File Entry: the one makefs wrote before the newest,
    // re-made to embed a copy of the table (ICB flags 3) with no
    // predecessor.
    let info_len = u64::from_le_bytes(img[vat_fe + 56..vat_fe + 64].try_into().unwrap()) as usize;
    let mut copy = img[table..table + info_len].to_vec();
    copy[132..136].copy_from_slice(&u32::MAX.to_le_bytes());
    let earlier_fe = vat_fe - BS;
    let earlier_lbn = u32_at(&img, earlier_fe + 12);
    let flags = u16_at(&img, earlier_fe + 34) & !7 | 3;
    img[earlier_fe + 34..earlier_fe + 36].copy_from_slice(&flags.to_le_bytes());
    img[earlier_fe + 212..earlier_fe + 216].copy_from_slice(&(info_len as u32).to_le_bytes());
    img[earlier_fe + 216..earlier_fe + 216 + info_len].copy_from_slice(&copy);
    let crc_len = (216 + info_len - 16) as u16;
    img[earlier_fe + 10..earlier_fe + 12].copy_from_slice(&crc_len.to_le_bytes());
    reseal(&mut img[earlier_fe..earlier_fe + 216 + info_len]);
    // The newest table names it as its predecessor.
    img[table + 132..table + 136].copy_from_slice(&earlier_lbn.to_le_bytes());

    let (out, vol) = read_bytes(img, name);
    assert_eq!(vol["vat_earlier_icb_lbns"], json!([earlier_lbn]));
    assert_eq!(vol["vat_earlier_states_not_walked"], true);
    assert!(vol.get("vat_earlier_chain_stopped").is_none(), "{vol}");
    assert_payload(name, &out, &vol, &key);
}
