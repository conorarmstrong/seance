//! The TrueCrypt/VeraCrypt stage: the driver's presence decided from the
//! module list, and the key-schedule sweep that runs only when it is there.

use super::truecrypt::*;
use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::{MemoryLayer, PhysicalLayer};

fn layer(bytes: Vec<u8>) -> Arc<dyn MemoryLayer> {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"))
}

/// FIPS-197 Appendix A.3's AES-256 key, whose expansion is the standard's own
/// worked example: a schedule the scanner must recognise.
const FIPS_AES256_KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

fn modules(names: &[&str]) -> Vec<DriverCandidate> {
    names
        .iter()
        .enumerate()
        .map(|(i, name)| DriverCandidate {
            name: Some((*name).to_string()),
            base: Some(0xFFFF_F800_0000_0000 + i as u64 * 0x10_0000),
            size: Some(0x8_0000),
        })
        .collect()
}

/// **No driver on the module list is the answer on a clean machine**, stated
/// with how many modules were walked and whether the list was whole, and no
/// sweep runs.
#[test]
fn an_absent_driver_is_the_answer_and_no_sweep_runs() {
    let out = survey_truecrypt(
        &modules(&["ntoskrnl.exe", "hal.dll", "tcpip.sys"]),
        true,
        None,
        &TrueCryptConfig::default(),
    );
    assert!(matches!(
        out.driver,
        DriverPresence::Absent {
            modules_walked: 3,
            list_complete: true
        }
    ));
    assert!(out.sweep.is_none());
    assert!(out.is_complete());
    let json = out.to_json();
    assert_eq!(json["driver_present"], serde_json::json!(false));
    assert_eq!(json["sweep_ran"], serde_json::json!(false));
}

/// **A module list that did not walk end to end cannot clear the machine**:
/// the driver is reported as not found on a partial list, and the record is
/// incomplete.
#[test]
fn a_partial_module_list_does_not_clear_the_machine() {
    let out = survey_truecrypt(
        &modules(&["ntoskrnl.exe"]),
        false,
        None,
        &TrueCryptConfig::default(),
    );
    assert!(matches!(
        out.driver,
        DriverPresence::Absent {
            list_complete: false,
            ..
        }
    ));
    assert!(!out.is_complete());
}

/// **The driver is recognised by name, case-insensitively**, for both the
/// TrueCrypt and the VeraCrypt spelling.
#[test]
fn the_driver_is_recognised_by_either_name() {
    for name in ["truecrypt.sys", "VeraCrypt.sys", "TRUECRYPT.SYS"] {
        let out = survey_truecrypt(
            &modules(&["ntoskrnl.exe", name]),
            true,
            None,
            &TrueCryptConfig::default(),
        );
        match &out.driver {
            DriverPresence::Present { name: found, .. } => assert_eq!(found, name),
            other => panic!("{name}: expected the driver, got {other:?}"),
        }
    }
}

/// **With the driver present, the sweep finds a verified schedule**: the
/// standard's own AES-256 expansion placed in the swept region is reported at
/// its address with its key size, and the key itself stays off the record.
#[test]
fn with_the_driver_present_a_verified_schedule_is_found_and_hashed() {
    let mut bytes = vec![0u8; 0x8000];
    let schedule = seance_bulk::aes::expand_key(&FIPS_AES256_KEY);
    assert_eq!(schedule.len(), 240);
    bytes[0x1000..0x10F0].copy_from_slice(&schedule);
    let region = SweepRegion {
        layer: layer(bytes),
        base: 0,
        bytes: 0x8000,
        description: "a test region".to_string(),
    };
    let out = survey_truecrypt(
        &modules(&["ntoskrnl.exe", "truecrypt.sys"]),
        true,
        Some(region),
        &TrueCryptConfig::default(),
    );
    let sweep = out.sweep.as_ref().expect("the sweep ran");
    assert_eq!(sweep.schedules.len(), 1);
    let found = &sweep.schedules[0];
    assert_eq!(found.address, 0x1000);
    assert_eq!(found.bits, 256);
    assert_eq!(found.key_sha256.len(), 64);
    assert_eq!(sweep.bytes_scanned, 0x8000);
    let json = out.to_json();
    assert_eq!(json["sweep_ran"], serde_json::json!(true));
    let text = json.to_string();
    assert!(
        !text.contains("603deb10"),
        "the key bytes must not appear on the record"
    );
}

/// **Two AES-256 schedules close together are reported as a possible XTS
/// pair, labelled as an inference**, never as a recovered volume key.
#[test]
fn two_adjacent_schedules_are_reported_as_a_possible_pair_labelled_as_inference() {
    let mut bytes = vec![0u8; 0x8000];
    let first = seance_bulk::aes::expand_key(&FIPS_AES256_KEY);
    let mut second_key = FIPS_AES256_KEY;
    second_key[0] ^= 0xFF;
    let second = seance_bulk::aes::expand_key(&second_key);
    bytes[0x1000..0x10F0].copy_from_slice(&first);
    bytes[0x1100..0x11F0].copy_from_slice(&second);
    let region = SweepRegion {
        layer: layer(bytes),
        base: 0,
        bytes: 0x8000,
        description: "a test region".to_string(),
    };
    let out = survey_truecrypt(
        &modules(&["truecrypt.sys"]),
        true,
        Some(region),
        &TrueCryptConfig::default(),
    );
    let sweep = out.sweep.as_ref().expect("the sweep ran");
    assert_eq!(sweep.schedules.len(), 2);
    assert_eq!(sweep.possible_xts_pairs.len(), 1);
    assert_eq!(sweep.possible_xts_pairs[0], (0x1000, 0x1100));
    let json = out.to_json();
    assert!(json["sweep"]["pairs_basis"]
        .as_str()
        .unwrap_or_default()
        .contains("inference"));
}

/// **The driver present and no region to sweep** is a sweep that did not run,
/// with the reason, never a machine with no keys in memory.
#[test]
fn the_driver_present_with_no_region_is_a_sweep_that_did_not_run() {
    let out = survey_truecrypt(
        &modules(&["veracrypt.sys"]),
        true,
        None,
        &TrueCryptConfig::default(),
    );
    assert!(matches!(out.driver, DriverPresence::Present { .. }));
    assert!(out.sweep.is_none());
    assert!(!out.is_complete());
    let json = out.to_json();
    assert_eq!(json["sweep_ran"], serde_json::json!(false));
    assert!(json["sweep_did_not_run_because"]
        .as_str()
        .unwrap_or_default()
        .contains("region"));
}

/// A layer whose short reads -- the key-sized re-read after a hit, not the
/// scan's chunk reads -- fail, standing in for a page that went away between
/// the sweep's read and the hash.
#[derive(Debug)]
struct ShortReadsFail {
    inner: Arc<dyn MemoryLayer>,
    max_failing_len: usize,
}

impl DataSource for ShortReadsFail {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() <= self.max_failing_len {
            return Err(std::io::Error::other("the page is gone"));
        }
        self.inner.as_data_source().read_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.as_data_source().size()
    }
}

impl MemoryLayer for ShortReadsFail {
    fn min_address(&self) -> u64 {
        self.inner.min_address()
    }
    fn max_address(&self) -> u64 {
        self.inner.max_address()
    }
    fn mapping(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<seance_memory::MappedRange>, seance_memory::LayerError> {
        self.inner.mapping(offset, length)
    }
    fn layer_meta(&self) -> &seance_memory::LayerMeta {
        self.inner.layer_meta()
    }
    fn as_data_source(&self) -> &dyn DataSource {
        self
    }
}

/// **A verified schedule whose key will not re-read is counted, not
/// dropped**: the sweep saw it, so the record lists its address and size
/// with the hash it could not make, and the survey is incomplete by that
/// number.
#[test]
fn a_schedule_whose_key_will_not_re_read_is_counted_not_dropped() {
    let mut bytes = vec![0u8; 0x8000];
    let schedule = seance_bulk::aes::expand_key(&FIPS_AES256_KEY);
    bytes[0x1000..0x10F0].copy_from_slice(&schedule);
    let flaky: Arc<dyn MemoryLayer> = Arc::new(ShortReadsFail {
        inner: layer(bytes),
        max_failing_len: 32,
    });
    let region = SweepRegion {
        layer: flaky,
        base: 0,
        bytes: 0x8000,
        description: "a test region".to_string(),
    };
    let out = survey_truecrypt(
        &modules(&["truecrypt.sys"]),
        true,
        Some(region),
        &TrueCryptConfig::default(),
    );
    let sweep = out.sweep.as_ref().expect("the sweep ran");
    assert!(sweep.schedules.is_empty(), "no hash could be made");
    assert_eq!(sweep.schedules_unhashed.len(), 1);
    assert_eq!(sweep.schedules_unhashed[0].address, 0x1000);
    assert_eq!(sweep.schedules_unhashed[0].bits, 256);
    assert!(!out.is_complete(), "a schedule without its hash is a gap");
    let json = out.to_json();
    assert_eq!(
        json["sweep"]["schedules_unhashed_total"],
        serde_json::json!(1)
    );
    assert!(json["incomplete"]
        .as_array()
        .expect("incomplete is a list")
        .iter()
        .any(|i| i.to_string().contains("could not be re-read")));
}

// ---------------------------------------------------------------------------
// CRYPTO_INFO container (MEM-044). The layout was read empirically from the
// VeraCrypt 1.26.29 / Windows 11 26200 capture (see VALIDATION.md MEM-VC-2):
// three dwords at offset 0 (cipher id, mode id, a third not decoded), the
// primary schedule at +0x10 and the secondary 5,312 bytes after it. The
// images below are SYNTHETIC: they reproduce that observed shape from FIPS-197
// schedules and grade the decoder's mechanics only, never a claim about real
// evidence.
// ---------------------------------------------------------------------------

/// Build a synthetic container: header dwords at `base`, schedules at
/// `base + 0x10` and `base + 0x10 + 5312`.
fn synthetic_container(base: usize, ea: u32, mode: u32, secondary_is_schedule: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x4000];
    bytes[base..base + 4].copy_from_slice(&ea.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&mode.to_le_bytes());
    bytes[base + 8..base + 12].copy_from_slice(&1u32.to_le_bytes());
    let first = seance_bulk::aes::expand_key(&FIPS_AES256_KEY);
    let mut second_key = FIPS_AES256_KEY;
    second_key[0] ^= 0xFF;
    let second = seance_bulk::aes::expand_key(&second_key);
    let p = base + 0x10;
    bytes[p..p + 240].copy_from_slice(&first);
    let s = p + 5312;
    if secondary_is_schedule {
        bytes[s..s + 240].copy_from_slice(&second);
    } else {
        bytes[s..s + 240].fill(0x5A);
    }
    bytes
}

fn sweep_of(bytes: Vec<u8>) -> KeySweep {
    let region = SweepRegion {
        layer: layer(bytes),
        base: 0,
        bytes: 0x4000,
        description: "a test region".to_string(),
    };
    survey_truecrypt(
        &modules(&["veracrypt.sys"]),
        true,
        Some(region),
        &TrueCryptConfig::default(),
    )
    .sweep
    .expect("the sweep ran")
}

/// **A container whose header and two schedules sit in the observed layout is
/// decoded**: cipher AES, mode XTS, primary and secondary named in order.
#[test]
fn a_container_in_the_observed_layout_is_decoded_with_primary_and_secondary() {
    let sweep = sweep_of(synthetic_container(0x400, 1, 1, true));
    assert_eq!(sweep.crypto_infos.len(), 1);
    let info = &sweep.crypto_infos[0];
    assert_eq!(info.address, 0x400);
    assert_eq!(info.cipher_id, 1);
    assert_eq!(info.cipher, Some("AES"));
    assert_eq!(info.mode_id, 1);
    assert_eq!(info.mode, Some("XTS"));
    assert_eq!(info.primary_schedule, 0x410);
    assert_eq!(info.secondary_schedule, 0x410 + 5312);
    let json = sweep.to_json();
    assert_eq!(json["crypto_infos"][0]["cipher"], serde_json::json!("AES"));
    assert_eq!(json["crypto_infos_total"], serde_json::json!(1));
}

/// **A secondary position that is not a verified schedule yields no
/// container.**
#[test]
fn a_secondary_that_is_not_a_schedule_yields_no_crypto_info() {
    let sweep = sweep_of(synthetic_container(0x400, 1, 1, false));
    assert!(sweep.crypto_infos.is_empty());
}

/// **A cipher or mode id of zero or far out of range is not a container.**
#[test]
fn an_out_of_range_cipher_or_mode_id_yields_no_crypto_info() {
    assert!(sweep_of(synthetic_container(0x400, 0, 1, true))
        .crypto_infos
        .is_empty());
    assert!(sweep_of(synthetic_container(0x400, 0x4141_4141, 1, true))
        .crypto_infos
        .is_empty());
    assert!(sweep_of(synthetic_container(0x400, 1, 0, true))
        .crypto_infos
        .is_empty());
}

/// **A schedule too near the start of the region to have a header before it
/// is not decoded**, and the read does not wrap.
#[test]
fn a_schedule_with_no_room_for_a_header_yields_no_crypto_info() {
    let mut bytes = vec![0u8; 0x4000];
    let first = seance_bulk::aes::expand_key(&FIPS_AES256_KEY);
    let mut second_key = FIPS_AES256_KEY;
    second_key[0] ^= 0xFF;
    let second = seance_bulk::aes::expand_key(&second_key);
    bytes[0x8..0x8 + 240].copy_from_slice(&first);
    bytes[0x8 + 5312..0x8 + 5312 + 240].copy_from_slice(&second);
    assert!(sweep_of(bytes).crypto_infos.is_empty());
}

/// **An id the observation does not explain is published raw and unnamed.**
#[test]
fn an_unobserved_cipher_id_is_published_raw_and_unnamed() {
    let sweep = sweep_of(synthetic_container(0x400, 7, 1, true));
    let info = &sweep.crypto_infos[0];
    assert_eq!(info.cipher_id, 7);
    assert_eq!(info.cipher, None);
    assert_eq!(info.mode, Some("XTS"));
}

/// Build a synthetic container in the **VeraCrypt 1.25.9** layout observed on a second capture
/// (`VALIDATION.md` `MEM-VC-3`): header dwords at `base`, the primary schedule at `base + 0x0c`
/// and the secondary 5,304 bytes after it.
fn synthetic_container_1259(base: usize, ea: u32, mode: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x4000];
    bytes[base..base + 4].copy_from_slice(&ea.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&mode.to_le_bytes());
    bytes[base + 8..base + 12].copy_from_slice(&1u32.to_le_bytes());
    let first = seance_bulk::aes::expand_key(&FIPS_AES256_KEY);
    let mut second_key = FIPS_AES256_KEY;
    second_key[0] ^= 0xFF;
    let second = seance_bulk::aes::expand_key(&second_key);
    let p = base + 0x0c;
    bytes[p..p + 240].copy_from_slice(&first);
    bytes[p + 5304..p + 5304 + 240].copy_from_slice(&second);
    bytes
}

/// **A container in the layout observed on VeraCrypt 1.25.9 is decoded too, and says which
/// layout it matched**; the 1.26.29 layout still reads as before and says so.
#[test]
fn a_container_in_the_1_25_9_layout_is_decoded_and_names_its_layout() {
    let sweep = sweep_of(synthetic_container_1259(0x400, 1, 1));
    assert_eq!(sweep.crypto_infos.len(), 1);
    let info = &sweep.crypto_infos[0];
    assert_eq!(info.address, 0x400);
    assert_eq!(info.cipher, Some("AES"));
    assert_eq!(info.mode, Some("XTS"));
    assert_eq!(info.primary_schedule, 0x40c);
    assert_eq!(info.secondary_schedule, 0x40c + 5304);
    assert_eq!(
        info.layout,
        "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)"
    );
    assert_eq!(
        sweep.to_json()["crypto_infos"][0]["layout"],
        serde_json::json!("VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)")
    );
    let old = sweep_of(synthetic_container(0x400, 1, 1, true));
    assert_eq!(
        old.crypto_infos[0].layout,
        "VeraCrypt 1.26.29 to 1.26.30 (observed on 1.26.29, 1.26.30)"
    );
}

// ---------------------------------------------------------------------------
// Serpent and Twofish (MEM-044). Synthetic regions built from the expansions graded against
// pyserpent and the Twofish reference library (`seance_bulk`), laid out as the VeraCrypt 1.25.9
// capture of `VALIDATION.md` MEM-VC-3 showed: a container whose header is `[id, mode, 1]`, a key
// schedule buffer from `+0x0c` (Serpent, then Twofish's tables and subkeys, then AES), and the tweak
// keys' copy 5,304 bytes on. They grade the mechanics, never a claim about real evidence.
// ---------------------------------------------------------------------------

const SERPENT_KEY: [u8; 32] = *b"serpent-primary-key-0123456789ab";
const SERPENT_KEY2: [u8; 32] = *b"serpent-tweak---key-0123456789ab";
const TWOFISH_KEY: [u8; 32] = *b"twofish-primary-key-0123456789ab";
const TWOFISH_KEY2: [u8; 32] = *b"twofish-tweak---key-0123456789ab";

fn serpent_bytes(key: &[u8; 32]) -> Vec<u8> {
    seance_bulk::serpent::expand_key(key)
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

fn twofish_bytes(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    for w in seance_bulk::twofish::mk_tab(key) {
        out.extend_from_slice(&w.to_le_bytes());
    }
    for w in seance_bulk::twofish::subkeys(key) {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn sha_hex(key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(key))
}

/// A 1.25.9 container at `base` in a 0x4_0000-byte region: header `[id, 1, 1]`, then the primary
/// schedules `members` back to back from `base + 0x0c`, and the secondary schedules 5,304 bytes on.
fn container_1259(id: u32, members: &[(&str, [u8; 32], [u8; 32])]) -> Vec<u8> {
    let base = 0x1000usize;
    let mut bytes = vec![0u8; 0x4_0000];
    bytes[base..base + 4].copy_from_slice(&id.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&1u32.to_le_bytes());
    bytes[base + 8..base + 12].copy_from_slice(&1u32.to_le_bytes());
    let mut at = base + 0x0c;
    for (cipher, primary, secondary) in members {
        let (p, q, len) = match *cipher {
            "Serpent" => (serpent_bytes(primary), serpent_bytes(secondary), 560),
            "Twofish" => (twofish_bytes(primary), twofish_bytes(secondary), 4256),
            "Camellia" => (camellia_bytes(primary), camellia_bytes(secondary), 272),
            "Kuznyechik" => (kuznyechik_bytes(primary), kuznyechik_bytes(secondary), 320),
            _ => (
                seance_bulk::aes::expand_key(primary),
                seance_bulk::aes::expand_key(secondary),
                488,
            ),
        };
        bytes[at..at + p.len()].copy_from_slice(&p);
        bytes[at + 5304..at + 5304 + q.len()].copy_from_slice(&q);
        at += len;
    }
    bytes
}

fn sweep_bytes(bytes: Vec<u8>) -> KeySweep {
    sweep_of(bytes)
}

/// **A Serpent schedule in the pool is found, named, and hashed by its key.**
#[test]
fn a_serpent_schedule_is_found_with_its_cipher_and_key_hash() {
    let sweep = sweep_bytes(container_1259(2, &[("Serpent", SERPENT_KEY, SERPENT_KEY2)]));
    let found: Vec<_> = sweep
        .schedules
        .iter()
        .filter(|s| s.cipher == "Serpent")
        .collect();
    assert_eq!(found.len(), 2, "{:?}", sweep.schedules);
    assert!(found.iter().any(|s| s.key_sha256 == sha_hex(&SERPENT_KEY)));
    assert!(found.iter().any(|s| s.key_sha256 == sha_hex(&SERPENT_KEY2)));
    assert!(sweep.possible_xts_pairs.iter().any(|(a, b)| b - a == 5304));
}

/// **A Twofish schedule is found and its key recovered from the subkeys**, the key being stored nowhere.
#[test]
fn a_twofish_schedule_is_found_and_its_key_recovered_for_the_hash() {
    let sweep = sweep_bytes(container_1259(
        7, // an id nothing has observed: only the schedules are claimed
        &[("Twofish", TWOFISH_KEY, TWOFISH_KEY2)],
    ));
    let found: Vec<_> = sweep
        .schedules
        .iter()
        .filter(|s| s.cipher == "Twofish")
        .collect();
    assert_eq!(found.len(), 2, "{:?}", sweep.schedules);
    assert!(found.iter().any(|s| s.key_sha256 == sha_hex(&TWOFISH_KEY)));
    assert!(found.iter().any(|s| s.key_sha256 == sha_hex(&TWOFISH_KEY2)));
    assert!(
        sweep.crypto_infos.is_empty(),
        "an unobserved id names no container"
    );
}

/// **A Serpent volume's container is decoded** (id 2): cipher named, mode XTS, both keys.
#[test]
fn a_serpent_volume_container_is_decoded_with_both_keys() {
    let sweep = sweep_bytes(container_1259(2, &[("Serpent", SERPENT_KEY, SERPENT_KEY2)]));
    assert_eq!(sweep.crypto_infos.len(), 1, "{:?}", sweep.crypto_infos);
    let info = &sweep.crypto_infos[0];
    assert_eq!(
        (info.cipher_id, info.cipher, info.mode),
        (2, Some("Serpent"), Some("XTS"))
    );
    assert_eq!(
        info.layout,
        "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)"
    );
    assert_eq!(info.members.len(), 1);
    assert_eq!(info.members[0].primary_key_sha256, sha_hex(&SERPENT_KEY));
    assert_eq!(info.members[0].secondary_key_sha256, sha_hex(&SERPENT_KEY2));
}

/// **An AES-Twofish-Serpent cascade's container is decoded with all three layers' keys** (id 8).
#[test]
fn a_three_cipher_cascade_container_is_decoded_with_every_layers_keys() {
    let aes_p: [u8; 32] = *b"aes-primary---key-0123456789abcd";
    let aes_s: [u8; 32] = *b"aes-tweak-----key-0123456789abcd";
    let sweep = sweep_bytes(container_1259(
        8,
        &[
            ("Serpent", SERPENT_KEY, SERPENT_KEY2),
            ("Twofish", TWOFISH_KEY, TWOFISH_KEY2),
            ("AES", aes_p, aes_s),
        ],
    ));
    assert_eq!(sweep.crypto_infos.len(), 1, "{:?}", sweep.crypto_infos);
    let info = &sweep.crypto_infos[0];
    assert_eq!(
        (info.cipher_id, info.cipher),
        (8, Some("AES-Twofish-Serpent"))
    );
    let by: std::collections::BTreeMap<_, _> = info.members.iter().map(|m| (m.cipher, m)).collect();
    assert_eq!(by["Serpent"].primary_key_sha256, sha_hex(&SERPENT_KEY));
    assert_eq!(by["Twofish"].primary_key_sha256, sha_hex(&TWOFISH_KEY));
    assert_eq!(by["Twofish"].secondary_key_sha256, sha_hex(&TWOFISH_KEY2));
    assert_eq!(by["AES"].primary_key_sha256, sha_hex(&aes_p));
    assert_eq!(by["AES"].secondary_key_sha256, sha_hex(&aes_s));
    // The AES layer of the cascade is not also published as a lone AES volume's container.
    assert_eq!(sweep.crypto_infos.len(), 1);
}

/// **A cascade missing a layer is not decoded as one**: no container is claimed from two of three.
#[test]
fn a_cascade_with_a_layer_missing_is_not_decoded() {
    let sweep = sweep_bytes(container_1259(
        8,
        &[
            ("Serpent", SERPENT_KEY, SERPENT_KEY2),
            ("Twofish", TWOFISH_KEY, TWOFISH_KEY2),
        ],
    ));
    assert!(sweep.crypto_infos.is_empty(), "{:?}", sweep.crypto_infos);
    assert_eq!(
        sweep
            .schedules
            .iter()
            .filter(|s| s.cipher == "Serpent")
            .count(),
        2
    );
}

/// **Every container shape seen on 1.25.9 is decoded with its layers in the order the buffer holds them**: a
/// cascade's schedules lie in the reverse of its name's order (`VALIDATION.md` `MEM-VC-3`). SYNTHETIC, one
/// container per id; the real capture pins the same table.
#[test]
fn each_observed_container_id_is_decoded_with_its_layers_in_buffer_order() {
    let aes = |n: u8| -> ([u8; 32], [u8; 32]) { ([n; 32], [n + 1; 32]) };
    // (id, name, buffer order)
    let cases: [(u32, &str, &[&str]); 5] = [
        (3, "Twofish", &["Twofish"]),
        (7, "AES-Twofish", &["Twofish", "AES"]),
        (9, "Serpent-AES", &["AES", "Serpent"]),
        (10, "Serpent-Twofish-AES", &["AES", "Twofish", "Serpent"]),
        (11, "Twofish-Serpent", &["Serpent", "Twofish"]),
    ];
    for (id, name, order) in cases {
        let members: Vec<(&str, [u8; 32], [u8; 32])> = order
            .iter()
            .map(|c| match *c {
                "Serpent" => ("Serpent", SERPENT_KEY, SERPENT_KEY2),
                "Twofish" => ("Twofish", TWOFISH_KEY, TWOFISH_KEY2),
                _ => ("AES", aes(0x40).0, aes(0x40).1),
            })
            .collect();
        let sweep = sweep_bytes(container_1259(id, &members));
        assert_eq!(
            sweep.crypto_infos.len(),
            1,
            "{name}: {:?}",
            sweep.crypto_infos
        );
        let info = &sweep.crypto_infos[0];
        assert_eq!((info.cipher_id, info.cipher), (id, Some(name)), "{name}");
        let got: Vec<&str> = info.members.iter().map(|m| m.cipher).collect();
        assert_eq!(got, order, "{name}: members in buffer order");
        for m in &info.members {
            let want = match m.cipher {
                "Serpent" => (sha_hex(&SERPENT_KEY), sha_hex(&SERPENT_KEY2)),
                "Twofish" => (sha_hex(&TWOFISH_KEY), sha_hex(&TWOFISH_KEY2)),
                _ => (sha_hex(&aes(0x40).0), sha_hex(&aes(0x40).1)),
            };
            assert_eq!(
                (m.primary_key_sha256.clone(), m.secondary_key_sha256.clone()),
                want,
                "{name} {}",
                m.cipher
            );
        }
    }
}

const CAMELLIA_KEY: [u8; 32] = *b"camellia-primary-key-0123456789a";
const CAMELLIA_KEY2: [u8; 32] = *b"camellia-tweak-key-0123456789abc";
const KUZNYECHIK_KEY: [u8; 32] = *b"kuznyechik-primary-key-012345678";
const KUZNYECHIK_KEY2: [u8; 32] = *b"kuznyechik-tweak-key-0123456789a";

/// A Camellia table whose `ke` subkeys are the key's (the only words the recogniser reads) and whose other
/// words are filler, as 272 bytes of 32-bit little-endian words.
fn camellia_bytes(key: &[u8; 32]) -> Vec<u8> {
    let mut t = vec![0x6Bu8; 272];
    for (slot, k) in [8usize, 9, 16, 17, 24, 25]
        .iter()
        .zip(seance_bulk::camellia::ke_words(key))
    {
        t[8 * slot..8 * slot + 4].copy_from_slice(&((k >> 32) as u32).to_le_bytes());
        t[8 * slot + 4..8 * slot + 8].copy_from_slice(&(k as u32).to_le_bytes());
    }
    t
}

fn kuznyechik_bytes(key: &[u8; 32]) -> Vec<u8> {
    // The encryption round keys, then 160 bytes of the decryption keys (filler here).
    let mut t = seance_bulk::kuznyechik::expand_key(key).concat();
    t.extend(std::iter::repeat_n(0x77, 160));
    t
}

/// A VeraCrypt 1.26.29 container: header of four dwords, buffer at `+0x10`, tweak keys 5,312 bytes on.
fn container_1260(id: u32, members: &[(&str, [u8; 32], [u8; 32])]) -> Vec<u8> {
    let base = 0x1000usize;
    let mut bytes = vec![0u8; 0x4_0000];
    bytes[base..base + 4].copy_from_slice(&id.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&1u32.to_le_bytes());
    bytes[base + 8..base + 12].copy_from_slice(&1u32.to_le_bytes());
    let mut at = base + 0x10;
    for (cipher, primary, secondary) in members {
        let (p, q, len) = match *cipher {
            "Serpent" => (serpent_bytes(primary), serpent_bytes(secondary), 560),
            "Twofish" => (twofish_bytes(primary), twofish_bytes(secondary), 4256),
            "Camellia" => (camellia_bytes(primary), camellia_bytes(secondary), 272),
            "Kuznyechik" => (kuznyechik_bytes(primary), kuznyechik_bytes(secondary), 320),
            _ => (
                seance_bulk::aes::expand_key(primary),
                seance_bulk::aes::expand_key(secondary),
                488,
            ),
        };
        bytes[at..at + p.len()].copy_from_slice(&p);
        bytes[at + 5312..at + 5312 + q.len()].copy_from_slice(&q);
        at += len;
    }
    bytes
}

/// **Camellia and Kuznyechik schedules are found and hashed by their keys.**
#[test]
fn camellia_and_kuznyechik_schedules_are_found_with_their_key_hashes() {
    let sweep = sweep_bytes(container_1260(
        11,
        &[
            ("Kuznyechik", KUZNYECHIK_KEY, KUZNYECHIK_KEY2),
            ("Camellia", CAMELLIA_KEY, CAMELLIA_KEY2),
        ],
    ));
    for (cipher, a, b) in [
        ("Camellia", CAMELLIA_KEY, CAMELLIA_KEY2),
        ("Kuznyechik", KUZNYECHIK_KEY, KUZNYECHIK_KEY2),
    ] {
        let found: Vec<_> = sweep
            .schedules
            .iter()
            .filter(|s| s.cipher == cipher)
            .collect();
        assert_eq!(found.len(), 2, "{cipher}: {:?}", sweep.schedules);
        assert!(
            found.iter().any(|s| s.key_sha256 == sha_hex(&a)),
            "{cipher}"
        );
        assert!(
            found.iter().any(|s| s.key_sha256 == sha_hex(&b)),
            "{cipher}"
        );
    }
}

/// **Each Camellia and Kuznyechik container id of VeraCrypt 1.26.29 is decoded with its layers in buffer order**
/// (the last-named cipher first; SYNTHETIC, one container per id; `win11_veracrypt_ck.rs` pins the table on a real capture).
#[test]
fn each_camellia_and_kuznyechik_container_id_is_decoded_with_its_layers_in_buffer_order() {
    let key = |c: &str| match c {
        "Camellia" => (CAMELLIA_KEY, CAMELLIA_KEY2),
        "Kuznyechik" => (KUZNYECHIK_KEY, KUZNYECHIK_KEY2),
        "Serpent" => (SERPENT_KEY, SERPENT_KEY2),
        "Twofish" => (TWOFISH_KEY, TWOFISH_KEY2),
        _ => ([0x40u8; 32], [0x41u8; 32]),
    };
    let cases: [(u32, &str, &[&str]); 7] = [
        (4, "Camellia", &["Camellia"]),
        (5, "Kuznyechik", &["Kuznyechik"]),
        (11, "Camellia-Kuznyechik", &["Kuznyechik", "Camellia"]),
        (12, "Kuznyechik-Twofish", &["Twofish", "Kuznyechik"]),
        (13, "Camellia-Serpent", &["Serpent", "Camellia"]),
        (14, "Kuznyechik-AES", &["AES", "Kuznyechik"]),
        (
            15,
            "Kuznyechik-Serpent-Camellia",
            &["Camellia", "Serpent", "Kuznyechik"],
        ),
    ];
    for (id, name, order) in cases {
        let members: Vec<(&str, [u8; 32], [u8; 32])> =
            order.iter().map(|c| (*c, key(c).0, key(c).1)).collect();
        let sweep = sweep_bytes(container_1260(id, &members));
        assert_eq!(
            sweep.crypto_infos.len(),
            1,
            "{name}: {:?}",
            sweep.crypto_infos
        );
        let info = &sweep.crypto_infos[0];
        assert_eq!((info.cipher_id, info.cipher), (id, Some(name)), "{name}");
        let got: Vec<&str> = info.members.iter().map(|m| m.cipher).collect();
        assert_eq!(got, order, "{name}: members in buffer order");
        for m in &info.members {
            assert_eq!(
                m.primary_key_sha256,
                sha_hex(&key(m.cipher).0),
                "{name} {}",
                m.cipher
            );
            assert_eq!(
                m.secondary_key_sha256,
                sha_hex(&key(m.cipher).1),
                "{name} {}",
                m.cipher
            );
        }
    }
}

/// **The same shapes on VeraCrypt 1.25.9 carry other ids** (Kuznyechik alone is 6 there and 5 on 1.26.29, the cascades one
/// higher): each is decoded in buffer order (SYNTHETIC; `win11_veracrypt_ck1259.rs` pins the table on a real capture).
#[test]
fn each_camellia_and_kuznyechik_container_id_of_1259_is_decoded_with_its_layers_in_buffer_order() {
    let key = |c: &str| match c {
        "Camellia" => (CAMELLIA_KEY, CAMELLIA_KEY2),
        "Kuznyechik" => (KUZNYECHIK_KEY, KUZNYECHIK_KEY2),
        "Serpent" => (SERPENT_KEY, SERPENT_KEY2),
        "Twofish" => (TWOFISH_KEY, TWOFISH_KEY2),
        _ => ([0x40u8; 32], [0x41u8; 32]),
    };
    let cases: [(u32, &str, &[&str]); 7] = [
        (4, "Camellia", &["Camellia"]),
        (6, "Kuznyechik", &["Kuznyechik"]),
        (12, "Camellia-Kuznyechik", &["Kuznyechik", "Camellia"]),
        (13, "Kuznyechik-Twofish", &["Twofish", "Kuznyechik"]),
        (14, "Camellia-Serpent", &["Serpent", "Camellia"]),
        (15, "Kuznyechik-AES", &["AES", "Kuznyechik"]),
        (
            16,
            "Kuznyechik-Serpent-Camellia",
            &["Camellia", "Serpent", "Kuznyechik"],
        ),
    ];
    for (id, name, order) in cases {
        let members: Vec<(&str, [u8; 32], [u8; 32])> =
            order.iter().map(|c| (*c, key(c).0, key(c).1)).collect();
        let sweep = sweep_bytes(container_1259(id, &members));
        assert_eq!(
            sweep.crypto_infos.len(),
            1,
            "{name}: {:?}",
            sweep.crypto_infos
        );
        let info = &sweep.crypto_infos[0];
        assert_eq!((info.cipher_id, info.cipher), (id, Some(name)), "{name}");
        let got: Vec<&str> = info.members.iter().map(|m| m.cipher).collect();
        assert_eq!(got, order, "{name}: members in buffer order");
    }
}

/// TrueCrypt 7.1a's Twofish structure: the subkeys, `S` reversed, the four tables interleaved, then `k_len`.
fn twofish_tc_bytes(key: &[u8; 32]) -> Vec<u8> {
    let k = seance_bulk::twofish::subkeys(key);
    let s = seance_bulk::twofish::s_vector(key);
    let mk = seance_bulk::twofish::mk_tab(key);
    let mut words: Vec<u32> = k.to_vec();
    words.extend([s[3], s[2], s[1], s[0]]);
    for x in 0..256 {
        for j in 0..4 {
            words.push(mk[j * 256 + x]);
        }
    }
    words.push(8);
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// A TrueCrypt 7.1a container: algorithm and mode dwords, buffer at `+0x08`, tweak keys 5,324 bytes on.
fn container_tc71a(id: u32, members: &[(&str, [u8; 32], [u8; 32])]) -> Vec<u8> {
    container_tc_style(id, members, 0x08)
}

/// A VeraCrypt 1.12 container (`MEM-VC-7`): TrueCrypt's ids and distance with a third header dword, buffer at `+0x0c`.
fn container_vc112(id: u32, members: &[(&str, [u8; 32], [u8; 32])]) -> Vec<u8> {
    container_tc_style(id, members, 0x0c)
}

fn container_tc_style(
    id: u32,
    members: &[(&str, [u8; 32], [u8; 32])],
    buffer_offset: usize,
) -> Vec<u8> {
    let base = 0x1000usize;
    let mut bytes = vec![0u8; 0x4_0000];
    bytes[base..base + 4].copy_from_slice(&id.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&1u32.to_le_bytes());
    if buffer_offset == 0x0c {
        bytes[base + 8..base + 12].copy_from_slice(&1u32.to_le_bytes());
    }
    let mut at = base + buffer_offset;
    for (cipher, primary, secondary) in members {
        let (p, q, len) = match *cipher {
            "Serpent" => (serpent_bytes(primary), serpent_bytes(secondary), 560),
            "Twofish" => (twofish_tc_bytes(primary), twofish_tc_bytes(secondary), 4276),
            _ => (
                seance_bulk::aes::expand_key(primary),
                seance_bulk::aes::expand_key(secondary),
                488,
            ),
        };
        bytes[at..at + p.len()].copy_from_slice(&p);
        bytes[at + 5324..at + 5324 + q.len()].copy_from_slice(&q);
        at += len;
    }
    bytes
}

/// **TrueCrypt 7.1a's Twofish layout is found and its key recovered**, and a VeraCrypt-layout Twofish structure
/// is not taken for it (nor the reverse): the two orders of the same data are separate recognisers.
#[test]
fn a_truecrypt_twofish_structure_is_found_and_its_key_recovered_for_the_hash() {
    let sweep = sweep_bytes(container_tc71a(
        3,
        &[("Twofish", TWOFISH_KEY, TWOFISH_KEY2)],
    ));
    let found: Vec<_> = sweep
        .schedules
        .iter()
        .filter(|s| s.cipher == "Twofish")
        .collect();
    assert_eq!(found.len(), 2, "{:?}", sweep.schedules);
    assert!(found.iter().any(|s| s.key_sha256 == sha_hex(&TWOFISH_KEY)));
    assert!(found.iter().any(|s| s.key_sha256 == sha_hex(&TWOFISH_KEY2)));
}

/// **Each TrueCrypt 7.1a algorithm id is decoded with its layers in buffer order** (the last-named cipher first;
/// SYNTHETIC, one container per id; `win11_truecrypt71a.rs` pins the table on a real capture).
#[test]
fn each_truecrypt_71a_container_id_is_decoded_with_its_layers_in_buffer_order() {
    let key = |c: &str| match c {
        "Serpent" => (SERPENT_KEY, SERPENT_KEY2),
        "Twofish" => (TWOFISH_KEY, TWOFISH_KEY2),
        _ => ([0x40u8; 32], [0x41u8; 32]),
    };
    let cases: [(u32, &str, &[&str]); 7] = [
        (2, "Serpent", &["Serpent"]),
        (3, "Twofish", &["Twofish"]),
        (4, "AES-Twofish", &["Twofish", "AES"]),
        (5, "AES-Twofish-Serpent", &["Serpent", "Twofish", "AES"]),
        (6, "Serpent-AES", &["AES", "Serpent"]),
        (7, "Serpent-Twofish-AES", &["AES", "Twofish", "Serpent"]),
        (8, "Twofish-Serpent", &["Serpent", "Twofish"]),
    ];
    for (id, name, order) in cases {
        let members: Vec<(&str, [u8; 32], [u8; 32])> =
            order.iter().map(|c| (*c, key(c).0, key(c).1)).collect();
        let sweep = sweep_bytes(container_tc71a(id, &members));
        assert_eq!(
            sweep.crypto_infos.len(),
            1,
            "{name}: {:?}",
            sweep.crypto_infos
        );
        let info = &sweep.crypto_infos[0];
        assert_eq!((info.cipher_id, info.cipher), (id, Some(name)), "{name}");
        assert_eq!(
            info.layout,
            "TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e (observed on TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1, 7.1a, 7.2 and VeraCrypt 1.0e)"
        );
        let got: Vec<&str> = info.members.iter().map(|m| m.cipher).collect();
        assert_eq!(got, order, "{name}: members in buffer order");
        for m in &info.members {
            assert_eq!(
                m.primary_key_sha256,
                sha_hex(&key(m.cipher).0),
                "{name} {}",
                m.cipher
            );
            assert_eq!(
                m.secondary_key_sha256,
                sha_hex(&key(m.cipher).1),
                "{name} {}",
                m.cipher
            );
        }
    }
}

/// **VeraCrypt 1.12's container is TrueCrypt's ids and distance with the buffer at `+0x0c`** (SYNTHETIC, one
/// container per id; `win11_veracrypt_112.rs` pins it on a real capture). The AES schedule at `+0x0c` of
/// a Serpent-AES container must not be read again as a plain AES volume of the TrueCrypt layout.
#[test]
fn each_veracrypt_112_container_id_is_decoded_once_with_its_layers_in_buffer_order() {
    let key = |c: &str| match c {
        "Serpent" => (SERPENT_KEY, SERPENT_KEY2),
        "Twofish" => (TWOFISH_KEY, TWOFISH_KEY2),
        _ => ([0x40u8; 32], [0x41u8; 32]),
    };
    let cases: [(u32, &str, &[&str]); 8] = [
        (1, "AES", &["AES"]),
        (2, "Serpent", &["Serpent"]),
        (3, "Twofish", &["Twofish"]),
        (4, "AES-Twofish", &["Twofish", "AES"]),
        (5, "AES-Twofish-Serpent", &["Serpent", "Twofish", "AES"]),
        (6, "Serpent-AES", &["AES", "Serpent"]),
        (7, "Serpent-Twofish-AES", &["AES", "Twofish", "Serpent"]),
        (8, "Twofish-Serpent", &["Serpent", "Twofish"]),
    ];
    for (id, name, order) in cases {
        let members: Vec<(&str, [u8; 32], [u8; 32])> =
            order.iter().map(|c| (*c, key(c).0, key(c).1)).collect();
        let sweep = sweep_bytes(container_vc112(id, &members));
        assert_eq!(
            sweep.crypto_infos.len(),
            1,
            "{name}: {:?}",
            sweep.crypto_infos
        );
        let info = &sweep.crypto_infos[0];
        assert_eq!(info.address, 0x1000, "{name}");
        assert_eq!((info.cipher_id, info.cipher), (id, Some(name)), "{name}");
        assert_eq!(
            info.layout,
            "VeraCrypt 1.0f to 1.18 (observed on 1.0f, 1.0f-1, 1.0f-2, 1.12, 1.13, 1.14, 1.16, 1.17, 1.18)"
        );
        let got: Vec<&str> = info.members.iter().map(|m| m.cipher).collect();
        assert_eq!(got, order, "{name}: members in buffer order");
    }
}

/// A TrueCrypt 7.1a plain AES volume is still one container in the TrueCrypt layout, not also one in 1.12's.
#[test]
fn a_truecrypt_aes_volume_is_one_container_in_the_truecrypt_layout() {
    let sweep = sweep_bytes(container_tc71a(1, &[("AES", [0x40; 32], [0x41; 32])]));
    assert_eq!(sweep.crypto_infos.len(), 1, "{:?}", sweep.crypto_infos);
    assert_eq!(
        sweep.crypto_infos[0].layout,
        "TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e (observed on TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1, 7.1a, 7.2 and VeraCrypt 1.0e)"
    );
}

/// **VeraCrypt 1.18 has 1.12's geometry and 1.25.9's ids** (SYNTHETIC; `win11_veracrypt_118.rs` pins it on a real capture).
/// The same geometry is read under two numberings, so id 8 is AES-Twofish-Serpent here (three layers) and
/// Twofish-Serpent in 1.12 (two): the layers decide, and the three-layer container is not named for its first two.
#[test]
fn each_veracrypt_118_container_id_is_decoded_once_with_its_layers_in_buffer_order() {
    let key = |c: &str| match c {
        "Serpent" => (SERPENT_KEY, SERPENT_KEY2),
        "Twofish" => (TWOFISH_KEY, TWOFISH_KEY2),
        _ => ([0x40u8; 32], [0x41u8; 32]),
    };
    let cases: [(u32, &str, &[&str]); 7] = [
        (2, "Serpent", &["Serpent"]),
        (3, "Twofish", &["Twofish"]),
        (7, "AES-Twofish", &["Twofish", "AES"]),
        (8, "AES-Twofish-Serpent", &["Serpent", "Twofish", "AES"]),
        (9, "Serpent-AES", &["AES", "Serpent"]),
        (10, "Serpent-Twofish-AES", &["AES", "Twofish", "Serpent"]),
        (11, "Twofish-Serpent", &["Serpent", "Twofish"]),
    ];
    for (id, name, order) in cases {
        let members: Vec<(&str, [u8; 32], [u8; 32])> =
            order.iter().map(|c| (*c, key(c).0, key(c).1)).collect();
        let sweep = sweep_bytes(container_vc112(id, &members));
        assert_eq!(
            sweep.crypto_infos.len(),
            1,
            "{name}: {:?}",
            sweep.crypto_infos
        );
        let info = &sweep.crypto_infos[0];
        assert_eq!((info.cipher_id, info.cipher), (id, Some(name)), "{name}");
        let got: Vec<&str> = info.members.iter().map(|m| m.cipher).collect();
        assert_eq!(got, order, "{name}: members in buffer order");
    }
}
