//! TrueCrypt and VeraCrypt in memory (`ROADMAP` §5.3, upstream's
//! `truecryptmaster` and its companions).
//!
//! # What an examiner learns
//!
//! Whether the machine was running a TrueCrypt or VeraCrypt volume driver at
//! capture, and — when it was — where in the kernel's non-paged pool the AES, Serpent
//! and Twofish key schedules that decrypt a mounted volume were. A mounted encrypted
//! volume's master key lives in RAM for as long as it is mounted, and a
//! capture taken then is the only route to it once the machine is off.
//!
//! # What this stage does, and what it does not
//!
//! The driver's presence is decided from the kernel's loaded-module list,
//! which every other kernel-side stage reads. Absent there, on a list that was
//! walked whole, is the answer on a clean machine, and no sweep runs.
//!
//! Present, the stage sweeps the kernel's non-paged pool region for AES key
//! schedules — a schedule is verified mathematically, by re-expanding its
//! leading key and comparing the rest (`seance_bulk::aes`), so a hit is a
//! real schedule and never a coincidence. **Only the schedule's address, key
//! size and the SHA-256 of the key are put on the record.** A mounted volume
//! under XTS needs two AES-256 keys, and the driver keeps their schedules
//! near each other, so two AES-256 schedules within a short distance are
//! reported as a *possible* pair. That is an inference and is labelled as
//! one. The driver's container (`CRYPTO_INFO`) was read from captures
//! alone, without consulting any driver source: a cipher id and a mode id at
//! offset 0, then the key schedule buffer, whose offset and tweak-key distance
//! differ between versions: VeraCrypt 1.26.29 at +0x10 and 5,312 bytes, VeraCrypt 1.19
//! to 1.26.24 at +0x0c and 5,304, VeraCrypt 1.0f to 1.18 at +0x0c and 5,324, TrueCrypt
//! 6.0 to 7.2 and VeraCrypt 1.0e at +0x08 and 5,324 (four layouts, read from captures of every version
//! the layout's label lists; `VALIDATION.md` MEM-VC-2 to MEM-VC-7). The cipher ids are
//! numbered one way by TrueCrypt and VeraCrypt up to 1.17, another way from 1.18, and
//! a third from 1.26.29, so each layout is read with the id tables observed on it. Where a
//! pair of AES-256 schedules has one of those shapes and a plausible header before it, the
//! container is published (`crypto_infos`, with the layout it matched); only the observed
//! ids are named, any other id is published raw. A version whose layout is none of the four
//! gets no container. A schedule with no such container is "a key the driver's memory
//! holds", not "the master key of volume X".
//!
//! # What was validated and what was not
//!
//! The decision on a clean machine is validated on this project's Windows 11
//! 26200 capture, which has no such driver. The positive path is validated on
//! a Windows 11 26200 capture taken while a VeraCrypt 1.26.29 AES volume was
//! mounted (`~/win11-lab/vc/GROUND-TRUTH.txt`): the two master keys, decrypted
//! from the container header on the host from the password, were both among
//! the schedules reported, in the pool region the virtual map names. That is
//! one volume, one version and one cipher; the container read from the same
//! capture names AES, XTS and the primary and secondary schedules in the order
//! the header decrypts to. The sweep also reports other
//! AES-256 schedules in the pool (that machine's BitLocker keys), and the pair
//! distance (8192 bytes) was set after the real pair was found 5312 bytes
//! apart, so the heuristic has been tuned on its only observation.

use std::sync::Arc;

use seance_bulk::aes::{verify_schedule_at, AesBits};
use seance_core::io::IncompleteReason;
use seance_memory::scan::{scan_range, Hit, ScanConfig, ScanControl, ScanOutcome, Scanner};
use seance_memory::{Incomplete, MemoryLayer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The driver names, compared case-insensitively.
pub const DRIVER_NAMES: &[&str] = &["truecrypt.sys", "veracrypt.sys"];

/// Caps.
#[derive(Debug, Clone)]
pub struct TrueCryptConfig {
    /// Byte step between schedule probes. Schedules are word-aligned.
    pub step: usize,
    /// Schedules published. Reaching it is stated.
    pub max_schedules: usize,
    /// How far apart two AES-256 schedules may be to be called a possible
    /// XTS pair.
    pub pair_distance: u64,
    pub scan: ScanConfig,
}

impl Default for TrueCryptConfig {
    fn default() -> Self {
        Self {
            step: 4,
            max_schedules: 4096,
            pair_distance: 8192,
            scan: ScanConfig::default(),
        }
    }
}

/// One loaded module, as the caller knows it.
#[derive(Debug, Clone)]
pub struct DriverCandidate {
    pub name: Option<String>,
    pub base: Option<u64>,
    pub size: Option<u64>,
}

/// Whether the driver was loaded.
#[derive(Debug, Clone)]
pub enum DriverPresence {
    Present {
        name: String,
        base: Option<u64>,
        size: Option<u64>,
    },
    Absent {
        modules_walked: usize,
        list_complete: bool,
    },
}

impl DriverPresence {
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Present { name, base, size } => json!({
                "present": true,
                "name": name,
                "base": base.map(|b| format!("{b:#018x}")),
                "size": size,
            }),
            Self::Absent {
                modules_walked,
                list_complete,
            } => json!({
                "present": false,
                "modules_walked": modules_walked,
                "list_complete": list_complete,
                "names_looked_for": DRIVER_NAMES,
            }),
        }
    }
}

/// The region a sweep runs over.
pub struct SweepRegion {
    pub layer: Arc<dyn MemoryLayer>,
    pub base: u64,
    pub bytes: u64,
    /// Where the region came from, for the record.
    pub description: String,
}

impl std::fmt::Debug for SweepRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SweepRegion")
            .field("base", &format_args!("{:#x}", self.base))
            .field("bytes", &self.bytes)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// One verified schedule.
#[derive(Debug, Clone)]
pub struct FoundSchedule {
    pub address: u64,
    pub bits: u32,
    /// `AES`, `Serpent` or `Twofish`.
    pub cipher: &'static str,
    /// SHA-256 of the key bytes. The key itself is not on the record.
    pub key_sha256: String,
}

impl FoundSchedule {
    pub fn to_json(&self) -> Value {
        json!({
            "address": format!("{:#018x}", self.address),
            "bits": self.bits,
            "cipher": self.cipher,
            "key_sha256": self.key_sha256,
        })
    }
}

/// A driver container decoded around two verified schedules.
#[derive(Debug, Clone)]
pub struct CryptoInfo {
    /// Address of the container's first byte.
    pub address: u64,
    pub cipher_id: u32,
    pub cipher: Option<&'static str>,
    pub mode_id: u32,
    pub mode: Option<&'static str>,
    pub primary_schedule: u64,
    pub secondary_schedule: u64,
    /// Which observed layout the container matched.
    pub layout: &'static str,
    /// Each cipher of the container with its primary and secondary (tweak) schedules; one for a single
    /// cipher, three for a cascade.
    pub members: Vec<CryptoMember>,
}

/// One cipher of a container.
#[derive(Debug, Clone)]
pub struct CryptoMember {
    pub cipher: &'static str,
    pub primary_schedule: u64,
    pub secondary_schedule: u64,
    pub primary_key_sha256: String,
    pub secondary_key_sha256: String,
}

impl CryptoMember {
    pub fn to_json(&self) -> Value {
        json!({
            "cipher": self.cipher,
            "primary_schedule": format!("{:#018x}", self.primary_schedule),
            "secondary_schedule": format!("{:#018x}", self.secondary_schedule),
            "primary_key_sha256": self.primary_key_sha256,
            "secondary_key_sha256": self.secondary_key_sha256,
        })
    }
}

impl CryptoInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "address": format!("{:#018x}", self.address),
            "cipher_id": self.cipher_id,
            "cipher": self.cipher,
            "mode_id": self.mode_id,
            "mode": self.mode,
            "primary_schedule": format!("{:#018x}", self.primary_schedule),
            "secondary_schedule": format!("{:#018x}", self.secondary_schedule),
            "layout": self.layout,
            "members": self.members.iter().map(CryptoMember::to_json).collect::<Vec<_>>(),
        })
    }
}

/// A container layout read off a real capture: where the primary schedule sits from the
/// container's first byte, and how far the secondary sits after the primary.
struct ContainerLayout {
    primary_offset: u64,
    secondary_delta: u64,
    observed_on: &'static str,
}

/// The layouts observed, one per capture: VeraCrypt 1.26.29 (`VALIDATION.md` MEM-VC-2),
/// VeraCrypt 1.25.9 (`MEM-VC-3`), VeraCrypt 1.12 (`MEM-VC-7`) and TrueCrypt 7.1a (`MEM-VC-5`), all on
/// Windows 11 25H2, all AES-256-XTS. The driver's structure grew between them; a version not listed here yields no
/// container.
const CONTAINER_LAYOUTS: [ContainerLayout; 4] = [
    ContainerLayout {
        primary_offset: 0x10,
        secondary_delta: 5312,
        observed_on: "VeraCrypt 1.26.29 to 1.26.30 (observed on 1.26.29, 1.26.30)",
    },
    ContainerLayout {
        primary_offset: 0x0c,
        secondary_delta: 5304,
        observed_on: "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)",
    },
    // VeraCrypt 1.12 (`MEM-VC-7`): TrueCrypt 7.1a's tweak-key distance and cipher ids with a header of three dwords
    // (the id, the mode and a third read 1), so the buffer starts at `+0x0c`. It is tried before the TrueCrypt layout:
    // the two share the delta, and an AES schedule at `+0x0c` of a 1.12 container reads as a TrueCrypt container
    // of id 1 one dword later.
    ContainerLayout {
        primary_offset: 0x0c,
        secondary_delta: 5324,
        observed_on: "VeraCrypt 1.0f to 1.18 (observed on 1.0f, 1.0f-1, 1.0f-2, 1.12, 1.13, 1.14, 1.16, 1.17, 1.18)",
    },
    ContainerLayout {
        primary_offset: 0x08,
        secondary_delta: 5324,
        observed_on: "TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e (observed on TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1, 7.1a, 7.2 and VeraCrypt 1.0e)",
    },
];
/// The largest cipher or mode id accepted. Only id 1 has been observed; the
/// bound rejects bytes that are plainly not a small enumeration.
const CONTAINER_MAX_ID: u32 = 0xFF;

/// Decode the container around each verified AES-256 schedule that has a
/// verified AES-256 schedule 5,312 bytes after it and a header of two plausible
/// ids before it. Anything that fails a check yields nothing, never a guess.
fn decode_crypto_infos(layer: &dyn MemoryLayer, schedules: &[FoundSchedule]) -> Vec<CryptoInfo> {
    let mut out = decode_cascades(layer, schedules);
    let named: std::collections::HashSet<u64> = out.iter().map(|c| c.address).collect();
    // A schedule that is a layer of a container already decoded is not a plain AES volume's.
    let claimed: std::collections::HashSet<u64> = out
        .iter()
        .flat_map(|c| {
            c.members
                .iter()
                .flat_map(|m| [m.primary_schedule, m.secondary_schedule])
        })
        .collect();
    for primary in schedules
        .iter()
        .filter(|s| s.cipher == "AES" && s.bits == 256)
    {
        if claimed.contains(&primary.address) {
            continue;
        }
        for layout in &CONTAINER_LAYOUTS {
            let secondary = primary.address.saturating_add(layout.secondary_delta);
            let Some(secondary_found) = schedules
                .iter()
                .find(|s| s.cipher == "AES" && s.bits == 256 && s.address == secondary)
            else {
                continue;
            };
            let Some(base) = primary.address.checked_sub(layout.primary_offset) else {
                continue;
            };
            if named.contains(&base) {
                continue;
            }
            let mut header = [0u8; 8];
            if seance_core::io::read_exact_or_fail(
                layer.as_data_source(),
                base,
                &mut header,
                "a driver container header",
            )
            .is_err()
            {
                continue;
            }
            let cipher_id = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let mode_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if !(1..=CONTAINER_MAX_ID).contains(&cipher_id)
                || !(1..=CONTAINER_MAX_ID).contains(&mode_id)
            {
                continue;
            }
            out.push(CryptoInfo {
                address: base,
                cipher_id,
                // Only the observed values are named: the capture's ground truth is
                // AES in XTS mode, and both ids read 1 there.
                cipher: (cipher_id == 1).then_some("AES"),
                mode_id,
                mode: (mode_id == 1).then_some("XTS"),
                primary_schedule: primary.address,
                secondary_schedule: secondary,
                layout: layout.observed_on,
                members: vec![CryptoMember {
                    cipher: "AES",
                    primary_schedule: primary.address,
                    secondary_schedule: secondary,
                    primary_key_sha256: primary.key_sha256.clone(),
                    secondary_key_sha256: secondary_found.key_sha256.clone(),
                }],
            });
            // The first layout that fits wins: two layouts can share a delta, and one volume is one container.
            break;
        }
    }
    out
}

/// One cipher of a cascade and where its schedule sits from the start of the container's key
/// schedule buffer.
struct CascadeMember {
    cipher: &'static str,
    offset: u64,
}

/// A container whose cipher id and member layout were read off a capture.
struct ObservedContainer {
    id: u32,
    name: &'static str,
    members: &'static [CascadeMember],
}

/// Bytes each cipher's schedule occupies in the buffer, as observed: AES 488 (the encrypt and decrypt contexts),
/// Serpent 140 words, Twofish the 1,024-word S-box tables and 40 subkeys.
const AES_BYTES: u64 = 488;
const SERPENT_BYTES: u64 = 560;
const TWOFISH_BYTES: u64 = 4256;
const CAMELLIA_BYTES: u64 = 272;
/// Kuznyechik's encryption and decryption round keys, 160 bytes each.
const KUZNYECHIK_BYTES: u64 = 320;
/// TrueCrypt's Twofish structure: `l_key`, `s_key`, the interleaved tables and `k_len`.
const TWOFISH_TC_BYTES: u64 = 4276;

const fn member(cipher: &'static str, offset: u64) -> CascadeMember {
    CascadeMember { cipher, offset }
}

/// The containers observed on VeraCrypt 1.25.9, Windows 11 25H2 (`VALIDATION.md` `MEM-VC-3`, `MEM-VC-4`), by the id in
/// the header: a Serpent volume (2), a Twofish volume (3), a Camellia volume (4), a Kuznyechik volume (6) and the cascades
/// AES-Twofish (7), AES-Twofish-Serpent (8), Serpent-AES (9), Serpent-Twofish-AES (10), Twofish-Serpent (11),
/// Camellia-Kuznyechik (12), Kuznyechik-Twofish (13), Camellia-Serpent (14), Kuznyechik-AES (15) and
/// Kuznyechik-Serpent-Camellia (16). A cascade's schedules lie one after another from the start of the buffer in the
/// **reverse** of the order its name gives (the last-named cipher first). Id 5 and ids above 16 have not been seen; none is named.
///
/// The ids are the version's: 1.26.29 numbers the same cascades differently (below).
const OBSERVED_CONTAINERS_1259: [ObservedContainer; 14] = [
    ObservedContainer {
        id: 2,
        name: "Serpent",
        members: &[member("Serpent", 0)],
    },
    ObservedContainer {
        id: 3,
        name: "Twofish",
        members: &[member("Twofish", 0)],
    },
    ObservedContainer {
        id: 7,
        name: "AES-Twofish",
        members: &[member("Twofish", 0), member("AES", TWOFISH_BYTES)],
    },
    ObservedContainer {
        id: 8,
        name: "AES-Twofish-Serpent",
        members: &[
            member("Serpent", 0),
            member("Twofish", SERPENT_BYTES),
            member("AES", SERPENT_BYTES + TWOFISH_BYTES),
        ],
    },
    ObservedContainer {
        id: 9,
        name: "Serpent-AES",
        members: &[member("AES", 0), member("Serpent", AES_BYTES)],
    },
    ObservedContainer {
        id: 10,
        name: "Serpent-Twofish-AES",
        members: &[
            member("AES", 0),
            member("Twofish", AES_BYTES),
            member("Serpent", AES_BYTES + TWOFISH_BYTES),
        ],
    },
    ObservedContainer {
        id: 11,
        name: "Twofish-Serpent",
        members: &[member("Serpent", 0), member("Twofish", SERPENT_BYTES)],
    },
    ObservedContainer {
        id: 4,
        name: "Camellia",
        members: &[member("Camellia", 0)],
    },
    ObservedContainer {
        id: 6,
        name: "Kuznyechik",
        members: &[member("Kuznyechik", 0)],
    },
    ObservedContainer {
        id: 12,
        name: "Camellia-Kuznyechik",
        members: &[
            member("Kuznyechik", 0),
            member("Camellia", KUZNYECHIK_BYTES),
        ],
    },
    ObservedContainer {
        id: 13,
        name: "Kuznyechik-Twofish",
        members: &[member("Twofish", 0), member("Kuznyechik", TWOFISH_BYTES)],
    },
    ObservedContainer {
        id: 14,
        name: "Camellia-Serpent",
        members: &[member("Serpent", 0), member("Camellia", SERPENT_BYTES)],
    },
    ObservedContainer {
        id: 15,
        name: "Kuznyechik-AES",
        members: &[member("AES", 0), member("Kuznyechik", AES_BYTES)],
    },
    ObservedContainer {
        id: 16,
        name: "Kuznyechik-Serpent-Camellia",
        members: &[
            member("Camellia", 0),
            member("Serpent", CAMELLIA_BYTES),
            member("Kuznyechik", CAMELLIA_BYTES + SERPENT_BYTES),
        ],
    },
];

/// The same containers on VeraCrypt 1.26.29 (`VALIDATION.md` `MEM-VC-3`): the ids are one lower from the
/// cascades up, AES-Twofish being **6**, AES-Twofish-Serpent **7**, Serpent-AES **8**, Serpent-Twofish-AES **9** and
/// Twofish-Serpent **10**, and the header is four dwords, so the key schedule buffer starts at `+0x10`. The
/// schedules sit in the same order and have the same sizes. An id means one container per version: 7 is
/// AES-Twofish on 1.25.9 and AES-Twofish-Serpent on 1.26.29.
const OBSERVED_CONTAINERS_1260: [ObservedContainer; 14] = [
    ObservedContainer {
        id: 2,
        name: "Serpent",
        members: &[member("Serpent", 0)],
    },
    ObservedContainer {
        id: 3,
        name: "Twofish",
        members: &[member("Twofish", 0)],
    },
    ObservedContainer {
        id: 6,
        name: "AES-Twofish",
        members: &[member("Twofish", 0), member("AES", TWOFISH_BYTES)],
    },
    ObservedContainer {
        id: 7,
        name: "AES-Twofish-Serpent",
        members: &[
            member("Serpent", 0),
            member("Twofish", SERPENT_BYTES),
            member("AES", SERPENT_BYTES + TWOFISH_BYTES),
        ],
    },
    ObservedContainer {
        id: 8,
        name: "Serpent-AES",
        members: &[member("AES", 0), member("Serpent", AES_BYTES)],
    },
    ObservedContainer {
        id: 9,
        name: "Serpent-Twofish-AES",
        members: &[
            member("AES", 0),
            member("Twofish", AES_BYTES),
            member("Serpent", AES_BYTES + TWOFISH_BYTES),
        ],
    },
    ObservedContainer {
        id: 10,
        name: "Twofish-Serpent",
        members: &[member("Serpent", 0), member("Twofish", SERPENT_BYTES)],
    },
    ObservedContainer {
        id: 4,
        name: "Camellia",
        members: &[member("Camellia", 0)],
    },
    ObservedContainer {
        id: 5,
        name: "Kuznyechik",
        members: &[member("Kuznyechik", 0)],
    },
    ObservedContainer {
        id: 11,
        name: "Camellia-Kuznyechik",
        members: &[
            member("Kuznyechik", 0),
            member("Camellia", KUZNYECHIK_BYTES),
        ],
    },
    ObservedContainer {
        id: 12,
        name: "Kuznyechik-Twofish",
        members: &[member("Twofish", 0), member("Kuznyechik", TWOFISH_BYTES)],
    },
    ObservedContainer {
        id: 13,
        name: "Camellia-Serpent",
        members: &[member("Serpent", 0), member("Camellia", SERPENT_BYTES)],
    },
    ObservedContainer {
        id: 14,
        name: "Kuznyechik-AES",
        members: &[member("AES", 0), member("Kuznyechik", AES_BYTES)],
    },
    ObservedContainer {
        id: 15,
        name: "Kuznyechik-Serpent-Camellia",
        members: &[
            member("Camellia", 0),
            member("Serpent", CAMELLIA_BYTES),
            member("Kuznyechik", CAMELLIA_BYTES + SERPENT_BYTES),
        ],
    },
];

/// The containers observed on VeraCrypt 1.26.7, Windows 11 25H2 (`VALIDATION.md` `MEM-VC-6`): the 1.25.9 geometry (`+0x0c`,
/// 5,304 bytes) with the cipher ids 1.26.29 uses. Serpent (2), Twofish (3), Camellia (4), Kuznyechik (5), AES-Twofish (6),
/// Serpent-AES (8) and Kuznyechik-Twofish (12) were mounted; the other cascades on this version were not, so none of their
/// ids is named. An id means one container per version and the members are checked too, which is what keeps this table and
/// the 1.25.9 one (where 6 is Kuznyechik and 12 is Camellia-Kuznyechik) from reading each other's containers.
const OBSERVED_CONTAINERS_1267: [ObservedContainer; 7] = [
    ObservedContainer {
        id: 2,
        name: "Serpent",
        members: &[member("Serpent", 0)],
    },
    ObservedContainer {
        id: 3,
        name: "Twofish",
        members: &[member("Twofish", 0)],
    },
    ObservedContainer {
        id: 4,
        name: "Camellia",
        members: &[member("Camellia", 0)],
    },
    ObservedContainer {
        id: 5,
        name: "Kuznyechik",
        members: &[member("Kuznyechik", 0)],
    },
    ObservedContainer {
        id: 6,
        name: "AES-Twofish",
        members: &[member("Twofish", 0), member("AES", TWOFISH_BYTES)],
    },
    ObservedContainer {
        id: 8,
        name: "Serpent-AES",
        members: &[member("AES", 0), member("Serpent", AES_BYTES)],
    },
    ObservedContainer {
        id: 12,
        name: "Kuznyechik-Twofish",
        members: &[member("Twofish", 0), member("Kuznyechik", TWOFISH_BYTES)],
    },
];

/// The containers observed on TrueCrypt 7.1a, Windows 11 25H2 (`VALIDATION.md` `MEM-VC-5`), by the id at the
/// start of the container (TrueCrypt's own numbering of its encryption algorithms): Serpent (2), Twofish (3), and
/// the cascades AES-Twofish (4), AES-Twofish-Serpent (5), Serpent-AES (6), Serpent-Twofish-AES (7) and
/// Twofish-Serpent (8). The container begins with two dwords (the algorithm and the mode), the schedules follow at
/// `+8` in the reverse of the order the name gives, and the tweak keys' copy is 5,324 bytes after the primary.
/// A plain AES volume (1) is decoded by the AES rule above.
const OBSERVED_CONTAINERS_TC71A: [ObservedContainer; 7] = [
    ObservedContainer {
        id: 2,
        name: "Serpent",
        members: &[member("Serpent", 0)],
    },
    ObservedContainer {
        id: 3,
        name: "Twofish",
        members: &[member("Twofish", 0)],
    },
    ObservedContainer {
        id: 4,
        name: "AES-Twofish",
        members: &[member("Twofish", 0), member("AES", TWOFISH_TC_BYTES)],
    },
    ObservedContainer {
        id: 5,
        name: "AES-Twofish-Serpent",
        members: &[
            member("Serpent", 0),
            member("Twofish", SERPENT_BYTES),
            member("AES", SERPENT_BYTES + TWOFISH_TC_BYTES),
        ],
    },
    ObservedContainer {
        id: 6,
        name: "Serpent-AES",
        members: &[member("AES", 0), member("Serpent", AES_BYTES)],
    },
    ObservedContainer {
        id: 7,
        name: "Serpent-Twofish-AES",
        members: &[
            member("AES", 0),
            member("Twofish", AES_BYTES),
            member("Serpent", AES_BYTES + TWOFISH_TC_BYTES),
        ],
    },
    ObservedContainer {
        id: 8,
        name: "Twofish-Serpent",
        members: &[member("Serpent", 0), member("Twofish", SERPENT_BYTES)],
    },
];

/// The containers observed on VeraCrypt 1.18, Windows 11 25H2 (`VALIDATION.md` `MEM-VC-7`): the geometry of 1.12 (buffer at
/// `+0x0c`, tweak keys 5,324 bytes on, TrueCrypt's 4,276-byte Twofish structure) with the ids of 1.25.9, the ones Camellia
/// brought: Serpent (2), Twofish (3), Camellia (4), Kuznyechik (6) and the cascades AES-Twofish (7), AES-Twofish-Serpent (8),
/// Serpent-AES (9), Serpent-Twofish-AES (10) and Twofish-Serpent (11). 1.12 numbers the cascades as TrueCrypt does, so an id
/// means one cascade per version: this table is tried first, and it asks for more layers than TrueCrypt's id 8 does.
const OBSERVED_CONTAINERS_118: [ObservedContainer; 9] = [
    ObservedContainer {
        id: 2,
        name: "Serpent",
        members: &[member("Serpent", 0)],
    },
    ObservedContainer {
        id: 3,
        name: "Twofish",
        members: &[member("Twofish", 0)],
    },
    ObservedContainer {
        id: 4,
        name: "Camellia",
        members: &[member("Camellia", 0)],
    },
    ObservedContainer {
        id: 6,
        name: "Kuznyechik",
        members: &[member("Kuznyechik", 0)],
    },
    ObservedContainer {
        id: 7,
        name: "AES-Twofish",
        members: &[member("Twofish", 0), member("AES", TWOFISH_TC_BYTES)],
    },
    ObservedContainer {
        id: 8,
        name: "AES-Twofish-Serpent",
        members: &[
            member("Serpent", 0),
            member("Twofish", SERPENT_BYTES),
            member("AES", SERPENT_BYTES + TWOFISH_TC_BYTES),
        ],
    },
    ObservedContainer {
        id: 9,
        name: "Serpent-AES",
        members: &[member("AES", 0), member("Serpent", AES_BYTES)],
    },
    ObservedContainer {
        id: 10,
        name: "Serpent-Twofish-AES",
        members: &[
            member("AES", 0),
            member("Twofish", AES_BYTES),
            member("Serpent", AES_BYTES + TWOFISH_TC_BYTES),
        ],
    },
    ObservedContainer {
        id: 11,
        name: "Twofish-Serpent",
        members: &[member("Serpent", 0), member("Twofish", SERPENT_BYTES)],
    },
];

/// Decode a Serpent or Twofish volume's or a cascade's container (VeraCrypt 1.25.9 and 1.26.29, TrueCrypt 7.1a): every member's schedule
/// must be a verified schedule at its observed offset, in the primary buffer and again, with the
/// tweak key, the layout's delta on, and the two header ids before them must be the container's.
fn decode_cascades(layer: &dyn MemoryLayer, schedules: &[FoundSchedule]) -> Vec<CryptoInfo> {
    let mut out = Vec::new();
    for (layout, containers) in [
        (&CONTAINER_LAYOUTS[1], &OBSERVED_CONTAINERS_1259[..]),
        (&CONTAINER_LAYOUTS[0], &OBSERVED_CONTAINERS_1260[..]),
        (&CONTAINER_LAYOUTS[1], &OBSERVED_CONTAINERS_1267[..]),
        (&CONTAINER_LAYOUTS[2], &OBSERVED_CONTAINERS_118[..]),
        (&CONTAINER_LAYOUTS[2], &OBSERVED_CONTAINERS_TC71A[..]),
        (&CONTAINER_LAYOUTS[3], &OBSERVED_CONTAINERS_TC71A[..]),
    ] {
        decode_cascades_of(layer, schedules, layout, containers, &mut out);
    }
    out
}

fn decode_cascades_of(
    layer: &dyn MemoryLayer,
    schedules: &[FoundSchedule],
    layout: &ContainerLayout,
    containers: &[ObservedContainer],
    out: &mut Vec<CryptoInfo>,
) {
    let find = |cipher: &str, address: u64| {
        schedules
            .iter()
            .find(|s| s.cipher == cipher && s.address == address)
    };
    for container in containers {
        let first = &container.members[0];
        for anchor in schedules.iter().filter(|s| s.cipher == first.cipher) {
            let Some(base) = anchor
                .address
                .checked_sub(first.offset + layout.primary_offset)
            else {
                continue;
            };
            if out.iter().any(|c| c.address == base) {
                continue;
            }
            let mut members = Vec::new();
            for m in container.members {
                let at = base + layout.primary_offset + m.offset;
                let (Some(p), Some(q)) = (
                    find(m.cipher, at),
                    find(m.cipher, at + layout.secondary_delta),
                ) else {
                    break;
                };
                members.push(CryptoMember {
                    cipher: m.cipher,
                    primary_schedule: at,
                    secondary_schedule: at + layout.secondary_delta,
                    primary_key_sha256: p.key_sha256.clone(),
                    secondary_key_sha256: q.key_sha256.clone(),
                });
            }
            if members.len() != container.members.len() {
                continue;
            }
            let mut header = [0u8; 8];
            if seance_core::io::read_exact_or_fail(
                layer.as_data_source(),
                base,
                &mut header,
                "a driver container header",
            )
            .is_err()
            {
                continue;
            }
            let cipher_id = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let mode_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if cipher_id != container.id {
                continue;
            }
            out.push(CryptoInfo {
                address: base,
                cipher_id,
                cipher: Some(container.name),
                mode_id,
                mode: (mode_id == 1).then_some("XTS"),
                primary_schedule: members[0].primary_schedule,
                secondary_schedule: members[0].secondary_schedule,
                layout: layout.observed_on,
                members,
            });
        }
    }
}

/// A schedule the sweep verified whose key bytes would not read again when
/// the hash was to be made. The sweep saw it; the record lists it without a
/// hash rather than not at all.
#[derive(Debug, Clone)]
pub struct UnhashedSchedule {
    pub address: u64,
    pub bits: u32,
    pub detail: String,
}

impl UnhashedSchedule {
    pub fn to_json(&self) -> Value {
        json!({
            "address": format!("{:#018x}", self.address),
            "bits": self.bits,
            "key_sha256": Value::Null,
            "detail": self.detail,
        })
    }
}

/// The sweep's result.
#[derive(Debug, Clone)]
pub struct KeySweep {
    pub region_base: u64,
    pub region_bytes: u64,
    pub region_description: String,
    pub scan: ScanOutcome,
    pub bytes_scanned: u64,
    pub schedules: Vec<FoundSchedule>,
    /// Verified schedules whose key could not be re-read for hashing.
    pub schedules_unhashed: Vec<UnhashedSchedule>,
    pub schedules_truncated: bool,
    /// Pairs of AES-256 schedule addresses within the pair distance.
    pub possible_xts_pairs: Vec<(u64, u64)>,
    /// Containers decoded around a primary and a secondary schedule.
    pub crypto_infos: Vec<CryptoInfo>,
}

impl KeySweep {
    pub fn is_complete(&self) -> bool {
        self.scan.is_complete() && !self.schedules_truncated && self.schedules_unhashed.is_empty()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "region_base": format!("{:#018x}", self.region_base),
            "region_bytes": self.region_bytes,
            "region": self.region_description,
            "scan": self.scan.to_json(),
            "bytes_scanned": self.bytes_scanned,
            "unread_bytes": self.scan.unread_bytes,
            "unmapped_bytes": self.scan.unmapped_bytes,
            "schedules": self.schedules.iter().map(FoundSchedule::to_json).collect::<Vec<_>>(),
            "schedules_total": self.schedules.len(),
            "schedules_unhashed": self.schedules_unhashed.iter().map(UnhashedSchedule::to_json).collect::<Vec<_>>(),
            "schedules_unhashed_total": self.schedules_unhashed.len(),
            "schedules_truncated": self.schedules_truncated,
            "possible_xts_pairs": self.possible_xts_pairs.iter().map(|(a, b)| json!([format!("{a:#018x}"), format!("{b:#018x}")])).collect::<Vec<_>>(),
            "crypto_infos": self.crypto_infos.iter().map(CryptoInfo::to_json).collect::<Vec<_>>(),
            "crypto_infos_total": self.crypto_infos.len(),
            "pairs_basis":
                "An XTS volume needs two AES-256 keys and the driver keeps their schedules near \
                 each other, so two AES-256 schedules within the pair distance are reported as \
                 a POSSIBLE pair. That is an inference. Where the container that holds the two \
                 schedules was also read in one of the two layouts observed (VeraCrypt 1.26.29 \
                 and 1.25.9, Windows 11, AES), `crypto_infos` names its cipher id, mode id, which \
                 schedule is primary and which secondary, and which layout matched; a pair with no such container stays \
                 an inference, and an id outside that observation is published raw and unnamed.",
            "key_basis":
                "A schedule is verified by re-expanding its leading key and comparing every \
                 derived word, so a hit is a real AES key schedule. Only its address, size and \
                 the SHA-256 of the key are recorded; the key bytes are not.",
        })
    }
}

/// What one survey produced.
#[derive(Debug)]
pub struct TrueCryptSurvey {
    pub driver: DriverPresence,
    pub sweep: Option<KeySweep>,
    /// Why the sweep did not run, when the driver was present and it did not.
    pub sweep_did_not_run_because: Option<String>,
}

impl TrueCryptSurvey {
    pub fn is_complete(&self) -> bool {
        match &self.driver {
            DriverPresence::Absent { list_complete, .. } => *list_complete,
            DriverPresence::Present { .. } => {
                self.sweep.as_ref().is_some_and(KeySweep::is_complete)
            }
        }
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let DriverPresence::Absent {
            list_complete: false,
            ..
        } = &self.driver
        {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                "the loaded-module list did not walk end to end, so the driver may be past the \
                 break rather than absent"
                    .to_string(),
            ));
        }
        if let Some(why) = &self.sweep_did_not_run_because {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the driver is loaded and the key sweep did not run: {why}"),
            ));
        }
        if let Some(sweep) = &self.sweep {
            if !sweep.scan.is_complete() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "{} byte(s) of the swept region were not examined ({} never mapped), so \
                         a schedule among them would not be listed",
                        sweep.scan.unread_bytes, sweep.scan.unmapped_bytes
                    ),
                ));
            }
            if sweep.schedules_truncated {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "only the first {} schedule(s) were recorded",
                        sweep.schedules.len()
                    ),
                ));
            }
            if !sweep.schedules_unhashed.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "{} verified schedule(s) could not be re-read for hashing and are listed \
                         by address without a key hash",
                        sweep.schedules_unhashed.len()
                    ),
                ));
            }
        }
        out
    }

    pub fn describe(&self) -> String {
        match (&self.driver, &self.sweep) {
            (
                DriverPresence::Absent {
                    modules_walked,
                    list_complete,
                },
                _,
            ) => format!(
                "No TrueCrypt or VeraCrypt driver is on the loaded-module list ({} module(s) \
                 walked{}), so no volume of that kind was mounted through a driver and nothing \
                 was swept for.",
                modules_walked,
                if *list_complete {
                    ""
                } else {
                    ", and the list did not walk end to end"
                }
            ),
            (DriverPresence::Present { name, .. }, Some(sweep)) => format!(
                "{name} is loaded. {} byte(s) of {} were swept; {} verified AES key schedule(s) \
                 were found and {} possible XTS pair(s) inferred from their spacing.{}",
                sweep.bytes_scanned,
                sweep.region_description,
                sweep.schedules.len(),
                sweep.possible_xts_pairs.len(),
                if sweep.schedules_unhashed.is_empty() {
                    String::new()
                } else {
                    format!(
                        " {} further verified schedule(s) could not be re-read for hashing.",
                        sweep.schedules_unhashed.len()
                    )
                }
            ),
            (DriverPresence::Present { name, .. }, None) => format!(
                "{name} is loaded and the key sweep did not run: {}",
                self.sweep_did_not_run_because
                    .clone()
                    .unwrap_or_else(|| "no reason recorded".to_string())
            ),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "driver": self.driver.to_json(),
            "driver_present": self.driver.is_present(),
            "sweep_ran": self.sweep.is_some(),
            "sweep": self.sweep.as_ref().map(KeySweep::to_json),
            "sweep_did_not_run_because": self.sweep_did_not_run_because,
            "validation_note":
                "The clean-machine decision is validated on this project's Windows 11 26200 \
                 capture, which loads no such driver. The sweep's positive path is validated on \
                 captures with veracrypt.sys loaded and volumes mounted (VeraCrypt 1.26.29, one AES \
                 volume, then a Serpent volume, a Twofish volume, a Camellia volume, a Kuznyechik volume and ten \
                 cascades; VeraCrypt 1.25.9, two AES volumes, then the same fourteen; and, with truecrypt.sys, TrueCrypt 7.1a, an AES, a Serpent and a Twofish volume and five cascades; Windows 11): every master key, known independently from \
                 its container header, was among the verified schedules, the Twofish and Camellia keys recovered \
                 from their schedules. Each container layout was read from its own capture, so the \
                 containers are bounded to those two VeraCrypt versions and TrueCrypt 7.1a (a container id means one cipher per version) and \
                 to the volumes and cascades of AES, Serpent, Twofish, Camellia and Kuznyechik seen, and \
                 the sweep does not tell VeraCrypt's schedules from \
                 any other AES-256, Serpent-256, Twofish-256, Camellia-256 or Kuznyechik schedules in the pool (a BitLocker \
                 volume's AES schedules are reported beside them). A Camellia key is recovered from \
                 the three key-dependent subkey pairs of its table, which are all that are checked of it.",
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// AES key schedules at word-aligned offsets, verified in place.
#[derive(Debug)]
struct ScheduleScanner {
    step: usize,
}

const BITS: [AesBits; 3] = [AesBits::Aes256, AesBits::Aes128, AesBits::Aes192];

/// Pattern ids past the AES sizes: a Serpent-256, a Twofish-256, a Camellia-256 and a Kuznyechik schedule.
const SERPENT_PATTERN: u32 = 3;
const TWOFISH_PATTERN: u32 = 4;
const CAMELLIA_PATTERN: u32 = 5;
const KUZNYECHIK_PATTERN: u32 = 6;
/// TrueCrypt 7.1a's Twofish structure (a different order of the same data).
const TWOFISH_TC_PATTERN: u32 = 7;
/// VeraCrypt 1.19's Twofish structure: the subkeys first, then the tables.
const TWOFISH_SUBKEYS_FIRST_PATTERN: u32 = 8;
/// VeraCrypt 1.19's Camellia table: one little-endian 64-bit word per subkey.
const CAMELLIA_LE64_PATTERN: u32 = 9;

impl Scanner for ScheduleScanner {
    fn name(&self) -> &str {
        "windows.aes_key_schedule"
    }

    fn max_match_len(&self) -> Option<u64> {
        Some(seance_bulk::twofish::TC_STRUCT_BYTES.max(seance_bulk::twofish::STRUCT_BYTES) as u64)
    }

    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl) {
        let mut offset = 0usize;
        while offset + AesBits::Aes128.schedule_len() <= chunk.len() {
            let hit = BITS
                .iter()
                .enumerate()
                .find_map(|(id, bits)| {
                    verify_schedule_at(chunk, offset, *bits)
                        .map(|_| (id as u32, bits.schedule_len()))
                })
                .or_else(|| {
                    seance_bulk::serpent::verify_schedule_at(chunk, offset)
                        .map(|_| (SERPENT_PATTERN, seance_bulk::serpent::SCHEDULE_BYTES))
                })
                .or_else(|| {
                    seance_bulk::twofish::verify_schedule_at(chunk, offset)
                        .map(|_| (TWOFISH_PATTERN, seance_bulk::twofish::STRUCT_BYTES))
                })
                .or_else(|| {
                    seance_bulk::twofish::verify_subkeys_first_schedule_at(chunk, offset).map(
                        |_| {
                            (
                                TWOFISH_SUBKEYS_FIRST_PATTERN,
                                seance_bulk::twofish::STRUCT_BYTES,
                            )
                        },
                    )
                })
                .or_else(|| {
                    seance_bulk::twofish::verify_tc_schedule_at(chunk, offset)
                        .map(|_| (TWOFISH_TC_PATTERN, seance_bulk::twofish::TC_STRUCT_BYTES))
                })
                .or_else(|| {
                    seance_bulk::kuznyechik::verify_schedule_at(chunk, offset)
                        .map(|_| (KUZNYECHIK_PATTERN, seance_bulk::kuznyechik::SCHEDULE_BYTES))
                })
                .or_else(|| {
                    seance_bulk::camellia::verify_table_at(chunk, offset)
                        .map(|_| (CAMELLIA_PATTERN, seance_bulk::camellia::TABLE_BYTES))
                })
                .or_else(|| {
                    seance_bulk::camellia::verify_table_le64_at(chunk, offset)
                        .map(|_| (CAMELLIA_LE64_PATTERN, seance_bulk::camellia::TABLE_BYTES))
                });
            match hit {
                Some((pattern_id, length)) => {
                    let hit = Hit {
                        address: base + offset as u64,
                        pattern_id,
                        length: length as u32,
                    };
                    if sink(hit) == ScanControl::Stop {
                        return;
                    }
                    offset += length;
                }
                None => offset += self.step.max(1),
            }
        }
    }
}

/// Decide the driver's presence and, when it is loaded, sweep the region.
pub fn survey_truecrypt(
    modules: &[DriverCandidate],
    list_complete: bool,
    region: Option<SweepRegion>,
    config: &TrueCryptConfig,
) -> TrueCryptSurvey {
    let found = modules.iter().find(|m| {
        m.name
            .as_deref()
            .is_some_and(|n| DRIVER_NAMES.iter().any(|d| n.eq_ignore_ascii_case(d)))
    });
    let driver = match found {
        Some(module) => DriverPresence::Present {
            name: module.name.clone().unwrap_or_default(),
            base: module.base,
            size: module.size,
        },
        None => {
            return TrueCryptSurvey {
                driver: DriverPresence::Absent {
                    modules_walked: modules.len(),
                    list_complete,
                },
                sweep: None,
                sweep_did_not_run_because: None,
            }
        }
    };
    let Some(region) = region else {
        return TrueCryptSurvey {
            driver,
            sweep: None,
            sweep_did_not_run_because: Some(
                "no non-paged pool region was available to sweep: the virtual-address map \
                 did not name one"
                    .to_string(),
            ),
        };
    };
    let scanner = ScheduleScanner { step: config.step };
    let end = region.base.saturating_add(region.bytes);
    let scan = match scan_range(
        region.layer.as_ref(),
        &scanner,
        region.base..end,
        &config.scan,
    ) {
        Ok(scan) => scan,
        Err(err) => {
            return TrueCryptSurvey {
                driver,
                sweep: None,
                sweep_did_not_run_because: Some(format!("the sweep could not start: {err}")),
            }
        }
    };
    let mut schedules = Vec::new();
    let mut unhashed = Vec::new();
    let mut truncated = false;
    for hit in &scan.hits {
        if schedules.len() + unhashed.len() >= config.max_schedules {
            truncated = true;
            break;
        }
        let (cipher, bits, key_len): (&'static str, u32, usize) = match hit.pattern_id {
            SERPENT_PATTERN => ("Serpent", 256, 32),
            TWOFISH_PATTERN => ("Twofish", 256, seance_bulk::twofish::STRUCT_BYTES),
            TWOFISH_TC_PATTERN => ("Twofish", 256, seance_bulk::twofish::TC_STRUCT_BYTES),
            TWOFISH_SUBKEYS_FIRST_PATTERN => ("Twofish", 256, seance_bulk::twofish::STRUCT_BYTES),
            CAMELLIA_PATTERN | CAMELLIA_LE64_PATTERN => {
                ("Camellia", 256, seance_bulk::camellia::TABLE_BYTES)
            }
            KUZNYECHIK_PATTERN => ("Kuznyechik", 256, seance_bulk::kuznyechik::SCHEDULE_BYTES),
            id => {
                let b = BITS[id as usize % BITS.len()];
                ("AES", b.bits(), b.key_len())
            }
        };
        let mut key = vec![0u8; key_len];
        match seance_core::io::read_exact_or_fail(
            region.layer.as_data_source(),
            hit.address,
            &mut key,
            "a key schedule",
        ) {
            Ok(()) => {
                // A Twofish or Camellia key is not stored in its schedule: it is recovered from it. A
                // Kuznyechik key is the schedule's first 32 bytes, and verifying it is the check.
                let key_bytes: Option<Vec<u8>> = match cipher {
                    "Twofish" if hit.pattern_id == TWOFISH_TC_PATTERN => {
                        seance_bulk::twofish::verify_tc_schedule_at(&key, 0).map(|r| r.key.to_vec())
                    }
                    "Twofish" if hit.pattern_id == TWOFISH_SUBKEYS_FIRST_PATTERN => {
                        seance_bulk::twofish::verify_subkeys_first_schedule_at(&key, 0)
                            .map(|r| r.key.to_vec())
                    }
                    "Twofish" => {
                        seance_bulk::twofish::verify_schedule_at(&key, 0).map(|r| r.key.to_vec())
                    }
                    "Camellia" if hit.pattern_id == CAMELLIA_LE64_PATTERN => {
                        seance_bulk::camellia::verify_table_le64_at(&key, 0).map(|r| r.key.to_vec())
                    }
                    "Camellia" => {
                        seance_bulk::camellia::verify_table_at(&key, 0).map(|r| r.key.to_vec())
                    }
                    "Kuznyechik" => {
                        seance_bulk::kuznyechik::verify_schedule_at(&key, 0).map(|r| r.key.to_vec())
                    }
                    _ => Some(key),
                };
                match key_bytes {
                    Some(k) => schedules.push(FoundSchedule {
                        address: hit.address,
                        bits,
                        cipher,
                        key_sha256: format!("{:x}", Sha256::digest(&k)),
                    }),
                    None => unhashed.push(UnhashedSchedule {
                        address: hit.address,
                        bits,
                        detail: "the schedule verified in the scan and its key could not be recovered when re-read"
                            .to_string(),
                    }),
                }
            }
            // The sweep verified the schedule from its own read; a key that
            // will not read again is still a schedule the region held.
            Err(err) => unhashed.push(UnhashedSchedule {
                address: hit.address,
                bits,
                detail: err.to_string(),
            }),
        }
    }
    let mut pairs = Vec::new();
    // A pair is two 256-bit schedules of the same cipher close together: an XTS volume's primary and
    // tweak keys.
    for cipher in ["AES", "Serpent", "Twofish"] {
        let same: Vec<u64> = schedules
            .iter()
            .filter(|s| s.bits == 256 && s.cipher == cipher)
            .map(|s| s.address)
            .collect();
        for window in same.windows(2) {
            if window[1].saturating_sub(window[0]) <= config.pair_distance {
                pairs.push((window[0], window[1]));
            }
        }
    }
    pairs.sort_unstable();
    let crypto_infos = decode_crypto_infos(region.layer.as_ref(), &schedules);
    TrueCryptSurvey {
        driver,
        sweep: Some(KeySweep {
            region_base: region.base,
            region_bytes: region.bytes,
            region_description: region.description,
            bytes_scanned: scan.bytes_scanned,
            scan,
            schedules,
            schedules_unhashed: unhashed,
            schedules_truncated: truncated,
            possible_xts_pairs: pairs,
            crypto_infos,
        }),
        sweep_did_not_run_because: None,
    }
}
