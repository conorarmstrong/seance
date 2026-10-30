//! The NTFS boot sector: the volume's own account of its geometry.
//!
//! # Why this is its own module
//!
//! Every NTFS reader in this plugin needs the same six numbers, and until now
//! two places decoded them: `parse_ntfs_boot_sector` took two fields, and
//! `mft_scan_phase` re-read `0x0B`, `0x0D` and `0x30` by hand. Two decoders for
//! one structure is how they come to disagree — and one of them already had:
//! the scan phase used the raw `sectors_per_cluster` byte, which on a volume
//! with clusters above 64 KiB is an encoded exponent, so it computed a bogus
//! alignment and found no records at all.
//!
//! `ROADMAP` §1.7.
//!
//! # The two signed fields
//!
//! `clusters_per_mft_record` (`0x40`) and `clusters_per_index_record` (`0x44`)
//! are **signed**. A negative `n` means `1 << -n` **bytes**; a positive `n`
//! means `n` clusters. The real image this was written against carries `0xF6`
//! (−10) → 1,024 bytes, which is what `fsstat` reports.
//!
//! The shift is guarded. A hostile `0x80` is −128, and `1 << 128` is a panic
//! under `overflow-checks` — the same class of defect as
//! `compression_unit_bytes`, and a panic here unwinds `process()` and loses
//! every file in the table rather than one field.
//!
//! # What this does not claim
//!
//! **The checksum at `0x50` is not validated.** Real NTFS leaves it zero, so
//! "checksum valid" would be a statement about a field nobody writes.

use byteorder::{ByteOrder, LittleEndian};

/// Bytes of a boot sector.
pub(crate) const BOOT_SECTOR_BYTES: usize = 512;

/// The NTFS signature at offset 3, including its padding.
const OEM_ID: &[u8; 8] = b"NTFS    ";

/// The NTFS boot sector / BPB, decoded in full.
///
/// Field offsets are named beside their values so a reader can check them
/// against the format without decoding arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NtfsBootSector {
    /// `0x0B`
    pub bytes_per_sector: u64,
    /// `0x0D`, after the `>0xF0` exponent encoding is resolved.
    pub sectors_per_cluster: u64,
    /// `0x15`
    pub media_descriptor: u8,
    /// `0x18`
    pub sectors_per_track: u16,
    /// `0x1A`
    pub number_of_heads: u16,
    /// `0x1C` — where the partition begins, in sectors.
    pub hidden_sectors: u32,
    /// `0x28`
    pub total_sectors: u64,
    /// `0x30` — signed in the format, and kept signed here.
    pub mft_cluster: i64,
    /// `0x38`
    pub mft_mirror_cluster: i64,
    /// `0x40`, raw.
    pub clusters_per_mft_record_raw: i8,
    /// `0x44`, raw.
    pub clusters_per_index_record_raw: i8,
    /// `0x48`
    pub volume_serial: u64,
}

/// Decode the NTFS sectors-per-cluster byte (BPB `0x0D`).
///
/// Values above `0xF0` encode `2^(256 - n)` sectors per cluster — the large
/// cluster sizes above 64 KiB; `1..=0x80` are literal counts; `0x81..=0xF0` is
/// reserved and yields `None`.
pub(crate) fn decode_sectors_per_cluster(spc: u8) -> Option<u64> {
    if spc == 0 {
        None
    } else if spc <= 0x80 {
        Some(spc as u64)
    } else if spc > 0xF0 {
        Some(1u64 << (256u32 - spc as u32))
    } else {
        None
    }
}

/// Resolve a signed record-size byte into bytes.
///
/// Negative `n` → `1 << -n` bytes. Positive `n` → `n * cluster_size` bytes.
///
/// The shift is bounded to `1..=31`. `0x80` is −128 and `1 << 128` panics under
/// `overflow-checks`; a value outside the range is a corrupt descriptor and
/// yields `None` rather than a fabricated size.
pub(crate) fn record_size_bytes(raw: i8, cluster_size: u64) -> Option<u64> {
    if raw < 0 {
        let shift = raw.unsigned_abs() as u32;
        if !(1..=31).contains(&shift) {
            return None;
        }
        Some(1u64 << shift)
    } else if raw == 0 {
        None
    } else {
        (raw as u64).checked_mul(cluster_size)
    }
}

impl NtfsBootSector {
    /// Decode a boot sector, or `None` when these bytes are not one.
    ///
    /// The gate is exactly the one the two previous decoders applied — the
    /// `NTFS    ` signature, a non-zero power-of-two sector size, and a
    /// decodable sectors-per-cluster — so no volume that parses today stops
    /// parsing.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < BOOT_SECTOR_BYTES || &bytes[3..11] != OEM_ID {
            return None;
        }
        let bytes_per_sector = LittleEndian::read_u16(&bytes[0x0B..0x0D]) as u64;
        if bytes_per_sector == 0 || !bytes_per_sector.is_power_of_two() {
            return None;
        }
        let sectors_per_cluster = decode_sectors_per_cluster(bytes[0x0D])?;
        Some(Self {
            bytes_per_sector,
            sectors_per_cluster,
            media_descriptor: bytes[0x15],
            sectors_per_track: LittleEndian::read_u16(&bytes[0x18..0x1A]),
            number_of_heads: LittleEndian::read_u16(&bytes[0x1A..0x1C]),
            hidden_sectors: LittleEndian::read_u32(&bytes[0x1C..0x20]),
            total_sectors: LittleEndian::read_u64(&bytes[0x28..0x30]),
            mft_cluster: LittleEndian::read_i64(&bytes[0x30..0x38]),
            mft_mirror_cluster: LittleEndian::read_i64(&bytes[0x38..0x40]),
            clusters_per_mft_record_raw: bytes[0x40] as i8,
            clusters_per_index_record_raw: bytes[0x44] as i8,
            volume_serial: LittleEndian::read_u64(&bytes[0x48..0x50]),
        })
    }

    pub(crate) fn cluster_size(&self) -> u64 {
        self.bytes_per_sector * self.sectors_per_cluster
    }

    /// Total clusters, by the arithmetic this plugin has always used.
    ///
    /// `fsstat` prints the cluster *range* — one less than this — so the two
    /// agree and neither is to be "corrected" into the other.
    pub(crate) fn total_clusters(&self) -> u64 {
        self.total_sectors / self.sectors_per_cluster
    }

    pub(crate) fn mft_record_size(&self) -> Option<u64> {
        record_size_bytes(self.clusters_per_mft_record_raw, self.cluster_size())
    }

    pub(crate) fn index_record_size(&self) -> Option<u64> {
        record_size_bytes(self.clusters_per_index_record_raw, self.cluster_size())
    }

    /// The serial as `fsstat` prints it: sixteen uppercase hex digits.
    pub(crate) fn volume_serial_hex(&self) -> String {
        format!("{:016X}", self.volume_serial)
    }

    /// The serial as Windows `vol` prints it: the low dword, `XXXX-XXXX`.
    pub(crate) fn volume_serial_short(&self) -> String {
        let low = (self.volume_serial & 0xFFFF_FFFF) as u32;
        format!("{:04X}-{:04X}", low >> 16, low & 0xFFFF)
    }

    /// Byte offset of the backup boot sector: the sector immediately past the
    /// volume's addressable range.
    pub(crate) fn backup_boot_sector_offset(&self) -> Option<u64> {
        self.total_sectors.checked_mul(self.bytes_per_sector)
    }
}

/// The record this boot sector becomes.
///
/// # What it states, and what it refuses to
///
/// **The serial in three labelled forms and no unlabelled one.** `fsstat`
/// prints sixteen hex digits, Windows `vol` prints the low dword as
/// `XXXX-XXXX`, and the raw `u64` is neither. An unlabelled "serial" invites a
/// reader to compare the wrong one against a note or a warrant.
///
/// **A record size the volume did not give is absent, not defaulted.** A
/// corrupt `0x40` yields no `mft_record_size` rather than 1,024 — the
/// constant `lib.rs` used to carry.
///
/// **The checksum at `0x50` is not validated.** Real NTFS leaves it zero, so a
/// "checksum valid" field would describe a value nobody writes.
pub(crate) fn boot_sector_metadata(
    b: &NtfsBootSector,
    backup: BackupComparison,
    boot_code_bytes_not_interpreted: Option<u64>,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    // `$.type` is what decides the UI grouping (`seance_db::RECORD_TYPE_EXPR`
    // coalesces it first). Not `record_type`, which exists only for legacy
    // rows and is the defect UI-009 came from.
    m.insert("type".into(), serde_json::json!("NtfsBootSector"));
    m.insert("name".into(), serde_json::json!("$Boot (NTFS boot sector)"));
    m.insert(
        "bytes_per_sector".into(),
        serde_json::json!(b.bytes_per_sector),
    );
    m.insert(
        "sectors_per_cluster".into(),
        serde_json::json!(b.sectors_per_cluster),
    );
    m.insert("cluster_size".into(), serde_json::json!(b.cluster_size()));
    m.insert("total_sectors".into(), serde_json::json!(b.total_sectors));
    m.insert(
        "total_clusters".into(),
        serde_json::json!(b.total_clusters()),
    );
    m.insert(
        "total_clusters_note".into(),
        serde_json::json!(
            "the count of clusters; `fsstat` prints the cluster RANGE, which is one less"
        ),
    );
    m.insert("hidden_sectors".into(), serde_json::json!(b.hidden_sectors));
    m.insert(
        "hidden_sectors_note".into(),
        serde_json::json!("where the partition begins, in sectors"),
    );
    m.insert(
        "media_descriptor".into(),
        serde_json::json!(b.media_descriptor),
    );
    m.insert(
        "sectors_per_track".into(),
        serde_json::json!(b.sectors_per_track),
    );
    m.insert(
        "number_of_heads".into(),
        serde_json::json!(b.number_of_heads),
    );
    m.insert("mft_cluster".into(), serde_json::json!(b.mft_cluster));
    m.insert(
        "mft_mirror_cluster".into(),
        serde_json::json!(b.mft_mirror_cluster),
    );
    m.insert(
        "clusters_per_mft_record_raw".into(),
        serde_json::json!(b.clusters_per_mft_record_raw),
    );
    m.insert(
        "clusters_per_index_record_raw".into(),
        serde_json::json!(b.clusters_per_index_record_raw),
    );
    m.insert(
        "mft_record_size".into(),
        serde_json::json!(b.mft_record_size()),
    );
    m.insert(
        "index_record_size".into(),
        serde_json::json!(b.index_record_size()),
    );
    if b.mft_record_size().is_none() || b.index_record_size().is_none() {
        m.insert(
            "record_size_note".into(),
            serde_json::json!(
                "a record-size byte this build cannot resolve is reported absent rather than \
                 defaulted; the value it would have been defaulted to is a guess about the \
                 volume"
            ),
        );
    }
    // Three forms, each labelled. See the doc comment.
    m.insert(
        "volume_serial_raw".into(),
        serde_json::json!(b.volume_serial),
    );
    m.insert(
        "volume_serial_hex".into(),
        serde_json::json!(b.volume_serial_hex()),
    );
    m.insert(
        "volume_serial_short".into(),
        serde_json::json!(b.volume_serial_short()),
    );
    m.insert(
        "volume_serial_note".into(),
        serde_json::json!(
            "three renderings of one number: `hex` is what fsstat prints, `short` is the low \
             dword as Windows `vol` prints it, `raw` is the u64. They are the same serial."
        ),
    );
    m.insert("checksum_validated".into(), serde_json::json!(false));
    m.insert(
        "checksum_note".into(),
        serde_json::json!(
            "the BPB checksum field at 0x50 is left zero by real NTFS, so it is reported as \
             not validated rather than as valid"
        ),
    );
    match backup {
        BackupComparison::Matches => {
            m.insert(
                "backup_boot_sector_assessed".into(),
                serde_json::json!(true),
            );
            m.insert("backup_boot_sector_matches".into(), serde_json::json!(true));
        }
        BackupComparison::Differs => {
            m.insert(
                "backup_boot_sector_assessed".into(),
                serde_json::json!(true),
            );
            m.insert(
                "backup_boot_sector_matches".into(),
                serde_json::json!(false),
            );
        }
        BackupComparison::NotReachable => {
            // NEVER `matches: false` here. A volume whose backup sector is
            // outside the window read would render as a tampered volume, which
            // is the most serious thing this record could say and would be
            // said by an absence rather than by evidence.
            m.insert(
                "backup_boot_sector_assessed".into(),
                serde_json::json!(false),
            );
            m.insert("content_incomplete".into(), serde_json::json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                serde_json::json!(seance_core::io::IncompleteReason::Unmapped.as_str()),
            );
            m.insert(
                "backup_boot_sector_note".into(),
                serde_json::json!(
                    "NTFS keeps a copy of this sector immediately past the volume's last \
                     addressable sector. It was not reachable in the bytes read, so the two \
                     were not compared. This is NOT a mismatch: a mismatch would be evidence \
                     the volume had been altered, and none was gathered either way."
                ),
            );
        }
    }
    if let Some(n) = boot_code_bytes_not_interpreted {
        m.insert(
            "boot_code_bytes_not_interpreted".into(),
            serde_json::json!(n),
        );
        m.insert(
            "boot_code_note".into(),
            serde_json::json!(
                "the $Boot file is larger than the 512-byte BPB this record decodes; the \
                 remainder is boot code, which is kept in the file and not interpreted here"
            ),
        );
    }
    serde_json::Value::Object(m)
}

/// Whether the volume's backup boot sector was compared, and what came of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackupComparison {
    Matches,
    Differs,
    /// The backup sector was not in the bytes read. **Not** a mismatch.
    NotReachable,
}

/// Compare the boot sector against the volume's backup copy.
///
/// Returns [`BackupComparison::NotReachable`] whenever the copy could not be
/// read — a bare 8 KiB `$Boot` file, a truncated image, an offset that
/// overflows. Reporting a mismatch in that case would accuse the volume on the
/// strength of a short read.
pub(crate) fn compare_backup(
    source: &dyn seance_core::data_source::DataSource,
    b: &NtfsBootSector,
    primary: &[u8],
) -> BackupComparison {
    let Some(offset) = b.backup_boot_sector_offset() else {
        return BackupComparison::NotReachable;
    };
    let mut copy = [0u8; BOOT_SECTOR_BYTES];
    match source.read_at(offset, &mut copy) {
        Ok(n) if n == BOOT_SECTOR_BYTES => {
            if primary.len() >= BOOT_SECTOR_BYTES && copy[..] == primary[..BOOT_SECTOR_BYTES] {
                BackupComparison::Matches
            } else {
                BackupComparison::Differs
            }
        }
        _ => BackupComparison::NotReachable,
    }
}
