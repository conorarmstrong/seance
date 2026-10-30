//! Master boot records in physical memory (`ROADMAP` §5.3, upstream's
//! `mbrscan`).
//!
//! # What an examiner learns
//!
//! The first sector of a disk the machine read can stay in RAM — in the
//! cache manager's pages, in a driver's buffer, in the bootloader's leavings —
//! and it holds the disk's partition table and the 440 bytes of code the
//! firmware ran first. A bootkit lives in those 440 bytes, and a disk the
//! machine was never supposed to have shows up as a partition table nobody
//! imaged. This sweep finds every sector in the capture that could be one and
//! decodes it. It does not say where a sector came from: a disk image, an ISO
//! or a virtual disk the machine handled leaves the same bytes in memory as
//! a disk it booted from, and the record claims a partition table, not a disk.
//!
//! # What is a candidate, and what is not
//!
//! A sector-aligned 512-byte block ending in `55 AA`. **Sector-aligned** is the
//! first filter: a disk buffer is copied sector by sector into page-aligned
//! memory, so a real MBR lies at a multiple of 512 from the start of a page,
//! and a `55 AA` at any other offset is not one. A filesystem's own boot
//! sector ends in the same two bytes, so the second filter is the partition
//! table itself: four 16-byte entries at byte 446 whose status byte is `00`
//! or `80`, whose empty entries are all zero, whose non-empty entries start
//! above sector zero and do not overlap. **Every candidate is reported with
//! the checks it passed and failed** — a sector that fails is not a disk, and
//! it is not dropped either, because "how many boot sectors were in RAM" is
//! also a question.
//!
//! # What the record says and does not
//!
//! The boot code is hashed, not interpreted: whether 440 bytes are the stock
//! Windows loader or a bootkit is a comparison against a known set, and this
//! stage carries no such set. A partition type is published as its number
//! with the well-known name beside it where one is documented; a number this
//! table does not know is published as the number.

use seance_core::io::{read_exact_or_fail, IncompleteReason};
use seance_memory::scan::{scan_layer, Hit, ScanConfig, ScanControl, ScanOutcome, Scanner};
use seance_memory::{Incomplete, MemoryLayer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// A disk sector.
pub const SECTOR: u64 = 512;
/// Where the partition table begins inside the sector.
const TABLE_OFFSET: usize = 446;
/// Where the boot code ends and the disk signature begins.
const BOOT_CODE_LEN: usize = 440;

/// Publication caps.
#[derive(Debug, Clone)]
pub struct MbrScanConfig {
    /// Candidates decoded and published. Reaching it is stated.
    pub max_candidates: usize,
    pub scan: ScanConfig,
}

impl Default for MbrScanConfig {
    fn default() -> Self {
        Self {
            max_candidates: 4096,
            scan: ScanConfig::default(),
        }
    }
}

/// The scanner: a `55 AA` at bytes 510–511 of a 512-byte-aligned sector.
///
/// Hits are reported at the sector's **first** byte. The match is declared
/// 512 bytes long so the driver's chunk overlap carries a sector that
/// straddles a chunk boundary whole into the chunk that owns its start.
#[derive(Debug)]
pub struct MbrSectorScanner;

impl Scanner for MbrSectorScanner {
    fn name(&self) -> &str {
        "windows.mbr_sector"
    }

    fn max_match_len(&self) -> Option<u64> {
        Some(SECTOR)
    }

    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl) {
        // The first sector start at or after `base`.
        let first = base.div_ceil(SECTOR) * SECTOR;
        let mut start = first;
        while let Some(rel) = start.checked_sub(base) {
            let rel = rel as usize;
            let Some(tail) = chunk.get(rel + 510..rel + 512) else {
                break;
            };
            if tail == [0x55, 0xAA] {
                let hit = Hit {
                    address: start,
                    pattern_id: 0,
                    length: SECTOR as u32,
                };
                if sink(hit) == ScanControl::Stop {
                    return;
                }
            }
            start += SECTOR;
        }
    }
}

/// What a candidate sector turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbrKind {
    /// A partition table that passed every check, with ordinary partitions.
    Mbr,
    /// A partition table that passed every check whose only entry is the
    /// `0xEE` protective entry a GPT disk carries.
    GptProtective,
    /// A sector that ends in the signature and fails at least one check.
    NotAPartitionTable,
}

impl MbrKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mbr => "mbr",
            Self::GptProtective => "gpt_protective",
            Self::NotAPartitionTable => "not_a_partition_table",
        }
    }
}

/// One of the checks a candidate is held to.
#[derive(Debug, Clone)]
pub struct MbrCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

impl MbrCheck {
    pub fn to_json(&self) -> Value {
        json!({"name": self.name, "passed": self.passed, "detail": self.detail})
    }
}

/// One partition entry.
#[derive(Debug, Clone)]
pub struct MbrPartition {
    pub index: usize,
    pub status: u8,
    pub active: bool,
    pub partition_type: u8,
    /// The well-known name for the type, where one is documented.
    pub type_name: Option<&'static str>,
    pub first_lba: u32,
    pub sectors: u32,
    /// The CHS fields, raw: three bytes each for start and end.
    pub chs_start: [u8; 3],
    pub chs_end: [u8; 3],
}

impl MbrPartition {
    /// An entry whose sixteen bytes are all zero.
    pub fn is_empty(&self) -> bool {
        self.status == 0
            && self.partition_type == 0
            && self.first_lba == 0
            && self.sectors == 0
            && self.chs_start == [0; 3]
            && self.chs_end == [0; 3]
    }

    /// Exclusive last LBA, or `None` on overflow.
    pub fn end_lba(&self) -> Option<u64> {
        u64::from(self.first_lba).checked_add(u64::from(self.sectors))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "empty": self.is_empty(),
            "status": self.status,
            "active": self.active,
            "type": self.partition_type,
            "type_name": self.type_name,
            "first_lba": self.first_lba,
            "sectors": self.sectors,
            "bytes": u64::from(self.sectors) * SECTOR,
            "chs_start": self.chs_start,
            "chs_end": self.chs_end,
        })
    }
}

/// Well-known partition type identifiers, from the public partition-type
/// list. A number not here is published as its number.
pub fn partition_type_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0x00 => "empty",
        0x01 => "FAT12",
        0x04 => "FAT16 (<32 MiB)",
        0x05 => "extended (CHS)",
        0x06 => "FAT16",
        0x07 => "NTFS/exFAT/HPFS (IFS)",
        0x0B => "FAT32 (CHS)",
        0x0C => "FAT32 (LBA)",
        0x0E => "FAT16 (LBA)",
        0x0F => "extended (LBA)",
        0x11 => "hidden FAT12",
        0x14 => "hidden FAT16 (<32 MiB)",
        0x16 => "hidden FAT16",
        0x17 => "hidden NTFS/HPFS",
        0x1B => "hidden FAT32 (CHS)",
        0x1C => "hidden FAT32 (LBA)",
        0x1E => "hidden FAT16 (LBA)",
        0x27 => "Windows recovery (hidden NTFS)",
        0x42 => "Windows dynamic disk (LDM)",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x85 => "Linux extended",
        0x8E => "Linux LVM",
        0xA5 => "FreeBSD",
        0xA6 => "OpenBSD",
        0xA8 => "Apple UFS",
        0xA9 => "NetBSD",
        0xAB => "Apple boot",
        0xAF => "Apple HFS/HFS+",
        0xEE => "GPT protective",
        0xEF => "EFI system (FAT)",
        0xFD => "Linux RAID",
        _ => return None,
    })
}

/// One decoded candidate.
#[derive(Debug, Clone)]
pub struct MbrCandidate {
    /// Physical offset of the sector's first byte.
    pub offset: u64,
    pub kind: MbrKind,
    pub well_formed: bool,
    /// The four bytes at 440.
    pub disk_signature: u32,
    /// The two bytes at 444, which are `0x5A5A` on a copy-protected disk and
    /// zero otherwise.
    pub reserved: u16,
    pub partitions: Vec<MbrPartition>,
    pub checks: Vec<MbrCheck>,
    /// SHA-256 of bytes 0–439, for comparison against a known set this stage
    /// does not carry.
    pub boot_code_sha256: String,
    /// The boot code is all zero: a table with no loader, which a protective
    /// MBR written by some tools has.
    pub boot_code_empty: bool,
}

impl MbrCandidate {
    pub fn partitions_in_use(&self) -> usize {
        self.partitions.iter().filter(|p| !p.is_empty()).count()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryMbrCandidate",
            "name": format!("{} at physical {:#x}", self.kind.as_str(), self.offset),
            "offset": self.offset,
            "offset_hex": format!("{:#x}", self.offset),
            "kind": self.kind.as_str(),
            "well_formed": self.well_formed,
            "disk_signature": format!("{:08x}", self.disk_signature),
            "reserved": self.reserved,
            "partitions": self.partitions.iter().map(MbrPartition::to_json).collect::<Vec<_>>(),
            "partitions_in_use": self.partitions_in_use(),
            "checks": self.checks.iter().map(MbrCheck::to_json).collect::<Vec<_>>(),
            "checks_failed": self.checks.iter().filter(|c| !c.passed).count(),
            "boot_code_sha256": self.boot_code_sha256,
            "boot_code_empty": self.boot_code_empty,
        })
    }
}

/// Decode one 512-byte sector as a candidate MBR.
///
/// # Panics
///
/// Never; a short slice is refused with `None`.
pub fn decode_sector(offset: u64, sector: &[u8]) -> Option<MbrCandidate> {
    if sector.len() < SECTOR as usize || sector[510..512] != [0x55, 0xAA] {
        return None;
    }
    let disk_signature = u32::from_le_bytes(sector[440..444].try_into().ok()?);
    let reserved = u16::from_le_bytes(sector[444..446].try_into().ok()?);
    let partitions: Vec<MbrPartition> = (0..4)
        .map(|index| {
            let at = TABLE_OFFSET + index * 16;
            let e = &sector[at..at + 16];
            MbrPartition {
                index,
                status: e[0],
                active: e[0] == 0x80,
                partition_type: e[4],
                type_name: partition_type_name(e[4]),
                first_lba: u32::from_le_bytes([e[8], e[9], e[10], e[11]]),
                sectors: u32::from_le_bytes([e[12], e[13], e[14], e[15]]),
                chs_start: [e[1], e[2], e[3]],
                chs_end: [e[5], e[6], e[7]],
            }
        })
        .collect();

    let mut checks = Vec::new();
    let bad_status: Vec<usize> = partitions
        .iter()
        .filter(|p| p.status != 0x00 && p.status != 0x80)
        .map(|p| p.index)
        .collect();
    checks.push(MbrCheck {
        name: "status_bytes",
        passed: bad_status.is_empty(),
        detail: if bad_status.is_empty() {
            "every entry's status byte is 0x00 or 0x80".to_string()
        } else {
            format!("entries {bad_status:?} have a status byte other than 0x00 or 0x80")
        },
    });
    let half_empty: Vec<usize> = partitions
        .iter()
        .filter(|p| p.partition_type == 0 && !p.is_empty())
        .map(|p| p.index)
        .collect();
    checks.push(MbrCheck {
        name: "empty_entries_zeroed",
        passed: half_empty.is_empty(),
        detail: if half_empty.is_empty() {
            "every entry of type 0 is all zero".to_string()
        } else {
            format!("entries {half_empty:?} have type 0 and non-zero fields")
        },
    });
    let in_use: Vec<&MbrPartition> = partitions.iter().filter(|p| !p.is_empty()).collect();
    checks.push(MbrCheck {
        name: "has_a_partition",
        passed: !in_use.is_empty(),
        detail: format!("{} entr(y|ies) in use", in_use.len()),
    });
    let zero_start: Vec<usize> = in_use
        .iter()
        .filter(|p| p.first_lba == 0 || p.sectors == 0)
        .map(|p| p.index)
        .collect();
    checks.push(MbrCheck {
        name: "extents_nonzero",
        passed: zero_start.is_empty(),
        detail: if zero_start.is_empty() {
            "every entry in use starts above sector 0 and spans at least one sector".to_string()
        } else {
            format!("entries {zero_start:?} start at sector 0 or span no sectors")
        },
    });
    let active: Vec<usize> = in_use
        .iter()
        .filter(|p| p.active)
        .map(|p| p.index)
        .collect();
    checks.push(MbrCheck {
        name: "at_most_one_active",
        passed: active.len() <= 1,
        detail: format!("{} active entr(y|ies)", active.len()),
    });
    let mut overlaps = Vec::new();
    for (i, a) in in_use.iter().enumerate() {
        for b in in_use.iter().skip(i + 1) {
            if let (Some(a_end), Some(b_end)) = (a.end_lba(), b.end_lba()) {
                if u64::from(a.first_lba) < b_end && u64::from(b.first_lba) < a_end {
                    overlaps.push((a.index, b.index));
                }
            }
        }
    }
    checks.push(MbrCheck {
        name: "no_overlap",
        passed: overlaps.is_empty(),
        detail: if overlaps.is_empty() {
            "no two entries in use overlap".to_string()
        } else {
            format!("entries overlap: {overlaps:?}")
        },
    });

    let well_formed = checks.iter().all(|c| c.passed);
    let kind = if !well_formed {
        MbrKind::NotAPartitionTable
    } else if in_use.len() == 1 && in_use[0].partition_type == 0xEE {
        MbrKind::GptProtective
    } else {
        MbrKind::Mbr
    };
    let boot_code = &sector[..BOOT_CODE_LEN];
    Some(MbrCandidate {
        offset,
        kind,
        well_formed,
        disk_signature,
        reserved,
        partitions,
        checks,
        boot_code_sha256: format!("{:x}", Sha256::digest(boot_code)),
        boot_code_empty: boot_code.iter().all(|b| *b == 0),
    })
}

/// What one sweep produced.
#[derive(Debug, Clone)]
pub struct MbrScan {
    pub scan: ScanOutcome,
    /// Sector-aligned sectors ending in `55 AA`, whether or not decoded.
    pub sectors_with_signature: u64,
    /// Candidates decoded, in ascending physical order, capped.
    pub candidates: Vec<MbrCandidate>,
    pub candidates_truncated: bool,
    /// Candidates whose 512 bytes could not be re-read for decoding.
    pub candidates_unreadable: u64,
}

impl MbrScan {
    pub fn well_formed(&self) -> usize {
        self.candidates.iter().filter(|c| c.well_formed).count()
    }

    pub fn is_complete(&self) -> bool {
        self.scan.is_complete() && !self.candidates_truncated && self.candidates_unreadable == 0
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if !self.scan.is_complete() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} byte(s) of the image were not examined ({} of them never mapped), so a \
                     boot sector among them would not be listed",
                    self.scan.unread_bytes, self.scan.unmapped_bytes
                ),
            ));
        }
        if self.candidates_truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} sector(s) carry the signature and only the first {} were decoded",
                    self.sectors_with_signature,
                    self.candidates.len()
                ),
            ));
        }
        if self.candidates_unreadable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} candidate sector(s) could not be re-read for decoding",
                    self.candidates_unreadable
                ),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        let protective = self
            .candidates
            .iter()
            .filter(|c| c.kind == MbrKind::GptProtective)
            .count();
        format!(
            "{} byte(s) of physical memory were examined for sector-aligned boot sectors; {} \
             end in 55 AA, {} decode as a well-formed partition table ({} of them a GPT \
             disk's protective MBR) and {} do not.",
            self.scan.bytes_scanned,
            self.sectors_with_signature,
            self.well_formed(),
            protective,
            self.candidates.len() - self.well_formed()
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "scan": self.scan.to_json(),
            "bytes_scanned": self.scan.bytes_scanned,
            "unread_bytes": self.scan.unread_bytes,
            "unmapped_bytes": self.scan.unmapped_bytes,
            "sectors_with_signature": self.sectors_with_signature,
            "candidates": self.candidates.iter().map(MbrCandidate::to_json).collect::<Vec<_>>(),
            "candidates_published": self.candidates.len(),
            "candidates_truncated": self.candidates_truncated,
            "candidates_unreadable": self.candidates_unreadable,
            "well_formed": self.well_formed(),
            "basis":
                "Every 512-byte-aligned sector of physical memory ending in 55 AA is a candidate; \
                 a disk buffer is copied sector by sector into page-aligned memory, so a real \
                 boot sector lies at a multiple of 512 and a signature elsewhere is not one. \
                 Each candidate's partition table is held to six checks (status bytes, empty \
                 entries zeroed, at least one entry, extents above sector 0, at most one \
                 active, no overlap) and is published with every check's outcome; a \
                 filesystem's own boot sector ends in the same bytes and fails them. The boot \
                 code is hashed, not judged: this stage carries no set of known loaders.",
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Sweep a physical layer for boot sectors.
pub fn scan_for_mbrs(layer: &dyn MemoryLayer, config: &MbrScanConfig) -> MbrScan {
    let outcome = match scan_layer(layer, &MbrSectorScanner, &config.scan) {
        Ok(outcome) => outcome,
        Err(err) => {
            return MbrScan {
                scan: ScanOutcome {
                    scanner: format!("windows.mbr_sector (did not run: {err})"),
                    truncated: true,
                    ..ScanOutcome::default()
                },
                sectors_with_signature: 0,
                candidates: Vec::new(),
                candidates_truncated: false,
                candidates_unreadable: 0,
            }
        }
    };
    let mut scan = MbrScan {
        sectors_with_signature: outcome.hits.len() as u64,
        scan: outcome,
        candidates: Vec::new(),
        candidates_truncated: false,
        candidates_unreadable: 0,
    };
    for hit in &scan.scan.hits {
        if scan.candidates.len() >= config.max_candidates {
            scan.candidates_truncated = true;
            break;
        }
        let mut sector = [0u8; SECTOR as usize];
        if read_exact_or_fail(
            layer.as_data_source(),
            hit.address,
            &mut sector,
            "a boot sector",
        )
        .is_err()
        {
            scan.candidates_unreadable += 1;
            continue;
        }
        if let Some(candidate) = decode_sector(hit.address, &sector) {
            scan.candidates.push(candidate);
        }
    }
    scan
}
