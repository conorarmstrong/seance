//! The file-structure layer (ECMA-167 part 4): File Entries, allocation
//! descriptors and the File Identifier Descriptors that make a directory.

use crate::cs0;
use crate::descriptors::LongAd;
use crate::partition::Partitions;
use crate::tag::{self, ident};
use crate::timestamp;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{byte_runs_to_metadata, DataSource, RunListDataSource};
use seance_core::io::{read_exact_or_fail, IncompleteReason};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

// Budgets that bound the work a crafted image can demand.
pub const MAX_RECORDS: usize = 200_000;
pub const MAX_DEPTH: usize = 64;
pub const MAX_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
/// Allocation Extent Descriptors followed for one file.
const MAX_AED_CHAIN: usize = 4096;
/// Allocation descriptors kept for one file.
const MAX_EXTENTS: usize = 1 << 20;

// ICB file types (ECMA-167 4/14.6.6).
const FT_DIRECTORY: u8 = 4;
const FT_SYMLINK: u8 = 12;

// File characteristics (ECMA-167 4/14.4.3).
const FC_HIDDEN: u8 = 0x01;
const FC_DIRECTORY: u8 = 0x02;
const FC_DELETED: u8 = 0x04;
const FC_PARENT: u8 = 0x08;

/// An extent of a file's content, in absolute bytes of the volume window.
#[derive(Debug, Clone, Copy)]
struct Run {
    /// `None` for an extent that is allocated but not recorded, or not
    /// allocated: it reads as zeros (ECMA-167 4/14.14.1.1).
    offset: Option<u64>,
    length: u64,
}

/// What a File Entry or Extended File Entry said.
pub(crate) struct Icb {
    pub(crate) file_type: u8,
    pub(crate) info_len: u64,
    uid: u32,
    gid: u32,
    permissions: u32,
    link_count: u16,
    unique_id: u64,
    accessed: Option<timestamp::Decoded>,
    modified: Option<timestamp::Decoded>,
    changed: Option<timestamp::Decoded>,
    created: Option<timestamp::Decoded>,
    /// Timestamp fields that were recorded (not all zero) but did not decode.
    undecodable_timestamps: Vec<&'static str>,
    ea_len: u32,
    stream_directory: bool,
    extended: bool,
    runs: Vec<Run>,
    /// Set when the content description is known to be short or wrong.
    pub(crate) content_problem: Option<(&'static str, IncompleteReason)>,
}

pub struct Walker<'a> {
    pub ds: &'a Arc<dyn DataSource>,
    pub block_size: u64,
    pub parts: &'a Partitions,
    pub case_id: Uuid,
    pub root_id: Uuid,
    pub produced: Vec<Artifact>,
    pub records_seen: usize,
    visited: HashSet<(u16, u32)>,
    pub any_incomplete: bool,
    /// The first reason any directory in the tree stopped short, so the
    /// volume record names it even when the failure was nested.
    pub first_incomplete_reason: Option<&'static str>,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]))
}

impl<'a> Walker<'a> {
    pub fn new(
        ds: &'a Arc<dyn DataSource>,
        block_size: u64,
        parts: &'a Partitions,
        case_id: Uuid,
        root_id: Uuid,
    ) -> Self {
        Self {
            ds,
            block_size,
            parts,
            case_id,
            root_id,
            produced: Vec::new(),
            records_seen: 0,
            visited: HashSet::new(),
            any_incomplete: false,
            first_incomplete_reason: None,
        }
    }

    fn mark(&mut self, reason: &'static str) -> &'static str {
        self.any_incomplete = true;
        self.first_incomplete_reason.get_or_insert(reason);
        reason
    }

    /// Absolute byte offset of a partition block, or why it has none.
    fn block_offset(&self, part_ref: u16, lbn: u32) -> Result<u64, &'static str> {
        Ok(self.parts.translate(part_ref, lbn)? * self.block_size)
    }

    /// Read and parse the File Entry at `at`.
    pub(crate) fn read_icb(&self, at: LongAd) -> Result<Icb, &'static str> {
        // An ICB extent of length zero records no File Entry at all (the
        // Linux driver zeroes a deleted FID's ICB this way). Block 0 is not
        // read in its place.
        if at.length == 0 {
            return Err("icb_not_recorded");
        }
        let off = self.block_offset(at.part_ref, at.lbn)?;
        let bs = self.block_size as usize;
        let mut b = vec![0u8; bs];
        read_exact_or_fail(self.ds.as_ref(), off, &mut b, "UDF file entry")
            .map_err(|_| "file_entry_unreadable")?;
        let t = tag::verify(&b, None, Some(at.lbn)).map_err(|e| e.as_str())?;
        let extended = match t.ident {
            ident::FE => false,
            ident::EFE => true,
            _ => return Err("not_a_file_entry"),
        };
        let strategy = u16_at(&b, 20);
        if strategy != 4 {
            return Err("icb_strategy_unsupported");
        }
        let file_type = b[27];
        let ad_type = u16_at(&b, 34) & 0x7;
        let (a_at, m_at, attr_at, c_at, ea_len_at, ad_base) = if extended {
            (80, 92, 116, Some(104), 208, 216)
        } else {
            (72, 84, 96, None, 168, 176)
        };
        let ea_len = u32_at(&b, ea_len_at);
        let ad_len = u32_at(&b, ea_len_at + 4);
        let ad_start = ad_base as u64 + ea_len as u64;
        let ad_end = ad_start + ad_len as u64;
        if ad_end > bs as u64 {
            return Err("allocation_descriptors_exceed_block");
        }
        let ads = &b[ad_start as usize..ad_end as usize];
        let info_len = u64_at(&b, 56);
        let ts = |o: usize| timestamp::decode(&b[o..o + 12]);
        let mut undecodable_timestamps = Vec::new();
        for (key, o) in [
            ("accessed", Some(a_at)),
            ("modified", Some(m_at)),
            ("changed", Some(attr_at)),
            ("created", c_at),
        ] {
            if let Some(o) = o {
                if ts(o).is_none() && b[o..o + 12].iter().any(|&x| x != 0) {
                    undecodable_timestamps.push(key);
                }
            }
        }
        let mut icb = Icb {
            file_type,
            info_len,
            uid: u32_at(&b, 36),
            gid: u32_at(&b, 40),
            permissions: u32_at(&b, 44),
            link_count: u16_at(&b, 48),
            unique_id: u64_at(&b, if extended { 200 } else { 160 }),
            accessed: ts(a_at),
            modified: ts(m_at),
            changed: ts(attr_at),
            created: c_at.and_then(ts),
            undecodable_timestamps,
            ea_len,
            stream_directory: extended
                && LongAd::parse(&b[152..168]).is_some_and(|l| l.length != 0),
            extended,
            runs: Vec::new(),
            content_problem: None,
        };
        match ad_type {
            0 | 1 => self.collect_runs(&mut icb, ads, ad_type, at.part_ref),
            3 => {
                // Embedded: the content is the allocation-descriptor area.
                icb.runs.push(Run {
                    offset: Some(off + ad_start),
                    length: ad_len as u64,
                });
                Self::check_shortfall(&mut icb);
            }
            _ => return Err("extended_allocation_descriptors_unsupported"),
        }
        Ok(icb)
    }

    /// Walk short (0) or long (1) allocation descriptors, following
    /// Allocation Extent Descriptors, into absolute runs.
    fn collect_runs(&self, icb: &mut Icb, first: &[u8], ad_type: u16, own_part: u16) {
        let ad_size = if ad_type == 0 { 8 } else { 16 };
        let mut area = first.to_vec();
        let mut chain = 0usize;
        'areas: loop {
            let mut next: Option<(u16, u32)> = None;
            for ad in area.chunks_exact(ad_size) {
                let raw = u32_at(ad, 0);
                let length = (raw & 0x3FFF_FFFF) as u64;
                let ext_type = (raw >> 30) as u8;
                if length == 0 {
                    break;
                }
                let (lbn, part_ref) = if ad_type == 0 {
                    (u32_at(ad, 4), own_part)
                } else {
                    (u32_at(ad, 4), u16_at(ad, 8))
                };
                if ext_type == 3 {
                    next = Some((part_ref, lbn));
                    break;
                }
                if icb.runs.len() >= MAX_EXTENTS {
                    icb.content_problem =
                        Some(("extent_budget_exhausted", IncompleteReason::CapReached));
                    break 'areas;
                }
                if ext_type != 0 {
                    icb.runs.push(Run {
                        offset: None,
                        length,
                    });
                    continue;
                }
                let mapped = match self.parts.map_extent(part_ref, lbn, length) {
                    Ok(m) => m,
                    Err(why) => {
                        icb.content_problem = Some((
                            if why == "block_outside_partition" {
                                "extent_outside_partition"
                            } else {
                                why
                            },
                            IncompleteReason::UnresolvedStructure,
                        ));
                        icb.runs.push(Run {
                            offset: None,
                            length,
                        });
                        continue;
                    }
                };
                for (offset, len) in mapped {
                    // The partition may say the block exists while the
                    // evidence (a truncated acquisition, an ISO cut at 4 GiB)
                    // ends before it: the read will come up short, and the
                    // entry must say so.
                    if offset.is_some_and(|o| o.saturating_add(len) > self.ds.size())
                        && icb.content_problem.is_none()
                    {
                        icb.content_problem =
                            Some(("extent_past_end_of_evidence", IncompleteReason::ShortRead));
                    }
                    icb.runs.push(Run {
                        offset,
                        length: len,
                    });
                }
            }
            let Some((part_ref, lbn)) = next else { break };
            chain += 1;
            if chain > MAX_AED_CHAIN {
                icb.content_problem = Some((
                    "allocation_extent_chain_too_long",
                    IncompleteReason::CapReached,
                ));
                break;
            }
            let aed = self.block_offset(part_ref, lbn).ok().and_then(|off| {
                let mut b = vec![0u8; self.block_size as usize];
                read_exact_or_fail(self.ds.as_ref(), off, &mut b, "UDF allocation extent").ok()?;
                tag::verify(&b, Some(ident::AED), Some(lbn)).ok()?;
                let l = u32_at(&b, 20) as usize;
                b.get(24..24 + l).map(<[u8]>::to_vec)
            });
            match aed {
                Some(a) => area = a,
                None => {
                    icb.content_problem = Some((
                        "allocation_extent_descriptor_unreadable",
                        IncompleteReason::UnresolvedStructure,
                    ));
                    break;
                }
            }
        }
        Self::check_shortfall(icb);
    }

    /// Flag a file whose recorded content (extents, or the embedded bytes)
    /// is shorter than its information length: the tail would otherwise be
    /// served as zeros that are not on the disc.
    fn check_shortfall(icb: &mut Icb) {
        let recorded: u64 = icb.runs.iter().map(|r| r.length).sum();
        if recorded < icb.info_len && icb.content_problem.is_none() {
            icb.content_problem = Some((
                "allocation_shorter_than_information_length",
                IncompleteReason::UnresolvedStructure,
            ));
        }
    }

    /// Runs fitted to the file's information length.
    fn fitted_runs(icb: &Icb) -> Vec<(Option<u64>, u64)> {
        seance_core::data_source::fit_runs_to_logical(
            icb.runs.iter().map(|r| (r.offset, r.length)).collect(),
            icb.info_len,
        )
    }

    /// Read a whole file's content into memory (a directory's FID stream,
    /// a Virtual Allocation Table), refusing past `max` bytes.
    pub(crate) fn file_bytes(&self, icb: &Icb, max: u64) -> Result<Vec<u8>, &'static str> {
        if icb.info_len > max {
            return Err("file_too_large_to_read_whole");
        }
        let src = RunListDataSource::from_allocation(Arc::clone(self.ds), Self::fitted_runs(icb));
        let mut buf = vec![0u8; icb.info_len as usize];
        read_exact_or_fail(&src, 0, &mut buf, "UDF file").map_err(|_| "extent_read_failed")?;
        Ok(buf)
    }

    /// The absolute byte runs of a file's content, fitted to its length.
    pub(crate) fn content_runs(icb: &Icb) -> Vec<(Option<u64>, u64)> {
        Self::fitted_runs(icb)
    }

    /// Read a directory's FID stream into memory.
    fn directory_bytes(&self, icb: &Icb) -> Result<Vec<u8>, &'static str> {
        if icb.info_len > MAX_DIRECTORY_BYTES {
            return Err("directory_too_large");
        }
        let src = RunListDataSource::from_allocation(Arc::clone(self.ds), Self::fitted_runs(icb));
        let mut buf = vec![0u8; icb.info_len as usize];
        read_exact_or_fail(&src, 0, &mut buf, "UDF directory").map_err(|_| "extent_read_failed")?;
        Ok(buf)
    }

    /// Walk the root directory.
    pub fn walk_root(&mut self, root: LongAd) -> Option<&'static str> {
        let icb = match self.read_icb(root) {
            Ok(i) => i,
            Err(e) => return Some(self.mark(e)),
        };
        self.visited.insert((root.part_ref, root.lbn));
        self.walk_dir(&icb, "/", 0)
    }

    fn walk_dir(&mut self, dir: &Icb, path: &str, depth: usize) -> Option<&'static str> {
        if depth > MAX_DEPTH {
            return Some(self.mark("max_depth"));
        }
        if let Some((reason, _)) = dir.content_problem {
            warn!("UDF: directory {} allocation: {}", path, reason);
            self.mark(reason);
        }
        let bytes = match self.directory_bytes(dir) {
            Ok(b) => b,
            Err(e) => return Some(self.mark(e)),
        };
        let mut o = 0usize;
        let mut status = dir.content_problem.map(|(r, _)| r);
        while o + 38 <= bytes.len() {
            let f = &bytes[o..];
            let l_iu = u16_at(f, 36) as usize;
            let l_fi = f[19] as usize;
            let len = (38 + l_iu + l_fi).div_ceil(4) * 4;
            if 38 + l_iu + l_fi > f.len() {
                return Some(self.mark("file_identifier_truncated"));
            }
            let fid = &f[..len.min(f.len())];
            if let Err(e) = tag::verify(fid, Some(ident::FID), None) {
                warn!("UDF: bad FID in {} at +{}: {}", path, o, e.as_str());
                return Some(self.mark("file_identifier_descriptor_invalid"));
            }
            o += len;
            let chars = fid[18];
            if chars & FC_PARENT != 0 {
                continue;
            }
            self.records_seen += 1;
            if self.records_seen > MAX_RECORDS {
                return Some(self.mark("record_budget_exhausted"));
            }
            let Some(target) = LongAd::parse(&fid[20..36]) else {
                continue;
            };
            let name_bytes = &fid[38 + l_iu..38 + l_iu + l_fi];
            if let Some(r) = self.emit(chars, target, name_bytes, path, depth) {
                status.get_or_insert(r);
            }
        }
        status
    }

    /// Emit one FID's entry, recursing into a directory. Returns a reason
    /// when something under it stopped short (for the caller's own flag).
    fn emit(
        &mut self,
        chars: u8,
        target: LongAd,
        name_bytes: &[u8],
        parent_path: &str,
        depth: usize,
    ) -> Option<&'static str> {
        let (name, name_error) = match cs0::decode(name_bytes) {
            Ok(n) => (n, None),
            Err(cs0::Cs0Error::UnsupportedCompression(id)) => {
                let hex: String = name_bytes.iter().map(|b| format!("{b:02x}")).collect();
                (format!("[undecoded CS0 {id}] {hex}"), Some(id))
            }
        };
        let deleted = chars & FC_DELETED != 0;
        let path = if parent_path == "/" {
            format!("/{name}")
        } else {
            format!("{parent_path}/{name}")
        };
        let icb = self.read_icb(target);
        let is_directory = match &icb {
            Ok(i) => i.file_type == FT_DIRECTORY,
            Err(_) => chars & FC_DIRECTORY != 0,
        };
        let mut m = json!({
            "name": name,
            "path": path,
            "parent_path": parent_path,
            "is_directory": is_directory,
            "size": 0,
            "filesystem_type": "UDF",
            "icb_lbn": target.lbn,
            "icb_partition_reference": target.part_ref,
        });
        if let Some(id) = name_error {
            m["name_decode_failed"] = json!(true);
            m["name_cs0_compression_id"] = json!(id);
        }
        if chars & FC_HIDDEN != 0 {
            m["hidden"] = json!(true);
        }
        if deleted {
            // The FID says the file was deleted; the File Entry it points at
            // may since have been reused for something else.
            m["deleted"] = json!(true);
            m["deleted_icb_may_be_reused"] = json!(true);
        }
        let mut content: Option<Arc<dyn DataSource>> = None;
        let mut recurse: Option<Icb> = None;
        match icb {
            Err(reason) => {
                m["icb_unreadable"] = json!(true);
                m["icb_unreadable_reason"] = json!(reason);
                if is_directory {
                    m["directory_parse_incomplete"] = json!(true);
                    m["directory_parse_incomplete_reason"] = json!(reason);
                    self.mark(reason);
                } else {
                    m["content_incomplete"] = json!(true);
                    m["content_incomplete_reason"] =
                        json!(IncompleteReason::UnresolvedStructure.as_str());
                }
            }
            Ok(i) => {
                stamp_icb(&mut m, &i);
                if is_directory {
                    recurse = Some(i);
                } else {
                    m["size"] = json!(i.info_len);
                    if i.file_type == FT_SYMLINK {
                        m["is_symlink"] = json!(true);
                        m["symlink_target_not_decoded"] = json!(true);
                    }
                    let runs = Self::fitted_runs(&i);
                    let (runs_json, complete) = byte_runs_to_metadata(&runs);
                    m["data_runs"] = runs_json;
                    m["data_runs_complete"] = json!(complete && i.content_problem.is_none());
                    if let Some((why, reason)) = i.content_problem {
                        m["content_incomplete"] = json!(true);
                        m["content_incomplete_reason"] = json!(reason.as_str());
                        m["udf_content_problem"] = json!(why);
                    }
                    content = Some(Arc::new(RunListDataSource::with_logical_size(
                        Arc::clone(self.ds),
                        runs,
                        i.info_len,
                    )));
                }
            }
        }
        let idx = self.produced.len();
        self.produced.push(
            Artifact::new(self.case_id, ArtifactType::FileEntry, content, m)
                .with_parent(self.root_id),
        );
        let dir = recurse?;
        if deleted {
            // A deleted directory's File Entry may be reused; its listing is
            // not walked, and the entry says so rather than reading as empty.
            let meta = &mut self.produced[idx].metadata;
            meta["directory_not_walked"] = json!("deleted");
            return None;
        }
        let reason = if !self.visited.insert((target.part_ref, target.lbn)) {
            Some(self.mark("cyclic_icb"))
        } else {
            self.walk_dir(&dir, &path, depth + 1)
        };
        if let Some(r) = reason {
            let meta = &mut self.produced[idx].metadata;
            meta["directory_parse_incomplete"] = json!(true);
            meta["directory_parse_incomplete_reason"] = json!(r);
        }
        None
    }
}

/// The File Entry fields every entry carries.
fn stamp_icb(m: &mut serde_json::Value, i: &Icb) {
    // 0xFFFFFFFF is "not recorded" (OSTA UDF 3.3.3.1/2).
    if i.uid != u32::MAX {
        m["uid"] = json!(i.uid);
    }
    if i.gid != u32::MAX {
        m["gid"] = json!(i.gid);
    }
    m["udf_permissions"] = json!(i.permissions);
    m["nlink"] = json!(i.link_count);
    m["udf_unique_id"] = json!(i.unique_id);
    m["udf_file_type"] = json!(i.file_type);
    m["udf_extended_file_entry"] = json!(i.extended);
    let mut unspecified = false;
    for (key, t) in [
        ("accessed", &i.accessed),
        ("modified", &i.modified),
        ("changed", &i.changed),
        ("created", &i.created),
    ] {
        if let Some(t) = t {
            m[key] = json!(t.text);
            unspecified |= !t.timezone_specified;
        }
    }
    if unspecified {
        m["timestamps_timezone_unspecified"] = json!(true);
    }
    if !i.undecodable_timestamps.is_empty() {
        // Recorded but out of range (a month of 13, say): named, not dropped.
        m["timestamps_undecodable"] = json!(i.undecodable_timestamps);
    }
    if i.ea_len > 0 {
        // Extended attributes are present and not decoded.
        m["udf_extended_attribute_bytes_not_read"] = json!(i.ea_len);
    }
    if i.stream_directory {
        m["udf_stream_directory_not_read"] = json!(true);
    }
}
