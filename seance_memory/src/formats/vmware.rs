//! VMware snapshot reader: the `.vmem` bytes plus the `.vmss`/`.vmsn` region
//! table.
//!
//! This is the only acquisition format with **two inputs**. The `.vmem` file is
//! headerless — it is raw guest memory and carries no magic at all — while the
//! mapping from guest-physical address to file offset lives in the snapshot
//! metadata beside it, as a set of `regionPPN` / `regionPageNum` / `regionSize`
//! tags. Without the metadata a `.vmem` can be read flat, and a flat read is
//! **wrong** for any guest whose memory is split into regions: every address
//! above the first region boundary lands on the wrong page, silently.
//!
//! ## Reaching the second input
//!
//! Upstream (`framework/layers/vmware.py:198-200`) string-munges a filesystem
//! path: `location[:-5] + ".vmss"`. That only works for a file on local disk,
//! which is exactly the case Séance most often does *not* have — the pair is
//! usually inside a ZIP, an E01 or a backup.
//!
//! Two routes are tried, in this order:
//!
//! 1. **[`DataSource::open_sibling`]**, which reaches a companion held by a
//!    container or attached by a filesystem parser, with no filesystem path
//!    involved. Note the exact contract: `open_sibling` **appends** its suffix
//!    to the source's own name (`"/e/1.db" + "-wal"`), so this route finds a
//!    companion that a container bundled under the key `".vmss"`. It does not,
//!    on a plain file, find `guest.vmss` beside `guest.vmem` — appending would
//!    ask for `guest.vmem.vmss`.
//! 2. **Extension replacement on the underlying path**, which is the
//!    `guest.vmem` → `guest.vmss` case for a pair sitting on disk.
//!
//! A candidate is only accepted once its VMware metadata magic has been
//! verified, so a same-named file of some other kind is not mistaken for the
//! snapshot metadata.
//!
//! ## Degrading honestly
//!
//! [`open`] treats missing metadata as a hard failure and says exactly what it
//! looked for, because a silent flat read of a regioned `.vmem` produces
//! confidently wrong addresses. Where an examiner has decided a flat read is
//! nonetheless the best available reading of the evidence,
//! [`open_degraded`] provides it — as a single identity segment carrying
//! [`IncompleteReason::UnresolvedStructure`] on the layer, so nothing
//! downstream can present it as a resolved address space.

use std::collections::HashMap;
use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::io::{read_exact_or_fail, read_full, IncompleteReason};
use tracing::debug;

use super::{u32_at, u64_at, Endian, FormatError};
use crate::format::MemoryImageFormat;
use crate::layer::MAX_SEGMENTS;
use crate::meta::LayerMeta;
use crate::segmented::{Segment, SegmentedLayer};

const FORMAT: MemoryImageFormat = MemoryImageFormat::VmwareSnapshot;

/// The four snapshot-metadata magics. The low nibble of the first byte is the
/// metadata version (0 through 3).
const VMWARE_MAGICS: [[u8; 4]; 4] = [
    [0xd0, 0xbe, 0xd2, 0xbe],
    [0xd1, 0xba, 0xd1, 0xba],
    [0xd2, 0xbe, 0xd2, 0xbe],
    [0xd3, 0xbe, 0xd3, 0xbe],
];

/// `<4sII`: magic, unknown, groupCount.
const HEADER_LEN: u64 = 12;
/// `64s Q Q`: group name, tag location, unknown.
const GROUP_ENTRY_LEN: u64 = 80;
/// Sanity bound on the declared group count. Real snapshots hold a handful.
const MAX_GROUPS: u32 = 4096;
/// The group whose tags describe guest memory.
const MEMORY_GROUP: &[u8] = b"memory";

/// Guest page size. VMware region tags are in pages.
const PAGE_SIZE: u64 = 0x1000;

/// Upper bound on tags walked before the walk is declared corrupt.
const MAX_TAGS: usize = 65_536;
/// Upper bound on a single tag's inline data blob.
const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// Suffixes tried through [`DataSource::open_sibling`], in order. Both cases
/// are tried because VMware writes `.vmss` for a suspended VM and `.vmsn` for a
/// snapshot, and archives preserve whatever case the host used.
pub const METADATA_SUFFIXES: [&str; 4] = [".vmss", ".vmsn", ".VMSS", ".VMSN"];

/// Open a VMware snapshot from its `.vmem`, locating the metadata beside it.
///
/// # Errors
///
/// - [`FormatError::MissingCompanion`] when neither route reaches a `.vmss` or
///   `.vmsn`. This is deliberately a hard failure: see [`open_degraded`] for
///   the examiner-chosen flat reading.
/// - Everything [`open_paired`] can return.
pub fn open(vmem: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
    let Some((origin, metadata)) = find_metadata(&*vmem) else {
        return Err(FormatError::missing_companion(
            FORMAT,
            format!(
                "no snapshot metadata found beside the .vmem. A .vmem holds guest memory but \
                 not the map from guest-physical address to file offset, which lives in the \
                 paired .vmss/.vmsn; without it the file can only be read flat, which is wrong \
                 for any guest whose memory is split into regions. Looked for siblings {:?} and, \
                 for a path-backed source, the same name with a .vmss/.vmsn extension",
                METADATA_SUFFIXES
            ),
        ));
    };
    build(vmem, &*metadata, origin)
}

/// Open a VMware snapshot from an explicitly supplied `.vmem` and metadata
/// pair.
///
/// # Errors
///
/// - [`FormatError::NotThisFormat`] when `metadata` carries no VMware magic.
/// - [`FormatError::Io`] when a structural read of the metadata is short.
/// - [`FormatError::Malformed`] when the metadata has no `memory` group, no
///   region tags, or a region whose extent overflows.
pub fn open_paired(
    vmem: Arc<dyn DataSource>,
    metadata: &dyn DataSource,
) -> Result<SegmentedLayer, FormatError> {
    build(
        vmem,
        metadata,
        "supplied directly by the caller".to_string(),
    )
}

/// Turn a `.vmem` plus its metadata into a layer, recording where the metadata
/// came from so a report can state which file the region map was read out of.
fn build(
    vmem: Arc<dyn DataSource>,
    metadata: &dyn DataSource,
    metadata_origin: String,
) -> Result<SegmentedLayer, FormatError> {
    let regions = read_regions(metadata)?;

    let mut segments = Vec::with_capacity(regions.len());
    for (index, region) in regions.iter().enumerate() {
        let memory_offset = region
            .ppn
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| region_overflow(index, "regionPPN", region.ppn))?;
        let file_offset = region
            .page_num
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| region_overflow(index, "regionPageNum", region.page_num))?;
        let length = region
            .size
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| region_overflow(index, "regionSize", region.size))?;
        if length == 0 {
            return Err(FormatError::malformed(
                FORMAT,
                format!("region {index} declares a size of zero pages"),
            ));
        }
        segments.push(Segment::new(file_offset, memory_offset, length));
    }

    let mapped: u64 = segments
        .iter()
        .fold(0u64, |a, s| a.saturating_add(s.length));
    let mut meta = LayerMeta::new(FORMAT)
        .with_note("vmware_regions", segments.len() as u64)
        .with_note("vmware_page_size", PAGE_SIZE)
        .with_note("vmware_mapped_bytes", mapped)
        .with_note("vmware_metadata_source", metadata_origin);

    // The top of the guest-physical address space the region table describes,
    // which is not the size of the `.vmem` holding it. Leaving it unset
    // published a layer with no declared size at all, so nothing downstream had
    // a figure to set the acquired bytes against and a report could only state
    // what was captured, never what the snapshot said should have been.
    let declared = segments
        .iter()
        .filter_map(|s| s.memory_end())
        .max()
        .unwrap_or(0);
    meta = meta.with_declared_size(declared);

    // A region whose bytes run past the end of the `.vmem` was never fully
    // written: the pair was copied while the snapshot was still being flushed,
    // or the capture was cut short. The regions keep their declared extents so
    // the discrepancy stays visible and `SegmentedLayer` short-reads at the
    // truncation point. Unstamped, the layer carried no incompleteness at all,
    // so a truncated capture was indistinguishable from a complete one and an
    // examiner meeting the short read would have concluded the guest held
    // nothing at those addresses, rather than that the bytes were never written
    // to the file.
    let needed = segments
        .iter()
        .filter_map(|s| s.file_end())
        .max()
        .unwrap_or(0);
    let available = vmem.size();
    if needed > available {
        meta.push_incomplete(
            IncompleteReason::ShortRead,
            format!(
                "the region table maps .vmem bytes up to {needed:#x} but the file holds \
                 {available:#x}; the final {:#x} bytes of guest memory were not written",
                needed - available
            ),
        );
    }

    SegmentedLayer::new(vmem, segments, meta).map_err(|e| FormatError::layer(FORMAT, e))
}

/// Read a `.vmem` flat, as one identity segment, when its metadata cannot be
/// reached.
///
/// This is **not** a fallback [`open`] applies on its own. A flat reading of a
/// regioned `.vmem` places every address above the first region boundary on the
/// wrong page, so it is only ever correct when the guest's memory happened to
/// be a single region — which cannot be known without the metadata. The layer
/// therefore carries [`IncompleteReason::UnresolvedStructure`], and every
/// consumer of [`crate::meta::LayerMeta`] sees it.
///
/// If the metadata *is* reachable, this defers to [`open`]: degrading when
/// there is no need to would throw away the region map.
pub fn open_degraded(vmem: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
    if find_metadata(&*vmem).is_some() {
        return open(vmem);
    }
    let size = vmem.size();
    if size == 0 {
        return Err(FormatError::malformed(
            FORMAT,
            "the .vmem is empty, so it describes no memory",
        ));
    }
    let meta = LayerMeta::new(FORMAT)
        .with_declared_size(size)
        .with_note("vmware_regions", serde_json::Value::Null)
        .with_note("vmware_metadata_source", "none: flat reading")
        .with_incomplete(
            IncompleteReason::UnresolvedStructure,
            "no .vmss/.vmsn metadata was reachable, so the guest-physical to file-offset map is \
             unknown and this layer is a flat reading of the .vmem. That is only correct if the \
             guest's memory was a single region; every address above a region boundary is \
             otherwise wrong",
        );
    SegmentedLayer::new(vmem, vec![Segment::new(0, 0, size)], meta)
        .map_err(|e| FormatError::layer(FORMAT, e))
}

fn region_overflow(index: usize, field: &str, value: u64) -> FormatError {
    FormatError::malformed(
        FORMAT,
        format!("region {index}: {field} {value} in pages overflows the address space"),
    )
}

/// One `(regionPPN, regionPageNum, regionSize)` triple, in pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    ppn: u64,
    page_num: u64,
    size: u64,
}

/// True if `ds` starts with a structurally plausible VMware metadata header.
fn has_metadata_header(ds: &dyn DataSource) -> bool {
    let mut head = [0u8; HEADER_LEN as usize];
    if read_full(ds, 0, &mut head) < head.len() {
        return false;
    }
    if !VMWARE_MAGICS.iter().any(|m| m[..] == head[0..4]) {
        return false;
    }
    match u32_at(&head, 8, Endian::Little) {
        Some(count) => count > 0 && count <= MAX_GROUPS,
        None => false,
    }
}

/// Locate the snapshot metadata beside `vmem`, returning a description of where
/// it came from so the layer can record it.
fn find_metadata(vmem: &dyn DataSource) -> Option<(String, Arc<dyn DataSource>)> {
    // Route 1: a companion the container or filesystem parser attached. This is
    // the route that works inside a ZIP, an E01 or a backup, where no
    // filesystem path exists at all.
    for suffix in METADATA_SUFFIXES {
        if let Some(candidate) = vmem.open_sibling(suffix) {
            if has_metadata_header(&*candidate) {
                return Some((format!("sibling {suffix}"), candidate));
            }
            debug!(
                suffix,
                "VMware sibling exists but carries no metadata magic"
            );
        }
    }

    // Route 2: `guest.vmem` -> `guest.vmss` on the local filesystem. This is an
    // extension *replacement*, which `open_sibling`'s append contract cannot
    // express.
    let path = vmem.get_underlying_path()?;
    if !path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("vmem"))
    {
        return None;
    }
    for extension in ["vmss", "vmsn", "VMSS", "VMSN"] {
        let candidate = path.with_extension(extension);
        if !candidate.is_file() {
            continue;
        }
        let Ok(opened) = FileDataSource::new(candidate.clone()) else {
            continue;
        };
        let opened: Arc<dyn DataSource> = Arc::new(opened);
        if has_metadata_header(&*opened) {
            return Some((candidate.display().to_string(), opened));
        }
        debug!(
            path = %candidate.display(),
            "VMware companion exists but carries no metadata magic"
        );
    }
    None
}

/// Decode the `memory` group's region table out of the snapshot metadata.
fn read_regions(metadata: &dyn DataSource) -> Result<Vec<Region>, FormatError> {
    let mut head = [0u8; HEADER_LEN as usize];
    read_exact_or_fail(metadata, 0, &mut head, "VMware metadata header")
        .map_err(|_| FormatError::not_this(FORMAT, "source is shorter than the metadata header"))?;

    if !VMWARE_MAGICS.iter().any(|m| m[..] == head[0..4]) {
        return Err(FormatError::not_this(FORMAT, "no VMware metadata magic"));
    }
    // The low nibble of the first magic byte is the metadata version, which
    // decides the width of a long tag's length prefix.
    let version = u32::from(head[0] & 0x0F);
    let group_count = u32_at(&head, 8, Endian::Little)
        .ok_or_else(|| FormatError::malformed(FORMAT, "group count is truncated"))?;
    if group_count == 0 || group_count > MAX_GROUPS {
        return Err(FormatError::malformed(
            FORMAT,
            format!("implausible group count {group_count}"),
        ));
    }

    let memory_group = find_memory_group(metadata, group_count)?;
    let tags = walk_tags(metadata, memory_group, version)?;

    let regions_count = tags
        .get(&(MEMORY_GROUP_REGIONS_COUNT.to_string(), Vec::new()))
        .copied()
        .ok_or_else(|| {
            FormatError::malformed(
                FORMAT,
                "the memory group has no regionsCount tag, so the region table cannot be located",
            )
        })?;
    if regions_count == 0 {
        return Err(FormatError::malformed(
            FORMAT,
            "regionsCount is 0: this .vmss/.vmsn does not describe a regioned .vmem, so the \
             guest-physical to file-offset map it should carry is absent",
        ));
    }
    if regions_count > MAX_SEGMENTS as u64 {
        return Err(FormatError::malformed(
            FORMAT,
            format!("regionsCount {regions_count} exceeds the cap of {MAX_SEGMENTS}"),
        ));
    }

    let mut regions = Vec::with_capacity(regions_count as usize);
    for index in 0..regions_count {
        let key = vec![index as u32];
        let field = |name: &str| -> Result<u64, FormatError> {
            tags.get(&(name.to_string(), key.clone()))
                .copied()
                .ok_or_else(|| {
                    FormatError::malformed(FORMAT, format!("region {index} has no {name} tag"))
                })
        };
        regions.push(Region {
            ppn: field("regionPPN")?,
            page_num: field("regionPageNum")?,
            size: field("regionSize")?,
        });
    }
    Ok(regions)
}

const MEMORY_GROUP_REGIONS_COUNT: &str = "regionsCount";

/// Find the `memory` group's tag offset in the group table.
fn find_memory_group(metadata: &dyn DataSource, group_count: u32) -> Result<u64, FormatError> {
    let mut entry = [0u8; GROUP_ENTRY_LEN as usize];
    for index in 0..group_count {
        let at = HEADER_LEN + u64::from(index) * GROUP_ENTRY_LEN;
        read_exact_or_fail(metadata, at, &mut entry, "VMware group table entry")
            .map_err(|e| FormatError::io(FORMAT, format!("group table entry {index}"), e))?;
        let name_end = entry[..64].iter().position(|&b| b == 0).unwrap_or(64);
        if &entry[..name_end] == MEMORY_GROUP {
            return u64_at(&entry, 64, Endian::Little).ok_or_else(|| {
                FormatError::malformed(FORMAT, "the memory group's tag offset is truncated")
            });
        }
    }
    Err(FormatError::malformed(
        FORMAT,
        format!("no \"memory\" group among the {group_count} groups in the metadata"),
    ))
}

/// Walk the tag list starting at `offset`, returning `(name, indices) -> value`.
///
/// A tag is `flags`, a name length, the name, an index tuple whose arity is in
/// the top two bits of `flags`, and a value whose width is the low six bits.
/// `data_len` 62 and 63 are the escape: the value is a length-prefixed blob
/// rather than an inline integer.
///
/// One deliberate departure from upstream: for a short tag it reads exactly
/// `data_len` bytes, whereas upstream reads 8 for every `data_len` other than
/// 4 (`_choose_type`), so a 1- or 2-byte tag's value there includes whatever
/// bytes follow it. The tags this reader needs are 4 bytes wide, where the two
/// agree; reading the declared width is simply correct for the rest. Values
/// wider than a `u64` are stepped over without being decoded — nothing needs
/// them, but the step still has to be exact.
fn walk_tags(
    metadata: &dyn DataSource,
    offset: u64,
    version: u32,
) -> Result<HashMap<(String, Vec<u32>), u64>, FormatError> {
    let mut tags: HashMap<(String, Vec<u32>), u64> = HashMap::new();
    let mut at = offset;

    for _ in 0..MAX_TAGS {
        let mut header = [0u8; 2];
        read_exact_or_fail(metadata, at, &mut header, "VMware tag header")
            .map_err(|e| FormatError::io(FORMAT, format!("tag header at {at:#x}"), e))?;
        let (flags, name_len) = (header[0], header[1]);
        if flags == 0 && name_len == 0 {
            return Ok(tags);
        }

        let indices_len = usize::from((flags >> 6) & 3);
        let data_len = u64::from(flags & 0x3F);

        // name, then the index tuple, then the value.
        let mut body = vec![0u8; usize::from(name_len) + indices_len * 4];
        read_exact_or_fail(metadata, at + 2, &mut body, "VMware tag name and indices")
            .map_err(|e| FormatError::io(FORMAT, format!("tag body at {at:#x}"), e))?;
        let name = String::from_utf8_lossy(&body[..usize::from(name_len)]).to_string();
        let mut indices = Vec::with_capacity(indices_len);
        for i in 0..indices_len {
            let raw_at = usize::from(name_len) + i * 4;
            indices.push(u32_at(&body, raw_at, Endian::Little).ok_or_else(|| {
                FormatError::malformed(FORMAT, format!("tag {name} has a truncated index tuple"))
            })?);
        }
        let value_at = at
            .checked_add(2 + body.len() as u64)
            .ok_or_else(|| FormatError::malformed(FORMAT, "the tag list overflows u64"))?;

        if data_len == 62 || data_len == 63 {
            // A long tag: a length prefix, two bytes of padding, then a blob.
            // The blob is not a region value, so only its length is needed to
            // step over it.
            let width = if version == 0 { 4u64 } else { 8 };
            let mut raw = vec![0u8; width as usize];
            read_exact_or_fail(metadata, value_at, &mut raw, "VMware tag blob length")
                .map_err(|e| FormatError::io(FORMAT, format!("tag {name} blob length"), e))?;
            let blob_len = match width {
                4 => u64::from(u32_at(&raw, 0, Endian::Little).unwrap_or(0)),
                _ => u64_at(&raw, 0, Endian::Little).unwrap_or(0),
            };
            if blob_len > MAX_BLOB_BYTES {
                return Err(FormatError::malformed(
                    FORMAT,
                    format!("tag {name} declares a {blob_len}-byte blob"),
                ));
            }
            at = value_at
                .checked_add(2 * width + 2)
                .and_then(|v| v.checked_add(blob_len))
                .ok_or_else(|| {
                    FormatError::malformed(FORMAT, format!("tag {name} overflows the metadata"))
                })?;
            continue;
        }

        // A short tag: `data_len` bytes of inline value. Values wider than a
        // `u64` are legal (`data_len` runs to 61) and are simply not region
        // tags, so they are stepped over rather than decoded — but the step has
        // to be right, or every tag after one of them is misread.
        if data_len > 0 && data_len <= 8 {
            let mut raw = [0u8; 8];
            read_exact_or_fail(
                metadata,
                value_at,
                &mut raw[..data_len as usize],
                "VMware tag value",
            )
            .map_err(|e| FormatError::io(FORMAT, format!("tag {name} value"), e))?;
            tags.insert((name, indices), u64::from_le_bytes(raw));
        }

        at = value_at.checked_add(data_len).ok_or_else(|| {
            FormatError::malformed(
                FORMAT,
                "the tag list runs past the end of the address space",
            )
        })?;
    }

    Err(FormatError::malformed(
        FORMAT,
        format!("the memory group's tag list exceeds {MAX_TAGS} tags without terminating"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{MemoryHole, MemoryLayer};
    use seance_core::data_source::{ByteSliceDataSource, SiblingBundleSource};

    // ── Synthetic fixtures, built byte by byte ──────────────────────────────

    /// Append one short tag: `flags`, name length, name, index tuple, value.
    fn tag(out: &mut Vec<u8>, name: &str, indices: &[u32], data_len: usize, value: u64) {
        let flags = ((indices.len() as u8) << 6) | (data_len as u8);
        out.push(flags);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        for index in indices {
            out.extend_from_slice(&index.to_le_bytes());
        }
        out.extend_from_slice(&value.to_le_bytes()[..data_len]);
    }

    /// Append a long tag: a length prefix, two bytes of padding, then a blob.
    fn blob_tag(out: &mut Vec<u8>, name: &str, version: u32, blob: &[u8]) {
        out.push(63); // data_len 63, no indices
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        let width = if version == 0 { 4usize } else { 8 };
        out.extend_from_slice(&(blob.len() as u64).to_le_bytes()[..width]);
        // Upstream skips `2 * width + 2` bytes between the length and the blob.
        out.resize(out.len() + width + 2, 0);
        out.extend_from_slice(blob);
    }

    /// Append a tag whose inline value is wider than a `u64` — legal, and not
    /// a region tag, so it must be stepped over exactly.
    fn wide_tag(out: &mut Vec<u8>, name: &str, data_len: usize) {
        out.push(data_len as u8);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.resize(out.len() + data_len, 0x5A);
    }

    /// `(regionPPN, regionPageNum, regionSize)`, in pages.
    type TestRegion = (u64, u64, u64);

    fn metadata_with(
        magic: [u8; 4],
        groups: &[(&str, Option<Vec<u8>>)],
        regions: Option<&[TestRegion]>,
        regions_count_override: Option<u64>,
    ) -> Vec<u8> {
        let version = u32::from(magic[0] & 0x0F);

        // Build each group's tag block; `None` means "an empty tag list".
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for (name, explicit) in groups {
            if let Some(bytes) = explicit {
                blocks.push(bytes.clone());
                continue;
            }
            let mut block = Vec::new();
            if *name == "memory" {
                if let Some(regions) = regions {
                    let count = regions_count_override.unwrap_or(regions.len() as u64);
                    tag(&mut block, "regionsCount", &[], 4, count);
                    // A long tag in the middle, because real metadata has them
                    // and the walk has to step over one correctly.
                    blob_tag(&mut block, "Memory", version, &[0xCC; 8]);
                    for (i, (ppn, page_num, size)) in regions.iter().enumerate() {
                        tag(&mut block, "regionPPN", &[i as u32], 4, *ppn);
                        tag(&mut block, "regionPageNum", &[i as u32], 4, *page_num);
                        tag(&mut block, "regionSize", &[i as u32], 4, *size);
                    }
                }
            }
            block.extend_from_slice(&[0, 0]); // terminator
            blocks.push(block);
        }

        let group_count = groups.len() as u64;
        let table_end = HEADER_LEN + group_count * GROUP_ENTRY_LEN;

        let mut out = Vec::new();
        out.extend_from_slice(&magic);
        out.extend_from_slice(&0u32.to_le_bytes()); // unknown
        out.extend_from_slice(&(group_count as u32).to_le_bytes());

        let mut cursor = table_end;
        for ((name, _), block) in groups.iter().zip(blocks.iter()) {
            let mut padded = [0u8; 64];
            padded[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&padded);
            out.extend_from_slice(&cursor.to_le_bytes()); // tag location
            out.extend_from_slice(&0u64.to_le_bytes()); // unknown
            cursor += block.len() as u64;
        }
        for block in blocks {
            out.extend_from_slice(&block);
        }
        out
    }

    fn metadata(regions: &[TestRegion]) -> Vec<u8> {
        metadata_with(VMWARE_MAGICS[2], &[("memory", None)], Some(regions), None)
    }

    /// A `.vmem` of `pages` pages, page `n` filled with `0xA0 + n`.
    fn vmem(pages: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for page in 0..pages {
            out.resize(
                out.len() + PAGE_SIZE as usize,
                0xA0u8.wrapping_add(page as u8),
            );
        }
        out
    }

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    /// A `.vmem` with its metadata bundled as a `.vmss` sibling, which is how a
    /// container or a filesystem parser presents the pair.
    fn bundled(vmem_bytes: Vec<u8>, metadata_bytes: Vec<u8>, key: &str) -> Arc<dyn DataSource> {
        let mut siblings = HashMap::new();
        siblings.insert(
            key.to_string(),
            Arc::new(ByteSliceDataSource::new(metadata_bytes)) as Arc<dyn DataSource>,
        );
        Arc::new(SiblingBundleSource::new(
            Arc::new(ByteSliceDataSource::new(vmem_bytes)),
            siblings,
        ))
    }

    // ── Valid pair ──────────────────────────────────────────────────────────

    #[test]
    fn a_valid_pair_maps_regions_from_the_metadata_not_from_file_order() {
        // Guest page 0 is file page 0; guest page 3 is file page 1. A flat read
        // would put the second region at guest 0x1000 — this is exactly the
        // error the metadata exists to prevent.
        let meta = metadata(&[(0, 0, 1), (3, 1, 1)]);
        let layer = open_paired(source(vmem(2)), &*source(meta)).expect("a well-formed pair");

        assert_eq!(layer.segments().len(), 2);
        assert_eq!(layer.min_address(), 0);
        assert_eq!(layer.max_address(), 0x3FFF);
        assert_eq!(layer.mapped_len(), 0x2000);

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0, &mut page).unwrap();
        assert!(page.iter().all(|&b| b == 0xA0));
        layer.read_at(0x3000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0xA1),
            "file page 1 at guest 0x3000"
        );
    }

    #[test]
    fn the_range_between_regions_is_a_hole_and_not_zeros() {
        let meta = metadata(&[(0, 0, 1), (3, 1, 1)]);
        let layer = open_paired(source(vmem(2)), &*source(meta)).unwrap();
        let mut buf = vec![0u8; 0x2000];
        let err = layer
            .read_at(0x1000, &mut buf)
            .expect_err("no region covers this");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x1000, 0x2000));
    }

    #[test]
    fn multi_page_regions_are_mapped_whole() {
        let meta = metadata(&[(0, 0, 2), (8, 2, 2)]);
        let layer = open_paired(source(vmem(4)), &*source(meta)).unwrap();
        assert_eq!(layer.mapped_len(), 0x4000);
        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x9000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0xA3),
            "guest 0x9000 is file page 3"
        );
        assert_eq!(layer.layer_meta().note("vmware_regions").unwrap(), 2);
        assert_eq!(
            layer.layer_meta().note("vmware_mapped_bytes").unwrap(),
            0x4000
        );
    }

    #[test]
    fn every_metadata_magic_is_accepted() {
        for magic in VMWARE_MAGICS {
            let meta = metadata_with(magic, &[("memory", None)], Some(&[(0, 0, 1)]), None);
            let layer = open_paired(source(vmem(1)), &*source(meta))
                .unwrap_or_else(|e| panic!("magic {magic:02x?} must be read: {e}"));
            assert_eq!(layer.mapped_len(), 0x1000);
        }
    }

    #[test]
    fn the_memory_group_is_found_among_several() {
        let meta = metadata_with(
            VMWARE_MAGICS[2],
            &[("cpu", None), ("memory", None), ("checkpoint", None)],
            Some(&[(0, 0, 1)]),
            None,
        );
        let layer =
            open_paired(source(vmem(1)), &*source(meta)).expect("the memory group is there");
        assert_eq!(layer.mapped_len(), 0x1000);
    }

    // ── A .vmem measured against its own region table ───────────────────────

    #[test]
    fn the_declared_size_is_the_top_of_the_region_table_not_the_file_size() {
        // The guest's memory runs to 0x4000 while the .vmem is 0x2000 bytes.
        // Without a declared size a report has nothing to set the acquired
        // bytes against, so a holed capture reads as a whole one.
        let meta = metadata(&[(0, 0, 1), (3, 1, 1)]);
        let layer = open_paired(source(vmem(2)), &*source(meta)).unwrap();
        assert_eq!(layer.layer_meta().declared_size(), Some(0x4000));
        assert_eq!(layer.mapped_len(), 0x2000);
        assert!(
            layer.layer_meta().incomplete().is_empty(),
            "every mapped byte is in the file, so nothing is short"
        );
    }

    #[test]
    fn a_vmem_truncated_below_its_region_table_is_stamped_short_read() {
        // The region table maps two file pages; the capture stops half a page
        // into the second. Unstamped this looked like a complete acquisition,
        // and the short read at 0x3000 like memory the guest never held.
        let meta = metadata(&[(0, 0, 1), (3, 1, 1)]);
        let mut bytes = vmem(2);
        bytes.truncate(0x1800);
        let layer = open_paired(source(bytes), &*source(meta))
            .expect("a truncated capture is still readable up to the cut");

        let incomplete = layer.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(
            incomplete[0].detail.contains("were not written"),
            "{}",
            incomplete[0].detail
        );

        // The region keeps its declared extent, so the layer still records that
        // the guest had memory at 0x3000; it is the bytes that are absent.
        assert_eq!(layer.segments().len(), 2);
        assert_eq!(layer.layer_meta().declared_size(), Some(0x4000));
        let mut page = vec![0u8; 0x1000];
        assert_eq!(
            layer.read_at(0x3000, &mut page).unwrap(),
            0x800,
            "the honest short count, not a fabricated page"
        );
    }

    // ── Reaching the second input ───────────────────────────────────────────

    #[test]
    fn the_metadata_is_reached_through_open_sibling_inside_a_container() {
        // No filesystem path exists here at all, which is the case upstream's
        // path munging cannot handle.
        for key in METADATA_SUFFIXES {
            let paired = bundled(vmem(2), metadata(&[(0, 0, 1), (3, 1, 1)]), key);
            assert!(paired.get_underlying_path().is_none());
            let layer = open(paired).unwrap_or_else(|e| panic!("sibling {key}: {e}"));
            assert_eq!(layer.mapped_len(), 0x2000);
            assert!(layer
                .layer_meta()
                .note("vmware_metadata_source")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains(key)));
        }
    }

    #[test]
    fn a_sibling_without_the_metadata_magic_is_not_mistaken_for_the_pair() {
        let paired = bundled(vmem(2), vec![0x5A; 0x400], ".vmss");
        let err = open(paired).expect_err("a same-named file of another kind is not metadata");
        assert!(matches!(err, FormatError::MissingCompanion { .. }), "{err}");
    }

    #[test]
    fn missing_metadata_is_a_hard_failure_that_says_what_it_looked_for() {
        let err = open(source(vmem(4))).expect_err("a bare .vmem cannot be mapped");
        match err {
            FormatError::MissingCompanion { ref detail, .. } => {
                assert!(detail.contains(".vmss"), "{detail}");
                assert!(detail.contains("split into regions"), "{detail}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // ── Degrading honestly ──────────────────────────────────────────────────

    #[test]
    fn the_degraded_reading_is_flat_and_carries_the_reason_it_is_degraded() {
        let layer = open_degraded(source(vmem(4))).expect("a flat reading is still a reading");
        assert_eq!(layer.segments().len(), 1);
        assert_eq!(layer.size(), 0x4000);
        assert_eq!(layer.mapped_len(), 0x4000);

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x2000, &mut page).unwrap();
        assert!(
            page.iter().all(|&b| b == 0xA2),
            "flat: guest == file offset"
        );

        let incomplete = layer.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::UnresolvedStructure);
        assert!(
            incomplete[0].detail.contains("single region"),
            "{}",
            incomplete[0].detail
        );
        assert_eq!(
            layer.layer_meta().note("vmware_regions").unwrap(),
            &serde_json::Value::Null,
            "a flat reading knows of no regions and must not claim one"
        );
    }

    #[test]
    fn the_degraded_path_still_prefers_real_metadata_when_it_is_reachable() {
        let paired = bundled(vmem(2), metadata(&[(0, 0, 1), (3, 1, 1)]), ".vmss");
        let layer = open_degraded(paired).expect("metadata is reachable");
        assert_eq!(
            layer.segments().len(),
            2,
            "the region map was not thrown away"
        );
        assert!(layer.layer_meta().incomplete().is_empty());
    }

    #[test]
    fn an_empty_vmem_is_refused_rather_than_becoming_a_zero_length_layer() {
        let err = open_degraded(source(Vec::new())).expect_err("no memory at all");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    // ── Truncated metadata ──────────────────────────────────────────────────

    #[test]
    fn a_truncated_metadata_header_fails_closed() {
        let full = metadata(&[(0, 0, 1)]);
        for cut in [0usize, 4, 8, 11] {
            let err = open_paired(source(vmem(1)), &*source(full[..cut].to_vec()))
                .expect_err("a partial header must not parse");
            assert!(err.is_not_this_format(), "cut {cut}: {err}");
        }
    }

    #[test]
    fn a_truncated_group_table_fails_closed_rather_than_parsing_zeros() {
        let full = metadata(&[(0, 0, 1)]);
        let cut = (HEADER_LEN + 40) as usize;
        let err = open_paired(source(vmem(1)), &*source(full[..cut].to_vec()))
            .expect_err("the group entry is not all present");
        match err {
            FormatError::Io {
                ref what,
                ref source,
                ..
            } => {
                assert!(what.contains("group table entry"), "{what}");
                assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_tag_list_truncated_mid_walk_fails_closed() {
        let full = metadata(&[(0, 0, 1), (3, 1, 1)]);
        // Chop the last few tags, so the walk runs off the end instead of
        // reaching the terminator.
        let cut = full.len() - 12;
        let err = open_paired(source(vmem(2)), &*source(full[..cut].to_vec()))
            .expect_err("an unterminated tag list must not yield a partial region table");
        assert!(matches!(err, FormatError::Io { .. }), "{err}");
    }

    #[test]
    fn a_region_table_shorter_than_its_own_count_is_refused() {
        // regionsCount says 4; only one region's tags are present.
        let meta = metadata_with(
            VMWARE_MAGICS[2],
            &[("memory", None)],
            Some(&[(0, 0, 1)]),
            Some(4),
        );
        let err = open_paired(source(vmem(1)), &*source(meta))
            .expect_err("a short region table must not be padded out");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("region 1"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // ── Malformed metadata ──────────────────────────────────────────────────

    #[test]
    fn metadata_without_the_magic_is_not_claimed() {
        let err =
            open_paired(source(vmem(1)), &*source(vec![0x5A; 0x400])).expect_err("no VMware magic");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn an_implausible_group_count_does_not_panic_and_is_refused() {
        for count in [0u32, MAX_GROUPS + 1, u32::MAX] {
            let mut meta = metadata(&[(0, 0, 1)]);
            meta[8..12].copy_from_slice(&count.to_le_bytes());
            let err = open_paired(source(vmem(1)), &*source(meta))
                .expect_err("a hostile group count must not be honoured");
            match err {
                FormatError::Malformed { ref detail, .. } => {
                    assert!(detail.contains("group count"), "count {count}: {detail}")
                }
                other => panic!("count {count}: unexpected error: {other}"),
            }
        }
    }

    #[test]
    fn metadata_with_no_memory_group_is_refused() {
        let meta = metadata_with(
            VMWARE_MAGICS[2],
            &[("cpu", None), ("checkpoint", None)],
            None,
            None,
        );
        let err = open_paired(source(vmem(1)), &*source(meta)).expect_err("no memory group");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("\"memory\" group"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_memory_group_without_regions_count_is_refused() {
        let meta = metadata_with(VMWARE_MAGICS[2], &[("memory", None)], None, None);
        let err = open_paired(source(vmem(1)), &*source(meta)).expect_err("no regionsCount tag");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("regionsCount"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn regions_count_of_zero_is_refused_rather_than_read_flat() {
        // Upstream raises here too. A silent flat read is the failure mode this
        // whole reader exists to prevent.
        let mut block = Vec::new();
        tag(&mut block, "regionsCount", &[], 4, 0);
        block.extend_from_slice(&[0, 0]);
        let meta = metadata_with(VMWARE_MAGICS[2], &[("memory", Some(block))], None, None);
        let err = open_paired(source(vmem(1)), &*source(meta)).expect_err("no region map");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("regionsCount is 0"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_region_extent_that_overflows_the_address_space_does_not_panic() {
        let mut block = Vec::new();
        tag(&mut block, "regionsCount", &[], 4, 1);
        tag(&mut block, "regionPPN", &[0], 8, u64::MAX / 2);
        tag(&mut block, "regionPageNum", &[0], 4, 0);
        tag(&mut block, "regionSize", &[0], 4, 1);
        block.extend_from_slice(&[0, 0]);
        let meta = metadata_with(VMWARE_MAGICS[2], &[("memory", Some(block))], None, None);
        let err = open_paired(source(vmem(1)), &*source(meta)).expect_err("page count overflows");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("overflows"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_zero_length_region_is_refused_by_name() {
        let meta = metadata(&[(0, 0, 0)]);
        let err = open_paired(source(vmem(1)), &*source(meta)).expect_err("a region of no pages");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("zero pages"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn overlapping_regions_are_refused_rather_than_silently_resolved() {
        let meta = metadata(&[(0, 0, 2), (1, 2, 2)]);
        let err = open_paired(source(vmem(4)), &*source(meta))
            .expect_err("two sets of bytes cannot share one guest address");
        assert!(matches!(err, FormatError::Layer { .. }), "{err}");
    }

    #[test]
    fn an_unterminated_tag_list_is_capped_rather_than_looping_forever() {
        // A tag with data_len 0 and a one-character name advances three bytes
        // per iteration and never terminates.
        let mut block = Vec::new();
        for _ in 0..(MAX_TAGS + 8) {
            block.push(0); // flags: no indices, zero-length value
            block.push(1); // name length
            block.push(b'x');
        }
        let meta = metadata_with(VMWARE_MAGICS[2], &[("memory", Some(block))], None, None);
        let err =
            open_paired(source(vmem(1)), &*source(meta)).expect_err("the walk must be capped");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("exceeds"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_tag_wider_than_a_u64_is_stepped_over_without_derailing_the_walk() {
        // data_len runs to 61, so a 16-byte inline value is legal. Refusing it,
        // or stepping the wrong distance, loses every tag after it.
        let mut block = Vec::new();
        tag(&mut block, "regionsCount", &[], 4, 1);
        wide_tag(&mut block, "uuid", 16);
        tag(&mut block, "regionPPN", &[0], 4, 2);
        wide_tag(&mut block, "cpuid", 61);
        tag(&mut block, "regionPageNum", &[0], 4, 0);
        tag(&mut block, "regionSize", &[0], 4, 1);
        block.extend_from_slice(&[0, 0]);
        let meta = metadata_with(VMWARE_MAGICS[2], &[("memory", Some(block))], None, None);

        let layer = open_paired(source(vmem(1)), &*source(meta))
            .expect("the region tags after the wide ones are still found");
        assert_eq!(layer.min_address(), 0x2000, "regionPPN 2 == guest 0x2000");
        assert_eq!(layer.mapped_len(), 0x1000);
    }

    #[test]
    fn a_tag_declaring_an_absurd_blob_is_refused_without_allocating() {
        let mut block = Vec::new();
        block.push(63); // long tag
        block.push(4);
        block.extend_from_slice(b"huge");
        block.extend_from_slice(&u64::MAX.to_le_bytes());
        block.extend_from_slice(&[0u8; 10]);
        let meta = metadata_with(VMWARE_MAGICS[2], &[("memory", Some(block))], None, None);
        let err = open_paired(source(vmem(1)), &*source(meta)).expect_err("a hostile blob length");
        match err {
            FormatError::Malformed { ref detail, .. } => {
                assert!(detail.contains("blob"), "{detail}")
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
