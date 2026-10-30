//! Per-snapshot VSS content reconstruction.
//!
//! A shadow copy is served by chaining one [`VssStore`] per stack position: a
//! block absent from store N falls through to store N+1, then to the live
//! volume (or null bytes, depending on the store's bitmap and flags). The
//! algorithm is a direct port of Maxim Suhanov's `dfir_ntfs/ShadowCopy.py`
//! (`translate_exact_offset` + `read_diff_area` + bitmap reading).
//!
//! All offsets are volume-relative; the enumerator supplies a window over the
//! NTFS+VSS partition as the `DataSource`.

use anyhow::{Context, Result};
use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io;
use std::sync::Arc;

use crate::vss_structs::*;

const BLOCK_LEN: usize = VSS_BLOCK_SIZE as usize;

/// One parsed diff-area table entry (32 bytes on disk).
#[derive(Debug, Clone)]
pub struct OnDiskTableEntry {
    pub original_volume_offset: u64,
    pub data_block_offset_in_store: u64,
    pub data_block_volume_offset: u64,
    pub flags: u32,
    pub allocation_bitmap: u32,
}

/// A resolved store (one shadow-copy stack position) with its diff area,
/// allocation bitmaps and a link to the next store in the stack.
#[derive(Debug)]
pub struct VssStore {
    /// Snapshot volume size (from the type-2 catalog item).
    pub volume_size: u64,
    /// STORE_FLAG_NULLIFY_UNUSED: bitmap-marked blocks read as null bytes.
    return_null_blocks: bool,
    /// Diff-area entries, stable-sorted by `original_volume_offset`.
    diff_area: Vec<OnDiskTableEntry>,
    /// First index in `diff_area` for a given `original_volume_offset`.
    diff_area_index: HashMap<u64, usize>,
    bitmap: Vec<u8>,
    previous_bitmap: Vec<u8>,
    /// Forward targets that may resolve to null blocks.
    possible_null_targets: HashSet<u64>,
    /// The store at stack_position + 1 (None for the store closest to live).
    next: Option<Arc<VssStore>>,
}

impl VssStore {
    /// How many older stores this one falls through to before reaching the live
    /// volume.
    ///
    /// Forensic meaning: a shadow copy is reconstructed by reading its own
    /// preserved blocks first and, for everything it did not preserve, the next
    /// store in the chain. A chain that is one link shorter than it should be
    /// serves present-day bytes in place of the snapshot's own, so a file the
    /// examiner believes was recovered "as of" the snapshot is partly today's
    /// copy. This exposes the chain length so that can be asserted.
    pub fn chain_depth(&self) -> usize {
        let mut depth = 0usize;
        let mut cur = self.next.as_ref();
        while let Some(store) = cur {
            depth += 1;
            cur = store.next.as_ref();
        }
        depth
    }

    /// Build a store for one stack position by reading its diff-area table
    /// chain and bitmaps from `source`. `next` is the next store the chain
    /// falls through to (the nearest higher stack position that built).
    pub fn build(
        source: &Arc<dyn DataSource>,
        diff_area_block_offset: u64,
        bitmap_offset: u64,
        previous_bitmap_offset: u64,
        volume_size: u64,
        store_flags: u64,
        next: Option<Arc<VssStore>>,
    ) -> Result<Self> {
        let diff_area = read_diff_area(source, diff_area_block_offset)?;

        let mut diff_area_index: HashMap<u64, usize> = HashMap::new();
        for (i, item) in diff_area.iter().enumerate() {
            diff_area_index
                .entry(item.original_volume_offset)
                .or_insert(i);
        }

        let bitmap = read_bitmap(source, bitmap_offset, volume_size)?;
        let previous_bitmap = read_bitmap(source, previous_bitmap_offset, volume_size)?;

        let mut store = VssStore {
            volume_size,
            return_null_blocks: store_flags & STORE_FLAG_NULLIFY_UNUSED != 0,
            diff_area,
            diff_area_index,
            bitmap,
            previous_bitmap,
            possible_null_targets: HashSet::new(),
            next,
        };

        // A forwarder whose forward target is marked used in this store's
        // bitmap is a "possible null target": if nothing else resolves it and
        // this store nullifies unused blocks, it reads as null.
        let mut targets = HashSet::new();
        for item in &store.diff_area {
            if item.flags & DIFF_AREA_ENTRY_FORWARDER != 0
                && store.check_bitmap(item.data_block_offset_in_store, true)
            {
                targets.insert(item.data_block_offset_in_store);
            }
        }
        store.possible_null_targets = targets;

        Ok(store)
    }

    /// Test-only constructor from already-resolved parts.
    #[cfg(test)]
    fn from_parts(
        volume_size: u64,
        return_null_blocks: bool,
        diff_area: Vec<OnDiskTableEntry>,
        bitmap: Vec<u8>,
        previous_bitmap: Vec<u8>,
        next: Option<Arc<VssStore>>,
    ) -> Self {
        let mut diff_area_index: HashMap<u64, usize> = HashMap::new();
        for (i, item) in diff_area.iter().enumerate() {
            diff_area_index
                .entry(item.original_volume_offset)
                .or_insert(i);
        }
        let mut store = VssStore {
            volume_size,
            return_null_blocks,
            diff_area,
            diff_area_index,
            bitmap,
            previous_bitmap,
            possible_null_targets: HashSet::new(),
            next,
        };
        let mut targets = HashSet::new();
        for item in &store.diff_area {
            if item.flags & DIFF_AREA_ENTRY_FORWARDER != 0
                && store.check_bitmap(item.data_block_offset_in_store, true)
            {
                targets.insert(item.data_block_offset_in_store);
            }
        }
        store.possible_null_targets = targets;
        store
    }

    /// Return true if the block at `offset` is marked in this store's bitmap
    /// (and, when requested, also in the previous bitmap).
    fn check_bitmap(&self, offset: u64, check_previous: bool) -> bool {
        let bit_pos = offset / VSS_BLOCK_SIZE;
        let byte_pos = (bit_pos / 8) as usize;
        let bit_shift = (bit_pos % 8) as u32;

        let result_1 = self
            .bitmap
            .get(byte_pos)
            .map(|b| (b >> bit_shift) & 1 != 0)
            .unwrap_or(false);

        if !check_previous {
            return result_1;
        }

        // A byte out of range in the previous bitmap (including an empty
        // previous bitmap) mirrors Python's IndexError: fall back to result_1.
        match self.previous_bitmap.get(byte_pos) {
            None => result_1,
            Some(pb) => result_1 && ((pb >> bit_shift) & 1 != 0),
        }
    }

    /// Resolve a block by delegating to the next store, or (at the end of the
    /// chain) to the live volume / null bytes per the bitmap and flags.
    fn lookup_in_next_store(&self, offset: u64, do_forward_lookup: bool) -> Vec<Option<u64>> {
        match &self.next {
            None => {
                if !self.check_bitmap(offset, true) {
                    original_offsets(offset)
                } else if self.return_null_blocks && !do_forward_lookup {
                    vec![None; VSS_SECTORS_PER_BLOCK]
                } else {
                    original_offsets(offset)
                }
            }
            Some(next) => next.translate_exact_offset(offset, true, do_forward_lookup),
        }
    }

    /// 0 = no switch, 1 = switch to next store, 2 = switch to original volume.
    fn can_switch_to_next_store(&self, offset: u64) -> u8 {
        let mut next = self.next.as_deref();
        if next.is_none() {
            return 2;
        }
        while let Some(np) = next {
            if let Some(&start) = np.diff_area_index.get(&offset) {
                let mut pos = start;
                while let Some(te) = np.diff_area.get(pos) {
                    if te.original_volume_offset != offset {
                        break;
                    }
                    if te.flags & DIFF_AREA_ENTRY_OVERLAY == 0 {
                        return 1;
                    }
                    pos += 1;
                }
            }
            next = np.next.as_deref();
        }
        0
    }

    /// Translate a 16 KiB-aligned volume offset to 32 physical 512-byte sector
    /// locations for this snapshot. Each entry is a volume offset to read, or
    /// `None` for a null (zero-filled) sector. An empty result means the block
    /// lies beyond the snapshot.
    pub fn translate_exact_offset(
        &self,
        offset: u64,
        ignore_overlay_entries: bool,
        do_forward_lookup: bool,
    ) -> Vec<Option<u64>> {
        let mut new_offsets: Vec<Option<u64>> = Vec::new();

        let mut forwarder_entry_found = false;
        let mut regular_entry_found = false;
        let mut overlay_entry_found = false;
        let mut forward_offset: u64 = 0;
        let mut cumulative_allocation_bitmap: u32 = 0;

        let switch_mode = self.can_switch_to_next_store(offset);
        let bitmap_check_result = self.check_bitmap(offset, true);

        if let Some(&start) = self.diff_area_index.get(&offset) {
            let mut pos = start;
            while let Some(table_entry) = self.diff_area.get(pos) {
                if table_entry.original_volume_offset != offset {
                    break;
                }
                pos += 1;

                let new_offset = table_entry.data_block_volume_offset;

                if table_entry.flags & DIFF_AREA_ENTRY_FORWARDER != 0
                    && table_entry.original_volume_offset != table_entry.data_block_offset_in_store
                {
                    // A forwarder entry: remember the forward offset for later.
                    forwarder_entry_found = true;
                    forward_offset = table_entry.data_block_offset_in_store;
                    continue;
                }

                if table_entry.flags & DIFF_AREA_ENTRY_OVERLAY != 0 {
                    // An overlay: the data block is used only partially, the
                    // allocation bitmap selects which 512-byte sectors apply.
                    overlay_entry_found = true;

                    if !ignore_overlay_entries {
                        if new_offsets.is_empty() {
                            if switch_mode == 1 {
                                new_offsets = self.lookup_in_next_store(offset, false);
                            } else if !bitmap_check_result {
                                new_offsets = original_offsets(offset);
                            } else if self.return_null_blocks {
                                new_offsets = vec![None; VSS_SECTORS_PER_BLOCK];
                            } else {
                                new_offsets = original_offsets(offset);
                            }
                        }

                        cumulative_allocation_bitmap |= table_entry.allocation_bitmap;
                        for (i, slot) in new_offsets
                            .iter_mut()
                            .enumerate()
                            .take(VSS_SECTORS_PER_BLOCK)
                        {
                            if (table_entry.allocation_bitmap >> i) & 1 != 0 {
                                *slot = Some(new_offset + i as u64 * VSS_SECTOR_SIZE);
                            }
                        }
                    }

                    continue;
                }

                // A regular entry: the entire 16 KiB data block is used.
                regular_entry_found = true;
                if new_offsets.is_empty() {
                    new_offsets = (0..VSS_SECTORS_PER_BLOCK)
                        .map(|i| Some(new_offset + i as u64 * VSS_SECTOR_SIZE))
                        .collect();
                } else {
                    // Account for previously seen overlays: only fill sectors
                    // that no overlay claimed.
                    for (i, slot) in new_offsets
                        .iter_mut()
                        .enumerate()
                        .take(VSS_SECTORS_PER_BLOCK)
                    {
                        if (cumulative_allocation_bitmap >> i) & 1 == 0 {
                            *slot = Some(new_offset + i as u64 * VSS_SECTOR_SIZE);
                        }
                    }
                }
            }
        }

        if forwarder_entry_found && !regular_entry_found {
            if overlay_entry_found && !ignore_overlay_entries {
                // Overlays take precedence; the forward lookup fills the rest.
                let forward_offsets = self.lookup_in_next_store(forward_offset, true);
                for i in 0..VSS_SECTORS_PER_BLOCK {
                    if (cumulative_allocation_bitmap >> i) & 1 == 0 {
                        new_offsets[i] = forward_offsets[i];
                    }
                }
            } else {
                return self.lookup_in_next_store(forward_offset, true);
            }
        }

        if !regular_entry_found
            && !do_forward_lookup
            && self.possible_null_targets.contains(&offset)
            && switch_mode == 0
            && self.return_null_blocks
        {
            return vec![None; VSS_SECTORS_PER_BLOCK];
        }

        if !forwarder_entry_found
            && !regular_entry_found
            && !overlay_entry_found
            && bitmap_check_result
            && switch_mode == 0
            && self.return_null_blocks
        {
            return vec![None; VSS_SECTORS_PER_BLOCK];
        }

        if new_offsets.is_empty() {
            return self.lookup_in_next_store(offset, false);
        }

        new_offsets
    }
}

fn original_offsets(offset: u64) -> Vec<Option<u64>> {
    (0..VSS_SECTORS_PER_BLOCK)
        .map(|i| Some(offset + i as u64 * VSS_SECTOR_SIZE))
        .collect()
}

/// Round `v` up to the next multiple of `a`. Returns `None` on overflow, which
/// for an attacker-controlled `volume_size` near `u64::MAX` would otherwise wrap
/// to a tiny value and silently truncate the bitmap.
fn align_up(v: u64, a: u64) -> Option<u64> {
    v.checked_next_multiple_of(a)
}

/// Read a shadow block header: (diff area GUID matches, type, this block's
/// volume offset, next block's volume offset). Returns None on a bad GUID.
fn shadow_block_header(block: &[u8]) -> Option<(u32, u64, u64)> {
    if block.len() < VSS_BLOCK_HEADER_SIZE || block[..16] != VSS_DIFF_AREA_GUID {
        return None;
    }
    let block_type = u32::from_le_bytes(block[20..24].try_into().unwrap());
    let block_vol_off = u64::from_le_bytes(block[32..40].try_into().unwrap());
    let next_offset = u64::from_le_bytes(block[40..48].try_into().unwrap());
    Some((block_type, block_vol_off, next_offset))
}

/// Parse the 32-byte entries in a single diff-area table block (from +0x80),
/// skipping ignore entries and stopping at the terminator / any invalid entry.
fn parse_diff_area_entries(block: &[u8]) -> Vec<OnDiskTableEntry> {
    let mut items = Vec::new();
    let mut pos = VSS_BLOCK_HEADER_SIZE;
    while pos + 32 <= block.len() {
        let e = &block[pos..pos + 32];
        let original_volume_offset = u64::from_le_bytes(e[0..8].try_into().unwrap());
        let data_block_offset_in_store = u64::from_le_bytes(e[8..16].try_into().unwrap());
        let data_block_volume_offset = u64::from_le_bytes(e[16..24].try_into().unwrap());
        let flags = u32::from_le_bytes(e[24..28].try_into().unwrap());
        let allocation_bitmap = u32::from_le_bytes(e[28..32].try_into().unwrap());
        pos += 32;

        // Stop on a clearly invalid entry rather than trusting garbage.
        if original_volume_offset % VSS_BLOCK_SIZE != 0
            || data_block_volume_offset % VSS_BLOCK_SIZE != 0
            || flags & 0xFFFF_FF00 != 0
        {
            break;
        }
        if flags & DIFF_AREA_ENTRY_FORWARDER != 0 && flags & DIFF_AREA_ENTRY_OVERLAY != 0 {
            break;
        }
        // Terminator entry.
        if data_block_volume_offset == 0 && flags == 0 {
            break;
        }

        if flags & DIFF_AREA_ENTRY_IGNORE == 0 {
            items.push(OnDiskTableEntry {
                original_volume_offset,
                data_block_offset_in_store,
                data_block_volume_offset,
                flags,
                allocation_bitmap,
            });
        }
    }
    items
}

/// Read and resolve a store's diff-area table chain into a stable-sorted list.
///
/// A forwarder entry carries a "forward context": a later regular entry whose
/// original offset equals the forwarder's forward target has its original
/// offset rewritten to the forwarder's original offset (a single rewrite per
/// forwarder). A self-referential forwarder deletes matching regular entries.
fn read_diff_area(
    source: &Arc<dyn DataSource>,
    diff_area_block_offset: u64,
) -> Result<Vec<OnDiskTableEntry>> {
    let mut items: Vec<OnDiskTableEntry> = Vec::new();
    let mut forward_context: HashMap<u64, u64> = HashMap::new();

    let mut current_offset = diff_area_block_offset;
    let mut tables = 0u64;
    let max_tables = 100_000u64; // bound the chain length on corrupt input

    while current_offset != 0 && tables < max_tables {
        tables += 1;
        let mut block = vec![0u8; BLOCK_LEN];
        // Loop until the block is full — a source may legally answer in
        // pieces (HUNT-154) — and fail closed when the bytes run out: a
        // zero-padded metadata block would parse fabricated diff-area entries
        // (BUG-164).
        read_exact_or_fail(
            source.as_ref(),
            current_offset,
            &mut block,
            "VSS diff-area table block",
        )
        .context("Failed to read diff-area table block")?;

        let (block_type, block_vol_off, next_offset) = match shadow_block_header(&block) {
            Some(h) => h,
            None => break,
        };
        if block_type != VSS_RECORD_TYPE_DIFF_AREA_TABLE || block_vol_off != current_offset {
            break;
        }

        for mut curr_item in parse_diff_area_entries(&block) {
            // Rewrite the original offset if a pending forwarder targets it
            // (overlay entries are never rewritten).
            if curr_item.flags & DIFF_AREA_ENTRY_OVERLAY == 0 {
                if let Some(new_vol_off) = forward_context.remove(&curr_item.original_volume_offset)
                {
                    curr_item.original_volume_offset = new_vol_off;
                }
            }

            if curr_item.flags & DIFF_AREA_ENTRY_FORWARDER != 0 {
                if curr_item.original_volume_offset != curr_item.data_block_offset_in_store {
                    // Expand the forward context.
                    forward_context.insert(
                        curr_item.data_block_offset_in_store,
                        curr_item.original_volume_offset,
                    );
                } else {
                    // Self-referential forwarder: drop matching regular entries.
                    let target = curr_item.original_volume_offset;
                    items.retain(|it| {
                        it.flags & (DIFF_AREA_ENTRY_FORWARDER | DIFF_AREA_ENTRY_OVERLAY) != 0
                            || it.original_volume_offset != target
                    });
                }
            }

            items.push(curr_item);
        }

        current_offset = next_offset;
    }

    // Stable sort so entries with equal original offsets keep on-disk order.
    items.sort_by_key(|e| e.original_volume_offset);
    Ok(items)
}

/// Read a store bitmap chain (one bit per 16 KiB volume block), truncated to
/// the number of bytes the snapshot volume size requires.
fn read_bitmap(
    source: &Arc<dyn DataSource>,
    bitmap_offset: u64,
    volume_size: u64,
) -> Result<Vec<u8>> {
    let aligned = align_up(volume_size, VSS_BLOCK_SIZE)
        .with_context(|| format!("volume_size {volume_size} too large to align"))?;
    let mut bits_count = aligned / VSS_BLOCK_SIZE;
    if !bits_count.is_multiple_of(8) {
        bits_count += 8 - bits_count % 8;
    }
    let bytes_count = (bits_count / 8) as usize;

    let mut out: Vec<u8> = Vec::new();
    let mut current_offset = bitmap_offset;
    let mut blocks = 0u64;
    let max_blocks = 100_000u64; // bound the chain length on corrupt input

    while current_offset != 0 && blocks < max_blocks {
        blocks += 1;
        let mut block = vec![0u8; BLOCK_LEN];
        // Loop until the block is full (HUNT-154), and fail closed when the
        // bytes run out: a zero-padded bitmap block would parse fabricated
        // allocation bits (BUG-164).
        read_exact_or_fail(
            source.as_ref(),
            current_offset,
            &mut block,
            "VSS store bitmap block",
        )
        .context("Failed to read bitmap block")?;

        let (block_type, block_vol_off, next_offset) = match shadow_block_header(&block) {
            Some(h) => h,
            None => break,
        };
        if block_type != VSS_RECORD_TYPE_STORE_BITMAP || block_vol_off != current_offset {
            break;
        }

        out.extend_from_slice(&block[VSS_BLOCK_HEADER_SIZE..]);
        current_offset = next_offset;
    }

    out.truncate(bytes_count);
    Ok(out)
}

/// Serves a shadow copy's point-in-time bytes: `read_at` splits the request
/// into 16 KiB blocks and, for each, uses the store chain to locate the 32
/// physical sectors (each a volume offset to read, or a null zero-fill).
#[derive(Debug)]
pub struct VssDataSource {
    volume: Arc<dyn DataSource>,
    store: Arc<VssStore>,
    volume_size: u64,
}

impl VssDataSource {
    pub fn new(volume: Arc<dyn DataSource>, store: Arc<VssStore>, volume_size: u64) -> Self {
        Self {
            volume,
            store,
            volume_size,
        }
    }

    /// Reconstruct a single 16 KiB-aligned block of the snapshot.
    ///
    /// `translate_exact_offset` hands back one volume offset per 512-byte
    /// sector (or `None` for a sparse/null sector). Adjacent sectors whose
    /// underlying offsets are themselves sequential (no jump to a different
    /// COW copy, no hole) are coalesced into a single `read_at` covering the
    /// whole run, instead of one syscall-sized read per sector: the block map
    /// for a large unmodified stretch of the volume is typically one long run
    /// of contiguous entries. A sector with no contiguous neighbour still
    /// goes through the original one-read path below, so the non-contiguous
    /// case is untouched.
    fn read_block(&self, block_offset: u64) -> io::Result<[u8; BLOCK_LEN]> {
        let mut out = [0u8; BLOCK_LEN];
        let offsets = self
            .store
            .translate_exact_offset(block_offset, false, false);
        if offsets.is_empty() {
            // Beyond the snapshot volume: zero-filled.
            return Ok(out);
        }

        let sector_len = VSS_SECTOR_SIZE as usize;
        let mut i = 0usize;
        while i < offsets.len() {
            let Some(run_start_off) = offsets[i] else {
                i += 1;
                continue;
            };

            // Extend the run while the next sector is present and its volume
            // offset immediately follows the current run.
            let mut run_len = 1usize;
            while i + run_len < offsets.len() {
                match offsets[i + run_len] {
                    Some(v) if v == run_start_off + run_len as u64 * VSS_SECTOR_SIZE => {
                        run_len += 1;
                    }
                    _ => break,
                }
            }

            let start = i * sector_len;
            let chunk = &mut out[start..start + run_len * sector_len];
            // A present (mapped) run is explicitly mapped into the volume, so
            // it must read in full. Loop over partial reads and fail closed on
            // a real short read (truncated/broken volume) rather than serve
            // fabricated zero sectors inside an allocated block (BUG-164).
            // Genuine sparseness is the `None` branch, which legitimately
            // leaves zeros.
            let mut done = 0usize;
            while done < chunk.len() {
                match self
                    .volume
                    .read_at(run_start_off + done as u64, &mut chunk[done..])?
                {
                    0 => break,
                    n => done += n,
                }
            }
            if done < chunk.len() {
                // The merged read came up short somewhere in the run. Redo it
                // one 512-byte sector at a time (the original, unmerged path)
                // to find exactly which sector failed and report the same
                // error the pre-batching code would have: the batching is a
                // read-count optimisation, not a change to what a short read
                // reports.
                for s in 0..run_len {
                    let v = run_start_off + s as u64 * VSS_SECTOR_SIZE;
                    let sector = &mut chunk[s * sector_len..(s + 1) * sector_len];
                    let mut sector_done = 0usize;
                    while sector_done < sector.len() {
                        match self
                            .volume
                            .read_at(v + sector_done as u64, &mut sector[sector_done..])?
                        {
                            0 => break,
                            n => sector_done += n,
                        }
                    }
                    if sector_done < sector.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "VSS present sector short read: {} of {} bytes at volume offset {}",
                                sector_done, VSS_SECTOR_SIZE, v
                            ),
                        ));
                    }
                }
                // Unreachable in practice: the merged read already proved this
                // run short, so the per-sector redo above must find the
                // sector that fails. Fail closed rather than serve a
                // fabricated full block if it somehow doesn't.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "VSS present run short read: {} of {} bytes at volume offset {}",
                        done,
                        chunk.len(),
                        run_start_off
                    ),
                ));
            }

            i += run_len;
        }
        Ok(out)
    }
}

impl DataSource for VssDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.volume_size {
            return Ok(0);
        }
        let max = std::cmp::min(buf.len() as u64, self.volume_size - offset) as usize;

        let mut written = 0usize;
        while written < max {
            let cur = offset + written as u64;
            let block_offset = cur / VSS_BLOCK_SIZE * VSS_BLOCK_SIZE;
            let in_block = (cur % VSS_BLOCK_SIZE) as usize;

            let block = self.read_block(block_offset)?;
            let take = std::cmp::min(BLOCK_LEN - in_block, max - written);
            buf[written..written + take].copy_from_slice(&block[in_block..in_block + take]);
            written += take;
        }

        Ok(written)
    }

    fn size(&self) -> u64 {
        self.volume_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory volume: byte at absolute offset O is O's low byte unless
    /// explicitly written. Reads past the end zero-fill.
    #[derive(Debug)]
    struct MemVolume(Vec<u8>);

    impl DataSource for MemVolume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let off = offset as usize;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0.get(off + i).copied().unwrap_or(0);
            }
            Ok(buf.len())
        }
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// A volume truncated at `.0` bytes: reads at/after the end return EOF
    /// (`Ok(0)`), and a read spanning the end returns only the available bytes.
    #[derive(Debug)]
    struct TruncatedVolume(usize);

    impl DataSource for TruncatedVolume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let off = offset as usize;
            if off >= self.0 {
                return Ok(0);
            }
            let n = buf.len().min(self.0 - off);
            for b in &mut buf[..n] {
                *b = 0xAB;
            }
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0 as u64
        }
    }

    #[test]
    fn read_block_fails_closed_on_present_sector_short_read() {
        // The store maps volume block 0 to a data block at 5*VSS_BLOCK_SIZE, but
        // the backing volume is truncated before that offset. A present (mapped)
        // sector that reads short must error rather than serve fabricated zero
        // sectors inside an allocated block (BUG-164).
        let store = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let volume: Arc<dyn DataSource> = Arc::new(TruncatedVolume(VSS_BLOCK_SIZE as usize));
        let vss = VssDataSource::new(volume, store, 3 * VSS_BLOCK_SIZE);
        let mut buf = vec![0u8; VSS_SECTOR_SIZE as usize];
        assert!(
            vss.read_at(0, &mut buf).is_err(),
            "a present sector short read must fail closed"
        );
    }

    #[test]
    fn read_block_batches_a_fully_contiguous_run_into_one_underlying_read() {
        // A regular entry remaps the whole 16 KiB block to a single
        // contiguous data block: all 32 sectors' underlying offsets are
        // sequential, so the batching path must service them with one
        // read_at call, not 32 (ROADMAP 5.10: "one syscall per 512 bytes
        // through the block map").
        let mut expected = vec![0u8; 8 * BLOCK_LEN];
        for (i, b) in expected[5 * BLOCK_LEN..6 * BLOCK_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 256) as u8;
        }
        let volume = Arc::new(CountingVolume::new(expected.clone()));
        let store = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let ds = VssDataSource::new(volume.clone(), store, 3 * VSS_BLOCK_SIZE);

        let mut buf = vec![0u8; BLOCK_LEN];
        ds.read_at(0, &mut buf).unwrap();

        assert_eq!(
            volume.call_count(),
            1,
            "a fully contiguous 16 KiB block must cost one underlying read, not one per sector"
        );
        assert_eq!(buf, expected[5 * BLOCK_LEN..6 * BLOCK_LEN]);
    }

    #[test]
    fn read_block_falls_back_to_per_sector_reads_for_a_scattered_map() {
        // Two overlay entries interleave every other sector between two
        // unrelated data blocks (even sectors from block 5, odd from block
        // 6): no two consecutive sectors share a contiguous underlying
        // offset, so the non-contiguous fallback must still do one read per
        // sector, and must still produce the correct bytes.
        let mut vol_bytes = vec![0u8; 8 * BLOCK_LEN];
        for (i, b) in vol_bytes[5 * BLOCK_LEN..6 * BLOCK_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = 0xCC;
            let _ = i;
        }
        for (i, b) in vol_bytes[6 * BLOCK_LEN..7 * BLOCK_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = 0xDD;
            let _ = i;
        }
        let expected: Vec<u8> = (0..VSS_SECTORS_PER_BLOCK)
            .flat_map(|s| {
                let fill = if s % 2 == 0 { 0xCCu8 } else { 0xDDu8 };
                vec![fill; VSS_SECTOR_SIZE as usize]
            })
            .collect();

        let volume = Arc::new(CountingVolume::new(vol_bytes));
        let store = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![
                overlay(0, 5 * VSS_BLOCK_SIZE, 0x5555_5555), // even sectors
                overlay(0, 6 * VSS_BLOCK_SIZE, 0xAAAA_AAAA), // odd sectors
            ],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let ds = VssDataSource::new(volume.clone(), store, 3 * VSS_BLOCK_SIZE);

        let mut buf = vec![0u8; BLOCK_LEN];
        ds.read_at(0, &mut buf).unwrap();

        assert_eq!(
            volume.call_count(),
            VSS_SECTORS_PER_BLOCK,
            "a scattered block map must not be merged across the diversion into a different data block"
        );
        assert_eq!(buf, expected);
    }

    #[test]
    fn read_block_matches_the_pre_batching_one_read_per_sector_reference() {
        // Pin the batched implementation against an independent
        // reimplementation of the original one-read-per-512-byte-sector
        // algorithm, across the representative block-map shapes: fully
        // contiguous (regular entry), unmodified/live, scattered (two
        // overlays into different data blocks), and null-marked. Output must
        // be byte-identical in every case.
        let mut vol_bytes = vec![0u8; 8 * BLOCK_LEN];
        for (i, b) in vol_bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let volume: Arc<dyn DataSource> = Arc::new(MemVolume(vol_bytes));

        // Case 1 & 2: fully contiguous regular entry, and the unmodified
        // block that falls through to live at its original offsets.
        let store12 = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let ds12 = VssDataSource::new(volume.clone(), store12, 3 * VSS_BLOCK_SIZE);
        assert_eq!(
            ds12.read_block(0).unwrap(),
            read_block_one_syscall_per_sector(&ds12, 0).unwrap()
        );
        assert_eq!(
            ds12.read_block(VSS_BLOCK_SIZE).unwrap(),
            read_block_one_syscall_per_sector(&ds12, VSS_BLOCK_SIZE).unwrap()
        );

        // Case 3: scattered overlay into two different data blocks.
        let store3 = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![
                overlay(0, 5 * VSS_BLOCK_SIZE, 0x5555_5555),
                overlay(0, 6 * VSS_BLOCK_SIZE, 0xAAAA_AAAA),
            ],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let ds3 = VssDataSource::new(volume.clone(), store3, 3 * VSS_BLOCK_SIZE);
        assert_eq!(
            ds3.read_block(0).unwrap(),
            read_block_one_syscall_per_sector(&ds3, 0).unwrap()
        );

        // Case 4: null-marked block with no next store.
        let store4 = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            true,
            Vec::new(),
            vec![0b0000_0010u8],
            Vec::new(),
            None,
        ));
        let ds4 = VssDataSource::new(volume.clone(), store4, 3 * VSS_BLOCK_SIZE);
        assert_eq!(
            ds4.read_block(VSS_BLOCK_SIZE).unwrap(),
            read_block_one_syscall_per_sector(&ds4, VSS_BLOCK_SIZE).unwrap()
        );
    }

    #[test]
    fn read_block_short_read_error_matches_the_reference_exactly() {
        // A present, fully contiguous run that comes up short must report the
        // exact same error the pre-batching one-read-per-sector code would
        // have: which 512-byte sector failed, and at what volume offset --
        // not a run-level offset/length that only exists after batching.
        let store = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let volume: Arc<dyn DataSource> = Arc::new(TruncatedVolume(VSS_BLOCK_SIZE as usize));
        let ds = VssDataSource::new(volume, store, 3 * VSS_BLOCK_SIZE);

        let batched_err = ds.read_block(0).unwrap_err();
        let reference_err = read_block_one_syscall_per_sector(&ds, 0).unwrap_err();
        assert_eq!(batched_err.to_string(), reference_err.to_string());
        assert_eq!(
            batched_err.to_string(),
            format!(
                "VSS present sector short read: 0 of {} bytes at volume offset {}",
                VSS_SECTOR_SIZE,
                5 * VSS_BLOCK_SIZE
            )
        );
    }

    #[test]
    fn read_block_batching_is_measurably_faster_than_one_read_per_sector() {
        // Simulate real read_at overhead (e.g. a syscall) with a fixed
        // per-call sleep, then time the batched implementation against the
        // pre-batching one-read-per-sector reference over the same fully
        // contiguous blocks. This is the actual before/after measurement
        // ROADMAP 5.10 asks for, not just an argument that fewer calls
        // should be faster.
        const PER_CALL: std::time::Duration = std::time::Duration::from_micros(10);
        const ITERATIONS: u64 = 500;

        let vol_bytes = vec![0xAAu8; 8 * BLOCK_LEN];
        let volume: Arc<dyn DataSource> = Arc::new(SlowVolume {
            data: vol_bytes,
            per_call: PER_CALL,
        });
        // A fully live (untouched) block: 32 sequential sector offsets --
        // the best case the batching path exists to serve.
        let store = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            Vec::new(),
            vec![0u8],
            Vec::new(),
            None,
        ));
        let ds = VssDataSource::new(volume.clone(), store.clone(), 3 * VSS_BLOCK_SIZE);

        let start_new = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            ds.read_block(VSS_BLOCK_SIZE).unwrap();
        }
        let new_elapsed = start_new.elapsed();

        let start_old = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            read_block_one_syscall_per_sector(&ds, VSS_BLOCK_SIZE).unwrap();
        }
        let old_elapsed = start_old.elapsed();

        eprintln!(
            "read_block batching: {ITERATIONS} blocks x {VSS_SECTORS_PER_BLOCK} sectors, \
             {PER_CALL:?}/call simulated I/O -> old (1 read/sector) = {old_elapsed:?}, \
             new (batched contiguous run) = {new_elapsed:?}, speedup = {:.1}x",
            old_elapsed.as_secs_f64() / new_elapsed.as_secs_f64().max(1e-9)
        );

        assert!(
            new_elapsed.saturating_mul(2) < old_elapsed,
            "batching should cut wall time by roughly the sector-count factor, got old={old_elapsed:?} new={new_elapsed:?}"
        );
    }

    #[test]
    fn align_up_saturates_instead_of_overflowing() {
        // A normal value rounds up to the next block multiple.
        assert_eq!(align_up(1, VSS_BLOCK_SIZE), Some(VSS_BLOCK_SIZE));
        assert_eq!(
            align_up(VSS_BLOCK_SIZE, VSS_BLOCK_SIZE),
            Some(VSS_BLOCK_SIZE)
        );
        // An attacker-controlled volume_size near u64::MAX must not overflow
        // (previously `v + a` panicked in debug / wrapped to a tiny value).
        assert_eq!(align_up(u64::MAX - 10, VSS_BLOCK_SIZE), None);
        assert_eq!(align_up(u64::MAX, VSS_BLOCK_SIZE), None);
    }

    fn regular(original: u64, data_block: u64) -> OnDiskTableEntry {
        OnDiskTableEntry {
            original_volume_offset: original,
            data_block_offset_in_store: 0,
            data_block_volume_offset: data_block,
            flags: 0,
            allocation_bitmap: 0,
        }
    }

    /// An overlay entry: only the sectors selected by `allocation_bitmap` come
    /// from `data_block`, the rest are left for another entry (or the
    /// fallback base) to fill.
    fn overlay(original: u64, data_block: u64, allocation_bitmap: u32) -> OnDiskTableEntry {
        OnDiskTableEntry {
            original_volume_offset: original,
            data_block_offset_in_store: 0,
            data_block_volume_offset: data_block,
            flags: DIFF_AREA_ENTRY_OVERLAY,
            allocation_bitmap,
        }
    }

    /// Independent reimplementation of the pre-batching `read_block`: one
    /// `read_at` call per 512-byte sector, unconditionally, even when several
    /// consecutive sectors resolve to consecutive underlying offsets. Kept
    /// only as an oracle so the batched implementation can be pinned against
    /// it byte-for-byte (and error-for-error).
    fn read_block_one_syscall_per_sector(
        ds: &VssDataSource,
        block_offset: u64,
    ) -> io::Result<[u8; BLOCK_LEN]> {
        let mut out = [0u8; BLOCK_LEN];
        let offsets = ds.store.translate_exact_offset(block_offset, false, false);
        if offsets.is_empty() {
            return Ok(out);
        }
        for (i, off) in offsets.iter().enumerate() {
            if let Some(v) = off {
                let start = i * VSS_SECTOR_SIZE as usize;
                let sector = &mut out[start..start + VSS_SECTOR_SIZE as usize];
                let mut done = 0usize;
                while done < sector.len() {
                    match ds.volume.read_at(*v + done as u64, &mut sector[done..])? {
                        0 => break,
                        n => done += n,
                    }
                }
                if done < sector.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "VSS present sector short read: {} of {} bytes at volume offset {}",
                            done, VSS_SECTOR_SIZE, v
                        ),
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Volume that records every `read_at` call's (offset, length), for
    /// asserting how many underlying reads a translation actually performs.
    #[derive(Debug)]
    struct CountingVolume {
        data: Vec<u8>,
        calls: std::sync::Mutex<Vec<(u64, usize)>>,
    }

    impl CountingVolume {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl DataSource for CountingVolume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.calls.lock().unwrap().push((offset, buf.len()));
            let off = offset as usize;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.data.get(off + i).copied().unwrap_or(0);
            }
            Ok(buf.len())
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    /// Volume that sleeps a fixed duration per `read_at` call, standing in
    /// for real per-syscall overhead so batching's wall-clock effect can be
    /// measured rather than just argued.
    #[derive(Debug)]
    struct SlowVolume {
        data: Vec<u8>,
        per_call: std::time::Duration,
    }

    impl DataSource for SlowVolume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(self.per_call);
            let off = offset as usize;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.data.get(off + i).copied().unwrap_or(0);
            }
            Ok(buf.len())
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    // -- translate_exact_offset ---------------------------------------------

    #[test]
    fn translate_regular_entry_points_at_store_data_block() {
        // A regular entry remaps volume block 0 to a data block at 5*16384.
        let store = VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8], // bitmap: block 0 not marked
            Vec::new(),
            None,
        );

        let offs = store.translate_exact_offset(0, false, false);
        assert_eq!(offs.len(), VSS_SECTORS_PER_BLOCK);
        for (i, o) in offs.iter().enumerate() {
            assert_eq!(*o, Some(5 * VSS_BLOCK_SIZE + i as u64 * VSS_SECTOR_SIZE));
        }
    }

    #[test]
    fn translate_unchanged_block_returns_original_offsets() {
        // Block 1 is not in the diff area and not marked -> read from live at
        // its original offset.
        let store = VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        );

        let offs = store.translate_exact_offset(VSS_BLOCK_SIZE, false, false);
        for (i, o) in offs.iter().enumerate() {
            assert_eq!(*o, Some(VSS_BLOCK_SIZE + i as u64 * VSS_SECTOR_SIZE));
        }
    }

    #[test]
    fn translate_marked_unused_block_returns_null_when_flag_set() {
        // return_null_blocks = true and block 1 marked in the bitmap, with no
        // diff-area entry and no next store -> a null (zero) block.
        let store = VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            true,
            Vec::new(),
            vec![0b0000_0010u8], // block 1 marked
            Vec::new(),
            None,
        );

        let offs = store.translate_exact_offset(VSS_BLOCK_SIZE, false, false);
        assert!(offs.iter().all(|o| o.is_none()), "expected all-null block");
    }

    #[test]
    fn translate_falls_through_to_next_store() {
        // Block 0 is absent from this store but a regular entry in the next
        // store remaps it. The current store must fall through to the next.
        let next = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 7 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let store = VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            Vec::new(),
            vec![0u8],
            Vec::new(),
            Some(next),
        );

        let offs = store.translate_exact_offset(0, false, false);
        for (i, o) in offs.iter().enumerate() {
            assert_eq!(*o, Some(7 * VSS_BLOCK_SIZE + i as u64 * VSS_SECTOR_SIZE));
        }
    }

    // -- read_diff_area forward context (synthetic on-disk bytes) -----------

    /// Write a shadow-block header (GUID, type, this-block offset, next offset)
    /// into `buf` at `at`.
    fn write_block_header(buf: &mut [u8], at: usize, block_type: u32, vol_off: u64, next: u64) {
        buf[at..at + 16].copy_from_slice(&VSS_DIFF_AREA_GUID);
        buf[at + 20..at + 24].copy_from_slice(&block_type.to_le_bytes());
        buf[at + 32..at + 40].copy_from_slice(&vol_off.to_le_bytes());
        buf[at + 40..at + 48].copy_from_slice(&next.to_le_bytes());
    }

    fn write_entry(buf: &mut [u8], at: usize, e: &OnDiskTableEntry) {
        buf[at..at + 8].copy_from_slice(&e.original_volume_offset.to_le_bytes());
        buf[at + 8..at + 16].copy_from_slice(&e.data_block_offset_in_store.to_le_bytes());
        buf[at + 16..at + 24].copy_from_slice(&e.data_block_volume_offset.to_le_bytes());
        buf[at + 24..at + 28].copy_from_slice(&e.flags.to_le_bytes());
        buf[at + 28..at + 32].copy_from_slice(&e.allocation_bitmap.to_le_bytes());
    }

    #[test]
    fn read_diff_area_applies_forward_context() {
        // One diff-area table at volume offset D holding, in order:
        //   [0] forwarder: original A -> forward target B (A != B)
        //   [1] regular:   original B, data block at C
        // The forwarder must rewrite entry [1]'s original offset B -> A.
        let d = 4 * VSS_BLOCK_SIZE;
        let a = VSS_BLOCK_SIZE;
        let b = 2 * VSS_BLOCK_SIZE;
        let c = 9 * VSS_BLOCK_SIZE;

        let mut vol = vec![0u8; 16 * BLOCK_LEN];
        write_block_header(&mut vol, d as usize, VSS_RECORD_TYPE_DIFF_AREA_TABLE, d, 0);

        let forwarder = OnDiskTableEntry {
            original_volume_offset: a,
            data_block_offset_in_store: b, // forward target
            data_block_volume_offset: 0,
            flags: DIFF_AREA_ENTRY_FORWARDER,
            allocation_bitmap: 0,
        };
        let reg = regular(b, c);
        write_entry(&mut vol, d as usize + VSS_BLOCK_HEADER_SIZE, &forwarder);
        write_entry(&mut vol, d as usize + VSS_BLOCK_HEADER_SIZE + 32, &reg);

        let source: Arc<dyn DataSource> = Arc::new(MemVolume(vol));
        let items = read_diff_area(&source, d).unwrap();

        // The regular entry's original offset should now be A (rewritten).
        let rewritten = items
            .iter()
            .find(|e| e.flags & (DIFF_AREA_ENTRY_FORWARDER | DIFF_AREA_ENTRY_OVERLAY) == 0)
            .expect("a regular entry survives");
        assert_eq!(rewritten.original_volume_offset, a);
        assert_eq!(rewritten.data_block_volume_offset, c);
    }

    /// A volume that holds every byte but answers at most `chunk` bytes per
    /// `read_at` — legal under the `DataSource` contract, and what a windowed
    /// or network-backed source does.
    #[derive(Debug)]
    struct ChunkedVolume {
        data: Vec<u8>,
        chunk: usize,
    }

    impl DataSource for ChunkedVolume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.chunk).min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    /// HUNT-154: the diff-area and bitmap readers did one `read_at` and
    /// errored on a short count, so a source that answers in pieces failed
    /// the whole store build. They must loop until the block is full, and
    /// still fail closed when the bytes genuinely run out (BUG-164).
    #[test]
    fn store_metadata_reads_survive_a_legal_short_read_and_fail_on_a_real_one() {
        let d = 4 * VSS_BLOCK_SIZE;
        let bm = 6 * VSS_BLOCK_SIZE;
        let mut vol = vec![0u8; 16 * BLOCK_LEN];
        write_block_header(&mut vol, d as usize, VSS_RECORD_TYPE_DIFF_AREA_TABLE, d, 0);
        write_entry(
            &mut vol,
            d as usize + VSS_BLOCK_HEADER_SIZE,
            &regular(VSS_BLOCK_SIZE, 9 * VSS_BLOCK_SIZE),
        );
        write_block_header(&mut vol, bm as usize, VSS_RECORD_TYPE_STORE_BITMAP, bm, 0);
        vol[bm as usize + VSS_BLOCK_HEADER_SIZE] = 0b1010_0101;

        let whole: Arc<dyn DataSource> = Arc::new(MemVolume(vol.clone()));
        let chunked: Arc<dyn DataSource> = Arc::new(ChunkedVolume {
            data: vol.clone(),
            chunk: 4096,
        });

        let expected = read_diff_area(&whole, d).unwrap();
        let got = read_diff_area(&chunked, d).expect("a legal short read must not fail the store");
        assert_eq!(got.len(), expected.len());
        assert_eq!(got[0].original_volume_offset, VSS_BLOCK_SIZE);
        assert_eq!(got[0].data_block_volume_offset, 9 * VSS_BLOCK_SIZE);

        let volume_size = 16 * BLOCK_LEN as u64;
        let bits = read_bitmap(&chunked, bm, volume_size)
            .expect("a legal short read must not fail the bitmap");
        assert_eq!(bits, read_bitmap(&whole, bm, volume_size).unwrap());
        assert_eq!(bits[0], 0b1010_0101);

        // Bytes that really are not there still fail closed.
        let cut: Arc<dyn DataSource> = Arc::new(ChunkedVolume {
            data: vol[..d as usize + 100].to_vec(),
            chunk: 4096,
        });
        assert!(read_diff_area(&cut, d).is_err());
    }

    // -- end-to-end VssDataSource read via the store chain ------------------

    #[test]
    fn vss_datasource_reads_reconstructed_bytes() {
        // Volume: original block 0 filled 0xAA; a store data block at 5*16384
        // filled 0xCC; block 1 unmodified (bytes default to offset low byte,
        // but we fill it 0xBB for clarity).
        let mut vol = vec![0u8; 8 * BLOCK_LEN];
        for b in &mut vol[0..BLOCK_LEN] {
            *b = 0xAA;
        }
        for b in &mut vol[BLOCK_LEN..2 * BLOCK_LEN] {
            *b = 0xBB;
        }
        for b in &mut vol[5 * BLOCK_LEN..6 * BLOCK_LEN] {
            *b = 0xCC;
        }
        let volume: Arc<dyn DataSource> = Arc::new(MemVolume(vol));

        let store = Arc::new(VssStore::from_parts(
            3 * VSS_BLOCK_SIZE,
            false,
            vec![regular(0, 5 * VSS_BLOCK_SIZE)],
            vec![0u8],
            Vec::new(),
            None,
        ));
        let ds = VssDataSource::new(volume, store, 3 * VSS_BLOCK_SIZE);

        // Block 0 is remapped to the store data block -> 0xCC.
        let mut b0 = vec![0u8; BLOCK_LEN];
        assert_eq!(ds.read_at(0, &mut b0).unwrap(), BLOCK_LEN);
        assert!(
            b0.iter().all(|&x| x == 0xCC),
            "block 0 should come from store"
        );

        // Block 1 is unchanged -> live volume 0xBB.
        let mut b1 = vec![0u8; BLOCK_LEN];
        ds.read_at(VSS_BLOCK_SIZE, &mut b1).unwrap();
        assert!(
            b1.iter().all(|&x| x == 0xBB),
            "block 1 should come from live"
        );

        // size() reports the snapshot volume size.
        assert_eq!(ds.size(), 3 * VSS_BLOCK_SIZE);
    }

    #[test]
    fn a_store_chain_records_every_older_store_it_falls_through_to() {
        // Three stores with no diff area of their own: what matters here is the
        // links between them. A store that reports depth 0 when an older store
        // exists is silently serving live-volume bytes for everything it did
        // not preserve.
        let vol: Arc<dyn DataSource> = Arc::new(MemVolume(vec![0u8; 16 * BLOCK_LEN]));
        let size = 8 * VSS_BLOCK_SIZE;

        let oldest = Arc::new(VssStore::build(&vol, 0, 0, 0, size, 0, None).unwrap());
        assert_eq!(oldest.chain_depth(), 0, "the oldest store ends the chain");

        let middle =
            Arc::new(VssStore::build(&vol, 0, 0, 0, size, 0, Some(oldest.clone())).unwrap());
        assert_eq!(middle.chain_depth(), 1);

        let newest =
            Arc::new(VssStore::build(&vol, 0, 0, 0, size, 0, Some(middle.clone())).unwrap());
        assert_eq!(
            newest.chain_depth(),
            2,
            "the newest snapshot must reach every older store, not just the next one"
        );
    }
}
