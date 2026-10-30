//! ext2/ext3 indirect-block-aware carve reconstruction (DFTT #12).
//!
//! ext2 (and ext3, which shares its block map) addresses a file's first 12
//! blocks directly from the inode. Block 12 onward is addressed through an
//! *indirect* block (IND): a block of little-endian `u32` block numbers. Past
//! `12 + N` blocks (`N = block_size / 4`) a *double-indirect* block (DIND)
//! points at further IND blocks. When the allocator lays a file out in free
//! space it writes those pointer blocks in line with the content: the IND sits
//! immediately before the file's block 12, the DIND immediately before the
//! first IND it points to. A carver that copies header..end contiguously
//! therefore includes pointer blocks as if they were file content, and the
//! file comes back the right size but byte-wrong.
//!
//! This module recognises that layout after a carve and rebuilds the file as
//! a run list that leaves every pointer block out. It never guesses: every
//! pointer block the layout predicts is read and must hold **exactly** the
//! block numbers of the content blocks (or IND blocks) the layout puts after
//! it, followed by zeros. One entry out of place and the carve is left as it
//! was. Block numbering is anchored on the first IND block's own first entry
//! (the block that follows it), so the carved region need not start at the
//! file system's first block.
//!
//! Bounds, stated rather than hidden:
//! - only the allocator's in-line layout is rebuilt: content that the pointer
//!   blocks place elsewhere (a file fragmented across free space) is not
//!   followed, and the carve is left unreconstructed;
//! - triple-indirect (TIND) files (more than `12 + N + N*N` blocks, 64 MiB at
//!   1 KiB blocks) are not rebuilt;
//! - ext4 extent-mapped files have no in-line pointer blocks and are not this
//!   module's concern.

use crate::engine::{read_full, CarvedFile, CarvingDataSource, CarvingEngine};

/// Block sizes tried, smallest first. ext2 allows 1, 2 and 4 KiB (larger
/// only on large-page architectures).
const BLOCK_SIZES: [u64; 3] = [1024, 2048, 4096];

/// Number of direct block pointers in an ext2 inode.
const DIRECT_BLOCKS: u64 = 12;

/// How the carve's recorded size should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarveSize {
    /// The size is the file's own logical length (taken from its header): the
    /// on-disk extent is that plus any pointer blocks in line with it.
    Logical,
    /// The size is the on-disk span the carve covered (ended by a footer or a
    /// structure walk): it already includes any pointer blocks.
    Physical,
}

/// A carve rebuilt without its in-line ext2 pointer blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext2Reconstruction {
    /// The file system block size the layout was verified at.
    pub block_size: u64,
    /// Content runs `(offset, length)` in the carved source's coordinates, in
    /// file order. Their lengths sum to `logical_size`.
    pub runs: Vec<(u64, u64)>,
    /// The rebuilt file's length.
    pub logical_size: u64,
    /// Offsets of the pointer blocks left out (IND and DIND), in disk order.
    pub pointer_blocks: Vec<u64>,
    /// Where `logical_size` came from, and so what the carve's validation
    /// flag describes.
    pub end: RebuiltEnd,
}

/// Where a rebuilt file's length came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuiltEnd {
    /// The carve's own size, read through the layout: the carve's validation
    /// flag still describes this end.
    AsCarved,
    /// A fresh scan over the [`LayoutView`] sized the file; `validated` is that
    /// scan's flag, and the original carve's flag describes an end the
    /// published file does not have.
    Resized { validated: Option<bool> },
}

impl Ext2Reconstruction {
    /// Offset one past the last byte the rebuilt file occupies on disk.
    pub fn physical_end(&self) -> u64 {
        self.runs.last().map(|&(o, l)| o + l).unwrap_or(0)
    }
}

/// Try to rebuild a carve at `offset` whose recorded size is `size`, read as
/// `kind`. Returns `None` when no pointer block is in line with the file (the
/// carve is already right, or the file is under 13 blocks), or when the layout
/// cannot be verified entry by entry.
pub fn reconstruct<S: CarvingDataSource + ?Sized>(
    source: &S,
    offset: u64,
    size: u64,
    kind: CarveSize,
) -> Option<Ext2Reconstruction> {
    if size == 0 {
        return None;
    }
    for bs in BLOCK_SIZES {
        if !looks_like_first_ind(source, offset, bs) {
            continue;
        }
        let candidates: Vec<u64> = match kind {
            CarveSize::Logical => vec![size],
            CarveSize::Physical => {
                // The span holds `k` pointer blocks; the file is the span less
                // them, and the layout of that length must itself need `k`.
                let n = bs / 4;
                let k_max = 3 + size.div_ceil(bs) / n;
                (1..=k_max)
                    .filter_map(|k| {
                        let logical = size.checked_sub(k * bs)?;
                        (logical > 0 && pointer_block_count(logical.div_ceil(bs), n) == Some(k))
                            .then_some(logical)
                    })
                    .collect()
            }
        };
        for logical in candidates {
            if let Some(r) = verify_layout(source, offset, logical, bs) {
                return Some(r);
            }
        }
    }
    None
}

/// The file an in-line ext2 layout at `offset` describes, read through its
/// pointer blocks as one contiguous source of whole blocks.
///
/// Its length is what the pointer blocks themselves say: `12 + n` blocks for
/// an IND holding `n` entries, and through the DIND for a larger file. The
/// file's own byte length is somewhere in its last block; a format sizer run
/// over this view finds it without the pointer blocks in the way.
pub struct LayoutView<'a, S: CarvingDataSource + ?Sized> {
    source: &'a S,
    /// File-system block size of the layout.
    pub block_size: u64,
    /// Content blocks the pointer blocks name, the direct ones included.
    pub blocks: u64,
    /// Offset of each content block in `source`, in file order.
    block_offsets: Vec<u64>,
}

impl<'a, S: CarvingDataSource + ?Sized> LayoutView<'a, S> {
    /// Build the view if an in-line first IND sits after the 12th block from
    /// `offset`, at the first block size where one does.
    pub fn at(source: &'a S, offset: u64) -> Option<Self> {
        for bs in BLOCK_SIZES {
            if !looks_like_first_ind(source, offset, bs) {
                continue;
            }
            let Some(blocks) = described_blocks(source, offset, bs) else {
                continue;
            };
            // Every pointer entry is checked against the layout, exactly as a
            // rebuild is; a view is never built over an unverified layout.
            let Some(r) = verify_layout(source, offset, blocks * bs, bs) else {
                continue;
            };
            let block_offsets = r
                .runs
                .iter()
                .flat_map(|&(o, len)| (0..len.div_ceil(bs)).map(move |i| o + i * bs))
                .collect();
            return Some(Self {
                source,
                block_size: bs,
                blocks,
                block_offsets,
            });
        }
        None
    }
}

impl<S: CarvingDataSource + ?Sized> CarvingDataSource for LayoutView<'_, S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let idx = pos / self.block_size;
            let Some(&base) = self.block_offsets.get(idx as usize) else {
                break;
            };
            let within = pos % self.block_size;
            let take = ((self.block_size - within) as usize).min(buf.len() - done);
            let n = self
                .source
                .read_at(base + within, &mut buf[done..done + take])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn size(&self) -> u64 {
        self.blocks * self.block_size
    }
}

/// Size a carve again through the in-line layout at its start, when the
/// carve's own sizing ran into a pointer block (a structure walk that read an
/// IND as content, for example) and so could not be rebuilt as recorded.
///
/// The carve's signature is run over the [`LayoutView`] from its first byte;
/// the size it finds there is accepted only if it ended on the file's own
/// terminator or structure (not at the view's end) and the layout for that
/// size verifies entry by entry.
pub fn resize_through_layout<S: CarvingDataSource + ?Sized>(
    engine: &CarvingEngine,
    source: &S,
    carved: &CarvedFile,
) -> Option<Ext2Reconstruction> {
    let view = LayoutView::at(source, carved.offset)?;
    let found = engine
        .scan(&view, view.size())
        .into_iter()
        .find(|f| f.offset == 0 && f.signature_name == carved.signature_name)?;
    if found.validated == Some(false) {
        return None;
    }
    verify_layout(source, carved.offset, found.size, view.block_size).map(|r| Ext2Reconstruction {
        end: RebuiltEnd::Resized {
            validated: found.validated,
        },
        ..r
    })
}

/// Entries before the first zero in a pointer block.
fn entry_count(block: &[u8]) -> (u64, Vec<u32>) {
    let entries: Vec<u32> = block
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .take_while(|&e| e != 0)
        .collect();
    (entries.len() as u64, entries)
}

/// Content blocks the in-line pointer blocks at `offset` name: the direct 12,
/// the first IND's entries, and through the DIND the entries of every IND
/// under it (all full but the last, which the layout check confirms).
fn described_blocks<S: CarvingDataSource + ?Sized>(
    source: &S,
    offset: u64,
    bs: u64,
) -> Option<u64> {
    let n = bs / 4;
    let mut buf = vec![0u8; bs as usize];
    let read_block = |pos: u64, buf: &mut [u8]| -> Option<()> {
        let at = offset.checked_add(pos.checked_mul(bs)?)?;
        (read_full(source, at, buf) == buf.len()).then_some(())
    };
    read_block(DIRECT_BLOCKS, &mut buf)?;
    let (first_count, first) = entry_count(&buf);
    if first_count < n {
        return Some(DIRECT_BLOCKS + first_count);
    }
    let anchor = (*first.first()? as u64).checked_sub(DIRECT_BLOCKS + 1)?;
    // The DIND follows the first IND's last content block.
    read_block(DIRECT_BLOCKS + 1 + n, &mut buf)?;
    let (children, dind) = entry_count(&buf);
    let last_ind_pos = (*dind.last()? as u64).checked_sub(anchor)?;
    read_block(last_ind_pos, &mut buf)?;
    let (last_count, _) = entry_count(&buf);
    Some(DIRECT_BLOCKS + n + (children - 1) * n + last_count)
}

/// Cheap pre-check before any layout is tried: the block where a first IND
/// would sit holds a run of consecutive block numbers, then only zeros.
fn looks_like_first_ind<S: CarvingDataSource + ?Sized>(source: &S, offset: u64, bs: u64) -> bool {
    let Some(at) = offset.checked_add(DIRECT_BLOCKS * bs) else {
        return false;
    };
    let mut buf = vec![0u8; bs as usize];
    if read_full(source, at, &mut buf) != buf.len() {
        return false;
    }
    let mut entries = buf
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c));
    let Some(first) = entries.next().filter(|&e| e > DIRECT_BLOCKS as u32) else {
        return false;
    };
    let mut expect = Some(first);
    for e in entries {
        match expect {
            Some(x) if e == x.wrapping_add(1) => expect = Some(e),
            _ if e == 0 => expect = None,
            _ => return false,
        }
    }
    true
}

/// Pointer blocks (IND + DIND + the INDs under it) a file of `nb` blocks needs
/// with `n` pointers per block, or `None` past the double-indirect range.
fn pointer_block_count(nb: u64, n: u64) -> Option<u64> {
    if nb <= DIRECT_BLOCKS {
        Some(0)
    } else if nb <= DIRECT_BLOCKS + n {
        Some(1)
    } else if nb <= DIRECT_BLOCKS + n + n * n {
        Some(2 + (nb - DIRECT_BLOCKS - n).div_ceil(n))
    } else {
        None
    }
}

/// One block of the predicted on-disk layout, by position from the carve start.
enum Slot {
    Data,
    /// A pointer block and the layout positions of the blocks it must name.
    Pointers(Vec<u64>),
}

/// The allocator's in-line layout for a file of `nb` blocks, `n` pointers per
/// block: 12 data, IND, up to `n` data, DIND, then (IND, up to `n` data)...
fn plan(nb: u64, n: u64) -> Option<Vec<Slot>> {
    pointer_block_count(nb, n)?;
    let mut slots: Vec<Slot> = Vec::new();
    let mut remaining = nb;
    let direct = remaining.min(DIRECT_BLOCKS);
    for _ in 0..direct {
        slots.push(Slot::Data);
    }
    remaining -= direct;
    // Push an IND and the data blocks it names; return the IND's position.
    let push_ind = |slots: &mut Vec<Slot>, remaining: &mut u64| {
        let count = (*remaining).min(n);
        let own = slots.len() as u64;
        slots.push(Slot::Pointers((own + 1..=own + count).collect()));
        for _ in 0..count {
            slots.push(Slot::Data);
        }
        *remaining -= count;
        own
    };
    if remaining > 0 {
        push_ind(&mut slots, &mut remaining);
    }
    if remaining > 0 {
        let dind = slots.len();
        slots.push(Slot::Pointers(Vec::new()));
        let mut children = Vec::new();
        while remaining > 0 {
            children.push(push_ind(&mut slots, &mut remaining));
        }
        slots[dind] = Slot::Pointers(children);
    }
    Some(slots)
}

/// Check every pointer block the layout of a `logical`-byte file predicts at
/// `offset` holds exactly the block numbers it must, then zeros.
fn verify_layout<S: CarvingDataSource + ?Sized>(
    source: &S,
    offset: u64,
    logical: u64,
    bs: u64,
) -> Option<Ext2Reconstruction> {
    let n = bs / 4;
    let nb = logical.div_ceil(bs);
    if nb <= DIRECT_BLOCKS {
        return None;
    }
    let slots = plan(nb, n)?;
    let tail = logical - (nb - 1) * bs;
    let end = offset.checked_add((slots.len() as u64 - 1) * bs + tail)?;
    if end > source.size() {
        return None;
    }

    // Anchor block numbering on the first IND's first entry: the block right
    // after it (layout position 13) carries that number.
    let mut buf = vec![0u8; bs as usize];
    let read_block = |pos: u64, buf: &mut [u8]| -> Option<()> {
        (read_full(source, offset + pos * bs, buf) == buf.len()).then_some(())
    };
    read_block(DIRECT_BLOCKS, &mut buf)?;
    let first = u32::from_le_bytes(buf[0..4].try_into().ok()?) as i64;
    let anchor = first - (DIRECT_BLOCKS as i64 + 1);
    if first == 0 || anchor < 0 {
        return None;
    }

    let mut pointer_blocks = Vec::new();
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut data_seen = 0u64;
    for (pos, slot) in slots.iter().enumerate() {
        let pos = pos as u64;
        match slot {
            Slot::Data => {
                data_seen += 1;
                let len = if data_seen == nb { tail } else { bs };
                let at = offset + pos * bs;
                match runs.last_mut() {
                    Some(last) if last.0 + last.1 == at => last.1 += len,
                    _ => runs.push((at, len)),
                }
            }
            Slot::Pointers(targets) => {
                read_block(pos, &mut buf)?;
                for (i, entry) in buf.as_chunks::<4>().0.iter().enumerate() {
                    let got = u32::from_le_bytes(*entry) as i64;
                    let want = targets.get(i).map(|&t| anchor + t as i64).unwrap_or(0);
                    if got != want {
                        return None;
                    }
                }
                pointer_blocks.push(offset + pos * bs);
            }
        }
    }
    Some(Ext2Reconstruction {
        block_size: bs,
        runs,
        logical_size: logical,
        pointer_blocks,
        end: RebuiltEnd::AsCarved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct Mem(Vec<u8>);
    impl CarvingDataSource for Mem {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let off = offset as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// Content bytes of a file of `len` bytes, varied so a misplaced run shows.
    fn content(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 1024) as u8).collect()
    }

    fn pointer_block(bs: usize, entries: &[u32]) -> Vec<u8> {
        let mut b = vec![0u8; bs];
        for (i, e) in entries.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&e.to_le_bytes());
        }
        b
    }

    /// Lay `file` out the way the ext2 allocator does in free space starting
    /// at file-system block `first_block`, with block size `bs`: 12 direct
    /// blocks, IND, the next N, DIND, then (IND, N blocks) per group.
    /// Returns the on-disk bytes (padded to whole blocks).
    fn ext2_layout(file: &[u8], bs: usize, first_block: u32) -> Vec<u8> {
        let n = bs / 4;
        let nb = file.len().div_ceil(bs);
        let mut disk: Vec<u8> = Vec::new();
        let blockno = |disk: &Vec<u8>| first_block + (disk.len() / bs) as u32;
        let push_data = |disk: &mut Vec<u8>, i: usize| {
            let mut b = vec![0u8; bs];
            let end = ((i + 1) * bs).min(file.len());
            b[..end - i * bs].copy_from_slice(&file[i * bs..end]);
            disk.extend_from_slice(&b);
        };
        let mut i = 0;
        while i < nb.min(12) {
            push_data(&mut disk, i);
            i += 1;
        }
        let write_ind = |disk: &mut Vec<u8>, i: &mut usize| {
            let count = (nb - *i).min(n);
            let own = blockno(disk);
            let entries: Vec<u32> = (1..=count as u32).map(|k| own + k).collect();
            disk.extend_from_slice(&pointer_block(bs, &entries));
            for _ in 0..count {
                push_data(disk, *i);
                *i += 1;
            }
        };
        if i < nb {
            write_ind(&mut disk, &mut i);
        }
        if i < nb {
            let groups = (nb - i).div_ceil(n);
            let dind_own = blockno(&disk);
            let entries: Vec<u32> = (0..groups as u32)
                .map(|g| dind_own + 1 + g * (n as u32 + 1))
                .collect();
            disk.extend_from_slice(&pointer_block(bs, &entries));
            while i < nb {
                write_ind(&mut disk, &mut i);
            }
        }
        disk
    }

    fn rebuilt(src: &Mem, r: &Ext2Reconstruction) -> Vec<u8> {
        let mut out = Vec::new();
        for &(o, l) in &r.runs {
            out.extend_from_slice(&src.0[o as usize..(o + l) as usize]);
        }
        out
    }

    #[test]
    fn detects_and_skips_ext2_indirect_block_at_file_block_12() {
        let file = content(20 * 1024 - 300);
        let mut disk = vec![0xAAu8; 4096]; // unrelated bytes before the file
        let start = disk.len() as u64;
        disk.extend(ext2_layout(&file, 1024, 5000));
        disk.extend(vec![0x55u8; 2048]);
        let src = Mem(disk);

        let r = reconstruct(&src, start, file.len() as u64, CarveSize::Logical)
            .expect("the in-line IND block is recognised");
        assert_eq!(r.block_size, 1024);
        assert_eq!(
            r.runs,
            vec![(start, 12 * 1024), (start + 13 * 1024, 8 * 1024 - 300)]
        );
        assert_eq!(r.pointer_blocks, vec![start + 12 * 1024]);
        assert_eq!(r.logical_size, file.len() as u64);
        assert_eq!(r.end, RebuiltEnd::AsCarved);
        assert_eq!(rebuilt(&src, &r), file);
    }

    #[test]
    fn a_physical_carve_span_is_rebuilt_to_the_file_without_its_pointer_block() {
        // A footer-ended carve covers the IND block: its size is the on-disk span.
        let file = content(15 * 1024 + 17);
        let disk = ext2_layout(&file, 1024, 777);
        let span = (file.len() + 1024) as u64;
        let src = Mem(disk);
        let r = reconstruct(&src, 0, span, CarveSize::Physical).expect("rebuilt");
        assert_eq!(r.logical_size, file.len() as u64);
        assert_eq!(rebuilt(&src, &r), file);
    }

    #[test]
    fn a_double_indirect_file_skips_the_dind_and_every_ind_block() {
        let bs = 1024;
        let file = content((12 + 256 + 300) * bs - 5);
        let src = Mem(ext2_layout(&file, bs, 1));
        let r = reconstruct(&src, 0, file.len() as u64, CarveSize::Logical).expect("rebuilt");
        // IND, DIND, and two IND blocks under it.
        assert_eq!(r.pointer_blocks.len(), 4);
        assert_eq!(rebuilt(&src, &r), file);

        let span = file.len() as u64 + 4 * bs as u64;
        let p = reconstruct(&src, 0, span, CarveSize::Physical).expect("physical rebuilt");
        assert_eq!(rebuilt(&src, &p), file);
    }

    #[test]
    fn a_4k_block_layout_is_found_at_its_own_block_size() {
        let file = content(14 * 4096 + 9);
        let src = Mem(ext2_layout(&file, 4096, 32768));
        let r = reconstruct(&src, 0, file.len() as u64, CarveSize::Logical).expect("rebuilt");
        assert_eq!(r.block_size, 4096);
        assert_eq!(rebuilt(&src, &r), file);
    }

    #[test]
    fn a_content_block_of_small_integers_that_are_not_the_next_blocks_is_not_skipped() {
        // Block 12 holds u32s then zeros, but not the consecutive block
        // numbers the in-line layout requires.
        let bs = 1024;
        let file = content(20 * bs);
        let mut disk = ext2_layout(&file, bs, 5000);
        let fake: Vec<u32> = (0..8).map(|k| 3 + k * 2).collect();
        disk[12 * bs..13 * bs].copy_from_slice(&pointer_block(bs, &fake));
        let src = Mem(disk);
        assert_eq!(
            reconstruct(&src, 0, file.len() as u64, CarveSize::Logical),
            None
        );
    }

    #[test]
    fn a_pointer_block_whose_entry_count_disagrees_with_the_file_size_is_not_used() {
        // The IND holds 8 pointers but the header says the file has 10 blocks
        // past block 12: the layout does not verify, so nothing is rebuilt.
        let bs = 1024;
        let file = content(20 * bs);
        let src = Mem(ext2_layout(&file, bs, 5000));
        assert_eq!(
            reconstruct(&src, 0, (22 * bs) as u64, CarveSize::Logical),
            None
        );
    }

    fn view_bytes<S: CarvingDataSource>(v: &LayoutView<'_, S>) -> Vec<u8> {
        let mut out = vec![0u8; v.size() as usize];
        assert_eq!(v.read_at(0, &mut out).unwrap(), out.len());
        out
    }

    #[test]
    fn the_layout_view_reads_the_file_through_its_ind_block() {
        let file = content(20 * 1024 - 300);
        let mut disk = vec![0x11u8; 3072];
        let start = disk.len() as u64;
        disk.extend(ext2_layout(&file, 1024, 900));
        disk.extend(vec![0x22u8; 4096]);
        let src = Mem(disk);
        let v = LayoutView::at(&src, start).expect("view");
        assert_eq!((v.block_size, v.blocks), (1024, 20));
        let bytes = view_bytes(&v);
        assert_eq!(&bytes[..file.len()], &file[..]);
        assert!(bytes[file.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_layout_view_follows_the_dind_to_the_last_ind() {
        let bs = 1024;
        let file = content((12 + 256 + 300) * bs - 5);
        let src = Mem(ext2_layout(&file, bs, 1));
        let v = LayoutView::at(&src, 0).expect("view");
        assert_eq!(v.blocks, 12 + 256 + 300);
        assert_eq!(&view_bytes(&v)[..file.len()], &file[..]);
    }

    #[test]
    fn no_layout_view_without_an_in_line_ind() {
        let src = Mem(content(40 * 1024));
        assert!(LayoutView::at(&src, 0).is_none());
    }

    #[test]
    fn a_small_file_has_no_pointer_block_and_is_left_alone() {
        let file = content(12 * 1024);
        let src = Mem(ext2_layout(&file, 1024, 10));
        assert_eq!(
            reconstruct(&src, 0, file.len() as u64, CarveSize::Logical),
            None
        );
    }

    #[test]
    fn a_layout_running_past_the_end_of_the_source_is_not_rebuilt() {
        let file = content(20 * 1024);
        let mut disk = ext2_layout(&file, 1024, 5000);
        disk.truncate(disk.len() - 1024);
        let src = Mem(disk);
        assert_eq!(
            reconstruct(&src, 0, file.len() as u64, CarveSize::Logical),
            None
        );
    }
}
