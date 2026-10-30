//! A SquashFS 4.0 reader: superblock, metadata blocks, inodes, the directory
//! tree, and regular-file extraction.
//!
//! SquashFS is a read-only compressed filesystem used for Android system
//! partitions, live-CD/appliance root images and firmware. This reads the layout
//! documented in the kernel's `squashfs` and the `squashfs-tools` sources: a
//! 96-byte superblock points at four metadata regions (inode, directory,
//! fragment, id tables), each a series of 8 KiB metadata blocks with a 2-byte
//! length header. Regular-file content is stored as full data blocks plus an
//! optional tail fragment.
//!
//! Compression: gzip and "uncompressed" are handled here. Other algorithms
//! (lzo/lzma/xz/lz4/zstd) are reported as unsupported rather than silently
//! producing nothing — an examiner learns the image needs a build with that
//! codec, not that it held no files.
//!
//! File content is read on demand: [`SquashReader::entries`] walks the tree
//! and attaches a [`SquashFileSource`] to each regular file instead of
//! decompressing it there and then. Every squashfs data block is its own
//! independent compressed stream, so a [`SquashFileSource`] can decompress
//! block *N* straight away — its compressed position is a sum of the on-disk
//! sizes the inode already carries, not something reached by decompressing
//! blocks 0..N first — and it caches a bounded number of decompressed blocks
//! so repeated reads that land back in one block are not re-inflated.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use seance_core::data_source::DataSource;

const MAGIC: u32 = 0x7371_7368; // "hsqs" little-endian (h=0x68,s=0x73,q=0x71,s=0x73)

/// The format's own ceiling on one metadata block once decompressed
/// (`SQUASHFS_METADATA_SIZE` in the kernel and squashfs-tools).
const META_BLOCK_SIZE: usize = 8192;

/// Ceiling on one *decompressed* metadata region (inode or directory table).
/// Generous next to real evidence — the directory table of an image at this
/// walker's own 5M-entry limit is a few hundred MB — but finite, so a chain of
/// compression bombs cannot grow a table until the worker dies.
const MAX_META_REGION_BYTES: usize = 512 * 1024 * 1024;

/// SquashFS compression ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Gzip,
    Lzo,
    Lzma,
    Xz,
    Lz4,
    Zstd,
    Unknown(u16),
}

impl Compression {
    fn from_id(id: u16) -> Self {
        match id {
            1 => Compression::Gzip,
            2 => Compression::Lzo,
            3 => Compression::Lzma,
            4 => Compression::Xz,
            5 => Compression::Lz4,
            6 => Compression::Zstd,
            other => Compression::Unknown(other),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Lzo => "lzo",
            Compression::Lzma => "lzma",
            Compression::Xz => "xz",
            Compression::Lz4 => "lz4",
            Compression::Zstd => "zstd",
            Compression::Unknown(_) => "unknown",
        }
    }
}

/// Errors reading a SquashFS image.
#[derive(Debug, thiserror::Error)]
pub enum SquashError {
    #[error("not a SquashFS image (bad magic)")]
    NotSquashfs,
    #[error("unsupported SquashFS version {0}.{1} (only 4.0 is read)")]
    UnsupportedVersion(u16, u16),
    #[error("unsupported compression: {0}")]
    UnsupportedCompression(&'static str),
    #[error("truncated or malformed image: {0}")]
    Malformed(String),
}

/// So a [`SquashFileSource`]'s `read_at` (which must return `io::Result`) can
/// use `?` directly against the same parsing/decompression errors `read_file`
/// returns.
impl From<SquashError> for io::Error {
    fn from(e: SquashError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    }
}

/// The parsed superblock (the fields this reader needs).
#[derive(Debug, Clone)]
pub struct SuperBlock {
    pub inode_count: u32,
    pub block_size: u32,
    pub compression: Compression,
    pub root_inode_ref: u64,
    pub bytes_used: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    pub id_table_start: u64,
    pub fragment_count: u32,
}

impl SuperBlock {
    pub fn parse(data: &[u8]) -> Result<Self, SquashError> {
        if data.len() < 96 {
            return Err(SquashError::Malformed("shorter than a superblock".into()));
        }
        let u32a = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let u16a = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().unwrap());
        let u64a = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        if u32a(0) != MAGIC {
            return Err(SquashError::NotSquashfs);
        }
        let major = u16a(28);
        let minor = u16a(30);
        if major != 4 {
            return Err(SquashError::UnsupportedVersion(major, minor));
        }
        Ok(SuperBlock {
            inode_count: u32a(4),
            block_size: u32a(12),
            fragment_count: u32a(16),
            compression: Compression::from_id(u16a(20)),
            root_inode_ref: u64a(32),
            bytes_used: u64a(40),
            id_table_start: u64a(48),
            inode_table_start: u64a(64),
            directory_table_start: u64a(72),
            fragment_table_start: u64a(80),
        })
    }
}

/// One decompressed metadata region (inode table or directory table), plus a map
/// from each block's compressed start offset (relative to the region start) to
/// its position in the concatenated decompressed stream. An inode reference is
/// `(block_offset << 16) | offset_in_block`, so both are needed to resolve it.
struct MetaRegion {
    data: Vec<u8>,
    block_map: BTreeMap<u64, usize>,
}

impl MetaRegion {
    /// Decompress every metadata block from `start` up to `end`.
    ///
    /// `max_bytes` bounds the region *after* decompression. Each block is
    /// separately capped at [`META_BLOCK_SIZE`], but a hostile image can chain
    /// thousands of bomb blocks and exhaust the worker in aggregate, so the
    /// region carries its own ceiling. Passing it is an error rather than a
    /// silent stop: a half-loaded table resolves inode references to the wrong
    /// bytes, which reads as recovered evidence.
    fn load(
        image: &[u8],
        start: u64,
        end: u64,
        comp: Compression,
        max_bytes: usize,
    ) -> Result<Self, SquashError> {
        let mut data = Vec::new();
        let mut block_map = BTreeMap::new();
        let mut pos = start;
        while pos < end {
            let rel = pos - start;
            block_map.insert(rel, data.len());
            let (block, next) = read_meta_block(image, pos as usize, comp)?;
            if data.len() + block.len() > max_bytes {
                return Err(SquashError::Malformed(
                    "metadata table decompresses past the region ceiling".into(),
                ));
            }
            data.extend_from_slice(&block);
            if next as u64 <= pos {
                break; // no progress — malformed
            }
            pos = next as u64;
        }
        Ok(MetaRegion { data, block_map })
    }

    /// Resolve a metadata reference `(block_offset, offset_in_block)` to an index
    /// into the concatenated decompressed stream.
    fn resolve(&self, block_offset: u64, in_block: u16) -> Option<usize> {
        self.block_map
            .get(&block_offset)
            .map(|&base| base + in_block as usize)
    }
}

/// Read one metadata block at `off`: a 2-byte little-endian header whose top bit
/// means "stored uncompressed", low 15 bits the on-disk size. Returns the
/// decompressed bytes and the offset just past the block.
fn read_meta_block(
    image: &[u8],
    off: usize,
    comp: Compression,
) -> Result<(Vec<u8>, usize), SquashError> {
    // `off` can be an attacker-controlled pointer (e.g. a fragment-table entry),
    // so read the 2-byte header through `get` rather than a panicking index.
    let header = image
        .get(off..off.saturating_add(2))
        .filter(|h| h.len() == 2)
        .ok_or_else(|| SquashError::Malformed("metadata header past end".into()))?;
    let hdr = u16::from_le_bytes([header[0], header[1]]);
    let uncompressed = hdr & 0x8000 != 0;
    let size = (hdr & 0x7fff) as usize;
    let start = off + 2;
    let end = start
        .checked_add(size)
        .filter(|&e| e <= image.len())
        .ok_or_else(|| SquashError::Malformed("metadata block past end".into()))?;
    let raw = &image[start..end];
    let out = if uncompressed {
        // Stored verbatim, so the on-disk size *is* the decompressed size and
        // the format's ceiling applies to it directly — the 15-bit header field
        // would otherwise admit four times the maximum.
        if size > META_BLOCK_SIZE {
            return Err(SquashError::Malformed(format!(
                "uncompressed metadata block of {size} bytes exceeds the 8 KiB ceiling"
            )));
        }
        raw.to_vec()
    } else {
        decompress(raw, comp, META_BLOCK_SIZE)?
    };
    Ok((out, end))
}

/// Decompress a block with the image's codec, refusing to inflate past `limit`
/// bytes. Only gzip is implemented; the others are named honestly so absence is
/// never mistaken for emptiness.
///
/// `limit` is the format's own ceiling for the block being read — 8 KiB for a
/// metadata block, the superblock's block size for a data or fragment block —
/// so a crafted stream cannot expand beyond what SquashFS itself permits.
/// Passing it is an error, never a truncation: a short block would reconstruct
/// a file that reads as complete.
fn decompress(raw: &[u8], comp: Compression, limit: usize) -> Result<Vec<u8>, SquashError> {
    match comp {
        Compression::Gzip => {
            let mut out = Vec::new();
            // Stop the inflate one byte past the ceiling: that single extra byte
            // is what distinguishes "exactly at the limit" from "over it", and
            // nothing beyond it is ever allocated.
            flate2::read::ZlibDecoder::new(raw)
                .take(limit as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| SquashError::Malformed(format!("zlib inflate: {e}")))?;
            if out.len() > limit {
                return Err(SquashError::Malformed(format!(
                    "compressed block inflates past its {limit}-byte ceiling"
                )));
            }
            Ok(out)
        }
        other => Err(SquashError::UnsupportedCompression(other.name())),
    }
}

/// A recovered filesystem entry.
#[derive(Debug, Clone)]
pub struct SquashEntry {
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mtime: u32,
    /// A lazy reader over regular-file content, attached when the file is
    /// small enough to extract (bounded by the caller's cap). Nothing is
    /// decompressed until a caller actually reads from it — see
    /// [`SquashFileSource`].
    pub content: Option<Arc<dyn DataSource>>,
    /// Symlink target, when this is a symlink.
    pub symlink_target: Option<String>,
}

/// A fragment-table entry: where a fragment block lives and its on-disk size.
#[derive(Debug, Clone, Copy)]
struct Fragment {
    start: u64,
    size: u32,
}

/// Everything a lazy per-file [`SquashFileSource`] needs from the reader that
/// opened it, shared with an `Arc` clone rather than copied: the image bytes,
/// the codec, the format's block size, and the fragment lookup table. Building
/// one costs three atomic increments, whether or not anything ever reads the
/// file it was made for.
#[derive(Clone)]
struct ImageContext {
    image: Arc<[u8]>,
    compression: Compression,
    block_size: u32,
    fragments: Arc<Vec<Fragment>>,
}

/// The reader. Holds the whole image in memory (the caller bounds the size) —
/// metadata (the inode, directory and fragment tables) is parsed eagerly since
/// walking the tree needs it regardless, but regular-file *content* is not:
/// see [`SquashReader::entries`].
pub struct SquashReader {
    image: Arc<[u8]>,
    sb: SuperBlock,
    inodes: MetaRegion,
    dirs: MetaRegion,
    fragments: Arc<Vec<Fragment>>,
}

impl SquashReader {
    pub fn open(image: Arc<[u8]>) -> Result<Self, SquashError> {
        let sb = SuperBlock::parse(&image)?;
        // Validate the block size before anything divides by it: it is read
        // straight from a hostile-controllable superblock, and a zero (or
        // absurd) value would otherwise panic in `parse_inode`. SquashFS
        // requires a power-of-two block size in [4 KiB, 1 MiB].
        if sb.block_size < 4096 || sb.block_size > 1024 * 1024 || !sb.block_size.is_power_of_two() {
            return Err(SquashError::Malformed(format!(
                "invalid block size {}",
                sb.block_size
            )));
        }
        // Fail fast on a codec we cannot inflate, so the error is one message
        // rather than a cascade of malformed-block errors.
        if !matches!(sb.compression, Compression::Gzip) {
            return Err(SquashError::UnsupportedCompression(sb.compression.name()));
        }
        let inodes = MetaRegion::load(
            &image,
            sb.inode_table_start,
            sb.directory_table_start,
            sb.compression,
            MAX_META_REGION_BYTES,
        )?;
        let dirs = MetaRegion::load(
            &image,
            sb.directory_table_start,
            sb.fragment_table_start
                .min(sb.id_table_start)
                .min(sb.bytes_used),
            sb.compression,
            MAX_META_REGION_BYTES,
        )?;
        let fragments = Arc::new(load_fragment_table(&image, &sb)?);
        Ok(SquashReader {
            image,
            sb,
            inodes,
            dirs,
            fragments,
        })
    }

    pub fn superblock(&self) -> &SuperBlock {
        &self.sb
    }

    /// A cheap (`Arc`-clone) snapshot of what a [`SquashFileSource`] needs,
    /// for handing to every file discovered during a walk.
    fn image_context(&self) -> ImageContext {
        ImageContext {
            image: self.image.clone(),
            compression: self.sb.compression,
            block_size: self.sb.block_size,
            fragments: self.fragments.clone(),
        }
    }

    /// Walk the whole tree from the root, returning every entry. `content_cap`
    /// bounds per-file content extraction; files larger than it get metadata only.
    pub fn entries(&self, content_cap: u64) -> Result<Vec<SquashEntry>, SquashError> {
        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.walk(
            self.sb.root_inode_ref,
            "",
            content_cap,
            &mut out,
            &mut visited,
            0,
        )?;
        Ok(out)
    }

    /// Hard ceiling on entries a single walk emits — defence in depth against a
    /// pathologically large or adversarial tree, on top of the cycle check.
    const MAX_ENTRIES: usize = 5_000_000;

    fn walk(
        &self,
        inode_ref: u64,
        prefix: &str,
        content_cap: u64,
        out: &mut Vec<SquashEntry>,
        visited: &mut std::collections::HashSet<u64>,
        depth: usize,
    ) -> Result<(), SquashError> {
        if depth > 64 {
            return Err(SquashError::Malformed("directory nesting too deep".into()));
        }
        // A directory graph can be a *cycle* (A→B→A) or a DAG that revisits a
        // directory via many paths; either makes an un-memoised walk blow up
        // (exponential with branching). Visit each directory inode at most once.
        if !visited.insert(inode_ref) {
            return Ok(());
        }
        if out.len() > Self::MAX_ENTRIES {
            return Err(SquashError::Malformed(
                "directory tree exceeds the entry limit".into(),
            ));
        }
        let inode = self.read_inode(inode_ref)?;
        match inode {
            Inode::Dir {
                block_idx,
                block_offset,
                size,
                ..
            } => {
                for (name, child_ref, _ty) in self.read_dir(block_idx, block_offset, size)? {
                    let path = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{prefix}/{name}")
                    };
                    let child = self.read_inode(child_ref)?;
                    match &child {
                        Inode::Dir { .. } => {
                            out.push(SquashEntry {
                                path: path.clone(),
                                is_dir: true,
                                is_symlink: false,
                                size: 0,
                                mtime: child.mtime(),
                                content: None,
                                symlink_target: None,
                            });
                            self.walk(child_ref, &path, content_cap, out, visited, depth + 1)?;
                        }
                        Inode::File { size, .. } => {
                            // Attach a lazy reader rather than decompressing
                            // here: nothing is inflated unless a caller later
                            // actually reads from it (HUNT/ROADMAP 5.10 — a
                            // walk used to decompress every file under the cap
                            // whether or not anything downstream ever read it).
                            let content: Option<Arc<dyn DataSource>> = if *size <= content_cap {
                                Some(Arc::new(SquashFileSource::new(
                                    self.image_context(),
                                    &child,
                                )?))
                            } else {
                                None
                            };
                            out.push(SquashEntry {
                                path,
                                is_dir: false,
                                is_symlink: false,
                                size: *size,
                                mtime: child.mtime(),
                                content,
                                symlink_target: None,
                            });
                        }
                        Inode::Symlink { target, .. } => {
                            out.push(SquashEntry {
                                path,
                                is_dir: false,
                                is_symlink: true,
                                size: target.len() as u64,
                                mtime: child.mtime(),
                                content: None,
                                symlink_target: Some(target.clone()),
                            });
                        }
                        Inode::Other { .. } => {
                            out.push(SquashEntry {
                                path,
                                is_dir: false,
                                is_symlink: false,
                                size: 0,
                                mtime: child.mtime(),
                                content: None,
                                symlink_target: None,
                            });
                        }
                    }
                }
                Ok(())
            }
            _ => Err(SquashError::Malformed(
                "root or a directory reference did not resolve to a directory".into(),
            )),
        }
    }

    fn read_inode(&self, inode_ref: u64) -> Result<Inode, SquashError> {
        let block_offset = inode_ref >> 16;
        let in_block = (inode_ref & 0xffff) as u16;
        let pos = self
            .inodes
            .resolve(block_offset, in_block)
            .ok_or_else(|| SquashError::Malformed("inode ref out of range".into()))?;
        parse_inode(&self.inodes.data, pos, self.sb.block_size)
    }

    /// Read a directory's entries: `(name, child_inode_ref, type)`.
    fn read_dir(
        &self,
        block_idx: u32,
        block_offset: u16,
        size: u32,
    ) -> Result<Vec<(String, u64, u16)>, SquashError> {
        let base = self
            .dirs
            .resolve(block_idx as u64, block_offset)
            .ok_or_else(|| SquashError::Malformed("dir ref out of range".into()))?;
        // The declared size includes a phantom 3 bytes; the real listing is
        // `size - 3` bytes of headers+entries.
        let end = base + size.saturating_sub(3) as usize;
        let data = &self.dirs.data;
        if end > data.len() {
            return Err(SquashError::Malformed(
                "directory extends past table".into(),
            ));
        }
        let mut p = base;
        let mut entries = Vec::new();
        while p + 12 <= end {
            let count = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
            let start_block = u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap());
            let _inode_base = u32::from_le_bytes(data[p + 8..p + 12].try_into().unwrap());
            p += 12;
            // `count + 1` entries follow this header.
            for _ in 0..=count {
                if p + 8 > end {
                    break;
                }
                let offset = u16::from_le_bytes(data[p..p + 2].try_into().unwrap());
                let _inode_delta = i16::from_le_bytes(data[p + 2..p + 4].try_into().unwrap());
                let ty = u16::from_le_bytes(data[p + 4..p + 6].try_into().unwrap());
                let name_size = u16::from_le_bytes(data[p + 6..p + 8].try_into().unwrap()) as usize;
                p += 8;
                let name_len = name_size + 1; // stored as (len - 1)
                if p + name_len > end {
                    break;
                }
                let name = String::from_utf8_lossy(&data[p..p + name_len]).into_owned();
                p += name_len;
                // Child inode ref: header's start_block (a metadata block offset)
                // plus this entry's in-block offset.
                let child_ref = ((start_block as u64) << 16) | offset as u64;
                entries.push((name, child_ref, ty));
            }
        }
        Ok(entries)
    }
}

/// A bounds- and overflow-checked view of `[start, start+len)` in `image`.
///
/// `start` is an attacker-controlled u64 inode field; computing `start + len`
/// with plain `usize` arithmetic can wrap (making `end < start`) and then
/// panic the slice index. `checked_add` + `get` turn every such case into a
/// clean `Malformed` error.
fn checked_image_slice(image: &[u8], start: u64, len: usize) -> Result<&[u8], SquashError> {
    let start = usize::try_from(start)
        .map_err(|_| SquashError::Malformed("region offset out of range".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| SquashError::Malformed("region length overflows".into()))?;
    image
        .get(start..end)
        .ok_or_else(|| SquashError::Malformed("region extends past image end".into()))
}

/// Decompressed blocks kept resident per open [`SquashFileSource`]. A small,
/// fixed ceiling (matching the workspace's `CachingDataSource` LRU convention
/// in `seance_core::data_source`) is enough for a forward scan or a cluster of
/// small reads within a block to avoid re-inflating it, without letting a
/// large file's cache grow with the file's size.
const CACHED_BLOCKS_PER_FILE: usize = 8;

/// Lazily reconstructs one regular file's content — full data blocks plus an
/// optional tail fragment — decompressing only the block(s) a caller's
/// `read_at` actually touches, in place of [`SquashReader::read_file`]
/// decompressing the whole thing up front.
///
/// This is possible without walking every earlier block first because a
/// squashfs data block is its own independent compressed stream: block *N*'s
/// compressed position is the sum of the on-disk sizes of blocks `0..N`, and
/// those sizes are already sitting in the inode's `block_sizes` — reading them
/// is arithmetic, not decompression. Decompressed blocks are then cached
/// (bounded, LRU — [`CACHED_BLOCKS_PER_FILE`]) so a caller re-reading inside a
/// block it already touched gets it from the cache.
pub struct SquashFileSource {
    ctx: ImageContext,
    blocks_start: u64,
    fragment: u32,
    block_offset: u32,
    size: u64,
    block_sizes: Vec<u32>,
    /// Compressed start offset of each `block_sizes` entry, relative to
    /// `blocks_start` — a prefix sum over on-disk sizes already known from the
    /// inode, computed once at construction so random access never needs to
    /// touch (let alone decompress) an earlier block to find a later one.
    block_positions: Vec<u64>,
    blocks: Mutex<LruCache<usize, Arc<Vec<u8>>>>,
    /// The tail fragment, decompressed at most once (a file has only one).
    fragment_block: Mutex<Option<Arc<Vec<u8>>>>,
}

impl std::fmt::Debug for SquashFileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SquashFileSource")
            .field("size", &self.size)
            .field("blocks", &self.block_sizes.len())
            .field("has_fragment", &(self.fragment != 0xffff_ffff))
            .finish()
    }
}

impl SquashFileSource {
    /// Build a lazy content reader for `inode`, which must be
    /// [`Inode::File`]. No image bytes are touched here — only the already-
    /// parsed inode fields are consulted.
    fn new(ctx: ImageContext, inode: &Inode) -> Result<Self, SquashError> {
        let Inode::File {
            blocks_start,
            fragment,
            block_offset,
            size,
            block_sizes,
            ..
        } = inode
        else {
            return Err(SquashError::Malformed("not a file".into()));
        };
        let mut block_positions = Vec::with_capacity(block_sizes.len());
        let mut pos = 0u64;
        for &bs in block_sizes {
            block_positions.push(pos);
            let on_disk = (bs & 0x00ff_ffff) as u64; // low 24 bits = on-disk size
            pos = pos.saturating_add(on_disk);
        }
        Ok(SquashFileSource {
            ctx,
            blocks_start: *blocks_start,
            fragment: *fragment,
            block_offset: *block_offset,
            size: *size,
            block_sizes: block_sizes.clone(),
            block_positions,
            blocks: Mutex::new(LruCache::new(
                NonZeroUsize::new(CACHED_BLOCKS_PER_FILE).unwrap(),
            )),
            fragment_block: Mutex::new(None),
        })
    }

    /// Decompressed bytes of data block `idx`, from the cache when a previous
    /// read already paid for it.
    fn block(&self, idx: usize) -> Result<Arc<Vec<u8>>, SquashError> {
        if let Some(hit) = self
            .blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&idx)
        {
            return Ok(hit.clone());
        }
        let bs = self.block_sizes[idx];
        let on_disk = (bs & 0x00ff_ffff) as usize;
        let uncompressed = bs & 0x0100_0000 != 0;
        let block_cap = self.ctx.block_size as usize;
        let decoded = if on_disk == 0 {
            // A sparse block: block_size zero bytes, exactly as the eager
            // reader synthesizes one (`read_file`'s own sparse-block arm).
            Arc::new(vec![0u8; block_cap])
        } else {
            let start = self.blocks_start.saturating_add(self.block_positions[idx]);
            let raw = checked_image_slice(&self.ctx.image, start, on_disk)?;
            let bytes = if uncompressed {
                // Stored verbatim, so its 24-bit on-disk size is its content
                // size and the same ceiling applies.
                if on_disk > block_cap {
                    return Err(SquashError::Malformed(format!(
                        "uncompressed data block of {on_disk} bytes exceeds the block size"
                    )));
                }
                raw.to_vec()
            } else {
                decompress(raw, self.ctx.compression, block_cap)?
            };
            Arc::new(bytes)
        };
        self.blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(idx, decoded.clone());
        Ok(decoded)
    }

    /// Decompressed bytes of the tail fragment block, decompressed once and
    /// remembered for later reads.
    fn fragment_bytes(&self) -> Result<Arc<Vec<u8>>, SquashError> {
        if let Some(hit) = self
            .fragment_block
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Ok(hit);
        }
        let frag = self
            .ctx
            .fragments
            .get(self.fragment as usize)
            .ok_or_else(|| SquashError::Malformed("fragment index out of range".into()))?;
        let on_disk = (frag.size & 0x00ff_ffff) as usize;
        let uncompressed = frag.size & 0x0100_0000 != 0;
        let block_cap = self.ctx.block_size as usize;
        let raw = checked_image_slice(&self.ctx.image, frag.start, on_disk)?;
        let bytes = if uncompressed {
            if on_disk > block_cap {
                return Err(SquashError::Malformed(format!(
                    "uncompressed fragment block of {on_disk} bytes exceeds the block size"
                )));
            }
            raw.to_vec()
        } else {
            // A fragment block packs tails into at most one block_size.
            decompress(raw, self.ctx.compression, block_cap)?
        };
        let bytes = Arc::new(bytes);
        *self
            .fragment_block
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(bytes.clone());
        Ok(bytes)
    }
}

impl DataSource for SquashFileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let block_size = self.ctx.block_size as u64;
        let n_full_blocks = self.block_sizes.len() as u64;
        let has_fragment = self.fragment != 0xffff_ffff;
        // saturating_add: an end offset that would pass u64::MAX must clamp to
        // the file size, never wrap below `offset` (which would read as EOF).
        let want_end = offset.saturating_add(buf.len() as u64).min(self.size);
        let mut pos = offset;
        let mut written = 0usize;
        while pos < want_end {
            let block_idx = pos / block_size;
            if block_idx < n_full_blocks {
                let block = self.block(block_idx as usize)?;
                let in_block_off = (pos % block_size) as usize;
                if in_block_off >= block.len() {
                    // A block decompressed shorter than the offset it must
                    // cover — only reachable on a malformed image (a genuine
                    // squashfs data block, other than a truncated final block
                    // handled below, always decompresses to exactly
                    // `block_size`). Stop rather than loop or read past the
                    // block, matching `CachingDataSource`'s same short-chunk
                    // convention (`seance_core::data_source`).
                    break;
                }
                let avail = block.len() - in_block_off;
                let take = ((want_end - pos) as usize).min(avail);
                buf[written..written + take]
                    .copy_from_slice(&block[in_block_off..in_block_off + take]);
                written += take;
                pos += take as u64;
            } else if has_fragment {
                let frag_file_start = n_full_blocks * block_size;
                let tail_len = (self.size - frag_file_start) as usize;
                let block = self.fragment_bytes()?;
                let bo = self.block_offset as usize;
                // `bo + tail_len` is bounded arithmetic on untrusted fields. If
                // the tail does not fit inside the decompressed fragment
                // block, the file cannot be reconstructed in full — fail
                // closed rather than silently return a file shorter than its
                // declared size, which a caller would read as complete (same
                // check as `SquashReader::read_file`).
                bo.checked_add(tail_len)
                    .filter(|e| *e <= block.len())
                    .ok_or_else(|| {
                        SquashError::Malformed(
                            "fragment tail extends past the decompressed fragment block".into(),
                        )
                    })?;
                let in_frag_off = (pos - frag_file_start) as usize;
                let avail = tail_len - in_frag_off;
                let take = ((want_end - pos) as usize).min(avail);
                buf[written..written + take]
                    .copy_from_slice(&block[bo + in_frag_off..bo + in_frag_off + take]);
                written += take;
                pos += take as u64;
            } else {
                // No fragment and past the last data block — unreachable while
                // pos < want_end <= size, since `n_full_blocks` (no-fragment
                // case) covers the whole file by construction. Kept as a
                // defensive stop rather than a loop.
                break;
            }
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// A parsed inode (the subset needed to walk the tree and read files).
enum Inode {
    Dir {
        mtime: u32,
        block_idx: u32,
        block_offset: u16,
        size: u32,
    },
    File {
        mtime: u32,
        blocks_start: u64,
        fragment: u32,
        block_offset: u32,
        size: u64,
        block_sizes: Vec<u32>,
    },
    Symlink {
        mtime: u32,
        target: String,
    },
    Other {
        mtime: u32,
    },
}

impl Inode {
    fn mtime(&self) -> u32 {
        match self {
            Inode::Dir { mtime, .. }
            | Inode::File { mtime, .. }
            | Inode::Symlink { mtime, .. }
            | Inode::Other { mtime } => *mtime,
        }
    }
}

/// Parse an inode at `pos` in the decompressed inode table.
fn parse_inode(data: &[u8], pos: usize, block_size: u32) -> Result<Inode, SquashError> {
    let need = |n: usize| -> Result<(), SquashError> {
        if pos + n > data.len() {
            Err(SquashError::Malformed("inode past table".into()))
        } else {
            Ok(())
        }
    };
    need(16)?;
    let u16a = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().unwrap());
    let u32a = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let ty = u16a(pos);
    let mtime = u32a(pos + 8);
    let body = pos + 16;
    match ty {
        // Basic directory.
        1 => {
            need(16 + 16)?;
            Ok(Inode::Dir {
                mtime,
                block_idx: u32a(body),
                size: u16a(body + 8) as u32,
                block_offset: u16a(body + 10),
            })
        }
        // Extended directory (`squashfs_ldir_inode_header`).
        8 => {
            need(16 + 24)?;
            // nlink(body+0), file_size(body+4), start_block(body+8),
            // parent(body+12), i_count(body+16), offset(body+18).
            Ok(Inode::Dir {
                mtime,
                size: u32a(body + 4),
                block_idx: u32a(body + 8),
                block_offset: u16a(body + 18),
            })
        }
        // Basic file.
        2 => {
            need(16 + 16)?;
            let blocks_start = u32a(body) as u64;
            let fragment = u32a(body + 4);
            let block_offset = u32a(body + 8);
            let size = u32a(body + 12) as u64;
            let n_blocks = if fragment == 0xffff_ffff {
                size.div_ceil(block_size as u64) as usize
            } else {
                (size / block_size as u64) as usize
            };
            need(16 + 16 + n_blocks * 4)?;
            let block_sizes = (0..n_blocks).map(|i| u32a(body + 16 + i * 4)).collect();
            Ok(Inode::File {
                mtime,
                blocks_start,
                fragment,
                block_offset,
                size,
                block_sizes,
            })
        }
        // Extended file (`squashfs_lreg_inode_header`).
        9 => {
            need(16 + 40)?;
            let u64a = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
            // start_block(body+0, u64), file_size(body+8, u64), sparse(body+16,
            // u64), nlink(body+24), fragment(body+28), offset(body+32),
            // xattr(body+36), block_sizes(body+40).
            let blocks_start = u64a(body);
            let size = u64a(body + 8);
            let fragment = u32a(body + 28);
            let block_offset = u32a(body + 32);
            let n_blocks = if fragment == 0xffff_ffff {
                size.div_ceil(block_size as u64) as usize
            } else {
                (size / block_size as u64) as usize
            };
            need(16 + 40 + n_blocks * 4)?;
            let block_sizes = (0..n_blocks).map(|i| u32a(body + 40 + i * 4)).collect();
            Ok(Inode::File {
                mtime,
                blocks_start,
                fragment,
                block_offset,
                size,
                block_sizes,
            })
        }
        // Basic symlink.
        3 => {
            need(16 + 8)?;
            let target_size = u32a(body + 4) as usize;
            let ts = body + 8;
            need(16 + 8 + target_size)?;
            let target = String::from_utf8_lossy(&data[ts..ts + target_size]).into_owned();
            Ok(Inode::Symlink { mtime, target })
        }
        _ => Ok(Inode::Other { mtime }),
    }
}

/// Load the fragment lookup table: an array of indirect metadata-block pointers,
/// each block holding fragment entries `(start:u64, size:u32, unused:u32)`.
fn load_fragment_table(image: &[u8], sb: &SuperBlock) -> Result<Vec<Fragment>, SquashError> {
    if sb.fragment_count == 0 || sb.fragment_table_start == 0xffff_ffff_ffff_ffff {
        return Ok(Vec::new());
    }
    // Number of indirect pointers: each metadata block holds up to 512 entries.
    let n_ptrs = (sb.fragment_count as usize).div_ceil(512);
    let table_start = sb.fragment_table_start as usize;
    // Bounds-check the pointer array without overflowing.
    let index_end = table_start.saturating_add(n_ptrs.saturating_mul(8));
    if index_end > image.len() {
        return Err(SquashError::Malformed("fragment index past end".into()));
    }
    // Reserve only a modest hint and let the vector grow — the fill loop is
    // bounded by the metadata blocks that actually exist. Reserving the raw,
    // attacker-controlled `fragment_count` would let a small image demand a
    // multi-gigabyte allocation (it can be up to 0xffffffff).
    let capacity = (sb.fragment_count as usize).min(65_536);
    let mut frags = Vec::with_capacity(capacity);
    for i in 0..n_ptrs {
        let ptr = u64::from_le_bytes(
            image[table_start + i * 8..table_start + i * 8 + 8]
                .try_into()
                .unwrap(),
        );
        let (block, _) = read_meta_block(image, ptr as usize, sb.compression)?;
        let mut p = 0;
        while p + 16 <= block.len() && frags.len() < sb.fragment_count as usize {
            let start = u64::from_le_bytes(block[p..p + 8].try_into().unwrap());
            let size = u32::from_le_bytes(block[p + 8..p + 12].try_into().unwrap());
            frags.push(Fragment { start, size });
            p += 16;
        }
    }
    Ok(frags)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal [`ImageContext`] whose only content is a single
    /// uncompressed fragment block, so a [`SquashFileSource`] can be exercised
    /// on a crafted file inode without a whole mksquashfs image.
    fn ctx_with_fragment(image: &[u8], frag_len: u32) -> ImageContext {
        // Uncompressed bit set so the fragment block is the raw bytes verbatim.
        ctx_with_fragment_entry(image, 0x0100_0000 | frag_len)
    }

    /// As above, but with the fragment entry's raw size field (compression bit
    /// included) chosen by the caller.
    fn ctx_with_fragment_entry(image: &[u8], frag_size: u32) -> ImageContext {
        ImageContext {
            image: Arc::from(image.to_vec()),
            compression: Compression::Gzip,
            block_size: 4096,
            fragments: Arc::new(vec![Fragment {
                start: 0,
                size: frag_size,
            }]),
        }
    }

    /// Read a [`DataSource`] to the end via `read_at`, the way every real
    /// caller (hasher, search, content viewer) does — proves the lazy reader
    /// produces the same bytes `read_file` used to hand back in one shot.
    fn read_all(ds: &dyn DataSource) -> io::Result<Vec<u8>> {
        let mut out = vec![0u8; ds.size() as usize];
        let mut got = 0usize;
        while got < out.len() {
            match ds.read_at(got as u64, &mut out[got..])? {
                0 => break,
                n => got += n,
            }
        }
        out.truncate(got);
        Ok(out)
    }

    /// Deflate `data` into a zlib stream, for building crafted blocks.
    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// One compressed metadata block: a 2-byte header (on-disk size, top bit
    /// clear so it reads as compressed) followed by the deflate stream.
    fn meta_block(payload: &[u8]) -> Vec<u8> {
        let z = zlib(payload);
        assert!(
            z.len() < 0x8000,
            "test block must fit the 15-bit size field"
        );
        let mut out = (z.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&z);
        out
    }

    /// A fragment tail whose (untrusted) block_offset + length runs past the
    /// decompressed fragment block must FAIL CLOSED, not silently return a file
    /// shorter than its declared size as if it were complete.
    #[test]
    fn read_file_fails_closed_on_out_of_range_fragment_tail() {
        let frag = vec![0xABu8; 8];
        let ctx = ctx_with_fragment(&frag, 8);
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0,
            block_offset: 100, // past the 8-byte fragment block
            size: 4,           // so tail_len = 4, and 100 + 4 > 8
            block_sizes: Vec::new(),
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        assert!(
            read_all(&source).is_err(),
            "an out-of-range fragment tail must be an error, not a silent short file"
        );
    }

    /// An in-range fragment tail still reconstructs the file bytes.
    #[test]
    fn read_file_reads_an_in_range_fragment_tail() {
        let frag = vec![0xABu8; 8];
        let ctx = ctx_with_fragment(&frag, 8);
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0,
            block_offset: 2,
            size: 3, // block[2..5]
            block_sizes: Vec::new(),
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        assert_eq!(read_all(&source).unwrap(), vec![0xAB, 0xAB, 0xAB]);
    }

    /// The whole point of [`SquashFileSource`]: building one, and asking its
    /// size, must not touch the image at all. Here the fragment table entry
    /// points at a block that would fail to decompress (it is truncated to
    /// nothing) -- if construction decompressed eagerly, it would either need
    /// to swallow that error or fail early; instead it must succeed, and only
    /// `read_at` — the caller actually asking for bytes — sees the error.
    #[test]
    fn building_a_file_source_does_not_touch_the_image() {
        let ctx = ImageContext {
            image: Arc::from(Vec::<u8>::new()), // nothing here decompresses to anything
            compression: Compression::Gzip,
            block_size: 4096,
            fragments: Arc::new(vec![Fragment {
                start: 0,
                size: 0x0100_0000 | 4096, // uncompressed, but the image is empty
            }]),
        };
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0,
            block_offset: 0,
            size: 10,
            block_sizes: Vec::new(),
        };
        let source = SquashFileSource::new(ctx, &inode)
            .expect("building a lazy source never reads image bytes");
        assert_eq!(source.size(), 10, "size is metadata, not content");
        assert!(
            read_all(&source).is_err(),
            "the image only turns out to be too short once something actually reads"
        );
    }

    /// A block decompressed once must be served from cache on a second read
    /// into the same block, not decompressed again — [`SquashFileSource`]'s
    /// whole reason for a bounded LRU. Proven directly: the second `block()`
    /// call must return the *same* `Arc` allocation as the first, not a fresh
    /// one holding equal-but-different bytes.
    #[test]
    fn a_decompressed_block_is_served_from_cache_on_a_second_read() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let raw = zlib(&payload);
        let ctx = ctx_with_fragment(&raw, 0); // block_size 4096, fragment unused
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0xffff_ffff,
            block_offset: 0,
            size: 4096,
            block_sizes: vec![raw.len() as u32],
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        let first = source.block(0).expect("decompress block 0");
        let second = source.block(0).expect("cache hit for block 0");
        assert!(
            Arc::ptr_eq(&first, &second),
            "a second read into an already-decompressed block must reuse it, not re-inflate it"
        );
    }

    #[test]
    fn rejects_non_squashfs() {
        assert!(matches!(
            SuperBlock::parse(&[0u8; 96]),
            Err(SquashError::NotSquashfs)
        ));
    }

    #[test]
    fn superblock_fields_from_a_known_header() {
        // The header captured from a real `mksquashfs -comp gzip` image.
        let mut d = vec![0u8; 96];
        d[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        d[4..8].copy_from_slice(&5u32.to_le_bytes()); // inode_count
        d[12..16].copy_from_slice(&0x20000u32.to_le_bytes()); // block_size
        d[20..22].copy_from_slice(&1u16.to_le_bytes()); // gzip
        d[28..30].copy_from_slice(&4u16.to_le_bytes()); // major
        let sb = SuperBlock::parse(&d).unwrap();
        assert_eq!(sb.inode_count, 5);
        assert_eq!(sb.block_size, 0x20000);
        assert_eq!(sb.compression, Compression::Gzip);
    }

    #[test]
    fn unsupported_version_is_named() {
        let mut d = vec![0u8; 96];
        d[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        d[28..30].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            SuperBlock::parse(&d),
            Err(SquashError::UnsupportedVersion(3, _))
        ));
    }

    /// A superblock with valid magic/version/codec but a zero block size must be
    /// rejected at `open`, not carried into a divide-by-zero in `parse_inode`.
    #[test]
    fn a_zero_block_size_is_refused_not_a_panic() {
        let mut d = vec![0u8; 96];
        d[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        d[4..8].copy_from_slice(&1u32.to_le_bytes());
        d[12..16].copy_from_slice(&0u32.to_le_bytes()); // block_size = 0
        d[20..22].copy_from_slice(&1u16.to_le_bytes()); // gzip
        d[28..30].copy_from_slice(&4u16.to_le_bytes()); // version 4
        assert!(matches!(
            SquashReader::open(Arc::from(d)),
            Err(SquashError::Malformed(_))
        ));
    }

    /// A non-power-of-two / out-of-range block size is equally refused.
    #[test]
    fn an_absurd_block_size_is_refused() {
        for bs in [1234u32, 3, 8 * 1024 * 1024] {
            let mut d = vec![0u8; 96];
            d[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            d[4..8].copy_from_slice(&1u32.to_le_bytes());
            d[12..16].copy_from_slice(&bs.to_le_bytes());
            d[20..22].copy_from_slice(&1u16.to_le_bytes());
            d[28..30].copy_from_slice(&4u16.to_le_bytes());
            assert!(
                matches!(
                    SquashReader::open(Arc::from(d)),
                    Err(SquashError::Malformed(_))
                ),
                "block size {bs} must be refused"
            );
        }
    }

    /// A metadata pointer past the image end returns an error, not a panic —
    /// `read_meta_block` must not index an attacker-controlled offset directly.
    #[test]
    fn a_metadata_offset_past_the_end_errors_cleanly() {
        let image = vec![0u8; 100];
        assert!(read_meta_block(&image, usize::MAX - 1, Compression::Gzip).is_err());
        assert!(read_meta_block(&image, 200, Compression::Gzip).is_err());
    }

    /// A metadata block is 8 KiB decompressed by the format's own definition. A
    /// crafted block whose deflate stream expands far past that must be refused
    /// at inflate time, not allowed to allocate whatever it wants.
    #[test]
    fn a_metadata_block_that_inflates_past_the_format_ceiling_is_refused() {
        // ~1 KiB of deflate expanding to 1 MiB — 128x the metadata ceiling.
        let image = meta_block(&vec![0u8; 1024 * 1024]);
        assert!(
            matches!(
                read_meta_block(&image, 0, Compression::Gzip),
                Err(SquashError::Malformed(_))
            ),
            "a metadata block inflating past 8 KiB must be an error, not an allocation"
        );
    }

    /// The ceiling is 8 KiB *inclusive*: a full-size metadata block, which every
    /// real image is made of, must still read.
    #[test]
    fn a_full_size_metadata_block_still_reads() {
        let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let image = meta_block(&payload);
        let (block, next) = read_meta_block(&image, 0, Compression::Gzip).expect("reads");
        assert_eq!(block, payload);
        assert_eq!(next, image.len());
    }

    /// An *uncompressed* metadata block is stored verbatim, so the same ceiling
    /// applies to its on-disk size — the 15-bit header field otherwise allows
    /// four times the format's maximum.
    #[test]
    fn an_oversized_uncompressed_metadata_block_is_refused() {
        let mut image = vec![0u8; 20_002];
        // Top bit set = stored uncompressed, low 15 bits = 20,000 on-disk bytes.
        image[0..2].copy_from_slice(&(0x8000u16 | 20_000u16).to_le_bytes());
        assert!(matches!(
            read_meta_block(&image, 0, Compression::Gzip),
            Err(SquashError::Malformed(_))
        ));
    }

    /// The per-block ceiling does not bound a *region*: a chain of bomb blocks
    /// grows the decompressed table without limit. The region must fail closed
    /// at its ceiling rather than keep growing — a half-loaded table would
    /// resolve inode references to the wrong bytes.
    #[test]
    fn a_chain_of_metadata_blocks_stops_at_the_region_ceiling() {
        let block = meta_block(&vec![0u8; 8192]);
        let mut image = Vec::new();
        for _ in 0..4 {
            image.extend_from_slice(&block);
        }
        let end = image.len() as u64;
        assert!(
            matches!(
                MetaRegion::load(&image, 0, end, Compression::Gzip, 16 * 1024),
                Err(SquashError::Malformed(_))
            ),
            "a region growing past its ceiling must be refused"
        );
        let region = MetaRegion::load(&image, 0, end, Compression::Gzip, 64 * 1024).unwrap();
        assert_eq!(region.data.len(), 4 * 8192);
    }

    /// A data block decompresses to at most the superblock's block size. A
    /// crafted block that expands past it must be refused, not accumulated and
    /// then truncated to the declared file size (which happens only after the
    /// whole block loop has already allocated).
    #[test]
    fn a_data_block_that_inflates_past_the_block_size_is_refused() {
        let bomb = zlib(&vec![0u8; 1024 * 1024]); // 256x the 4 KiB block size
                                                  // The fragment entry is unused here: the inode declares no fragment.
        let ctx = ctx_with_fragment(&bomb, 0);
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0xffff_ffff,
            block_offset: 0,
            size: 4096,
            block_sizes: vec![bomb.len() as u32], // compressed (bit 24 clear)
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        assert!(
            read_all(&source).is_err(),
            "a data block inflating past the block size must be an error"
        );
    }

    /// A block that decompresses to exactly the block size is normal content and
    /// must still reconstruct.
    #[test]
    fn a_data_block_of_exactly_the_block_size_still_reads() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let raw = zlib(&payload);
        let ctx = ctx_with_fragment(&raw, 0);
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0xffff_ffff,
            block_offset: 0,
            size: 4096,
            block_sizes: vec![raw.len() as u32],
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        assert_eq!(read_all(&source).unwrap(), payload);
    }

    /// An uncompressed data block is stored verbatim, so its 24-bit on-disk size
    /// must also respect the block size — otherwise each block can copy up to
    /// 16 MiB into the output and the file grows far past what it declares.
    #[test]
    fn an_oversized_uncompressed_data_block_is_refused() {
        let image = vec![0xCDu8; 16 * 1024];
        let ctx = ctx_with_fragment(&image, 0);
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0xffff_ffff,
            block_offset: 0,
            size: 4096,
            block_sizes: vec![0x0100_0000 | 16_384], // uncompressed, 4x block size
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        assert!(read_all(&source).is_err());
    }

    /// The fragment path inflates too, and is bounded the same way.
    #[test]
    fn a_fragment_block_that_inflates_past_the_block_size_is_refused() {
        let bomb = zlib(&vec![0u8; 1024 * 1024]);
        let ctx = ctx_with_fragment_entry(&bomb, bomb.len() as u32); // compressed
        let inode = Inode::File {
            mtime: 0,
            blocks_start: 0,
            fragment: 0,
            block_offset: 0,
            size: 16,
            block_sizes: Vec::new(),
        };
        let source = SquashFileSource::new(ctx, &inode).expect("build lazy source");
        assert!(
            read_all(&source).is_err(),
            "a fragment block inflating past the block size must be an error"
        );
    }

    /// A huge declared `fragment_count` on a small image must not attempt a
    /// multi-gigabyte reservation; it is bounded by the index-array check.
    #[test]
    fn a_huge_fragment_count_does_not_over_allocate() {
        let mut sb = SuperBlock::parse(&{
            let mut d = vec![0u8; 96];
            d[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            d[4..8].copy_from_slice(&1u32.to_le_bytes());
            d[12..16].copy_from_slice(&0x20000u32.to_le_bytes());
            d[20..22].copy_from_slice(&1u16.to_le_bytes());
            d[28..30].copy_from_slice(&4u16.to_le_bytes());
            d
        })
        .unwrap();
        sb.fragment_count = 0xffff_ffff;
        sb.fragment_table_start = 32;
        // A 100-byte image cannot hold ~8.4M index pointers, so this is refused
        // by the bounds check rather than reserving gigabytes.
        assert!(load_fragment_table(&[0u8; 100], &sb).is_err());
    }
}
